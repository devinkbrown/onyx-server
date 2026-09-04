// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict, allocation-free X.509 Certificate Revocation List parser.
//!
//! This module parses the RFC 5280 §5 `CertificateList` structure and exposes
//! issuer/update metadata plus an on-demand iterator over revoked certificate
//! serial numbers. Parsing itself is allocation-free and does no crypto.
//!
//! ## Authenticating and using a CRL
//!
//! Revocation results are only trustworthy once the CRL has been authenticated
//! against the *issuing CA*. The intended integration flow (the fetch and
//! policy live in the caller, e.g. `tls_client.zig`) is:
//!
//!   1. Extract the distribution-point URL(s) from the leaf/CA cert with
//!      `x509.parseCrlDistributionPoint`.
//!   2. Fetch the CRL DER from a distribution-point URL (caller's transport).
//!   3. `verifyCrlSignature(crl_der, issuer_spki_der)` — SECURITY GATE. Reject
//!      any CRL whose outer signature does not verify under the issuing CA.
//!   4. `crlIsCurrent(parsed, now)` — reject stale/expired CRLs.
//!   5. `isSerialRevoked(parsed, leaf_serial_der)` — if true, reject the peer.
//!
//! ### Fail-open vs fail-closed
//!
//! CRLs are large and their distribution points are frequently unreachable, so
//! the recommended default is **soft-fail (fail-open)**: if the CRL cannot be
//! fetched, parsed, or authenticated, proceed WITHOUT a revocation verdict
//! rather than dropping the connection. A definitive `isSerialRevoked == true`
//! from an authenticated, current CRL is always fail-closed (reject). Deployments
//! that require hard-fail (e.g. a `mustRevoke`/pinned high-assurance path)
//! should treat steps 2–4 failing as a connection failure instead. Crucially,
//! a signature-verification failure in step 3 is NOT a soft "unavailable" — a
//! CRL that fails `verifyCrlSignature` must be discarded (treated as no CRL),
//! never trusted, because an unauthenticated CRL can forge or withhold
//! revocations.
const std = @import("std");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");

pub const Error = x509.Error;
pub const Time = x509.Time;

/// Error set for CRL signature verification. Extends `x509_verify.Error` (which
/// already includes every `x509.Error` DER-parse variant plus the signature
/// dispatch outcomes `BadSignature` / `UnsupportedSigAlg`) with the RFC 5280
/// §5.1.1.2 inner/outer algorithm-identifier agreement check.
pub const VerifyError = x509_verify.Error || error{AlgorithmMismatch};

/// Parsed CRL data. All slices point into caller-owned `der`.
pub const CertificateRevocationList = struct {
    der: []const u8,
    tbs_der: []const u8,
    issuer_der: []const u8,
    this_update: Time,
    next_update: ?Time,
    tbs_signature_algorithm_oid: []const u8,
    signature_algorithm_oid: []const u8,
    signature_value: []const u8,
    revoked_certificates_der: []const u8,

    /// Return an on-demand iterator over revoked serial-number INTEGER values.
    pub fn revokedSerials(self: CertificateRevocationList) RevokedSerialIterator {
        return .{ .reader = x509.DerReader.init(self.revoked_certificates_der) };
    }
};

/// Iterator over `revokedCertificates`. Each returned slice is the DER INTEGER
/// contents for `userCertificate`, including any required DER sign-padding byte.
pub const RevokedSerialIterator = struct {
    reader: x509.DerReader,

    pub fn next(self: *RevokedSerialIterator) Error!?[]const u8 {
        if (!self.reader.hasRemaining()) return null;

        const entry_tlv = try self.reader.readExpected(x509.Tag.sequence);
        var entry = try self.reader.child(entry_tlv);
        const serial_tlv = try entry.readExpected(x509.Tag.integer);
        try validatePositiveInteger(serial_tlv.value);

        _ = try parseTime(try entry.readTlv());
        if (entry.hasRemaining()) {
            const extensions_tlv = try entry.readExpected(x509.Tag.sequence);
            try validateExtensions(entry, extensions_tlv);
        }
        try entry.expectEmpty();
        return serial_tlv.value;
    }
};

/// Parse a DER RFC 5280 CertificateList.
pub fn parse(der: []const u8) Error!CertificateRevocationList {
    if (der.len == 0) return error.EmptyInput;
    if (der.len > x509.MaxDerLen) return error.Oversize;

    var parsed = CertificateRevocationList{
        .der = der,
        .tbs_der = &.{},
        .issuer_der = &.{},
        .this_update = emptyTime(),
        .next_update = null,
        .tbs_signature_algorithm_oid = &.{},
        .signature_algorithm_oid = &.{},
        .signature_value = &.{},
        .revoked_certificates_der = &.{},
    };

    var top = x509.DerReader.init(der);
    const crl_tlv = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();

    var crl = try top.child(crl_tlv);
    const tbs_tlv = try crl.readExpected(x509.Tag.sequence);
    parsed.tbs_der = tbs_tlv.raw;
    try parseTbs(&parsed, crl, tbs_tlv);

    const signature_algorithm_tlv = try crl.readExpected(x509.Tag.sequence);
    parsed.signature_algorithm_oid = try parseAlgorithmOid(crl, signature_algorithm_tlv);

    const signature_tlv = try crl.readExpected(x509.Tag.bit_string);
    parsed.signature_value = try bitStringBytes(signature_tlv);
    try crl.expectEmpty();

    if (parsed.issuer_der.len == 0 or
        parsed.tbs_signature_algorithm_oid.len == 0 or
        parsed.signature_algorithm_oid.len == 0)
    {
        return error.MissingField;
    }
    return parsed;
}

/// Return true when `serial_der` exactly matches a revoked `userCertificate`
/// serial number. `serial_der` is the DER INTEGER *contents* (value bytes,
/// including any DER sign-padding 0x00) of the leaf certificate's serial — i.e.
/// exactly `x509.Certificate.serial_der`. The comparison is a raw byte compare
/// against each revoked entry's serial, which is well-defined because both
/// sides are canonical DER INTEGER encodings of the same magnitude.
///
/// A `false` result means "not listed in THIS CRL"; it is only a revocation
/// verdict once the CRL has been authenticated (`verifyCrlSignature`) and is
/// current (`crlIsCurrent`).
pub fn isSerialRevoked(parsed: CertificateRevocationList, serial_der: []const u8) bool {
    var serials = parsed.revokedSerials();
    while (true) {
        const revoked = serials.next() catch return false;
        const candidate = revoked orelse return false;
        if (std.mem.eql(u8, candidate, serial_der)) return true;
    }
}

/// Backward-compatible alias for `isSerialRevoked`.
pub fn isRevoked(parsed: CertificateRevocationList, serial: []const u8) bool {
    return isSerialRevoked(parsed, serial);
}

/// Return true when `now_epoch_seconds` falls inside the CRL validity window
/// `thisUpdate <= now < nextUpdate` (RFC 5280 §5.1.2.4 / §5.1.2.5).
///
/// A CRL outside this window is stale and MUST NOT be trusted for revocation
/// decisions: before `thisUpdate` it may predate the issuer's clock; at or
/// after `nextUpdate` a newer CRL has superseded it and could list serials this
/// one omits. `nextUpdate` is technically OPTIONAL in RFC 5280 but SHOULD be
/// present; this function treats an ABSENT `nextUpdate` as *not current*
/// (returns false) because such a CRL carries no freshness bound. An integrator
/// that must accept `nextUpdate`-less CRLs should instead apply its own max-age
/// policy against `parsed.this_update.epoch_seconds`.
pub fn crlIsCurrent(parsed: CertificateRevocationList, now_epoch_seconds: i64) bool {
    if (now_epoch_seconds < parsed.this_update.epoch_seconds) return false;
    const next = parsed.next_update orelse return false;
    return now_epoch_seconds < next.epoch_seconds;
}

/// SECURITY GATE — verify the CertificateList's outer signature against the
/// ISSUING CA's public key.
///
/// Parses `crl_der`, enforces that the inner (`tbsCertList.signature`) and
/// outer (`signatureAlgorithm`) algorithm identifiers agree (RFC 5280
/// §5.1.1.2), then cryptographically verifies the `tbsCertList` bytes against
/// `signatureValue` under the CA public key in `issuer_spki_der` via
/// `x509_verify.verifyCertSignature` (RSA PKCS#1 v1.5 / ECDSA P-256 / Ed25519).
///
/// A CRL whose signature does not verify under the issuing CA MUST be rejected:
/// an unauthenticated CRL can withhold revocations (e.g. an attacker-supplied
/// empty CRL) or forge them. On success returns `{}`, meaning the CRL is
/// authentic for `issuer_spki_der`. Failure modes:
///   * `error.AlgorithmMismatch` — inner/outer algorithm OIDs disagree,
///   * `error.BadSignature`      — signature invalid or key/scheme mismatch,
///   * `error.UnsupportedSigAlg` — scheme outside the supported dispatch set,
///   * any `x509.Error`          — the CRL DER was malformed.
pub fn verifyCrlSignature(crl_der: []const u8, issuer_spki_der: []const u8) VerifyError!void {
    const parsed = try parse(crl_der);
    return verifyParsedCrlSignature(parsed, issuer_spki_der);
}

/// Parsed-CRL form of `verifyCrlSignature` for callers that already ran
/// `parse` (avoids re-parsing). Identical security contract.
pub fn verifyParsedCrlSignature(parsed: CertificateRevocationList, issuer_spki_der: []const u8) VerifyError!void {
    if (!std.mem.eql(u8, parsed.tbs_signature_algorithm_oid, parsed.signature_algorithm_oid))
        return error.AlgorithmMismatch;
    if (parsed.tbs_der.len == 0 or parsed.signature_value.len == 0) return error.MissingField;
    return x509_verify.verifyCertSignature(
        parsed.tbs_der,
        parsed.signature_value,
        parsed.signature_algorithm_oid,
        // No PSS params to thread: CRLs are signed with RSA-PKCS1 v1.5 / ECDSA /
        // Ed25519 in the supported set (a PSS-signed CRL fails closed).
        null,
        issuer_spki_der,
    );
}

/// Boolean convenience wrapper over `verifyParsedCrlSignature`: returns true iff
/// the CRL signature authenticates under `issuer_spki_der`. Prefer
/// `verifyCrlSignature` / `verifyParsedCrlSignature` when the failure reason
/// matters (distinguishing an unsupported scheme from a bad signature).
pub fn verifySignature(parsed: CertificateRevocationList, issuer_spki_der: []const u8) bool {
    verifyParsedCrlSignature(parsed, issuer_spki_der) catch return false;
    return true;
}

fn parseTbs(parsed: *CertificateRevocationList, parent: x509.DerReader, tbs_tlv: x509.Tlv) Error!void {
    var tbs = try parent.child(tbs_tlv);

    if (tbs.hasRemaining() and try tbs.peekTag() == x509.Tag.integer) {
        try parseVersion(try tbs.readTlv());
    }

    const signature_tlv = try tbs.readExpected(x509.Tag.sequence);
    parsed.tbs_signature_algorithm_oid = try parseAlgorithmOid(tbs, signature_tlv);

    const issuer_tlv = try tbs.readExpected(x509.Tag.sequence);
    parsed.issuer_der = issuer_tlv.raw;

    parsed.this_update = try parseTime(try tbs.readTlv());
    if (tbs.hasRemaining()) {
        const tag = try tbs.peekTag();
        if (tag == x509.Tag.utc_time or tag == x509.Tag.generalized_time) {
            parsed.next_update = try parseTime(try tbs.readTlv());
        }
    }

    var saw_revoked = false;
    var saw_extensions = false;
    while (tbs.hasRemaining()) {
        const tag = try tbs.peekTag();
        if (tag == x509.Tag.sequence and !saw_revoked and !saw_extensions) {
            const revoked_tlv = try tbs.readExpected(x509.Tag.sequence);
            parsed.revoked_certificates_der = revoked_tlv.value;
            try validateRevokedCertificates(tbs, revoked_tlv);
            saw_revoked = true;
        } else if (tag == x509.Tag.context_0_constructed and !saw_extensions) {
            try validateCrlExtensions(tbs, try tbs.readTlv());
            saw_extensions = true;
        } else {
            return error.InvalidTag;
        }
    }
}

fn parseVersion(version_tlv: x509.Tlv) Error!void {
    try validateDerInteger(version_tlv.value);
    if (version_tlv.value.len != 1 or version_tlv.value[0] > 1) return error.InvalidCertificate;
}

fn validateRevokedCertificates(parent: x509.DerReader, revoked_tlv: x509.Tlv) Error!void {
    var serials = RevokedSerialIterator{ .reader = try parent.child(revoked_tlv) };
    while (try serials.next()) |_| {}
}

fn validateCrlExtensions(parent: x509.DerReader, explicit_tlv: x509.Tlv) Error!void {
    var explicit = try parent.child(explicit_tlv);
    const extensions_tlv = try explicit.readExpected(x509.Tag.sequence);
    try explicit.expectEmpty();
    try validateExtensions(explicit, extensions_tlv);
}

fn validateExtensions(parent: x509.DerReader, extensions_tlv: x509.Tlv) Error!void {
    var extensions = try parent.child(extensions_tlv);
    while (extensions.hasRemaining()) {
        const extension_tlv = try extensions.readExpected(x509.Tag.sequence);
        var extension = try extensions.child(extension_tlv);

        const oid_tlv = try extension.readExpected(x509.Tag.oid);
        try validateOid(oid_tlv.value);

        if (extension.hasRemaining() and try extension.peekTag() == x509.Tag.boolean) {
            _ = try parseBoolean(try extension.readTlv());
        }

        _ = try extension.readExpected(x509.Tag.octet_string);
        try extension.expectEmpty();
    }
}

fn parseAlgorithmOid(parent: x509.DerReader, seq_tlv: x509.Tlv) Error![]const u8 {
    var algorithm = try parent.child(seq_tlv);
    const oid_tlv = try algorithm.readExpected(x509.Tag.oid);
    try validateOid(oid_tlv.value);
    if (algorithm.hasRemaining()) {
        _ = try algorithm.readTlv();
    }
    try algorithm.expectEmpty();
    return oid_tlv.value;
}

fn bitStringBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.InvalidBitString;
    const unused_bits = tlv.value[0];
    if (unused_bits > 7) return error.InvalidBitString;
    if (tlv.value.len == 1 and unused_bits != 0) return error.InvalidBitString;
    return tlv.value[1..];
}

fn parseBoolean(tlv: x509.Tlv) Error!bool {
    if (tlv.tag != x509.Tag.boolean or tlv.value.len != 1) return error.InvalidBoolean;
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

fn parseTime(tlv: x509.Tlv) Error!Time {
    return switch (tlv.tag) {
        x509.Tag.utc_time => parseUtcTime(tlv.value),
        x509.Tag.generalized_time => parseGeneralizedTime(tlv.value),
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

const MinimalCrlWithRevoked = [_]u8{
    0x30, 0x62,
    0x30, 0x55,
    0x02, 0x01,
    0x01, 0x30,
    0x05, 0x06,
    0x03, 0x2B,
    0x65, 0x70,
    0x30, 0x00,
    0x17, 0x0D,
    '2',  '6',
    '0',  '1',
    '0',  '1',
    '0',  '0',
    '0',  '0',
    '0',  '0',
    'Z',  0x17,
    0x0D, '2',
    '6',  '0',
    '2',  '0',
    '1',  '0',
    '0',  '0',
    '0',  '0',
    '0',  'Z',
    0x30, 0x29,
    0x30, 0x12,
    0x02, 0x01,
    0x05, 0x17,
    0x0D, '2',
    '6',  '0',
    '1',  '0',
    '2',  '0',
    '0',  '0',
    '0',  '0',
    '0',  'Z',
    0x30, 0x13,
    0x02, 0x02,
    0x00, 0x80,
    0x17, 0x0D,
    '2',  '6',
    '0',  '1',
    '0',  '3',
    '0',  '0',
    '0',  '0',
    '0',  '0',
    'Z',  0x30,
    0x05, 0x06,
    0x03, 0x2B,
    0x65, 0x70,
    0x03, 0x02,
    0x00, 0x00,
};

const MinimalCrlWithoutRevoked = [_]u8{
    0x30, 0x28,
    0x30, 0x1B,
    0x02, 0x01,
    0x01, 0x30,
    0x05, 0x06,
    0x03, 0x2B,
    0x65, 0x70,
    0x30, 0x00,
    0x17, 0x0D,
    '2',  '6',
    '0',  '1',
    '0',  '1',
    '0',  '0',
    '0',  '0',
    '0',  '0',
    'Z',  0x30,
    0x05, 0x06,
    0x03, 0x2B,
    0x65, 0x70,
    0x03, 0x02,
    0x00, 0x00,
};

test "crl parses revoked serials and checks revocation" {
    const parsed = try parse(&MinimalCrlWithRevoked);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x00 }, parsed.issuer_der);
    try std.testing.expectEqualSlices(u8, "260101000000Z", parsed.this_update.bytes);
    try std.testing.expect(parsed.next_update != null);
    try std.testing.expectEqualSlices(u8, "260201000000Z", parsed.next_update.?.bytes);

    try std.testing.expect(isRevoked(parsed, &[_]u8{0x05}));
    try std.testing.expect(isRevoked(parsed, &[_]u8{ 0x00, 0x80 }));
    try std.testing.expect(!isRevoked(parsed, &[_]u8{0x06}));

    var serials = parsed.revokedSerials();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x05}, (try serials.next()).?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x80 }, (try serials.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try serials.next());
}

test "crl accepts absent revokedCertificates" {
    const parsed = try parse(&MinimalCrlWithoutRevoked);

    try std.testing.expectEqual(@as(?Time, null), parsed.next_update);
    try std.testing.expect(!isRevoked(parsed, &[_]u8{0x05}));

    var serials = parsed.revokedSerials();
    try std.testing.expectEqual(@as(?[]const u8, null), try serials.next());
}

test "crl rejects malformed input" {
    try std.testing.expectError(error.EmptyInput, parse(&.{}));
    try std.testing.expectError(error.Truncated, parse(&[_]u8{ 0x30, 0x00 }));

    var bad_time = MinimalCrlWithRevoked;
    bad_time[16] = x509.Tag.null_value;
    try std.testing.expectError(error.InvalidTime, parse(&bad_time));

    var bad_serial = MinimalCrlWithRevoked;
    bad_serial[52] = 0x80;
    try std.testing.expectError(error.InvalidInteger, parse(&bad_serial));

    var trailing = MinimalCrlWithRevoked ++ [_]u8{0x00};
    try std.testing.expectError(error.TrailingData, parse(&trailing));
}

test "crl verifySignature accepts direct issuer Ed25519 signature" {
    const allocator = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6B)));
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);
    const der = try testSignedCrl(allocator, kp);
    defer allocator.free(der);

    const parsed = try parse(der);
    try std.testing.expect(verifySignature(parsed, spki));

    var tampered = try allocator.dupe(u8, der);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    const bad = try parse(tampered);
    try std.testing.expect(!verifySignature(bad, spki));
}

test "crl verifyCrlSignature rejects a CRL signed by a non-issuer key" {
    const allocator = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const issuer_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6B)));
    const attacker_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x2C)));

    // The CRL is signed by the ISSUER key only.
    const der = try testSignedCrl(allocator, issuer_kp);
    defer allocator.free(der);

    // Positive: authenticates under the genuine issuing-CA SPKI.
    const issuer_spki = try testEd25519Spki(allocator, issuer_kp.public_key.toBytes());
    defer allocator.free(issuer_spki);
    try verifyCrlSignature(der, issuer_spki);

    // LOAD-BEARING NEGATIVE: a CRL that is NOT signed by the presented issuer
    // must be rejected. Without this gate an attacker could serve a CRL signed
    // by any key and either forge or withhold revocations.
    const attacker_spki = try testEd25519Spki(allocator, attacker_kp.public_key.toBytes());
    defer allocator.free(attacker_spki);
    try std.testing.expectError(error.BadSignature, verifyCrlSignature(der, attacker_spki));
}

test "crl verifyCrlSignature reports typed tamper and algorithm-mismatch failures" {
    const allocator = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6B)));
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);
    const der = try testSignedCrl(allocator, kp);
    defer allocator.free(der);

    // Flipping a signature byte must surface as BadSignature, never a silent accept.
    var tampered = try allocator.dupe(u8, der);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, verifyCrlSignature(tampered, spki));

    // Inner (tbsCertList.signature) vs outer (signatureAlgorithm) OID mismatch
    // is rejected before any crypto (RFC 5280 §5.1.1.2).
    const parsed = try parse(der);
    var mismatched = parsed;
    mismatched.signature_algorithm_oid = &oid_ecdsa_sha256; // differs from the Ed25519 tbs OID
    try std.testing.expectError(error.AlgorithmMismatch, verifyParsedCrlSignature(mismatched, spki));
}

test "crl verifyCrlSignature accepts an ECDSA P-256 issuer and rejects a wrong key" {
    const allocator = std.testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const spki = try testEcSpki(allocator, kp.public_key);
    defer allocator.free(spki);
    const der = try testEcdsaSignedCrl(allocator, kp);
    defer allocator.free(der);

    // Positive: authenticates under the genuine ECDSA issuer SPKI.
    try verifyCrlSignature(der, spki);

    // Negative: an unrelated ECDSA key must not authenticate this CRL.
    const wrong = ecdsa_p256.KeyPair.generate(std.testing.io);
    const wrong_spki = try testEcSpki(allocator, wrong.public_key);
    defer allocator.free(wrong_spki);
    try std.testing.expectError(error.BadSignature, verifyCrlSignature(der, wrong_spki));
}

test "crl isSerialRevoked matches revoked serials and misses others" {
    const parsed = try parse(&MinimalCrlWithRevoked);
    try std.testing.expect(isSerialRevoked(parsed, &[_]u8{0x05}));
    try std.testing.expect(isSerialRevoked(parsed, &[_]u8{ 0x00, 0x80 }));
    try std.testing.expect(!isSerialRevoked(parsed, &[_]u8{0x06}));
    try std.testing.expect(!isSerialRevoked(parsed, &[_]u8{ 0x01, 0x02 }));

    // A CRL with no revokedCertificates revokes nothing.
    const empty = try parse(&MinimalCrlWithoutRevoked);
    try std.testing.expect(!isSerialRevoked(empty, &[_]u8{0x05}));
}

test "crl crlIsCurrent enforces the thisUpdate..nextUpdate window" {
    const parsed = try parse(&MinimalCrlWithRevoked);
    const this_u = parsed.this_update.epoch_seconds;
    const next_u = parsed.next_update.?.epoch_seconds;

    try std.testing.expect(crlIsCurrent(parsed, this_u)); // lower bound inclusive
    try std.testing.expect(crlIsCurrent(parsed, this_u + 1)); // in-window
    try std.testing.expect(crlIsCurrent(parsed, next_u - 1)); // in-window
    try std.testing.expect(!crlIsCurrent(parsed, this_u - 1)); // before thisUpdate
    try std.testing.expect(!crlIsCurrent(parsed, next_u)); // upper bound exclusive (superseded)
    try std.testing.expect(!crlIsCurrent(parsed, next_u + 100)); // expired

    // A CRL lacking nextUpdate has no freshness bound → treated as not current.
    const no_next = try parse(&MinimalCrlWithoutRevoked);
    try std.testing.expect(!crlIsCurrent(no_next, no_next.this_update.epoch_seconds + 1));
}

/// Test-only mint: a CertificateList signed by `kp` (Ed25519). Used by
/// substrate KATs and by `armor crl` CLI tests. Not a production builder.
pub fn testSignedCrl(allocator: std.mem.Allocator, kp: std.crypto.sign.Ed25519.KeyPair) ![]u8 {
    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(allocator);
    try appendDerTlv(allocator, &tbs_body, x509.Tag.integer, &[_]u8{1});
    try appendAlgId(allocator, &tbs_body, &oid_ed25519, false);
    try appendDerSeq(allocator, &tbs_body, "");
    try appendDerTlv(allocator, &tbs_body, x509.Tag.utc_time, "260101000000Z");
    try appendDerTlv(allocator, &tbs_body, x509.Tag.utc_time, "270101000000Z");

    var revoked_entry: std.ArrayList(u8) = .empty;
    defer revoked_entry.deinit(allocator);
    try appendDerTlv(allocator, &revoked_entry, x509.Tag.integer, &[_]u8{0x05});
    try appendDerTlv(allocator, &revoked_entry, x509.Tag.utc_time, "260102000000Z");
    var revoked_list: std.ArrayList(u8) = .empty;
    defer revoked_list.deinit(allocator);
    try appendDerSeq(allocator, &revoked_list, revoked_entry.items);
    try appendDerSeq(allocator, &tbs_body, revoked_list.items);

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, tbs_body.items);
    const sig = try kp.sign(tbs.items, null);
    const sig_bytes = sig.toBytes();

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, tbs.items);
    try appendAlgId(allocator, &body, &oid_ed25519, false);
    try appendDerBitString(allocator, &body, &sig_bytes);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

pub fn testEd25519Spki(allocator: std.mem.Allocator, public_key: [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendAlgId(allocator, &body, &oid_ed25519, false);
    try appendDerBitString(allocator, &body, &public_key);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

fn testEcdsaSignedCrl(allocator: std.mem.Allocator, kp: ecdsa_p256.KeyPair) ![]u8 {
    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(allocator);
    try appendDerTlv(allocator, &tbs_body, x509.Tag.integer, &[_]u8{1});
    try appendAlgId(allocator, &tbs_body, &oid_ecdsa_sha256, false);
    try appendDerSeq(allocator, &tbs_body, "");
    try appendDerTlv(allocator, &tbs_body, x509.Tag.utc_time, "260101000000Z");

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(allocator);
    try appendDerSeq(allocator, &tbs, tbs_body.items);
    const sig = try ecdsa_p256.sign(tbs.items, kp);
    var sig_der_buf: [80]u8 = undefined;
    const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, tbs.items);
    try appendAlgId(allocator, &body, &oid_ecdsa_sha256, false);
    try appendDerBitString(allocator, &body, sig_der);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

fn testEcSpki(allocator: std.mem.Allocator, public_key: ecdsa_p256.PublicKey) ![]u8 {
    const sec1 = public_key.toUncompressedSec1();
    var alg: std.ArrayList(u8) = .empty;
    defer alg.deinit(allocator);
    try appendDerTlv(allocator, &alg, x509.Tag.oid, &oid_ec_public_key);
    try appendDerTlv(allocator, &alg, x509.Tag.oid, &oid_prime256v1);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendDerSeq(allocator, &body, alg.items);
    try appendDerBitString(allocator, &body, &sec1);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
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

const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };
const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
