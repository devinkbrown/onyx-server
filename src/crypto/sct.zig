// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 6962 Certificate Transparency — Signed Certificate Timestamp (SCT)
//! parsing and signed-data reconstruction.
//!
//! This module decodes the `SignedCertificateTimestampList` carried by the
//! X.509 SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) and each contained
//! `SignedCertificateTimestamp` (SCT), and reconstructs the byte string a CT
//! log signs over (`CertificateTimestamp`) so a caller can later verify an
//! SCT's signature against a known log's public key.
//!
//! Scope and boundaries:
//!   * Input is the *unwrapped* extension value. The X.509 extension stores its
//!     value as a DER OCTET STRING whose contents are themselves a DER OCTET
//!     STRING wrapping the TLS-encoded list. The caller is responsible for
//!     peeling both OCTET STRING wrappers (the daemon's `x509.zig` DER reader
//!     does this); `parseList` receives the raw TLS bytes:
//!
//!         struct {
//!             SerializedSCT sct_list<1..2^16-1>;
//!         } SignedCertificateTimestampList;
//!
//!     i.e. a 2-byte big-endian total length followed by a sequence of
//!     `serialized_sct` items, each itself prefixed with a 2-byte length.
//!
//!   * Each `SignedCertificateTimestamp` (RFC 6962 §3.2) is:
//!
//!         struct {
//!             Version sct_version;            // u8, v1 = 0
//!             LogID id;                       // opaque[32]
//!             uint64 timestamp;               // ms since the epoch
//!             CtExtensions extensions;        // opaque<0..2^16-1>
//!             digitally-signed struct { ... } signature;
//!         } SignedCertificateTimestamp;
//!
//!     where the trailing `digitally-signed` value (RFC 5246 §4.7) is a
//!     `SignatureAndHashAlgorithm` (2 bytes: hash, signature) followed by an
//!     opaque signature `<0..2^16-1>`.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation. Callers own every
//! buffer. Parsed structs alias the input slice; every length is bounds-checked
//! and a truncated or malformed block yields a typed error rather than reading
//! past the slice.
//!
//! ## Verification pipeline and the pinned-log registry
//!
//! Beyond parsing, this module verifies an SCT signature against a
//! CALLER-PROVIDED set of pinned CT logs (`[]const CtLog`). Onyx Server bundles NO
//! log list; a deployment that wants CT enforcement supplies the logs it trusts
//! from configuration. Each `CtLog` pairs a log's DER SubjectPublicKeyInfo with
//! its RFC 6962 `log_id` (SHA-256 of that SPKI — derive it with `logIdFromSpki`
//! so an operator need only configure the key). Supported log key algorithms are
//! the RFC 6962 pair — ECDSA P-256 (`ecdsa_secp256r1_sha256`) and RSA
//! (`rsa_pkcs1_sha256`); Ed25519 also verifies but is not an RFC 6962 log type.
//!
//! `verifySctAgainstLogs` / `verifyList` return a `VerifyResult`:
//!   * `.valid`             — a pinned log matched and the signature checked out.
//!   * `.no_applicable_log` — no pinned log matched the SCT's `log_id` (empty
//!                            registry, or an SCT from a log this deployment does
//!                            not pin). NOT an authentication failure.
//!   * `.invalid`           — a pinned log matched but verification failed
//!                            (bad signature, malformed SCT/key, algorithm
//!                            mismatch, or a future-dated SCT). Always a reject.
//!
//! ### Intended tls_client integration (the integrator wires this; see report)
//!
//!   * CALL SITE: after the X.509 chain is verified. SCT verification is an
//!     ADDITIONAL assurance that the leaf was publicly logged, not a substitute
//!     for chain validation; if the chain fails, never reach this code.
//!   * SCT SOURCES: embedded X.509 extension (parsed via `x509.parseSctList` /
//!     `x509.findSctListExtension`), the TLS `signed_certificate_timestamp`
//!     extension (18), and OCSP (the stapled response's SingleResponse SCT
//!     extension, OID 1.3.6.1.4.1.11129.2.4.5, mined via
//!     `ocsp.sctListFromSingleExtensions`). All three reuse the same `parseList`
//!     + `verifySctAgainstLogs` path once their SCT bytes are in hand, and the
//!     tls_client pools them into ONE `DistinctValidLogs` union quorum.
//!   * ENTRY TYPE: SCTs EMBEDDED in the certificate sign over the PRECERTIFICATE
//!     (`precert_entry`): the leaf's TBSCertificate with the CT poison extension
//!     and the SCT-list extension removed, prefixed by the issuer key hash (use
//!     `buildPrecertEntry`). SCTs delivered over the TLS extension or OCSP sign
//!     over the FINAL certificate (`x509_entry`: the leaf DER). The caller sets
//!     `CertContext.entry_type`/`signed_entry` accordingly; assembling the
//!     precert TBS (extension stripping) is the caller's responsibility.
//!   * FAIL-OPEN vs FAIL-CLOSED (recommendation): a plain TLS client with no CT
//!     configured should treat `.no_applicable_log` as fail-OPEN (do not regress
//!     connectivity when CT is not deployed), while `.invalid` is ALWAYS a hard
//!     reject. A deployment that explicitly enables CT enforcement with a
//!     non-empty pinned set and a policy (e.g. "≥1 valid SCT", or a Chrome-style
//!     "≥2 SCTs from distinct pinned logs") should treat failure to meet that
//!     policy as fail-CLOSED. This module returns only the primitive result; the
//!     tls_client owns the open/closed policy decision.
//!
//! OUT OF SCOPE for this module (by design):
//!   * Shipping or fabricating a real CT log list / public keys — the registry
//!     is always caller-provided.
//!   * DER decoding of the X.509 extension envelope (handled by `x509.zig`).
//!   * Assembling the precert TBSCertificate (poison/SCT extension stripping)
//!     for `precert_entry` — the caller supplies `CertContext.signed_entry`.
//!   * The fail-open vs fail-closed policy decision (the tls_client owns it).
const std = @import("std");
const x509 = @import("x509.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");
const hash = @import("hash.zig");

const Ed25519 = std.crypto.sign.Ed25519;

/// Width of a length prefix used throughout the SCT wire format.
const len_prefix_len: usize = 2;

/// Width of the fixed `LogID` field (RFC 6962 §3.2: SHA-256 of the log key).
pub const log_id_len: usize = 32;

/// Width of the `timestamp` field in bytes (a big-endian `uint64`).
const timestamp_len: usize = 8;

/// Width of a `SignatureAndHashAlgorithm` (RFC 5246 §7.4.1.4.1).
const sig_alg_len: usize = 2;

/// Maximum number of SCTs `parseList` will surface from a single list.
///
/// A bounded fixed array keeps the hot path allocation-free. CT lists are
/// small in practice (a handful of logs); lists longer than this are rejected
/// with `error.TooManySct` so the cap never silently truncates.
pub const max_scts: usize = 8;

/// SCT structure version (RFC 6962 §3.2). Only `v1` is defined.
pub const Version = enum(u8) {
    v1 = 0,
    _,
};

/// `SignatureType` discriminant for the signed `CertificateTimestamp`
/// (RFC 6962 §3.2). `certificate_timestamp` is the only value used when a log
/// signs an SCT; `tree_hash` appears in Signed Tree Heads, outside this module.
pub const SignatureType = enum(u8) {
    certificate_timestamp = 0,
    tree_hash = 1,
};

/// `LogEntryType` (RFC 6962 §3.1): the kind of entry the log certified.
pub const LogEntryType = enum(u16) {
    /// A full X.509 certificate. `signed_entry` is its DER, length-prefixed.
    x509_entry = 0,
    /// A precertificate. `signed_entry` is the issuer key hash (32 bytes)
    /// followed by the length-prefixed TBSCertificate.
    precert_entry = 1,
};

/// Errors produced while parsing an SCT list or building signed data.
pub const Error = error{
    /// A length prefix or fixed field ran past the end of the input.
    Truncated,
    /// A declared length did not match the bytes actually present, or the
    /// outer list length disagreed with its trailing bytes.
    LengthMismatch,
    /// An individual `serialized_sct` declared zero length (RFC 6962 requires
    /// `<1..2^16-1>`), or the list framing was otherwise inconsistent.
    InvalidLength,
    /// More SCTs were present than `max_scts` allows.
    TooManySct,
    /// A build target buffer ran out of room. Matches `std`'s spelling.
    NoSpaceLeft,
};

/// A single parsed `SignedCertificateTimestamp`. All slice fields alias the
/// input passed to `parseList`; copy them out if the input is transient.
pub const Sct = struct {
    /// SCT structure version (`v1` in practice).
    version: Version,
    /// SHA-256 hash of the issuing log's public key (DER SubjectPublicKeyInfo).
    log_id: [log_id_len]u8,
    /// Milliseconds since the Unix epoch at which the log issued the SCT.
    timestamp: u64,
    /// `CtExtensions` opaque blob (almost always empty); aliases the input.
    extensions: []const u8,
    /// `SignatureAndHashAlgorithm.hash` (RFC 5246 §7.4.1.4.1 HashAlgorithm).
    sig_hash_alg: u8,
    /// `SignatureAndHashAlgorithm.signature` (RFC 5246 SignatureAlgorithm).
    sig_signature_alg: u8,
    /// Raw signature bytes (the opaque body of the `digitally-signed` struct);
    /// aliases the input.
    signature: []const u8,

    /// Convenience accessor for the combined 16-bit
    /// `SignatureAndHashAlgorithm` code (hash in the high byte). This matches
    /// the TLS 1.3 `SignatureScheme` numbering only for schemes whose legacy
    /// hash/sig pair coincides with the modern code; treat it as informational.
    pub fn sigAlgCode(self: *const Sct) u16 {
        return (@as(u16, self.sig_hash_alg) << 8) | @as(u16, self.sig_signature_alg);
    }
};

/// A bounded, parsed `SignedCertificateTimestampList`. Holds up to `max_scts`
/// SCTs whose slices alias the input passed to `parseList`.
pub const SctList = struct {
    items: [max_scts]Sct = undefined,
    len: usize = 0,

    /// The populated prefix of `items` as a slice.
    pub fn slice(self: *const SctList) []const Sct {
        return self.items[0..self.len];
    }
};

/// Read a big-endian `u16` from the first two bytes of `b` (caller guarantees
/// `b.len >= 2`).
fn readU16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}

/// Write a big-endian `u16` into the first two bytes of `out` (caller
/// guarantees `out.len >= 2`).
fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

/// A length-prefixed-vector reader that refuses to read past `buf`. Used to
/// walk the SCT wire format field by field without aliasing past the input.
const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    /// Take exactly `n` bytes, advancing the cursor. Fails closed if short.
    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.Truncated;
        const out = self.buf[self.pos..][0..n];
        self.pos += n;
        return out;
    }

    /// Read a single big-endian `u8`.
    fn readU8(self: *Reader) Error!u8 {
        const b = try self.take(1);
        return b[0];
    }

    /// Read a big-endian `u16`.
    fn readU16(self: *Reader) Error!u16 {
        const b = try self.take(len_prefix_len);
        return std.mem.readInt(u16, b[0..2], .big);
    }

    /// Read a big-endian `u64`.
    fn readU64(self: *Reader) Error!u64 {
        const b = try self.take(timestamp_len);
        return std.mem.readInt(u64, b[0..8], .big);
    }

    /// Read a `u16`-length-prefixed opaque vector and return its body (aliasing
    /// the input). The declared length is validated against the remaining bytes.
    fn readVarU16(self: *Reader) Error![]const u8 {
        const n = try self.readU16();
        return self.take(n);
    }
};

/// Parse a `SignedCertificateTimestampList` into a bounded `SctList`.
///
/// `bytes` must be the TLS-encoded list (both X.509 OCTET STRING wrappers
/// already stripped): a 2-byte total length followed by that many bytes of
/// `serialized_sct` items, each 2-byte-length-prefixed. The total length must
/// exactly account for the trailing bytes; trailing slack is rejected.
///
/// On success the returned `SctList` aliases `bytes`. Fails closed with a typed
/// error on any framing inconsistency, and with `error.TooManySct` if the list
/// holds more than `max_scts` SCTs.
pub fn parseList(bytes: []const u8) Error!SctList {
    if (bytes.len < len_prefix_len) return error.Truncated;
    const declared = readU16(bytes[0..len_prefix_len]);
    const body = bytes[len_prefix_len..];
    if (body.len != declared) return error.LengthMismatch;

    var list: SctList = .{};
    var r = Reader.init(body);
    while (r.remaining() != 0) {
        const item = try r.readVarU16();
        // RFC 6962 declares serialized_sct as <1..2^16-1>; a zero-length item
        // is malformed framing.
        if (item.len == 0) return error.InvalidLength;
        if (list.len >= max_scts) return error.TooManySct;
        list.items[list.len] = try parseSct(item);
        list.len += 1;
    }
    return list;
}

/// Parse a single `serialized_sct` body (one `SignedCertificateTimestamp`).
///
/// `bytes` is exactly the SCT body (the per-item 2-byte length prefix already
/// stripped by `parseList`). Every field is bounds-checked; any trailing byte
/// after the signature is a framing error.
pub fn parseSct(bytes: []const u8) Error!Sct {
    var r = Reader.init(bytes);

    const version: Version = @fromBackingInt(@intCast(try r.readU8()));

    const id_bytes = try r.take(log_id_len);
    var log_id: [log_id_len]u8 = undefined;
    @memcpy(&log_id, id_bytes);

    const timestamp = try r.readU64();
    const extensions = try r.readVarU16();

    const sig_alg = try r.take(sig_alg_len);
    const sig_hash_alg = sig_alg[0];
    const sig_signature_alg = sig_alg[1];
    const signature = try r.readVarU16();

    // A well-formed SCT consumes its body exactly; surplus bytes are malformed.
    if (r.remaining() != 0) return error.LengthMismatch;

    return .{
        .version = version,
        .log_id = log_id,
        .timestamp = timestamp,
        .extensions = extensions,
        .sig_hash_alg = sig_hash_alg,
        .sig_signature_alg = sig_signature_alg,
        .signature = signature,
    };
}

/// Inputs to `buildSignedData`: the parsed SCT plus the certified entry.
///
/// The caller supplies `signed_entry` already in the form the log signs:
///   * For `x509_entry`: the leaf certificate's DER (`ASN.1Cert`), which is
///     emitted length-prefixed with a 24-bit length.
///   * For `precert_entry`: the 32-byte issuer-key hash concatenated with the
///     TBSCertificate, emitted as `PreCert { opaque[32]; opaque<1..2^24-1> }`.
///     Construct this blob with `buildPrecertEntry` before calling.
///
/// `extensions` mirrors the SCT's `CtExtensions` (usually empty); pass
/// `sct.extensions`.
pub const SignedDataInput = struct {
    version: Version = .v1,
    timestamp: u64,
    entry_type: LogEntryType,
    /// The `signed_entry` bytes exactly as the log hashes them (see above).
    signed_entry: []const u8,
    /// `CtExtensions` opaque body (typically empty).
    extensions: []const u8 = &.{},
};

/// Width of the 24-bit length prefix used by the precert TBSCertificate vector.
const u24_prefix_len: usize = 3;

/// Reconstruct the byte string a CT log signs for a certificate/precert entry:
/// the `CertificateTimestamp` structure of RFC 6962 §3.2.
///
///     digitally-signed struct {
///         Version sct_version;            // u8
///         SignatureType signature_type;   // u8 = certificate_timestamp(0)
///         uint64 timestamp;
///         LogEntryType entry_type;        // u16
///         select(entry_type) {
///             case x509_entry:   ASN.1Cert;   // opaque<1..2^24-1>
///             case precert_entry: PreCert;     // already in signed_entry
///         } signed_entry;
///         CtExtensions extensions;        // opaque<0..2^16-1>
///     } CertificateTimestamp;
///
/// `signed_entry` is written verbatim for `precert_entry` (the caller framed
/// the `PreCert`), and wrapped in a 24-bit length prefix for `x509_entry`
/// (the `ASN.1Cert` opaque<1..2^24-1>).
///
/// Writes into `out` and returns the written prefix; fails with
/// `error.NoSpaceLeft` if `out` is too small. The resulting bytes are exactly
/// what `ecdsa_p256`/`sign` would later verify against a log's public key.
pub fn buildSignedData(out: []u8, input: SignedDataInput) Error![]const u8 {
    const entry_overhead: usize = switch (input.entry_type) {
        .x509_entry => u24_prefix_len,
        .precert_entry => 0,
    };
    if (input.extensions.len > 0xffff) return error.InvalidLength;
    if (input.signed_entry.len > 0xff_ffff) return error.InvalidLength;

    const total =
        1 + // version
        1 + // signature_type
        timestamp_len +
        sig_alg_len + // entry_type (u16)
        entry_overhead +
        input.signed_entry.len +
        len_prefix_len + // extensions length
        input.extensions.len;
    if (out.len < total) return error.NoSpaceLeft;

    var off: usize = 0;

    out[off] = @backingInt(input.version);
    off += 1;
    out[off] = @backingInt(SignatureType.certificate_timestamp);
    off += 1;

    std.mem.writeInt(u64, out[off..][0..timestamp_len], input.timestamp, .big);
    off += timestamp_len;

    writeU16(out[off..], @backingInt(input.entry_type));
    off += sig_alg_len;

    switch (input.entry_type) {
        .x509_entry => {
            // ASN.1Cert is opaque<1..2^24-1>: a 24-bit length then the DER.
            writeU24(out[off..], @intCast(input.signed_entry.len));
            off += u24_prefix_len;
        },
        .precert_entry => {}, // signed_entry already carries its own framing.
    }
    @memcpy(out[off..][0..input.signed_entry.len], input.signed_entry);
    off += input.signed_entry.len;

    writeU16(out[off..], @intCast(input.extensions.len));
    off += len_prefix_len;
    @memcpy(out[off..][0..input.extensions.len], input.extensions);
    off += input.extensions.len;

    return out[0..off];
}

/// Frame a `PreCert { opaque issuer_key_hash[32]; TBSCertificate tbs; }` blob
/// (RFC 6962 §3.2) into `out` so it can be passed as `signed_entry` for a
/// `precert_entry`. `tbs` is the TBSCertificate DER, emitted as opaque<1..2^24-1>.
pub fn buildPrecertEntry(out: []u8, issuer_key_hash: [log_id_len]u8, tbs: []const u8) Error![]const u8 {
    if (tbs.len > 0xff_ffff) return error.InvalidLength;
    const total = log_id_len + u24_prefix_len + tbs.len;
    if (out.len < total) return error.NoSpaceLeft;

    @memcpy(out[0..log_id_len], &issuer_key_hash);
    writeU24(out[log_id_len..], @intCast(tbs.len));
    @memcpy(out[log_id_len + u24_prefix_len ..][0..tbs.len], tbs);
    return out[0..total];
}

// TLS 1.2 SignatureAndHashAlgorithm codes (RFC 5246 §7.4.1.4.1) as they appear
// in an SCT's trailing `digitally-signed` struct. RFC 6962 §2.1.4 restricts CT
// logs to ECDSA-P256 (`ecdsa_secp256r1_sha256`, hash sha256 + sig ecdsa) or RSA
// (`rsa_pkcs1_sha256`, hash sha256 + sig rsa). Ed25519 (intrinsic hash + sig
// ed25519, RFC 8422) is not an RFC 6962 log type but is accepted if a caller
// pins such a key.
const hash_sha256: u8 = 4; // HashAlgorithm.sha256
const hash_intrinsic: u8 = 8; // Ed25519 signs the message directly
const sig_rsa: u8 = 1; // SignatureAlgorithm.rsa
const sig_ecdsa: u8 = 3; // SignatureAlgorithm.ecdsa
const sig_ed25519: u8 = 7; // ed25519 (RFC 8422)

/// Verify an SCT's digitally-signed value against a CT log public key.
///
/// `log_public_key_spki_der` is the log's DER SubjectPublicKeyInfo (the same
/// bytes hashed to form its `log_id`). `signed_data` must be the exact
/// `CertificateTimestamp` byte string returned by `buildSignedData` for the
/// certificate or precertificate entry being checked. This function
/// authenticates the SCT signature only; selecting the correct CT log key from
/// `sct.log_id` and the pinned CT log set is the caller's responsibility (see
/// `verifySctAgainstLogs`).
///
/// The SPKI is parsed with the shared `x509.extractPublicKey`, so the log key
/// may be ECDSA P-256, RSA, or Ed25519. The SCT's advertised
/// `SignatureAndHashAlgorithm` must match the key family (SHA-256 throughout);
/// any mismatch, malformed key, malformed signature, or verification failure
/// returns `false` (fail closed).
pub fn verifySct(sct: Sct, log_public_key_spki_der: []const u8, signed_data: []const u8) bool {
    const key = x509.extractPublicKey(log_public_key_spki_der) catch return false;
    switch (key) {
        .ecdsa_p256 => |sec1| {
            if (sct.sig_hash_alg != hash_sha256 or sct.sig_signature_alg != sig_ecdsa) return false;
            const pk = ecdsa_p256.parsePublicKeySec1(sec1) catch return false;
            const decoded = ecdsa_p256.signatureFromDer(sct.signature) catch return false;
            return ecdsa_p256.verify(decoded, signed_data, pk);
        },
        .rsa => |rsa_key| {
            if (sct.sig_hash_alg != hash_sha256 or sct.sig_signature_alg != sig_rsa) return false;
            const digest = hash.Sha256.hash(signed_data);
            const pk = rsa_verify.PublicKey{ .n = rsa_key.modulus, .e = rsa_key.exponent };
            return rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sct.signature);
        },
        .ed25519 => |raw| {
            if (sct.sig_hash_alg != hash_intrinsic or sct.sig_signature_alg != sig_ed25519) return false;
            if (sct.signature.len != Ed25519.Signature.encoded_length) return false;
            if (raw.len != Ed25519.PublicKey.encoded_length) return false;
            const pk = Ed25519.PublicKey.fromBytes(raw[0..Ed25519.PublicKey.encoded_length].*) catch return false;
            const decoded = Ed25519.Signature.fromBytes(sct.signature[0..Ed25519.Signature.encoded_length].*);
            decoded.verify(signed_data, pk) catch return false;
            return true;
        },
    }
}

// ---------------------------------------------------------------------------
// Pinned-log registry and verification entrypoints.
//
// Onyx Server ships NO built-in CT log list. A deployment supplies its own pinned
// logs (from config) as a `[]const CtLog`. An empty set — or an SCT from an
// unpinned log — yields `.no_applicable_log`; the caller's fail-open/closed
// policy decides what that means. This module never fabricates a trusted log
// and never makes the open/closed decision.
// ---------------------------------------------------------------------------

/// One pinned Certificate Transparency log.
pub const CtLog = struct {
    /// RFC 6962 §3.2 LogID: SHA-256 over the log key's DER SubjectPublicKeyInfo.
    /// Derive it from `key_spki_der` with `logIdFromSpki`.
    log_id: [log_id_len]u8,
    /// The log's public key as a DER SubjectPublicKeyInfo (the full SEQUENCE),
    /// aliased not copied. ECDSA P-256 and RSA are the RFC 6962 log key types.
    key_spki_der: []const u8,
};

/// Compute the RFC 6962 LogID (SHA-256 of the DER SubjectPublicKeyInfo) for a
/// log key. A caller building a `CtLog` from a configured SPKI uses this so it
/// need not also hardcode the id; the result equals the `log_id` carried by
/// SCTs the log issues.
pub fn logIdFromSpki(spki_der: []const u8) [log_id_len]u8 {
    return hash.Sha256.hash(spki_der);
}

/// Outcome of verifying an SCT against a pinned log set. See the module docs for
/// the fail-open vs fail-closed recommendation the tls_client applies to these.
pub const VerifyResult = enum {
    /// A pinned log matched the SCT's `log_id`, its signature verified over the
    /// reconstructed `CertificateTimestamp`, and (when a clock was supplied) the
    /// timestamp was not in the future. The SCT is authentic.
    valid,
    /// No pinned log matched the SCT's `log_id` — the set was empty, or the SCT
    /// came from a log this deployment does not pin. NOT an authentication
    /// failure; the caller's policy decides whether to accept.
    no_applicable_log,
    /// A pinned log matched but verification failed: bad signature, malformed
    /// SCT/key, an unsupported/mismatched algorithm, an oversized certified
    /// entry, or a future-dated SCT. Always a hard reject.
    invalid,
};

/// What the log signed over: the certified entry (RFC 6962 §3.2).
pub const CertContext = struct {
    entry_type: LogEntryType,
    /// The `signed_entry` bytes exactly as the log hashes them:
    ///   * `x509_entry`   — the leaf certificate DER (`ASN.1Cert`). Use for SCTs
    ///     delivered over the TLS `signed_certificate_timestamp` extension or
    ///     OCSP, which sign over the FINAL certificate.
    ///   * `precert_entry` — the pre-framed `PreCert` blob
    ///     (`issuer_key_hash[32] || TBSCertificate<1..2^24-1>`) from
    ///     `buildPrecertEntry`. Use for SCTs EMBEDDED in the X.509 SCT extension,
    ///     which sign over the PRECERTIFICATE (its TBS with the SCT-list and CT
    ///     poison extensions removed). Assembling that TBS is the caller's job.
    signed_entry: []const u8,
};

/// Clock-skew tolerance for the future-timestamp check: an SCT timestamp up to
/// this many milliseconds ahead of the supplied `now_ms` is still accepted.
/// RFC 6962 §5.2 says a log must not issue future-dated SCTs; this margin only
/// absorbs modest local clock skew.
pub const future_skew_ms: u64 = 5 * 60 * 1000;

/// Upper bound on the certified-entry (`signed_entry`) size that `verifyOneSct`,
/// `verifySctAgainstLogs`, and `verifyList` will frame in their internal
/// stack buffer. Comfortably covers real leaf certs and precert TBS; a larger
/// entry yields `.invalid` (fail closed). A deployment with atypically large
/// certificates can build the signed data itself and call
/// `verifySignedDataAgainstLogs`, which imposes no such bound.
pub const max_internal_signed_entry: usize = 16 * 1024;

/// Internal signed-data buffer size: the `CertificateTimestamp` fixed header
/// (14 bytes) plus the x509 entry's 24-bit length prefix plus the certified
/// entry. `CtExtensions` are effectively always empty for CT SCTs; a non-empty
/// extension that would overflow this yields `error.NoSpaceLeft` → `.invalid`.
const internal_signed_data_buf_len: usize = 14 + u24_prefix_len + max_internal_signed_entry;

/// Upper bound on a reconstructed precertificate TBSCertificate that still fits,
/// once framed as a `PreCert` (`issuer_key_hash[32] || TBS<1..2^24-1>`), within
/// `max_internal_signed_entry` — and hence within the internal signed-data
/// buffer of `verifyOneSct`/`verifyList`. A caller reconstructing a precert TBS
/// (see `x509.buildPrecertTbs`) sizes its output buffer to this so a legitimate
/// certificate never spuriously overflows the framing; a TBS larger than this is
/// rejected at reconstruction time (fail-open) rather than mis-tallied `.invalid`.
pub const max_precert_tbs_len: usize = max_internal_signed_entry - log_id_len - u24_prefix_len;

fn findLog(target: [log_id_len]u8, logs: []const CtLog) ?CtLog {
    for (logs) |log| {
        if (std.mem.eql(u8, &log.log_id, &target)) return log;
    }
    return null;
}

/// Frame the `CertificateTimestamp` a log signs for `sct` over `ctx` into `buf`.
fn frameSignedData(buf: []u8, sct: Sct, ctx: CertContext) Error![]const u8 {
    return buildSignedData(buf, .{
        .version = sct.version,
        .timestamp = sct.timestamp,
        .entry_type = ctx.entry_type,
        .signed_entry = ctx.signed_entry,
        .extensions = sct.extensions,
    });
}

/// Match `sct` to a pinned log, enforce the future-timestamp rule, then verify
/// the SCT signature over an already-reconstructed `signed_data`.
///
/// `signed_data` must be the exact `CertificateTimestamp` for `sct`'s entry (as
/// `buildSignedData` produces). When `now_ms` is non-null, an SCT dated more
/// than `future_skew_ms` ahead of it is rejected as `.invalid`; pass null to
/// skip the temporal check (e.g. when no trusted clock is available). This is
/// the buffer-free core: callers holding large certificates build `signed_data`
/// themselves and avoid the internal-buffer bound of `verifyOneSct`.
pub fn verifySignedDataAgainstLogs(
    sct: Sct,
    signed_data: []const u8,
    logs: []const CtLog,
    now_ms: ?u64,
) VerifyResult {
    const log = findLog(sct.log_id, logs) orelse return .no_applicable_log;
    if (now_ms) |now| {
        if (sct.timestamp > now and sct.timestamp - now > future_skew_ms) return .invalid;
    }
    return if (verifySct(sct, log.key_spki_der, signed_data)) .valid else .invalid;
}

/// Verify one parsed SCT against a pinned CT log set.
///
/// Reconstructs the signed `CertificateTimestamp` for `ctx` into an internal
/// buffer (bounded by `max_internal_signed_entry`; an oversized entry fails
/// closed to `.invalid`) and delegates to `verifySignedDataAgainstLogs`.
pub fn verifyOneSct(sct: Sct, ctx: CertContext, logs: []const CtLog, now_ms: ?u64) VerifyResult {
    var buf: [internal_signed_data_buf_len]u8 = undefined;
    const signed = frameSignedData(&buf, sct, ctx) catch return .invalid;
    return verifySignedDataAgainstLogs(sct, signed, logs, now_ms);
}

/// Verify one serialized SCT (a single `serialized_sct` body — the per-item
/// length prefix already stripped, as `x509.parseSctList` + list framing yield)
/// against a pinned CT log set.
///
/// Parses the SCT (fail-closed to `.invalid` on malformed bytes) and delegates
/// to `verifyOneSct`. This is the entrypoint the tls_client calls once per SCT
/// it extracts from the certificate, the TLS extension, or an OCSP response.
pub fn verifySctAgainstLogs(
    sct_der: []const u8,
    ctx: CertContext,
    logs: []const CtLog,
    now_ms: ?u64,
) VerifyResult {
    const sct = parseSct(sct_der) catch return .invalid;
    return verifyOneSct(sct, ctx, logs, now_ms);
}

/// Tally of `verifyList` outcomes across a `SignedCertificateTimestampList`.
/// The tls_client applies its policy to these counts (e.g. require `valid >= 1`,
/// or a distinct-log quorum) and decides fail-open vs fail-closed.
pub const ListSummary = struct {
    valid: usize = 0,
    no_applicable_log: usize = 0,
    invalid: usize = 0,
    /// Number of DISTINCT pinned logs (counted by `log_id`) that contributed at
    /// least one `.valid` SCT. This is the RFC 6962 §5.1-style presence-quorum
    /// count: two valid SCTs from the SAME log count once, so a "≥ N distinct
    /// logs" policy cannot be satisfied by N copies from a single log. An
    /// `.invalid` or `.no_applicable_log` SCT never contributes. Always
    /// `<= valid` (and `<= max_scts`).
    distinct_valid_logs: usize = 0,
};

/// Upper bound on the number of DISTINCT pinned logs a `DistinctValidLogs`
/// accumulator can hold. A CT policy pools SCTs delivered by all three RFC 6962 §3
/// methods (the embedded X.509 extension, the TLS `signed_certificate_timestamp`
/// extension, AND the OCSP `SingleResponse` SCT extension), and each list surfaces
/// at most `max_scts` SCTs, so the union across the three sources is bounded by
/// `3 * max_scts`.
pub const max_distinct_logs: usize = 3 * max_scts;

/// A bounded accumulator of DISTINCT CT `log_id`s that have contributed at least
/// one `.valid` SCT, ACROSS one or more `verifyListAccumulating` calls.
///
/// A single `ListSummary.distinct_valid_logs` counts distinct logs within ONE
/// list. When a caller pools SCTs from multiple delivery methods (embedded cert
/// extension + the TLS extension + the OCSP SingleResponse extension) it must
/// count the distinct-log presence quorum over the UNION — a log that validly
/// appears in more than one source counts once
/// (RFC 6962 §5.1-style). This accumulator carries that union across calls;
/// `count()` is the quorum a fail-closed policy compares against `require_sct`.
pub const DistinctValidLogs = struct {
    ids: [max_distinct_logs][log_id_len]u8 = undefined,
    len: usize = 0,

    /// Number of distinct valid logs recorded so far (`<= max_distinct_logs`).
    pub fn count(self: *const DistinctValidLogs) usize {
        return self.len;
    }

    /// Record `id` if not already present. Silently ignores an `id` past
    /// `max_distinct_logs` — the union of two `max_scts`-bounded lists never
    /// exceeds that bound, so this saturates only on impossible input and, if it
    /// ever did, would UNDER-count (a fail-CLOSED direction for a quorum check).
    fn add(self: *DistinctValidLogs, id: [log_id_len]u8) void {
        for (self.ids[0..self.len]) |seen| {
            if (std.mem.eql(u8, &seen, &id)) return;
        }
        if (self.len < self.ids.len) {
            self.ids[self.len] = id;
            self.len += 1;
        }
    }
};

/// Parse a `SignedCertificateTimestampList` and verify every SCT it carries
/// against the pinned log set, returning a `ListSummary`. Propagates a parse
/// error (malformed list framing / too many SCTs) so the caller treats a
/// structurally broken list as a hard failure. Per-SCT verification failures are
/// tallied, not raised, so one bad SCT does not mask the others.
pub fn verifyList(
    list_bytes: []const u8,
    ctx: CertContext,
    logs: []const CtLog,
    now_ms: ?u64,
) Error!ListSummary {
    return verifyListImpl(list_bytes, ctx, logs, now_ms, null);
}

/// Like `verifyList`, but ALSO records every DISTINCT pinned log that
/// contributed a `.valid` SCT into `acc`. A caller verifying SCTs from more than
/// one delivery method calls this once per source with the SAME `acc`, then
/// checks `acc.count()` against its distinct-log presence quorum — so a log valid
/// in two sources counts once (RFC 6962 §5.1). The returned `ListSummary` still
/// reports this call's own tallies (e.g. `.invalid` for tamper detection).
pub fn verifyListAccumulating(
    list_bytes: []const u8,
    ctx: CertContext,
    logs: []const CtLog,
    now_ms: ?u64,
    acc: *DistinctValidLogs,
) Error!ListSummary {
    return verifyListImpl(list_bytes, ctx, logs, now_ms, acc);
}

fn verifyListImpl(
    list_bytes: []const u8,
    ctx: CertContext,
    logs: []const CtLog,
    now_ms: ?u64,
    acc: ?*DistinctValidLogs,
) Error!ListSummary {
    const list = try parseList(list_bytes);
    var buf: [internal_signed_data_buf_len]u8 = undefined;
    var summary: ListSummary = .{};
    // Log ids of the DISTINCT pinned logs already credited with a `.valid` SCT,
    // so a second valid SCT from the same log does not double-count toward the
    // presence quorum. Bounded by `max_scts` (`parseList` never yields more).
    var seen_valid_logs: [max_scts][log_id_len]u8 = undefined;
    var seen_len: usize = 0;
    for (list.slice()) |sct| {
        const signed = frameSignedData(&buf, sct, ctx) catch {
            summary.invalid += 1;
            continue;
        };
        switch (verifySignedDataAgainstLogs(sct, signed, logs, now_ms)) {
            .valid => {
                summary.valid += 1;
                // Credit this log toward the distinct-log quorum only the first
                // time a valid SCT from it is seen. `sct.log_id` matched a pinned
                // log (else `.valid` would be impossible), so it identifies a
                // pinned log unambiguously.
                var already_seen = false;
                for (seen_valid_logs[0..seen_len]) |id| {
                    if (std.mem.eql(u8, &id, &sct.log_id)) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen) {
                    seen_valid_logs[seen_len] = sct.log_id;
                    seen_len += 1;
                    summary.distinct_valid_logs += 1;
                }
                // The cross-source accumulator dedups globally (a log valid here
                // and in another source counts once), so feed it every `.valid`.
                if (acc) |a| a.add(sct.log_id);
            },
            .no_applicable_log => summary.no_applicable_log += 1,
            .invalid => summary.invalid += 1,
        }
    }
    return summary;
}

/// Write a big-endian 24-bit length into the first three bytes of `out`
/// (caller guarantees `out.len >= 3` and `value <= 0xff_ffff`).
fn writeU24(out: []u8, value: u24) void {
    out[0] = @intCast((value >> 16) & 0xff);
    out[1] = @intCast((value >> 8) & 0xff);
    out[2] = @intCast(value & 0xff);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// id-Ed25519 (1.3.101.112), for hand-building an Ed25519 log SPKI in tests.
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };
/// id-ecPublicKey (1.2.840.10045.2.1) and prime256v1 (1.2.840.10045.3.1.7),
/// for hand-building an ECDSA-P256 log SPKI in tests.
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/// Hand-build a `serialized_sct` body for one v1 SCT.
fn buildOneSctBody(
    out: []u8,
    log_id: [log_id_len]u8,
    timestamp: u64,
    extensions: []const u8,
    signature: []const u8,
) []const u8 {
    var off: usize = 0;
    out[off] = @backingInt(Version.v1);
    off += 1;
    @memcpy(out[off..][0..log_id_len], &log_id);
    off += log_id_len;
    std.mem.writeInt(u64, out[off..][0..8], timestamp, .big);
    off += 8;
    writeU16(out[off..], @intCast(extensions.len));
    off += 2;
    @memcpy(out[off..][0..extensions.len], extensions);
    off += extensions.len;
    out[off] = hash_sha256;
    off += 1;
    out[off] = sig_ecdsa;
    off += 1;
    writeU16(out[off..], @intCast(signature.len));
    off += 2;
    @memcpy(out[off..][0..signature.len], signature);
    off += signature.len;
    return out[0..off];
}

/// Wrap one or more `serialized_sct` bodies into a full
/// `SignedCertificateTimestampList` (outer u16 length + per-item u16 lengths).
fn buildList(out: []u8, bodies: []const []const u8) []const u8 {
    var inner_off: usize = len_prefix_len;
    for (bodies) |b| {
        writeU16(out[inner_off..], @intCast(b.len));
        inner_off += len_prefix_len;
        @memcpy(out[inner_off..][0..b.len], b);
        inner_off += b.len;
    }
    writeU16(out[0..], @intCast(inner_off - len_prefix_len));
    return out[0..inner_off];
}

test "parseList decodes a single v1 SCT with every field intact" {
    // Arrange
    var log_id: [log_id_len]u8 = undefined;
    for (&log_id, 0..) |*b, i| b.* = @intCast(i + 1);
    const timestamp: u64 = 0x0000_0193_4d2e_a1f0;
    const signature = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x07 };

    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, timestamp, &.{}, &signature);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{body});

    // Act
    const parsed = try parseList(list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 1), parsed.len);
    const sct = parsed.slice()[0];
    try testing.expectEqual(Version.v1, sct.version);
    try testing.expectEqualSlices(u8, &log_id, &sct.log_id);
    try testing.expectEqual(timestamp, sct.timestamp);
    try testing.expectEqual(@as(usize, 0), sct.extensions.len);
    try testing.expectEqual(hash_sha256, sct.sig_hash_alg);
    try testing.expectEqual(sig_ecdsa, sct.sig_signature_alg);
    try testing.expectEqual(@as(u16, 0x0403), sct.sigAlgCode());
    try testing.expectEqualSlices(u8, &signature, sct.signature);
}

test "parseList preserves non-empty CtExtensions" {
    // Arrange
    const log_id = @as([log_id_len]u8, @splat(0xAB));
    const extensions = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const signature = [_]u8{ 0x01, 0x02 };

    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, 42, &extensions, &signature);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{body});

    // Act
    const parsed = try parseList(list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqualSlices(u8, &extensions, parsed.slice()[0].extensions);
}

test "parseList decodes two SCTs in wire order" {
    // Arrange
    const log_id_a = @as([log_id_len]u8, @splat(0x11));
    const log_id_b = @as([log_id_len]u8, @splat(0x22));
    const sig_a = [_]u8{0xaa};
    const sig_b = [_]u8{ 0xbb, 0xbb };

    var ba: [128]u8 = undefined;
    var bb: [128]u8 = undefined;
    const body_a = buildOneSctBody(&ba, log_id_a, 1, &.{}, &sig_a);
    const body_b = buildOneSctBody(&bb, log_id_b, 2, &.{}, &sig_b);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{ body_a, body_b });

    // Act
    const parsed = try parseList(list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqualSlices(u8, &log_id_a, &parsed.slice()[0].log_id);
    try testing.expectEqual(@as(u64, 1), parsed.slice()[0].timestamp);
    try testing.expectEqualSlices(u8, &log_id_b, &parsed.slice()[1].log_id);
    try testing.expectEqualSlices(u8, &sig_b, parsed.slice()[1].signature);
}

test "parseList accepts an empty list" {
    // Arrange: outer length 0, no items.
    const list_bytes = [_]u8{ 0x00, 0x00 };

    // Act
    const parsed = try parseList(&list_bytes);

    // Assert
    try testing.expectEqual(@as(usize, 0), parsed.len);
    try testing.expectEqual(@as(usize, 0), parsed.slice().len);
}

test "parseList rejects input with no full outer length prefix" {
    // Arrange
    const list_bytes = [_]u8{0x00};

    // Act / Assert
    try testing.expectError(error.Truncated, parseList(&list_bytes));
}

test "parseList rejects an outer length that exceeds the body" {
    // Arrange: declares 8 body bytes but carries only 4.
    const list_bytes = [_]u8{ 0x00, 0x08, 0x00, 0x01, 0x00, 0x02 };

    // Act / Assert
    try testing.expectError(error.LengthMismatch, parseList(&list_bytes));
}

test "parseList rejects trailing bytes after the declared body" {
    // Arrange: declares 4 body bytes but carries 5.
    const list_bytes = [_]u8{ 0x00, 0x04, 0x00, 0x01, 0xff, 0xff, 0x00 };

    // Act / Assert
    try testing.expectError(error.LengthMismatch, parseList(&list_bytes));
}

test "parseList rejects a zero-length serialized_sct item" {
    // Arrange: outer length 2, one item declaring length 0.
    const list_bytes = [_]u8{ 0x00, 0x02, 0x00, 0x00 };

    // Act / Assert
    try testing.expectError(error.InvalidLength, parseList(&list_bytes));
}

test "parseList rejects a serialized_sct that overruns the list body" {
    // Arrange: item declares 16 bytes but only 2 follow.
    const list_bytes = [_]u8{ 0x00, 0x04, 0x00, 0x10, 0xaa, 0xbb };

    // Act / Assert
    try testing.expectError(error.Truncated, parseList(&list_bytes));
}

test "parseSct rejects a truncated SCT (LogID cut short)" {
    // Arrange: version + 4 LogID bytes, then nothing.
    const body = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04 };

    // Act / Assert
    try testing.expectError(error.Truncated, parseSct(&body));
}

test "parseSct rejects surplus bytes after the signature" {
    // Arrange: a valid SCT body with one extra trailing byte appended.
    const log_id = @as([log_id_len]u8, @splat(0x07));
    const signature = [_]u8{ 0x09, 0x0a };
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, 99, &.{}, &signature);

    var overlong: [256]u8 = undefined;
    @memcpy(overlong[0..body.len], body);
    overlong[body.len] = 0xff;

    // Act / Assert
    try testing.expectError(error.LengthMismatch, parseSct(overlong[0 .. body.len + 1]));
}

test "parseSct rejects a signature length that overruns the body" {
    // Arrange: hand-build an SCT whose signature length prefix lies.
    var body: [1 + log_id_len + 8 + 2 + 2 + 2]u8 = undefined;
    var off: usize = 0;
    body[off] = @backingInt(Version.v1);
    off += 1;
    @memset(body[off..][0..log_id_len], 0x00);
    off += log_id_len;
    @memset(body[off..][0..8], 0x00);
    off += 8;
    writeU16(body[off..], 0); // empty extensions
    off += 2;
    body[off] = hash_sha256;
    body[off + 1] = sig_ecdsa;
    off += 2;
    writeU16(body[off..], 0x00ff); // claims 255 signature bytes
    off += 2;

    // Act / Assert
    try testing.expectError(error.Truncated, parseSct(body[0..off]));
}

test "parseList surfaces version even for an unknown version byte" {
    // Arrange: an SCT whose version byte is 9 (not v1).
    const log_id = @as([log_id_len]u8, @splat(0x01));
    const signature = [_]u8{0x00};
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, 0, &.{}, &signature);
    var mutable: [256]u8 = undefined;
    @memcpy(mutable[0..body.len], body);
    mutable[0] = 9; // corrupt the version

    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{mutable[0..body.len]});

    // Act
    const parsed = try parseList(list_bytes);

    // Assert: non-exhaustive enum preserves the wire value; v1 is the only
    // named member, so an unknown byte is not equal to v1.
    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expect(parsed.slice()[0].version != .v1);
    try testing.expectEqual(@as(u8, 9), @backingInt(parsed.slice()[0].version));
}

test "parseList rejects more than max_scts entries" {
    // Arrange: build max_scts + 1 minimal SCTs.
    const log_id = @as([log_id_len]u8, @splat(0x00));
    const signature = [_]u8{0x00};
    var bodies_storage: [max_scts + 1][128]u8 = undefined;
    var bodies: [max_scts + 1][]const u8 = undefined;
    for (0..max_scts + 1) |i| {
        bodies[i] = buildOneSctBody(&bodies_storage[i], log_id, @intCast(i), &.{}, &signature);
    }
    var list_buf: [2048]u8 = undefined;
    const list_bytes = buildList(&list_buf, &bodies);

    // Act / Assert
    try testing.expectError(error.TooManySct, parseList(list_bytes));
}

test "buildSignedData frames an x509 entry as CertificateTimestamp" {
    // Arrange
    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x05 };
    var out: [128]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .timestamp = 0x0102_0304_0506_0708,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });

    // Assert: layout is version|sigtype|ts|entry_type|certlen24|cert|extlen16.
    const expected = [_]u8{
        0x00, // version v1
        0x00, // signature_type certificate_timestamp
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // timestamp
        0x00, 0x00, // entry_type x509_entry
        0x00, 0x00, 0x05, // 24-bit cert length
        0x30, 0x03, 0x02, 0x01, 0x05, // cert DER
        0x00, 0x00, // extensions length 0
    };
    try testing.expectEqualSlices(u8, &expected, signed);
}

test "buildSignedData includes non-empty extensions" {
    // Arrange
    const cert_der = [_]u8{0x42};
    const extensions = [_]u8{ 0xaa, 0xbb };
    var out: [64]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .timestamp = 0,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &extensions,
    });

    // Assert: last four bytes are extlen(0x0002) || extensions.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x02, 0xaa, 0xbb }, signed[signed.len - 4 ..]);
}

test "buildSignedData writes a precert entry verbatim" {
    // Arrange: precert signed_entry is issuer_key_hash[32] || tbs<1..2^24-1>.
    const issuer_key_hash = @as([log_id_len]u8, @splat(0x33));
    const tbs = [_]u8{ 0x30, 0x01, 0x00 };
    var entry_buf: [64]u8 = undefined;
    const entry = try buildPrecertEntry(&entry_buf, issuer_key_hash, &tbs);

    var out: [128]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .timestamp = 7,
        .entry_type = .precert_entry,
        .signed_entry = entry,
        .extensions = &.{},
    });

    // Assert: entry_type is precert(0x0001) and the entry follows un-prefixed.
    try testing.expectEqual(@as(u16, 0x0001), readU16(signed[10..12]));
    try testing.expectEqualSlices(u8, entry, signed[12 .. 12 + entry.len]);
    // entry itself: 32-byte hash, then 24-bit tbs length, then tbs.
    try testing.expectEqualSlices(u8, &issuer_key_hash, entry[0..log_id_len]);
    try testing.expectEqual(@as(u24, tbs.len), std.mem.readInt(u24, entry[log_id_len..][0..3], .big));
    try testing.expectEqualSlices(u8, &tbs, entry[log_id_len + 3 ..]);
}

test "buildSignedData reports NoSpaceLeft when out is too small" {
    // Arrange
    const cert_der = [_]u8{ 0x01, 0x02, 0x03 };
    var tiny: [8]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.NoSpaceLeft, buildSignedData(&tiny, .{
        .timestamp = 0,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    }));
}

test "buildSignedData output round-trips the parsed SCT timestamp" {
    // Arrange: parse an SCT, then rebuild signed data using its timestamp.
    const log_id = @as([log_id_len]u8, @splat(0x5a));
    const ts: u64 = 0x0000_018f_aa00_1234;
    const signature = [_]u8{ 0x30, 0x02, 0x05, 0x00 };
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log_id, ts, &.{}, &signature);
    var list_buf: [512]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{body});
    const parsed = try parseList(list_bytes);
    const sct = parsed.slice()[0];

    const cert_der = [_]u8{0x99};
    var out: [64]u8 = undefined;

    // Act
    const signed = try buildSignedData(&out, .{
        .version = sct.version,
        .timestamp = sct.timestamp,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = sct.extensions,
    });

    // Assert: the timestamp field (bytes 2..10) equals the parsed timestamp.
    try testing.expectEqual(ts, std.mem.readInt(u64, signed[2..10], .big));
}

test "buildPrecertEntry reports NoSpaceLeft when out is too small" {
    // Arrange
    const issuer_key_hash = @as([log_id_len]u8, @splat(0x00));
    const tbs = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var tiny: [16]u8 = undefined; // needs 32 + 3 + 4

    // Act / Assert
    try testing.expectError(error.NoSpaceLeft, buildPrecertEntry(&tiny, issuer_key_hash, &tbs));
}

test "verifySct accepts Ed25519 log signature over built signed data" {
    const allocator = testing.allocator;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x7C)));
    const spki = try testEd25519Spki(allocator, kp.public_key.toBytes());
    defer allocator.free(spki);

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x09 };
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = 0x0102_0304_0506_0708,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });
    const sig = try kp.sign(signed, null);
    const sig_bytes = sig.toBytes();
    const sct = Sct{
        .version = .v1,
        .log_id = @as([log_id_len]u8, @splat(0xAA)),
        .timestamp = 0x0102_0304_0506_0708,
        .extensions = &.{},
        .sig_hash_alg = hash_intrinsic,
        .sig_signature_alg = sig_ed25519,
        .signature = &sig_bytes,
    };

    try testing.expect(verifySct(sct, spki, signed));
    signed_buf[0] ^= 1;
    try testing.expect(!verifySct(sct, spki, signed));
}

fn testEd25519Spki(allocator: std.mem.Allocator, public_key: [Ed25519.PublicKey.encoded_length]u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendAlgId(allocator, &body, &oid_ed25519, false);
    try appendDerBitString(allocator, &body, &public_key);
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

/// rsaEncryption (1.2.840.113549.1.1.1), for a hand-built RSA log SPKI.
const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

/// Append a DER INTEGER with `magnitude` as a big-endian unsigned value: strips
/// leading zeros to the minimal form, then adds a single 0x00 sign byte when the
/// leading content byte's high bit is set (X.690 positivity).
fn appendDerInteger(allocator: std.mem.Allocator, out: *std.ArrayList(u8), magnitude: []const u8) !void {
    var v = magnitude;
    while (v.len > 1 and v[0] == 0) v = v[1..];
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    if (v.len == 0 or (v[0] & 0x80) != 0) try body.append(allocator, 0);
    try body.appendSlice(allocator, v);
    try appendDerTlv(allocator, out, x509.Tag.integer, body.items);
}

/// Build an ECDSA-P256 log SPKI: SEQUENCE { SEQUENCE { OID ecPublicKey, OID
/// prime256v1 }, BIT STRING { 0x00 || sec1 } }.
fn testEcdsaSpki(allocator: std.mem.Allocator, sec1: [ecdsa_p256.sec1_uncompressed_length]u8) ![]u8 {
    var alg_body: std.ArrayList(u8) = .empty;
    defer alg_body.deinit(allocator);
    try appendDerTlv(allocator, &alg_body, x509.Tag.oid, &oid_ec_public_key);
    try appendDerTlv(allocator, &alg_body, x509.Tag.oid, &oid_prime256v1);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendDerSeq(allocator, &body, alg_body.items);
    try appendDerBitString(allocator, &body, &sec1);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

/// Build an RSA log SPKI: SEQUENCE { SEQUENCE { OID rsaEncryption, NULL },
/// BIT STRING { 0x00 || SEQUENCE { INTEGER n, INTEGER e } } }.
fn testRsaSpki(allocator: std.mem.Allocator, n: []const u8, e: []const u8) ![]u8 {
    var rsa_body: std.ArrayList(u8) = .empty;
    defer rsa_body.deinit(allocator);
    try appendDerInteger(allocator, &rsa_body, n);
    try appendDerInteger(allocator, &rsa_body, e);

    var rsa_seq: std.ArrayList(u8) = .empty;
    defer rsa_seq.deinit(allocator);
    try appendDerSeq(allocator, &rsa_seq, rsa_body.items);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendAlgId(allocator, &body, &oid_rsa_encryption, true);
    try appendDerBitString(allocator, &body, rsa_seq.items);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try appendDerSeq(allocator, &out, body.items);
    return out.toOwnedSlice(allocator);
}

// M2281 = 2^2281-1 (a Mersenne PRIME) with e = d = n-2 ≡ -1 (mod n-1): a
// self-signing RSA key needing no key generation or modular inverse, mirroring
// the trick `rsa_verify.zig` uses for its own KAT. It exercises the RSA branch
// of `verifySct` with our own signer. 2281 bits = 286 bytes (0x01 then
// 285×0xFF) — comfortably above rsa_verify's 2048-bit modern-hardening floor,
// so verifySct's RSA branch still accepts the key; n-2 flips the low byte to
// 0xFD.
const m2281_n = blk: {
    var n: [286]u8 = @splat(0xFF);
    n[0] = 0x01;
    break :blk n;
};
const m2281_ed = blk: {
    var e: [286]u8 = @splat(0xFF);
    e[0] = 0x01;
    e[285] = 0xFD;
    break :blk e;
};
/// DER DigestInfo prefix for SHA-256 (RFC 8017 §9.2), for the PKCS1 KAT below.
const sha256_digest_info_prefix = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

test "verify accepts an ECDSA-P256 log signature (self-consistency KAT)" {
    // NOTE: the log key is a fresh test keypair we control — this is a
    // self-consistency check of the reconstruction + verify path, not an
    // external RFC 6962 CT vector.
    const allocator = testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    const spki = try testEcdsaSpki(allocator, kp.public_key.toUncompressedSec1());
    defer allocator.free(spki);
    const log = CtLog{ .log_id = logIdFromSpki(spki), .key_spki_der = spki };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x07 };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };
    const ts: u64 = 0x0000_0193_4d2e_a1f0;
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });
    const sig = try ecdsa_p256.sign(signed, kp);
    var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = try ecdsa_p256.signatureToDer(sig, &der_buf);
    const sct = Sct{
        .version = .v1,
        .log_id = log.log_id,
        .timestamp = ts,
        .extensions = &.{},
        .sig_hash_alg = hash_sha256,
        .sig_signature_alg = sig_ecdsa,
        .signature = der_sig,
    };

    // Direct signature check and both registry entrypoints accept it.
    try testing.expect(verifySct(sct, spki, signed));
    try testing.expectEqual(VerifyResult.valid, verifyOneSct(sct, ctx, &.{log}, ts));
    try testing.expectEqual(VerifyResult.valid, verifySignedDataAgainstLogs(sct, signed, &.{log}, null));

    // No pinned log matches a different id, and an empty registry never matches.
    const other = CtLog{ .log_id = @as([log_id_len]u8, @splat(0x00)), .key_spki_der = spki };
    try testing.expectEqual(VerifyResult.no_applicable_log, verifyOneSct(sct, ctx, &.{other}, null));
    try testing.expectEqual(VerifyResult.no_applicable_log, verifyOneSct(sct, ctx, &.{}, null));

    // Tampering the signed data flips the outcome to a hard reject.
    signed_buf[0] ^= 1;
    try testing.expectEqual(VerifyResult.invalid, verifySignedDataAgainstLogs(sct, signed, &.{log}, null));
}

test "verifySctAgainstLogs verifies an ECDSA SCT from its serialized bytes" {
    const allocator = testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    const spki = try testEcdsaSpki(allocator, kp.public_key.toUncompressedSec1());
    defer allocator.free(spki);
    const log = CtLog{ .log_id = logIdFromSpki(spki), .key_spki_der = spki };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x0b };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };
    const ts: u64 = 42;
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });
    const sig = try ecdsa_p256.sign(signed, kp);
    var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = try ecdsa_p256.signatureToDer(sig, &der_buf);
    var body_buf: [256]u8 = undefined;
    const body = buildOneSctBody(&body_buf, log.log_id, ts, &.{}, der_sig);

    // Valid over the wire bytes.
    try testing.expectEqual(VerifyResult.valid, verifySctAgainstLogs(body, ctx, &.{log}, null));
    // Unknown log and empty registry.
    const other = CtLog{ .log_id = @as([log_id_len]u8, @splat(0x00)), .key_spki_der = spki };
    try testing.expectEqual(VerifyResult.no_applicable_log, verifySctAgainstLogs(body, ctx, &.{other}, null));
    try testing.expectEqual(VerifyResult.no_applicable_log, verifySctAgainstLogs(body, ctx, &.{}, null));
    // Flipping the trailing signature byte → hard reject.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..body.len], body);
    tampered[body.len - 1] ^= 0x01;
    try testing.expectEqual(VerifyResult.invalid, verifySctAgainstLogs(tampered[0..body.len], ctx, &.{log}, null));
    // Malformed (truncated) SCT bytes → invalid, never a match.
    try testing.expectEqual(VerifyResult.invalid, verifySctAgainstLogs(body[0..5], ctx, &.{log}, null));
}

test "verifyOneSct accepts an RSA-PKCS1-SHA256 log signature (self-consistency KAT)" {
    // The RSA log key is the self-signing M2281 key we control (see above): this
    // exercises verifySct's RSA branch, not an external CT vector.
    const allocator = testing.allocator;
    const spki = try testRsaSpki(allocator, &m2281_n, &m2281_ed);
    defer allocator.free(spki);
    const log = CtLog{ .log_id = logIdFromSpki(spki), .key_spki_der = spki };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x2a };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };
    const ts: u64 = 0x0000_0193_0000_0001;
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });

    // Encode EM = 00 01 FF.. 00 || DigestInfo(sha256) || SHA256(signed), then
    // self-sign s = EM^d mod n with our controlled M2281 private exponent.
    const digest = hash.Sha256.hash(signed);
    const k = m2281_n.len; // 286
    const t_len = sha256_digest_info_prefix.len + digest.len; // 51
    var em: [286]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x01;
    const ps_len = k - t_len - 3; // 232
    @memset(em[2 .. 2 + ps_len], 0xFF);
    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len ..][0..sha256_digest_info_prefix.len], &sha256_digest_info_prefix);
    @memcpy(em[3 + ps_len + sha256_digest_info_prefix.len ..][0..digest.len], &digest);
    var sig: [286]u8 = undefined;
    try rsa_verify.modExp(&em, &m2281_ed, &m2281_n, &sig);

    const sct = Sct{
        .version = .v1,
        .log_id = log.log_id,
        .timestamp = ts,
        .extensions = &.{},
        .sig_hash_alg = hash_sha256,
        .sig_signature_alg = sig_rsa,
        .signature = &sig,
    };

    try testing.expect(verifySct(sct, spki, signed));
    try testing.expectEqual(VerifyResult.valid, verifyOneSct(sct, ctx, &.{log}, null));

    // A flipped signature byte → invalid.
    var bad_sig = sig;
    bad_sig[10] ^= 0x01;
    var bad_sct = sct;
    bad_sct.signature = &bad_sig;
    try testing.expectEqual(VerifyResult.invalid, verifyOneSct(bad_sct, ctx, &.{log}, null));

    // Algorithm mismatch (SCT claims ECDSA over an RSA key) → invalid.
    var mism = sct;
    mism.sig_signature_alg = sig_ecdsa;
    try testing.expectEqual(VerifyResult.invalid, verifyOneSct(mism, ctx, &.{log}, null));
}

test "verifyOneSct rejects a future-dated SCT when a clock is supplied" {
    const allocator = testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    const spki = try testEcdsaSpki(allocator, kp.public_key.toUncompressedSec1());
    defer allocator.free(spki);
    const log = CtLog{ .log_id = logIdFromSpki(spki), .key_spki_der = spki };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };
    const ts: u64 = 10_000_000_000;
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });
    const sig = try ecdsa_p256.sign(signed, kp);
    var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = try ecdsa_p256.signatureToDer(sig, &der_buf);
    const sct = Sct{
        .version = .v1,
        .log_id = log.log_id,
        .timestamp = ts,
        .extensions = &.{},
        .sig_hash_alg = hash_sha256,
        .sig_signature_alg = sig_ecdsa,
        .signature = der_sig,
    };

    // A clock well before the SCT timestamp (beyond skew) rejects it.
    try testing.expectEqual(VerifyResult.invalid, verifyOneSct(sct, ctx, &.{log}, ts - future_skew_ms - 1000));
    // Within the skew window, exactly at the timestamp, or with no clock: accept.
    try testing.expectEqual(VerifyResult.valid, verifyOneSct(sct, ctx, &.{log}, ts - future_skew_ms + 1000));
    try testing.expectEqual(VerifyResult.valid, verifyOneSct(sct, ctx, &.{log}, ts));
    try testing.expectEqual(VerifyResult.valid, verifyOneSct(sct, ctx, &.{log}, null));
}

test "verifyList tallies valid and no_applicable_log outcomes" {
    const allocator = testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    const spki = try testEcdsaSpki(allocator, kp.public_key.toUncompressedSec1());
    defer allocator.free(spki);
    const log = CtLog{ .log_id = logIdFromSpki(spki), .key_spki_der = spki };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x03 };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };

    // SCT 1: valid, from the pinned log.
    const ts1: u64 = 100;
    var sbuf1: [128]u8 = undefined;
    const s1 = try buildSignedData(&sbuf1, .{
        .timestamp = ts1,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });
    const sig1 = try ecdsa_p256.sign(s1, kp);
    var db1: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const dsig1 = try ecdsa_p256.signatureToDer(sig1, &db1);
    var bb1: [256]u8 = undefined;
    const body1 = buildOneSctBody(&bb1, log.log_id, ts1, &.{}, dsig1);

    // SCT 2: from a log this deployment does not pin (signature irrelevant).
    const junk = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
    var bb2: [256]u8 = undefined;
    const body2 = buildOneSctBody(&bb2, @as([log_id_len]u8, @splat(0x00)), 200, &.{}, &junk);

    var list_buf: [768]u8 = undefined;
    const list_bytes = buildList(&list_buf, &.{ body1, body2 });

    // Act
    const summary = try verifyList(list_bytes, ctx, &.{log}, null);

    // Assert
    try testing.expectEqual(@as(usize, 1), summary.valid);
    try testing.expectEqual(@as(usize, 1), summary.no_applicable_log);
    try testing.expectEqual(@as(usize, 0), summary.invalid);

    // A structurally broken list is a hard failure, not a summary.
    try testing.expectError(error.LengthMismatch, verifyList(&[_]u8{ 0x00, 0x08, 0x00, 0x01, 0x00, 0x02 }, ctx, &.{log}, null));
}

test "verifyList counts distinct valid logs for a presence quorum" {
    const allocator = testing.allocator;
    // Two DISTINCT pinned logs (fresh, independent keys), both signing the same
    // x509 entry so their SCTs are individually valid.
    const kp_a = ecdsa_p256.KeyPair.generate(testing.io);
    const spki_a = try testEcdsaSpki(allocator, kp_a.public_key.toUncompressedSec1());
    defer allocator.free(spki_a);
    const log_a = CtLog{ .log_id = logIdFromSpki(spki_a), .key_spki_der = spki_a };

    const kp_b = ecdsa_p256.KeyPair.generate(testing.io);
    const spki_b = try testEcdsaSpki(allocator, kp_b.public_key.toUncompressedSec1());
    defer allocator.free(spki_b);
    const log_b = CtLog{ .log_id = logIdFromSpki(spki_b), .key_spki_der = spki_b };
    // The two logs are genuinely distinct — otherwise the quorum test is vacuous.
    try testing.expect(!std.mem.eql(u8, &log_a.log_id, &log_b.log_id));

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x0d };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };
    const ts: u64 = 1234;
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });

    // A valid SCT from log A.
    const sig_a = try ecdsa_p256.sign(signed, kp_a);
    var da: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const dsig_a = try ecdsa_p256.signatureToDer(sig_a, &da);
    var ba: [256]u8 = undefined;
    const body_a = buildOneSctBody(&ba, log_a.log_id, ts, &.{}, dsig_a);
    // A SECOND valid SCT that is ALSO from log A (same log id, same signature).
    var ba2: [256]u8 = undefined;
    const body_a2 = buildOneSctBody(&ba2, log_a.log_id, ts, &.{}, dsig_a);
    // A valid SCT from the distinct log B.
    const sig_b = try ecdsa_p256.sign(signed, kp_b);
    var db: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const dsig_b = try ecdsa_p256.signatureToDer(sig_b, &db);
    var bb: [256]u8 = undefined;
    const body_b = buildOneSctBody(&bb, log_b.log_id, ts, &.{}, dsig_b);

    // Two valid SCTs from the SAME log ⇒ valid=2 but distinct_valid_logs=1: a
    // "≥2 distinct logs" policy is NOT satisfiable by duplicating one log.
    {
        var lb: [768]u8 = undefined;
        const list_bytes = buildList(&lb, &.{ body_a, body_a2 });
        const summary = try verifyList(list_bytes, ctx, &.{ log_a, log_b }, null);
        try testing.expectEqual(@as(usize, 2), summary.valid);
        try testing.expectEqual(@as(usize, 1), summary.distinct_valid_logs);
    }

    // One valid SCT from each of two distinct pinned logs ⇒ distinct_valid_logs=2.
    {
        var lb: [768]u8 = undefined;
        const list_bytes = buildList(&lb, &.{ body_a, body_b });
        const summary = try verifyList(list_bytes, ctx, &.{ log_a, log_b }, null);
        try testing.expectEqual(@as(usize, 2), summary.valid);
        try testing.expectEqual(@as(usize, 2), summary.distinct_valid_logs);
    }

    // An INVALID SCT (tampered signature) from a pinned log never contributes to
    // the distinct-log count, even though its log_id matches a pinned log.
    {
        var tampered: [256]u8 = undefined;
        @memcpy(tampered[0..body_b.len], body_b);
        tampered[body_b.len - 1] ^= 0x01;
        var lb: [768]u8 = undefined;
        const list_bytes = buildList(&lb, &.{ body_a, tampered[0..body_b.len] });
        const summary = try verifyList(list_bytes, ctx, &.{ log_a, log_b }, null);
        try testing.expectEqual(@as(usize, 1), summary.valid);
        try testing.expectEqual(@as(usize, 1), summary.invalid);
        try testing.expectEqual(@as(usize, 1), summary.distinct_valid_logs);
    }

    // An SCT from an UNPINNED log is no_applicable_log ⇒ contributes nothing.
    {
        var junk_body: [256]u8 = undefined;
        const body_unpinned = buildOneSctBody(&junk_body, @as([log_id_len]u8, @splat(0xEE)), ts, &.{}, dsig_a);
        var lb: [768]u8 = undefined;
        const list_bytes = buildList(&lb, &.{body_unpinned});
        const summary = try verifyList(list_bytes, ctx, &.{ log_a, log_b }, null);
        try testing.expectEqual(@as(usize, 0), summary.valid);
        try testing.expectEqual(@as(usize, 1), summary.no_applicable_log);
        try testing.expectEqual(@as(usize, 0), summary.distinct_valid_logs);
    }
}

test "verifyListAccumulating unions distinct valid logs across two sources" {
    // Two lists over the SAME x509 entry: list 1 has valid SCTs from logs A and
    // B; list 2 has valid SCTs from logs B and C. The per-list distinct counts are
    // 2 and 2, but the UNION (a cross-source presence quorum) is {A,B,C} = 3, with
    // B counted once. This models embedded + TLS-extension SCT pooling.
    const allocator = testing.allocator;

    const kp_a = ecdsa_p256.KeyPair.generate(testing.io);
    const spki_a = try testEcdsaSpki(allocator, kp_a.public_key.toUncompressedSec1());
    defer allocator.free(spki_a);
    const log_a = CtLog{ .log_id = logIdFromSpki(spki_a), .key_spki_der = spki_a };
    const kp_b = ecdsa_p256.KeyPair.generate(testing.io);
    const spki_b = try testEcdsaSpki(allocator, kp_b.public_key.toUncompressedSec1());
    defer allocator.free(spki_b);
    const log_b = CtLog{ .log_id = logIdFromSpki(spki_b), .key_spki_der = spki_b };
    const kp_c = ecdsa_p256.KeyPair.generate(testing.io);
    const spki_c = try testEcdsaSpki(allocator, kp_c.public_key.toUncompressedSec1());
    defer allocator.free(spki_c);
    const log_c = CtLog{ .log_id = logIdFromSpki(spki_c), .key_spki_der = spki_c };

    const cert_der = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x21 };
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = &cert_der };
    const ts: u64 = 555;
    var signed_buf: [128]u8 = undefined;
    const signed = try buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = &cert_der,
        .extensions = &.{},
    });

    const SignFn = struct {
        fn go(kp: ecdsa_p256.KeyPair, s: []const u8, out: []u8) []const u8 {
            const sig = ecdsa_p256.sign(s, kp) catch unreachable;
            var db: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
            const d = ecdsa_p256.signatureToDer(sig, &db) catch unreachable;
            @memcpy(out[0..d.len], d);
            return out[0..d.len];
        }
    };
    var da: [128]u8 = undefined;
    var db: [128]u8 = undefined;
    var dc: [128]u8 = undefined;
    const dsig_a = SignFn.go(kp_a, signed, &da);
    const dsig_b = SignFn.go(kp_b, signed, &db);
    const dsig_c = SignFn.go(kp_c, signed, &dc);

    var ba: [256]u8 = undefined;
    var bb1: [256]u8 = undefined;
    var bb2: [256]u8 = undefined;
    var bc: [256]u8 = undefined;
    const body_a = buildOneSctBody(&ba, log_a.log_id, ts, &.{}, dsig_a);
    const body_b1 = buildOneSctBody(&bb1, log_b.log_id, ts, &.{}, dsig_b);
    const body_b2 = buildOneSctBody(&bb2, log_b.log_id, ts, &.{}, dsig_b);
    const body_c = buildOneSctBody(&bc, log_c.log_id, ts, &.{}, dsig_c);

    var lb1: [768]u8 = undefined;
    var lb2: [768]u8 = undefined;
    const list1 = buildList(&lb1, &.{ body_a, body_b1 });
    const list2 = buildList(&lb2, &.{ body_b2, body_c });
    const pins = [_]CtLog{ log_a, log_b, log_c };

    var acc: DistinctValidLogs = .{};
    const s1 = try verifyListAccumulating(list1, ctx, &pins, null, &acc);
    try testing.expectEqual(@as(usize, 2), s1.distinct_valid_logs);
    try testing.expectEqual(@as(usize, 2), acc.count());
    const s2 = try verifyListAccumulating(list2, ctx, &pins, null, &acc);
    try testing.expectEqual(@as(usize, 2), s2.distinct_valid_logs);
    // Union {A,B,C} = 3, NOT 2+2 = 4 (log B contributed to both lists).
    try testing.expectEqual(@as(usize, 3), acc.count());

    // verifyList (no accumulator) still behaves identically for a single list.
    const plain = try verifyList(list1, ctx, &pins, null);
    try testing.expectEqual(@as(usize, 2), plain.distinct_valid_logs);
}

test "verifyOneSct fails closed when the certified entry exceeds the internal buffer" {
    const allocator = testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    const spki = try testEcdsaSpki(allocator, kp.public_key.toUncompressedSec1());
    defer allocator.free(spki);
    const log = CtLog{ .log_id = logIdFromSpki(spki), .key_spki_der = spki };

    // A signed_entry one byte past the internal cap forces buildSignedData to
    // run out of room; verifyOneSct maps that to .invalid rather than reading
    // uninitialized memory.
    const big = try allocator.alloc(u8, max_internal_signed_entry + 1);
    defer allocator.free(big);
    @memset(big, 0x00);
    const ctx = CertContext{ .entry_type = .x509_entry, .signed_entry = big };
    const sct = Sct{
        .version = .v1,
        .log_id = log.log_id,
        .timestamp = 1,
        .extensions = &.{},
        .sig_hash_alg = hash_sha256,
        .sig_signature_alg = sig_ecdsa,
        .signature = &[_]u8{0x00},
    };
    try testing.expectEqual(VerifyResult.invalid, verifyOneSct(sct, ctx, &.{log}, null));
}

test "logIdFromSpki equals the SHA-256 of the SPKI DER" {
    const allocator = testing.allocator;
    const kp = ecdsa_p256.KeyPair.generate(testing.io);
    const spki = try testEcdsaSpki(allocator, kp.public_key.toUncompressedSec1());
    defer allocator.free(spki);
    try testing.expectEqualSlices(u8, &hash.Sha256.hash(spki), &logIdFromSpki(spki));
}

test {
    std.testing.refAllDecls(@This());
}
