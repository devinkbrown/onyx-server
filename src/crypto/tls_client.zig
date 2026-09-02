// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socketless TLS 1.3 client handshake state machine for outbound HTTPS.
//!
//! The caller owns transport I/O: call `start()` to get the ClientHello record,
//! pass received bytes to `feed()`, send any returned bytes, then use
//! `encrypt()` / `decrypt()` once `handshakeDone()` is true.

const std = @import("std");

const hkdf_tls13 = @import("hkdf_tls13.zig");
const tls_resumption = @import("tls_resumption.zig");
const tls_record = @import("tls_record.zig");
const x509 = @import("x509.zig");
const x509_verify = @import("x509_verify.zig");
const ocsp = @import("ocsp.zig");
const crl = @import("crl.zig");
const sct = @import("sct.zig");
const hash = @import("hash.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const rsa_verify = @import("rsa_verify.zig");
const rsa_sign = @import("rsa_sign.zig");
const sign = @import("sign.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const kx = @import("kx.zig");
const random_mod = @import("random.zig");

const tls_supported_versions = @import("../proto/tls_supported_versions.zig");
const tls_keyshare = @import("../proto/tls_keyshare.zig");
const tls_signature_scheme = @import("../proto/tls_signature_scheme.zig");
const tls_extension = @import("../proto/tls_extension.zig");
const delegated_credential = @import("../proto/delegated_credential.zig");
const supported_groups = @import("../proto/supported_groups.zig");
const cert_compression = @import("../proto/cert_compression.zig");
const sni = @import("../proto/sni.zig");
// ECH: `ech_seal` (this package) does the HPKE seal + acceptance confirmation;
// `ech_config` (proto) parses/selects the caller-supplied ECHConfigList. See
// their module docs for why they live apart from the pre-existing, unwired
// `proto/ech.zig` (which decodes to owned structs and drops the raw config bytes
// HPKE's `info` needs).
const ech = @import("ech_seal.zig");
const ech_config = @import("../proto/ech_config.zig");
const tls_alert = @import("../proto/tls_alert.zig");
const tls_finished = @import("../proto/tls_finished.zig");
const tls_psk = @import("../proto/tls_psk.zig");
const tls_session_ticket = @import("../proto/tls_session_ticket.zig");
const tls_alpn = @import("../proto/tls_alpn.zig");
const toml = @import("../proto/toml.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");

const Allocator = std.mem.Allocator;
const Sha256 = hkdf_tls13.Sha256;
const Sha384 = hkdf_tls13.Sha384;
/// Largest TLS 1.3 transcript-hash / traffic-secret length we handle (SHA-384).
const max_hash_len = Sha384.hash_len;

/// Fail-closed cap on how many handshake messages one post-handshake record may
/// coalesce. RFC 8446 §5.1 permits several messages per record, and a real
/// server does send a couple of NewSessionTickets back to back, but nothing
/// legitimate approaches this bound. Each KeyUpdate costs six HKDF-Expand-Label
/// derivations plus a sealed reply record, and each NewSessionTicket costs a
/// PSK derivation and a ticket store; a KeyUpdate is five bytes on the wire, so
/// an uncapped loop lets one maximal 2^14-byte record buy ~3.2k rotations and
/// ~85 KiB of queued egress. Capping the count bounds the work a single record
/// from a hostile server can purchase.
const max_post_handshake_msgs_per_record: usize = 8;

/// Opt-in handshake tracing (set by out-of-band tools like acme_runner).
pub var debug_log: bool = false;

/// Overlay `[tls].debug_log` onto the module-level tracing flag. Absent key
/// leaves the current value unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getBool("tls.debug_log")) |v| debug_log = v;
}
fn dbg(comptime fmt: []const u8, args: anytype) void {
    if (debug_log) std.debug.print("tls: " ++ fmt ++ "\n", args);
}
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const HashAlg = enum { sha256, sha384 };

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("tls_client requires a 64-bit target");
}

pub const Error = error{
    BadCertificate,
    BadHandshake,
    BadRecord,
    BadSct,
    BadSignature,
    BadState,
    CertificateNameMismatch,
    CertificateRevoked,
    DecodeError,
    /// RFC 9345: the delegation (leaf) certificate lacks the id-ce-delegationUsage
    /// extension, so it may not authorize a delegated credential.
    DelegatedCredentialNoDelegationUsage,
    /// RFC 9345: the delegation certificate lacks the digitalSignature KeyUsage.
    DelegatedCredentialKeyUsage,
    /// RFC 9345: the current time is past notBefore + valid_time.
    DelegatedCredentialExpired,
    /// RFC 9345 §4.1.3 check 2: the credential's expiry time (notBefore +
    /// valid_time) is more than 7 days past now — its remaining lifetime exceeds
    /// the maximum validity period.
    DelegatedCredentialLifetimeTooLong,
    /// RFC 9345 §4.1.3 check 2: the credential's expiry time is not strictly
    /// before the delegation certificate's own notAfter — the DC would outlive
    /// the certificate that authorized it.
    DelegatedCredentialOutlivesCertificate,
    /// RFC 9345: no wall-clock was supplied, so the DC validity window cannot be
    /// enforced — fail closed rather than trust an unbounded credential.
    DelegatedCredentialNoClock,
    /// RFC 9345 §4: CertificateVerify.algorithm must equal the DC's
    /// dc_cert_verify_algorithm.
    DelegatedCredentialSchemeMismatch,
    EmptyCertificateChain,
    FinishedMismatch,
    HelloRetryRequestUnsupported,
    /// Certificate Transparency presence policy (`Options.require_sct`) was not
    /// met: the leaf did not present at least `require_sct` embedded SCTs that
    /// each verify against a DISTINCT pinned CT log. Distinct from `BadSct`,
    /// which flags a tampered SCT; this flags MISSING logged-ness.
    InsufficientScts,
    MissingExtension,
    NeedMore,
    OutputTooSmall,
    ProtocolVersion,
    TlsAlert,
    TranscriptOverflow,
    UnknownCa,
    UnsupportedCipherSuite,
    UnsupportedGroup,
    UnsupportedSignatureScheme,
    UnsupportedPublicKey,
} || Allocator.Error || hkdf_tls13.Error || tls_record.Error || x509.Error ||
    x509_verify.Error || ecdh_p256.EcdhError || kx.KeyExchangeError ||
    ecdsa_p256.DerError || ecdsa_p256.Sec1Error || tls_extension.Error ||
    tls_keyshare.Error || tls_supported_versions.Error ||
    tls_signature_scheme.Error || supported_groups.Error || tls_alpn.Error ||
    tls_alert.ParseError || rsa_verify.Error || sign.VerifyError ||
    tls_psk.Error || tls_session_ticket.ParseError || tls_session_ticket.EncodeError ||
    tls_resumption.Error || ocsp.Error || cert_compression.Error ||
    delegated_credential.Error ||
    ech.Error || ech_config.Error;

pub const Options = struct {
    server_name: []const u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8 = &.{},
    /// Current wall-clock time (Unix seconds) used to reject expired and
    /// not-yet-valid certificates in the chain. When null the validity window is
    /// not checked — callers that can supply a trustworthy clock (the live HTTPS
    /// and ACME paths) should always set it; loopback tests with fixed fixtures
    /// leave it null.
    now_unix_seconds: ?i64 = null,
    /// Optional caller-supplied CRL (DER) for leaf revocation checking, e.g. one
    /// a CDP fetch retrieved out of band. When set AND `now_unix_seconds` is set,
    /// a CRL that verifies under the leaf's issuer key and is current can REJECT a
    /// revoked leaf (`error.CertificateRevoked`). Fail-open in every other case
    /// (absent, unparseable, wrong-issuer signature, stale, or no clock) so a
    /// missing or broken CRL never breaks an otherwise-valid handshake. Borrowed
    /// for the call; the client copies it.
    crl: ?[]const u8 = null,
    /// RFC 7250 raw public keys. When true, the ClientHello offers
    /// `server_certificate_type = [RawPublicKey, X509]`, permitting the server
    /// to reply with a bare `SubjectPublicKeyInfo` in place of an X.509 chain.
    /// Default false ⇒ the extension is never emitted (the ClientHello is
    /// byte-identical to the pre-feature wire) and only the X.509 path is ever
    /// taken. A raw public key has NO CA chain, so this mode does not bypass the
    /// normal X.509 trust checks — it *replaces* them with caller trust
    /// (TOFU/pinning), and only when explicitly opted in here.
    offer_raw_public_key: bool = false,
    /// Optional caller-supplied ECHConfigList (draft-ietf-tls-esni, version
    /// `0xfe0d`) — e.g. base64-decoded from a config file or a DNS HTTPS RR. This
    /// module never fetches it; the bytes are supplied out of band, mirroring how
    /// `crl` takes caller-supplied data. When set AND a usable config is present,
    /// the ClientHello is split into an HPKE-encrypted ClientHelloInner (carrying
    /// the real SNI) wrapped in a ClientHelloOuter (SNI = the config's
    /// `public_name`). Null, empty, or no supported config ⇒ the ClientHello is
    /// byte-identical to today (ECH omitted entirely). ECH is also skipped when a
    /// resumption offer or 0-RTT is configured (ECH-over-PSK is a follow-up).
    /// Borrowed for the call; the client copies it.
    ech_config_list: ?[]const u8 = null,
    /// Optional `signature_algorithms_cert` list (RFC 8446 §4.2.3): the signature
    /// schemes the client will accept on the CERTIFICATES in the server's chain,
    /// as distinct from `signature_algorithms` (which governs the CertificateVerify
    /// signature). OPT-IN and byte-identical when null — the default omits the
    /// extension entirely, so the peer applies `signature_algorithms` to
    /// certificates too (the compliant fallback, §4.2.3). When set, the schemes are
    /// emitted in descending preference in a `signature_algorithms_cert(50)`
    /// extension in the ClientHello (and, under ECH, the ClientHelloInner).
    /// Borrowed for the call; the client copies it.
    cert_signature_schemes: ?[]const tls_signature_scheme.SignatureScheme = null,
    /// Optional caller-supplied set of pinned Certificate Transparency logs (RFC
    /// 6962) for verifying SCTs embedded in the leaf certificate. Onyx Server ships NO
    /// log list; a deployment that wants CT enforcement supplies the logs it
    /// trusts (each `CtLog` pairs a log's DER SubjectPublicKeyInfo with its
    /// `log_id` — derive the id with `sct.logIdFromSpki`).
    ///
    /// OPT-IN and FAIL-OPEN. When this is empty (the default) the whole SCT path
    /// is skipped and the handshake is byte-identical to before. When non-empty,
    /// each embedded SCT is verified against the pinned logs, but by default a
    /// leaf with no SCTs, or SCTs only from unpinned logs, still passes —
    /// verification alone is marginal for an outbound ACME/HTTPS client and must
    /// never regress connectivity unless an operator explicitly opts into a
    /// stricter policy via `enforce_sct` (tamper detection) and/or `require_sct`
    /// (presence + distinct-log quorum). Borrowed for the call; the client
    /// deep-copies it (both the slice and each `key_spki_der`).
    ct_logs: []const sct.CtLog = &.{},
    /// TAMPER DETECTION. When true AND `ct_logs` is non-empty, an SCT that is
    /// present, matches a pinned log, and whose signature is INVALID fails the
    /// handshake closed (`error.BadSct`). Default false: verification still runs
    /// but never rejects, so even a pinned + invalid SCT is tolerated — keeping
    /// the outbound TLS surface byte-identical until an operator opts in.
    ///
    /// Note this alone does NOT close the mis-issuance gap: an attacker holding a
    /// mis-issued cert simply embeds no SCT (or only unpinned-log SCTs), which
    /// `enforce_sct` never rejects. `require_sct` closes that gap.
    enforce_sct: bool = false,
    /// PRESENCE + DISTINCT-LOG QUORUM (the real mis-issuance protection). The CT
    /// policy threshold N. When `>= 1` AND `ct_logs` is non-empty, the handshake
    /// REQUIRES the leaf to present at least N embedded SCTs that EACH verify
    /// (valid signature) against a DISTINCT pinned log (RFC 6962 §5.1-style
    /// quorum — duplicate SCTs from one log count once). A leaf below the
    /// threshold — no SCTs, too few, only unpinned-log SCTs, or a malformed /
    /// unreconstructable SCT set — is REJECTED with `error.InsufficientScts`,
    /// closing the embed-nothing bypass that `enforce_sct` cannot. Composes with
    /// `enforce_sct` (a signature-invalid pinned SCT still fails under it, and an
    /// invalid SCT never counts toward the quorum here).
    ///
    /// Default 0 ⇒ presence is NOT enforced: behavior is identical to before
    /// (fail-open), so an empty `ct_logs` OR `require_sct == 0` leaves the wire
    /// byte-identical. This is a fail-CLOSED policy — enable it only where the
    /// peer is expected to serve publicly-logged certificates.
    require_sct: u8 = 0,
};

pub const FeedResult = union(enum) {
    need_more,
    bytes_to_send: []u8,
};

/// Result of `decryptApp`: decrypted application bytes (caller owns) or a
/// benign post-handshake control record that was consumed and ignored.
pub const AppRead = union(enum) {
    application_data: []u8,
    control,
};

const State = enum {
    idle,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    connected,
};

const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    compressed_certificate = 25, // RFC 8879
    _,
};

const KeyUpdateRequest = enum(u8) {
    not_requested = 0,
    requested = 1,
};

const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,

    fn fromWire(v: u16) Error!CipherSuite {
        return switch (v) {
            0x1301 => .tls_aes_128_gcm_sha256,
            0x1302 => .tls_aes_256_gcm_sha384,
            0x1303 => .tls_chacha20_poly1305_sha256,
            else => error.UnsupportedCipherSuite,
        };
    }

    fn keyLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => Aes128Gcm.key_length,
            .tls_aes_256_gcm_sha384 => Aes256Gcm.key_length,
            .tls_chacha20_poly1305_sha256 => ChaCha20Poly1305.key_length,
        };
    }

    fn tagLen(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => Aes128Gcm.tag_length,
            .tls_aes_256_gcm_sha384 => Aes256Gcm.tag_length,
            .tls_chacha20_poly1305_sha256 => ChaCha20Poly1305.tag_length,
        };
    }

    fn hashAlg(self: CipherSuite) HashAlg {
        return switch (self) {
            .tls_aes_256_gcm_sha384 => .sha384,
            else => .sha256,
        };
    }

    fn hashLen(self: CipherSuite) usize {
        return switch (self.hashAlg()) {
            .sha256 => Sha256.hash_len,
            .sha384 => Sha384.hash_len,
        };
    }
};

const TrafficKeys = struct {
    key: [ChaCha20Poly1305.key_length]u8 = @splat(0),
    iv: tls_record.Nonce96 = @splat(0),

    fn wipe(self: *TrafficKeys) void {
        secureZero(&self.key);
        secureZero(&self.iv);
    }
};

const HandshakeMsg = struct {
    typ: HandshakeType,
    body: []const u8,
    raw: []const u8,
};

/// Test-only client-certificate signing key (mutual TLS loopback tests).
const ClientCertKey = union(enum) {
    ed25519: sign.KeyPair,
    ecdsa_p256: ecdsa_p256.KeyPair,
    rsa: rsa_sign.PrivateKey,
};

const LeafPublicKey = union(enum) {
    rsa: rsa_verify.PublicKey,
    ecdsa_p256: ecdsa_p256.PublicKey,
    ecdsa_p384: EcdsaP384.PublicKey,
    ed25519: sign.PublicKey,
};

const CertParts = struct {
    tbs_der: []const u8,
    signature_algorithm_oid: []const u8,
    /// Raw `parameters` TLV of the outer signatureAlgorithm, or `null` if absent.
    /// Needed for RSASSA-PSS, whose hash/MGF/salt live here, not in the OID.
    signature_algorithm_params: ?[]const u8,
    signature: []const u8,
    issuer_der: []const u8,
    subject_der: []const u8,
    spki_der: []const u8,
};

const ResumeOffer = struct {
    ticket: []u8,
    ticket_age_add: u32,
    ticket_lifetime: u32,
    ticket_age_ms: u64,
    suite: CipherSuite,
    psk: [max_hash_len]u8,
    psk_len: usize,
    max_early_data_size: u32,

    fn wipe(self: *ResumeOffer, allocator: Allocator) void {
        allocator.free(self.ticket);
        secureZero(&self.psk);
        self.* = undefined;
    }
};

pub const Client = struct {
    allocator: Allocator,
    server_name: []u8,
    trust_anchors: []const []const u8,
    alpn_protocols: []const []const u8,
    /// Owned copy of the caller-supplied CRL DER (see `Options.crl`), or null.
    crl: ?[]u8 = null,
    /// Owned copy of the caller-supplied `signature_algorithms_cert` schemes (see
    /// `Options.cert_signature_schemes`), or null when the extension is not
    /// offered. Retained (not just consumed at CH1) so the second ClientHello
    /// after a HelloRetryRequest re-emits the identical extension.
    cert_signature_schemes: ?[]tls_signature_scheme.SignatureScheme = null,
    /// Owned deep copy of the caller-supplied pinned CT logs (see
    /// `Options.ct_logs`). Empty when CT verification is not configured; each
    /// entry's `key_spki_der` is separately owned and freed on `deinit`.
    ct_logs: []sct.CtLog = &.{},
    /// When true and `ct_logs` is non-empty, a signature-invalid pinned SCT fails
    /// the handshake closed (see `Options.enforce_sct`).
    enforce_sct: bool = false,
    /// CT presence-quorum threshold: when `>= 1` and `ct_logs` is non-empty, the
    /// leaf must present at least this many valid SCTs from distinct pinned logs
    /// or the handshake fails closed (see `Options.require_sct`).
    require_sct: u8 = 0,

    state: State = .idle,
    /// Wall-clock time (Unix seconds) for certificate validity checks, or null to
    /// skip the validity window (see `Options.now_unix_seconds`).
    verify_time: ?i64 = null,
    x25519_pair: kx.X25519Kx.KeyPair,
    p256_pair: ecdh_p256.KeyPair,
    /// Ephemeral X25519MLKEM768 keypair (its own x25519 half + an ML-KEM-768
    /// keypair) backing the post-quantum hybrid key_share we offer. Distinct from
    /// `x25519_pair` (the classical x25519 share) so the two shares never share
    /// an ephemeral.
    hybrid_pair: kx.HybridKx.KeyPair,
    legacy_session_id: [32]u8,
    /// ClientHello random, generated once. RFC 8446 §4.1.2 requires the second
    /// ClientHello (after a HelloRetryRequest) to carry the same random. This is
    /// the *outer* random when ECH is offered.
    client_random: [32]u8,

    // --- Encrypted Client Hello (ECH) client state (roadmap 5.1) ---
    // All ECH state is inert unless a usable config is found in `start()`; when it
    // is not, `ech_active` stays false and the ClientHello is byte-identical.
    /// Owned copy of the caller-supplied ECHConfigList (see `Options.ech_config_list`).
    ech_config_list: ?[]u8 = null,
    /// The config `start()` committed to offering ECH under. Borrows
    /// `ech_config_list` (owned, stable for the client's life). Null unless ECH
    /// is active.
    ech_selected: ?ech_config.Config = null,
    /// True once `start()` has committed to offering ECH.
    ech_active: bool = false,
    /// Owned copy of the selected config's `public_name` — the ClientHelloOuter
    /// SNI and the identity authenticated if the server rejects ECH.
    ech_public_name: ?[]u8 = null,
    /// ClientHelloInner random (distinct from `client_random`, the outer random).
    /// Feeds the acceptance-confirmation HKDF-Extract as its IKM.
    ech_inner_random: [32]u8,
    /// Owned ClientHelloInner handshake-message bytes (real SNI, real session_id,
    /// inner ECH marker). Retained so the transcript can switch to the inner on
    /// acceptance and so the confirmation can be recomputed. Null unless active.
    ech_inner_hello: ?[]u8 = null,
    /// Set when ServerHello is processed: whether the server accepted ECH. Null
    /// until then, or when ECH was never offered.
    ech_accepted: ?bool = null,
    /// Owned `retry_configs` ECHConfigList (draft-ietf-tls-esni §7.1) the server
    /// delivered in EncryptedExtensions when it could NOT decrypt our ECH. Only
    /// captured when we offered ECH and the server rejected it — the EE (and thus
    /// the retry_configs) is then authenticated by the public_name certificate, so
    /// the caller may safely adopt these for the NEXT connection. Null otherwise.
    ech_retry_configs: ?[]u8 = null,

    selected_suite: ?CipherSuite = null,
    selected_alpn: ?[]const u8 = null,
    /// Owned storage for `selected_alpn`: the negotiated protocol is read from the
    /// EncryptedExtensions body in `hs_plain`, which is consumed after the message,
    /// so the borrowed slice would dangle for any post-handshake reader. Copy it.
    selected_alpn_buf: [256]u8 = undefined,
    leaf_key: ?LeafPublicKey = null,
    /// Owned storage for the leaf RSA key's modulus/exponent. The parsed key
    /// borrows the certificate SPKI bytes, which live in `hs_plain` and are
    /// consumed (shifted) after the Certificate message — so an RSA key would
    /// dangle by the time the server CertificateVerify is verified. We copy
    /// n/e here and re-point the key. (EC/Ed25519 keys are value types.)
    leaf_rsa_n: [rsa_verify.max_bytes]u8 = undefined,
    leaf_rsa_e: [16]u8 = undefined,
    last_alert: ?tls_alert.Alert = null,

    /// HelloRetryRequest state. `hrr_seen` guards against a second HRR (fatal per
    /// RFC 8446). `cookie` (when present) is echoed in the second ClientHello;
    /// it borrows `cookie_buf` (copied out of the consumed record). `retry_hello`
    /// holds the second ClientHello bytes to send, owned until `feed` returns them.
    hrr_seen: bool = false,
    cookie: ?[]const u8 = null,
    cookie_buf: [512]u8 = undefined,
    /// Cipher suite the HelloRetryRequest committed to. RFC 8446 §4.1.4: the
    /// subsequent ServerHello MUST carry the same suite — enforced in
    /// parseServerHello (the transcript hash alone would not catch a swap
    /// between two suites that share a hash, e.g. 0x1301 ↔ 0x1303).
    hrr_suite: ?CipherSuite = null,
    retry_hello: ?[]u8 = null,
    /// Group a HelloRetryRequest asked us to retry with. When set, the second
    /// ClientHello offers exactly one key_share — for this group (RFC 8446
    /// §4.1.2). Null on the first ClientHello.
    retry_key_share_group: ?supported_groups.NamedGroup = null,

    /// Post-handshake records the client must send back (a KeyUpdate response
    /// when the peer requested one). Drained by the caller via `takePendingSend`.
    post_handshake_send: std.ArrayList(u8) = .empty,

    // --- Test-only client-certificate support (mutual TLS) ---
    // Existing behavior is fully preserved when no client cert is configured:
    // an incoming CertificateRequest is otherwise ignored and no client
    // Certificate/CertificateVerify is ever sent. These are exercised only by
    // the tls_server mTLS loopback tests, never by the production HTTPS path.
    /// Set true once the server's CertificateRequest is seen.
    cert_requested: bool = false,
    /// RFC 7250: opt-in offer that this test client can present a raw public key
    /// as its client certificate. Default false keeps ClientHello byte-identical.
    offer_client_raw_public_key: bool = false,
    /// Certificate type selected by the server's CertificateRequest. Defaults to
    /// X.509 (absence of `client_certificate_type` means X.509).
    client_cert_type: tls_extension.CertificateType = .x509,
    /// RFC 8879 diagnostic: set true when the server's certificate arrived as a
    /// CompressedCertificate that we inflated (rather than a plain Certificate).
    received_compressed_cert: bool = false,
    /// Borrowed client certificate data to present, or null to present an empty
    /// Certificate (decline). This is DER X.509 unless `client_cert_type` is
    /// RawPublicKey, in which case it is DER SubjectPublicKeyInfo.
    client_cert_der: ?[]const u8 = null,
    /// Key pair matching `client_cert_der`'s SPKI, used to sign the client
    /// CertificateVerify (Ed25519 or ECDSA P-256).
    client_key_pair: ?ClientCertKey = null,
    /// RFC 8879: when true, advertise `compress_certificate` (zlib) and decode a
    /// server's CompressedCertificate. Default false ⇒ the ClientHello is
    /// byte-identical and no compressed-cert decode path is reachable, keeping
    /// the outbound (ACME) TLS surface unchanged until explicitly opted in —
    /// symmetric with the server's `enable_cert_compression`.
    offer_cert_compression: bool = false,
    /// RFC 9345: when true, advertise `delegated_credential` (type 34) and, if the
    /// server presents a DC in its leaf CertificateEntry, verify it and bind the
    /// handshake's CertificateVerify to the DC's public key. Default false ⇒ the
    /// ClientHello is byte-identical and any server-sent DC is ignored (normal
    /// cert-key CertificateVerify path), keeping the outbound TLS surface
    /// unchanged until explicitly opted in.
    offer_delegated_credential: bool = false,
    /// A validated delegated credential's public key (RFC 9345). When set, the
    /// server CertificateVerify is verified with THIS key instead of the leaf
    /// certificate's key. Populated by `verifyDelegatedCredential` only after the
    /// DC's own signature (made by the leaf key), its DelegationUsage, and its
    /// validity window all pass.
    dc_verified_key: ?LeafPublicKey = null,
    /// The DC's `dc_cert_verify_algorithm`; CertificateVerify.algorithm MUST equal
    /// it (RFC 9345 §4). Only meaningful when `dc_verified_key` is set.
    dc_expected_scheme: ?u16 = null,
    /// Owned storage for a DC RSA key's modulus/exponent — the DC's SPKI bytes
    /// live in the consumed handshake buffer, so an RSA DC key would dangle by
    /// CertificateVerify time (mirrors `leaf_rsa_n`/`leaf_rsa_e`). EC/Ed25519 DC
    /// keys are value types and need no copy.
    dc_rsa_n: [rsa_verify.max_bytes]u8 = undefined,
    dc_rsa_e: [16]u8 = undefined,
    /// When true, the server certificate's chain-to-trust-anchor and DNS-name
    /// checks are skipped (the leaf key is still parsed so the server
    /// CertificateVerify signature is verified). Used only by the tls_server
    /// mTLS loopback tests, whose x509_selfsign leaves carry a CN but no SAN.
    skip_cert_verify_for_test: bool = false,
    /// Test-only: offer secp256r1 as the sole key-exchange group, so the server's
    /// P-256 fallback path can be exercised over the loopback.
    force_p256_only_for_test: bool = false,
    /// Test-only: offer X25519MLKEM768 as the sole key-exchange group, so the
    /// post-quantum hybrid encaps/decaps path is exercised over the loopback (the
    /// server otherwise prefers classical x25519).
    force_hybrid_only_for_test: bool = false,
    /// Test-only: advertise the full supported_groups but send an EMPTY key_share
    /// list, forcing the server to answer with a HelloRetryRequest. The client
    /// then retries with exactly the requested group's share.
    force_no_shares_for_test: bool = false,
    /// Test-only: offer TLS_AES_256_GCM_SHA384 as the sole cipher suite, so the
    /// SHA-384 key schedule is exercised end-to-end over the loopback.
    force_aes256_only_for_test: bool = false,

    /// Optional PSK resumption offer loaded from a serialized session ticket.
    resume_offer: ?ResumeOffer = null,
    /// True when the server echoes `pre_shared_key(selected_identity = 0)` in
    /// ServerHello and the certificate-auth flight is therefore omitted.
    psk_accepted: bool = false,
    /// Caller-owned 0-RTT payload copied by `setEarlyData`, or null when this
    /// resumption attempt is a normal 1-RTT PSK-DHE handshake.
    early_data: ?[]u8 = null,
    /// Null until EncryptedExtensions is processed, then the server's decision
    /// for this ClientHello's `early_data` offer.
    early_data_accepted: ?bool = null,
    /// Latest captured serialized session ticket. Ownership transfers through
    /// `takeSessionTicket`.
    captured_session_ticket: ?[]u8 = null,

    transcript: std.ArrayList(u8) = .empty,
    recv_buf: std.ArrayList(u8) = .empty,
    hs_plain: std.ArrayList(u8) = .empty,
    /// Count of unencrypted change_cipher_spec records the peer has sent, over
    /// the whole connection. Unbounded, this is a channel a hostile (or
    /// MITM-substituted) server can use to stall an outbound handshake
    /// indefinitely — which for the ACME client means a certificate renewal that
    /// never completes. See `tls_record.max_change_cipher_spec_records`.
    ccs_records_seen: usize = 0,

    // Traffic secrets are stored at the maximum hash length (SHA-384); only the
    // first `selected_suite.hashLen()` bytes are live for a given connection.
    early_secret: [max_hash_len]u8 = @splat(0),
    handshake_secret: [max_hash_len]u8 = @splat(0),
    master_secret: [max_hash_len]u8 = @splat(0),
    exporter_master_secret: [max_hash_len]u8 = @splat(0),
    exporter_master_secret_ready: bool = false,
    resumption_master_secret: [max_hash_len]u8 = @splat(0),
    client_hs_secret: [max_hash_len]u8 = @splat(0),
    server_hs_secret: [max_hash_len]u8 = @splat(0),
    client_app_secret: [max_hash_len]u8 = @splat(0),
    server_app_secret: [max_hash_len]u8 = @splat(0),
    client_hs_keys: TrafficKeys = .{},
    server_hs_keys: TrafficKeys = .{},
    client_early_keys: TrafficKeys = .{},
    client_app_keys: TrafficKeys = .{},
    server_app_keys: TrafficKeys = .{},
    hs_read_seq: u64 = 0,
    hs_write_seq: u64 = 0,
    early_write_seq: u64 = 0,
    app_read_seq: u64 = 0,
    app_write_seq: u64 = 0,
    /// RFC 8449 record_size_limit advertised by the server (max TLSInnerPlaintext
    /// it accepts). Default 2^14+1 = unrestricted; outbound records are fragmented
    /// to honor a smaller value.
    peer_record_size_limit: usize = tls_record.max_plaintext_len + 1,
    /// RFC 7250: whether this client offered raw public keys (copied from
    /// `Options` at init). Gates both the ClientHello offer and whether a
    /// `server_certificate_type` response is even permitted in EncryptedExtensions.
    offer_raw_public_key: bool = false,
    /// The certificate type the server selected via `server_certificate_type`.
    /// Defaults to `.x509` (RFC 8446/7250: absence means X.509), so the normal,
    /// fully trust-verified chain path runs unless the server explicitly picks
    /// `.raw_public_key` after we offered it.
    server_cert_type: tls_extension.CertificateType = .x509,

    pub fn init(allocator: Allocator, options: Options) Error!Client {
        if (options.server_name.len == 0) return error.BadHandshake;
        var seed: [kx.X25519Kx.seed_len]u8 = undefined;
        try osEntropy(&seed);
        var hy_seed: [kx.HybridKx.seed_len]u8 = undefined;
        try osEntropy(&hy_seed);
        defer secureZero(&hy_seed);
        var session_id: [32]u8 = undefined;
        try osEntropy(&session_id);
        var random: [32]u8 = undefined;
        try osEntropy(&random);
        var ech_inner_random: [32]u8 = undefined;
        try osEntropy(&ech_inner_random);

        const name = try allocator.dupe(u8, options.server_name);
        errdefer allocator.free(name);
        const anchors = try allocator.dupe([]const u8, options.trust_anchors);
        errdefer allocator.free(anchors);
        const alpn = try allocator.dupe([]const u8, options.alpn_protocols);
        errdefer allocator.free(alpn);
        const crl_owned = if (options.crl) |c| try allocator.dupe(u8, c) else null;
        errdefer if (crl_owned) |c| allocator.free(c);
        const ech_list_owned = if (options.ech_config_list) |e| try allocator.dupe(u8, e) else null;
        errdefer if (ech_list_owned) |e| allocator.free(e);
        const cert_sig_owned = if (options.cert_signature_schemes) |s|
            try allocator.dupe(tls_signature_scheme.SignatureScheme, s)
        else
            null;
        errdefer if (cert_sig_owned) |s| allocator.free(s);
        const ct_logs_owned = try dupeCtLogs(allocator, options.ct_logs);
        errdefer freeCtLogs(allocator, ct_logs_owned);

        return .{
            .allocator = allocator,
            .server_name = name,
            .trust_anchors = anchors,
            .alpn_protocols = alpn,
            .crl = crl_owned,
            .ech_config_list = ech_list_owned,
            .cert_signature_schemes = cert_sig_owned,
            .ech_inner_random = ech_inner_random,
            .ct_logs = ct_logs_owned,
            .enforce_sct = options.enforce_sct,
            .require_sct = options.require_sct,
            .verify_time = options.now_unix_seconds,
            .offer_raw_public_key = options.offer_raw_public_key,
            .x25519_pair = try kx.X25519Kx.generateDeterministic(seed),
            .p256_pair = try ecdh_p256.generate(),
            .hybrid_pair = try kx.HybridKx.generateDeterministic(hy_seed),
            .legacy_session_id = session_id,
            .client_random = random,
        };
    }

    pub fn deinit(self: *Client) void {
        self.x25519_pair.wipe();
        self.hybrid_pair.wipe();
        secureZero(&self.p256_pair.secret);
        secureZero(&self.legacy_session_id);
        secureZero(&self.early_secret);
        secureZero(&self.handshake_secret);
        secureZero(&self.master_secret);
        secureZero(&self.exporter_master_secret);
        secureZero(&self.resumption_master_secret);
        secureZero(&self.client_hs_secret);
        secureZero(&self.server_hs_secret);
        secureZero(&self.client_app_secret);
        secureZero(&self.server_app_secret);
        self.client_hs_keys.wipe();
        self.server_hs_keys.wipe();
        self.client_early_keys.wipe();
        self.client_app_keys.wipe();
        self.server_app_keys.wipe();
        self.transcript.deinit(self.allocator);
        self.recv_buf.deinit(self.allocator);
        self.hs_plain.deinit(self.allocator);
        self.post_handshake_send.deinit(self.allocator);
        if (self.early_data) |data| self.allocator.free(data);
        if (self.retry_hello) |r| self.allocator.free(r);
        if (self.resume_offer) |*offer| offer.wipe(self.allocator);
        if (self.captured_session_ticket) |ticket| self.allocator.free(ticket);
        self.allocator.free(self.server_name);
        self.allocator.free(self.trust_anchors);
        self.allocator.free(self.alpn_protocols);
        if (self.crl) |c| self.allocator.free(c);
        if (self.cert_signature_schemes) |s| self.allocator.free(s);
        secureZero(&self.ech_inner_random);
        if (self.ech_config_list) |e| self.allocator.free(e);
        if (self.ech_public_name) |p| self.allocator.free(p);
        if (self.ech_inner_hello) |h| self.allocator.free(h);
        if (self.ech_retry_configs) |r| self.allocator.free(r);
        freeCtLogs(self.allocator, self.ct_logs);
        self.* = undefined;
    }

    pub fn start(self: *Client) Error![]u8 {
        if (self.state != .idle) return error.BadState;
        var handshake: std.ArrayList(u8) = .empty;
        defer handshake.deinit(self.allocator);
        if (try self.prepareEch()) {
            // ECH active: `handshake` becomes the ClientHelloOuter (SNI =
            // public_name) with the sealed ClientHelloInner inside; the outer is
            // what enters the transcript until/unless the server confirms
            // acceptance (then the transcript switches to the inner).
            try self.writeClientHelloOuterEch(&handshake);
        } else {
            try self.writeClientHello(&handshake);
        }
        try self.appendTranscript(handshake.items);
        self.state = .wait_server_hello;
        const ch_record = try writePlainRecord(self.allocator, .handshake, handshake.items);
        if (self.early_data == null) return ch_record;
        defer self.allocator.free(ch_record);

        try self.deriveClientEarlyTrafficKeys();
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        try out.appendSlice(self.allocator, ch_record);

        const early = self.early_data.?;
        const early_record = try sealRecordAlloc(
            self.allocator,
            self.resume_offer.?.suite,
            &self.client_early_keys,
            self.early_write_seq,
            .application_data,
            early,
        );
        defer self.allocator.free(early_record);
        self.early_write_seq += 1;
        try out.appendSlice(self.allocator, early_record);

        var eoed: std.ArrayList(u8) = .empty;
        defer eoed.deinit(self.allocator);
        try writeHandshake(self.allocator, &eoed, .end_of_early_data, "");
        const eoed_record = try sealRecordAlloc(
            self.allocator,
            self.resume_offer.?.suite,
            &self.client_early_keys,
            self.early_write_seq,
            .handshake,
            eoed.items,
        );
        defer self.allocator.free(eoed_record);
        self.early_write_seq += 1;
        try out.appendSlice(self.allocator, eoed_record);
        return out.toOwnedSlice(self.allocator);
    }

    pub fn feed(self: *Client, received: []const u8) Error!FeedResult {
        if (self.state == .idle or self.state == .connected) return error.BadState;
        try self.recv_buf.appendSlice(self.allocator, received);

        if (self.state == .wait_server_hello) {
            switch (try self.tryConsumeServerHello()) {
                .need_more => return .need_more,
                .retry => {
                    // Send ClientHello2; keep waiting for the real ServerHello.
                    const reply = self.retry_hello.?;
                    self.retry_hello = null;
                    return .{ .bytes_to_send = reply };
                },
                .proceed => {},
            }
        }

        if (try self.tryConsumeServerFlight()) |reply| {
            return .{ .bytes_to_send = reply };
        }
        return .need_more;
    }

    pub fn handshakeDone(self: *const Client) bool {
        return self.state == .connected;
    }

    /// True when this handshake offered Encrypted Client Hello (a usable
    /// ECHConfig was found in `start()`).
    pub fn echOffered(self: *const Client) bool {
        return self.ech_active;
    }

    /// The server's ECH decision, available once ServerHello is processed:
    /// `true` = accepted (the real inner SNI is authenticated), `false` =
    /// rejected (only the cover `public_name` is authenticated — the caller must
    /// treat the inner ClientHello as not delivered and should not send inner
    /// application data over this connection). Null before ServerHello, or when
    /// ECH was never offered.
    pub fn echAccepted(self: *const Client) ?bool {
        return self.ech_accepted;
    }

    /// The `retry_configs` ECHConfigList the server offered after rejecting our
    /// ECH (draft-ietf-tls-esni §7.1), or null if none. Present only when ECH was
    /// offered AND rejected — the bytes are authenticated by the public_name
    /// certificate this handshake validated. A caller may persist them and pass
    /// them as `ech_config_list` on the next connection to recover from a stale
    /// config. Borrowed from the client; copy before `deinit`.
    pub fn echRetryConfigs(self: *const Client) ?[]const u8 {
        return self.ech_retry_configs;
    }

    /// RFC 8446 section 7.5 TLS exporter. Valid only after the handshake
    /// reaches connected state.
    pub fn exportKeyingMaterial(self: *const Client, label: []const u8, context: []const u8, out: []u8) Error!void {
        if (self.state != .connected) return error.BadState;
        if (!self.exporter_master_secret_ready) return error.BadState;
        switch (self.hashAlg()) {
            .sha256 => try self.exportKeyingMaterialT(Sha256, label, context, out),
            .sha384 => try self.exportKeyingMaterialT(Sha384, label, context, out),
        }
    }

    /// RFC 9266 tls-exporter channel binding for SCRAM-SHA-*-PLUS.
    pub fn channelBindingTlsExporter(self: *const Client, out: *[32]u8) Error!void {
        try self.exportKeyingMaterial("EXPORTER-Channel-Binding", "", out[0..]);
    }

    /// Load a serialized TLS 1.3 session ticket previously returned by
    /// `takeSessionTicket`. `ticket_age_ms` is the caller's elapsed wall-clock
    /// age for the ticket and is folded into `obfuscated_ticket_age`.
    pub fn setSessionTicket(self: *Client, serialized: []const u8, ticket_age_ms: u64) Error!void {
        const decoded = try tls_resumption.decodeStoredSession(serialized);
        const suite = try CipherSuite.fromWire(decoded.suite);
        if (decoded.psk.len != suite.hashLen()) return error.BadSession;
        if (self.resume_offer) |*old| {
            old.wipe(self.allocator);
            self.resume_offer = null;
        }
        const ticket = try self.allocator.dupe(u8, decoded.ticket);
        errdefer self.allocator.free(ticket);
        var psk: [max_hash_len]u8 = @splat(0);
        @memcpy(psk[0..decoded.psk.len], decoded.psk);
        self.resume_offer = .{
            .ticket = ticket,
            .ticket_age_add = decoded.ticket_age_add,
            .ticket_lifetime = decoded.ticket_lifetime,
            .ticket_age_ms = ticket_age_ms,
            .suite = suite,
            .psk = psk,
            .psk_len = decoded.psk.len,
            .max_early_data_size = decoded.max_early_data_size,
        };
    }

    /// Queue TLS 1.3 0-RTT early application data for the next `start()`.
    ///
    /// This is deliberately opt-in: it is valid only before the handshake
    /// starts, only when a resumption session with a non-zero
    /// `max_early_data_size` is loaded, and only when `bytes` fits that limit.
    /// Anti-replay policy is not enforced in this socketless TLS module; callers
    /// must layer single-use tickets or a replay cache above it before sending
    /// non-idempotent data.
    pub fn setEarlyData(self: *Client, bytes: []const u8) Error!void {
        if (self.state != .idle) return error.BadState;
        const offer = self.resume_offer orelse return error.BadState;
        if (offer.max_early_data_size == 0 or bytes.len > offer.max_early_data_size) return error.BadHandshake;
        const copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(copy);
        if (self.early_data) |old| self.allocator.free(old);
        self.early_data = copy;
        self.early_data_accepted = null;
    }

    /// Return the server's 0-RTT decision after EncryptedExtensions is parsed.
    /// Null means this handshake has not reached EncryptedExtensions yet.
    pub fn earlyDataAccepted(self: *const Client) ?bool {
        return self.early_data_accepted;
    }

    /// Take ownership of the newest captured resumable session ticket, if a
    /// post-handshake NewSessionTicket has been received and parsed.
    pub fn takeSessionTicket(self: *Client) ?[]u8 {
        const ticket = self.captured_session_ticket orelse return null;
        self.captured_session_ticket = null;
        return ticket;
    }

    /// Test-only: configure a client certificate to present in response to a
    /// server CertificateRequest. `der` and `key_pair` are borrowed. Without
    /// this call (or `declineClientCertForTest`) the client never sends a
    /// client Certificate, preserving the production server-only-auth path.
    pub fn setClientCertForTest(self: *Client, der: []const u8, key_pair: sign.KeyPair) void {
        self.client_cert_der = der;
        self.client_key_pair = .{ .ed25519 = key_pair };
    }

    /// Test-only: present a bare DER SubjectPublicKeyInfo as the client
    /// certificate when the server selects RFC 7250 RawPublicKey.
    pub fn setClientRawPublicKeyForTest(self: *Client, spki_der: []const u8, key_pair: sign.KeyPair) void {
        self.client_cert_der = spki_der;
        self.client_key_pair = .{ .ed25519 = key_pair };
        self.offer_client_raw_public_key = true;
    }

    /// Test-only: like `setClientCertForTest` but for an ECDSA P-256 client
    /// certificate; CertificateVerify is signed with ecdsa_secp256r1_sha256.
    pub fn setClientCertEcdsaP256ForTest(self: *Client, der: []const u8, key_pair: ecdsa_p256.KeyPair) void {
        self.client_cert_der = der;
        self.client_key_pair = .{ .ecdsa_p256 = key_pair };
    }

    /// Test-only: like `setClientCertForTest` but for an RSA client certificate;
    /// CertificateVerify is signed with rsa_pss_rsae_sha256 (TLS 1.3's only
    /// RSA scheme). `der` and `key` are borrowed.
    pub fn setClientCertRsaForTest(self: *Client, der: []const u8, key: rsa_sign.PrivateKey) void {
        self.client_cert_der = der;
        self.client_key_pair = .{ .rsa = key };
    }

    /// Test-only: respond to a server CertificateRequest with an empty
    /// Certificate (decline client auth). The client still completes the
    /// handshake; no CertificateVerify is sent. This is the default behavior
    /// when no client cert is configured; the explicit call documents intent.
    pub fn declineClientCertForTest(self: *Client) void {
        self.client_cert_der = null;
        self.client_key_pair = null;
    }

    /// Test-only: skip the server-certificate chain and DNS-name checks. The
    /// leaf public key is still parsed and the server CertificateVerify is
    /// still verified. Lets the mTLS loopback use CN-only self-signed leaves.
    pub fn skipServerCertVerifyForTest(self: *Client) void {
        self.skip_cert_verify_for_test = true;
    }

    /// Test-only: offer secp256r1 as the sole supported group + key share.
    pub fn offerOnlyP256ForTest(self: *Client) void {
        self.force_p256_only_for_test = true;
    }

    /// Test-only: offer X25519MLKEM768 as the sole supported group + key share.
    pub fn offerOnlyHybridForTest(self: *Client) void {
        self.force_hybrid_only_for_test = true;
    }

    /// Test-only: offer TLS_AES_256_GCM_SHA384 as the sole cipher suite.
    pub fn offerOnlyAes256ForTest(self: *Client) void {
        self.force_aes256_only_for_test = true;
    }

    /// Test-only: advertise the full group set but send no key_shares, forcing the
    /// server to respond with a HelloRetryRequest.
    pub fn offerNoSharesForTest(self: *Client) void {
        self.force_no_shares_for_test = true;
    }

    /// Opt into RFC 8879 certificate compression: advertise `compress_certificate`
    /// (zlib) and decode a server's CompressedCertificate under the bomb guard.
    pub fn offerCertCompression(self: *Client) void {
        self.offer_cert_compression = true;
    }

    /// Opt into RFC 9345 delegated credentials: advertise the `delegated_credential`
    /// extension and, when the server presents a DC in its leaf CertificateEntry,
    /// verify it (leaf-key signature, DelegationUsage, validity window) and bind
    /// CertificateVerify to the DC key. A trustworthy clock (`Options.now_unix_seconds`)
    /// is required to accept a DC — without one the DC is rejected, not trusted.
    pub fn offerDelegatedCredentials(self: *Client) void {
        self.offer_delegated_credential = true;
    }

    /// Test-only: emit a post-handshake KeyUpdate — a TLS 1.3 *control* record
    /// (inner content_type = handshake). Drain it via `takePendingSend`. Used to
    /// exercise how a kTLS-RX peer surfaces a non-application-data record.
    pub fn sendKeyUpdateForTest(self: *Client) Error!void {
        try self.sendKeyUpdate(.not_requested);
    }

    /// Groups this client can complete a key exchange for. Kept in sync with the
    /// supported_groups advertisement and the key_share builder in writeClientHello.
    fn supportsGroup(self: *const Client, g: supported_groups.NamedGroup) bool {
        _ = self;
        return switch (g) {
            .x25519, .secp256r1, .x25519mlkem768 => true,
            else => false,
        };
    }

    /// Whether ClientHello1 already carried a key_share for `g` — an HRR asking us
    /// to retry with a group we already shared changes nothing and is illegal.
    fn offeredShareFor(self: *const Client, g: supported_groups.NamedGroup) bool {
        if (self.force_no_shares_for_test) return false;
        if (self.force_p256_only_for_test) return g == .secp256r1;
        if (self.force_hybrid_only_for_test) return g == .x25519mlkem768;
        return switch (g) {
            .x25519, .secp256r1, .x25519mlkem768 => true,
            else => false,
        };
    }

    /// Raw (still-encrypted) record bytes received but not consumed by the
    /// handshake driver. After `handshakeDone()`, a one-shot caller should frame
    /// and `decryptApp` these *before* reading further from the socket, since a
    /// server may flush post-handshake records in the same segment as Finished.
    pub fn pendingBytes(self: *const Client) []const u8 {
        return self.recv_buf.items;
    }

    pub fn encrypt(self: *Client, appdata: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const limit = tls_record.recordContentLimit(self.peer_record_size_limit);
        if (appdata.len <= limit) {
            const out = try sealRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_write_seq, .application_data, appdata);
            self.app_write_seq += 1;
            return out;
        }
        // RFC 8449: fragment application data to the server's smaller record limit,
        // one record per fragment, concatenated (seq bumped per record).
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(self.allocator);
        var off: usize = 0;
        while (off < appdata.len) {
            const n = @min(limit, appdata.len - off);
            const rec = try sealRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_write_seq, .application_data, appdata[off .. off + n]);
            defer self.allocator.free(rec);
            try buf.appendSlice(self.allocator, rec);
            self.app_write_seq += 1;
            off += n;
        }
        return buf.toOwnedSlice(self.allocator);
    }

    pub fn decrypt(self: *Client, record: []const u8) Error![]u8 {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_read_seq, record);
        self.app_read_seq += 1;
        errdefer self.allocator.free(opened.content);
        if (opened.content_type == .alert) {
            self.last_alert = try tls_alert.parse(opened.content);
            return error.TlsAlert;
        }
        if (opened.content_type == .handshake) {
            // On error the function-scoped errdefer frees opened.content; on
            // success free it here (no application bytes to return).
            try self.handlePostHandshake(opened.content);
            self.allocator.free(opened.content);
            return self.allocator.alloc(u8, 0);
        }
        if (opened.content_type != .application_data) return error.BadRecord;
        return opened.content;
    }

    /// Post-handshake-aware read of one decrypted record. Returns the decrypted
    /// application bytes, or `.control` for post-handshake handshake records
    /// (NewSessionTicket is ignored; a KeyUpdate rotates the server→client keys
    /// and, when the peer set update_requested, queues our own KeyUpdate reply in
    /// `post_handshake_send` — flush it with `takePendingSend`). Alerts raise
    /// `error.TlsAlert`.
    pub fn decryptApp(self: *Client, record: []const u8) Error!AppRead {
        if (self.state != .connected) return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        const opened = try openRecordAlloc(self.allocator, suite, &self.server_app_keys, self.app_read_seq, record);
        self.app_read_seq += 1;
        switch (opened.content_type) {
            .application_data => return .{ .application_data = opened.content },
            .alert => {
                defer self.allocator.free(opened.content);
                self.last_alert = try tls_alert.parse(opened.content);
                return error.TlsAlert;
            },
            .handshake => {
                defer self.allocator.free(opened.content);
                try self.handlePostHandshake(opened.content);
                return .control;
            },
            else => {
                self.allocator.free(opened.content);
                return error.BadRecord;
            },
        }
    }

    /// Take ownership of any queued post-handshake bytes the caller must write to
    /// the socket (currently a KeyUpdate reply). Returns null when nothing is
    /// queued; otherwise the caller owns and must free the returned slice.
    pub fn takePendingSend(self: *Client) Error!?[]u8 {
        if (self.post_handshake_send.items.len == 0) return null;
        return try self.post_handshake_send.toOwnedSlice(self.allocator);
    }

    /// Process a decrypted post-handshake handshake fragment. NewSessionTicket
    /// is captured for resumption; a KeyUpdate rotates the server→client
    /// application keys and, when the peer requested an update, queues our own
    /// KeyUpdate(update_not_requested) reply and rotates the client→server keys
    /// (RFC 8446 §4.6.3). The fragment may carry more than one handshake
    /// message. FAIL-CLOSED: a zero-length fragment (prohibited, RFC 8446 §5.1),
    /// any other handshake type (unexpected_message — we never advertise
    /// post_handshake_auth, so even CertificateRequest is illegal here), or
    /// trailing partial bytes (this engine performs no cross-record
    /// post-handshake reassembly, so they would otherwise be silently lost) all
    /// abort the connection, as does a record coalescing more than
    /// `max_post_handshake_msgs_per_record` messages (KeyUpdate/ticket flood).
    fn handlePostHandshake(self: *Client, fragment: []const u8) Error!void {
        if (fragment.len == 0) return error.BadHandshake;
        var off: usize = 0;
        var seen: usize = 0;
        while (parseHandshakeMaybe(fragment, &off)) |msg| {
            seen += 1;
            if (seen > max_post_handshake_msgs_per_record) return error.BadHandshake;
            if (msg.typ == .key_update) {
                if (msg.body.len != 1) return error.BadHandshake;
                const request = msg.body[0];
                if (request != @intFromEnum(KeyUpdateRequest.not_requested) and
                    request != @intFromEnum(KeyUpdateRequest.requested))
                {
                    return error.BadHandshake;
                }
                // Rotate the receive (server) application traffic secret + keys.
                try self.applyKeyUpdate(&self.server_app_secret, &self.server_app_keys);
                self.app_read_seq = 0;
                if (request == @intFromEnum(KeyUpdateRequest.requested)) {
                    try self.sendKeyUpdate(.not_requested);
                }
            } else if (msg.typ == .new_session_ticket) {
                try self.captureNewSessionTicket(msg.body);
            } else {
                // RFC 8446 §5.1: any other handshake type after the handshake
                // is unexpected_message — fatal, never silently skipped.
                return error.BadHandshake;
            }
        }
        if (off != fragment.len) return error.BadHandshake;
    }

    fn captureNewSessionTicket(self: *Client, body: []const u8) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        const ticket = try tls_session_ticket.parse(body);
        if (ticket.ticket.len == 0 or ticket.ticket_lifetime == 0) return;
        const max_early_data_size = try parseTicketEarlyDataLimit(ticket.extensions);

        var psk: [max_hash_len]u8 = undefined;
        const psk_len = switch (self.hashAlg()) {
            .sha256 => try self.deriveTicketPskT(Sha256, ticket.ticket_nonce, &psk),
            .sha384 => try self.deriveTicketPskT(Sha384, ticket.ticket_nonce, &psk),
        };
        const serialized = try tls_resumption.encodeStoredSession(self.allocator, .{
            .suite = @intFromEnum(suite),
            .ticket_lifetime = ticket.ticket_lifetime,
            .ticket_age_add = ticket.ticket_age_add,
            .ticket = ticket.ticket,
            .psk = psk[0..psk_len],
            .max_early_data_size = max_early_data_size,
        });
        secureZero(psk[0..psk_len]);
        if (self.captured_session_ticket) |old| self.allocator.free(old);
        self.captured_session_ticket = serialized;
    }

    fn deriveTicketPskT(self: *Client, comptime KS: type, ticket_nonce: []const u8, out: *[max_hash_len]u8) Error!usize {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.resumption_master_secret[0..KS.hash_len]);
        var rms = KS.SecretBytes.init(sk);
        defer rms.wipe();
        try KS.hkdfExpandLabel(&rms, "resumption", ticket_nonce, out[0..KS.hash_len]);
        return KS.hash_len;
    }

    /// Emit a KeyUpdate of our own (encrypted under the *current* send keys),
    /// queue it for the caller, then rotate the client→server application keys so
    /// the next application record uses the new keys (RFC 8446 §4.6.3).
    fn sendKeyUpdate(self: *Client, request: KeyUpdateRequest) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .key_update, &[_]u8{@intFromEnum(request)});
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_app_keys, self.app_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.app_write_seq += 1;
        try self.post_handshake_send.appendSlice(self.allocator, record);
        try self.applyKeyUpdate(&self.client_app_secret, &self.client_app_keys);
        self.app_write_seq = 0;
    }

    /// In-place KeyUpdate of one traffic secret: secret' =
    /// HKDF-Expand-Label(secret, "traffic upd", "", Hash.length); re-derive keys.
    fn applyKeyUpdate(self: *Client, secret: *[max_hash_len]u8, keys: *TrafficKeys) Error!void {
        const suite = self.selected_suite orelse return error.BadState;
        switch (self.hashAlg()) {
            .sha256 => try applyKeyUpdateT(Sha256, suite, secret, keys),
            .sha384 => try applyKeyUpdateT(Sha384, suite, secret, keys),
        }
    }

    // -----------------------------------------------------------------------
    // Encrypted Client Hello (ECH) — client, roadmap 5.1.
    //
    // Wire-model: draft-ietf-tls-esni §5. ClientHelloInner carries the real SNI;
    // it is HPKE-sealed and placed in the outer `encrypted_client_hello`
    // extension of a ClientHelloOuter whose SNI is the config's `public_name`.
    // The seal is bound to the ClientHelloOuterAAD (the outer with the ECH
    // payload zeroed). Outer-extension compression (`ech_outer_extensions`) is
    // deliberately omitted — the inner carries the full extension set — so the
    // ClientHelloOuter is larger than a compressing client would send. That is a
    // size/privacy trade-off, not a correctness one, and is a noted follow-up.
    // -----------------------------------------------------------------------

    /// Constant-time byte compare (equal length assumed by callers). Used for the
    /// ECH acceptance signal, which is derived from public transcript material —
    /// CT is hygiene, not a hard secrecy requirement.
    fn ctBytesEqual(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        var diff: u8 = 0;
        for (a, b) |x, y| diff |= x ^ y;
        return diff == 0;
    }

    /// The name whose certificate must validate: the real inner name when ECH was
    /// accepted (or not offered), else the cover `public_name` (ECH rejected —
    /// the client authenticates the client-facing server).
    fn effectiveVerifyName(self: *const Client) []const u8 {
        if (self.ech_active) {
            if (self.ech_accepted orelse false) return self.server_name;
            // Rejected ⇒ authenticate the cover name. `orelse` is defensive: the
            // ech_active ⇒ ech_public_name-set invariant already guarantees it.
            return self.ech_public_name orelse self.server_name;
        }
        return self.server_name;
    }

    /// Decide whether to offer ECH this handshake; latch the selected config and
    /// an owned copy of its `public_name` on success. Returns true iff ECH is
    /// active. FAIL-SAFE (RFC-appropriate for a DNS/config-sourced list): ANY
    /// reason not to offer ECH — no list, a *malformed* list, no supported/
    /// sealable config, or a resumption / 0-RTT offer whose ECH interaction is
    /// deferred — yields false and a byte-identical ClientHello. An unusable
    /// ECHConfigList must never abort the connection; the client just proceeds
    /// without ECH.
    fn prepareEch(self: *Client) Error!bool {
        if (self.ech_active) return true; // idempotent: never re-select / re-dupe
        const list = self.ech_config_list orelse return false;
        if (self.resume_offer != null or self.early_data != null) return false;
        // A malformed list ⇒ stand down (do not propagate the parse error out of
        // start()); a broken ECHConfigList should degrade to plain, not fail.
        const cfg = (ech_config.selectSupported(list, ech.kem_id, ech.kdf_id, ech.aead_id) catch return false) orelse return false;
        // Only offer ECH under a config we can actually seal: our KEM (X25519)
        // needs a 32-byte public key. This guarantees `beginSeal` cannot fail on
        // the selected config, so no ECH error can escape start().
        if (cfg.public_key.len != ech.hpke_public_key_len) return false;
        const public_name = try self.allocator.dupe(u8, cfg.public_name);
        errdefer self.allocator.free(public_name);
        self.ech_selected = cfg;
        self.ech_public_name = public_name;
        self.ech_active = true;
        return true;
    }

    /// Append a ClientHello *body* (legacy_version … extensions, no handshake
    /// header) for the ECH path. `sni`, `session_id`, and `random` differ between
    /// the inner and outer hellos; `ech_ext_data` is the `encrypted_client_hello`
    /// extension body (the 1-byte inner marker, or the serialized outer body).
    /// Mirrors the non-PSK, non-test extension set of `writeClientHello`, so an
    /// accepted ClientHelloInner is a well-formed ordinary ClientHello.
    fn appendEchHelloBody(
        self: *Client,
        body: *std.ArrayList(u8),
        server_name: []const u8,
        session_id: []const u8,
        random: []const u8,
        ech_ext_data: []const u8,
    ) Error!void {
        const a = self.allocator;
        try appendU16(a, body, tls_record.legacy_record_version);
        try body.appendSlice(a, random); // 32 bytes
        try body.append(a, @intCast(session_id.len));
        try body.appendSlice(a, session_id);
        // cipher_suites: aes256, chacha20, aes128 — same order as writeClientHello.
        try appendU16(a, body, 6);
        try appendU16(a, body, @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384));
        try appendU16(a, body, @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256));
        try appendU16(a, body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
        try body.append(a, 1);
        try body.append(a, 0);

        // Extensions built into a heap buffer sized for the (large, hybrid) key
        // share plus the ECH extension. The ECH path is handshake setup, not the
        // hot path, so allocation here is fine.
        const ext_cap = ech_ext_data.len + 8192;
        const ext_buf = try a.alloc(u8, ext_cap);
        defer a.free(ext_buf);
        var eb = try tls_extension.Builder.begin(ext_buf);

        var sni_buf: [512]u8 = undefined;
        const sni_body = try buildSniBody(&sni_buf, server_name);
        try eb.addTyped(.server_name, sni_body);

        var versions_buf: [8]u8 = undefined;
        const versions = try tls_supported_versions.buildClient(&versions_buf, &[_]u16{tls_supported_versions.tls13});
        try eb.addTyped(.supported_versions, versions);

        var groups_buf: [16]u8 = undefined;
        const groups = try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{ .x25519mlkem768, .x25519, .secp256r1 });
        try eb.addTyped(.supported_groups, groups);

        var sigs_buf: [16]u8 = undefined;
        const sigs = try tls_signature_scheme.build(&sigs_buf, &[_]tls_signature_scheme.SignatureScheme{
            .rsa_pss_rsae_sha256,
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .ed25519,
            .rsa_pkcs1_sha256,
        });
        try eb.addTyped(.signature_algorithms, sigs);
        try self.appendCertSigAlgs(&eb);

        var rsl_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &rsl_buf, tls_record.record_size_limit_max, .big);
        try eb.addTyped(.record_size_limit, &rsl_buf);

        var hybrid_share: [kx.HybridKx.mlkem_public_len + kx.X25519Kx.public_len]u8 = undefined;
        const hy_pub = self.hybrid_pair.publicShare();
        @memcpy(hybrid_share[0..kx.HybridKx.mlkem_public_len], &hy_pub.mlkem_public_key);
        @memcpy(hybrid_share[kx.HybridKx.mlkem_public_len..], &hy_pub.x25519_public_key);
        var keyshare_buf: [1400]u8 = undefined;
        // `force_no_shares_for_test` withholds all key_shares (advertising the
        // groups only) so a test can drive the server to a HelloRetryRequest through
        // the ECH path — exercising the ECH×HRR fail-closed abort. Off in production
        // (the default), so the inner/outer bodies stay byte-identical.
        const keyshares = if (self.force_no_shares_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{})
        else
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
                .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key },
                .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
            });
        try eb.addTyped(.key_share, keyshares);

        if (self.alpn_protocols.len != 0) {
            var alpn_buf: [512]u8 = undefined;
            var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
            for (self.alpn_protocols) |proto| try alpn_builder.add(proto);
            const alpn_body = try alpn_builder.finish();
            try eb.addTyped(.alpn, alpn_body);
        }

        try eb.add(ext_status_request, &[_]u8{ 1, 0, 0, 0, 0 });
        // RFC 6962 §3.3: request TLS-delivered SCTs with an EMPTY extension, only
        // when CT is opted in (a pinned log set is configured). Off ⇒ not emitted,
        // so the ClientHello wire is byte-identical to the pre-feature encoding.
        if (self.ct_logs.len != 0) {
            try eb.add(ext_signed_certificate_timestamp, &.{});
        }
        if (self.offer_cert_compression) {
            try eb.addTyped(.compress_certificate, &[_]u8{ 2, 0x00, 0x01 });
        }

        // The encrypted_client_hello extension: inner marker or outer body.
        try eb.add(ech.extension_type, ech_ext_data);

        const extensions = try eb.finish();
        try body.appendSlice(a, extensions);
    }

    /// Build a full ClientHello handshake *message* (with header) for the ECH
    /// path; caller owns the result.
    fn buildEchHelloMessage(
        self: *Client,
        server_name: []const u8,
        session_id: []const u8,
        random: []const u8,
        ech_ext_data: []const u8,
    ) Error![]u8 {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try self.appendEchHelloBody(&body, server_name, session_id, random, ech_ext_data);
        var msg: std.ArrayList(u8) = .empty;
        errdefer msg.deinit(self.allocator);
        try writeHandshake(self.allocator, &msg, .client_hello, body.items);
        return msg.toOwnedSlice(self.allocator);
    }

    /// Build a ClientHelloOuter *body* (SNI = public_name, outer random; the
    /// `ClientHello` structure legacy_version…extensions, WITHOUT the 4-byte
    /// Handshake header) whose `encrypted_client_hello` extension carries `enc`
    /// and `payload`. Used both for the ClientHelloOuterAAD (payload = zeros) and,
    /// wrapped by `writeHandshake`, for the final wire message.
    ///
    /// AAD convention: the ClientHelloOuterAAD is this header-LESS ClientHello
    /// body with the ECH payload zeroed — matching the header-less
    /// EncodedClientHelloInner plaintext (ECH operates at the ClientHello-body
    /// level, draft-ietf-tls-esni §5.2). This is the single point to flip if a
    /// reference ECH server proves the AAD must include the Handshake header.
    fn buildOuterEchBody(
        self: *Client,
        cfg: ech_config.Config,
        enc: []const u8,
        payload: []const u8,
    ) Error![]u8 {
        const a = self.allocator;
        const ech_body = try a.alloc(u8, ech.outerExtBodyLen(enc.len, payload.len));
        defer a.free(ech_body);
        _ = try ech.writeOuterExtBody(ech_body, cfg.config_id, enc, payload);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(a);
        try self.appendEchHelloBody(&body, self.ech_public_name.?, &self.legacy_session_id, &self.client_random, ech_body);
        return body.toOwnedSlice(a);
    }

    /// Assemble the ClientHelloOuter (with the sealed ClientHelloInner inside) and
    /// append it to `out`. Precondition: `prepareEch()` returned true.
    fn writeClientHelloOuterEch(self: *Client, out: *std.ArrayList(u8)) Error!void {
        const a = self.allocator;
        const cfg = self.ech_selected orelse return error.BadState;

        // 1. ClientHelloInner message (real SNI, real session_id, inner marker) —
        //    retained for the transcript switch on acceptance and the confirmation.
        const inner_hello = try self.buildEchHelloMessage(self.server_name, &self.legacy_session_id, &self.ech_inner_random, &ech.inner_ext_body);
        // Freed on any error below; stored (and thus not freed here) on success.
        errdefer a.free(inner_hello);

        // 2. EncodedClientHelloInner = the inner CH *body* with an EMPTY session_id
        //    (reconstructed from the outer by the server) plus §6.1.3 padding.
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(a);
        try self.appendEchHelloBody(&encoded, self.server_name, &.{}, &self.ech_inner_random, &ech.inner_ext_body);
        const pad = ech.paddingLen(encoded.items.len, self.server_name.len, cfg.maximum_name_length);
        try encoded.appendNTimes(a, 0, pad);

        // 3. HPKE sender context; `enc` is known before the AAD is built.
        var eph_seed: [32]u8 = undefined;
        try osEntropy(&eph_seed);
        defer secureZero(&eph_seed);
        var sealer = try ech.beginSeal(a, cfg, eph_seed);
        errdefer sealer.wipe(); // `seal` wipes it on the success path

        // 4. ClientHelloOuterAAD: the header-less outer ClientHello body with a
        //    zeroed payload placeholder of the exact sealed length.
        const payload_len = encoded.items.len + ech.tag_len;
        const zero_payload = try a.alloc(u8, payload_len);
        defer a.free(zero_payload);
        @memset(zero_payload, 0);
        const aad_body = try self.buildOuterEchBody(cfg, &sealer.enc, zero_payload);
        defer a.free(aad_body);

        // 5. Seal the padded encoded inner, authenticating the AAD.
        const payload = try sealer.seal(a, aad_body, encoded.items);
        defer a.free(payload);
        if (payload.len != payload_len) return error.BadHandshake;

        // 6. Final ClientHelloOuter body — identical to the AAD body except the
        //    real payload replaces the zeros — wrapped into the handshake message
        //    and appended to `out`.
        const outer_body = try self.buildOuterEchBody(cfg, &sealer.enc, payload);
        defer a.free(outer_body);
        try writeHandshake(a, out, .client_hello, outer_body);

        // Commit (last statement — no fallible op follows). Free any prior inner
        // hello so a re-entrant start() (e.g. retried after a mid-start OOM) stays
        // free-once; the idempotent `prepareEch` makes this unreachable in normal use.
        if (self.ech_inner_hello) |old| a.free(old);
        self.ech_inner_hello = inner_hello;
    }

    /// Verify the ECH acceptance confirmation in ServerHello.random[24..32]
    /// (draft-ietf-tls-esni §7.2). On acceptance, switch the running transcript
    /// from ClientHelloOuter to ClientHelloInner. Must run after `parseServerHello`
    /// (so the suite is known) and before ServerHello is folded into the
    /// transcript / the handshake keys are derived.
    fn checkEchAcceptance(self: *Client, sh_raw: []const u8) Error!void {
        const inner = self.ech_inner_hello orelse return error.BadState;
        const suite = self.selected_suite orelse return error.BadState;
        // ServerHello = header(4) + legacy_version(2) + random(32) + …; the
        // confirmation is random[24..32] = sh_raw[30..38].
        if (sh_raw.len < 38) return error.BadHandshake;

        // Confirmation transcript = ClientHelloInner || ServerHelloECHConf, where
        // ServerHelloECHConf is this ServerHello with random[24..32] set to zero.
        var conf: std.ArrayList(u8) = .empty;
        defer conf.deinit(self.allocator);
        try conf.appendSlice(self.allocator, inner);
        try conf.appendSlice(self.allocator, sh_raw);
        @memset(conf.items[inner.len + 30 .. inner.len + 38], 0);

        var expected: [ech.confirmation_len]u8 = undefined;
        switch (suite.hashAlg()) {
            .sha256 => {
                const th = Sha256.transcriptHash(conf.items);
                try ech.acceptConfirmation(Sha256, &self.ech_inner_random, &th, .server_hello, &expected);
            },
            .sha384 => {
                const th = Sha384.transcriptHash(conf.items);
                try ech.acceptConfirmation(Sha384, &self.ech_inner_random, &th, .server_hello, &expected);
            },
        }

        const accepted = ctBytesEqual(&expected, sh_raw[30..38]);
        secureZero(&expected);
        self.ech_accepted = accepted;
        if (accepted) {
            // The server accepted ECH: the handshake proceeds over the inner
            // transcript. Replace the outer ClientHello bytes with the inner.
            self.transcript.clearRetainingCapacity();
            try self.appendTranscript(inner);
        }
    }

    /// Emit the opt-in `signature_algorithms_cert` extension (RFC 8446 §4.2.3)
    /// immediately after `signature_algorithms`, when the caller supplied a
    /// cert-scheme list; a no-op (byte-identical wire) otherwise. Called from
    /// every ClientHello variant — the plain CH1, the HRR-retry CH2, and the ECH
    /// ClientHelloInner/Outer — so the extension is identical across the retry.
    fn appendCertSigAlgs(self: *Client, eb: *tls_extension.Builder) Error!void {
        const schemes = self.cert_signature_schemes orelse return;
        // Bounded: the SignatureSchemeList body is 2-byte length + 2 bytes/scheme.
        // 128 schemes (258 bytes) is far beyond any real advertisement.
        if (schemes.len == 0 or schemes.len > 128) return error.BadState;
        var buf: [2 + 128 * 2]u8 = undefined;
        const body = try tls_signature_scheme.build(&buf, schemes);
        try eb.addTyped(.signature_algorithms_cert, body);
    }

    fn writeClientHello(self: *Client, out: *std.ArrayList(u8)) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);

        try appendU16(self.allocator, &body, tls_record.legacy_record_version);
        // RFC 8446 §4.1.2: a retried ClientHello reuses the same random.
        try body.appendSlice(self.allocator, &self.client_random);

        try body.append(self.allocator, @intCast(self.legacy_session_id.len));
        try body.appendSlice(self.allocator, &self.legacy_session_id);

        if (self.force_aes256_only_for_test) {
            try appendU16(self.allocator, &body, 2);
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384));
        } else {
            try appendU16(self.allocator, &body, 6);
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_256_gcm_sha384));
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256));
            try appendU16(self.allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
        }

        try body.append(self.allocator, 1);
        try body.append(self.allocator, 0);

        var ext_storage: [4096]u8 = undefined;
        var ext_builder = try tls_extension.Builder.begin(&ext_storage);

        var sni_buf: [512]u8 = undefined;
        const sni_body = try buildSniBody(&sni_buf, self.server_name);
        try ext_builder.addTyped(.server_name, sni_body);

        var versions_buf: [8]u8 = undefined;
        const versions = try tls_supported_versions.buildClient(&versions_buf, &[_]u16{tls_supported_versions.tls13});
        try ext_builder.addTyped(.supported_versions, versions);

        var groups_buf: [16]u8 = undefined;
        const groups = if (self.force_p256_only_for_test)
            try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{.secp256r1})
        else if (self.force_hybrid_only_for_test)
            try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{.x25519mlkem768})
        else
            // Prefer the post-quantum hybrid, then classical x25519 / P-256.
            try supported_groups.build(&groups_buf, &[_]supported_groups.NamedGroup{ .x25519mlkem768, .x25519, .secp256r1 });
        try ext_builder.addTyped(.supported_groups, groups);

        var sigs_buf: [16]u8 = undefined;
        const sigs = try tls_signature_scheme.build(&sigs_buf, &[_]tls_signature_scheme.SignatureScheme{
            .rsa_pss_rsae_sha256,
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .ed25519,
            .rsa_pkcs1_sha256,
        });
        try ext_builder.addTyped(.signature_algorithms, sigs);
        try self.appendCertSigAlgs(&ext_builder);

        // RFC 8449 record_size_limit: advertise the largest TLSInnerPlaintext we
        // accept (the protocol max — our recv path handles full-size records).
        var rsl_buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &rsl_buf, tls_record.record_size_limit_max, .big);
        try ext_builder.addTyped(.record_size_limit, &rsl_buf);

        // X25519MLKEM768 client key_share = ml-kem_ek(1184) || x25519_pub(32).
        var hybrid_share: [kx.HybridKx.mlkem_public_len + kx.X25519Kx.public_len]u8 = undefined;
        const hy_pub = self.hybrid_pair.publicShare();
        @memcpy(hybrid_share[0..kx.HybridKx.mlkem_public_len], &hy_pub.mlkem_public_key);
        @memcpy(hybrid_share[kx.HybridKx.mlkem_public_len..], &hy_pub.x25519_public_key);

        // Sized for the hybrid share (1216B) + x25519 (32B) + P-256 (65B) + headers.
        var keyshare_buf: [1400]u8 = undefined;
        const keyshares = if (self.retry_key_share_group) |g|
            // ClientHello2 after a HelloRetryRequest: exactly one share, for the
            // group the server requested (RFC 8446 §4.1.2).
            switch (g) {
                .x25519 => try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                    .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key },
                }),
                .secp256r1 => try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                    .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
                }),
                .x25519mlkem768 => try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                    .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
                }),
                else => return error.UnsupportedGroup,
            }
        else if (self.force_no_shares_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{})
        else if (self.force_p256_only_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
            })
        else if (self.force_hybrid_only_for_test)
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
            })
        else
            try tls_keyshare.buildClientShares(&keyshare_buf, &[_]tls_keyshare.Entry{
                .{ .group = .x25519mlkem768, .key_exchange = &hybrid_share },
                .{ .group = .x25519, .key_exchange = &self.x25519_pair.public_key },
                .{ .group = .secp256r1, .key_exchange = &self.p256_pair.public_sec1 },
            });
        try ext_builder.addTyped(.key_share, keyshares);

        if (self.alpn_protocols.len != 0) {
            var alpn_buf: [512]u8 = undefined;
            var alpn_builder = try tls_alpn.Builder.begin(&alpn_buf);
            for (self.alpn_protocols) |proto| try alpn_builder.add(proto);
            const alpn_body = try alpn_builder.finish();
            try ext_builder.addTyped(.alpn, alpn_body);
        }

        // RFC 6066 / RFC 8446 OCSP stapling request:
        // status_type=ocsp(1), empty responder_id_list, empty request_extensions.
        try ext_builder.add(ext_status_request, &[_]u8{ 1, 0, 0, 0, 0 });
        // RFC 6962 §3.3: request TLS-delivered SCTs with an EMPTY extension, only
        // when CT is opted in (a pinned log set is configured). Off ⇒ not emitted,
        // so the ClientHello wire is byte-identical to the pre-feature encoding.
        if (self.ct_logs.len != 0) {
            try ext_builder.add(ext_signed_certificate_timestamp, &.{});
        }

        // RFC 8879 certificate compression: advertise the one algorithm we can
        // decode (zlib). algorithms_length=2, then the u16 zlib(1) code point. A
        // server MAY then send a CompressedCertificate; our wait_certificate path
        // inflates it under the mandatory decompression-bomb guard. Opt-in so the
        // outbound TLS surface stays unchanged by default.
        if (self.offer_cert_compression) {
            try ext_builder.addTyped(.compress_certificate, &[_]u8{ 2, 0x00, 0x01 });
        }

        // RFC 7250 raw public keys: offer server_certificate_type = [RawPublicKey,
        // X509], preferring a bare SPKI but accepting the classic chain. Opt-in
        // only — when off, no bytes are emitted here, so the ClientHello wire is
        // byte-identical to the pre-feature encoding. (Placed before any
        // pre_shared_key extension, which RFC 8446 §4.2.11 requires to be last.)
        if (self.offer_raw_public_key) {
            var ct_buf: [8]u8 = undefined;
            const ct_body = try tls_extension.buildCertTypeList(&ct_buf, &[_]tls_extension.CertificateType{
                .raw_public_key,
                .x509,
            });
            try ext_builder.addTyped(.server_certificate_type, ct_body);
        }
        if (self.offer_client_raw_public_key) {
            var ct_buf: [8]u8 = undefined;
            const ct_body = try tls_extension.buildCertTypeList(&ct_buf, &[_]tls_extension.CertificateType{
                .raw_public_key,
                .x509,
            });
            try ext_builder.addTyped(.client_certificate_type, ct_body);
        }

        // RFC 9345 delegated_credential: a SignatureSchemeList naming the schemes
        // we accept for the DC's dc_cert_verify_algorithm (i.e. the schemes we can
        // verify the DC-key CertificateVerify with). Opt-in so the ClientHello is
        // byte-identical by default.
        if (self.offer_delegated_credential) {
            var dc_buf: [16]u8 = undefined;
            const dc_body = try tls_signature_scheme.build(&dc_buf, &dc_accepted_schemes);
            try ext_builder.add(delegated_credential.extension_type, dc_body);
        }

        // Echo a HelloRetryRequest cookie in the retried ClientHello. The cookie
        // extension body is opaque cookie<1..2^16-1>: a u16 length then the bytes.
        if (self.cookie) |cookie| {
            var cookie_ext: [514]u8 = undefined;
            std.mem.writeInt(u16, cookie_ext[0..2], @intCast(cookie.len), .big);
            @memcpy(cookie_ext[2..][0..cookie.len], cookie);
            try ext_builder.addTyped(.cookie, cookie_ext[0 .. 2 + cookie.len]);
        }

        var binder_offset: ?usize = null;
        var binder_len: usize = 0;
        var binder_truncated_len: usize = 0;
        if (self.resume_offer) |offer| {
            if (self.early_data != null) {
                var early_body: [0]u8 = .{};
                try ext_builder.addTyped(.early_data, &early_body);
            }
            // RFC 8446 §4.2.9: PSK resumption here always keeps a fresh ECDHE
            // key_share, so advertise only psk_dhe_ke.
            try ext_builder.addTyped(.psk_key_exchange_modes, &[_]u8{ 1, 1 });

            const identity = tls_psk.PskIdentity{
                .identity = offer.ticket,
                .obfuscated_ticket_age = tls_session_ticket.obfuscatedAge(offer.ticket_age_ms, offer.ticket_age_add),
            };
            var zero_binder: [max_hash_len]u8 = @splat(0);
            const binders = [_][]const u8{zero_binder[0..offer.psk_len]};
            const psk_ext_data_offset = ext_builder.len + tls_extension.header_len;
            const psk_tmp_len = 2 + (try identity.wireLen()) + 2 + 1 + offer.psk_len;
            const psk_tmp = try self.allocator.alloc(u8, psk_tmp_len);
            defer self.allocator.free(psk_tmp);
            const psk_body = try tls_psk.buildClientPsk(psk_tmp, &[_]tls_psk.PskIdentity{identity}, &binders);
            const binder_list_offset = try tls_psk.binderListOffset(psk_body);
            try ext_builder.addTyped(.pre_shared_key, psk_body);

            const extensions_offset_in_body = body.items.len;
            binder_truncated_len = 4 + extensions_offset_in_body + psk_ext_data_offset + binder_list_offset;
            binder_offset = binder_truncated_len + 2 + 1;
            binder_len = offer.psk_len;
        }

        const extensions = try ext_builder.finish();
        try body.appendSlice(self.allocator, extensions);
        const hs_start = out.items.len;
        try writeHandshake(self.allocator, out, .client_hello, body.items);
        if (binder_offset) |rel| {
            const hs = out.items[hs_start..];
            if (rel + binder_len > hs.len or binder_truncated_len > hs.len) return error.BadHandshake;
            var binder: [max_hash_len]u8 = undefined;
            try self.computePskBinder(hs[0..binder_truncated_len], binder[0..binder_len]);
            @memcpy(hs[rel..][0..binder_len], binder[0..binder_len]);
            secureZero(binder[0..binder_len]);
        }
    }

    fn computePskBinder(self: *Client, truncated_client_hello: []const u8, out: []u8) Error!void {
        const offer = self.resume_offer orelse return error.BadState;
        switch (offer.suite.hashAlg()) {
            .sha256 => try self.computePskBinderT(Sha256, offer, truncated_client_hello, out),
            .sha384 => try self.computePskBinderT(Sha384, offer, truncated_client_hello, out),
        }
    }

    fn computePskBinderT(
        self: *Client,
        comptime KS: type,
        offer: ResumeOffer,
        truncated_client_hello: []const u8,
        out: []u8,
    ) Error!void {
        if (offer.psk_len != KS.hash_len or out.len != KS.hash_len) return error.BadHandshake;
        var early = KS.earlySecret(offer.psk[0..offer.psk_len]);
        defer early.wipe();
        var binder_key = try KS.deriveSecret(&early, "res binder", &KS.emptyTranscriptHash());
        defer binder_key.wipe();

        var transcript = std.ArrayList(u8).empty;
        defer transcript.deinit(self.allocator);
        try transcript.appendSlice(self.allocator, self.transcript.items);
        try transcript.appendSlice(self.allocator, truncated_client_hello);
        const th = KS.transcriptHash(transcript.items);
        const verify = tls_finished.For(KS).verifyData(binder_key.declassify(), th);
        @memcpy(out, &verify);
    }

    const ServerHelloStep = enum { need_more, proceed, retry };

    /// Validate one middlebox-compatibility change_cipher_spec record before the
    /// caller drops it. RFC 8446 §5 permits exactly the single byte 0x01 and
    /// requires an abort on any other value; the per-connection count cap keeps
    /// the "drop and continue" branches bounded so a peer cannot stall us here.
    fn acceptCompatCcs(self: *Client, fragment: []const u8) Error!void {
        if (!tls_record.isLegalCompatCcs(fragment)) return error.BadRecord;
        self.ccs_records_seen += 1;
        if (self.ccs_records_seen > tls_record.max_change_cipher_spec_records) return error.BadRecord;
    }

    fn tryConsumeServerHello(self: *Client) Error!ServerHelloStep {
        while (true) {
            const rec = try completePlainRecord(self.recv_buf.items) orelse return .need_more;
            if (rec.content_type == .change_cipher_spec) {
                try self.acceptCompatCcs(rec.fragment);
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type == .alert) {
                self.last_alert = try tls_alert.parse(rec.fragment);
                return error.TlsAlert;
            }
            if (rec.content_type != .handshake) return error.BadRecord;

            var off: usize = 0;
            const msg = try parseHandshake(rec.fragment, &off);
            if (off != rec.fragment.len or msg.typ != .server_hello) return error.BadHandshake;

            if (isHelloRetryRequest(msg.body)) {
                // A second HelloRetryRequest in one connection is fatal.
                if (self.hrr_seen) return error.BadHandshake;
                // ECH + HRR (re-seal the ClientHelloInner under the same HPKE
                // context with an empty `enc`, plus the "hrr ech accept
                // confirmation" transcript) is not yet implemented (deferred, gated
                // on an external ECH oracle). Rather than emit a subtly non-compliant
                // CH2 that silently downgrades ECH, refuse — FAIL CLOSED. The server
                // enforces the symmetric guard (`EchHrrUnsupported`) when it accepted
                // an inner and would itself need to HelloRetryRequest.
                if (self.ech_active) return error.HelloRetryRequestUnsupported;
                const ch2 = try self.handleHelloRetryRequest(msg.body, msg.raw);
                consumePrefix(&self.recv_buf, rec.wire_len);
                self.retry_hello = ch2;
                return .retry;
            }

            var selected = try self.parseServerHello(msg.body);
            // ECH acceptance: inspect the confirmation in ServerHello.random and,
            // if the server accepted, switch the transcript to the ClientHelloInner
            // BEFORE ServerHello is folded in and the handshake keys are derived.
            if (self.ech_active) try self.checkEchAcceptance(msg.raw);
            try self.appendTranscript(msg.raw);
            try self.deriveHandshakeKeys(selected.buf[0..selected.len]);
            secureZero(&selected.buf);
            consumePrefix(&self.recv_buf, rec.wire_len);
            self.state = .wait_encrypted_extensions;
            return .proceed;
        }
    }

    /// Process a HelloRetryRequest (RFC 8446 §4.1.4): apply the cookie, rewrite
    /// the transcript with the synthetic message_hash, and produce the second
    /// ClientHello to send. Returns the plaintext handshake record (caller owns).
    fn handleHelloRetryRequest(self: *Client, body: []const u8, raw: []const u8) Error![]u8 {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        _ = try c.take(32); // the HelloRetryRequest magic random
        const sid = try c.take(try c.readU8());
        if (!std.mem.eql(u8, sid, &self.legacy_session_id)) return error.BadHandshake;
        const suite = try CipherSuite.fromWire(try c.readU16());
        if (try c.readU8() != 0) return error.BadHandshake;
        const ext_block = try c.take(try c.readU16());
        try c.expectEmpty();

        var selected_version = false;
        var hrr_group: ?u16 = null;
        var cookie_bytes: ?[]const u8 = null;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .supported_versions => {
                    if (try tls_supported_versions.parseServer(ext.data) != tls_supported_versions.tls13) {
                        return error.ProtocolVersion;
                    }
                    selected_version = true;
                },
                .key_share => {
                    // In a HelloRetryRequest the key_share carries only the group.
                    if (ext.data.len != 2) return error.BadHandshake;
                    hrr_group = std.mem.readInt(u16, ext.data[0..2], .big);
                },
                .cookie => {
                    if (ext.data.len < 2) return error.BadHandshake;
                    const clen = std.mem.readInt(u16, ext.data[0..2], .big);
                    if (ext.data.len != 2 + @as(usize, clen)) return error.BadHandshake;
                    cookie_bytes = ext.data[2..];
                },
                else => {},
            }
        }
        if (!selected_version) return error.MissingExtension;
        self.selected_suite = suite; // selects the transcript hash below
        self.hrr_suite = suite; // §4.1.4: the ServerHello MUST keep this suite

        // RFC 8446 §4.1.4: the requested group must be one we support AND did not
        // already offer a key_share for (a change-nothing HRR is illegal). By
        // default we share every group we support, so any group-change request is
        // non-compliant — but a test that withheld shares legitimately retries.
        if (hrr_group) |g| {
            const ng = supported_groups.NamedGroup.fromInt(g);
            if (!self.supportsGroup(ng)) return error.UnsupportedGroup;
            if (self.offeredShareFor(ng)) return error.BadHandshake; // no change — illegal
            self.retry_key_share_group = ng;
        }

        if (cookie_bytes) |cb| {
            if (cb.len == 0 or cb.len > self.cookie_buf.len) return error.BadHandshake;
            @memcpy(self.cookie_buf[0..cb.len], cb);
            self.cookie = self.cookie_buf[0..cb.len];
        }

        // Replace ClientHello1 in the transcript with the synthetic message_hash
        // (handshake type 254): 0xFE || uint24(Hash.length) || Hash(ClientHello1).
        var ch1_hash: [max_hash_len]u8 = undefined;
        const hlen = self.transcriptHash(&ch1_hash);
        self.transcript.clearRetainingCapacity();
        try self.transcript.append(self.allocator, 0xFE);
        try appendU24(self.allocator, &self.transcript, hlen);
        try self.transcript.appendSlice(self.allocator, ch1_hash[0..hlen]);
        try self.appendTranscript(raw); // fold in the HelloRetryRequest itself
        self.hrr_seen = true;

        // Build ClientHello2 (same random/session-id; key_share now the single
        // requested group when the HRR changed groups, plus any cookie) and fold
        // it into the transcript before sending.
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try self.writeClientHello(&hs);
        try self.appendTranscript(hs.items);
        return writePlainRecord(self.allocator, .handshake, hs.items);
    }

    fn tryConsumeServerFlight(self: *Client) Error!?[]u8 {
        while (self.state != .connected) {
            while (try self.tryProcessPlainHandshake()) {}
            if (self.state == .connected) return try self.writeClientFinishedRecord();

            const rec = try completePlainRecord(self.recv_buf.items) orelse return null;
            if (rec.content_type == .change_cipher_spec) {
                try self.acceptCompatCcs(rec.fragment);
                consumePrefix(&self.recv_buf, rec.wire_len);
                continue;
            }
            if (rec.content_type != .application_data) return error.BadRecord;
            const suite = self.selected_suite orelse return error.BadState;
            const opened = try openRecordAlloc(self.allocator, suite, &self.server_hs_keys, self.hs_read_seq, self.recv_buf.items[0..rec.wire_len]);
            self.hs_read_seq += 1;
            defer self.allocator.free(opened.content);
            consumePrefix(&self.recv_buf, rec.wire_len);

            dbg("decrypted flight record ct={d} len={d}", .{ @intFromEnum(opened.content_type), opened.content.len });
            if (opened.content_type == .alert) {
                self.last_alert = try tls_alert.parse(opened.content);
                return error.TlsAlert;
            }
            if (opened.content_type != .handshake) return error.BadRecord;
            // RFC 8446 §5.1: zero-length handshake fragments MUST NOT be sent;
            // receiving one is fatal rather than an ignorable no-op.
            if (opened.content.len == 0) return error.BadHandshake;
            try self.hs_plain.appendSlice(self.allocator, opened.content);
        }
        return null;
    }

    fn tryProcessPlainHandshake(self: *Client) Error!bool {
        var off: usize = 0;
        const msg = parseHandshakeMaybe(self.hs_plain.items, &off) orelse return false;
        dbg("plain handshake state={s} msg typ={d} len={d}", .{ @tagName(self.state), @intFromEnum(msg.typ), msg.body.len });
        switch (self.state) {
            .wait_encrypted_extensions => {
                if (msg.typ != .encrypted_extensions) return error.BadHandshake;
                try self.parseEncryptedExtensions(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = if (self.psk_accepted) .wait_finished else .wait_certificate;
            },
            .wait_certificate => {
                // An optional CertificateRequest precedes the server
                // Certificate (RFC 8446 §4.3.2). Record it and keep waiting for
                // the server Certificate; the request itself stays in the
                // transcript. Only the test-only mTLS path acts on it later.
                if (msg.typ == .certificate_request) {
                    self.client_cert_type = try validateCertificateRequest(msg.body, self.offer_client_raw_public_key);
                    self.cert_requested = true;
                    try self.appendTranscript(msg.raw);
                } else if (msg.typ == .compressed_certificate) {
                    // RFC 8879 §4: a CompressedCertificate we never solicited is a
                    // protocol violation — reject it rather than decode it.
                    if (!self.offer_cert_compression) return error.BadHandshake;
                    // Inflate into a plain Certificate body, verify it, then fold
                    // the type-25 wire bytes (not a reconstructed type-11) into the
                    // transcript — exactly what the peer hashed.
                    const plain = try self.decompressCertificate(msg.body);
                    defer self.allocator.free(plain);
                    try self.parseAndVerifyCertificate(plain);
                    try self.appendTranscript(msg.raw);
                    self.received_compressed_cert = true;
                    self.state = .wait_certificate_verify;
                } else {
                    if (msg.typ != .certificate) return error.BadHandshake;
                    try self.parseAndVerifyCertificate(msg.body);
                    try self.appendTranscript(msg.raw);
                    self.state = .wait_certificate_verify;
                }
            },
            .wait_certificate_verify => {
                if (msg.typ != .certificate_verify) return error.BadHandshake;
                try self.verifyCertificateVerify(msg.body);
                try self.appendTranscript(msg.raw);
                self.state = .wait_finished;
            },
            .wait_finished => {
                if (msg.typ != .finished) return error.BadHandshake;
                try self.verifyFinished(msg.body);
                try self.appendTranscript(msg.raw);
                try self.deriveApplicationKeys();
                self.state = .connected;
            },
            else => return error.BadState,
        }
        consumePrefix(&self.hs_plain, off);
        return true;
    }

    /// The negotiated (EC)DHE secret: 32 bytes for a classical group, 64 for the
    /// X25519MLKEM768 hybrid (ml-kem_ss || x25519_ss). Fed to the key schedule.
    const ServerKexSecret = struct { buf: [64]u8 = undefined, len: usize = 0 };

    fn parseServerHello(self: *Client, body: []const u8) Error!ServerKexSecret {
        var c = Cursor.init(body);
        if (try c.readU16() != tls_record.legacy_record_version) return error.ProtocolVersion;
        const random = try c.take(32);
        // HelloRetryRequest is intercepted in tryConsumeServerHello; a magic
        // random reaching here would be a logic error or a second HRR.
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.BadHandshake;
        const sid = try c.take(try c.readU8());
        if (!std.mem.eql(u8, sid, &self.legacy_session_id)) return error.BadHandshake;
        const suite = try CipherSuite.fromWire(try c.readU16());
        // RFC 8446 §4.1.4: after a HelloRetryRequest the ServerHello MUST carry
        // the same cipher suite the HRR committed to. Enforced explicitly — two
        // suites sharing a transcript hash (0x1301 ↔ 0x1303) would otherwise
        // slide through until (at best) a Finished mismatch.
        if (self.hrr_suite) |committed| {
            if (committed != suite) return error.BadHandshake;
        }
        if (try c.readU8() != 0) return error.BadHandshake;
        const extensions_block = try c.take(try c.readU16());
        try c.expectEmpty();

        var selected_version = false;
        var selected_share: ?tls_keyshare.Entry = null;
        var selected_psk: ?u16 = null;
        var it = tls_extension.Iterator.init(extensions_block);
        while (try it.next()) |ext| {
            switch (ext.typed()) {
                .supported_versions => {
                    if (try tls_supported_versions.parseServer(ext.data) != tls_supported_versions.tls13) {
                        return error.ProtocolVersion;
                    }
                    selected_version = true;
                },
                .key_share => selected_share = try tls_keyshare.parseServerShare(ext.data),
                .pre_shared_key => selected_psk = try tls_psk.parseServerPsk(ext.data),
                else => {},
            }
        }
        if (!selected_version or selected_share == null) return error.MissingExtension;
        self.selected_suite = suite;
        self.psk_accepted = false;
        if (selected_psk) |idx| {
            if (idx != 0) return error.BadHandshake;
            const offer = self.resume_offer orelse return error.BadHandshake;
            if (offer.suite != suite or offer.psk_len != suite.hashLen()) return error.BadHandshake;
            self.psk_accepted = true;
        }
        const share = selected_share.?;
        // RFC 8446 §4.2.8: the server's key_share MUST name a group we actually
        // sent a KeyShareEntry for — after a HelloRetryRequest, exactly the
        // retry group ClientHello2 carried.
        if (self.retry_key_share_group) |g| {
            if (share.group.toInt() != g.toInt()) return error.BadHandshake;
        } else if (!self.offeredShareFor(supported_groups.NamedGroup.fromInt(share.group.toInt()))) {
            return error.BadHandshake;
        }
        var out = ServerKexSecret{};
        switch (share.group) {
            .x25519 => {
                if (share.key_exchange.len != kx.X25519Kx.public_len) return error.BadHandshake;
                var peer: kx.PublicKey = undefined;
                @memcpy(&peer, share.key_exchange);
                var secret = try kx.X25519Kx.sharedSecret(&self.x25519_pair.secret_key, peer);
                defer secret.wipe();
                const ss = secret.declassify();
                @memcpy(out.buf[0..32], &ss);
                out.len = 32;
            },
            .secp256r1 => {
                if (share.key_exchange.len != ecdh_p256.public_length) return error.BadHandshake;
                const ss = try ecdh_p256.sharedSecret(self.p256_pair.secret, share.key_exchange[0..ecdh_p256.public_length].*);
                @memcpy(out.buf[0..32], &ss);
                out.len = 32;
            },
            .x25519mlkem768 => {
                // Server share = ml-kem_ct(1088) || x25519_pub(32). The combined
                // (EC)DHE secret is the RAW concatenation ml-kem_ss(32) || x25519_ss(32)
                // fed to the TLS key schedule — matching tls_server. (NOT
                // kx.HybridKx.decapsulate, which is the MOORING mesh HKDF combiner.)
                const ct_len = kx.HybridKx.mlkem_ciphertext_len;
                if (share.key_exchange.len != ct_len + kx.X25519Kx.public_len) return error.BadHandshake;
                var ct: [ct_len]u8 = undefined;
                @memcpy(&ct, share.key_exchange[0..ct_len]);
                var mlkem_ss = try self.hybrid_pair.mlkem.secret_key.decaps(&ct);
                defer secureZero(&mlkem_ss);
                var x_peer: kx.PublicKey = undefined;
                @memcpy(&x_peer, share.key_exchange[ct_len..]);
                var x_secret = try kx.X25519Kx.sharedSecret(&self.hybrid_pair.x25519.secret_key, x_peer);
                defer x_secret.wipe();
                const x_ss = x_secret.declassify();
                @memcpy(out.buf[0..32], &mlkem_ss);
                @memcpy(out.buf[32..64], &x_ss);
                out.len = 64;
            },
            else => return error.UnsupportedGroup,
        }
        return out;
    }

    fn parseEncryptedExtensions(self: *Client, body: []const u8) Error!void {
        const extensions = try tls_extension.unwrap(body);
        var it = tls_extension.Iterator.init(extensions);
        var server_accepted_early = false;
        while (try it.next()) |ext| {
            // draft-ietf-tls-esni §7.1: the server delivers retry_configs in the
            // `encrypted_client_hello` EE extension when it could not decrypt our
            // ECH. Capture it ONLY when we offered ECH and it was rejected — the EE
            // is then authenticated by the public_name cert, so these bytes are
            // trustworthy. A server MUST NOT send it otherwise; if it does while we
            // never offered ECH we ignore it (a non-ECH client tolerates it rather
            // than treating it as unsolicited). Not applied this connection; the
            // caller may adopt it on the next.
            if (ext.ext_type == ech.extension_type) {
                if (self.ech_active and !(self.ech_accepted orelse false) and self.ech_retry_configs == null) {
                    self.ech_retry_configs = try self.allocator.dupe(u8, ext.data);
                }
                continue;
            }
            switch (ext.typed()) {
                .alpn => {
                    var names = try tls_alpn.Iterator.fromBlock(ext.data);
                    const selected = (try names.next()) orelse return error.BadHandshake;
                    if ((try names.next()) != null) return error.BadHandshake;
                    var ok = false;
                    for (self.alpn_protocols) |offered| {
                        if (std.mem.eql(u8, offered, selected)) ok = true;
                    }
                    if (!ok) return error.BadHandshake;
                    // Copy into owned storage; `selected` borrows hs_plain.
                    if (selected.len > self.selected_alpn_buf.len) return error.BadHandshake;
                    @memcpy(self.selected_alpn_buf[0..selected.len], selected);
                    self.selected_alpn = self.selected_alpn_buf[0..selected.len];
                },
                .early_data => {
                    if (ext.data.len != 0 or self.early_data == null or !self.psk_accepted) return error.BadHandshake;
                    server_accepted_early = true;
                },
                .record_size_limit => {
                    // RFC 8449: a 2-byte value in [64, 2^14+1]; anything else is
                    // illegal_parameter. Store it so our outbound records honor it.
                    if (ext.data.len != 2) return error.BadHandshake;
                    const limit = std.mem.readInt(u16, ext.data[0..2], .big);
                    if (limit < tls_record.record_size_limit_min or limit > tls_record.record_size_limit_max) return error.BadHandshake;
                    self.peer_record_size_limit = limit;
                },
                // RFC 7250 / RFC 8446 §4.2: the server's chosen certificate type
                // is echoed here. It is legal only if we offered raw public keys
                // (a server MUST NOT send an unsolicited extension response) and
                // may only name a type we offered ([RawPublicKey, X509]).
                .server_certificate_type => {
                    if (!self.offer_raw_public_key) return error.BadHandshake;
                    self.server_cert_type = switch (try tls_extension.parseSelectedCertType(ext.data)) {
                        .raw_public_key => .raw_public_key,
                        .x509 => .x509,
                        else => return error.BadHandshake,
                    };
                },
                // We never offer client_certificate_type (we present no client
                // cert by default), so any response for it is unsolicited.
                .client_certificate_type => return error.BadHandshake,
                // key_share / supported_versions / signature_algorithms belong to
                // ServerHello/CertificateRequest and are illegal here. server_name
                // (empty SNI ack) and supported_groups ARE permitted in EE
                // (RFC 8446 §4.3.1), so only reject the genuinely-illegal ones.
                .supported_versions, .key_share, .signature_algorithms => {
                    return error.BadHandshake;
                },
                else => {},
            }
        }
        if (self.early_data != null) self.early_data_accepted = server_accepted_early;
    }

    /// Inflate a CompressedCertificate (RFC 8879 §5) body into the plain
    /// Certificate message bytes. Layout: u16 algorithm, u24 uncompressed_length,
    /// then `compressed_certificate_message<1..2^24-1>` (a u24-prefixed vector).
    /// We only advertised zlib, so any other algorithm is a protocol violation.
    /// Caller owns the returned slice. The bomb guard lives in `inflateZlib`.
    fn decompressCertificate(self: *Client, body: []const u8) Error![]u8 {
        var c = Cursor.init(body);
        const algorithm = try c.readU16();
        if (algorithm != cert_compression.Algorithm.zlib.toInt()) return error.BadHandshake;
        const uncompressed_length = try c.readU24();
        const compressed_length = try c.readU24();
        const compressed = try c.take(compressed_length);
        try c.expectEmpty();
        return cert_compression.inflateZlib(self.allocator, compressed, uncompressed_length);
    }

    fn parseAndVerifyCertificate(self: *Client, body: []const u8) Error!void {
        // RFC 7250: if the server negotiated RawPublicKey, the Certificate
        // message carries a bare SubjectPublicKeyInfo, not an X.509 chain. This
        // branch is only reachable when the caller opted in AND the server
        // selected it; the default (.x509) falls straight through to the normal,
        // fully trust-verified chain path below.
        if (self.server_cert_type == .raw_public_key) {
            return self.parseRawPublicKey(body);
        }

        var c = Cursor.init(body);
        const request_context = try c.take(try c.readU8());
        if (request_context.len != 0) return error.BadHandshake;
        const list = try c.take(try c.readU24());
        try c.expectEmpty();

        var chain_buf: [16][]const u8 = undefined;
        var count: usize = 0;
        var leaf_ocsp_staple: ?[]const u8 = null;
        // RFC 6962 §3.3: SCTs the server delivers in the leaf CertificateEntry's
        // `signed_certificate_timestamp` extension (extension_data IS the raw
        // `SignedCertificateTimestampList`). Only captured when CT is opted in and
        // we advertised the extension in the ClientHello; a server MUST NOT send
        // one otherwise. These SCTs sign the FINAL cert (`x509_entry`), unlike the
        // embedded extension's precert SCTs.
        var leaf_tls_ext_scts: ?[]const u8 = null;
        // RFC 9345: raw DelegatedCredential from the leaf entry's extensions, only
        // captured when we advertised the extension (a server MUST NOT send one
        // otherwise; if it does we ignore it and take the normal cert-key path).
        var leaf_dc_raw: ?[]const u8 = null;
        var certs = Cursor.init(list);
        while (certs.remaining() != 0) {
            if (count == chain_buf.len) return error.BadCertificate;
            const der = try certs.take(try certs.readU24());
            const ext = try certs.take(try certs.readU16());
            if (ext.len != 0) {
                var eit = tls_extension.Iterator.init(ext);
                while (try eit.next()) |entry_ext| {
                    if (count == 0 and entry_ext.ext_type == ext_status_request) {
                        leaf_ocsp_staple = try parseCertificateStatusOcsp(entry_ext.data);
                    } else if (count == 0 and self.ct_logs.len != 0 and
                        entry_ext.ext_type == ext_signed_certificate_timestamp)
                    {
                        leaf_tls_ext_scts = entry_ext.data;
                    } else if (count == 0 and self.offer_delegated_credential and
                        entry_ext.ext_type == delegated_credential.extension_type)
                    {
                        leaf_dc_raw = entry_ext.data;
                    }
                }
            }
            chain_buf[count] = der;
            count += 1;
        }
        if (count == 0) return error.EmptyCertificateChain;
        const chain = chain_buf[0..count];
        if (!self.skip_cert_verify_for_test) {
            try verifyChainToTrustAnchors(chain, self.trust_anchors, self.effectiveVerifyName(), self.verify_time);
        }
        if (leaf_ocsp_staple) |staple| {
            const leaf = try x509.parse(chain[0]);
            const issuer_der = if (chain.len > 1) chain[1] else chain[0];
            const issuer_parts = try extractCertParts(issuer_der);
            try verifyOcspStapleForLeaf(staple, issuer_parts.spki_der, leaf.serial_der, self.verify_time);
        }
        if (self.crl) |crl_der| {
            const leaf = try x509.parse(chain[0]);
            const issuer_der = if (chain.len > 1) chain[1] else chain[0];
            const issuer_parts = try extractCertParts(issuer_der);
            try checkCrlRevocation(crl_der, issuer_parts.spki_der, leaf.serial_der, self.verify_time);
        }
        // Opt-in SCT (Certificate Transparency) verification, pooling SCTs from
        // ALL THREE RFC 6962 §3 sources — the embedded X.509 extension (precert
        // entry), any TLS `signed_certificate_timestamp` extension (final-cert
        // entry), and the stapled OCSP response's SingleResponse SCT extension
        // (final-cert entry) — into ONE cross-source distinct-log quorum. Byte-
        // identical when `ct_logs` is empty (the default): the path is skipped, no
        // ext-18 was ever advertised, and OCSP stapling is requested regardless
        // (so the OCSP source adds no wire change). `enforce_sct` adds tamper
        // detection; `require_sct` adds the presence + distinct-log quorum.
        try verifyScts(chain, leaf_tls_ext_scts, leaf_ocsp_staple, self.ct_logs, self.enforce_sct, self.require_sct);
        self.leaf_key = try parsePublicKeyFromSpki((try extractCertParts(chain[0])).spki_der);
        try self.ownLeafRsaKey();

        // RFC 9345: if the server delegated to a credential, verify it now (while
        // the leaf key and DC bytes are still live) and arm the DC key for
        // CertificateVerify. Fails closed — a bad DC rejects the handshake.
        if (leaf_dc_raw) |dc_raw| {
            try self.verifyDelegatedCredential(chain[0], dc_raw);
        }
    }

    /// After `leaf_key` is parsed from SPKI bytes that alias `hs_plain`, copy any
    /// RSA modulus/exponent into owned storage so the key survives the
    /// post-message consume of `hs_plain`. ECDSA/Ed25519 leaves are value types
    /// with no borrowed slices, so they need no copy. Shared by the X.509 chain
    /// path and the RFC 7250 raw-public-key path.
    fn ownLeafRsaKey(self: *Client) Error!void {
        const lk = self.leaf_key orelse return;
        if (lk != .rsa) return;
        const n = lk.rsa.n;
        const e = lk.rsa.e;
        if (n.len > self.leaf_rsa_n.len or e.len > self.leaf_rsa_e.len) return error.BadCertificate;
        @memcpy(self.leaf_rsa_n[0..n.len], n);
        @memcpy(self.leaf_rsa_e[0..e.len], e);
        self.leaf_key = .{ .rsa = .{ .n = self.leaf_rsa_n[0..n.len], .e = self.leaf_rsa_e[0..e.len] } };
    }

    /// RFC 7250 §3 + RFC 8446 §4.4.2: parse a Certificate message whose single
    /// CertificateEntry's `cert_data` is a bare `SubjectPublicKeyInfo`. There is
    /// no chain and no trust-anchor path — a raw public key is TOFU/pinning
    /// territory, so this only establishes the peer key used to verify the
    /// server CertificateVerify signature. It runs solely when the caller opted
    /// in and the server negotiated RawPublicKey (gated in
    /// `parseAndVerifyCertificate`); it NEVER runs on the default X.509 path.
    fn parseRawPublicKey(self: *Client, body: []const u8) Error!void {
        var c = Cursor.init(body);
        const request_context = try c.take(try c.readU8());
        if (request_context.len != 0) return error.BadHandshake;
        const list = try c.take(try c.readU24());
        try c.expectEmpty();

        // Exactly one CertificateEntry, carrying the SPKI as its cert_data
        // (a raw-public-key Certificate has no chain — RFC 7250 §4.4).
        var entries = Cursor.init(list);
        const spki = try entries.take(try entries.readU24());
        const entry_ext = try entries.take(try entries.readU16());
        if (entry_ext.len != 0) {
            var eit = tls_extension.Iterator.init(entry_ext);
            while (try eit.next()) |_| {}
        }
        try entries.expectEmpty();
        if (spki.len == 0) return error.EmptyCertificateChain;

        self.leaf_key = try parsePublicKeyFromSpki(spki);
        try self.ownLeafRsaKey();
    }

    /// RFC 9345 §4.1.3/§4.2: validate a server-presented delegated credential and,
    /// on success, arm `dc_verified_key`/`dc_expected_scheme` so CertificateVerify
    /// is bound to the DC's public key instead of the leaf certificate's. Every
    /// defect (bad framing, missing DelegationUsage/KeyUsage, un-accepted scheme,
    /// expired, remaining lifetime > 7 days, expiry ≥ the cert's notAfter, or a
    /// forged DC signature) rejects the handshake.
    fn verifyDelegatedCredential(self: *Client, leaf_der: []const u8, dc_raw: []const u8) Error!void {
        const dc = try delegated_credential.parse(dc_raw);

        // (1) The delegation (leaf) certificate MUST carry id-ce-delegationUsage
        // and assert the digitalSignature KeyUsage (RFC 9345 §4.2).
        const leaf = try x509.parse(leaf_der);
        if (!leaf.delegation_usage) return error.DelegatedCredentialNoDelegationUsage;
        if (!leaf.key_usage_digital_signature) return error.DelegatedCredentialKeyUsage;

        // (2) Scheme allowed for DCs (RFC 9345 §4.1.3 check 3, first clause): we
        // only accept a dc_cert_verify_algorithm we advertised. (The match to the
        // CertificateVerify scheme is enforced at CertVerify time.)
        if (!dcSchemeAccepted(dc.dc_cert_verify_algorithm)) return error.UnsupportedSignatureScheme;

        // (3) Validity window (RFC 9345 §4.1.3 checks 1–2), anchored on the
        // "expiry time" = the leaf's notBefore + valid_time. Enforcing it needs a
        // trustworthy clock; without one, fail closed. NOTE: the 7-day maximum
        // bounds the *remaining* lifetime (expiry ≤ now + 7d), NOT the raw
        // valid_time field — a DC on a cert issued weeks ago legitimately has a
        // valid_time far larger than 7 days.
        const now = self.verify_time orelse return error.DelegatedCredentialNoClock;
        const expiry = leaf.not_before.epoch_seconds + @as(i64, dc.valid_time);
        // check 1: current time within the credential's validity interval.
        if (now > expiry) return error.DelegatedCredentialExpired;
        // check 2a: remaining validity ≤ the 7-day maximum.
        if (expiry > now + @as(i64, delegated_credential.max_valid_time_seconds)) {
            return error.DelegatedCredentialLifetimeTooLong;
        }
        // check 2b: the credential must not outlive the delegation certificate.
        if (expiry >= leaf.not_after.epoch_seconds) return error.DelegatedCredentialOutlivesCertificate;

        // (4) The DC signature is made by the LEAF certificate's public key over
        // the RFC 9345 §4.1.3 content, using DelegatedCredential.algorithm. A
        // forged/tampered signature fails here (error.BadSignature).
        const leaf_key = self.leaf_key orelse return error.BadCertificate;
        const msg_len = delegated_credential.signedMessageLen(leaf_der.len, dc.signed_portion.len);
        const msg = try self.allocator.alloc(u8, msg_len);
        defer self.allocator.free(msg);
        const signed = try delegated_credential.writeSignedMessage(msg, leaf_der, dc.signed_portion);
        try verifySignatureScheme(
            leaf_key,
            tls_signature_scheme.SignatureScheme.fromInt(dc.algorithm),
            signed,
            dc.signature,
        );

        // (5) Bind CertificateVerify to the DC public key. The DC's SPKI aliases
        // the soon-consumed handshake buffer, so copy any RSA key material into
        // owned storage (mirrors the leaf-key copy above); EC/Ed25519 are values.
        var dc_key = try parsePublicKeyFromSpki(dc.spki);
        if (dc_key == .rsa) {
            const n = dc_key.rsa.n;
            const e = dc_key.rsa.e;
            if (n.len > self.dc_rsa_n.len or e.len > self.dc_rsa_e.len) return error.BadCertificate;
            @memcpy(self.dc_rsa_n[0..n.len], n);
            @memcpy(self.dc_rsa_e[0..e.len], e);
            dc_key = .{ .rsa = .{ .n = self.dc_rsa_n[0..n.len], .e = self.dc_rsa_e[0..e.len] } };
        }
        self.dc_verified_key = dc_key;
        self.dc_expected_scheme = dc.dc_cert_verify_algorithm;
    }

    fn verifyCertificateVerify(self: *Client, body: []const u8) Error!void {
        if (body.len < 4) return error.BadHandshake;
        const scheme = tls_signature_scheme.SignatureScheme.fromInt(std.mem.readInt(u16, body[0..2], .big));
        const sig_len = std.mem.readInt(u16, body[2..4], .big);
        if (body.len != 4 + @as(usize, sig_len)) return error.BadHandshake;
        const sig_bytes = body[4..];
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, certificate_verify_context, th[0..th_len]);
        // RFC 9345 §4: when a delegated credential was validated, verify with the
        // DC key and require the CertVerify scheme to equal the DC's
        // dc_cert_verify_algorithm. Otherwise use the leaf certificate's key.
        const key = if (self.dc_verified_key) |dc_key| blk: {
            const expected = self.dc_expected_scheme orelse return error.BadState;
            if (scheme.toInt() != expected) return error.DelegatedCredentialSchemeMismatch;
            break :blk dc_key;
        } else self.leaf_key orelse return error.BadCertificate;
        try verifySignatureScheme(key, scheme, input, sig_bytes);
    }

    fn verifyFinished(self: *Client, body: []const u8) Error!void {
        if (!self.finishedVerify(&self.server_hs_secret, body)) return error.FinishedMismatch;
    }

    fn writeClientFinishedRecord(self: *Client) Error![]u8 {
        const suite = self.selected_suite orelse return error.BadState;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);

        // mTLS (test-only): if the server requested a client certificate, send
        // a client Certificate first (empty when declining), then a
        // CertificateVerify when a key pair is configured. Each goes out as its
        // own encrypted handshake record and is folded into the transcript
        // before the client Finished MAC is computed.
        if (self.cert_requested) {
            try self.appendClientCertificate(&out, suite);
            if (self.client_cert_der != null and self.client_key_pair != null) {
                try self.appendClientCertificateVerify(&out, suite);
            }
        }

        var vd_buf: [max_hash_len]u8 = undefined;
        const vd_len = self.finishedVerifyData(&self.client_hs_secret, &vd_buf);
        const verify_data = vd_buf[0..vd_len];
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, .finished, verify_data);
        try self.appendTranscript(hs.items);
        try self.deriveResumptionMasterSecret();
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.hs_write_seq += 1;
        try out.appendSlice(self.allocator, record);
        return out.toOwnedSlice(self.allocator);
    }

    /// Test-only: append an encrypted client Certificate handshake record. When
    /// no client cert is configured the CertificateEntry list is empty (a
    /// well-formed decline per RFC 8446 §4.4.2).
    fn appendClientCertificate(self: *Client, out: *std.ArrayList(u8), suite: CipherSuite) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.append(self.allocator, 0); // certificate_request_context: empty
        if (self.client_cert_der) |der| {
            const entry_len = 3 + der.len + 2;
            try appendU24(self.allocator, &body, entry_len);
            try appendU24(self.allocator, &body, der.len);
            try body.appendSlice(self.allocator, der);
            try appendU16(self.allocator, &body, 0); // no certificate extensions
        } else {
            try appendU24(self.allocator, &body, 0); // empty entry list
        }
        try self.appendClientHandshakeRecord(out, suite, .certificate, body.items);
    }

    /// Test-only: append an encrypted client CertificateVerify signed with the
    /// configured key over the "client CertificateVerify" context, using the
    /// scheme matching the key type.
    fn appendClientCertificateVerify(self: *Client, out: *std.ArrayList(u8), suite: CipherSuite) Error!void {
        const key_pair = self.client_key_pair orelse return error.BadState;
        var th: [max_hash_len]u8 = undefined;
        const th_len = self.transcriptHash(&th);
        var in_buf: [cert_verify_input_max]u8 = undefined;
        const input = buildCertVerifyInput(&in_buf, client_certificate_verify_context, th[0..th_len]);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        switch (key_pair) {
            .ed25519 => |kp| {
                const sig = kp.sign(input) catch return error.BadSignature;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ed25519));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, &sig);
            },
            .ecdsa_p256 => |kp| {
                const sig = ecdsa_p256.sign(input, kp) catch return error.BadSignature;
                var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
                const der = ecdsa_p256.signatureToDer(sig, &der_buf) catch return error.BadSignature;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256));
                try appendU16(self.allocator, &body, @intCast(der.len));
                try body.appendSlice(self.allocator, der);
            },
            .rsa => |key| {
                var mhash: [Sha256.hash_len]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(input, &mhash, .{});
                var salt: [Sha256.hash_len]u8 = undefined;
                try osEntropy(&salt);
                defer secureZero(&salt);
                var sig_buf: [rsa_verify.max_bytes]u8 = undefined;
                const sig = rsa_sign.signPss(key, .sha256, &mhash, &salt, &sig_buf) catch return error.BadSignature;
                try appendU16(self.allocator, &body, @intFromEnum(tls_signature_scheme.SignatureScheme.rsa_pss_rsae_sha256));
                try appendU16(self.allocator, &body, @intCast(sig.len));
                try body.appendSlice(self.allocator, sig);
            },
        }
        try self.appendClientHandshakeRecord(out, suite, .certificate_verify, body.items);
    }

    fn appendClientHandshakeRecord(
        self: *Client,
        out: *std.ArrayList(u8),
        suite: CipherSuite,
        typ: HandshakeType,
        body: []const u8,
    ) Error!void {
        var hs: std.ArrayList(u8) = .empty;
        defer hs.deinit(self.allocator);
        try writeHandshake(self.allocator, &hs, typ, body);
        try self.appendTranscript(hs.items);
        const record = try sealRecordAlloc(self.allocator, suite, &self.client_hs_keys, self.hs_write_seq, .handshake, hs.items);
        defer self.allocator.free(record);
        self.hs_write_seq += 1;
        try out.appendSlice(self.allocator, record);
    }

    /// Negotiated transcript-hash algorithm (defaults to SHA-256 before the
    /// ServerHello selects a suite).
    fn hashAlg(self: *const Client) HashAlg {
        const suite = self.selected_suite orelse return .sha256;
        return suite.hashAlg();
    }

    fn hashLen(self: *const Client) usize {
        return switch (self.hashAlg()) {
            .sha256 => Sha256.hash_len,
            .sha384 => Sha384.hash_len,
        };
    }

    /// Transcript-Hash of the handshake so far, written into `out`; returns the
    /// digest length (32 for SHA-256, 48 for SHA-384).
    fn transcriptHash(self: *const Client, out: *[max_hash_len]u8) usize {
        switch (self.hashAlg()) {
            .sha256 => {
                const d = Sha256.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
            .sha384 => {
                const d = Sha384.transcriptHash(self.transcript.items);
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
        }
    }

    /// Constant-time Finished verify against the negotiated hash.
    fn finishedVerify(self: *const Client, base_key: *const [max_hash_len]u8, received: []const u8) bool {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        return switch (self.hashAlg()) {
            .sha256 => tls_finished.Sha256F.verify(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*, received),
            .sha384 => tls_finished.Sha384F.verify(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*, received),
        };
    }

    /// Finished verify_data for our own Finished, written into `out`; returns len.
    fn finishedVerifyData(self: *const Client, base_key: *const [max_hash_len]u8, out: *[max_hash_len]u8) usize {
        var th: [max_hash_len]u8 = undefined;
        _ = self.transcriptHash(&th);
        switch (self.hashAlg()) {
            .sha256 => {
                const v = tls_finished.Sha256F.verifyData(base_key[0..Sha256.hash_len].*, th[0..Sha256.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
            .sha384 => {
                const v = tls_finished.Sha384F.verifyData(base_key[0..Sha384.hash_len].*, th[0..Sha384.hash_len].*);
                @memcpy(out[0..v.len], &v);
                return v.len;
            },
        }
    }

    fn deriveHandshakeKeys(self: *Client, shared_secret: []const u8) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveHandshakeKeysT(Sha256, shared_secret),
            .sha384 => try self.deriveHandshakeKeysT(Sha384, shared_secret),
        }
    }

    fn deriveClientEarlyTrafficKeys(self: *Client) Error!void {
        const offer = self.resume_offer orelse return error.BadState;
        switch (offer.suite.hashAlg()) {
            .sha256 => try self.deriveClientEarlyTrafficKeysT(Sha256, offer),
            .sha384 => try self.deriveClientEarlyTrafficKeysT(Sha384, offer),
        }
    }

    fn deriveClientEarlyTrafficKeysT(self: *Client, comptime KS: type, offer: ResumeOffer) Error!void {
        if (offer.psk_len != KS.hash_len) return error.BadHandshake;
        var early = KS.earlySecret(offer.psk[0..offer.psk_len]);
        defer early.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.deriveSecret(&early, "c e traffic", &th);
        defer traffic.wipe();
        var traffic_bytes = traffic.declassify();
        defer secureZero(&traffic_bytes);
        try deriveTrafficKeys(offer.suite, &traffic_bytes, &self.client_early_keys);
        self.early_write_seq = 0;
    }

    fn deriveHandshakeKeysT(self: *Client, comptime KS: type, shared_secret: []const u8) Error!void {
        const psk = if (self.psk_accepted) blk: {
            const offer = self.resume_offer orelse return error.BadHandshake;
            if (offer.psk_len != KS.hash_len) return error.BadHandshake;
            break :blk offer.psk[0..offer.psk_len];
        } else "";
        var early = KS.earlySecret(psk);
        defer early.wipe();
        self.early_secret[0..KS.hash_len].* = early.declassify();

        var handshake = try KS.handshakeSecret(&early, shared_secret);
        defer handshake.wipe();
        self.handshake_secret[0..KS.hash_len].* = handshake.declassify();

        const th = KS.transcriptHash(self.transcript.items);
        var traffic = try KS.handshakeTrafficSecrets(&handshake, &th);
        defer traffic.wipe();
        self.client_hs_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_hs_secret[0..KS.hash_len].* = traffic.server.declassify();

        var master = try KS.masterSecret(&handshake);
        defer master.wipe();
        self.master_secret[0..KS.hash_len].* = master.declassify();

        const suite = self.selected_suite orelse return error.BadState;
        try deriveTrafficKeys(suite, self.client_hs_secret[0..KS.hash_len], &self.client_hs_keys);
        try deriveTrafficKeys(suite, self.server_hs_secret[0..KS.hash_len], &self.server_hs_keys);
        self.hs_read_seq = 0;
        self.hs_write_seq = 0;
    }

    fn deriveApplicationKeys(self: *Client) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveApplicationKeysT(Sha256),
            .sha384 => try self.deriveApplicationKeysT(Sha384),
        }
    }

    fn deriveApplicationKeysT(self: *Client, comptime KS: type) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.master_secret[0..KS.hash_len]);
        var master = KS.SecretBytes.init(sk);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var exporter_master = try KS.exporterMasterSecret(&master, &th);
        defer exporter_master.wipe();
        self.exporter_master_secret[0..KS.hash_len].* = exporter_master.declassify();
        self.exporter_master_secret_ready = true;
        var traffic = try KS.applicationTrafficSecrets(&master, &th);
        defer traffic.wipe();
        self.client_app_secret[0..KS.hash_len].* = traffic.client.declassify();
        self.server_app_secret[0..KS.hash_len].* = traffic.server.declassify();
        const suite = self.selected_suite orelse return error.BadState;
        try deriveTrafficKeys(suite, self.client_app_secret[0..KS.hash_len], &self.client_app_keys);
        try deriveTrafficKeys(suite, self.server_app_secret[0..KS.hash_len], &self.server_app_keys);
        self.app_read_seq = 0;
        self.app_write_seq = 0;
    }

    fn deriveResumptionMasterSecret(self: *Client) Error!void {
        switch (self.hashAlg()) {
            .sha256 => try self.deriveResumptionMasterSecretT(Sha256),
            .sha384 => try self.deriveResumptionMasterSecretT(Sha384),
        }
    }

    fn deriveResumptionMasterSecretT(self: *Client, comptime KS: type) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.master_secret[0..KS.hash_len]);
        var master = KS.SecretBytes.init(sk);
        defer master.wipe();
        const th = KS.transcriptHash(self.transcript.items);
        var rms = try KS.deriveSecret(&master, "res master", &th);
        defer rms.wipe();
        self.resumption_master_secret[0..KS.hash_len].* = rms.declassify();
    }

    fn exportKeyingMaterialT(self: *const Client, comptime KS: type, label: []const u8, context: []const u8, out: []u8) Error!void {
        var sk: [KS.hash_len]u8 = undefined;
        @memcpy(&sk, self.exporter_master_secret[0..KS.hash_len]);
        var exporter_master = KS.SecretBytes.init(sk);
        defer exporter_master.wipe();
        try KS.exportKeyingMaterial(&exporter_master, label, context, out);
    }

    fn appendTranscript(self: *Client, bytes: []const u8) Error!void {
        if (self.transcript.items.len > std.math.maxInt(usize) - bytes.len) return error.TranscriptOverflow;
        try self.transcript.appendSlice(self.allocator, bytes);
    }
};

const PlainRecord = struct {
    content_type: tls_record.ContentType,
    fragment: []const u8,
    wire_len: usize,
};

const OpenedRecord = struct {
    content_type: tls_record.ContentType,
    content: []u8,
};

const ServerNameTypeHost: u8 = 0;
const ext_status_request: u16 = 5;
/// RFC 6962 §3.3 `signed_certificate_timestamp` extension. Advertised (empty) in
/// the ClientHello ONLY when a pinned CT log set is configured, so the SCT that a
/// TLS-1.3 server may return in the leaf CertificateEntry — signing over the
/// FINAL certificate (`x509_entry`), not the precertificate — can be collected.
const ext_signed_certificate_timestamp: u16 = 18;
const hello_retry_request_random = [_]u8{
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/// A ServerHello whose random equals the magic value is a HelloRetryRequest
/// (RFC 8446 §4.1.3). `body` is the handshake message body (legacy_version then
/// the 32-byte random).
fn isHelloRetryRequest(body: []const u8) bool {
    if (body.len < 2 + 32) return false;
    return std.mem.eql(u8, body[2..34], &hello_retry_request_random);
}

fn osEntropy(buf: []u8) Error!void {
    random_mod.fillOsEntropy(buf) catch return error.BadHandshake;
}

fn writePlainRecord(allocator: Allocator, typ: tls_record.ContentType, fragment: []const u8) Error![]u8 {
    if (fragment.len > tls_record.max_plaintext_len) return error.BadRecord;
    var out = try allocator.alloc(u8, tls_record.record_header_len + fragment.len);
    errdefer allocator.free(out);
    out[0] = @intFromEnum(typ);
    std.mem.writeInt(u16, out[1..3], 0x0301, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(fragment.len), .big);
    @memcpy(out[5..], fragment);
    return out;
}

/// Frame one complete plaintext record out of `buf`.
///
/// Returns null ONLY when more bytes are genuinely needed. A structurally
/// invalid header is an error, never a null — conflating "invalid" with
/// "incomplete" leaves the offending bytes in `recv_buf` forever, so a hostile
/// (or MITM-substituted) server streaming records with an unknown outer content
/// type grows that buffer without bound while the handshake neither advances nor
/// fails. For the ACME client that is a renewal that never completes.
///
///   * RFC 8446 §5: an unexpected record type MUST terminate the connection.
///   * RFC 8446 §5.2: TLSCiphertext.length MUST NOT exceed 2^14+256; the wire
///     field is a u16, so the cap has to be applied explicitly.
fn completePlainRecord(buf: []const u8) Error!?PlainRecord {
    if (buf.len < tls_record.record_header_len) return null;
    const typ = tls_record.ContentType.fromWire(buf[0]) orelse return error.BadRecord;
    const len = std.mem.readInt(u16, buf[3..5], .big);
    if (len > tls_record.max_ciphertext_len) return error.BadRecord;
    const total = tls_record.record_header_len + @as(usize, len);
    if (buf.len < total) return null;
    return .{ .content_type = typ, .fragment = buf[5..total], .wire_len = total };
}

fn sealRecordAlloc(
    allocator: Allocator,
    suite: CipherSuite,
    keys: *const TrafficKeys,
    seq: u64,
    typ: tls_record.ContentType,
    plaintext: []const u8,
) Error![]u8 {
    const inner_len = plaintext.len + 1;
    const inner = try allocator.alloc(u8, inner_len);
    defer allocator.free(inner);
    const encoded = try tls_record.encodeInnerPlaintext(typ, plaintext, 0, inner);
    const encrypted_len = encoded.len + suite.tagLen();
    var out = try allocator.alloc(u8, tls_record.record_header_len + encrypted_len);
    errdefer allocator.free(out);
    const aad = tls_record.makeAdditionalData(@intCast(encrypted_len));
    @memcpy(out[0..tls_record.record_header_len], &aad);
    const nonce = tls_record.deriveNonce(keys.iv, seq);
    switch (suite) {
        .tls_aes_128_gcm_sha256 => {
            const key = keys.key[0..Aes128Gcm.key_length].*;
            var tag: [Aes128Gcm.tag_length]u8 = undefined;
            Aes128Gcm.encrypt(out[5..][0..encoded.len], &tag, encoded, &aad, nonce, key);
            @memcpy(out[5 + encoded.len ..][0..tag.len], &tag);
        },
        .tls_aes_256_gcm_sha384 => {
            const key = keys.key[0..Aes256Gcm.key_length].*;
            var tag: [Aes256Gcm.tag_length]u8 = undefined;
            Aes256Gcm.encrypt(out[5..][0..encoded.len], &tag, encoded, &aad, nonce, key);
            @memcpy(out[5 + encoded.len ..][0..tag.len], &tag);
        },
        .tls_chacha20_poly1305_sha256 => {
            const key = keys.key[0..ChaCha20Poly1305.key_length].*;
            var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
            ChaCha20Poly1305.encrypt(out[5..][0..encoded.len], &tag, encoded, &aad, nonce, key);
            @memcpy(out[5 + encoded.len ..][0..tag.len], &tag);
        },
    }
    return out;
}

fn openRecordAlloc(
    allocator: Allocator,
    suite: CipherSuite,
    keys: *const TrafficKeys,
    seq: u64,
    record: []const u8,
) Error!OpenedRecord {
    const parsed = try tls_record.parseCiphertext(record);
    if (parsed.encrypted_record.len < suite.tagLen()) return error.BadRecord;
    const clen = parsed.encrypted_record.len - suite.tagLen();
    const inner = try allocator.alloc(u8, clen);
    errdefer allocator.free(inner);
    const aad = parsed.headerBytes();
    const nonce = tls_record.deriveNonce(keys.iv, seq);
    switch (suite) {
        .tls_aes_128_gcm_sha256 => {
            const key = keys.key[0..Aes128Gcm.key_length].*;
            const tag = parsed.encrypted_record[clen..][0..Aes128Gcm.tag_length].*;
            Aes128Gcm.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
        },
        .tls_aes_256_gcm_sha384 => {
            const key = keys.key[0..Aes256Gcm.key_length].*;
            const tag = parsed.encrypted_record[clen..][0..Aes256Gcm.tag_length].*;
            Aes256Gcm.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
        },
        .tls_chacha20_poly1305_sha256 => {
            const key = keys.key[0..ChaCha20Poly1305.key_length].*;
            const tag = parsed.encrypted_record[clen..][0..ChaCha20Poly1305.tag_length].*;
            ChaCha20Poly1305.decrypt(inner, parsed.encrypted_record[0..clen], tag, &aad, nonce, key) catch return error.BadRecord;
        },
    }
    const opened = try tls_record.decodeInnerPlaintext(inner);
    const content = try allocator.dupe(u8, opened.content);
    allocator.free(inner);
    return .{ .content_type = opened.content_type, .content = content };
}

fn deriveTrafficKeys(suite: CipherSuite, secret_bytes: []const u8, out: *TrafficKeys) Error!void {
    switch (suite.hashAlg()) {
        .sha256 => try deriveTrafficKeysT(Sha256, suite, secret_bytes, out),
        .sha384 => try deriveTrafficKeysT(Sha384, suite, secret_bytes, out),
    }
}

fn deriveTrafficKeysT(comptime KS: type, suite: CipherSuite, secret_bytes: []const u8, out: *TrafficKeys) Error!void {
    if (secret_bytes.len < KS.hash_len) return error.BadState;
    var sk: [KS.hash_len]u8 = undefined;
    @memcpy(&sk, secret_bytes[0..KS.hash_len]);
    var secret = KS.SecretBytes.init(sk);
    defer secret.wipe();
    out.wipe();
    try KS.hkdfExpandLabel(&secret, "key", "", out.key[0..suite.keyLen()]);
    try KS.hkdfExpandLabel(&secret, "iv", "", &out.iv);
}

/// In-place KeyUpdate of a traffic secret stored in a `[max_hash_len]u8` field;
/// only the schedule's digest-length prefix is live.
fn applyKeyUpdateT(comptime KS: type, suite: CipherSuite, secret: *[max_hash_len]u8, keys: *TrafficKeys) Error!void {
    var sk: [KS.hash_len]u8 = undefined;
    @memcpy(&sk, secret[0..KS.hash_len]);
    var cur = KS.SecretBytes.init(sk);
    defer cur.wipe();
    var next: [KS.hash_len]u8 = undefined;
    try KS.hkdfExpandLabel(&cur, "traffic upd", "", &next);
    @memcpy(secret[0..KS.hash_len], &next);
    secureZero(&next);
    try deriveTrafficKeys(suite, secret[0..KS.hash_len], keys);
}

fn buildSniBody(out: []u8, name: []const u8) Error![]const u8 {
    if (name.len > std.math.maxInt(u16)) return error.BadHandshake;
    const entry_len = 1 + 2 + name.len;
    const total = 2 + entry_len;
    if (out.len < total) return error.OutputTooSmall;
    std.mem.writeInt(u16, out[0..2], @intCast(entry_len), .big);
    out[2] = ServerNameTypeHost;
    std.mem.writeInt(u16, out[3..5], @intCast(name.len), .big);
    @memcpy(out[5..][0..name.len], name);
    return out[0..total];
}

fn parseTicketEarlyDataLimit(extensions: []const u8) Error!u32 {
    var it = tls_extension.Iterator.init(extensions);
    var limit: u32 = 0;
    while (try it.next()) |ext| {
        if (ext.typed() == .early_data) {
            if (ext.data.len != 4) return error.BadHandshake;
            limit = std.mem.readInt(u32, ext.data[0..4], .big);
        }
    }
    return limit;
}

/// Parse a TLS 1.3 CertificateEntry status_request extension body.
///
/// The extension_data is a CertificateStatus:
/// status_type(1) || ocsp_response_length(uint24) || OCSPResponse DER. Only
/// status_type=ocsp(1) is accepted here.
/// Config-gated CRL revocation check for the leaf, FAIL-OPEN. Only a CRL that
/// (a) parses, (b) verifies under the leaf issuer's key, and (c) is current at
/// `now_unix` may revoke: it returns `error.CertificateRevoked` iff the leaf
/// serial is listed. Every other case — no clock, unparseable, wrong-issuer
/// signature, or a stale/not-yet-valid window — is IGNORED, so a missing or
/// broken CRL never breaks an otherwise-valid handshake. Conservative posture for
/// an outbound HTTPS/ACME client: soft-fail revocation, hard-fail forgery (the
/// chain verifier already enforced the latter; a CRL can only ever authenticate a
/// *revocation*, never clear a bad chain).
fn checkCrlRevocation(crl_der: []const u8, issuer_spki_der: []const u8, leaf_serial_der: []const u8, now_unix: ?i64) Error!void {
    const now = now_unix orelse return; // no trustworthy clock → can't judge currency
    const parsed = crl.parse(crl_der) catch return; // fail-open: unparseable CRL
    crl.verifyParsedCrlSignature(parsed, issuer_spki_der) catch return; // fail-open: not authentic for this issuer
    if (!crl.crlIsCurrent(parsed, now)) return; // fail-open: stale or not-yet-valid
    if (crl.isSerialRevoked(parsed, leaf_serial_der)) return error.CertificateRevoked;
}

fn parseCertificateStatusOcsp(data: []const u8) Error![]const u8 {
    if (data.len < 4) return error.BadCertificate;
    if (data[0] != 1) return error.BadCertificate;
    const len = readU24Bytes(data[1..4]);
    if (data.len != 4 + len or len == 0) return error.BadCertificate;
    return data[4..];
}

/// Authenticate a stapled OCSP response and enforce the leaf's serial status.
///
/// Absence is handled by the caller. A signed `good`, signed `unknown`, or a
/// signed response with no matching SingleResponse soft-passes; a matching
/// `revoked` SingleResponse fails closed.
///
/// `now_unix` (the client's validity clock) enables delegated-responder
/// authorization (RFC 6960 §4.2.2.2 — most public CAs), which needs a clock to
/// check the responder cert's validity window. Without a clock we fall back to
/// direct-issuer signing only (fail-closed: a delegated staple is rejected rather
/// than trusted with an unverifiable responder-cert lifetime).
fn verifyOcspStapleForLeaf(staple_der: []const u8, issuer_spki_der: []const u8, leaf_serial: []const u8, now_unix: ?i64) Error!void {
    const parsed = try ocsp.parse(staple_der);
    const authenticated = if (now_unix) |now|
        ocsp.verifyResponseSignatureWithChain(parsed, issuer_spki_der, now)
    else
        ocsp.verifyResponseSignature(parsed, issuer_spki_der);
    if (!authenticated) return error.BadCertificate;
    try enforceOcspStatusForSerial(parsed, leaf_serial);
}

fn enforceOcspStatusForSerial(parsed: anytype, leaf_serial: []const u8) Error!void {
    const status = ocsp.statusForSerial(parsed, leaf_serial) orelse return;
    switch (status) {
        .revoked => return error.CertificateRevoked,
        .good, .unknown => return,
    }
}

// ---------------------------------------------------------------------------
// Embedded-SCT (Certificate Transparency, RFC 6962) verification — roadmap 4.1.
//
// OPT-IN, mirroring the CRL wiring above: runs only when a non-empty pinned CT
// log set was configured, and byte-identical to the pre-feature client when it
// is empty. Two composable policies gate the result:
//   * `enforce_sct` (tamper detection): a pinned-log-matched, signature-INVALID
//     SCT rejects the handshake (`error.BadSct`).
//   * `require_sct` (presence + distinct-log quorum): the leaf must present at
//     least N SCTs that each verify against a DISTINCT pinned log, else
//     `error.InsufficientScts` — closing the "embed no SCT" mis-issuance bypass.
// With both off (`enforce_sct=false`, `require_sct=0`) the path is FAIL-OPEN: a
// leaf with no SCT extension, or SCTs only from unpinned logs, always passes.
// ---------------------------------------------------------------------------

/// Deep-copy a caller-supplied pinned CT log set into allocator-owned storage:
/// the `[]sct.CtLog` slice and each entry's `key_spki_der`. Leak-tight on OOM —
/// on failure every byte allocated so far is freed. An empty input yields the
/// empty slice with no allocation.
fn dupeCtLogs(allocator: Allocator, logs: []const sct.CtLog) Allocator.Error![]sct.CtLog {
    if (logs.len == 0) return &.{};
    const owned = try allocator.alloc(sct.CtLog, logs.len);
    var made: usize = 0;
    errdefer {
        for (owned[0..made]) |l| allocator.free(l.key_spki_der);
        allocator.free(owned);
    }
    while (made < logs.len) : (made += 1) {
        const key = try allocator.dupe(u8, logs[made].key_spki_der);
        owned[made] = .{ .log_id = logs[made].log_id, .key_spki_der = key };
    }
    return owned;
}

/// Free a deep-copied CT log set (each `key_spki_der` then the slice). A no-op on
/// the empty set so it is safe to call unconditionally.
fn freeCtLogs(allocator: Allocator, logs: []sct.CtLog) void {
    if (logs.len == 0) return;
    for (logs) |l| allocator.free(l.key_spki_der);
    allocator.free(logs);
}

/// OPT-IN Certificate Transparency (RFC 6962) verification for the leaf, pooling
/// SCTs from ALL THREE delivery methods a TLS-1.3 client can receive:
///
///   * the EMBEDDED X.509 SCT-list extension — SCTs signing the PRECERTIFICATE
///     (`precert_entry`: the leaf TBS with the SCT-list + poison extensions
///     stripped, prefixed by the issuer key hash);
///   * the leaf CertificateEntry's `signed_certificate_timestamp` extension
///     (`tls_ext_scts`, RFC 6962 §3.3) — SCTs signing the FINAL certificate
///     (`x509_entry`: the leaf DER); and
///   * the stapled OCSP response's SingleResponse SCT extension (`ocsp_staple`,
///     OID 1.3.6.1.4.1.11129.2.4.5) — SCTs also signing the FINAL certificate
///     (`x509_entry`), mined from the response matching the leaf serial.
///
/// All three sources are verified against `ct_logs` and pooled into ONE cross-
/// source distinct-log presence quorum (a log valid in more than one source counts
/// once), which two independent, composable policies act on:
///
///   * `enforce` (tamper detection): ANY pinned-log-matched SCT from ANY source
///     whose signature is INVALID rejects with `error.BadSct`.
///   * `require` (presence + distinct-log quorum): when `>= 1`, the pooled set
///     must reach `require` DISTINCT pinned logs with a valid SCT, else
///     `error.InsufficientScts`.
///
/// Fail-open vs fail-closed hinges on `require`. When `require == 0` this stays
/// FAIL-OPEN: absent SCTs, an unpinned log, or any parse/reconstruction failure
/// contributes a zero summary that no enabled policy rejects. When `require >= 1`
/// those same "no valid SCTs proven" outcomes are a hard reject — an attacker
/// omitting SCTs from all three sources cannot reach the quorum.
///
/// `ct_logs` empty ⇒ the entire path is skipped AND no ext-18 was ever advertised
/// in the ClientHello (OCSP stapling is requested regardless, so the OCSP source
/// adds no wire change) ⇒ the wire is byte-identical to the pre-feature client
/// regardless of `enforce`/`require`.
///
/// The temporal (future-dated) check is deliberately NOT enforced here: passing
/// a null clock scopes `.invalid` to genuine authentication failures (bad
/// signature, malformed SCT, algorithm mismatch), matching the conservative
/// outbound-client posture where only a forged SCT — never clock skew — rejects.
fn verifyScts(
    chain: []const []const u8,
    tls_ext_scts: ?[]const u8,
    ocsp_staple: ?[]const u8,
    ct_logs: []const sct.CtLog,
    enforce: bool,
    require: u8,
) Error!void {
    if (ct_logs.len == 0) return; // feature off ⇒ nothing runs, wire byte-identical

    // Pool distinct valid logs across all sources; track any invalid SCT for the
    // tamper-detection policy. Every fail-open path (missing chain, absent SCTs,
    // precert reconstruction failure, unparseable staple, malformed list) yields a
    // zero summary, so a mis-issued cert that simply omits SCTs cannot bypass a
    // `require >= 1` policy.
    var pooled: sct.DistinctValidLogs = .{};
    var any_invalid = false;

    const embedded = embeddedSctSummary(chain, ct_logs, &pooled);
    if (embedded.invalid > 0) any_invalid = true;

    if (tls_ext_scts) |list_bytes| {
        const ext = tlsExtSctSummary(chain, list_bytes, ct_logs, &pooled);
        if (ext.invalid > 0) any_invalid = true;
    }

    if (ocsp_staple) |staple| {
        const oc = ocspSctSummary(chain, staple, ct_logs, &pooled);
        if (oc.invalid > 0) any_invalid = true;
    }

    // Tamper detection: an authenticated-but-invalid SCT rejects under `enforce`.
    if (enforce and any_invalid) return error.BadSct;
    // Presence + distinct-log quorum over the pooled set. Skipped entirely when
    // `require == 0`, so the default path is byte-for-byte the prior fail-open
    // behavior.
    if (require >= 1 and pooled.count() < require) return error.InsufficientScts;
}

/// OPT-IN embedded-SCT verification for the leaf certificate. Thin wrapper over
/// `verifyScts` with no TLS-extension or OCSP source (the embedded X.509 SCT
/// extension only). Retained as a standalone entrypoint for direct embedded-only
/// checks.
fn verifyEmbeddedScts(
    chain: []const []const u8,
    ct_logs: []const sct.CtLog,
    enforce: bool,
    require: u8,
) Error!void {
    return verifyScts(chain, null, null, ct_logs, enforce, require);
}

/// Verify the leaf's EMBEDDED SCT-list extension against `ct_logs`, recording
/// distinct valid logs into `pooled`. Returns a zero `sct.ListSummary` on every
/// fail-open path (no leaf, no SCT extension, precert reconstruction failure,
/// malformed SCT list) — the caller's `require` gate decides open vs closed.
fn embeddedSctSummary(
    chain: []const []const u8,
    ct_logs: []const sct.CtLog,
    pooled: *sct.DistinctValidLogs,
) sct.ListSummary {
    if (chain.len == 0) return .{}; // defensive: no leaf to check
    const leaf_der = chain[0];
    const list_bytes = (x509.findSctListExtension(leaf_der) catch return .{}) orelse
        return .{}; // no embedded SCTs

    // Reconstruct the precert TBS (zero summary on any reconstruction failure).
    var tbs_buf: [sct.max_precert_tbs_len]u8 = undefined;
    const tbs = x509.buildPrecertTbs(&tbs_buf, leaf_der) catch return .{};

    // issuer_key_hash = SHA-256 of the issuer's SubjectPublicKeyInfo. The issuer
    // is chain[1] when present, else the leaf itself — matching the OCSP/CRL
    // issuer fallback above. A leaf-ONLY chain whose issuer is a directly-trusted
    // root (absent from `chain`) would hash the leaf's own SPKI, so a genuine
    // embedded SCT tallies `.invalid` — under `enforce` a false reject and under
    // `require` a below-quorum reject (both fail-CLOSED, never a security bypass)
    // for a cert shape that is essentially nonexistent (SCT-embedding issuers are
    // intermediates that ship in the chain). With both policies off it is tolerated.
    const issuer_der = if (chain.len > 1) chain[1] else chain[0];
    const issuer_parts = extractCertParts(issuer_der) catch return .{};
    const issuer_key_hash = hash.Sha256.hash(issuer_parts.spki_der);

    var entry_buf: [sct.max_internal_signed_entry]u8 = undefined;
    const entry = sct.buildPrecertEntry(&entry_buf, issuer_key_hash, tbs) catch return .{};
    const ctx = sct.CertContext{ .entry_type = .precert_entry, .signed_entry = entry };

    return sct.verifyListAccumulating(list_bytes, ctx, ct_logs, null, pooled) catch return .{};
}

/// Verify the leaf's TLS-extension SCT list (RFC 6962 §3.3 `x509_entry`, signing
/// the FINAL leaf DER) against `ct_logs`, recording distinct valid logs into
/// `pooled`. Returns a zero `sct.ListSummary` on any fail-open path (no leaf,
/// malformed list) so the caller's `require` gate decides open vs closed.
///
/// TLS-delivered SCTs sign the `x509_entry` (final cert) — the common case. Should
/// a server uncommonly deliver a PRECERT SCT over this extension, it reconstructs
/// under the wrong entry type and tallies `.invalid`: a false-reject under
/// `enforce` and a non-credit under `require` — both fail-CLOSED, never a bypass —
/// mirroring the embedded path's issuer-fallback note above.
fn tlsExtSctSummary(
    chain: []const []const u8,
    list_bytes: []const u8,
    ct_logs: []const sct.CtLog,
    pooled: *sct.DistinctValidLogs,
) sct.ListSummary {
    if (chain.len == 0) return .{}; // defensive: no leaf to check
    const ctx = sct.CertContext{ .entry_type = .x509_entry, .signed_entry = chain[0] };
    return sct.verifyListAccumulating(list_bytes, ctx, ct_logs, null, pooled) catch return .{};
}

/// Verify the leaf's OCSP-DELIVERED SCT list against `ct_logs`, recording distinct
/// valid logs into `pooled`. Mines the SCT-list extension (OID
/// 1.3.6.1.4.1.11129.2.4.5) from the SingleResponse whose CertID serial matches
/// the leaf, in the stapled OCSP response `ocsp_staple`. OCSP-delivered SCTs sign
/// the FINAL leaf DER (`x509_entry`) — the same entry type as the TLS extension.
///
/// The SCT's authenticity is established by its OWN log signature (verified against
/// `ct_logs`), NOT by the OCSP response signature — so the staple need not be
/// separately validated here; the leaf-serial scoping is only to find the right
/// SingleResponse. The leaf serial is read STRUCTURALLY (`leafSerialDer`) rather
/// than via a full `x509.parse`: the chain was already verified at the call site,
/// and this keeps the OCSP source symmetric with `embeddedSctSummary` /
/// `tlsExtSctSummary` (all navigate structurally). Returns a zero `sct.ListSummary`
/// on every fail-open path (no leaf, unreadable serial, unparseable staple, no
/// matching SingleResponse, no SCT extension, malformed list) so the caller's
/// `require` gate decides open vs closed. Should a server uncommonly deliver a
/// PRECERT SCT over OCSP, it reconstructs under the wrong entry type and tallies
/// `.invalid` — a false-reject under `enforce` and a non-credit under `require`,
/// both fail-CLOSED, never a bypass — mirroring the TLS-extension path.
fn ocspSctSummary(
    chain: []const []const u8,
    ocsp_staple: []const u8,
    ct_logs: []const sct.CtLog,
    pooled: *sct.DistinctValidLogs,
) sct.ListSummary {
    if (chain.len == 0) return .{}; // defensive: no leaf to check
    const serial = leafSerialDer(chain[0]) orelse return .{};
    const parsed = ocsp.parse(ocsp_staple) catch return .{};
    const single = ocsp.singleForSerial(parsed, serial) orelse return .{};
    const list_bytes = (ocsp.sctListFromSingleExtensions(single.single_extensions_der) catch return .{}) orelse
        return .{}; // no OCSP-delivered SCTs
    const ctx = sct.CertContext{ .entry_type = .x509_entry, .signed_entry = chain[0] };
    return sct.verifyListAccumulating(list_bytes, ctx, ct_logs, null, pooled) catch return .{};
}

/// Structurally extract the leaf's `serialNumber` INTEGER value — the exact bytes
/// `x509.parse` exposes as `serial_der` — by navigating Certificate → TBS →
/// serialNumber without a full parse or validation (the chain is verified
/// elsewhere). Fail-open: any malformed DER yields `null`, so a caller treats an
/// unreadable serial as "no OCSP SCTs to mine".
fn leafSerialDer(cert_der: []const u8) ?[]const u8 {
    var top = x509.DerReader.init(cert_der);
    const cert_seq = top.readExpected(x509.Tag.sequence) catch return null;
    var body = top.child(cert_seq) catch return null;
    const tbs = body.readExpected(x509.Tag.sequence) catch return null;
    var tbs_reader = body.child(tbs) catch return null;
    if (tbs_reader.hasRemaining() and (tbs_reader.peekTag() catch return null) == x509.Tag.context_0_constructed) {
        _ = tbs_reader.readTlv() catch return null; // [0] EXPLICIT version
    }
    const serial = tbs_reader.readExpected(x509.Tag.integer) catch return null;
    return serial.value;
}

fn writeHandshake(allocator: Allocator, out: *std.ArrayList(u8), typ: HandshakeType, body: []const u8) Error!void {
    if (body.len > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @intFromEnum(typ));
    try appendU24(allocator, out, body.len);
    try out.appendSlice(allocator, body);
}

fn parseHandshake(input: []const u8, offset: *usize) Error!HandshakeMsg {
    if (input.len - offset.* < 4) return error.BadHandshake;
    const start = offset.*;
    const typ: HandshakeType = @enumFromInt(input[start]);
    const len = readU24Bytes(input[start + 1 ..][0..3]);
    const body_start = start + 4;
    const body_end = body_start + len;
    if (body_end > input.len) return error.BadHandshake;
    offset.* = body_end;
    return .{ .typ = typ, .body = input[body_start..body_end], .raw = input[start..body_end] };
}

fn parseHandshakeMaybe(input: []const u8, offset: *usize) ?HandshakeMsg {
    if (input.len - offset.* < 4) return null;
    const len = readU24Bytes(input[offset.* + 1 ..][0..3]);
    if (input.len - offset.* < 4 + len) return null;
    return parseHandshake(input, offset) catch null;
}

fn appendU16(allocator: Allocator, out: *std.ArrayList(u8), value: u16) Allocator.Error!void {
    try out.append(allocator, @intCast(value >> 8));
    try out.append(allocator, @intCast(value & 0xff));
}

fn appendU24(allocator: Allocator, out: *std.ArrayList(u8), value: usize) Error!void {
    if (value > 0x00ff_ffff) return error.BadHandshake;
    try out.append(allocator, @intCast((value >> 16) & 0xff));
    try out.append(allocator, @intCast((value >> 8) & 0xff));
    try out.append(allocator, @intCast(value & 0xff));
}

fn readU24Bytes(bytes: []const u8) usize {
    return (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const remain = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..remain], list.items[n..]);
    list.shrinkRetainingCapacity(remain);
}

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(buf: []const u8) Cursor {
        return .{ .buf = buf };
    }

    fn remaining(self: Cursor) usize {
        return self.buf.len - self.pos;
    }

    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (self.remaining() < n) return error.DecodeError;
        const out = self.buf[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn readU8(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Cursor) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn readU24(self: *Cursor) Error!usize {
        return readU24Bytes((try self.take(3))[0..3]);
    }

    fn expectEmpty(self: Cursor) Error!void {
        if (self.remaining() != 0) return error.DecodeError;
    }
};

const certificate_verify_context = "TLS 1.3, server CertificateVerify";
const client_certificate_verify_context = "TLS 1.3, client CertificateVerify";

/// RFC 9345: the SignatureSchemes we accept for a delegated credential's
/// `dc_cert_verify_algorithm`. Advertised in the ClientHello `delegated_credential`
/// extension AND required of any DC we validate (§4.1.3 check 3: the algorithm
/// must be "allowed for use with delegated credentials"). These are exactly the
/// TLS 1.3 handshake-signature schemes `verifySignatureScheme` can verify.
const dc_accepted_schemes = [_]tls_signature_scheme.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .ed25519,
    .rsa_pss_rsae_sha256,
};

/// True when `scheme` (a raw wire code) is one we accept for a delegated
/// credential's `dc_cert_verify_algorithm`.
fn dcSchemeAccepted(scheme: u16) bool {
    for (dc_accepted_schemes) |s| {
        if (s.toInt() == scheme) return true;
    }
    return false;
}
/// 64 spaces + the longest context + 1 separator + the longest transcript hash.
const cert_verify_input_max = 64 + client_certificate_verify_context.len + 1 + max_hash_len;

/// Build the CertificateVerify signed content (RFC 8446 §4.4.3): 64 0x20 bytes,
/// the context string, a 0x00 separator, then the transcript hash. Written into
/// `out`; the returned slice is the used prefix. `context` is the server or
/// client context string and `transcript_hash` is 32 or 48 bytes.
fn buildCertVerifyInput(out: *[cert_verify_input_max]u8, context: []const u8, transcript_hash: []const u8) []const u8 {
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..context.len], context);
    out[64 + context.len] = 0;
    const tail = 64 + context.len + 1;
    @memcpy(out[tail..][0..transcript_hash.len], transcript_hash);
    return out[0 .. tail + transcript_hash.len];
}

/// Strictly validate a TLS 1.3 CertificateRequest body (RFC 8446 §4.3.2):
/// a 1-byte certificate_request_context (empty in the main handshake), then a
/// 2-byte length-prefixed extensions vector that parses cleanly, spans the
/// rest of the body exactly, and contains a well-formed, non-empty
/// signature_algorithms extension (the only mandatory one). Real clients
/// (gnutls/openssl) enforce all of this, so the loopback client must too —
/// otherwise server-side encoding bugs survive the round-trip tests.
fn validateCertificateRequest(body: []const u8, offered_client_raw_public_key: bool) Error!tls_extension.CertificateType {
    if (body.len < 1) return error.BadHandshake;
    const ctx_len = body[0];
    if (ctx_len != 0) return error.BadHandshake; // MUST be empty outside post-handshake auth
    const block = body[1..];
    const ext_body = tls_extension.unwrap(block) catch return error.BadHandshake;
    if (2 + ext_body.len != block.len) return error.BadHandshake; // trailing garbage
    var saw_signature_algorithms = false;
    var cert_type: tls_extension.CertificateType = .x509;
    var it = tls_extension.Iterator.init(ext_body);
    while (it.next() catch return error.BadHandshake) |ext| {
        switch (ext.typed()) {
            .signature_algorithms => {
                // signature_algorithms data: 2-byte list length + even-sized,
                // non-empty list of u16 schemes spanning the data exactly.
                if (ext.data.len < 4) return error.BadHandshake;
                const list_len = std.mem.readInt(u16, ext.data[0..2], .big);
                if (list_len == 0 or list_len % 2 != 0) return error.BadHandshake;
                if (2 + @as(usize, list_len) != ext.data.len) return error.BadHandshake;
                saw_signature_algorithms = true;
            },
            .client_certificate_type => {
                const selected = try tls_extension.parseSelectedCertType(ext.data);
                cert_type = switch (selected) {
                    .x509 => .x509,
                    .raw_public_key => if (offered_client_raw_public_key) .raw_public_key else return error.BadHandshake,
                    else => return error.BadHandshake,
                };
            },
            else => {},
        }
    }
    if (!saw_signature_algorithms) return error.BadHandshake;
    return cert_type;
}

fn verifySignatureScheme(key: LeafPublicKey, scheme: tls_signature_scheme.SignatureScheme, msg: []const u8, sig: []const u8) Error!void {
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            const pk = switch (key) {
                .ecdsa_p256 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            const decoded = try ecdsa_p256.signatureFromDer(sig);
            if (!ecdsa_p256.verify(decoded, msg, pk)) return error.BadSignature;
        },
        .ecdsa_secp384r1_sha384 => {
            const pk = switch (key) {
                .ecdsa_p384 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            const decoded = EcdsaP384.Signature.fromDer(sig) catch return error.BadSignature;
            decoded.verify(msg, pk) catch return error.BadSignature;
        },
        .rsa_pss_rsae_sha256 => {
            const pk = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            if (!rsa_verify.verifyPss(pk, .sha256, &digest, sig, 32)) return error.BadSignature;
        },
        .rsa_pkcs1_sha256 => {
            const pk = switch (key) {
                .rsa => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(msg, &digest, .{});
            if (!rsa_verify.verifyPkcs1v15(pk, .sha256, &digest, sig)) return error.BadSignature;
        },
        .ed25519 => {
            const pk = switch (key) {
                .ed25519 => |pk| pk,
                else => return error.UnsupportedPublicKey,
            };
            if (sig.len != sign.signature_len) return error.BadSignature;
            var fixed: sign.Signature = undefined;
            @memcpy(&fixed, sig);
            if (!try sign.verify(msg, fixed, pk)) return error.BadSignature;
        },
        else => return error.UnsupportedSignatureScheme,
    }
}

fn verifyChainToTrustAnchors(chain: []const []const u8, anchors: []const []const u8, server_name: []const u8, now: ?i64) Error!void {
    if (chain.len == 0) return error.EmptyCertificateChain;
    if (anchors.len == 0) return error.UnknownCa;
    const leaf = try x509.parse(chain[0]);
    if (!dnsNameMatchesCert(server_name, leaf)) return error.CertificateNameMismatch;
    // Reject expired / not-yet-valid leaf certificates when a clock is supplied.
    if (now) |t| try x509_verify.validateParsedAt(leaf, t);
    // The leaf must be usable for TLS server authentication: when an
    // ExtendedKeyUsage extension is present it has to list serverAuth (or
    // anyExtendedKeyUsage). Absent EKU is permitted (unrestricted).
    if (leaf.eku_present and !leaf.eku_server_auth) return error.BadCertificate;

    var i: usize = 0;
    while (i + 1 < chain.len) : (i += 1) {
        try verifyIssuedBy(chain[i], chain[i + 1]);
        const issuer = try x509.parse(chain[i + 1]);
        if (!issuer.basic_constraints_ca) return error.BadCertificate;
        // A CA in the path must be allowed to sign certificates and be valid now.
        if (issuer.key_usage_present and !issuer.key_usage_cert_sign) return error.BadCertificate;
        if (now) |t| try x509_verify.validateParsedAt(issuer, t);
        // RFC 5280 §4.2.1.10: a CA's NameConstraints bind the leaf's SAN
        // dNSNames. Shared with the hardened TLS 1.2 client (x509_verify.zig)
        // so the two engines cannot silently diverge on this check.
        try x509_verify.enforceNameConstraints(issuer, leaf);
    }

    // RFC 5280 §4.2.1.10 / §6.1.4(m): pathLenConstraint enforcement, shared
    // with the hardened TLS 1.2 client. Reduce the chain to per-cert facts
    // (path limit + self-issued) then check with the pure `enforcePathLen`
    // helper.
    var facts_buf: [16]x509_verify.CaPathFact = undefined;
    const fn_count = x509_verify.buildPathFacts(chain, &facts_buf);
    try x509_verify.enforcePathLen(facts_buf[0..fn_count]);

    // Anchor the chain tip: its issuer DN (or, for a self-issued tip, its own
    // subject DN) must match a configured anchor's subject, and its signature must
    // verify under that anchor's public key. A malformed anchor or a failed
    // match/verify falls through to the next anchor — the search never aborts on
    // one. The signature primitive delegates to `x509_verify.verifySignedBy`,
    // which covers the full sig-alg set (RSA PKCS#1 SHA-256/384/512, RSASSA-PSS,
    // ECDSA P-256/P-384, Ed25519), so real CA links signed with sha384WithRSA,
    // RSASSA-PSS, or ecdsa-with-SHA384 anchor correctly.
    const last = chain[chain.len - 1];
    const last_info = try x509_verify.linkInfo(last);
    for (anchors) |anchor_der| {
        const anchor_info = x509_verify.linkInfo(anchor_der) catch continue;
        if (!std.mem.eql(u8, last_info.issuer_der, anchor_info.subject_der) and
            !std.mem.eql(u8, last_info.subject_der, anchor_info.subject_der))
        {
            continue;
        }
        x509_verify.verifySignedBy(last_info, anchor_info) catch |err| {
            dbg("trust-anchor DN matched but signature check failed: {s}", .{@errorName(err)});
            continue;
        };
        return;
    }
    return error.UnknownCa;
}

fn verifyIssuedBy(child_der: []const u8, issuer_der: []const u8) Error!void {
    const child = try x509_verify.linkInfo(child_der);
    const issuer = try x509_verify.linkInfo(issuer_der);
    if (!std.mem.eql(u8, child.issuer_der, issuer.subject_der)) return error.BadCertificate;
    // Full sig-alg set via x509_verify (see verifyChainToTrustAnchors).
    try x509_verify.verifySignedBy(child, issuer);
}

fn dnsNameMatchesCert(server_name: []const u8, cert: x509.Certificate) bool {
    var i: usize = 0;
    while (i < cert.san_dns_count) : (i += 1) {
        if (dnsPatternMatches(cert.san_dns[i], server_name)) return true;
    }
    return false;
}

fn dnsPatternMatches(pattern: []const u8, name: []const u8) bool {
    if (asciiEqlIgnoreCase(pattern, name)) return true;
    if (pattern.len < 3 or pattern[0] != '*' or pattern[1] != '.') return false;
    const suffix = pattern[1..];
    if (!asciiEndsWithIgnoreCase(name, suffix)) return false;
    const prefix = name[0 .. name.len - suffix.len];
    return prefix.len != 0 and std.mem.indexOfScalar(u8, prefix, '.') == null;
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

fn extractCertParts(der: []const u8) Error!CertParts {
    _ = try x509_verify.linkInfo(der);
    var top = x509.DerReader.init(der);
    const cert_seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var body = try top.child(cert_seq);
    const tbs = try body.readExpected(x509.Tag.sequence);
    const sig_alg = try body.readExpected(x509.Tag.sequence);
    const signature = try body.readExpected(x509.Tag.bit_string);
    try body.expectEmpty();

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

    const sig_alg_parts = try algorithmOidParams(body, sig_alg);
    return .{
        .tbs_der = tbs.raw,
        .signature_algorithm_oid = sig_alg_parts.oid,
        .signature_algorithm_params = sig_alg_parts.params,
        .signature = try bitStringBytes(signature),
        .issuer_der = issuer.raw,
        .subject_der = subject.raw,
        .spki_der = spki.raw,
    };
}

fn parsePublicKeyFromSpki(spki_der: []const u8) Error!LeafPublicKey {
    var top = x509.DerReader.init(spki_der);
    const seq = try top.readExpected(x509.Tag.sequence);
    try top.expectEmpty();
    var spki = try top.child(seq);
    const alg_seq = try spki.readExpected(x509.Tag.sequence);
    const key_bits = try spki.readExpected(x509.Tag.bit_string);
    try spki.expectEmpty();
    const alg = try parseSpkiAlgorithm(spki, alg_seq);
    const key_bytes = try bitStringBytes(key_bits);
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
        if (key_bytes.len != sign.public_key_len) return error.UnsupportedPublicKey;
        var pk: sign.PublicKey = undefined;
        @memcpy(&pk, key_bytes);
        return .{ .ed25519 = pk };
    }
    return error.UnsupportedPublicKey;
}

const SpkiAlgorithm = struct {
    oid: []const u8,
    params: ?[]const u8,
};

fn parseSpkiAlgorithm(parent: x509.DerReader, seq_tlv: x509.Tlv) Error!SpkiAlgorithm {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) {
        const p = try r.readTlv();
        if (p.tag == x509.Tag.oid) params = p.value;
    }
    try r.expectEmpty();
    return .{ .oid = oid.value, .params = params };
}

fn algorithmOid(parent: x509.DerReader, seq_tlv: x509.Tlv) Error![]const u8 {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    while (r.hasRemaining()) _ = try r.readTlv();
    return oid.value;
}

/// Like `algorithmOid` but also returns the raw `parameters` TLV (if present) —
/// RSASSA-PSS carries its hash/MGF/salt there rather than in the OID.
fn algorithmOidParams(parent: x509.DerReader, seq_tlv: x509.Tlv) Error!struct {
    oid: []const u8,
    params: ?[]const u8,
} {
    var r = try parent.child(seq_tlv);
    const oid = try r.readExpected(x509.Tag.oid);
    var params: ?[]const u8 = null;
    if (r.hasRemaining()) params = (try r.readTlv()).raw;
    while (r.hasRemaining()) _ = try r.readTlv();
    return .{ .oid = oid.value, .params = params };
}

fn bitStringBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.bit_string or tlv.value.len == 0) return error.BadCertificate;
    if (tlv.value[0] != 0) return error.BadCertificate;
    return tlv.value[1..];
}

fn positiveIntegerBytes(tlv: x509.Tlv) Error![]const u8 {
    if (tlv.tag != x509.Tag.integer or tlv.value.len == 0) return error.BadCertificate;
    // A DER INTEGER is two's-complement: a set high bit on the *first* byte means
    // negative. Positive values whose magnitude MSB is set carry a leading 0x00
    // sign byte, which we strip to get the unsigned magnitude. (The previous
    // check tested the high bit *after* stripping, wrongly rejecting every
    // RSA modulus, whose magnitude MSB is always set.)
    if (tlv.value[0] & 0x80 != 0) return error.BadCertificate; // negative
    var v = tlv.value;
    if (v.len > 1 and v[0] == 0) v = v[1..]; // drop the sign byte
    if (v.len == 0) return error.BadCertificate;
    return v;
}

fn oidEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };
const oid_ed25519 = [_]u8{ 0x2B, 0x65, 0x70 };

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const p: *volatile u8 = @ptrCast(b);
        p.* = 0;
    }
}

test "ClientHello record carries SNI, TLS 1.3, suites, and key shares" {
    // Arrange
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();

    // Act
    const record = try client.start();
    defer allocator.free(record);

    // Assert
    try std.testing.expectEqual(@as(u8, @intFromEnum(tls_record.ContentType.handshake)), record[0]);
    try std.testing.expectEqual(.found, std.meta.activeTag(sni.extract(record)));
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    try std.testing.expectEqual(HandshakeType.client_hello, ch.typ);
    const ext_block = clientHelloExtensions(ch.body).?;
    var ext_it = tls_extension.Iterator.init(ext_block);
    var offers_tls13 = false;
    while (try ext_it.next()) |ext| {
        if (ext.typed() == .supported_versions) {
            offers_tls13 = tls_supported_versions.clientOffers(ext.data, tls_supported_versions.tls13);
        }
    }
    try std.testing.expect(offers_tls13);
}

test "ClientHello advertises OCSP status_request" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const ext_block = clientHelloExtensions(ch.body).?;
    var ext_it = tls_extension.Iterator.init(ext_block);
    var saw = false;
    while (try ext_it.next()) |ext| {
        if (ext.ext_type == ext_status_request) {
            saw = true;
            try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 0, 0, 0, 0 }, ext.data);
        }
    }
    try std.testing.expect(saw);
}

// ---------------------------------------------------------------------------
// RFC 7250 raw public keys (roadmap 5.3) — client-side negotiation + consume.
// ---------------------------------------------------------------------------

/// Wrap a 32-byte Ed25519 public key in a DER SubjectPublicKeyInfo:
/// SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00 || key } }.
fn ed25519Spki(pubkey: [sign.public_key_len]u8) [44]u8 {
    var spki: [44]u8 = undefined;
    const header = [_]u8{ 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00 };
    @memcpy(spki[0..header.len], &header);
    @memcpy(spki[header.len..][0..pubkey.len], &pubkey);
    return spki;
}

/// Build a TLS 1.3 Certificate message body carrying a single RawPublicKey
/// CertificateEntry whose cert_data is `spki` (RFC 7250 §3, RFC 8446 §4.4.2):
/// request_context(0) then one entry {u24 cert_data_len, spki, u16 ext_len=0}.
fn rawPubKeyCertificateBody(a: std.mem.Allocator, spki: []const u8) !std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(a);
    try body.append(a, 0); // certificate_request_context length = 0
    const entry_len: usize = 3 + spki.len + 2; // certLen(u24) + spki + extLen(u16)
    try body.append(a, @intCast((entry_len >> 16) & 0xff));
    try body.append(a, @intCast((entry_len >> 8) & 0xff));
    try body.append(a, @intCast(entry_len & 0xff));
    try body.append(a, @intCast((spki.len >> 16) & 0xff));
    try body.append(a, @intCast((spki.len >> 8) & 0xff));
    try body.append(a, @intCast(spki.len & 0xff));
    try body.appendSlice(a, spki);
    try body.append(a, 0);
    try body.append(a, 0); // extensions length = 0
    return body;
}

test "ClientHello omits certificate_type extensions when raw public keys are off (byte-identical gate)" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const ext_block = clientHelloExtensions(ch.body).?;

    // The default client offers NEITHER certificate_type extension, so no bytes
    // are added and the ClientHello wire is byte-identical to the pre-feature
    // encoding (the sole feature-added code is skipped when the gate is off).
    var it = tls_extension.Iterator.init(ext_block);
    while (try it.next()) |ext| {
        try std.testing.expect(ext.typed() != .server_certificate_type);
        try std.testing.expect(ext.typed() != .client_certificate_type);
    }
}

test "ClientHello offers server_certificate_type=[RawPublicKey, X509] when enabled" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{
        .server_name = "example.com",
        .trust_anchors = &.{},
        .offer_raw_public_key = true,
    });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const ext_block = clientHelloExtensions(ch.body).?;

    var saw_server: ?[]const u8 = null;
    var it = tls_extension.Iterator.init(ext_block);
    while (try it.next()) |ext| {
        // We present no client cert, so client_certificate_type is never offered.
        try std.testing.expect(ext.typed() != .client_certificate_type);
        if (ext.typed() == .server_certificate_type) saw_server = ext.data;
    }
    try std.testing.expect(saw_server != null);
    const data = saw_server.?;
    // Body: 1-byte list length (2) then RawPublicKey(2), X509(0), in preference order.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x02, 0x00 }, data);
    var out: [4]tls_extension.CertificateType = undefined;
    const parsed = try tls_extension.parseCertTypeList(data, &out);
    try std.testing.expectEqual(tls_extension.CertificateType.raw_public_key, parsed[0]);
    try std.testing.expectEqual(tls_extension.CertificateType.x509, parsed[1]);
}

test "ClientHello offers client_certificate_type=[RawPublicKey, X509] when raw client key is configured" {
    const allocator = std.testing.allocator;
    const seed: [sign.seed_len]u8 = @splat(0x43);
    var kp = try sign.KeyPair.fromSeed(seed);
    defer kp.deinit();
    const spki = ed25519Spki(kp.public_key);

    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();
    client.setClientRawPublicKeyForTest(&spki, kp);

    const record = try client.start();
    defer allocator.free(record);
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const ext_block = clientHelloExtensions(ch.body).?;

    var saw_client: ?[]const u8 = null;
    var it = tls_extension.Iterator.init(ext_block);
    while (try it.next()) |ext| {
        if (ext.typed() == .client_certificate_type) saw_client = ext.data;
    }
    try std.testing.expect(saw_client != null);
    const data = saw_client.?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x02, 0x00 }, data);
    var out: [4]tls_extension.CertificateType = undefined;
    const parsed = try tls_extension.parseCertTypeList(data, &out);
    try std.testing.expectEqual(tls_extension.CertificateType.raw_public_key, parsed[0]);
    try std.testing.expectEqual(tls_extension.CertificateType.x509, parsed[1]);
}

test "raw public key: bare SPKI Certificate sets the leaf key and validates the CertificateVerify signature" {
    const a = std.testing.allocator;

    // A deterministic Ed25519 server key; its bare SPKI IS the "certificate".
    const seed: [sign.seed_len]u8 = @splat(0x42);
    var kp = try sign.KeyPair.fromSeed(seed);
    defer kp.deinit();
    const spki = ed25519Spki(kp.public_key);

    var body = try rawPubKeyCertificateBody(a, &spki);
    defer body.deinit(a);

    var client = try Client.init(a, .{
        .server_name = "rpk.test",
        .trust_anchors = &.{},
        .offer_raw_public_key = true,
    });
    defer client.deinit();
    // Simulate the EncryptedExtensions negotiation result.
    client.server_cert_type = .raw_public_key;

    // The bare SPKI is accepted with NO chain and NO trust anchors, yielding the
    // Ed25519 leaf key.
    try client.parseAndVerifyCertificate(body.items);
    const lk = client.leaf_key.?;
    try std.testing.expect(lk == .ed25519);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &lk.ed25519);

    // Fold the Certificate into the transcript (as the driver would), then build
    // and verify a server CertificateVerify signed by the raw public key — proving
    // the RPK-derived key actually authenticates the handshake signature.
    try client.appendTranscript(body.items);
    var th: [max_hash_len]u8 = undefined;
    const th_len = client.transcriptHash(&th);
    var in_buf: [cert_verify_input_max]u8 = undefined;
    const input = buildCertVerifyInput(&in_buf, certificate_verify_context, th[0..th_len]);
    const sig = try kp.sign(input);

    var cv: std.ArrayList(u8) = .empty;
    defer cv.deinit(a);
    try cv.append(a, 0x08); // ed25519 signature scheme = 0x0807
    try cv.append(a, 0x07);
    try cv.append(a, @intCast((sig.len >> 8) & 0xff));
    try cv.append(a, @intCast(sig.len & 0xff));
    try cv.appendSlice(a, &sig);
    try client.verifyCertificateVerify(cv.items);

    // A tampered signature must fail against the same raw public key.
    cv.items[cv.items.len - 1] ^= 0x01;
    try std.testing.expectError(error.BadSignature, client.verifyCertificateVerify(cv.items));
}

test "raw public key OFF: a bare SPKI Certificate is rejected by the X.509 path (no trust bypass)" {
    const a = std.testing.allocator;
    const seed: [sign.seed_len]u8 = @splat(0x24);
    var kp = try sign.KeyPair.fromSeed(seed);
    defer kp.deinit();
    const spki = ed25519Spki(kp.public_key);

    var body = try rawPubKeyCertificateBody(a, &spki);
    defer body.deinit(a);

    // Default client: raw public keys OFF, so server_cert_type stays .x509.
    var client = try Client.init(a, .{ .server_name = "rpk.test", .trust_anchors = &.{} });
    defer client.deinit();
    try std.testing.expectEqual(tls_extension.CertificateType.x509, client.server_cert_type);

    // The same bare SPKI is NOT a valid X.509 chain — the normal path MUST reject
    // it. A raw key is never silently accepted when RPK was not negotiated.
    if (client.parseAndVerifyCertificate(body.items)) |_| {
        return error.RawKeyMustNotBeAcceptedOnX509Path;
    } else |_| {}
    try std.testing.expect(client.leaf_key == null);
}

test "EncryptedExtensions rejects a server_certificate_type we did not offer" {
    const a = std.testing.allocator;
    var client = try Client.init(a, .{ .server_name = "rpk.test", .trust_anchors = &.{} });
    defer client.deinit();

    var ext_buf: [64]u8 = undefined;
    var b = try tls_extension.Builder.begin(&ext_buf);
    try b.addTyped(.server_certificate_type, &[_]u8{tls_extension.CertificateType.raw_public_key.toInt()});
    const block = try b.finish();

    // Unsolicited: we never advertised raw public keys, so this is illegal.
    try std.testing.expectError(error.BadHandshake, client.parseEncryptedExtensions(block));
    try std.testing.expectEqual(tls_extension.CertificateType.x509, client.server_cert_type);
}

test "EncryptedExtensions server_certificate_type selection flips only the negotiated path" {
    const a = std.testing.allocator;
    var client = try Client.init(a, .{
        .server_name = "rpk.test",
        .trust_anchors = &.{},
        .offer_raw_public_key = true,
    });
    defer client.deinit();

    // Selecting X509 keeps the normal, fully-verified chain path.
    var buf_x509: [64]u8 = undefined;
    var bx = try tls_extension.Builder.begin(&buf_x509);
    try bx.addTyped(.server_certificate_type, &[_]u8{tls_extension.CertificateType.x509.toInt()});
    try client.parseEncryptedExtensions(try bx.finish());
    try std.testing.expectEqual(tls_extension.CertificateType.x509, client.server_cert_type);

    // Selecting RawPublicKey flips us onto the RPK path.
    var buf_rpk: [64]u8 = undefined;
    var br = try tls_extension.Builder.begin(&buf_rpk);
    try br.addTyped(.server_certificate_type, &[_]u8{tls_extension.CertificateType.raw_public_key.toInt()});
    try client.parseEncryptedExtensions(try br.finish());
    try std.testing.expectEqual(tls_extension.CertificateType.raw_public_key, client.server_cert_type);

    // A type we never offered (e.g. an unknown 0x63) is rejected.
    var buf_bad: [64]u8 = undefined;
    var bb = try tls_extension.Builder.begin(&buf_bad);
    try bb.addTyped(.server_certificate_type, &[_]u8{0x63});
    try std.testing.expectError(error.BadHandshake, client.parseEncryptedExtensions(try bb.finish()));
}

test "OCSP staple status decision rejects revoked and soft-passes good or absent" {
    var parsed = ocsp.Parsed{
        .der = &.{},
        .response_status = .successful,
        .basic_response_der = null,
        .tbs_response_data_der = &.{},
        .signature_algorithm_oid = &.{},
        .signature_value = &.{},
        .responses = undefined,
        .response_count = 1,
    };
    parsed.responses[0] = .{
        .hash_algorithm_oid = &.{},
        .issuer_name_hash = &.{},
        .issuer_key_hash = &.{},
        .serial = &[_]u8{0x10},
        .cert_status = .revoked,
        .this_update = "20260102030405Z",
        .next_update = null,
    };
    try std.testing.expectError(error.CertificateRevoked, enforceOcspStatusForSerial(parsed, &[_]u8{0x10}));

    parsed.responses[0].cert_status = .good;
    try enforceOcspStatusForSerial(parsed, &[_]u8{0x10});
    try enforceOcspStatusForSerial(parsed, &[_]u8{0x11});
}

test "DNS wildcard matching is single-label only" {
    // Arrange
    const pattern = "*.example.com";

    // Act / Assert
    try std.testing.expect(dnsPatternMatches(pattern, "www.example.com"));
    try std.testing.expect(!dnsPatternMatches(pattern, "example.com"));
    try std.testing.expect(!dnsPatternMatches(pattern, "a.b.example.com"));
}

test "Finished verify detects tampering" {
    // Arrange
    const base = @as([tls_finished.mac_len]u8, @splat(0x11));
    const transcript = @as([tls_finished.mac_len]u8, @splat(0x22));
    var mac = tls_finished.verifyData(base, transcript);

    // Act
    const ok = tls_finished.verify(base, transcript, &mac);
    mac[0] ^= 1;
    const tampered = tls_finished.verify(base, transcript, &mac);

    // Assert
    try std.testing.expect(ok);
    try std.testing.expect(!tampered);
}

test "application record seals and opens with AES-128-GCM" {
    // Arrange
    const allocator = std.testing.allocator;
    var keys = TrafficKeys{};
    keys.key[0..Aes128Gcm.key_length].* = @as([Aes128Gcm.key_length]u8, @splat(0x42));
    keys.iv = @as([12]u8, @splat(0x24));
    const msg = "GET / HTTP/1.1\r\n\r\n";

    // Act
    const record = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &keys, 0, .application_data, msg);
    defer allocator.free(record);
    const opened = try openRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &keys, 0, record);
    defer allocator.free(opened.content);

    // Assert
    try std.testing.expectEqual(tls_record.ContentType.application_data, opened.content_type);
    try std.testing.expectEqualSlices(u8, msg, opened.content);
}

test "decryptApp skips post-handshake handshake records (NewSessionTicket)" {
    // Arrange: a connected client with known server app keys.
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();
    client.state = .connected;
    client.selected_suite = .tls_aes_128_gcm_sha256;
    client.server_app_keys.key[0..Aes128Gcm.key_length].* = @as([Aes128Gcm.key_length]u8, @splat(0x5A));
    client.server_app_keys.iv = @as([12]u8, @splat(0xA5));

    // A syntactically valid, zero-lifetime NewSessionTicket arrives first
    // (seq 0), then real application data (seq 1). Zero lifetime means it is
    // consumed as control but not persisted for resumption.
    var ticket_body_buf: [32]u8 = undefined;
    const ticket_body = try tls_session_ticket.encode(&ticket_body_buf, .{
        .ticket_lifetime = 0,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = &.{0xaa},
        .extensions = "",
    });
    var ticket_hs: std.ArrayList(u8) = .empty;
    defer ticket_hs.deinit(allocator);
    try writeHandshake(allocator, &ticket_hs, .new_session_ticket, ticket_body);
    const ticket = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 0, .handshake, ticket_hs.items);
    defer allocator.free(ticket);
    const app = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 1, .application_data, "HTTP/1.1 200 OK");
    defer allocator.free(app);

    // Act / Assert
    try std.testing.expectEqual(AppRead.control, try client.decryptApp(ticket));
    const got = try client.decryptApp(app);
    defer allocator.free(got.application_data);
    try std.testing.expectEqualSlices(u8, "HTTP/1.1 200 OK", got.application_data);
}

test "TLS 1.3 post-handshake: unknown types, empty and truncated fragments are fatal (fail-closed)" {
    // Arrange: a connected client with known server app keys (same shape as the
    // NewSessionTicket skip test above).
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();
    client.state = .connected;
    client.selected_suite = .tls_aes_128_gcm_sha256;
    client.server_app_keys.key[0..Aes128Gcm.key_length].* = @as([Aes128Gcm.key_length]u8, @splat(0x5A));
    client.server_app_keys.iv = @as([12]u8, @splat(0xA5));

    // 1. A post-handshake handshake message that is neither KeyUpdate nor
    //    NewSessionTicket (here an out-of-place Finished) is unexpected_message
    //    (RFC 8446 §5.1) — fatal, never silently skipped.
    var bogus: std.ArrayList(u8) = .empty;
    defer bogus.deinit(allocator);
    try writeHandshake(allocator, &bogus, .finished, &(@as([32]u8, @splat(0x11))));
    const bogus_rec = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 0, .handshake, bogus.items);
    defer allocator.free(bogus_rec);
    try std.testing.expectError(error.BadHandshake, client.decryptApp(bogus_rec));

    // 2. A zero-length handshake fragment MUST NOT be sent (RFC 8446 §5.1) —
    //    receiving one is fatal, not a no-op.
    const empty_rec = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 1, .handshake, "");
    defer allocator.free(empty_rec);
    try std.testing.expectError(error.BadHandshake, client.decryptApp(empty_rec));

    // 3. Truncated trailing handshake bytes must not be silently dropped: this
    //    engine performs no cross-record post-handshake reassembly, so a partial
    //    message would otherwise vanish (silent data corruption).
    const truncated = [_]u8{ @intFromEnum(HandshakeType.key_update), 0, 0 }; // 3 of 4 header bytes
    const trunc_rec = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 2, .handshake, &truncated);
    defer allocator.free(trunc_rec);
    try std.testing.expectError(error.BadHandshake, client.decryptApp(trunc_rec));

    // 4. A well-formed KeyUpdate on the next record still rotates cleanly.
    var ku: std.ArrayList(u8) = .empty;
    defer ku.deinit(allocator);
    try writeHandshake(allocator, &ku, .key_update, &[_]u8{@intFromEnum(KeyUpdateRequest.not_requested)});
    const ku_rec = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 3, .handshake, ku.items);
    defer allocator.free(ku_rec);
    try std.testing.expectEqual(AppRead.control, try client.decryptApp(ku_rec));
}

test "exploit: TLS 1.3 post-handshake coalesced KeyUpdate flood from the server is rejected" {
    // Hostile-server regression, mirroring the server-side cap. A KeyUpdate is
    // five bytes on the wire, so one maximal record can coalesce thousands; each
    // costs six HKDF-Expand-Label derivations and, when update_requested, an
    // AEAD-sealed reply appended to our egress queue. Uncapped that is a CPU
    // multiplier plus a bandwidth amplifier bought with a single record. The cap
    // must reject the flood while still accepting a legitimately coalesced batch
    // (RFC 8446 §5.1 permits several messages per record).
    const allocator = std.testing.allocator;

    const Fragment = struct {
        fn build(a: Allocator, n: usize) !std.ArrayList(u8) {
            var buf: std.ArrayList(u8) = .empty;
            errdefer buf.deinit(a);
            for (0..n) |_| {
                try writeHandshake(a, &buf, .key_update, &[_]u8{@intFromEnum(KeyUpdateRequest.requested)});
            }
            return buf;
        }
    };

    const connected = struct {
        fn open(a: Allocator) !Client {
            var c = try Client.init(a, .{ .server_name = "example.com", .trust_anchors = &.{} });
            errdefer c.deinit();
            c.state = .connected;
            c.selected_suite = .tls_aes_128_gcm_sha256;
            c.server_app_keys.key[0..Aes128Gcm.key_length].* = @as([Aes128Gcm.key_length]u8, @splat(0x5A));
            c.server_app_keys.iv = @as([12]u8, @splat(0xA5));
            return c;
        }
    };

    // One over the cap aborts the connection before the rotation loop's tail.
    {
        var client = try connected.open(allocator);
        defer client.deinit();
        var frag = try Fragment.build(allocator, max_post_handshake_msgs_per_record + 1);
        defer frag.deinit(allocator);
        const rec = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 0, .handshake, frag.items);
        defer allocator.free(rec);
        try std.testing.expectError(error.BadHandshake, client.decryptApp(rec));
    }

    // A maximal legitimate batch still succeeds and queues its replies.
    {
        var client = try connected.open(allocator);
        defer client.deinit();
        var frag = try Fragment.build(allocator, max_post_handshake_msgs_per_record);
        defer frag.deinit(allocator);
        const rec = try sealRecordAlloc(allocator, .tls_aes_128_gcm_sha256, &client.server_app_keys, 0, .handshake, frag.items);
        defer allocator.free(rec);
        try std.testing.expectEqual(AppRead.control, try client.decryptApp(rec));
        try std.testing.expect(client.post_handshake_send.items.len > 0);
    }
}

/// Build a minimal TLS 1.3 ServerHello body (legacy_version, random, echoed
/// session id, suite, null compression, then supported_versions=0x0304 and one
/// key_share entry) for driving parseServerHello directly in tests.
fn buildTestServerHelloBody(
    allocator: Allocator,
    session_id: []const u8,
    suite: u16,
    group: u16,
    key_exchange: []const u8,
) ![]u8 {
    var exts: std.ArrayList(u8) = .empty;
    defer exts.deinit(allocator);
    try appendU16(allocator, &exts, @intFromEnum(tls_extension.ExtensionType.supported_versions));
    try appendU16(allocator, &exts, 2);
    try appendU16(allocator, &exts, tls_supported_versions.tls13);
    try appendU16(allocator, &exts, @intFromEnum(tls_extension.ExtensionType.key_share));
    try appendU16(allocator, &exts, @intCast(4 + key_exchange.len));
    try appendU16(allocator, &exts, group);
    try appendU16(allocator, &exts, @intCast(key_exchange.len));
    try exts.appendSlice(allocator, key_exchange);

    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    try appendU16(allocator, &body, tls_record.legacy_record_version);
    try body.appendSlice(allocator, &(@as([32]u8, @splat(0x42)))); // non-HRR random
    try body.append(allocator, @intCast(session_id.len));
    try body.appendSlice(allocator, session_id);
    try appendU16(allocator, &body, suite);
    try body.append(allocator, 0); // legacy_compression_method
    try appendU16(allocator, &body, @intCast(exts.items.len));
    try body.appendSlice(allocator, exts.items);
    return body.toOwnedSlice(allocator);
}

test "TLS 1.3 ServerHello after HRR must keep the HRR cipher suite (RFC 8446 §4.1.4)" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
    defer client.deinit();
    client.hrr_seen = true;
    client.hrr_suite = .tls_aes_128_gcm_sha256;

    // A ServerHello that switches suite after the HelloRetryRequest committed
    // (0x1303 chacha shares SHA-256 with 0x1301, so the transcript hash alone
    // would not catch the swap) is fatal.
    const swapped = try buildTestServerHelloBody(
        allocator,
        &client.legacy_session_id,
        @intFromEnum(CipherSuite.tls_chacha20_poly1305_sha256),
        supported_groups.NamedGroup.x25519.toInt(),
        &client.x25519_pair.public_key,
    );
    defer allocator.free(swapped);
    try std.testing.expectError(error.BadHandshake, client.parseServerHello(swapped));

    // The HRR-committed suite is accepted.
    const kept = try buildTestServerHelloBody(
        allocator,
        &client.legacy_session_id,
        @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256),
        supported_groups.NamedGroup.x25519.toInt(),
        &client.x25519_pair.public_key,
    );
    defer allocator.free(kept);
    const shared = try client.parseServerHello(kept);
    try std.testing.expectEqual(@as(usize, 32), shared.len);
}

test "TLS 1.3 ServerHello key_share group must be one the ClientHello offered (RFC 8446 §4.2.8)" {
    const allocator = std.testing.allocator;

    // After an HRR that pinned the retry group, the ServerHello MUST answer with
    // exactly that group — an x25519 answer to a hybrid retry is fatal.
    {
        var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
        defer client.deinit();
        client.hrr_seen = true;
        client.hrr_suite = .tls_aes_128_gcm_sha256;
        client.retry_key_share_group = .x25519mlkem768;
        const body = try buildTestServerHelloBody(
            allocator,
            &client.legacy_session_id,
            @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256),
            supported_groups.NamedGroup.x25519.toInt(),
            &client.x25519_pair.public_key,
        );
        defer allocator.free(body);
        try std.testing.expectError(error.BadHandshake, client.parseServerHello(body));
    }

    // Without an HRR the selected group must still be one we sent a share for:
    // a client that offered only P-256 rejects an x25519 selection.
    {
        var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
        defer client.deinit();
        client.offerOnlyP256ForTest();
        const body = try buildTestServerHelloBody(
            allocator,
            &client.legacy_session_id,
            @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256),
            supported_groups.NamedGroup.x25519.toInt(),
            &client.x25519_pair.public_key,
        );
        defer allocator.free(body);
        try std.testing.expectError(error.BadHandshake, client.parseServerHello(body));
    }
}

fn clientHelloExtensions(body: []const u8) ?[]const u8 {
    var c = Cursor.init(body);
    _ = c.take(2) catch return null;
    _ = c.take(32) catch return null;
    _ = c.take(c.readU8() catch return null) catch return null;
    _ = c.take(c.readU16() catch return null) catch return null;
    _ = c.take(c.readU8() catch return null) catch return null;
    return c.take(c.readU16() catch return null) catch return null;
}

test "applyToml toggles the tls debug_log flag and restores cleanly" {
    const saved = debug_log;
    defer debug_log = saved; // never leak the override into other tests
    const allocator = std.testing.allocator;

    var on = try toml.parse(allocator, "[tls]\ndebug_log = true\n");
    defer on.deinit(allocator);
    applyToml(&on);
    try std.testing.expectEqual(true, debug_log);

    var off = try toml.parse(allocator, "[tls]\ndebug_log = false\n");
    defer off.deinit(allocator);
    applyToml(&off);
    try std.testing.expectEqual(false, debug_log);

    // Absent key leaves the current value unchanged.
    debug_log = true;
    var none = try toml.parse(allocator, "[server]\nname = \"mz\"\n");
    defer none.deinit(allocator);
    applyToml(&none);
    try std.testing.expectEqual(true, debug_log);
}

/// Build a HelloRetryRequest plaintext record carrying a cookie, for the given
/// client session_id. Used only by the HRR test below.
fn buildTestHrr(allocator: Allocator, session_id: []const u8, cookie: []const u8) ![]u8 {
    var ext: std.ArrayList(u8) = .empty;
    defer ext.deinit(allocator);
    // supported_versions (server form): selected_version = TLS 1.3.
    try appendU16(allocator, &ext, @intFromEnum(tls_extension.ExtensionType.supported_versions));
    try appendU16(allocator, &ext, 2);
    try appendU16(allocator, &ext, tls_supported_versions.tls13);
    // cookie: opaque cookie<1..2^16-1> (u16 length + bytes).
    try appendU16(allocator, &ext, @intFromEnum(tls_extension.ExtensionType.cookie));
    try appendU16(allocator, &ext, @intCast(2 + cookie.len));
    try appendU16(allocator, &ext, @intCast(cookie.len));
    try ext.appendSlice(allocator, cookie);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, tls_record.legacy_record_version);
    try body.appendSlice(allocator, &hello_retry_request_random);
    try body.append(allocator, @intCast(session_id.len));
    try body.appendSlice(allocator, session_id);
    try appendU16(allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
    try body.append(allocator, 0); // null compression
    try appendU16(allocator, &body, @intCast(ext.items.len));
    try body.appendSlice(allocator, ext.items);

    var hs: std.ArrayList(u8) = .empty;
    defer hs.deinit(allocator);
    try writeHandshake(allocator, &hs, .server_hello, body.items);
    return writePlainRecord(allocator, .handshake, hs.items);
}

test "HelloRetryRequest: client echoes the cookie, reuses its random, rejects a second HRR" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "irc.test", .trust_anchors = &.{} });
    defer client.deinit();

    const ch1 = try client.start();
    defer allocator.free(ch1);
    // ClientHello random sits at record(5) + handshake header(4) + legacy_version(2).
    const ch1_random = ch1[11..43];

    const cookie = "retry-cookie-1234";
    const hrr = try buildTestHrr(allocator, &client.legacy_session_id, cookie);
    defer allocator.free(hrr);

    const ch2 = switch (try client.feed(hrr)) {
        .bytes_to_send => |b| b,
        .need_more => return error.TestUnexpectedResult,
    };
    defer allocator.free(ch2);

    // ClientHello2 must carry the cookie and reuse ClientHello1's random.
    try std.testing.expect(std.mem.indexOf(u8, ch2, cookie) != null);
    try std.testing.expectEqualSlices(u8, ch1_random, ch2[11..43]);
    try std.testing.expect(client.hrr_seen);

    // A second HelloRetryRequest is fatal (RFC 8446 §4.1.4).
    const hrr2 = try buildTestHrr(allocator, &client.legacy_session_id, cookie);
    defer allocator.free(hrr2);
    try std.testing.expectError(error.BadHandshake, client.feed(hrr2));
}

test {
    std.testing.refAllDecls(@This());
}

test "validateCertificateRequest enforces RFC 8446 §4.3.2 framing" {
    // Well-formed: empty context, exact extensions vector, one
    // signature_algorithms extension listing ed25519 + ecdsa_secp256r1_sha256.
    const good = [_]u8{
        0x00, // empty certificate_request_context
        0x00, 0x0a, // extensions total length (10)
        0x00, 0x0d, 0x00, 0x06, // signature_algorithms, data length 6
        0x00, 0x04, 0x08, 0x07, 0x04, 0x03, // list length 4: ed25519, ecdsa_p256
    };
    try std.testing.expectEqual(tls_extension.CertificateType.x509, try validateCertificateRequest(&good, false));

    const raw_select = good ++ [_]u8{
        0x00, 0x13, 0x00, 0x01, 0x02, // client_certificate_type = RawPublicKey
    };
    var raw = raw_select;
    std.mem.writeInt(u16, raw[1..3], 15, .big);
    try std.testing.expectEqual(tls_extension.CertificateType.raw_public_key, try validateCertificateRequest(&raw, true));
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&raw, false));

    // The historical server bug: a second (doubled) extensions-length prefix.
    // Real clients reject this with "Invalid TLS extensions length field".
    const doubled = [_]u8{
        0x00,
        0x00, 0x0c, // outer (spurious) extensions length
        0x00, 0x0a, // inner extensions length — parsed as an extension type
        0x00, 0x0d,
        0x00, 0x06,
        0x00, 0x04,
        0x08, 0x07,
        0x04, 0x03,
    };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&doubled, false));

    // A non-empty context is illegal in the main handshake.
    const nonempty_ctx = [_]u8{ 0x01, 0xaa, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x08, 0x07, 0x04, 0x03 };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&nonempty_ctx, false));

    // Missing the mandatory signature_algorithms extension.
    const no_sigalgs = [_]u8{ 0x00, 0x00, 0x04, 0x00, 0x2b, 0x00, 0x00 };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&no_sigalgs, false));

    // Extensions vector shorter than the remaining body (trailing garbage).
    const trailing = good ++ [_]u8{0x00};
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&trailing, false));

    // signature_algorithms list length disagreeing with the extension data.
    const bad_list = [_]u8{
        0x00,
        0x00,
        0x0a,
        0x00,
        0x0d,
        0x00,
        0x06,
        0x00, 0x06, 0x08, 0x07, 0x04, 0x03, // claims 6 list bytes, has 4
    };
    try std.testing.expectError(error.BadHandshake, validateCertificateRequest(&bad_list, false));
}

test "leaf RSA key survives the hs_plain consume (regression: copied, not borrowed)" {
    // A Certificate handshake whose RSA leaf-key bytes get clobbered after parse
    // (simulating the post-message consume of hs_plain). Pre-fix the key borrowed
    // those bytes and read garbage at CertificateVerify time; it must now be owned.
    const cert_der = [_]u8{ 0x30, 0x82, 0x03, 0x07, 0x30, 0x82, 0x01, 0xef, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x53, 0xd9, 0xd0, 0x2f, 0x30, 0xba, 0xc3, 0x6e, 0xa1, 0xb7, 0x63, 0xe4, 0x7b, 0xfe, 0x9c, 0x90, 0xdd, 0x91, 0xb3, 0xad, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x72, 0x73, 0x61, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36, 0x31, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36, 0x31, 0x33, 0x30, 0x30, 0x30, 0x31, 0x30, 0x32, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x72, 0x73, 0x61, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcf, 0xef, 0x05, 0x77, 0x1d, 0xde, 0x6a, 0x66, 0xdf, 0xf9, 0x2c, 0x29, 0xbf, 0x5a, 0xb6, 0x97, 0x86, 0xa2, 0xd1, 0x8b, 0x6c, 0xfa, 0x28, 0x6b, 0x30, 0x1f, 0x00, 0x11, 0x2e, 0x11, 0x0d, 0x84, 0x57, 0x73, 0x9e, 0x0f, 0xb2, 0xd5, 0x50, 0x1a, 0x1c, 0xc4, 0x24, 0xdb, 0x95, 0x70, 0xba, 0x05, 0x6d, 0xa7, 0x85, 0x1f, 0x71, 0xc2, 0x6c, 0x42, 0x74, 0xd1, 0x3a, 0x35, 0x58, 0x9d, 0x70, 0x13, 0x07, 0xc0, 0x30, 0x1e, 0xf6, 0x9c, 0xfc, 0xe8, 0xb7, 0xf1, 0xa6, 0x4b, 0xa3, 0xbe, 0x52, 0x37, 0x5f, 0x4b, 0x73, 0x1f, 0x76, 0x11, 0xd3, 0xf4, 0x9d, 0x01, 0x34, 0xa0, 0x59, 0x09, 0x3d, 0x90, 0x9c, 0x2b, 0xb5, 0x5c, 0x24, 0x47, 0xec, 0x77, 0x08, 0x98, 0x56, 0x59, 0x6a, 0xda, 0x64, 0xf0, 0x27, 0x4a, 0x41, 0xcf, 0xba, 0x6c, 0x22, 0xc2, 0x51, 0x98, 0xe0, 0xc2, 0xb6, 0x12, 0xc7, 0xbc, 0x8f, 0xcb, 0x2b, 0x06, 0x7d, 0xac, 0xb3, 0x25, 0x4c, 0x82, 0x4d, 0x86, 0xb4, 0xb8, 0xac, 0x7d, 0xfc, 0xbf, 0xdf, 0xc2, 0x73, 0xa5, 0x73, 0x5b, 0x6e, 0x26, 0x4a, 0x44, 0x5b, 0xe5, 0xaa, 0xa6, 0xa3, 0x68, 0x88, 0x0e, 0x95, 0xbf, 0x82, 0x53, 0xf0, 0xd3, 0xe6, 0x34, 0xc1, 0x41, 0xd4, 0x48, 0x34, 0x3b, 0x63, 0xb8, 0x4b, 0xdd, 0xfb, 0x7f, 0x8e, 0xcf, 0xfd, 0x95, 0x96, 0x41, 0xe3, 0x7b, 0xf9, 0x4e, 0xc5, 0x46, 0xa4, 0x7b, 0xde, 0x42, 0x37, 0x2b, 0x54, 0xb0, 0x5f, 0x12, 0x77, 0x01, 0x23, 0x5c, 0xb7, 0x6c, 0x77, 0xc0, 0xe2, 0x4d, 0x87, 0x07, 0x9e, 0xed, 0x45, 0x34, 0x1b, 0x44, 0x4e, 0x02, 0x22, 0xfa, 0x47, 0x81, 0x12, 0xf2, 0xc9, 0xc6, 0x2c, 0xa8, 0x46, 0x2b, 0x0d, 0xf1, 0x4d, 0x94, 0x14, 0x3f, 0x88, 0x81, 0x84, 0xe2, 0x10, 0x8d, 0xd1, 0x99, 0x37, 0xfa, 0x15, 0x61, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x1a, 0xec, 0x86, 0x56, 0xd0, 0x23, 0x92, 0x61, 0x5e, 0x10, 0x5b, 0xb5, 0xc0, 0x0f, 0xa8, 0xef, 0xfe, 0xdd, 0x3e, 0xce, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x1a, 0xec, 0x86, 0x56, 0xd0, 0x23, 0x92, 0x61, 0x5e, 0x10, 0x5b, 0xb5, 0xc0, 0x0f, 0xa8, 0xef, 0xfe, 0xdd, 0x3e, 0xce, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x47, 0xe6, 0x09, 0x03, 0xef, 0x69, 0x19, 0x42, 0x65, 0xfd, 0x25, 0xb4, 0xe2, 0xb4, 0xf7, 0xea, 0x57, 0x60, 0x83, 0x89, 0x1e, 0x5e, 0x0a, 0x55, 0x90, 0xf9, 0xee, 0x92, 0x21, 0x5c, 0x2d, 0x0e, 0x2b, 0xc7, 0x8e, 0x89, 0xdb, 0x23, 0xfe, 0x53, 0x9b, 0xd2, 0x22, 0x68, 0x85, 0xe3, 0xd3, 0x52, 0xfd, 0x11, 0x43, 0xc2, 0xf2, 0x70, 0x3d, 0x9b, 0x77, 0x44, 0x5e, 0xe3, 0xcc, 0x64, 0x8b, 0xaa, 0x5d, 0x82, 0x26, 0xa5, 0xd0, 0x3b, 0x06, 0xc4, 0xf0, 0xa4, 0x18, 0x64, 0xe2, 0x13, 0xf6, 0x66, 0xe4, 0xda, 0xbb, 0x97, 0xce, 0x10, 0xcd, 0x0a, 0xa9, 0xd6, 0x71, 0x90, 0x16, 0x5e, 0x2d, 0xda, 0x53, 0xf2, 0xc6, 0xce, 0x8a, 0x51, 0xac, 0x17, 0x29, 0x63, 0xc2, 0x9b, 0x41, 0xda, 0xb7, 0x75, 0x18, 0x0a, 0xc9, 0xe3, 0x0c, 0xa8, 0x9f, 0x52, 0x5e, 0xe6, 0x3f, 0xef, 0x3d, 0x73, 0x3a, 0xe3, 0x60, 0x30, 0xed, 0x98, 0x88, 0x44, 0x52, 0x28, 0x30, 0x92, 0xf3, 0xb5, 0xe7, 0x29, 0x13, 0x3d, 0x2e, 0x2f, 0x82, 0xe1, 0x55, 0x1e, 0x53, 0x12, 0x38, 0xb4, 0x9f, 0xc4, 0x2a, 0xca, 0xc6, 0xaf, 0xcf, 0xe2, 0xb6, 0x20, 0x7b, 0xe1, 0xee, 0x6b, 0x7d, 0x02, 0x83, 0xdb, 0x64, 0x37, 0x5a, 0x84, 0x8c, 0xe2, 0xa9, 0xec, 0x9e, 0xc0, 0x6f, 0x04, 0x44, 0x6a, 0xa4, 0xc1, 0xfe, 0x75, 0x81, 0xbb, 0x4f, 0x37, 0x20, 0x97, 0x64, 0xdd, 0x0e, 0xcc, 0x85, 0x71, 0x2a, 0x45, 0x61, 0x7d, 0x08, 0x1a, 0x5c, 0xa8, 0xc3, 0x35, 0x6a, 0xa5, 0x7e, 0x69, 0x14, 0x9b, 0x2b, 0x1c, 0xf2, 0x13, 0x66, 0x5d, 0xaf, 0xf2, 0x14, 0xc3, 0xad, 0xa2, 0x55, 0x1d, 0xe3, 0x7d, 0x52, 0x4b, 0xf1, 0x2b, 0xf1, 0xa2, 0x81, 0xf7, 0xcf, 0x92, 0x40, 0xf5, 0x1f, 0x0a, 0xdb, 0x22, 0x5a, 0xa7, 0x91, 0x3f, 0x0c, 0xb7 };
    const a = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try body.append(a, 0); // certificate_request_context length = 0
    const entry_len: usize = 3 + cert_der.len + 2; // certLen(3) + cert + extLen(2)
    try body.append(a, @intCast((entry_len >> 16) & 0xff));
    try body.append(a, @intCast((entry_len >> 8) & 0xff));
    try body.append(a, @intCast(entry_len & 0xff));
    try body.append(a, @intCast((cert_der.len >> 16) & 0xff));
    try body.append(a, @intCast((cert_der.len >> 8) & 0xff));
    try body.append(a, @intCast(cert_der.len & 0xff));
    try body.appendSlice(a, &cert_der);
    try body.append(a, 0);
    try body.append(a, 0); // extensions length = 0

    var client = try Client.init(a, .{ .server_name = "rsa.test", .trust_anchors = &.{} });
    defer client.deinit();
    client.skipServerCertVerifyForTest();
    try client.parseAndVerifyCertificate(body.items);

    const lk = client.leaf_key.?;
    try std.testing.expect(lk == .rsa);
    var n_snapshot: [rsa_verify.max_bytes]u8 = undefined;
    const n_len = lk.rsa.n.len;
    @memcpy(n_snapshot[0..n_len], lk.rsa.n);

    // Clobber the source buffer; an owned key is unaffected, a borrowed one reads 0xAA.
    @memset(body.items, 0xAA);
    try std.testing.expectEqualSlices(u8, n_snapshot[0..n_len], client.leaf_key.?.rsa.n);
    try std.testing.expect(client.leaf_key.?.rsa.n[0] != 0xAA);
    try std.testing.expect(client.leaf_key.?.rsa.e.len >= 1 and client.leaf_key.?.rsa.e[client.leaf_key.?.rsa.e.len - 1] == 0x01);
}

// ---------------------------------------------------------------------------
// CRL revocation wiring (roadmap 4.2) — end-to-end over `checkCrlRevocation`.
// A self-contained Ed25519 signed-CRL builder keeps these hermetic; the CRL
// parse/verify primitives themselves are exercised in crl.zig. What is proven
// HERE is the wiring's fail-open composition: only an authentic + current CRL
// that lists the leaf serial may revoke; every other outcome is ignored.
// ---------------------------------------------------------------------------

fn crlTestDerLen(out: *std.ArrayList(u8), a: std.mem.Allocator, len: usize) !void {
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

fn crlTestTlv(out: *std.ArrayList(u8), a: std.mem.Allocator, tag: u8, value: []const u8) !void {
    try out.append(a, tag);
    try crlTestDerLen(out, a, value.len);
    try out.appendSlice(a, value);
}

const crl_test_ed25519_oid = [_]u8{ 0x2B, 0x65, 0x70 };

fn crlTestAlgIdEd25519(out: *std.ArrayList(u8), a: std.mem.Allocator) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try crlTestTlv(&body, a, x509.Tag.oid, &crl_test_ed25519_oid);
    try crlTestTlv(out, a, x509.Tag.sequence, body.items);
}

fn crlTestBitString(out: *std.ArrayList(u8), a: std.mem.Allocator, value: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try body.append(a, 0); // 0 unused bits
    try body.appendSlice(a, value);
    try crlTestTlv(out, a, x509.Tag.bit_string, body.items);
}

fn crlTestEd25519Spki(a: std.mem.Allocator, public_key: [32]u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try crlTestAlgIdEd25519(&body, a);
    try crlTestBitString(&body, a, &public_key);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try crlTestTlv(&out, a, x509.Tag.sequence, body.items);
    return out.toOwnedSlice(a);
}

/// Signed Ed25519 CRL that revokes `revoked_serial`, valid 2026-01-01..2026-02-01.
fn crlTestSignedCrlWithRevoked(
    a: std.mem.Allocator,
    kp: std.crypto.sign.Ed25519.KeyPair,
    revoked_serial: []const u8,
) ![]u8 {
    // revokedCertificates ::= SEQUENCE OF SEQUENCE { serial INTEGER, date UTCTime }
    var entry: std.ArrayList(u8) = .empty;
    defer entry.deinit(a);
    try crlTestTlv(&entry, a, x509.Tag.integer, revoked_serial);
    try crlTestTlv(&entry, a, x509.Tag.utc_time, "260115000000Z");
    var revoked: std.ArrayList(u8) = .empty;
    defer revoked.deinit(a);
    try crlTestTlv(&revoked, a, x509.Tag.sequence, entry.items);

    var tbs_body: std.ArrayList(u8) = .empty;
    defer tbs_body.deinit(a);
    try crlTestTlv(&tbs_body, a, x509.Tag.integer, &[_]u8{1}); // version v2(1)
    try crlTestAlgIdEd25519(&tbs_body, a); // signature AlgId
    try crlTestTlv(&tbs_body, a, x509.Tag.sequence, ""); // issuer (empty Name)
    try crlTestTlv(&tbs_body, a, x509.Tag.utc_time, "260101000000Z"); // thisUpdate
    try crlTestTlv(&tbs_body, a, x509.Tag.utc_time, "260201000000Z"); // nextUpdate
    try crlTestTlv(&tbs_body, a, x509.Tag.sequence, revoked.items); // revokedCertificates

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(a);
    try crlTestTlv(&tbs, a, x509.Tag.sequence, tbs_body.items);
    const sig = try kp.sign(tbs.items, null);
    const sig_bytes = sig.toBytes();

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(a);
    try body.appendSlice(a, tbs.items);
    try crlTestAlgIdEd25519(&body, a);
    try crlTestBitString(&body, a, &sig_bytes);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    try crlTestTlv(&out, a, x509.Tag.sequence, body.items);
    return out.toOwnedSlice(a);
}

test "checkCrlRevocation fail-open: no clock and unparseable CRL never error" {
    // No trustworthy clock → cannot judge currency → fail-open (returns before
    // touching the CRL) even against a syntactically valid-looking input.
    try checkCrlRevocation(&[_]u8{ 0x30, 0x00 }, &[_]u8{}, &[_]u8{0x2A}, null);
    // Clock present but the bytes are not a CRL → parse fails → fail-open.
    try checkCrlRevocation(&[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, &[_]u8{}, &[_]u8{0x2A}, 1_767_225_601);
}

test "checkCrlRevocation revokes only a listed serial under an authentic, current CRL" {
    const a = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    const spki = try crlTestEd25519Spki(a, kp.public_key.toBytes());
    defer a.free(spki);
    const der = try crlTestSignedCrlWithRevoked(a, kp, &[_]u8{0x2A});
    defer a.free(der);

    const parsed = try crl.parse(der);
    const now = parsed.this_update.epoch_seconds + 1; // inside [thisUpdate, nextUpdate)

    // Positive: an authentic, current CRL that lists the leaf serial MUST revoke.
    try std.testing.expectError(error.CertificateRevoked, checkCrlRevocation(der, spki, &[_]u8{0x2A}, now));
    // A serial absent from the CRL passes cleanly.
    try checkCrlRevocation(der, spki, &[_]u8{0x2B}, now);
}

test "checkCrlRevocation fail-open on wrong issuer key or a stale window" {
    const a = std.testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x51)));
    const der = try crlTestSignedCrlWithRevoked(a, kp, &[_]u8{0x2A});
    defer a.free(der);
    const parsed = try crl.parse(der);
    const now = parsed.this_update.epoch_seconds + 1;

    // Authenticated under the WRONG issuer key → the CRL is discarded (fail-open)
    // even though the serial is listed: an unauthenticated CRL must never revoke.
    const attacker = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x77)));
    const attacker_spki = try crlTestEd25519Spki(a, attacker.public_key.toBytes());
    defer a.free(attacker_spki);
    try checkCrlRevocation(der, attacker_spki, &[_]u8{0x2A}, now);

    // Correct issuer key but the CRL is stale (now == nextUpdate) → fail-open.
    const spki = try crlTestEd25519Spki(a, kp.public_key.toBytes());
    defer a.free(spki);
    const stale = parsed.next_update.?.epoch_seconds;
    try checkCrlRevocation(der, spki, &[_]u8{0x2A}, stale);
}

// ---------------------------------------------------------------------------
// RFC 9345 Delegated Credentials (client side).
// ---------------------------------------------------------------------------

/// Standard SubjectPublicKeyInfo prefix for a P-256 key: SEQUENCE { AlgId
/// {ecPublicKey, prime256v1}, BIT STRING { 0x00 || <65-byte SEC1 point> } }.
/// The 65 uncompressed SEC1 bytes follow this 26-byte prefix.
const dc_test_p256_spki_prefix = [_]u8{
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};

/// Build a P-256 SubjectPublicKeyInfo into `out` from a keypair's SEC1 point.
fn dcTestP256Spki(out: *[dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8, kp: ecdsa_p256.KeyPair) []const u8 {
    @memcpy(out[0..dc_test_p256_spki_prefix.len], &dc_test_p256_spki_prefix);
    const sec1 = kp.public_key.toUncompressedSec1();
    @memcpy(out[dc_test_p256_spki_prefix.len..], &sec1);
    return out[0..];
}

/// Serialize a DelegatedCredential signed by `leaf_kp` (P-256). When `tamper`,
/// the last signature byte is flipped so the DER stays well-formed but the
/// signature no longer verifies. Returns a slice into `out`.
fn dcTestBuildWire(
    out: []u8,
    leaf_der: []const u8,
    dc_spki: []const u8,
    valid_time: u32,
    leaf_kp: ecdsa_p256.KeyPair,
    tamper: bool,
) ![]const u8 {
    const cred: delegated_credential.Credential = .{
        .valid_time = valid_time,
        .dc_cert_verify_algorithm = tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt(),
        .spki = dc_spki,
    };
    const algorithm = tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt();

    var portion_buf: [256]u8 = undefined;
    const portion = try delegated_credential.writeSignedPortion(&portion_buf, cred, algorithm);

    var msg_buf: [2048]u8 = undefined;
    const msg = try delegated_credential.writeSignedMessage(&msg_buf, leaf_der, portion);

    const sig = try ecdsa_p256.sign(msg, leaf_kp);
    var sig_der_buf: [80]u8 = undefined;
    const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);
    if (tamper) sig_der_buf[sig_der.len - 1] ^= 0xFF;

    return delegated_credential.serialize(out, cred, algorithm, sig_der);
}

/// Assemble a TLS 1.3 Certificate message body carrying a single leaf entry,
/// with `dc_wire` (when non-null) as the leaf entry's delegated_credential
/// extension. Returns a slice into `out`.
fn dcTestCertMessage(out: []u8, leaf_der: []const u8, dc_wire: ?[]const u8) []const u8 {
    // Leaf entry extension block.
    var ext_block_len: usize = 0;
    if (dc_wire) |dw| ext_block_len = 4 + dw.len;
    const entry_len = 3 + leaf_der.len + 2 + ext_block_len;
    const list_len = entry_len;

    var pos: usize = 0;
    out[pos] = 0; // empty certificate_request_context
    pos += 1;
    std.mem.writeInt(u24, out[pos..][0..3], @intCast(list_len), .big);
    pos += 3;
    // CertificateEntry: cert_data<1..2^24-1>
    std.mem.writeInt(u24, out[pos..][0..3], @intCast(leaf_der.len), .big);
    pos += 3;
    @memcpy(out[pos..][0..leaf_der.len], leaf_der);
    pos += leaf_der.len;
    // extensions<0..2^16-1>
    std.mem.writeInt(u16, out[pos..][0..2], @intCast(ext_block_len), .big);
    pos += 2;
    if (dc_wire) |dw| {
        std.mem.writeInt(u16, out[pos..][0..2], delegated_credential.extension_type, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], @intCast(dw.len), .big);
        pos += 2;
        @memcpy(out[pos..][0..dw.len], dw);
        pos += dw.len;
    }
    return out[0..pos];
}

const DcLeaf = struct {
    kp: ecdsa_p256.KeyPair,
    der: []const u8,
    not_before: i64,
    not_after: i64,
};

const dc_test_one_year: i64 = 365 * 24 * 60 * 60;

/// Build a self-signed P-256 leaf cert into `out` with a 1-year validity window,
/// optionally carrying the id-ce-delegationUsage and digitalSignature-KeyUsage
/// extensions.
fn dcTestLeaf(out: []u8, delegation_usage: bool, key_usage: bool, not_before: i64) !DcLeaf {
    return dcTestLeafWindow(out, delegation_usage, key_usage, not_before, not_before + dc_test_one_year);
}

/// Like `dcTestLeaf` but with an explicit notAfter (to exercise the DC-outlives-
/// certificate check).
fn dcTestLeafWindow(out: []u8, delegation_usage: bool, key_usage: bool, not_before: i64, not_after: i64) !DcLeaf {
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(out, .{
        .common_name = "dc-leaf.example",
        .not_before = not_before,
        .not_after = not_after,
        .serial = &[_]u8{0x2A},
        .key_pair = kp,
        .delegation_usage = delegation_usage,
        .key_usage_digital_signature = key_usage,
    });
    return .{ .kp = kp, .der = der, .not_before = not_before, .not_after = not_after };
}

test "delegated_credential: ClientHello omits the extension by default and carries it when opted in" {
    const allocator = std.testing.allocator;

    // Off (default): no delegated_credential extension on the wire.
    {
        var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
        defer client.deinit();
        const record = try client.start();
        defer allocator.free(record);
        var off: usize = 0;
        const ch = try parseHandshake(record[tls_record.record_header_len..], &off);
        const ext_block = clientHelloExtensions(ch.body).?;
        var it = tls_extension.Iterator.init(ext_block);
        while (try it.next()) |ext| {
            try std.testing.expect(ext.ext_type != delegated_credential.extension_type);
        }
    }

    // On: exactly one delegated_credential extension whose body is the
    // SignatureSchemeList we accept for a DC.
    {
        var client = try Client.init(allocator, .{ .server_name = "example.com", .trust_anchors = &.{} });
        defer client.deinit();
        client.offerDelegatedCredentials();
        const record = try client.start();
        defer allocator.free(record);
        var off: usize = 0;
        const ch = try parseHandshake(record[tls_record.record_header_len..], &off);
        const ext_block = clientHelloExtensions(ch.body).?;
        var it = tls_extension.Iterator.init(ext_block);
        var found: ?[]const u8 = null;
        var count: usize = 0;
        while (try it.next()) |ext| {
            if (ext.ext_type == delegated_credential.extension_type) {
                found = ext.data;
                count += 1;
            }
        }
        try std.testing.expectEqual(@as(usize, 1), count);
        const body = found.?;
        try std.testing.expect(tls_signature_scheme.offers(body, .ecdsa_secp256r1_sha256));
        try std.testing.expect(tls_signature_scheme.offers(body, .ecdsa_secp384r1_sha384));
        try std.testing.expect(tls_signature_scheme.offers(body, .ed25519));
        try std.testing.expect(tls_signature_scheme.offers(body, .rsa_pss_rsae_sha256));
    }
}

test "delegated_credential: a valid DC is accepted and CertificateVerify uses the DC key" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200; // 2024-01-01
    const now: i64 = not_before + 3600; // one hour in — inside the window

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);

    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);

    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, 86400, leaf.kp, false);

    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = now,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    // The DC verifies: leaf key signed it, DelegationUsage present, in window.
    try client.parseAndVerifyCertificate(cert_msg);
    try std.testing.expect(client.dc_verified_key != null);
    try std.testing.expectEqual(
        @as(?u16, tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt()),
        client.dc_expected_scheme,
    );

    // CertificateVerify must now verify under the DC key, not the leaf key.
    try client.transcript.appendSlice(allocator, &[_]u8{ 0x01, 0x02, 0x03, 0x04 });
    var th: [max_hash_len]u8 = undefined;
    const th_len = client.transcriptHash(&th);
    var in_buf: [cert_verify_input_max]u8 = undefined;
    const input = buildCertVerifyInput(&in_buf, certificate_verify_context, th[0..th_len]);

    // Signed by the DC key → accepted.
    {
        const sig = try ecdsa_p256.sign(input, dc_kp);
        var der: [80]u8 = undefined;
        const sig_der = try ecdsa_p256.signatureToDer(sig, &der);
        var body: [96]u8 = undefined;
        std.mem.writeInt(u16, body[0..2], tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt(), .big);
        std.mem.writeInt(u16, body[2..4], @intCast(sig_der.len), .big);
        @memcpy(body[4..][0..sig_der.len], sig_der);
        try client.verifyCertificateVerify(body[0 .. 4 + sig_der.len]);
    }

    // Signed by the LEAF key → rejected (proves the DC key is what's bound).
    {
        const sig = try ecdsa_p256.sign(input, leaf.kp);
        var der: [80]u8 = undefined;
        const sig_der = try ecdsa_p256.signatureToDer(sig, &der);
        var body: [96]u8 = undefined;
        std.mem.writeInt(u16, body[0..2], tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt(), .big);
        std.mem.writeInt(u16, body[2..4], @intCast(sig_der.len), .big);
        @memcpy(body[4..][0..sig_der.len], sig_der);
        try std.testing.expectError(error.BadSignature, client.verifyCertificateVerify(body[0 .. 4 + sig_der.len]));
    }
}

test "delegated_credential: CertificateVerify scheme must equal dc_cert_verify_algorithm" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;
    const now: i64 = not_before + 3600;

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, 86400, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = now,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();
    try client.parseAndVerifyCertificate(cert_msg);

    // A CertificateVerify claiming ed25519 while the DC binds P-256 is rejected
    // BEFORE any signature math (RFC 9345 §4).
    var body: [8]u8 = undefined;
    std.mem.writeInt(u16, body[0..2], tls_signature_scheme.SignatureScheme.ed25519.toInt(), .big);
    std.mem.writeInt(u16, body[2..4], 2, .big);
    body[4] = 0;
    body[5] = 0;
    try std.testing.expectError(error.DelegatedCredentialSchemeMismatch, client.verifyCertificateVerify(body[0..6]));
}

test "delegated_credential: absent DC leaves the normal cert-key path (dc_verified_key null)" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, null); // no DC extension

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = not_before + 3600,
    });
    defer client.deinit();
    client.offerDelegatedCredentials(); // opted in, but the server sent no DC
    client.skipServerCertVerifyForTest();

    try client.parseAndVerifyCertificate(cert_msg);
    try std.testing.expect(client.dc_verified_key == null);
    try std.testing.expect(client.leaf_key != null); // normal leaf-key path armed
}

test "delegated_credential: reject when the leaf lacks the DelegationUsage extension" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;

    var leaf_buf: [1024]u8 = undefined;
    // digitalSignature KeyUsage present, but NO DelegationUsage.
    const leaf = try dcTestLeaf(&leaf_buf, false, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, 86400, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = not_before + 3600,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.DelegatedCredentialNoDelegationUsage, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

test "delegated_credential: reject a tampered DC signature" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, 86400, leaf.kp, true); // tamper
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = not_before + 3600,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.BadSignature, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

test "delegated_credential: reject an expired credential" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;
    const valid_time: u32 = 86400; // 1 day; expiry = not_before + 86400
    const now: i64 = not_before + 86400 + 1; // one second past expiry

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, valid_time, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = now,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.DelegatedCredentialExpired, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

test "delegated_credential: accept a large valid_time whose REMAINING lifetime is within 7 days" {
    // Regression for RFC 9345 §4.1.3 check 2: the 7-day bound is on the remaining
    // lifetime (expiry - now), NOT the raw valid_time field. A DC on a cert issued
    // 30 days ago with a 1-day remaining window has valid_time = 31 days (well over
    // 7) yet MUST be accepted.
    const allocator = std.testing.allocator;
    const now: i64 = 1_704_067_200;
    const day: i64 = 24 * 60 * 60;
    const not_before: i64 = now - 30 * day; // cert issued 30 days ago
    const valid_time: u32 = @intCast(31 * day); // expiry = now + 1 day; remaining 1 day

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, valid_time, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = now,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try client.parseAndVerifyCertificate(cert_msg); // accepted despite valid_time = 31 days
    try std.testing.expect(client.dc_verified_key != null);
}

test "delegated_credential: reject when the REMAINING lifetime exceeds the 7-day maximum" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;
    const day: i64 = 24 * 60 * 60;
    const now: i64 = not_before; // fresh cert
    const valid_time: u32 = @intCast(8 * day); // expiry = now + 8 days > now + 7 days

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, valid_time, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = now,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.DelegatedCredentialLifetimeTooLong, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

test "delegated_credential: reject when the DC would outlive the delegation certificate" {
    // RFC 9345 §4.1.3 check 2, second clause: expiry MUST be < the cert's notAfter.
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;
    const day: i64 = 24 * 60 * 60;
    const not_after: i64 = not_before + 3 * day; // short-lived cert
    const now: i64 = not_before + day; // cert still valid
    const valid_time: u32 = @intCast(5 * day); // expiry = not_before + 5d > notAfter (3d); remaining 4d ≤ 7d

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeafWindow(&leaf_buf, true, true, not_before, not_after);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, valid_time, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = now,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.DelegatedCredentialOutlivesCertificate, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

test "delegated_credential: reject a dc_cert_verify_algorithm we did not advertise" {
    // RFC 9345 §4.1.3 check 3: the algorithm must be one allowed for DCs. We build
    // a DC whose dc_cert_verify_algorithm is rsa_pkcs1_sha256 (not in our accepted
    // set — PKCS#1 is not a TLS 1.3 handshake-signature scheme).
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);

    // Hand-build a DC whose dc_cert_verify_algorithm is the un-accepted scheme.
    const bad_scheme = tls_signature_scheme.SignatureScheme.rsa_pkcs1_sha256.toInt();
    const cred: delegated_credential.Credential = .{
        .valid_time = 86400,
        .dc_cert_verify_algorithm = bad_scheme,
        .spki = dc_spki,
    };
    const algorithm = tls_signature_scheme.SignatureScheme.ecdsa_secp256r1_sha256.toInt();
    var portion_buf: [256]u8 = undefined;
    const portion = try delegated_credential.writeSignedPortion(&portion_buf, cred, algorithm);
    var msg_buf: [2048]u8 = undefined;
    const msg = try delegated_credential.writeSignedMessage(&msg_buf, leaf.der, portion);
    const sig = try ecdsa_p256.sign(msg, leaf.kp);
    var sig_der_buf: [80]u8 = undefined;
    const sig_der = try ecdsa_p256.signatureToDer(sig, &sig_der_buf);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try delegated_credential.serialize(&dc_wire_buf, cred, algorithm, sig_der);

    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        .now_unix_seconds = not_before + 3600,
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.UnsupportedSignatureScheme, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

test "delegated_credential: reject when no clock is available to enforce the window" {
    const allocator = std.testing.allocator;
    const not_before: i64 = 1_704_067_200;

    var leaf_buf: [1024]u8 = undefined;
    const leaf = try dcTestLeaf(&leaf_buf, true, true, not_before);
    const dc_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    var spki_buf: [dc_test_p256_spki_prefix.len + ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
    const dc_spki = dcTestP256Spki(&spki_buf, dc_kp);
    var dc_wire_buf: [512]u8 = undefined;
    const dc_wire = try dcTestBuildWire(&dc_wire_buf, leaf.der, dc_spki, 86400, leaf.kp, false);
    var cert_buf: [2048]u8 = undefined;
    const cert_msg = dcTestCertMessage(&cert_buf, leaf.der, dc_wire);

    var client = try Client.init(allocator, .{
        .server_name = "dc-leaf.example",
        .trust_anchors = &.{},
        // now_unix_seconds left null → no clock.
    });
    defer client.deinit();
    client.offerDelegatedCredentials();
    client.skipServerCertVerifyForTest();

    try std.testing.expectError(error.DelegatedCredentialNoClock, client.parseAndVerifyCertificate(cert_msg));
    try std.testing.expect(client.dc_verified_key == null);
}

// Encrypted Client Hello (ECH) — client integration tests (roadmap 5.1)
// ---------------------------------------------------------------------------

const ech_hpke = @import("hpke.zig");

/// Build a single-entry ECHConfigList into `buf` around HPKE public key `pk`,
/// with the given `kem_id`, one cipher suite `{HKDF-SHA256, ChaCha20-Poly1305}`,
/// and `public_name`. Returns the slice.
fn buildEchTestList(buf: []u8, config_id: u8, kem_id: u16, pk: []const u8, public_name: []const u8) []const u8 {
    var contents: [512]u8 = undefined;
    var n: usize = 0;
    contents[n] = config_id;
    n += 1;
    std.mem.writeInt(u16, contents[n..][0..2], kem_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], @intCast(pk.len), .big);
    n += 2;
    @memcpy(contents[n..][0..pk.len], pk);
    n += pk.len;
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], ech.kdf_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], ech.aead_id, .big);
    n += 2;
    contents[n] = 64; // maximum_name_length
    n += 1;
    contents[n] = @intCast(public_name.len);
    n += 1;
    @memcpy(contents[n..][0..public_name.len], public_name);
    n += public_name.len;
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big); // extensions
    n += 2;

    var entry: [560]u8 = undefined;
    var m: usize = 0;
    std.mem.writeInt(u16, entry[m..][0..2], ech_config.version_draft13, .big);
    m += 2;
    std.mem.writeInt(u16, entry[m..][0..2], @intCast(n), .big);
    m += 2;
    @memcpy(entry[m..][0..n], contents[0..n]);
    m += n;

    std.mem.writeInt(u16, buf[0..2], @intCast(m), .big);
    @memcpy(buf[2..][0..m], entry[0..m]);
    return buf[0 .. 2 + m];
}

fn findClientExt(exts: []const u8, ext_type: u16) ?[]const u8 {
    var it = tls_extension.Iterator.init(exts);
    while (it.next() catch return null) |e| {
        if (e.ext_type == ext_type) return e.data;
    }
    return null;
}

test "ECH off (no config) ⇒ ClientHello is the ordinary form: real SNI, no ECH extension" {
    const allocator = std.testing.allocator;
    var client = try Client.init(allocator, .{ .server_name = "secret.example", .trust_anchors = &.{} });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);

    try std.testing.expect(!client.echOffered());
    try std.testing.expectEqual(@as(?bool, null), client.echAccepted());
    switch (sni.extract(record)) {
        .found => |name| try std.testing.expectEqualSlices(u8, "secret.example", name),
        else => return error.TestExpectedSni,
    }
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const exts = clientHelloExtensions(ch.body).?;
    try std.testing.expect(findClientExt(exts, ech.extension_type) == null);
}

test "ECH with an unsupported-KEM config ⇒ byte-identical off-path (no ECH offered)" {
    const allocator = std.testing.allocator;
    var pk: [32]u8 = @splat(0x77);
    var list_buf: [600]u8 = undefined;
    // KEM 0x0010 (P-256) is not one hpke.zig can seal under ⇒ no usable config.
    const list = buildEchTestList(&list_buf, 4, 0x0010, &pk, "cover.example");

    var client = try Client.init(allocator, .{
        .server_name = "secret.example",
        .trust_anchors = &.{},
        .ech_config_list = list,
    });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);

    try std.testing.expect(!client.echOffered());
    // The real SNI is on the wire (not a cover name) and no ECH extension leaks.
    switch (sni.extract(record)) {
        .found => |name| try std.testing.expectEqualSlices(u8, "secret.example", name),
        else => return error.TestExpectedSni,
    }
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const exts = clientHelloExtensions(ch.body).?;
    try std.testing.expect(findClientExt(exts, ech.extension_type) == null);
}

test "ECH fail-safe: a malformed ECHConfigList stands down to a plain ClientHello (never aborts start)" {
    const allocator = std.testing.allocator;
    // Truncated list: 2-byte prefix declares 10 bytes, only 2 follow ⇒ Malformed.
    const bad_list = [_]u8{ 0x00, 0x0A, 0x01, 0x02 };
    var client = try Client.init(allocator, .{
        .server_name = "secret.example",
        .trust_anchors = &.{},
        .ech_config_list = &bad_list,
    });
    defer client.deinit();

    // start() must NOT propagate error.Malformed; it degrades to plain.
    const record = try client.start();
    defer allocator.free(record);
    try std.testing.expect(!client.echOffered());
    switch (sni.extract(record)) {
        .found => |name| try std.testing.expectEqualSlices(u8, "secret.example", name),
        else => return error.TestExpectedSni,
    }
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const exts = clientHelloExtensions(ch.body).?;
    try std.testing.expect(findClientExt(exts, ech.extension_type) == null);
}

test "ECH fail-safe: a KEM-matching config with a wrong-length public key is not offered" {
    const allocator = std.testing.allocator;
    // Hand-build a 0xfe0d / KEM-0x0020 config whose public_key is 5 bytes (not
    // the 32 X25519 needs). It matches the KEM+suite but is not sealable.
    var contents: [64]u8 = undefined;
    var n: usize = 0;
    contents[n] = 9;
    n += 1; // config_id
    std.mem.writeInt(u16, contents[n..][0..2], ech.kem_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], 5, .big);
    n += 2; // public_key length = 5 (invalid for X25519)
    @memcpy(contents[n..][0..5], &[_]u8{ 1, 2, 3, 4, 5 });
    n += 5;
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big);
    n += 2; // cipher_suites length
    std.mem.writeInt(u16, contents[n..][0..2], ech.kdf_id, .big);
    n += 2;
    std.mem.writeInt(u16, contents[n..][0..2], ech.aead_id, .big);
    n += 2;
    contents[n] = 32;
    n += 1; // maximum_name_length
    contents[n] = 9;
    n += 1;
    @memcpy(contents[n..][0..9], "a.example");
    n += 9;
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big);
    n += 2; // extensions

    var entry: [96]u8 = undefined;
    var m: usize = 0;
    std.mem.writeInt(u16, entry[m..][0..2], ech_config.version_draft13, .big);
    m += 2;
    std.mem.writeInt(u16, entry[m..][0..2], @intCast(n), .big);
    m += 2;
    @memcpy(entry[m..][0..n], contents[0..n]);
    m += n;
    var list_buf: [128]u8 = undefined;
    std.mem.writeInt(u16, list_buf[0..2], @intCast(m), .big);
    @memcpy(list_buf[2..][0..m], entry[0..m]);
    const list = list_buf[0 .. 2 + m];

    var client = try Client.init(allocator, .{
        .server_name = "secret.example",
        .trust_anchors = &.{},
        .ech_config_list = list,
    });
    defer client.deinit();
    const record = try client.start();
    defer allocator.free(record);
    try std.testing.expect(!client.echOffered()); // not sealable ⇒ stand down
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const exts = clientHelloExtensions(ch.body).?;
    try std.testing.expect(findClientExt(exts, ech.extension_type) == null);
}

test "ECH active ⇒ ClientHelloOuter uses public_name and a config holder opens the real inner" {
    const allocator = std.testing.allocator;
    // The config holder's HPKE recipient keypair.
    const kp = try ech_hpke.KeyPair.generateDeterministic(@splat(0x5A));
    var list_buf: [600]u8 = undefined;
    const list = buildEchTestList(&list_buf, 7, ech.kem_id, &kp.public_key, "cover.example");

    var client = try Client.init(allocator, .{
        .server_name = "secret.example",
        .trust_anchors = &.{},
        .ech_config_list = list,
    });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);

    try std.testing.expect(client.echOffered());
    // The outer SNI is the cover name, never the real one.
    switch (sni.extract(record)) {
        .found => |name| try std.testing.expectEqualSlices(u8, "cover.example", name),
        else => return error.TestExpectedSni,
    }

    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const exts = clientHelloExtensions(ch.body).?;
    const ech_ext = findClientExt(exts, ech.extension_type) orelse return error.TestExpectedEch;

    // Parse the outer ECH extension: type(0) kdf(2) aead(2) config_id(1) enc<2> payload<2>.
    try std.testing.expectEqual(@as(u8, 0), ech_ext[0]); // ClientHelloType.outer
    try std.testing.expectEqual(ech.kdf_id, std.mem.readInt(u16, ech_ext[1..3], .big));
    try std.testing.expectEqual(ech.aead_id, std.mem.readInt(u16, ech_ext[3..5], .big));
    try std.testing.expectEqual(@as(u8, 7), ech_ext[5]); // config_id
    const enc_len = std.mem.readInt(u16, ech_ext[6..8], .big);
    try std.testing.expectEqual(@as(u16, ech_hpke.enc_len), enc_len);
    const enc = ech_ext[8 .. 8 + enc_len];
    const payload = ech_ext[8 + enc_len + 2 ..];

    // Reconstruct the ClientHelloOuterAAD: the header-LESS outer ClientHello body
    // (ch.body, i.e. without the 4-byte Handshake header) with the ECH payload
    // zeroed. `payload` aliases `record`, so its offset within ch.body is a
    // pointer delta.
    const aad = try allocator.dupe(u8, ch.body);
    defer allocator.free(aad);
    const poff = @intFromPtr(payload.ptr) - @intFromPtr(ch.body.ptr);
    @memset(aad[poff .. poff + payload.len], 0);

    // The config holder opens the payload with its secret key + the same info.
    const cfg = (try ech_config.selectSupported(list, ech.kem_id, ech.kdf_id, ech.aead_id)).?;
    const info = try ech.buildInfo(allocator, cfg);
    defer allocator.free(info);
    var enc_arr: [ech_hpke.enc_len]u8 = undefined;
    @memcpy(&enc_arr, enc);
    const opened = try ech_hpke.openBase(allocator, enc_arr, kp.secret_key, info, aad, payload);
    defer opened.deinit(allocator);

    // opened.bytes = EncodedClientHelloInner (inner CH body + padding). Its
    // legacy_session_id is empty and it carries the REAL SNI + the inner marker.
    const inner_body = opened.bytes;
    try std.testing.expectEqual(@as(u8, 0), inner_body[34]); // empty session_id
    const inner_exts = clientHelloExtensions(inner_body).?;
    const inner_sni = findClientExt(inner_exts, 0) orelse return error.TestExpectedInnerSni;
    try std.testing.expect(std.mem.indexOf(u8, inner_sni, "secret.example") != null);
    const inner_marker = findClientExt(inner_exts, ech.extension_type) orelse return error.TestExpectedInnerEch;
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, inner_marker);
}

test "ECH + CT: the empty SCT extension rides inside the encrypted ClientHelloInner" {
    const allocator = std.testing.allocator;
    const kp = try ech_hpke.KeyPair.generateDeterministic(@splat(0x6B));
    var list_buf: [600]u8 = undefined;
    const list = buildEchTestList(&list_buf, 9, ech.kem_id, &kp.public_key, "cover.example");

    // CT opted in (a pinned log) AND ECH active: the ext-18 request must ride the
    // ENCRYPTED inner ClientHello (the `eb` builder). Like `status_request`, it is
    // also present in the outer cover hello (both builders emit it) — the test
    // below proves the load-bearing half: it reaches the sealed inner.
    const spki = try allocator.dupe(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x07 });
    defer allocator.free(spki);
    const logs = [_]sct.CtLog{.{ .log_id = @as([32]u8, @splat(0xC7)), .key_spki_der = spki }};
    var client = try Client.init(allocator, .{
        .server_name = "secret.example",
        .trust_anchors = &.{},
        .ech_config_list = list,
        .ct_logs = &logs,
    });
    defer client.deinit();

    const record = try client.start();
    defer allocator.free(record);
    try std.testing.expect(client.echOffered());

    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = try parseHandshake(fragment, &off);
    const exts = clientHelloExtensions(ch.body).?;
    const ech_ext = findClientExt(exts, ech.extension_type) orelse return error.TestExpectedEch;
    const enc_len = std.mem.readInt(u16, ech_ext[6..8], .big);
    const enc = ech_ext[8 .. 8 + enc_len];
    const payload = ech_ext[8 + enc_len + 2 ..];

    const aad = try allocator.dupe(u8, ch.body);
    defer allocator.free(aad);
    const poff = @intFromPtr(payload.ptr) - @intFromPtr(ch.body.ptr);
    @memset(aad[poff .. poff + payload.len], 0);

    const cfg = (try ech_config.selectSupported(list, ech.kem_id, ech.kdf_id, ech.aead_id)).?;
    const info = try ech.buildInfo(allocator, cfg);
    defer allocator.free(info);
    var enc_arr: [ech_hpke.enc_len]u8 = undefined;
    @memcpy(&enc_arr, enc);
    const opened = try ech_hpke.openBase(allocator, enc_arr, kp.secret_key, info, aad, payload);
    defer opened.deinit(allocator);

    const inner_exts = clientHelloExtensions(opened.bytes).?;
    const inner_sct = findClientExt(inner_exts, ext_signed_certificate_timestamp) orelse
        return error.TestExpectedInnerSct;
    // RFC 6962 §3.3: the client's request is an EMPTY extension.
    try std.testing.expectEqual(@as(usize, 0), inner_sct.len);
}

test "ECH acceptance signal: client switches to the inner transcript on match, rejects on mismatch" {
    const allocator = std.testing.allocator;
    const kp = try ech_hpke.KeyPair.generateDeterministic(@splat(0x21));
    var list_buf: [600]u8 = undefined;
    const list = buildEchTestList(&list_buf, 1, ech.kem_id, &kp.public_key, "cover.example");

    var client = try Client.init(allocator, .{
        .server_name = "secret.example",
        .trust_anchors = &.{},
        .ech_config_list = list,
    });
    defer client.deinit();
    const record = try client.start();
    defer allocator.free(record);
    try std.testing.expect(client.echOffered());

    // After start() the transcript holds the ClientHelloOuter; snapshot it.
    const outer_copy = try allocator.dupe(u8, client.transcript.items);
    defer allocator.free(outer_copy);
    const inner = client.ech_inner_hello.?;

    // parseServerHello would set this; craft the state directly for the unit.
    client.selected_suite = .tls_aes_128_gcm_sha256;

    // A ServerHello raw (only random[24..32] is read by the acceptance check).
    var sh: [64]u8 = @splat(0xAB);

    // Compute the signal a real accepting server would stamp: over
    // ClientHelloInner || ServerHelloECHConf (this SH with random[24..32] zeroed).
    var conf: std.ArrayList(u8) = .empty;
    defer conf.deinit(allocator);
    try conf.appendSlice(allocator, inner);
    try conf.appendSlice(allocator, &sh);
    @memset(conf.items[inner.len + 30 .. inner.len + 38], 0);
    const th = Sha256.transcriptHash(conf.items);
    var signal: [ech.confirmation_len]u8 = undefined;
    try ech.acceptConfirmation(Sha256, &client.ech_inner_random, &th, .server_hello, &signal);

    // --- Reject path first (wrong signal): transcript must stay the outer. ---
    var sh_bad = sh;
    @memcpy(sh_bad[30..38], &signal);
    sh_bad[30] ^= 0x01;
    try client.checkEchAcceptance(&sh_bad);
    try std.testing.expectEqual(@as(?bool, false), client.ech_accepted);
    try std.testing.expectEqualSlices(u8, outer_copy, client.transcript.items);
    try std.testing.expectEqualSlices(u8, "cover.example", client.effectiveVerifyName()); // rejected ⇒ public name

    // --- Accept path (correct signal): transcript switches to the inner. ---
    @memcpy(sh[30..38], &signal);
    try client.checkEchAcceptance(&sh);
    try std.testing.expectEqual(@as(?bool, true), client.ech_accepted);
    try std.testing.expectEqualSlices(u8, inner, client.transcript.items);
    try std.testing.expectEqualSlices(u8, "secret.example", client.effectiveVerifyName()); // accepted ⇒ real name
}

// Embedded-SCT (Certificate Transparency, roadmap 4.1) wiring — end-to-end over
// `verifyEmbeddedScts`. A real Ed25519 self-signed issuer (so `extractCertParts`
// succeeds) is paired with a SYNTHETIC leaf that carries a genuine embedded SCT
// signed, by a test ECDSA log key, over the reconstructed precertificate. What
// is proven HERE is the wiring's opt-in / fail-open composition: a pinned +
// signature-INVALID SCT rejects ONLY under enforcement; absent, unpinned, or
// tolerated-invalid SCTs never break an otherwise-valid handshake.
// ---------------------------------------------------------------------------

/// One canonical DER TLV (arena-owned), reusing the CRL test length encoder.
fn sctTlv(a: Allocator, tag: u8, value: []const u8) []u8 {
    var out: std.ArrayList(u8) = .empty;
    crlTestTlv(&out, a, tag, value) catch unreachable;
    return out.toOwnedSlice(a) catch unreachable;
}

/// An ECDSA-P256 log SPKI: SEQUENCE { SEQUENCE { OID ecPublicKey, OID
/// prime256v1 }, BIT STRING { 0x00 || sec1 } }.
fn sctTestEcdsaSpki(a: Allocator, sec1: [65]u8) []u8 {
    const oid_ec = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    const oid_p256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    var alg: std.ArrayList(u8) = .empty;
    alg.appendSlice(a, sctTlv(a, x509.Tag.oid, &oid_ec)) catch unreachable;
    alg.appendSlice(a, sctTlv(a, x509.Tag.oid, &oid_p256)) catch unreachable;
    var bits: std.ArrayList(u8) = .empty;
    bits.append(a, 0) catch unreachable; // 0 unused bits
    bits.appendSlice(a, &sec1) catch unreachable;
    var body: std.ArrayList(u8) = .empty;
    body.appendSlice(a, sctTlv(a, x509.Tag.sequence, alg.items)) catch unreachable;
    body.appendSlice(a, sctTlv(a, x509.Tag.bit_string, bits.items)) catch unreachable;
    return sctTlv(a, x509.Tag.sequence, body.items);
}

/// A structurally-walkable leaf TBS prefix (version[0]…spki) — copied verbatim.
fn sctTestPrefix(a: Allocator) []u8 {
    return sctTestPrefixSerial(a, &[_]u8{ 0xAB, 0xCD });
}

/// `sctTestPrefix` with a caller-chosen `serialNumber` value. OCSP-source tests
/// need a DER-POSITIVE serial (high bit clear) so `ocsp.parse`'s CertID validation
/// accepts it, whereas the embedded/ext-18 paths never inspect the serial.
fn sctTestPrefixSerial(a: Allocator, serial: []const u8) []u8 {
    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(a, sctTlv(a, x509.Tag.context_0_constructed, sctTlv(a, x509.Tag.integer, &[_]u8{0x02}))) catch unreachable;
    out.appendSlice(a, sctTlv(a, x509.Tag.integer, serial)) catch unreachable;
    for (0..5) |_| out.appendSlice(a, sctTlv(a, x509.Tag.sequence, "")) catch unreachable;
    return out.toOwnedSlice(a) catch unreachable;
}

/// A generic `Extension ::= SEQUENCE { OID, OCTET STRING }`.
fn sctTestExt(a: Allocator, oid: []const u8, extn_value_content: []const u8) []u8 {
    var body: std.ArrayList(u8) = .empty;
    body.appendSlice(a, sctTlv(a, x509.Tag.oid, oid)) catch unreachable;
    body.appendSlice(a, sctTlv(a, x509.Tag.octet_string, extn_value_content)) catch unreachable;
    return sctTlv(a, x509.Tag.sequence, body.items);
}

/// The SCT-list extension carrying `list` (OCTET STRING wrapping OCTET STRING).
fn sctTestSctExt(a: Allocator, list: []const u8) []u8 {
    return sctTestExt(a, &x509.sct_list_extension_oid, sctTlv(a, x509.Tag.octet_string, list));
}

/// Assemble a TBSCertificate from `prefix` and ordered extension TLVs.
fn sctTestTbs(a: Allocator, prefix: []const u8, exts: []const []const u8) []u8 {
    var ext_content: std.ArrayList(u8) = .empty;
    for (exts) |e| ext_content.appendSlice(a, e) catch unreachable;
    const ext3 = sctTlv(a, x509.Tag.context_3_constructed, sctTlv(a, x509.Tag.sequence, ext_content.items));
    var tbs_body: std.ArrayList(u8) = .empty;
    tbs_body.appendSlice(a, prefix) catch unreachable;
    tbs_body.appendSlice(a, ext3) catch unreachable;
    return sctTlv(a, x509.Tag.sequence, tbs_body.items);
}

/// Wrap a TBS into a `Certificate ::= SEQUENCE { tbs, sigAlg, sigValue }`.
fn sctTestCert(a: Allocator, tbs: []const u8) []u8 {
    var body: std.ArrayList(u8) = .empty;
    body.appendSlice(a, tbs) catch unreachable;
    body.appendSlice(a, sctTlv(a, x509.Tag.sequence, "")) catch unreachable;
    body.appendSlice(a, sctTlv(a, x509.Tag.bit_string, &[_]u8{0x00})) catch unreachable;
    return sctTlv(a, x509.Tag.sequence, body.items);
}

/// A single `serialized_sct` body (RFC 6962 §3.2 wire format) for a v1 SCT with
/// an ECDSA-P256/SHA-256 signature and empty CtExtensions.
fn sctTestSctBody(a: Allocator, log_id: [32]u8, ts: u64, der_sig: []const u8) []u8 {
    var out: std.ArrayList(u8) = .empty;
    out.append(a, 0) catch unreachable; // version v1
    out.appendSlice(a, &log_id) catch unreachable;
    var ts_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &ts_be, ts, .big);
    out.appendSlice(a, &ts_be) catch unreachable;
    out.appendSlice(a, &[_]u8{ 0x00, 0x00 }) catch unreachable; // CtExtensions length 0
    out.appendSlice(a, &[_]u8{ 0x04, 0x03 }) catch unreachable; // sha256, ecdsa
    var sig_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &sig_len, @intCast(der_sig.len), .big);
    out.appendSlice(a, &sig_len) catch unreachable;
    out.appendSlice(a, der_sig) catch unreachable;
    return out.toOwnedSlice(a) catch unreachable;
}

/// Wrap one `serialized_sct` body into a `SignedCertificateTimestampList`.
fn sctTestList(a: Allocator, body: []const u8) []u8 {
    var out: std.ArrayList(u8) = .empty;
    var total: [2]u8 = undefined;
    std.mem.writeInt(u16, &total, @intCast(body.len + 2), .big);
    var item_len: [2]u8 = undefined;
    std.mem.writeInt(u16, &item_len, @intCast(body.len), .big);
    out.appendSlice(a, &total) catch unreachable;
    out.appendSlice(a, &item_len) catch unreachable;
    out.appendSlice(a, body) catch unreachable;
    return out.toOwnedSlice(a) catch unreachable;
}

/// Everything a wiring test needs: a real issuer, a valid SCT-bearing leaf, and
/// the pinned log that issued it.
const SctFixture = struct {
    issuer_der: []const u8,
    prefix: []const u8,
    other_ext: []const u8,
    precert_tbs: []const u8,
    log: sct.CtLog,
    ts: u64,
    der_sig: []u8, // mutable so a test can tamper it
    /// The exact `CertificateTimestamp` bytes every embedded SCT signs over (the
    /// precert entry framed by `verifyList`). Additional CT logs sign these same
    /// bytes to build a distinct-log quorum (see `sctFixtureSignWithLog`).
    signed: []const u8,
};

fn buildSctFixture(a: Allocator) !SctFixture {
    return buildSctFixtureSerial(a, &[_]u8{ 0xAB, 0xCD });
}

/// `buildSctFixture` with a caller-chosen leaf `serial` — the OCSP-source tests
/// need a DER-positive one so the stapled response's CertID parses.
fn buildSctFixtureSerial(a: Allocator, serial: []const u8) !SctFixture {
    // A real Ed25519 self-signed issuer so `extractCertParts` succeeds.
    const Ed25519 = std.crypto.sign.Ed25519;
    const issuer_kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x33)));
    var issuer_buf: [1024]u8 = undefined;
    const issuer_der = try a.dupe(u8, try x509_selfsign.buildSelfSigned(&issuer_buf, .{
        .common_name = "issuer.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x12, 0x34 },
        .key_pair = issuer_kp,
        .dns_names = &.{"issuer.test"},
        .is_ca = true,
    }));
    const issuer_parts = try extractCertParts(issuer_der);
    const issuer_key_hash = hash.Sha256.hash(issuer_parts.spki_der);

    // A test ECDSA-P256 CT log key.
    const log_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const log_spki = sctTestEcdsaSpki(a, log_kp.public_key.toUncompressedSec1());
    const log = sct.CtLog{ .log_id = sct.logIdFromSpki(log_spki), .key_spki_der = log_spki };

    // The precertificate TBS the SCT signs over (leaf minus the SCT extension).
    const prefix = sctTestPrefixSerial(a, serial);
    const other_ext = sctTestExt(a, &[_]u8{ 0x55, 0x1D, 0x13 }, sctTlv(a, x509.Tag.sequence, "")); // basicConstraints
    const precert_tbs = sctTestTbs(a, prefix, &.{other_ext});

    // Sign the SCT over the precert entry exactly as `verifyList` reframes it.
    const ts: u64 = 1_700_000_000_000;
    var entry_buf: [1024]u8 = undefined;
    const entry = try sct.buildPrecertEntry(&entry_buf, issuer_key_hash, precert_tbs);
    var signed_buf: [2048]u8 = undefined;
    const signed = try sct.buildSignedData(&signed_buf, .{
        .timestamp = ts,
        .entry_type = .precert_entry,
        .signed_entry = entry,
        .extensions = &.{},
    });
    const sig = try ecdsa_p256.sign(signed, log_kp);
    var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = try a.dupe(u8, try ecdsa_p256.signatureToDer(sig, &der_buf));

    return .{
        .issuer_der = issuer_der,
        .prefix = prefix,
        .other_ext = other_ext,
        .precert_tbs = precert_tbs,
        .log = log,
        .ts = ts,
        .der_sig = der_sig,
        .signed = try a.dupe(u8, signed), // signed aliases the stack buffer; own it
    };
}

/// A pinned CT log plus a valid SCT signature over a fixture's `signed` bytes.
const SctLogSig = struct {
    log: sct.CtLog,
    der_sig: []u8,
};

/// Mint a FRESH, distinct ECDSA-P256 CT log and produce a valid SCT signature
/// over `f.signed` with it — the building block for a distinct-log quorum. Each
/// call generates an independent key (via `testing.io`), so successive logs have
/// distinct `log_id`s.
fn sctFixtureSignWithLog(a: Allocator, f: SctFixture) SctLogSig {
    const log_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const log_spki = sctTestEcdsaSpki(a, log_kp.public_key.toUncompressedSec1());
    const log = sct.CtLog{ .log_id = sct.logIdFromSpki(log_spki), .key_spki_der = log_spki };
    const sig = ecdsa_p256.sign(f.signed, log_kp) catch unreachable;
    var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = a.dupe(u8, ecdsa_p256.signatureToDer(sig, &der_buf) catch unreachable) catch unreachable;
    return .{ .log = log, .der_sig = der_sig };
}

/// One embedded SCT to place in a multi-SCT leaf: which log id claims it, and the
/// signature bytes to carry (valid or deliberately broken).
const SctLeafEntry = struct {
    log_id: [32]u8,
    der_sig: []const u8,
};

/// Wrap several `serialized_sct` bodies into one `SignedCertificateTimestampList`
/// (outer u16 length + per-item u16-length-prefixed bodies).
fn sctTestListMulti(a: Allocator, bodies: []const []const u8) []u8 {
    var inner: std.ArrayList(u8) = .empty;
    for (bodies) |b| {
        var item_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &item_len, @intCast(b.len), .big);
        inner.appendSlice(a, &item_len) catch unreachable;
        inner.appendSlice(a, b) catch unreachable;
    }
    var out: std.ArrayList(u8) = .empty;
    var total: [2]u8 = undefined;
    std.mem.writeInt(u16, &total, @intCast(inner.items.len), .big);
    out.appendSlice(a, &total) catch unreachable;
    out.appendSlice(a, inner.items) catch unreachable;
    return out.toOwnedSlice(a) catch unreachable;
}

/// Assemble a leaf carrying MANY embedded SCTs (in order), for quorum tests. The
/// precert TBS (and thus `f.signed`) is independent of the SCT list, so every
/// entry signs the same bytes; the leaf reconstructs to `f.precert_tbs`.
fn sctFixtureLeafMulti(a: Allocator, f: SctFixture, entries: []const SctLeafEntry) []u8 {
    var bodies: std.ArrayList([]const u8) = .empty;
    for (entries) |e| bodies.append(a, sctTestSctBody(a, e.log_id, f.ts, e.der_sig)) catch unreachable;
    const list = sctTestListMulti(a, bodies.items);
    const sct_ext = sctTestSctExt(a, list);
    return sctTestCert(a, sctTestTbs(a, f.prefix, &.{ f.other_ext, sct_ext }));
}

/// Assemble the SCT-bearing leaf certificate for a fixture given a signature.
fn sctFixtureLeaf(a: Allocator, f: SctFixture, der_sig: []const u8) []u8 {
    const body = sctTestSctBody(a, f.log.log_id, f.ts, der_sig);
    const list = sctTestList(a, body);
    const sct_ext = sctTestSctExt(a, list);
    return sctTestCert(a, sctTestTbs(a, f.prefix, &.{ f.other_ext, sct_ext }));
}

test "verifyEmbeddedScts: reconstruction round-trips and a valid pinned SCT verifies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);
    const leaf = sctFixtureLeaf(a, f, f.der_sig);

    // The production reconstruction reproduces the exact bytes we signed over.
    var tbs_buf: [4096]u8 = undefined;
    try std.testing.expectEqualSlices(u8, f.precert_tbs, try x509.buildPrecertTbs(&tbs_buf, leaf));

    // A valid pinned SCT passes under enforcement (and, trivially, without it).
    const chain = [_][]const u8{ leaf, f.issuer_der };
    try verifyEmbeddedScts(&chain, &.{f.log}, true, 0);
    try verifyEmbeddedScts(&chain, &.{f.log}, false, 0);
}

test "verifyEmbeddedScts: a tampered pinned SCT rejects ONLY under enforcement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);

    // Flip a signature byte so the pinned log matches but verification fails.
    const bad_sig = try a.dupe(u8, f.der_sig);
    bad_sig[bad_sig.len - 1] ^= 0x01;
    const bad_leaf = sctFixtureLeaf(a, f, bad_sig);
    const chain = [_][]const u8{ bad_leaf, f.issuer_der };

    // Enforcement on → the invalid pinned SCT is a hard reject.
    try std.testing.expectError(error.BadSct, verifyEmbeddedScts(&chain, &.{f.log}, true, 0));
    // Enforcement off → the same invalid SCT is tolerated (fail-open).
    try verifyEmbeddedScts(&chain, &.{f.log}, false, 0);
}

test "verifyEmbeddedScts: absent, unpinned, and feature-off cases all pass" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);
    const leaf = sctFixtureLeaf(a, f, f.der_sig);

    // Feature off (empty log set) is a pure no-op even under enforcement AND a
    // presence requirement, even for a structurally broken leaf — the
    // byte-identical-when-off gate (an empty `ct_logs` short-circuits before any
    // policy, so `require_sct` cannot manufacture a rejection out of thin air).
    try verifyEmbeddedScts(&.{&[_]u8{ 0xDE, 0xAD }}, &.{}, true, 2);

    // An SCT from a log this deployment does not pin → no_applicable_log → pass
    // when presence is not required.
    const other_log = sct.CtLog{ .log_id = @as([32]u8, @splat(0x00)), .key_spki_der = f.log.key_spki_der };
    const chain = [_][]const u8{ leaf, f.issuer_der };
    try verifyEmbeddedScts(&chain, &.{other_log}, true, 0);

    // A leaf with NO embedded SCT extension → nothing to check → pass when
    // presence is not required.
    const no_sct_leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const no_sct_chain = [_][]const u8{ no_sct_leaf, f.issuer_der };
    try verifyEmbeddedScts(&no_sct_chain, &.{f.log}, true, 0);

    // A tampered (invalid) SCT with the feature off is still tolerated.
    const bad_sig = try a.dupe(u8, f.der_sig);
    bad_sig[0] ^= 0xFF;
    const bad_chain = [_][]const u8{ sctFixtureLeaf(a, f, bad_sig), f.issuer_der };
    try verifyEmbeddedScts(&bad_chain, &.{}, true, 0);
}

test "verifyEmbeddedScts: require_sct enforces a distinct-log presence quorum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);

    // Two ADDITIONAL, independent pinned logs, each signing the same precert.
    const l1 = sctFixtureSignWithLog(a, f);
    const l2 = sctFixtureSignWithLog(a, f);
    try std.testing.expect(!std.mem.eql(u8, &l1.log.log_id, &l2.log.log_id));

    // A leaf carrying one valid SCT from each of the two DISTINCT logs.
    const two_distinct = sctFixtureLeafMulti(a, f, &.{
        .{ .log_id = l1.log.log_id, .der_sig = l1.der_sig },
        .{ .log_id = l2.log.log_id, .der_sig = l2.der_sig },
    });
    const chain = [_][]const u8{ two_distinct, f.issuer_der };
    const pins = [_]sct.CtLog{ l1.log, l2.log };

    // At or below the number of distinct valid logs present ⇒ pass.
    try verifyEmbeddedScts(&chain, &pins, false, 1);
    try verifyEmbeddedScts(&chain, &pins, false, 2);
    // Requiring MORE distinct logs than are present ⇒ hard reject.
    try std.testing.expectError(error.InsufficientScts, verifyEmbeddedScts(&chain, &pins, false, 3));
}

test "verifyEmbeddedScts: duplicate-log SCTs cannot satisfy a 2-log quorum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);
    const l1 = sctFixtureSignWithLog(a, f);

    // TWO valid SCTs, both from the SAME pinned log l1.
    const dup = sctFixtureLeafMulti(a, f, &.{
        .{ .log_id = l1.log.log_id, .der_sig = l1.der_sig },
        .{ .log_id = l1.log.log_id, .der_sig = l1.der_sig },
    });
    const chain = [_][]const u8{ dup, f.issuer_der };
    const pins = [_]sct.CtLog{l1.log};

    // distinct_valid_logs = 1: satisfies a 1-log quorum but NOT a 2-log quorum —
    // N copies from one log can never meet an N-distinct-log policy.
    try verifyEmbeddedScts(&chain, &pins, false, 1);
    try std.testing.expectError(error.InsufficientScts, verifyEmbeddedScts(&chain, &pins, false, 2));
}

test "verifyEmbeddedScts: require_sct rejects absent and unpinned-only SCTs (mis-issuance gate)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);
    const leaf = sctFixtureLeaf(a, f, f.der_sig); // one valid SCT from f.log
    const chain = [_][]const u8{ leaf, f.issuer_der };

    // 1) A leaf with NO SCT extension is exactly the bypass `enforce_sct` cannot
    //    catch (nothing present to be "invalid"); `require_sct` MUST reject it.
    const no_sct_leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const no_sct_chain = [_][]const u8{ no_sct_leaf, f.issuer_der };
    try std.testing.expectError(error.InsufficientScts, verifyEmbeddedScts(&no_sct_chain, &.{f.log}, false, 1));
    // enforce_sct alone never rejects the absent-SCT leaf — the very gap we close.
    try verifyEmbeddedScts(&no_sct_chain, &.{f.log}, true, 0);

    // 2) A valid SCT but from an UNPINNED log ⇒ distinct_valid_logs = 0 ⇒ reject.
    const other_log = sct.CtLog{ .log_id = @as([32]u8, @splat(0x00)), .key_spki_der = f.log.key_spki_der };
    try std.testing.expectError(error.InsufficientScts, verifyEmbeddedScts(&chain, &.{other_log}, false, 1));

    // 3) Non-vacuous: the SAME leaf PASSES once its issuing log is pinned, so the
    //    rejections above are about presence/pinning, not a broken fixture.
    try verifyEmbeddedScts(&chain, &.{f.log}, false, 1);

    // 4) require_sct = 0 (default) keeps the absent-SCT leaf passing — the opt-in,
    //    byte-identical-when-off contract, independent of enforce_sct.
    try verifyEmbeddedScts(&no_sct_chain, &.{f.log}, false, 0);
}

test "verifyEmbeddedScts: require_sct composes with enforce_sct" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);
    const good = sctFixtureSignWithLog(a, f);
    const other = sctFixtureSignWithLog(a, f);

    // A tampered signature for `other`'s pinned log: matches a pin but invalid.
    const bad_sig = try a.dupe(u8, other.der_sig);
    bad_sig[bad_sig.len - 1] ^= 0x01;

    // Leaf: one VALID SCT (good's log) + one INVALID SCT (other's log).
    const leaf = sctFixtureLeafMulti(a, f, &.{
        .{ .log_id = good.log.log_id, .der_sig = good.der_sig },
        .{ .log_id = other.log.log_id, .der_sig = bad_sig },
    });
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const pins = [_]sct.CtLog{ good.log, other.log };

    // enforce on: the invalid pinned SCT hard-rejects (BadSct) regardless of quorum.
    try std.testing.expectError(error.BadSct, verifyEmbeddedScts(&chain, &pins, true, 1));
    // enforce off, require 1: one distinct VALID log present ⇒ pass; the invalid
    // SCT is tolerated and never counts toward the quorum.
    try verifyEmbeddedScts(&chain, &pins, false, 1);
    // enforce off, require 2: only ONE distinct valid log ⇒ below quorum ⇒ reject.
    // The invalid SCT does NOT make up the shortfall.
    try std.testing.expectError(error.InsufficientScts, verifyEmbeddedScts(&chain, &pins, false, 2));
}

/// A pinned CT log plus a `SignedCertificateTimestampList` whose single SCT signs
/// over the FINAL leaf DER (`x509_entry`) — the shape a server delivers in the
/// leaf CertificateEntry's `signed_certificate_timestamp` extension (RFC 6962
/// §3.3). Each call mints a fresh, distinct ECDSA-P256 log.
const SctX509Sig = struct {
    log: sct.CtLog,
    list: []u8, // the raw SignedCertificateTimestampList (ext-18 extension_data)
};

/// Sign an `x509_entry` SCT over `leaf_der` with a fresh pinned log and wrap it in
/// a one-item `SignedCertificateTimestampList`.
fn sctFixtureSignX509(a: Allocator, leaf_der: []const u8, ts: u64) SctX509Sig {
    const log_kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const log_spki = sctTestEcdsaSpki(a, log_kp.public_key.toUncompressedSec1());
    const log = sct.CtLog{ .log_id = sct.logIdFromSpki(log_spki), .key_spki_der = log_spki };

    const signed_buf = a.alloc(u8, leaf_der.len + 64) catch unreachable;
    const signed = sct.buildSignedData(signed_buf, .{
        .timestamp = ts,
        .entry_type = .x509_entry,
        .signed_entry = leaf_der,
        .extensions = &.{},
    }) catch unreachable;
    const sig = ecdsa_p256.sign(signed, log_kp) catch unreachable;
    var der_buf: [ecdsa_p256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = ecdsa_p256.signatureToDer(sig, &der_buf) catch unreachable;
    const body = sctTestSctBody(a, log.log_id, ts, der_sig);
    const list = sctTestListMulti(a, &.{body});
    return .{ .log = log, .list = list };
}

test "verifyScts: a TLS-extension SCT satisfies the quorum with no embedded SCT" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);

    // A leaf carrying NO embedded SCT extension; SCTs arrive only over ext-18.
    const leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const x = sctFixtureSignX509(a, leaf, f.ts);
    const pins = [_]sct.CtLog{x.log};

    // The valid ext-18 SCT meets a 1-log presence quorum (and passes under enforce).
    try verifyScts(&chain, x.list, null, &pins, false, 1);
    try verifyScts(&chain, x.list, null, &pins, true, 1);
    // Without the ext-18 source, the same leaf has no SCTs at all ⇒ below quorum.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, null, &pins, false, 1));
    // A 2-log quorum is not met by a single ext-18 log.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, x.list, null, &pins, false, 2));
}

test "verifyScts: embedded and TLS-extension SCTs pool into one distinct-log quorum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);

    // Embedded SCT from f.log (precert entry), plus an ext-18 SCT from a DISTINCT
    // log (x509 entry over the SAME leaf).
    const leaf = sctFixtureLeaf(a, f, f.der_sig);
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const x = sctFixtureSignX509(a, leaf, f.ts);
    try std.testing.expect(!std.mem.eql(u8, &f.log.log_id, &x.log.log_id));
    const pins = [_]sct.CtLog{ f.log, x.log };

    // Pooled union {embedded f.log, ext-18 x.log} = 2 distinct logs.
    try verifyScts(&chain, x.list, null, &pins, false, 2);
    try verifyScts(&chain, x.list, null, &pins, true, 2);
    // 3 distinct logs are not available ⇒ reject.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, x.list, null, &pins, false, 3));
    // Neither source ALONE reaches 2 distinct logs — proving the pooling matters.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, null, &pins, false, 2));
    const no_embed = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const no_embed_chain = [_][]const u8{ no_embed, f.issuer_der };
    const x2 = sctFixtureSignX509(a, no_embed, f.ts);
    try std.testing.expectError(error.InsufficientScts, verifyScts(&no_embed_chain, x2.list, null, &[_]sct.CtLog{x2.log}, false, 2));
}

test "verifyScts: a tampered TLS-extension SCT rejects ONLY under enforcement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);

    const leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const x = sctFixtureSignX509(a, leaf, f.ts);
    const pins = [_]sct.CtLog{x.log};

    // Flip the LAST byte of the ext-18 list (the trailing signature byte): the
    // pinned log still matches, but the signature is invalid.
    x.list[x.list.len - 1] ^= 0x01;
    // enforce on → the invalid pinned ext-18 SCT is a hard reject.
    try std.testing.expectError(error.BadSct, verifyScts(&chain, x.list, null, &pins, true, 0));
    // enforce off → tolerated (fail-open); and it never counts toward a quorum.
    try verifyScts(&chain, x.list, null, &pins, false, 0);
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, x.list, null, &pins, false, 1));
}

test "verifyScts: TLS-extension SCTs are ignored when the feature is off" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try buildSctFixture(a);
    const leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const x = sctFixtureSignX509(a, leaf, f.ts);

    // ct_logs empty ⇒ the whole path is skipped (no ext-18 was ever advertised),
    // even under enforce AND a presence requirement: byte-identical-when-off.
    try verifyScts(&chain, x.list, null, &.{}, true, 2);
    // A structurally broken ext-18 list is likewise a no-op when the feature is off.
    try verifyScts(&chain, &[_]u8{ 0xDE, 0xAD }, null, &.{}, true, 2);
}

/// Assemble a minimal RFC 6960 OCSP response DER that `ocsp.parse` accepts, with
/// one `good` SingleResponse for `leaf_serial`. When `sct_list` is non-null it is
/// carried in that SingleResponse's `singleExtensions` under the OCSP SCT-list OID
/// (1.3.6.1.4.1.11129.2.4.5); null omits the extension. The BasicOCSPResponse
/// signature is a placeholder — `ocspSctSummary` authenticates each SCT by its own
/// log signature, never the OCSP response signature.
fn sctTestOcspStaple(a: Allocator, leaf_serial: []const u8, sct_list: ?[]const u8) []u8 {
    const enumerated: u8 = 0x0A;
    const context_0_primitive: u8 = 0x80; // certStatus good [0] IMPLICIT NULL
    const context_2_primitive: u8 = 0x82; // responderID byKey [2] KeyHash

    // CertID ::= SEQUENCE { hashAlgorithm SEQUENCE{OID sha1, NULL}, issuerNameHash
    // OCTET STRING, issuerKeyHash OCTET STRING, serialNumber INTEGER }.
    const oid_sha1 = [_]u8{ 0x2B, 0x0E, 0x03, 0x02, 0x1A };
    var hash_alg_body: std.ArrayList(u8) = .empty;
    hash_alg_body.appendSlice(a, sctTlv(a, x509.Tag.oid, &oid_sha1)) catch unreachable;
    hash_alg_body.appendSlice(a, sctTlv(a, x509.Tag.null_value, "")) catch unreachable;
    var cert_id_body: std.ArrayList(u8) = .empty;
    cert_id_body.appendSlice(a, sctTlv(a, x509.Tag.sequence, hash_alg_body.items)) catch unreachable;
    cert_id_body.appendSlice(a, sctTlv(a, x509.Tag.octet_string, &@as([20]u8, @splat(0x11)))) catch unreachable;
    cert_id_body.appendSlice(a, sctTlv(a, x509.Tag.octet_string, &@as([20]u8, @splat(0x22)))) catch unreachable;
    cert_id_body.appendSlice(a, sctTlv(a, x509.Tag.integer, leaf_serial)) catch unreachable;
    const cert_id = sctTlv(a, x509.Tag.sequence, cert_id_body.items);

    // SingleResponse: CertID, certStatus good, thisUpdate, [singleExtensions].
    var single_body: std.ArrayList(u8) = .empty;
    single_body.appendSlice(a, cert_id) catch unreachable;
    single_body.appendSlice(a, sctTlv(a, context_0_primitive, "")) catch unreachable; // good
    single_body.appendSlice(a, sctTlv(a, x509.Tag.generalized_time, "20260102030405Z")) catch unreachable;
    if (sct_list) |list| {
        // Extension: SEQUENCE { OID sct-ocsp, OCTET STRING( OCTET STRING(list) ) };
        // wrapped in singleExtensions [1] EXPLICIT SEQUENCE OF Extension.
        const ext = sctTestExt(a, &ocsp.sct_ocsp_extension_oid, sctTlv(a, x509.Tag.octet_string, list));
        const ext_seq = sctTlv(a, x509.Tag.sequence, ext);
        single_body.appendSlice(a, sctTlv(a, x509.Tag.context_1_constructed, ext_seq)) catch unreachable;
    }
    const single = sctTlv(a, x509.Tag.sequence, single_body.items);

    // ResponseData: responderID byKey [2], producedAt, responses SEQUENCE OF.
    var tbs_body: std.ArrayList(u8) = .empty;
    tbs_body.appendSlice(a, sctTlv(a, context_2_primitive, &@as([20]u8, @splat(0x33)))) catch unreachable;
    tbs_body.appendSlice(a, sctTlv(a, x509.Tag.generalized_time, "20260102030405Z")) catch unreachable;
    tbs_body.appendSlice(a, sctTlv(a, x509.Tag.sequence, single)) catch unreachable;
    const tbs = sctTlv(a, x509.Tag.sequence, tbs_body.items);

    // BasicOCSPResponse: tbsResponseData, signatureAlgorithm, signature (dummy).
    const oid_ecdsa_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    var basic_body: std.ArrayList(u8) = .empty;
    basic_body.appendSlice(a, tbs) catch unreachable;
    basic_body.appendSlice(a, sctTlv(a, x509.Tag.sequence, sctTlv(a, x509.Tag.oid, &oid_ecdsa_sha256))) catch unreachable;
    basic_body.appendSlice(a, sctTlv(a, x509.Tag.bit_string, &[_]u8{ 0x00, 0xAB, 0xCD })) catch unreachable;
    const basic = sctTlv(a, x509.Tag.sequence, basic_body.items);

    // responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING }.
    const oid_ocsp_basic = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
    var rb_body: std.ArrayList(u8) = .empty;
    rb_body.appendSlice(a, sctTlv(a, x509.Tag.oid, &oid_ocsp_basic)) catch unreachable;
    rb_body.appendSlice(a, sctTlv(a, x509.Tag.octet_string, basic)) catch unreachable;
    const response_bytes = sctTlv(a, x509.Tag.context_0_constructed, sctTlv(a, x509.Tag.sequence, rb_body.items));

    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED successful, responseBytes }.
    var ocsp_body: std.ArrayList(u8) = .empty;
    ocsp_body.appendSlice(a, sctTlv(a, enumerated, &[_]u8{0x00})) catch unreachable;
    ocsp_body.appendSlice(a, response_bytes) catch unreachable;
    return sctTlv(a, x509.Tag.sequence, ocsp_body.items);
}

test "verifyScts: an OCSP-delivered SCT satisfies the quorum with no embedded/ext-18 SCT" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const serial = [_]u8{ 0x02, 0x9A }; // DER-positive so the CertID parses
    const f = try buildSctFixtureSerial(a, &serial);
    // A leaf carrying NO embedded SCT extension; SCTs arrive only over OCSP.
    const leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    try std.testing.expectEqualSlices(u8, &serial, leafSerialDer(leaf).?);
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const o = sctFixtureSignX509(a, leaf, f.ts); // OCSP SCT signs the final leaf (x509_entry)
    const staple = sctTestOcspStaple(a, &serial, o.list);
    const pins = [_]sct.CtLog{o.log};

    // The valid OCSP SCT meets a 1-log presence quorum (and passes under enforce).
    try verifyScts(&chain, null, staple, &pins, false, 1);
    try verifyScts(&chain, null, staple, &pins, true, 1);
    // Without the OCSP staple, the same leaf has no SCTs at all ⇒ below quorum.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, null, &pins, false, 1));
    // A 2-log quorum is not met by a single OCSP log.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, staple, &pins, false, 2));
}

test "verifyScts: embedded, TLS-extension, and OCSP SCTs pool into one distinct-log quorum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const serial = [_]u8{ 0x03, 0x11 };
    const f = try buildSctFixtureSerial(a, &serial);
    // Leaf carrying the embedded precert SCT from f.log.
    const leaf = sctFixtureLeaf(a, f, f.der_sig);
    const chain = [_][]const u8{ leaf, f.issuer_der };
    // ext-18 SCT from a DISTINCT log, OCSP SCT from a THIRD distinct log — both
    // over the FINAL leaf DER (x509_entry).
    const x = sctFixtureSignX509(a, leaf, f.ts);
    const o = sctFixtureSignX509(a, leaf, f.ts);
    try std.testing.expect(!std.mem.eql(u8, &f.log.log_id, &x.log.log_id));
    try std.testing.expect(!std.mem.eql(u8, &f.log.log_id, &o.log.log_id));
    try std.testing.expect(!std.mem.eql(u8, &x.log.log_id, &o.log.log_id));
    const staple = sctTestOcspStaple(a, &serial, o.list);
    const pins = [_]sct.CtLog{ f.log, x.log, o.log };

    // Pooled union {embedded f.log, ext-18 x.log, OCSP o.log} = 3 distinct logs.
    try verifyScts(&chain, x.list, staple, &pins, false, 3);
    try verifyScts(&chain, x.list, staple, &pins, true, 3);
    // 4 distinct logs are not available ⇒ reject.
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, x.list, staple, &pins, false, 4));
    // NONE of the three sources dropped leaves 3 reachable — proving the pooling
    // matters (embedded is always present on this leaf; each pair reaches only 2).
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, null, &pins, false, 3));
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, x.list, null, &pins, false, 3));
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, staple, &pins, false, 3));
}

test "verifyScts: a tampered OCSP-delivered SCT rejects ONLY under enforcement" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const serial = [_]u8{ 0x02, 0x9A };
    const f = try buildSctFixtureSerial(a, &serial);
    const leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const o = sctFixtureSignX509(a, leaf, f.ts);
    // Flip the LAST byte of the SCT list (the trailing signature byte): the pinned
    // log still matches, but the signature is invalid. Tamper BEFORE embedding.
    o.list[o.list.len - 1] ^= 0x01;
    const staple = sctTestOcspStaple(a, &serial, o.list);
    const pins = [_]sct.CtLog{o.log};

    // enforce on → the invalid pinned OCSP SCT is a hard reject.
    try std.testing.expectError(error.BadSct, verifyScts(&chain, null, staple, &pins, true, 0));
    // enforce off → tolerated (fail-open); and it never counts toward a quorum.
    try verifyScts(&chain, null, staple, &pins, false, 0);
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, staple, &pins, false, 1));
}

test "verifyScts: OCSP-delivered SCTs are ignored when the feature is off" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const serial = [_]u8{ 0x02, 0x9A };
    const f = try buildSctFixtureSerial(a, &serial);
    const leaf = sctTestCert(a, sctTestTbs(a, f.prefix, &.{f.other_ext}));
    const chain = [_][]const u8{ leaf, f.issuer_der };
    const o = sctFixtureSignX509(a, leaf, f.ts);
    const staple = sctTestOcspStaple(a, &serial, o.list);

    // ct_logs empty ⇒ the whole path is skipped. OCSP stapling is requested
    // regardless, so mining adds no wire change: byte-identical-when-off — even
    // under enforce AND a presence requirement.
    try verifyScts(&chain, null, staple, &.{}, true, 2);
    // A structurally broken staple is likewise a no-op when the feature is off.
    try verifyScts(&chain, null, &[_]u8{ 0xDE, 0xAD }, &.{}, true, 2);
    // Feature ON but the staple carries NO SCT extension ⇒ contributes nothing
    // (fail-open); require 1 with only the OCSP source ⇒ below quorum.
    const no_sct_staple = sctTestOcspStaple(a, &serial, null);
    try std.testing.expectError(error.InsufficientScts, verifyScts(&chain, null, no_sct_staple, &[_]sct.CtLog{o.log}, false, 1));
}

test "Client advertises the SCT extension only when CT logs are pinned" {
    const a = std.testing.allocator;

    // Off (default): no ct_logs ⇒ ext-18 (type 18) MUST NOT appear in ClientHello.
    {
        var client = try Client.init(a, .{ .server_name = "ct.test", .trust_anchors = &.{} });
        defer client.deinit();
        const hello = try client.start();
        defer a.free(hello);
        try std.testing.expect(!clientHelloHasExtension(hello, ext_signed_certificate_timestamp));
        // Sanity: the status_request extension (always sent) IS present, proving
        // the scan works and the ClientHello parsed.
        try std.testing.expect(clientHelloHasExtension(hello, ext_status_request));
    }

    // On: a pinned log ⇒ the empty ext-18 IS advertised.
    {
        const spki = try a.dupe(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x07 });
        defer a.free(spki);
        const logs = [_]sct.CtLog{.{ .log_id = @as([32]u8, @splat(0xA5)), .key_spki_der = spki }};
        var client = try Client.init(a, .{ .server_name = "ct.test", .trust_anchors = &.{}, .ct_logs = &logs });
        defer client.deinit();
        const hello = try client.start();
        defer a.free(hello);
        try std.testing.expect(clientHelloHasExtension(hello, ext_signed_certificate_timestamp));
    }
}

/// Scan a raw ClientHello handshake record (the bytes `start()` returns) for an
/// extension of `ext_type`. Test-only; walks the record → handshake → ClientHello
/// body → extensions block, mirroring the OCSP `status_request` test above.
fn clientHelloHasExtension(record: []const u8, ext_type: u16) bool {
    const fragment = record[tls_record.record_header_len..];
    var off: usize = 0;
    const ch = parseHandshake(fragment, &off) catch return false;
    const ext_block = clientHelloExtensions(ch.body) orelse return false;
    var it = tls_extension.Iterator.init(ext_block);
    while (it.next() catch return false) |e| {
        if (e.ext_type == ext_type) return true;
    }
    return false;
}

test "Client deep-copies pinned CT logs and frees them (no leak, no dangle)" {
    const a = std.testing.allocator;
    // A heap-allocated SPKI that we free right after init: the client must own
    // its own copy, so a later use must not read freed memory.
    const src_spki = try a.dupe(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x07 });
    const logs = [_]sct.CtLog{.{ .log_id = @as([32]u8, @splat(0xA5)), .key_spki_der = src_spki }};

    var client = try Client.init(a, .{
        .server_name = "ct.test",
        .trust_anchors = &.{},
        .ct_logs = &logs,
        .enforce_sct = true,
        .require_sct = 2,
    });
    // Free the caller's SPKI; the client's deep copy must be unaffected.
    a.free(src_spki);
    try std.testing.expectEqual(@as(usize, 1), client.ct_logs.len);
    try std.testing.expect(client.enforce_sct);
    try std.testing.expectEqual(@as(u8, 2), client.require_sct); // policy threshold round-trips
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x07 }, client.ct_logs[0].key_spki_der);
    try std.testing.expect(client.ct_logs[0].key_spki_der.ptr != src_spki.ptr);
    client.deinit(); // the testing allocator flags any leak or double-free here
}

// ===========================================================================
// Certificate-chain signature-algorithm coverage (roadmap 1.3, #46 follow-up).
//
// verifyChainToTrustAnchors / verifyIssuedBy delegate their signature primitive
// to x509_verify.verifySignedBy, so the production TLS 1.3 client now anchors CA
// links across the FULL sig-alg set (RSA PKCS#1 SHA-256/384/512, RSASSA-PSS,
// ECDSA P-256/P-384, Ed25519) — the single, independently-tested x509_verify
// implementation — instead of a duplicated local dispatch. Each cert below is
// minted self-signed with a SAN and used as its OWN trust anchor: the anchor
// loop matches the tip's subject DN, then verifies the tip's signature under the
// anchor's public key — precisely the code path a real intermediate->root link
// drives, exercised once per algorithm. `now = null` skips the validity window;
// the certs carry no EKU, so the serverAuth gate passes.
// ===========================================================================

const chain_test_san = "leaf.tls13.onyx.test";

fn hexConst(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

fn verifySelfAnchored(der: []const u8) Error!void {
    const chain = [_][]const u8{der};
    const anchors = [_][]const u8{der};
    return verifyChainToTrustAnchors(&chain, &anchors, chain_test_san, null);
}

// A real RSA-2048 private key (the same vector x509_selfsign's own tests use) for
// minting RSA-signed test certs.
const chain_test_rsa_n = hexConst("a0bd1304a87f0a69b8ef18eaa1da15522c221b1e9b1efaee23bea1faa7eaaefe1e09eba390ec9334aea9457530d40c6a6b89c039865e98dd9d7491ea57288debf370f796fe05904a589027272fc9bd803fcf9d228c5552da7ff4f2a25c1606b3a4794f4ffa5bd94ab2150026dbcd31c4f4a5755d449a7aaf41861ff069fa455563cb22de14114aff8085fc3d3c07bc929d761f6449c1a13975738c9876319599f88bd3676230802d76b7292ad0759dad8fc70ee18fded69e32216a7f52833f1138caa7f90307c236500c3aa1a6cd082097fc3e28609b8d33514f16d6687bed504aee82775a41e4b125eba9ca544dc375c29c19d20f10900301eea8e68be3b3d7");
const chain_test_rsa_e = hexConst("010001");
const chain_test_rsa_d = hexConst("12036e6cb0b76002de1b49770e01632f4ccbdbaf2fe2266be6ac97f97fb4f0bc80c04adc8f42bbf284fa6a52ca50913da1e4939abec0be2fe3d3eb0050993662716b410bf656c84754aa7f00c8bdba93735340805d2ab8b8cceb35ffd50310e833eff65ff7a630714b08c876125eea0b710153e84a6667865978fefe51da1ec7d7cfc1afb96c4223b187b49cb6305be1a2eccbb8d07ed016bc257908bec7daf322658bda2dc4abd3671ffa6919da8b86ecbefa2658c3c01bacee5c9cff02f1cbac3f05feb2d68c61ef9a5427f73edb1949f776350bd63475c3cb78c5605b094d5043756e894bf538e811903212b6990a75153e261a36630657f8b91dfdadf45d");
const chain_test_rsa_p = hexConst("e03b0d999233d320ae90bb8fa28ba36ad8c0bedeea9bc1218f65f1aac329e0c921a6aaf62a56719c6bd01c33ff119a657005eb500c33aa52e6d2fb6a55723f6fc2076fb8d30df12801dca523515992cad6ad628d180947e846fa3a3a3046c84c25266faf9079f44022bd4b5600d98a8ee4cbda9fddf01e9efb5d7eb62f7edb5d");
const chain_test_rsa_q = hexConst("b7832256daec3eb9c325d1cdd4b3e2036723d02daa96e029518640c40d87bde9df147bd8488031df85caa449ec42735cbfd1125f843027352d396e7e9024b76335a98148a553d31872f32275582897d1e8f2b1460f1a3bd0375fe8a884f2372e716d51a4b71043c9730d74a7263476362d502496c19f6a45a615517b4a7f4cc3");
const chain_test_rsa_dp = hexConst("1a1be62e7e8e9843d2efb95735370b3532bde6bbb017a8ba4ea731279007fd4b8e2688fb96dc6fe825c99aaf174126782f3e113345e87229ab04e00f769991f762615949ed114f86380948153fb0ad5dfef73b65706a0c3c689f544e5836b5b5e01184a9ada9f59dce2dba6aee386660d31545849de40abcba4a1da9fb07cb65");
const chain_test_rsa_dq = hexConst("90779aabf7b2adfabda763507fd790e10eec41b201aebf0fa80f61a335e79bd9a675d0bd46ee2cd503d5b09a457556ae388f95c03e274e666d90ddeca2fb54a7b49219a620092a90ffc56a66289de44f2aed0c23d435d9caa41d4be286aecc4432a555f5aeec0e016422bea7ebcab71915791724db8eed31a17afce76b9165d3");
const chain_test_rsa_qinv = hexConst("c4cae178938b60717e4d0484c144c548b275f87dd2723cfe1b6a5ba68305b154d1c86c894716bd9d5b4f974f51ad98942fa26005188896931a73206b778b946f96c6443f67bbb1861ce8a2e9d438befdb6cb1b7f413edc5b155b436660320f3cd26b0f65a9f586f957257b81e7c410856150abf4bb8f691beabecf7e428a2f8c");

fn chainTestRsaKey() rsa_sign.PrivateKey {
    return .{
        .n = &chain_test_rsa_n,
        .e = &chain_test_rsa_e,
        .d = &chain_test_rsa_d,
        .p = &chain_test_rsa_p,
        .q = &chain_test_rsa_q,
        .dp = &chain_test_rsa_dp,
        .dq = &chain_test_rsa_dq,
        .qinv = &chain_test_rsa_qinv,
    };
}

const RsaSigVariant = struct { sig_sha384: bool = false, sig_pss: bool = false };

fn buildRsaChainCert(out: []u8, serial: u8, variant: RsaSigVariant) ![]const u8 {
    return x509_selfsign.buildSelfSignedRsa(out, .{
        .common_name = "onyx tls13 rsa test",
        .not_before = 1_704_067_200, // 2024-01-01
        .not_after = 1_924_991_999, // 2030-12-31
        .serial = &.{ 0x53, serial },
        .public_modulus = &chain_test_rsa_n,
        .public_exponent = &chain_test_rsa_e,
        .private_key = chainTestRsaKey(),
        .dns_names = &.{chain_test_san},
        .sig_sha384 = variant.sig_sha384,
        .sig_pss = variant.sig_pss,
    });
}

test "TLS 1.3 client anchors an RSA PKCS#1 SHA-256 self-signed chain (regression)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x01, .{});
    try verifySelfAnchored(der);
}

test "TLS 1.3 client anchors an RSA PKCS#1 SHA-384 self-signed chain (sha384WithRSA)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x02, .{ .sig_sha384 = true });
    try verifySelfAnchored(der);
}

test "TLS 1.3 client anchors an RSASSA-PSS self-signed chain (params threaded through)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x03, .{ .sig_pss = true });
    try verifySelfAnchored(der);
}

test "TLS 1.3 client anchors an ECDSA P-256 SHA-256 self-signed chain (regression)" {
    const kp = try ecdsa_p256.KeyPair.generateDeterministic(@as([ecdsa_p256.KeyPair.seed_length]u8, @splat(0x2c)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP256(&buf, .{
        .common_name = "onyx tls13 ecdsa test",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x53, 0x04 },
        .key_pair = kp,
        .dns_names = &.{chain_test_san},
    });
    try verifySelfAnchored(der);
}

test "TLS 1.3 client anchors an ECDSA P-384 SHA-384 self-signed chain (ecdsa-with-SHA384)" {
    const kp = try EcdsaP384.KeyPair.generateDeterministic(@as([EcdsaP384.KeyPair.seed_length]u8, @splat(0x2e)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP384(&buf, .{
        .common_name = "onyx tls13 p384 test",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x53, 0x06 },
        .key_pair = kp,
        .dns_names = &.{chain_test_san},
    });
    try verifySelfAnchored(der);
}

test "TLS 1.3 client anchors an Ed25519 self-signed chain (regression)" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x2d)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&buf, .{
        .common_name = "onyx tls13 ed25519 test",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x53, 0x05 },
        .key_pair = kp,
        .dns_names = &.{chain_test_san},
    });
    try verifySelfAnchored(der);
}

test "TLS 1.3 client rejects a self-signed chain whose signature byte was flipped (isolates the sig check)" {
    var buf: [2048]u8 = undefined;
    const der = try buildRsaChainCert(&buf, 0x0a, .{ .sig_pss = true });
    // Baseline: the untampered RSASSA-PSS self-signature anchors.
    try verifySelfAnchored(der);

    // Flip one bit in the trailing signature BIT STRING; every other byte — name,
    // validity, SPKI, DN linkage — is byte-identical, so only the signature check
    // can be what now rejects. The anchor loop's `catch continue` turns the failed
    // verify into UnknownCa (no other anchor to try).
    var tampered: [2048]u8 = undefined;
    @memcpy(tampered[0..der.len], der);
    tampered[der.len - 1] ^= 0x01;
    try std.testing.expectError(error.UnknownCa, verifySelfAnchored(tampered[0..der.len]));
}

test "TLS 1.3 client rejects a P-384 self-signed chain whose signature byte was flipped" {
    const kp = try EcdsaP384.KeyPair.generateDeterministic(@as([EcdsaP384.KeyPair.seed_length]u8, @splat(0x2e)));
    var buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSignedEcdsaP384(&buf, .{
        .common_name = "onyx tls13 p384 tamper",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x53, 0x07 },
        .key_pair = kp,
        .dns_names = &.{chain_test_san},
    });
    try verifySelfAnchored(der);

    var tampered: [1024]u8 = undefined;
    @memcpy(tampered[0..der.len], der);
    tampered[der.len - 1] ^= 0x01;
    try std.testing.expectError(error.UnknownCa, verifySelfAnchored(tampered[0..der.len]));
}

// F1 control: the TLS 1.3 client already enforces NameConstraints (unchanged
// by the F1 refactor into x509_verify.zig). This is the exact chain the
// hardened TLS 1.2 client's mirror test in tls12_client.zig proves it now
// ALSO rejects — before F1 it silently accepted this cross-domain leaf.
test "TLS 1.3 client rejects a name-constrained CA's cross-domain leaf (F1 control)" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const ca_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xc1)));
    const leaf_kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xc2)));

    var ca_buf: [1024]u8 = undefined;
    const ca_der = try x509_verify.mintEd25519CertExt(
        &ca_buf,
        "Onyx Name-Constrained CA",
        "Onyx Name-Constrained CA",
        ca_kp.public_key.toBytes(),
        ca_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .is_ca = true, .permitted_dns = &.{".corp.example"} },
    );

    var leaf_buf: [1024]u8 = undefined;
    const leaf_der = try x509_verify.mintEd25519CertExt(
        &leaf_buf,
        "Onyx Name-Constrained CA",
        "login.victim-bank.com",
        leaf_kp.public_key.toBytes(),
        ca_kp,
        1_704_067_200,
        1_924_991_999,
        .{ .dns_names = &.{"login.victim-bank.com"} },
    );

    const chain = [_][]const u8{ leaf_der, ca_der };
    const anchors = [_][]const u8{ca_der};
    try std.testing.expectError(
        error.BadCertificate,
        verifyChainToTrustAnchors(&chain, &anchors, "login.victim-bank.com", null),
    );
}

// ---------------------------------------------------------------------------
// Adversarial corpus (`zig build test-exploit`).
//
// The client half is what reaches out to an ACME CA and to mail relays, so its
// hostile peer is a malicious (or MITM-substituted) *server*. A stall here is a
// certificate renewal that never completes, so the framing layer must fail
// closed rather than wait forever.
// ---------------------------------------------------------------------------

/// Hand-frame one plaintext record: [type][0x0303][len16][body].
fn exploitPlainRecord(out: []u8, typ: u8, body: []const u8) []const u8 {
    out[0] = typ;
    std.mem.writeInt(u16, out[1..3], 0x0303, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(body.len), .big);
    @memcpy(out[5..][0..body.len], body);
    return out[0 .. 5 + body.len];
}

test "exploit: a hostile server cannot stall the client with a change_cipher_spec flood" {
    // Unbounded middlebox-compatibility CCS records would let a server keep an
    // outbound handshake alive indefinitely without ever answering it.
    const alloc = std.testing.allocator;
    var client = try Client.init(alloc, .{ .server_name = "stall.test", .trust_anchors = &.{} });
    defer client.deinit();
    const ch = try client.start();
    defer alloc.free(ch);

    var rec_buf: [16]u8 = undefined;
    const ccs = exploitPlainRecord(&rec_buf, 20, &.{0x01});

    var sent: usize = 0;
    while (sent < tls_record.max_change_cipher_spec_records) : (sent += 1) {
        _ = client.feed(ccs) catch |err| {
            std.debug.print("legitimate CCS {d} rejected: {s}\n", .{ sent, @errorName(err) });
            return err;
        };
    }
    try std.testing.expectError(error.BadRecord, client.feed(ccs));
}

test "exploit: a hostile server cannot stall the client with unknown record types" {
    // The same "invalid vs incomplete" conflation on the client: an unrecognized
    // outer content type must terminate, not accumulate in `recv_buf` forever.
    const alloc = std.testing.allocator;
    for ([_]u8{ 0, 1, 24, 99, 0xFF }) |bad_type| {
        var client = try Client.init(alloc, .{ .server_name = "stall.test", .trust_anchors = &.{} });
        defer client.deinit();
        const ch = try client.start();
        defer alloc.free(ch);

        var rec_buf: [64]u8 = undefined;
        const rec = exploitPlainRecord(&rec_buf, bad_type, "payload");
        try std.testing.expectError(error.BadRecord, client.feed(rec));
    }
}

test "exploit: a server record declaring more than 2^14+256 is rejected by the client" {
    const alloc = std.testing.allocator;
    var client = try Client.init(alloc, .{ .server_name = "stall.test", .trust_anchors = &.{} });
    defer client.deinit();
    const ch = try client.start();
    defer alloc.free(ch);

    const header = [_]u8{ 22, 0x03, 0x03, 0xFF, 0xFF };
    try std.testing.expectError(error.BadRecord, client.feed(&header));
}

test "exploit: a change_cipher_spec with an illegal body is rejected by the client" {
    const alloc = std.testing.allocator;
    var big_body: [512]u8 = @splat(0x01);
    const cases: []const []const u8 = &.{ &.{}, &.{0x00}, &.{0x02}, &.{ 0x01, 0x01 }, &big_body };
    for (cases) |body| {
        var client = try Client.init(alloc, .{ .server_name = "stall.test", .trust_anchors = &.{} });
        defer client.deinit();
        const ch = try client.start();
        defer alloc.free(ch);

        var rec_buf: [1024]u8 = undefined;
        const rec = exploitPlainRecord(&rec_buf, 20, body);
        try std.testing.expectError(error.BadRecord, client.feed(rec));
    }
}
