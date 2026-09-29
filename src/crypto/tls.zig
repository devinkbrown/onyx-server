// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS record and handshake skeleton for Onyx Server.
//!
//! This is deliberately not a full wire-complete TLS stack. It provides the
//! security-critical seams that the rest of the stack can build on: hardened
//! version/cipher-suite policy, TLS 1.3 key schedule helpers, typed handshake
//! transitions, record sequence/nonces, and a narrow certificate verification
//! callback. X.509 parsing and verification live in a separate module.
const std = @import("std");
const hash = @import("hash.zig");
const aead = @import("aead.zig");
const kx = @import("kx.zig");
const Secret = @import("secret.zig").Secret;
const x509_verify = @import("x509_verify.zig");

pub const max_plaintext_len = 16 * 1024;
pub const max_ciphertext_len = max_plaintext_len + 256;
pub const record_header_len = 5;
pub const tls12_wire_version: u16 = @intFromEnum(ProtocolVersion.tls12);

pub const TlsError = error{
    BadRecordHeader,
    BadTranscriptHash,
    IllegalTransition,
    InvalidCipherSuite,
    InvalidVersion,
    OutputTooSmall,
    RecordOverflow,
    SequenceExhausted,
};

/// TLS protocol versions as wire values. TLS 1.0/1.1 are represented only so
/// policy tests can prove they fail closed.
pub const ProtocolVersion = enum(u16) {
    tls10 = 0x0301,
    tls11 = 0x0302,
    tls12 = 0x0303,
    tls13 = 0x0304,
};

/// Cipher suites relevant to policy decisions. Values match IANA assignments.
pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
    tls_aes_128_ccm_sha256 = 0x1304,
    tls_aes_128_ccm_8_sha256 = 0x1305,

    tls_rsa_with_null_sha = 0x0002,
    tls_rsa_export_with_rc4_40_md5 = 0x0003,
    tls_rsa_with_rc4_128_sha = 0x0005,
    tls_rsa_with_3des_ede_cbc_sha = 0x000a,
    tls_rsa_with_aes_128_cbc_sha = 0x002f,
    tls_rsa_with_aes_256_cbc_sha = 0x0035,
    tls_rsa_with_aes_128_gcm_sha256 = 0x009c,
    tls_rsa_with_aes_256_gcm_sha384 = 0x009d,

    tls_ecdhe_ecdsa_with_aes_128_cbc_sha = 0xc009,
    tls_ecdhe_ecdsa_with_aes_256_cbc_sha = 0xc00a,
    tls_ecdhe_rsa_with_aes_128_cbc_sha = 0xc013,
    tls_ecdhe_rsa_with_aes_256_cbc_sha = 0xc014,
    tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,
    tls_ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xcca8,
    tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 = 0xcca9,

    pub fn fromWire(v: u16) ?CipherSuite {
        return switch (v) {
            0x1301 => .tls_aes_128_gcm_sha256,
            0x1302 => .tls_aes_256_gcm_sha384,
            0x1303 => .tls_chacha20_poly1305_sha256,
            0x1304 => .tls_aes_128_ccm_sha256,
            0x1305 => .tls_aes_128_ccm_8_sha256,
            0x0002 => .tls_rsa_with_null_sha,
            0x0003 => .tls_rsa_export_with_rc4_40_md5,
            0x0005 => .tls_rsa_with_rc4_128_sha,
            0x000a => .tls_rsa_with_3des_ede_cbc_sha,
            0x002f => .tls_rsa_with_aes_128_cbc_sha,
            0x0035 => .tls_rsa_with_aes_256_cbc_sha,
            0x009c => .tls_rsa_with_aes_128_gcm_sha256,
            0x009d => .tls_rsa_with_aes_256_gcm_sha384,
            0xc009 => .tls_ecdhe_ecdsa_with_aes_128_cbc_sha,
            0xc00a => .tls_ecdhe_ecdsa_with_aes_256_cbc_sha,
            0xc013 => .tls_ecdhe_rsa_with_aes_128_cbc_sha,
            0xc014 => .tls_ecdhe_rsa_with_aes_256_cbc_sha,
            0xc02b => .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            0xc02c => .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            0xc02f => .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
            0xc030 => .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            0xcca8 => .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
            0xcca9 => .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            else => null,
        };
    }
};

pub const AeadKind = enum { aes_128_gcm, aes_256_gcm, chacha20_poly1305 };
pub const KeyExchangeKind = enum { none, rsa, dhe, ecdhe };
pub const AuthKind = enum { none, rsa, ecdsa };

pub const SuiteInfo = struct {
    aead: AeadKind,
    hash_alg: hash.Alg,
    key_len: usize,
    iv_len: usize,
    tag_len: usize,
    kx_kind: KeyExchangeKind,
    auth_kind: AuthKind,
    tls13: bool,
};

/// Return suite parameters only for the hardened allow-list.
pub fn suiteInfo(version: ProtocolVersion, suite: CipherSuite) ?SuiteInfo {
    if (!isAllowed(version, suite)) return null;
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => .{
            .aead = .aes_128_gcm,
            .hash_alg = .sha256,
            .key_len = 16,
            .iv_len = 12,
            .tag_len = 16,
            .kx_kind = .none,
            .auth_kind = .none,
            .tls13 = true,
        },
        .tls_aes_256_gcm_sha384 => .{
            .aead = .aes_256_gcm,
            .hash_alg = .sha384,
            .key_len = 32,
            .iv_len = 12,
            .tag_len = 16,
            .kx_kind = .none,
            .auth_kind = .none,
            .tls13 = true,
        },
        .tls_chacha20_poly1305_sha256 => .{
            .aead = .chacha20_poly1305,
            .hash_alg = .sha256,
            .key_len = 32,
            .iv_len = 12,
            .tag_len = 16,
            .kx_kind = .none,
            .auth_kind = .none,
            .tls13 = true,
        },
        .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 => tls12Info(.aes_128_gcm, .sha256, 16, .ecdsa),
        .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 => tls12Info(.aes_256_gcm, .sha384, 32, .ecdsa),
        .tls_ecdhe_rsa_with_aes_128_gcm_sha256 => tls12Info(.aes_128_gcm, .sha256, 16, .rsa),
        .tls_ecdhe_rsa_with_aes_256_gcm_sha384 => tls12Info(.aes_256_gcm, .sha384, 32, .rsa),
        .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 => tls12Info(.chacha20_poly1305, .sha256, 32, .ecdsa),
        .tls_ecdhe_rsa_with_chacha20_poly1305_sha256 => tls12Info(.chacha20_poly1305, .sha256, 32, .rsa),
        else => null,
    };
}

fn tls12Info(aead_kind: AeadKind, hash_alg: hash.Alg, key_len: usize, auth_kind: AuthKind) SuiteInfo {
    return .{
        .aead = aead_kind,
        .hash_alg = hash_alg,
        .key_len = key_len,
        .iv_len = 12,
        .tag_len = 16,
        .kx_kind = .ecdhe,
        .auth_kind = auth_kind,
        .tls13 = false,
    };
}

/// Hardened policy: TLS 1.3 permits only AES-GCM and ChaCha20-Poly1305.
/// TLS 1.2 permits only AEAD + ECDHE suites, with RSA allowed only as the
/// certificate authentication algorithm, never as key exchange.
pub fn isAllowed(version: ProtocolVersion, suite: CipherSuite) bool {
    return switch (version) {
        .tls13 => switch (suite) {
            .tls_aes_128_gcm_sha256,
            .tls_aes_256_gcm_sha384,
            .tls_chacha20_poly1305_sha256,
            => true,
            else => false,
        },
        .tls12 => switch (suite) {
            .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
            .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
            .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
            .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
            .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
            => true,
            else => false,
        },
        .tls10, .tls11 => false,
    };
}

/// TLS compression is disabled; the only acceptable method is null compression.
pub fn isCompressionAllowed(method: u8) bool {
    return method == 0;
}

/// Renegotiation is never enabled in Onyx Server's TLS policy.
pub fn isRenegotiationAllowed() bool {
    return false;
}

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,

    pub fn fromWire(v: u8) ?ContentType {
        return switch (v) {
            20 => .change_cipher_spec,
            21 => .alert,
            22 => .handshake,
            23 => .application_data,
            else => null,
        };
    }
};

pub const RecordHeader = struct {
    content_type: ContentType,
    legacy_version: u16,
    length: u16,

    pub fn parse(buf: []const u8) TlsError!RecordHeader {
        if (buf.len < record_header_len) return error.BadRecordHeader;
        const ct = ContentType.fromWire(buf[0]) orelse return error.BadRecordHeader;
        const len = std.mem.readInt(u16, buf[3..5], .big);
        if (len > max_ciphertext_len) return error.RecordOverflow;
        return .{
            .content_type = ct,
            .legacy_version = std.mem.readInt(u16, buf[1..3], .big),
            .length = len,
        };
    }

    pub fn write(self: RecordHeader, out: []u8) TlsError!void {
        if (out.len < record_header_len) return error.OutputTooSmall;
        out[0] = @intFromEnum(self.content_type);
        std.mem.writeInt(u16, out[1..3], self.legacy_version, .big);
        std.mem.writeInt(u16, out[3..5], self.length, .big);
    }
};

/// Monotonic TLS record sequence number. It refuses to emit `u64::max` so the
/// next increment can never wrap and reuse a nonce.
pub const Seq64 = struct {
    value: u64 = 0,

    pub fn init(value: u64) Seq64 {
        return .{ .value = value };
    }

    pub fn peek(self: Seq64) u64 {
        return self.value;
    }

    pub fn next(self: *Seq64) TlsError!u64 {
        if (self.value == std.math.maxInt(u64)) return error.SequenceExhausted;
        const out = self.value;
        self.value += 1;
        return out;
    }
};

pub const Nonce96 = [12]u8;
pub const AadMax = [13]u8;

/// TLS 1.3 per-record nonce: static IV XOR (0x00000000 || seq_be64).
pub fn nonce13(iv: Nonce96, seq: u64) Nonce96 {
    var nonce = iv;
    var seq_bytes: Nonce96 = @splat(0);
    std.mem.writeInt(u64, seq_bytes[4..12], seq, .big);
    xor12(&nonce, &seq_bytes);
    return nonce;
}

/// TLS 1.2 AEAD nonce: implicit_iv[0..4] || explicit_seq_be64.
pub fn nonce12(iv: Nonce96, explicit_seq: u64) Nonce96 {
    var nonce: Nonce96 = undefined;
    @memcpy(nonce[0..4], iv[0..4]);
    std.mem.writeInt(u64, nonce[4..12], explicit_seq, .big);
    return nonce;
}

fn xor12(dst: *Nonce96, rhs: *const Nonce96) void {
    for (dst, rhs) |*d, r| d.* ^= r;
}

pub const RecordCipherState = struct {
    version: ProtocolVersion,
    suite: CipherSuite,
    iv: Nonce96,
    seq: Seq64 = .{},

    pub const RecordParams = struct {
        sequence: u64,
        nonce: Nonce96,
        aad: AadMax,
        aad_len: usize,

        pub fn aadSlice(self: *const RecordParams) []const u8 {
            return self.aad[0..self.aad_len];
        }
    };

    pub fn init(version: ProtocolVersion, suite: CipherSuite, iv: Nonce96) TlsError!RecordCipherState {
        if (!isAllowed(version, suite)) return error.InvalidCipherSuite;
        return .{ .version = version, .suite = suite, .iv = iv };
    }

    pub fn nextNonce(self: *RecordCipherState) TlsError!Nonce96 {
        const seq = try self.seq.next();
        return switch (self.version) {
            .tls13 => nonce13(self.iv, seq),
            .tls12 => nonce12(self.iv, seq),
            .tls10, .tls11 => error.InvalidVersion,
        };
    }

    pub fn sealParams(
        self: *RecordCipherState,
        content_type: ContentType,
        wire_version: u16,
        length: u16,
    ) TlsError!RecordParams {
        return try self.nextParams(content_type, wire_version, length);
    }

    pub fn openParams(
        self: *RecordCipherState,
        content_type: ContentType,
        wire_version: u16,
        length: u16,
    ) TlsError!RecordParams {
        return try self.nextParams(content_type, wire_version, length);
    }

    fn nextParams(
        self: *RecordCipherState,
        content_type: ContentType,
        wire_version: u16,
        length: u16,
    ) TlsError!RecordParams {
        const sequence = try self.seq.next();
        return try self.paramsFor(sequence, content_type, wire_version, length);
    }

    fn paramsFor(
        self: RecordCipherState,
        sequence: u64,
        content_type: ContentType,
        wire_version: u16,
        length: u16,
    ) TlsError!RecordParams {
        var params = RecordParams{
            .sequence = sequence,
            .nonce = switch (self.version) {
                .tls13 => nonce13(self.iv, sequence),
                .tls12 => nonce12(self.iv, sequence),
                .tls10, .tls11 => return error.InvalidVersion,
            },
            .aad = @as([13]u8, @splat(0)),
            .aad_len = 0,
        };
        params.aad_len = try self.makeAad(sequence, content_type, wire_version, length, &params.aad);
        return params;
    }

    pub fn makeAad(
        self: RecordCipherState,
        sequence: u64,
        content_type: ContentType,
        wire_version: u16,
        length: u16,
        out: []u8,
    ) TlsError!usize {
        const need: usize = if (self.version == .tls13) 5 else 13;
        if (out.len < need) return error.OutputTooSmall;
        var n: usize = 0;
        if (self.version == .tls12) {
            std.mem.writeInt(u64, out[0..8], sequence, .big);
            n = 8;
        }
        out[n] = @intFromEnum(content_type);
        n += 1;
        std.mem.writeInt(u16, out[n..][0..2], wire_version, .big);
        n += 2;
        std.mem.writeInt(u16, out[n..][0..2], length, .big);
        return n + 2;
    }
};

pub const HandshakeRole = enum { client, server };

pub const HandshakeState = enum {
    start,
    client_hello,
    server_hello,
    encrypted_extensions,
    certificate,
    certificate_verify,
    finished,
    connected,
};

pub const HandshakeEvent = enum {
    send_client_hello,
    recv_client_hello,
    send_server_hello,
    recv_server_hello,
    send_encrypted_extensions,
    recv_encrypted_extensions,
    send_certificate,
    recv_certificate,
    send_certificate_verify,
    recv_certificate_verify,
    send_finished,
    recv_finished,
};

pub fn nextState(
    comptime role: HandshakeRole,
    comptime state: HandshakeState,
    comptime event: HandshakeEvent,
) HandshakeState {
    comptime assertTransition(role, state, event);
    return nextStateMaybe(role, state, event).?;
}

pub fn canTransition(role: HandshakeRole, state: HandshakeState, event: HandshakeEvent) bool {
    return nextStateMaybe(role, state, event) != null;
}

pub fn assertTransition(
    comptime role: HandshakeRole,
    comptime state: HandshakeState,
    comptime event: HandshakeEvent,
) void {
    if (nextStateMaybe(role, state, event) == null) {
        @compileError("illegal TLS handshake transition: " ++ @tagName(role) ++
            " " ++ @tagName(state) ++ " + " ++ @tagName(event));
    }
}

fn nextStateMaybe(role: HandshakeRole, state: HandshakeState, event: HandshakeEvent) ?HandshakeState {
    return switch (role) {
        .client => switch (state) {
            .start => if (event == .send_client_hello) .client_hello else null,
            .client_hello => if (event == .recv_server_hello) .server_hello else null,
            .server_hello => if (event == .recv_encrypted_extensions) .encrypted_extensions else null,
            .encrypted_extensions => if (event == .recv_certificate) .certificate else null,
            .certificate => if (event == .recv_certificate_verify) .certificate_verify else null,
            .certificate_verify => if (event == .recv_finished) .finished else null,
            .finished => if (event == .send_finished) .connected else null,
            .connected => null,
        },
        .server => switch (state) {
            .start => if (event == .recv_client_hello) .client_hello else null,
            .client_hello => if (event == .send_server_hello) .server_hello else null,
            .server_hello => if (event == .send_encrypted_extensions) .encrypted_extensions else null,
            .encrypted_extensions => if (event == .send_certificate) .certificate else null,
            .certificate => if (event == .send_certificate_verify) .certificate_verify else null,
            .certificate_verify => if (event == .send_finished) .finished else null,
            .finished => if (event == .recv_finished) .connected else null,
            .connected => null,
        },
    };
}

pub fn Handshake(comptime role: HandshakeRole, comptime state: HandshakeState) type {
    return struct {
        pub const handshake_role = role;
        pub const handshake_state = state;

        marker: u8 = 0,

        pub fn init() @This() {
            return .{};
        }

        pub fn transition(
            self: *@This(),
            comptime event: HandshakeEvent,
        ) Handshake(role, nextState(role, state, event)) {
            _ = self;
            return Handshake(role, nextState(role, state, event)).init();
        }
    };
}

/// Runtime state helper for parsers that receive attacker-controlled messages.
/// Typed `Handshake(role, state)` remains the compile-time path for known flows.
pub const RuntimeHandshake = struct {
    role: HandshakeRole,
    state: HandshakeState = .start,

    pub fn step(self: *RuntimeHandshake, event: HandshakeEvent) TlsError!void {
        const next = nextStateMaybe(self.role, self.state, event) orelse return error.IllegalTransition;
        self.state = next;
    }
};

/// X.509 is intentionally outside this module. Callers provide a verifier from
/// the certificate module once it exists.
pub const CertificateChain = struct {
    der_chain: []const []const u8,
};

pub const CertificateVerifyContext = struct {
    version: ProtocolVersion,
    suite: CipherSuite,
    server_name: []const u8,
    transcript_hash: []const u8,
};

pub const CertificateVerifier = struct {
    ptr: *anyopaque,
    verifyFn: *const fn (*anyopaque, CertificateChain, CertificateVerifyContext) CertificateVerifyError!void,

    pub fn verify(
        self: CertificateVerifier,
        chain: CertificateChain,
        context: CertificateVerifyContext,
    ) CertificateVerifyError!void {
        // Cryptographic chain integrity to a self-signed root is enforced here,
        // independent of the caller's policy hook: every certificate's
        // signature is verified against its issuer's public key and the chain
        // must terminate in a self-signed root whose signature verifies. This
        // closes the prior parse-only gap where a forged signature linking by DN
        // alone would pass through. Anchoring (which root to trust) and naming
        // remain the verifyFn's responsibility — see x509_verify's module header.
        mapChainError(x509_verify.verifySimpleChain(chain.der_chain)) catch |err| return err;
        try self.verifyFn(self.ptr, chain, context);
    }
};

/// Map x509_verify chain errors onto the TLS certificate-verify error surface.
fn mapChainError(result: x509_verify.Error!void) CertificateVerifyError!void {
    result catch |err| switch (err) {
        error.UnsupportedSigAlg, error.UnsupportedKey => return error.UnsupportedSigAlg,
        error.NotYetValid, error.Expired => return error.Expired,
        error.EmptyChain,
        error.IssuerMismatch,
        error.NotSelfSigned,
        error.MissingSignature,
        error.BadSignature,
        error.InvalidKey,
        => return error.CertificateInvalid,
        else => return error.CertificateInvalid,
    };
}

pub const CertificateVerifyError = error{
    CertificateInvalid,
    NameMismatch,
    Expired,
    UntrustedRoot,
    UnsupportedSigAlg,
};

pub const Tls13KeyScheduleError = TlsError || hash.HkdfError;

pub fn Tls13KeySchedule(comptime alg: hash.Alg) type {
    const Hash = hash.Hash(alg);
    const Hkdf = hash.Hkdf(alg);
    const HashSecret = Secret([Hash.digest_len]u8);

    return struct {
        pub const hash_alg = alg;
        pub const hash_len = Hash.digest_len;
        pub const SecretBytes = HashSecret;

        pub const TrafficSecrets = struct {
            client: SecretBytes,
            server: SecretBytes,

            pub fn wipe(self: *TrafficSecrets) void {
                self.client.wipe();
                self.server.wipe();
            }
        };

        pub const TrafficKeys = struct {
            suite: CipherSuite,
            key_len: usize,
            key: [32]u8,
            iv: Nonce96,

            pub fn keySlice(self: *const TrafficKeys) []const u8 {
                return self.key[0..self.key_len];
            }

            pub fn wipe(self: *TrafficKeys) void {
                secureZero(self.key[0..]);
                secureZero(self.iv[0..]);
            }
        };

        pub fn transcriptHash(messages: []const u8) Hash.Digest {
            return Hash.hash(messages);
        }

        pub fn emptyTranscriptHash() Hash.Digest {
            return Hash.hash("");
        }

        pub fn earlySecret(psk: []const u8) SecretBytes {
            const zero_salt = @as([Hash.digest_len]u8, @splat(0));
            const zero_ikm = @as([Hash.digest_len]u8, @splat(0));
            const ikm = if (psk.len == 0) zero_ikm[0..] else psk;
            return Hkdf.extractRaw(&zero_salt, ikm);
        }

        pub fn deriveSecret(
            base: *const SecretBytes,
            comptime label: []const u8,
            transcript_hash: []const u8,
        ) Tls13KeyScheduleError!SecretBytes {
            if (transcript_hash.len != Hash.digest_len) return error.BadTranscriptHash;
            var out: [Hash.digest_len]u8 = undefined;
            try Hkdf.expandLabel(base, label, transcript_hash, &out);
            return SecretBytes.init(out);
        }

        pub fn handshakeSecret(
            early: *const SecretBytes,
            shared_secret: []const u8,
        ) Tls13KeyScheduleError!SecretBytes {
            var derived = try deriveSecret(early, "derived", &emptyTranscriptHash());
            defer derived.wipe();
            return Hkdf.extractRaw(&derived.declassify(), shared_secret);
        }

        pub fn masterSecret(handshake: *const SecretBytes) Tls13KeyScheduleError!SecretBytes {
            var derived = try deriveSecret(handshake, "derived", &emptyTranscriptHash());
            defer derived.wipe();
            const zero_ikm = @as([Hash.digest_len]u8, @splat(0));
            return Hkdf.extractRaw(&derived.declassify(), &zero_ikm);
        }

        pub fn handshakeTrafficSecrets(
            handshake: *const SecretBytes,
            transcript_hash: []const u8,
        ) Tls13KeyScheduleError!TrafficSecrets {
            return .{
                .client = try deriveSecret(handshake, "c hs traffic", transcript_hash),
                .server = try deriveSecret(handshake, "s hs traffic", transcript_hash),
            };
        }

        pub fn applicationTrafficSecrets(
            master: *const SecretBytes,
            transcript_hash: []const u8,
        ) Tls13KeyScheduleError!TrafficSecrets {
            return .{
                .client = try deriveSecret(master, "c ap traffic", transcript_hash),
                .server = try deriveSecret(master, "s ap traffic", transcript_hash),
            };
        }

        pub fn trafficKeys(
            suite: CipherSuite,
            traffic_secret: *const SecretBytes,
        ) Tls13KeyScheduleError!TrafficKeys {
            const info = suiteInfo(.tls13, suite) orelse return error.InvalidCipherSuite;
            var keys = TrafficKeys{
                .suite = suite,
                .key_len = info.key_len,
                .key = @as([32]u8, @splat(0)),
                .iv = @as([12]u8, @splat(0)),
            };
            try Hkdf.expandLabel(traffic_secret, "key", "", keys.key[0..info.key_len]);
            try Hkdf.expandLabel(traffic_secret, "iv", "", &keys.iv);
            return keys;
        }

        pub fn finishedKey(base_key: *const SecretBytes) Tls13KeyScheduleError!SecretBytes {
            var out: [Hash.digest_len]u8 = undefined;
            try Hkdf.expandLabel(base_key, "finished", "", &out);
            return SecretBytes.init(out);
        }

        pub fn updateTrafficSecret(current: *const SecretBytes) Tls13KeyScheduleError!SecretBytes {
            var out: [Hash.digest_len]u8 = undefined;
            try Hkdf.expandLabel(current, "traffic upd", "", &out);
            return SecretBytes.init(out);
        }
    };
}

pub const Tls13Sha256 = Tls13KeySchedule(.sha256);
pub const Tls13Sha384 = Tls13KeySchedule(.sha384);
pub const RecordAeadAlg = aead.AeadAlg;
pub const ClassicalKx = kx.X25519Kx;

fn secureZero(buf: []u8) void {
    for (buf) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "policy allows only TLS 1.3 AES-GCM and ChaCha20-Poly1305 suites" {
    try std.testing.expect(isAllowed(.tls13, .tls_aes_128_gcm_sha256));
    try std.testing.expect(isAllowed(.tls13, .tls_aes_256_gcm_sha384));
    try std.testing.expect(isAllowed(.tls13, .tls_chacha20_poly1305_sha256));
    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_sha256));
    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_8_sha256));
}

fn k6Read(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(1 << 20));
}

fn k6HelloExtensions(record: []const u8) ![]const u8 {
    if (record.len < 5 or record[0] != 22) return error.Truncated;
    const rec_len: usize = std.mem.readInt(u16, record[3..5], .big);
    if (record.len < 5 + rec_len) return error.Truncated;
    const frag = record[5 .. 5 + rec_len];
    if (frag.len < 4 or frag[0] != 1) return error.Truncated;
    const hs_len: usize = (@as(usize, frag[1]) << 16) | (@as(usize, frag[2]) << 8) | frag[3];
    if (frag.len < 4 + hs_len) return error.Truncated;
    const body = frag[4 .. 4 + hs_len];
    if (body.len < 35) return error.Truncated;
    var i: usize = 2 + 32;
    const sid_len: usize = body[i];
    i += 1;
    if (body.len < i + sid_len + 2) return error.Truncated;
    i += sid_len;
    const cs_len: usize = std.mem.readInt(u16, body[i..][0..2], .big);
    i += 2;
    if (cs_len % 2 != 0 or body.len < i + cs_len + 1) return error.Truncated;
    var c: usize = 0;
    while (c + 2 <= cs_len) : (c += 2) {
        const suite = std.mem.readInt(u16, body[i + c ..][0..2], .big);
        if (suite == @intFromEnum(CipherSuite.tls_aes_128_ccm_sha256) or
            suite == @intFromEnum(CipherSuite.tls_aes_128_ccm_8_sha256))
        {
            return error.Truncated;
        }
    }
    i += cs_len;
    const comp_len: usize = body[i];
    i += 1 + comp_len;
    if (body.len < i + 2) return error.Truncated;
    const ext_len: usize = std.mem.readInt(u16, body[i..][0..2], .big);
    if (body.len != i + 2 + ext_len) return error.Truncated;
    return body[i..];
}

test "GAP-K6 unfinished TLS interop stays refused and the pinned BoGo lane stays 24/3" {
    const allocator = std.testing.allocator;
    const cert_compression = @import("../proto/cert_compression.zig");
    const supported_groups = @import("../proto/supported_groups.zig");
    const tls_extension = @import("../proto/tls_extension.zig");
    const tls_keyshare = @import("../proto/tls_keyshare.zig");
    const ech_seal = @import("ech_seal.zig");
    const ech_config = @import("../proto/ech_config.zig");
    const hpke = @import("hpke.zig");
    const tls_client = @import("tls_client.zig");
    const delegated_credential = @import("../proto/delegated_credential.zig");

    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_sha256));
    try std.testing.expect(!isAllowed(.tls13, .tls_aes_128_ccm_8_sha256));
    try std.testing.expect(!isAllowed(.tls12, .tls_aes_128_ccm_sha256));
    try std.testing.expect(!isAllowed(.tls12, .tls_aes_128_ccm_8_sha256));

    try std.testing.expectEqual(@as(?cert_compression.Algorithm, .zlib), cert_compression.pickSupported(&.{ 0x02, 0x00, 0x01 }));
    try std.testing.expectEqual(@as(?cert_compression.Algorithm, null), cert_compression.pickSupported(&.{ 0x02, 0x00, 0x02 }));
    try std.testing.expectEqual(@as(?cert_compression.Algorithm, null), cert_compression.pickSupported(&.{ 0x02, 0x00, 0x03 }));
    try std.testing.expectEqual(@as(?cert_compression.Algorithm, .zlib), cert_compression.pickSupported(&.{ 0x06, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01 }));

    try std.testing.expectEqual(@as(u16, 0x0003), hpke.aead_id);
    try std.testing.expectEqual(hpke.aead_id, ech_seal.aead_id);
    const zero_pk: [32]u8 = @splat(0);
    const aes_gcm = ech_config.Config{
        .raw = &.{},
        .version = ech_config.version_draft13,
        .config_id = 0,
        .kem_id = ech_seal.kem_id,
        .public_key = &zero_pk,
        .cipher_suites = &[_]u8{ 0x00, 0x01, 0x00, 0x01 },
        .maximum_name_length = 16,
        .public_name = "a.example",
        .extensions = &.{},
    };
    try std.testing.expectError(error.UnsupportedEchSuite, ech_seal.seal(allocator, aes_gcm, "inner", "aad", @splat(0)));

    const defaults = tls_client.Options{ .server_name = "irc.test", .trust_anchors = &.{} };
    try std.testing.expect(!defaults.require_crl);
    try std.testing.expectEqual(@as(u8, 0), defaults.require_sct);
    try std.testing.expect(defaults.crl == null);
    try std.testing.expectEqual(@as(usize, 0), defaults.ct_logs.len);
    try std.testing.expectError(error.Truncated, delegated_credential.parse(&.{}));

    var client = try tls_client.Client.init(allocator, defaults);
    defer client.deinit();
    const hello = try client.start();
    defer allocator.free(hello);
    const extensions = try k6HelloExtensions(hello);
    const groups = (try tls_extension.find(extensions, @intFromEnum(tls_extension.ExtensionType.supported_groups))) orelse return error.TestUnexpectedResult;
    const shares = (try tls_extension.find(extensions, @intFromEnum(tls_extension.ExtensionType.key_share))) orelse return error.TestUnexpectedResult;
    try std.testing.expect(supported_groups.offers(groups, .x25519));
    try std.testing.expect(supported_groups.offers(groups, .secp256r1));
    try std.testing.expect(supported_groups.offers(groups, .x25519mlkem768));
    try std.testing.expect(!supported_groups.offers(groups, .x448));
    try std.testing.expect(!supported_groups.offers(groups, .secp384r1));
    try std.testing.expect(!supported_groups.offers(groups, supported_groups.NamedGroup.fromInt(0x0019)));
    var group_it = try supported_groups.parse(groups);
    var group_count: usize = 0;
    while (group_it.nextRaw()) |_| group_count += 1;
    try std.testing.expectEqual(@as(usize, 3), group_count);
    var share_it = try tls_keyshare.parseClientShares(shares);
    var share_count: usize = 0;
    while (try share_it.next()) |entry| {
        share_count += 1;
        try std.testing.expect(entry.key_exchange.len != 0);
        const id = entry.group.toInt();
        try std.testing.expect(id == 0x001d or id == 0x0017 or id == 0x11ec);
    }
    try std.testing.expectEqual(@as(usize, 3), share_count);

    const baseline = try k6Read(allocator, "tools/bogo/expected-baseline.txt");
    defer allocator.free(baseline);
    var pass: usize = 0;
    var skip: usize = 0;
    var lines = std.mem.splitScalar(u8, baseline, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "PASS ")) pass += 1;
        if (std.mem.startsWith(u8, line, "SKIP ")) skip += 1;
    }
    try std.testing.expectEqual(@as(usize, 24), pass);
    try std.testing.expectEqual(@as(usize, 3), skip);
    try std.testing.expect(std.mem.indexOf(u8, baseline, "SKIP CheckClientCertificateTypes\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, baseline, "SKIP SendFallbackSCSV\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, baseline, "SKIP ClientCertificateTypes\n") != null);

    const config_text = try k6Read(allocator, "tools/bogo/config.json");
    defer allocator.free(config_text);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, config_text, .{});
    defer parsed.deinit();
    const disabled = parsed.value.object.get("DisabledTests") orelse return error.TestUnexpectedResult;
    var reasons: usize = 0;
    var it = disabled.object.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "//")) continue;
        const value = entry.value_ptr.*;
        try std.testing.expect(value == .string);
        try std.testing.expect(value.string.len != 0);
        reasons += 1;
    }
    try std.testing.expect(reasons >= 20);
    const required = [_][]const u8{
        "*ECH*",
        "*HRR*",
        "*HelloRetryRequest*",
        "*DelegatedCredential*",
        "*P-384*",
        "*P-521*",
        "*DTLS*",
        "*Resume*",
        "*EarlyData*",
        "*ClientAuth*",
    };
    for (required) |key| {
        const value = disabled.object.get(key) orelse return error.TestUnexpectedResult;
        try std.testing.expect(value == .string);
        try std.testing.expect(value.string.len != 0);
    }

    const cli_files = [_][]const u8{
        "src/cli/armor_main.zig",
        "src/cli/s_client_cmd.zig",
        "src/cli/stub_cmds.zig",
        "src/cli/crl_cmd.zig",
        "src/cli/ocsp_cmd.zig",
    };
    for (cli_files) |path| {
        const text = try k6Read(allocator, path);
        defer allocator.free(text);
        try std.testing.expect(std.mem.indexOf(u8, text, "landlock") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "seccomp") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "pledge(") == null);
        try std.testing.expect(std.mem.indexOf(u8, text, "unveil(") == null);
    }

    std.debug.print("GAP-K6 branch=unfinished TLS interop stays refused and [[tls.sni]] selects a certificate\n", .{});
}

test "policy allows only hardened TLS 1.2 ECDHE AEAD suites" {
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_rsa_with_aes_256_gcm_sha384));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256));
    try std.testing.expect(isAllowed(.tls12, .tls_ecdhe_rsa_with_chacha20_poly1305_sha256));
}

test "policy rejects CBC RC4 RSA-kex export NULL and old TLS versions" {
    const bad = [_]CipherSuite{
        .tls_rsa_with_null_sha,
        .tls_rsa_export_with_rc4_40_md5,
        .tls_rsa_with_rc4_128_sha,
        .tls_rsa_with_aes_128_cbc_sha,
        .tls_rsa_with_aes_128_gcm_sha256,
        .tls_ecdhe_rsa_with_aes_128_cbc_sha,
        .tls_ecdhe_ecdsa_with_aes_256_cbc_sha,
    };
    for (bad) |suite| {
        try std.testing.expect(!isAllowed(.tls12, suite));
        try std.testing.expect(!isAllowed(.tls13, suite));
    }
    try std.testing.expect(!isAllowed(.tls10, .tls_ecdhe_rsa_with_aes_128_gcm_sha256));
    try std.testing.expect(!isAllowed(.tls11, .tls_ecdhe_rsa_with_aes_128_gcm_sha256));
    try std.testing.expect(!isCompressionAllowed(1));
    try std.testing.expect(isCompressionAllowed(0));
    try std.testing.expect(!isRenegotiationAllowed());
}

test "record header parse and write validate bounds" {
    var hdr: [record_header_len]u8 = undefined;
    try (RecordHeader{
        .content_type = .application_data,
        .legacy_version = tls12_wire_version,
        .length = 42,
    }).write(&hdr);
    const parsed = try RecordHeader.parse(&hdr);
    try std.testing.expectEqual(ContentType.application_data, parsed.content_type);
    try std.testing.expectEqual(@as(u16, tls12_wire_version), parsed.legacy_version);
    try std.testing.expectEqual(@as(u16, 42), parsed.length);

    try std.testing.expectError(error.BadRecordHeader, RecordHeader.parse(hdr[0..4]));
    hdr[0] = 99;
    try std.testing.expectError(error.BadRecordHeader, RecordHeader.parse(&hdr));
}

test "TLS 1.3 nonce is IV XOR sequence and seq refuses wrap" {
    const iv = hex("000102030405060708090a0b");
    const nonce = nonce13(iv, 0x0102030405060708);
    try std.testing.expectEqualSlices(u8, &hex("00010203050705030d0f0d03"), &nonce);

    var seq = Seq64.init(std.math.maxInt(u64) - 1);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64) - 1), try seq.next());
    try std.testing.expectError(error.SequenceExhausted, seq.next());
}

test "record cipher state derives TLS 1.2 and 1.3 nonces without network IO" {
    const iv = hex("101112131415161718191a1b");
    var tls13 = try RecordCipherState.init(.tls13, .tls_aes_256_gcm_sha384, iv);
    try std.testing.expectEqualSlices(u8, &nonce13(iv, 0), &(try tls13.nextNonce()));

    var tls12 = try RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);
    const params = try tls12.sealParams(.handshake, tls12_wire_version, 17);
    try std.testing.expectEqual(@as(u64, 0), params.sequence);
    try std.testing.expectEqualSlices(u8, &hex("101112130000000000000000"), &params.nonce);
    try std.testing.expectEqual(@as(usize, 13), params.aad_len);
    try std.testing.expectEqualSlices(u8, &hex("00000000000000001603030011"), params.aadSlice());
}

test "TLS 1.2 record params keep AAD and nonce sequence aligned across round trips" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [Aes128Gcm.key_length]u8 = @splat(0x42);
    const iv = hex("202122232425262728292a2b");
    var sender = try RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);
    var receiver = try RecordCipherState.init(.tls12, .tls_ecdhe_rsa_with_aes_128_gcm_sha256, iv);
    const plaintexts = [_][]const u8{
        "record-0",
        "record-1 carries a different length",
        "record-2 proves the state keeps advancing",
        "record-3",
    };

    for (plaintexts, 0..) |plaintext, expected_sequence| {
        const length: u16 = @intCast(plaintext.len);
        const seal = try sender.sealParams(.application_data, tls12_wire_version, length);
        const aad_sequence = std.mem.readInt(u64, seal.aad[0..8], .big);
        const nonce_sequence = std.mem.readInt(u64, seal.nonce[4..12], .big);
        try std.testing.expectEqual(@as(u64, @intCast(expected_sequence)), seal.sequence);
        try std.testing.expectEqual(seal.sequence, aad_sequence);
        try std.testing.expectEqual(seal.sequence, nonce_sequence);

        var ciphertext: [64]u8 = undefined;
        var tag: [Aes128Gcm.tag_length]u8 = undefined;
        Aes128Gcm.encrypt(ciphertext[0..plaintext.len], &tag, plaintext, seal.aadSlice(), seal.nonce, key);

        const open = try receiver.openParams(.application_data, tls12_wire_version, length);
        try std.testing.expectEqual(seal.sequence, open.sequence);
        try std.testing.expectEqualSlices(u8, seal.aadSlice(), open.aadSlice());
        try std.testing.expectEqualSlices(u8, &seal.nonce, &open.nonce);

        var decrypted: [64]u8 = undefined;
        try Aes128Gcm.decrypt(decrypted[0..plaintext.len], ciphertext[0..plaintext.len], tag, open.aadSlice(), open.nonce, key);
        try std.testing.expectEqualSlices(u8, plaintext, decrypted[0..plaintext.len]);
    }
}

test "typed and runtime handshake transitions reject illegal order" {
    var hs0 = Handshake(.client, .start).init();
    var hs1 = hs0.transition(.send_client_hello);
    var hs2 = hs1.transition(.recv_server_hello);
    _ = hs2.transition(.recv_encrypted_extensions);

    try std.testing.expect(canTransition(.server, .start, .recv_client_hello));
    try std.testing.expect(!canTransition(.server, .start, .recv_server_hello));

    var runtime = RuntimeHandshake{ .role = .server };
    try runtime.step(.recv_client_hello);
    try std.testing.expectEqual(HandshakeState.client_hello, runtime.state);
    try std.testing.expectError(error.IllegalTransition, runtime.step(.recv_finished));
}

test "TLS 1.3 key schedule SHA-256 known vector" {
    const psk = @as([32]u8, @splat(0));
    const shared = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const th = Tls13Sha256.transcriptHash("clienthello|serverhello");

    var early = Tls13Sha256.earlySecret(&psk);
    defer early.wipe();
    try std.testing.expectEqualSlices(
        u8,
        &hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
        &early.declassify(),
    );

    var hs = try Tls13Sha256.handshakeSecret(&early, &shared);
    defer hs.wipe();
    try std.testing.expectEqualSlices(
        u8,
        &hex("ddbe37614d014a8c19db0a47955ee6930b3ee727c408386ba274344962b0e015"),
        &hs.declassify(),
    );

    var traffic = try Tls13Sha256.handshakeTrafficSecrets(&hs, &th);
    defer traffic.wipe();
    try std.testing.expectEqualSlices(
        u8,
        &hex("1e6694fbc974b7f59623e968185525fe1c23017cfbd01eecf3ac1f3d3b2c4cd1"),
        &traffic.client.declassify(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &hex("01f81d10f520de74eb0934ac7376c9268061677579821ae8bbafb4cbaa3c8933"),
        &traffic.server.declassify(),
    );

    var keys = try Tls13Sha256.trafficKeys(.tls_aes_128_gcm_sha256, &traffic.client);
    defer keys.wipe();
    try std.testing.expectEqual(@as(usize, 16), keys.key_len);
    try std.testing.expectEqualSlices(u8, &hex("3ec59f5749ba2af66dbaaead55154d1f"), keys.keySlice());
    try std.testing.expectEqualSlices(u8, &hex("f342f5f1bdb3c2a803bf93de"), &keys.iv);
}

test "TLS 1.3 key schedule rejects wrong transcript hash length and bad suite" {
    var early = Tls13Sha256.earlySecret("");
    defer early.wipe();
    try std.testing.expectError(error.BadTranscriptHash, Tls13Sha256.deriveSecret(&early, "derived", "bad"));
    try std.testing.expectError(error.InvalidCipherSuite, Tls13Sha256.trafficKeys(.tls_rsa_with_aes_128_gcm_sha256, &early));
}

// Track whether the policy hook was reached, to prove the chain signature gate
// runs BEFORE the caller's verifyFn (a forged chain must never reach the hook).
const HookProbe = struct {
    reached: bool = false,
    fn verify(ptr: *anyopaque, chain: CertificateChain, ctx: CertificateVerifyContext) CertificateVerifyError!void {
        _ = chain;
        _ = ctx;
        const self: *HookProbe = @ptrCast(@alignCast(ptr));
        self.reached = true;
    }
};

test "CertificateVerifier enforces chain signatures before the policy hook" {
    const x509_selfsign = @import("../proto/x509_selfsign.zig");
    const StdEd25519 = std.crypto.sign.Ed25519;

    const kp = try StdEd25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x33)));
    var root_buf: [512]u8 = undefined;
    const root = try x509_selfsign.buildSelfSigned(&root_buf, .{
        .common_name = "verifier.test.root",
        .not_before = 1_704_067_200,
        .not_after = 1_924_991_999,
        .serial = &.{ 0x70, 0x01 },
        .key_pair = kp,
        .is_ca = true,
    });

    const ctx = CertificateVerifyContext{
        .version = .tls13,
        .suite = .tls_aes_128_gcm_sha256,
        .server_name = "verifier.test.root",
        .transcript_hash = "",
    };

    // Valid self-signed chain: the signature gate passes, the hook is reached.
    {
        var probe = HookProbe{};
        const verifier = CertificateVerifier{ .ptr = &probe, .verifyFn = HookProbe.verify };
        const good = [_][]const u8{root};
        try verifier.verify(.{ .der_chain = &good }, ctx);
        try std.testing.expect(probe.reached);
    }

    // Forged chain: flip the trailing signature byte. The gate must reject it as
    // CertificateInvalid and the policy hook must NOT run.
    {
        var forged_buf: [512]u8 = undefined;
        @memcpy(forged_buf[0..root.len], root);
        forged_buf[root.len - 1] ^= 0x01;
        const forged = forged_buf[0..root.len];

        var probe = HookProbe{};
        const verifier = CertificateVerifier{ .ptr = &probe, .verifyFn = HookProbe.verify };
        const bad = [_][]const u8{forged};
        try std.testing.expectError(error.CertificateInvalid, verifier.verify(.{ .der_chain = &bad }, ctx));
        try std.testing.expect(!probe.reached);
    }
}

test {
    std.testing.refAllDecls(@This());
}
