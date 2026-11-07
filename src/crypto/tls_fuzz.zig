// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Robustness harnesses for the attacker-facing wire parsers.
//!
//! Every function here feeds hostile bytes — pure random and bit-flipped
//! near-valid — to the X.509, TLS-record, and TLS-handshake-message parsers and
//! asserts the ONLY observable outcome is a returned value or a returned error,
//! never a panic (a safety-check trap on OOB / integer overflow / `unreachable`
//! is a real bug and fails the test).
//!
//! Two layers:
//!
//!  1. DETERMINISTIC tests (fixed PRNG seed) that always run in the normal
//!     `zig build test`: pure-random, structured length-prefixed noise, and
//!     bit-flipped-valid-certificate corpora (~44k inputs/run, reproducible).
//!     `feedAll` fans every input out to ALL of the attacker-facing parsers
//!     (X.509, TLS record framing + ciphertext + inner-plaintext, OCSP,
//!     TLS handshake messages, and the SNI extractor); the cert-compression
//!     bomb guard gets its own dedicated deterministic loop below. This layer
//!     is the fuzzing that actually runs in CI and does NOT depend on `--fuzz`.
//!
//!  2. COVERAGE-GUIDED targets (`cov-fuzz:` tests) built on Zig's builtin fuzzer
//!     via `std.testing.fuzz`. Each wraps one high-value parser so the fuzzer's
//!     coverage feedback can steer mutation into deep parser paths. Under a plain
//!     `zig build test` the fuzz runner only replays each target's seed corpus
//!     plus an empty-string smoke input (bounded, fast — it does NOT balloon the
//!     ~6280-test suite); under `zig build test --fuzz` (or the dedicated
//!     `zig build fuzz --fuzz` step) the SAME targets run coverage-guided. See
//!     build.zig's `fuzz` step.
//!
//!     TOOLCHAIN NOTE (re-verified 2026-11-07 against Zig 0.17.0):
//!       * `zig build fuzz` (bounded corpus replay, no `--fuzz`) compiles and
//!         passes.
//!       * `zig build fuzz --fuzz[=N]` runs coverage-guided. Earlier failures had
//!         two causes. On 0.17.0-dev.1282 the fuzzer runtime panicked with
//!         `start index 1 is larger than end index 0`; that panic does not
//!         reproduce on 0.17.0 (a trivial standalone target and these targets
//!         both run cleanly). On 0.17.0 the remaining failure was
//!         `corrupted coverage file ...: pcs_len was zero`: the default Debug
//!         backend on x86_64 Linux is self-hosted and emits no SanitizerCoverage
//!         PCs. build.zig now forces the fuzz artifact onto the LLVM backend,
//!         and the x509 target then ran about 900k inputs with no crash.
//!     Whole-engine fuzzing (TLS 1.3 server/client, QUIC, DTLS) is in
//!     `tls_engine_fuzz.zig`, `proto/quic_fuzz.zig` and `proto/dtls_fuzz.zig`.
const std = @import("std");

const x509 = @import("x509.zig");
const tls12 = @import("tls12.zig");
const tls_record = @import("tls_record.zig");
const ocsp = @import("ocsp.zig");
const tls12_handshake = @import("../proto/tls12_handshake.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const sni = @import("../proto/sni.zig");
const cert_compression = @import("../proto/cert_compression.zig");
const ech_config = @import("../proto/ech_config.zig");
const delegated_credential = @import("../proto/delegated_credential.zig");
const Ed25519 = std.crypto.sign.Ed25519;

// One representative id-slh-dsa-* OID for the SLH-DSA SPKI extractor's fuzz
// coverage: id-slh-dsa-sha2-128s (2.16.840.1.101.3.4.3.20 = prefix ‖ 0x14) with a
// 32-byte raw public key (PK.seed ‖ PK.root). The OID suffix and the length only
// gate `extractSlhDsaPublicKey`'s exact-match/length checks, so exercising the
// walker with a single parameter set reaches every structural branch.
const slh_dsa_128s_oid = x509.slh_dsa_oid_prefix ++ [_]u8{0x14};
const slh_dsa_128s_pk_len: usize = 32;
// id-ML-DSA-65 (2.16.840.1.101.3.4.3.18 = prefix ‖ 0x12) shares the NIST sigAlgs
// OID prefix that `x509.slh_dsa_oid_prefix` names, so we build it the same way.
const ml_dsa_65_oid = x509.slh_dsa_oid_prefix ++ [_]u8{0x12};

/// Run every parser against one input. A panic inside any of them aborts the
/// test — which is exactly the signal we want. Errors are swallowed; iterators
/// are drained (bounded) so lazy per-element parsing is exercised too. Every
/// parser here is allocation-free on the reject path, so this stays cheap enough
/// to run tens of thousands of times per test. (The cert-compression bomb guard
/// is the one allocating parser; it gets its own bounded loop below.)
fn feedAll(input: []const u8) void {
    _ = x509.parse(input) catch {};
    _ = tls12.completeRecord(input) catch {};
    _ = tls_record.parseCiphertext(input) catch {};
    _ = ocsp.parse(input) catch {};
    _ = sni.extract(input); // returns a Result union, never errors — must never trap
    _ = tls12_handshake.parseClientHello(input) catch {};
    _ = tls12_handshake.parseServerHello(input) catch {};
    _ = tls12_handshake.parseHandshakeHeader(input) catch {};
    _ = tls12_handshake.parseNewSessionTicket(input) catch {};
    if (tls12_handshake.parseCertificate(input)) |it| {
        var iter = it;
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            const nxt = iter.next() catch break;
            if (nxt == null) break;
        }
    } else |_| {}

    // Roadmap-5.x attacker-facing parsers landed this session. All are pure and
    // allocation-free on every path (they borrow the caller's bytes and only
    // bounds-check), so they ride the shared hostile-bytes corpus here alongside
    // the older parsers; the contract is identical (a value or an error, never a
    // trap).
    //   * SubjectPublicKeyInfo extraction — the RFC 7250 raw-public-key SPKI path
    //     (classical RSA/ECDSA-P256/Ed25519 families) plus the post-quantum
    //     ML-DSA-44/65/87 and SLH-DSA raw-key extractors.
    _ = x509.extractPublicKey(input) catch {};
    _ = x509.extractMlDsa44PublicKey(input) catch {};
    _ = x509.extractMlDsa65PublicKey(input) catch {};
    _ = x509.extractMlDsa87PublicKey(input) catch {};
    _ = x509.extractSlhDsaPublicKey(input, &slh_dsa_128s_oid, slh_dsa_128s_pk_len) catch {};
    //   * RFC 9345 DelegatedCredential wire parse.
    _ = delegated_credential.parse(input) catch {};
    //   * RFC 9xxx ECH ECHConfigList selection (walks List → parse →
    //     hasUnsupportedMandatoryExtension → isValidPublicName). The KEM/KDF/AEAD
    //     ids only steer which entries are *selected*, not how deeply the list is
    //     parsed; supported values maximize the reachable depth.
    _ = ech_config.selectSupported(input, 0x0020, 0x0001, 0x0003) catch {};
}

test "wire parsers never panic on random input" {
    var prng = std.Random.DefaultPrng.init(0xA5A5_1234_DEAD_BEEF);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    var i: usize = 0;
    while (i < 12_000) : (i += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        rand.bytes(buf[0..len]);
        feedAll(buf[0..len]);
    }
}

test "wire parsers never panic on structured length-prefixed noise" {
    // Random bytes rarely reach past the outermost length field. Bias toward
    // plausible DER/TLS shapes: a leading tag/type byte, then a length, then
    // random contents — this drives the parsers deeper into their bounds logic.
    var prng = std.Random.DefaultPrng.init(0x0BADC0DE_F00DFACE);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    var i: usize = 0;
    while (i < 12_000) : (i += 1) {
        // Byte 0: a common structural tag (SEQUENCE / handshake type / content type).
        buf[0] = rand.intRangeAtMost(u8, 0, 0x30);
        // Bytes 1..3: a 2- or 3-byte length that may over- or under-run the buffer.
        buf[1] = rand.int(u8);
        buf[2] = rand.int(u8);
        buf[3] = rand.int(u8);
        const len = rand.intRangeAtMost(usize, 4, buf.len);
        rand.bytes(buf[4..len]);
        feedAll(buf[0..len]);
    }
}

test "x509.parse never panics on bit-flipped valid certificates" {
    // A real, structurally-valid cert mutated one byte at a time reaches parser
    // paths pure random never does (valid outer TLV, corrupt inner fields).
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x7c)));
    var der_buf: [1024]u8 = undefined;
    const base = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = "fuzz.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x33, 0x01 },
        .key_pair = kp,
        .dns_names = &.{"fuzz.test"},
        .is_ca = true,
        .path_len = 3,
    });
    try std.testing.expect((x509.parse(base) catch null) != null); // sanity: base parses

    var prng = std.Random.DefaultPrng.init(0xFACEFEED_1357_2468);
    const rand = prng.random();
    var scratch: [1024]u8 = undefined;
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        @memcpy(scratch[0..base.len], base);
        // Flip 1..4 random bytes.
        const flips = rand.intRangeAtMost(usize, 1, 4);
        var f: usize = 0;
        while (f < flips) : (f += 1) {
            const pos = rand.intRangeLessThan(usize, 0, base.len);
            scratch[pos] ^= rand.int(u8);
        }
        _ = x509.parse(scratch[0..base.len]) catch {};
    }
}

test "cert_compression.inflateZlib never panics on hostile input" {
    // The bomb guard is the one allocating wire parser, so it gets a dedicated
    // bounded loop rather than riding in `feedAll`. Feeds a mix of bit-flipped
    // valid zlib (to drive the decompressor's inner paths) and pure-random bytes,
    // each with a declared length spanning below / at / above the cap so the
    // §4 pre-allocation guard, the §5 exact-length guard, and the happy path are
    // all reachable. The testing allocator's leak check backstops every branch.
    const alloc = std.testing.allocator;
    const body = "a certificate body that is worth compressing for the fuzz corpus";
    const valid = try cert_compression.deflateZlib(alloc, body);
    defer alloc.free(valid);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE_D00D_1279);
    const rand = prng.random();
    var scratch: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const len = @min(valid.len, scratch.len);
        if (rand.boolean()) {
            @memcpy(scratch[0..len], valid[0..len]);
            const flips = rand.intRangeAtMost(usize, 1, 4);
            var f: usize = 0;
            while (f < flips) : (f += 1) {
                scratch[rand.intRangeLessThan(usize, 0, len)] ^= rand.int(u8);
            }
        } else {
            rand.bytes(scratch[0..len]);
        }
        const declared = rand.intRangeAtMost(usize, 0, cert_compression.max_uncompressed_len + 32);
        if (cert_compression.inflateZlib(alloc, scratch[0..len], declared)) |out| {
            alloc.free(out);
        } else |_| {}
    }

    // Sanity: the pristine stream still round-trips at its true declared length.
    const restored = try cert_compression.inflateZlib(alloc, valid, body.len);
    defer alloc.free(restored);
    try std.testing.expectEqualSlices(u8, body, restored);
}

// ---------------------------------------------------------------------------
// Valid-instance builders shared by the deterministic bit-flip loop below and the
// coverage-guided seed corpora. They emit STRUCTURALLY-VALID wire objects so a
// bit-flip keeps most of the structure intact, driving mutation deep into the
// parsers' bounds/length/OID logic that pure-random bytes never reach.
// ---------------------------------------------------------------------------

/// Number of bytes a definite-form DER length of `n` occupies (≤ 0xffff — all the
/// SPKI seeds here fit). Pure companion to `emitDerLen`, so enclosing lengths can
/// be computed before any bytes are written.
fn derLenSize(n: usize) usize {
    if (n < 0x80) return 1;
    if (n <= 0xff) return 2;
    return 3;
}

/// Emit a definite-form DER length (≤ 0xffff) into `out`, returning the number of
/// length bytes written (always equal to `derLenSize(n)`).
fn emitDerLen(out: []u8, n: usize) usize {
    if (n < 0x80) {
        out[0] = @intCast(n);
        return 1;
    }
    if (n <= 0xff) {
        out[0] = 0x81;
        out[1] = @intCast(n);
        return 2;
    }
    out[0] = 0x82;
    std.mem.writeInt(u16, out[1..3], @intCast(n), .big);
    return 3;
}

/// Build a raw-key `SubjectPublicKeyInfo` — `SEQUENCE { SEQUENCE { OID }, BIT
/// STRING { 0x00 ‖ key } }`, parameters absent — into `out`, returning the used
/// prefix. This is the exact shape the ML-DSA / SLH-DSA extractors accept; the key
/// bytes are opaque to them (they check only the OID and the length), so an
/// all-zero key of the right size is a valid instance. `oid.len` must be < 128
/// (every OID here is 9 bytes) and `out` large enough for the whole SPKI.
fn buildRawKeySpki(out: []u8, oid: []const u8, key: []const u8) []const u8 {
    const alg_content = 1 + derLenSize(oid.len) + oid.len; // OID TLV
    const alg_tlv = 1 + derLenSize(alg_content) + alg_content;
    const bit_content = 1 + key.len; // unused-bits octet ‖ key
    const bit_tlv = 1 + derLenSize(bit_content) + bit_content;
    const outer_content = alg_tlv + bit_tlv;

    var i: usize = 0;
    out[i] = 0x30; // outer SEQUENCE
    i += 1;
    i += emitDerLen(out[i..], outer_content);
    out[i] = 0x30; // AlgorithmIdentifier SEQUENCE
    i += 1;
    i += emitDerLen(out[i..], alg_content);
    out[i] = 0x06; // OID
    i += 1;
    i += emitDerLen(out[i..], oid.len);
    @memcpy(out[i..][0..oid.len], oid);
    i += oid.len;
    out[i] = 0x03; // BIT STRING
    i += 1;
    i += emitDerLen(out[i..], bit_content);
    out[i] = 0x00; // zero unused bits (byte-aligned raw key)
    i += 1;
    @memcpy(out[i..][0..key.len], key);
    i += key.len;
    return out[0..i];
}

/// Build a minimal well-formed single-entry `ECHConfigList` (version 0xfe0d, KEM
/// 0x0020, one `{0x0001,0x0003}` cipher suite, no ECHConfig extensions) into
/// `out`, returning the used prefix.
fn buildEchList(out: []u8, pk: []const u8, public_name: []const u8) []const u8 {
    var c: [512]u8 = undefined;
    var n: usize = 0;
    c[n] = 0x07; // config_id
    n += 1;
    std.mem.writeInt(u16, c[n..][0..2], 0x0020, .big); // kem_id (X25519)
    n += 2;
    std.mem.writeInt(u16, c[n..][0..2], @intCast(pk.len), .big);
    n += 2;
    @memcpy(c[n..][0..pk.len], pk);
    n += pk.len;
    std.mem.writeInt(u16, c[n..][0..2], 4, .big); // cipher_suites length
    n += 2;
    std.mem.writeInt(u16, c[n..][0..2], 0x0001, .big); // kdf_id
    n += 2;
    std.mem.writeInt(u16, c[n..][0..2], 0x0003, .big); // aead_id
    n += 2;
    c[n] = 64; // maximum_name_length
    n += 1;
    c[n] = @intCast(public_name.len);
    n += 1;
    @memcpy(c[n..][0..public_name.len], public_name);
    n += public_name.len;
    std.mem.writeInt(u16, c[n..][0..2], 0, .big); // extensions length = 0
    n += 2;

    var e: [560]u8 = undefined;
    var m: usize = 0;
    std.mem.writeInt(u16, e[m..][0..2], ech_config.version_draft13, .big);
    m += 2;
    std.mem.writeInt(u16, e[m..][0..2], @intCast(n), .big);
    m += 2;
    @memcpy(e[m..][0..n], c[0..n]);
    m += n;

    std.mem.writeInt(u16, out[0..2], @intCast(m), .big);
    @memcpy(out[2..][0..m], e[0..m]);
    return out[0 .. 2 + m];
}

/// Copy `base` into `dst` (equal lengths) then XOR 1..4 random bytes — the shared
/// bit-flip mutation used by the "bit-flipped valid instance" loops.
fn flipInto(rand: std.Random, dst: []u8, base: []const u8) void {
    @memcpy(dst, base);
    const flips = rand.intRangeAtMost(usize, 1, 4);
    var f: usize = 0;
    while (f < flips) : (f += 1) {
        dst[rand.intRangeLessThan(usize, 0, dst.len)] ^= rand.int(u8);
    }
}

test "roadmap-5.x parsers never panic on bit-flipped valid instances" {
    // Pure random / structured noise almost never gets past the outer length or
    // OID gate of these parsers, so — as with the bit-flipped-certificate test
    // above — start from a STRUCTURALLY-VALID instance of each and flip 1..4 bytes
    // per iteration. That drives mutation deep into the bounds/length/OID-match
    // logic random bytes never reach. The property under test is unchanged: a
    // returned value or error, NEVER a trap.
    var prng = std.Random.DefaultPrng.init(0x5109_A5A5_0D0E_BEEF);
    const rand = prng.random();

    // ECHConfigList.
    var ech_buf: [600]u8 = undefined;
    const ech_pk: [32]u8 = @splat(0xAB);
    const ech_valid = buildEchList(&ech_buf, &ech_pk, "cover.example");
    try std.testing.expect((ech_config.selectSupported(ech_valid, 0x0020, 0x0001, 0x0003) catch null) != null);

    // DelegatedCredential.
    var dc_buf: [64]u8 = undefined;
    const dc_spki = [_]u8{ 0x30, 0x03, 0xAA, 0xBB, 0xCC };
    const dc_sig = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const dc_valid = try delegated_credential.serialize(&dc_buf, .{
        .valid_time = 0x00015180,
        .dc_cert_verify_algorithm = 0x0403,
        .spki = &dc_spki,
    }, 0x0807, &dc_sig);
    try std.testing.expect((delegated_credential.parse(dc_valid) catch null) != null);

    // ML-DSA-65 raw-key SPKI.
    var mldsa_buf: [2048]u8 = undefined;
    const mldsa_key: [x509.ml_dsa_65_public_key_len]u8 = @splat(0);
    const mldsa_valid = buildRawKeySpki(&mldsa_buf, &ml_dsa_65_oid, &mldsa_key);
    try std.testing.expect((x509.extractMlDsa65PublicKey(mldsa_valid) catch null) != null);

    // SLH-DSA-128s raw-key SPKI.
    var slh_buf: [128]u8 = undefined;
    const slh_key: [slh_dsa_128s_pk_len]u8 = @splat(0);
    const slh_valid = buildRawKeySpki(&slh_buf, &slh_dsa_128s_oid, &slh_key);
    try std.testing.expect((x509.extractSlhDsaPublicKey(slh_valid, &slh_dsa_128s_oid, slh_dsa_128s_pk_len) catch null) != null);

    var ech_s: [600]u8 = undefined;
    var dc_s: [64]u8 = undefined;
    var mldsa_s: [2048]u8 = undefined;
    var slh_s: [128]u8 = undefined;
    var i: usize = 0;
    while (i < 6000) : (i += 1) {
        flipInto(rand, ech_s[0..ech_valid.len], ech_valid);
        _ = ech_config.selectSupported(ech_s[0..ech_valid.len], 0x0020, 0x0001, 0x0003) catch {};

        flipInto(rand, dc_s[0..dc_valid.len], dc_valid);
        _ = delegated_credential.parse(dc_s[0..dc_valid.len]) catch {};

        flipInto(rand, mldsa_s[0..mldsa_valid.len], mldsa_valid);
        _ = x509.extractMlDsa65PublicKey(mldsa_s[0..mldsa_valid.len]) catch {};
        _ = x509.extractPublicKey(mldsa_s[0..mldsa_valid.len]) catch {}; // classical path on the same bytes

        flipInto(rand, slh_s[0..slh_valid.len], slh_valid);
        _ = x509.extractSlhDsaPublicKey(slh_s[0..slh_valid.len], &slh_dsa_128s_oid, slh_dsa_128s_pk_len) catch {};
    }
}

// ---------------------------------------------------------------------------
// Coverage-guided targets (`std.testing.fuzz`).
//
// Each `oneInput` is a `fn (context, *std.testing.Smith) anyerror!void`: it pulls
// a variable-length byte string from the Smith (which, under the fuzzer, is
// driven by coverage-guided mutation; under a normal test run, by the replayed
// seed corpus) and feeds it to exactly one attacker-facing parser. The contract
// is identical to the deterministic tests above: a returned value or error is
// fine; a panic / safety-check trap / UB is a real bug and fails the run.
//
// `slice_cap` bounds the input a single target extracts. Certs and records here
// are all well under this; the fuzzer is free to explore the whole range.
// ---------------------------------------------------------------------------

const slice_cap = 4096;

/// Frame a raw payload as a Smith corpus seed: `smith.slice` reads a leading
/// little-endian u32 length, then that many bytes, so a corpus entry that should
/// decode to `payload` must be `<u32 len><payload>`. Returns a slice of `out`.
fn frameSlice(out: []u8, payload: []const u8) []const u8 {
    std.debug.assert(out.len >= 4 + payload.len);
    std.mem.writeInt(u32, out[0..4], @intCast(payload.len), .little);
    @memcpy(out[4..][0..payload.len], payload);
    return out[0 .. 4 + payload.len];
}

fn oneX509(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    _ = x509.parse(buf[0..n]) catch {};
}

fn oneTlsRecord(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    // Outer TLSCiphertext framing check and the daemon's record framer.
    _ = tls_record.parseCiphertext(buf[0..n]) catch {};
    _ = tls12.completeRecord(buf[0..n]) catch {};
    // Inner-plaintext content-type/padding scan (mutates its buffer in place).
    _ = tls_record.decodeInnerPlaintext(buf[0..n]) catch {};
}

fn oneOcsp(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    _ = ocsp.parse(buf[0..n]) catch {};
}

fn oneHandshake(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    const input = buf[0..n];
    _ = tls12_handshake.parseClientHello(input) catch {};
    _ = tls12_handshake.parseServerHello(input) catch {};
    _ = tls12_handshake.parseHandshakeHeader(input) catch {};
    _ = tls12_handshake.parseNewSessionTicket(input) catch {};
    if (tls12_handshake.parseCertificate(input)) |it| {
        var iter = it;
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            const nxt = iter.next() catch break;
            if (nxt == null) break;
        }
    } else |_| {}
}

fn oneCertCompression(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    // Exercise the RFC 8879 §4/§5 bomb guard across the whole declared-length
    // range, including values above the cap (which must be rejected BEFORE any
    // allocation). +16 so the fuzzer also visits the reject-above-cap branch.
    const declared: u32 = smith.valueRangeAtMost(u32, 0, cert_compression.max_uncompressed_len + 16);
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    const out = cert_compression.inflateZlib(std.testing.allocator, buf[0..n], declared) catch return;
    // A successful inflate returns an owned buffer; free it so the testing
    // allocator's leak check (run at test end during corpus replay) stays clean.
    std.testing.allocator.free(out);
}

fn oneSni(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    // `extract` never returns an error (it maps every failure to `.malformed`);
    // the property under test is that it never traps on hostile bytes.
    _ = sni.extract(buf[0..n]);
    _ = sni.extractOptional(buf[0..n]);
}

fn oneSpki(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    const input = buf[0..n];
    // RFC 7250 raw-public-key SubjectPublicKeyInfo — the classical extractor
    // (RSA/ECDSA-P256/Ed25519) and the post-quantum ML-DSA/SLH-DSA raw-key paths,
    // all fed the same hostile bytes.
    _ = x509.extractPublicKey(input) catch {};
    _ = x509.extractMlDsa44PublicKey(input) catch {};
    _ = x509.extractMlDsa65PublicKey(input) catch {};
    _ = x509.extractMlDsa87PublicKey(input) catch {};
    _ = x509.extractSlhDsaPublicKey(input, &slh_dsa_128s_oid, slh_dsa_128s_pk_len) catch {};
}

fn oneDelegatedCredential(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    _ = delegated_credential.parse(buf[0..n]) catch {};
}

fn oneEchConfig(_: void, smith: *std.testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [slice_cap]u8 = undefined;
    const n = smith.slice(&buf);
    // Walks List → parse → hasUnsupportedMandatoryExtension → isValidPublicName.
    _ = ech_config.selectSupported(buf[0..n], 0x0020, 0x0001, 0x0003) catch {};
}

test "cov-fuzz: x509.parse never traps on arbitrary DER" {
    // Seed with a real self-signed certificate so the fuzzer starts from a
    // structurally-valid TLV tree and mutates inward.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x3a)));
    var der_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = "cov.fuzz.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x44, 0x02 },
        .key_pair = kp,
        .dns_names = &.{"cov.fuzz.test"},
        .is_ca = true,
        .path_len = 2,
    });
    var seed_buf: [1100]u8 = undefined;
    const seed = frameSlice(&seed_buf, der);
    try std.testing.fuzz({}, oneX509, .{ .corpus = &.{seed} });
}

test "cov-fuzz: tls_record parsers never trap on arbitrary bytes" {
    // A well-formed application_data record header + 3-byte fragment.
    var s0: [32]u8 = undefined;
    const seed = frameSlice(&s0, &.{ 0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC });
    try std.testing.fuzz({}, oneTlsRecord, .{ .corpus = &.{seed} });
}

test "cov-fuzz: ocsp.parse never traps on arbitrary DER" {
    // Two small structural seeds that reach distinct outer-response branches.
    var s0: [32]u8 = undefined;
    var s1: [32]u8 = undefined;
    const seed0 = frameSlice(&s0, &.{ 0x30, 0x08, 0x0A, 0x01, 0x01, 0xA0, 0x03, 0x30, 0x01, 0x00 });
    const seed1 = frameSlice(&s1, &.{ 0x30, 0x03, 0x0A, 0x01, 0x00 });
    try std.testing.fuzz({}, oneOcsp, .{ .corpus = &.{ seed0, seed1 } });
}

test "cov-fuzz: tls12 handshake parsers never trap on arbitrary bytes" {
    // A minimal but structurally-valid ClientHello body (no handshake header:
    // `parseClientHello` consumes the body directly).
    const ch_body = [_]u8{ 0x03, 0x03 } ++ @as([32]u8, @splat(0)) ++ // version + random
        [_]u8{0x00} ++ // session_id length
        [_]u8{ 0x00, 0x02, 0x00, 0x2f } ++ // cipher_suites: len + TLS_RSA_WITH_AES_128_CBC_SHA
        [_]u8{ 0x01, 0x00 } ++ // compression_methods: len + null
        [_]u8{ 0x00, 0x00 }; // extensions: len 0
    var s0: [128]u8 = undefined;
    const seed = frameSlice(&s0, &ch_body);
    try std.testing.fuzz({}, oneHandshake, .{ .corpus = &.{seed} });
}

test "cov-fuzz: cert_compression.inflateZlib bomb guard never traps" {
    // Seed: <u64 declared_len><u32 compressed_len><compressed>. The declared
    // length is pulled first (Smith reads 8 bytes for an integer), then the
    // compressed slice. Setting declared == body.len drives the happy path;
    // the fuzzer mutates toward the bomb-guard reject branches from there.
    const body = "certificate-shaped body for the zlib fuzz seed \x00\x01\x02\x03";
    const compressed = try cert_compression.deflateZlib(std.testing.allocator, body);
    defer std.testing.allocator.free(compressed);

    var seed_buf: [512]u8 = undefined;
    std.mem.writeInt(u64, seed_buf[0..8], body.len, .little);
    std.mem.writeInt(u32, seed_buf[8..12], @intCast(compressed.len), .little);
    @memcpy(seed_buf[12..][0..compressed.len], compressed);
    const seed = seed_buf[0 .. 12 + compressed.len];
    try std.testing.fuzz({}, oneCertCompression, .{ .corpus = &.{seed} });
}

test "cov-fuzz: sni.extract never traps on arbitrary bytes" {
    // A bare ClientHello (handshake type 1) carrying a single server_name
    // extension for "a" — the deepest reachable path in the SNI walker.
    const sni_ext_data = [_]u8{ 0x00, 0x04, 0x00, 0x00, 0x01, 'a' }; // list_len + name_type + name_len + name
    const sni_ext = [_]u8{ 0x00, 0x00, 0x00, @as(u8, @intCast(sni_ext_data.len)) } ++ sni_ext_data;
    const ch_body = [_]u8{ 0x03, 0x03 } ++ @as([32]u8, @splat(0)) ++
        [_]u8{0x00} ++ // session_id length
        [_]u8{ 0x00, 0x02, 0x00, 0x2f } ++ // cipher_suites
        [_]u8{ 0x01, 0x00 } ++ // compression_methods
        [_]u8{ 0x00, @as(u8, @intCast(sni_ext.len)) } ++ sni_ext; // extensions
    const ch_len = ch_body.len;
    const ch_msg = [_]u8{ 0x01, @intCast((ch_len >> 16) & 0xff), @intCast((ch_len >> 8) & 0xff), @intCast(ch_len & 0xff) } ++ ch_body;
    var s0: [256]u8 = undefined;
    const seed = frameSlice(&s0, &ch_msg);
    try std.testing.fuzz({}, oneSni, .{ .corpus = &.{seed} });
}

test "cov-fuzz: SubjectPublicKeyInfo extractors never trap on arbitrary DER" {
    // Seed 1: a real Ed25519 SPKI (the classical / RFC 7250 path), lifted from a
    // self-signed certificate. Seeds 2 & 3: structurally-valid ML-DSA-65 and
    // SLH-DSA-128s raw-key SPKIs (opaque all-zero keys of the exact required
    // length) so the fuzzer starts inside the OID/length branches and mutates out.
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x5e)));
    var der_buf: [1024]u8 = undefined;
    const der = try x509_selfsign.buildSelfSigned(&der_buf, .{
        .common_name = "spki.fuzz.test",
        .not_before = 1_704_067_200,
        .not_after = 1_735_689_599,
        .serial = &.{ 0x55, 0x03 },
        .key_pair = kp,
        .dns_names = &.{"spki.fuzz.test"},
        .is_ca = true,
        .path_len = 1,
    });
    const cert = try x509.parse(der);

    var mldsa_buf: [2048]u8 = undefined;
    const mldsa_key: [x509.ml_dsa_65_public_key_len]u8 = @splat(0);
    const mldsa_spki = buildRawKeySpki(&mldsa_buf, &ml_dsa_65_oid, &mldsa_key);

    var slh_buf: [128]u8 = undefined;
    const slh_key: [slh_dsa_128s_pk_len]u8 = @splat(0);
    const slh_spki = buildRawKeySpki(&slh_buf, &slh_dsa_128s_oid, &slh_key);

    var s0: [1100]u8 = undefined;
    var s1: [2100]u8 = undefined;
    var s2: [160]u8 = undefined;
    const seed0 = frameSlice(&s0, cert.spki_der);
    const seed1 = frameSlice(&s1, mldsa_spki);
    const seed2 = frameSlice(&s2, slh_spki);
    try std.testing.fuzz({}, oneSpki, .{ .corpus = &.{ seed0, seed1, seed2 } });
}

test "cov-fuzz: DelegatedCredential parse never traps on arbitrary bytes" {
    // A well-formed RFC 9345 DelegatedCredential: the fuzzer mutates toward the
    // truncation / trailing-byte / zero-SPKI reject branches from here.
    var dc_buf: [64]u8 = undefined;
    const spki = [_]u8{ 0x30, 0x03, 0xAA, 0xBB, 0xCC };
    const sig = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const valid = try delegated_credential.serialize(&dc_buf, .{
        .valid_time = 0x00015180,
        .dc_cert_verify_algorithm = 0x0403,
        .spki = &spki,
    }, 0x0807, &sig);
    var s0: [96]u8 = undefined;
    const seed = frameSlice(&s0, valid);
    try std.testing.fuzz({}, oneDelegatedCredential, .{ .corpus = &.{seed} });
}

test "cov-fuzz: ECH ECHConfigList selection never traps on arbitrary bytes" {
    // A well-formed single-entry ECHConfigList (version 0xfe0d, matching KEM/suite)
    // so the fuzzer begins at the deepest reachable selection path.
    var list_buf: [600]u8 = undefined;
    const pk: [32]u8 = @splat(0xAB);
    const valid = buildEchList(&list_buf, &pk, "cover.example");
    var s0: [700]u8 = undefined;
    const seed = frameSlice(&s0, valid);
    try std.testing.fuzz({}, oneEchConfig, .{ .corpus = &.{seed} });
}
