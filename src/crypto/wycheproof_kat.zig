// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wycheproof conformance for the Armor crypto primitives.
//!
//! Two layers live here:
//!
//!   1. The real upstream corpus (github.com/C2SP/wycheproof, `testvectors_v1/`)
//!      for AES-GCM, ChaCha20-Poly1305, X25519, ECDH P-256, ECDSA P-256/SHA-256
//!      (DER and IEEE P1363), RSA PKCS#1 v1.5 and RSA-PSS 2048/SHA-256, HKDF-SHA-256
//!      and Ed25519. The vectors are vendored in compact form under
//!      `testdata/wycheproof/` (provenance, upstream commit and source SHA-256 in
//!      each file header; regenerate with `tools/wycheproof_extract.py`). Every
//!      vector is driven through Armor's own API — the same entry points the TLS,
//!      X.509 and Mooring code call — and must land on the upstream verdict:
//!      `valid` must be accepted with the exact expected output, `invalid` must be
//!      rejected, and `acceptable` may go either way but, if accepted, must produce
//!      the expected output. The per-file tallies are pinned exactly, so a
//!      silently skipped or reinterpreted vector fails the test.
//!
//!   2. A handful of hand-written rejection cases (above the corpus drivers)
//!      that pre-date the import and pin specific edge behavior directly.
//!
//! "Unsupported" vectors are ones Armor's API cannot even express (AES-192, GCM
//! nonces other than 96 bits, compressed SEC1 points); they are counted, pinned,
//! and never silently treated as a pass. An unexpressible vector that upstream
//! marks `invalid` is refused by type and tallied as `invalid_unexpressible`,
//! separately from vectors the API actually received and rejected.
const std = @import("std");

const aead = @import("aead.zig");
const kx = @import("kx.zig");
const ecdsa_p256 = @import("ecdsa_p256.zig");
const ecdh_p256 = @import("ecdh_p256.zig");
const rsa_verify = @import("rsa_verify.zig");
const sign = @import("sign.zig");
const hash = @import("hash.zig");

const testing = std.testing;

// ── AEAD: any single-bit change to ciphertext, tag, or nonce must fail open ──

fn aeadTamperRejected(comptime A: type) !void {
    const key: A.Key = @splat(0xC3);
    const nonce: A.Nonce = @splat(0x5A);
    const ad = "aead-associated-data";
    const pt = "wycheproof adversarial plaintext payload!";

    var a = A.init(key);
    defer a.deinit();

    var ct: [pt.len]u8 = undefined;
    const tag = try a.seal(nonce, ad, pt, &ct);

    var out: [pt.len]u8 = undefined;
    // Sanity: the untampered record opens.
    try a.open(nonce, ad, &ct, tag, &out);
    try testing.expectEqualSlices(u8, pt, &out);

    // Flip one ciphertext bit → AuthFailed.
    var ct_bad = ct;
    ct_bad[ct_bad.len / 2] ^= 0x01;
    try testing.expectError(error.AuthFailed, a.open(nonce, ad, &ct_bad, tag, &out));

    // Flip one tag bit → AuthFailed.
    var tag_bad = tag;
    tag_bad[0] ^= 0x80;
    try testing.expectError(error.AuthFailed, a.open(nonce, ad, &ct, tag_bad, &out));

    // Wrong nonce → AuthFailed.
    var nonce_bad = nonce;
    nonce_bad[0] ^= 0x01;
    try testing.expectError(error.AuthFailed, a.open(nonce_bad, ad, &ct, tag, &out));

    // Tampered associated data → AuthFailed.
    try testing.expectError(error.AuthFailed, a.open(nonce, "different-ad", &ct, tag, &out));
}

test "Wycheproof: AES-256-GCM rejects tampered ciphertext/tag/nonce/aad" {
    try aeadTamperRejected(aead.Aead(.aes256_gcm));
}

test "Wycheproof: ChaCha20-Poly1305 rejects tampered ciphertext/tag/nonce/aad" {
    try aeadTamperRejected(aead.Aead(.chacha20_poly1305));
}

// ── X25519: a low-order peer point (all-zero u) must be rejected, never yield
//    a usable shared secret (RFC 7748 §6.1 / the classic contributory-behavior
//    attack). Onyx Server's wrapper rejects an all-zero shared secret. ──

test "Wycheproof: X25519 rejects the all-zero low-order point" {
    const sk = kx.SecretKey.init(@as([32]u8, @splat(0x33)));
    const all_zero: kx.PublicKey = @splat(0);
    try testing.expectError(error.LowOrderPoint, kx.X25519Kx.sharedSecret(&sk, all_zero));
}

// ── ECDSA P-256: a signature with r == 0 or s == 0 is outside [1, n-1] and MUST
//    NOT verify, for any key or message (a classic Wycheproof malleability/edge
//    case). ──

test "Wycheproof: ECDSA-P256 rejects zero r or s" {
    const kp = ecdsa_p256.KeyPair.generate(std.testing.io);
    const msg = "message under an adversarial signature";

    // r = 0, s = 0.
    try testing.expect(!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes(@as([64]u8, @splat(0))), msg, kp.public_key));

    // r = 0, s = 1.
    var r0s1 = @as([64]u8, @splat(0));
    r0s1[63] = 1;
    try testing.expect(!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes(r0s1), msg, kp.public_key));

    // r = 1, s = 0.
    var r1s0 = @as([64]u8, @splat(0));
    r1s0[31] = 1;
    try testing.expect(!ecdsa_p256.verify(ecdsa_p256.Signature.fromBytes(r1s0), msg, kp.public_key));
}

// ═════════════════════════════════════════════════════════════════════════════
// Upstream Wycheproof corpus drivers
// ═════════════════════════════════════════════════════════════════════════════

const corpus = struct {
    const aes_gcm = @embedFile("testdata/wycheproof/aes_gcm_test.txt");
    const chacha20_poly1305 = @embedFile("testdata/wycheproof/chacha20_poly1305_test.txt");
    const x25519 = @embedFile("testdata/wycheproof/x25519_test.txt");
    const ecdh_p256 = @embedFile("testdata/wycheproof/ecdh_secp256r1_ecpoint_test.txt");
    const ecdsa_p256_der = @embedFile("testdata/wycheproof/ecdsa_secp256r1_sha256_test.txt");
    const ecdsa_p256_p1363 = @embedFile("testdata/wycheproof/ecdsa_secp256r1_sha256_p1363_test.txt");
    const ed25519 = @embedFile("testdata/wycheproof/ed25519_test.txt");
    const rsa_pkcs1 = @embedFile("testdata/wycheproof/rsa_signature_2048_sha256_test.txt");
    const rsa_pss_0 = @embedFile("testdata/wycheproof/rsa_pss_2048_sha256_mgf1_0_test.txt");
    const rsa_pss_32 = @embedFile("testdata/wycheproof/rsa_pss_2048_sha256_mgf1_32_test.txt");
    const hkdf_sha256 = @embedFile("testdata/wycheproof/hkdf_sha256_test.txt");
};

/// Upstream verdict for one vector.
const Expected = enum { valid, invalid, acceptable };

/// What Armor did with one vector.
const Outcome = enum {
    /// Accepted, and any produced output matched the vector.
    accept,
    /// Rejected (error, `false`, or not representable for an `invalid` vector).
    reject,
    /// Accepted but produced output differing from the vector (always a failure).
    wrong_output,
    /// Not expressible through Armor's API at all (AES-192, non-96-bit nonce,
    /// compressed point). For an `invalid` vector this is a refusal by type and
    /// is tallied separately from a real API rejection.
    unsupported,
};

/// Per-file tally. `expectCounts` pins every bucket so a parser regression
/// that silently drops or reclassifies vectors cannot pass.
const Tally = struct {
    file: []const u8,
    total: usize = 0,
    valid_accepted: usize = 0,
    invalid_rejected: usize = 0,
    invalid_unexpressible: usize = 0,
    acceptable_accepted: usize = 0,
    acceptable_rejected: usize = 0,
    unsupported: usize = 0,
    failures: usize = 0,
    /// Suppress diagnostics (harness self-test only).
    quiet: bool = false,

    fn record(self: *Tally, tc_id: []const u8, flags: []const u8, expected: Expected, outcome: Outcome) void {
        self.total += 1;
        const ok = switch (expected) {
            .valid => switch (outcome) {
                .accept => blk: {
                    self.valid_accepted += 1;
                    break :blk true;
                },
                .unsupported => blk: {
                    self.unsupported += 1;
                    break :blk true;
                },
                .reject, .wrong_output => false,
            },
            .invalid => switch (outcome) {
                .reject => blk: {
                    self.invalid_rejected += 1;
                    break :blk true;
                },
                .unsupported => blk: {
                    self.invalid_unexpressible += 1;
                    break :blk true;
                },
                .accept, .wrong_output => false,
            },
            .acceptable => switch (outcome) {
                .accept => blk: {
                    self.acceptable_accepted += 1;
                    break :blk true;
                },
                .reject => blk: {
                    self.acceptable_rejected += 1;
                    break :blk true;
                },
                .unsupported => blk: {
                    self.unsupported += 1;
                    break :blk true;
                },
                .wrong_output => false,
            },
        };
        if (!ok) {
            self.failures += 1;
            if (!self.quiet) std.debug.print("wycheproof {s}: tcId {s} [{s}] expected {t}, Armor gave {t}\n", .{ self.file, tc_id, flags, expected, outcome });
        }
    }

    const Counts = struct {
        total: usize,
        valid_accepted: usize,
        invalid_rejected: usize,
        invalid_unexpressible: usize = 0,
        acceptable_accepted: usize = 0,
        acceptable_rejected: usize = 0,
        unsupported: usize = 0,
    };

    fn expectCounts(self: *const Tally, want: Counts) !void {
        if (self.failures != 0) {
            if (!self.quiet) std.debug.print("wycheproof {s}: {d} of {d} vectors disagree with upstream\n", .{ self.file, self.failures, self.total });
            return error.WycheproofMismatch;
        }
        const got: Counts = .{
            .total = self.total,
            .valid_accepted = self.valid_accepted,
            .invalid_rejected = self.invalid_rejected,
            .invalid_unexpressible = self.invalid_unexpressible,
            .acceptable_accepted = self.acceptable_accepted,
            .acceptable_rejected = self.acceptable_rejected,
            .unsupported = self.unsupported,
        };
        if (!std.meta.eql(got, want)) {
            if (!self.quiet) std.debug.print("wycheproof {s}: tally {any} != pinned {any}\n", .{ self.file, got, want });
            return error.WycheproofTallyChanged;
        }
    }
};

/// Maximum whitespace-separated fields on one corpus line.
const max_fields = 12;

/// One parsed corpus line: `G <fields>` (group) or `T <tcId> <res> <flags> <fields>`.
const Record = struct {
    kind: u8,
    fields: [max_fields][]const u8 = undefined,
    len: usize = 0,

    fn tcId(self: *const Record) []const u8 {
        return self.fields[0];
    }

    fn expected(self: *const Record) !Expected {
        const r = self.fields[1];
        if (r.len != 1) return error.MalformedCorpus;
        return switch (r[0]) {
            'v' => .valid,
            'i' => .invalid,
            'a' => .acceptable,
            else => error.MalformedCorpus,
        };
    }

    fn flags(self: *const Record) []const u8 {
        return self.fields[2];
    }

    /// Test payload field `i` (after tcId/result/flags).
    fn arg(self: *const Record, i: usize) []const u8 {
        return self.fields[3 + i];
    }
};

const Reader = struct {
    lines: std.mem.SplitIterator(u8, .scalar),

    fn init(text: []const u8) Reader {
        return .{ .lines = std.mem.splitScalar(u8, text, '\n') };
    }

    fn next(self: *Reader) !?Record {
        while (self.lines.next()) |line| {
            if (line.len == 0 or line[0] == '#') continue;
            var toks = std.mem.tokenizeScalar(u8, line, ' ');
            const kind = toks.next() orelse return error.MalformedCorpus;
            if (kind.len != 1 or (kind[0] != 'G' and kind[0] != 'T')) return error.MalformedCorpus;
            var rec: Record = .{ .kind = kind[0] };
            while (toks.next()) |tok| {
                if (rec.len == max_fields) return error.MalformedCorpus;
                rec.fields[rec.len] = tok;
                rec.len += 1;
            }
            if (rec.kind == 'T' and rec.len < 3) return error.MalformedCorpus;
            return rec;
        }
        return null;
    }
};

/// Decode a hex corpus field (`-` = empty) into arena memory.
fn unhex(a: std.mem.Allocator, field: []const u8) ![]u8 {
    if (std.mem.eql(u8, field, "-")) return &.{};
    if (field.len % 2 != 0) return error.MalformedCorpus;
    const out = try a.alloc(u8, field.len / 2);
    _ = std.fmt.hexToBytes(out, field) catch return error.MalformedCorpus;
    return out;
}

fn parseUsize(field: []const u8) !usize {
    return std.fmt.parseInt(usize, field, 10) catch error.MalformedCorpus;
}

/// Wycheproof encodes integers (RSA n/e, EC private scalars) as two's-complement
/// big-endian hex, so a positive value with its top bit set carries a leading
/// 0x00. Strip leading zero bytes to get the unsigned magnitude.
fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) i += 1;
    return bytes[i..];
}

// ── AEAD (AES-GCM, ChaCha20-Poly1305) via aead.Aead ──────────────────────────

fn aeadCase(
    comptime A: type,
    a: std.mem.Allocator,
    key_b: []const u8,
    iv_b: []const u8,
    aad: []const u8,
    msg: []const u8,
    ct: []const u8,
    tag_b: []const u8,
) !Outcome {
    if (key_b.len != A.key_length or iv_b.len != A.nonce_length) return .unsupported;
    // A tag of the wrong length can never authenticate; the fixed-size API
    // refuses it by type.
    if (tag_b.len != A.tag_length) return .reject;
    const key: A.Key = key_b[0..A.key_length].*;
    const nonce: A.Nonce = iv_b[0..A.nonce_length].*;
    const tag: A.Tag = tag_b[0..A.tag_length].*;

    var cipher = A.init(key);
    defer cipher.deinit();

    // Decrypt direction: this is the attacker-facing path.
    const pt = try a.alloc(u8, ct.len);
    cipher.open(nonce, aad, ct, tag, pt) catch return .reject;
    if (!std.mem.eql(u8, pt, msg)) return .wrong_output;

    // Encrypt direction: an accepted vector must also be reproducible.
    const ct2 = try a.alloc(u8, msg.len);
    const tag2 = cipher.seal(nonce, aad, msg, ct2) catch return .wrong_output;
    if (!std.mem.eql(u8, ct2, ct) or !std.mem.eql(u8, &tag2, &tag)) return .wrong_output;
    return .accept;
}

fn runAead(file: []const u8, text: []const u8, comptime chacha: bool) !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tally: Tally = .{ .file = file };
    var rd = Reader.init(text);
    var key_bits: usize = 0;
    var iv_bits: usize = 0;
    var tag_bits: usize = 0;
    while (try rd.next()) |rec| {
        if (rec.kind == 'G') {
            if (rec.len != 3) return error.MalformedCorpus;
            key_bits = try parseUsize(rec.fields[0]);
            iv_bits = try parseUsize(rec.fields[1]);
            tag_bits = try parseUsize(rec.fields[2]);
            continue;
        }
        if (rec.len != 9) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const key = try unhex(a, rec.arg(0));
        const iv = try unhex(a, rec.arg(1));
        const aad = try unhex(a, rec.arg(2));
        const msg = try unhex(a, rec.arg(3));
        const ct = try unhex(a, rec.arg(4));
        const tag = try unhex(a, rec.arg(5));
        // Cross-check the group header against the decoded field widths.
        if (key.len * 8 != key_bits or iv.len * 8 != iv_bits or tag_bits != 128) return error.MalformedCorpus;
        const expected = try rec.expected();

        var outcome: Outcome = undefined;
        if (chacha) {
            outcome = try aeadCase(aead.Aead(.chacha20_poly1305), a, key, iv, aad, msg, ct, tag);
        } else switch (key.len) {
            16 => outcome = try aeadCase(aead.Aead(.aes128_gcm), a, key, iv, aad, msg, ct, tag),
            32 => outcome = try aeadCase(aead.Aead(.aes256_gcm), a, key, iv, aad, msg, ct, tag),
            else => outcome = .unsupported, // AES-192: Armor has no 192-bit AES suite
        }
        tally.record(rec.tcId(), rec.flags(), expected, outcome);
    }
    return tally;
}

// ── X25519 via kx.X25519Kx ──────────────────────────────────────────────────

fn runX25519() !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tally: Tally = .{ .file = "x25519_test" };
    var rd = Reader.init(corpus.x25519);
    while (try rd.next()) |rec| {
        if (rec.kind != 'T' or rec.len != 6) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const public = try unhex(a, rec.arg(0));
        const private = try unhex(a, rec.arg(1));
        const shared = try unhex(a, rec.arg(2));
        if (public.len != 32 or private.len != 32 or shared.len != 32) return error.MalformedCorpus;

        const sk = kx.SecretKey.init(private[0..32].*);
        var outcome: Outcome = if (kx.X25519Kx.sharedSecret(&sk, public[0..32].*)) |ss|
            (if (std.mem.eql(u8, &ss.declassify(), shared)) .accept else .wrong_output)
        else |_|
            .reject;
        // Armor's contract (kx.zig `rejectAllZero`): the wrapper refuses exactly
        // the all-zero shared secret (RFC 7748 §6.1 contributory check) and
        // accepts every other input. Pin that precisely rather than letting
        // "acceptable" absorb either direction.
        const zero_shared = std.mem.indexOf(u8, rec.flags(), "ZeroSharedSecret") != null;
        if (zero_shared != (outcome == .reject)) outcome = .wrong_output;
        tally.record(rec.tcId(), rec.flags(), try rec.expected(), outcome);
    }
    return tally;
}

// ── ECDH P-256 via ecdh_p256.sharedSecret ───────────────────────────────────

fn runEcdhP256() !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tally: Tally = .{ .file = "ecdh_secp256r1_ecpoint_test" };
    var rd = Reader.init(corpus.ecdh_p256);
    while (try rd.next()) |rec| {
        if (rec.kind != 'T' or rec.len != 6) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const public = try unhex(a, rec.arg(0));
        const private_int = stripLeadingZeros(try unhex(a, rec.arg(1)));
        const shared = try unhex(a, rec.arg(2));
        const expected = try rec.expected();
        if (private_int.len > ecdh_p256.scalar_length) return error.MalformedCorpus;

        var outcome: Outcome = undefined;
        if (public.len != ecdh_p256.public_length) {
            // Armor's ECDH takes only an uncompressed SEC1 point; compressed or
            // empty encodings are refused by type.
            outcome = .unsupported;
        } else {
            var secret: [ecdh_p256.scalar_length]u8 = @splat(0);
            @memcpy(secret[secret.len - private_int.len ..], private_int);
            outcome = if (ecdh_p256.sharedSecret(secret, public[0..ecdh_p256.public_length].*)) |ss|
                (if (std.mem.eql(u8, &ss, shared)) .accept else .wrong_output)
            else |_|
                .reject;
        }
        tally.record(rec.tcId(), rec.flags(), expected, outcome);
    }
    return tally;
}

// ── ECDSA P-256 / SHA-256 via ecdsa_p256 (DER and P1363 signatures) ─────────

fn runEcdsaP256(file: []const u8, text: []const u8, comptime der: bool) !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tally: Tally = .{ .file = file };
    var rd = Reader.init(text);
    var pk: ?ecdsa_p256.PublicKey = null;
    var have_group = false;
    while (try rd.next()) |rec| {
        if (rec.kind == 'G') {
            if (rec.len != 1) return error.MalformedCorpus;
            var sec1: [ecdsa_p256.sec1_uncompressed_length]u8 = undefined;
            if (rec.fields[0].len != 2 * sec1.len) return error.MalformedCorpus;
            _ = std.fmt.hexToBytes(&sec1, rec.fields[0]) catch return error.MalformedCorpus;
            pk = ecdsa_p256.parsePublicKeySec1(&sec1) catch null;
            have_group = true;
            continue;
        }
        if (!have_group or rec.len != 5) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const msg = try unhex(a, rec.arg(0));
        const sig_bytes = try unhex(a, rec.arg(1));

        const outcome: Outcome = blk: {
            const key = pk orelse break :blk .reject;
            const sig: ecdsa_p256.Signature = if (der)
                ecdsa_p256.signatureFromDer(sig_bytes) catch break :blk .reject
            else sig: {
                if (sig_bytes.len != ecdsa_p256.raw_signature_length) break :blk .reject;
                break :sig ecdsa_p256.Signature.fromBytes(sig_bytes[0..ecdsa_p256.raw_signature_length].*);
            };
            break :blk if (ecdsa_p256.verify(sig, msg, key)) .accept else .reject;
        };
        tally.record(rec.tcId(), rec.flags(), try rec.expected(), outcome);
    }
    return tally;
}

// ── Ed25519 via sign.verify ─────────────────────────────────────────────────

fn runEd25519() !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tally: Tally = .{ .file = "ed25519_test" };
    var rd = Reader.init(corpus.ed25519);
    var pk: ?sign.PublicKey = null;
    while (try rd.next()) |rec| {
        if (rec.kind == 'G') {
            if (rec.len != 1) return error.MalformedCorpus;
            var buf: sign.PublicKey = undefined;
            if (rec.fields[0].len != 2 * buf.len) return error.MalformedCorpus;
            _ = std.fmt.hexToBytes(&buf, rec.fields[0]) catch return error.MalformedCorpus;
            pk = buf;
            continue;
        }
        const key = pk orelse return error.MalformedCorpus;
        if (rec.len != 5) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const msg = try unhex(a, rec.arg(0));
        const sig = try unhex(a, rec.arg(1));

        const outcome: Outcome = blk: {
            if (sig.len != sign.signature_len) break :blk .reject;
            const ok = sign.verify(msg, sig[0..sign.signature_len].*, key) catch break :blk .reject;
            break :blk if (ok) .accept else .reject;
        };
        tally.record(rec.tcId(), rec.flags(), try rec.expected(), outcome);
    }
    return tally;
}

// ── RSA PKCS#1 v1.5 and PSS (SHA-256) via rsa_verify ────────────────────────

fn runRsa(file: []const u8, text: []const u8, comptime pss: bool) !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var group_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer group_arena.deinit();
    var tally: Tally = .{ .file = file };
    var rd = Reader.init(text);
    var pub_key: ?rsa_verify.PublicKey = null;
    var salt_len: usize = 0;
    while (try rd.next()) |rec| {
        if (rec.kind == 'G') {
            if (rec.len != (if (pss) @as(usize, 3) else 2)) return error.MalformedCorpus;
            const ga = group_arena.allocator();
            pub_key = .{
                .n = stripLeadingZeros(try unhex(ga, rec.fields[0])),
                .e = stripLeadingZeros(try unhex(ga, rec.fields[1])),
            };
            if (pss) salt_len = try parseUsize(rec.fields[2]);
            continue;
        }
        const key = pub_key orelse return error.MalformedCorpus;
        if (rec.len != 5) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const msg = try unhex(a, rec.arg(0));
        const sig = try unhex(a, rec.arg(1));

        var msg_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(msg, &msg_hash, .{});
        const ok = if (pss)
            rsa_verify.verifyPss(key, .sha256, &msg_hash, sig, salt_len)
        else
            rsa_verify.verifyPkcs1v15(key, .sha256, &msg_hash, sig);
        tally.record(rec.tcId(), rec.flags(), try rec.expected(), if (ok) .accept else .reject);
    }
    return tally;
}

// ── HKDF-SHA-256 via hash.HkdfSha256 ────────────────────────────────────────

fn runHkdfSha256() !Tally {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var tally: Tally = .{ .file = "hkdf_sha256_test" };
    var rd = Reader.init(corpus.hkdf_sha256);
    while (try rd.next()) |rec| {
        if (rec.kind != 'T' or rec.len != 8) return error.MalformedCorpus;
        _ = arena.reset(.retain_capacity);
        const a = arena.allocator();
        const ikm = try unhex(a, rec.arg(0));
        const salt = try unhex(a, rec.arg(1));
        const info = try unhex(a, rec.arg(2));
        const size = try parseUsize(rec.arg(3));
        const okm = try unhex(a, rec.arg(4));
        const expected = try rec.expected();
        if (expected != .invalid and okm.len != size) return error.MalformedCorpus;

        const prk = hash.HkdfSha256.extractRaw(salt, ikm);
        const out = try a.alloc(u8, size);
        const outcome: Outcome = if (hash.HkdfSha256.expand(&prk, info, out)) |_|
            (if (std.mem.eql(u8, out, okm)) .accept else .wrong_output)
        else |_|
            .reject;
        tally.record(rec.tcId(), rec.flags(), expected, outcome);
    }
    return tally;
}

// ── Tests: one per upstream file, with exact pinned tallies ─────────────────

test "Wycheproof corpus: AES-GCM (aes_gcm_test)" {
    const t = try runAead("aes_gcm_test", corpus.aes_gcm, false);
    // 150 valid vectors are unexpressible (AES-192 groups, nonces other than
    // 96 bits); 33 invalid ones are refused by type for the same reasons.
    try t.expectCounts(.{ .total = 316, .valid_accepted = 79, .invalid_rejected = 54, .invalid_unexpressible = 33, .unsupported = 150 });
}

test "Wycheproof corpus: ChaCha20-Poly1305 (chacha20_poly1305_test)" {
    const t = try runAead("chacha20_poly1305_test", corpus.chacha20_poly1305, true);
    // 9 invalid vectors use a non-96-bit nonce and are refused by type.
    try t.expectCounts(.{ .total = 325, .valid_accepted = 256, .invalid_rejected = 60, .invalid_unexpressible = 9 });
}

test "Wycheproof corpus: X25519 (x25519_test)" {
    const t = try runX25519();
    // The 31 rejected `acceptable` vectors are exactly the ZeroSharedSecret
    // (low-order public key) cases; the driver enforces that correspondence.
    try t.expectCounts(.{ .total = 518, .valid_accepted = 264, .invalid_rejected = 0, .acceptable_accepted = 223, .acceptable_rejected = 31 });
}

test "Wycheproof corpus: ECDH P-256 (ecdh_secp256r1_ecpoint_test)" {
    const t = try runEcdhP256();
    // Compressed/empty points are not expressible (uncompressed SEC1 only):
    // 8 invalid ones are refused by type, 1 acceptable one is unsupported.
    try t.expectCounts(.{ .total = 355, .valid_accepted = 330, .invalid_rejected = 16, .invalid_unexpressible = 8, .unsupported = 1 });
}

test "Wycheproof corpus: ECDSA P-256 SHA-256 DER (ecdsa_secp256r1_sha256_test)" {
    const t = try runEcdsaP256("ecdsa_secp256r1_sha256_test", corpus.ecdsa_p256_der, true);
    try t.expectCounts(.{ .total = 484, .valid_accepted = 174, .invalid_rejected = 310 });
}

test "Wycheproof corpus: ECDSA P-256 SHA-256 P1363 (ecdsa_secp256r1_sha256_p1363_test)" {
    const t = try runEcdsaP256("ecdsa_secp256r1_sha256_p1363_test", corpus.ecdsa_p256_p1363, false);
    try t.expectCounts(.{ .total = 262, .valid_accepted = 173, .invalid_rejected = 89 });
}

test "Wycheproof corpus: Ed25519 (ed25519_test)" {
    const t = try runEd25519();
    // Rejected `acceptable`: the 8 SmallOrderPublicKey cases (strict key
    // check); the 21 MixedOrderPublicKey cases verify.
    try t.expectCounts(.{ .total = 210, .valid_accepted = 117, .invalid_rejected = 64, .acceptable_accepted = 21, .acceptable_rejected = 8 });
}

test "Wycheproof corpus: RSA PKCS#1 v1.5 2048 SHA-256 (rsa_signature_2048_sha256_test)" {
    const t = try runRsa("rsa_signature_2048_sha256_test", corpus.rsa_pkcs1, false);
    // The single `acceptable` vector (tcId 8, DigestInfo without its NULL
    // parameters) is rejected: Armor compares against the canonical encoding.
    try t.expectCounts(.{ .total = 259, .valid_accepted = 9, .invalid_rejected = 249, .acceptable_rejected = 1 });
}

test "Wycheproof corpus: RSA-PSS 2048 SHA-256 MGF1 salt 0 (rsa_pss_2048_sha256_mgf1_0_test)" {
    const t = try runRsa("rsa_pss_2048_sha256_mgf1_0_test", corpus.rsa_pss_0, true);
    try t.expectCounts(.{ .total = 103, .valid_accepted = 61, .invalid_rejected = 42 });
}

test "Wycheproof corpus: RSA-PSS 2048 SHA-256 MGF1 salt 32 (rsa_pss_2048_sha256_mgf1_32_test)" {
    const t = try runRsa("rsa_pss_2048_sha256_mgf1_32_test", corpus.rsa_pss_32, true);
    try t.expectCounts(.{ .total = 108, .valid_accepted = 63, .invalid_rejected = 45 });
}

test "Wycheproof corpus: HKDF-SHA-256 (hkdf_sha256_test)" {
    const t = try runHkdfSha256();
    try t.expectCounts(.{ .total = 86, .valid_accepted = 83, .invalid_rejected = 3 });
}

test "Wycheproof harness: any verdict disagreement or tally drift fails" {
    // Every illegal (expected, outcome) pair must count as a failure.
    const illegal = [_]struct { Expected, Outcome }{
        .{ .valid, .reject },            .{ .valid, .wrong_output },
        .{ .invalid, .accept },          .{ .invalid, .wrong_output },
        .{ .acceptable, .wrong_output },
    };
    for (illegal) |c| {
        var t: Tally = .{ .file = "self-test", .quiet = true };
        t.record("1", "-", c[0], c[1]);
        try testing.expectError(error.WycheproofMismatch, t.expectCounts(.{ .total = 1, .valid_accepted = 0, .invalid_rejected = 0 }));
    }

    // Legal outcomes land in their own buckets, and a pinned tally that does
    // not match exactly (here: one vector silently dropped) still fails.
    var t: Tally = .{ .file = "self-test", .quiet = true };
    t.record("1", "-", .valid, .accept);
    t.record("2", "-", .invalid, .reject);
    t.record("3", "-", .invalid, .unsupported);
    t.record("4", "-", .acceptable, .accept);
    t.record("5", "-", .acceptable, .reject);
    t.record("6", "-", .valid, .unsupported);
    try t.expectCounts(.{ .total = 6, .valid_accepted = 1, .invalid_rejected = 1, .invalid_unexpressible = 1, .acceptable_accepted = 1, .acceptable_rejected = 1, .unsupported = 1 });
    try testing.expectError(error.WycheproofTallyChanged, t.expectCounts(.{ .total = 5, .valid_accepted = 1, .invalid_rejected = 1, .invalid_unexpressible = 1, .acceptable_accepted = 1, .acceptable_rejected = 1 }));
}
