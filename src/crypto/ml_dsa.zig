// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ML-DSA (FIPS 204) signature VERIFICATION — from scratch, verify-only.
//!
//! Onyx Server verifies post-quantum certificate signatures; it never *signs* them,
//! so this module implements only `ML-DSA.Verify` / `ML-DSA.Verify_internal`
//! (FIPS 204 Algorithms 3 and 8). There is no key generation and no signing
//! here by design.
//!
//! 1.x permanently verifies and does not sign. A later signing implementation
//! requires NIST ACVP `sigGen` vectors and is not 1.x. There is no private
//! hybrid certificate profile.
//!
//! All three FIPS 204 parameter sets are supported, generic over a comptime
//! `Params` struct so the lattice/NTT/decode machinery is written once:
//!
//!   set         (k,l)  η   τ    γ1     γ2         ω   λ   pk      sig
//!   ML-DSA-44   (4,4)  2   39   2^17   (q−1)/88   80  128 1312    2420
//!   ML-DSA-65   (6,5)  4   49   2^19   (q−1)/32   55  192 1952    3309
//!   ML-DSA-87   (8,7)  2   60   2^19   (q−1)/32   75  256 2592    4627
//!
//! Shared across every set: q = 8380417, n = 256, d = 13, ζ = 1753, β = τ·η.
//! c̃ is 2λ/8 bytes; z is BitPack(γ1−1, γ1) at bitlen(2γ1−1) bits/coeff; w1 is
//! SimpleBitPack at bitlen((q−1)/(2γ2)−1) bits/coeff.
//!
//! Arithmetic strategy: this is a *verifier* run on public data (certificate
//! chains), not a hot path, and not secret-dependent, so correctness-by-
//! construction beats cleverness. All modular reduction uses a plain `% q`
//! (no Montgomery/Barrett), which removes an entire class of subtle reduction
//! bugs. There is no secret input, so there is no constant-time requirement.
//!
//! Correctness is pinned by INDEPENDENT NIST ACVP FIPS 204 sigVer vectors:
//! `ml_dsa_kat.zig` (ML-DSA-65) and `ml_dsa_variants_kat.zig` (ML-DSA-44/87).
//! A plausible-but-wrong lattice verifier would fail those accept vectors,
//! which is exactly why the KAT — not this code's own output — is the gate.
//!
//! References: FIPS 204 (final, 2024). Algorithm numbers cited inline.

const std = @import("std");
const Shake128 = std.crypto.hash.sha3.Shake128;
const Shake256 = std.crypto.hash.sha3.Shake256;

// ── Shared field / ring constants (identical for all parameter sets) ─────────

/// Modulus q = 2^23 − 2^13 + 1.
pub const Q: u32 = 8380417;
/// Ring degree.
pub const N: usize = 256;
/// Dropped low bits of t.
pub const D: u32 = 13;

/// Bit-length of `v` (number of bits to represent it; `bitLen(0) == 0`).
fn bitLen(v: u64) u6 {
    var n: u6 = 0;
    var x = v;
    while (x != 0) : (x >>= 1) n += 1;
    return n;
}

// ── Parameter set ────────────────────────────────────────────────────────────

/// A FIPS 204 parameter set. Only the values that actually differ between the
/// three sets are stored; every other quantity (bit widths, encoded lengths,
/// the UseHint modulus) is *derived* here so a mistyped field cannot silently
/// desynchronize the packer from the byte-length checks.
pub const Params = struct {
    name: []const u8,
    /// Matrix rows.
    k: usize,
    /// Matrix columns / z length.
    l: usize,
    /// Number of ±1 coefficients in the challenge polynomial c.
    tau: usize,
    /// Rejection bound β = τ·η.
    beta: i32,
    /// γ1 (a power of two).
    gamma1: i32,
    /// γ2 = (q−1)/(2·m) where m is the UseHint modulus.
    gamma2: i32,
    /// Max hint weight ω.
    omega: usize,
    /// c̃ length in bytes (2λ/8).
    ctilde_len: usize,

    /// Bits per z coefficient: BitPack(γ1−1, γ1) uses bitlen(2γ1−1).
    fn zBits(comptime P: Params) u6 {
        return bitLen(@intCast(2 * P.gamma1 - 1));
    }
    /// UseHint / w1 modulus m = (q−1)/(2γ2) (16 for 65/87, 44 for 44).
    fn useHintMod(comptime P: Params) i32 {
        return @intCast(@divExact(@as(i64, Q) - 1, 2 * @as(i64, P.gamma2)));
    }
    /// Bits per w1 coefficient: SimpleBitPack(m−1) uses bitlen(m−1).
    fn w1Bits(comptime P: Params) u6 {
        return bitLen(@intCast(P.useHintMod() - 1));
    }
    /// Encoded public-key length (ρ ‖ t1 packed at 10 bits/coeff).
    fn publicKeyLen(comptime P: Params) usize {
        return 32 + P.k * N * 10 / 8;
    }
    /// Encoded signature length (c̃ ‖ z ‖ h).
    fn signatureLen(comptime P: Params) usize {
        return P.ctilde_len + P.l * N * @as(usize, P.zBits()) / 8 + (P.omega + P.k);
    }
    /// w1Encode output length.
    fn w1EncLen(comptime P: Params) usize {
        return P.k * N * @as(usize, P.w1Bits()) / 8;
    }
};

/// ML-DSA-44 (a.k.a. Dilithium2), NIST Category 2.
pub const params_44 = Params{
    .name = "ML-DSA-44",
    .k = 4,
    .l = 4,
    .tau = 39,
    .beta = 39 * 2, // τ·η
    .gamma1 = 1 << 17,
    .gamma2 = (@as(i32, @intCast(Q)) - 1) / 88,
    .omega = 80,
    .ctilde_len = 32, // 2λ/8, λ = 128
};

/// ML-DSA-65 (a.k.a. Dilithium3), NIST Category 3.
pub const params_65 = Params{
    .name = "ML-DSA-65",
    .k = 6,
    .l = 5,
    .tau = 49,
    .beta = 49 * 4, // τ·η
    .gamma1 = 1 << 19,
    .gamma2 = (@as(i32, @intCast(Q)) - 1) / 32,
    .omega = 55,
    .ctilde_len = 48, // 2λ/8, λ = 192
};

/// ML-DSA-87 (a.k.a. Dilithium5), NIST Category 5.
pub const params_87 = Params{
    .name = "ML-DSA-87",
    .k = 8,
    .l = 7,
    .tau = 60,
    .beta = 60 * 2, // τ·η
    .gamma1 = 1 << 19,
    .gamma2 = (@as(i32, @intCast(Q)) - 1) / 32,
    .omega = 75,
    .ctilde_len = 64, // 2λ/8, λ = 256
};

comptime {
    // Byte-length invariants, derived independently of the FIPS 204 spec tables
    // so a mistyped parameter is caught at compile time rather than by a KAT.
    std.debug.assert(params_44.publicKeyLen() == 1312 and params_44.signatureLen() == 2420);
    std.debug.assert(params_65.publicKeyLen() == 1952 and params_65.signatureLen() == 3309);
    std.debug.assert(params_87.publicKeyLen() == 2592 and params_87.signatureLen() == 4627);
    // z/w1 bit widths and the UseHint modulus per set.
    std.debug.assert(params_44.zBits() == 18 and params_44.w1Bits() == 6 and params_44.useHintMod() == 44);
    std.debug.assert(params_65.zBits() == 20 and params_65.w1Bits() == 4 and params_65.useHintMod() == 16);
    std.debug.assert(params_87.zBits() == 20 and params_87.w1Bits() == 4 and params_87.useHintMod() == 16);
}

// ── Back-compat aliases for the ML-DSA-65 public surface ─────────────────────
// The pre-existing ML-DSA-65 verifier exposed these three constants; keep them
// so `ml_dsa_kat.zig` and any 65-only caller compile unchanged.

/// c̃ length in bytes for ML-DSA-65.
pub const CTILDE_LEN: usize = params_65.ctilde_len;
/// Encoded ML-DSA-65 public-key length.
pub const public_key_len: usize = params_65.publicKeyLen();
/// Encoded ML-DSA-65 signature length.
pub const signature_len: usize = params_65.signatureLen();

// ── Modular arithmetic in canonical [0, q) ──────────────────────────────────

inline fn addQ(a: u32, b: u32) u32 {
    const s = a + b; // a,b < q < 2^23 ⇒ s < 2^24, no overflow
    return if (s >= Q) s - Q else s;
}

inline fn subQ(a: u32, b: u32) u32 {
    return if (a >= b) a - b else a + Q - b;
}

inline fn mulQ(a: u32, b: u32) u32 {
    return @intCast((@as(u64, a) * @as(u64, b)) % Q);
}

/// Reduce a signed value into canonical [0, q).
inline fn canon(v: i64) u32 {
    const m = @mod(v, @as(i64, Q));
    return @intCast(m);
}

fn modpow(base: u64, exp: u64) u32 {
    var result: u64 = 1;
    var b = base % Q;
    var e = exp;
    while (e > 0) : (e >>= 1) {
        if (e & 1 == 1) result = (result * b) % Q;
        b = (b * b) % Q;
    }
    return @intCast(result);
}

/// n^{-1} mod q, for the inverse-NTT final scaling.
const N_INV: u32 = modpow(N, Q - 2);

comptime {
    std.debug.assert(@as(u64, N_INV) * N % Q == 1);
}

// ── NTT tables (q, n and ζ are shared, so one table serves every set) ────────

/// ζ = 1753 is a primitive 512-th root of unity mod q (FIPS 204).
const ZETA: u64 = 1753;

/// Bit-reverse the low 8 bits of `x`.
fn brv8(x: usize) usize {
    var r: usize = 0;
    var v = x;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    return r;
}

/// ZETAS[i] = ζ^{brv8(i)} mod q — the standard Dilithium negacyclic-NTT table.
const ZETAS: [256]u32 = blk: {
    @setEvalBranchQuota(100000);
    var t: [256]u32 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) t[i] = modpow(ZETA, brv8(i));
    break :blk t;
};

comptime {
    // ζ is a primitive 512-th root: ζ^256 ≡ −1 (mod q), ζ^512 ≡ 1.
    std.debug.assert(modpow(ZETA, 256) == Q - 1);
    std.debug.assert(modpow(ZETA, 512) == 1);
}

/// A polynomial with coefficients in canonical [0, q).
const Poly = [N]u32;

/// Forward NTT in place (Cooley-Tukey), matching the Dilithium reference
/// ordering: `t = ζ·a[j+len]; a[j+len] = a[j]−t; a[j] = a[j]+t`.
fn nttForward(a: *Poly) void {
    var k: usize = 0;
    var len: usize = 128;
    while (len >= 1) : (len >>= 1) {
        var start: usize = 0;
        while (start < N) : (start += 2 * len) {
            k += 1;
            const zeta = ZETAS[k];
            var j = start;
            while (j < start + len) : (j += 1) {
                const t = mulQ(zeta, a[j + len]);
                a[j + len] = subQ(a[j], t);
                a[j] = addQ(a[j], t);
            }
        }
    }
}

/// Inverse NTT in place (Gentleman-Sande), then scale by n^{-1}.
fn nttInverse(a: *Poly) void {
    var k: usize = 256;
    var len: usize = 1;
    while (len < N) : (len <<= 1) {
        var start: usize = 0;
        while (start < N) : (start += 2 * len) {
            k -= 1;
            const zeta = Q - ZETAS[k]; // −ζ mod q; ZETAS[k] ∈ [1,q) ⇒ result ∈ [1,q)
            var j = start;
            while (j < start + len) : (j += 1) {
                const t = a[j];
                a[j] = addQ(t, a[j + len]);
                a[j + len] = mulQ(zeta, subQ(t, a[j + len]));
            }
        }
    }
    for (a) |*x| x.* = mulQ(x.*, N_INV);
}

inline fn pointwise(a: Poly, b: Poly) Poly {
    var c: Poly = undefined;
    for (0..N) |i| c[i] = mulQ(a[i], b[i]);
    return c;
}

// ── Bit-level pack/unpack (FIPS 204 §7) ─────────────────────────────────────

/// LSB-first bit reader over a fixed byte slice (matches IntegerToBits, which is
/// little-endian within the stream).
const BitReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    buf: u64 = 0,
    bits: u6 = 0,

    fn read(self: *BitReader, c: u6) u32 {
        while (self.bits < c) {
            self.buf |= @as(u64, self.bytes[self.pos]) << self.bits;
            self.pos += 1;
            self.bits += 8;
        }
        const mask = (@as(u64, 1) << c) - 1;
        const v: u32 = @intCast(self.buf & mask);
        self.buf >>= c;
        self.bits -= c;
        return v;
    }
};

/// LSB-first bit writer into a caller-provided output slice.
const BitWriter = struct {
    out: []u8,
    pos: usize = 0,
    buf: u64 = 0,
    bits: u6 = 0,

    fn write(self: *BitWriter, val: u32, c: u6) void {
        self.buf |= @as(u64, val) << self.bits;
        self.bits += c;
        while (self.bits >= 8) {
            self.out[self.pos] = @truncate(self.buf & 0xff);
            self.pos += 1;
            self.buf >>= 8;
            self.bits -= 8;
        }
    }
};

/// SimpleBitUnpack(v) with `bits`-bit coefficients (Algorithm 18).
fn simpleBitUnpack(v: []const u8, comptime bits: u6) Poly {
    var r = BitReader{ .bytes = v };
    var out: Poly = undefined;
    for (0..N) |i| out[i] = r.read(bits);
    return out;
}

// ── Public-key decode (Algorithm 22 pkDecode) ───────────────────────────────

/// Decode t1 (the k high-half polynomials) from the public key. ρ is the first
/// 32 bytes; each t1_i is SimpleBitPack'd with 10-bit coefficients (320 bytes).
fn decodeT1(comptime P: Params, pk: []const u8) [P.k]Poly {
    var t1: [P.k]Poly = undefined;
    const stride = N * 10 / 8; // 320
    for (0..P.k) |i| {
        const off = 32 + i * stride;
        t1[i] = simpleBitUnpack(pk[off .. off + stride], 10);
    }
    return t1;
}

// ── Signature decode (Algorithm 26 sigDecode) ───────────────────────────────

/// The decoded (c̃, z, h) for a parameter set. A function-returned type keeps the
/// array dimensions pinned to `P` without runtime slices.
fn DecodedSig(comptime P: Params) type {
    return struct {
        ctilde: [P.ctilde_len]u8,
        /// z as signed coefficients (BitUnpack, a = γ1−1, b = γ1).
        z: [P.l][N]i32,
        /// Hint bits per polynomial (0/1).
        h: [P.k][N]u1,
    };
}

const DecodeError = error{InvalidHint};

/// Decode c̃, z, and the hint h. Returns `error.InvalidHint` when HintBitUnpack
/// rejects the hint encoding (the FIPS 204 ⊥ case) — the caller treats this as a
/// verification failure.
fn decodeSig(comptime P: Params, sig: []const u8) DecodeError!DecodedSig(P) {
    var out: DecodedSig(P) = undefined;
    @memcpy(&out.ctilde, sig[0..P.ctilde_len]);

    // z: l polynomials, BitUnpack with zBits-bit values, w_i = γ1 − value.
    const z_bits = P.zBits();
    const z_stride = N * @as(usize, z_bits) / 8;
    var off: usize = P.ctilde_len;
    for (0..P.l) |j| {
        var r = BitReader{ .bytes = sig[off .. off + z_stride] };
        for (0..N) |i| {
            const value: i32 = @intCast(r.read(z_bits));
            out.z[j][i] = P.gamma1 - value;
        }
        off += z_stride;
    }

    // h: HintBitUnpack over the trailing (ω + k) bytes (Algorithm 21).
    const y = sig[off .. off + P.omega + P.k];
    for (0..P.k) |i| @memset(&out.h[i], 0);
    var index: usize = 0;
    for (0..P.k) |i| {
        const end: usize = y[P.omega + i];
        if (end < index or end > P.omega) return error.InvalidHint;
        const first = index;
        while (index < end) {
            if (index > first and y[index - 1] >= y[index]) return error.InvalidHint;
            out.h[i][y[index]] = 1;
            index += 1;
        }
    }
    // Remaining hint slots must be zero padding.
    var p = index;
    while (p < P.omega) : (p += 1) {
        if (y[p] != 0) return error.InvalidHint;
    }
    return out;
}

/// ‖z‖∞ over every signed z coefficient (any `[l][256]i32`).
fn zInfNorm(z: anytype) i32 {
    var m: i32 = 0;
    for (z) |poly| {
        for (poly) |c| {
            const a = if (c < 0) -c else c;
            if (a > m) m = a;
        }
    }
    return m;
}

// ── ExpandA (Algorithm 32) + RejNTTPoly (Algorithm 30) ──────────────────────

/// CoeffFromThreeBytes (Algorithm 14): clear the top bit of b2, assemble a
/// 23-bit little-endian integer, reject if ≥ q.
inline fn coeffFromThreeBytes(b0: u8, b1: u8, b2: u8) ?u32 {
    const z: u32 = @as(u32, b0) | (@as(u32, b1) << 8) | (@as(u32, b2 & 0x7f) << 16);
    return if (z < Q) z else null;
}

/// RejNTTPoly: sample one NTT-domain polynomial by rejection from SHAKE128(seed).
fn rejNttPoly(seed: []const u8) Poly {
    var xof = Shake128.init(.{});
    xof.update(seed);
    var out: Poly = undefined;
    var j: usize = 0;
    var block: [168]u8 = undefined; // SHAKE128 rate
    while (j < N) {
        xof.squeeze(&block);
        var i: usize = 0;
        while (i + 3 <= block.len and j < N) : (i += 3) {
            if (coeffFromThreeBytes(block[i], block[i + 1], block[i + 2])) |c| {
                out[j] = c;
                j += 1;
            }
        }
    }
    return out;
}

/// Â[r][s] = RejNTTPoly(ρ ‖ IntegerToBytes(s,1) ‖ IntegerToBytes(r,1)). Emits the
/// L polynomials of a single row `r`.
fn expandARow(comptime P: Params, rho: []const u8, r: usize, row: *[P.l]Poly) void {
    var seed: [34]u8 = undefined;
    @memcpy(seed[0..32], rho[0..32]);
    seed[33] = @intCast(r);
    for (0..P.l) |s| {
        seed[32] = @intCast(s);
        row[s] = rejNttPoly(&seed);
    }
}

// ── SampleInBall (Algorithm 29) ─────────────────────────────────────────────

/// Sample the challenge polynomial c (τ nonzero ±1 coefficients) from c̃. The
/// 8-byte sign block holds 64 bits, enough for every set's τ ≤ 64.
fn sampleInBall(comptime P: Params, ctilde: []const u8) Poly {
    var xof = Shake256.init(.{});
    xof.update(ctilde);
    var signs: [8]u8 = undefined;
    xof.squeeze(&signs);

    var c: Poly = @splat(0);
    var i: usize = N - P.tau;
    while (i < N) : (i += 1) {
        var jb: [1]u8 = undefined;
        xof.squeeze(&jb);
        while (jb[0] > i) xof.squeeze(&jb);
        const j = jb[0];
        c[i] = c[j];
        const bit_index = i + P.tau - N;
        const bit: u1 = @intCast((signs[bit_index >> 3] >> @intCast(bit_index & 7)) & 1);
        c[j] = if (bit == 0) 1 else Q - 1; // +1 or −1
    }
    return c;
}

// ── Decompose / UseHint / w1Encode (Algorithms 36, 40, 28) ──────────────────

const Decomposed = struct { r1: i32, r0: i32 };

/// Decompose r (canonical [0,q)) into (r1, r0) with r0 = r mod± 2γ2 and the
/// FIPS 204 top-bucket special case.
fn decompose(comptime P: Params, r: u32) Decomposed {
    const two_g2: i32 = 2 * P.gamma2;
    var r0: i32 = @intCast(@rem(@as(i64, r), @as(i64, two_g2))); // [0, 2γ2)
    if (r0 > P.gamma2) r0 -= two_g2; // (−γ2, γ2]
    const rp: i32 = @intCast(r);
    if (rp - r0 == @as(i32, @intCast(Q)) - 1) {
        return .{ .r1 = 0, .r0 = r0 - 1 };
    }
    const r1: i32 = @intCast(@divExact(@as(i64, rp) - r0, two_g2));
    return .{ .r1 = r1, .r0 = r0 };
}

/// UseHint(hbit, r) → recovered high bits (Algorithm 40). The wrap modulus is
/// m = (q−1)/(2γ2) (16 for ML-DSA-65/87, 44 for ML-DSA-44).
inline fn useHint(comptime P: Params, hbit: u1, r: u32) u32 {
    const d = decompose(P, r);
    if (hbit == 0) return @intCast(d.r1);
    const adjusted: i32 = if (d.r0 > 0) d.r1 + 1 else d.r1 - 1;
    return @intCast(@mod(adjusted, P.useHintMod()));
}

/// w1Encode: SimpleBitPack each of the k w1 polynomials with w1Bits-bit
/// coefficients, concatenated into `out` (Algorithm 28).
fn w1Encode(comptime P: Params, w1: [P.k]Poly, out: []u8) void {
    var w = BitWriter{ .out = out };
    const bits = P.w1Bits();
    for (w1) |poly| {
        for (poly) |c| w.write(c, bits);
    }
}

// ── Verify ──────────────────────────────────────────────────────────────────

/// `ML-DSA.Verify_internal` (FIPS 204 Algorithm 8) for parameter set `P` over
/// the internal message `m_prime` (already domain-separated). Returns `true` on
/// a valid signature, `false` on any structural or cryptographic failure. Never
/// errors, never panics on attacker-controlled input.
pub fn verifyInternalFor(comptime P: Params, pk: []const u8, m_prime: []const u8, sig: []const u8) bool {
    return verifyInternalParts(P, pk, &.{m_prime}, sig);
}

/// Like `verifyInternalFor`, but the internal message is provided as an ordered
/// set of byte slices concatenated in place (avoids materializing a large M′).
fn verifyInternalParts(comptime P: Params, pk: []const u8, m_parts: []const []const u8, sig: []const u8) bool {
    if (pk.len != P.publicKeyLen()) return false;
    if (sig.len != P.signatureLen()) return false;

    const rho = pk[0..32];
    const t1 = decodeT1(P, pk);
    const dec = decodeSig(P, sig) catch return false; // ⊥ hint ⇒ reject

    // ‖z‖∞ < γ1 − β.
    if (zInfNorm(dec.z) >= P.gamma1 - P.beta) return false;

    // tr = H(pk, 64); μ = H(tr ‖ M′, 64).
    var tr: [64]u8 = undefined;
    {
        var h = Shake256.init(.{});
        h.update(pk);
        h.squeeze(&tr);
    }
    var mu: [64]u8 = undefined;
    {
        var h = Shake256.init(.{});
        h.update(&tr);
        for (m_parts) |part| h.update(part);
        h.squeeze(&mu);
    }

    // c ← SampleInBall(c̃); ĉ ← NTT(c).
    var c = sampleInBall(P, &dec.ctilde);
    nttForward(&c);

    // NTT(z_j) for each column.
    var z_ntt: [P.l]Poly = undefined;
    for (0..P.l) |j| {
        for (0..N) |i| z_ntt[j][i] = canon(dec.z[j][i]);
        nttForward(&z_ntt[j]);
    }

    // NTT(t1_i · 2^d) for each row.
    var t1d_ntt: [P.k]Poly = undefined;
    for (0..P.k) |i| {
        for (0..N) |n| t1d_ntt[i][n] = mulQ(t1[i][n], @as(u32, 1) << @intCast(D));
        nttForward(&t1d_ntt[i]);
    }

    // w′Approx = NTT⁻¹(Â∘NTT(z) − ĉ∘NTT(t1·2^d)); then w1 = UseHint(h, w′Approx).
    var w1: [P.k]Poly = undefined;
    var arow: [P.l]Poly = undefined;
    for (0..P.k) |i| {
        expandARow(P, rho, i, &arow);
        var acc: Poly = @splat(0);
        for (0..P.l) |j| {
            const prod = pointwise(arow[j], z_ntt[j]);
            for (0..N) |n| acc[n] = addQ(acc[n], prod[n]);
        }
        const ct1 = pointwise(c, t1d_ntt[i]);
        for (0..N) |n| acc[n] = subQ(acc[n], ct1[n]);
        nttInverse(&acc);
        for (0..N) |n| w1[i][n] = useHint(P, dec.h[i][n], acc[n]);
    }

    // c̃′ = H(μ ‖ w1Encode(w1), 2λ/8).
    var w1_enc: [P.w1EncLen()]u8 = undefined;
    w1Encode(P, w1, &w1_enc);
    var ctilde_prime: [P.ctilde_len]u8 = undefined;
    {
        var h = Shake256.init(.{});
        h.update(&mu);
        h.update(&w1_enc);
        h.squeeze(&ctilde_prime);
    }

    return ctEqual(&dec.ctilde, &ctilde_prime);
}

/// `ML-DSA.Verify(pk, M, sig, ctx)` for parameter set `P` (FIPS 204 Algorithm
/// 3), pure (non-prehashed) variant. `ctx` is the context string (empty for
/// X.509 certificate signatures per draft-ietf-lamps-dilithium-certificates).
/// Returns `false` on any failure, including `ctx.len > 255`.
pub fn verify(comptime P: Params, pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
    if (ctx.len > 255) return false;
    // M′ = IntegerToBytes(0,1) ‖ IntegerToBytes(|ctx|,1) ‖ ctx ‖ M.
    const prefix = [2]u8{ 0x00, @intCast(ctx.len) };
    return verifyInternalParts(P, pk, &.{ &prefix, ctx, msg }, sig);
}

// ── Per-set convenience wrappers ─────────────────────────────────────────────

/// ML-DSA-44 pure Verify.
pub fn verify44(pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
    return verify(params_44, pk, msg, ctx, sig);
}
/// ML-DSA-65 pure Verify.
pub fn verify65(pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
    return verify(params_65, pk, msg, ctx, sig);
}
/// ML-DSA-87 pure Verify.
pub fn verify87(pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
    return verify(params_87, pk, msg, ctx, sig);
}

/// ML-DSA-65 Verify_internal (back-compat name; equals `verifyInternalFor(params_65,…)`).
pub fn verifyInternal(pk: []const u8, m_prime: []const u8, sig: []const u8) bool {
    return verifyInternalFor(params_65, pk, m_prime, sig);
}

/// Length-checked, timing-independent byte compare. (All inputs here are public,
/// so this is hygiene, not a secret-dependency requirement.)
fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

test "ml-dsa parameter and NTT self-consistency (all sets)" {
    // Cheap invariants that would surface a mistyped constant before the
    // (expensive) KATs run. Independent published-vector KATs live in
    // ml_dsa_kat.zig (65) and ml_dsa_variants_kat.zig (44/87).
    try std.testing.expectEqual(@as(i32, 261888), params_65.gamma2);
    try std.testing.expectEqual(@as(i32, 524288), params_65.gamma1);
    try std.testing.expectEqual(@as(i32, 95232), params_44.gamma2);
    try std.testing.expectEqual(@as(i32, 131072), params_44.gamma1);
    // γ2·2·m == q−1 for every set.
    inline for (.{ params_44, params_65, params_87 }) |P| {
        try std.testing.expectEqual(@as(i64, Q) - 1, 2 * @as(i64, P.gamma2) * P.useHintMod());
    }
    // NTT round-trip on a spread of coefficients is the identity (q/n/ζ shared).
    var p: Poly = undefined;
    for (0..N) |i| p[i] = @intCast((i * 7919 + 13) % Q);
    const orig = p;
    nttForward(&p);
    nttInverse(&p);
    try std.testing.expectEqualSlices(u32, &orig, &p);
}
