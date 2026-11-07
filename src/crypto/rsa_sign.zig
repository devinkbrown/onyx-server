// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clean-room RSA signature generation (private-key operations).
//!
//! Implements RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.1 / §9.2) and RSASSA-PSS
//! (§8.1.1 / §9.1.1) for SHA-256/384/512 digests, using the verifier module's
//! fixed-capacity bignum and modular exponentiation primitives.
//!
//! Side-channel posture: this module performs RFC-standard RSA base blinding
//! before every private operation: m' = m * r^e mod n, s' = (m')^d mod n,
//! s = s' * r^-1 mod n. That randomizes the modular exponentiation base for
//! both CRT and non-CRT signing paths. The underlying fixed-capacity bignum
//! multiply, reduction, inverse, and exponentiation routines remain
//! variable-time; blinding is the primary defense against remote timing leakage
//! from secret-exponent private operations.
//!
//! Fault posture: every private operation (CRT and non-CRT) is re-verified
//! before the signature leaves this module. The unblinded signature `s` is
//! raised to the public exponent and compared with the encoded representative;
//! on mismatch the output buffer is wiped and `error.SignatureFault` is
//! returned. This closes the Bellcore/Lenstra attack in which a single induced
//! fault in one CRT branch yields gcd(s^e - m, n) = p or q.

const std = @import("std");
const builtin = @import("builtin");
const crypto_random = @import("random.zig");
const rsa_verify = @import("rsa_verify.zig");

const Big = rsa_verify.Big;

/// Errors returned by RSA signing.
pub const Error = rsa_verify.Error || crypto_random.Error || error{
    /// The private key is empty, internally inconsistent, or has partial CRT
    /// parameters.
    InvalidKey,
    /// The digest/salt/message representative is invalid for the requested
    /// signature scheme and key size.
    InvalidInput,
    /// The private operation produced a signature that does not verify under
    /// the public key (s^e mod n != m). Either the key material is
    /// inconsistent or a computational fault occurred; the faulty signature is
    /// never released because it could leak a prime factor.
    SignatureFault,
};

/// Test-only fault injection point for the private operation. Production
/// builds compile this to `void`, so no fault can be injected outside tests.
const FaultInjection = enum { none, crt_m1, crt_m2, non_crt };
threadlocal var test_fault: if (builtin.is_test) FaultInjection else void =
    if (builtin.is_test) .none else {};

fn injectedFault() FaultInjection {
    return if (builtin.is_test) test_fault else .none;
}

/// Big-endian RSA private key material.
///
/// `n`, `e`, and `d` are required. CRT parameters are optional, but if any CRT
/// parameter is provided then all of `p`, `q`, `dp`, `dq`, and `qinv` must be
/// present. `qinv` is q^-1 mod p, matching RFC 8017's two-prime CRT form:
/// m1=c^dp mod p, m2=c^dq mod q, h=(qinv*(m1-m2)) mod p, m=m2+q*h.
pub const PrivateKey = struct {
    /// Big-endian modulus.
    n: []const u8,
    /// Big-endian public exponent.
    e: []const u8,
    /// Big-endian private exponent.
    d: []const u8,
    /// Big-endian first prime.
    p: ?[]const u8 = null,
    /// Big-endian second prime.
    q: ?[]const u8 = null,
    /// Big-endian first CRT exponent, d mod (p - 1).
    dp: ?[]const u8 = null,
    /// Big-endian second CRT exponent, d mod (q - 1).
    dq: ?[]const u8 = null,
    /// Big-endian CRT coefficient, q^-1 mod p.
    qinv: ?[]const u8 = null,
};

/// RSASSA-PKCS1-v1_5 signature generation (RFC 8017 §8.2.1).
///
/// `digest` must already be the hash selected by `alg`. `out` must have room
/// for `priv.n.len` bytes. The returned slice aliases `out[0..priv.n.len]`.
pub fn signPkcs1v15(priv: PrivateKey, alg: rsa_verify.HashAlg, digest: []const u8, out: []u8) Error![]const u8 {
    try validatePrivateKey(priv);
    if (digest.len != alg.digestLen()) return error.InvalidInput;

    const k = priv.n.len;
    if (out.len < k) return error.NoSpaceLeft;

    const prefix = digestInfoPrefix(alg);
    const t_len = prefix.len + digest.len;
    if (k < t_len + 11) return error.InvalidInput;

    var em: [rsa_verify.max_bytes]u8 = undefined;
    em[0] = 0x00;
    em[1] = 0x01;
    const ps_len = k - t_len - 3;
    @memset(em[2 .. 2 + ps_len], 0xff);
    em[2 + ps_len] = 0x00;
    @memcpy(em[3 + ps_len ..][0..prefix.len], prefix);
    @memcpy(em[3 + ps_len + prefix.len ..][0..digest.len], digest);

    return privateOp(priv, em[0..k], out);
}

/// RSASSA-PSS signature generation (RFC 8017 §8.1.1).
///
/// `mhash` must already be the hash selected by `alg`. `salt` is supplied by
/// the caller to make tests deterministic; production callers must pass a fresh
/// unpredictable salt for each signature. `out` must have room for
/// `priv.n.len` bytes. The returned slice aliases `out[0..priv.n.len]`.
pub fn signPss(priv: PrivateKey, alg: rsa_verify.HashAlg, mhash: []const u8, salt: []const u8, out: []u8) Error![]const u8 {
    try validatePrivateKey(priv);

    const h_len = alg.digestLen();
    if (mhash.len != h_len) return error.InvalidInput;
    if (salt.len > rsa_verify.max_bytes) return error.InvalidInput;

    const k = priv.n.len;
    if (out.len < k) return error.NoSpaceLeft;

    const n_big = try Big.fromBytesBE(priv.n);
    const mod_bits = n_big.bitLen();
    if (mod_bits == 0) return error.InvalidKey;
    const em_bits = mod_bits - 1;
    const em_len = (em_bits + 7) / 8;
    if (em_len > k or em_len > rsa_verify.max_bytes) return error.InvalidKey;
    if (em_len < h_len + salt.len + 2) return error.InvalidInput;

    var mprime: [8 + 64 + rsa_verify.max_bytes]u8 = undefined;
    @memset(mprime[0..8], 0);
    @memcpy(mprime[8..][0..h_len], mhash);
    @memcpy(mprime[8 + h_len ..][0..salt.len], salt);

    var h: [64]u8 = undefined;
    hashOf(alg, mprime[0 .. 8 + h_len + salt.len], h[0..h_len]);

    const db_len = em_len - h_len - 1;
    const ps_len = db_len - salt.len - 1;
    var em: [rsa_verify.max_bytes]u8 = undefined;
    const db = em[0..db_len];
    @memset(db[0..ps_len], 0);
    db[ps_len] = 0x01;
    @memcpy(db[ps_len + 1 ..][0..salt.len], salt);

    // `mgf1` XORs its output into the supplied mask buffer, so this turns DB
    // into maskedDB in place.
    rsa_verify.mgf1(alg, h[0..h_len], db);

    const top_bits: u3 = @intCast(8 * em_len - em_bits);
    if (top_bits != 0) {
        const keep: u8 = @as(u8, 0xff) >> @intCast(top_bits);
        em[0] &= keep;
    }
    @memcpy(em[db_len..][0..h_len], h[0..h_len]);
    em[em_len - 1] = 0xbc;

    return privateOp(priv, em[0..em_len], out);
}

fn privateOp(priv: PrivateKey, representative: []const u8, out: []u8) Error![]const u8 {
    const k = priv.n.len;
    if (out.len < k) return error.NoSpaceLeft;

    const n_big = try Big.fromBytesBE(priv.n);
    if (n_big.isZero() or n_big.limbs[0] & 1 == 0) return error.InvalidKey;
    const m_big = try Big.fromBytesBE(representative);
    if (m_big.cmp(&n_big) != .lt) return error.InvalidInput;

    var rinv = Big{};
    var blinded: [rsa_verify.max_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &blinded);
    try blindRepresentative(priv, &n_big, &m_big, blinded[0..k], &rinv);

    var blinded_sig: [rsa_verify.max_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &blinded_sig);
    try privateOpRaw(priv, blinded[0..k], blinded_sig[0..k]);

    const s_prime = try Big.fromBytesBE(blinded_sig[0..k]);
    var unblinded = s_prime.mul(&rinv);
    unblinded = unblinded.mod(&n_big);
    unblinded.toBytesBE(out[0..k]);

    // Bellcore/Lenstra fault check: recompute s^e mod n with the public
    // exponent and refuse to release s unless it maps back to the exact
    // representative. Covers CRT and non-CRT paths and the unblinding step.
    var check: [rsa_verify.max_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &check);
    modExpMont(out[0..k], priv.e, priv.n, check[0..k]) catch |err| {
        std.crypto.secureZero(u8, out[0..k]);
        return err;
    };
    const check_big = Big.fromBytesBE(check[0..k]) catch |err| {
        std.crypto.secureZero(u8, out[0..k]);
        return err;
    };
    if (check_big.cmp(&m_big) != .eq) {
        std.crypto.secureZero(u8, out[0..k]);
        return error.SignatureFault;
    }
    return out[0..k];
}

fn privateOpRaw(priv: PrivateKey, representative: []const u8, out: []u8) Error!void {
    const k = priv.n.len;
    if (out.len < k) return error.NoSpaceLeft;

    if (hasCrt(priv)) {
        try privateOpCrt(priv, representative, out[0..k]);
    } else {
        try modExpMont(representative, priv.d, priv.n, out[0..k]);
        if (injectedFault() == .non_crt) out[k - 1] ^= 0x01;
    }
}

/// Blind an encoded message representative before applying the RSA private
/// exponent. `r` is freshly sampled in [2, n - 1), rejected unless gcd(r,n)=1,
/// and inverted with the binary extended-GCD helper used for unblinding.
fn blindRepresentative(priv: PrivateKey, n: *const Big, m: *const Big, out: []u8, rinv_out: *Big) Error!void {
    const k = priv.n.len;
    if (out.len != k) return error.NoSpaceLeft;

    while (true) {
        var r_bytes: [rsa_verify.max_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &r_bytes);
        try randomBlindingBase(n, r_bytes[0..k]);

        const r = try Big.fromBytesBE(r_bytes[0..k]);
        const rinv = modInverseOdd(&r, n) catch |err| switch (err) {
            error.InvalidInput => continue,
            else => |e| return e,
        };

        var r_to_e: [rsa_verify.max_bytes]u8 = undefined;
        defer std.crypto.secureZero(u8, &r_to_e);
        try modExpMont(r_bytes[0..k], priv.e, priv.n, r_to_e[0..k]);

        const re_big = try Big.fromBytesBE(r_to_e[0..k]);
        var blinded = m.mul(&re_big);
        blinded = blinded.mod(n);
        blinded.toBytesBE(out);
        rinv_out.* = rinv;
        return;
    }
}

/// Sample a candidate blinding base uniformly by rejection from the bit width of
/// `n`, accepting only the RFC blinding range [2, n - 1). The gcd check is done
/// by modular inversion so the rare non-coprime candidate is retried there.
fn randomBlindingBase(n: *const Big, out: []u8) Error!void {
    const n_bits = n.bitLen();
    if (n_bits == 0) return error.InvalidKey;
    const random_len = (n_bits + 7) / 8;
    if (random_len == 0 or random_len > out.len) return error.InvalidKey;

    const one = oneBig();
    const two = twoBig();
    var n_minus_one = n.*;
    n_minus_one.subAssign(&one);
    if (n_minus_one.cmp(&two) != .gt) return error.InvalidKey;

    while (true) {
        @memset(out, 0);
        const start = out.len - random_len;
        try crypto_random.fillOsEntropy(out[start..]);
        const top_unused = random_len * 8 - n_bits;
        if (top_unused != 0) {
            const keep: u8 = @as(u8, 0xff) >> @intCast(top_unused);
            out[start] &= keep;
        }

        const r = try Big.fromBytesBE(out);
        if (r.cmp(&two) == .lt) continue;
        if (r.cmp(&n_minus_one) != .lt) continue;
        return;
    }
}

/// Compute a^-1 mod odd `modulus` with the binary extended GCD algorithm.
///
/// The coefficient state is always kept in [0, modulus), avoiding a signed Big
/// type. Halving an odd coefficient adds the odd modulus first, then shifts the
/// now-even value. If the gcd is not one, `InvalidInput` is returned so callers
/// can reject the candidate blinding base and sample a new `r`.
fn modInverseOdd(a: *const Big, modulus: *const Big) Error!Big {
    if (modulus.isZero() or modulus.limbs[0] & 1 == 0) return error.InvalidKey;

    const one = oneBig();
    var u = a.mod(modulus);
    if (u.isZero()) return error.InvalidInput;
    var v = modulus.*;
    var x1 = one;
    var x2 = Big{};

    while (u.cmp(&one) != .eq and v.cmp(&one) != .eq) {
        if (u.isZero() or v.isZero()) return error.InvalidInput;

        while (isEven(&u)) {
            shrOne(&u);
            x1 = try halveCoeffModOdd(&x1, modulus);
        }
        while (isEven(&v)) {
            shrOne(&v);
            x2 = try halveCoeffModOdd(&x2, modulus);
        }

        if (u.cmp(&v) != .lt) {
            u.subAssign(&v);
            x1 = try subMod(&x1, &x2, modulus);
        } else {
            v.subAssign(&u);
            x2 = try subMod(&x2, &x1, modulus);
        }
    }

    return if (u.cmp(&one) == .eq) x1 else x2;
}

fn halveCoeffModOdd(x: *const Big, modulus: *const Big) Error!Big {
    var out = x.*;
    if (isEven(&out)) {
        shrOne(&out);
        return out;
    }

    out = try addBig(&out, modulus);
    shrOne(&out);
    return out;
}

fn subMod(a: *const Big, b: *const Big, modulus: *const Big) Error!Big {
    var out = a.*;
    if (out.cmp(b) == .lt) out = try addBig(&out, modulus);
    out.subAssign(b);
    return out;
}

fn isEven(x: *const Big) bool {
    return x.isZero() or x.limbs[0] & 1 == 0;
}

fn shrOne(x: *Big) void {
    var carry: u64 = 0;
    var i = x.len;
    while (i > 0) {
        i -= 1;
        const next_carry = x.limbs[i] & 1;
        x.limbs[i] = (x.limbs[i] >> 1) | (carry << 63);
        carry = next_carry;
    }
    x.normalize();
}

fn oneBig() Big {
    var one = Big{ .len = 1 };
    one.limbs[0] = 1;
    return one;
}

fn twoBig() Big {
    var two = Big{ .len = 1 };
    two.limbs[0] = 2;
    return two;
}

fn privateOpCrt(priv: PrivateKey, representative: []const u8, out: []u8) Error!void {
    const p = priv.p.?;
    const q = priv.q.?;
    const dp = priv.dp.?;
    const dq = priv.dq.?;
    const qinv = priv.qinv.?;

    var m1_bytes: [rsa_verify.max_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &m1_bytes);
    var m2_bytes: [rsa_verify.max_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &m2_bytes);
    try modExpMont(representative, dp, p, m1_bytes[0..p.len]);
    try modExpMont(representative, dq, q, m2_bytes[0..q.len]);
    switch (injectedFault()) {
        .crt_m1 => m1_bytes[p.len - 1] ^= 0x01,
        .crt_m2 => m2_bytes[q.len - 1] ^= 0x01,
        else => {},
    }

    const p_big = try Big.fromBytesBE(p);
    const q_big = try Big.fromBytesBE(q);
    const qinv_big = try Big.fromBytesBE(qinv);
    const m1 = try Big.fromBytesBE(m1_bytes[0..p.len]);
    const m2 = try Big.fromBytesBE(m2_bytes[0..q.len]);

    var m2_mod_p = m2.mod(&p_big);
    var diff = m1;
    if (diff.cmp(&m2_mod_p) == .lt) diff = try addBig(&diff, &p_big);
    diff.subAssign(&m2_mod_p);

    var h = qinv_big.mul(&diff);
    h = h.mod(&p_big);
    var qh = q_big.mul(&h);
    const result = try addBig(&qh, &m2);

    const n_big = try Big.fromBytesBE(priv.n);
    if (result.cmp(&n_big) != .lt) return error.InvalidKey;
    result.toBytesBE(out);
}

fn modExpMont(base_be: []const u8, exp_be: []const u8, mod_be: []const u8, out: []u8) Error!void {
    const n = try Big.fromBytesBE(mod_be);
    if (n.isZero() or n.limbs[0] & 1 == 0) return error.InvalidKey;
    if (n.len * 2 + 1 > rsa_verify.max_limbs) return error.TooLarge;

    const exp = try Big.fromBytesBE(exp_be);
    var base = try Big.fromBytesBE(base_be);
    base = base.mod(&n);

    const n0_inv = montgomeryN0Inv(n.limbs[0]);
    const m = n.len;
    var r = Big{};
    r.len = m + 1;
    r.limbs[m] = 1;
    r = r.mod(&n);
    var r2 = r.mul(&r);
    r2 = r2.mod(&n);

    var one = Big{ .len = 1 };
    one.limbs[0] = 1;
    var result = r; // Montgomery form of 1.
    var base_mont = montMul(&base, &r2, &n, n0_inv, m);

    var i = exp.bitLen();
    while (i > 0) {
        i -= 1;
        result = montMul(&result, &result, &n, n0_inv, m);
        if (exp.bit(i) == 1) result = montMul(&result, &base_mont, &n, n0_inv, m);
    }

    result = montMul(&result, &one, &n, n0_inv, m);
    result.toBytesBE(out);
}

fn montgomeryN0Inv(n0: u64) u64 {
    var inv: u64 = 1;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        inv *%= 2 -% n0 *% inv;
    }
    return 0 -% inv;
}

fn montMul(a: *const Big, b: *const Big, n: *const Big, n0_inv: u64, m: usize) Big {
    var t = a.mul(b);
    return montReduce(&t, n, n0_inv, m);
}

fn montReduce(t_in: *const Big, n: *const Big, n0_inv: u64, m: usize) Big {
    var t = t_in.*;
    var i: usize = 0;
    while (i < m) : (i += 1) {
        const u = t.limbs[i] *% n0_inv;
        var carry: u64 = 0;
        var j: usize = 0;
        while (j < m) : (j += 1) {
            const idx = i + j;
            const w = @as(u128, u) * @as(u128, n.limbs[j]) + t.limbs[idx] + carry;
            t.limbs[idx] = @truncate(w);
            carry = @intCast(w >> 64);
        }
        var idx = i + m;
        var c = carry;
        while (c != 0) {
            const w = @as(u128, t.limbs[idx]) + c;
            t.limbs[idx] = @truncate(w);
            c = @intCast(w >> 64);
            idx += 1;
        }
    }

    var r = Big{};
    r.len = m + 1;
    @memcpy(r.limbs[0 .. m + 1], t.limbs[m .. m + m + 1]);
    r.normalize();
    if (r.cmp(n) != .lt) r.subAssign(n);
    return r;
}

fn validatePrivateKey(priv: PrivateKey) Error!void {
    try validateRequired(priv.n);
    try validateRequired(priv.e);
    try validateRequired(priv.d);

    const any_crt = priv.p != null or priv.q != null or priv.dp != null or priv.dq != null or priv.qinv != null;
    if (any_crt) {
        if (priv.p == null or priv.q == null or priv.dp == null or priv.dq == null or priv.qinv == null) {
            return error.InvalidKey;
        }
        try validateRequired(priv.p.?);
        try validateRequired(priv.q.?);
        try validateRequired(priv.dp.?);
        try validateRequired(priv.dq.?);
        try validateRequired(priv.qinv.?);
    }
}

fn validateRequired(bytes: []const u8) Error!void {
    if (bytes.len == 0) return error.InvalidKey;
    if (bytes.len > rsa_verify.max_bytes) return error.TooLarge;
}

fn hasCrt(priv: PrivateKey) bool {
    return priv.p != null and priv.q != null and priv.dp != null and priv.dq != null and priv.qinv != null;
}

fn addBig(a: *const Big, b: *const Big) Error!Big {
    var out = Big{};
    const len = @max(a.len, b.len);
    var carry: u128 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (i >= rsa_verify.max_limbs) return error.TooLarge;
        const av: u128 = if (i < a.len) a.limbs[i] else 0;
        const bv: u128 = if (i < b.len) b.limbs[i] else 0;
        const sum = av + bv + carry;
        out.limbs[i] = @truncate(sum);
        carry = sum >> 64;
    }
    out.len = len;
    if (carry != 0) {
        if (out.len >= rsa_verify.max_limbs) return error.TooLarge;
        out.limbs[out.len] = @intCast(carry);
        out.len += 1;
    }
    out.normalize();
    return out;
}

/// DER DigestInfo prefix for each hash (RFC 8017 §9.2).
fn digestInfoPrefix(alg: rsa_verify.HashAlg) []const u8 {
    return switch (alg) {
        .sha256 => &.{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
        .sha384 => &.{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 },
        .sha512 => &.{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
    };
}

fn hashOf(alg: rsa_verify.HashAlg, msg: []const u8, out: []u8) void {
    switch (alg) {
        .sha256 => {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(msg);
            h.final(out[0..32]);
        },
        .sha384 => {
            var h = std.crypto.hash.sha2.Sha384.init(.{});
            h.update(msg);
            h.final(out[0..48]);
        },
        .sha512 => {
            var h = std.crypto.hash.sha2.Sha512.init(.{});
            h.update(msg);
            h.final(out[0..64]);
        },
    }
}

const testing = std.testing;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

const rsa_n = [_]u8{ 0xa0, 0xbd, 0x13, 0x04, 0xa8, 0x7f, 0x0a, 0x69, 0xb8, 0xef, 0x18, 0xea, 0xa1, 0xda, 0x15, 0x52, 0x2c, 0x22, 0x1b, 0x1e, 0x9b, 0x1e, 0xfa, 0xee, 0x23, 0xbe, 0xa1, 0xfa, 0xa7, 0xea, 0xae, 0xfe, 0x1e, 0x09, 0xeb, 0xa3, 0x90, 0xec, 0x93, 0x34, 0xae, 0xa9, 0x45, 0x75, 0x30, 0xd4, 0x0c, 0x6a, 0x6b, 0x89, 0xc0, 0x39, 0x86, 0x5e, 0x98, 0xdd, 0x9d, 0x74, 0x91, 0xea, 0x57, 0x28, 0x8d, 0xeb, 0xf3, 0x70, 0xf7, 0x96, 0xfe, 0x05, 0x90, 0x4a, 0x58, 0x90, 0x27, 0x27, 0x2f, 0xc9, 0xbd, 0x80, 0x3f, 0xcf, 0x9d, 0x22, 0x8c, 0x55, 0x52, 0xda, 0x7f, 0xf4, 0xf2, 0xa2, 0x5c, 0x16, 0x06, 0xb3, 0xa4, 0x79, 0x4f, 0x4f, 0xfa, 0x5b, 0xd9, 0x4a, 0xb2, 0x15, 0x00, 0x26, 0xdb, 0xcd, 0x31, 0xc4, 0xf4, 0xa5, 0x75, 0x5d, 0x44, 0x9a, 0x7a, 0xaf, 0x41, 0x86, 0x1f, 0xf0, 0x69, 0xfa, 0x45, 0x55, 0x63, 0xcb, 0x22, 0xde, 0x14, 0x11, 0x4a, 0xff, 0x80, 0x85, 0xfc, 0x3d, 0x3c, 0x07, 0xbc, 0x92, 0x9d, 0x76, 0x1f, 0x64, 0x49, 0xc1, 0xa1, 0x39, 0x75, 0x73, 0x8c, 0x98, 0x76, 0x31, 0x95, 0x99, 0xf8, 0x8b, 0xd3, 0x67, 0x62, 0x30, 0x80, 0x2d, 0x76, 0xb7, 0x29, 0x2a, 0xd0, 0x75, 0x9d, 0xad, 0x8f, 0xc7, 0x0e, 0xe1, 0x8f, 0xde, 0xd6, 0x9e, 0x32, 0x21, 0x6a, 0x7f, 0x52, 0x83, 0x3f, 0x11, 0x38, 0xca, 0xa7, 0xf9, 0x03, 0x07, 0xc2, 0x36, 0x50, 0x0c, 0x3a, 0xa1, 0xa6, 0xcd, 0x08, 0x20, 0x97, 0xfc, 0x3e, 0x28, 0x60, 0x9b, 0x8d, 0x33, 0x51, 0x4f, 0x16, 0xd6, 0x68, 0x7b, 0xed, 0x50, 0x4a, 0xee, 0x82, 0x77, 0x5a, 0x41, 0xe4, 0xb1, 0x25, 0xeb, 0xa9, 0xca, 0x54, 0x4d, 0xc3, 0x75, 0xc2, 0x9c, 0x19, 0xd2, 0x0f, 0x10, 0x90, 0x03, 0x01, 0xee, 0xa8, 0xe6, 0x8b, 0xe3, 0xb3, 0xd7 };
const rsa_e = [_]u8{ 0x01, 0x00, 0x01 };
const rsa_d = [_]u8{ 0x12, 0x03, 0x6e, 0x6c, 0xb0, 0xb7, 0x60, 0x02, 0xde, 0x1b, 0x49, 0x77, 0x0e, 0x01, 0x63, 0x2f, 0x4c, 0xcb, 0xdb, 0xaf, 0x2f, 0xe2, 0x26, 0x6b, 0xe6, 0xac, 0x97, 0xf9, 0x7f, 0xb4, 0xf0, 0xbc, 0x80, 0xc0, 0x4a, 0xdc, 0x8f, 0x42, 0xbb, 0xf2, 0x84, 0xfa, 0x6a, 0x52, 0xca, 0x50, 0x91, 0x3d, 0xa1, 0xe4, 0x93, 0x9a, 0xbe, 0xc0, 0xbe, 0x2f, 0xe3, 0xd3, 0xeb, 0x00, 0x50, 0x99, 0x36, 0x62, 0x71, 0x6b, 0x41, 0x0b, 0xf6, 0x56, 0xc8, 0x47, 0x54, 0xaa, 0x7f, 0x00, 0xc8, 0xbd, 0xba, 0x93, 0x73, 0x53, 0x40, 0x80, 0x5d, 0x2a, 0xb8, 0xb8, 0xcc, 0xeb, 0x35, 0xff, 0xd5, 0x03, 0x10, 0xe8, 0x33, 0xef, 0xf6, 0x5f, 0xf7, 0xa6, 0x30, 0x71, 0x4b, 0x08, 0xc8, 0x76, 0x12, 0x5e, 0xea, 0x0b, 0x71, 0x01, 0x53, 0xe8, 0x4a, 0x66, 0x67, 0x86, 0x59, 0x78, 0xfe, 0xfe, 0x51, 0xda, 0x1e, 0xc7, 0xd7, 0xcf, 0xc1, 0xaf, 0xb9, 0x6c, 0x42, 0x23, 0xb1, 0x87, 0xb4, 0x9c, 0xb6, 0x30, 0x5b, 0xe1, 0xa2, 0xec, 0xcb, 0xb8, 0xd0, 0x7e, 0xd0, 0x16, 0xbc, 0x25, 0x79, 0x08, 0xbe, 0xc7, 0xda, 0xf3, 0x22, 0x65, 0x8b, 0xda, 0x2d, 0xc4, 0xab, 0xd3, 0x67, 0x1f, 0xfa, 0x69, 0x19, 0xda, 0x8b, 0x86, 0xec, 0xbe, 0xfa, 0x26, 0x58, 0xc3, 0xc0, 0x1b, 0xac, 0xee, 0x5c, 0x9c, 0xff, 0x02, 0xf1, 0xcb, 0xac, 0x3f, 0x05, 0xfe, 0xb2, 0xd6, 0x8c, 0x61, 0xef, 0x9a, 0x54, 0x27, 0xf7, 0x3e, 0xdb, 0x19, 0x49, 0xf7, 0x76, 0x35, 0x0b, 0xd6, 0x34, 0x75, 0xc3, 0xcb, 0x78, 0xc5, 0x60, 0x5b, 0x09, 0x4d, 0x50, 0x43, 0x75, 0x6e, 0x89, 0x4b, 0xf5, 0x38, 0xe8, 0x11, 0x90, 0x32, 0x12, 0xb6, 0x99, 0x0a, 0x75, 0x15, 0x3e, 0x26, 0x1a, 0x36, 0x63, 0x06, 0x57, 0xf8, 0xb9, 0x1d, 0xfd, 0xad, 0xf4, 0x5d };
const rsa_p = [_]u8{ 0xe0, 0x3b, 0x0d, 0x99, 0x92, 0x33, 0xd3, 0x20, 0xae, 0x90, 0xbb, 0x8f, 0xa2, 0x8b, 0xa3, 0x6a, 0xd8, 0xc0, 0xbe, 0xde, 0xea, 0x9b, 0xc1, 0x21, 0x8f, 0x65, 0xf1, 0xaa, 0xc3, 0x29, 0xe0, 0xc9, 0x21, 0xa6, 0xaa, 0xf6, 0x2a, 0x56, 0x71, 0x9c, 0x6b, 0xd0, 0x1c, 0x33, 0xff, 0x11, 0x9a, 0x65, 0x70, 0x05, 0xeb, 0x50, 0x0c, 0x33, 0xaa, 0x52, 0xe6, 0xd2, 0xfb, 0x6a, 0x55, 0x72, 0x3f, 0x6f, 0xc2, 0x07, 0x6f, 0xb8, 0xd3, 0x0d, 0xf1, 0x28, 0x01, 0xdc, 0xa5, 0x23, 0x51, 0x59, 0x92, 0xca, 0xd6, 0xad, 0x62, 0x8d, 0x18, 0x09, 0x47, 0xe8, 0x46, 0xfa, 0x3a, 0x3a, 0x30, 0x46, 0xc8, 0x4c, 0x25, 0x26, 0x6f, 0xaf, 0x90, 0x79, 0xf4, 0x40, 0x22, 0xbd, 0x4b, 0x56, 0x00, 0xd9, 0x8a, 0x8e, 0xe4, 0xcb, 0xda, 0x9f, 0xdd, 0xf0, 0x1e, 0x9e, 0xfb, 0x5d, 0x7e, 0xb6, 0x2f, 0x7e, 0xdb, 0x5d };
const rsa_q = [_]u8{ 0xb7, 0x83, 0x22, 0x56, 0xda, 0xec, 0x3e, 0xb9, 0xc3, 0x25, 0xd1, 0xcd, 0xd4, 0xb3, 0xe2, 0x03, 0x67, 0x23, 0xd0, 0x2d, 0xaa, 0x96, 0xe0, 0x29, 0x51, 0x86, 0x40, 0xc4, 0x0d, 0x87, 0xbd, 0xe9, 0xdf, 0x14, 0x7b, 0xd8, 0x48, 0x80, 0x31, 0xdf, 0x85, 0xca, 0xa4, 0x49, 0xec, 0x42, 0x73, 0x5c, 0xbf, 0xd1, 0x12, 0x5f, 0x84, 0x30, 0x27, 0x35, 0x2d, 0x39, 0x6e, 0x7e, 0x90, 0x24, 0xb7, 0x63, 0x35, 0xa9, 0x81, 0x48, 0xa5, 0x53, 0xd3, 0x18, 0x72, 0xf3, 0x22, 0x75, 0x58, 0x28, 0x97, 0xd1, 0xe8, 0xf2, 0xb1, 0x46, 0x0f, 0x1a, 0x3b, 0xd0, 0x37, 0x5f, 0xe8, 0xa8, 0x84, 0xf2, 0x37, 0x2e, 0x71, 0x6d, 0x51, 0xa4, 0xb7, 0x10, 0x43, 0xc9, 0x73, 0x0d, 0x74, 0xa7, 0x26, 0x34, 0x76, 0x36, 0x2d, 0x50, 0x24, 0x96, 0xc1, 0x9f, 0x6a, 0x45, 0xa6, 0x15, 0x51, 0x7b, 0x4a, 0x7f, 0x4c, 0xc3 };
const rsa_dp = [_]u8{ 0x1a, 0x1b, 0xe6, 0x2e, 0x7e, 0x8e, 0x98, 0x43, 0xd2, 0xef, 0xb9, 0x57, 0x35, 0x37, 0x0b, 0x35, 0x32, 0xbd, 0xe6, 0xbb, 0xb0, 0x17, 0xa8, 0xba, 0x4e, 0xa7, 0x31, 0x27, 0x90, 0x07, 0xfd, 0x4b, 0x8e, 0x26, 0x88, 0xfb, 0x96, 0xdc, 0x6f, 0xe8, 0x25, 0xc9, 0x9a, 0xaf, 0x17, 0x41, 0x26, 0x78, 0x2f, 0x3e, 0x11, 0x33, 0x45, 0xe8, 0x72, 0x29, 0xab, 0x04, 0xe0, 0x0f, 0x76, 0x99, 0x91, 0xf7, 0x62, 0x61, 0x59, 0x49, 0xed, 0x11, 0x4f, 0x86, 0x38, 0x09, 0x48, 0x15, 0x3f, 0xb0, 0xad, 0x5d, 0xfe, 0xf7, 0x3b, 0x65, 0x70, 0x6a, 0x0c, 0x3c, 0x68, 0x9f, 0x54, 0x4e, 0x58, 0x36, 0xb5, 0xb5, 0xe0, 0x11, 0x84, 0xa9, 0xad, 0xa9, 0xf5, 0x9d, 0xce, 0x2d, 0xba, 0x6a, 0xee, 0x38, 0x66, 0x60, 0xd3, 0x15, 0x45, 0x84, 0x9d, 0xe4, 0x0a, 0xbc, 0xba, 0x4a, 0x1d, 0xa9, 0xfb, 0x07, 0xcb, 0x65 };
const rsa_dq = [_]u8{ 0x90, 0x77, 0x9a, 0xab, 0xf7, 0xb2, 0xad, 0xfa, 0xbd, 0xa7, 0x63, 0x50, 0x7f, 0xd7, 0x90, 0xe1, 0x0e, 0xec, 0x41, 0xb2, 0x01, 0xae, 0xbf, 0x0f, 0xa8, 0x0f, 0x61, 0xa3, 0x35, 0xe7, 0x9b, 0xd9, 0xa6, 0x75, 0xd0, 0xbd, 0x46, 0xee, 0x2c, 0xd5, 0x03, 0xd5, 0xb0, 0x9a, 0x45, 0x75, 0x56, 0xae, 0x38, 0x8f, 0x95, 0xc0, 0x3e, 0x27, 0x4e, 0x66, 0x6d, 0x90, 0xdd, 0xec, 0xa2, 0xfb, 0x54, 0xa7, 0xb4, 0x92, 0x19, 0xa6, 0x20, 0x09, 0x2a, 0x90, 0xff, 0xc5, 0x6a, 0x66, 0x28, 0x9d, 0xe4, 0x4f, 0x2a, 0xed, 0x0c, 0x23, 0xd4, 0x35, 0xd9, 0xca, 0xa4, 0x1d, 0x4b, 0xe2, 0x86, 0xae, 0xcc, 0x44, 0x32, 0xa5, 0x55, 0xf5, 0xae, 0xec, 0x0e, 0x01, 0x64, 0x22, 0xbe, 0xa7, 0xeb, 0xca, 0xb7, 0x19, 0x15, 0x79, 0x17, 0x24, 0xdb, 0x8e, 0xed, 0x31, 0xa1, 0x7a, 0xfc, 0xe7, 0x6b, 0x91, 0x65, 0xd3 };
const rsa_qinv = [_]u8{ 0xc4, 0xca, 0xe1, 0x78, 0x93, 0x8b, 0x60, 0x71, 0x7e, 0x4d, 0x04, 0x84, 0xc1, 0x44, 0xc5, 0x48, 0xb2, 0x75, 0xf8, 0x7d, 0xd2, 0x72, 0x3c, 0xfe, 0x1b, 0x6a, 0x5b, 0xa6, 0x83, 0x05, 0xb1, 0x54, 0xd1, 0xc8, 0x6c, 0x89, 0x47, 0x16, 0xbd, 0x9d, 0x5b, 0x4f, 0x97, 0x4f, 0x51, 0xad, 0x98, 0x94, 0x2f, 0xa2, 0x60, 0x05, 0x18, 0x88, 0x96, 0x93, 0x1a, 0x73, 0x20, 0x6b, 0x77, 0x8b, 0x94, 0x6f, 0x96, 0xc6, 0x44, 0x3f, 0x67, 0xbb, 0xb1, 0x86, 0x1c, 0xe8, 0xa2, 0xe9, 0xd4, 0x38, 0xbe, 0xfd, 0xb6, 0xcb, 0x1b, 0x7f, 0x41, 0x3e, 0xdc, 0x5b, 0x15, 0x5b, 0x43, 0x66, 0x60, 0x32, 0x0f, 0x3c, 0xd2, 0x6b, 0x0f, 0x65, 0xa9, 0xf5, 0x86, 0xf9, 0x57, 0x25, 0x7b, 0x81, 0xe7, 0xc4, 0x10, 0x85, 0x61, 0x50, 0xab, 0xf4, 0xbb, 0x8f, 0x69, 0x1b, 0xea, 0xbe, 0xcf, 0x7e, 0x42, 0x8a, 0x2f, 0x8c };

// Fast self-contained signing key for randomized blinding stress tests:
// n = M2281 = 2^2281 - 1, e = d = n - 2. Since M2281 is prime, exponent -1 is
// its own inverse modulo n - 1, so sign/verify round-trips without external
// vectors. 2281 bits = 286 bytes (0x01 then 285×0xFF), comfortably above
// rsa_verify's 2048-bit modern-hardening floor, so verifyPkcs1v15 still accepts
// the key and exercises the private op — mirroring the M2281 KAT key
// rsa_verify.zig bumped to for the same reason.
const m2281_n = blk: {
    var n: [286]u8 = @splat(0xff);
    n[0] = 0x01;
    break :blk n;
};
const m2281_ed = blk: {
    var ed: [286]u8 = @splat(0xff);
    ed[0] = 0x01;
    ed[285] = 0xfd;
    break :blk ed;
};

fn testPrivateKey() PrivateKey {
    return .{
        .n = &rsa_n,
        .e = &rsa_e,
        .d = &rsa_d,
        .p = &rsa_p,
        .q = &rsa_q,
        .dp = &rsa_dp,
        .dq = &rsa_dq,
        .qinv = &rsa_qinv,
    };
}

test "signPkcs1v15 with a real RSA-2048 key verifies and rejects tampering" {
    const digest = hexToBytes("24ddade2122077b86a4ea8ed269ec44c16e3c7105d30c28c3a7060bc718f89a5");
    const priv = testPrivateKey();
    const pub_key = rsa_verify.PublicKey{ .n = priv.n, .e = priv.e };

    var sig: [rsa_verify.max_bytes]u8 = undefined;
    const got = try signPkcs1v15(priv, .sha256, &digest, &sig);
    try testing.expectEqual(@as(usize, 256), got.len);
    try testing.expect(rsa_verify.verifyPkcs1v15(pub_key, .sha256, &digest, got));

    var bad_digest = digest;
    bad_digest[0] ^= 0x80;
    try testing.expect(!rsa_verify.verifyPkcs1v15(pub_key, .sha256, &bad_digest, got));

    var wrong_n = rsa_n;
    wrong_n[wrong_n.len - 1] ^= 0x01;
    const wrong_pub = rsa_verify.PublicKey{ .n = &wrong_n, .e = &rsa_e };
    try testing.expect(!rsa_verify.verifyPkcs1v15(wrong_pub, .sha256, &digest, got));
}

test "signPss with a real RSA-2048 key and fixed salt verifies and rejects tampering" {
    const digest = hexToBytes("6de91ba6970c3fe88f3d643f9694eb81eb1d674e474074eb1e01613f1d2999b5");
    const salt = [_]u8{ 0xa7, 0x2d, 0x44, 0x11, 0x90, 0x5c, 0x8e, 0x6f, 0x14, 0x00, 0xcd, 0x99, 0x21, 0x33, 0x78, 0x5a, 0xee, 0x7b, 0x10, 0x51, 0x23, 0xf0, 0x48, 0x6d, 0x5c, 0xb9, 0x01, 0x3a, 0x4f, 0x62, 0x70, 0x88 };
    const priv = testPrivateKey();
    const pub_key = rsa_verify.PublicKey{ .n = priv.n, .e = priv.e };

    var sig: [rsa_verify.max_bytes]u8 = undefined;
    const got = try signPss(priv, .sha256, &digest, &salt, &sig);
    try testing.expectEqual(@as(usize, 256), got.len);
    try testing.expect(rsa_verify.verifyPss(pub_key, .sha256, &digest, got, salt.len));

    var bad_sig: [256]u8 = undefined;
    @memcpy(&bad_sig, got);
    bad_sig[12] ^= 0x01;
    try testing.expect(!rsa_verify.verifyPss(pub_key, .sha256, &digest, &bad_sig, salt.len));
    try testing.expect(!rsa_verify.verifyPss(pub_key, .sha256, &digest, got, salt.len - 1));
}

test "blinded PKCS1 signing verifies across many random blinding bases and stays deterministic" {
    const digest = hexToBytes("24ddade2122077b86a4ea8ed269ec44c16e3c7105d30c28c3a7060bc718f89a5");
    const priv = PrivateKey{ .n = &m2281_n, .e = &m2281_ed, .d = &m2281_ed };
    const pub_key = rsa_verify.PublicKey{ .n = priv.n, .e = priv.e };

    var first: [rsa_verify.max_bytes]u8 = undefined;
    const first_sig = try signPkcs1v15(priv, .sha256, &digest, &first);
    try testing.expect(rsa_verify.verifyPkcs1v15(pub_key, .sha256, &digest, first_sig));

    const Work = struct {
        const worker_count = 4;
        const Job = struct {
            signature: [rsa_verify.max_bytes]u8 = undefined,
            result: Error!usize = error.InvalidInput,
            verified: bool = false,
        };

        fn run(jobs: *[25]Job, worker: usize, message_digest: []const u8) void {
            const key = PrivateKey{ .n = &m2281_n, .e = &m2281_ed, .d = &m2281_ed };
            const public = rsa_verify.PublicKey{ .n = key.n, .e = key.e };
            var index = worker;
            while (index < jobs.len) : (index += worker_count) {
                const job = &jobs[index];
                const got = signPkcs1v15(key, .sha256, message_digest, &job.signature) catch |err| {
                    job.result = err;
                    continue;
                };
                job.verified = rsa_verify.verifyPkcs1v15(public, .sha256, message_digest, got);
                job.result = got.len;
            }
        }
    };
    // Preserve all 26 independently blinded signatures and comparisons. Only
    // this arithmetic-only case uses workers: each owns disjoint stack-backed
    // results, OS entropy has no shared DRBG, and assertions stay on this thread.
    var jobs: [25]Work.Job = @splat(.{});
    {
        var threads: [Work.worker_count]std.Thread = undefined;
        var spawned: usize = 0;
        defer for (threads[0..spawned]) |thread| thread.join();
        while (spawned < threads.len) : (spawned += 1) {
            threads[spawned] = try std.Thread.spawn(.{}, Work.run, .{ &jobs, spawned, &digest });
        }
    }
    for (&jobs) |*job| {
        const len = try job.result;
        try testing.expect(job.verified);
        try testing.expectEqualSlices(u8, first_sig, job.signature[0..len]);
    }
}

// Regression for the ReleaseFast mulAddWord inline-asm earlyclobber bug (see
// rsa_verify.zig): with the broken constraint, every one of these signatures
// came out garbage in optimized builds (gnutls TLS 1.3 clients then rejected
// the RSA-PSS CertificateVerify with "Public key signature verification has
// failed"), while Debug builds passed. Random salts keep the private op
// (blinding + CRT) on fresh inputs each iteration; the explicit structural
// decode asserts the exact RFC 8017 §9.1.1 EM layout that strict verifiers
// (gnutls/nettle enforce salt_len == hash_len; openssl is lenient) require.
test "signPss random salts: exactly k bytes with strict 32-byte-salt PSS structure" {
    const priv = testPrivateKey();
    const pub_key = rsa_verify.PublicKey{ .n = priv.n, .e = priv.e };
    var prng = std.Random.DefaultPrng.init(0x5EED);
    const random = prng.random();

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var digest: [32]u8 = undefined;
        random.bytes(&digest);
        var salt: [32]u8 = undefined;
        random.bytes(&salt);

        var sig: [rsa_verify.max_bytes]u8 = undefined;
        const got = try signPss(priv, .sha256, &digest, &salt, &sig);

        // Signature is the full modulus length (left-zero-padded big-endian I2OSP).
        try testing.expectEqual(priv.n.len, got.len);
        try testing.expectEqual(@as(usize, 256), got.len);
        // Strict verify at the exact TLS 1.3 salt length (32 = SHA-256 len).
        try testing.expect(rsa_verify.verifyPss(pub_key, .sha256, &digest, got, salt.len));
        // A different claimed salt length must fail: the 0x01 separator sits at
        // one exact offset, so this proves the embedded salt is exactly 32 bytes.
        try testing.expect(!rsa_verify.verifyPss(pub_key, .sha256, &digest, got, salt.len - 1));
        try testing.expect(!rsa_verify.verifyPss(pub_key, .sha256, &digest, got, salt.len + 1));

        // Structural decode of EM = maskedDB || H || 0xbc (emBits = 2047,
        // emLen = k = 256 for a 2048-bit modulus).
        var em: [256]u8 = undefined;
        try rsa_verify.modExp(got, priv.e, priv.n, &em);
        try testing.expectEqual(@as(u8, 0xbc), em[255]);
        try testing.expectEqual(@as(u8, 0), em[0] & 0x80); // top (8*emLen - emBits) bits clear
        const db_len = 256 - 32 - 1; // 223
        const h = em[db_len..][0..32];
        var db: [db_len]u8 = undefined;
        @memcpy(&db, em[0..db_len]);
        rsa_verify.mgf1(.sha256, h, &db); // unmask: DB = maskedDB XOR MGF1(H)
        db[0] &= 0x7f;
        const ps_len = db_len - salt.len - 1; // 190
        for (db[0..ps_len]) |byte| try testing.expectEqual(@as(u8, 0), byte);
        try testing.expectEqual(@as(u8, 0x01), db[ps_len]);
        try testing.expectEqualSlices(u8, &salt, db[ps_len + 1 ..][0..salt.len]);
    }
}

test "modular inverse returns rinv where r * rinv mod n is one" {
    const n = try Big.fromBytesBE(&rsa_n);
    const cases = [_][]const u8{
        &[_]u8{0x02},
        &[_]u8{0x03},
        &[_]u8{0x11},
        &[_]u8{ 0x01, 0x00, 0x01 },
        &[_]u8{ 0xde, 0xad, 0xbe, 0xef, 0x42 },
    };

    const one = oneBig();
    for (cases) |case| {
        const r = try Big.fromBytesBE(case);
        const rinv = try modInverseOdd(&r, &n);
        var product = r.mul(&rinv);
        product = product.mod(&n);
        try testing.expectEqual(std.math.Order.eq, product.cmp(&one));
    }
}

fn expectFaultRefused(priv: PrivateKey, fault: FaultInjection) !void {
    const digest = hexToBytes("24ddade2122077b86a4ea8ed269ec44c16e3c7105d30c28c3a7060bc718f89a5");
    const salt: [32]u8 = @splat(0x5a);
    test_fault = fault;
    defer test_fault = .none;

    var sig: [rsa_verify.max_bytes]u8 = @splat(0xee);
    try testing.expectError(error.SignatureFault, signPkcs1v15(priv, .sha256, &digest, &sig));
    // The faulty signature must not leak through the output buffer.
    for (sig[0..priv.n.len]) |byte| try testing.expectEqual(@as(u8, 0), byte);

    @memset(&sig, 0xee);
    try testing.expectError(error.SignatureFault, signPss(priv, .sha256, &digest, &salt, &sig));
    for (sig[0..priv.n.len]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "A3: CRT fault in m1 or m2 is detected and the signature is withheld" {
    const priv = testPrivateKey();
    try expectFaultRefused(priv, .crt_m1);
    try expectFaultRefused(priv, .crt_m2);

    // Without an injected fault the same key still signs and verifies.
    const digest = hexToBytes("24ddade2122077b86a4ea8ed269ec44c16e3c7105d30c28c3a7060bc718f89a5");
    var sig: [rsa_verify.max_bytes]u8 = undefined;
    const got = try signPkcs1v15(priv, .sha256, &digest, &sig);
    try testing.expect(rsa_verify.verifyPkcs1v15(.{ .n = priv.n, .e = priv.e }, .sha256, &digest, got));
}

test "A3: non-CRT private-op fault is detected and the signature is withheld" {
    const priv = testPrivateKey();
    const non_crt = PrivateKey{ .n = priv.n, .e = priv.e, .d = priv.d };
    try expectFaultRefused(non_crt, .non_crt);
}

test "A3: inconsistent CRT parameters are refused instead of signed" {
    // A wrong dp is indistinguishable from a persistent fault in the m1 branch;
    // without the check the signer would emit a factor-leaking signature.
    var bad_dp = rsa_dp;
    bad_dp[bad_dp.len - 1] ^= 0x02;
    var priv = testPrivateKey();
    priv.dp = &bad_dp;
    const digest = hexToBytes("24ddade2122077b86a4ea8ed269ec44c16e3c7105d30c28c3a7060bc718f89a5");
    var sig: [rsa_verify.max_bytes]u8 = undefined;
    try testing.expectError(error.SignatureFault, signPkcs1v15(priv, .sha256, &digest, &sig));
}
