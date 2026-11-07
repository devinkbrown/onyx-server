// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Constant-time NIST P-256 arithmetic for the ECDSA signing path.
//!
//! Why this exists: `zig build ct-check` showed Zig 0.17's
//! `std.crypto.ecc.P256.mul` leaking under ReleaseFast. Fixed-scalar runs were
//! ~2 us (|t| ~ 100-860) faster than random-scalar runs. The disassembly shows
//! why. The fiat-crypto style `cmovznz` selects are written as branch-free
//! mask arithmetic, but LLVM rewrites them as `select`s and then emits
//! conditional jumps (`test $1, ..; je`) for some of them. That includes the
//! window-table lookup in `pcMul16`, which is keyed on the secret nibble. The
//! branch predictor learns a repeated scalar, so timing depends on the secret
//! scalar (the ECDSA nonce, or the private key during key derivation). That is
//! a real leak, not a harness artifact.
//!
//! The fix keeps the same math but closes the compiler's escape route.
//! Every secret-dependent select goes through `ctMask`. It passes the 0/1
//! condition through an empty inline-asm value barrier before widening it to an
//! all-zeros/all-ones mask, so LLVM cannot prove the mask is boolean and cannot
//! turn `(a & m) | (b & ~m)` back into a branch. Building blocks:
//!
//!   * `MontField(m)`: 4x64-limb Montgomery arithmetic (CIOS), used both for
//!     the base field F_p and the scalar field F_n. Reductions are masked
//!     conditional subtractions. Inversion is Fermat exponentiation `a^(m-2)`
//!     by a PUBLIC comptime exponent with a fixed 4-bit window, so its control
//!     flow does not depend on `a`.
//!   * Projective points with the complete Renes-Costello-Batina formulas for
//!     a = -3 (ePrint 2015/1060, Algorithms 4 and 6). They have no exceptional
//!     cases, so the identity and doubling-via-add need no branches.
//!   * `mulCt`: fixed 4-bit-window scalar multiplication. Every window does 4
//!     doublings and 1 complete addition of a table entry, selected by a masked
//!     scan over all 16 entries. Same operation count and memory access pattern
//!     for every scalar.
//!
//! Branches that remain test only public values or results that almost never
//! happen (r == 0, s == 0, nonce rejection with probability ~2^-32). SEC 1 v2
//! sec. 4.1.3 and RFC 6979 sec. 3.2 step h.3 branch the same way.

const std = @import("std");
const builtin = @import("builtin");

// -- Constant-time primitives -----------------------------------------------

/// Hide `x` from the optimizer: the result is the same value, but LLVM can no
/// longer reason about its range (e.g. that it is 0 or 1), so it cannot turn
/// mask arithmetic built from it back into a branch or a `select`.
inline fn valueBarrier(x: u64) u64 {
    if (@inComptime()) return x;
    if (builtin.zig_backend != .stage2_llvm) return x;
    switch (builtin.cpu.arch) {
        .x86_64, .x86, .aarch64, .aarch64_be, .arm, .armeb, .thumb, .thumbeb, .riscv64, .riscv32 => {
            return asm ("" // empty: only the register constraint matters
                : [ret] "=r" (-> u64),
                : [x] "0" (x),
            );
        },
        else => return x,
    }
}

/// All-ones when `bit == 1`, all-zeros when `bit == 0`. `bit` must be 0 or 1.
inline fn ctMask(bit: u64) u64 {
    return 0 -% valueBarrier(bit);
}

/// 1 when `a == b`, else 0, without a data-dependent branch.
inline fn ctEqBit(a: u64, b: u64) u64 {
    const x = a ^ b;
    // (x | -x) has the top bit set iff x != 0.
    return ((x | (0 -% x)) >> 63) ^ 1;
}

inline fn ctSelect(mask: u64, if_set: u64, if_clear: u64) u64 {
    return (if_set & mask) | (if_clear & ~mask);
}

inline fn addc(a: u64, b: u64, carry: u64) struct { u64, u64 } {
    const s: u128 = @as(u128, a) + b + carry;
    return .{ @truncate(s), @intCast(s >> 64) };
}

inline fn subb(a: u64, b: u64, borrow: u64) struct { u64, u64 } {
    const d: u128 = @as(u128, a) -% b -% borrow;
    return .{ @truncate(d), @intCast(d >> 127) };
}

/// `acc + a*b + carry` as (lo, hi). Never overflows 128 bits.
inline fn mac(acc: u64, a: u64, b: u64, carry: u64) struct { u64, u64 } {
    const w: u128 = @as(u128, a) * b + acc + carry;
    return .{ @truncate(w), @intCast(w >> 64) };
}

// -- Montgomery field over a 256-bit odd modulus ----------------------------

pub fn MontField(comptime modulus: u256) type {
    return struct {
        const Self = @This();

        /// Little-endian 64-bit limbs of the value in Montgomery form (a*R mod m).
        limbs: [4]u64,

        pub const m: [4]u64 = toLimbs(modulus);
        /// -m^-1 mod 2^64.
        const m0inv: u64 = blk: {
            var inv: u64 = 1;
            for (0..6) |_| inv = inv *% (2 -% m[0] *% inv);
            break :blk 0 -% inv;
        };
        /// R^2 mod m, R = 2^256.
        const r2: [4]u64 = toLimbs(@intCast((@as(u1024, 1) << 512) % modulus));
        pub const zero: Self = .{ .limbs = .{ 0, 0, 0, 0 } };
        pub const one: Self = .{ .limbs = toLimbs(@intCast((@as(u512, 1) << 256) % modulus)) };

        fn toLimbs(v: u256) [4]u64 {
            return .{ @truncate(v), @truncate(v >> 64), @truncate(v >> 128), @truncate(v >> 192) };
        }

        /// Comptime constructor from a canonical integer.
        pub fn fromInt(comptime v: u256) Self {
            @setEvalBranchQuota(100_000);
            comptime std.debug.assert(v < modulus);
            return comptime (Self{ .limbs = toLimbs(v) }).mulRaw(.{ .limbs = r2 });
        }

        /// Montgomery product a*b*R^-1 mod m (CIOS). Inputs must be < m.
        fn mulRaw(a: Self, b: Self) Self {
            var t: [6]u64 = .{ 0, 0, 0, 0, 0, 0 };
            for (0..4) |i| {
                var c: u64 = 0;
                for (0..4) |j| {
                    t[j], c = mac(t[j], a.limbs[j], b.limbs[i], c);
                }
                t[4], t[5] = addc(t[4], c, 0);

                const q = t[0] *% m0inv;
                _, c = mac(t[0], q, m[0], 0);
                for (1..4) |j| {
                    t[j - 1], c = mac(t[j], q, m[j], c);
                }
                t[3], c = addc(t[4], c, 0);
                t[4] = t[5] + c;
                t[5] = 0;
            }
            // t[0..4] + t[4]*2^256 < 2m: one masked conditional subtraction.
            return reduceOnce(t[0..4].*, t[4]);
        }

        /// Given v = hi*2^256 + lo < 2m, return v mod m in constant time.
        inline fn reduceOnce(lo: [4]u64, hi: u64) Self {
            var d: [4]u64 = undefined;
            var b: u64 = 0;
            for (0..4) |j| d[j], b = subb(lo[j], m[j], b);
            // Keep `lo` iff the subtraction borrowed overall: hi == 0 and b == 1.
            const keep = ctMask(b & ~hi & 1);
            var out: Self = undefined;
            for (0..4) |j| out.limbs[j] = ctSelect(keep, lo[j], d[j]);
            return out;
        }

        pub fn mul(a: Self, b: Self) Self {
            return a.mulRaw(b);
        }

        pub fn sq(a: Self) Self {
            return a.mulRaw(a);
        }

        pub fn add(a: Self, b: Self) Self {
            var s: [4]u64 = undefined;
            var c: u64 = 0;
            for (0..4) |j| s[j], c = addc(a.limbs[j], b.limbs[j], c);
            return reduceOnce(s, c);
        }

        pub fn dbl(a: Self) Self {
            return a.add(a);
        }

        pub fn sub(a: Self, b: Self) Self {
            var d: [4]u64 = undefined;
            var bw: u64 = 0;
            for (0..4) |j| d[j], bw = subb(a.limbs[j], b.limbs[j], bw);
            // Add m back iff the subtraction borrowed.
            const mask = ctMask(bw);
            var out: Self = undefined;
            var c: u64 = 0;
            for (0..4) |j| out.limbs[j], c = addc(d[j], m[j] & mask, c);
            return out;
        }

        /// 1 if `a` is zero, else 0 (constant time).
        pub fn isZeroBit(a: Self) u64 {
            return ctEqBit(a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3], 0);
        }

        /// Replace `a` by `b` iff `bit == 1` (constant time).
        pub fn cmov(a: *Self, b: Self, bit: u64) void {
            const mask = ctMask(bit);
            for (0..4) |j| a.limbs[j] = ctSelect(mask, b.limbs[j], a.limbs[j]);
        }

        /// a^e for a PUBLIC comptime exponent: fixed 4-bit window over the
        /// exponent's nibbles. Control flow depends only on `e`, never on `a`.
        fn powPublic(a: Self, comptime e: u256) Self {
            var table: [16]Self = undefined;
            table[0] = one;
            table[1] = a;
            for (2..16) |i| table[i] = table[i - 1].mul(a);
            const nibbles = comptime blk: {
                var n: [64]u4 = undefined;
                for (0..64) |i| n[i] = @truncate(e >> @intCast(4 * (63 - i)));
                break :blk n;
            };
            var acc = one;
            for (nibbles, 0..) |nib, i| {
                if (i != 0) acc = acc.sq().sq().sq().sq();
                if (nib != 0) acc = acc.mul(table[nib]); // public exponent nibble
            }
            for (&table) |*entry| entry.wipe();
            return acc;
        }

        /// Multiplicative inverse by Fermat's little theorem (m prime):
        /// a^(m-2). Maps 0 to 0.
        pub fn invert(a: Self) Self {
            return a.powPublic(modulus - 2);
        }

        /// Parse a 32-byte big-endian integer. Returns null unless the value
        /// is canonical (< m). The comparison itself is constant time; only
        /// the validity verdict is branched on.
        pub fn fromBytes(bytes: [32]u8) ?Self {
            var raw: [4]u64 = undefined;
            for (0..4) |j| raw[j] = std.mem.readInt(u64, bytes[32 - 8 * (j + 1) ..][0..8], .big);
            var b: u64 = 0;
            for (0..4) |j| _, b = subb(raw[j], m[j], b);
            if (b == 0) return null; // raw >= m
            return (Self{ .limbs = raw }).mulRaw(.{ .limbs = r2 });
        }

        /// Reduce any 32-byte big-endian integer below 2m modulo m. Every
        /// 256-bit value is below 2m for both P-256 moduli, since m > 2^255.
        pub fn fromBytesReduce(bytes: [32]u8) Self {
            comptime std.debug.assert(modulus > (1 << 255));
            var raw: [4]u64 = undefined;
            for (0..4) |j| raw[j] = std.mem.readInt(u64, bytes[32 - 8 * (j + 1) ..][0..8], .big);
            const reduced = reduceOnce(raw, 0);
            return reduced.mulRaw(.{ .limbs = r2 });
        }

        /// Canonical 32-byte big-endian encoding.
        pub fn toBytes(a: Self) [32]u8 {
            const plain = a.mulRaw(.{ .limbs = .{ 1, 0, 0, 0 } });
            var out: [32]u8 = undefined;
            for (0..4) |j| std.mem.writeInt(u64, out[32 - 8 * (j + 1) ..][0..8], plain.limbs[j], .big);
            return out;
        }

        pub fn wipe(a: *Self) void {
            std.crypto.secureZero(u64, &a.limbs);
        }
    };
}

/// P-256 base field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (SEC 2 v2 sec. 2.4.2).
pub const p_int: u256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
/// P-256 group order n (SEC 2 v2 sec. 2.4.2).
pub const n_int: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

pub const Fe = MontField(p_int);
pub const Scalar = MontField(n_int);

// -- Points ------------------------------------------------------------------

/// Curve coefficient b (SEC 2 v2 sec. 2.4.2); a = -3.
const curve_b = Fe.fromInt(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b);
const gx = Fe.fromInt(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296);
const gy = Fe.fromInt(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5);

/// A point in homogeneous projective coordinates (X:Y:Z), x = X/Z, y = Y/Z.
pub const Point = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    pub const identity: Point = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };
    pub const base: Point = .{ .x = gx, .y = gy, .z = Fe.one };

    /// Complete doubling, a = -3 (ePrint 2015/1060 Algorithm 6).
    pub fn dbl(p: Point) Point {
        var t0 = p.x.sq();
        var t1 = p.y.sq();
        var t2 = p.z.sq();
        var t3 = p.x.mul(p.y);
        t3 = t3.dbl();
        var z3 = p.x.mul(p.z);
        z3 = z3.dbl();
        var y3 = curve_b.mul(t2);
        y3 = y3.sub(z3);
        var x3 = y3.dbl();
        y3 = x3.add(y3);
        x3 = t1.sub(y3);
        y3 = t1.add(y3);
        y3 = x3.mul(y3);
        x3 = x3.mul(t3);
        t3 = t2.dbl();
        t2 = t2.add(t3);
        z3 = curve_b.mul(z3);
        z3 = z3.sub(t2);
        z3 = z3.sub(t0);
        t3 = z3.dbl();
        z3 = z3.add(t3);
        t3 = t0.dbl();
        t0 = t3.add(t0);
        t0 = t0.sub(t2);
        t0 = t0.mul(z3);
        y3 = y3.add(t0);
        t0 = p.y.mul(p.z);
        t0 = t0.dbl();
        z3 = t0.mul(z3);
        x3 = x3.sub(z3);
        z3 = t0.mul(t1);
        z3 = z3.dbl().dbl();
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Complete addition, a = -3 (ePrint 2015/1060 Algorithm 4). Valid for
    /// every pair of inputs, including identity and p == q.
    pub fn add(p: Point, q: Point) Point {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t2 = p.z.mul(q.z);
        var t3 = p.x.add(p.y);
        var t4 = q.x.add(q.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = p.y.add(p.z);
        var x3 = q.y.add(q.z);
        t4 = t4.mul(x3);
        x3 = t1.add(t2);
        t4 = t4.sub(x3);
        x3 = p.x.add(p.z);
        var y3 = q.x.add(q.z);
        x3 = x3.mul(y3);
        y3 = t0.add(t2);
        y3 = x3.sub(y3);
        var z3 = curve_b.mul(t2);
        x3 = y3.sub(z3);
        z3 = x3.dbl();
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = curve_b.mul(y3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        y3 = y3.sub(t2);
        y3 = y3.sub(t0);
        t1 = y3.dbl();
        y3 = t1.add(y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3);
        y3 = y3.add(t2);
        x3 = t3.mul(x3);
        x3 = x3.sub(t1);
        z3 = t4.mul(z3);
        t1 = t3.mul(t0);
        z3 = z3.add(t1);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// Lift a PUBLIC affine point given as canonical big-endian coordinates.
    /// Fails closed (null) unless 0 <= x, y < p and y^2 = x^3 - 3x + b
    /// (SEC 1 v2 sec. 3.2.2.1 steps 2-3). The identity has no affine form, so
    /// it can never be returned. The inputs are public, so branching on the
    /// verdict reveals nothing secret.
    pub fn fromAffine(x_bytes: [32]u8, y_bytes: [32]u8) ?Point {
        const x = Fe.fromBytes(x_bytes) orelse return null;
        const y = Fe.fromBytes(y_bytes) orelse return null;
        const lhs = y.sq();
        const rhs = x.sq().mul(x).sub(x.dbl().add(x)).add(curve_b);
        if (lhs.sub(rhs).isZeroBit() != 1) return null;
        return .{ .x = x, .y = y, .z = Fe.one };
    }

    fn cmov(p: *Point, q: Point, bit: u64) void {
        p.x.cmov(q.x, bit);
        p.y.cmov(q.y, bit);
        p.z.cmov(q.z, bit);
    }

    /// Affine (x, y) as canonical big-endian bytes, or null for the identity.
    /// The inversion is constant time; only the "is identity" verdict is
    /// branched on (never true for a scalar in [1, n-1]).
    pub fn affine(p: Point) ?struct { x: [32]u8, y: [32]u8 } {
        if (p.z.isZeroBit() == 1) return null;
        var zinv = p.z.invert();
        defer zinv.wipe();
        return .{ .x = p.x.mul(zinv).toBytes(), .y = p.y.mul(zinv).toBytes() };
    }

    pub fn wipe(p: *Point) void {
        p.x.wipe();
        p.y.wipe();
        p.z.wipe();
    }
};

/// Constant-time variable-base scalar multiplication [k]P with `k` a 32-byte
/// big-endian integer (any value; it is not reduced). Fixed 4-bit windows:
/// 64 iterations of 4 doublings + 1 complete addition. The table entry is
/// picked by a masked scan of all 16 entries, so neither the control flow
/// nor the memory access pattern depends on `k`.
pub fn mulCt(p: Point, k: [32]u8) Point {
    var table: [16]Point = undefined;
    table[0] = Point.identity;
    table[1] = p;
    for (2..16) |i| table[i] = if (i % 2 == 0) table[i / 2].dbl() else table[i - 1].add(p);

    var q = Point.identity;
    for (0..64) |w| {
        if (w != 0) q = q.dbl().dbl().dbl().dbl();
        const byte = k[w / 2];
        const nib: u64 = if (w % 2 == 0) byte >> 4 else byte & 0x0f;
        var sel = Point.identity;
        for (1..16) |i| sel.cmov(table[i], ctEqBit(nib, i));
        q = q.add(sel);
        sel.wipe();
    }
    for (&table) |*e| e.wipe();
    return q;
}

/// [k]G for the P-256 generator.
pub fn mulBaseCt(k: [32]u8) Point {
    return mulCt(Point.base, k);
}

/// ECDH primitive (SEC 1 v2 sec. 3.3.1, RFC 8446 sec. 7.4.2 / RFC 4492 sec.
/// 5.10): the big-endian x-coordinate of [k]P for a validated public point
/// `peer` and a secret scalar `k`, computed in constant time. Returns null
/// only if [k]P is the identity (k = 0 mod n), which SEC 1 says to reject.
/// The intermediate point and the y-coordinate are wiped.
pub fn ecdhX(peer: Point, k: [32]u8) ?[32]u8 {
    var product = mulCt(peer, k);
    defer product.wipe();
    var aff = product.affine() orelse return null;
    defer std.crypto.secureZero(u8, &aff.y);
    return aff.x;
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const StdP256 = std.crypto.ecc.P256;

test "MontField constants: m0inv, R mod m, and arithmetic identities" {
    // m * m0inv == -1 mod 2^64 for both moduli.
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), Fe.m[0] *% Fe.m0inv);
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), Scalar.m[0] *% Scalar.m0inv);
    const a = Fe.fromInt(123456789);
    try testing.expectEqualSlices(u8, &a.toBytes(), &a.mul(Fe.one).toBytes());
    // (p - 1) + 1 == 0 and 0 - 1 == p - 1.
    const pm1 = Fe.fromInt(p_int - 1);
    try testing.expectEqual(@as(u64, 1), pm1.add(Fe.one).isZeroBit());
    try testing.expectEqualSlices(u8, &pm1.toBytes(), &Fe.zero.sub(Fe.one).toBytes());
}

test "Fe and Scalar arithmetic agree with std over random inputs" {
    var prng = std.Random.DefaultPrng.init(0x6f6e7978);
    const rnd = prng.random();
    for (0..500) |_| {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rnd.bytes(&ab);
        rnd.bytes(&bb);
        ab[0] &= 0x7f;
        bb[0] &= 0x7f;
        const a = Fe.fromBytes(ab).?;
        const b = Fe.fromBytes(bb).?;
        const sa = try StdP256.Fe.fromBytes(ab, .big);
        const sb = try StdP256.Fe.fromBytes(bb, .big);
        try testing.expectEqualSlices(u8, &sa.mul(sb).toBytes(.big), &a.mul(b).toBytes());
        try testing.expectEqualSlices(u8, &sa.add(sb).toBytes(.big), &a.add(b).toBytes());
        try testing.expectEqualSlices(u8, &sa.sub(sb).toBytes(.big), &a.sub(b).toBytes());
        try testing.expectEqualSlices(u8, &sb.sub(sa).toBytes(.big), &b.sub(a).toBytes());
        try testing.expectEqualSlices(u8, &sa.invert().toBytes(.big), &a.invert().toBytes());

        const x = Scalar.fromBytes(ab).?;
        const y = Scalar.fromBytes(bb).?;
        const sx = try StdP256.scalar.Scalar.fromBytes(ab, .big);
        const sy = try StdP256.scalar.Scalar.fromBytes(bb, .big);
        try testing.expectEqualSlices(u8, &sx.mul(sy).toBytes(.big), &x.mul(y).toBytes());
        try testing.expectEqualSlices(u8, &sx.add(sy).toBytes(.big), &x.add(y).toBytes());
        try testing.expectEqualSlices(u8, &sx.sub(sy).toBytes(.big), &x.sub(y).toBytes());
        try testing.expectEqualSlices(u8, &sx.invert().toBytes(.big), &x.invert().toBytes());
    }
}

test "fromBytes rejects non-canonical values; fromBytesReduce reduces them" {
    var pb: [32]u8 = undefined;
    std.mem.writeInt(u256, &pb, p_int, .big);
    try testing.expect(Fe.fromBytes(pb) == null);
    try testing.expect(Fe.fromBytesReduce(pb).isZeroBit() == 1);
    var nb: [32]u8 = undefined;
    std.mem.writeInt(u256, &nb, n_int + 5, .big);
    try testing.expect(Scalar.fromBytes(nb) == null);
    try testing.expectEqualSlices(u8, &Scalar.fromInt(5).toBytes(), &Scalar.fromBytesReduce(nb).toBytes());
    const ff: [32]u8 = @splat(0xff);
    try testing.expect(Scalar.fromBytes(ff) == null);
    var want: [32]u8 = undefined;
    std.mem.writeInt(u256, &want, std.math.maxInt(u256) - n_int, .big);
    try testing.expectEqualSlices(u8, &want, &Scalar.fromBytesReduce(ff).toBytes());
}

test "mulBaseCt agrees with std basePoint.mul over random and edge scalars" {
    var prng = std.Random.DefaultPrng.init(0x7032353663);
    const rnd = prng.random();
    var scalars: [64][32]u8 = undefined;
    for (&scalars) |*s| rnd.bytes(s);
    // Edge cases: 1, 2, 15, 16, n-1, a value with all-zero leading windows.
    std.mem.writeInt(u256, &scalars[0], 1, .big);
    std.mem.writeInt(u256, &scalars[1], 2, .big);
    std.mem.writeInt(u256, &scalars[2], 15, .big);
    std.mem.writeInt(u256, &scalars[3], 16, .big);
    std.mem.writeInt(u256, &scalars[4], n_int - 1, .big);
    std.mem.writeInt(u256, &scalars[5], 0x1234 << 200, .big);
    for (&scalars) |s| {
        if (std.mem.readInt(u256, &s, .big) >= n_int) continue;
        const want = (try StdP256.basePoint.mul(s, .big)).affineCoordinates();
        const got = mulBaseCt(s).affine().?;
        try testing.expectEqualSlices(u8, &want.x.toBytes(.big), &got.x);
        try testing.expectEqualSlices(u8, &want.y.toBytes(.big), &got.y);
    }
}

test "ecdhX on a variable base agrees with std P256.mul over random points and scalars" {
    var prng = std.Random.DefaultPrng.init(0x6563646878);
    const rnd = prng.random();
    for (0..48) |_| {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        rnd.bytes(&a);
        rnd.bytes(&b);
        a[0] &= 0x7f;
        b[0] &= 0x7f;
        // Peer point = [a]G (public), our scalar = b.
        const peer_std = try StdP256.basePoint.mul(a, .big);
        const peer_aff = peer_std.affineCoordinates();
        const peer = Point.fromAffine(peer_aff.x.toBytes(.big), peer_aff.y.toBytes(.big)).?;
        const want = (try peer_std.mul(b, .big)).affineCoordinates().x.toBytes(.big);
        try testing.expectEqualSlices(u8, &want, &ecdhX(peer, b).?);
    }
    // Scalar n maps to the identity and is refused.
    var nb: [32]u8 = undefined;
    std.mem.writeInt(u256, &nb, n_int, .big);
    try testing.expect(ecdhX(Point.base, nb) == null);
}

test "fromAffine fails closed on off-curve and non-canonical coordinates" {
    const g = Point.base.affine().?;
    try testing.expect(Point.fromAffine(g.x, g.y) != null);
    var bad_y = g.y;
    bad_y[31] ^= 1;
    try testing.expect(Point.fromAffine(g.x, bad_y) == null);
    var p_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &p_bytes, p_int, .big);
    try testing.expect(Point.fromAffine(p_bytes, g.y) == null);
    try testing.expect(Point.fromAffine(@splat(0), @splat(0)) == null);
}

test "mulBaseCt maps 0 and n to the identity" {
    try testing.expect(mulBaseCt(@splat(0)).affine() == null);
    var nb: [32]u8 = undefined;
    std.mem.writeInt(u256, &nb, n_int, .big);
    try testing.expect(mulBaseCt(nb).affine() == null);
}

test "complete addition handles P + P and P + (-P)" {
    const g2a = Point.base.add(Point.base).affine().?;
    const g2b = Point.base.dbl().affine().?;
    try testing.expectEqualSlices(u8, &g2a.x, &g2b.x);
    try testing.expectEqualSlices(u8, &g2a.y, &g2b.y);
    const neg_g: Point = .{ .x = gx, .y = Fe.zero.sub(gy), .z = Fe.one };
    try testing.expect(Point.base.add(neg_g).affine() == null);
    const g_again = Point.identity.add(Point.base).affine().?;
    try testing.expectEqualSlices(u8, &gx.toBytes(), &g_again.x);
}
