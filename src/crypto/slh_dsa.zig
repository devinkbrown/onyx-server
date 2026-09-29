// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SLH-DSA (SPHINCS+, FIPS 205) signature VERIFICATION — from scratch,
//! verify-only, comptime-generic over ALL 12 standard parameter sets
//! (SHA2 and SHAKE, {128,192,256}×{s,f}).
//!
//! Onyx Server verifies post-quantum certificate signatures; it never *signs* them,
//! so this module implements only `slh_verify` / `slh_verify_internal`
//! (FIPS 205 Algorithms 24 and 20). There is no key generation and no signing.
//!
//! 1.x permanently verifies and does not sign. A later signing implementation
//! requires NIST ACVP `sigGen` vectors and is not 1.x. There is no private
//! hybrid certificate profile.
//!
//! A single generic `Verifier(P)` is instantiated once per parameter set
//! (`Sha2_128s`, `Shake_256f`, …). The parameter sets differ only in the numeric
//! tree/FORS/Winternitz parameters (Table 2) and the tweakable-hash family
//! (§11):
//!
//!   * SHAKE (all sizes):  F/H/T_ℓ = SHAKE256(PK.seed ‖ ADRS ‖ M, 8n),
//!     using the FULL 32-byte ADRS; H_msg = SHAKE256(R‖PK.seed‖PK.root‖M, 8m).
//!   * SHA2 category 1 (n=16):  F/H/T_ℓ = Trunc_n(SHA-256(PK.seed ‖ toByte(0,
//!     64−n) ‖ ADRS^c ‖ M)) — all three use SHA-256; H_msg = MGF1-SHA-256(…,
//!     SHA-256(…)).
//!   * SHA2 categories 3/5 (n=24,32):  F uses SHA-256 (64−n pad), but H and T_ℓ
//!     use SHA-512 (128−n pad); H_msg = MGF1-SHA-512(…, SHA-512(…)).
//!
//! `ADRS^c` is the 22-byte SHA-2 compressed address
//! (ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32]). For SHA-2 the constant hash
//! prefix `PK.seed ‖ toByte(0, blocklen−n)` lands on a hash block boundary and is
//! precomputed once as a streaming midstate, cloned per tweakable-hash call.
//!
//! Strategy: this is a *verifier* on public data (certificate chains), not a
//! secret-dependent hot path, so it is a direct, allocation-free transcription of
//! the FIPS 205 algorithms — correctness-by-construction over cleverness. No
//! secret input ⇒ no constant-time requirement. Every entry point fails closed on
//! attacker-controlled input; it never panics.
//!
//! Correctness is pinned by INDEPENDENT NIST ACVP FIPS 205 `SLH-DSA-sigVer`
//! vectors for all 12 sets in `slh_dsa_kat.zig`; a plausible-but-wrong hash-based
//! verifier fails those accept vectors, which is exactly why the KAT — not this
//! code's own output — is the gate.
//!
//! References: FIPS 205 (final, 2024). Algorithm numbers cited inline.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Shake256 = std.crypto.hash.sha3.Shake256;

/// Tweakable-hash family (FIPS 205 §11).
pub const Family = enum { shake, sha2_cat1, sha2_cat35 };

/// A parameter set (FIPS 205 Table 2). `lg_w` is 4 (⇒ w = 16) for every
/// standardized set, so it is fixed rather than carried here.
pub const Params = struct {
    /// Security parameter / hash output length in bytes.
    n: usize,
    /// Total hypertree height.
    h: usize,
    /// Number of hypertree layers.
    d: usize,
    /// FORS tree height.
    a: usize,
    /// Number of FORS trees.
    k: usize,
    /// Message-digest length H_msg produces, in bytes.
    m: usize,
    family: Family,
};

// ── ADRS type constants (§4.2) ──────────────────────────────────────────────

const AdrsType = struct {
    const wots_hash: u32 = 0;
    const wots_pk: u32 = 1;
    const tree: u32 = 2;
    const fors_tree: u32 = 3;
    const fors_roots: u32 = 4;
};

/// The address is a fixed 32-byte array of eight big-endian 32-bit words:
///   word 0     layer address        (bytes  0.. 4)
///   words 1-3  tree address (96-bit) (bytes  4..16)
///   word 4     type                  (bytes 16..20)
///   words 5-7  type-specific         (bytes 20..32)
const Adrs = [32]u8;

inline fn writeU32be(a: *Adrs, off: usize, v: u32) void {
    std.mem.writeInt(u32, a[off..][0..4], v, .big);
}
inline fn readU32be(a: Adrs, off: usize) u32 {
    return std.mem.readInt(u32, a[off..][0..4], .big);
}
inline fn setLayerAddr(a: *Adrs, layer: u32) void {
    writeU32be(a, 0, layer);
}
/// Tree address is 96-bit; idx_tree here is < 2^64, so the high word is zero.
inline fn setTreeAddr(a: *Adrs, t: u64) void {
    writeU32be(a, 4, 0);
    std.mem.writeInt(u64, a[8..16], t, .big);
}
/// setTypeAndClear(Y): set the type word and zero the final 12 bytes.
inline fn setType(a: *Adrs, ty: u32) void {
    writeU32be(a, 16, ty);
    @memset(a[20..32], 0);
}
inline fn setKeyPairAddr(a: *Adrs, i: u32) void {
    writeU32be(a, 20, i);
}
inline fn getKeyPairAddr(a: Adrs) u32 {
    return readU32be(a, 20);
}
/// setChainAddress and setTreeHeight share word 6 (bytes 24..28).
inline fn setChainAddr(a: *Adrs, i: u32) void {
    writeU32be(a, 24, i);
}
inline fn setTreeHeight(a: *Adrs, i: u32) void {
    writeU32be(a, 24, i);
}
/// setHashAddress and setTreeIndex share word 7 (bytes 28..32).
inline fn setHashAddr(a: *Adrs, i: u32) void {
    writeU32be(a, 28, i);
}
inline fn setTreeIndex(a: *Adrs, i: u32) void {
    writeU32be(a, 28, i);
}
inline fn getTreeIndex(a: Adrs) u32 {
    return readU32be(a, 28);
}

/// ADRS^c (SHA-2 compressed address, 22 bytes):
///   ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32].
inline fn compressAdrs(a: Adrs) [22]u8 {
    var c: [22]u8 = undefined;
    c[0] = a[3];
    @memcpy(c[1..9], a[8..16]);
    c[9] = a[19];
    @memcpy(c[10..22], a[20..32]);
    return c;
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// MGF1 with a comptime SHA-2 hash (RFC 8017).
fn mgf1(comptime Hash: type, seed_parts: []const []const u8, out: []u8) void {
    var counter: u32 = 0;
    var pos: usize = 0;
    while (pos < out.len) {
        var s = Hash.init(.{});
        for (seed_parts) |p| s.update(p);
        var cbytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &cbytes, counter, .big);
        s.update(&cbytes);
        var block: [Hash.digest_length]u8 = undefined;
        s.final(&block);
        const take = @min(block.len, out.len - pos);
        @memcpy(out[pos .. pos + take], block[0..take]);
        pos += take;
        counter += 1;
    }
}

/// Convert `x` into `out.len` integers, each `b` bits, MSB-first (Algorithm 4).
/// Consumes ⌈out.len·b / 8⌉ bytes of `x`; the caller guarantees `x` is long
/// enough.
fn base2b(x: []const u8, comptime b: u6, out: []u32) void {
    var in: usize = 0;
    var bits: u6 = 0;
    var total: u32 = 0;
    const mask: u32 = (@as(u32, 1) << b) - 1;
    for (out) |*o| {
        while (bits < b) {
            total = (total << 8) | x[in];
            in += 1;
            bits += 8;
        }
        bits -= b;
        o.* = (total >> @intCast(bits)) & mask;
    }
}

/// Big-endian byte string → integer (up to 8 bytes).
fn toIntBE(bytes: []const u8) u64 {
    var v: u64 = 0;
    for (bytes) |b| v = (v << 8) | b;
    return v;
}

/// Length-checked, timing-independent byte compare. (All inputs here are public,
/// so this is hygiene, not a secret-dependency requirement.)
fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ── Generic verifier ────────────────────────────────────────────────────────

/// Build a verify-only SLH-DSA implementation for parameter set `P`.
pub fn Verifier(comptime P: Params) type {
    return struct {
        pub const N: usize = P.n;
        const H: usize = P.h;
        const D: usize = P.d;
        const HP: usize = P.h / P.d; // h′
        const A: usize = P.a;
        const K: usize = P.k;
        const M_DIGEST: usize = P.m;
        const LG_W: u6 = 4;
        const W: u32 = 16;
        const LEN1: usize = (8 * P.n) / 4; // ⌈8n/lg_w⌉, lg_w = 4
        const LEN2: usize = 3; // constant for every standardized set
        const LEN: usize = LEN1 + LEN2;

        pub const public_key_len: usize = 2 * N;
        const fors_tree_stride: usize = (A + 1) * N;
        const sig_fors_len: usize = K * fors_tree_stride;
        const xmss_sig_stride: usize = (LEN + HP) * N;
        const sig_ht_len: usize = D * xmss_sig_stride;
        pub const signature_len: usize = N + sig_fors_len + sig_ht_len;

        // Message-digest field widths (Algorithm 20 steps 7-11).
        const md_len: usize = (K * A + 7) / 8;
        const idx_tree_bits: usize = H - HP;
        const idx_tree_bytes: usize = (idx_tree_bits + 7) / 8;
        const idx_leaf_bytes: usize = (H + 8 * D - 1) / (8 * D);
        // idx_tree can span a full 64 bits (SLH-DSA-*-256f: h − h/d = 64), where a
        // `1 << 64` mask would overflow — use the all-ones mask there.
        const tree_mask: u64 = if (idx_tree_bits >= 64)
            std.math.maxInt(u64)
        else
            (@as(u64, 1) << @intCast(idx_tree_bits)) - 1;
        const leaf_mask: u64 = (@as(u64, 1) << @intCast(HP)) - 1;

        comptime {
            // Byte-length invariants derived independently, so a mistyped
            // parameter is caught at compile time rather than by a KAT.
            std.debug.assert(LEN1 == 2 * N);
            std.debug.assert(md_len + idx_tree_bytes + idx_leaf_bytes == M_DIGEST);
            std.debug.assert(HP * D == H);
        }

        // SHA-2 midstate padding: PK.seed ‖ toByte(0, blocklen−n) fills one block.
        const sha256_pad: [64 - P.n]u8 = @splat(0);
        const sha512_pad: [128 - P.n]u8 = @splat(0);

        const FBase = if (P.family == .shake) void else Sha256;
        const HwBase = if (P.family == .sha2_cat35) Sha512 else void;

        /// Precomputed tweakable-hash context keyed on PK.seed.
        const Tweak = struct {
            pk_seed: [N]u8,
            f_base: FBase,
            hw_base: HwBase,

            fn init(pk_seed_in: []const u8) Tweak {
                var pk_seed: [N]u8 = undefined;
                @memcpy(&pk_seed, pk_seed_in[0..N]);
                switch (P.family) {
                    .shake => return .{ .pk_seed = pk_seed, .f_base = {}, .hw_base = {} },
                    .sha2_cat1 => {
                        var fs = Sha256.init(.{});
                        fs.update(&pk_seed);
                        fs.update(&sha256_pad);
                        return .{ .pk_seed = pk_seed, .f_base = fs, .hw_base = {} };
                    },
                    .sha2_cat35 => {
                        var fs = Sha256.init(.{});
                        fs.update(&pk_seed);
                        fs.update(&sha256_pad);
                        var hs = Sha512.init(.{});
                        hs.update(&pk_seed);
                        hs.update(&sha512_pad);
                        return .{ .pk_seed = pk_seed, .f_base = fs, .hw_base = hs };
                    },
                }
            }

            /// F(PK.seed, ADRS, msg) — the WOTS+ chain / FORS-leaf hash.
            fn f(self: *const Tweak, adrs: Adrs, msg: []const u8) [N]u8 {
                if (P.family == .shake) {
                    var x = Shake256.init(.{});
                    x.update(&self.pk_seed);
                    x.update(&adrs);
                    x.update(msg);
                    var o: [N]u8 = undefined;
                    x.squeeze(&o);
                    return o;
                }
                var s = self.f_base; // clone SHA-256 midstate (value struct)
                const c = compressAdrs(adrs);
                s.update(&c);
                s.update(msg);
                var digest: [32]u8 = undefined;
                s.final(&digest);
                return digest[0..N].*;
            }

            /// H / T_ℓ(PK.seed, ADRS, msg) — tree-node and root-compression hash.
            /// SHA-512 for SHA-2 cat 3/5; otherwise identical to F.
            fn hw(self: *const Tweak, adrs: Adrs, msg: []const u8) [N]u8 {
                if (P.family == .sha2_cat35) {
                    var s = self.hw_base; // clone SHA-512 midstate
                    const c = compressAdrs(adrs);
                    s.update(&c);
                    s.update(msg);
                    var digest: [64]u8 = undefined;
                    s.final(&digest);
                    return digest[0..N].*;
                }
                return self.f(adrs, msg);
            }
        };

        /// H_msg(R, PK.seed, PK.root, M) → m-byte digest. The message `m_parts`
        /// are concatenated in place so no large M′ is materialized.
        fn hMsg(
            pk_seed: []const u8,
            pk_root: []const u8,
            r: []const u8,
            m_parts: []const []const u8,
            out: *[M_DIGEST]u8,
        ) void {
            if (P.family == .shake) {
                var x = Shake256.init(.{});
                x.update(r);
                x.update(pk_seed);
                x.update(pk_root);
                for (m_parts) |p| x.update(p);
                x.squeeze(out);
                return;
            }
            const Inner = if (P.family == .sha2_cat1) Sha256 else Sha512;
            var s = Inner.init(.{});
            s.update(r);
            s.update(pk_seed);
            s.update(pk_root);
            for (m_parts) |p| s.update(p);
            var inner: [Inner.digest_length]u8 = undefined;
            s.final(&inner);
            mgf1(Inner, &.{ r, pk_seed, &inner }, out);
        }

        /// chain(X, i, s): apply F for `s` steps starting at chain position `i`.
        fn chain(x: [N]u8, start: u32, steps: u32, th: *const Tweak, adrs: *Adrs) [N]u8 {
            var tmp = x;
            var j = start;
            while (j < start + steps) : (j += 1) {
                setHashAddr(adrs, j);
                tmp = th.f(adrs.*, &tmp);
            }
            return tmp;
        }

        /// Expand the WOTS+ message into `len` base-w chain lengths, including the
        /// len2 checksum chains (Algorithm 8, steps 1-6).
        fn wotsChainLengths(m: [N]u8) [LEN]u32 {
            var msg: [LEN]u32 = undefined;
            base2b(&m, LG_W, msg[0..LEN1]);
            var csum: u32 = 0;
            for (msg[0..LEN1]) |mi| csum += W - 1 - mi;
            const shift: u6 = @intCast((8 - ((LEN2 * @as(usize, LG_W)) % 8)) % 8);
            csum <<= shift;
            // toByte(csum, ⌈len2·lg_w/8⌉ = 2) then base_2^b to len2 chains.
            var csum_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &csum_bytes, @intCast(csum), .big);
            base2b(&csum_bytes, LG_W, msg[LEN1..LEN]);
            return msg;
        }

        /// wots_pkFromSig (Algorithm 8).
        fn wotsPkFromSig(sig: []const u8, m: [N]u8, th: *const Tweak, adrs: *Adrs) [N]u8 {
            const msg = wotsChainLengths(m);
            var pk_buf: [LEN * N]u8 = undefined;
            for (0..LEN) |i| {
                setChainAddr(adrs, @intCast(i));
                const start = msg[i];
                const chained = chain(sig[i * N ..][0..N].*, start, W - 1 - start, th, adrs);
                @memcpy(pk_buf[i * N ..][0..N], &chained);
            }
            var pk_adrs = adrs.*;
            setType(&pk_adrs, AdrsType.wots_pk);
            setKeyPairAddr(&pk_adrs, getKeyPairAddr(adrs.*));
            return th.hw(pk_adrs, &pk_buf); // T_len
        }

        /// xmss_pkFromSig (Algorithm 10).
        fn xmssPkFromSig(idx: u32, sig_xmss: []const u8, m: [N]u8, th: *const Tweak, adrs: *Adrs) [N]u8 {
            setType(adrs, AdrsType.wots_hash);
            setKeyPairAddr(adrs, idx);
            const wots_sig = sig_xmss[0 .. LEN * N];
            const auth = sig_xmss[LEN * N ..][0 .. HP * N];

            var node = wotsPkFromSig(wots_sig, m, th, adrs);

            setType(adrs, AdrsType.tree);
            setTreeIndex(adrs, idx);
            for (0..HP) |kk| {
                setTreeHeight(adrs, @intCast(kk + 1));
                const auth_k = auth[kk * N ..][0..N];
                var buf: [2 * N]u8 = undefined;
                if ((idx >> @intCast(kk)) & 1 == 0) {
                    setTreeIndex(adrs, getTreeIndex(adrs.*) / 2);
                    @memcpy(buf[0..N], &node);
                    @memcpy(buf[N..], auth_k);
                } else {
                    setTreeIndex(adrs, (getTreeIndex(adrs.*) - 1) / 2);
                    @memcpy(buf[0..N], auth_k);
                    @memcpy(buf[N..], &node);
                }
                node = th.hw(adrs.*, &buf); // H
            }
            return node;
        }

        /// ht_verify (Algorithm 19).
        fn htVerify(
            m: [N]u8,
            sig_ht: []const u8,
            th: *const Tweak,
            idx_tree_init: u64,
            idx_leaf_init: u32,
            pk_root: []const u8,
        ) bool {
            var adrs: Adrs = @splat(0);
            var idx_tree = idx_tree_init;
            setTreeAddr(&adrs, idx_tree);

            var node = xmssPkFromSig(idx_leaf_init, sig_ht[0..xmss_sig_stride], m, th, &adrs);

            for (1..D) |j| {
                const idx_leaf: u32 = @intCast(idx_tree & leaf_mask);
                idx_tree >>= @intCast(HP);
                setLayerAddr(&adrs, @intCast(j));
                setTreeAddr(&adrs, idx_tree);
                const off = j * xmss_sig_stride;
                node = xmssPkFromSig(idx_leaf, sig_ht[off..][0..xmss_sig_stride], node, th, &adrs);
            }
            return ctEqual(&node, pk_root);
        }

        /// fors_pkFromSig (Algorithm 17): recover the FORS public key (n bytes).
        fn forsPkFromSig(sig_fors: []const u8, md: []const u8, th: *const Tweak, adrs: *Adrs) [N]u8 {
            var indices: [K]u32 = undefined;
            base2b(md, @intCast(A), &indices);

            var roots: [K * N]u8 = undefined;
            for (0..K) |i| {
                const tree = sig_fors[i * fors_tree_stride ..][0..fors_tree_stride];
                const sk = tree[0..N];
                const auth = tree[N .. N + A * N];

                setTreeHeight(adrs, 0);
                setTreeIndex(adrs, @intCast(i * (@as(usize, 1) << @intCast(A)) + indices[i]));
                var node = th.f(adrs.*, sk); // F(PK.seed, ADRS, sk)

                for (0..A) |j| {
                    setTreeHeight(adrs, @intCast(j + 1));
                    const auth_j = auth[j * N ..][0..N];
                    var buf: [2 * N]u8 = undefined;
                    if ((indices[i] >> @intCast(j)) & 1 == 0) {
                        setTreeIndex(adrs, getTreeIndex(adrs.*) / 2);
                        @memcpy(buf[0..N], &node);
                        @memcpy(buf[N..], auth_j);
                    } else {
                        setTreeIndex(adrs, (getTreeIndex(adrs.*) - 1) / 2);
                        @memcpy(buf[0..N], auth_j);
                        @memcpy(buf[N..], &node);
                    }
                    node = th.hw(adrs.*, &buf); // H
                }
                @memcpy(roots[i * N ..][0..N], &node);
            }

            var pk_adrs = adrs.*;
            setType(&pk_adrs, AdrsType.fors_roots);
            setKeyPairAddr(&pk_adrs, getKeyPairAddr(adrs.*));
            return th.hw(pk_adrs, &roots); // T_k
        }

        /// `slh_verify_internal(M, SIG, PK)` (Algorithm 20). `m_parts` is the
        /// internal message provided as ordered slices concatenated in place.
        fn verifyInternalParts(pk: []const u8, m_parts: []const []const u8, sig: []const u8) bool {
            if (pk.len != public_key_len) return false;
            if (sig.len != signature_len) return false;

            const pk_seed = pk[0..N];
            const pk_root = pk[N .. 2 * N];

            const r = sig[0..N];
            const sig_fors = sig[N .. N + sig_fors_len];
            const sig_ht = sig[N + sig_fors_len ..][0..sig_ht_len];

            var digest: [M_DIGEST]u8 = undefined;
            hMsg(pk_seed, pk_root, r, m_parts, &digest);

            const md = digest[0..md_len];
            const idx_tree = toIntBE(digest[md_len .. md_len + idx_tree_bytes]) & tree_mask;
            const idx_leaf: u32 =
                @intCast(toIntBE(digest[md_len + idx_tree_bytes ..][0..idx_leaf_bytes]) & leaf_mask);

            const th = Tweak.init(pk_seed);

            var adrs: Adrs = @splat(0);
            setTreeAddr(&adrs, idx_tree);
            setType(&adrs, AdrsType.fors_tree);
            setKeyPairAddr(&adrs, idx_leaf);

            const pk_fors = forsPkFromSig(sig_fors, md, &th, &adrs);
            return htVerify(pk_fors, sig_ht, &th, idx_tree, idx_leaf, pk_root);
        }

        /// `slh_verify_internal` over a single contiguous internal message.
        pub fn verifyInternal(pk: []const u8, m_prime: []const u8, sig: []const u8) bool {
            return verifyInternalParts(pk, &.{m_prime}, sig);
        }

        /// `slh_verify(M, ctx, SIG, PK)` (Algorithm 24), pure (non-prehashed).
        /// `ctx` is the context string (empty for X.509 certificate signatures
        /// per draft-ietf-lamps-x509-slhdsa). Returns `false` on any failure,
        /// including `ctx.len > 255`.
        pub fn verify(pk: []const u8, msg: []const u8, ctx: []const u8, sig: []const u8) bool {
            if (ctx.len > 255) return false;
            // M′ = toByte(0,1) ‖ toByte(|ctx|,1) ‖ ctx ‖ M.
            const prefix = [2]u8{ 0x00, @intCast(ctx.len) };
            return verifyInternalParts(pk, &.{ &prefix, ctx, msg }, sig);
        }
    };
}

// ── The 12 standardized parameter sets (FIPS 205 Table 2) ───────────────────

pub const Sha2_128s = Verifier(.{ .n = 16, .h = 63, .d = 7, .a = 12, .k = 14, .m = 30, .family = .sha2_cat1 });
pub const Sha2_128f = Verifier(.{ .n = 16, .h = 66, .d = 22, .a = 6, .k = 33, .m = 34, .family = .sha2_cat1 });
pub const Sha2_192s = Verifier(.{ .n = 24, .h = 63, .d = 7, .a = 14, .k = 17, .m = 39, .family = .sha2_cat35 });
pub const Sha2_192f = Verifier(.{ .n = 24, .h = 66, .d = 22, .a = 8, .k = 33, .m = 42, .family = .sha2_cat35 });
pub const Sha2_256s = Verifier(.{ .n = 32, .h = 64, .d = 8, .a = 14, .k = 22, .m = 47, .family = .sha2_cat35 });
pub const Sha2_256f = Verifier(.{ .n = 32, .h = 68, .d = 17, .a = 9, .k = 35, .m = 49, .family = .sha2_cat35 });
pub const Shake_128s = Verifier(.{ .n = 16, .h = 63, .d = 7, .a = 12, .k = 14, .m = 30, .family = .shake });
pub const Shake_128f = Verifier(.{ .n = 16, .h = 66, .d = 22, .a = 6, .k = 33, .m = 34, .family = .shake });
pub const Shake_192s = Verifier(.{ .n = 24, .h = 63, .d = 7, .a = 14, .k = 17, .m = 39, .family = .shake });
pub const Shake_192f = Verifier(.{ .n = 24, .h = 66, .d = 22, .a = 8, .k = 33, .m = 42, .family = .shake });
pub const Shake_256s = Verifier(.{ .n = 32, .h = 64, .d = 8, .a = 14, .k = 22, .m = 47, .family = .shake });
pub const Shake_256f = Verifier(.{ .n = 32, .h = 68, .d = 17, .a = 9, .k = 35, .m = 49, .family = .shake });

test "slh-dsa parameter and structural self-consistency across all sets" {
    // Expected (public_key_len, signature_len) per set, independent of the code
    // paths that compute them — a mistyped parameter surfaces here before the
    // (expensive) KAT runs. Independent published-vector KATs live in
    // slh_dsa_kat.zig.
    inline for (.{
        .{ Sha2_128s, 32, 7856 },   .{ Sha2_128f, 32, 17088 },
        .{ Sha2_192s, 48, 16224 },  .{ Sha2_192f, 48, 35664 },
        .{ Sha2_256s, 64, 29792 },  .{ Sha2_256f, 64, 49856 },
        .{ Shake_128s, 32, 7856 },  .{ Shake_128f, 32, 17088 },
        .{ Shake_192s, 48, 16224 }, .{ Shake_192f, 48, 35664 },
        .{ Shake_256s, 64, 29792 }, .{ Shake_256f, 64, 49856 },
    }) |spec| {
        const V = spec[0];
        try std.testing.expectEqual(@as(usize, spec[1]), V.public_key_len);
        try std.testing.expectEqual(@as(usize, spec[2]), V.signature_len);

        // Structural rejects fail closed (no panic, no OOB) for every set.
        const pk: [spec[1]]u8 = @splat(0);
        const sig: [spec[2]]u8 = @splat(0);
        try std.testing.expect(!V.verifyInternal(pk[0 .. spec[1] - 1], "m", &sig));
        try std.testing.expect(!V.verifyInternal(&pk, "m", sig[0 .. spec[2] - 1]));
        const big_ctx: [256]u8 = @splat(0);
        try std.testing.expect(!V.verify(&pk, "m", &big_ctx, &sig));
    }

    // base_2^b MSB-first spot check: 0xAB, 0xCD → nibbles A,B,C.
    var out3: [3]u32 = undefined;
    base2b(&[_]u8{ 0xAB, 0xCD }, 4, &out3);
    try std.testing.expectEqual([3]u32{ 0xA, 0xB, 0xC }, out3);

    // Compressed-ADRS field selection.
    var a: Adrs = @splat(0);
    setLayerAddr(&a, 6);
    setTreeAddr(&a, 0x0102030405);
    setType(&a, AdrsType.fors_tree);
    setKeyPairAddr(&a, 0x11223344);
    const c = compressAdrs(a);
    try std.testing.expectEqual(@as(u8, 6), c[0]); // ADRS[3] = layer LSB
    try std.testing.expectEqual(@as(u8, 3), c[9]); // ADRS[19] = type LSB
    try std.testing.expectEqual(@as(u8, 0x11), c[10]); // ADRS[20] = keypair MSB
}
