// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! dudect-style constant-time verification harness (roadmap 0.4).
//!
//! This is a STANDALONE, opt-in tool — `zig build ct-check` — and is NOT part of
//! `zig build test`. That separation is deliberate: a timing measurement is
//! inherently noisy, and folding a "measure two timings, assert a bound" check
//! into the 6100-test suite would make the suite flaky. Here the measurement
//! lives in its own binary that a human (or a dedicated CI job) runs on purpose.
//!
//! Method (Reparaz/Balasch/Verbauwhede, "Dude, is my code constant time?"):
//!
//!   * Two input classes per primitive: a FIXED secret and a RANDOM secret.
//!   * Interleave the two classes on a shuffled schedule so slow drift (thermal
//!     throttling, frequency scaling) hits both classes equally and cancels.
//!   * Time only the secret-dependent operation with a monotonic ns clock.
//!   * Crop tail outliers (scheduler preemptions, migrations) at several
//!     percentiles and, for each crop, run Welch's t-test between the two
//!     classes. Report the largest |t| over all crops.
//!
//! Interpreting |t| (dudect's rule of thumb): |t| < ~4.5 ⇒ no timing dependence
//! detected; a large, crop-stable |t| ⇒ a real leak. We gate at a GENEROUS
//! |t| < 10 so ordinary machine noise never trips it while a gross leak still
//! would. A PASS here is evidence for — not a proof of — the constant-time claim.
//!
//! Covered secret-dependent operations:
//!   * ECDSA-P256 sign — secrets = the private scalar d AND the nonce k. The
//!     message is the SAME constant in both classes, and the nonce is derived
//!     deterministically from (d, H(m)). So the fixed class repeats one (d, k)
//!     pair and the random class gets a fresh (d, k) pair every sample. Only
//!     secrets differ between the classes. The hashed input length, the
//!     message bytes and the allocator do not, so they cannot cause a
//!     difference. Varying the message under a fixed key would be the weaker
//!     test: it changes k, but it never repeats a secret, so the classes would
//!     not differ in what the branch predictor and caches can learn.
//!   * ECDSA-P256 key derivation — secret = the private scalar (d·G), via the
//!     constant-time `keyPairFromSecretKey`.
//!   * X25519 scalarmult — secret = the private scalar (Montgomery ladder).
//!   * RSA-2048 private op (PKCS#1 v1.5 sign, CRT + base blinding). RSA key
//!     generation is not exposed here, so we cannot randomize the KEY across the
//!     two classes the way we do for ECDSA/X25519. Instead we hold the private
//!     key fixed and vary the MESSAGE representative (fixed vs random digest),
//!     which validates exactly the property base blinding exists to provide:
//!     the private exponentiation's timing is independent of its input. This is
//!     an honest narrowing of the axis and is called out in the report.
//!
//! ECDSA history (2026-11-07): this check failed for ECDSA sign with
//! |t| ~ 100-540 (native) and ~ 18-22 (-Dcpu=baseline). The fixed class ran
//! ~2 us faster than the random class out of ~320 us. That was a REAL
//! leak, not a harness artifact. Isolating the steps put almost all of it in
//! `std.crypto.ecc.P256.mul`. Fixed vs random scalar gave |t| ~ 870, while
//! scalar inversion was clean and two interleaved fixed scalars were nearly
//! equal. Under ReleaseFast, LLVM had compiled std's mask-based selects,
//! including the secret-nibble table lookup, into conditional jumps, so the
//! branch predictor sped up a repeated scalar. `ecdsa_p256.sign` now runs on
//! `src/crypto/p256_ct.zig`, which keeps those selects branch-free, and the
//! check passes with |t| < 3.
//!
//! Tunable via environment variables:
//!   * CT_ITERS      — samples per class for ECDSA/X25519 (default 25000).
//!   * CT_RSA_ITERS  — samples per class for RSA          (default 500).

const std = @import("std");
const onyx_server = @import("onyx_server");

const ecdsa = onyx_server.crypto.ecdsa_p256;
const kx = onyx_server.crypto.kx;
const rsa_sign = onyx_server.crypto.rsa_sign;
const rsa_verify = onyx_server.crypto.rsa_verify;
const random = onyx_server.crypto.random;

/// |t| at or above this is reported as a FAIL. Generous on purpose (dudect's
/// leak rule of thumb is ~4.5); the slack absorbs CI/desktop noise while still
/// catching a gross, obviously-secret-dependent branch.
const threshold_t: f64 = 10.0;

/// Default sample counts per class, chosen to keep a full run to a minute or so
/// on a typical machine (ECDSA sign and the clean-room RSA private op are the
/// slow ops). Raise them via CT_ITERS / CT_RSA_ITERS for a more sensitive sweep.
const default_ec_iters: usize = 25_000;
const default_rsa_iters: usize = 500;

/// Percentile crops applied before each t-test. 1.0 keeps every sample; the
/// lower crops progressively discard the slow tail (preemptions, page faults).
const crops = [_]f64{ 1.0, 0.9999, 0.999, 0.99, 0.95, 0.90, 0.80, 0.70, 0.60, 0.50 };

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    const ec_iters = envUsize("CT_ITERS", default_ec_iters);
    const rsa_iters = envUsize("CT_RSA_ITERS", default_rsa_iters);

    var drbg = try random.Drbg.init();
    defer drbg.deinit();

    std.debug.print(
        \\[ct-check] dudect-style constant-time verification (roadmap 0.4)
        \\[ct-check] gate: |t| < {d:.1}  (dudect leak rule of thumb ~4.5)
        \\[ct-check] ecdsa/x25519 samples/class={d}  rsa samples/class={d}
        \\
    , .{ threshold_t, ec_iters, rsa_iters });

    var all_pass = true;

    all_pass = (try runEcdsa(alloc, &drbg, ec_iters)) and all_pass;
    all_pass = (try runEcdsaKeygen(alloc, &drbg, ec_iters)) and all_pass;
    all_pass = (try runX25519(alloc, &drbg, ec_iters)) and all_pass;
    all_pass = (try runRsa(alloc, &drbg, rsa_iters)) and all_pass;

    if (all_pass) {
        std.debug.print("\n[ct-check] RESULT: PASS — no timing dependence above |t|={d:.1}\n", .{threshold_t});
    } else {
        std.debug.print("\n[ct-check] RESULT: FAIL — a primitive exceeded |t|={d:.1}\n", .{threshold_t});
        std.process.exit(1);
    }
}

// -- ECDSA-P256 sign ---------------------------------------------------------

fn runEcdsa(alloc: std.mem.Allocator, drbg: *random.Drbg, count: usize) !bool {
    const msg = "onyx ct-check ecdsa-p256 fixed message";

    // Fixed class: one canonical scalar reused for every fixed measurement.
    const fixed_scalar = [_]u8{
        0x3b, 0x9a, 0xca, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    };
    const fixed_sk = try ecdsa.SecretKey.fromBytes(fixed_scalar);
    const fixed_kp = try ecdsa.keyPairFromSecretKey(fixed_sk);

    // Random class: a distinct fresh keypair per measurement.
    const random_kps = try alloc.alloc(ecdsa.KeyPair, count);
    defer alloc.free(random_kps);
    for (random_kps) |*kp| kp.* = try randomEcdsaKeyPair(drbg);

    const fixed_t = try alloc.alloc(u64, count);
    defer alloc.free(fixed_t);
    const random_t = try alloc.alloc(u64, count);
    defer alloc.free(random_t);

    const schedule = try buildSchedule(alloc, drbg, count);
    defer alloc.free(schedule);

    // Warm up so the first-touch/frequency-ramp cost is not charged to sample 0.
    var w: usize = 0;
    while (w < 512) : (w += 1) {
        std.mem.doNotOptimizeAway(ecdsa.sign(msg, fixed_kp) catch unreachable);
    }

    // The selected keypair is copied into one reused stack slot immediately
    // before the timed region. That equalizes the memory-access pattern between
    // classes (fixed = one hot line; random = cold lines from a big array would
    // otherwise add cache-miss latency to only the random class) so the t-test
    // reflects dependence on the secret VALUE, not on where the harness stored
    // it. `doNotOptimizeAway(&work)` forbids hoisting the fixed-class call.
    var work: ecdsa.KeyPair = undefined;
    var fi: usize = 0;
    var ri: usize = 0;
    for (schedule) |is_fixed| {
        work = if (is_fixed) fixed_kp else random_kps[ri];
        std.mem.doNotOptimizeAway(&work);
        const t0 = monotonicNanos();
        const sig = ecdsa.sign(msg, work) catch |e| std.debug.panic("ecdsa sign: {s}", .{@errorName(e)});
        const t1 = monotonicNanos();
        std.mem.doNotOptimizeAway(sig);
        if (is_fixed) {
            fixed_t[fi] = t1 -% t0;
            fi += 1;
        } else {
            random_t[ri] = t1 -% t0;
            ri += 1;
        }
    }

    return report(alloc, "ECDSA-P256 sign      (secrets = key d + nonce k)", fixed_t, random_t);
}

fn randomEcdsaKeyPair(drbg: *random.Drbg) !ecdsa.KeyPair {
    while (true) {
        var scalar: [32]u8 = undefined;
        try drbg.fillPublic(&scalar);
        const sk = ecdsa.SecretKey.fromBytes(scalar) catch continue;
        // Rejects d outside [1, n-1], so `sign` can never fail on these keys.
        const kp = ecdsa.keyPairFromSecretKey(sk) catch continue;
        return kp;
    }
}

// -- ECDSA-P256 key derivation ----------------------------------------------

fn runEcdsaKeygen(alloc: std.mem.Allocator, drbg: *random.Drbg, count: usize) !bool {
    // Same fixed scalar as the sign check. Random class: a fresh valid scalar
    // per measurement.
    const fixed_sk = try ecdsa.SecretKey.fromBytes(.{
        0x3b, 0x9a, 0xca, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    });
    const random_sks = try alloc.alloc(ecdsa.SecretKey, count);
    defer alloc.free(random_sks);
    for (random_sks) |*sk| sk.* = (try randomEcdsaKeyPair(drbg)).secret_key;

    const fixed_t = try alloc.alloc(u64, count);
    defer alloc.free(fixed_t);
    const random_t = try alloc.alloc(u64, count);
    defer alloc.free(random_t);

    const schedule = try buildSchedule(alloc, drbg, count);
    defer alloc.free(schedule);

    var w: usize = 0;
    while (w < 512) : (w += 1) {
        std.mem.doNotOptimizeAway(ecdsa.keyPairFromSecretKey(fixed_sk) catch unreachable);
    }

    // Hot reused slot, as in the sign loop.
    var work: ecdsa.SecretKey = undefined;
    var fi: usize = 0;
    var ri: usize = 0;
    for (schedule) |is_fixed| {
        work = if (is_fixed) fixed_sk else random_sks[ri];
        std.mem.doNotOptimizeAway(&work);
        const t0 = monotonicNanos();
        const kp = ecdsa.keyPairFromSecretKey(work) catch |e| std.debug.panic("ecdsa keygen: {s}", .{@errorName(e)});
        const t1 = monotonicNanos();
        std.mem.doNotOptimizeAway(kp);
        if (is_fixed) {
            fixed_t[fi] = t1 -% t0;
            fi += 1;
        } else {
            random_t[ri] = t1 -% t0;
            ri += 1;
        }
    }

    return report(alloc, "ECDSA-P256 keygen    (secret = private scalar, d*G)", fixed_t, random_t);
}

// -- X25519 scalar multiplication --------------------------------------------

fn runX25519(alloc: std.mem.Allocator, drbg: *random.Drbg, count: usize) !bool {
    // A fixed, valid peer public key (both classes multiply against it).
    var peer_seed: [kx.X25519Kx.seed_len]u8 = undefined;
    @memset(&peer_seed, 0x5a);
    var peer_kp = try kx.X25519Kx.generateDeterministic(peer_seed);
    defer peer_kp.wipe();
    const peer_public = peer_kp.public_key;

    // Fixed class: the all-zero secret (dudect's canonical fixed input). X25519
    // clamps it to a fixed scalar; against a normal peer point this yields a
    // valid, non-low-order shared secret.
    const fixed_sk = kx.SecretKey.init(@as([32]u8, @splat(0)));

    // Random class: a fresh random secret scalar per measurement.
    const random_sks = try alloc.alloc(kx.SecretKey, count);
    defer alloc.free(random_sks);
    for (random_sks) |*sk| {
        var bytes: [32]u8 = undefined;
        try drbg.fillPublic(&bytes);
        sk.* = kx.SecretKey.init(bytes);
    }

    const fixed_t = try alloc.alloc(u64, count);
    defer alloc.free(fixed_t);
    const random_t = try alloc.alloc(u64, count);
    defer alloc.free(random_t);

    const schedule = try buildSchedule(alloc, drbg, count);
    defer alloc.free(schedule);

    var w: usize = 0;
    while (w < 512) : (w += 1) {
        std.mem.doNotOptimizeAway(kx.X25519Kx.sharedSecret(&fixed_sk, peer_public) catch unreachable);
    }

    // Copy the selected secret into one reused hot slot before timing (see the
    // ECDSA loop for the rationale — equalizes storage access so the t-test
    // isolates value-dependence).
    var work: kx.SecretKey = undefined;
    var fi: usize = 0;
    var ri: usize = 0;
    for (schedule) |is_fixed| {
        work = if (is_fixed) fixed_sk else random_sks[ri];
        std.mem.doNotOptimizeAway(&work);
        const t0 = monotonicNanos();
        const ss = kx.X25519Kx.sharedSecret(&work, peer_public) catch |e| std.debug.panic("x25519: {s}", .{@errorName(e)});
        const t1 = monotonicNanos();
        std.mem.doNotOptimizeAway(ss);
        if (is_fixed) {
            fixed_t[fi] = t1 -% t0;
            fi += 1;
        } else {
            random_t[ri] = t1 -% t0;
            ri += 1;
        }
    }

    return report(alloc, "X25519 scalarmult    (secret = private scalar)", fixed_t, random_t);
}

// -- RSA-2048 private operation ----------------------------------------------

fn runRsa(alloc: std.mem.Allocator, drbg: *random.Drbg, count: usize) !bool {
    const priv = rsaTestKey();

    // Axis note: no RSA keygen is exposed, so we vary the INPUT (message digest)
    // rather than the KEY. Fixed class = one fixed digest; random class = fresh
    // random digests. With base blinding, the private op's timing should not
    // depend on the input — that is what we measure.
    const fixed_digest = [_]u8{
        0x24, 0xdd, 0xad, 0xe2, 0x12, 0x20, 0x77, 0xb8,
        0x6a, 0x4e, 0xa8, 0xed, 0x26, 0x9e, 0xc4, 0x4c,
        0x16, 0xe3, 0xc7, 0x10, 0x5d, 0x30, 0xc2, 0x8c,
        0x3a, 0x70, 0x60, 0xbc, 0x71, 0x8f, 0x89, 0xa5,
    };

    const random_digests = try alloc.alloc([32]u8, count);
    defer alloc.free(random_digests);
    for (random_digests) |*d| try drbg.fillPublic(d);

    const fixed_t = try alloc.alloc(u64, count);
    defer alloc.free(fixed_t);
    const random_t = try alloc.alloc(u64, count);
    defer alloc.free(random_t);

    const schedule = try buildSchedule(alloc, drbg, count);
    defer alloc.free(schedule);

    var out: [rsa_verify.max_bytes]u8 = undefined;

    var w: usize = 0;
    while (w < 16) : (w += 1) {
        std.mem.doNotOptimizeAway(rsa_sign.signPkcs1v15(priv, .sha256, &fixed_digest, &out) catch unreachable);
    }

    // Copy the selected digest into one reused hot slot before timing (equalizes
    // storage access; see the ECDSA loop). Negligible for RSA at ~ms/op, kept for
    // methodological consistency.
    var work: [32]u8 = undefined;
    var fi: usize = 0;
    var ri: usize = 0;
    for (schedule) |is_fixed| {
        work = if (is_fixed) fixed_digest else random_digests[ri];
        std.mem.doNotOptimizeAway(&work);
        const t0 = monotonicNanos();
        const sig = rsa_sign.signPkcs1v15(priv, .sha256, &work, &out) catch |e| std.debug.panic("rsa sign: {s}", .{@errorName(e)});
        const t1 = monotonicNanos();
        std.mem.doNotOptimizeAway(sig.len);
        if (is_fixed) {
            fixed_t[fi] = t1 -% t0;
            fi += 1;
        } else {
            random_t[ri] = t1 -% t0;
            ri += 1;
        }
    }

    return report(alloc, "RSA-2048 sign        (blinded; secret = fixed key, vary input)", fixed_t, random_t);
}

// -- Statistics --------------------------------------------------------------

/// Streaming (Welford) accumulator for count / mean / sum-of-squares.
const Acc = struct {
    n: u64 = 0,
    mean: f64 = 0,
    m2: f64 = 0,

    fn add(self: *Acc, x: f64) void {
        self.n += 1;
        const delta = x - self.mean;
        self.mean += delta / @as(f64, @floatFromInt(self.n));
        self.m2 += delta * (x - self.mean);
    }

    fn variance(self: Acc) f64 {
        if (self.n < 2) return 0;
        return self.m2 / @as(f64, @floatFromInt(self.n - 1));
    }
};

/// Welch's two-sample t-statistic (unequal variances). Zero when a side has too
/// few samples or both are degenerate (identical constant timings).
fn welchT(a: Acc, b: Acc) f64 {
    if (a.n < 2 or b.n < 2) return 0;
    const va = a.variance() / @as(f64, @floatFromInt(a.n));
    const vb = b.variance() / @as(f64, @floatFromInt(b.n));
    const denom = @sqrt(va + vb);
    if (denom == 0) return 0;
    return (a.mean - b.mean) / denom;
}

/// Run the t-test over every crop, print the summary line, and return whether
/// the largest |t| stayed under the gate.
fn report(alloc: std.mem.Allocator, name: []const u8, fixed_t: []const u64, random_t: []const u64) !bool {
    // Combined, sorted view for percentile crop cutoffs.
    const combined = try alloc.alloc(u64, fixed_t.len + random_t.len);
    defer alloc.free(combined);
    @memcpy(combined[0..fixed_t.len], fixed_t);
    @memcpy(combined[fixed_t.len..], random_t);
    std.mem.sort(u64, combined, {}, std.sort.asc(u64));

    var max_abs_t: f64 = 0;
    var max_crop: f64 = 1.0;
    var max_n: u64 = 0;
    for (crops) |p| {
        const idx: usize = @intFromFloat(p * @as(f64, @floatFromInt(combined.len - 1)));
        const cutoff = combined[idx];

        var fa: Acc = .{};
        var ra: Acc = .{};
        for (fixed_t) |x| if (x <= cutoff) fa.add(@floatFromInt(x));
        for (random_t) |x| if (x <= cutoff) ra.add(@floatFromInt(x));

        const t = welchT(fa, ra);
        const at = @abs(t);
        if (at > max_abs_t) {
            max_abs_t = at;
            max_crop = p;
            max_n = fa.n + ra.n;
        }
    }

    // Uncropped means for human context.
    var full_fixed: Acc = .{};
    var full_random: Acc = .{};
    for (fixed_t) |x| full_fixed.add(@floatFromInt(x));
    for (random_t) |x| full_random.add(@floatFromInt(x));

    const pass = max_abs_t < threshold_t;
    std.debug.print(
        "[ct-check] {s}\n" ++
            "             max|t|={d:.2} @crop={d:.2}% (kept {d} samples)  " ++
            "fixed_mean={d:.0}ns random_mean={d:.0}ns  => {s}\n",
        .{
            name,
            max_abs_t,
            max_crop * 100.0,
            max_n,
            full_fixed.mean,
            full_random.mean,
            if (pass) "PASS" else "FAIL",
        },
    );
    return pass;
}

// -- Helpers -----------------------------------------------------------------

/// A balanced, shuffled fixed/random schedule of length `2*count` (exactly
/// `count` of each). Interleaving the classes cancels slow, monotonic drift.
fn buildSchedule(alloc: std.mem.Allocator, drbg: *random.Drbg, count: usize) ![]bool {
    const total = count * 2;
    const sched = try alloc.alloc(bool, total);
    for (sched[0..count]) |*b| b.* = true;
    for (sched[count..]) |*b| b.* = false;

    // Fisher-Yates using the project DRBG for unbiased indices.
    var i: usize = total;
    while (i > 1) {
        i -= 1;
        const j = try drbg.boundedInt(usize, i + 1);
        const tmp = sched[i];
        sched[i] = sched[j];
        sched[j] = tmp;
    }
    return sched;
}

/// Monotonic clock in nanoseconds. Mirrors substrate/platform.zig's per-OS
/// sourcing but at nanosecond resolution (the ops here run in microseconds).
fn monotonicNanos() u64 {
    switch (@import("builtin").os.tag) {
        .linux => {
            var ts: std.os.linux.timespec = undefined;
            _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
            return nsFrom(@intCast(ts.sec), @intCast(ts.nsec));
        },
        .windows => {
            var freq: i64 = 0;
            var cnt: i64 = 0;
            _ = std.os.windows.ntdll.RtlQueryPerformanceFrequency(&freq);
            _ = std.os.windows.ntdll.RtlQueryPerformanceCounter(&cnt);
            if (freq == 0) return 0;
            return @intCast(@divTrunc(@as(i128, cnt) * 1_000_000_000, @as(i128, freq)));
        },
        else => {
            var ts: std.c.timespec = undefined;
            _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
            return nsFrom(@intCast(ts.sec), @intCast(ts.nsec));
        },
    }
}

fn nsFrom(sec: i64, nsec: i64) u64 {
    return @as(u64, @intCast(sec)) * 1_000_000_000 + @as(u64, @intCast(nsec));
}

/// Parse an unsigned environment override, falling back to `default` on absence
/// or a malformed value. Env lookup is Linux-only (via `/proc/self/environ`,
/// since Zig 0.16 dropped `std.posix.getenv` on no-libc Linux); other targets
/// always use the defaults.
fn envUsize(name: []const u8, default: usize) usize {
    var buf: [16384]u8 = undefined;
    const raw = envValue(name, &buf) orelse return default;
    return std.fmt.parseInt(usize, std.mem.trim(u8, raw, " \t\r\n"), 10) catch default;
}

/// Look up an environment variable's value by scanning `/proc/self/environ`
/// (NUL-separated `KEY=VALUE` records). Returns a slice into `buf`. Linux-only;
/// returns null elsewhere.
fn envValue(name: []const u8, buf: []u8) ?[]const u8 {
    if (@import("builtin").os.tag != .linux) return null;
    const linux = std.os.linux;
    const rc = linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    const sfd: isize = @bitCast(rc);
    if (sfd < 0) return null;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const n = linux.read(fd, buf[total..].ptr, buf.len - total);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        total += n;
    }
    var it = std.mem.splitScalar(u8, buf[0..total], 0);
    while (it.next()) |record| {
        const eq = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (std.mem.eql(u8, record[0..eq], name)) return record[eq + 1 ..];
    }
    return null;
}

// -- RSA-2048 test key (real key with CRT parameters) ------------------------
//
// Duplicated from the rsa_sign.zig test vectors (those constants are file-local
// to that module's tests). Self-contained here so the harness needs no changes
// to the crypto modules. This is a throwaway TEST key, never a live secret.

fn rsaTestKey() rsa_sign.PrivateKey {
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

const rsa_n = [_]u8{ 0xa0, 0xbd, 0x13, 0x04, 0xa8, 0x7f, 0x0a, 0x69, 0xb8, 0xef, 0x18, 0xea, 0xa1, 0xda, 0x15, 0x52, 0x2c, 0x22, 0x1b, 0x1e, 0x9b, 0x1e, 0xfa, 0xee, 0x23, 0xbe, 0xa1, 0xfa, 0xa7, 0xea, 0xae, 0xfe, 0x1e, 0x09, 0xeb, 0xa3, 0x90, 0xec, 0x93, 0x34, 0xae, 0xa9, 0x45, 0x75, 0x30, 0xd4, 0x0c, 0x6a, 0x6b, 0x89, 0xc0, 0x39, 0x86, 0x5e, 0x98, 0xdd, 0x9d, 0x74, 0x91, 0xea, 0x57, 0x28, 0x8d, 0xeb, 0xf3, 0x70, 0xf7, 0x96, 0xfe, 0x05, 0x90, 0x4a, 0x58, 0x90, 0x27, 0x27, 0x2f, 0xc9, 0xbd, 0x80, 0x3f, 0xcf, 0x9d, 0x22, 0x8c, 0x55, 0x52, 0xda, 0x7f, 0xf4, 0xf2, 0xa2, 0x5c, 0x16, 0x06, 0xb3, 0xa4, 0x79, 0x4f, 0x4f, 0xfa, 0x5b, 0xd9, 0x4a, 0xb2, 0x15, 0x00, 0x26, 0xdb, 0xcd, 0x31, 0xc4, 0xf4, 0xa5, 0x75, 0x5d, 0x44, 0x9a, 0x7a, 0xaf, 0x41, 0x86, 0x1f, 0xf0, 0x69, 0xfa, 0x45, 0x55, 0x63, 0xcb, 0x22, 0xde, 0x14, 0x11, 0x4a, 0xff, 0x80, 0x85, 0xfc, 0x3d, 0x3c, 0x07, 0xbc, 0x92, 0x9d, 0x76, 0x1f, 0x64, 0x49, 0xc1, 0xa1, 0x39, 0x75, 0x73, 0x8c, 0x98, 0x76, 0x31, 0x95, 0x99, 0xf8, 0x8b, 0xd3, 0x67, 0x62, 0x30, 0x80, 0x2d, 0x76, 0xb7, 0x29, 0x2a, 0xd0, 0x75, 0x9d, 0xad, 0x8f, 0xc7, 0x0e, 0xe1, 0x8f, 0xde, 0xd6, 0x9e, 0x32, 0x21, 0x6a, 0x7f, 0x52, 0x83, 0x3f, 0x11, 0x38, 0xca, 0xa7, 0xf9, 0x03, 0x07, 0xc2, 0x36, 0x50, 0x0c, 0x3a, 0xa1, 0xa6, 0xcd, 0x08, 0x20, 0x97, 0xfc, 0x3e, 0x28, 0x60, 0x9b, 0x8d, 0x33, 0x51, 0x4f, 0x16, 0xd6, 0x68, 0x7b, 0xed, 0x50, 0x4a, 0xee, 0x82, 0x77, 0x5a, 0x41, 0xe4, 0xb1, 0x25, 0xeb, 0xa9, 0xca, 0x54, 0x4d, 0xc3, 0x75, 0xc2, 0x9c, 0x19, 0xd2, 0x0f, 0x10, 0x90, 0x03, 0x01, 0xee, 0xa8, 0xe6, 0x8b, 0xe3, 0xb3, 0xd7 };
const rsa_e = [_]u8{ 0x01, 0x00, 0x01 };
const rsa_d = [_]u8{ 0x12, 0x03, 0x6e, 0x6c, 0xb0, 0xb7, 0x60, 0x02, 0xde, 0x1b, 0x49, 0x77, 0x0e, 0x01, 0x63, 0x2f, 0x4c, 0xcb, 0xdb, 0xaf, 0x2f, 0xe2, 0x26, 0x6b, 0xe6, 0xac, 0x97, 0xf9, 0x7f, 0xb4, 0xf0, 0xbc, 0x80, 0xc0, 0x4a, 0xdc, 0x8f, 0x42, 0xbb, 0xf2, 0x84, 0xfa, 0x6a, 0x52, 0xca, 0x50, 0x91, 0x3d, 0xa1, 0xe4, 0x93, 0x9a, 0xbe, 0xc0, 0xbe, 0x2f, 0xe3, 0xd3, 0xeb, 0x00, 0x50, 0x99, 0x36, 0x62, 0x71, 0x6b, 0x41, 0x0b, 0xf6, 0x56, 0xc8, 0x47, 0x54, 0xaa, 0x7f, 0x00, 0xc8, 0xbd, 0xba, 0x93, 0x73, 0x53, 0x40, 0x80, 0x5d, 0x2a, 0xb8, 0xb8, 0xcc, 0xeb, 0x35, 0xff, 0xd5, 0x03, 0x10, 0xe8, 0x33, 0xef, 0xf6, 0x5f, 0xf7, 0xa6, 0x30, 0x71, 0x4b, 0x08, 0xc8, 0x76, 0x12, 0x5e, 0xea, 0x0b, 0x71, 0x01, 0x53, 0xe8, 0x4a, 0x66, 0x67, 0x86, 0x59, 0x78, 0xfe, 0xfe, 0x51, 0xda, 0x1e, 0xc7, 0xd7, 0xcf, 0xc1, 0xaf, 0xb9, 0x6c, 0x42, 0x23, 0xb1, 0x87, 0xb4, 0x9c, 0xb6, 0x30, 0x5b, 0xe1, 0xa2, 0xec, 0xcb, 0xb8, 0xd0, 0x7e, 0xd0, 0x16, 0xbc, 0x25, 0x79, 0x08, 0xbe, 0xc7, 0xda, 0xf3, 0x22, 0x65, 0x8b, 0xda, 0x2d, 0xc4, 0xab, 0xd3, 0x67, 0x1f, 0xfa, 0x69, 0x19, 0xda, 0x8b, 0x86, 0xec, 0xbe, 0xfa, 0x26, 0x58, 0xc3, 0xc0, 0x1b, 0xac, 0xee, 0x5c, 0x9c, 0xff, 0x02, 0xf1, 0xcb, 0xac, 0x3f, 0x05, 0xfe, 0xb2, 0xd6, 0x8c, 0x61, 0xef, 0x9a, 0x54, 0x27, 0xf7, 0x3e, 0xdb, 0x19, 0x49, 0xf7, 0x76, 0x35, 0x0b, 0xd6, 0x34, 0x75, 0xc3, 0xcb, 0x78, 0xc5, 0x60, 0x5b, 0x09, 0x4d, 0x50, 0x43, 0x75, 0x6e, 0x89, 0x4b, 0xf5, 0x38, 0xe8, 0x11, 0x90, 0x32, 0x12, 0xb6, 0x99, 0x0a, 0x75, 0x15, 0x3e, 0x26, 0x1a, 0x36, 0x63, 0x06, 0x57, 0xf8, 0xb9, 0x1d, 0xfd, 0xad, 0xf4, 0x5d };
const rsa_p = [_]u8{ 0xe0, 0x3b, 0x0d, 0x99, 0x92, 0x33, 0xd3, 0x20, 0xae, 0x90, 0xbb, 0x8f, 0xa2, 0x8b, 0xa3, 0x6a, 0xd8, 0xc0, 0xbe, 0xde, 0xea, 0x9b, 0xc1, 0x21, 0x8f, 0x65, 0xf1, 0xaa, 0xc3, 0x29, 0xe0, 0xc9, 0x21, 0xa6, 0xaa, 0xf6, 0x2a, 0x56, 0x71, 0x9c, 0x6b, 0xd0, 0x1c, 0x33, 0xff, 0x11, 0x9a, 0x65, 0x70, 0x05, 0xeb, 0x50, 0x0c, 0x33, 0xaa, 0x52, 0xe6, 0xd2, 0xfb, 0x6a, 0x55, 0x72, 0x3f, 0x6f, 0xc2, 0x07, 0x6f, 0xb8, 0xd3, 0x0d, 0xf1, 0x28, 0x01, 0xdc, 0xa5, 0x23, 0x51, 0x59, 0x92, 0xca, 0xd6, 0xad, 0x62, 0x8d, 0x18, 0x09, 0x47, 0xe8, 0x46, 0xfa, 0x3a, 0x3a, 0x30, 0x46, 0xc8, 0x4c, 0x25, 0x26, 0x6f, 0xaf, 0x90, 0x79, 0xf4, 0x40, 0x22, 0xbd, 0x4b, 0x56, 0x00, 0xd9, 0x8a, 0x8e, 0xe4, 0xcb, 0xda, 0x9f, 0xdd, 0xf0, 0x1e, 0x9e, 0xfb, 0x5d, 0x7e, 0xb6, 0x2f, 0x7e, 0xdb, 0x5d };
const rsa_q = [_]u8{ 0xb7, 0x83, 0x22, 0x56, 0xda, 0xec, 0x3e, 0xb9, 0xc3, 0x25, 0xd1, 0xcd, 0xd4, 0xb3, 0xe2, 0x03, 0x67, 0x23, 0xd0, 0x2d, 0xaa, 0x96, 0xe0, 0x29, 0x51, 0x86, 0x40, 0xc4, 0x0d, 0x87, 0xbd, 0xe9, 0xdf, 0x14, 0x7b, 0xd8, 0x48, 0x80, 0x31, 0xdf, 0x85, 0xca, 0xa4, 0x49, 0xec, 0x42, 0x73, 0x5c, 0xbf, 0xd1, 0x12, 0x5f, 0x84, 0x30, 0x27, 0x35, 0x2d, 0x39, 0x6e, 0x7e, 0x90, 0x24, 0xb7, 0x63, 0x35, 0xa9, 0x81, 0x48, 0xa5, 0x53, 0xd3, 0x18, 0x72, 0xf3, 0x22, 0x75, 0x58, 0x28, 0x97, 0xd1, 0xe8, 0xf2, 0xb1, 0x46, 0x0f, 0x1a, 0x3b, 0xd0, 0x37, 0x5f, 0xe8, 0xa8, 0x84, 0xf2, 0x37, 0x2e, 0x71, 0x6d, 0x51, 0xa4, 0xb7, 0x10, 0x43, 0xc9, 0x73, 0x0d, 0x74, 0xa7, 0x26, 0x34, 0x76, 0x36, 0x2d, 0x50, 0x24, 0x96, 0xc1, 0x9f, 0x6a, 0x45, 0xa6, 0x15, 0x51, 0x7b, 0x4a, 0x7f, 0x4c, 0xc3 };
const rsa_dp = [_]u8{ 0x1a, 0x1b, 0xe6, 0x2e, 0x7e, 0x8e, 0x98, 0x43, 0xd2, 0xef, 0xb9, 0x57, 0x35, 0x37, 0x0b, 0x35, 0x32, 0xbd, 0xe6, 0xbb, 0xb0, 0x17, 0xa8, 0xba, 0x4e, 0xa7, 0x31, 0x27, 0x90, 0x07, 0xfd, 0x4b, 0x8e, 0x26, 0x88, 0xfb, 0x96, 0xdc, 0x6f, 0xe8, 0x25, 0xc9, 0x9a, 0xaf, 0x17, 0x41, 0x26, 0x78, 0x2f, 0x3e, 0x11, 0x33, 0x45, 0xe8, 0x72, 0x29, 0xab, 0x04, 0xe0, 0x0f, 0x76, 0x99, 0x91, 0xf7, 0x62, 0x61, 0x59, 0x49, 0xed, 0x11, 0x4f, 0x86, 0x38, 0x09, 0x48, 0x15, 0x3f, 0xb0, 0xad, 0x5d, 0xfe, 0xf7, 0x3b, 0x65, 0x70, 0x6a, 0x0c, 0x3c, 0x68, 0x9f, 0x54, 0x4e, 0x58, 0x36, 0xb5, 0xb5, 0xe0, 0x11, 0x84, 0xa9, 0xad, 0xa9, 0xf5, 0x9d, 0xce, 0x2d, 0xba, 0x6a, 0xee, 0x38, 0x66, 0x60, 0xd3, 0x15, 0x45, 0x84, 0x9d, 0xe4, 0x0a, 0xbc, 0xba, 0x4a, 0x1d, 0xa9, 0xfb, 0x07, 0xcb, 0x65 };
const rsa_dq = [_]u8{ 0x90, 0x77, 0x9a, 0xab, 0xf7, 0xb2, 0xad, 0xfa, 0xbd, 0xa7, 0x63, 0x50, 0x7f, 0xd7, 0x90, 0xe1, 0x0e, 0xec, 0x41, 0xb2, 0x01, 0xae, 0xbf, 0x0f, 0xa8, 0x0f, 0x61, 0xa3, 0x35, 0xe7, 0x9b, 0xd9, 0xa6, 0x75, 0xd0, 0xbd, 0x46, 0xee, 0x2c, 0xd5, 0x03, 0xd5, 0xb0, 0x9a, 0x45, 0x75, 0x56, 0xae, 0x38, 0x8f, 0x95, 0xc0, 0x3e, 0x27, 0x4e, 0x66, 0x6d, 0x90, 0xdd, 0xec, 0xa2, 0xfb, 0x54, 0xa7, 0xb4, 0x92, 0x19, 0xa6, 0x20, 0x09, 0x2a, 0x90, 0xff, 0xc5, 0x6a, 0x66, 0x28, 0x9d, 0xe4, 0x4f, 0x2a, 0xed, 0x0c, 0x23, 0xd4, 0x35, 0xd9, 0xca, 0xa4, 0x1d, 0x4b, 0xe2, 0x86, 0xae, 0xcc, 0x44, 0x32, 0xa5, 0x55, 0xf5, 0xae, 0xec, 0x0e, 0x01, 0x64, 0x22, 0xbe, 0xa7, 0xeb, 0xca, 0xb7, 0x19, 0x15, 0x79, 0x17, 0x24, 0xdb, 0x8e, 0xed, 0x31, 0xa1, 0x7a, 0xfc, 0xe7, 0x6b, 0x91, 0x65, 0xd3 };
const rsa_qinv = [_]u8{ 0xc4, 0xca, 0xe1, 0x78, 0x93, 0x8b, 0x60, 0x71, 0x7e, 0x4d, 0x04, 0x84, 0xc1, 0x44, 0xc5, 0x48, 0xb2, 0x75, 0xf8, 0x7d, 0xd2, 0x72, 0x3c, 0xfe, 0x1b, 0x6a, 0x5b, 0xa6, 0x83, 0x05, 0xb1, 0x54, 0xd1, 0xc8, 0x6c, 0x89, 0x47, 0x16, 0xbd, 0x9d, 0x5b, 0x4f, 0x97, 0x4f, 0x51, 0xad, 0x98, 0x94, 0x2f, 0xa2, 0x60, 0x05, 0x18, 0x88, 0x96, 0x93, 0x1a, 0x73, 0x20, 0x6b, 0x77, 0x8b, 0x94, 0x6f, 0x96, 0xc6, 0x44, 0x3f, 0x67, 0xbb, 0xb1, 0x86, 0x1c, 0xe8, 0xa2, 0xe9, 0xd4, 0x38, 0xbe, 0xfd, 0xb6, 0xcb, 0x1b, 0x7f, 0x41, 0x3e, 0xdc, 0x5b, 0x15, 0x5b, 0x43, 0x66, 0x60, 0x32, 0x0f, 0x3c, 0xd2, 0x6b, 0x0f, 0x65, 0xa9, 0xf5, 0x86, 0xf9, 0x57, 0x25, 0x7b, 0x81, 0xe7, 0xc4, 0x10, 0x85, 0x61, 0x50, 0xab, 0xf4, 0xbb, 0x8f, 0x69, 0x1b, 0xea, 0xbe, 0xcf, 0x7e, 0x42, 0x8a, 0x2f, 0x8c };
