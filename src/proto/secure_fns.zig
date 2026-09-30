// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! secure_fns — hardened, security-critical helper primitives for the daemon.
//!
//! This is the daemon's *stable* surface for the handful of low-level security
//! operations that must be gotten exactly right: constant-time comparison,
//! optimizer-proof zeroization, branchless selection, and unbiased CSPRNG
//! draws. Call sites depend on the names here, not on the underlying `std`
//! shape, so the implementation can be re-pointed (e.g. at a future audited
//! intrinsic) without churn across the tree.
//!
//! Purity contract:
//!   - Every function here is a pure transform of its inputs EXCEPT the
//!     `random*` family, which is the ONE permitted side effect: it draws from
//!     the operating-system CSPRNG. On this 64-bit Linux target that is the
//!     `getrandom(2)` syscall via `std.os.linux`. No sockets, no filesystem,
//!     no clock, no environment reads.
//!   - The task brief names `std.crypto.random`; that top-level accessor does
//!     not exist in this Zig 0.16 toolchain, so we use the equivalent and more
//!     direct OS entropy source. Same guarantee (kernel CSPRNG), fewer moving
//!     parts, no global PRNG state to misuse across a fork.
//!
//! Target: 64-bit only (x86_64 / aarch64).

const std = @import("std");
const builtin = @import("builtin");

comptime {
    // Hard 64-bit-only guarantee for this module's pointer/word assumptions.
    if (@bitSizeOf(usize) != 64) {
        @compileError("secure_fns targets 64-bit only");
    }
}

/// Raised when the kernel entropy source is unavailable or misbehaves.
pub const Error = error{
    /// `getrandom(2)` returned an error or an impossible short count.
    RandomSourceFailed,
};

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Constant-time byte-slice equality.
///
/// Returns `true` iff `a` and `b` are the same length AND have identical
/// contents. The running time depends only on the lengths of the inputs, never
/// on *where* (or whether) they differ:
///   - The length check folds into the accumulator instead of taking an early
///     branch on mismatch, so a wrong length is indistinguishable timing-wise
///     from a content mismatch.
///   - Content bytes are XORed and OR-accumulated; the loop never short-circuits.
///
/// Pure: no side effects.
pub fn ctEq(a: []const u8, b: []const u8) bool {
    // Difference in length, reduced to a single nonzero-if-unequal byte without
    // a data-dependent branch. usize is 64-bit here (asserted at comptime).
    const len_diff: usize = a.len ^ b.len;
    const len_fold: u8 = foldNonzero(len_diff);

    // Compare over the shorter length so neither index goes out of bounds; the
    // length fold above already makes any length mismatch fail regardless.
    const n: usize = if (a.len < b.len) a.len else b.len;

    var acc: u8 = len_fold;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        acc |= a[i] ^ b[i];
    }

    // acc == 0  <=>  equal length and equal content.
    return acc == 0;
}

/// Fold a usize down to a single byte that is zero iff the input is zero,
/// without branching on the value. Each output bit ORs in evidence from the
/// whole word.
fn foldNonzero(v: usize) u8 {
    var x: usize = v;
    // OR the high half into the low half repeatedly: any set bit anywhere ends
    // up in the low 8 bits.
    x |= x >> 32;
    x |= x >> 16;
    x |= x >> 8;
    return @truncate(x);
}

// ---------------------------------------------------------------------------
// Branchless select
// ---------------------------------------------------------------------------

/// Branchless constant-time select over bytes: returns `a` if `cond`, else `b`.
///
/// Builds a full-width mask from `cond` (all-ones / all-zeros) and blends the
/// two inputs, so the chosen value never leaks through a branch.
///
/// Pure: no side effects.
pub fn ctSelect(cond: bool, a: u8, b: u8) u8 {
    // @intFromBool yields 0 or 1; negating in two's complement over u8 gives
    // 0x00 or 0xFF. We do the negate in unsigned wrapping arithmetic.
    const one: u8 = @intFromBool(cond); // 0 or 1
    const mask: u8 = 0 -% one; // 0x00 (false) or 0xFF (true)
    return (a & mask) | (b & ~mask);
}

// ---------------------------------------------------------------------------
// Zeroization
// ---------------------------------------------------------------------------

/// Zero `buf` in a way the optimizer must not elide.
///
/// Delegates to `std.crypto.secureZero`, the audited std primitive that writes
/// through a `volatile` slice so dead-store elimination cannot remove the wipe.
/// Use this for key material, session secrets, and any buffer that held a
/// secret before it is freed or reused.
///
/// Pure with respect to inputs (mutates only `buf`); no external side effects.
pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

// ---------------------------------------------------------------------------
// CSPRNG (the one permitted side effect: OS entropy)
// ---------------------------------------------------------------------------

/// GRND_NONBLOCK is intentionally NOT set: at daemon runtime the kernel pool is
/// long since initialized, and we prefer a blocking fill over a short read.
const grnd_flags: u32 = 0;

/// Fill `buf` from the operating-system CSPRNG, panicking on the (practically
/// impossible at runtime) event that the kernel entropy source fails — a dead
/// entropy source is unrecoverable for a security daemon.
///
/// Side effect: reads OS entropy via `getrandom(2)`.
pub fn randomBytes(buf: []u8) void {
    fillFromOs(buf) catch |err| {
        std.debug.panic("secure_fns.randomBytes: {s}", .{@errorName(err)});
    };
}

/// Draw a uniformly random `u64` from the OS CSPRNG.
///
/// Side effect: reads OS entropy via `getrandom(2)`.
pub fn randomU64() u64 {
    var bytes: [8]u8 = undefined;
    randomBytes(bytes[0..]);
    return std.mem.readInt(u64, &bytes, .little);
}

/// Uniformly random value in the half-open interval `[0, n)` with NO modulo
/// bias, via rejection sampling.
///
/// `n == 0` is an empty range and is rejected with a panic (there is no valid
/// value to return); call sites must guarantee `n >= 1`.
///
/// Algorithm: compute the largest multiple of `n` that fits in u64 and reject
/// any draw at or above it, so the accepted region is an exact multiple of `n`.
///
/// Side effect: reads OS entropy via `getrandom(2)`.
pub fn randomLessThan(n: u64) u64 {
    if (n == 0) {
        std.debug.panic("secure_fns.randomLessThan: bound must be >= 1", .{});
    }
    // Size of the bias-inducing tail at the top of the u64 range: the number of
    // values that would make [0, 2^64) not an exact multiple of n.
    //   (0 -% n) is 2^64 - n in wrapping u64 arithmetic, so this is 2^64 % n.
    const remainder: u64 = (0 -% n) % n;
    // Smallest rejected value. When n divides 2^64 exactly (every power of two,
    // including n == 1) remainder is 0 and the entire range is acceptable; we
    // represent that as "reject nothing" rather than overflowing the threshold.
    if (remainder == 0) {
        return randomU64() % n;
    }
    const reject_at: u64 = 0 -% remainder; // 2^64 - remainder, the cutoff
    while (true) {
        const x = randomU64();
        if (x < reject_at) return x % n;
        // else: in the bias-inducing tail; draw again.
    }
}

/// Core OS entropy fill. Handles short reads and EINTR by looping, and maps any
/// hard failure to `error.RandomSourceFailed`.
fn fillFromOs(buf: []u8) Error!void {
    if (comptime builtin.os.tag != .linux) {
        return @import("../substrate/platform.zig").fillOsEntropy(buf);
    }
    var filled: usize = 0;
    while (filled < buf.len) {
        const want = buf.len - filled;
        const rc = std.os.linux.getrandom(buf.ptr + filled, want, grnd_flags);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                const got: usize = rc;
                if (got == 0) return error.RandomSourceFailed;
                filled += got;
            },
            .INTR => continue, // interrupted before any byte; retry
            else => return error.RandomSourceFailed,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

test "ctEq returns true for byte-identical equal-length slices" {
    // Arrange
    const a = "correct horse battery staple";
    const b = "correct horse battery staple";

    // Act
    const equal = ctEq(a, b);

    // Assert
    try std.testing.expect(equal);
}

test "ctEq returns false when a single byte differs" {
    // Arrange
    var a = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var b = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    b[4] ^= 0x01; // flip exactly one bit of one byte

    // Act
    const equal = ctEq(a[0..], b[0..]);

    // Assert
    try std.testing.expect(!equal);
}

test "ctEq returns false for different lengths even when prefix matches" {
    // Arrange
    const a = "abcdef";
    const b = "abcdefg"; // identical prefix, longer by one

    // Act
    const equal = ctEq(a, b);

    // Assert
    try std.testing.expect(!equal);
}

test "ctEq treats two empty slices as equal" {
    // Arrange
    const a: []const u8 = &.{};
    const b: []const u8 = &.{};

    // Act / Assert
    try std.testing.expect(ctEq(a, b));
}

test "secureZero clears every byte of a buffer" {
    // Arrange
    var buf = @as([64]u8, @splat(0xAA));

    // Act
    secureZero(buf[0..]);

    // Assert
    for (buf) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "secureZero on an empty slice is a no-op and does not crash" {
    // Arrange
    var buf = [_]u8{};

    // Act / Assert (must simply not panic)
    secureZero(buf[0..]);
}

test "ctSelect returns the first argument when cond is true" {
    // Arrange
    const a: u8 = 0x5A;
    const b: u8 = 0xA5;

    // Act
    const got = ctSelect(true, a, b);

    // Assert
    try std.testing.expectEqual(a, got);
}

test "ctSelect returns the second argument when cond is false" {
    // Arrange
    const a: u8 = 0x5A;
    const b: u8 = 0xA5;

    // Act
    const got = ctSelect(false, a, b);

    // Assert
    try std.testing.expectEqual(b, got);
}

test "randomLessThan always returns a value strictly below the bound" {
    // Arrange
    const bounds = [_]u64{ 1, 2, 3, 7, 256, 1000, 0xFFFF_FFFF, 0x8000_0000_0000_0001 };

    // Act / Assert
    for (bounds) |n| {
        var draw: usize = 0;
        while (draw < 2000) : (draw += 1) {
            const v = randomLessThan(n);
            try std.testing.expect(v < n);
        }
    }
}

test "randomLessThan covers both low and high values of its range" {
    // Arrange
    const n: u64 = 16;
    var seen_low = false;
    var seen_high = false;

    // Act
    var draw: usize = 0;
    while (draw < 5000 and !(seen_low and seen_high)) : (draw += 1) {
        const v = randomLessThan(n);
        try std.testing.expect(v < n);
        if (v == 0) seen_low = true;
        if (v == n - 1) seen_high = true;
    }

    // Assert
    try std.testing.expect(seen_low);
    try std.testing.expect(seen_high);
}

test "randomBytes produces differing output across two draws" {
    // Arrange
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;

    // Act
    randomBytes(first[0..]);
    randomBytes(second[0..]);

    // Assert: collision over 256 bits is astronomically improbable.
    try std.testing.expect(!std.mem.eql(u8, first[0..], second[0..]));
}

test "randomU64 produces differing values across two draws" {
    // Arrange / Act
    const a = randomU64();
    const b = randomU64();

    // Assert: 64-bit collision is astronomically improbable.
    try std.testing.expect(a != b);
}
