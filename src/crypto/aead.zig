// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed AEAD layer (planning/02, "AEAD Interface" + "Cipher Foundry").
//!
//! `Aead(alg)` wraps a std.crypto AEAD behind fixed-size `Key`/`Nonce`/`Tag`
//! types so a caller cannot mix a ChaCha key with an AES nonce, pass a
//! wrong-length buffer, or ignore a tag-verify failure. `seal` returns the tag
//! by value; `open` returns `error.AuthFailed` on mismatch using the
//! constant-time verify provided by std (no early-out, no caller branch on the
//! secret comparison).
//!
//! Nonces follow the MOORING scheme (planning/02, "Frame crypto"): a 96-bit nonce
//! built from an 8-byte random base plus a big-endian u32 counter. The counter
//! constructor refuses to wrap, turning nonce reuse into an explicit error
//! before it can ever reach the cipher.
//!
//! Self-contained: imports only `std` (plus the sibling `Secret(T)` seam for
//! ergonomic key interop), so it can be compiled and tested in isolation.
const std = @import("std");
const Secret = @import("secret.zig").Secret;
const platform = @import("../substrate/platform.zig");

/// Errors surfaced by this layer.
pub const Error = error{
    /// AEAD tag verification failed (forged, corrupted, or wrong key/nonce/aad).
    AuthFailed,
    /// The caller-provided output buffer length does not match the input.
    BufferLengthMismatch,
    /// The 32-bit nonce counter has been exhausted; advancing would reuse a
    /// nonce. The caller must rekey instead.
    NonceCounterExhausted,
};

/// Supported AEAD algorithms. Each maps to a vetted std.crypto construction.
pub const AeadAlg = enum {
    /// RFC 8439 ChaCha20-Poly1305 (MOORING default; mobile/ARM friendly).
    chacha20_poly1305,
    /// AES-256-GCM (allowed when both peers advertise hardware support).
    aes256_gcm,
    /// AES-128-GCM (the default GCM suite for TLS 1.2/1.3; 16-byte key).
    aes128_gcm,

    /// The backing std.crypto type for this algorithm.
    fn Impl(comptime alg: AeadAlg) type {
        return switch (alg) {
            .chacha20_poly1305 => std.crypto.aead.chacha_poly.ChaCha20Poly1305,
            .aes256_gcm => std.crypto.aead.aes_gcm.Aes256Gcm,
            .aes128_gcm => std.crypto.aead.aes_gcm.Aes128Gcm,
        };
    }
};

/// A 96-bit (12-byte) AEAD nonce. Both supported ciphers use a 12-byte nonce.
pub const Nonce96 = [12]u8;

/// Length in bytes of the random base in a counter nonce.
pub const nonce_base_len = 8;
/// Length in bytes of the big-endian counter suffix in a counter nonce.
pub const nonce_counter_len = 4;

comptime {
    std.debug.assert(nonce_base_len + nonce_counter_len == @typeInfo(Nonce96).array.len);
}

/// Counter-based nonce source matching the MOORING frame scheme: an 8-byte random
/// base concatenated with a big-endian u32 counter. The counter is monotonic
/// and refuses to wrap, so each `next()` yields a distinct 96-bit nonce for the
/// lifetime of the base. Rekey (new base) before the counter is exhausted.
pub const CounterNonce = struct {
    base: [nonce_base_len]u8,
    counter: u32 = 0,
    /// Set once the maxint nonce has been emitted; the next call must refuse.
    exhausted: bool = false,

    /// Construct from an explicit random base (e.g. derived alongside a key).
    pub fn init(base: [nonce_base_len]u8) CounterNonce {
        return .{ .base = base, .counter = 0 };
    }

    /// Construct with an OS-CSPRNG-filled base. Use at key-establishment time.
    /// The 64-bit base is non-secret wire data (it travels in the MOORING frame),
    /// but we still source it from the kernel CSPRNG so bases do not collide.
    pub fn random() error{RandomSourceFailed}!CounterNonce {
        var base: [nonce_base_len]u8 = undefined;
        try fillOsRandom(&base);
        return .{ .base = base, .counter = 0 };
    }

    /// Errors from `resumeFrom`. Kept separate from `Error` so existing
    /// exhaustive switches over the AEAD error set are unaffected.
    pub const ResumeError = error{
        /// The snapshot says the final nonce under this base was already
        /// emitted; resuming would re-emit it. Rekey instead.
        NonceCounterExhausted,
        /// The restored counter is below the caller's monotonic floor, so the
        /// next `next()` would re-emit a nonce already used under this base.
        NonceCounterRewound,
    };

    /// Portable nonce position for a hot-upgrade (Helix) snapshot. Export with
    /// `snapshot()` and restore with `resumeFrom` so exhaustion survives the
    /// round trip.
    pub const Snapshot = struct {
        base: [nonce_base_len]u8,
        counter: u32,
        exhausted: bool = false,
    };

    /// Capture the current position for a snapshot.
    pub fn snapshot(self: *const CounterNonce) Snapshot {
        return .{ .base = self.base, .counter = self.counter, .exhausted = self.exhausted };
    }

    /// Resume from a snapshot, e.g. after a hot-upgrade import. The next
    /// `next()` will emit `snap.counter` then advance.
    ///
    /// Fails closed when resuming would reuse a nonce:
    ///   * an exhausted snapshot is refused (the maxint nonce was already
    ///     emitted, and a fresh `exhausted = false` would emit it again);
    ///   * `floor` is the lowest counter value the caller can independently
    ///     prove has NOT been emitted under `snap.base` (for example the
    ///     highest sequence number observed on the wire, plus one, or a
    ///     persisted high-water mark). A snapshot counter below it is refused.
    ///     Pass 0 when no independent record exists.
    pub fn resumeFrom(snap: Snapshot, floor: u32) ResumeError!CounterNonce {
        if (snap.exhausted) return ResumeError.NonceCounterExhausted;
        if (snap.counter < floor) return ResumeError.NonceCounterRewound;
        return .{ .base = snap.base, .counter = snap.counter };
    }

    /// The nonce for the current counter value, without advancing.
    fn current(self: *const CounterNonce) Nonce96 {
        var nonce: Nonce96 = undefined;
        @memcpy(nonce[0..nonce_base_len], &self.base);
        std.mem.writeInt(u32, nonce[nonce_base_len..][0..nonce_counter_len], self.counter, .big);
        return nonce;
    }

    /// Yield the nonce for the current counter, then advance. Returns
    /// `error.NonceCounterExhausted` once the counter cannot advance without
    /// wrapping (i.e. after emitting the maxint nonce), preventing reuse.
    pub fn next(self: *CounterNonce) Error!Nonce96 {
        if (self.exhausted) return Error.NonceCounterExhausted;
        const nonce = self.current();
        if (self.counter == std.math.maxInt(u32)) {
            // Just produced the final usable nonce (maxint). Mark exhausted so
            // the next call errors rather than wrapping the counter to 0 and
            // reusing nonces.
            self.exhausted = true;
        } else {
            self.counter += 1;
        }
        return nonce;
    }
};

/// Fill `buf` from the kernel CSPRNG (getrandom(2)), retrying on EINTR. Returns
/// `error.RandomSourceFailed` if the source is unavailable. Kept Linux-local to
/// match the daemon's platform (see substrate/reactor.zig); the broader RNG
/// strategy (per-worker DRBG, fork reseed) lives in the keyring layer.
fn fillOsRandom(buf: []u8) error{RandomSourceFailed}!void {
    platform.fillOsEntropy(buf) catch return error.RandomSourceFailed;
}

/// A typed AEAD over algorithm `alg`. Associated `Key`/`Nonce`/`Tag` types are
/// fixed-size and algorithm-specific, so they cannot be confused across ciphers.
pub fn Aead(comptime alg: AeadAlg) type {
    const Impl = alg.Impl();
    comptime {
        // Both supported ciphers are 12-byte nonce, 16-byte tag, 32-byte key.
        std.debug.assert(Impl.nonce_length == @typeInfo(Nonce96).array.len);
        std.debug.assert(Impl.tag_length == 16);
    }

    return struct {
        const Self = @This();

        /// The algorithm this instantiation wraps.
        pub const algorithm = alg;
        /// Fixed-size key bytes for `alg`.
        pub const Key = [Impl.key_length]u8;
        /// Fixed-size nonce bytes for `alg` (96-bit for both supported ciphers).
        pub const Nonce = [Impl.nonce_length]u8;
        /// Fixed-size authentication tag for `alg`.
        pub const Tag = [Impl.tag_length]u8;
        /// `Secret`-wrapped key for keyring interop (planning/02 "CT-Zone").
        pub const SecretKey = Secret(Key);

        pub const key_length = Impl.key_length;
        pub const nonce_length = Impl.nonce_length;
        pub const tag_length = Impl.tag_length;

        key: SecretKey,

        /// Construct from raw key bytes. Prefer `fromSecret` when the key
        /// already lives behind the `Secret` seam.
        pub fn init(key: Key) Self {
            return .{ .key = SecretKey.init(key) };
        }

        /// Construct from a `Secret`-wrapped key (keyring ergonomics).
        pub fn fromSecret(key: SecretKey) Self {
            return .{ .key = key };
        }

        /// Zeroize the wrapped key. Call via `defer aead.deinit()`.
        pub fn deinit(self: *Self) void {
            self.key.wipe();
        }

        /// Encrypt `plaintext` into `out` (which must be exactly `plaintext.len`
        /// bytes) under `nonce` and `aad`, returning the authentication tag.
        /// The caller is responsible for never reusing a (key, nonce) pair —
        /// use `CounterNonce` to enforce this.
        pub fn seal(
            self: *const Self,
            nonce: Nonce,
            aad: []const u8,
            plaintext: []const u8,
            out: []u8,
        ) Error!Tag {
            if (out.len != plaintext.len) return Error.BufferLengthMismatch;
            var tag: Tag = undefined;
            const key = self.key.declassify();
            Impl.encrypt(out, &tag, plaintext, aad, nonce, key);
            return tag;
        }

        /// Decrypt `ciphertext` into `out` (which must be exactly
        /// `ciphertext.len` bytes), verifying `tag` against `aad` and `nonce`.
        /// Returns `error.AuthFailed` on any verification failure; on failure
        /// `out` holds no usable plaintext. Verification is constant-time as
        /// provided by std.
        pub fn open(
            self: *const Self,
            nonce: Nonce,
            aad: []const u8,
            ciphertext: []const u8,
            tag: Tag,
            out: []u8,
        ) Error!void {
            if (out.len != ciphertext.len) return Error.BufferLengthMismatch;
            const key = self.key.declassify();
            Impl.decrypt(out, ciphertext, tag, aad, nonce, key) catch {
                return Error.AuthFailed;
            };
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const ChaCha = Aead(.chacha20_poly1305);
const AesGcm = Aead(.aes256_gcm);

fn roundTrip(comptime A: type) !void {
    const key: A.Key = @splat(0xA5);
    const nonce: A.Nonce = @splat(0x07);
    const aad = "undertow-outer-header|gen=1|kind=data";
    const plaintext = "the quick brown fox jumps over the lazy dog";

    var aead = A.init(key);
    defer aead.deinit();

    var ct: [plaintext.len]u8 = undefined;
    const tag = try aead.seal(nonce, aad, plaintext, &ct);

    var pt: [plaintext.len]u8 = undefined;
    try aead.open(nonce, aad, &ct, tag, &pt);
    try testing.expectEqualSlices(u8, plaintext, &pt);
}

test "round-trip seal/open: ChaCha20-Poly1305" {
    try roundTrip(ChaCha);
}

test "round-trip seal/open: AES-256-GCM" {
    try roundTrip(AesGcm);
}

fn aadMismatch(comptime A: type) !void {
    const key: A.Key = @splat(0x11);
    const nonce: A.Nonce = @splat(0x22);
    const plaintext = "secret payload";

    var aead = A.init(key);
    defer aead.deinit();

    var ct: [plaintext.len]u8 = undefined;
    const tag = try aead.seal(nonce, "aad-A", plaintext, &ct);

    var pt: [plaintext.len]u8 = undefined;
    try testing.expectError(Error.AuthFailed, aead.open(nonce, "aad-B", &ct, tag, &pt));
}

test "AAD mismatch yields AuthFailed: ChaCha20-Poly1305" {
    try aadMismatch(ChaCha);
}

test "AAD mismatch yields AuthFailed: AES-256-GCM" {
    try aadMismatch(AesGcm);
}

fn tamperedCiphertext(comptime A: type) !void {
    const key: A.Key = @splat(0x33);
    const nonce: A.Nonce = @splat(0x44);
    const aad = "header";
    const plaintext = "do not tamper with me";

    var aead = A.init(key);
    defer aead.deinit();

    var ct: [plaintext.len]u8 = undefined;
    const tag = try aead.seal(nonce, aad, plaintext, &ct);

    // Flip a single bit in the ciphertext.
    ct[0] ^= 0x01;

    var pt: [plaintext.len]u8 = undefined;
    try testing.expectError(Error.AuthFailed, aead.open(nonce, aad, &ct, tag, &pt));

    // A flipped tag bit must also fail (restore ciphertext first).
    ct[0] ^= 0x01;
    var bad_tag = tag;
    bad_tag[0] ^= 0x80;
    try testing.expectError(Error.AuthFailed, aead.open(nonce, aad, &ct, bad_tag, &pt));
}

test "tampered ciphertext yields AuthFailed: ChaCha20-Poly1305" {
    try tamperedCiphertext(ChaCha);
}

test "tampered ciphertext yields AuthFailed: AES-256-GCM" {
    try tamperedCiphertext(AesGcm);
}

test "buffer length mismatch is rejected" {
    var aead = ChaCha.init(@as([ChaCha.key_length]u8, @splat(0)));
    defer aead.deinit();
    const nonce: ChaCha.Nonce = @splat(0);
    var short: [3]u8 = undefined;
    try testing.expectError(Error.BufferLengthMismatch, aead.seal(nonce, "", "four", &short));
    const tag: ChaCha.Tag = undefined;
    try testing.expectError(Error.BufferLengthMismatch, aead.open(nonce, "", "four", tag, &short));
}

test "Aead interops with Secret-wrapped key" {
    const raw: ChaCha.Key = @splat(0x5C);
    var aead = ChaCha.fromSecret(ChaCha.SecretKey.init(raw));
    defer aead.deinit();

    const nonce: ChaCha.Nonce = @splat(0x01);
    const msg = "via keyring";
    var ct: [msg.len]u8 = undefined;
    const tag = try aead.seal(nonce, "", msg, &ct);
    var pt: [msg.len]u8 = undefined;
    try aead.open(nonce, "", &ct, tag, &pt);
    try testing.expectEqualSlices(u8, msg, &pt);
}

// --- Counter nonce -------------------------------------------------------

test "counter nonce composes base + big-endian u32 and advances" {
    var cn = CounterNonce.init([_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });

    const n0 = try cn.next();
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, n0[0..nonce_base_len]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, n0[nonce_base_len..]);

    const n1 = try cn.next();
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 1 }, n1[nonce_base_len..]);

    const n2 = try cn.next();
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 2 }, n2[nonce_base_len..]);
}

test "counter nonce refuses to wrap" {
    var cn = try CounterNonce.resumeFrom(.{ .base = @as([nonce_base_len]u8, @splat(0xFF)), .counter = std.math.maxInt(u32) - 1 }, 0);

    // counter = max-1 : usable
    const a = try cn.next();
    try testing.expectEqual(@as(u32, std.math.maxInt(u32) - 1), std.mem.readInt(u32, a[nonce_base_len..][0..4], .big));

    // counter = max : the final usable nonce is still produced.
    const b = try cn.next();
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), std.mem.readInt(u32, b[nonce_base_len..][0..4], .big));

    // Now it refuses to wrap, and keeps refusing.
    try testing.expectError(Error.NonceCounterExhausted, cn.next());
    try testing.expectError(Error.NonceCounterExhausted, cn.next());
}

test "random base nonce starts at counter zero and advances" {
    var cn = try CounterNonce.random();
    try testing.expectEqual(@as(u32, 0), cn.counter);
    const n0 = try cn.next();
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, n0[nonce_base_len..][0..4], .big));
    try testing.expectEqual(@as(u32, 1), cn.counter);
}

test "resumeFrom restores a known counter position" {
    var cn = try CounterNonce.resumeFrom(.{ .base = @as([nonce_base_len]u8, @splat(0xAB)), .counter = 42 }, 0);
    const n = try cn.next();
    try testing.expectEqual(@as(u32, 42), std.mem.readInt(u32, n[nonce_base_len..][0..4], .big));
    try testing.expectEqual(@as(u32, 43), cn.counter);
}

test "resumeFrom round-trips a snapshot and continues without reuse" {
    var cn = CounterNonce.init(@as([nonce_base_len]u8, @splat(0x5C)));
    _ = try cn.next();
    const last = try cn.next();
    const snap = cn.snapshot();
    // The highest emitted counter (1) plus one is a legitimate floor.
    const floor = std.mem.readInt(u32, last[nonce_base_len..][0..4], .big) + 1;
    var resumed = try CounterNonce.resumeFrom(snap, floor);
    const n = try resumed.next();
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, n[nonce_base_len..][0..4], .big));
}

test "resumeFrom refuses an exhausted snapshot instead of re-emitting the maxint nonce" {
    var cn = try CounterNonce.resumeFrom(.{ .base = @as([nonce_base_len]u8, @splat(0x01)), .counter = std.math.maxInt(u32) }, 0);
    _ = try cn.next();
    try testing.expectError(Error.NonceCounterExhausted, cn.next());
    const snap = cn.snapshot();
    try testing.expect(snap.exhausted);
    try testing.expectError(CounterNonce.ResumeError.NonceCounterExhausted, CounterNonce.resumeFrom(snap, 0));
}

test "resumeFrom refuses a counter rewound below the caller's monotonic floor" {
    const base: [nonce_base_len]u8 = @splat(0x77);
    try testing.expectError(
        CounterNonce.ResumeError.NonceCounterRewound,
        CounterNonce.resumeFrom(.{ .base = base, .counter = 9 }, 10),
    );
    // Equal to the floor is the first unused counter: accepted.
    var cn = try CounterNonce.resumeFrom(.{ .base = base, .counter = 10 }, 10);
    const n = try cn.next();
    try testing.expectEqual(@as(u32, 10), std.mem.readInt(u32, n[nonce_base_len..][0..4], .big));
}

// --- Published KAT: RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD ---------------

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 8439 ChaCha20-Poly1305 AEAD test vector" {
    // RFC 8439, Section 2.8.2.
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you " ++
        "only one tip for the future, sunscreen would be it.";

    const key = hexToBytes("808182838485868788898a8b8c8d8e8f" ++
        "909192939495969798999a9b9c9d9e9f");
    const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    // 32-bit constant 0x07000000 (LE on wire) || 64-bit IV 4041424344454647.
    const nonce = hexToBytes("070000004041424344454647");

    const expected_ct = hexToBytes(
        "d31a8d34648e60db7b86afbc53ef7ec2" ++
            "a4aded51296e08fea9e2b5a736ee62d6" ++
            "3dbea45e8ca9671282fafb69da92728b" ++
            "1a71de0a9e060b2905d6a5b67ecd3b36" ++
            "92ddbd7f2d778b8c9803aee328091b58" ++
            "fab324e4fad675945585808b4831d7bc" ++
            "3ff4def08e4b7a9de576d26586cec64b" ++
            "6116",
    );
    const expected_tag = hexToBytes("1ae10b594f09e26a7e902ecbd0600691");

    var aead = ChaCha.init(key);
    defer aead.deinit();

    var ct: [plaintext.len]u8 = undefined;
    const tag = try aead.seal(nonce, &aad, plaintext, &ct);

    try testing.expectEqualSlices(u8, &expected_ct, &ct);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);

    // And it must decrypt back to the plaintext.
    var pt: [plaintext.len]u8 = undefined;
    try aead.open(nonce, &aad, &ct, tag, &pt);
    try testing.expectEqualSlices(u8, plaintext, &pt);
}

test {
    testing.refAllDecls(@This());
}
