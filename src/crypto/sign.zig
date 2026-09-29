// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ed25519 signatures for Onyx Server identity and authorization boundaries.
//!
//! This module wraps Zig 0.16's `std.crypto.sign.Ed25519` key/public/signature
//! encodings while keeping private key material behind `Secret(T)`. Signing is
//! deterministic RFC 8032 Ed25519, with a zero-allocation domain-separated path
//! for Undertow/MeshPass uses where signatures must not be reusable across
//! node identity, capability token, and operator challenge contexts.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;
const Secret = @import("secret.zig").Secret;

const StdEd25519 = std.crypto.sign.Ed25519;
const Curve = StdEd25519.Curve;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub const public_key_len = StdEd25519.PublicKey.encoded_length;
pub const secret_key_len = StdEd25519.SecretKey.encoded_length;
pub const seed_len = StdEd25519.KeyPair.seed_length;
pub const signature_len = StdEd25519.Signature.encoded_length;

pub const PublicKey = [public_key_len]u8;
pub const Signature = [signature_len]u8;
pub const Seed = [seed_len]u8;
pub const SecretKey = Secret([secret_key_len]u8);

/// One private anonymous page holding the only long-lived copy of an Ed25519
/// secret. On Linux the page is MADV_DONTDUMP and MADV_WIPEONFORK.
pub const SealedSecretKey = struct {
    page: ?[]align(4096) u8 = null,

    pub fn seal(bytes: *const [secret_key_len]u8) error{SecretPageUnavailable}!SealedSecretKey {
        const page = try mapSecretPage();
        @memcpy(page[0..secret_key_len], bytes);
        return .{ .page = page };
    }

    pub fn expose(self: *const SealedSecretKey) []const u8 {
        const page = self.page orelse return &.{};
        return page[0..secret_key_len];
    }

    pub fn declassify(self: *const SealedSecretKey) [secret_key_len]u8 {
        var out: [secret_key_len]u8 = @splat(0);
        const src = self.expose();
        if (src.len != secret_key_len) return out;
        @memcpy(&out, src);
        return out;
    }

    pub fn toBytes(self: *const SealedSecretKey) [secret_key_len]u8 {
        return self.declassify();
    }

    pub fn wipe(self: *SealedSecretKey) void {
        const page = self.page orelse return;
        std.crypto.secureZero(u8, page);
        self.page = null;
        if (comptime builtin.os.tag == .linux) {
            _ = linux.munmap(page.ptr, page.len);
        } else {
            std.heap.page_allocator.free(page);
        }
    }
};

fn mapSecretPage() error{SecretPageUnavailable}![]align(4096) u8 {
    if (comptime builtin.os.tag != .linux) {
        return std.heap.page_allocator.alignedAlloc(u8, std.mem.Alignment.fromByteUnits(4096), 4096) catch return error.SecretPageUnavailable;
    }
    const prot: linux.PROT = .{ .READ = true, .WRITE = true };
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    const rc = linux.mmap(null, 4096, prot, flags, -1, 0);
    if (posix.errno(rc) != .SUCCESS) return error.SecretPageUnavailable;
    const ptr: [*]u8 = @ptrFromInt(rc);
    const advised = linux.madvise(ptr, 4096, linux.MADV.DONTDUMP);
    if (posix.errno(advised) != .SUCCESS) {
        _ = linux.munmap(ptr, 4096);
        return error.SecretPageUnavailable;
    }
    const wiped = linux.madvise(ptr, 4096, linux.MADV.WIPEONFORK);
    if (posix.errno(wiped) != .SUCCESS) {
        _ = linux.munmap(ptr, 4096);
        return error.SecretPageUnavailable;
    }
    return @alignCast(ptr[0..4096]);
}

pub const SignError = std.crypto.errors.IdentityElementError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.WeakPublicKeyError ||
    error{InvalidInfixWidth};

pub const VerifyError = StdEd25519.Signature.VerifyError || error{InvalidInfixWidth};

/// Wire domain-prefix magic bound into every `signCtx` / `signCtxInfix`
/// transcript. This is a **protocol constant**, not a product brand string:
/// changing it silently invalidates Mooring prekeys, M1/M2, and signed S2S
/// frames against any peer that still produces the previous magic (the
/// Orochi→Onyx mesh netsplit of 2026-07-19, where `orochi-ed25519ctx-v1` was
/// renamed to `onyx-ed25519ctx-v1` on one node only). Keep the historical
/// value so mixed-version and rolling deploys keep a shared wire domain.
const domain_prefix_magic = "orochi-ed25519ctx-v1";

/// Additional domain-prefix magics accepted on verify only. Covers the short
/// window where a renamed binary signed with `onyx-ed25519ctx-v1`. Sign paths
/// always use `domain_prefix_magic`; verify tries the primary first, then each
/// alternate — never the reverse on the sign side (no dual signatures).
const alt_domain_prefix_magics = [_][]const u8{"onyx-ed25519ctx-v1"};

/// The `infix` in signCtxInfix/verifyCtxInfix is concatenated with `msg` WITHOUT
/// a length delimiter, so (infix="AB",msg="C") and (infix="A",msg="BC") would
/// sign identical bytes. Every real caller (undertow signed_frame) passes a
/// fixed-width 1-byte frame-type tag, so we enforce that width here — a future
/// variable-length infix is rejected fail-closed rather than producing an
/// ambiguous signature. AUDIT every caller before widening this.
const known_infix_len: usize = 1;

/// Ed25519 key pair. `secret_key` is seed || public key, matching std/RFC
/// Ed25519 storage, and is wiped by `deinit`.
pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SealedSecretKey,

    /// Address of the dedicated secret page, when this pair still owns one.
    pub fn secretPage(self: *const KeyPair) ?[*]u8 {
        const page = self.secret_key.page orelse return null;
        return page.ptr;
    }

    /// Generate a new key pair using the caller-provided Zig 0.16 `std.Io`
    /// randomness source.
    pub fn generate(io: std.Io) error{SecretPageUnavailable}!KeyPair {
        var kp = StdEd25519.KeyPair.generate(io);
        defer secureZero(std.mem.asBytes(&kp.secret_key));
        var material = kp.secret_key.toBytes();
        defer secureZero(&material);
        return .{
            .public_key = kp.public_key.toBytes(),
            .secret_key = try SealedSecretKey.seal(&material),
        };
    }

    /// Deterministically derive a key pair from a 32-byte Ed25519 seed.
    pub fn fromSeed(seed: Seed) (std.crypto.errors.IdentityElementError || error{SecretPageUnavailable})!KeyPair {
        var kp = try StdEd25519.KeyPair.generateDeterministic(seed);
        defer secureZero(std.mem.asBytes(&kp.secret_key));
        var material = kp.secret_key.toBytes();
        defer secureZero(&material);
        return .{
            .public_key = kp.public_key.toBytes(),
            .secret_key = try SealedSecretKey.seal(&material),
        };
    }

    /// Zeroize the wrapped private key material and unmap its page.
    pub fn deinit(self: *KeyPair) void {
        self.secret_key.wipe();
    }

    /// A second sealed page holding the same secret. Each `KeyPair` unmaps
    /// only the page it still points at, so a copy that shares `page` is not
    /// a second owner.
    pub fn clone(self: *const KeyPair) error{SecretPageUnavailable}!KeyPair {
        if (self.secret_key.page == null) return error.SecretPageUnavailable;
        var material = self.secret_key.declassify();
        defer secureZero(&material);
        return .{
            .public_key = self.public_key,
            .secret_key = try SealedSecretKey.seal(&material),
        };
    }

    /// Sign `msg` with plain RFC 8032 Ed25519.
    pub fn sign(self: *const KeyPair, msg: []const u8) SignError!Signature {
        return self.signPrefixed("", "", msg);
    }

    /// Sign `msg` under a compile-time domain label.
    ///
    /// The domain is length-framed into the signed transcript:
    /// `magic || len(domain) || domain || msg`.
    pub fn signCtx(
        self: *const KeyPair,
        comptime domain: []const u8,
        msg: []const u8,
    ) SignError!Signature {
        const prefix = domainPrefix(domain);
        return self.signPrefixed(&prefix, "", msg);
    }

    /// Sign `infix ++ msg` under a compile-time domain label, streaming both
    /// segments into the transcript without a contiguous copy. The transcript is
    /// `magic || len(domain) || domain || infix || msg`, so `infix` (e.g. a frame
    /// type byte) is bound into the signature exactly as `verifyCtxInfix` checks.
    pub fn signCtxInfix(
        self: *const KeyPair,
        comptime domain: []const u8,
        infix: []const u8,
        msg: []const u8,
    ) SignError!Signature {
        if (infix.len != known_infix_len) return error.InvalidInfixWidth;
        const prefix = domainPrefix(domain);
        return self.signPrefixed(&prefix, infix, msg);
    }

    fn signPrefixed(
        self: *const KeyPair,
        prefix: []const u8,
        infix: []const u8,
        msg: []const u8,
    ) SignError!Signature {
        var sk_bytes = self.secret_key.declassify();
        defer secureZero(&sk_bytes);

        if (!std.mem.eql(u8, sk_bytes[seed_len..], self.public_key[0..])) {
            return error.KeyMismatch;
        }

        const seed = sk_bytes[0..seed_len].*;
        const public_key = sk_bytes[seed_len..].*;

        var expanded: [Sha512.digest_length]u8 = undefined;
        defer secureZero(&expanded);
        var seed_hash = Sha512.init(.{});
        seed_hash.update(&seed);
        seed_hash.final(&expanded);

        var scalar = expanded[0..32].*;
        defer secureZero(&scalar);
        Curve.scalar.clamp(&scalar);

        var nonce64: [Sha512.digest_length]u8 = undefined;
        defer secureZero(&nonce64);
        var nonce_hash = Sha512.init(.{});
        nonce_hash.update(expanded[32..]);
        nonce_hash.update(prefix);
        nonce_hash.update(infix);
        nonce_hash.update(msg);
        nonce_hash.final(&nonce64);

        var nonce = Curve.scalar.reduce64(nonce64);
        defer secureZero(&nonce);

        const r = try Curve.basePoint.mul(nonce);
        const r_bytes = r.toBytes();

        var challenge64: [Sha512.digest_length]u8 = undefined;
        defer secureZero(&challenge64);
        var challenge_hash = Sha512.init(.{});
        challenge_hash.update(&r_bytes);
        challenge_hash.update(&public_key);
        challenge_hash.update(prefix);
        challenge_hash.update(infix);
        challenge_hash.update(msg);
        challenge_hash.final(&challenge64);

        const challenge = Curve.scalar.reduce64(challenge64);
        const s = Curve.scalar.mulAdd(challenge, scalar, nonce);

        var out: Signature = undefined;
        out[0..Curve.encoded_length].* = r_bytes;
        out[Curve.encoded_length..].* = s;
        return out;
    }
};

/// Verify a plain RFC 8032 Ed25519 signature.
pub fn verify(msg: []const u8, sig: Signature, public_key: PublicKey) VerifyError!bool {
    return verifyPrefixed("", "", msg, sig, public_key);
}

/// Verify a domain-separated Ed25519 signature created by `KeyPair.signCtx`.
/// Accepts the current wire magic and any `alt_domain_prefix_magics` entry so a
/// peer that briefly signed under a renamed prefix still verifies.
pub fn verifyCtx(
    comptime domain: []const u8,
    msg: []const u8,
    sig: Signature,
    public_key: PublicKey,
) VerifyError!bool {
    return verifyCtxWithMagics(domain, "", msg, sig, public_key, false);
}

/// Verify a signature created by `KeyPair.signCtxInfix` over `infix ++ msg`.
/// Same dual-magic acceptance as `verifyCtx`.
pub fn verifyCtxInfix(
    comptime domain: []const u8,
    infix: []const u8,
    msg: []const u8,
    sig: Signature,
    public_key: PublicKey,
) VerifyError!bool {
    if (infix.len != known_infix_len) return error.InvalidInfixWidth;
    return verifyCtxWithMagics(domain, infix, msg, sig, public_key, true);
}

fn verifyCtxWithMagics(
    comptime domain: []const u8,
    infix: []const u8,
    msg: []const u8,
    sig: Signature,
    public_key: PublicKey,
    enforce_infix: bool,
) VerifyError!bool {
    _ = enforce_infix;
    const primary = domainPrefix(domain);
    if (try verifyPrefixed(&primary, infix, msg, sig, public_key)) return true;
    inline for (alt_domain_prefix_magics) |alt_magic| {
        const alt = domainPrefixWithMagic(alt_magic, domain);
        if (try verifyPrefixed(&alt, infix, msg, sig, public_key)) return true;
    }
    return false;
}

fn verifyPrefixed(
    prefix: []const u8,
    infix: []const u8,
    msg: []const u8,
    sig: Signature,
    public_key: PublicKey,
) VerifyError!bool {
    const pk = try StdEd25519.PublicKey.fromBytes(public_key);
    const std_sig = StdEd25519.Signature.fromBytes(sig);

    var verifier = try std_sig.verifier(pk);
    verifier.update(prefix);
    verifier.update(infix);
    verifier.update(msg);
    verifier.verify() catch |err| switch (err) {
        error.SignatureVerificationFailed => return false,
        else => return err,
    };
    return true;
}

fn domainPrefix(comptime domain: []const u8) [domain_prefix_magic.len + 1 + domain.len]u8 {
    return domainPrefixWithMagic(domain_prefix_magic, domain);
}

fn domainPrefixWithMagic(
    comptime magic: []const u8,
    comptime domain: []const u8,
) [magic.len + 1 + domain.len]u8 {
    comptime {
        if (domain.len == 0) @compileError("Ed25519 domain label must not be empty");
        if (domain.len > std.math.maxInt(u8)) @compileError("Ed25519 domain label exceeds 255 bytes");
        if (magic.len == 0) @compileError("Ed25519 domain-prefix magic must not be empty");
    }

    var out: [magic.len + 1 + domain.len]u8 = undefined;
    @memcpy(out[0..magic.len], magic);
    out[magic.len] = @intCast(domain.len);
    @memcpy(out[magic.len + 1 ..], domain);
    return out;
}

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

test "RFC 8032 Ed25519 test vector 1" {
    var kp = try KeyPair.fromSeed(hex("9d61b19deffd5a60ba844af492ec2cc4" ++
        "4449c5697b326919703bac031cae7f60"));
    defer kp.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &hex("d75a980182b10ab7d54bfed3c964073a" ++
            "0ee172f3daa62325af021a68f707511a"),
        &kp.public_key,
    );

    const sig = try kp.sign("");
    try std.testing.expectEqualSlices(
        u8,
        &hex("e5564300c360ac729086e2cc806e828a" ++
            "84877f1eb8e5d974d873e06522490155" ++
            "5fb8821590a33bacc61e39701cf9b46b" ++
            "d25bf5f0595bbe24655141438e7a100b"),
        &sig,
    );
    try std.testing.expect(try verify("", sig, kp.public_key));
}

test "RFC 8032 Ed25519 test vector 2" {
    var kp = try KeyPair.fromSeed(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));
    defer kp.deinit();

    const msg = hex("72");
    const sig = try kp.sign(&msg);

    try std.testing.expectEqualSlices(
        u8,
        &hex("92a009a9f0d4cab8720e820b5f642540" ++
            "a2b27b5416503f8fb3762223ebdb69da" ++
            "085ac1e43e15996e458f3613d0f11d8c" ++
            "387b2eaeb4302aeeb00d291612bb0c00"),
        &sig,
    );
    try std.testing.expect(try verify(&msg, sig, kp.public_key));
}

test "tampered signature is rejected" {
    var kp = try KeyPair.fromSeed(hex("9d61b19deffd5a60ba844af492ec2cc4" ++
        "4449c5697b326919703bac031cae7f60"));
    defer kp.deinit();

    var sig = try kp.sign("onyx");
    sig[32] ^= 0x01;

    try std.testing.expect(!try verify("onyx", sig, kp.public_key));
}

test "domain separation prevents cross-use" {
    var kp = try KeyPair.fromSeed(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));
    defer kp.deinit();

    const msg = "same transcript bytes";
    const node_sig = try kp.signCtx("node-identity", msg);
    const cap_sig = try kp.signCtx("capability-token", msg);

    try std.testing.expect(!std.mem.eql(u8, &node_sig, &cap_sig));
    try std.testing.expect(try verifyCtx("node-identity", msg, node_sig, kp.public_key));
    try std.testing.expect(try verifyCtx("capability-token", msg, cap_sig, kp.public_key));
    try std.testing.expect(!try verifyCtx("capability-token", msg, node_sig, kp.public_key));
    try std.testing.expect(!try verify(msg, node_sig, kp.public_key));
}

test "LOW-2: signCtxInfix/verifyCtxInfix reject a non-fixed-width infix" {
    var kp = try KeyPair.fromSeed(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));
    defer kp.deinit();

    // The one width every real caller uses (a 1-byte frame-type tag) works.
    const sig = try kp.signCtxInfix("onyx-low2-guard-test-v1", &[_]u8{0x07}, "msg");
    try std.testing.expect(try verifyCtxInfix("onyx-low2-guard-test-v1", &[_]u8{0x07}, "msg", sig, kp.public_key));

    // A 0-byte or >1-byte infix is rejected fail-closed (the infix/msg-boundary
    // ambiguity guard), on both the sign and verify side — no ambiguous signature.
    try std.testing.expectError(error.InvalidInfixWidth, kp.signCtxInfix("onyx-low2-guard-test-v1", "", "msg"));
    try std.testing.expectError(error.InvalidInfixWidth, kp.signCtxInfix("onyx-low2-guard-test-v1", "AB", "msg"));
    try std.testing.expectError(error.InvalidInfixWidth, verifyCtxInfix("onyx-low2-guard-test-v1", "AB", "msg", sig, kp.public_key));
}

test "legacy Onyx rename domain-prefix magic still verifies (mesh rollout)" {
    // Regression for the 2026-07-19 netsplit: a peer signed under the short-lived
    // `onyx-ed25519ctx-v1` magic must still verify on a node that signs with the
    // wire-stable `orochi-ed25519ctx-v1` magic. Sign path stays on the primary
    // magic; only verify is dual-accept.
    var kp = try KeyPair.fromSeed(hex("4ccd089b28ff96da9db6c346ec114e0f" ++
        "5b8a319f35aba624da8cf6ed4fb8a6fb"));
    defer kp.deinit();

    const domain = "tsumugi-prekey-v1";
    const msg = "prekey transcript bytes";

    // Primary (wire-stable) sign/verify still round-trips.
    const primary_sig = try kp.signCtx(domain, msg);
    try std.testing.expect(try verifyCtx(domain, msg, primary_sig, kp.public_key));

    // A signature produced under the renamed magic (what a mid-rename peer
    // would emit) must also verify — dual-magic acceptance on the verify path.
    const alt_prefix = domainPrefixWithMagic("onyx-ed25519ctx-v1", domain);
    const alt_sig = try kp.signPrefixed(&alt_prefix, "", msg);
    try std.testing.expect(try verifyCtx(domain, msg, alt_sig, kp.public_key));

    // Same for the infix path used by signed S2S frames.
    const infix = &[_]u8{0x2a};
    const primary_infix = try kp.signCtxInfix("signed-frame-v1", infix, msg);
    try std.testing.expect(try verifyCtxInfix("signed-frame-v1", infix, msg, primary_infix, kp.public_key));
    const alt_infix_prefix = domainPrefixWithMagic("onyx-ed25519ctx-v1", "signed-frame-v1");
    const alt_infix_sig = try kp.signPrefixed(&alt_infix_prefix, infix, msg);
    try std.testing.expect(try verifyCtxInfix("signed-frame-v1", infix, msg, alt_infix_sig, kp.public_key));

    // Tamper still fails under both magics.
    var bad = alt_sig;
    bad[0] ^= 0x01;
    try std.testing.expect(!try verifyCtx(domain, msg, bad, kp.public_key));
}

test {
    std.testing.refAllDecls(@This());
}
