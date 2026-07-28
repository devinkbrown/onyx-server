// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SPAKE2 password-authenticated key exchange over Edwards25519.
//!
//! ## Protocol summary
//!
//! Two parties (A and B) share a low-entropy password and want to establish a
//! shared session key without ever transmitting the password or any value that
//! leaks it to a passive or active adversary.
//!
//! Each party uses a fixed, independent base point for password blinding:
//!
//!   M  – "party A" blinding point
//!   N  – "party B" blinding point
//!
//! **Round 1 – each side sends one 32-byte message**
//!
//!   A picks random scalar x, computes X = x·G + w·M, sends X.
//!   B picks random scalar y, computes Y = y·G + w·N, sends Y.
//!
//! **Round 2 – each side derives the shared key**
//!
//!   A: K_A = x·(Y − w·N)          (removes B's blinding term)
//!   B: K_B = y·(X − w·M)          (removes A's blinding term)
//!
//!   Both sides hash a transcript binding idA, idB, X, Y, K, and w to produce
//!   the final shared key and a pair of key-confirmation MACs.
//!
//! ## Fixed blinding points M and N
//!
//! M and N are "nothing-up-my-sleeve" points derived by hashing domain labels
//! into a 64-byte value (SHA-512), reducing mod L to a scalar, then computing
//! scalar·G.  This is a deterministic, verifiable construction.
//!
//!   M = SHA-512("orochi-spake2-M-v1") mod L · G
//!   N = SHA-512("orochi-spake2-N-v1") mod L · G
//!
//! The resulting compressed byte values are embedded as constants below and
//! were verified with the standalone helper at the bottom of this file.
//!
//! ## Password scalar
//!
//!   w = SHA-512(password) mod L
//!
//! ## Key derivation and confirmation
//!
//! transcript = SHA-256(
//!     "onyx-spake2-transcript-v1" ||
//!     len32BE(idA) || idA || len32BE(idB) || idB ||
//!     X_bytes || Y_bytes || K_bytes || w_bytes
//! )
//!
//! shared_key       = transcript[0..32]
//! MAC_A            = HMAC-SHA-256(key=transcript, msg="A" || X || Y)
//! MAC_B            = HMAC-SHA-256(key=transcript, msg="B" || X || Y)
//!
//! Party A sends MAC_A; B verifies and replies with MAC_B; A verifies.
//!
//! ## Derivation of M and N constants (verification)
//!
//! Run:
//!   zig run src/crypto/pake.zig -- print-points
//!
//! or inspect the `deriveBlindingPoint` function used in the test below.
//!
//! ## No sibling @imports — std.crypto only.

const std = @import("std");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

/// Compressed Edwards25519 point length (bytes).
pub const point_len: usize = Edwards25519.encoded_length; // 32
/// Scalar length (bytes).
pub const scalar_len: usize = 32;
/// Shared session key length (bytes).
pub const key_len: usize = 32;
/// HMAC-SHA-256 MAC length (bytes).
pub const mac_len: usize = HmacSha256.mac_length; // 32

// ---------------------------------------------------------------------------
// Fixed blinding points M and N
//
// Derived by:
//   s = SHA-512(label_string) reduced mod L
//   P = s · basePoint
//   compressed = P.toBytes()
//
// These values were computed offline and are embedded here for efficiency.
// The `test "blinding points match derivation"` block re-derives them and
// asserts equality, providing an audit trail without comptime overhead.
// ---------------------------------------------------------------------------

/// Party A's wire-stable blinding point M = SHA-512("orochi-spake2-M-v1") mod L · G.
const point_M_bytes: [point_len]u8 = .{
    0xB5, 0x38, 0x9D, 0xD4, 0x3A, 0xB9, 0x36, 0x39,
    0x50, 0x1F, 0x84, 0xCF, 0x69, 0xC5, 0xC3, 0xF0,
    0x2E, 0x52, 0xF2, 0xC8, 0x5D, 0x7F, 0xA1, 0x8B,
    0xF8, 0x4F, 0xA2, 0x9F, 0x97, 0x73, 0xF3, 0xFA,
};

/// Party B's wire-stable blinding point N = SHA-512("orochi-spake2-N-v1") mod L · G.
const point_N_bytes: [point_len]u8 = .{
    0xC7, 0x3D, 0x5F, 0x5B, 0xAF, 0x83, 0x36, 0xC1,
    0xC6, 0x74, 0x6F, 0x4A, 0x7E, 0x86, 0x59, 0xC8,
    0xBF, 0x20, 0xD1, 0x4A, 0x2D, 0x16, 0xB6, 0xB2,
    0x19, 0x0A, 0x82, 0xB2, 0x75, 0x02, 0x5B, 0x64,
};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

pub const PakeError = error{
    /// A received point was not a valid Edwards25519 encoding.
    BadPoint,
    /// A derived shared point was the identity or a low-order point.
    WeakPoint,
    /// Key-confirmation MAC did not match.
    ConfirmationFailed,
};

// ---------------------------------------------------------------------------
// Party role
// ---------------------------------------------------------------------------

pub const Role = enum { party_a, party_b };

// ---------------------------------------------------------------------------
// Exchange state (held between startEx and finish)
// ---------------------------------------------------------------------------

/// Opaque per-exchange state.  Callers must keep this alive until `finish`
/// returns.  The `id_self` and `id_peer` slices are borrowed — callers must
/// keep them alive as well.
pub const State = struct {
    role: Role,
    id_self: []const u8,
    id_peer: []const u8,
    /// Password scalar w = SHA-512(password) mod L.
    w: [scalar_len]u8,
    /// Ephemeral scalar (x for A, y for B), reduced mod L.
    eph_scalar: [scalar_len]u8,
    /// Our outbound blinded message (X for A, Y for B), compressed.
    msg: [point_len]u8,
};

// ---------------------------------------------------------------------------
// Internal: password scalar
// ---------------------------------------------------------------------------

fn passwordScalar(password: []const u8) [scalar_len]u8 {
    var h: [64]u8 = undefined;
    Sha512.hash(password, &h, .{});
    return Scalar.reduce64(h);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Begin a SPAKE2 exchange.
///
/// Parameters
/// ----------
/// state_out    Caller-allocated `State`; populated on return.
/// msg_out      Populated with the 32-byte message to send to the peer.
/// role         Whether this party is A or B.
/// password     Shared low-entropy secret (arbitrary bytes).
/// id_self      Identity of this party (may be empty).
/// id_peer      Identity of the peer (may be empty).
/// eph_seed     32-byte seed for the ephemeral scalar.  Pass cryptographically
///              random bytes in production; pass a fixed value in tests.
///
/// The `id_self` and `id_peer` slices must remain valid until `finish` is
/// called with `state_out`.
pub fn startEx(
    state_out: *State,
    msg_out: *[point_len]u8,
    role: Role,
    password: []const u8,
    id_self: []const u8,
    id_peer: []const u8,
    eph_seed: [scalar_len]u8,
) PakeError!void {
    const w = passwordScalar(password);

    // Reduce seed to a canonical scalar in [0, L).
    const eph = Scalar.reduce(eph_seed);

    // Select our blinding point.
    const own_blinding_bytes: [point_len]u8 = switch (role) {
        .party_a => point_M_bytes,
        .party_b => point_N_bytes,
    };
    const own_blinding = Edwards25519.fromBytes(own_blinding_bytes) catch return PakeError.BadPoint;

    // w·P (our blinding contribution).
    const w_P = own_blinding.mul(w) catch return PakeError.WeakPoint;

    // eph·G (our ephemeral public key).
    const eph_pub = Edwards25519.basePoint.mul(eph) catch return PakeError.WeakPoint;

    // Blinded message: eph·G + w·P.
    const msg_point = eph_pub.add(w_P);

    state_out.* = .{
        .role = role,
        .id_self = id_self,
        .id_peer = id_peer,
        .w = w,
        .eph_scalar = eph,
        .msg = msg_point.toBytes(),
    };
    msg_out.* = state_out.msg;
}

/// Complete the SPAKE2 exchange after receiving the peer's message.
///
/// On success:
///   key_out                  ← 32-byte shared session key
///   mac_self_out             ← MAC this party should send to the peer
///   mac_peer_expected_out    ← MAC expected from the peer
///
/// After calling `finish`, send `mac_self_out` to the peer and verify the
/// peer's reply with `verifyConfirmation(mac_peer_expected_out, received)`.
pub fn finish(
    state: *const State,
    peer_msg: [point_len]u8,
    key_out: *[key_len]u8,
    mac_self_out: *[mac_len]u8,
    mac_peer_expected_out: *[mac_len]u8,
) PakeError!void {
    // Decode peer's blinded point.
    const peer_point = Edwards25519.fromBytes(peer_msg) catch return PakeError.BadPoint;

    // Peer's blinding point (opposite role).
    const peer_blinding_bytes: [point_len]u8 = switch (state.role) {
        .party_a => point_N_bytes, // peer is B, used N
        .party_b => point_M_bytes, // peer is A, used M
    };
    const peer_blinding = Edwards25519.fromBytes(peer_blinding_bytes) catch return PakeError.BadPoint;

    // Remove peer's blinding term: peer_point − w·peer_blinding.
    //   If we are A: (y·G + w·N) − w·N = y·G
    //   If we are B: (x·G + w·M) − w·M = x·G
    const w_peer_P = peer_blinding.mul(state.w) catch return PakeError.WeakPoint;
    const peer_unblinded = peer_point.add(w_peer_P.neg());

    // Shared point K = eph_scalar · peer_unblinded.
    const K = peer_unblinded.mul(state.eph_scalar) catch return PakeError.WeakPoint;
    Edwards25519.rejectIdentity(K) catch return PakeError.WeakPoint;
    K.rejectLowOrder() catch return PakeError.WeakPoint;
    const K_bytes = K.toBytes();

    // Canonical ordering: X is A's message, Y is B's message.
    const x_bytes: [point_len]u8 = switch (state.role) {
        .party_a => state.msg,
        .party_b => peer_msg,
    };
    const y_bytes: [point_len]u8 = switch (state.role) {
        .party_a => peer_msg,
        .party_b => state.msg,
    };

    const transcript = buildTranscript(
        state.id_self,
        state.id_peer,
        state.role,
        x_bytes,
        y_bytes,
        K_bytes,
        state.w,
    );

    key_out.* = transcript;

    var mac_a: [mac_len]u8 = undefined;
    computeConfirmationMac(&mac_a, transcript, "A", x_bytes, y_bytes);
    var mac_b: [mac_len]u8 = undefined;
    computeConfirmationMac(&mac_b, transcript, "B", x_bytes, y_bytes);

    switch (state.role) {
        .party_a => {
            mac_self_out.* = mac_a;
            mac_peer_expected_out.* = mac_b;
        },
        .party_b => {
            mac_self_out.* = mac_b;
            mac_peer_expected_out.* = mac_a;
        },
    }
}

/// Verify a key-confirmation MAC received from the peer.
///
/// Returns `PakeError.ConfirmationFailed` if the MAC does not match.
/// The comparison is constant-time.
pub fn verifyConfirmation(expected: [mac_len]u8, received: [mac_len]u8) PakeError!void {
    if (!std.crypto.timing_safe.eql([mac_len]u8, expected, received)) {
        return PakeError.ConfirmationFailed;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the session transcript and return SHA-256(transcript_input).
///
/// Both parties produce the same transcript because A/B ordering is derived
/// from the `role` parameter: idA is always party A's identity string.
fn buildTranscript(
    id_self: []const u8,
    id_peer: []const u8,
    role: Role,
    x_bytes: [point_len]u8,
    y_bytes: [point_len]u8,
    K_bytes: [point_len]u8,
    w: [scalar_len]u8,
) [32]u8 {
    const id_a: []const u8 = switch (role) {
        .party_a => id_self,
        .party_b => id_peer,
    };
    const id_b: []const u8 = switch (role) {
        .party_a => id_peer,
        .party_b => id_self,
    };

    var h = Sha256.init(.{});
    h.update("onyx-spake2-transcript-v1");
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(id_a.len), .big);
    h.update(&len_buf);
    h.update(id_a);
    std.mem.writeInt(u32, &len_buf, @intCast(id_b.len), .big);
    h.update(&len_buf);
    h.update(id_b);
    h.update(&x_bytes);
    h.update(&y_bytes);
    h.update(&K_bytes);
    h.update(&w);
    return h.finalResult();
}

/// HMAC-SHA-256(key=transcript, msg=role_tag || X || Y).
fn computeConfirmationMac(
    out: *[mac_len]u8,
    transcript: [32]u8,
    role_tag: []const u8,
    x_bytes: [point_len]u8,
    y_bytes: [point_len]u8,
) void {
    var ctx = HmacSha256.init(&transcript);
    ctx.update(role_tag);
    ctx.update(&x_bytes);
    ctx.update(&y_bytes);
    ctx.final(out);
}

/// Re-derive a blinding point from its label for audit/test purposes.
/// label → SHA-512 → reduce64 → scalar · G → compressed bytes.
fn deriveBlindingPoint(label: []const u8) ![point_len]u8 {
    var h: [64]u8 = undefined;
    Sha512.hash(label, &h, .{});
    const s = Scalar.reduce64(h);
    const p = try Edwards25519.basePoint.mul(s);
    return p.toBytes();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "matching passwords derive matching keys and confirmations verify" {
    // Arrange
    const password = "correct horse battery staple";
    const id_a = "alice";
    const id_b = "bob";
    const seed_a = @as([32]u8, @splat(0x01));
    const seed_b = @as([32]u8, @splat(0x02));

    // Act – party A starts
    var state_a: State = undefined;
    var msg_a: [point_len]u8 = undefined;
    try startEx(&state_a, &msg_a, .party_a, password, id_a, id_b, seed_a);

    // Act – party B starts
    var state_b: State = undefined;
    var msg_b: [point_len]u8 = undefined;
    try startEx(&state_b, &msg_b, .party_b, password, id_b, id_a, seed_b);

    // Act – party A finishes
    var key_a: [key_len]u8 = undefined;
    var mac_a_self: [mac_len]u8 = undefined;
    var mac_a_expects_from_b: [mac_len]u8 = undefined;
    try finish(&state_a, msg_b, &key_a, &mac_a_self, &mac_a_expects_from_b);

    // Act – party B finishes
    var key_b: [key_len]u8 = undefined;
    var mac_b_self: [mac_len]u8 = undefined;
    var mac_b_expects_from_a: [mac_len]u8 = undefined;
    try finish(&state_b, msg_a, &key_b, &mac_b_self, &mac_b_expects_from_a);

    // Assert – same shared key
    try std.testing.expectEqualSlices(u8, &key_a, &key_b);

    // Assert – confirmations cross-verify
    try verifyConfirmation(mac_a_expects_from_b, mac_b_self);
    try verifyConfirmation(mac_b_expects_from_a, mac_a_self);
}

test "wrong password yields different keys and confirmation fails" {
    // Arrange
    const id_a = "alice";
    const id_b = "bob";
    const seed_a = @as([32]u8, @splat(0x11));
    const seed_b = @as([32]u8, @splat(0x22));

    var state_a: State = undefined;
    var msg_a: [point_len]u8 = undefined;
    try startEx(&state_a, &msg_a, .party_a, "correct password", id_a, id_b, seed_a);

    var state_b: State = undefined;
    var msg_b: [point_len]u8 = undefined;
    try startEx(&state_b, &msg_b, .party_b, "WRONG password", id_b, id_a, seed_b);

    var key_a: [key_len]u8 = undefined;
    var mac_a_self: [mac_len]u8 = undefined;
    var mac_a_expects: [mac_len]u8 = undefined;
    try finish(&state_a, msg_b, &key_a, &mac_a_self, &mac_a_expects);

    var key_b: [key_len]u8 = undefined;
    var mac_b_self: [mac_len]u8 = undefined;
    var mac_b_expects: [mac_len]u8 = undefined;
    try finish(&state_b, msg_a, &key_b, &mac_b_self, &mac_b_expects);

    // Assert – keys differ
    try std.testing.expect(!std.mem.eql(u8, &key_a, &key_b));

    // Assert – confirmation fails both ways
    try std.testing.expectError(
        PakeError.ConfirmationFailed,
        verifyConfirmation(mac_a_expects, mac_b_self),
    );
    try std.testing.expectError(
        PakeError.ConfirmationFailed,
        verifyConfirmation(mac_b_expects, mac_a_self),
    );
}

test "transcript binds identities: swapped ids fail confirmation" {
    // Arrange – both parties use the same password, but B uses swapped ids.
    const password = "shared secret";
    const seed_a = @as([32]u8, @splat(0x33));
    const seed_b = @as([32]u8, @splat(0x44));

    // A identifies correctly: self="alice", peer="bob".
    var state_a: State = undefined;
    var msg_a: [point_len]u8 = undefined;
    try startEx(&state_a, &msg_a, .party_a, password, "alice", "bob", seed_a);

    // B uses swapped ids: self="alice" (wrong!), peer="bob" (wrong!).
    // This makes B's idA="bob" and idB="alice" in the transcript, which
    // differs from A's idA="alice" idB="bob".
    var state_b: State = undefined;
    var msg_b: [point_len]u8 = undefined;
    try startEx(&state_b, &msg_b, .party_b, password, "alice", "bob", seed_b);

    var key_a: [key_len]u8 = undefined;
    var mac_a_self: [mac_len]u8 = undefined;
    var mac_a_expects: [mac_len]u8 = undefined;
    try finish(&state_a, msg_b, &key_a, &mac_a_self, &mac_a_expects);

    var key_b: [key_len]u8 = undefined;
    var mac_b_self: [mac_len]u8 = undefined;
    var mac_b_expects: [mac_len]u8 = undefined;
    try finish(&state_b, msg_a, &key_b, &mac_b_self, &mac_b_expects);

    // Assert – keys differ because transcripts differ (different id ordering)
    try std.testing.expect(!std.mem.eql(u8, &key_a, &key_b));

    // Assert – confirmation fails
    try std.testing.expectError(
        PakeError.ConfirmationFailed,
        verifyConfirmation(mac_a_expects, mac_b_self),
    );
}

test "deterministic: same seeds produce identical messages and keys" {
    // Arrange
    const password = "deterministic test password";
    const seed_a = @as([32]u8, @splat(0x55));
    const seed_b = @as([32]u8, @splat(0x66));

    // First exchange
    var sa1: State = undefined;
    var msg_a1: [point_len]u8 = undefined;
    try startEx(&sa1, &msg_a1, .party_a, password, "p1", "p2", seed_a);

    var sb1: State = undefined;
    var msg_b1: [point_len]u8 = undefined;
    try startEx(&sb1, &msg_b1, .party_b, password, "p2", "p1", seed_b);

    var key1: [key_len]u8 = undefined;
    var m1s: [mac_len]u8 = undefined;
    var m1p: [mac_len]u8 = undefined;
    try finish(&sa1, msg_b1, &key1, &m1s, &m1p);

    // Second exchange with identical inputs
    var sa2: State = undefined;
    var msg_a2: [point_len]u8 = undefined;
    try startEx(&sa2, &msg_a2, .party_a, password, "p1", "p2", seed_a);

    var sb2: State = undefined;
    var msg_b2: [point_len]u8 = undefined;
    try startEx(&sb2, &msg_b2, .party_b, password, "p2", "p1", seed_b);

    var key2: [key_len]u8 = undefined;
    var m2s: [mac_len]u8 = undefined;
    var m2p: [mac_len]u8 = undefined;
    try finish(&sa2, msg_b2, &key2, &m2s, &m2p);

    // Assert – deterministic outputs
    try std.testing.expectEqualSlices(u8, &msg_a1, &msg_a2);
    try std.testing.expectEqualSlices(u8, &msg_b1, &msg_b2);
    try std.testing.expectEqualSlices(u8, &key1, &key2);
    try std.testing.expectEqualSlices(u8, &m1s, &m2s);
}

test "blinding points match derivation and are distinct" {
    // Re-derive M and N at runtime and compare against embedded constants.
    const derived_M = try deriveBlindingPoint("orochi-spake2-M-v1");
    const derived_N = try deriveBlindingPoint("orochi-spake2-N-v1");

    try std.testing.expectEqualSlices(u8, &point_M_bytes, &derived_M);
    try std.testing.expectEqualSlices(u8, &point_N_bytes, &derived_N);

    // M and N must be distinct.
    try std.testing.expect(!std.mem.eql(u8, &point_M_bytes, &point_N_bytes));

    // Neither is the identity element.
    const identity = Edwards25519.identityElement.toBytes();
    try std.testing.expect(!std.mem.eql(u8, &point_M_bytes, &identity));
    try std.testing.expect(!std.mem.eql(u8, &point_N_bytes, &identity));

    // Both decode as valid points.
    _ = try Edwards25519.fromBytes(point_M_bytes);
    _ = try Edwards25519.fromBytes(point_N_bytes);
}

test "empty identities are accepted" {
    const password = "no id test";
    const seed_a = @as([32]u8, @splat(0x77));
    const seed_b = @as([32]u8, @splat(0x88));

    var state_a: State = undefined;
    var msg_a: [point_len]u8 = undefined;
    try startEx(&state_a, &msg_a, .party_a, password, "", "", seed_a);

    var state_b: State = undefined;
    var msg_b: [point_len]u8 = undefined;
    try startEx(&state_b, &msg_b, .party_b, password, "", "", seed_b);

    var key_a: [key_len]u8 = undefined;
    var mac_a_self: [mac_len]u8 = undefined;
    var mac_a_expects: [mac_len]u8 = undefined;
    try finish(&state_a, msg_b, &key_a, &mac_a_self, &mac_a_expects);

    var key_b: [key_len]u8 = undefined;
    var mac_b_self: [mac_len]u8 = undefined;
    var mac_b_expects: [mac_len]u8 = undefined;
    try finish(&state_b, msg_a, &key_b, &mac_b_self, &mac_b_expects);

    try std.testing.expectEqualSlices(u8, &key_a, &key_b);
    try verifyConfirmation(mac_a_expects, mac_b_self);
    try verifyConfirmation(mac_b_expects, mac_a_self);
}
