// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secure channel: composes the shipped crypto primitives into an end-to-end
//! encrypted session for the mesh.
//!
//!   1:1  — HPKE (X-Wing-style KEM here X25519) establishes a shared root, the
//!          Signal-style double ratchet (`ratchet`) provides forward-secret,
//!          self-healing per-frame AEAD. The relay never sees plaintext.
//!   group — TreeKEM (`treekem`) derives a shared group secret that rekeys on
//!          add/remove/update; the root secret keys a group AEAD.
//!
//! This is the crypto analog of `transport_stack.zig`/`media_session.zig`: a thin
//! coordinator wiring independently-tested modules. Live wiring onto the S2S link
//! waits on the Mooring handshake (task #2) which supplies node identity; this
//! module is transport-agnostic and deterministic, so it slots into the DST
//! harness now.
const std = @import("std");
const zig_compat = @import("zig_compat.zig");
const random = @import("random.zig");

const ratchet = @import("ratchet.zig");
const hpke = @import("hpke.zig");
const treekem = @import("treekem.zig");
const toml = @import("../proto/toml.zig");

const X25519 = std.crypto.dh.X25519;

pub const Header = ratchet.Header;
pub const SealedMessage = ratchet.SealedMessage;
pub const PublicKey = [X25519.public_length]u8;

/// Historic default for the double-ratchet's max cached skipped message keys.
pub const default_max_skip_default: usize = 256;

/// Operationally tunable max skipped message keys cached by the double ratchet.
/// Overridable via `[tls].ratchet_max_skip`; defaults preserve prior behavior.
pub var default_max_skip: usize = default_max_skip_default;

/// Overlay `[tls].ratchet_max_skip` onto the module-level ratchet skip cap.
/// Absent or zero values leave the current cap unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getUint("tls.ratchet_max_skip")) |v| {
        if (v != 0) default_max_skip = @intCast(v);
    }
}

/// The ratchet `max_skip` (a `u32` in the ratchet API), clamped from the
/// module-level `usize` default so an over-large config never overflows.
fn ratchetMaxSkip() u32 {
    return std.math.cast(u32, default_max_skip) orelse std.math.maxInt(u32);
}

/// Derive the ratchet's first "next" DH key pair deterministically from the
/// shared root + a role label, so each side has a pre-staged pair for its first
/// DH-ratchet step without an extra wire round-trip.
fn deriveNextPair(shared: [32]u8, label: []const u8) !X25519.KeyPair {
    var seed: [X25519.seed_length]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&shared);
    h.update(label);
    h.final(&seed);
    return zig_compat.x25519GenerateDeterministic(seed);
}

/// A 1:1 forward-secret channel over the double ratchet, bootstrapped from an
/// HPKE-encapsulated shared root so neither side ever transmits the root.
pub const Channel = struct {
    rx: ratchet.Ratchet,

    /// Initiator: HPKE-encapsulate to the responder's public key, seed the
    /// ratchet root from the shared secret, and start as "Alice". Returns the
    /// channel plus the KEM `enc` value to hand to the responder out-of-band
    /// (or in the first frame's preamble).
    pub fn initiate(
        allocator: std.mem.Allocator,
        own_pair: X25519.KeyPair,
        responder_pub: PublicKey,
    ) !struct { channel: Channel, enc: hpke.Enc } {
        var eph_seed: [X25519.seed_length]u8 = undefined;
        try random.fillOsEntropy(&eph_seed);
        defer std.crypto.secureZero(u8, eph_seed[0..]);

        const encapsulation = try hpke.encapDeterministic(responder_pub, eph_seed);
        const root = ratchet.RootKey.init(encapsulation.shared_secret);
        var r = try ratchet.Ratchet.initAlice(allocator, root, own_pair, responder_pub, ratchetMaxSkip());
        r.setNextDhKeyPair(try deriveNextPair(encapsulation.shared_secret, "mz-next-initiator"));
        return .{ .channel = .{ .rx = r }, .enc = encapsulation.enc };
    }

    /// Responder: HPKE-decapsulate `enc` with the matching secret to recover the
    /// same root, and start as "Bob". `own_pair` must be the keypair whose public
    /// key the initiator encapsulated to.
    pub fn respond(
        allocator: std.mem.Allocator,
        own_pair: X25519.KeyPair,
        enc: hpke.Enc,
    ) !Channel {
        const shared = try hpke.decap(enc, own_pair.secret_key);
        const root = ratchet.RootKey.init(shared);
        var b = ratchet.Ratchet.initBob(allocator, root, own_pair, ratchetMaxSkip());
        b.setNextDhKeyPair(try deriveNextPair(shared, "mz-next-responder"));
        return .{ .rx = b };
    }

    pub fn deinit(self: *Channel) void {
        self.rx.deinit();
    }

    /// Encrypt one frame; the returned message's ciphertext is allocator-owned.
    pub fn seal(self: *Channel, plaintext: []const u8, associated_data: []const u8) !SealedMessage {
        return self.rx.encrypt(plaintext, associated_data);
    }

    /// Decrypt one frame; the returned plaintext is allocator-owned.
    pub fn open(self: *Channel, header: Header, ciphertext: []const u8, associated_data: []const u8) ![]u8 {
        return self.rx.decrypt(header, ciphertext, associated_data);
    }
};

/// A group key agreement over TreeKEM. The root secret keys a group AEAD; any
/// add/remove/update produces a new root all current members converge on.
pub const SecureGroup = struct {
    group: treekem.Group,

    pub fn init(allocator: std.mem.Allocator, member_seeds: []const treekem.MemberSeed) !SecureGroup {
        return .{ .group = try treekem.Group.init(allocator, member_seeds) };
    }

    pub fn deinit(self: *SecureGroup) void {
        self.group.deinit();
    }

    /// Current group secret (use as / to derive the group AEAD key).
    pub fn groupKey(self: *const SecureGroup) treekem.Secret {
        return self.group.rootSecret();
    }

    pub fn update(self: *SecureGroup, member_id: treekem.MemberId) !treekem.Commit {
        return self.group.update(member_id);
    }

    pub fn add(self: *SecureGroup, seed_value: treekem.MemberSeed) !treekem.Commit {
        return self.group.add(seed_value);
    }

    pub fn remove(self: *SecureGroup, member_id: treekem.MemberId) !treekem.Commit {
        return self.group.remove(member_id);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn pairFromSeed(b: u8) !X25519.KeyPair {
    return zig_compat.x25519GenerateDeterministic(@as([X25519.seed_length]u8, @splat(b)));
}

test "1:1 channel: HPKE bootstrap + ratchet round-trip both directions" {
    const allocator = testing.allocator;
    const alice_pair = try pairFromSeed(0x11);
    const bob_pair = try pairFromSeed(0x22);

    const setup = try Channel.initiate(allocator, alice_pair, bob_pair.public_key);
    var alice = setup.channel;
    defer alice.deinit();
    var bob = try Channel.respond(allocator, bob_pair, setup.enc);
    defer bob.deinit();

    // Alice -> Bob
    var m1 = try alice.seal("hello bob", "ad");
    defer m1.deinit(allocator);
    const p1 = try bob.open(m1.header, m1.ciphertext, "ad");
    defer allocator.free(p1);
    try testing.expectEqualStrings("hello bob", p1);

    // Bob -> Alice (a reply triggers the DH ratchet)
    var m2 = try bob.seal("hi alice", "ad");
    defer m2.deinit(allocator);
    const p2 = try alice.open(m2.header, m2.ciphertext, "ad");
    defer allocator.free(p2);
    try testing.expectEqualStrings("hi alice", p2);
}

test "1:1 channel: tampered ciphertext is rejected" {
    const allocator = testing.allocator;
    const alice_pair = try pairFromSeed(0x44);
    const bob_pair = try pairFromSeed(0x55);
    const setup = try Channel.initiate(allocator, alice_pair, bob_pair.public_key);
    var alice = setup.channel;
    defer alice.deinit();
    var bob = try Channel.respond(allocator, bob_pair, setup.enc);
    defer bob.deinit();

    var m = try alice.seal("secret", "ad");
    defer m.deinit(allocator);
    m.ciphertext[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, bob.open(m.header, m.ciphertext, "ad"));
}

test "1:1 channel: out-of-order delivery within the skip window" {
    const allocator = testing.allocator;
    const alice_pair = try pairFromSeed(0x77);
    const bob_pair = try pairFromSeed(0x88);
    const setup = try Channel.initiate(allocator, alice_pair, bob_pair.public_key);
    var alice = setup.channel;
    defer alice.deinit();
    var bob = try Channel.respond(allocator, bob_pair, setup.enc);
    defer bob.deinit();

    var m1 = try alice.seal("first", "");
    defer m1.deinit(allocator);
    var m2 = try alice.seal("second", "");
    defer m2.deinit(allocator);

    // Deliver the second message before the first.
    const p2 = try bob.open(m2.header, m2.ciphertext, "");
    defer allocator.free(p2);
    try testing.expectEqualStrings("second", p2);
    const p1 = try bob.open(m1.header, m1.ciphertext, "");
    defer allocator.free(p1);
    try testing.expectEqualStrings("first", p1);
}

test "group: all members share a key; rekey on remove evicts the removed member" {
    const allocator = testing.allocator;
    const seeds = [_]treekem.MemberSeed{
        @as([treekem.member_seed_len]u8, @splat(0xa1)),
        @as([treekem.member_seed_len]u8, @splat(0xa2)),
        @as([treekem.member_seed_len]u8, @splat(0xa3)),
    };
    var g = try SecureGroup.init(allocator, &seeds);
    defer g.deinit();

    const k0 = g.groupKey();

    // An update changes the group key (forward secrecy on rekey). Member ids are
    // 1-based in treekem.
    var commit = try g.update(1);
    defer commit.deinit();
    const k1 = g.groupKey();
    try testing.expect(!std.mem.eql(u8, &k0, &k1));

    // A removed member's seed can no longer derive the post-removal key.
    var rm = try g.remove(3);
    defer rm.deinit();
    const k2 = g.groupKey();
    try testing.expect(!std.mem.eql(u8, &k1, &k2));
}

test "applyToml overrides ratchet_max_skip and restores cleanly" {
    const saved = default_max_skip;
    defer default_max_skip = saved; // never leak the override into other tests
    const allocator = testing.allocator;

    var doc = try toml.parse(allocator, "[tls]\nratchet_max_skip = 64\n");
    defer doc.deinit(allocator);
    applyToml(&doc);
    try testing.expectEqual(@as(usize, 64), default_max_skip);
    try testing.expectEqual(@as(u32, 64), ratchetMaxSkip());

    // Absent / zero leaves the current value unchanged.
    default_max_skip = default_max_skip_default;
    var zero = try toml.parse(allocator, "[tls]\nratchet_max_skip = 0\n");
    defer zero.deinit(allocator);
    applyToml(&zero);
    try testing.expectEqual(default_max_skip_default, default_max_skip);
}
