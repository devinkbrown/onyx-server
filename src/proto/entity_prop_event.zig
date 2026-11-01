// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ENTITY_PROP frame payload codec (S2S IRCX user/member PROP convergence).
//!
//! Carries one last-writer-wins NON-CHANNEL property fact between mesh peers:
//! key `key` on the `kind` entity `entity` is present with `value`/`owner` as of
//! `hlc`, or absent when `present` is false. This is the user/member counterpart
//! of `channel_prop_event.zig`: channel props ride CHANNEL_PROP, while `user` and
//! `member` entity props ride ENTITY_PROP. Decode borrows the input and allocates
//! nothing; all fields are bounded to IRCX-compatible limits.
//!
//! Like CHANNEL_PROP, an ENTITY_PROP fact is a CRDT fact RE-BROADCAST across the
//! mesh: a node that learns a remote prop applies it and re-forwards it, preserving
//! the ORIGINAL `origin_node`. To authenticate that fact end-to-end (so a relay
//! cannot forge or alter another node's prop), the AUTHOR signs a canonical
//! transcript of the immutable fields ONCE and stamps a self-contained
//! `origin_pubkey`/`origin_sig` pair, which every relay forwards VERBATIM and
//! every hop verifies against the claimed `origin_node` (self-certifying:
//! `originShortId(pubkey) == origin_node`). Both are empty on the legacy unsigned
//! path, and the codec stays forward-compatible: an absent signature decodes to
//! empty, exactly like a legacy frame.
//!
//! The `kind` byte is the only field that distinguishes this frame from
//! CHANNEL_PROP, and it is BOTH on the wire AND folded into the signed transcript,
//! so a relay cannot reclassify a user prop as a member prop (or vice-versa)
//! without invalidating the signature. The transcript is domain-separated
//! (`sign_domain`) so an ENTITY_PROP signature can never validate as a
//! CHANNEL_PROP one (or any other Onyx Server Ed25519 use).
const std = @import("std");

const sign = @import("../crypto/sign.zig");
const ircx_prop_store = @import("ircx_prop_store.zig");

pub const max_entity_len = 256; // member ids are "channel:nick" — wider than a channel
pub const max_key_len = 64;
pub const max_value_len = 512;
pub const max_owner_len = 128;

pub const pubkey_len = sign.public_key_len; // 32
pub const sig_len = sign.signature_len; // 64

const fixed_prefix = 1 + 1 + 8 + 8; // present + kind + origin_node + hlc

pub const Error = error{
    Truncated,
    FieldTooLong,
    TrailingBytes,
    BadSignatureWidth,
    BadEntityKind,
};

/// The non-channel entity kinds carried by ENTITY_PROP. Mirrors
/// `ircx_prop_store.EntityKind` minus `channel` (which rides CHANNEL_PROP). The
/// numeric tag is stable wire + transcript surface; do NOT renumber.
pub const EntityKind = enum(u8) {
    user = 1,
    member = 2,

    pub fn fromTag(tag: u8) ?EntityKind {
        return switch (tag) {
            @backingInt(EntityKind.user) => .user,
            @backingInt(EntityKind.member) => .member,
            else => null,
        };
    }

    /// Bridge to the prop-store entity kind for store insert/lookup.
    pub fn toStoreKind(self: EntityKind) ircx_prop_store.EntityKind {
        return switch (self) {
            .user => .user,
            .member => .member,
        };
    }

    /// Map a prop-store entity kind onto an ENTITY_PROP kind, or null for
    /// `channel` (which is NOT carried here — channels ride CHANNEL_PROP).
    pub fn fromStoreKind(kind: ircx_prop_store.EntityKind) ?EntityKind {
        return switch (kind) {
            .channel => null,
            .user => .user,
            .member => .member,
        };
    }
};

pub const EntityPropEvent = struct {
    present: bool,
    kind: EntityKind,
    origin_node: u64,
    hlc: u64,
    entity: []const u8,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
    /// SELF-CONTAINED multi-hop origin signature: the origin node's 32-byte
    /// Ed25519 public key, minted ONCE by the author and forwarded VERBATIM by
    /// every relay. Empty ("") on the legacy unsigned path. When non-empty it is
    /// exactly `pubkey_len` bytes and self-certifies the origin: a receiver
    /// requires `originShortId(origin_pubkey) == origin_node`.
    origin_pubkey: []const u8 = "",
    /// The 64-byte Ed25519 signature over the canonical origin transcript (see
    /// `originTranscript`), bound to `sign_domain`. Empty when unsigned; always
    /// paired with `origin_pubkey` (both empty or both present). A relay re-emits
    /// this byte-for-byte and never re-signs.
    origin_sig: []const u8 = "",
};

/// True when the event carries a well-formed self-contained origin signature
/// (both fields present at their exact Ed25519 widths). Empty pair => unsigned.
fn signaturePresent(ev: EntityPropEvent) Error!bool {
    const have_pk = ev.origin_pubkey.len != 0;
    const have_sig = ev.origin_sig.len != 0;
    if (have_pk != have_sig) return error.BadSignatureWidth;
    if (!have_pk) return false;
    if (ev.origin_pubkey.len != pubkey_len or ev.origin_sig.len != sig_len) return error.BadSignatureWidth;
    return true;
}

pub fn encodedLen(ev: EntityPropEvent) Error!usize {
    if (ev.entity.len > max_entity_len or
        ev.key.len > max_key_len or
        ev.value.len > max_value_len or
        ev.owner.len > max_owner_len)
    {
        return error.FieldTooLong;
    }
    const base = fixed_prefix + 2 + ev.entity.len + 2 + ev.key.len + 2 + ev.value.len + 2 + ev.owner.len;
    // Forward-compatible signature suffix: a 1-byte flag, plus the fixed-width
    // pubkey+sig only when present. Absent (legacy) frames carry NO suffix at
    // all, so an unsigned event is byte-for-byte identical to the prior format.
    if (try signaturePresent(ev)) return base + 1 + pubkey_len + sig_len;
    return base;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: EntityPropEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    out[i] = @backingInt(ev.kind);
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    i = writeField(out, i, ev.entity);
    i = writeField(out, i, ev.key);
    i = writeField(out, i, ev.value);
    i = writeField(out, i, ev.owner);
    if (try signaturePresent(ev)) {
        out[i] = 1;
        i += 1;
        @memcpy(out[i..][0..pubkey_len], ev.origin_pubkey);
        i += pubkey_len;
        @memcpy(out[i..][0..sig_len], ev.origin_sig);
        i += sig_len;
    }
    return out[0..i];
}

fn writeField(out: []u8, i_in: usize, bytes: []const u8) usize {
    var i = i_in;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(bytes.len), .little);
    i += 2;
    @memcpy(out[i..][0..bytes.len], bytes);
    return i + bytes.len;
}

/// Decode from `bytes`; returned slices borrow `bytes`.
pub fn decode(bytes: []const u8) Error!EntityPropEvent {
    if (bytes.len < fixed_prefix + 8) return error.Truncated;
    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const kind = EntityKind.fromTag(bytes[i]) orelse return error.BadEntityKind;
    i += 1;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const entity = try readField(bytes, &i, max_entity_len);
    const key = try readField(bytes, &i, max_key_len);
    const value = try readField(bytes, &i, max_value_len);
    const owner = try readField(bytes, &i, max_owner_len);

    // Forward-compatible signature suffix. No trailing bytes => legacy unsigned
    // frame (empty pubkey/sig). A 1-byte flag of 0 likewise means unsigned; 1
    // means a fixed-width pubkey+sig follows. Any other shape is malformed.
    var origin_pubkey: []const u8 = "";
    var origin_sig: []const u8 = "";
    if (i != bytes.len) {
        if (bytes.len < i + 1) return error.Truncated;
        const flag = bytes[i];
        i += 1;
        if (flag == 1) {
            if (bytes.len < i + pubkey_len + sig_len) return error.Truncated;
            origin_pubkey = bytes[i .. i + pubkey_len];
            i += pubkey_len;
            origin_sig = bytes[i .. i + sig_len];
            i += sig_len;
        } else if (flag != 0) {
            return error.BadSignatureWidth;
        }
        if (i != bytes.len) return error.TrailingBytes;
    }

    return .{
        .present = present,
        .kind = kind,
        .origin_node = origin_node,
        .hlc = hlc,
        .entity = entity,
        .key = key,
        .value = value,
        .owner = owner,
        .origin_pubkey = origin_pubkey,
        .origin_sig = origin_sig,
    };
}

fn readField(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.FieldTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const field = bytes[i.* .. i.* + len];
    i.* += len;
    return field;
}

// ---------------------------------------------------------------------------
// Self-contained multi-hop origin signature
//
// ENTITY_PROP is a CRDT fact RE-BROADCAST with the original `origin_node`
// preserved, so the per-link `signed_frame` envelope (where the sending peer IS
// the origin) cannot authenticate it past the first hop. Instead the AUTHOR
// signs a canonical transcript of its IMMUTABLE fields ONCE; every relay
// forwards the `(origin_pubkey, origin_sig)` pair byte-for-byte, and every hop
// verifies it against the CLAIMED origin. Because the node id is self-certifying
// (`node_id = BLAKE3-160(pubkey)`, `origin_node = shortId(node_id)`), a receiver
// needs NO key distribution: it checks `originShortId(pubkey) == origin_node`
// plus the signature. A relay cannot forge or alter an authored prop fact
// without the origin's private key.
//
// SIGNED FIELDS (immutable, origin-authored): origin_node, hlc, present, kind,
// entity, key, value, owner. There are no mutable/hop-local prop fields, so the
// entire LWW fact is bound — tampering with any field after signing fails.
// ---------------------------------------------------------------------------

const node_identity = @import("../daemon/node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

/// Domain label folded into the Ed25519 transcript (via `sign.signCtx`).
/// Distinct from every other Ed25519 use in Onyx Server (node identity, oper grants,
/// migration tokens, the per-link `signed_frame`, the MESSAGE relay, and the
/// channel-prop origin signature), so a user/member entity-prop signature can
/// never validate in another context — including the channel-prop one.
pub const sign_domain = "onyx-s2s-entityprop-v1";

pub const SignError = sign.SignError || error{NoSpaceLeft};

/// The u64 mesh routing handle (origin short id) self-certified by `pubkey`:
/// `shortId(nodeIdFromPublicKey(pubkey))`. A receiver requires this to equal the
/// fact's claimed `origin_node` so a relay cannot assert another node's origin.
pub fn originShortId(pubkey: sign.PublicKey) u64 {
    return node_short_id.shortId(node_identity.nodeIdFromPublicKey(pubkey));
}

/// Append a length-prefixed string field to the transcript: a u32-LE length
/// followed by the raw bytes. Length-framing every variable field makes the
/// serialization unambiguous (no field boundary can be shifted by moving bytes
/// between adjacent fields).
fn appendLenPrefixed(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, field: []const u8) !void {
    var len_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_le, @intCast(field.len), .little);
    try out.appendSlice(allocator, &len_le);
    try out.appendSlice(allocator, field);
}

/// Build the canonical signed transcript of `ev`'s immutable origin-authored
/// fields into a freshly-allocated buffer the caller owns. Deterministic across
/// nodes: fixed field order, fixed-width integers (LE), and u32-LE length framing
/// on every string. Independent of the on-wire codec layout, so the signature is
/// stable regardless of how the frame is (re)encoded. The `kind` byte is folded
/// in so a relay cannot reclassify the entity without invalidating the signature.
pub fn originTranscript(allocator: std.mem.Allocator, ev: EntityPropEvent) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var u64_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64_le, ev.origin_node, .little);
    try out.appendSlice(allocator, &u64_le);
    std.mem.writeInt(u64, &u64_le, ev.hlc, .little);
    try out.appendSlice(allocator, &u64_le);
    try out.append(allocator, @intFromBool(ev.present));
    try out.append(allocator, @backingInt(ev.kind));
    try appendLenPrefixed(&out, allocator, ev.entity);
    try appendLenPrefixed(&out, allocator, ev.key);
    try appendLenPrefixed(&out, allocator, ev.value);
    try appendLenPrefixed(&out, allocator, ev.owner);

    return out.toOwnedSlice(allocator);
}

/// Sign `ev`'s canonical origin transcript with the author's Ed25519 keypair and
/// STAMP `origin_pubkey`/`origin_sig` in place. Call this ONCE, at the node that
/// AUTHORS the prop (where `origin_node` is the local node). The caller MUST
/// guarantee the self-certifying invariant `originShortId(kp.public_key) ==
/// ev.origin_node`; otherwise the stamped signature would fail every receiver's
/// origin check (sign at the origin or not at all). `pubkey_buf`/`sig_buf` back
/// the stamped slices and must outlive any encode that follows.
pub fn signInPlace(
    ev: *EntityPropEvent,
    kp: *const sign.KeyPair,
    transcript: []const u8,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) sign.SignError!void {
    const sig = try kp.signCtx(sign_domain, transcript);
    pubkey_buf.* = kp.public_key;
    sig_buf.* = sig;
    ev.origin_pubkey = pubkey_buf;
    ev.origin_sig = sig_buf;
}

pub const VerifyOutcome = enum {
    /// No `(origin_pubkey, origin_sig)` present: legacy unsigned path. The caller
    /// follows the existing (pre-signature) behavior unchanged.
    unsigned,
    /// Signature present, origin self-certifies, and the transcript verifies.
    verified,
    /// Signature present but the self-certified origin id did not match
    /// `origin_node` (a peer asserting another node's origin without its key).
    origin_mismatch,
    /// Signature present and origin matched, but the Ed25519 signature over the
    /// canonical transcript failed (forged or tampered fact).
    bad_signature,
};

/// Verify `ev`'s self-contained origin signature. Allocates the transcript
/// internally (freed before return). Returns `.unsigned` when no signature is
/// carried (backward-compatible legacy path), `.verified` on full success, or a
/// specific rejection reason. Decode enforces the field widths, but this is
/// defensive against a hand-built struct too.
pub fn verifyOrigin(allocator: std.mem.Allocator, ev: EntityPropEvent) !VerifyOutcome {
    if (ev.origin_pubkey.len == 0 and ev.origin_sig.len == 0) return .unsigned;
    if (ev.origin_pubkey.len != pubkey_len or ev.origin_sig.len != sig_len) return .bad_signature;

    const pubkey: sign.PublicKey = ev.origin_pubkey[0..pubkey_len].*;
    if (originShortId(pubkey) != ev.origin_node) return .origin_mismatch;

    const sig: sign.Signature = ev.origin_sig[0..sig_len].*;
    const transcript = try originTranscript(allocator, ev);
    defer allocator.free(transcript);

    const ok = sign.verifyCtx(sign_domain, transcript, sig, pubkey) catch return .bad_signature;
    return if (ok) .verified else .bad_signature;
}

const testing = std.testing;

test "entity prop event set round-trips (user)" {
    const ev = EntityPropEvent{
        .present = true,
        .kind = .user,
        .origin_node = 7,
        .hlc = 12345,
        .entity = "alice",
        .key = "STATUS",
        .value = "away mesh",
        .owner = "alice",
    };
    var buf: [800]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expect(got.present);
    try testing.expectEqual(EntityKind.user, got.kind);
    try testing.expectEqual(@as(u64, 7), got.origin_node);
    try testing.expectEqual(@as(u64, 12345), got.hlc);
    try testing.expectEqualStrings("alice", got.entity);
    try testing.expectEqualStrings("STATUS", got.key);
    try testing.expectEqualStrings("away mesh", got.value);
    try testing.expectEqualStrings("alice", got.owner);
}

test "entity prop event set round-trips (member)" {
    const ev = EntityPropEvent{
        .present = true,
        .kind = .member,
        .origin_node = 3,
        .hlc = 42,
        .entity = "#chat:bob",
        .key = "ROLE",
        .value = "moderator",
        .owner = "founder",
    };
    var buf: [800]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqual(EntityKind.member, got.kind);
    try testing.expectEqualStrings("#chat:bob", got.entity);
    try testing.expectEqualStrings("moderator", got.value);
}

test "entity prop delete round-trips" {
    const ev = EntityPropEvent{ .present = false, .kind = .user, .origin_node = 7, .hlc = 9, .entity = "alice", .key = "STATUS", .value = "", .owner = "alice" };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expect(!got.present);
    try testing.expectEqualStrings("", got.value);
}

test "entity prop codec rejects truncated and trailing input" {
    const ev = EntityPropEvent{ .present = true, .kind = .user, .origin_node = 7, .hlc = 1, .entity = "u", .key = "K", .value = "V", .owner = "o" };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var padded: [258]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0; // unsigned flag
    padded[wire.len + 1] = 0xAA; // stray trailing byte after the flag
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 2]));

    padded[wire.len] = 0x7f;
    try testing.expectError(error.BadSignatureWidth, decode(padded[0 .. wire.len + 1]));
}

test "entity prop codec rejects a bad entity kind byte" {
    const ev = EntityPropEvent{ .present = true, .kind = .user, .origin_node = 7, .hlc = 1, .entity = "u", .key = "K", .value = "V", .owner = "o" };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);
    var mutable: [256]u8 = undefined;
    @memcpy(mutable[0..wire.len], wire);
    mutable[1] = 0; // 0 is not a valid EntityKind (channel rides CHANNEL_PROP)
    try testing.expectError(error.BadEntityKind, decode(mutable[0..wire.len]));
    mutable[1] = 0xff;
    try testing.expectError(error.BadEntityKind, decode(mutable[0..wire.len]));
}

test "entity prop codec rejects oversized fields" {
    const big = &@as([(max_value_len + 1)]u8, @splat('x'));
    const ev = EntityPropEvent{ .present = true, .kind = .user, .origin_node = 7, .hlc = 1, .entity = "u", .key = "K", .value = big, .owner = "o" };
    try testing.expectError(error.FieldTooLong, encodedLen(ev));
}

// ---------------------------------------------------------------------------
// Self-contained multi-hop origin signature tests
// ---------------------------------------------------------------------------

fn propTestKeyPair(seed_byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed_byte)));
}

/// Build a prop fact whose `origin_node` is the self-certified short id of `kp`,
/// then sign it in place using caller-provided backing buffers.
fn signPropSample(
    kp: *const sign.KeyPair,
    kind: EntityKind,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) !EntityPropEvent {
    var ev = EntityPropEvent{
        .present = true,
        .kind = kind,
        .origin_node = originShortId(kp.public_key),
        .hlc = 9001,
        .entity = if (kind == .member) "#room:alice" else "alice",
        .key = "MARK",
        .value = "authored once, relayed everywhere",
        .owner = "alice",
    };
    const transcript = try originTranscript(testing.allocator, ev);
    defer testing.allocator.free(transcript);
    try signInPlace(&ev, kp, transcript, pubkey_buf, sig_buf);
    return ev;
}

test "entity prop event round-trips WITHOUT a signature (legacy unsigned)" {
    const ev = EntityPropEvent{
        .present = true,
        .kind = .user,
        .origin_node = 7,
        .hlc = 12345,
        .entity = "alice",
        .key = "STATUS",
        .value = "hello mesh",
        .owner = "alice",
    };
    var buf: [800]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);
    const got = try decode(wire);
    try testing.expectEqual(@as(usize, 0), got.origin_pubkey.len);
    try testing.expectEqual(@as(usize, 0), got.origin_sig.len);
    try testing.expectEqual(VerifyOutcome.unsigned, try verifyOrigin(testing.allocator, got));
}

test "entity prop event round-trips WITH a signature and verifies (user and member)" {
    inline for (.{ EntityKind.user, EntityKind.member }) |kind| {
        var kp = try propTestKeyPair(0xA1);
        defer kp.deinit();
        var pk_buf: [pubkey_len]u8 = undefined;
        var sig_buf: [sig_len]u8 = undefined;
        const ev = try signPropSample(&kp, kind, &pk_buf, &sig_buf);

        var buf: [900]u8 = undefined;
        const wire = try encode(ev, &buf);
        try testing.expectEqual(try encodedLen(ev), wire.len);

        const got = try decode(wire);
        try testing.expectEqual(kind, got.kind);
        try testing.expectEqual(@as(usize, pubkey_len), got.origin_pubkey.len);
        try testing.expectEqual(@as(usize, sig_len), got.origin_sig.len);
        try testing.expectEqualSlices(u8, ev.origin_pubkey, got.origin_pubkey);
        try testing.expectEqualSlices(u8, ev.origin_sig, got.origin_sig);
        try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, got));
    }
}

test "entity prop signature is rejected when origin_pubkey does not self-certify origin_node" {
    var attacker = try propTestKeyPair(0xD5);
    defer attacker.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var ev = try signPropSample(&attacker, .user, &pk_buf, &sig_buf);
    ev.origin_node = originShortId(attacker.public_key) ^ 0x1;
    try testing.expectEqual(VerifyOutcome.origin_mismatch, try verifyOrigin(testing.allocator, ev));
}

test "entity prop signature is rejected when re-signed with a foreign key" {
    var origin_kp = try propTestKeyPair(0xC3);
    defer origin_kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    var ev = try signPropSample(&origin_kp, .user, &pk_buf, &sig_buf);

    var attacker = try propTestKeyPair(0xC4);
    defer attacker.deinit();
    const transcript = try originTranscript(testing.allocator, ev);
    defer testing.allocator.free(transcript);
    sig_buf = try attacker.signCtx(sign_domain, transcript);
    ev.origin_sig = &sig_buf;
    try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
}

test "entity prop tampering with any field after signing fails (incl. kind)" {
    var kp = try propTestKeyPair(0xE6);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    const base = try signPropSample(&kp, .user, &pk_buf, &sig_buf);

    {
        var ev = base;
        ev.value = "tampered value the origin never authored";
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
    {
        var ev = base;
        ev.owner = "mallory";
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
    {
        var ev = base;
        ev.entity = "eve";
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
    {
        var ev = base;
        ev.key = "OTHERKEY";
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
    {
        // Reclassifying a user prop as a member prop must break the signature.
        var ev = base;
        ev.kind = .member;
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
    {
        var ev = base;
        ev.present = !base.present;
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
    {
        var ev = base;
        ev.hlc = base.hlc + 1;
        try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, ev));
    }
}

test "entity prop signature survives a re-encode/decode round-trip verbatim (multi-hop)" {
    var kp = try propTestKeyPair(0xF8);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    const origin_ev = try signPropSample(&kp, .member, &pk_buf, &sig_buf);

    var buf1: [900]u8 = undefined;
    const wire1 = try encode(origin_ev, &buf1);
    const hop1 = try decode(wire1);
    try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, hop1));

    var buf2: [900]u8 = undefined;
    const wire2 = try encode(hop1, &buf2);
    const hop2 = try decode(wire2);
    try testing.expectEqualSlices(u8, origin_ev.origin_pubkey, hop2.origin_pubkey);
    try testing.expectEqualSlices(u8, origin_ev.origin_sig, hop2.origin_sig);
    try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, hop2));
}

test "entity prop signature does NOT validate under the channel-prop domain" {
    // Domain separation: an ENTITY_PROP signature must be specific to its domain.
    var kp = try propTestKeyPair(0x4D);
    defer kp.deinit();
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    const ev = try signPropSample(&kp, .user, &pk_buf, &sig_buf);

    const transcript = try originTranscript(testing.allocator, ev);
    defer testing.allocator.free(transcript);
    const sig: sign.Signature = ev.origin_sig[0..sig_len].*;
    const pubkey: sign.PublicKey = ev.origin_pubkey[0..pubkey_len].*;
    // Verifying the SAME signature under a different domain must fail.
    const ok = try sign.verifyCtx("onyx-s2s-chanprop-v1", transcript, sig, pubkey);
    try testing.expect(!ok);
    // ...while it verifies under its own domain.
    const ok_own = try sign.verifyCtx(sign_domain, transcript, sig, pubkey);
    try testing.expect(ok_own);
}

test "entity prop encode rejects a half-present signature pair" {
    var pk = @as([pubkey_len]u8, @splat(0xAB));
    const ev = EntityPropEvent{
        .present = true,
        .kind = .user,
        .origin_node = 7,
        .hlc = 1,
        .entity = "u",
        .key = "K",
        .value = "V",
        .owner = "o",
        .origin_pubkey = pk[0..],
        .origin_sig = "",
    };
    try testing.expectError(error.BadSignatureWidth, encodedLen(ev));
}
