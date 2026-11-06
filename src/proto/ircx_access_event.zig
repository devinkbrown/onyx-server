// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ACCESS_ENTRY frame payload codec (S2S IRCX channel ACCESS convergence).
//!
//! Carries one last-writer-wins channel ACCESS fact between mesh peers: the
//! entry (channel, level, mask) is present with `set_by`/`duration` as of `hlc`,
//! or absent (a tombstone) when `present` is false. Decode borrows the input and
//! allocates nothing; every field is bounded to the IRCX ACCESS limits in
//! `ircx_access_store.zig`.
//!
//! Before this frame existed an ACCESS entry was node-local: an ACL added on
//! node A never gated a JOIN landing on node B, and a DELETE on A left B
//! enforcing a stale grant. ACCESS is an operator/founder-trust surface, so the
//! fact is authenticated end-to-end exactly like `channel_prop_event.zig`: the
//! AUTHOR signs a canonical transcript of the immutable fields ONCE and stamps a
//! self-contained `origin_pubkey`/`origin_sig` pair, which every relay forwards
//! VERBATIM and every hop verifies against the claimed `origin_node`
//! (self-certifying: `originShortId(pubkey) == origin_node`). Both are empty on
//! the unsigned path (a keyless single node), and the codec stays
//! forward-compatible: an absent signature decodes to empty.
//!
//! TOMBSTONES ARE LOAD-BEARING. A delete must travel as `present = false` with a
//! HIGHER `hlc` than the add it retracts, because the add is re-broadcast across
//! the mesh; dropping the delete instead of tombstoning it lets a relayed add
//! resurrect a revoked grant. `ircx_access_store.applyRemote` implements that
//! resolution; this module only frames the fact.
const std = @import("std");

const sign = @import("../crypto/sign.zig");
const access_store = @import("ircx_access_store.zig");

pub const max_channel_len = access_store.DEFAULT_MAX_CHANNEL_BYTES;
pub const max_mask_len = access_store.DEFAULT_MAX_MASK_BYTES;
pub const max_set_by_len = access_store.DEFAULT_MAX_SET_BY_BYTES;

pub const pubkey_len = sign.public_key_len; // 32
pub const sig_len = sign.signature_len; // 64

/// present(1) + level(1) + origin_node(8) + hlc(8) + duration(8)
const fixed_prefix = 1 + 1 + 8 + 8 + 8;

pub const Error = error{
    Truncated,
    FieldTooLong,
    TrailingBytes,
    BadSignatureWidth,
    UnknownLevel,
};

/// Wire ordinals for `ircx_access_store.Level`. Pinned explicitly (never
/// `@intFromEnum`) so reordering the store enum cannot silently re-map a remote
/// peer's DENY onto FOUNDER — the ordinals are a wire contract, the declaration
/// order is not.
pub const LevelTag = enum(u8) {
    voice = 1,
    host = 2,
    owner = 3,
    founder = 4,
    grant = 5,
    deny = 6,

    pub fn fromLevel(level: access_store.Level) LevelTag {
        return switch (level) {
            .voice => .voice,
            .host => .host,
            .owner => .owner,
            .founder => .founder,
            .grant => .grant,
            .deny => .deny,
        };
    }

    pub fn toLevel(self: LevelTag) access_store.Level {
        return switch (self) {
            .voice => .voice,
            .host => .host,
            .owner => .owner,
            .founder => .founder,
            .grant => .grant,
            .deny => .deny,
        };
    }

    fn fromByte(raw: u8) Error!LevelTag {
        return switch (raw) {
            1 => .voice,
            2 => .host,
            3 => .owner,
            4 => .founder,
            5 => .grant,
            6 => .deny,
            else => error.UnknownLevel,
        };
    }
};

comptime {
    // Every store level must have a wire ordinal. Adding a level without
    // extending `LevelTag` would otherwise compile and then drop that level's
    // entries silently on every mesh hop.
    const levels = [_]access_store.Level{ .voice, .host, .owner, .founder, .grant, .deny };
    if (levels.len != @typeInfo(access_store.Level).@"enum".field_names.len)
        @compileError("ircx_access_event: add the new ACCESS Level to LevelTag and this guard");
    if (levels.len != @typeInfo(LevelTag).@"enum".field_names.len)
        @compileError("ircx_access_event: LevelTag and ACCESS Level must stay 1:1");
}

pub const AccessEvent = struct {
    /// False makes this a TOMBSTONE: the (channel, level, mask) entry is absent
    /// as of `hlc`. Never encode a delete as "no frame" — see the module doc.
    present: bool,
    origin_node: u64,
    hlc: u64,
    channel: []const u8,
    level: access_store.Level,
    mask: []const u8,
    /// Setter display name, echoed in ACCESS LIST replies on every node.
    set_by: []const u8 = "",
    /// Timed lifetime in seconds relative to `hlc`'s wall-clock second; 0 is
    /// permanent. Every node stores the SAME absolute expiry
    /// `hlc / 1000 + duration` (`ircx_access_store.anchoredExpiry`), never
    /// one derived from its own arrival time, so a fact applied live,
    /// replayed by anti-entropy, or first seen by a cold-restarted node
    /// expires at one mesh-wide instant. The author folds any lead of its
    /// HLC over its wall clock out of this value, so it normally equals the
    /// requested timeout. A forward-skewed author can stretch its own facts
    /// by at most `AccessStore.max_future_hlc_skew_ms`; anything further
    /// ahead is refused as `error.FutureHlc`.
    duration: u64 = 0,
    /// SELF-CONTAINED multi-hop origin signature: the origin node's 32-byte
    /// Ed25519 public key, minted ONCE by the author and forwarded VERBATIM by
    /// every relay. Empty ("") on the unsigned path. When non-empty it is
    /// exactly `pubkey_len` bytes and self-certifies the origin.
    origin_pubkey: []const u8 = "",
    /// The 64-byte Ed25519 signature over the canonical origin transcript,
    /// bound to `sign_domain`. Empty when unsigned; always paired with
    /// `origin_pubkey`. A relay re-emits this byte-for-byte and never re-signs.
    origin_sig: []const u8 = "",
};

/// True when the event carries a well-formed self-contained origin signature
/// (both fields present at their exact Ed25519 widths). Empty pair => unsigned.
fn signaturePresent(ev: AccessEvent) Error!bool {
    const have_pk = ev.origin_pubkey.len != 0;
    const have_sig = ev.origin_sig.len != 0;
    if (have_pk != have_sig) return error.BadSignatureWidth;
    if (!have_pk) return false;
    if (ev.origin_pubkey.len != pubkey_len or ev.origin_sig.len != sig_len) return error.BadSignatureWidth;
    return true;
}

pub fn encodedLen(ev: AccessEvent) Error!usize {
    if (ev.channel.len > max_channel_len or
        ev.mask.len > max_mask_len or
        ev.set_by.len > max_set_by_len)
    {
        return error.FieldTooLong;
    }
    const base = fixed_prefix + 2 + ev.channel.len + 2 + ev.mask.len + 2 + ev.set_by.len;
    // Forward-compatible signature suffix: a 1-byte flag, plus the fixed-width
    // pubkey+sig only when present. An unsigned frame carries NO suffix at all.
    if (try signaturePresent(ev)) return base + 1 + pubkey_len + sig_len;
    return base;
}

/// Encode into `out`; returns the written slice. `out` must be >= encodedLen.
pub fn encode(ev: AccessEvent, out: []u8) Error![]const u8 {
    const need = try encodedLen(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @intFromBool(ev.present);
    i += 1;
    out[i] = @backingInt(LevelTag.fromLevel(ev.level));
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .little);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.duration, .little);
    i += 8;
    i = writeField(out, i, ev.channel);
    i = writeField(out, i, ev.mask);
    i = writeField(out, i, ev.set_by);
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
pub fn decode(bytes: []const u8) Error!AccessEvent {
    if (bytes.len < fixed_prefix) return error.Truncated;
    var i: usize = 0;
    const present = bytes[i] != 0;
    i += 1;
    const level = (try LevelTag.fromByte(bytes[i])).toLevel();
    i += 1;
    const origin_node = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const hlc = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;
    const duration = std.mem.readInt(u64, bytes[i..][0..8], .little);
    i += 8;

    const channel = try readField(bytes, &i, max_channel_len);
    const mask = try readField(bytes, &i, max_mask_len);
    const set_by = try readField(bytes, &i, max_set_by_len);

    // Forward-compatible signature suffix. No trailing bytes => unsigned frame
    // (empty pubkey/sig). A 1-byte flag of 0 likewise means unsigned; 1 means a
    // fixed-width pubkey+sig follows. Any other shape is malformed.
    var origin_pubkey: []const u8 = "";
    var origin_sig: []const u8 = "";
    if (i != bytes.len) {
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
        .origin_node = origin_node,
        .hlc = hlc,
        .channel = channel,
        .level = level,
        .mask = mask,
        .set_by = set_by,
        .duration = duration,
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

comptime {
    if (pubkey_len != access_store.origin_pubkey_len or sig_len != access_store.origin_sig_len)
        @compileError("ircx_access_event: store OriginProof widths must match Ed25519");
}

/// Project a decoded event onto the store's remote-apply record. Borrows the
/// event's slices, so the backing frame bytes must outlive the apply call. A
/// signed event also hands the store an opaque copy of its origin signature,
/// which the store retains only on rows that reproduce the signed fields
/// exactly (see `access_store.OriginProof`).
pub fn toRemoteFact(ev: AccessEvent) access_store.RemoteFact {
    const signed = ev.origin_pubkey.len == pubkey_len and ev.origin_sig.len == sig_len;
    return .{
        .present = ev.present,
        .channel = ev.channel,
        .level = ev.level,
        .mask = ev.mask,
        .set_by = ev.set_by,
        .duration = if (ev.duration == 0) null else ev.duration,
        .hlc = ev.hlc,
        .origin_node = ev.origin_node,
        .origin_proof = if (signed) .{
            .pubkey = ev.origin_pubkey[0..pubkey_len].*,
            .sig = ev.origin_sig[0..sig_len].*,
        } else null,
    };
}

/// Rebuild the signed event for one fact retained by the store
/// (`AccessStore.signedFacts`), so a node can re-flood a fact it did not
/// author, unchanged. The inverse of `toRemoteFact` for every field the
/// signature covers; the result encodes canonically, so a wire produced by
/// this daemon is rebuilt byte for byte. The caller must still put the
/// result through `verifyOrigin` (the link's forward path does) and must not
/// mutate the store while the returned slices are in use: they borrow it.
pub fn fromSignedFact(fact: *const access_store.SignedFact) AccessEvent {
    return .{
        .present = fact.present,
        .origin_node = fact.origin_node,
        .hlc = fact.hlc,
        .channel = fact.channel,
        .level = fact.level,
        .mask = fact.mask,
        .set_by = fact.set_by,
        .duration = fact.duration orelse 0,
        .origin_pubkey = &fact.proof.pubkey,
        .origin_sig = &fact.proof.sig,
    };
}

// ---------------------------------------------------------------------------
// Self-contained multi-hop origin signature
//
// ACCESS_ENTRY is a CRDT fact RE-BROADCAST with the original `origin_node`
// preserved, so the per-link `signed_frame` envelope (where the sending peer IS
// the origin) cannot authenticate it past the first hop. The AUTHOR signs a
// canonical transcript of its IMMUTABLE fields ONCE; every relay forwards the
// `(origin_pubkey, origin_sig)` pair byte-for-byte, and every hop verifies it
// against the CLAIMED origin. Because the node id is self-certifying
// (`node_id = BLAKE3-160(pubkey)`, `origin_node = shortId(node_id)`), a receiver
// needs NO key distribution.
//
// SIGNED FIELDS (all of them — an ACCESS fact has no hop-local field):
// origin_node, hlc, duration, present, level, channel, mask, set_by. Tampering
// with the level (a privilege escalation: HOST -> FOUNDER) or flipping a
// tombstone back to present therefore fails verification.
// ---------------------------------------------------------------------------

const node_identity = @import("../daemon/node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");

/// Domain label folded into the Ed25519 transcript (via `sign.signCtx`).
/// Distinct from every other Ed25519 use in Onyx Server, so an ACCESS origin
/// signature can never validate in another context (notably not as a
/// channel-prop or oper-grant signature).
pub const sign_domain = "onyx-s2s-ircxaccess-v1";

pub const SignError = sign.SignError || error{NoSpaceLeft};

/// The u64 mesh routing handle (origin short id) self-certified by `pubkey`.
/// A receiver requires this to equal the fact's claimed `origin_node` so a relay
/// cannot assert another node's origin.
pub fn originShortId(pubkey: sign.PublicKey) u64 {
    return node_short_id.shortId(node_identity.nodeIdFromPublicKey(pubkey));
}

fn appendLenPrefixed(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, field: []const u8) !void {
    var len_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_le, @intCast(field.len), .little);
    try out.appendSlice(allocator, &len_le);
    try out.appendSlice(allocator, field);
}

/// Build the canonical signed transcript of `ev`'s immutable origin-authored
/// fields into a freshly-allocated buffer the caller owns. Deterministic across
/// nodes: fixed field order, fixed-width integers (LE), and u32-LE length
/// framing on every string. Independent of the on-wire codec layout, so the
/// signature is stable regardless of how the frame is (re)encoded.
pub fn originTranscript(allocator: std.mem.Allocator, ev: AccessEvent) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    var u64_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64_le, ev.origin_node, .little);
    try out.appendSlice(allocator, &u64_le);
    std.mem.writeInt(u64, &u64_le, ev.hlc, .little);
    try out.appendSlice(allocator, &u64_le);
    std.mem.writeInt(u64, &u64_le, ev.duration, .little);
    try out.appendSlice(allocator, &u64_le);
    try out.append(allocator, @intFromBool(ev.present));
    try out.append(allocator, @backingInt(LevelTag.fromLevel(ev.level)));
    try appendLenPrefixed(&out, allocator, ev.channel);
    try appendLenPrefixed(&out, allocator, ev.mask);
    try appendLenPrefixed(&out, allocator, ev.set_by);

    return out.toOwnedSlice(allocator);
}

/// Sign `ev`'s canonical origin transcript with the author's Ed25519 keypair and
/// STAMP `origin_pubkey`/`origin_sig` in place. Call this ONCE, at the node that
/// AUTHORS the entry. The caller MUST guarantee the self-certifying invariant
/// `originShortId(kp.public_key) == ev.origin_node`; otherwise the stamped
/// signature fails every receiver's origin check. `pubkey_buf`/`sig_buf` back
/// the stamped slices and must outlive any encode that follows.
pub fn signInPlace(
    ev: *AccessEvent,
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
    /// No `(origin_pubkey, origin_sig)` present: unsigned path. An ACCESS fact
    /// is operator-trust state, so a receiver that requires signed frames MUST
    /// treat this as a refusal, not a fallback.
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
/// internally (freed before return). Decode enforces the field widths, but this
/// is defensive against a hand-built struct too.
pub fn verifyOrigin(allocator: std.mem.Allocator, ev: AccessEvent) !VerifyOutcome {
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

test "IRCX ACCESS event: grant fact round-trips" {
    const ev = AccessEvent{
        .present = true,
        .origin_node = 7,
        .hlc = 12345,
        .channel = "#chat",
        .level = .host,
        .mask = "alice!*@*",
        .set_by = "founder",
        .duration = 3600,
    };
    var buf: [512]u8 = undefined;
    const wire = try encode(ev, &buf);
    try testing.expectEqual(try encodedLen(ev), wire.len);

    const got = try decode(wire);
    try testing.expect(got.present);
    try testing.expectEqual(@as(u64, 7), got.origin_node);
    try testing.expectEqual(@as(u64, 12345), got.hlc);
    try testing.expectEqualStrings("#chat", got.channel);
    try testing.expectEqual(access_store.Level.host, got.level);
    try testing.expectEqualStrings("alice!*@*", got.mask);
    try testing.expectEqualStrings("founder", got.set_by);
    try testing.expectEqual(@as(u64, 3600), got.duration);
    try testing.expectEqual(@as(usize, 0), got.origin_pubkey.len);
}

test "IRCX ACCESS event: tombstone round-trips with its retracting hlc" {
    const ev = AccessEvent{
        .present = false,
        .origin_node = 9,
        .hlc = 99,
        .channel = "#chat",
        .level = .deny,
        .mask = "spam!*@*",
    };
    var buf: [512]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expect(!got.present);
    try testing.expectEqual(@as(u64, 99), got.hlc);
    try testing.expectEqual(access_store.Level.deny, got.level);
    try testing.expectEqualStrings("", got.set_by);
    try testing.expectEqual(@as(u64, 0), got.duration);
}

test "IRCX ACCESS event: every level survives the wire ordinal map" {
    for ([_]access_store.Level{ .voice, .host, .owner, .founder, .grant, .deny }) |level| {
        const ev = AccessEvent{
            .present = true,
            .origin_node = 1,
            .hlc = 2,
            .channel = "#c",
            .level = level,
            .mask = "m",
        };
        var buf: [256]u8 = undefined;
        const got = try decode(try encode(ev, &buf));
        try testing.expectEqual(level, got.level);
    }
}

test "IRCX ACCESS event: hostile frames fail closed" {
    const ev = AccessEvent{
        .present = true,
        .origin_node = 1,
        .hlc = 2,
        .channel = "#c",
        .level = .voice,
        .mask = "m",
    };
    var buf: [256]u8 = undefined;
    const wire = try encode(ev, &buf);

    // Truncated at every length short of the full frame.
    var cut: usize = 0;
    while (cut < wire.len) : (cut += 1) {
        try testing.expectError(error.Truncated, decode(wire[0..cut]));
    }

    // Trailing garbage after a complete unsigned frame is rejected, not ignored.
    var padded: [300]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0;
    padded[wire.len + 1] = 0xAA;
    try testing.expectError(error.TrailingBytes, decode(padded[0 .. wire.len + 2]));

    // An unknown level ordinal is refused rather than defaulted to a tier.
    @memcpy(padded[0..wire.len], wire);
    padded[1] = 0xFF;
    try testing.expectError(error.UnknownLevel, decode(padded[0..wire.len]));
    padded[1] = 0;
    try testing.expectError(error.UnknownLevel, decode(padded[0..wire.len]));

    // An oversize declared field length is refused before any copy.
    var over: [64]u8 = undefined;
    @memset(&over, 0);
    over[1] = @backingInt(LevelTag.voice);
    std.mem.writeInt(u16, over[fixed_prefix..][0..2], max_channel_len + 1, .little);
    try testing.expectError(error.FieldTooLong, decode(over[0 .. fixed_prefix + 2]));
}

test "IRCX ACCESS event: oversize fields are refused by the encoder" {
    var big: [max_mask_len + 8]u8 = undefined;
    @memset(&big, 'a');
    const ev = AccessEvent{
        .present = true,
        .origin_node = 1,
        .hlc = 1,
        .channel = "#c",
        .level = .voice,
        .mask = &big,
    };
    try testing.expectError(error.FieldTooLong, encodedLen(ev));
    var out: [1024]u8 = undefined;
    try testing.expectError(error.FieldTooLong, encode(ev, &out));
}

test "IRCX ACCESS event: half a signature pair is malformed" {
    var pk: [pubkey_len]u8 = undefined;
    @memset(&pk, 3);
    const ev = AccessEvent{
        .present = true,
        .origin_node = 1,
        .hlc = 1,
        .channel = "#c",
        .level = .voice,
        .mask = "m",
        .origin_pubkey = &pk,
    };
    try testing.expectError(error.BadSignatureWidth, encodedLen(ev));
}

test "IRCX ACCESS event: signed fact verifies and tampering is caught" {
    var seed: sign.Seed = undefined;
    @memset(&seed, 0x5A);
    const kp = try sign.KeyPair.fromSeed(seed);

    var ev = AccessEvent{
        .present = true,
        .origin_node = originShortId(kp.public_key),
        .hlc = 42,
        .channel = "#ops",
        .level = .founder,
        .mask = "boss!*@trusted",
        .set_by = "boss",
        .duration = 0,
    };
    const transcript = try originTranscript(testing.allocator, ev);
    defer testing.allocator.free(transcript);
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    try signInPlace(&ev, &kp, transcript, &pk_buf, &sig_buf);

    var buf: [512]u8 = undefined;
    const wire = try encode(ev, &buf);
    const got = try decode(wire);
    try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, got));

    // Escalating the level after signing must not verify.
    var escalated = got;
    escalated.level = .deny;
    try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, escalated));

    // Un-tombstoning a revocation after signing must not verify.
    var revived = got;
    revived.present = false;
    try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, revived));

    // A relay claiming someone else's origin id is rejected on the origin check.
    var stolen = got;
    stolen.origin_node = got.origin_node ^ 1;
    try testing.expectEqual(VerifyOutcome.origin_mismatch, try verifyOrigin(testing.allocator, stolen));

    // An unsigned fact reports `.unsigned` so a signing-required node refuses it.
    var bare = got;
    bare.origin_pubkey = "";
    bare.origin_sig = "";
    try testing.expectEqual(VerifyOutcome.unsigned, try verifyOrigin(testing.allocator, bare));
}

test "IRCX ACCESS event: signature domain is not interchangeable with channel prop" {
    const channel_prop_event = @import("channel_prop_event.zig");
    try testing.expect(!std.mem.eql(u8, sign_domain, channel_prop_event.sign_domain));
}

test "IRCX ACCESS event: projects onto a store remote fact" {
    const ev = AccessEvent{
        .present = true,
        .origin_node = 5,
        .hlc = 77,
        .channel = "#c",
        .level = .voice,
        .mask = "v!*@*",
        .set_by = "op",
        .duration = 0,
    };
    const fact = toRemoteFact(ev);
    try testing.expectEqual(@as(?u64, null), fact.duration);
    try testing.expectEqual(@as(u64, 77), fact.hlc);
    try testing.expectEqualStrings("#c", fact.channel);
}

test "IRCX ACCESS event: signed timed fact expires at one instant on every receiver" {
    var seed: sign.Seed = undefined;
    @memset(&seed, 0x6B);
    const kp = try sign.KeyPair.fromSeed(seed);
    const t: u64 = 1_700_000_000;

    var ev = AccessEvent{
        .present = true,
        .origin_node = originShortId(kp.public_key),
        .hlc = t * 1000,
        .channel = "#ops",
        .level = .deny,
        .mask = "*!*@timed.test",
        .set_by = "boss",
        .duration = 600,
    };
    const transcript = try originTranscript(testing.allocator, ev);
    defer testing.allocator.free(transcript);
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    try signInPlace(&ev, &kp, transcript, &pk_buf, &sig_buf);
    var buf: [512]u8 = undefined;
    const got = try decode(try encode(ev, &buf));
    try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, got));

    // Stretching the lifetime after signing (a relay keeping a DENY or a
    // grant alive longer) is caught by the origin signature.
    var stretched = got;
    stretched.duration = 6000;
    try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, stretched));
    var restamped = got;
    restamped.hlc += 3_600_000;
    try testing.expectEqual(VerifyOutcome.bad_signature, try verifyOrigin(testing.allocator, restamped));

    // A live receiver and a cold-restarted receiver replaying the same wire
    // later store the identical absolute expiry; past it the replay is a
    // tombstone, not a fresh lifetime.
    for ([_]u64{ t + 1, t + 599 }) |receiver_now| {
        var store = access_store.AccessStore.init(testing.allocator);
        defer store.deinit();
        store.now_seconds = receiver_now;
        try testing.expectEqual(access_store.ApplyOutcome.applied, try store.applyRemote(toRemoteFact(got)));
        const entry = (try store.matchHostmask("#ops", "x!u@timed.test")).?;
        try testing.expectEqual(t + 600, entry.expires_at.?);
    }
    var late = access_store.AccessStore.init(testing.allocator);
    defer late.deinit();
    late.now_seconds = t + 600;
    try testing.expectEqual(access_store.ApplyOutcome.deleted, try late.applyRemote(toRemoteFact(got)));
    try testing.expectEqual(@as(?access_store.EntryView, null), try late.matchHostmask("#ops", "x!u@timed.test"));
}

fn testSignWire(kp: *const sign.KeyPair, ev_in: AccessEvent, out: []u8) ![]const u8 {
    var ev = ev_in;
    const transcript = try originTranscript(testing.allocator, ev);
    defer testing.allocator.free(transcript);
    var pk_buf: [pubkey_len]u8 = undefined;
    var sig_buf: [sig_len]u8 = undefined;
    try signInPlace(&ev, kp, transcript, &pk_buf, &sig_buf);
    return encode(ev, out);
}

test "IRCX ACCESS event: cold-restarted author re-learns its timed DENY from a peer re-flood" {
    var seed: sign.Seed = undefined;
    @memset(&seed, 0xA1);
    const kp = try sign.KeyPair.fromSeed(seed);
    const node_a = originShortId(kp.public_key);
    const t: u64 = 1_700_000_000;

    // Node A authors a one-hour DENY and a delete; both travel signed.
    var author = access_store.AccessStore.init(testing.allocator);
    defer author.deinit();
    author.now_seconds = t;
    author.local_node = node_a;
    try author.add("#c", .deny, "*!*@bad.test", "boss", 3600);
    const own = (try author.matchHostmask("#c", "x!u@bad.test")).?;
    var add_buf: [512]u8 = undefined;
    const add_wire = try testSignWire(&kp, .{
        .present = true,
        .origin_node = node_a,
        .hlc = own.hlc,
        .channel = own.channel,
        .level = own.level,
        .mask = own.mask,
        .set_by = own.set_by,
        .duration = own.duration.?,
    }, &add_buf);
    var del_buf: [512]u8 = undefined;
    const del_wire = try testSignWire(&kp, .{
        .present = false,
        .origin_node = node_a,
        .hlc = own.hlc + 1,
        .channel = "#c",
        .level = .voice,
        .mask = "*!*@gone.test",
    }, &del_buf);

    var peer = access_store.AccessStore.init(testing.allocator);
    defer peer.deinit();
    peer.now_seconds = t + 10;
    peer.local_node = 77;
    try testing.expectEqual(access_store.ApplyOutcome.applied, try peer.applyRemote(toRemoteFact(try decode(add_wire))));
    try testing.expectEqual(access_store.ApplyOutcome.deleted, try peer.applyRemote(toRemoteFact(try decode(del_wire))));

    // A cold-restarts: empty store. The peer re-floods every retained signed
    // fact, byte-identical to what A originally signed.
    var restarted = access_store.AccessStore.init(testing.allocator);
    defer restarted.deinit();
    restarted.now_seconds = t + 20;
    restarted.local_node = node_a;
    var it = peer.signedFacts(t + 20);
    var reflooded: usize = 0;
    while (it.next()) |fact| {
        const ev = fromSignedFact(&fact);
        try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, ev));
        var buf: [512]u8 = undefined;
        const wire = try encode(ev, &buf);
        try testing.expectEqualSlices(u8, if (fact.present) add_wire else del_wire, wire);
        _ = try restarted.applyRemote(toRemoteFact(try decode(wire)));
        reflooded += 1;
    }
    try testing.expectEqual(@as(usize, 2), reflooded);

    const relearned = (try restarted.matchHostmask("#c", "x!u@bad.test")).?;
    const at_peer = (try peer.matchHostmask("#c", "x!u@bad.test")).?;
    try testing.expectEqual(access_store.Level.deny, relearned.level);
    try testing.expectEqual(t + 3600, relearned.expires_at.?);
    try testing.expectEqual(at_peer.expires_at, relearned.expires_at);
    try testing.expectEqual(own.hlc, relearned.hlc);
    try testing.expectEqual(@as(usize, 1), restarted.tombstoneCount());
    // The author's clock folded its own stamp back in, so its next write
    // still outranks the re-learned fact.
    try testing.expect(restarted.hlc >= own.hlc + 1);

    restarted.now_seconds = t + 3600;
    peer.now_seconds = t + 3600;
    try testing.expectEqual(@as(?access_store.EntryView, null), try restarted.matchHostmask("#c", "x!u@bad.test"));
    try testing.expectEqual(@as(?access_store.EntryView, null), try peer.matchHostmask("#c", "x!u@bad.test"));
    // Past expiry only the delete remains offered for re-flood.
    var late = peer.signedFacts(t + 3600);
    try testing.expect(!late.next().?.present);
    try testing.expectEqual(@as(?access_store.SignedFact, null), late.next());
}

test "IRCX ACCESS event: re-flood after a differently cased signed overwrite still verifies" {
    var seed: sign.Seed = undefined;
    @memset(&seed, 0xB2);
    const kp = try sign.KeyPair.fromSeed(seed);
    const node = originShortId(kp.public_key);
    const t: u64 = 1_700_000_000;

    var first_buf: [512]u8 = undefined;
    const first = try testSignWire(&kp, .{
        .present = true,
        .origin_node = node,
        .hlc = t * 1000,
        .channel = "#Chan",
        .level = .host,
        .mask = "*!*@X.test",
        .set_by = "a",
        .duration = 600,
    }, &first_buf);
    var second_buf: [512]u8 = undefined;
    const second = try testSignWire(&kp, .{
        .present = true,
        .origin_node = node,
        .hlc = t * 1000 + 1,
        .channel = "#chan",
        .level = .host,
        .mask = "*!*@x.test",
        .set_by = "b",
    }, &second_buf);

    var store = access_store.AccessStore.init(testing.allocator);
    defer store.deinit();
    store.now_seconds = t + 1;
    _ = try store.applyRemote(toRemoteFact(try decode(first)));
    _ = try store.applyRemote(toRemoteFact(try decode(second)));
    var it = store.signedFacts(t + 1);
    const fact = it.next().?;
    const ev = fromSignedFact(&fact);
    try testing.expectEqual(VerifyOutcome.verified, try verifyOrigin(testing.allocator, ev));
    var buf: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, second, try encode(ev, &buf));
    try testing.expectEqual(@as(?access_store.SignedFact, null), it.next());

    // An unsigned fact never yields a re-floodable proof.
    var unsigned_store = access_store.AccessStore.init(testing.allocator);
    defer unsigned_store.deinit();
    var plain = try decode(second);
    plain.origin_pubkey = "";
    plain.origin_sig = "";
    _ = try unsigned_store.applyRemote(toRemoteFact(plain));
    var none = unsigned_store.signedFacts(t + 1);
    try testing.expectEqual(@as(?access_store.SignedFact, null), none.next());
}
