// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OPER_EVENT payload codecs for mesh-wide Event Spine propagation.
//!
//! `signed_v2` is the correctness boundary for multi-hop flooding. The origin
//! authors one immutable event, stamps one mesh HLC, and signs every displayed
//! field. Relays forward the exact bytes and every receiver derives the same
//! `(origin_node, hlc)`, wall-clock time, and event id. The self-contained
//! Ed25519 signature remains attributable after the immediate peer changes.
//!
//! `legacy_v1` is the deployed direct-peer layout. It has no event identity or
//! end-to-end origin proof and therefore MUST only be decoded on a link that
//! explicitly negotiated v1 compatibility; it is not safe to re-flood.
const std = @import("std");

const sign = @import("../crypto/sign.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");

pub const max_origin_len: usize = 128;
/// Subject used by per-category Event Spine glob filters. This matches the
/// daemon's exact cross-shard subject width so no node or reactor truncates a
/// signed filtering decision differently.
pub const max_subject_len: usize = 256;
/// Same width as `event_history.max_message_len`. The signed handshake is
/// longer than the old 400-byte oper line, and the wire must carry it whole.
pub const max_message_len: usize = 1024;
pub const max_severity: u8 = 5;
pub const pubkey_len: usize = sign.public_key_len;
pub const sig_len: usize = sign.signature_len;
pub const event_id_len: usize = 16;

pub const EventId = [event_id_len]u8;

pub const Error = error{
    Truncated,
    NameTooLong,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    ReservedBits,
    InvalidCategory,
    InvalidSeverity,
    InvalidIdentity,
    BadSignatureWidth,
};

// ---------------------------------------------------------------------------
// Legacy v1 compatibility codec
// ---------------------------------------------------------------------------

const legacy_fixed_prefix: usize = 1 + 1; // category, severity

/// Deployed direct-peer payload. This type is intentionally named legacy: it
/// has no stable identity and must never be used as a multi-hop flood object.
pub const LegacyOperEvent = struct {
    category: u6,
    severity: u8,
    origin_server: []const u8,
    message: []const u8,
};

pub const max_legacy_encoded_len: usize = legacy_fixed_prefix + 2 + max_origin_len + 2 + max_message_len;

pub fn encodedLenLegacyV1(ev: LegacyOperEvent) Error!usize {
    try validateRenderedFields(ev.origin_server, ev.message, false);
    return legacy_fixed_prefix + 2 + ev.origin_server.len + 2 + ev.message.len;
}

pub fn encodeLegacyV1(ev: LegacyOperEvent, out: []u8) Error![]const u8 {
    const need = try encodedLenLegacyV1(ev);
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    out[i] = @as(u8, ev.category);
    i += 1;
    out[i] = ev.severity;
    i += 1;
    putBytes16Little(out, &i, ev.origin_server);
    putBytes16Little(out, &i, ev.message);
    return out[0..i];
}

/// Decode ONLY after the S2S link negotiated legacy OPER_EVENT v1. Returned
/// fields borrow `bytes`. A v1 event is local-delivery-only and is never
/// re-forwarded because it cannot be authenticated beyond its immediate hop.
pub fn decodeLegacyV1(bytes: []const u8) Error!LegacyOperEvent {
    if (bytes.len < legacy_fixed_prefix + 2) return error.Truncated;
    var i: usize = 0;
    const category_raw = bytes[i];
    i += 1;
    if (category_raw > 0x3f) return error.InvalidCategory;
    const severity = bytes[i];
    i += 1;
    const origin = try takeBytes16Little(bytes, &i, max_origin_len);
    const message = try takeBytes16Little(bytes, &i, max_message_len);
    if (i != bytes.len) return error.TrailingBytes;
    try validateRenderedFields(origin, message, false);
    return .{
        .category = @intCast(category_raw),
        .severity = severity,
        .origin_server = origin,
        .message = message,
    };
}

// Transitional source compatibility for the existing v1-only S2S sender and
// daemon drain. New wiring must use the explicit versioned APIs below.
pub const OperEvent = LegacyOperEvent;
pub const max_encoded_len = max_legacy_encoded_len;
pub const encodedLen = encodedLenLegacyV1;
pub const encode = encodeLegacyV1;
pub const decode = decodeLegacyV1;

// ---------------------------------------------------------------------------
// Signed, canonical v2 codec
// ---------------------------------------------------------------------------

pub const WireVersion = enum(u8) {
    legacy_v1 = 1,
    signed_v2 = 2,
};

pub const SignedOperEventV2 = struct {
    category: u6,
    severity: u8,
    /// Stable self-certified mesh routing handle of the author.
    origin_node: u64,
    /// MeshClock stamp. Its high bits derive the same Unix-ms time everywhere.
    hlc: u64,
    origin_server: []const u8,
    /// Immutable filtering subject. It is deliberately distinct from the
    /// rendered message (for example a channel or `nick!user@host`).
    subject: []const u8,
    message: []const u8,
    /// Original author's Ed25519 public key, forwarded byte-for-byte.
    origin_pubkey: []const u8 = "",
    /// Signature over the canonical immutable transcript, forwarded verbatim.
    origin_sig: []const u8 = "",

    pub fn originTimeMs(self: SignedOperEventV2) u64 {
        return mesh_clock.MeshClock.physicalOf(self.hlc);
    }
};

pub const DecodedEvent = union(WireVersion) {
    legacy_v1: LegacyOperEvent,
    signed_v2: SignedOperEventV2,
};

const v2_magic = "OEVT";
const v2_version: u8 = @intFromEnum(WireVersion.signed_v2);
const v2_flags_none: u8 = 0;
const v2_header_len: usize = v2_magic.len + 1 + 1 + 1 + 1 + 8 + 8 + 2 + 2 + 2 + pubkey_len + sig_len;
pub const max_v2_encoded_len: usize = v2_header_len + max_origin_len + max_subject_len + max_message_len;
const max_v2_transcript_len: usize = v2_magic.len + 1 + 1 + 1 + 8 + 8 + 2 + max_origin_len + 2 + max_subject_len + 2 + max_message_len;
const sign_domain = "onyx-s2s-oper-event-v2";
const event_id_domain = "onyx-s2s-oper-event-id-v2";

pub fn encodedLenV2(ev: SignedOperEventV2) Error!usize {
    try validateV2(ev, true);
    return v2_header_len + ev.origin_server.len + ev.subject.len + ev.message.len;
}

/// Canonical fixed-layout v2 wire image (big-endian integers):
///
/// `"OEVT" | version=2 | flags=0 | category | severity | origin_node:u64 |
///  hlc:u64 | origin_len:u16 | subject_len:u16 | message_len:u16 | pubkey:32 |
///  signature:64 | origin | subject | message`
///
/// Fixed field positions make duplicate keys unrepresentable. Exact total-length
/// checking rejects concatenated/duplicated documents and all trailing bytes.
pub fn encodeV2(ev: SignedOperEventV2, out: []u8) Error![]const u8 {
    const need = try encodedLenV2(ev);
    if (out.len < need) return error.Truncated;
    @memcpy(out[0..v2_magic.len], v2_magic);
    out[4] = v2_version;
    out[5] = v2_flags_none;
    out[6] = @as(u8, ev.category);
    out[7] = ev.severity;
    std.mem.writeInt(u64, out[8..16], ev.origin_node, .big);
    std.mem.writeInt(u64, out[16..24], ev.hlc, .big);
    std.mem.writeInt(u16, out[24..26], @intCast(ev.origin_server.len), .big);
    std.mem.writeInt(u16, out[26..28], @intCast(ev.subject.len), .big);
    std.mem.writeInt(u16, out[28..30], @intCast(ev.message.len), .big);
    @memcpy(out[30 .. 30 + pubkey_len], ev.origin_pubkey);
    @memcpy(out[30 + pubkey_len .. v2_header_len], ev.origin_sig);
    var i: usize = v2_header_len;
    @memcpy(out[i..][0..ev.origin_server.len], ev.origin_server);
    i += ev.origin_server.len;
    @memcpy(out[i..][0..ev.subject.len], ev.subject);
    i += ev.subject.len;
    @memcpy(out[i..][0..ev.message.len], ev.message);
    i += ev.message.len;
    std.debug.assert(i == need);
    return out[0..i];
}

/// Strict current decoder. Returned slices borrow `bytes`.
pub fn decodeV2(bytes: []const u8) Error!SignedOperEventV2 {
    if (bytes.len < v2_magic.len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..v2_magic.len], v2_magic)) return error.BadMagic;
    if (bytes.len < v2_header_len) return error.Truncated;
    if (bytes[4] != v2_version) return error.UnsupportedVersion;
    if (bytes[5] != v2_flags_none) return error.ReservedBits;
    if (bytes[6] > 0x3f) return error.InvalidCategory;

    const origin_node = std.mem.readInt(u64, bytes[8..16], .big);
    const hlc = std.mem.readInt(u64, bytes[16..24], .big);
    const origin_len: usize = std.mem.readInt(u16, bytes[24..26], .big);
    const subject_len: usize = std.mem.readInt(u16, bytes[26..28], .big);
    const message_len: usize = std.mem.readInt(u16, bytes[28..30], .big);
    if (origin_len > max_origin_len or subject_len > max_subject_len or
        message_len > max_message_len) return error.NameTooLong;
    const expected_len = v2_header_len + origin_len + subject_len + message_len;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;

    const origin_start = v2_header_len;
    const subject_start = origin_start + origin_len;
    const message_start = subject_start + subject_len;
    const ev = SignedOperEventV2{
        .category = @intCast(bytes[6]),
        .severity = bytes[7],
        .origin_node = origin_node,
        .hlc = hlc,
        .origin_pubkey = bytes[30 .. 30 + pubkey_len],
        .origin_sig = bytes[30 + pubkey_len .. v2_header_len],
        .origin_server = bytes[origin_start..subject_start],
        .subject = bytes[subject_start..message_start],
        .message = bytes[message_start..expected_len],
    };
    try validateV2(ev, true);
    return ev;
}

/// Decode according to the version negotiated by the link. This deliberately
/// does not silently downgrade a malformed v2 frame into the legacy parser.
pub fn decodeNegotiated(version: WireVersion, bytes: []const u8) Error!DecodedEvent {
    return switch (version) {
        .legacy_v1 => .{ .legacy_v1 = try decodeLegacyV1(bytes) },
        .signed_v2 => .{ .signed_v2 = try decodeV2(bytes) },
    };
}

/// Inspect only the unambiguous wire discriminator. Callers still pass the
/// result through negotiated-capability policy before accepting a frame.
pub fn detectWireVersion(bytes: []const u8) Error!WireVersion {
    if (bytes.len >= v2_magic.len and std.mem.eql(u8, bytes[0..v2_magic.len], v2_magic)) {
        if (bytes.len < v2_magic.len + 1) return error.Truncated;
        if (bytes[4] != v2_version) return error.UnsupportedVersion;
        return .signed_v2;
    }
    return .legacy_v1;
}

fn validateV2(ev: SignedOperEventV2, require_signature: bool) Error!void {
    if (ev.origin_node == 0 or ev.hlc == 0) return error.InvalidIdentity;
    if (ev.severity > max_severity) return error.InvalidSeverity;
    try validateRenderedFields(ev.origin_server, ev.message, true);
    if (ev.subject.len > max_subject_len) return error.NameTooLong;
    for (ev.subject) |byte| if (byte < 0x20 or byte == 0x7f) return error.NameTooLong;
    const have_pk = ev.origin_pubkey.len != 0;
    const have_sig = ev.origin_sig.len != 0;
    if (have_pk != have_sig) return error.BadSignatureWidth;
    if (require_signature and !have_pk) return error.BadSignatureWidth;
    if (have_pk and (ev.origin_pubkey.len != pubkey_len or ev.origin_sig.len != sig_len))
        return error.BadSignatureWidth;
}

fn validateRenderedFields(origin: []const u8, message: []const u8, require_message: bool) Error!void {
    if (origin.len == 0 or origin.len > max_origin_len) return error.NameTooLong;
    if ((require_message and message.len == 0) or message.len > max_message_len) return error.NameTooLong;
    for (origin) |byte| if (byte <= 0x20 or byte == 0x7f) return error.NameTooLong;
    for (message) |byte| if (byte < 0x20 or byte == 0x7f) return error.NameTooLong;
}

fn putBytes16Little(out: []u8, i: *usize, bytes: []const u8) void {
    std.mem.writeInt(u16, out[i.*..][0..2], @intCast(bytes.len), .little);
    i.* += 2;
    @memcpy(out[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

fn takeBytes16Little(bytes: []const u8, i: *usize, max_len: usize) Error![]const u8 {
    if (bytes.len < i.* + 2) return error.Truncated;
    const len: usize = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    if (len > max_len) return error.NameTooLong;
    if (bytes.len < i.* + len) return error.Truncated;
    const out = bytes[i.* .. i.* + len];
    i.* += len;
    return out;
}

// ---------------------------------------------------------------------------
// End-to-end origin authentication and stable event identity
// ---------------------------------------------------------------------------

pub const StampError = Error || sign.SignError || error{OriginMismatch};

pub const VerifyOutcome = enum {
    verified,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

pub const VerifiedEvent = struct {
    origin_pubkey: [pubkey_len]u8,
    event_id: EventId,
};

pub const VerifyAndIdOutcome = union(enum) {
    verified: VerifiedEvent,
    origin_mismatch,
    bad_signature,
    invalid_semantic,
};

pub fn originShortId(pubkey: sign.PublicKey) u64 {
    var full: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    std.crypto.hash.Blake3.hash(&pubkey, &full, .{});
    return node_short_id.shortId(full[0..20].*);
}

fn transcriptInto(ev: SignedOperEventV2, out: []u8) Error![]const u8 {
    try validateV2(ev, false);
    const need = v2_magic.len + 1 + 1 + 1 + 8 + 8 +
        2 + ev.origin_server.len + 2 + ev.subject.len + 2 + ev.message.len;
    if (out.len < need) return error.Truncated;
    var i: usize = 0;
    @memcpy(out[i..][0..v2_magic.len], v2_magic);
    i += v2_magic.len;
    out[i] = v2_version;
    i += 1;
    out[i] = @as(u8, ev.category);
    i += 1;
    out[i] = ev.severity;
    i += 1;
    std.mem.writeInt(u64, out[i..][0..8], ev.origin_node, .big);
    i += 8;
    std.mem.writeInt(u64, out[i..][0..8], ev.hlc, .big);
    i += 8;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.origin_server.len), .big);
    i += 2;
    @memcpy(out[i..][0..ev.origin_server.len], ev.origin_server);
    i += ev.origin_server.len;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.subject.len), .big);
    i += 2;
    @memcpy(out[i..][0..ev.subject.len], ev.subject);
    i += ev.subject.len;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(ev.message.len), .big);
    i += 2;
    @memcpy(out[i..][0..ev.message.len], ev.message);
    i += ev.message.len;
    std.debug.assert(i == need);
    return out[0..i];
}

/// Stamp once at the author. Relays must never re-sign or rewrite this object.
pub fn stampOrigin(
    ev: *SignedOperEventV2,
    kp: *const sign.KeyPair,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) StampError!void {
    if (originShortId(kp.public_key) != ev.origin_node) return error.OriginMismatch;
    var transcript_buf: [max_v2_transcript_len]u8 = undefined;
    const transcript = try transcriptInto(ev.*, &transcript_buf);
    pubkey_buf.* = kp.public_key;
    sig_buf.* = try kp.signCtx(sign_domain, transcript);
    ev.origin_pubkey = pubkey_buf;
    ev.origin_sig = sig_buf;
}

pub fn verifyOrigin(ev: SignedOperEventV2) VerifyOutcome {
    validateV2(ev, true) catch return .invalid_semantic;
    const pubkey: sign.PublicKey = ev.origin_pubkey[0..pubkey_len].*;
    if (originShortId(pubkey) != ev.origin_node) return .origin_mismatch;
    const signature: sign.Signature = ev.origin_sig[0..sig_len].*;
    var transcript_buf: [max_v2_transcript_len]u8 = undefined;
    const transcript = transcriptInto(ev, &transcript_buf) catch return .invalid_semantic;
    const ok = sign.verifyCtx(sign_domain, transcript, signature, pubkey) catch return .bad_signature;
    return if (ok) .verified else .bad_signature;
}

/// Deterministic event id used by the durable replay guard and exposed as the
/// Event Spine msgid seed. It binds the complete signed event, not mutable hop
/// metadata.
pub fn eventId(ev: SignedOperEventV2) Error!EventId {
    try validateV2(ev, true);
    var transcript_buf: [max_v2_transcript_len]u8 = undefined;
    const transcript = try transcriptInto(ev, &transcript_buf);
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(event_id_domain);
    h.update(ev.origin_pubkey);
    h.update(ev.origin_sig);
    h.update(transcript);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    h.final(&digest);
    return digest[0..event_id_len].*;
}

/// Verify before deriving a replay key so a forged frame cannot poison the
/// valid author's `(pubkey, hlc)` namespace.
pub fn verifyAndEventId(ev: SignedOperEventV2) VerifyAndIdOutcome {
    return switch (verifyOrigin(ev)) {
        .verified => .{ .verified = .{
            .origin_pubkey = ev.origin_pubkey[0..pubkey_len].*,
            .event_id = eventId(ev) catch return .invalid_semantic,
        } },
        .origin_mismatch => .origin_mismatch,
        .bad_signature => .bad_signature,
        .invalid_semantic => .invalid_semantic,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testKeyPair(byte: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(byte)));
}

fn signedSample(
    kp: *const sign.KeyPair,
    pubkey_buf: *[pubkey_len]u8,
    sig_buf: *[sig_len]u8,
) !SignedOperEventV2 {
    var ev = SignedOperEventV2{
        .category = 13,
        .severity = 2,
        .origin_node = originShortId(kp.public_key),
        .hlc = (1_700_000_000_123 << mesh_clock.seq_bits) | 17,
        .origin_server = "eshmaki.me",
        .subject = "#root",
        .message = "FLOOD possible raid on #root: join rate exceeded",
    };
    try stampOrigin(&ev, kp, pubkey_buf, sig_buf);
    return ev;
}

test "oper event legacy v1 round-trips only through explicit compatibility codec" {
    const ev = LegacyOperEvent{
        .category = 13,
        .severity = 2,
        .origin_server = "eshmaki.me",
        .message = "FLOOD possible raid on #root: join rate exceeded",
    };
    var buf: [max_legacy_encoded_len]u8 = undefined;
    const wire = try encodeLegacyV1(ev, &buf);
    const got = try decodeLegacyV1(wire);
    try testing.expectEqual(@as(u6, 13), got.category);
    try testing.expectEqualStrings(ev.origin_server, got.origin_server);
    try testing.expectEqual(WireVersion.legacy_v1, try detectWireVersion(wire));
    try testing.expectError(error.BadMagic, decodeNegotiated(.signed_v2, wire));
}

test "oper event legacy v1 rejects every truncation trailing bytes and controls" {
    const ev = LegacyOperEvent{ .category = 1, .severity = 0, .origin_server = "ircx.us", .message = "OPER_ACTION WARD ADD" };
    var buf: [max_legacy_encoded_len]u8 = undefined;
    const wire = try encodeLegacyV1(ev, &buf);
    for (0..wire.len) |cut| try testing.expectError(error.Truncated, decodeLegacyV1(wire[0..cut]));
    var padded: [max_legacy_encoded_len + 1]u8 = undefined;
    @memcpy(padded[0..wire.len], wire);
    padded[wire.len] = 0xaa;
    try testing.expectError(error.TrailingBytes, decodeLegacyV1(padded[0 .. wire.len + 1]));
    try testing.expectError(error.NameTooLong, encodedLenLegacyV1(.{
        .category = 0,
        .severity = 0,
        .origin_server = "n",
        .message = "a\nb",
    }));
}

test "oper event signed v2 is canonical deterministic and derives one origin time" {
    var kp = try testKeyPair(0xa1);
    defer kp.deinit();
    var pk: [pubkey_len]u8 = undefined;
    var sig: [sig_len]u8 = undefined;
    const ev = try signedSample(&kp, &pk, &sig);
    var pk_again: [pubkey_len]u8 = undefined;
    var sig_again: [sig_len]u8 = undefined;
    const ev_again = try signedSample(&kp, &pk_again, &sig_again);
    var a: [max_v2_encoded_len]u8 = undefined;
    var b: [max_v2_encoded_len]u8 = undefined;
    const wire_a = try encodeV2(ev, &a);
    const wire_b = try encodeV2(ev_again, &b);
    try testing.expectEqualSlices(u8, wire_a, wire_b);
    try testing.expectEqualSlices(u8, &sig, &sig_again);
    try testing.expectEqual(WireVersion.signed_v2, try detectWireVersion(wire_a));
    const got = try decodeV2(wire_a);
    try testing.expectEqual(ev.origin_node, got.origin_node);
    try testing.expectEqual(ev.hlc, got.hlc);
    try testing.expectEqual(@as(u64, 1_700_000_000_123), got.originTimeMs());
    try testing.expectEqualStrings(ev.origin_server, got.origin_server);
    try testing.expectEqualStrings(ev.subject, got.subject);
    try testing.expectEqualStrings(ev.message, got.message);
    try testing.expectEqual(VerifyOutcome.verified, verifyOrigin(got));
    const source_id = try eventId(ev);
    const decoded_id = try eventId(got);
    try testing.expectEqualSlices(u8, &source_id, &decoded_id);
}

test "oper event origin short id exactly matches daemon NodeIdentity" {
    const daemon_node_identity = @import("../daemon/node_identity.zig");
    var identity = try daemon_node_identity.fromSeed(@as([sign.seed_len]u8, @splat(0xb1)), "oper-event-test");
    defer identity.deinit();
    try testing.expectEqual(identity.shortId(), originShortId(identity.sign_kp.public_key));
}

test "oper event signed v2 rejects every truncated prefix" {
    var kp = try testKeyPair(0xa2);
    defer kp.deinit();
    var pk: [pubkey_len]u8 = undefined;
    var sig: [sig_len]u8 = undefined;
    const ev = try signedSample(&kp, &pk, &sig);
    var buf: [max_v2_encoded_len]u8 = undefined;
    const wire = try encodeV2(ev, &buf);
    for (0..wire.len) |cut| try testing.expectError(error.Truncated, decodeV2(wire[0..cut]));
}

test "oper event signed v2 rejects reserved version trailing and duplicate documents" {
    var kp = try testKeyPair(0xa3);
    defer kp.deinit();
    var pk: [pubkey_len]u8 = undefined;
    var sig: [sig_len]u8 = undefined;
    const ev = try signedSample(&kp, &pk, &sig);
    var buf: [max_v2_encoded_len]u8 = undefined;
    const wire = try encodeV2(ev, &buf);

    var mutated: [max_v2_encoded_len]u8 = undefined;
    @memcpy(mutated[0..wire.len], wire);
    mutated[5] = 1;
    try testing.expectError(error.ReservedBits, decodeV2(mutated[0..wire.len]));
    mutated[5] = 0;
    mutated[4] = 3;
    try testing.expectError(error.UnsupportedVersion, decodeV2(mutated[0..wire.len]));
    mutated[4] = v2_version;
    mutated[0] ^= 1;
    try testing.expectError(error.BadMagic, decodeV2(mutated[0..wire.len]));

    var duplicate: [max_v2_encoded_len * 2]u8 = undefined;
    @memcpy(duplicate[0..wire.len], wire);
    @memcpy(duplicate[wire.len..][0..wire.len], wire);
    try testing.expectError(error.TrailingBytes, decodeV2(duplicate[0 .. wire.len * 2]));
}

test "oper event signed v2 mutation invalidates the origin signature" {
    var kp = try testKeyPair(0xa4);
    defer kp.deinit();
    var pk: [pubkey_len]u8 = undefined;
    var sig: [sig_len]u8 = undefined;
    const base = try signedSample(&kp, &pk, &sig);
    inline for (.{ "message", "subject", "origin", "hlc", "category", "severity" }) |field| {
        var changed = base;
        if (comptime std.mem.eql(u8, field, "message")) changed.message = "tampered";
        if (comptime std.mem.eql(u8, field, "subject")) changed.subject = "#elsewhere";
        if (comptime std.mem.eql(u8, field, "origin")) changed.origin_server = "mallory.test";
        if (comptime std.mem.eql(u8, field, "hlc")) changed.hlc +%= 1;
        if (comptime std.mem.eql(u8, field, "category")) changed.category = 12;
        if (comptime std.mem.eql(u8, field, "severity")) changed.severity +%= 1;
        try testing.expectEqual(VerifyOutcome.bad_signature, verifyOrigin(changed));
    }
}

test "oper event signed v2 rejects origin substitution and malformed identity" {
    var kp = try testKeyPair(0xa5);
    defer kp.deinit();
    var pk: [pubkey_len]u8 = undefined;
    var sig: [sig_len]u8 = undefined;
    var ev = try signedSample(&kp, &pk, &sig);
    ev.origin_node ^= 1;
    try testing.expectEqual(VerifyOutcome.origin_mismatch, verifyOrigin(ev));
    ev.origin_node = 0;
    try testing.expectEqual(VerifyOutcome.invalid_semantic, verifyOrigin(ev));

    var attacker = try testKeyPair(0xa6);
    defer attacker.deinit();
    ev = try signedSample(&kp, &pk, &sig);
    var attacker_pk = attacker.public_key;
    ev.origin_pubkey = &attacker_pk;
    try testing.expectEqual(VerifyOutcome.origin_mismatch, verifyOrigin(ev));

    ev = try signedSample(&kp, &pk, &sig);
    var corrupt_sig = sig;
    corrupt_sig[0] ^= 1;
    ev.origin_sig = &corrupt_sig;
    try testing.expectEqual(VerifyOutcome.bad_signature, verifyOrigin(ev));

    ev = try signedSample(&kp, &pk, &sig);
    ev.severity = max_severity + 1;
    try testing.expectEqual(VerifyOutcome.invalid_semantic, verifyOrigin(ev));
    try testing.expectError(error.InvalidSeverity, encodedLenV2(ev));
}
