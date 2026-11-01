// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Versioned transport envelopes for SESSION_REPLICA S2S frames.
//!
//! The daemon's Helix `session_replica` module owns the self-certifying signed
//! OFFER/ACK objects and their semantic verification. This protocol module adds
//! a small rolling-upgrade-safe transport header, binds each payload to the S2S
//! frame kind, and enforces a bound that still fits inside the default S2S frame
//! after the direct-peer signed envelope is added.
//!
//! Wire format (the payload schema is selected explicitly by the version):
//!   magic[4] = "SRTF"
//!   version u8 = 2 | 3 | 4
//!   kind u8 = OFFER(1) | ACK(2) | REVOKE(3) | ATTACHMENT_LEASE(4)
//!   signed_payload_len u32 (big endian)
//!   signed_payload bytes
//!
//! The v2 API carries the legacy token-scoped SRO2/SRA2/SRL2 objects. The
//! attachment API carries the current SRO3/SRV3/SRA3/SRL3 objects, whose
//! authority key includes a stable physical attachment id. Callers must choose
//! one API after capability negotiation; decode never guesses from inner magic
//! and never falls back across versions. Redundant kind binding prevents a
//! valid object being reclassified merely by changing the outer S2S frame tag.
//! Version 4 explicitly carries current inventory offers and terminal group
//! revocation; it cannot be decoded through either frozen compatibility API.
//! Cryptographic verification remains the daemon callback's responsibility.

const std = @import("std");
const s2s_frame = @import("s2s_frame.zig");
const session_portability = @import("session_portability.zig");

pub const magic = [_]u8{ 'S', 'R', 'T', 'F' };
pub const token_version: u8 = 2;
pub const attachment_version: u8 = 3;
pub const current_version: u8 = 4;
/// Compatibility name retained for the live v2 call sites.
pub const version: u8 = token_version;
pub const header_len: usize = magic.len + 1 + 1 + 4;

pub const WireVersion = enum(u8) {
    token_v2 = token_version,
    attachment_v3 = attachment_version,
    current_v4 = current_version,
};

/// `[Ed25519 public key:32][signature:64]` added by `signed_frame` on the S2S
/// direct-peer authentication layer. Kept explicit here to make the frame-size
/// proof visible at the protocol boundary without importing daemon/substrate
/// implementation code into `proto`.
pub const outer_signed_envelope_len: usize = 32 + 64;

/// Largest Helix signed object that can be encoded, wrapped in the S2S signed
/// envelope, and still fit the default length-delimited frame exactly.
pub const max_signed_payload_len: usize = s2s_frame.default_max_frame_size -
    s2s_frame.header_len - outer_signed_envelope_len - header_len;

const offer_magic = [_]u8{ 'S', 'R', 'O', '2' };
const ack_magic = [_]u8{ 'S', 'R', 'A', '2' };
const attachment_lease_magic = [_]u8{ 'S', 'R', 'L', '2' };
const offer_fixed_len: usize = 4 + 1 + 16 + 24 + 8 + 8 + 2 + 2 + 4;
const ack_transcript_len: usize = 4 + 1 + 16 + 24 + 24 + 8 + 8 + 8;
const inner_signature_len: usize = 32 + 64;
const ack_signed_len: usize = ack_transcript_len + inner_signature_len;
const attachment_lease_signed_len: usize = 4 + 16 + 24 + 8 + 8 + inner_signature_len;
const account_len_offset: usize = 4 + 1 + 16 + 24 + 8 + 8;
const max_account_len: usize = 128;
const max_nick_len: usize = 64;
const max_snapshot_len: usize = session_portability.max_snapshot_len;

const attachment_offer_magic = [_]u8{ 'S', 'R', 'O', '3' };
const attachment_ack_magic = [_]u8{ 'S', 'R', 'A', '3' };
const attachment_revoke_magic = [_]u8{ 'S', 'R', 'V', '3' };
const attachment_lease_magic_v3 = [_]u8{ 'S', 'R', 'L', '3' };
const attachment_identity_len: usize = 16 + 16;
const attachment_revision_len: usize = 8 + 8 + 8;
const attachment_offer_fixed_len: usize = 4 + attachment_identity_len + attachment_revision_len + 8 + 8 + 2 + 2 + 4;
const attachment_offer_account_len_offset: usize = 4 + attachment_identity_len + attachment_revision_len + 8 + 8;
const attachment_ack_signed_len: usize = 4 + 1 + attachment_identity_len + attachment_revision_len + attachment_revision_len + 8 + 8 + 8 + inner_signature_len;
const attachment_lease_signed_len_v3: usize = 4 + attachment_identity_len + attachment_revision_len + 8 + 8 + inner_signature_len;
const attachment_revoke_tail_len: usize = attachment_identity_len + attachment_revision_len + 8 + 8 + inner_signature_len;

comptime {
    // The shared portability ceiling deliberately reserves more than every v3
    // signed-object and transport wrapper combined.
    std.debug.assert(attachment_offer_fixed_len + inner_signature_len +
        max_account_len + max_nick_len + max_snapshot_len <= max_signed_payload_len);
}

pub const Kind = enum(u8) {
    offer = 1,
    ack = 2,
    revoke = 3,
    attachment_lease = 4,

    pub fn fromByte(value: u8) ?Kind {
        return switch (value) {
            1 => .offer,
            2 => .ack,
            3 => .revoke,
            4 => .attachment_lease,
            else => null,
        };
    }
};

pub const Frame = struct {
    kind: Kind,
    /// Borrowed from the encoded transport frame.
    signed_payload: []const u8,
};

pub const EncodeError = error{
    BufferTooSmall,
    InvalidPayload,
    PayloadTooLarge,
};

pub const DecodeError = error{
    BadMagic,
    InvalidKind,
    InvalidPayload,
    PayloadTooLarge,
    TrailingBytes,
    Truncated,
    UnsupportedVersion,
    WrongKind,
};

/// Inspect only the authenticated transport discriminator so a negotiated link
/// can route to one exact decoder. This never validates or returns the payload;
/// callers must immediately invoke `decode`, `decodeAttachment`, or `decodeCurrent` and must not
/// try the other decoder after a failure.
pub fn inspectVersion(bytes: []const u8) DecodeError!WireVersion {
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    return switch (bytes[magic.len]) {
        token_version => .token_v2,
        attachment_version => .attachment_v3,
        current_version => .current_v4,
        else => error.UnsupportedVersion,
    };
}

pub fn encodedLen(signed_payload_len: usize) EncodeError!usize {
    if (signed_payload_len > max_signed_payload_len) return error.PayloadTooLarge;
    return header_len + signed_payload_len;
}

pub fn encode(kind: Kind, signed_payload: []const u8, out: []u8) EncodeError![]const u8 {
    return encodeVersioned(token_version, validatePayload, kind, signed_payload, out);
}

/// Encode one attachment-scoped v3 object. This is intentionally a separate
/// entry point from `encode`: negotiated v2 peers must never receive an SRA3
/// object inside a version-2 transport header.
pub fn encodeAttachment(kind: Kind, signed_payload: []const u8, out: []u8) EncodeError![]const u8 {
    return encodeVersioned(attachment_version, validateAttachmentPayload, kind, signed_payload, out);
}

/// Explicit negotiated current schema. Frozen v2 never accepts inventory,
/// terminal group fences, or current-capability acknowledgement statuses.
pub fn encodeCurrent(kind: Kind, signed_payload: []const u8, out: []u8) EncodeError![]const u8 {
    return encodeVersioned(current_version, validateCurrentPayload, kind, signed_payload, out);
}

pub fn decodeCurrent(expected_kind: Kind, bytes: []const u8) DecodeError!Frame {
    return decodeVersioned(current_version, validateCurrentPayload, expected_kind, bytes);
}

fn encodeVersioned(
    comptime wire_version: u8,
    comptime validate: fn (Kind, []const u8) EncodeError!void,
    kind: Kind,
    signed_payload: []const u8,
    out: []u8,
) EncodeError![]const u8 {
    try validate(kind, signed_payload);
    const total = try encodedLen(signed_payload.len);
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..magic.len], &magic);
    out[magic.len] = wire_version;
    out[magic.len + 1] = @backingInt(kind);
    std.mem.writeInt(u32, out[magic.len + 2 ..][0..4], @intCast(signed_payload.len), .big);
    @memcpy(out[header_len..total], signed_payload);
    return out[0..total];
}

/// Strictly decode one transport frame. `expected_kind` is derived from the
/// outer S2S frame tag and prevents cross-tag replay. Returned bytes borrow
/// `bytes` and still require Helix signature + semantic verification.
pub fn decode(expected_kind: Kind, bytes: []const u8) DecodeError!Frame {
    return decodeVersioned(token_version, validatePayload, expected_kind, bytes);
}

/// Strict v3 counterpart to `decode`. There is no v2 compatibility fallback;
/// the caller selects this only after negotiating attachment-scoped replicas.
pub fn decodeAttachment(expected_kind: Kind, bytes: []const u8) DecodeError!Frame {
    return decodeVersioned(attachment_version, validateAttachmentPayload, expected_kind, bytes);
}

fn decodeVersioned(
    comptime wire_version: u8,
    comptime validate: fn (Kind, []const u8) EncodeError!void,
    expected_kind: Kind,
    bytes: []const u8,
) DecodeError!Frame {
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != wire_version) return error.UnsupportedVersion;
    const kind = Kind.fromByte(bytes[magic.len + 1]) orelse return error.InvalidKind;
    if (kind != expected_kind) return error.WrongKind;

    const payload_len: usize = @intCast(std.mem.readInt(u32, bytes[magic.len + 2 ..][0..4], .big));
    if (payload_len > max_signed_payload_len) return error.PayloadTooLarge;
    if (payload_len > bytes.len - header_len) return error.Truncated;
    const total = header_len + payload_len;
    if (bytes.len != total) return error.TrailingBytes;
    const signed_payload = bytes[header_len..total];
    validate(kind, signed_payload) catch |err| return switch (err) {
        error.PayloadTooLarge => error.PayloadTooLarge,
        else => error.InvalidPayload,
    };
    return .{ .kind = kind, .signed_payload = signed_payload };
}

fn validateAttachmentPayload(kind: Kind, payload: []const u8) EncodeError!void {
    if (payload.len > max_signed_payload_len) return error.PayloadTooLarge;
    switch (kind) {
        .offer => try validateAttachmentOffer(payload),
        .revoke => try validateAttachmentRevoke(payload),
        .ack => {
            if (payload.len != attachment_ack_signed_len or
                !std.mem.eql(u8, payload[0..attachment_ack_magic.len], &attachment_ack_magic) or
                payload[attachment_ack_magic.len] < 1 or payload[attachment_ack_magic.len] > 7 or
                !validAttachmentIdentity(payload, attachment_ack_magic.len + 1))
            {
                return error.InvalidPayload;
            }
        },
        .attachment_lease => {
            if (payload.len != attachment_lease_signed_len_v3 or
                !std.mem.eql(u8, payload[0..attachment_lease_magic_v3.len], &attachment_lease_magic_v3) or
                !validAttachmentIdentity(payload, attachment_lease_magic_v3.len))
            {
                return error.InvalidPayload;
            }
        },
    }
}

fn validateAttachmentOffer(payload: []const u8) EncodeError!void {
    if (payload.len < attachment_offer_fixed_len + inner_signature_len or
        !std.mem.eql(u8, payload[0..attachment_offer_magic.len], &attachment_offer_magic) or
        !validAttachmentIdentity(payload, attachment_offer_magic.len))
    {
        return error.InvalidPayload;
    }
    const account_len: usize = std.mem.readInt(u16, payload[attachment_offer_account_len_offset..][0..2], .big);
    const nick_len: usize = std.mem.readInt(u16, payload[attachment_offer_account_len_offset + 2 ..][0..2], .big);
    const snapshot_len: usize = @intCast(std.mem.readInt(u32, payload[attachment_offer_account_len_offset + 4 ..][0..4], .big));
    if (account_len == 0 or account_len > max_account_len or
        nick_len == 0 or nick_len > max_nick_len or
        snapshot_len == 0 or snapshot_len > max_snapshot_len)
    {
        return error.InvalidPayload;
    }
    const variable_len = std.math.add(usize, account_len, nick_len) catch return error.InvalidPayload;
    const content_len = std.math.add(usize, variable_len, snapshot_len) catch return error.InvalidPayload;
    const expected_len = std.math.add(usize, attachment_offer_fixed_len + inner_signature_len, content_len) catch
        return error.InvalidPayload;
    if (payload.len != expected_len) return error.InvalidPayload;
}

fn validateAttachmentRevoke(payload: []const u8) EncodeError!void {
    const prefix_len = attachment_revoke_magic.len + 1;
    if (payload.len < prefix_len + attachment_revoke_tail_len or
        !std.mem.eql(u8, payload[0..attachment_revoke_magic.len], &attachment_revoke_magic))
    {
        return error.InvalidPayload;
    }
    const account_len: usize = payload[attachment_revoke_magic.len];
    if (account_len == 0 or account_len > max_account_len) return error.InvalidPayload;
    const identity_offset = prefix_len + account_len;
    if (payload.len != identity_offset + attachment_revoke_tail_len or
        !validAttachmentIdentity(payload, identity_offset))
    {
        return error.InvalidPayload;
    }
}

fn validAttachmentIdentity(payload: []const u8, offset: usize) bool {
    if (offset > payload.len or attachment_identity_len > payload.len - offset) return false;
    const token = payload[offset .. offset + 16];
    const attachment_id = payload[offset + 16 .. offset + attachment_identity_len];
    return !allZero(token) and !allZero(attachment_id);
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

fn validateCurrentPayload(kind: Kind, payload: []const u8) EncodeError!void {
    if (payload.len > max_signed_payload_len) return error.PayloadTooLarge;
    switch (kind) {
        .offer => try validateCurrentOffer(payload, 1, 3),
        .revoke => try validateCurrentOffer(payload, 2, 4),
        .ack => {
            if (payload.len < ack_magic.len + 1 or !std.mem.eql(u8, payload[0..ack_magic.len], &ack_magic)) return error.InvalidPayload;
            const status = payload[ack_magic.len];
            if (status < 1 or status > 9) return error.InvalidPayload;
            const current = status == 8 or status == 9;
            if (payload.len != ack_signed_len + (if (current) @as(usize, 40) else 0)) return error.InvalidPayload;
            if (current and (std.mem.readInt(u64, payload[ack_transcript_len..][0..8], .big) == 0 or
                allZero(payload[ack_transcript_len + 8 ..][0..32]))) return error.InvalidPayload;
        },
        .attachment_lease => try validatePayload(.attachment_lease, payload),
    }
}

// Negotiated current links still carry ordinary legacy-shaped authority facts
// while local physical inventory is unavailable or not being published. Their
// signed operation remains explicit; a v4 header never upgrades their meaning.
fn validateCurrentOffer(payload: []const u8, legacy_operation: u8, current_operation: u8) EncodeError!void {
    if (payload.len < offer_magic.len + 1) return error.InvalidPayload;
    const operation = payload[offer_magic.len];
    if (operation != legacy_operation and operation != current_operation) return error.InvalidPayload;
    try validateOffer(payload, operation);
}

fn validatePayload(kind: Kind, payload: []const u8) EncodeError!void {
    if (payload.len > max_signed_payload_len) return error.PayloadTooLarge;
    switch (kind) {
        .offer => try validateOffer(payload, 1),
        .revoke => try validateOffer(payload, 2),
        .ack => {
            if (payload.len != ack_signed_len) return error.InvalidPayload;
            if (!std.mem.eql(u8, payload[0..ack_magic.len], &ack_magic) or payload[ack_magic.len] < 1 or payload[ack_magic.len] > 7) return error.InvalidPayload;
        },
        .attachment_lease => {
            if (payload.len != attachment_lease_signed_len) return error.InvalidPayload;
            if (!std.mem.eql(u8, payload[0..attachment_lease_magic.len], &attachment_lease_magic))
                return error.InvalidPayload;
        },
    }
}

fn validateOffer(payload: []const u8, expected_operation: u8) EncodeError!void {
    if (payload.len < offer_fixed_len + inner_signature_len) return error.InvalidPayload;
    if (!std.mem.eql(u8, payload[0..offer_magic.len], &offer_magic)) return error.InvalidPayload;
    if (payload[offer_magic.len] != expected_operation) return error.InvalidPayload;

    const account_len: usize = std.mem.readInt(u16, payload[account_len_offset..][0..2], .big);
    const nick_len: usize = std.mem.readInt(u16, payload[account_len_offset + 2 ..][0..2], .big);
    const snapshot_len: usize = @intCast(std.mem.readInt(u32, payload[account_len_offset + 4 ..][0..4], .big));
    if (account_len > max_account_len or nick_len > max_nick_len or snapshot_len > max_snapshot_len) return error.InvalidPayload;

    const inventory_count: usize = if (expected_operation == 3) blk: {
        if (payload.len < offer_fixed_len + 3 + inner_signature_len) return error.InvalidPayload;
        break :blk std.mem.readInt(u16, payload[offer_fixed_len + 1 ..][0..2], .big);
    } else 0;
    if (inventory_count > 256) return error.InvalidPayload;
    const variable_len = account_len + nick_len + snapshot_len;
    const inventory_len = inventory_count * 25;
    const count_len: usize = if (expected_operation == 3) 3 else 0;
    if (payload.len != offer_fixed_len + count_len + variable_len + inventory_len + inner_signature_len) return error.InvalidPayload;
    if (expected_operation == 3 and payload[offer_fixed_len] > 1) return error.InvalidPayload;
    if (expected_operation == 1 or (expected_operation == 3 and payload[offer_fixed_len] == 1)) {
        if (account_len == 0 or nick_len == 0 or snapshot_len == 0) return error.InvalidPayload;
    } else if (expected_operation == 3) {
        if (account_len == 0 or nick_len != 0 or snapshot_len != 0) return error.InvalidPayload;
    } else if (expected_operation == 4) {
        if (account_len == 0 or nick_len != 0 or snapshot_len != 0 or std.mem.allEqual(u8, payload[5..21], 0)) return error.InvalidPayload;
    } else if (variable_len != 0) return error.InvalidPayload;
    const inventory_start = offer_fixed_len + count_len + variable_len;
    for (0..inventory_count) |i| {
        const row = payload[inventory_start + i * 25 ..][0..25];
        if (std.mem.allEqual(u8, row[0..16], 0) or std.mem.readInt(u64, row[16..24], .big) > std.math.maxInt(i64) or row[24] > 1) return error.InvalidPayload;
        if (i > 0) {
            const previous = payload[inventory_start + (i - 1) * 25 ..][0..16];
            if (std.mem.order(u8, previous, row[0..16]) != .lt) return error.InvalidPayload;
        }
    }
}

const testing = std.testing;

fn fakeOffer(allocator: std.mem.Allocator, kind: Kind) ![]u8 {
    const is_offer = kind == .offer;
    const account = if (is_offer) "a" else "";
    const nick = if (is_offer) "n" else "";
    const snapshot = if (is_offer) "s" else "";
    const total = offer_fixed_len + account.len + nick.len + snapshot.len + inner_signature_len;
    const out = try allocator.alloc(u8, total);
    @memset(out, 0);
    @memcpy(out[0..offer_magic.len], &offer_magic);
    out[offer_magic.len] = if (is_offer) 1 else 2;
    std.mem.writeInt(u16, out[account_len_offset..][0..2], @intCast(account.len), .big);
    std.mem.writeInt(u16, out[account_len_offset + 2 ..][0..2], @intCast(nick.len), .big);
    std.mem.writeInt(u32, out[account_len_offset + 4 ..][0..4], @intCast(snapshot.len), .big);
    var pos: usize = offer_fixed_len;
    @memcpy(out[pos .. pos + account.len], account);
    pos += account.len;
    @memcpy(out[pos .. pos + nick.len], nick);
    pos += nick.len;
    @memcpy(out[pos .. pos + snapshot.len], snapshot);
    return out;
}

fn fakeAck() [ack_signed_len]u8 {
    var out: [ack_signed_len]u8 = @splat(0);
    @memcpy(out[0..ack_magic.len], &ack_magic);
    out[ack_magic.len] = 1;
    return out;
}

fn fakeAttachmentLease() [attachment_lease_signed_len]u8 {
    var out: [attachment_lease_signed_len]u8 = @splat(0);
    @memcpy(out[0..attachment_lease_magic.len], &attachment_lease_magic);
    return out;
}

fn putFakeAttachmentIdentity(out: []u8, offset: usize) void {
    out[offset] = 0x31;
    out[offset + 16] = 0x72;
}

fn fakeAttachmentOffer(allocator: std.mem.Allocator) ![]u8 {
    const account = "alice";
    const nick = "Alice";
    const snapshot = "attachment-snapshot";
    const total = attachment_offer_fixed_len + account.len + nick.len + snapshot.len + inner_signature_len;
    const out = try allocator.alloc(u8, total);
    @memset(out, 0);
    @memcpy(out[0..attachment_offer_magic.len], &attachment_offer_magic);
    putFakeAttachmentIdentity(out, attachment_offer_magic.len);
    std.mem.writeInt(u16, out[attachment_offer_account_len_offset..][0..2], account.len, .big);
    std.mem.writeInt(u16, out[attachment_offer_account_len_offset + 2 ..][0..2], nick.len, .big);
    std.mem.writeInt(u32, out[attachment_offer_account_len_offset + 4 ..][0..4], snapshot.len, .big);
    var pos = attachment_offer_fixed_len;
    @memcpy(out[pos .. pos + account.len], account);
    pos += account.len;
    @memcpy(out[pos .. pos + nick.len], nick);
    pos += nick.len;
    @memcpy(out[pos .. pos + snapshot.len], snapshot);
    return out;
}

fn fakeAttachmentRevoke(allocator: std.mem.Allocator) ![]u8 {
    const account = "alice";
    const identity_offset = attachment_revoke_magic.len + 1 + account.len;
    const out = try allocator.alloc(u8, identity_offset + attachment_revoke_tail_len);
    @memset(out, 0);
    @memcpy(out[0..attachment_revoke_magic.len], &attachment_revoke_magic);
    out[attachment_revoke_magic.len] = account.len;
    @memcpy(out[attachment_revoke_magic.len + 1 .. identity_offset], account);
    putFakeAttachmentIdentity(out, identity_offset);
    return out;
}

fn fakeAttachmentAck() [attachment_ack_signed_len]u8 {
    var out: [attachment_ack_signed_len]u8 = @splat(0);
    @memcpy(out[0..attachment_ack_magic.len], &attachment_ack_magic);
    out[attachment_ack_magic.len] = 1;
    putFakeAttachmentIdentity(&out, attachment_ack_magic.len + 1);
    return out;
}

fn fakeAttachmentLeaseV3() [attachment_lease_signed_len_v3]u8 {
    var out: [attachment_lease_signed_len_v3]u8 = @splat(0);
    @memcpy(out[0..attachment_lease_magic_v3.len], &attachment_lease_magic_v3);
    putFakeAttachmentIdentity(&out, attachment_lease_magic_v3.len);
    return out;
}

test "session replica transport OFFER ACK REVOKE and attachment lease round-trip" {
    const offer = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer);
    const revoke = try fakeOffer(testing.allocator, .revoke);
    defer testing.allocator.free(revoke);
    const ack = fakeAck();
    const lease = fakeAttachmentLease();

    const cases = [_]struct { kind: Kind, payload: []const u8 }{
        .{ .kind = .offer, .payload = offer },
        .{ .kind = .ack, .payload = &ack },
        .{ .kind = .revoke, .payload = revoke },
        .{ .kind = .attachment_lease, .payload = &lease },
    };
    for (cases) |case| {
        const out = try testing.allocator.alloc(u8, header_len + case.payload.len);
        defer testing.allocator.free(out);
        const wire = try encode(case.kind, case.payload, out);
        const decoded = try decode(case.kind, wire);
        try testing.expectEqual(case.kind, decoded.kind);
        try testing.expectEqualSlices(u8, case.payload, decoded.signed_payload);
    }
}

test "attachment session replica transport round-trips every v3 object kind" {
    const offer = try fakeAttachmentOffer(testing.allocator);
    defer testing.allocator.free(offer);
    const revoke = try fakeAttachmentRevoke(testing.allocator);
    defer testing.allocator.free(revoke);
    const ack = fakeAttachmentAck();
    const lease = fakeAttachmentLeaseV3();

    const cases = [_]struct { kind: Kind, payload: []const u8 }{
        .{ .kind = .offer, .payload = offer },
        .{ .kind = .ack, .payload = &ack },
        .{ .kind = .revoke, .payload = revoke },
        .{ .kind = .attachment_lease, .payload = &lease },
    };
    for (cases) |case| {
        const out = try testing.allocator.alloc(u8, header_len + case.payload.len);
        defer testing.allocator.free(out);
        const wire = try encodeAttachment(case.kind, case.payload, out);
        try testing.expectEqual(attachment_version, wire[magic.len]);
        const decoded = try decodeAttachment(case.kind, wire);
        try testing.expectEqual(case.kind, decoded.kind);
        try testing.expectEqualSlices(u8, case.payload, decoded.signed_payload);
    }
}

test "session replica transport never guesses or falls back across v2 and v3" {
    const offer_v2 = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer_v2);
    const offer_v3 = try fakeAttachmentOffer(testing.allocator);
    defer testing.allocator.free(offer_v3);
    const max_len = @max(offer_v2.len, offer_v3.len);
    const out = try testing.allocator.alloc(u8, header_len + max_len);
    defer testing.allocator.free(out);

    try testing.expectError(error.InvalidPayload, encode(.offer, offer_v3, out));
    try testing.expectError(error.InvalidPayload, encodeAttachment(.offer, offer_v2, out));

    const wire_v2 = try encode(.offer, offer_v2, out);
    try testing.expectError(error.UnsupportedVersion, decodeAttachment(.offer, wire_v2));
    const wire_v3 = try encodeAttachment(.offer, offer_v3, out);
    try testing.expectError(error.UnsupportedVersion, decode(.offer, wire_v3));
}

test "attachment session replica transport binds distinct inner objects to outer kind" {
    const offer = try fakeAttachmentOffer(testing.allocator);
    defer testing.allocator.free(offer);
    const revoke = try fakeAttachmentRevoke(testing.allocator);
    defer testing.allocator.free(revoke);
    const ack = fakeAttachmentAck();
    const lease = fakeAttachmentLeaseV3();
    const max_len = @max(@max(offer.len, revoke.len), @max(ack.len, lease.len));
    const out = try testing.allocator.alloc(u8, header_len + max_len);
    defer testing.allocator.free(out);

    try testing.expectError(error.InvalidPayload, encodeAttachment(.revoke, offer, out));
    try testing.expectError(error.InvalidPayload, encodeAttachment(.offer, revoke, out));
    try testing.expectError(error.InvalidPayload, encodeAttachment(.offer, &ack, out));
    try testing.expectError(error.InvalidPayload, encodeAttachment(.ack, &lease, out));
    const ack_wire = try encodeAttachment(.ack, &ack, out);
    try testing.expectError(error.WrongKind, decodeAttachment(.offer, ack_wire));
}

test "attachment session replica transport rejects all truncation and trailing bytes" {
    const ack = fakeAttachmentAck();
    var out: [header_len + attachment_ack_signed_len + 1]u8 = undefined;
    const wire = try encodeAttachment(.ack, &ack, out[0 .. out.len - 1]);
    for (0..wire.len) |end|
        try testing.expectError(error.Truncated, decodeAttachment(.ack, wire[0..end]));
    out[wire.len] = 0xff;
    try testing.expectError(error.TrailingBytes, decodeAttachment(.ack, &out));
}

test "attachment session replica transport rejects malformed identity status and lengths" {
    const ack = fakeAttachmentAck();
    var ack_out: [header_len + attachment_ack_signed_len]u8 = undefined;
    _ = try encodeAttachment(.ack, &ack, &ack_out);

    var bad_ack = ack;
    bad_ack[attachment_ack_magic.len] = 0;
    try testing.expectError(error.InvalidPayload, encodeAttachment(.ack, &bad_ack, &ack_out));
    bad_ack = ack;
    @memset(bad_ack[attachment_ack_magic.len + 1 .. attachment_ack_magic.len + 1 + 16], 0);
    try testing.expectError(error.InvalidPayload, encodeAttachment(.ack, &bad_ack, &ack_out));
    bad_ack = ack;
    @memset(bad_ack[attachment_ack_magic.len + 1 + 16 .. attachment_ack_magic.len + 1 + attachment_identity_len], 0);
    try testing.expectError(error.InvalidPayload, encodeAttachment(.ack, &bad_ack, &ack_out));

    const offer = try fakeAttachmentOffer(testing.allocator);
    defer testing.allocator.free(offer);
    const changed = try testing.allocator.dupe(u8, offer);
    defer testing.allocator.free(changed);
    const transport = try testing.allocator.alloc(u8, header_len + changed.len);
    defer testing.allocator.free(transport);
    std.mem.writeInt(u16, changed[attachment_offer_account_len_offset..][0..2], 0, .big);
    try testing.expectError(error.InvalidPayload, encodeAttachment(.offer, changed, transport));
    @memcpy(changed, offer);
    std.mem.writeInt(u32, changed[attachment_offer_account_len_offset + 4 ..][0..4], @intCast(max_snapshot_len + 1), .big);
    try testing.expectError(error.InvalidPayload, encodeAttachment(.offer, changed, transport));

    const revoke = try fakeAttachmentRevoke(testing.allocator);
    defer testing.allocator.free(revoke);
    revoke[attachment_revoke_magic.len] = 0;
    try testing.expectError(error.InvalidPayload, encodeAttachment(.revoke, revoke, transport));
}

test "session replica transport binds inner object to outer kind" {
    const offer = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer);
    const revoke = try fakeOffer(testing.allocator, .revoke);
    defer testing.allocator.free(revoke);
    const ack = fakeAck();
    const lease = fakeAttachmentLease();
    var out: [header_len + ack_signed_len]u8 = undefined;

    try testing.expectError(error.InvalidPayload, encode(.revoke, offer, &out));
    try testing.expectError(error.InvalidPayload, encode(.offer, revoke, &out));
    try testing.expectError(error.InvalidPayload, encode(.offer, &ack, &out));
    try testing.expectError(error.InvalidPayload, encode(.ack, &lease, &out));
    const ack_wire = try encode(.ack, &ack, &out);
    try testing.expectError(error.WrongKind, decode(.offer, ack_wire));
}

test "session replica transport rejects every truncation and trailing bytes" {
    const ack = fakeAck();
    var out: [header_len + ack_signed_len + 1]u8 = undefined;
    const wire = try encode(.ack, &ack, out[0 .. out.len - 1]);
    for (0..wire.len) |end| try testing.expectError(error.Truncated, decode(.ack, wire[0..end]));
    out[wire.len] = 0xff;
    try testing.expectError(error.TrailingBytes, decode(.ack, &out));
}

test "session replica transport rejects malformed headers lengths and payloads" {
    const ack = fakeAck();
    var out: [header_len + ack_signed_len]u8 = undefined;
    _ = try encode(.ack, &ack, &out);

    var changed = out;
    changed[0] = 'X';
    try testing.expectError(error.BadMagic, decode(.ack, &changed));
    changed = out;
    changed[magic.len] = version + 1;
    try testing.expectError(error.UnsupportedVersion, decode(.ack, &changed));
    changed = out;
    changed[magic.len + 1] = 0xff;
    try testing.expectError(error.InvalidKind, decode(.ack, &changed));
    changed = out;
    std.mem.writeInt(u32, changed[magic.len + 2 ..][0..4], ack_signed_len + 1, .big);
    try testing.expectError(error.Truncated, decode(.ack, &changed));
    changed = out;
    changed[header_len] = 'X';
    try testing.expectError(error.InvalidPayload, decode(.ack, &changed));
}

test "session replica transport enforces frame-size bound before allocation or parse" {
    const oversized = try testing.allocator.alloc(u8, max_signed_payload_len + 1);
    defer testing.allocator.free(oversized);
    @memset(oversized, 0);
    var one: [1]u8 = undefined;
    try testing.expectError(error.PayloadTooLarge, encode(.offer, oversized, &one));

    var header: [header_len]u8 = @splat(0);
    @memcpy(header[0..magic.len], &magic);
    header[magic.len] = version;
    header[magic.len + 1] = @backingInt(Kind.offer);
    std.mem.writeInt(u32, header[magic.len + 2 ..][0..4], @intCast(max_signed_payload_len + 1), .big);
    try testing.expectError(error.PayloadTooLarge, decode(.offer, &header));
}

test "session replica transport OFFER declared fields are strict and bounded" {
    const offer = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(offer);
    var changed = try testing.allocator.dupe(u8, offer);
    defer testing.allocator.free(changed);
    std.mem.writeInt(u16, changed[account_len_offset..][0..2], max_account_len + 1, .big);
    var out: [512]u8 = undefined;
    try testing.expectError(error.InvalidPayload, encode(.offer, changed, &out));

    @memcpy(changed, offer);
    std.mem.writeInt(u32, changed[account_len_offset + 4 ..][0..4], 99, .big);
    try testing.expectError(error.InvalidPayload, encode(.offer, changed, &out));

    @memcpy(changed, offer);
    std.mem.writeInt(
        u32,
        changed[account_len_offset + 4 ..][0..4],
        @intCast(session_portability.max_snapshot_len + 1),
        .big,
    );
    try testing.expectError(error.InvalidPayload, encode(.offer, changed, &out));
}

test "current transport retains byte exact ordinary upsert and origin removal authority" {
    for ([_]Kind{ .offer, .revoke }) |kind| {
        const signed = try fakeOffer(testing.allocator, kind);
        defer testing.allocator.free(signed);
        var current_storage: [512]u8 = undefined;
        const current = try encodeCurrent(kind, signed, &current_storage);
        try testing.expectEqual(WireVersion.current_v4, try inspectVersion(current));
        try testing.expectEqualSlices(u8, signed, (try decodeCurrent(kind, current)).signed_payload);
        try testing.expectError(error.UnsupportedVersion, decode(kind, current));
        var frozen_storage: [512]u8 = undefined;
        const frozen = try encode(kind, signed, &frozen_storage);
        try testing.expectEqual(WireVersion.token_v2, try inspectVersion(frozen));
        try testing.expectEqualSlices(u8, signed, (try decode(kind, frozen)).signed_payload);
        try testing.expectError(error.UnsupportedVersion, decodeCurrent(kind, frozen));
    }
}

test "session replica current inventory eligibility is mandatory canonical and private when false" {
    const legacy = try fakeOffer(testing.allocator, .offer);
    defer testing.allocator.free(legacy);
    const current = try testing.allocator.alloc(u8, legacy.len + 3);
    defer testing.allocator.free(current);
    @memcpy(current[0..offer_fixed_len], legacy[0..offer_fixed_len]);
    current[offer_magic.len] = 3;
    current[offer_fixed_len] = 1;
    @memset(current[offer_fixed_len + 1 .. offer_fixed_len + 3], 0);
    @memcpy(current[offer_fixed_len + 3 ..], legacy[offer_fixed_len..]);
    var out: [1024]u8 = undefined;
    _ = try encodeCurrent(.offer, current, &out);
    try testing.expectError(error.InvalidPayload, encode(.offer, current, &out));
    current[offer_fixed_len] = 2;
    try testing.expectError(error.InvalidPayload, encodeCurrent(.offer, current, &out));
    current[offer_fixed_len] = 0;
    try testing.expectError(error.InvalidPayload, encodeCurrent(.offer, current, &out));
    const private = try testing.allocator.alloc(u8, offer_fixed_len + 3 + 1 + inner_signature_len);
    defer testing.allocator.free(private);
    @memcpy(private[0 .. offer_fixed_len + 3], current[0 .. offer_fixed_len + 3]);
    std.mem.writeInt(u16, private[account_len_offset + 2 ..][0..2], 0, .big);
    std.mem.writeInt(u32, private[account_len_offset + 4 ..][0..4], 0, .big);
    @memset(private[offer_fixed_len + 3 ..], 0);
    private[offer_fixed_len + 3] = 'a';
    const encoded = try encodeCurrent(.offer, private, &out);
    try testing.expectEqualSlices(u8, private, (try decodeCurrent(.offer, encoded)).signed_payload);
    // An old op3 without the mandatory bit is not an accepted current record.
    try testing.expectError(error.InvalidPayload, encodeCurrent(.offer, private[0 .. private.len - 1], &out));
    _ = try encode(.offer, legacy, &out);
    _ = try encodeCurrent(.offer, legacy, &out);
}
