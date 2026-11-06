// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SESSION_REPLICA convergence core with negotiated current inventory and terminal revocation.
//!
//! This module deliberately owns no sockets. It defines the signed,
//! self-certifying OFFER/ACK/attachment-lease wire objects and the bounded
//! in-memory convergence store driven by the daemon's live S2S capability. The safety rules are
//! intentionally strict:
//!
//!   * authority is keyed by `(token, origin_node)` so simultaneous attachments
//!     coexist; the revision total order only selects a deterministic projection;
//!   * equal revision + equal signed fact is an idempotent duplicate;
//!   * same-origin equal-revision equivocation retains the lexicographically
//!     smaller transcript digest, independent of arrival order;
//!   * lower revisions are stale only within the same origin authority;
//!   * higher revisions supersede only that origin's entry or tombstone;
//!   * every route is bound to the live revision of its authority origin;
//!   * entries and routes have independent hard bounds; brand-new tombstones
//!     without live authority (soft-capped) are bounded by `max_tombstones`
//!     apart from conversions, converting a live entry into its tombstone
//!     always succeeds (it frees the slot it occupies), and every
//!     origin slot stays within `max_entries + max_tombstones`
//!     (`session_replica_revocation`); no live authority is evicted merely to
//!     admit attacker-controlled input;
//!   * peer removal and time sweeping are allocation-free once state exists.
//!
//! OFFER carries either a complete replica upsert (account, nick, snapshot) or
//! a removal tombstone. ACK carries the receiver's disposition and observed
//! revision. An attachment lease is short-lived positive liveness evidence.
//! All objects embed the signing public key, bind every semantic field under a
//! distinct Ed25519 domain, and require the claimed node id to be the
//! self-certified short id of that key. They are safe to forward unchanged
//! across multiple hops.

const std = @import("std");
const builtin = @import("builtin");

const sign = @import("../../crypto/sign.zig");
const session_portability = @import("../../proto/session_portability.zig");
const session_replica_transport = @import("../../proto/session_replica_frame.zig");
const mesh_clock = @import("../../substrate/undertow/mesh_clock.zig");
const signed_frame = @import("../../substrate/undertow/signed_frame.zig");
const session_replica_revocation = @import("session_replica_revocation.zig");

pub const Token = [16]u8;
pub const NodeId = u64;
pub const Digest = [std.crypto.hash.Blake3.digest_length]u8;

pub const offer_magic = [_]u8{ 'S', 'R', 'O', '2' };
pub const ack_magic = [_]u8{ 'S', 'R', 'A', '2' };
pub const attachment_lease_magic = [_]u8{ 'S', 'R', 'L', '2' };
pub const offer_sign_domain = "onyx-session-replica-offer-v2";
pub const ack_sign_domain = "onyx-session-replica-ack-v2";
pub const attachment_lease_sign_domain = "onyx-session-replica-attachment-lease-v2";

pub const max_account_len: usize = 128;
pub const max_nick_len: usize = 64;
pub const default_max_future_skew_ms: u64 = mesh_clock.default_max_future_skew_ms;

const revision_wire_len: usize = 8 + 8 + 8;
const signature_wire_len: usize = sign.public_key_len + sign.signature_len;
const offer_fixed_len: usize = offer_magic.len + 1 + @sizeOf(Token) + revision_wire_len + 8 + 8 + 2 + 2 + 4;
const ack_fixed_len: usize = ack_magic.len + 1 + @sizeOf(Token) + revision_wire_len + revision_wire_len + 8 + 8 + 8;
const attachment_lease_fixed_len: usize = attachment_lease_magic.len + @sizeOf(Token) + revision_wire_len + 8 + 8;
/// Transport-derived ceiling before the cross-version portability cap is
/// applied. Kept explicit so the compile-time minimum proves both envelopes.
const transport_max_snapshot_len: usize = session_replica_transport.max_signed_payload_len -
    offer_fixed_len - signature_wire_len - max_account_len - max_nick_len;

/// Largest snapshot accepted by both current SESSION_REPLICA and rolling-old
/// SESSION_MIGRATE paths.
pub const max_snapshot_len: usize = @min(
    transport_max_snapshot_len,
    session_portability.max_snapshot_len,
);

/// Complete 256-row inventory plus this snapshot, maximal account/nick,
/// both signatures and both transport envelopes fits the existing frame cap.
/// Larger snapshots remain valid only with fewer rows if encodeOffer proves
/// the actual complete signed object still fits; no bytes are truncated.
pub const max_inventory_snapshot_len: usize = @min(max_snapshot_len, session_replica_transport.max_signed_payload_len - offer_fixed_len - signature_wire_len -
    max_account_len - max_nick_len - 3 - 256 * 25);
comptime {
    std.debug.assert(offer_fixed_len + signature_wire_len + max_account_len + max_nick_len +
        3 + 256 * 25 + max_inventory_snapshot_len <= session_replica_transport.max_signed_payload_len);
}

/// A restart-safe, deterministic total-order revision. `sequence` is the full
/// packed MeshClock stamp and `epoch` is its canonical physical projection.
/// Carrying both on the wire makes ordering explicit while the equality
/// invariant prevents a signer from placing an unrelated, unobservable epoch
/// above every future local mutation. `origin_node` breaks simultaneous
/// cross-node ties without depending on arrival order.
pub const Revision = struct {
    epoch: u64,
    sequence: u64,
    origin_node: NodeId,

    pub fn compare(a: Revision, b: Revision) std.math.Order {
        if (a.epoch < b.epoch) return .lt;
        if (a.epoch > b.epoch) return .gt;
        if (a.sequence < b.sequence) return .lt;
        if (a.sequence > b.sequence) return .gt;
        if (a.origin_node < b.origin_node) return .lt;
        if (a.origin_node > b.origin_node) return .gt;
        return .eq;
    }

    pub fn eql(a: Revision, b: Revision) bool {
        return compare(a, b) == .eq;
    }

    pub fn isCanonical(self: Revision) bool {
        return self.epoch == mesh_clock.MeshClock.physicalOf(self.sequence);
    }
};

pub const OfferOperation = enum(u8) {
    upsert = 1,
    remove = 2,
    inventory_upsert = 3,
    group_revoke = 4,
};

pub const inventory_row_len: usize = 25;
pub const max_inventory_attachments: usize = 256;
pub const AttachmentMetadata = struct {
    attachment_id: [16]u8,
    signon_ms: i64,
    attached: bool,
};

pub const Inventory = struct {
    bytes: []const u8,

    pub fn count(self: Inventory) usize {
        return self.bytes.len / inventory_row_len;
    }

    pub fn at(self: Inventory, index: usize) AttachmentMetadata {
        const row = self.bytes[index * inventory_row_len ..][0..inventory_row_len];
        return .{
            .attachment_id = row[0..16].*,
            .signon_ms = @bitCast(std.mem.readInt(u64, row[16..24], .big)),
            .attached = row[24] == 1,
        };
    }
};

pub fn encodeInventory(out: []u8, rows: []const AttachmentMetadata) error{ InvalidInventory, BufferTooSmall }![]const u8 {
    if (rows.len > max_inventory_attachments) return error.InvalidInventory;
    for (rows, 0..) |row, i| {
        if (std.mem.allEqual(u8, &row.attachment_id, 0) or row.signon_ms < 0) return error.InvalidInventory;
        if (i > 0 and std.mem.order(u8, &rows[i - 1].attachment_id, &row.attachment_id) != .lt) return error.InvalidInventory;
    }
    const len = rows.len * inventory_row_len;
    if (out.len < len) return error.BufferTooSmall;
    for (rows, 0..) |row, i| {
        const target = out[i * inventory_row_len ..][0..inventory_row_len];
        @memcpy(target[0..16], &row.attachment_id);
        std.mem.writeInt(u64, target[16..24], @bitCast(row.signon_ms), .big);
        target[24] = @intFromBool(row.attached);
    }
    return out[0..len];
}

fn validInventory(bytes: []const u8) bool {
    if (bytes.len % inventory_row_len != 0 or bytes.len / inventory_row_len > max_inventory_attachments) return false;
    const inventory = Inventory{ .bytes = bytes };
    for (0..inventory.count()) |i| {
        const row = inventory.at(i);
        if (std.mem.allEqual(u8, &row.attachment_id, 0) or row.signon_ms < 0 or bytes[i * inventory_row_len + 24] > 1) return false;
        if (i > 0 and std.mem.order(u8, &inventory.at(i - 1).attachment_id, &row.attachment_id) != .lt) return false;
    }
    return true;
}

/// Unsigned semantic OFFER. `encodeOffer` signs this value and returns the
/// complete owned wire object. Variable fields are borrowed for the call.
pub const Offer = struct {
    operation: OfferOperation,
    token: Token,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
    account: []const u8 = "",
    nick: []const u8 = "",
    snapshot: []const u8 = "",
    inventory: []const u8 = "",
    /// Mandatory signed authority decision for inventory offers only.
    resume_eligible: ?bool = null,

    pub fn allowsResume(self: Offer) bool {
        return self.operation == .upsert or (self.operation == .inventory_upsert and self.resume_eligible == true);
    }
};

/// Decoded signed OFFER. Variable fields and `transcript` borrow the input wire.
pub const SignedOffer = struct {
    offer: Offer,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
};

pub const AckStatus = enum(u8) {
    accepted = 1,
    duplicate = 2,
    conflict = 3,
    stale = 4,
    superseded = 5,
    tombstoned = 6,
    capacity = 7,
    current_ready = 8,
    group_revoked = 9,
};

/// Unsigned semantic ACK. `offered_revision` identifies the fact being
/// acknowledged; `observed_revision` reports the receiver's current authority.
pub const Ack = struct {
    status: AckStatus,
    token: Token,
    offered_revision: Revision,
    observed_revision: Revision,
    ack_node: NodeId,
    issued_at_ms: i64,
    expires_at_ms: i64,
    /// Mandatory signed current-cohort binding for statuses8/9 only. Frozen
    /// statuses retain their exact old transcript and reject extra context.
    membership_epoch: u64 = 0,
    roster_digest: Digest = @splat(0),
};

/// Decoded signed ACK. `transcript` borrows the input wire.
pub const SignedAck = struct {
    ack: Ack,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
};

/// Positive, short-lived proof that one origin currently has at least one live
/// attachment for this exact token. Retained OFFERs deliberately outlive live
/// sockets, so they cannot serve as presence evidence. A lease is effective
/// only while it is newer than that origin's current OFFER revision.
pub const AttachmentLease = struct {
    token: Token,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
};

pub const SignedAttachmentLease = struct {
    lease: AttachmentLease,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
};

pub const EncodeError = error{
    InvalidOffer,
    InvalidAck,
    InvalidAttachmentLease,
    OriginMismatch,
    TooLong,
} || std.mem.Allocator.Error || sign.SignError;

pub const DecodeError = error{
    BadMagic,
    InvalidOffer,
    InvalidAck,
    InvalidAttachmentLease,
    TooLong,
    TrailingBytes,
    Truncated,
};

pub const VerifyError = error{
    BadSignature,
    OriginMismatch,
    TranscriptMismatch,
};

/// Encode and sign one canonical OFFER. The caller owns the returned bytes.
pub fn encodeOffer(allocator: std.mem.Allocator, offer: Offer, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateOfferShape(offer);
    if (signed_frame.originShortId(kp.public_key) != offer.revision.origin_node) return error.OriginMismatch;

    const transcript_len = offer_fixed_len + offer.account.len + offer.nick.len + offer.snapshot.len +
        (if (offer.operation == .inventory_upsert) @as(usize, 3) + offer.inventory.len else 0);
    if (transcript_len + signature_wire_len > session_replica_transport.max_signed_payload_len) return error.TooLong;
    const total_len = transcript_len + signature_wire_len;
    var out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    var writer = Writer{ .bytes = out };
    writer.writeBytes(&offer_magic);
    writer.writeByte(@backingInt(offer.operation));
    writer.writeBytes(&offer.token);
    writer.writeRevision(offer.revision);
    writer.writeI64(offer.issued_at_ms);
    writer.writeI64(offer.expires_at_ms);
    writer.writeU16(@intCast(offer.account.len));
    writer.writeU16(@intCast(offer.nick.len));
    writer.writeU32(@intCast(offer.snapshot.len));
    if (offer.operation == .inventory_upsert) {
        writer.writeByte(@intFromBool(offer.resume_eligible.?));
        writer.writeU16(@intCast(offer.inventory.len / inventory_row_len));
    }
    writer.writeBytes(offer.account);
    writer.writeBytes(offer.nick);
    writer.writeBytes(offer.snapshot);
    writer.writeBytes(offer.inventory);
    std.debug.assert(writer.pos == transcript_len);

    const signature = try kp.signCtx(offer_sign_domain, out[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == out.len);
    return out;
}

/// Strictly decode one canonical signed OFFER. Returned slices borrow `bytes`.
pub fn decodeOffer(bytes: []const u8) DecodeError!SignedOffer {
    if (bytes.len > session_replica_transport.max_signed_payload_len) return error.TooLong;
    var reader = Reader{ .bytes = bytes };
    const offer = try readOffer(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != bytes.len) return error.TrailingBytes;

    return .{
        .offer = offer,
        .signer = signer,
        .signature = signature,
        .transcript = bytes[0..transcript_end],
    };
}

fn readOffer(reader: *Reader) DecodeError!Offer {
    if (!std.mem.eql(u8, try reader.take(offer_magic.len), &offer_magic)) return error.BadMagic;
    const operation: OfferOperation = switch (try reader.readByte()) {
        1 => .upsert,
        2 => .remove,
        3 => .inventory_upsert,
        4 => .group_revoke,
        else => return error.InvalidOffer,
    };
    const token = (try reader.take(@sizeOf(Token)))[0..@sizeOf(Token)].*;
    const revision = try reader.readRevision();
    const issued_at_ms = try reader.readI64();
    const expires_at_ms = try reader.readI64();
    const account_len = try reader.readU16();
    const nick_len = try reader.readU16();
    const snapshot_len = try reader.readU32();
    if (account_len > max_account_len or nick_len > max_nick_len or snapshot_len > max_snapshot_len) return error.TooLong;
    const resume_eligible: ?bool = if (operation == .inventory_upsert) switch (try reader.readByte()) {
        0 => false,
        1 => true,
        else => return error.InvalidOffer,
    } else null;
    const inventory_count = if (operation == .inventory_upsert) try reader.readU16() else 0;
    if (inventory_count > max_inventory_attachments) return error.TooLong;
    const account = try reader.take(account_len);
    const nick = try reader.take(nick_len);
    const snapshot = try reader.take(snapshot_len);
    const inventory = try reader.take(@as(usize, inventory_count) * inventory_row_len);
    const offer = Offer{
        .operation = operation,
        .token = token,
        .revision = revision,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
        .account = account,
        .nick = nick,
        .snapshot = snapshot,
        .inventory = inventory,
        .resume_eligible = resume_eligible,
    };
    validateOfferShape(offer) catch return error.InvalidOffer;
    return offer;
}

fn validateOfferProjection(signed: SignedOffer) VerifyError!void {
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readOffer(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !offerEql(projected, signed.offer)) return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.offer.revision.origin_node) return error.OriginMismatch;
}
fn verifyOfferSignature(signed: SignedOffer) VerifyError!void {
    const valid = sign.verifyCtx(offer_sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}
pub fn verifyOffer(signed: SignedOffer) VerifyError!void {
    try validateOfferProjection(signed);
    try verifyOfferSignature(signed);
}

/// Captures the caller's current validated cohort, not authorization itself.
/// The caller MUST independently check the current authenticated peer, issuer
/// membership and revocation before every call, including cache hits.
pub const OfferMemoAuthority = struct {
    declared: bool,
    epoch: u64,
    roster_digest: [32]u8,
};
/// Process-local performance hint. Exact bytes only; no Store/Helix authority.
/// Caller owns this fixed memory and must serialize access and call deinit.
pub const OfferSignatureMemo = struct {
    pub const capacity = 4;
    pub const max_transcript_bytes = 4096;
    const Slot = struct {
        valid: bool = false,
        len: usize = 0,
        transcript: [max_transcript_bytes]u8 = @splat(0),
        signer: sign.PublicKey = @splat(0),
        signature: sign.Signature = @splat(0),
        authority: OfferMemoAuthority = .{ .declared = false, .epoch = 0, .roster_digest = @splat(0) },
        expires_ms: i64 = 0,
    };
    slots: [capacity]Slot = @splat(.{}),
    next: usize = 0,
    last_now_ms: i64 = -1,
    /// Saturating process-local work observations, never authority or wire data.
    /// The legacy storage name preserves existing Server test access; this is
    /// the SAME signature counter in every build, not an additional test copy.
    test_signature_checks: u64 = 0,
    cache_hits: u64 = 0,
    fallbacks: u64 = 0,

    pub const Stats = struct {
        /// Actual signature verification attempts, including failed signatures.
        signature_checks: u64 = 0,
        /// Exact signature memo matches; normal Store checks still run afterward.
        cache_hits: u64 = 0,
        /// Valid projections outside memo eligibility that use full verification.
        /// Eligible misses are checks, not fallbacks. Outer group-revoke bypass
        /// and projection refusals do not call this memo verification path.
        fallbacks: u64 = 0,
    };

    /// Read under the same owner exclusion required by verify/deinit. This value
    /// copy owns no references and grants no authority. Not a concurrent metrics
    /// API: callers must not race the serialized owner or checkpoint these data.
    pub fn stats(self: *const OfferSignatureMemo) Stats {
        return .{ .signature_checks = self.test_signature_checks, .cache_hits = self.cache_hits, .fallbacks = self.fallbacks };
    }
    pub fn deinit(self: *OfferSignatureMemo) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.* = .{};
    }
    fn verify(self: *OfferSignatureMemo, signed: SignedOffer, authority: OfferMemoAuthority, now_ms: i64) VerifyError!void {
        try validateOfferProjection(signed);
        const forward_clock = now_ms > 0 and now_ms >= self.last_now_ms;
        if (forward_clock) self.last_now_ms = now_ms;
        const eligible = (signed.offer.operation == .upsert or signed.offer.operation == .inventory_upsert) and
            signed.transcript.len <= max_transcript_bytes and
            forward_clock and now_ms >= signed.offer.issued_at_ms and now_ms <= signed.offer.expires_at_ms;
        if (eligible) {
            var padded: [max_transcript_bytes]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &padded);
            @memcpy(padded[0..signed.transcript.len], signed.transcript);
            for (&self.slots) |*slot| {
                if (!slot.valid or slot.len != signed.transcript.len or slot.expires_ms != signed.offer.expires_at_ms or
                    slot.authority.declared != authority.declared or slot.authority.epoch != authority.epoch) continue;
                if (!std.crypto.timing_safe.eql([32]u8, slot.authority.roster_digest, authority.roster_digest) or
                    !std.crypto.timing_safe.eql(sign.PublicKey, slot.signer, signed.signer) or
                    !std.crypto.timing_safe.eql(sign.Signature, slot.signature, signed.signature) or
                    !std.crypto.timing_safe.eql([max_transcript_bytes]u8, slot.transcript, padded)) continue;
                self.cache_hits +|= 1;
                return;
            }
            self.test_signature_checks +|= 1;
            try verifyOfferSignature(signed);
            const slot = &self.slots[self.next];
            std.crypto.secureZero(u8, std.mem.asBytes(slot));
            slot.* = .{ .valid = true, .len = signed.transcript.len, .transcript = padded, .signer = signed.signer, .signature = signed.signature, .authority = authority, .expires_ms = signed.offer.expires_at_ms };
            self.next = (self.next + 1) % capacity;
            return;
        }
        self.fallbacks +|= 1;
        self.test_signature_checks +|= 1;
        try verifyOfferSignature(signed);
    }
};

/// Encode and sign one canonical ACK. The caller owns the returned bytes.
pub fn encodeAck(allocator: std.mem.Allocator, ack: Ack, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateAckShape(ack);
    if (signed_frame.originShortId(kp.public_key) != ack.ack_node) return error.OriginMismatch;

    const transcript_len = ack_fixed_len + (if (ack.status == .current_ready or ack.status == .group_revoked) @as(usize, 40) else 0);
    var out = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&ack_magic);
    writer.writeByte(@backingInt(ack.status));
    writer.writeBytes(&ack.token);
    writer.writeRevision(ack.offered_revision);
    writer.writeRevision(ack.observed_revision);
    writer.writeU64(ack.ack_node);
    writer.writeI64(ack.issued_at_ms);
    writer.writeI64(ack.expires_at_ms);
    if (ack.status == .current_ready or ack.status == .group_revoked) {
        writer.writeU64(ack.membership_epoch);
        writer.writeBytes(&ack.roster_digest);
    }
    std.debug.assert(writer.pos == transcript_len);

    const signature = try kp.signCtx(ack_sign_domain, out[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == out.len);
    return out;
}

/// Strictly decode one canonical signed ACK. Returned transcript borrows bytes.
pub fn decodeAck(bytes: []const u8) DecodeError!SignedAck {
    var reader = Reader{ .bytes = bytes };
    const ack = try readAck(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != bytes.len) return error.TrailingBytes;

    return .{
        .ack = ack,
        .signer = signer,
        .signature = signature,
        .transcript = bytes[0..transcript_end],
    };
}

fn readAck(reader: *Reader) DecodeError!Ack {
    if (!std.mem.eql(u8, try reader.take(ack_magic.len), &ack_magic)) return error.BadMagic;
    const status: AckStatus = switch (try reader.readByte()) {
        1 => .accepted,
        2 => .duplicate,
        3 => .conflict,
        4 => .stale,
        5 => .superseded,
        6 => .tombstoned,
        7 => .capacity,
        8 => .current_ready,
        9 => .group_revoked,
        else => return error.InvalidAck,
    };
    const token = (try reader.take(@sizeOf(Token)))[0..@sizeOf(Token)].*;
    const offered_revision = try reader.readRevision();
    const observed_revision = try reader.readRevision();
    const ack_node = try reader.readU64();
    const issued_at_ms = try reader.readI64();
    const expires_at_ms = try reader.readI64();
    const current = status == .current_ready or status == .group_revoked;
    const membership_epoch = if (current) try reader.readU64() else 0;
    const roster_digest: Digest = if (current) (try reader.take(@sizeOf(Digest)))[0..@sizeOf(Digest)].* else @splat(0);
    const ack = Ack{
        .status = status,
        .token = token,
        .offered_revision = offered_revision,
        .observed_revision = observed_revision,
        .ack_node = ack_node,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
        .membership_epoch = membership_epoch,
        .roster_digest = roster_digest,
    };
    validateAckShape(ack) catch return error.InvalidAck;
    return ack;
}

pub fn verifyAck(signed: SignedAck) VerifyError!void {
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readAck(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !ackEql(projected, signed.ack)) return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.ack.ack_node) return error.OriginMismatch;
    const valid = sign.verifyCtx(ack_sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}

/// Encode and sign one canonical positive attachment lease.
pub fn encodeAttachmentLease(
    allocator: std.mem.Allocator,
    lease: AttachmentLease,
    kp: *const sign.KeyPair,
) EncodeError![]u8 {
    try validateAttachmentLeaseShape(lease);
    if (signed_frame.originShortId(kp.public_key) != lease.revision.origin_node) return error.OriginMismatch;

    var out = try allocator.alloc(u8, attachment_lease_fixed_len + signature_wire_len);
    errdefer allocator.free(out);
    var writer = Writer{ .bytes = out };
    writer.writeBytes(&attachment_lease_magic);
    writer.writeBytes(&lease.token);
    writer.writeRevision(lease.revision);
    writer.writeI64(lease.issued_at_ms);
    writer.writeI64(lease.expires_at_ms);
    std.debug.assert(writer.pos == attachment_lease_fixed_len);
    const signature = try kp.signCtx(attachment_lease_sign_domain, out[0..attachment_lease_fixed_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == out.len);
    return out;
}

pub fn decodeAttachmentLease(bytes: []const u8) DecodeError!SignedAttachmentLease {
    var reader = Reader{ .bytes = bytes };
    const lease = try readAttachmentLease(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != bytes.len) return error.TrailingBytes;
    return .{
        .lease = lease,
        .signer = signer,
        .signature = signature,
        .transcript = bytes[0..transcript_end],
    };
}

fn readAttachmentLease(reader: *Reader) DecodeError!AttachmentLease {
    if (!std.mem.eql(u8, try reader.take(attachment_lease_magic.len), &attachment_lease_magic)) return error.BadMagic;
    const lease = AttachmentLease{
        .token = (try reader.take(@sizeOf(Token)))[0..@sizeOf(Token)].*,
        .revision = try reader.readRevision(),
        .issued_at_ms = try reader.readI64(),
        .expires_at_ms = try reader.readI64(),
    };
    validateAttachmentLeaseShape(lease) catch return error.InvalidAttachmentLease;
    return lease;
}

pub fn verifyAttachmentLease(signed: SignedAttachmentLease) VerifyError!void {
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readAttachmentLease(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !attachmentLeaseEql(projected, signed.lease))
        return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.lease.revision.origin_node) return error.OriginMismatch;
    const valid = sign.verifyCtx(
        attachment_lease_sign_domain,
        signed.transcript,
        signed.signature,
        signed.signer,
    ) catch false;
    if (!valid) return error.BadSignature;
}

fn validateOfferShape(offer: Offer) error{ InvalidOffer, TooLong }!void {
    if (offer.revision.origin_node == 0 or !offer.revision.isCanonical()) return error.InvalidOffer;
    if (offer.issued_at_ms < 0 or offer.expires_at_ms < offer.issued_at_ms) return error.InvalidOffer;
    if (offer.account.len > max_account_len or offer.nick.len > max_nick_len or offer.snapshot.len > max_snapshot_len) return error.TooLong;
    if (offer.operation != .inventory_upsert and offer.resume_eligible != null) return error.InvalidOffer;
    switch (offer.operation) {
        .upsert, .inventory_upsert => {
            if (offer.account.len == 0) return error.InvalidOffer;
            if (offer.operation == .inventory_upsert and offer.resume_eligible == null) return error.InvalidOffer;
            if (offer.allowsResume()) {
                if (offer.nick.len == 0 or offer.snapshot.len == 0) return error.InvalidOffer;
            } else if (offer.nick.len != 0 or offer.snapshot.len != 0) return error.InvalidOffer;
            if (offer.operation == .upsert and offer.inventory.len != 0) return error.InvalidOffer;
            if (!validInventory(offer.inventory)) return error.InvalidOffer;
        },
        .group_revoke => {
            if (std.mem.allEqual(u8, &offer.token, 0) or offer.account.len == 0 or offer.nick.len != 0 or offer.snapshot.len != 0 or offer.inventory.len != 0) return error.InvalidOffer;
        },
        .remove => {
            if (offer.account.len != 0 or offer.nick.len != 0 or offer.snapshot.len != 0 or offer.inventory.len != 0) return error.InvalidOffer;
        },
    }
}

fn validateAckShape(ack: Ack) error{InvalidAck}!void {
    const current = ack.status == .current_ready or ack.status == .group_revoked;
    const empty_digest = std.mem.allEqual(u8, &ack.roster_digest, 0);
    if (current) {
        if (ack.membership_epoch == 0 or empty_digest) return error.InvalidAck;
    } else if (ack.membership_epoch != 0 or !empty_digest) return error.InvalidAck;
    if (ack.ack_node == 0 or ack.offered_revision.origin_node == 0 or ack.observed_revision.origin_node == 0) return error.InvalidAck;
    if (ack.offered_revision.origin_node != ack.observed_revision.origin_node and ack.status != .group_revoked) return error.InvalidAck;
    if (!ack.offered_revision.isCanonical() or !ack.observed_revision.isCanonical()) return error.InvalidAck;
    if (ack.issued_at_ms < 0 or ack.expires_at_ms < ack.issued_at_ms) return error.InvalidAck;
}

fn validateAttachmentLeaseShape(lease: AttachmentLease) error{InvalidAttachmentLease}!void {
    if (lease.revision.origin_node == 0 or !lease.revision.isCanonical()) return error.InvalidAttachmentLease;
    if (lease.issued_at_ms < 0 or lease.expires_at_ms < lease.issued_at_ms) return error.InvalidAttachmentLease;
}

pub const ApplyDisposition = enum {
    inserted,
    duplicate,
    conflict,
    conflict_replaced,
    quarantined,
    stale,
    superseded,
    tombstoned,

    pub fn ackStatus(self: ApplyDisposition) AckStatus {
        return switch (self) {
            .inserted => .accepted,
            .duplicate => .duplicate,
            .conflict => .conflict,
            .conflict_replaced => .conflict,
            .quarantined => .conflict,
            .stale => .stale,
            .superseded => .superseded,
            .tombstoned => .tombstoned,
        };
    }
};

pub const ApplyResult = struct {
    disposition: ApplyDisposition,
    current_revision: Revision,
};

pub const RouteDisposition = enum {
    inserted,
    refreshed,
    ignored,
    stale,
};

/// ACKs are authenticated receipt metadata only. They never create an active
/// route because v2 ACKs carry no path vector with which to prevent loops.
pub const AckDisposition = enum {
    accepted,
    ignored,
    stale,
};

pub const ApplyError = VerifyError || error{
    EntryFull,
    Expired,
    IdentityConflict,
    InvalidLifetime,
    InvalidOffer,
    QuarantineFull,
    RouteFull,
    TombstoneFull,
    GroupRevokeFull,
    AccountMismatch,
} || std.mem.Allocator.Error;

pub const AckApplyError = VerifyError || error{
    Expired,
    InvalidLifetime,
};

pub const AttachmentLeaseDisposition = enum {
    inserted,
    duplicate,
    conflict,
    stale,
    superseded,
};

pub const AttachmentLeaseApplyError = VerifyError || error{
    AttachmentLeaseFull,
    Expired,
    InvalidAttachmentLease,
    InvalidLifetime,
} || std.mem.Allocator.Error;

pub const GroupRevokeError = ApplyError;
pub const GroupRevocation = struct {
    wire: []const u8,
    account: []const u8,
    revision: Revision,
    digest: Digest,
};

/// Caller serializes Store access from preparation through commit/abort. All
/// fallible work precedes the durable-write boundary; commit cannot allocate.
pub const PreparedGroupRevoke = struct {
    store: *Store,
    token: Token,
    wire: ?[]const u8 = null,
    done: bool = false,

    pub fn commit(self: *PreparedGroupRevoke) ApplyDisposition {
        std.debug.assert(!self.done);
        self.done = true;
        const wire = self.wire orelse return .duplicate;
        self.wire = null;
        const signed = decodeOffer(wire) catch unreachable;
        self.store.account_index.getPtr(accountDigest(signed.offer.account)).?.origins.appendAssumeCapacity(.{ .token = self.token, .origin_node = 0 });
        self.store.bumpInventoryAccount(signed.offer.account);
        self.store.group_revocations.putAssumeCapacityNoClobber(self.token, .{
            .wire = wire,
            .account = signed.offer.account,
            .revision = signed.offer.revision,
            .digest = digestBytes(signed.transcript),
        });
        self.store.removeStateForToken(self.token);
        self.store.removeLeasesForToken(self.token);
        return .inserted;
    }

    pub fn abort(self: *PreparedGroupRevoke) void {
        if (self.done) return;
        self.done = true;
        if (self.wire) |wire| {
            const signed = decodeOffer(wire) catch unreachable;
            const digest = accountDigest(signed.offer.account);
            if (self.store.account_index.getPtr(digest)) |origins| {
                if (origins.origins.items.len == 0) {
                    origins.origins.deinit(self.store.allocator);
                    _ = self.store.account_index.remove(digest);
                }
            }
            self.store.allocator.free(wire);
        }
        self.wire = null;
    }

    pub fn deinit(self: *PreparedGroupRevoke) void {
        self.abort();
    }
};

pub const InventoryCursor = struct {
    token: Token,
    origin_node: NodeId,
    attachment_id: [16]u8,

    pub fn compare(a: InventoryCursor, b: InventoryCursor) std.math.Order {
        const token_order = std.mem.order(u8, &a.token, &b.token);
        if (token_order != .eq) return token_order;
        const origin_order = std.math.order(a.origin_node, b.origin_node);
        if (origin_order != .eq) return origin_order;
        return std.mem.order(u8, &a.attachment_id, &b.attachment_id);
    }
};

/// Internal inventory only: token bytes must never be formatted for clients.
pub const InventoryRow = struct {
    token: Token,
    attachment_id: ?[16]u8,
    origin_node: NodeId,
    signon_ms: i64,
    /// Signed observation; only fresh=true permits treating it as current.
    attached: bool,
    fresh: bool,
    inventory_complete: bool,
    revoked: bool = false,

    pub fn cursor(self: InventoryRow) InventoryCursor {
        return .{ .token = self.token, .origin_node = self.origin_node, .attachment_id = self.attachment_id orelse @splat(0) };
    }
};

pub const InventoryPage = struct {
    integrity_ok: bool = true,
    items: []const InventoryRow,
    next: ?InventoryCursor,
    complete: bool,
};

/// Private volatile cursor. Never serialize or reuse across Store replacement;
/// daemon enumeration caches must be reset on restore/adopt.
pub const InventoryScanCursor = struct {
    account_digest: Digest,
    generation: u64,
    origin_index: usize,
    attachment_index: usize,
};

pub const max_inventory_scan_work: usize = 64;
pub const max_inventory_scan_rows: usize = 32;
pub const InventoryScanPage = struct {
    items: []const InventoryRow,
    next: ?InventoryScanCursor,
    complete: bool,
    integrity_ok: bool,
    generation: u64,
    work_used: usize,
};

const AccountInventoryIndex = struct {
    origins: std.ArrayListUnmanaged(Store.OriginKey) = .empty,
    generation: u64 = 0,
};

/// Complete current restart checkpoint for the authoritative SESSION_REPLICA
/// Store. This is carried inside Helix's backwards-compatible mesh-checkpoint
/// capsule family, so the inner magic must remain independently recognizable.
pub const upgrade_checkpoint_magic = [_]u8{ 'S', 'R', 'S', 'T' };
pub const upgrade_checkpoint_version: u8 = 3;
const upgrade_checkpoint_v2_version: u8 = 2;
const upgrade_checkpoint_v1_version: u8 = 1;
const upgrade_checkpoint_checksum_len = 32;
const upgrade_checkpoint_v1_header_len = upgrade_checkpoint_magic.len + 1 + 8 + 4 + 4 + 4;
const upgrade_checkpoint_v2_header_len = upgrade_checkpoint_v1_header_len + 4;
const upgrade_checkpoint_header_len = upgrade_checkpoint_v2_header_len + 4;

pub const UpgradeCheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    CapacityExceeded,
    DuplicateState,
    InvalidMetadata,
    InvalidSignedObject,
    TooLarge,
} || std.mem.Allocator.Error;

/// Core retry progress and its exact Store image form one hot-handoff cut.
/// The inner SRSTv3 authority format is unchanged and remains independently
/// usable at explicit Store/cold boundaries. Current Core requires this wrapper.
pub const core_checkpoint_magic = "SRHC";
pub const core_checkpoint_version: u8 = 1;
const core_checksum_domain = "onyx-session-replica-core-checkpoint-v1";
const core_fixed_bytes = 4 + 1 + 1 + 4 + 32;
pub const CoreCheckpointView = struct {
    orphan_revoke_cursor: ?Token,
    store_bytes: []const u8,
};

pub fn isCoreUpgradeCheckpoint(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, core_checkpoint_magic);
}

fn coreCheckpointDigest(bytes: []const u8) Digest {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(core_checksum_domain);
    hash.update(bytes);
    var out: Digest = undefined;
    hash.final(&out);
    return out;
}

pub fn encodeCoreUpgradeCheckpoint(allocator: std.mem.Allocator, store: *const Store, captured_at_ms: i64, cursor: ?Token) UpgradeCheckpointError![]u8 {
    const inner = try store.encodeUpgradeCheckpoint(allocator, captured_at_ms);
    defer allocator.free(inner);
    const extra: usize = if (cursor != null) @sizeOf(Token) else 0;
    if (inner.len > std.math.maxInt(u32)) return error.TooLarge;
    const size = std.math.add(usize, core_fixed_bytes + extra, inner.len) catch return error.TooLarge;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    @memcpy(out[0..4], core_checkpoint_magic);
    out[4] = core_checkpoint_version;
    out[5] = @intFromBool(cursor != null);
    var offset: usize = 6;
    if (cursor) |token| {
        @memcpy(out[offset..][0..@sizeOf(Token)], &token);
        offset += @sizeOf(Token);
    }
    std.mem.writeInt(u32, out[offset..][0..4], @intCast(inner.len), .big);
    offset += 4;
    @memcpy(out[offset..][0..inner.len], inner);
    const checksum = coreCheckpointDigest(out[0 .. size - 32]);
    @memcpy(out[size - 32 ..], &checksum);
    return out;
}

/// Allocation-free framing validation; signed Store validation still occurs in
/// restoreCurrentUpgradeCheckpoint before any candidate authority is published.
pub fn decodeCoreUpgradeCheckpoint(bytes: []const u8) UpgradeCheckpointError!CoreCheckpointView {
    if (!isCoreUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes.len < core_fixed_bytes) return error.Truncated;
    if (bytes[4] != core_checkpoint_version) return error.UnsupportedVersion;
    const cursor_present = switch (bytes[5]) {
        0 => false,
        1 => true,
        else => return error.InvalidMetadata,
    };
    var offset: usize = 6;
    var cursor: ?Token = null;
    if (cursor_present) {
        if (bytes.len < core_fixed_bytes + @sizeOf(Token)) return error.Truncated;
        cursor = bytes[offset..][0..@sizeOf(Token)].*;
        offset += @sizeOf(Token);
    }
    const length: usize = std.mem.readInt(u32, bytes[offset..][0..4], .big);
    offset += 4;
    const end = bytes.len - 32;
    if (length > end - offset) return error.Truncated;
    if (length != end - offset) return error.TrailingBytes;
    const expected = coreCheckpointDigest(bytes[0..end]);
    if (!std.crypto.timing_safe.eql(Digest, expected, bytes[end..][0..32].*)) return error.ChecksumMismatch;
    const inner = bytes[offset..end];
    if (!Store.isUpgradeCheckpoint(inner)) return error.BadMagic;
    if (inner.len <= upgrade_checkpoint_magic.len) return error.Truncated;
    if (inner[upgrade_checkpoint_magic.len] != upgrade_checkpoint_version) return error.UnsupportedVersion;
    return .{ .orphan_revoke_cursor = cursor, .store_bytes = inner };
}

pub const Store = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    entries: std.AutoHashMapUnmanaged(OriginKey, Entry) = .empty,
    attachment_leases: std.AutoHashMapUnmanaged(OriginKey, AttachmentLeaseEntry) = .empty,
    routes: std.AutoHashMapUnmanaged(RouteKey, RouteValue) = .empty,
    tombstones: std.AutoHashMapUnmanaged(OriginKey, Tombstone) = .empty,
    /// Count of `tombstones` with `soft_capped` set; the only quantity the
    /// `max_tombstones` soft cap applies to. Maintained by `dropTombstone`,
    /// `installTombstone`, and checkpoint restore.
    soft_capped_tombstones: usize = 0,
    quarantines: std.AutoHashMapUnmanaged(Token, Quarantine) = .empty,
    group_revocations: std.AutoHashMapUnmanaged(Token, GroupRevocation) = .empty,
    account_index: std.AutoHashMapUnmanaged(Digest, AccountInventoryIndex) = .empty,
    inventory_generation: u64 = 0,
    inventory_generation_exhausted: bool = false,
    inventory_source_visits: std.atomic.Value(usize) = .init(0),
    inventory_row_visits: std.atomic.Value(usize) = .init(0),

    pub const Config = struct {
        max_entries: usize = 4096,
        max_attachment_leases: usize = 4096,
        max_routes: usize = 16_384,
        max_tombstones: usize = 4096,
        max_quarantines: usize = 1024,
        max_group_revocations: usize = 4096,
        max_offer_lifetime_ms: u64 = 24 * 60 * 60 * 1000,
        max_attachment_lease_lifetime_ms: u64 = 5 * 60 * 1000,
        max_future_skew_ms: u64 = default_max_future_skew_ms,
        route_ttl_ms: u64 = 15 * 60 * 1000,
        tombstone_ttl_ms: u64 = 24 * 60 * 60 * 1000,
        max_account_bytes: usize = max_account_len,
        max_nick_bytes: usize = max_nick_len,
        max_snapshot_bytes: usize = max_snapshot_len,

        /// The revocation/retention view of this config; see
        /// `session_replica_revocation.validateRetentionConfig`.
        pub fn retention(self: Config) session_replica_revocation.RetentionConfig {
            return .{
                .max_entries = self.max_entries,
                .max_tombstones = self.max_tombstones,
                .tombstone_ttl_ms = self.tombstone_ttl_ms,
                .max_offer_lifetime_ms = self.max_offer_lifetime_ms,
                .max_future_skew_ms = self.max_future_skew_ms,
            };
        }
    };

    pub const Entry = struct {
        /// Exact canonical signed OFFER, owned by the Store. Variable semantic
        /// slices below borrow this stable heap allocation.
        wire: []const u8,
        account: []const u8,
        nick: []const u8,
        snapshot: []const u8,
        inventory: []const u8 = "",
        resume_eligible: bool,
        revision: Revision,
        issued_at_ms: i64,
        expires_at_ms: i64,
        updated_at_ms: i64,
        digest: Digest,
        /// First ingress selected for this exact authority revision. Reflected
        /// duplicates cannot add alternate parents; a newer revision reselects.
        ingress_peer: ?NodeId,
        /// Allocation-free deny marker used if full quarantine evidence cannot
        /// be installed under allocator or quarantine-capacity pressure.
        quarantine_until_ms: ?i64,
        /// T10 superseded-authority high-water marks: the greatest signed
        /// issuance and expiry of every revision of this (token, origin)
        /// accepted while this entry (or the tombstone it replaced) was
        /// retained. After a backward wall-clock step an older revision can
        /// carry a later window than the current one; a REVOKE minted from
        /// these marks, and the tombstone it leaves, outlive every such
        /// revision. In-memory only: SRSTv3 checkpoints carry no marks, so a
        /// restored entry starts from its own window (the pre-T10 bound).
        /// Read through `authorityIssuedHighWater`/`authorityExpiresHighWater`.
        authority_issued_hwm_ms: i64 = std.math.minInt(i64),
        authority_expires_hwm_ms: i64 = std.math.minInt(i64),

        pub fn authorityIssuedHighWater(self: Entry) i64 {
            return @max(self.issued_at_ms, self.authority_issued_hwm_ms);
        }

        pub fn authorityExpiresHighWater(self: Entry) i64 {
            return @max(self.expires_at_ms, self.authority_expires_hwm_ms);
        }
    };

    pub const AttachmentLeaseEntry = struct {
        wire: []const u8,
        revision: Revision,
        issued_at_ms: i64,
        expires_at_ms: i64,
        /// Retain the greatest accepted revision/conflict marker after positive
        /// liveness expires. Past this horizon every same-or-older legal lease
        /// is necessarily expired, so the bounded replay floor may be removed.
        replay_until_ms: i64,
        signer: sign.PublicKey,
        digest: Digest,
        /// Equal-revision transcript disagreement fails closed until a strictly
        /// newer, valid lease supersedes both observations.
        conflicted: bool,
        /// Second exact signed transcript proving the disagreement to replaying
        /// peers. Null with `conflicted=true` is an allocation-fallback deny
        /// marker; a later repeat retries witness capture.
        conflict_wire: ?[]const u8,
    };

    /// The authority scope for one attachment. One bearer token may have
    /// several simultaneous origin entries, but an origin has at most one live
    /// entry or tombstone for that token.
    pub const OriginKey = struct {
        token: Token,
        origin_node: NodeId,
    };

    pub const Route = struct {
        /// Anti-entropy provenance only: this is the first peer from which the
        /// signed authority fact was learned, not proof of live reachability.
        token: Token,
        destination: NodeId,
        next_hop: NodeId,
        revision: Revision,
        last_seen_ms: i64,
    };

    const RouteKey = struct {
        token: Token,
        destination: NodeId,
        next_hop: NodeId,
    };

    const RouteValue = struct {
        revision: Revision,
        last_seen_ms: i64,
    };

    pub const Tombstone = struct {
        /// Exact canonical signed REVOKE, owned by the Store.
        wire: []const u8,
        revision: Revision,
        removed_at_ms: i64,
        /// Signed REVOKE expiry: the anti-entropy export horizon
        /// (`session_replica_revocation.tombstoneExportable`).
        offer_expires_at_ms: i64,
        /// Inclusive local resurrection-block horizon
        /// (`session_replica_revocation.tombstoneRetainUntil`); never shorter
        /// than the superseded authority's expiry. In-memory only: checkpoint
        /// restore recomputes it from `removed_at_ms` and the signed REVOKE.
        retain_until_ms: i64,
        digest: Digest,
        /// Binds a removed origin to the token's account identity while replay
        /// protection is active. Unknown-token removals have no identity yet.
        identity_digest: ?Digest,
        quarantine_until_ms: ?i64,
        /// Installed without converting a live entry of this origin
        /// (unknown-token churn, or a REVOKE delivered ahead of its OFFER), so
        /// it counts against `max_tombstones`. A conversion never does; a
        /// newer REVOKE replacing a tombstone in place inherits this flag.
        soft_capped: bool,
    };

    pub const Quarantine = struct {
        first_wire: []const u8,
        second_wire: []const u8,
        expires_at_ms: i64,
        detected_at_ms: i64,
    };

    pub const RetainedKind = enum {
        offer,
        revoke,
        attachment_lease,
        group_revoke,
    };

    fn retainedKindRank(kind: RetainedKind) u8 {
        return switch (kind) {
            .offer => 0,
            .revoke => 1,
            .attachment_lease => 2,
            .group_revoke => 3,
        };
    }

    /// Mutation-independent position in the retained signed-object order.
    /// Every field is a value: callers never retain a hash-map iterator or a
    /// pointer into Store-owned memory between pages. The transcript digest is
    /// the final discriminator for equal-revision equivocation witnesses.
    pub const RetainedCursor = struct {
        token: Token,
        kind: RetainedKind,
        origin_node: NodeId,
        revision: Revision,
        digest: Digest,

        pub fn compare(a: RetainedCursor, b: RetainedCursor) std.math.Order {
            const token_order = std.mem.order(u8, &a.token, &b.token);
            if (token_order != .eq) return token_order;
            const kind_order = std.math.order(retainedKindRank(a.kind), retainedKindRank(b.kind));
            if (kind_order != .eq) return kind_order;
            const origin_order = std.math.order(a.origin_node, b.origin_node);
            if (origin_order != .eq) return origin_order;
            const revision_order = a.revision.compare(b.revision);
            if (revision_order != .eq) return revision_order;
            return std.mem.order(u8, &a.digest, &b.digest);
        }

        pub fn eql(a: RetainedCursor, b: RetainedCursor) bool {
            return a.compare(b) == .eq;
        }
    };

    /// Borrowed retransmission view. `wire` stays valid until the corresponding
    /// Store origin is superseded, swept, or the Store is deinitialized.
    pub const RetainedObject = struct {
        kind: RetainedKind,
        token: Token,
        origin_node: NodeId,
        revision: Revision,
        expires_at_ms: i64,
        wire: []const u8,
        digest: Digest,

        pub fn cursor(self: RetainedObject) RetainedCursor {
            return .{
                .token = self.token,
                .kind = self.kind,
                .origin_node = self.origin_node,
                .revision = self.revision,
                .digest = self.digest,
            };
        }
    };

    pub const SweepResult = struct {
        entries: usize = 0,
        attachment_leases: usize = 0,
        routes: usize = 0,
        tombstones: usize = 0,
        quarantines: usize = 0,
    };

    pub fn init(allocator: std.mem.Allocator) Store {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) Store {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    pub fn deinit(self: *Store) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| freeEntry(self.allocator, entry.*);
        var lease_it = self.attachment_leases.valueIterator();
        while (lease_it.next()) |lease| freeAttachmentLease(self.allocator, lease.*);
        var tombstone_it = self.tombstones.valueIterator();
        while (tombstone_it.next()) |tombstone| freeTombstone(self.allocator, tombstone.*);
        var quarantine_it = self.quarantines.valueIterator();
        while (quarantine_it.next()) |quarantine| freeQuarantine(self.allocator, quarantine.*);
        var groups = self.group_revocations.valueIterator();
        while (groups.next()) |group| self.allocator.free(group.wire);
        self.group_revocations.deinit(self.allocator);
        var accounts = self.account_index.valueIterator();
        while (accounts.next()) |account| account.origins.deinit(self.allocator);
        self.account_index.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.attachment_leases.deinit(self.allocator);
        self.routes.deinit(self.allocator);
        self.tombstones.deinit(self.allocator);
        self.quarantines.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isGroupRevoked(self: *const Store, account: []const u8, token: Token) bool {
        const group = self.group_revocations.get(token) orelse return false;
        return std.ascii.eqlIgnoreCase(group.account, account);
    }

    pub fn groupRevokeForToken(self: *const Store, token: Token) ?*const GroupRevocation {
        return @constCast(&self.group_revocations).getPtr(token);
    }

    pub fn prepareGroupRevoke(self: *Store, signed: SignedOffer, now_ms: i64) GroupRevokeError!PreparedGroupRevoke {
        try verifyOffer(signed);
        const offer = signed.offer;
        if (offer.operation != .group_revoke) return error.InvalidOffer;
        try self.validateOfferForStore(offer, now_ms);
        if (self.group_revocations.get(offer.token)) |old| {
            if (!std.ascii.eqlIgnoreCase(old.account, offer.account)) return error.AccountMismatch;
            return .{ .store = self, .token = offer.token };
        }
        var entries = self.entries.iterator();
        while (entries.next()) |entry| {
            if (tokenEql(entry.key_ptr.token, offer.token) and !std.ascii.eqlIgnoreCase(entry.value_ptr.account, offer.account)) return error.AccountMismatch;
        }
        const expected = accountDigest(offer.account);
        var tombstones = self.tombstones.iterator();
        while (tombstones.next()) |entry| {
            if (!tokenEql(entry.key_ptr.token, offer.token)) continue;
            if (entry.value_ptr.identity_digest) |bound| {
                if (!std.crypto.timing_safe.eql(Digest, expected, bound)) return error.AccountMismatch;
            }
        }
        if (self.quarantines.contains(offer.token)) return error.IdentityConflict;
        if (self.group_revocations.count() >= self.cfg.max_group_revocations) return error.GroupRevokeFull;
        const wire = try ownSignedOffer(self.allocator, signed);
        errdefer self.allocator.free(wire);
        try self.group_revocations.ensureUnusedCapacity(self.allocator, 1);
        const added = try self.reserveAccountOrigin(offer.account, .{ .token = offer.token, .origin_node = 0 });
        std.debug.assert(added);
        return .{ .store = self, .token = offer.token, .wire = wire };
    }

    /// Visits only the selected folded account's origin index. Revocations are
    /// separately bounded and retained forever; their account filter never
    /// exposes another account's token or attachment metadata.
    pub fn accountInventoryPageInto(self: *const Store, account: []const u8, now_ms: i64, after: ?InventoryCursor, out: []InventoryRow) InventoryPage {
        var count: usize = 0;
        var eligible: usize = 0;
        var integrity_ok = true;
        const requested_account = accountDigest(account);
        if (self.account_index.get(requested_account)) |origins| {
            for (origins.origins.items) |key| {
                if (builtin.is_test) _ = @constCast(&self.inventory_source_visits).fetchAdd(1, .monotonic);
                if (key.origin_node == 0) {
                    const group = self.group_revocations.get(key.token) orelse {
                        integrity_ok = false;
                        continue;
                    };
                    if (!std.crypto.timing_safe.eql(Digest, requested_account, accountDigest(group.account))) {
                        integrity_ok = false;
                        continue;
                    }
                    considerInventory(after, .{ .token = key.token, .attachment_id = null, .origin_node = group.revision.origin_node, .signon_ms = 0, .attached = false, .fresh = true, .inventory_complete = true, .revoked = true }, out, &count, &eligible);
                    continue;
                }
                const entry = @constCast(&self.entries).getPtr(key) orelse {
                    integrity_ok = false;
                    continue;
                };
                // The index is acceleration, never account authorization. A
                // corrupt/stale locator cannot expose another account's rows.
                if (!std.crypto.timing_safe.eql(Digest, requested_account, accountDigest(entry.account))) {
                    integrity_ok = false;
                    continue;
                }
                if (entry.quarantine_until_ms != null or self.quarantines.contains(key.token)) continue;
                const signed = decodeOffer(entry.wire) catch unreachable;
                const inventory = Inventory{ .bytes = entry.inventory };
                const complete = signed.offer.operation == .inventory_upsert;
                const lease_live = if (self.attachment_leases.get(key)) |lease|
                    !lease.conflicted and now_ms <= lease.expires_at_ms and lease.revision.compare(entry.revision) == .gt and
                        std.crypto.timing_safe.eql(sign.PublicKey, lease.signer, signed.signer)
                else
                    false;
                if (!complete) {
                    considerInventory(after, .{ .token = key.token, .attachment_id = null, .origin_node = key.origin_node, .signon_ms = 0, .attached = false, .fresh = false, .inventory_complete = false }, out, &count, &eligible);
                } else for (0..inventory.count()) |i| {
                    const row = inventory.at(i);
                    considerInventory(after, .{ .token = key.token, .attachment_id = row.attachment_id, .origin_node = key.origin_node, .signon_ms = row.signon_ms, .attached = row.attached, .fresh = now_ms <= entry.expires_at_ms and (!row.attached or lease_live), .inventory_complete = true }, out, &count, &eligible);
                }
            }
        }
        return .{ .items = out[0..count], .next = if (count == 0) after else out[count - 1].cursor(), .complete = integrity_ok and eligible <= count, .integrity_ok = integrity_ok };
    }

    /// Account-index traversal, bounded by both physical output and source work.
    /// No lexical rescan, complete signed-offer decode, allocation or global
    /// census occurs here. `complete` means end of this structural scan; lease
    /// freshness is sampled per call and is not an atomic account snapshot.
    pub fn accountInventoryBatchInto(self: *const Store, account: []const u8, now_ms: i64, after: ?InventoryScanCursor, out: []InventoryRow) error{ StaleCursor, InvalidCursor }!InventoryScanPage {
        if (account.len == 0 or account.len > max_account_len) return error.InvalidCursor;
        const digest = accountDigest(account);
        if (after) |cursor| {
            if (!std.crypto.timing_safe.eql(Digest, digest, cursor.account_digest) or cursor.generation == 0)
                return error.InvalidCursor;
        }
        if (self.inventory_generation_exhausted) return error.StaleCursor;
        const bucket = self.account_index.get(digest) orelse {
            if (after != null) return error.StaleCursor;
            return .{ .items = out[0..0], .next = null, .complete = true, .integrity_ok = true, .generation = 0, .work_used = 0 };
        };
        if (after) |cursor| if (cursor.generation != bucket.generation) return error.StaleCursor;
        var cursor = after orelse InventoryScanCursor{ .account_digest = digest, .generation = bucket.generation, .origin_index = 0, .attachment_index = 0 };
        if (cursor.origin_index > bucket.origins.items.len or
            (cursor.origin_index == bucket.origins.items.len and cursor.attachment_index != 0)) return error.InvalidCursor;
        var count: usize = 0;
        var work: usize = 0;
        var integrity_ok = true;
        const limit = @min(out.len, max_inventory_scan_rows);
        scan: while (cursor.origin_index < bucket.origins.items.len and count < limit and work < max_inventory_scan_work) {
            work += 1;
            if (builtin.is_test) _ = @constCast(&self.inventory_source_visits).fetchAdd(1, .monotonic);
            const key = bucket.origins.items[cursor.origin_index];
            if (key.origin_node == 0) {
                if (cursor.attachment_index != 0) return error.InvalidCursor;
                const group = self.group_revocations.get(key.token) orelse {
                    integrity_ok = false;
                    break;
                };
                if (group.account.len > max_account_len or !std.crypto.timing_safe.eql(Digest, digest, accountDigest(group.account))) {
                    integrity_ok = false;
                    break;
                }
                if (work == max_inventory_scan_work) break;
                work += 1;
                if (builtin.is_test) _ = @constCast(&self.inventory_row_visits).fetchAdd(1, .monotonic);
                out[count] = .{ .token = key.token, .attachment_id = null, .origin_node = group.revision.origin_node, .signon_ms = 0, .attached = false, .fresh = true, .inventory_complete = true, .revoked = true };
                count += 1;
            } else {
                const entry = self.entries.getPtr(key) orelse {
                    integrity_ok = false;
                    break;
                };
                // This selector index is never authorization. Even an invalid
                // stored locator/image cannot expose foreign account metadata.
                if (entry.account.len > max_account_len or !std.crypto.timing_safe.eql(Digest, digest, accountDigest(entry.account)) or
                    entry.wire.len < offer_fixed_len + signature_wire_len or
                    entry.wire.len > session_replica_transport.max_signed_payload_len or
                    !std.mem.eql(u8, entry.wire[0..offer_magic.len], &offer_magic) or
                    entry.inventory.len % inventory_row_len != 0 or entry.inventory.len / inventory_row_len > max_inventory_attachments)
                {
                    integrity_ok = false;
                    break;
                }
                const operation = entry.wire[offer_magic.len];
                const complete = operation == @backingInt(OfferOperation.inventory_upsert);
                if ((!complete and operation != @backingInt(OfferOperation.upsert)) or (!complete and entry.inventory.len != 0)) {
                    integrity_ok = false;
                    break;
                }
                const inventory = Inventory{ .bytes = entry.inventory };
                const row_count = if (complete) inventory.count() else 1;
                if (cursor.attachment_index >= row_count and !(row_count == 0 and cursor.attachment_index == 0)) return error.InvalidCursor;
                if (entry.quarantine_until_ms == null and !self.quarantines.contains(key.token)) {
                    // The canonical image was authenticated at admission. Read
                    // only its bounded fixed operation and signer suffix here.
                    const signer = entry.wire[entry.wire.len - signature_wire_len ..][0..@sizeOf(sign.PublicKey)].*;
                    const lease_live = if (self.attachment_leases.get(key)) |lease|
                        !lease.conflicted and now_ms <= lease.expires_at_ms and lease.revision.compare(entry.revision) == .gt and
                            std.crypto.timing_safe.eql(sign.PublicKey, lease.signer, signer)
                    else
                        false;
                    while (cursor.attachment_index < row_count) {
                        if (count == limit or work == max_inventory_scan_work) break :scan;
                        work += 1;
                        if (builtin.is_test) _ = @constCast(&self.inventory_row_visits).fetchAdd(1, .monotonic);
                        if (complete) {
                            const row = inventory.at(cursor.attachment_index);
                            const unordered = if (cursor.attachment_index > 0)
                                std.mem.order(u8, entry.inventory[(cursor.attachment_index - 1) * inventory_row_len ..][0..16], &row.attachment_id) != .lt
                            else
                                false;
                            if (std.mem.allEqual(u8, &row.attachment_id, 0) or row.signon_ms < 0 or entry.inventory[cursor.attachment_index * inventory_row_len + 24] > 1 or unordered) {
                                integrity_ok = false;
                                break :scan;
                            }
                            out[count] = .{ .token = key.token, .attachment_id = row.attachment_id, .origin_node = key.origin_node, .signon_ms = row.signon_ms, .attached = row.attached, .fresh = now_ms <= entry.expires_at_ms and (!row.attached or lease_live), .inventory_complete = true };
                        } else out[count] = .{ .token = key.token, .attachment_id = null, .origin_node = key.origin_node, .signon_ms = 0, .attached = false, .fresh = false, .inventory_complete = false };
                        count += 1;
                        cursor.attachment_index += 1;
                    }
                }
            }
            cursor.origin_index += 1;
            cursor.attachment_index = 0;
        }
        const complete = integrity_ok and cursor.origin_index == bucket.origins.items.len;
        return .{ .items = out[0..count], .next = if (complete or !integrity_ok) null else cursor, .complete = complete, .integrity_ok = integrity_ok, .generation = bucket.generation, .work_used = work };
    }

    // Derived cursor generations are published only after every fallible
    // reservation. Exhaustion disables scans rather than reusing a generation.
    fn bumpInventoryAccount(self: *Store, account: []const u8) void {
        if (self.inventory_generation == std.math.maxInt(u64)) {
            self.inventory_generation_exhausted = true;
            return;
        }
        self.inventory_generation += 1;
        if (self.account_index.getPtr(accountDigest(account))) |bucket|
            bucket.generation = self.inventory_generation;
    }

    fn reserveAccountOrigin(self: *Store, account: []const u8, key: OriginKey) std.mem.Allocator.Error!bool {
        const digest = accountDigest(account);
        if (self.account_index.getPtr(digest)) |bucket| {
            for (bucket.origins.items) |old| if (std.meta.eql(old, key)) return false;
            try bucket.origins.ensureUnusedCapacity(self.allocator, 1);
        } else {
            var bucket: AccountInventoryIndex = .{};
            errdefer bucket.origins.deinit(self.allocator);
            try bucket.origins.ensureUnusedCapacity(self.allocator, 1);
            try self.account_index.put(self.allocator, digest, bucket);
        }
        return true;
    }

    fn removeAccountOrigin(self: *Store, account: []const u8, key: OriginKey) void {
        const digest = accountDigest(account);
        const bucket = self.account_index.getPtr(digest) orelse unreachable;
        for (bucket.origins.items, 0..) |old, i| {
            if (!std.meta.eql(old, key)) continue;
            self.bumpInventoryAccount(account);
            _ = bucket.origins.swapRemove(i);
            if (bucket.origins.items.len == 0) {
                bucket.origins.deinit(self.allocator);
                _ = self.account_index.remove(digest);
            }
            return;
        }
        unreachable;
    }

    fn removeLeasesForToken(self: *Store, token: Token) void {
        while (true) {
            var victim: ?OriginKey = null;
            var entries = self.attachment_leases.keyIterator();
            while (entries.next()) |key| if (tokenEql(key.token, token)) {
                victim = key.*;
                break;
            };
            const key = victim orelse break;
            const removed = self.attachment_leases.fetchRemove(key).?;
            freeAttachmentLease(self.allocator, removed.value);
        }
    }

    /// Cheap discriminator for Helix mesh-checkpoint capsules. Full integrity,
    /// version, signature, and invariant checks happen during restore.
    pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
        return bytes.len >= upgrade_checkpoint_magic.len and
            std.mem.eql(u8, bytes[0..upgrade_checkpoint_magic.len], &upgrade_checkpoint_magic);
    }

    /// Encode every authoritative Store fact and its non-derived metadata.
    /// Hop routes and ingress parents are deliberately omitted: they are link
    /// observations and must be relearned after exec, not resurrected.
    pub fn encodeUpgradeCheckpoint(
        self: *const Store,
        allocator: std.mem.Allocator,
        captured_at_ms: i64,
    ) UpgradeCheckpointError![]u8 {
        if (captured_at_ms < 0) return error.InvalidMetadata;
        if (self.entries.count() > std.math.maxInt(u32) or
            self.attachment_leases.count() > std.math.maxInt(u32) or
            self.tombstones.count() > std.math.maxInt(u32) or
            self.quarantines.count() > std.math.maxInt(u32) or
            self.group_revocations.count() > std.math.maxInt(u32)) return error.TooLarge;

        var total_len: usize = upgrade_checkpoint_header_len;
        var entry_it = @constCast(&self.entries).valueIterator();
        while (entry_it.next()) |entry| {
            try checkpointAddLen(&total_len, 4);
            try checkpointAddLen(&total_len, entry.wire.len);
            try checkpointAddLen(&total_len, 8 + 1);
            if (entry.quarantine_until_ms != null) try checkpointAddLen(&total_len, 8);
        }
        var tombstone_it = @constCast(&self.tombstones).valueIterator();
        while (tombstone_it.next()) |tombstone| {
            try checkpointAddLen(&total_len, 4);
            try checkpointAddLen(&total_len, tombstone.wire.len);
            try checkpointAddLen(&total_len, 8 + 1 + 1);
            if (tombstone.identity_digest != null) try checkpointAddLen(&total_len, @sizeOf(Digest));
            if (tombstone.quarantine_until_ms != null) try checkpointAddLen(&total_len, 8);
        }
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            try checkpointAddLen(&total_len, 4);
            try checkpointAddLen(&total_len, quarantine.first_wire.len);
            try checkpointAddLen(&total_len, 4);
            try checkpointAddLen(&total_len, quarantine.second_wire.len);
            try checkpointAddLen(&total_len, 8 + 8);
        }
        var attachment_lease_it = @constCast(&self.attachment_leases).valueIterator();
        while (attachment_lease_it.next()) |lease| {
            try checkpointAddLen(&total_len, 4);
            try checkpointAddLen(&total_len, lease.wire.len);
            try checkpointAddLen(&total_len, 1);
            if (lease.conflict_wire) |wire| {
                try checkpointAddLen(&total_len, 4);
                try checkpointAddLen(&total_len, wire.len);
            }
        }
        var groups = @constCast(&self.group_revocations).valueIterator();
        while (groups.next()) |group| {
            try checkpointAddLen(&total_len, 4 + group.wire.len);
        }
        try checkpointAddLen(&total_len, upgrade_checkpoint_checksum_len);

        var out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = Writer{ .bytes = out };
        writer.writeBytes(&upgrade_checkpoint_magic);
        writer.writeByte(upgrade_checkpoint_version);
        writer.writeI64(captured_at_ms);
        writer.writeU32(@intCast(self.entries.count()));
        writer.writeU32(@intCast(self.tombstones.count()));
        writer.writeU32(@intCast(self.quarantines.count()));
        writer.writeU32(@intCast(self.attachment_leases.count()));
        writer.writeU32(@intCast(self.group_revocations.count()));

        entry_it = @constCast(&self.entries).valueIterator();
        while (entry_it.next()) |entry| {
            try checkpointWriteWire(&writer, entry.wire);
            writer.writeI64(entry.updated_at_ms);
            writer.writeByte(@intFromBool(entry.quarantine_until_ms != null));
            if (entry.quarantine_until_ms) |until_ms| writer.writeI64(until_ms);
        }
        tombstone_it = @constCast(&self.tombstones).valueIterator();
        while (tombstone_it.next()) |tombstone| {
            try checkpointWriteWire(&writer, tombstone.wire);
            writer.writeI64(tombstone.removed_at_ms);
            writer.writeByte(@intFromBool(tombstone.identity_digest != null));
            if (tombstone.identity_digest) |identity_digest| writer.writeBytes(&identity_digest);
            writer.writeByte(@intFromBool(tombstone.quarantine_until_ms != null));
            if (tombstone.quarantine_until_ms) |until_ms| writer.writeI64(until_ms);
        }
        quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            try checkpointWriteWire(&writer, quarantine.first_wire);
            try checkpointWriteWire(&writer, quarantine.second_wire);
            writer.writeI64(quarantine.expires_at_ms);
            writer.writeI64(quarantine.detected_at_ms);
        }
        attachment_lease_it = @constCast(&self.attachment_leases).valueIterator();
        while (attachment_lease_it.next()) |lease| {
            try checkpointWriteWire(&writer, lease.wire);
            writer.writeByte(if (!lease.conflicted) 0 else if (lease.conflict_wire != null) 1 else 2);
            if (lease.conflict_wire) |wire| try checkpointWriteWire(&writer, wire);
        }

        groups = @constCast(&self.group_revocations).valueIterator();
        while (groups.next()) |group| try checkpointWriteWire(&writer, group.wire);

        std.debug.assert(writer.pos + upgrade_checkpoint_checksum_len == out.len);
        const checksum = digestBytes(out[0..writer.pos]);
        writer.writeBytes(&checksum);
        std.debug.assert(writer.pos == out.len);
        return out;
    }

    /// Decode into a fresh Store, validating the whole checkpoint before any
    /// caller-visible state can change. Signed facts are validated at capture
    /// time so a harmless wall-clock rollback cannot invalidate an accepted
    /// checkpoint; expiry is then swept at the restore wall time.
    fn restoreVersionedUpgradeCheckpoint(
        allocator: std.mem.Allocator,
        cfg: Config,
        bytes: []const u8,
        restore_now_ms: i64,
        allow_cold_legacy: bool,
    ) UpgradeCheckpointError!Store {
        if (bytes.len < upgrade_checkpoint_v1_header_len + upgrade_checkpoint_checksum_len) return error.Truncated;
        if (!Store.isUpgradeCheckpoint(bytes)) return error.BadMagic;

        const body_end = bytes.len - upgrade_checkpoint_checksum_len;
        const expected_checksum: Digest = bytes[body_end..][0..upgrade_checkpoint_checksum_len].*;
        const actual_checksum = digestBytes(bytes[0..body_end]);
        if (!std.crypto.timing_safe.eql(Digest, expected_checksum, actual_checksum)) return error.ChecksumMismatch;

        var reader = UpgradeCheckpointReader{ .bytes = bytes[0..body_end] };
        _ = try reader.take(upgrade_checkpoint_magic.len);
        const version = try reader.readByte();
        if (version != upgrade_checkpoint_version and
            !(allow_cold_legacy and (version == upgrade_checkpoint_v1_version or version == upgrade_checkpoint_v2_version))) return error.UnsupportedVersion;
        const captured_at_ms = try reader.readI64();
        if (captured_at_ms < 0) return error.InvalidMetadata;
        const entry_count: usize = try reader.readU32();
        const tombstone_count: usize = try reader.readU32();
        const quarantine_count: usize = try reader.readU32();
        const attachment_lease_count: usize = if (version >= upgrade_checkpoint_v2_version)
            try reader.readU32()
        else
            0;
        const group_count: usize = if (version >= upgrade_checkpoint_version) try reader.readU32() else 0;
        // Live-entry conversions may legitimately grow tombstones past their
        // soft cap, so restore enforces the same combined origin-slot bound
        // the Store itself maintains rather than rejecting a valid image.
        if (group_count > cfg.max_group_revocations or entry_count > cfg.max_entries or
            entry_count +| tombstone_count > session_replica_revocation.combinedSlots(cfg.retention()) or
            quarantine_count > cfg.max_quarantines or
            attachment_lease_count > cfg.max_attachment_leases)
            return error.CapacityExceeded;

        // Reject impossible record counts before reserving any map storage.
        // These are deliberately conservative minima (one-byte wire), while
        // each record's exact signed-wire bound is enforced as it is read.
        var minimum_record_bytes: usize = 0;
        try checkpointAddProduct(&minimum_record_bytes, entry_count, 4 + 1 + 8 + 1);
        try checkpointAddProduct(&minimum_record_bytes, tombstone_count, 4 + 1 + 8 + 1 + 1);
        try checkpointAddProduct(&minimum_record_bytes, quarantine_count, 4 + 1 + 4 + 1 + 8 + 8);
        try checkpointAddProduct(&minimum_record_bytes, attachment_lease_count, 4 + 1 + 1);
        try checkpointAddProduct(&minimum_record_bytes, group_count, 4 + 1);
        if (minimum_record_bytes > reader.bytes.len - reader.pos) return error.Truncated;

        var restored = initWithConfig(allocator, cfg);
        errdefer restored.deinit();
        try restored.entries.ensureTotalCapacity(allocator, @intCast(entry_count));
        try restored.attachment_leases.ensureTotalCapacity(allocator, @intCast(attachment_lease_count));
        try restored.tombstones.ensureTotalCapacity(allocator, @intCast(tombstone_count));
        try restored.quarantines.ensureTotalCapacity(allocator, @intCast(quarantine_count));

        for (0..entry_count) |_| {
            const wire = try checkpointReadWire(&reader);
            const updated_at_ms = try reader.readI64();
            const quarantine_until_ms = try checkpointReadOptionalI64(&reader);
            try restored.restoreCheckpointEntry(wire, updated_at_ms, quarantine_until_ms, captured_at_ms);
        }
        for (0..tombstone_count) |_| {
            const wire = try checkpointReadWire(&reader);
            const removed_at_ms = try reader.readI64();
            const identity_digest = try checkpointReadOptionalDigest(&reader);
            const quarantine_until_ms = try checkpointReadOptionalI64(&reader);
            try restored.restoreCheckpointTombstone(wire, removed_at_ms, identity_digest, quarantine_until_ms, captured_at_ms);
        }
        for (0..quarantine_count) |_| {
            const first_wire = try checkpointReadWire(&reader);
            const second_wire = try checkpointReadWire(&reader);
            const expires_at_ms = try reader.readI64();
            const detected_at_ms = try reader.readI64();
            try restored.restoreCheckpointQuarantine(first_wire, second_wire, expires_at_ms, detected_at_ms, captured_at_ms);
        }
        for (0..attachment_lease_count) |_| {
            const wire = try checkpointReadWire(&reader);
            const conflict_tag = try reader.readByte();
            const conflict_wire: ?[]const u8 = switch (conflict_tag) {
                0, 2 => null,
                1 => try checkpointReadWire(&reader),
                else => return error.InvalidMetadata,
            };
            try restored.restoreCheckpointAttachmentLease(wire, conflict_tag != 0, conflict_wire, captured_at_ms);
        }
        for (0..group_count) |_| {
            const wire = try checkpointReadWire(&reader);
            const signed = restored.validateCheckpointSignedOffer(wire, .group_revoke, captured_at_ms) catch return error.InvalidSignedObject;
            const token = signed.offer.token;
            if (restored.group_revocations.contains(token) or restored.hasAnyCheckpointState(token) or restored.quarantines.contains(token)) return error.DuplicateState;
            var leases = restored.attachment_leases.keyIterator();
            while (leases.next()) |key| if (tokenEql(key.token, token)) return error.DuplicateState;
            var ticket = restored.prepareGroupRevoke(signed, captured_at_ms) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidMetadata,
            };
            defer ticket.deinit();
            _ = ticket.commit();
        }
        if (reader.pos != reader.bytes.len) return error.TrailingBytes;

        // Cross-map invariants are checked only after all facts are present.
        try restored.validateCheckpointIdentityState();
        _ = restored.sweep(restore_now_ms);
        return restored;
    }

    /// Current Helix and durable staging require every current state family,
    /// including terminal group fences. Legacy omissions are never inferred.
    pub fn restoreUpgradeCheckpoint(allocator: std.mem.Allocator, cfg: Config, bytes: []const u8, restore_now_ms: i64) UpgradeCheckpointError!Store {
        return restoreVersionedUpgradeCheckpoint(allocator, cfg, bytes, restore_now_ms, false);
    }

    pub fn restoreCurrentUpgradeCheckpoint(allocator: std.mem.Allocator, cfg: Config, bytes: []const u8, restore_now_ms: i64) UpgradeCheckpointError!Store {
        return restoreUpgradeCheckpoint(allocator, cfg, bytes, restore_now_ms);
    }

    /// Explicit accepted cold-migration boundary; callers must restore durable
    /// group fences before publishing this detached legacy store.
    pub fn restoreColdMigrationCheckpoint(allocator: std.mem.Allocator, cfg: Config, bytes: []const u8, restore_now_ms: i64) UpgradeCheckpointError!Store {
        return restoreVersionedUpgradeCheckpoint(allocator, cfg, bytes, restore_now_ms, true);
    }

    /// Atomically replace this Store. On corruption, capacity pressure, or OOM,
    /// `self` remains byte-for-byte owned and usable.
    pub fn replaceFromUpgradeCheckpoint(
        self: *Store,
        bytes: []const u8,
        restore_now_ms: i64,
    ) UpgradeCheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, self.cfg, bytes, restore_now_ms);
        errdefer replacement.deinit();
        var groups = self.group_revocations.iterator();
        while (groups.next()) |group| {
            if (!replacement.isGroupRevoked(group.value_ptr.account, group.key_ptr.*)) return error.InvalidMetadata;
        }
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
    }

    /// Verify and converge a signed OFFER learned through `via_peer`. Zero means
    /// locally seeded state and deliberately creates no route.
    pub fn applySignedOffer(self: *Store, signed: SignedOffer, via_peer: NodeId, now_ms: i64) ApplyError!ApplyResult {
        return self.applySignedOfferInner(signed, via_peer, now_ms, null);
    }
    /// Signature-only memo. Caller must recheck current issuer/cohort authority
    /// and authenticated peer before every call; no trust is cached here.
    pub fn applySignedOfferMemoized(self: *Store, signed: SignedOffer, via_peer: NodeId, now_ms: i64, memo: *OfferSignatureMemo, authority: OfferMemoAuthority) ApplyError!ApplyResult {
        return self.applySignedOfferInner(signed, via_peer, now_ms, .{ .memo = memo, .authority = authority });
    }
    const MemoInput = struct { memo: *OfferSignatureMemo, authority: OfferMemoAuthority };
    fn applySignedOfferInner(self: *Store, signed: SignedOffer, via_peer: NodeId, now_ms: i64, memo: ?MemoInput) ApplyError!ApplyResult {
        const offer = signed.offer;
        if (offer.operation == .group_revoke) {
            var prepared = try self.prepareGroupRevoke(signed, now_ms);
            defer prepared.deinit();
            const disposition = prepared.commit();
            return .{ .disposition = disposition, .current_revision = self.group_revocations.get(offer.token).?.revision };
        }
        if (memo) |m| try m.memo.verify(signed, m.authority, now_ms) else try verifyOffer(signed);
        try self.validateOfferForStore(offer, now_ms);
        if (self.group_revocations.get(offer.token)) |group| return .{ .disposition = .tombstoned, .current_revision = group.revision };
        const digest = digestBytes(signed.transcript);
        return self.applyVerifiedOffer(signed, digest, via_peer, now_ms);
    }

    /// Verify a signed ACK as receipt metadata. No route is installed: ACK v2
    /// has no path vector, so treating its ingress as reachability can form a
    /// loop when the receipt is forwarded or reflected.
    pub fn applySignedAck(self: *Store, signed: SignedAck, via_peer: NodeId, now_ms: i64) AckApplyError!AckDisposition {
        try verifyAck(signed);
        const ack = signed.ack;
        try validateLifetime(ack.issued_at_ms, ack.expires_at_ms, now_ms, self.cfg.max_offer_lifetime_ms, self.cfg.max_future_skew_ms);
        try validateRevisionAt(ack.offered_revision, now_ms, self.cfg.max_future_skew_ms);
        try validateRevisionAt(ack.observed_revision, now_ms, self.cfg.max_future_skew_ms);
        if (via_peer == 0) return .ignored;
        switch (ack.status) {
            .accepted, .duplicate, .superseded => {},
            .conflict, .stale, .tombstoned, .capacity, .current_ready, .group_revoked => return .ignored,
        }
        if (ack.offered_revision.origin_node != ack.observed_revision.origin_node) return .stale;
        if (!ack.offered_revision.eql(ack.observed_revision)) return .stale;
        const origin = ack.observed_revision.origin_node;
        const current = self.getOrigin(ack.token, origin) orelse return .stale;
        if (!current.revision.eql(ack.observed_revision)) return .stale;
        return .accepted;
    }

    /// Converge a positive short-lived attachment lease independently of OFFER
    /// arrival order. It remains inert until a matching signed OFFER exists and
    /// its revision is strictly older than the lease.
    pub fn applySignedAttachmentLease(
        self: *Store,
        signed: SignedAttachmentLease,
        now_ms: i64,
    ) AttachmentLeaseApplyError!AttachmentLeaseDisposition {
        try verifyAttachmentLease(signed);
        const lease = signed.lease;
        if (self.group_revocations.contains(lease.token)) return .stale;
        validateAttachmentLeaseShape(lease) catch return error.InvalidAttachmentLease;
        validateLifetime(
            lease.issued_at_ms,
            lease.expires_at_ms,
            now_ms,
            self.cfg.max_attachment_lease_lifetime_ms,
            self.cfg.max_future_skew_ms,
        ) catch |err| switch (err) {
            // Expired signed leases remain admissible only as inert bounded
            // replay/conflict floors. This lets late peers consume both sides of
            // unequal-expiry equivocation without ever reviving liveness.
            error.Expired => if (now_ms > attachmentLeaseReplayUntil(
                lease,
                self.cfg.max_attachment_lease_lifetime_ms,
            )) return error.Expired,
            else => return err,
        };
        try validateRevisionAt(lease.revision, now_ms, self.cfg.max_future_skew_ms);
        // Binding issue time to the revision's physical component gives an
        // accepted revision a finite replay horizon. Without it, a signer could
        // continually reissue an older revision with a fresh future expiry.
        if (@as(i128, lease.issued_at_ms) > @as(i128, lease.revision.epoch))
            return error.InvalidLifetime;

        const digest = digestBytes(signed.transcript);
        if (self.getAttachmentLeaseMutable(lease.token, lease.revision.origin_node)) |current| {
            switch (lease.revision.compare(current.revision)) {
                .lt => return .stale,
                .eq => {
                    if (std.crypto.timing_safe.eql(Digest, current.digest, digest)) return .duplicate;
                    if (current.conflict_wire) |wire| {
                        const witness = decodeAttachmentLease(wire) catch unreachable;
                        if (std.crypto.timing_safe.eql(Digest, digestBytes(witness.transcript), digest))
                            return .duplicate;
                        // Two authenticated unequal transcripts are sufficient
                        // portable evidence. Further variants remain denied but
                        // cannot grow retained state.
                        return .conflict;
                    }
                    current.conflicted = true;
                    current.conflict_wire = ownSignedAttachmentLease(self.allocator, signed) catch |err| return err;
                    return .conflict;
                },
                .gt => {
                    try self.installAttachmentLease(signed, digest, true);
                    return .superseded;
                },
            }
        }
        if (self.attachment_leases.count() >= self.cfg.max_attachment_leases) return error.AttachmentLeaseFull;
        try self.installAttachmentLease(signed, digest, false);
        return .inserted;
    }

    /// Return the live fact asserted by exactly one origin. Token comparison is
    /// constant-time; the public lookup deliberately does not use hash equality.
    pub fn getOrigin(self: *const Store, token: Token, origin_node: NodeId) ?*const Entry {
        const entry = self.getOriginInventory(token, origin_node) orelse return null;
        return if (entry.resume_eligible) entry else null;
    }

    /// Inventory-only lookup. Never use this as remote resume authority.
    pub fn getOriginInventory(self: *const Store, token: Token, origin_node: NodeId) ?*const Entry {
        if (self.group_revocations.contains(token) or self.isQuarantined(token)) return null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    /// Retained receipt metadata, including inventory-only origins. This is
    /// not positive presence or resume authority; use hasAttachedOriginOtherThan.
    pub fn getAttachmentLease(
        self: *const Store,
        token: Token,
        origin_node: NodeId,
    ) ?*const AttachmentLeaseEntry {
        if (self.group_revocations.contains(token)) return null;
        var it = @constCast(&self.attachment_leases).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    /// Deterministic current identity projection for callers that need one
    /// representative. Concurrent origins remain stored and addressable.
    pub fn bestIdentity(self: *const Store, token: Token) ?*const Entry {
        if (self.group_revocations.contains(token) or self.isQuarantined(token)) return null;
        var best: ?*const Entry = null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!slot.value_ptr.resume_eligible) continue;
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (best == null or slot.value_ptr.revision.compare(best.?.revision) == .gt) best = slot.value_ptr;
        }
        return best;
    }

    /// Deterministic representative restricted to signed facts that remain
    /// live at `now_ms`; safe for hot paths between periodic sweeps.
    pub fn bestLiveIdentity(self: *const Store, token: Token, now_ms: i64) ?*const Entry {
        if (self.group_revocations.contains(token) or self.isQuarantined(token)) return null;
        var best: ?*const Entry = null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!slot.value_ptr.resume_eligible) continue;
            if (!tokenEql(slot.key_ptr.token, token) or now_ms > slot.value_ptr.expires_at_ms) continue;
            if (best == null or slot.value_ptr.revision.compare(best.?.revision) == .gt) best = slot.value_ptr;
        }
        return best;
    }

    /// Copy a bounded page of unique live OFFER tokens in lexicographic order,
    /// strictly after the caller-owned value cursor. This scan is allocation
    /// free and does not depend on hash-map iteration position, so the cursor
    /// remains valid even when its entry expires or is revoked between pages.
    /// Concurrent origins collapse to one token. Quarantined and expired facts
    /// are omitted.
    ///
    /// An empty result marks the end of the ordered pass. Set `after` to null to
    /// wrap to the smallest live token and begin the next fair circular pass.
    /// Tokens inserted behind the current cursor are therefore visited after at
    /// most one wrap instead of perturbing or starving the current pass.
    pub fn liveTokensAfter(self: *const Store, now_ms: i64, after: ?Token, out: []Token) []const Token {
        if (out.len == 0) return out[0..0];

        var count: usize = 0;
        var lower_bound = after;
        while (count < out.len) {
            var candidate: ?Token = null;
            var it = @constCast(&self.entries).iterator();
            while (it.next()) |slot| {
                if (!slot.value_ptr.resume_eligible) continue;
                if (slot.value_ptr.quarantine_until_ms != null or now_ms > slot.value_ptr.expires_at_ms) continue;
                const token = slot.key_ptr.token;
                if (lower_bound) |lower| {
                    if (std.mem.order(u8, &token, &lower) != .gt) continue;
                }
                if (candidate == null or std.mem.order(u8, &token, &candidate.?) == .lt)
                    candidate = token;
            }

            const token = candidate orelse break;
            out[count] = token;
            count += 1;
            lower_bound = token;
        }
        return out[0..count];
    }

    /// Ordered unique tokens with any nonexpired retained authority, including
    /// tombstones and quarantine markers. Retry cursors use this broader view so
    /// a failed revoke/quarantine route reconciliation is not stranded merely
    /// because the token deliberately has no live identity projection.
    pub fn authorityTokensAfter(self: *const Store, now_ms: i64, after: ?Token, out: []Token) []const Token {
        if (out.len == 0) return out[0..0];
        var count: usize = 0;
        var lower_bound = after;
        while (count < out.len) {
            var candidate: ?Token = null;
            var quarantine_it = @constCast(&self.quarantines).iterator();
            while (quarantine_it.next()) |slot| {
                if (now_ms > slot.value_ptr.expires_at_ms) continue;
                considerOrderedToken(slot.key_ptr.*, lower_bound, &candidate);
            }
            var entry_it = @constCast(&self.entries).iterator();
            while (entry_it.next()) |slot| {
                if (!slot.value_ptr.resume_eligible) continue;
                if (now_ms > slot.value_ptr.expires_at_ms) continue;
                considerOrderedToken(slot.key_ptr.token, lower_bound, &candidate);
            }
            var lease_it = @constCast(&self.attachment_leases).iterator();
            while (lease_it.next()) |slot| {
                if (slot.value_ptr.conflicted or now_ms > slot.value_ptr.expires_at_ms or self.getOrigin(slot.key_ptr.token, slot.key_ptr.origin_node) == null) continue;
                considerOrderedToken(slot.key_ptr.token, lower_bound, &candidate);
            }
            var tombstone_it = @constCast(&self.tombstones).iterator();
            while (tombstone_it.next()) |slot| {
                if (!session_replica_revocation.tombstoneExportable(now_ms, slot.value_ptr.offer_expires_at_ms)) continue;
                considerOrderedToken(slot.key_ptr.token, lower_bound, &candidate);
            }
            const token = candidate orelse break;
            out[count] = token;
            count += 1;
            lower_bound = token;
        }
        return out[0..count];
    }

    /// Ordered unique tokens represented by any stored authority object,
    /// including objects whose wall-clock lifetime has just elapsed but which
    /// have not yet been swept. The daemon snapshots this bounded key set before
    /// destructive expiry so every formerly-authoritative projection, including
    /// a token whose last origin expired, can be reconciled afterward.
    pub fn storedTokensAfter(self: *const Store, after: ?Token, out: []Token) []const Token {
        if (out.len == 0) return out[0..0];
        var count: usize = 0;
        var lower_bound = after;
        while (count < out.len) {
            var candidate: ?Token = null;
            var quarantine_it = @constCast(&self.quarantines).keyIterator();
            while (quarantine_it.next()) |token| considerOrderedToken(token.*, lower_bound, &candidate);
            var entry_it = @constCast(&self.entries).keyIterator();
            while (entry_it.next()) |key| considerOrderedToken(key.token, lower_bound, &candidate);
            var lease_it = @constCast(&self.attachment_leases).keyIterator();
            while (lease_it.next()) |key| considerOrderedToken(key.token, lower_bound, &candidate);
            var tombstone_it = @constCast(&self.tombstones).keyIterator();
            while (tombstone_it.next()) |key| considerOrderedToken(key.token, lower_bound, &candidate);
            const token = candidate orelse break;
            out[count] = token;
            count += 1;
            lower_bound = token;
        }
        return out[0..count];
    }

    /// Ordered unique tokens whose authoritative projection can change during
    /// `sweep(now_ms)`. Route-only expiry is excluded because it does not alter
    /// identity state. Callers reconcile these keys before destructive removal
    /// and again afterward so deny-marker expiry can safely reveal a survivor.
    pub fn projectionSweepTokensAfter(self: *const Store, now_ms: i64, after: ?Token, out: []Token) []const Token {
        if (out.len == 0) return out[0..0];
        var count: usize = 0;
        var lower_bound = after;
        while (count < out.len) {
            var candidate: ?Token = null;
            var quarantine_it = @constCast(&self.quarantines).iterator();
            while (quarantine_it.next()) |slot| {
                if (now_ms > slot.value_ptr.expires_at_ms)
                    considerOrderedToken(slot.key_ptr.*, lower_bound, &candidate);
            }
            var entry_it = @constCast(&self.entries).iterator();
            while (entry_it.next()) |slot| {
                const marker_expires = if (slot.value_ptr.quarantine_until_ms) |until_ms| now_ms > until_ms else false;
                if (now_ms > slot.value_ptr.expires_at_ms or marker_expires)
                    considerOrderedToken(slot.key_ptr.token, lower_bound, &candidate);
            }
            var tombstone_it = @constCast(&self.tombstones).iterator();
            while (tombstone_it.next()) |slot| {
                const object_expires = !session_replica_revocation.tombstoneRetained(now_ms, slot.value_ptr.retain_until_ms);
                const marker_expires = if (slot.value_ptr.quarantine_until_ms) |until_ms| now_ms > until_ms else false;
                if (object_expires or marker_expires)
                    considerOrderedToken(slot.key_ptr.token, lower_bound, &candidate);
            }
            const token = candidate orelse break;
            out[count] = token;
            count += 1;
            lower_bound = token;
        }
        return out[0..count];
    }

    pub const OriginIdentity = struct {
        origin_node: NodeId,
        nick: []const u8,
    };

    /// Page every live origin/nick authority for one exact token in stable
    /// origin order. Views borrow Store-owned memory and remain valid until the
    /// next mutation. Route projection uses this to retroactively tag all
    /// compatibility rows before exact-token reconciliation, including retries.
    pub fn liveOriginIdentitiesAfter(
        self: *const Store,
        token: Token,
        now_ms: i64,
        after_origin: ?NodeId,
        out: []OriginIdentity,
    ) []const OriginIdentity {
        if (out.len == 0) return out[0..0];
        var count: usize = 0;
        var lower_bound = after_origin;
        while (count < out.len) {
            var candidate_origin: ?NodeId = null;
            var candidate_nick: []const u8 = &.{};
            var it = @constCast(&self.entries).iterator();
            while (it.next()) |slot| {
                if (!slot.value_ptr.resume_eligible) continue;
                if (!tokenEql(slot.key_ptr.token, token) or
                    slot.value_ptr.quarantine_until_ms != null or
                    now_ms > slot.value_ptr.expires_at_ms) continue;
                const origin = slot.key_ptr.origin_node;
                if (lower_bound) |lower| if (origin <= lower) continue;
                if (candidate_origin == null or origin < candidate_origin.?) {
                    candidate_origin = origin;
                    candidate_nick = slot.value_ptr.nick;
                }
            }
            const origin = candidate_origin orelse break;
            out[count] = .{ .origin_node = origin, .nick = candidate_nick };
            count += 1;
            lower_bound = origin;
        }
        return out[0..count];
    }

    pub const LiveIdentity = struct {
        token: Token,
        entry: *const Entry,
    };

    /// Allocation-free casemapped lookup for a detached origin/nick projection.
    /// Compatibility roster identities are ASCII-case-insensitive throughout
    /// the daemon; applying the same fold here prevents a peer from bypassing
    /// exact-token binding with a wire-case variant. Null means no live match and
    /// `error.Ambiguous` means that a token cannot be selected safely.
    pub fn uniqueLiveOriginNick(self: *const Store, origin_node: NodeId, nick: []const u8, now_ms: i64) error{Ambiguous}!?LiveIdentity {
        var match: ?LiveIdentity = null;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!slot.value_ptr.resume_eligible) continue;
            if (slot.key_ptr.origin_node != origin_node or now_ms > slot.value_ptr.expires_at_ms) continue;
            // Full quarantine removes token entries; the embedded marker is the
            // allocation-failure fallback and must be checked directly here.
            if (slot.value_ptr.quarantine_until_ms != null) continue;
            if (!std.ascii.eqlIgnoreCase(slot.value_ptr.nick, nick)) continue;
            if (match != null) return error.Ambiguous;
            match = .{ .token = slot.key_ptr.token, .entry = slot.value_ptr };
        }
        return match;
    }

    /// Whether any authenticated origin retains live signed authority for the
    /// logical IRC identity. Unlike `uniqueLiveOriginNick`, this predicate
    /// deliberately applies the daemon's ASCII casemapping and does not require
    /// a unique token: a capability downgrade or hop-by-hop reannouncement must
    /// not widen one or several end-to-end v2 token authorities into a
    /// token-less account-wide mutation.
    pub fn hasLiveIdentity(
        self: *const Store,
        account: []const u8,
        nick: []const u8,
        now_ms: i64,
    ) bool {
        if (account.len == 0 or nick.len == 0) return false;
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!slot.value_ptr.resume_eligible) continue;
            if (now_ms > slot.value_ptr.expires_at_ms) continue;
            if (!std.ascii.eqlIgnoreCase(slot.value_ptr.account, account) or
                !std.ascii.eqlIgnoreCase(slot.value_ptr.nick, nick)) continue;
            return true;
        }
        // A full account-conflict quarantine removes ordinary entries, but its
        // two verified OFFER wires remain receiver-owned fail-closed evidence.
        // Either signed identity must continue blocking a token-less downgrade
        // until the quarantine expires. Decoding borrows Store-owned memory and
        // performs no allocation.
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms > quarantine.expires_at_ms) continue;
            const wires = [_][]const u8{ quarantine.first_wire, quarantine.second_wire };
            for (wires) |wire| {
                const signed = decodeOffer(wire) catch continue;
                if (!signed.offer.allowsResume()) continue;
                if (std.ascii.eqlIgnoreCase(signed.offer.account, account) and
                    std.ascii.eqlIgnoreCase(signed.offer.nick, nick)) return true;
            }
        }
        return false;
    }

    /// Fail-closed retained evidence lookup for peers that omitted the optional
    /// account block as well as v2. This intentionally matches only the IRC nick
    /// (ASCII-insensitive) across every origin/token, including deny markers and
    /// both sides of a full account-conflict quarantine. Tombstones carry no nick
    /// and therefore do not participate.
    pub fn hasRetainedNick(self: *const Store, nick: []const u8, now_ms: i64) bool {
        if (nick.len == 0) return false;
        var it = @constCast(&self.entries).valueIterator();
        while (it.next()) |entry| {
            if (!entry.resume_eligible) continue;
            if (now_ms > entry.expires_at_ms) continue;
            if (std.ascii.eqlIgnoreCase(entry.nick, nick)) return true;
        }
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms > quarantine.expires_at_ms) continue;
            const wires = [_][]const u8{ quarantine.first_wire, quarantine.second_wire };
            for (wires) |wire| {
                const signed = decodeOffer(wire) catch continue;
                if (signed.offer.allowsResume() and
                    std.ascii.eqlIgnoreCase(signed.offer.nick, nick)) return true;
            }
        }
        return false;
    }

    /// Compatibility alias for the deterministic representative.
    pub fn get(self: *const Store, token: Token) ?*const Entry {
        return self.bestIdentity(token);
    }

    pub fn getOriginTombstone(self: *const Store, token: Token, origin_node: NodeId) ?Tombstone {
        var it = @constCast(&self.tombstones).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr.*;
        }
        return null;
    }

    /// Compatibility projection selecting the highest tombstone revision.
    pub fn getTombstone(self: *const Store, token: Token) ?Tombstone {
        var best: ?Tombstone = null;
        var it = @constCast(&self.tombstones).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (best == null or slot.value_ptr.revision.compare(best.?.revision) == .gt) best = slot.value_ptr.*;
        }
        return best;
    }

    pub fn entryCount(self: *const Store) usize {
        return self.entries.count();
    }

    pub fn attachmentLeaseCount(self: *const Store) usize {
        return self.attachment_leases.count();
    }

    pub fn routeCount(self: *const Store) usize {
        return self.routes.count();
    }

    pub fn tombstoneCount(self: *const Store) usize {
        return self.tombstones.count();
    }

    /// The signed authority window a new REVOKE from `origin_node` would
    /// supersede: the high-water window of its retained entry (resume
    /// eligible or inventory-only, and regardless of group-revoke or
    /// quarantine projection, so no retained revision is skipped), or its
    /// current tombstone's signed REVOKE. Input to
    /// `session_replica_revocation.revokeLifetime`.
    pub fn supersededAuthority(self: *const Store, token: Token, origin_node: NodeId) ?session_replica_revocation.SupersededAuthority {
        if (@constCast(self).getOriginMutable(token, origin_node)) |entry| return .{
            .issued_at_ms = entry.authorityIssuedHighWater(),
            .expires_at_ms = entry.authorityExpiresHighWater(),
        };
        const tombstone = self.getOriginTombstone(token, origin_node) orelse return null;
        // Store-owned wires were canonically decoded and verified on install.
        const revoke = decodeOffer(tombstone.wire) catch unreachable;
        return .{ .issued_at_ms = revoke.offer.issued_at_ms, .expires_at_ms = revoke.offer.expires_at_ms };
    }

    /// Allocation-free retention/memory report (O(tombstones)).
    pub fn retentionReport(self: *const Store, now_ms: i64) session_replica_revocation.Report {
        var oldest: ?i64 = null;
        var exported: usize = 0;
        var it = @constCast(&self.tombstones).valueIterator();
        while (it.next()) |tombstone| {
            if (oldest == null or tombstone.retain_until_ms < oldest.?) oldest = tombstone.retain_until_ms;
            if (session_replica_revocation.tombstoneExportable(now_ms, tombstone.offer_expires_at_ms)) exported += 1;
        }
        const tombstones = self.tombstones.count();
        return session_replica_revocation.Report.build(
            self.entries.count(),
            tombstones,
            self.soft_capped_tombstones,
            oldest,
            exported,
            self.cfg.retention(),
        );
    }

    pub fn quarantineCount(self: *const Store) usize {
        return self.quarantines.count();
    }

    /// Highest authenticated causal revision retained anywhere in the Store.
    /// This allocation-free scan includes ordinary rows, allocation-fallback
    /// deny-marker rows, tombstones, and both signed sides of full quarantine.
    /// A successor advances its MeshClock past this value before it can issue a
    /// new local authority fact.
    pub fn maxAuthorityRevision(self: *const Store) ?Revision {
        var maximum: ?Revision = null;
        var entry_it = @constCast(&self.entries).valueIterator();
        while (entry_it.next()) |entry| checkpointRaiseRevision(&maximum, entry.revision);
        var lease_it = @constCast(&self.attachment_leases).valueIterator();
        while (lease_it.next()) |lease| checkpointRaiseRevision(&maximum, lease.revision);
        var tombstone_it = @constCast(&self.tombstones).valueIterator();
        while (tombstone_it.next()) |tombstone| checkpointRaiseRevision(&maximum, tombstone.revision);
        var groups = @constCast(&self.group_revocations).valueIterator();
        while (groups.next()) |group| checkpointRaiseRevision(&maximum, group.revision);
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            const wires = [_][]const u8{ quarantine.first_wire, quarantine.second_wire };
            for (wires) |wire| {
                // Quarantine wires enter only through verified apply or strict
                // checkpoint restore and remain Store-owned until removal.
                const signed = decodeOffer(wire) catch unreachable;
                checkpointRaiseRevision(&maximum, signed.offer.revision);
            }
        }
        return maximum;
    }

    pub fn isQuarantined(self: *const Store, token: Token) bool {
        var quarantine_it = @constCast(&self.quarantines).keyIterator();
        while (quarantine_it.next()) |stored| {
            if (tokenEql(stored.*, token)) return true;
        }
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        return false;
    }

    pub fn retainedCount(self: *const Store, now_ms: i64) usize {
        var count: usize = 0;
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms <= quarantine.expires_at_ms) count += 2;
        }
        var entry_it = @constCast(&self.entries).valueIterator();
        while (entry_it.next()) |entry| {
            if (entry.quarantine_until_ms == null and now_ms <= entry.expires_at_ms) count += 1;
        }
        var tombstone_it = @constCast(&self.tombstones).valueIterator();
        while (tombstone_it.next()) |tombstone| {
            if (tombstone.quarantine_until_ms == null and session_replica_revocation.tombstoneExportable(now_ms, tombstone.offer_expires_at_ms)) count += 1;
        }
        var lease_it = @constCast(&self.attachment_leases).valueIterator();
        while (lease_it.next()) |lease| {
            if (now_ms > lease.replay_until_ms) continue;
            if (lease.conflicted and lease.conflict_wire == null) continue;
            count += 1 + @as(usize, @intFromBool(lease.conflict_wire != null));
        }
        return count + self.group_revocations.count();
    }

    /// Copy bounded borrowed views of every nonexpired current signed object.
    /// Ordering is unspecified; compare the result with `retainedCount` to
    /// detect truncation. Callers forward each `wire` byte-for-byte unchanged.
    pub fn retainedObjectsInto(self: *const Store, now_ms: i64, out: []RetainedObject) usize {
        return self.retainedObjectsRange(now_ms, 0, out);
    }

    /// Bounded pagination over the same unspecified but mutation-stable map
    /// iteration used by `retainedObjectsInto`. Callers must restart at zero if
    /// the Store mutates between pages.
    pub fn retainedObjectsRange(self: *const Store, now_ms: i64, skip: usize, out: []RetainedObject) usize {
        var count: usize = 0;
        var seen: usize = 0;
        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms > quarantine.expires_at_ms) continue;
            const wires = [_][]const u8{ quarantine.first_wire, quarantine.second_wire };
            for (wires) |wire| {
                if (seen < skip) {
                    seen += 1;
                    continue;
                }
                if (count == out.len) return count;
                out[count] = retainedObjectFromWire(wire);
                count += 1;
            }
        }
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null or now_ms > slot.value_ptr.expires_at_ms) continue;
            if (seen < skip) {
                seen += 1;
                continue;
            }
            if (count == out.len) return count;
            out[count] = .{
                .kind = .offer,
                .token = slot.key_ptr.token,
                .origin_node = slot.key_ptr.origin_node,
                .revision = slot.value_ptr.revision,
                .expires_at_ms = slot.value_ptr.expires_at_ms,
                .wire = slot.value_ptr.wire,
                .digest = slot.value_ptr.digest,
            };
            count += 1;
        }
        var lease_it = @constCast(&self.attachment_leases).iterator();
        while (lease_it.next()) |slot| {
            const lease = slot.value_ptr;
            if (now_ms > lease.replay_until_ms or (lease.conflicted and lease.conflict_wire == null)) continue;
            const wires = [_]?[]const u8{ lease.wire, lease.conflict_wire };
            for (wires) |wire_opt| {
                const wire = wire_opt orelse continue;
                if (seen < skip) {
                    seen += 1;
                    continue;
                }
                if (count == out.len) return count;
                out[count] = retainedAttachmentLeaseObjectFromWire(wire);
                count += 1;
            }
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null or !session_replica_revocation.tombstoneExportable(now_ms, slot.value_ptr.offer_expires_at_ms)) continue;
            if (seen < skip) {
                seen += 1;
                continue;
            }
            if (count == out.len) return count;
            out[count] = .{
                .kind = .revoke,
                .token = slot.key_ptr.token,
                .origin_node = slot.key_ptr.origin_node,
                .revision = slot.value_ptr.revision,
                .expires_at_ms = slot.value_ptr.offer_expires_at_ms,
                .wire = slot.value_ptr.wire,
                .digest = slot.value_ptr.digest,
            };
            count += 1;
        }
        var groups = @constCast(&self.group_revocations).valueIterator();
        while (groups.next()) |group| {
            if (seen < skip) {
                seen += 1;
                continue;
            }
            if (count == out.len) return count;
            out[count] = retainedObjectFromWire(group.wire);
            count += 1;
        }
        return count;
    }

    /// Return the smallest retained signed objects strictly greater than the
    /// supplied value cursor. Results are deterministic and strictly ordered
    /// even when the Store's hash maps rehash or the object named by `after`
    /// disappears between calls. Returned wires remain borrowed Store memory.
    pub fn retainedObjectsAfter(
        self: *const Store,
        now_ms: i64,
        after: ?RetainedCursor,
        out: []RetainedObject,
    ) usize {
        if (out.len == 0) return 0;
        var count: usize = 0;

        var quarantine_it = @constCast(&self.quarantines).valueIterator();
        while (quarantine_it.next()) |quarantine| {
            if (now_ms > quarantine.expires_at_ms) continue;
            considerRetainedObject(after, retainedObjectFromWire(quarantine.first_wire), out, &count);
            considerRetainedObject(after, retainedObjectFromWire(quarantine.second_wire), out, &count);
        }

        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null or now_ms > slot.value_ptr.expires_at_ms) continue;
            considerRetainedObject(after, .{
                .kind = .offer,
                .token = slot.key_ptr.token,
                .origin_node = slot.key_ptr.origin_node,
                .revision = slot.value_ptr.revision,
                .expires_at_ms = slot.value_ptr.expires_at_ms,
                .wire = slot.value_ptr.wire,
                .digest = slot.value_ptr.digest,
            }, out, &count);
        }

        var lease_it = @constCast(&self.attachment_leases).iterator();
        while (lease_it.next()) |slot| {
            const lease = slot.value_ptr;
            if (now_ms > lease.replay_until_ms or (lease.conflicted and lease.conflict_wire == null)) continue;
            considerRetainedObject(after, retainedAttachmentLeaseObjectFromWire(lease.wire), out, &count);
            if (lease.conflict_wire) |wire|
                considerRetainedObject(after, retainedAttachmentLeaseObjectFromWire(wire), out, &count);
        }

        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null or !session_replica_revocation.tombstoneExportable(now_ms, slot.value_ptr.offer_expires_at_ms)) continue;
            considerRetainedObject(after, .{
                .kind = .revoke,
                .token = slot.key_ptr.token,
                .origin_node = slot.key_ptr.origin_node,
                .revision = slot.value_ptr.revision,
                .expires_at_ms = slot.value_ptr.offer_expires_at_ms,
                .wire = slot.value_ptr.wire,
                .digest = slot.value_ptr.digest,
            }, out, &count);
        }
        var groups = @constCast(&self.group_revocations).valueIterator();
        while (groups.next()) |group| considerRetainedObject(after, retainedObjectFromWire(group.wire), out, &count);
        return count;
    }

    /// Retained inventory count, including non-authorizing origin records.
    pub fn originCountForToken(self: *const Store, token: Token) usize {
        var count: usize = 0;
        var it = @constCast(&self.entries).keyIterator();
        while (it.next()) |key| {
            if (tokenEql(key.token, token)) count += 1;
        }
        return count;
    }

    /// Whether an exact token has a live, nonquarantined authority at another
    /// mesh origin. Connection teardown uses this receiver-owned fact instead of
    /// treating an arbitrary established peer as proof that a remote attachment
    /// exists for the departing logical session.
    pub fn hasLiveOriginOtherThan(self: *const Store, token: Token, excluded_origin: NodeId, now_ms: i64) bool {
        var it = @constCast(&self.entries).iterator();
        while (it.next()) |slot| {
            if (!slot.value_ptr.resume_eligible) continue;
            if (!tokenEql(slot.key_ptr.token, token) or slot.key_ptr.origin_node == excluded_origin) continue;
            if (slot.value_ptr.quarantine_until_ms != null or now_ms > slot.value_ptr.expires_at_ms) continue;
            return true;
        }
        return false;
    }

    /// Positive liveness proof for teardown. A retained OFFER alone is never
    /// sufficient: the matching origin must also hold a nonconflicted lease
    /// from the same signing key whose revision is newer than the current
    /// OFFER. The lease expiry is a refresh hint. Logical presence continues
    /// until the OFFER's own expiry (the session TTL) or a newer OFFER, which
    /// is how an explicit detach invalidates an older lease. `now_ms` is the
    /// caller's local clock. A newer revision by itself does not mean dead.
    pub fn hasAttachedOriginOtherThan(
        self: *const Store,
        token: Token,
        excluded_origin: NodeId,
        now_ms: i64,
    ) bool {
        if (self.isQuarantined(token)) return false;
        var it = @constCast(&self.attachment_leases).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token) or slot.key_ptr.origin_node == excluded_origin) continue;
            if (self.positiveLeaseCoversUnexpiredOffer(slot.key_ptr.*, slot.value_ptr, now_ms)) return true;
        }
        return false;
    }

    /// A late lease refresh must not look like a detach while the session
    /// OFFER is still inside its TTL. Conflicted leases and newer OFFERs do
    /// not qualify.
    fn positiveLeaseCoversUnexpiredOffer(
        self: *const Store,
        key: OriginKey,
        lease: *const AttachmentLeaseEntry,
        now_ms: i64,
    ) bool {
        if (lease.conflicted or self.isQuarantined(key.token)) return false;
        const offer = self.getOrigin(key.token, key.origin_node) orelse return false;
        if (offer.quarantine_until_ms != null or now_ms > offer.expires_at_ms) return false;
        if (lease.revision.compare(offer.revision) != .gt) return false;
        const signed_offer = decodeOffer(offer.wire) catch return false;
        return std.crypto.timing_safe.eql(sign.PublicKey, signed_offer.signer, lease.signer);
    }

    /// Test for any or one exact anti-entropy parent of an authority origin.
    pub fn hasReplicaParent(self: *const Store, token: Token, origin_node: NodeId, parent_peer: ?NodeId) bool {
        if (self.isQuarantined(token)) return false;
        var it = @constCast(&self.routes).keyIterator();
        while (it.next()) |key| {
            if (!tokenEql(key.token, token) or key.destination != origin_node) continue;
            if (parent_peer == null or key.next_hop == parent_peer.?) return true;
        }
        return false;
    }

    /// Compatibility name. This reports provenance, never live reachability.
    pub fn hasOriginRoute(self: *const Store, token: Token, origin_node: NodeId, next_hop: ?NodeId) bool {
        return self.hasReplicaParent(token, origin_node, next_hop);
    }

    pub fn hasRoute(self: *const Store, token: Token, destination: NodeId, next_hop: NodeId) bool {
        return self.hasOriginRoute(token, destination, next_hop);
    }

    /// Allocation-free check for any OFFER provenance learned through one peer.
    /// ACKs never populate this table and callers must not infer reachability.
    pub fn hasReplicaParentVia(self: *const Store, token: Token, parent_peer: NodeId) bool {
        if (self.isQuarantined(token)) return false;
        var it = @constCast(&self.routes).keyIterator();
        while (it.next()) |key| {
            if (key.next_hop == parent_peer and tokenEql(key.token, token)) return true;
        }
        return false;
    }

    /// Compatibility name. This reports provenance, never live reachability.
    pub fn hasAuthorityRouteVia(self: *const Store, token: Token, next_hop: NodeId) bool {
        return self.hasReplicaParentVia(token, next_hop);
    }

    /// Copy matching routes into `out`. Returns the number copied; callers can
    /// compare with `routeCountForToken` to detect truncation.
    pub fn routesInto(self: *const Store, token: Token, out: []Route) usize {
        if (self.isQuarantined(token)) return 0;
        var n: usize = 0;
        var it = @constCast(&self.routes).iterator();
        while (it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (n == out.len) break;
            out[n] = .{
                .token = slot.key_ptr.token,
                .destination = slot.key_ptr.destination,
                .next_hop = slot.key_ptr.next_hop,
                .revision = slot.value_ptr.revision,
                .last_seen_ms = slot.value_ptr.last_seen_ms,
            };
            n += 1;
        }
        return n;
    }

    pub fn routeCountForToken(self: *const Store, token: Token) usize {
        var n: usize = 0;
        var it = @constCast(&self.routes).keyIterator();
        while (it.next()) |key| {
            if (tokenEql(key.token, token)) n += 1;
        }
        return n;
    }

    pub fn routeCountForOrigin(self: *const Store, token: Token, origin_node: NodeId) usize {
        var n: usize = 0;
        var it = @constCast(&self.routes).iterator();
        while (it.next()) |slot| {
            if (slot.value_ptr.revision.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) n += 1;
        }
        return n;
    }

    /// Remove every provenance parent equal to `peer`. Allocation-free and safe
    /// under pressure; retained signed objects remain available for resync.
    pub fn removePeer(self: *Store, peer: NodeId) usize {
        var removed: usize = 0;
        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.keyIterator();
            while (it.next()) |key| {
                if (key.next_hop == peer) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) removed += 1;
        }
        return removed;
    }

    /// Sweep expired signed state, stale/expired routes, and mature tombstones.
    /// Tombstones are retained until their configured TTL, the signed remove
    /// offer's expiry, and the superseded authority's expiry all pass
    /// (`Tombstone.retain_until_ms`), preventing replay resurrection.
    pub fn sweep(self: *Store, now_ms: i64) SweepResult {
        var result = SweepResult{};
        while (true) {
            var victim: ?Token = null;
            var it = self.quarantines.iterator();
            while (it.next()) |slot| {
                if (now_ms > slot.value_ptr.expires_at_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const token = victim orelse break;
            if (self.quarantines.fetchRemove(token)) |removed| {
                freeQuarantine(self.allocator, removed.value);
                result.quarantines += 1;
            }
        }

        while (true) {
            var victim: ?OriginKey = null;
            var it = self.entries.iterator();
            while (it.next()) |slot| {
                if (now_ms > slot.value_ptr.expires_at_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.entries.fetchRemove(key)) |removed| {
                self.removeAccountOrigin(removed.value.account, key);
                freeEntry(self.allocator, removed.value);
                result.entries += 1;
                result.routes += self.removeRoutesForOrigin(key.token, key.origin_node);
            }
        }

        while (true) {
            var victim: ?OriginKey = null;
            var it = self.attachment_leases.iterator();
            while (it.next()) |slot| {
                if (now_ms > slot.value_ptr.replay_until_ms and
                    !self.positiveLeaseCoversUnexpiredOffer(slot.key_ptr.*, slot.value_ptr, now_ms))
                {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.attachment_leases.fetchRemove(key)) |removed| {
                freeAttachmentLease(self.allocator, removed.value);
                result.attachment_leases += 1;
            }
        }

        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.iterator();
            while (it.next()) |slot| {
                const age = nonNegativeAge(now_ms, slot.value_ptr.last_seen_ms);
                const current = self.getOrigin(slot.key_ptr.token, slot.value_ptr.revision.origin_node);
                const invalid_revision = if (current) |entry| !entry.revision.eql(slot.value_ptr.revision) else true;
                if (invalid_revision or age >= self.cfg.route_ttl_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) result.routes += 1;
        }

        while (true) {
            var victim: ?OriginKey = null;
            var it = self.tombstones.iterator();
            while (it.next()) |slot| {
                if (!session_replica_revocation.tombstoneRetained(now_ms, slot.value_ptr.retain_until_ms)) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.dropTombstone(key)) result.tombstones += 1;
        }

        var entry_it = self.entries.valueIterator();
        while (entry_it.next()) |entry| {
            if (entry.quarantine_until_ms) |until_ms| {
                if (now_ms > until_ms) {
                    self.bumpInventoryAccount(entry.account);
                    entry.quarantine_until_ms = null;
                }
            }
        }
        var tombstone_it = self.tombstones.valueIterator();
        while (tombstone_it.next()) |tombstone| {
            if (tombstone.quarantine_until_ms) |until_ms| {
                if (now_ms > until_ms) tombstone.quarantine_until_ms = null;
            }
        }
        return result;
    }

    fn validateOfferForStore(self: *const Store, offer: Offer, now_ms: i64) ApplyError!void {
        validateOfferShape(offer) catch return error.InvalidOffer;
        if (offer.account.len > self.cfg.max_account_bytes or offer.nick.len > self.cfg.max_nick_bytes or offer.snapshot.len > self.cfg.max_snapshot_bytes) return error.InvalidOffer;
        validateLifetime(offer.issued_at_ms, offer.expires_at_ms, now_ms, self.cfg.max_offer_lifetime_ms, self.cfg.max_future_skew_ms) catch |err| {
            if (err != error.Expired or offer.operation != .group_revoke) return err;
        };
        try validateRevisionAt(offer.revision, now_ms, self.cfg.max_future_skew_ms);
    }

    fn applyVerifiedOffer(self: *Store, signed: SignedOffer, digest: Digest, via_peer: NodeId, now_ms: i64) ApplyError!ApplyResult {
        const offer = signed.offer;
        if (self.hasFullQuarantine(offer.token)) return .{ .disposition = .quarantined, .current_revision = offer.revision };
        if ((offer.operation == .upsert or offer.operation == .inventory_upsert)) {
            if (self.findIdentityConflict(offer.token, offer.account, now_ms)) |conflict| {
                if (conflict.wire) |wire| {
                    try self.installQuarantine(signed, wire, conflict.expires_at_ms, now_ms);
                } else {
                    self.markTokenDenied(offer.token, @min(conflict.expires_at_ms, offer.expires_at_ms));
                }
                return .{ .disposition = .quarantined, .current_revision = offer.revision };
            }
            if (self.hasDenyMarker(offer.token)) return .{ .disposition = .quarantined, .current_revision = offer.revision };
        } else if (self.hasDenyMarker(offer.token)) {
            return .{ .disposition = .quarantined, .current_revision = offer.revision };
        }

        const origin = offer.revision.origin_node;
        const entry = self.getOriginMutable(offer.token, origin);
        const tombstone = self.getOriginTombstoneMutable(offer.token, origin);
        std.debug.assert(entry == null or tombstone == null);

        const current_revision: ?Revision = if (entry) |value| value.revision else if (tombstone) |value| value.revision else null;
        if (current_revision) |current| {
            switch (offer.revision.compare(current)) {
                .lt => return .{ .disposition = .stale, .current_revision = current },
                .eq => {
                    const current_digest = if (entry) |value| value.digest else tombstone.?.digest;
                    if (!std.crypto.timing_safe.eql(Digest, current_digest, digest)) {
                        if (std.mem.order(u8, &digest, &current_digest) == .lt) {
                            switch (offer.operation) {
                                .upsert, .inventory_upsert => try self.installUpsert(signed, digest, via_peer, now_ms),
                                .remove => try self.installTombstone(signed, digest, now_ms),
                                .group_revoke => unreachable,
                            }
                            return .{ .disposition = .conflict_replaced, .current_revision = current };
                        }
                        return .{ .disposition = .conflict, .current_revision = current };
                    }
                    if ((offer.operation == .upsert or offer.operation == .inventory_upsert) and entry != null) {
                        // The first ingress is pinned for this exact revision.
                        // A reflected duplicate from another peer must not form
                        // an alternate path back toward the first parent.
                        const same_ingress = if (entry.?.ingress_peer) |peer| peer == via_peer else via_peer == 0;
                        if (same_ingress) {
                            if (via_peer != 0) _ = try self.recordRoute(offer.token, offer.revision.origin_node, via_peer, offer.revision, now_ms);
                            entry.?.updated_at_ms = now_ms;
                        }
                    }
                    return .{ .disposition = .duplicate, .current_revision = current };
                },
                .gt => {},
            }
        }

        const disposition: ApplyDisposition = if (current_revision == null)
            if (offer.operation == .remove) .tombstoned else .inserted
        else
            .superseded;

        switch (offer.operation) {
            .upsert, .inventory_upsert => try self.installUpsert(signed, digest, via_peer, now_ms),
            .remove => try self.installTombstone(signed, digest, now_ms),
            .group_revoke => unreachable,
        }
        return .{ .disposition = disposition, .current_revision = offer.revision };
    }

    fn installUpsert(self: *Store, signed: SignedOffer, digest: Digest, via_peer: NodeId, now_ms: i64) ApplyError!void {
        const offer = signed.offer;
        const key = OriginKey{ .token = offer.token, .origin_node = offer.revision.origin_node };
        const replacing_entry = self.getOriginMutable(offer.token, offer.revision.origin_node) != null;
        try session_replica_revocation.admitNewEntry(.{
            .entries = self.entries.count(),
            .tombstones = self.tombstones.count(),
            .replacing_entry = replacing_entry,
            .converting_tombstone = !replacing_entry and self.getOriginTombstoneMutable(offer.token, offer.revision.origin_node) != null,
        }, self.cfg.retention());

        const route_key = RouteKey{ .token = offer.token, .destination = offer.revision.origin_node, .next_hop = via_peer };
        const removable_routes = self.routeCountForOrigin(offer.token, offer.revision.origin_node);
        const wants_route = via_peer != 0 and offer.allowsResume();
        if (wants_route and self.routes.count() - removable_routes >= self.cfg.max_routes) return error.RouteFull;

        const wire = try ownSignedOffer(self.allocator, signed);
        errdefer self.allocator.free(wire);
        const owned = decodeOffer(wire) catch unreachable;

        if (!replacing_entry) try self.entries.ensureUnusedCapacity(self.allocator, 1);
        if (wants_route and removable_routes == 0) try self.routes.ensureUnusedCapacity(self.allocator, 1);

        const add_account_origin = try self.reserveAccountOrigin(offer.account, key);
        const inventory_changed = if (self.getOriginMutable(offer.token, offer.revision.origin_node)) |old|
            old.resume_eligible != owned.offer.allowsResume() or
                old.quarantine_until_ms != null or
                old.wire[offer_magic.len] != wire[offer_magic.len] or
                !std.mem.eql(u8, old.inventory, owned.offer.inventory)
        else
            true;
        if (add_account_origin) self.account_index.getPtr(accountDigest(offer.account)).?.origins.appendAssumeCapacity(key);
        if (add_account_origin or inventory_changed) self.bumpInventoryAccount(offer.account);

        // T10: carry the superseded-authority high-water marks across the
        // replacement (and across a tombstone this OFFER converts, whose
        // REVOKE window and retention horizon already cover what it removed).
        var issued_hwm: i64 = offer.issued_at_ms;
        var expires_hwm: i64 = offer.expires_at_ms;
        if (self.getOriginMutable(offer.token, offer.revision.origin_node)) |old| {
            issued_hwm = @max(issued_hwm, old.authorityIssuedHighWater());
            expires_hwm = @max(expires_hwm, old.authorityExpiresHighWater());
        } else if (self.getOriginTombstoneMutable(offer.token, offer.revision.origin_node)) |tomb| {
            const revoke = decodeOffer(tomb.wire) catch unreachable;
            issued_hwm = @max(issued_hwm, revoke.offer.issued_at_ms);
            expires_hwm = @max(expires_hwm, tomb.retain_until_ms);
        }

        if (self.getOriginMutable(offer.token, offer.revision.origin_node)) |old| {
            // Expired authority may be rebound to a different account before
            // sweep removes it. Retire its old account index only after every
            // replacement allocation succeeds, and before freeing its key.
            if (!std.ascii.eqlIgnoreCase(old.account, owned.offer.account))
                self.removeAccountOrigin(old.account, key);
            freeEntry(self.allocator, old.*);
            old.* = .{
                .wire = wire,
                .account = owned.offer.account,
                .nick = owned.offer.nick,
                .snapshot = owned.offer.snapshot,
                .inventory = owned.offer.inventory,
                .resume_eligible = owned.offer.allowsResume(),
                .revision = offer.revision,
                .issued_at_ms = offer.issued_at_ms,
                .expires_at_ms = offer.expires_at_ms,
                .updated_at_ms = now_ms,
                .digest = digest,
                .ingress_peer = if (via_peer == 0) null else via_peer,
                .quarantine_until_ms = null,
                .authority_issued_hwm_ms = issued_hwm,
                .authority_expires_hwm_ms = expires_hwm,
            };
        } else {
            self.entries.putAssumeCapacityNoClobber(key, .{
                .wire = wire,
                .account = owned.offer.account,
                .nick = owned.offer.nick,
                .snapshot = owned.offer.snapshot,
                .inventory = owned.offer.inventory,
                .resume_eligible = owned.offer.allowsResume(),
                .revision = offer.revision,
                .issued_at_ms = offer.issued_at_ms,
                .expires_at_ms = offer.expires_at_ms,
                .updated_at_ms = now_ms,
                .digest = digest,
                .ingress_peer = if (via_peer == 0) null else via_peer,
                .quarantine_until_ms = null,
                .authority_issued_hwm_ms = issued_hwm,
                .authority_expires_hwm_ms = expires_hwm,
            });
        }
        _ = self.dropTombstone(key);
        _ = self.removeRoutesForOrigin(offer.token, offer.revision.origin_node);
        if (wants_route) self.putRouteAssumeCapacity(route_key, offer.revision, now_ms);
    }

    fn installTombstone(self: *Store, signed: SignedOffer, digest: Digest, now_ms: i64) ApplyError!void {
        const offer = signed.offer;
        const key = OriginKey{ .token = offer.token, .origin_node = offer.revision.origin_node };
        const existing_tombstone = self.getOriginTombstoneMutable(offer.token, offer.revision.origin_node);
        const existing_entry = self.getOriginMutable(offer.token, offer.revision.origin_node);
        std.debug.assert(existing_tombstone == null or existing_entry == null);
        const replacing = existing_tombstone != null;
        // Converting this origin's live entry can never fail on tombstone
        // capacity: it frees the entry slot it now occupies. Only a brand-new
        // tombstone (no live authority here) is soft-capped, and only other
        // soft-capped tombstones count against that cap.
        const soft_capped = if (existing_tombstone) |old| old.soft_capped else existing_entry == null;
        try session_replica_revocation.admitTombstone(.{
            .entries = self.entries.count(),
            .tombstones = self.tombstones.count(),
            .soft_capped_tombstones = self.soft_capped_tombstones,
            .replacing = replacing,
            .converting_live_entry = existing_entry != null,
        }, self.cfg.retention());

        const wire = try ownSignedOffer(self.allocator, signed);
        errdefer self.allocator.free(wire);
        if (!replacing) try self.tombstones.ensureUnusedCapacity(self.allocator, 1);

        const identity_digest = if (existing_tombstone) |old|
            old.identity_digest orelse self.identityDigestForToken(offer.token)
        else if (existing_entry) |entry|
            accountDigest(entry.account)
        else
            self.identityDigestForToken(offer.token);
        // Local retention never shortens below what it replaces: a converted
        // live entry's high-water signed expiry (covering older revisions
        // with later windows after a backward clock step), or the previous
        // tombstone's horizon.
        const superseded_expires_at_ms: ?i64 = if (existing_tombstone) |old|
            old.retain_until_ms
        else if (existing_entry) |entry|
            entry.authorityExpiresHighWater()
        else
            null;

        if (self.entries.fetchRemove(key)) |removed| {
            self.removeAccountOrigin(removed.value.account, key);
            freeEntry(self.allocator, removed.value);
        }
        _ = self.removeRoutesForOrigin(offer.token, offer.revision.origin_node);
        const value = Tombstone{
            .wire = wire,
            .revision = offer.revision,
            .removed_at_ms = now_ms,
            .offer_expires_at_ms = offer.expires_at_ms,
            .retain_until_ms = session_replica_revocation.tombstoneRetainUntil(
                now_ms,
                offer.expires_at_ms,
                superseded_expires_at_ms,
                self.cfg.tombstone_ttl_ms,
            ),
            .digest = digest,
            .identity_digest = identity_digest,
            .quarantine_until_ms = null,
            .soft_capped = soft_capped,
        };
        if (self.getOriginTombstoneMutable(offer.token, offer.revision.origin_node)) |old| {
            freeTombstone(self.allocator, old.*);
            old.* = value;
        } else {
            self.tombstones.putAssumeCapacityNoClobber(key, value);
            if (soft_capped) self.soft_capped_tombstones += 1;
        }
    }

    fn installAttachmentLease(
        self: *Store,
        signed: SignedAttachmentLease,
        digest: Digest,
        replacing: bool,
    ) std.mem.Allocator.Error!void {
        const lease = signed.lease;
        const key = OriginKey{ .token = lease.token, .origin_node = lease.revision.origin_node };
        const wire = try ownSignedAttachmentLease(self.allocator, signed);
        errdefer self.allocator.free(wire);
        if (!replacing) try self.attachment_leases.ensureUnusedCapacity(self.allocator, 1);
        const value = AttachmentLeaseEntry{
            .wire = wire,
            .revision = lease.revision,
            .issued_at_ms = lease.issued_at_ms,
            .expires_at_ms = lease.expires_at_ms,
            .replay_until_ms = attachmentLeaseReplayUntil(
                lease,
                self.cfg.max_attachment_lease_lifetime_ms,
            ),
            .signer = signed.signer,
            .digest = digest,
            .conflicted = false,
            .conflict_wire = null,
        };
        if (self.getAttachmentLeaseMutable(lease.token, lease.revision.origin_node)) |old| {
            freeAttachmentLease(self.allocator, old.*);
            old.* = value;
        } else {
            self.attachment_leases.putAssumeCapacityNoClobber(key, value);
        }
    }

    fn recordRoute(self: *Store, token: Token, destination: NodeId, next_hop: NodeId, revision: Revision, now_ms: i64) (error{RouteFull} || std.mem.Allocator.Error)!RouteDisposition {
        const current = self.getOrigin(token, revision.origin_node) orelse return .stale;
        if (!current.revision.eql(revision)) return .stale;
        const key = RouteKey{ .token = token, .destination = destination, .next_hop = next_hop };
        if (self.routes.getPtr(key)) |route| {
            if (revision.compare(route.revision) == .lt) return .stale;
            route.revision = revision;
            route.last_seen_ms = now_ms;
            return .refreshed;
        }
        if (self.routes.count() >= self.cfg.max_routes) return error.RouteFull;
        try self.routes.ensureUnusedCapacity(self.allocator, 1);
        self.putRouteAssumeCapacity(key, revision, now_ms);
        return .inserted;
    }

    fn putRouteAssumeCapacity(self: *Store, key: RouteKey, revision: Revision, now_ms: i64) void {
        if (self.routes.getPtr(key)) |route| {
            route.* = .{ .revision = revision, .last_seen_ms = now_ms };
        } else {
            self.routes.putAssumeCapacityNoClobber(key, .{ .revision = revision, .last_seen_ms = now_ms });
        }
    }

    fn removeRoutesForOrigin(self: *Store, token: Token, origin_node: NodeId) usize {
        var removed: usize = 0;
        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.iterator();
            while (it.next()) |slot| {
                if (slot.value_ptr.revision.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) removed += 1;
        }
        return removed;
    }

    fn getOriginMutable(self: *Store, token: Token, origin_node: NodeId) ?*Entry {
        var it = self.entries.iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    fn getAttachmentLeaseMutable(self: *Store, token: Token, origin_node: NodeId) ?*AttachmentLeaseEntry {
        var it = self.attachment_leases.iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    fn getOriginTombstoneMutable(self: *Store, token: Token, origin_node: NodeId) ?*Tombstone {
        var it = self.tombstones.iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and tokenEql(slot.key_ptr.token, token)) return slot.value_ptr;
        }
        return null;
    }

    fn identityDigestForToken(self: *const Store, token: Token) ?Digest {
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token)) return accountDigest(slot.value_ptr.account);
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token) and slot.value_ptr.identity_digest != null) return slot.value_ptr.identity_digest.?;
        }
        return null;
    }

    const IdentityConflictEvidence = struct {
        wire: ?[]const u8,
        expires_at_ms: i64,
    };

    fn findIdentityConflict(self: *const Store, token: Token, account: []const u8, now_ms: i64) ?IdentityConflictEvidence {
        const account_digest = accountDigest(account);
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (now_ms > slot.value_ptr.expires_at_ms) continue;
            if (!std.ascii.eqlIgnoreCase(slot.value_ptr.account, account)) return .{
                .wire = slot.value_ptr.wire,
                .expires_at_ms = slot.value_ptr.expires_at_ms,
            };
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token)) continue;
            if (now_ms > slot.value_ptr.offer_expires_at_ms) continue;
            const bound = slot.value_ptr.identity_digest orelse continue;
            if (!std.crypto.timing_safe.eql(Digest, bound, account_digest)) return .{
                // REVOKE v2 carries no account field, so a tombstone can deny
                // locally but cannot supply portable account-conflict evidence.
                .wire = null,
                .expires_at_ms = slot.value_ptr.offer_expires_at_ms,
            };
        }
        return null;
    }

    fn hasFullQuarantine(self: *const Store, token: Token) bool {
        var it = @constCast(&self.quarantines).keyIterator();
        while (it.next()) |stored| {
            if (tokenEql(stored.*, token)) return true;
        }
        return false;
    }

    fn hasDenyMarker(self: *const Store, token: Token) bool {
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |slot| {
            if (slot.value_ptr.quarantine_until_ms != null and tokenEql(slot.key_ptr.token, token)) return true;
        }
        return false;
    }

    fn installQuarantine(self: *Store, incoming: SignedOffer, existing_wire: []const u8, existing_expires_at_ms: i64, now_ms: i64) ApplyError!void {
        const until_ms = @min(existing_expires_at_ms, incoming.offer.expires_at_ms);
        if (self.quarantines.count() >= self.cfg.max_quarantines) {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return error.QuarantineFull;
        }

        const existing_copy = self.allocator.dupe(u8, existing_wire) catch |err| {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return err;
        };
        errdefer self.allocator.free(existing_copy);
        const incoming_copy = ownSignedOffer(self.allocator, incoming) catch |err| {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return err;
        };
        errdefer self.allocator.free(incoming_copy);
        self.quarantines.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.markTokenDenied(incoming.offer.token, until_ms);
            return err;
        };

        const existing_signed = decodeOffer(existing_copy) catch unreachable;
        const existing_digest = digestBytes(existing_signed.transcript);
        const incoming_digest = digestBytes(incoming.transcript);
        const existing_first = std.mem.order(u8, &existing_digest, &incoming_digest) == .lt;
        const quarantine = Quarantine{
            .first_wire = if (existing_first) existing_copy else incoming_copy,
            .second_wire = if (existing_first) incoming_copy else existing_copy,
            .expires_at_ms = until_ms,
            .detected_at_ms = now_ms,
        };
        self.removeStateForToken(incoming.offer.token);
        self.quarantines.putAssumeCapacityNoClobber(incoming.offer.token, quarantine);
    }

    fn markTokenDenied(self: *Store, token: Token, until_ms: i64) void {
        var entry_it = self.entries.iterator();
        while (entry_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token)) {
                if (slot.value_ptr.quarantine_until_ms == null) self.bumpInventoryAccount(slot.value_ptr.account);
                slot.value_ptr.quarantine_until_ms = until_ms;
            }
        }
        var tombstone_it = self.tombstones.iterator();
        while (tombstone_it.next()) |slot| {
            if (tokenEql(slot.key_ptr.token, token)) slot.value_ptr.quarantine_until_ms = until_ms;
        }
        _ = self.removeRoutesForToken(token);
    }

    fn removeStateForToken(self: *Store, token: Token) void {
        while (true) {
            var victim: ?OriginKey = null;
            var it = self.entries.keyIterator();
            while (it.next()) |key| {
                if (tokenEql(key.token, token)) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.entries.fetchRemove(key)) |removed| {
                self.removeAccountOrigin(removed.value.account, key);
                freeEntry(self.allocator, removed.value);
            }
        }
        while (true) {
            var victim: ?OriginKey = null;
            var it = self.tombstones.keyIterator();
            while (it.next()) |key| {
                if (tokenEql(key.token, token)) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            _ = self.dropTombstone(key);
        }
        _ = self.removeRoutesForToken(token);
    }

    /// The only tombstone removal path: frees it and keeps
    /// `soft_capped_tombstones` exact. Allocation-free.
    fn dropTombstone(self: *Store, key: OriginKey) bool {
        const removed = self.tombstones.fetchRemove(key) orelse return false;
        if (removed.value.soft_capped) self.soft_capped_tombstones -= 1;
        freeTombstone(self.allocator, removed.value);
        return true;
    }

    fn removeRoutesForToken(self: *Store, token: Token) usize {
        var removed: usize = 0;
        while (true) {
            var victim: ?RouteKey = null;
            var it = self.routes.keyIterator();
            while (it.next()) |key| {
                if (tokenEql(key.token, token)) {
                    victim = key.*;
                    break;
                }
            }
            const key = victim orelse break;
            if (self.routes.remove(key)) removed += 1;
        }
        return removed;
    }

    fn restoreCheckpointEntry(
        self: *Store,
        borrowed_wire: []const u8,
        updated_at_ms: i64,
        quarantine_until_ms: ?i64,
        captured_at_ms: i64,
    ) UpgradeCheckpointError!void {
        const signed = try self.validateCheckpointSignedOffer(borrowed_wire, .upsert, captured_at_ms);
        if (!checkpointTimeAtOrBefore(updated_at_ms, signed.offer.expires_at_ms) or
            !checkpointTimeNearCapture(updated_at_ms, captured_at_ms, self.cfg.max_future_skew_ms) or
            !checkpointOptionalUntilValid(quarantine_until_ms, signed.offer.expires_at_ms))
            return error.InvalidMetadata;

        const key = OriginKey{ .token = signed.offer.token, .origin_node = signed.offer.revision.origin_node };
        if (self.entries.contains(key) or self.tombstones.contains(key)) return error.DuplicateState;

        const wire = try self.allocator.dupe(u8, borrowed_wire);
        errdefer self.allocator.free(wire);
        const owned = decodeOffer(wire) catch unreachable;
        const add_account_origin = try self.reserveAccountOrigin(owned.offer.account, key);
        if (!add_account_origin) return error.DuplicateState;
        self.account_index.getPtr(accountDigest(owned.offer.account)).?.origins.appendAssumeCapacity(key);
        self.bumpInventoryAccount(owned.offer.account);
        self.entries.putAssumeCapacityNoClobber(key, .{
            .wire = wire,
            .account = owned.offer.account,
            .nick = owned.offer.nick,
            .snapshot = owned.offer.snapshot,
            .inventory = owned.offer.inventory,
            .resume_eligible = owned.offer.allowsResume(),
            .revision = owned.offer.revision,
            .issued_at_ms = owned.offer.issued_at_ms,
            .expires_at_ms = owned.offer.expires_at_ms,
            .updated_at_ms = updated_at_ms,
            .digest = digestBytes(owned.transcript),
            .ingress_peer = null,
            .quarantine_until_ms = quarantine_until_ms,
        });
    }

    fn restoreCheckpointTombstone(
        self: *Store,
        borrowed_wire: []const u8,
        removed_at_ms: i64,
        identity_digest: ?Digest,
        quarantine_until_ms: ?i64,
        captured_at_ms: i64,
    ) UpgradeCheckpointError!void {
        const signed = try self.validateCheckpointSignedOffer(borrowed_wire, .remove, captured_at_ms);
        if (!checkpointTimeAtOrBefore(removed_at_ms, signed.offer.expires_at_ms) or
            !checkpointTimeNearCapture(removed_at_ms, captured_at_ms, self.cfg.max_future_skew_ms) or
            !checkpointOptionalUntilValid(quarantine_until_ms, signed.offer.expires_at_ms))
            return error.InvalidMetadata;

        const key = OriginKey{ .token = signed.offer.token, .origin_node = signed.offer.revision.origin_node };
        if (self.entries.contains(key) or self.tombstones.contains(key)) return error.DuplicateState;
        // SRSTv3 records no soft-cap flag. A live-entry conversion always
        // binds the converted entry's account identity (and a replacing
        // REVOKE keeps it), so a null identity can only be a soft-capped
        // tombstone. Treating every bound tombstone as a conversion never
        // over-counts, so a valid image never trips the soft cap here.
        const soft_capped = identity_digest == null;
        if (soft_capped and self.soft_capped_tombstones >= self.cfg.max_tombstones) return error.CapacityExceeded;

        const wire = try self.allocator.dupe(u8, borrowed_wire);
        errdefer self.allocator.free(wire);
        const owned = decodeOffer(wire) catch unreachable;
        self.tombstones.putAssumeCapacityNoClobber(key, .{
            .wire = wire,
            .revision = owned.offer.revision,
            .removed_at_ms = removed_at_ms,
            .offer_expires_at_ms = owned.offer.expires_at_ms,
            // SRSTv3 records no superseded expiry (adding one is a layout and
            // version change). Any authority this tombstone superseded was
            // accepted at or before `removed_at_ms`, so the accepted-authority
            // horizon bounds its expiry and restore never shortens the
            // resurrection block the live Store kept.
            .retain_until_ms = session_replica_revocation.tombstoneRetainUntil(
                removed_at_ms,
                owned.offer.expires_at_ms,
                session_replica_revocation.acceptedAuthorityHorizon(removed_at_ms, self.cfg.retention()),
                self.cfg.tombstone_ttl_ms,
            ),
            .digest = digestBytes(owned.transcript),
            .identity_digest = identity_digest,
            .quarantine_until_ms = quarantine_until_ms,
            .soft_capped = soft_capped,
        });
        if (soft_capped) self.soft_capped_tombstones += 1;
    }

    fn restoreCheckpointQuarantine(
        self: *Store,
        borrowed_first_wire: []const u8,
        borrowed_second_wire: []const u8,
        expires_at_ms: i64,
        detected_at_ms: i64,
        captured_at_ms: i64,
    ) UpgradeCheckpointError!void {
        const first = try self.validateCheckpointSignedOffer(borrowed_first_wire, .upsert, captured_at_ms);
        const second = try self.validateCheckpointSignedOffer(borrowed_second_wire, .upsert, captured_at_ms);
        if (!tokenEql(first.offer.token, second.offer.token) or
            std.mem.eql(u8, first.offer.account, second.offer.account)) return error.InvalidMetadata;
        const first_digest = digestBytes(first.transcript);
        const second_digest = digestBytes(second.transcript);
        if (std.mem.order(u8, &first_digest, &second_digest) != .lt) return error.InvalidMetadata;
        if (expires_at_ms != @min(first.offer.expires_at_ms, second.offer.expires_at_ms) or
            !checkpointTimeAtOrBefore(detected_at_ms, expires_at_ms) or
            !checkpointTimeNearCapture(detected_at_ms, captured_at_ms, self.cfg.max_future_skew_ms))
            return error.InvalidMetadata;
        if (self.quarantines.contains(first.offer.token) or self.hasAnyCheckpointState(first.offer.token))
            return error.DuplicateState;

        const first_wire = try self.allocator.dupe(u8, borrowed_first_wire);
        errdefer self.allocator.free(first_wire);
        const second_wire = try self.allocator.dupe(u8, borrowed_second_wire);
        errdefer self.allocator.free(second_wire);
        self.quarantines.putAssumeCapacityNoClobber(first.offer.token, .{
            .first_wire = first_wire,
            .second_wire = second_wire,
            .expires_at_ms = expires_at_ms,
            .detected_at_ms = detected_at_ms,
        });
    }

    fn restoreCheckpointAttachmentLease(
        self: *Store,
        borrowed_wire: []const u8,
        conflicted: bool,
        borrowed_conflict_wire: ?[]const u8,
        captured_at_ms: i64,
    ) UpgradeCheckpointError!void {
        const signed = decodeAttachmentLease(borrowed_wire) catch return error.InvalidSignedObject;
        verifyAttachmentLease(signed) catch return error.InvalidSignedObject;
        const lease = signed.lease;
        const lifetime: i128 = @as(i128, lease.expires_at_ms) - @as(i128, lease.issued_at_ms);
        const latest: i128 = @as(i128, captured_at_ms) + @as(i128, self.cfg.max_future_skew_ms);
        if (lease.issued_at_ms < 0 or
            lifetime < 0 or
            lifetime > self.cfg.max_attachment_lease_lifetime_ms or
            @as(i128, lease.issued_at_ms) > @as(i128, lease.revision.epoch) or
            @as(i128, lease.issued_at_ms) > latest or
            @as(i128, lease.revision.epoch) > latest)
            return error.InvalidMetadata;
        const conflict_signed: ?SignedAttachmentLease = if (borrowed_conflict_wire) |conflict_wire| blk: {
            if (!conflicted) return error.InvalidMetadata;
            const candidate = decodeAttachmentLease(conflict_wire) catch return error.InvalidSignedObject;
            verifyAttachmentLease(candidate) catch return error.InvalidSignedObject;
            const conflict_lease = candidate.lease;
            const conflict_lifetime: i128 = @as(i128, conflict_lease.expires_at_ms) - @as(i128, conflict_lease.issued_at_ms);
            if (!tokenEql(lease.token, conflict_lease.token) or
                !lease.revision.eql(conflict_lease.revision) or
                std.crypto.timing_safe.eql(Digest, digestBytes(signed.transcript), digestBytes(candidate.transcript)) or
                conflict_lease.issued_at_ms < 0 or
                conflict_lifetime < 0 or
                conflict_lifetime > self.cfg.max_attachment_lease_lifetime_ms or
                @as(i128, conflict_lease.issued_at_ms) > @as(i128, conflict_lease.revision.epoch) or
                @as(i128, conflict_lease.issued_at_ms) > latest or
                @as(i128, conflict_lease.revision.epoch) > latest)
                return error.InvalidMetadata;
            break :blk candidate;
        } else null;

        const key = OriginKey{ .token = lease.token, .origin_node = lease.revision.origin_node };
        if (self.attachment_leases.contains(key)) return error.DuplicateState;

        const wire = try self.allocator.dupe(u8, borrowed_wire);
        errdefer self.allocator.free(wire);
        const conflict_wire = if (borrowed_conflict_wire) |borrowed|
            try self.allocator.dupe(u8, borrowed)
        else
            null;
        errdefer if (conflict_wire) |owned_conflict| self.allocator.free(owned_conflict);
        const owned = decodeAttachmentLease(wire) catch unreachable;
        self.attachment_leases.putAssumeCapacityNoClobber(key, .{
            .wire = wire,
            .revision = owned.lease.revision,
            .issued_at_ms = owned.lease.issued_at_ms,
            .expires_at_ms = owned.lease.expires_at_ms,
            .replay_until_ms = attachmentLeaseReplayUntil(
                owned.lease,
                self.cfg.max_attachment_lease_lifetime_ms,
            ),
            .signer = owned.signer,
            .digest = digestBytes(owned.transcript),
            .conflicted = conflicted,
            .conflict_wire = conflict_wire,
        });
        _ = conflict_signed;
    }

    fn validateCheckpointSignedOffer(
        self: *const Store,
        wire: []const u8,
        operation: OfferOperation,
        captured_at_ms: i64,
    ) UpgradeCheckpointError!SignedOffer {
        const signed = decodeOffer(wire) catch return error.InvalidSignedObject;
        verifyOffer(signed) catch return error.InvalidSignedObject;
        const offer = signed.offer;
        if ((offer.operation != operation and !(operation == .upsert and offer.operation == .inventory_upsert)) or
            offer.account.len > self.cfg.max_account_bytes or
            offer.nick.len > self.cfg.max_nick_bytes or
            offer.snapshot.len > self.cfg.max_snapshot_bytes) return error.InvalidMetadata;
        const lifetime: i128 = @as(i128, offer.expires_at_ms) - @as(i128, offer.issued_at_ms);
        if (lifetime < 0 or lifetime > self.cfg.max_offer_lifetime_ms) return error.InvalidMetadata;
        const latest: i128 = @as(i128, captured_at_ms) + @as(i128, self.cfg.max_future_skew_ms);
        if (@as(i128, offer.issued_at_ms) > latest or @as(i128, offer.revision.epoch) > latest)
            return error.InvalidMetadata;
        return signed;
    }

    fn hasAnyCheckpointState(self: *const Store, token: Token) bool {
        var entry_it = @constCast(&self.entries).keyIterator();
        while (entry_it.next()) |key| if (tokenEql(key.token, token)) return true;
        var tombstone_it = @constCast(&self.tombstones).keyIterator();
        while (tombstone_it.next()) |key| if (tokenEql(key.token, token)) return true;
        return false;
    }

    fn validateCheckpointIdentityState(self: *const Store) UpgradeCheckpointError!void {
        var entry_it = @constCast(&self.entries).iterator();
        while (entry_it.next()) |left| {
            if (self.hasFullQuarantine(left.key_ptr.token)) return error.DuplicateState;
            const expected = accountDigest(left.value_ptr.account);
            var other_entry_it = @constCast(&self.entries).iterator();
            while (other_entry_it.next()) |right| {
                if (!tokenEql(left.key_ptr.token, right.key_ptr.token)) continue;
                if (!std.ascii.eqlIgnoreCase(left.value_ptr.account, right.value_ptr.account)) return error.InvalidMetadata;
            }
            var tombstone_it = @constCast(&self.tombstones).iterator();
            while (tombstone_it.next()) |tombstone| {
                if (!tokenEql(left.key_ptr.token, tombstone.key_ptr.token)) continue;
                if (tombstone.value_ptr.identity_digest) |actual| {
                    if (!std.crypto.timing_safe.eql(Digest, expected, actual)) return error.InvalidMetadata;
                }
            }
        }
        var tombstone_it = @constCast(&self.tombstones).iterator();
        while (tombstone_it.next()) |left| {
            if (self.hasFullQuarantine(left.key_ptr.token)) return error.DuplicateState;
            const expected = left.value_ptr.identity_digest orelse continue;
            var other_it = @constCast(&self.tombstones).iterator();
            while (other_it.next()) |right| {
                if (!tokenEql(left.key_ptr.token, right.key_ptr.token)) continue;
                if (right.value_ptr.identity_digest) |actual| {
                    if (!std.crypto.timing_safe.eql(Digest, expected, actual)) return error.InvalidMetadata;
                }
            }
        }
    }
};

/// Module-level discriminator for callers that do not otherwise name Store.
pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return Store.isUpgradeCheckpoint(bytes);
}

fn validateLifetime(issued_at_ms: i64, expires_at_ms: i64, now_ms: i64, max_lifetime_ms: u64, max_future_skew_ms: u64) error{ Expired, InvalidLifetime }!void {
    if (issued_at_ms < 0 or expires_at_ms < issued_at_ms) return error.InvalidLifetime;
    const lifetime: i128 = @as(i128, expires_at_ms) - @as(i128, issued_at_ms);
    if (lifetime > max_lifetime_ms) return error.InvalidLifetime;
    const future_delta: i128 = @as(i128, issued_at_ms) - @as(i128, now_ms);
    if (future_delta > max_future_skew_ms) return error.InvalidLifetime;
    if (now_ms > expires_at_ms) return error.Expired;
}

fn attachmentLeaseReplayUntil(lease: AttachmentLease, max_lifetime_ms: u64) i64 {
    const revision_horizon: i128 = @as(i128, lease.revision.epoch) + @as(i128, max_lifetime_ms);
    const bounded_horizon: i64 = if (revision_horizon > std.math.maxInt(i64))
        std.math.maxInt(i64)
    else
        @intCast(revision_horizon);
    return @max(lease.expires_at_ms, bounded_horizon);
}

/// A revision participates in the same wall-clock domain as its signed
/// lifetime. Canonical shape is checked at encode/decode; the Store adds this
/// apply-time bound so an otherwise-authentic peer cannot advance the
/// restart-persistent causal clock beyond the configured skew window. i128 math
/// keeps `now + skew` overflow-free for every i64/u64 input.
fn validateRevisionAt(revision: Revision, now_ms: i64, max_future_skew_ms: u64) error{InvalidLifetime}!void {
    if (!revision.isCanonical()) return error.InvalidLifetime;
    const latest_physical: i128 = @as(i128, now_ms) + @as(i128, max_future_skew_ms);
    if (@as(i128, revision.epoch) > latest_physical) return error.InvalidLifetime;
}

fn freeEntry(allocator: std.mem.Allocator, entry: Store.Entry) void {
    allocator.free(entry.wire);
}

fn freeAttachmentLease(allocator: std.mem.Allocator, lease: Store.AttachmentLeaseEntry) void {
    allocator.free(lease.wire);
    if (lease.conflict_wire) |wire| allocator.free(wire);
}

fn freeTombstone(allocator: std.mem.Allocator, tombstone: Store.Tombstone) void {
    allocator.free(tombstone.wire);
}

fn freeQuarantine(allocator: std.mem.Allocator, quarantine: Store.Quarantine) void {
    allocator.free(quarantine.first_wire);
    allocator.free(quarantine.second_wire);
}

fn ownSignedOffer(allocator: std.mem.Allocator, signed: SignedOffer) std.mem.Allocator.Error![]u8 {
    const wire = try allocator.alloc(u8, signed.transcript.len + signature_wire_len);
    @memcpy(wire[0..signed.transcript.len], signed.transcript);
    @memcpy(wire[signed.transcript.len..][0..sign.public_key_len], &signed.signer);
    @memcpy(wire[signed.transcript.len + sign.public_key_len ..], &signed.signature);
    return wire;
}

fn ownSignedAttachmentLease(
    allocator: std.mem.Allocator,
    signed: SignedAttachmentLease,
) std.mem.Allocator.Error![]u8 {
    const wire = try allocator.alloc(u8, signed.transcript.len + signature_wire_len);
    @memcpy(wire[0..signed.transcript.len], signed.transcript);
    @memcpy(wire[signed.transcript.len..][0..sign.public_key_len], &signed.signer);
    @memcpy(wire[signed.transcript.len + sign.public_key_len ..], &signed.signature);
    return wire;
}

fn retainedObjectFromWire(wire: []const u8) Store.RetainedObject {
    const signed = decodeOffer(wire) catch unreachable;
    return .{
        .kind = if (signed.offer.operation == .group_revoke) .group_revoke else if (signed.offer.operation == .upsert or signed.offer.operation == .inventory_upsert) .offer else .revoke,
        .token = signed.offer.token,
        .origin_node = signed.offer.revision.origin_node,
        .revision = signed.offer.revision,
        .expires_at_ms = if (signed.offer.operation == .group_revoke) std.math.maxInt(i64) else signed.offer.expires_at_ms,
        .wire = wire,
        .digest = digestBytes(signed.transcript),
    };
}

fn retainedAttachmentLeaseObjectFromWire(wire: []const u8) Store.RetainedObject {
    const signed = decodeAttachmentLease(wire) catch unreachable;
    return .{
        .kind = .attachment_lease,
        .token = signed.lease.token,
        .origin_node = signed.lease.revision.origin_node,
        .revision = signed.lease.revision,
        .expires_at_ms = signed.lease.expires_at_ms,
        .wire = wire,
        .digest = digestBytes(signed.transcript),
    };
}

/// Insert one candidate into the bounded ascending prefix in `out`. Once full,
/// candidates above the current largest value are ignored and smaller values
/// displace that largest value. This produces the first N objects after a
/// cursor without allocating or depending on hash-map iteration order.
fn considerRetainedObject(
    after: ?Store.RetainedCursor,
    candidate: Store.RetainedObject,
    out: []Store.RetainedObject,
    count: *usize,
) void {
    if (out.len == 0) return;
    const cursor = candidate.cursor();
    if (after) |lower| if (cursor.compare(lower) != .gt) return;

    var insert_at: usize = 0;
    while (insert_at < count.*) : (insert_at += 1) {
        switch (cursor.compare(out[insert_at].cursor())) {
            .lt => break,
            .eq => return,
            .gt => {},
        }
    }
    if (insert_at == out.len) return;

    if (count.* < out.len) {
        var shift = count.*;
        while (shift > insert_at) : (shift -= 1) out[shift] = out[shift - 1];
        count.* += 1;
    } else {
        var shift = out.len - 1;
        while (shift > insert_at) : (shift -= 1) out[shift] = out[shift - 1];
    }
    out[insert_at] = candidate;
}

fn considerOrderedToken(token: Token, lower_bound: ?Token, candidate: *?Token) void {
    if (lower_bound) |lower| if (std.mem.order(u8, &token, &lower) != .gt) return;
    if (candidate.* == null or std.mem.order(u8, &token, &candidate.*.?) == .lt)
        candidate.* = token;
}

fn tokenEql(a: Token, b: Token) bool {
    // A replica token is the reusable bearer credential. Even internal
    // equality checks must not reintroduce an early-exit timing oracle at an
    // apply/lookup boundary.
    return std.crypto.timing_safe.eql(Token, a, b);
}

fn accountDigest(account: []const u8) Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    for (account) |byte| {
        const folded: [1]u8 = .{std.ascii.toLower(byte)};
        hasher.update(&folded);
    }
    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

fn considerInventory(after: ?InventoryCursor, row: InventoryRow, out: []InventoryRow, count: *usize, eligible: *usize) void {
    const cursor = row.cursor();
    if (after) |lower| if (cursor.compare(lower) != .gt) return;
    eligible.* += 1;
    if (out.len == 0) return;
    var index: usize = 0;
    while (index < count.* and cursor.compare(out[index].cursor()) == .gt) : (index += 1) {}
    if (index == out.len) return;
    const end = @min(count.*, out.len - 1);
    std.mem.copyBackwards(InventoryRow, out[index + 1 .. end + 1], out[index..end]);
    out[index] = row;
    count.* = @min(count.* + 1, out.len);
}

fn offerEql(a: Offer, b: Offer) bool {
    return a.operation == b.operation and
        tokenEql(a.token, b.token) and
        a.revision.eql(b.revision) and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms and
        std.mem.eql(u8, a.account, b.account) and
        std.mem.eql(u8, a.nick, b.nick) and
        std.mem.eql(u8, a.snapshot, b.snapshot) and
        std.mem.eql(u8, a.inventory, b.inventory) and
        a.resume_eligible == b.resume_eligible;
}

fn ackEql(a: Ack, b: Ack) bool {
    return a.status == b.status and
        tokenEql(a.token, b.token) and
        a.offered_revision.eql(b.offered_revision) and
        a.observed_revision.eql(b.observed_revision) and
        a.ack_node == b.ack_node and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms and
        a.membership_epoch == b.membership_epoch and
        std.crypto.timing_safe.eql(Digest, a.roster_digest, b.roster_digest);
}

fn attachmentLeaseEql(a: AttachmentLease, b: AttachmentLease) bool {
    return tokenEql(a.token, b.token) and
        a.revision.eql(b.revision) and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms;
}

fn digestBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

fn nonNegativeAge(now_ms: i64, then_ms: i64) u64 {
    if (now_ms <= then_ms) return 0;
    const age: i128 = @as(i128, now_ms) - @as(i128, then_ms);
    return @intCast(age);
}

fn checkpointAddLen(total: *usize, amount: usize) UpgradeCheckpointError!void {
    if (amount > std.math.maxInt(usize) - total.*) return error.TooLarge;
    total.* += amount;
}

fn checkpointAddProduct(total: *usize, count: usize, unit: usize) UpgradeCheckpointError!void {
    if (count != 0 and unit > std.math.maxInt(usize) / count) return error.TooLarge;
    try checkpointAddLen(total, count * unit);
}

fn checkpointWriteWire(writer: *Writer, wire: []const u8) UpgradeCheckpointError!void {
    if (wire.len == 0 or wire.len > std.math.maxInt(u32)) return error.TooLarge;
    writer.writeU32(@intCast(wire.len));
    writer.writeBytes(wire);
}

fn checkpointReadWire(reader: *UpgradeCheckpointReader) UpgradeCheckpointError![]const u8 {
    const len: usize = try reader.readU32();
    if (len == 0 or len > session_replica_transport.max_signed_payload_len) return error.InvalidMetadata;
    return reader.take(len);
}

fn checkpointReadOptionalI64(reader: *UpgradeCheckpointReader) UpgradeCheckpointError!?i64 {
    return switch (try reader.readByte()) {
        0 => null,
        1 => try reader.readI64(),
        else => error.InvalidMetadata,
    };
}

fn checkpointReadOptionalDigest(reader: *UpgradeCheckpointReader) UpgradeCheckpointError!?Digest {
    return switch (try reader.readByte()) {
        0 => null,
        1 => (try reader.take(@sizeOf(Digest)))[0..@sizeOf(Digest)].*,
        else => error.InvalidMetadata,
    };
}

fn checkpointReadBool(reader: *UpgradeCheckpointReader) UpgradeCheckpointError!bool {
    return switch (try reader.readByte()) {
        0 => false,
        1 => true,
        else => error.InvalidMetadata,
    };
}

fn checkpointTimeAtOrBefore(value_ms: i64, limit_ms: i64) bool {
    return value_ms >= 0 and value_ms <= limit_ms;
}

fn checkpointTimeNearCapture(value_ms: i64, captured_at_ms: i64, max_future_skew_ms: u64) bool {
    return @as(i128, value_ms) <= @as(i128, captured_at_ms) + @as(i128, max_future_skew_ms);
}

fn checkpointOptionalUntilValid(until_ms: ?i64, expires_at_ms: i64) bool {
    const value = until_ms orelse return true;
    return checkpointTimeAtOrBefore(value, expires_at_ms);
}

fn checkpointRaiseRevision(maximum: *?Revision, candidate: Revision) void {
    if (maximum.* == null or candidate.compare(maximum.*.?) == .gt) maximum.* = candidate;
}

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeByte(self: *Writer, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeBytes(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.pos .. self.pos + value.len], value);
        self.pos += value.len;
    }

    fn writeU16(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn writeU32(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .big);
        self.pos += 4;
    }

    fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }

    fn writeI64(self: *Writer, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }

    fn writeRevision(self: *Writer, revision: Revision) void {
        self.writeU64(revision.epoch);
        self.writeU64(revision.sequence);
        self.writeU64(revision.origin_node);
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, len: usize) DecodeError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const result = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *Reader) DecodeError!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *Reader) DecodeError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn readU32(self: *Reader) DecodeError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }

    fn readU64(self: *Reader) DecodeError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    fn readI64(self: *Reader) DecodeError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
    }

    fn readRevision(self: *Reader) DecodeError!Revision {
        return .{
            .epoch = try self.readU64(),
            .sequence = try self.readU64(),
            .origin_node = try self.readU64(),
        };
    }
};

const UpgradeCheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *UpgradeCheckpointReader, len: usize) UpgradeCheckpointError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const result = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *UpgradeCheckpointReader) UpgradeCheckpointError!u8 {
        return (try self.take(1))[0];
    }

    fn readU32(self: *UpgradeCheckpointReader) UpgradeCheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }

    fn readI64(self: *UpgradeCheckpointReader) UpgradeCheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testKey(seed: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(seed)));
}

fn revisionFor(kp: *const sign.KeyPair, physical_ms: u64, logical: u64) Revision {
    const stamp = (physical_ms << mesh_clock.seq_bits) |
        (logical & ((@as(u64, 1) << mesh_clock.seq_bits) - 1));
    return .{
        .epoch = physical_ms,
        .sequence = stamp,
        .origin_node = signed_frame.originShortId(kp.public_key),
    };
}

fn testToken(byte: u8) Token {
    var result: Token = @splat(0);
    result[15] = byte;
    return result;
}

fn testWideToken(value: u16) Token {
    var result: Token = @splat(0);
    result[14] = @intCast(value >> 8);
    result[15] = @intCast(value & 0xff);
    return result;
}

fn upsertOffer(kp: *const sign.KeyPair, tok: Token, epoch: u64, sequence: u64, snapshot: []const u8) Offer {
    return .{
        .operation = .upsert,
        .token = tok,
        .revision = revisionFor(kp, epoch, sequence),
        .issued_at_ms = 100,
        .expires_at_ms = 10_000,
        .account = "alice",
        .nick = "Alice",
        .snapshot = snapshot,
    };
}

fn removeOffer(kp: *const sign.KeyPair, tok: Token, epoch: u64, sequence: u64) Offer {
    return .{
        .operation = .remove,
        .token = tok,
        .revision = revisionFor(kp, epoch, sequence),
        .issued_at_ms = 100,
        .expires_at_ms = 10_000,
    };
}

fn signedOffer(allocator: std.mem.Allocator, offer: Offer, kp: *const sign.KeyPair) !struct { wire: []u8, decoded: SignedOffer } {
    const wire = try encodeOffer(allocator, offer, kp);
    return .{ .wire = wire, .decoded = try decodeOffer(wire) };
}

fn signedAttachmentLease(
    allocator: std.mem.Allocator,
    lease: AttachmentLease,
    kp: *const sign.KeyPair,
) !struct { wire: []u8, decoded: SignedAttachmentLease } {
    const wire = try encodeAttachmentLease(allocator, lease, kp);
    return .{ .wire = wire, .decoded = try decodeAttachmentLease(wire) };
}

fn rewriteUpgradeCheckpointChecksum(bytes: []u8) void {
    std.debug.assert(bytes.len >= upgrade_checkpoint_checksum_len);
    const body_end = bytes.len - upgrade_checkpoint_checksum_len;
    const checksum = digestBytes(bytes[0..body_end]);
    @memcpy(bytes[body_end..], &checksum);
}

fn testDowngradeEmptyLeaseCheckpointToV1(allocator: std.mem.Allocator, v2: []const u8) ![]u8 {
    std.debug.assert(v2.len >= upgrade_checkpoint_header_len + upgrade_checkpoint_checksum_len);
    const lease_count_offset = upgrade_checkpoint_v1_header_len;
    std.debug.assert(std.mem.readInt(u32, v2[lease_count_offset..][0..4], .big) == 0);
    std.debug.assert(std.mem.readInt(u32, v2[upgrade_checkpoint_v2_header_len..][0..4], .big) == 0);
    var v1 = try allocator.alloc(u8, v2.len - 8);
    @memcpy(v1[0..lease_count_offset], v2[0..lease_count_offset]);
    v1[upgrade_checkpoint_magic.len] = upgrade_checkpoint_v1_version;
    @memcpy(v1[lease_count_offset..], v2[upgrade_checkpoint_header_len..]);
    rewriteUpgradeCheckpointChecksum(v1);
    return v1;
}

fn expectUpgradeCheckpointRejected(cfg: Store.Config, bytes: []const u8, now_ms: i64) !void {
    if (Store.restoreUpgradeCheckpoint(testing.allocator, cfg, bytes, now_ms)) |value| {
        var restored = value;
        restored.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}

fn nextTestPermutation(values: []u8) bool {
    if (values.len < 2) return false;
    var pivot = values.len - 1;
    while (pivot > 0 and values[pivot - 1] >= values[pivot]) pivot -= 1;
    if (pivot == 0) return false;
    const left = pivot - 1;
    var successor = values.len - 1;
    while (values[successor] <= values[left]) successor -= 1;
    std.mem.swap(u8, &values[left], &values[successor]);
    var lo = pivot;
    var hi = values.len - 1;
    while (lo < hi) {
        std.mem.swap(u8, &values[lo], &values[hi]);
        lo += 1;
        hi -= 1;
    }
    return true;
}

test "session replica revision comparison is a deterministic total order" {
    const values = [_]Revision{
        .{ .epoch = 1, .sequence = (1 << mesh_clock.seq_bits) | 1, .origin_node = 1 },
        .{ .epoch = 1, .sequence = (1 << mesh_clock.seq_bits) | 1, .origin_node = 2 },
        .{ .epoch = 1, .sequence = (1 << mesh_clock.seq_bits) | 2, .origin_node = 1 },
        .{ .epoch = 2, .sequence = (2 << mesh_clock.seq_bits), .origin_node = 1 },
    };
    for (values) |revision| try testing.expect(revision.isCanonical());
    for (values, 0..) |left, i| {
        try testing.expectEqual(std.math.Order.eq, left.compare(left));
        for (values, 0..) |right, j| {
            const expected: std.math.Order = if (i < j) .lt else if (i > j) .gt else .eq;
            try testing.expectEqual(expected, left.compare(right));
        }
    }
    for (values, 0..) |a, i| for (values, 0..) |_, j| for (values, 0..) |c, k| {
        if (i < j and j < k) try testing.expect(a.compare(c) == .lt);
    };
}

test "session replica attachment lease round-trips and tampering fails closed" {
    var kp = try testKey(0x0a);
    defer kp.deinit();
    const lease = AttachmentLease{
        .token = testToken(0xa1),
        .revision = revisionFor(&kp, 200, 2),
        .issued_at_ms = 100,
        .expires_at_ms = 250,
    };
    const wire = try encodeAttachmentLease(testing.allocator, lease, &kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeAttachmentLease(wire);
    try verifyAttachmentLease(decoded);
    try testing.expect(attachmentLeaseEql(lease, decoded.lease));

    var projected = decoded;
    projected.lease.expires_at_ms += 1;
    try testing.expectError(error.TranscriptMismatch, verifyAttachmentLease(projected));

    var tampered = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(tampered);
    tampered[attachment_lease_magic.len] ^= 1;
    try testing.expectError(error.BadSignature, verifyAttachmentLease(try decodeAttachmentLease(tampered)));
    try testing.expectError(error.Truncated, decodeAttachmentLease(wire[0 .. wire.len - 1]));
    const trailing = try std.mem.concat(testing.allocator, u8, &.{ wire, "x" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.TrailingBytes, decodeAttachmentLease(trailing));
}

test "session replica attachment lease makes retained OFFER liveness explicit and ordered" {
    var origin = try testKey(0x0b);
    defer origin.deinit();
    const token = testToken(0xb1);
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const offer_1 = try signedOffer(testing.allocator, upsertOffer(&origin, token, 200, 1, "one"), &origin);
    defer testing.allocator.free(offer_1.wire);
    const lease_1 = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 300,
    }, &origin);
    defer testing.allocator.free(lease_1.wire);

    // Reordering is conservative: a positive lease without its OFFER is inert.
    try testing.expectEqual(AttachmentLeaseDisposition.inserted, try store.applySignedAttachmentLease(lease_1.decoded, 150));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 150));
    _ = try store.applySignedOffer(offer_1.decoded, 7, 150);
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 150));

    // A newer retained/detached snapshot invalidates the old live lease.
    const offer_2 = try signedOffer(testing.allocator, upsertOffer(&origin, token, 202, 1, "detached"), &origin);
    defer testing.allocator.free(offer_2.wire);
    _ = try store.applySignedOffer(offer_2.decoded, 7, 160);
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 160));
    try testing.expectEqual(AttachmentLeaseDisposition.duplicate, try store.applySignedAttachmentLease(lease_1.decoded, 160));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 160));

    const lease_2 = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 203, 1),
        .issued_at_ms = 160,
        .expires_at_ms = 260,
    }, &origin);
    defer testing.allocator.free(lease_2.wire);
    try testing.expectEqual(AttachmentLeaseDisposition.superseded, try store.applySignedAttachmentLease(lease_2.decoded, 170));
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 170));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, signed_frame.originShortId(origin.public_key), 170));
    // The lease refresh is late (expires at 260) and the session OFFER is
    // still inside its TTL, so the attachment stays present. It ends at the
    // session TTL, not because a newer clock value arrived.
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 261));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 10_001));

    const reissued_old_clock = try signedAttachmentLease(testing.allocator, .{
        .token = testToken(0xb2),
        .revision = revisionFor(&origin, 200, 2),
        .issued_at_ms = 201,
        .expires_at_ms = 250,
    }, &origin);
    defer testing.allocator.free(reissued_old_clock.wire);
    try testing.expectError(
        error.InvalidLifetime,
        store.applySignedAttachmentLease(reissued_old_clock.decoded, 201),
    );
}

test "session replica attachment lease conflict and allocation failure stay fail closed" {
    var origin = try testKey(0x0c);
    defer origin.deinit();
    const token = testToken(0xc1);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, token, 200, 1, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    const first = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 250,
    }, &origin);
    defer testing.allocator.free(first.wire);
    const conflict = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 101,
        .expires_at_ms = 250,
    }, &origin);
    defer testing.allocator.free(conflict.wire);

    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(offer.decoded, 0, 150);
    _ = try store.applySignedAttachmentLease(first.decoded, 150);
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 150));
    try testing.expectEqual(AttachmentLeaseDisposition.conflict, try store.applySignedAttachmentLease(conflict.decoded, 150));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 150));

    const newer = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 202, 2),
        .issued_at_ms = 150,
        .expires_at_ms = 250,
    }, &origin);
    defer testing.allocator.free(newer.wire);
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    store.allocator = failing.allocator();
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, store.applySignedAttachmentLease(newer.decoded, 160));
    try testing.expect(store.getAttachmentLease(token, signed_frame.originShortId(origin.public_key)).?.conflicted);
    failing.fail_index = std.math.maxInt(usize);
    try testing.expectEqual(AttachmentLeaseDisposition.superseded, try store.applySignedAttachmentLease(newer.decoded, 160));
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 160));
    _ = store.sweep(251);
    try testing.expectEqual(@as(usize, 1), store.attachmentLeaseCount());
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 251));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 10_001));
    _ = store.sweep(300_203);
    try testing.expectEqual(@as(usize, 0), store.attachmentLeaseCount());
}

test "session replica attachment lease replay floor rejects older live lease after newer expiry" {
    var origin = try testKey(0x0d);
    defer origin.deinit();
    const token = testToken(0xd1);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, token, 100, 1, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    const older_long = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 101, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 300,
    }, &origin);
    defer testing.allocator.free(older_long.wire);
    const newer_short = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 102, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
    }, &origin);
    defer testing.allocator.free(newer_short.wire);

    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(offer.decoded, 0, 150);
    _ = try store.applySignedAttachmentLease(older_long.decoded, 150);
    _ = try store.applySignedAttachmentLease(newer_short.decoded, 150);
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 150));
    _ = store.sweep(201);
    try testing.expectEqual(@as(usize, 1), store.attachmentLeaseCount());
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 201));
    try testing.expectEqual(AttachmentLeaseDisposition.stale, try store.applySignedAttachmentLease(older_long.decoded, 201));
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 201));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 10_001));
}

test "DST GAP-A10 late attachment lease stays present until the session TTL" {
    var origin = try testKey(0xa9);
    defer origin.deinit();
    const token = testToken(0xa9);
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, token, 200, 1, "live"), &origin);
    defer testing.allocator.free(offer.wire);
    const late = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 300,
    }, &origin);
    defer testing.allocator.free(late.wire);
    _ = try store.applySignedOffer(offer.decoded, 0, 150);
    _ = try store.applySignedAttachmentLease(late.decoded, 150);

    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 150));
    // Local clock is past the lease expiry and past the lease revision's
    // physical component. The session OFFER has not expired, so this is a
    // late refresh, not a dead peer.
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 301));

    const refreshed = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 400, 1),
        .issued_at_ms = 400,
        .expires_at_ms = 500,
    }, &origin);
    defer testing.allocator.free(refreshed.wire);
    try testing.expectEqual(
        AttachmentLeaseDisposition.superseded,
        try store.applySignedAttachmentLease(refreshed.decoded, 400),
    );
    try testing.expect(store.hasAttachedOriginOtherThan(token, 999, 400));

    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 10_001));

    const detached = try signedOffer(testing.allocator, upsertOffer(&origin, token, 600, 1, "detached"), &origin);
    defer testing.allocator.free(detached.wire);
    _ = try store.applySignedOffer(detached.decoded, 0, 450);
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 450));
}

test "session replica attachment lease conflict floor survives unequal expiry replay" {
    var origin = try testKey(0x0e);
    defer origin.deinit();
    const token = testToken(0xe1);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, token, 100, 1, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    const short = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 101, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
    }, &origin);
    defer testing.allocator.free(short.wire);
    const long_conflict = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 101, 1),
        .issued_at_ms = 99,
        .expires_at_ms = 300,
    }, &origin);
    defer testing.allocator.free(long_conflict.wire);

    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(offer.decoded, 0, 150);
    _ = try store.applySignedAttachmentLease(short.decoded, 150);
    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try store.applySignedAttachmentLease(long_conflict.decoded, 150),
    );
    _ = store.sweep(201);
    try testing.expect(store.getAttachmentLease(token, offer.decoded.offer.revision.origin_node).?.conflicted);
    try testing.expectEqual(
        AttachmentLeaseDisposition.duplicate,
        try store.applySignedAttachmentLease(long_conflict.decoded, 201),
    );
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 999, 201));
}

test "session replica attachment lease conflict witnesses replay fail closed to a fresh store" {
    var origin = try testKey(0x0f);
    defer origin.deinit();
    const token = testToken(0xf1);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, token, 100, 1, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    const short = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 101, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
    }, &origin);
    defer testing.allocator.free(short.wire);
    const long_conflict = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 101, 1),
        .issued_at_ms = 99,
        .expires_at_ms = 300,
    }, &origin);
    defer testing.allocator.free(long_conflict.wire);

    var source = Store.init(testing.allocator);
    defer source.deinit();
    _ = try source.applySignedOffer(offer.decoded, 0, 150);
    _ = try source.applySignedAttachmentLease(short.decoded, 150);
    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try source.applySignedAttachmentLease(long_conflict.decoded, 150),
    );

    // The positive lifetime of the first witness has elapsed, but its bounded
    // replay floor and the still-live conflicting witness must travel together.
    try testing.expectEqual(@as(usize, 3), source.retainedCount(201));
    var retained: [3]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 3), source.retainedObjectsInto(201, &retained));
    try testing.expectEqual(Store.RetainedKind.offer, retained[0].kind);
    try testing.expectEqual(Store.RetainedKind.attachment_lease, retained[1].kind);
    try testing.expectEqual(Store.RetainedKind.attachment_lease, retained[2].kind);

    var fresh = Store.init(testing.allocator);
    defer fresh.deinit();
    _ = try fresh.applySignedOffer(try decodeOffer(retained[0].wire), 7, 201);
    _ = try fresh.applySignedAttachmentLease(try decodeAttachmentLease(retained[1].wire), 201);
    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try fresh.applySignedAttachmentLease(try decodeAttachmentLease(retained[2].wire), 201),
    );
    const restored = fresh.getAttachmentLease(token, offer.decoded.offer.revision.origin_node).?;
    try testing.expect(restored.conflicted);
    try testing.expect(restored.conflict_wire != null);
    try testing.expect(!fresh.hasAttachedOriginOtherThan(token, 999, 201));

    // Arrival order cannot change the denial: a peer may learn the still-live
    // witness before the expired-but-retained first transcript.
    var reverse = Store.init(testing.allocator);
    defer reverse.deinit();
    _ = try reverse.applySignedOffer(try decodeOffer(retained[0].wire), 8, 201);
    _ = try reverse.applySignedAttachmentLease(try decodeAttachmentLease(retained[2].wire), 201);
    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try reverse.applySignedAttachmentLease(try decodeAttachmentLease(retained[1].wire), 201),
    );
    try testing.expect(reverse.getAttachmentLease(token, offer.decoded.offer.revision.origin_node).?.conflicted);
    try testing.expect(!reverse.hasAttachedOriginOtherThan(token, 999, 201));
}

test "session replica attachment lease conflict OOM checkpoint remains denied and recovers witness" {
    var origin = try testKey(0x10);
    defer origin.deinit();
    const token = testToken(0x10);
    const first = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 250,
    }, &origin);
    defer testing.allocator.free(first.wire);
    const conflict = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 101,
        .expires_at_ms = 250,
    }, &origin);
    defer testing.allocator.free(conflict.wire);

    var source = Store.init(testing.allocator);
    defer source.deinit();
    _ = try source.applySignedAttachmentLease(first.decoded, 150);
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    source.allocator = failing.allocator();
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, source.applySignedAttachmentLease(conflict.decoded, 150));
    source.allocator = testing.allocator;
    const denied = source.getAttachmentLease(token, signed_frame.originShortId(origin.public_key)).?;
    try testing.expect(denied.conflicted);
    try testing.expect(denied.conflict_wire == null);
    try testing.expectEqual(@as(usize, 0), source.retainedCount(150));

    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 150);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, source.cfg, checkpoint, 150);
    defer restored.deinit();
    const restored_denied = restored.getAttachmentLease(token, signed_frame.originShortId(origin.public_key)).?;
    try testing.expect(restored_denied.conflicted);
    try testing.expect(restored_denied.conflict_wire == null);
    try testing.expectEqual(@as(usize, 0), restored.retainedCount(150));

    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try restored.applySignedAttachmentLease(conflict.decoded, 150),
    );
    try testing.expect(restored.getAttachmentLease(token, signed_frame.originShortId(origin.public_key)).?.conflict_wire != null);
    try testing.expectEqual(@as(usize, 2), restored.retainedCount(150));

    // A checkpoint must never accept a duplicated primary wire as the second
    // equivocation witness, even when the outer checksum is recomputed.
    const witnessed_checkpoint = try restored.encodeUpgradeCheckpoint(testing.allocator, 150);
    defer testing.allocator.free(witnessed_checkpoint);
    var duplicated = try testing.allocator.dupe(u8, witnessed_checkpoint);
    defer testing.allocator.free(duplicated);
    const primary_record = upgrade_checkpoint_header_len;
    const primary_len: usize = std.mem.readInt(u32, duplicated[primary_record..][0..4], .big);
    const conflict_tag = primary_record + 4 + primary_len;
    try testing.expectEqual(@as(u8, 1), duplicated[conflict_tag]);
    const witness_record = conflict_tag + 1;
    const witness_len: usize = std.mem.readInt(u32, duplicated[witness_record..][0..4], .big);
    try testing.expectEqual(primary_len, witness_len);
    @memcpy(
        duplicated[witness_record + 4 ..][0..witness_len],
        duplicated[primary_record + 4 ..][0..primary_len],
    );
    rewriteUpgradeCheckpointChecksum(duplicated);
    try testing.expectError(
        error.InvalidMetadata,
        Store.restoreUpgradeCheckpoint(testing.allocator, restored.cfg, duplicated, 150),
    );
}

test "session replica signed OFFER upsert round-trips and verifies" {
    var kp = try testKey(0x11);
    defer kp.deinit();
    const original = upsertOffer(&kp, testToken(1), 7, 9, "snapshot-v1");
    const wire = try encodeOffer(testing.allocator, original, &kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeOffer(wire);
    try verifyOffer(decoded);
    try testing.expectEqual(OfferOperation.upsert, decoded.offer.operation);
    try testing.expectEqualStrings("alice", decoded.offer.account);
    try testing.expectEqualStrings("Alice", decoded.offer.nick);
    try testing.expectEqualStrings("snapshot-v1", decoded.offer.snapshot);
    try testing.expect(decoded.offer.revision.eql(original.revision));
    var forged_projection = decoded;
    forged_projection.offer.nick = "Mallory";
    try testing.expectError(error.TranscriptMismatch, verifyOffer(forged_projection));
}

test "session replica OFFER rejects non-canonical mesh-clock revisions" {
    var kp = try testKey(0x0f);
    defer kp.deinit();
    var offer = upsertOffer(&kp, testToken(0xf0), 100, 7, "state");
    offer.revision.epoch += 1;
    try testing.expectError(error.InvalidOffer, encodeOffer(testing.allocator, offer, &kp));

    const canonical = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xf0), 100, 7, "state"), &kp);
    defer testing.allocator.free(canonical.wire);
    var malformed = try testing.allocator.dupe(u8, canonical.wire);
    defer testing.allocator.free(malformed);
    const revision_epoch_offset = offer_magic.len + 1 + @sizeOf(Token);
    std.mem.writeInt(u64, malformed[revision_epoch_offset..][0..8], 101, .big);
    try testing.expectError(error.InvalidOffer, decodeOffer(malformed));
}

test "session replica portable snapshot fits transport and boundary plus one rejects" {
    var kp = try testKey(0x10);
    defer kp.deinit();
    const account: [max_account_len]u8 = @splat('a');
    const nick: [max_nick_len]u8 = @splat('n');
    const snapshot = try testing.allocator.alloc(u8, max_snapshot_len + 1);
    defer testing.allocator.free(snapshot);
    @memset(snapshot, 's');
    const offer = Offer{
        .operation = .upsert,
        .token = testToken(41),
        .revision = revisionFor(&kp, 1, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
        .account = &account,
        .nick = &nick,
        .snapshot = snapshot[0..max_snapshot_len],
    };
    const signed_wire = try encodeOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed_wire);
    try testing.expect(signed_wire.len <= session_replica_transport.max_signed_payload_len);
    try testing.expectEqual(session_portability.max_snapshot_len, max_snapshot_len);
    const transport_buf = try testing.allocator.alloc(u8, session_replica_transport.header_len + signed_wire.len);
    defer testing.allocator.free(transport_buf);
    const transport_wire = try session_replica_transport.encode(.offer, signed_wire, transport_buf);
    const framed = try session_replica_transport.decode(.offer, transport_wire);
    try testing.expectEqualSlices(u8, signed_wire, framed.signed_payload);
    try verifyOffer(try decodeOffer(framed.signed_payload));

    var oversized = offer;
    oversized.snapshot = snapshot;
    try testing.expectError(error.TooLong, encodeOffer(testing.allocator, oversized, &kp));
}

test "session replica signed OFFER remove round-trips and canonical shape is enforced" {
    var kp = try testKey(0x12);
    defer kp.deinit();
    const wire = try encodeOffer(testing.allocator, removeOffer(&kp, testToken(2), 1, 2), &kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeOffer(wire);
    try verifyOffer(decoded);
    try testing.expectEqual(OfferOperation.remove, decoded.offer.operation);
    try testing.expectEqual(@as(usize, 0), decoded.offer.snapshot.len);

    var invalid = removeOffer(&kp, testToken(2), 1, 3);
    invalid.account = "alice";
    try testing.expectError(error.InvalidOffer, encodeOffer(testing.allocator, invalid, &kp));
}

test "session replica OFFER rejects signer-origin mismatch tampering truncation and trailing bytes" {
    var kp = try testKey(0x21);
    defer kp.deinit();
    var other = try testKey(0x22);
    defer other.deinit();
    const original = upsertOffer(&kp, testToken(3), 1, 1, "state");
    try testing.expectError(error.OriginMismatch, encodeOffer(testing.allocator, original, &other));

    const wire = try encodeOffer(testing.allocator, original, &kp);
    defer testing.allocator.free(wire);
    var tampered = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(tampered);
    tampered[offer_fixed_len] ^= 1;
    try testing.expectError(error.BadSignature, verifyOffer(try decodeOffer(tampered)));
    try testing.expectError(error.Truncated, decodeOffer(wire[0 .. wire.len - 1]));
    const trailing = try std.mem.concat(testing.allocator, u8, &.{ wire, "x" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.TrailingBytes, decodeOffer(trailing));
    tampered[0] = 'X';
    try testing.expectError(error.BadMagic, decodeOffer(tampered));
}

test "session replica OFFER decode rejects invalid operation and oversized declared fields" {
    var kp = try testKey(0x23);
    defer kp.deinit();
    const wire = try encodeOffer(testing.allocator, upsertOffer(&kp, testToken(4), 1, 1, "state"), &kp);
    defer testing.allocator.free(wire);
    var changed = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(changed);
    changed[offer_magic.len] = 0xff;
    try testing.expectError(error.InvalidOffer, decodeOffer(changed));
    changed[offer_magic.len] = @backingInt(OfferOperation.upsert);
    const account_len_offset = offer_magic.len + 1 + @sizeOf(Token) + revision_wire_len + 8 + 8;
    std.mem.writeInt(u16, changed[account_len_offset..][0..2], @intCast(max_account_len + 1), .big);
    try testing.expectError(error.TooLong, decodeOffer(changed));
}

test "session replica signed ACK round-trips verifies and rejects tampering" {
    var offer_kp = try testKey(0x31);
    defer offer_kp.deinit();
    var ack_kp = try testKey(0x32);
    defer ack_kp.deinit();
    const rev = revisionFor(&offer_kp, 3, 4);
    const ack = Ack{
        .status = .accepted,
        .token = testToken(5),
        .offered_revision = rev,
        .observed_revision = rev,
        .ack_node = signed_frame.originShortId(ack_kp.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 500,
    };
    const wire = try encodeAck(testing.allocator, ack, &ack_kp);
    defer testing.allocator.free(wire);
    const decoded = try decodeAck(wire);
    try verifyAck(decoded);
    try testing.expectEqual(AckStatus.accepted, decoded.ack.status);
    try testing.expectEqual(ack.ack_node, decoded.ack.ack_node);
    var forged_projection = decoded;
    forged_projection.ack.status = .duplicate;
    try testing.expectError(error.TranscriptMismatch, verifyAck(forged_projection));

    var tampered = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(tampered);
    tampered[ack_magic.len] = @backingInt(AckStatus.stale);
    try testing.expectError(error.BadSignature, verifyAck(try decodeAck(tampered)));
    tampered[ack_magic.len] = 0xff;
    try testing.expectError(error.InvalidAck, decodeAck(tampered));
    try testing.expectError(error.Truncated, decodeAck(wire[0 .. wire.len - 1]));
}

test "session replica ACK rejects non-canonical offered and observed revisions" {
    var origin = try testKey(0x34);
    defer origin.deinit();
    var receiver = try testKey(0x35);
    defer receiver.deinit();
    const revision = revisionFor(&origin, 200, 9);
    var ack = Ack{
        .status = .accepted,
        .token = testToken(0xf1),
        .offered_revision = revision,
        .observed_revision = revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 300,
    };

    ack.offered_revision.epoch += 1;
    try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, ack, &receiver));
    ack.offered_revision = revision;
    ack.observed_revision.epoch += 1;
    try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, ack, &receiver));
}

test "session replica ACK signer must self-certify ack node and wire has no trailing tolerance" {
    var kp = try testKey(0x33);
    defer kp.deinit();
    var origin = try testKey(0x34);
    defer origin.deinit();
    const rev = revisionFor(&origin, 1, 1);
    var ack = Ack{
        .status = .duplicate,
        .token = testToken(6),
        .offered_revision = rev,
        .observed_revision = rev,
        .ack_node = 7,
        .issued_at_ms = 1,
        .expires_at_ms = 2,
    };
    try testing.expectError(error.OriginMismatch, encodeAck(testing.allocator, ack, &kp));
    ack.ack_node = signed_frame.originShortId(kp.public_key);
    ack.observed_revision.origin_node +%= 1;
    try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, ack, &kp));
    ack.observed_revision = ack.offered_revision;
    const wire = try encodeAck(testing.allocator, ack, &kp);
    defer testing.allocator.free(wire);

    var cross_origin = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(cross_origin);
    const observed_origin_offset = ack_magic.len + 1 + @sizeOf(Token) + revision_wire_len + 16;
    std.mem.writeInt(u64, cross_origin[observed_origin_offset..][0..8], ack.offered_revision.origin_node +% 1, .big);
    try testing.expectError(error.InvalidAck, decodeAck(cross_origin));

    const trailing = try std.mem.concat(testing.allocator, u8, &.{ wire, "x" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.TrailingBytes, decodeAck(trailing));
}

test "session replica every single-byte OFFER and ACK corruption fails closed" {
    var origin = try testKey(0x35);
    defer origin.deinit();
    var receiver = try testKey(0x36);
    defer receiver.deinit();
    const tok = testToken(35);
    const offer_wire = try encodeOffer(testing.allocator, upsertOffer(&origin, tok, 1, 1, "corruption-target"), &origin);
    defer testing.allocator.free(offer_wire);
    var corrupted_offer = try testing.allocator.dupe(u8, offer_wire);
    defer testing.allocator.free(corrupted_offer);
    for (corrupted_offer, 0..) |_, index| {
        corrupted_offer[index] ^= 1;
        const decoded = decodeOffer(corrupted_offer) catch {
            corrupted_offer[index] ^= 1;
            continue;
        };
        verifyOffer(decoded) catch {
            corrupted_offer[index] ^= 1;
            continue;
        };
        corrupted_offer[index] ^= 1;
        return error.TestUnexpectedResult;
    }

    const revision = revisionFor(&origin, 1, 1);
    const ack_wire = try encodeAck(testing.allocator, .{
        .status = .accepted,
        .token = tok,
        .offered_revision = revision,
        .observed_revision = revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 100,
        .expires_at_ms = 200,
    }, &receiver);
    defer testing.allocator.free(ack_wire);
    var corrupted_ack = try testing.allocator.dupe(u8, ack_wire);
    defer testing.allocator.free(corrupted_ack);
    for (corrupted_ack, 0..) |_, index| {
        corrupted_ack[index] ^= 1;
        const decoded = decodeAck(corrupted_ack) catch {
            corrupted_ack[index] ^= 1;
            continue;
        };
        verifyAck(decoded) catch {
            corrupted_ack[index] ^= 1;
            continue;
        };
        corrupted_ack[index] ^= 1;
        return error.TestUnexpectedResult;
    }
}

test "session replica store distinguishes duplicate conflict stale and supersede without mutation leaks" {
    var kp = try testKey(0x41);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(7);

    const first = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "v1"), &kp);
    defer testing.allocator.free(first.wire);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(first.decoded, 10, 150)).disposition);
    try testing.expectEqualStrings("v1", store.get(tok).?.snapshot);
    try testing.expect(store.hasRoute(tok, first.decoded.offer.revision.origin_node, 10));

    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(first.decoded, 11, 160)).disposition);
    try testing.expectEqual(@as(usize, 1), store.routeCount());
    try testing.expect(!store.hasRoute(tok, first.decoded.offer.revision.origin_node, 11));

    const conflict = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "evil-same-revision"), &kp);
    defer testing.allocator.free(conflict.wire);
    const conflict_result = try store.applySignedOffer(conflict.decoded, 12, 170);
    try testing.expect(conflict_result.disposition == .conflict or conflict_result.disposition == .conflict_replaced);
    const conflict_digest = digestBytes(conflict.decoded.transcript);
    const first_digest = digestBytes(first.decoded.transcript);
    const expected_snapshot: []const u8 = if (std.mem.order(u8, &conflict_digest, &first_digest) == .lt)
        "evil-same-revision"
    else
        "v1";
    try testing.expectEqualStrings(expected_snapshot, store.get(tok).?.snapshot);
    try testing.expectEqual(@as(usize, 1), store.routeCount());

    const stale = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 0, "old"), &kp);
    defer testing.allocator.free(stale.wire);
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(stale.decoded, 13, 180)).disposition);
    try testing.expectEqualStrings(expected_snapshot, store.get(tok).?.snapshot);

    const newer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 2, "v2"), &kp);
    defer testing.allocator.free(newer.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(newer.decoded, 14, 190)).disposition);
    try testing.expectEqualStrings("v2", store.get(tok).?.snapshot);
    try testing.expectEqual(@as(usize, 1), store.routeCountForToken(tok));
    try testing.expect(store.hasRoute(tok, newer.decoded.offer.revision.origin_node, 14));
}

test "session replica cross-node equal-clock origins coexist and best identity is deterministic" {
    var low = try testKey(0x42);
    defer low.deinit();
    var high = try testKey(0x43);
    defer high.deinit();
    if (signed_frame.originShortId(low.public_key) > signed_frame.originShortId(high.public_key)) std.mem.swap(sign.KeyPair, &low, &high);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(8);
    const a = try signedOffer(testing.allocator, upsertOffer(&low, tok, 9, 9, "low"), &low);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&high, tok, 9, 9, "high"), &high);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(a.decoded, 1, 200);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(b.decoded, 2, 201)).disposition);
    try testing.expectEqual(@as(usize, 2), store.originCountForToken(tok));
    try testing.expectEqualStrings("low", store.getOrigin(tok, a.decoded.offer.revision.origin_node).?.snapshot);
    try testing.expectEqualStrings("high", store.getOrigin(tok, b.decoded.offer.revision.origin_node).?.snapshot);
    try testing.expectEqualStrings("high", store.get(tok).?.snapshot);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(a.decoded, 1, 202)).disposition);
}

test "session replica A B C attachments preserve independent origins paths and removal" {
    var a_key = try testKey(0x45);
    defer a_key.deinit();
    var b_key = try testKey(0x46);
    defer b_key.deinit();
    var c_key = try testKey(0x47);
    defer c_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const tok = testToken(23);
    const a_node = signed_frame.originShortId(a_key.public_key);
    const b_node = signed_frame.originShortId(b_key.public_key);
    const c_node = signed_frame.originShortId(c_key.public_key);
    const a = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 10, 1, "A-state"), &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 10, 2, "B-state"), &b_key);
    defer testing.allocator.free(b.wire);
    const c = try signedOffer(testing.allocator, upsertOffer(&c_key, tok, 10, 3, "C-state"), &c_key);
    defer testing.allocator.free(c.wire);

    // A reflected through C cannot replace or augment the first parent B.
    _ = try store.applySignedOffer(a.decoded, b_node, 200);
    _ = try store.applySignedOffer(a.decoded, c_node, 201);
    _ = try store.applySignedOffer(b.decoded, c_node, 202);
    _ = try store.applySignedOffer(c.decoded, b_node, 203);
    try testing.expectEqual(@as(usize, 3), store.originCountForToken(tok));
    try testing.expect(store.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!store.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, b_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, c_node, b_node));

    var routes: [8]Store.Route = undefined;
    try testing.expectEqual(@as(usize, 3), store.routesInto(tok, &routes));
    for (routes[0..3]) |route| {
        const origin = store.getOrigin(tok, route.revision.origin_node) orelse return error.TestUnexpectedResult;
        try testing.expect(origin.revision.eql(route.revision));
    }

    const b_new = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 10, 5, "B-state-2"), &b_key);
    defer testing.allocator.free(b_new.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(b_new.decoded, a_node, 203)).disposition);
    try testing.expect(!store.hasOriginRoute(tok, b_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, b_node, a_node));
    try testing.expect(store.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!store.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, c_node, b_node));

    const remove_c = try signedOffer(testing.allocator, removeOffer(&c_key, tok, 10, 4), &c_key);
    defer testing.allocator.free(remove_c.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(remove_c.decoded, b_node, 204)).disposition);
    try testing.expectEqual(@as(usize, 2), store.originCountForToken(tok));
    try testing.expect(store.getOrigin(tok, c_node) == null);
    try testing.expect(store.getOriginTombstone(tok, c_node) != null);
    try testing.expect(store.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!store.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(store.hasOriginRoute(tok, b_node, a_node));
    try testing.expect(!store.hasOriginRoute(tok, c_node, null));
    try testing.expectEqualStrings("A-state", store.getOrigin(tok, a_node).?.snapshot);
    try testing.expectEqualStrings("B-state-2", store.getOrigin(tok, b_node).?.snapshot);
}

test "session replica retained canonical wire replays OFFER and REVOKE after origin loss" {
    var a_key = try testKey(0x4b);
    defer a_key.deinit();
    const tok = testToken(28);
    const a_node = signed_frame.originShortId(a_key.public_key);
    const offer = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 4, 1, "offline-A"), &a_key);
    defer testing.allocator.free(offer.wire);

    var at_b = Store.init(testing.allocator);
    defer at_b.deinit();
    _ = try at_b.applySignedOffer(offer.decoded, a_node, 200);
    try testing.expectEqual(@as(usize, 1), at_b.retainedCount(200));
    var retained: [1]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), at_b.retainedObjectsInto(200, &retained));
    try testing.expectEqual(Store.RetainedKind.offer, retained[0].kind);
    try testing.expectEqualSlices(u8, offer.wire, retained[0].wire);
    try testing.expect(offer.wire.ptr != retained[0].wire.ptr);
    try testing.expectEqual(@as(usize, 1), at_b.removePeer(a_node));
    try testing.expect(!at_b.hasReplicaParent(tok, a_node, a_node));
    try testing.expectEqual(@as(usize, 1), at_b.retainedCount(200));

    // A is no longer available; newly connected C learns the exact signed fact
    // from B without B possessing A's signing key.
    var at_c = Store.init(testing.allocator);
    defer at_c.deinit();
    try testing.expectEqual(ApplyDisposition.inserted, (try at_c.applySignedOffer(try decodeOffer(retained[0].wire), 0xb0, 201)).disposition);
    try testing.expectEqualStrings("offline-A", at_c.getOrigin(tok, a_node).?.snapshot);
    // C records only that B supplied the cache object; this is not evidence
    // that B or A is presently reachable for live message relay.
    try testing.expect(at_c.hasReplicaParent(tok, a_node, 0xb0));

    const revoke = try signedOffer(testing.allocator, removeOffer(&a_key, tok, 4, 2), &a_key);
    defer testing.allocator.free(revoke.wire);
    _ = try at_b.applySignedOffer(revoke.decoded, 0xb0, 202);
    try testing.expectEqual(@as(usize, 1), at_b.retainedCount(202));
    try testing.expectEqual(@as(usize, 1), at_b.retainedObjectsInto(202, &retained));
    try testing.expectEqual(Store.RetainedKind.revoke, retained[0].kind);
    try testing.expectEqualSlices(u8, revoke.wire, retained[0].wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try at_c.applySignedOffer(try decodeOffer(retained[0].wire), 0xb0, 203)).disposition);
    try testing.expect(at_c.getOrigin(tok, a_node) == null);
    try testing.expect(at_c.getOriginTombstone(tok, a_node) != null);
    try testing.expectEqual(@as(usize, 0), at_b.retainedCount(10_001));
}

test "session replica retained enumeration is bounded across concurrent origins" {
    var a_key = try testKey(0x4c);
    defer a_key.deinit();
    var b_key = try testKey(0x4d);
    defer b_key.deinit();
    const tok = testToken(29);
    const a = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 1, "A"), &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 1, 2, "B"), &b_key);
    defer testing.allocator.free(b.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(a.decoded, 1, 200);
    _ = try store.applySignedOffer(b.decoded, 2, 201);
    try testing.expectEqual(@as(usize, 2), store.retainedCount(201));
    var one: [1]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), store.retainedObjectsInto(201, &one));
    try verifyOffer(try decodeOffer(one[0].wire));
    var second: [1]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), store.retainedObjectsRange(201, 1, &second));
    try verifyOffer(try decodeOffer(second[0].wire));
    try testing.expect(one[0].origin_node != second[0].origin_node);
}

test "session replica retained value cursor survives 182 objects replacement and rehash" {
    var key = try testKey(0x91);
    defer key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const Apply = struct {
        fn upsert(target: *Store, kp: *const sign.KeyPair, token: Token, epoch: u64, logical: u64) !void {
            const signed = try signedOffer(testing.allocator, upsertOffer(kp, token, epoch, logical, "state"), kp);
            defer testing.allocator.free(signed.wire);
            _ = try target.applySignedOffer(signed.decoded, logical + 1_000, 200);
        }
    };

    // A wide two-byte token space leaves values on both sides of every page
    // boundary while the entry count is large enough to force map growth.
    for (0..140) |index| {
        const value: u16 = @intCast((index + 1) * 2);
        try Apply.upsert(&store, &key, testWideToken(value), 100, index + 1);
    }
    try testing.expectEqual(@as(usize, 140), store.retainedCount(200));

    var first_page: [7]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, first_page.len), store.retainedObjectsAfter(200, null, &first_page));
    for (first_page[1..], 1..) |object, index|
        try testing.expect(object.cursor().compare(first_page[index - 1].cursor()) == .gt);
    try testing.expect(tokenEql(testWideToken(2), first_page[0].token));
    try testing.expect(tokenEql(testWideToken(14), first_page[first_page.len - 1].token));
    const removed_cursor = first_page[first_page.len - 1].cursor();

    // Superseding the cursor's exact object frees its borrowed wire. Only the
    // cursor value is retained. Insertions behind and ahead of it plus another
    // growth wave must not duplicate, strand, or reorder later objects.
    try Apply.upsert(&store, &key, testWideToken(14), 101, 500);
    try Apply.upsert(&store, &key, testWideToken(3), 100, 501);
    try Apply.upsert(&store, &key, testWideToken(15), 100, 502);
    for (0..40) |index| {
        const value: u16 = @intCast(282 + index * 2);
        try Apply.upsert(&store, &key, testWideToken(value), 100, 600 + index);
    }
    try testing.expectEqual(@as(usize, 182), store.retainedCount(200));

    var page: [7]Store.RetainedObject = undefined;
    var after = removed_cursor;
    var returned: usize = 0;
    while (true) {
        const count = store.retainedObjectsAfter(200, after, &page);
        for (page[0..count]) |object| {
            const current = object.cursor();
            try testing.expect(current.compare(after) == .gt);
            after = current;
            returned += 1;
        }
        if (count < page.len) break;
    }
    // Replacement token 14, new token 15, the 133 untouched original values
    // after 14, and the 40 growth-wave values are all visited exactly once.
    try testing.expectEqual(@as(usize, 175), returned);
    try testing.expectEqual(@as(usize, 0), store.retainedObjectsAfter(200, after, &page));
    try testing.expectEqual(@as(usize, 0), store.retainedObjectsAfter(200, null, page[0..0]));

    // Restarting from null wraps to the beginning and sees the behind-cursor
    // insertion without disturbing forward progress in the prior traversal.
    var restarted: [2]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 2), store.retainedObjectsAfter(200, null, &restarted));
    try testing.expect(tokenEql(testWideToken(2), restarted[0].token));
    try testing.expect(tokenEql(testWideToken(3), restarted[1].token));
}

test "session replica retained value cursor orders all kinds and conflict witnesses" {
    var alice_key = try testKey(0x92);
    defer alice_key.deinit();
    var mallory_key = try testKey(0x93);
    defer mallory_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const live = try signedOffer(testing.allocator, upsertOffer(&alice_key, testWideToken(0x10), 100, 1, "live"), &alice_key);
    defer testing.allocator.free(live.wire);
    _ = try store.applySignedOffer(live.decoded, 1, 150);

    const removed_live = try signedOffer(testing.allocator, upsertOffer(&alice_key, testWideToken(0x20), 100, 2, "remove-me"), &alice_key);
    defer testing.allocator.free(removed_live.wire);
    _ = try store.applySignedOffer(removed_live.decoded, 1, 150);
    const removed = try signedOffer(testing.allocator, removeOffer(&alice_key, testWideToken(0x20), 101, 1), &alice_key);
    defer testing.allocator.free(removed.wire);
    _ = try store.applySignedOffer(removed.decoded, 1, 150);

    const quarantined_alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, testWideToken(0x30), 100, 3, "alice"), &alice_key);
    defer testing.allocator.free(quarantined_alice.wire);
    var mallory_offer = upsertOffer(&mallory_key, testWideToken(0x30), 100, 4, "mallory");
    mallory_offer.account = "mallory";
    const quarantined_mallory = try signedOffer(testing.allocator, mallory_offer, &mallory_key);
    defer testing.allocator.free(quarantined_mallory.wire);
    _ = try store.applySignedOffer(quarantined_alice.decoded, 2, 150);
    try testing.expectEqual(
        ApplyDisposition.quarantined,
        (try store.applySignedOffer(quarantined_mallory.decoded, 3, 150)).disposition,
    );

    const lease_token = testWideToken(0x40);
    const first_lease = try signedAttachmentLease(testing.allocator, .{
        .token = lease_token,
        .revision = revisionFor(&alice_key, 120, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 300,
    }, &alice_key);
    defer testing.allocator.free(first_lease.wire);
    const conflicting_lease = try signedAttachmentLease(testing.allocator, .{
        .token = lease_token,
        .revision = revisionFor(&alice_key, 120, 1),
        .issued_at_ms = 101,
        .expires_at_ms = 300,
    }, &alice_key);
    defer testing.allocator.free(conflicting_lease.wire);
    _ = try store.applySignedAttachmentLease(first_lease.decoded, 150);
    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try store.applySignedAttachmentLease(conflicting_lease.decoded, 150),
    );

    try testing.expectEqual(@as(usize, 6), store.retainedCount(150));
    var page: [1]Store.RetainedObject = undefined;
    var after: ?Store.RetainedCursor = null;
    var kinds = [_]usize{ 0, 0, 0 };
    var quarantine_witnesses: usize = 0;
    var lease_cursors: [2]Store.RetainedCursor = undefined;
    var lease_witnesses: usize = 0;
    var total: usize = 0;
    while (store.retainedObjectsAfter(150, after, &page) == 1) {
        const cursor = page[0].cursor();
        if (after) |previous| try testing.expect(cursor.compare(previous) == .gt);
        kinds[Store.retainedKindRank(page[0].kind)] += 1;
        if (tokenEql(page[0].token, testWideToken(0x30))) quarantine_witnesses += 1;
        if (page[0].kind == .attachment_lease) {
            lease_cursors[lease_witnesses] = cursor;
            lease_witnesses += 1;
        }
        after = cursor;
        total += 1;
    }
    try testing.expectEqual(@as(usize, 6), total);
    try testing.expectEqualSlices(usize, &[_]usize{ 3, 1, 2 }, &kinds);
    try testing.expectEqual(@as(usize, 2), quarantine_witnesses);
    try testing.expectEqual(@as(usize, 2), lease_witnesses);
    try testing.expect(lease_cursors[0].compare(lease_cursors[1]) == .lt);
    try testing.expect(tokenEql(lease_cursors[0].token, lease_cursors[1].token));
    try testing.expectEqual(lease_cursors[0].origin_node, lease_cursors[1].origin_node);
    try testing.expect(lease_cursors[0].revision.eql(lease_cursors[1].revision));
    try testing.expect(!std.mem.eql(u8, &lease_cursors[0].digest, &lease_cursors[1].digest));
    try testing.expectEqual(@as(usize, 0), store.retainedObjectsAfter(150, after, &page));
}

test "session replica live token pages are unique stable and fair after cursor disappearance" {
    var a_key = try testKey(0x9a);
    defer a_key.deinit();
    var b_key = try testKey(0x9b);
    defer b_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const Apply = struct {
        fn upsert(target: *Store, kp: *const sign.KeyPair, token: Token, logical: u64, now_ms: i64) !void {
            const signed = try signedOffer(testing.allocator, upsertOffer(kp, token, 1, logical, "state"), kp);
            defer testing.allocator.free(signed.wire);
            _ = try target.applySignedOffer(signed.decoded, @intCast(logical + 100), now_ms);
        }

        fn remove(target: *Store, kp: *const sign.KeyPair, token: Token, logical: u64, now_ms: i64) !void {
            const signed = try signedOffer(testing.allocator, removeOffer(kp, token, 2, logical), kp);
            defer testing.allocator.free(signed.wire);
            _ = try target.applySignedOffer(signed.decoded, @intCast(logical + 200), now_ms);
        }
    };

    // Deliberately insert out of order. Token 0x20 has concurrent origins but
    // must occupy only one page slot.
    try Apply.upsert(&store, &a_key, testToken(0x30), 1, 150);
    try Apply.upsert(&store, &a_key, testToken(0x10), 2, 150);
    try Apply.upsert(&store, &a_key, testToken(0x50), 3, 150);
    try Apply.upsert(&store, &a_key, testToken(0x20), 4, 150);
    try Apply.upsert(&store, &b_key, testToken(0x20), 5, 150);
    try Apply.upsert(&store, &a_key, testToken(0x40), 6, 150);

    // An expired fact and a fully quarantined token never enter the live page.
    var expired_offer = upsertOffer(&a_key, testToken(0x05), 1, 7, "expired");
    expired_offer.expires_at_ms = 200;
    const expired = try signedOffer(testing.allocator, expired_offer, &a_key);
    defer testing.allocator.free(expired.wire);
    _ = try store.applySignedOffer(expired.decoded, 107, 150);

    try Apply.upsert(&store, &a_key, testToken(0x60), 8, 150);
    var conflict_offer = upsertOffer(&b_key, testToken(0x60), 1, 9, "conflict");
    conflict_offer.account = "mallory";
    const conflict = try signedOffer(testing.allocator, conflict_offer, &b_key);
    defer testing.allocator.free(conflict.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(conflict.decoded, 109, 150)).disposition);

    var first_buf: [3]Token = undefined;
    const first = store.liveTokensAfter(201, null, &first_buf);
    try testing.expectEqual(@as(usize, 3), first.len);
    try testing.expect(tokenEql(testToken(0x10), first[0]));
    try testing.expect(tokenEql(testToken(0x20), first[1]));
    try testing.expect(tokenEql(testToken(0x30), first[2]));

    // The value cursor remains useful after its entry disappears. A new token
    // inserted behind it waits for wrap while later tokens keep progressing.
    try Apply.remove(&store, &a_key, testToken(0x30), 10, 202);
    try Apply.upsert(&store, &a_key, testToken(0x15), 11, 202);
    var later_buf: [2]Token = undefined;
    const later = store.liveTokensAfter(202, first[2], &later_buf);
    try testing.expectEqual(@as(usize, 2), later.len);
    try testing.expect(tokenEql(testToken(0x40), later[0]));
    try testing.expect(tokenEql(testToken(0x50), later[1]));

    var end_buf: [1]Token = undefined;
    try testing.expectEqual(@as(usize, 0), store.liveTokensAfter(202, later[1], &end_buf).len);
    var wrapped_buf: [2]Token = undefined;
    const wrapped = store.liveTokensAfter(202, null, &wrapped_buf);
    try testing.expectEqual(@as(usize, 2), wrapped.len);
    try testing.expect(tokenEql(testToken(0x10), wrapped[0]));
    try testing.expect(tokenEql(testToken(0x15), wrapped[1]));
}

test "session replica stored token and live origin pages preserve expiry cleanup keys" {
    var a_key = try testKey(0xa1);
    defer a_key.deinit();
    var b_key = try testKey(0xa2);
    defer b_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const shared = testToken(0x22);
    const expired_token = testToken(0x11);
    var expired_offer = upsertOffer(&a_key, expired_token, 1, 1, "expired");
    expired_offer.expires_at_ms = 200;
    const expired = try signedOffer(testing.allocator, expired_offer, &a_key);
    defer testing.allocator.free(expired.wire);
    _ = try store.applySignedOffer(expired.decoded, 1, 150);

    var a_offer = upsertOffer(&a_key, shared, 2, 2, "a");
    a_offer.nick = "Alice-A";
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    _ = try store.applySignedOffer(a.decoded, 2, 150);
    var b_offer = upsertOffer(&b_key, shared, 2, 3, "b");
    b_offer.nick = "Alice-B";
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(b.decoded, 3, 150);

    var stored_buf: [4]Token = undefined;
    const stored = store.storedTokensAfter(null, &stored_buf);
    try testing.expectEqual(@as(usize, 2), stored.len);
    try testing.expect(tokenEql(expired_token, stored[0]));
    try testing.expect(tokenEql(shared, stored[1]));
    var live_buf: [4]Token = undefined;
    const live = store.authorityTokensAfter(201, null, &live_buf);
    try testing.expectEqual(@as(usize, 1), live.len);
    try testing.expect(tokenEql(shared, live[0]));
    var sweep_buf: [2]Token = undefined;
    const sweep_tokens = store.projectionSweepTokensAfter(201, null, &sweep_buf);
    try testing.expectEqual(@as(usize, 1), sweep_tokens.len);
    try testing.expect(tokenEql(expired_token, sweep_tokens[0]));

    var origins_buf: [1]Store.OriginIdentity = undefined;
    const first = store.liveOriginIdentitiesAfter(shared, 201, null, &origins_buf);
    try testing.expectEqual(@as(usize, 1), first.len);
    const first_origin = first[0].origin_node;
    const second = store.liveOriginIdentitiesAfter(shared, 201, first_origin, &origins_buf);
    try testing.expectEqual(@as(usize, 1), second.len);
    try testing.expect(first_origin < second[0].origin_node);
    try testing.expectEqual(@as(usize, 0), store.liveOriginIdentitiesAfter(shared, 201, second[0].origin_node, &origins_buf).len);
}

test "session replica authority token pages include revoke and quarantine retry keys" {
    var a_key = try testKey(0xb1);
    defer a_key.deinit();
    var b_key = try testKey(0xb2);
    defer b_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const live_token = testToken(0x10);
    const revoked_token = testToken(0x20);
    const quarantined_token = testToken(0x30);
    const live = try signedOffer(testing.allocator, upsertOffer(&a_key, live_token, 1, 1, "live"), &a_key);
    defer testing.allocator.free(live.wire);
    _ = try store.applySignedOffer(live.decoded, 1, 200);
    const revoked_live = try signedOffer(testing.allocator, upsertOffer(&a_key, revoked_token, 1, 2, "before-revoke"), &a_key);
    defer testing.allocator.free(revoked_live.wire);
    _ = try store.applySignedOffer(revoked_live.decoded, 1, 200);
    const revoke = try signedOffer(testing.allocator, removeOffer(&a_key, revoked_token, 2, 3), &a_key);
    defer testing.allocator.free(revoke.wire);
    _ = try store.applySignedOffer(revoke.decoded, 1, 201);

    const first = try signedOffer(testing.allocator, upsertOffer(&a_key, quarantined_token, 1, 4, "first"), &a_key);
    defer testing.allocator.free(first.wire);
    _ = try store.applySignedOffer(first.decoded, 1, 200);
    var conflict_offer = upsertOffer(&b_key, quarantined_token, 1, 5, "conflict");
    conflict_offer.account = "mallory";
    const conflict = try signedOffer(testing.allocator, conflict_offer, &b_key);
    defer testing.allocator.free(conflict.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(conflict.decoded, 2, 201)).disposition);

    var page_buf: [4]Token = undefined;
    const page = store.authorityTokensAfter(201, null, &page_buf);
    try testing.expectEqual(@as(usize, 3), page.len);
    try testing.expect(tokenEql(live_token, page[0]));
    try testing.expect(tokenEql(revoked_token, page[1]));
    try testing.expect(tokenEql(quarantined_token, page[2]));
}

test "session replica nick revisions evolve until account conflict quarantines the token" {
    var a_key = try testKey(0x48);
    defer a_key.deinit();
    var b_key = try testKey(0x49);
    defer b_key.deinit();
    var c_key = try testKey(0x4a);
    defer c_key.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();

    const tok = testToken(24);
    var a_offer = upsertOffer(&a_key, tok, 1, 1, "A-1");
    a_offer.nick = "Alice-A";
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    var b_offer = upsertOffer(&b_key, tok, 1, 2, "B-1");
    b_offer.nick = "Alice-B";
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(a.decoded, 11, 200);
    _ = try store.applySignedOffer(b.decoded, 12, 201);
    try testing.expectEqualStrings("Alice-B", store.bestIdentity(tok).?.nick);

    var a_new_offer = upsertOffer(&a_key, tok, 1, 3, "A-2");
    a_new_offer.nick = "Alice-A2";
    const a_new = try signedOffer(testing.allocator, a_new_offer, &a_key);
    defer testing.allocator.free(a_new.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(a_new.decoded, 13, 202)).disposition);
    try testing.expectEqualStrings("Alice-A2", store.bestIdentity(tok).?.nick);
    try testing.expectEqualStrings("Alice-B", store.getOrigin(tok, b.decoded.offer.revision.origin_node).?.nick);

    var incompatible = upsertOffer(&c_key, tok, 9, 9, "evil");
    incompatible.account = "mallory";
    const evil = try signedOffer(testing.allocator, incompatible, &c_key);
    defer testing.allocator.free(evil.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(evil.decoded, 14, 203)).disposition);
    try testing.expect(store.isQuarantined(tok));
    try testing.expectEqual(@as(usize, 0), store.originCountForToken(tok));
    try testing.expectEqual(@as(usize, 1), store.quarantineCount());
    try testing.expect(store.bestIdentity(tok) == null);
    try testing.expect(!store.hasOriginRoute(tok, evil.decoded.offer.revision.origin_node, null));

    const remove_a = try signedOffer(testing.allocator, removeOffer(&a_key, tok, 2, 1), &a_key);
    defer testing.allocator.free(remove_a.wire);
    const remove_b = try signedOffer(testing.allocator, removeOffer(&b_key, tok, 2, 1), &b_key);
    defer testing.allocator.free(remove_b.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(remove_a.decoded, 0, 204)).disposition);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(remove_b.decoded, 0, 205)).disposition);
    try testing.expect(store.bestIdentity(tok) == null);
    try testing.expectEqual(@as(usize, 2), store.retainedCount(206));
    try testing.expectEqual(@as(usize, 0), store.sweep(10_000).quarantines);
    try testing.expectEqual(@as(usize, 1), store.sweep(10_001).quarantines);
    try testing.expect(!store.isQuarantined(tok));
}

test "session replica cross-origin account permutations converge on portable quarantine evidence" {
    var alice_key = try testKey(0x55);
    defer alice_key.deinit();
    var mallory_key = try testKey(0x56);
    defer mallory_key.deinit();
    const tok = testToken(36);
    const alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, tok, 1, 1, "alice-state"), &alice_key);
    defer testing.allocator.free(alice.wire);
    var mallory_offer = upsertOffer(&mallory_key, tok, 9, 9, "mallory-state");
    mallory_offer.account = "mallory";
    const mallory = try signedOffer(testing.allocator, mallory_offer, &mallory_key);
    defer testing.allocator.free(mallory.wire);

    var alice_first = Store.init(testing.allocator);
    defer alice_first.deinit();
    var mallory_first = Store.init(testing.allocator);
    defer mallory_first.deinit();
    _ = try alice_first.applySignedOffer(alice.decoded, 91, 200);
    try testing.expectEqual(ApplyDisposition.quarantined, (try alice_first.applySignedOffer(mallory.decoded, 92, 201)).disposition);
    _ = try mallory_first.applySignedOffer(mallory.decoded, 92, 200);
    try testing.expectEqual(ApplyDisposition.quarantined, (try mallory_first.applySignedOffer(alice.decoded, 91, 201)).disposition);
    try testing.expect(alice_first.isQuarantined(tok));
    try testing.expect(mallory_first.isQuarantined(tok));
    try testing.expect(alice_first.bestIdentity(tok) == null);
    try testing.expect(mallory_first.bestIdentity(tok) == null);
    try testing.expectEqual(@as(usize, 0), alice_first.routeCountForToken(tok));
    try testing.expectEqual(@as(usize, 0), mallory_first.routeCountForToken(tok));

    var first_evidence: [2]Store.RetainedObject = undefined;
    var second_evidence: [2]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 2), alice_first.retainedObjectsInto(201, &first_evidence));
    try testing.expectEqual(@as(usize, 2), mallory_first.retainedObjectsInto(201, &second_evidence));
    try testing.expectEqualSlices(u8, first_evidence[0].wire, second_evidence[0].wire);
    try testing.expectEqualSlices(u8, first_evidence[1].wire, second_evidence[1].wire);

    var replay = Store.init(testing.allocator);
    defer replay.deinit();
    _ = try replay.applySignedOffer(try decodeOffer(first_evidence[0].wire), 93, 202);
    try testing.expectEqual(ApplyDisposition.quarantined, (try replay.applySignedOffer(try decodeOffer(first_evidence[1].wire), 93, 203)).disposition);
    try testing.expect(replay.isQuarantined(tok));
    try testing.expect(replay.bestIdentity(tok) == null);

    var capped = Store.initWithConfig(testing.allocator, .{ .max_quarantines = 0 });
    defer capped.deinit();
    _ = try capped.applySignedOffer(alice.decoded, 91, 200);
    try testing.expectError(error.QuarantineFull, capped.applySignedOffer(mallory.decoded, 92, 201));
    try testing.expect(capped.isQuarantined(tok));
    try testing.expect(capped.bestIdentity(tok) == null);
    try testing.expectEqual(@as(usize, 0), capped.routeCountForToken(tok));
    try testing.expectEqual(@as(usize, 0), capped.quarantineCount());
}

test "session replica all lifecycle arrival permutations converge after a higher revision" {
    var kp = try testKey(0x4e);
    defer kp.deinit();
    const tok = testToken(31);
    const stale = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 0, "stale"), &kp);
    defer testing.allocator.free(stale.wire);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const conflict = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "equivocation"), &kp);
    defer testing.allocator.free(conflict.wire);
    const removed = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(removed.wire);
    const resurrected = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 3, "resurrected"), &kp);
    defer testing.allocator.free(resurrected.wire);
    const Event = struct { signed: SignedOffer, via: NodeId };
    const events = [_]Event{
        .{ .signed = stale.decoded, .via = 10 },
        .{ .signed = live.decoded, .via = 11 },
        .{ .signed = live.decoded, .via = 12 },
        .{ .signed = conflict.decoded, .via = 13 },
        .{ .signed = removed.decoded, .via = 14 },
        .{ .signed = resurrected.decoded, .via = 15 },
    };
    var order = [_]u8{ 0, 1, 2, 3, 4, 5 };
    var permutations: usize = 0;
    while (true) {
        var store = Store.init(testing.allocator);
        defer store.deinit();
        for (order) |event_index| {
            const event = events[event_index];
            _ = try store.applySignedOffer(event.signed, event.via, 500);
        }
        const current = store.getOrigin(tok, resurrected.decoded.offer.revision.origin_node).?;
        try testing.expect(current.revision.eql(resurrected.decoded.offer.revision));
        try testing.expectEqualStrings("resurrected", current.snapshot);
        try testing.expectEqual(@as(?NodeId, 15), current.ingress_peer);
        try testing.expect(store.getOriginTombstone(tok, current.revision.origin_node) == null);
        try testing.expect(store.hasOriginRoute(tok, current.revision.origin_node, 15));
        try testing.expectEqual(@as(usize, 1), store.routeCountForOrigin(tok, current.revision.origin_node));
        var retained: [1]Store.RetainedObject = undefined;
        try testing.expectEqual(@as(usize, 1), store.retainedObjectsInto(500, &retained));
        try testing.expectEqualSlices(u8, resurrected.wire, retained[0].wire);
        permutations += 1;
        if (!nextTestPermutation(&order)) break;
    }
    try testing.expectEqual(@as(usize, 720), permutations);
}

test "session replica all A B C authority permutations converge independently" {
    var a_key = try testKey(0x4f);
    defer a_key.deinit();
    var b_key = try testKey(0x50);
    defer b_key.deinit();
    var c_key = try testKey(0x53);
    defer c_key.deinit();
    const tok = testToken(32);
    const a1 = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 2, 1, "A-1"), &a_key);
    defer testing.allocator.free(a1.wire);
    const a2 = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 2, 2, "A-2"), &a_key);
    defer testing.allocator.free(a2.wire);
    const b1 = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 2, 1, "B-1"), &b_key);
    defer testing.allocator.free(b1.wire);
    const b2 = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 2, 2, "B-2"), &b_key);
    defer testing.allocator.free(b2.wire);
    const c1 = try signedOffer(testing.allocator, upsertOffer(&c_key, tok, 2, 1, "C-1"), &c_key);
    defer testing.allocator.free(c1.wire);
    const c2 = try signedOffer(testing.allocator, removeOffer(&c_key, tok, 2, 2), &c_key);
    defer testing.allocator.free(c2.wire);
    const Event = struct { signed: SignedOffer, via: NodeId };
    const events = [_]Event{
        .{ .signed = a1.decoded, .via = 21 },
        .{ .signed = a2.decoded, .via = 22 },
        .{ .signed = b1.decoded, .via = 31 },
        .{ .signed = b2.decoded, .via = 32 },
        .{ .signed = c1.decoded, .via = 41 },
        .{ .signed = c2.decoded, .via = 42 },
    };
    var order = [_]u8{ 0, 1, 2, 3, 4, 5 };
    var permutations: usize = 0;
    while (true) {
        var store = Store.init(testing.allocator);
        defer store.deinit();
        for (order) |event_index| {
            const event = events[event_index];
            _ = try store.applySignedOffer(event.signed, event.via, 500);
        }
        try testing.expectEqual(@as(usize, 2), store.originCountForToken(tok));
        try testing.expectEqualStrings("A-2", store.getOrigin(tok, a2.decoded.offer.revision.origin_node).?.snapshot);
        try testing.expectEqualStrings("B-2", store.getOrigin(tok, b2.decoded.offer.revision.origin_node).?.snapshot);
        try testing.expect(store.getOrigin(tok, c2.decoded.offer.revision.origin_node) == null);
        try testing.expect(store.getOriginTombstone(tok, c2.decoded.offer.revision.origin_node) != null);
        try testing.expect(store.hasOriginRoute(tok, a2.decoded.offer.revision.origin_node, 22));
        try testing.expect(store.hasOriginRoute(tok, b2.decoded.offer.revision.origin_node, 32));
        try testing.expect(!store.hasOriginRoute(tok, c2.decoded.offer.revision.origin_node, null));
        try testing.expectEqual(@as(usize, 3), store.retainedCount(500));
        const expected_best = if (a2.decoded.offer.revision.compare(b2.decoded.offer.revision) == .gt)
            a2.decoded.offer.revision
        else
            b2.decoded.offer.revision;
        try testing.expect(store.bestIdentity(tok).?.revision.eql(expected_best));
        permutations += 1;
        if (!nextTestPermutation(&order)) break;
    }
    try testing.expectEqual(@as(usize, 720), permutations);
}

test "session replica remove creates a bounded tombstone blocks replay and yields to a newer upsert" {
    var kp = try testKey(0x51);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(9);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(remove.wire);
    _ = try store.applySignedOffer(live.decoded, 10, 200);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(remove.decoded, 10, 210)).disposition);
    try testing.expect(store.get(tok) == null);
    try testing.expect(store.getTombstone(tok) != null);
    try testing.expectEqual(@as(usize, 0), store.routeCountForToken(tok));
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(live.decoded, 11, 220)).disposition);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(remove.decoded, 11, 230)).disposition);

    const resurrect = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 3, "new-live"), &kp);
    defer testing.allocator.free(resurrect.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(resurrect.decoded, 12, 240)).disposition);
    try testing.expect(store.getTombstone(tok) == null);
    try testing.expectEqualStrings("new-live", store.get(tok).?.snapshot);
}

test "session replica tombstone anti-entropy revoke before stale upsert cannot resurrect" {
    var kp = try testKey(0x59);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(0x59);
    // Anti-entropy may deliver the REVOKE before the live OFFER it removes.
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 5), &kp);
    defer testing.allocator.free(remove.wire);
    const stale_live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "revoked-live"), &kp);
    defer testing.allocator.free(stale_live.wire);

    try testing.expectEqual(ApplyDisposition.tombstoned, (try store.applySignedOffer(remove.decoded, 10, 200)).disposition);
    try testing.expect(store.get(tok) == null);
    try testing.expect(store.getTombstone(tok) != null);

    // The revocation-era record, replayed from another peer, stays revoked.
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(stale_live.decoded, 11, 210)).disposition);
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(stale_live.decoded, 12, 220)).disposition);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(remove.decoded, 12, 230)).disposition);
    try testing.expect(store.get(tok) == null);
    try testing.expectEqual(@as(usize, 0), store.entryCount());
    try testing.expectEqual(@as(usize, 1), store.tombstoneCount());
    try testing.expect(store.getTombstone(tok).?.revision.eql(remove.decoded.offer.revision));
}

test "session replica tombstone bound at cap is fail closed without eviction" {
    var kp = try testKey(0x5a);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{ .max_entries = 4, .max_routes = 4, .max_tombstones = 3 });
    defer store.deinit();

    const first = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x5a), 1, 1), &kp);
    defer testing.allocator.free(first.wire);
    const second = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x5b), 1, 1), &kp);
    defer testing.allocator.free(second.wire);
    const third = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x5c), 1, 1), &kp);
    defer testing.allocator.free(third.wire);
    const overflow = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x5d), 1, 1), &kp);
    defer testing.allocator.free(overflow.wire);
    _ = try store.applySignedOffer(first.decoded, 0, 200);
    _ = try store.applySignedOffer(second.decoded, 0, 201);
    _ = try store.applySignedOffer(third.decoded, 0, 202);

    // Existing policy is fail-closed (error.TombstoneFull), never eviction:
    // growth stops at the cap and every retained tombstone keeps blocking.
    try testing.expectError(error.TombstoneFull, store.applySignedOffer(overflow.decoded, 0, 203));
    try testing.expectEqual(@as(usize, 3), store.tombstoneCount());
    try testing.expect(store.getTombstone(testToken(0x5d)) == null);
    const stale_first = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x5a), 1, 0, "stale"), &kp);
    defer testing.allocator.free(stale_first.wire);
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(stale_first.decoded, 9, 204)).disposition);
    try testing.expect(store.get(testToken(0x5a)) == null);

    // Replacing an already-retained origin at the cap needs no new slot.
    const newer_first = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x5a), 1, 2), &kp);
    defer testing.allocator.free(newer_first.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(newer_first.decoded, 0, 205)).disposition);
    try testing.expectEqual(@as(usize, 3), store.tombstoneCount());
    try testing.expect(store.getTombstone(testToken(0x5a)).?.revision.eql(newer_first.decoded.offer.revision));
}

test "session replica revocation of a live entry succeeds when the tombstone table is full, and stale replay stays blocked" {
    var kp = try testKey(0x70);
    defer kp.deinit();
    // TTL deliberately shorter than the superseded OFFER so the superseded
    // expiry term alone determines how long resurrection stays blocked.
    var store = Store.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_routes = 4,
        .max_tombstones = 2,
        .tombstone_ttl_ms = 100,
        .max_offer_lifetime_ms = 20_000,
    });
    defer store.deinit();

    const filler_a = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x70), 1, 1), &kp);
    defer testing.allocator.free(filler_a.wire);
    const filler_b = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x71), 1, 1), &kp);
    defer testing.allocator.free(filler_b.wire);
    _ = try store.applySignedOffer(filler_a.decoded, 0, 200);
    _ = try store.applySignedOffer(filler_b.decoded, 0, 200);

    const tok = testToken(0x72);
    var live_offer = upsertOffer(&kp, tok, 1, 1, "live");
    live_offer.expires_at_ms = 15_000;
    const live = try signedOffer(testing.allocator, live_offer, &kp);
    defer testing.allocator.free(live.wire);
    _ = try store.applySignedOffer(live.decoded, 9, 200);
    try testing.expectEqual(@as(usize, 2), store.tombstoneCount());

    // Unknown-token churn is still refused at the soft cap, without mutation.
    const unknown = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x73), 1, 1), &kp);
    defer testing.allocator.free(unknown.wire);
    try testing.expectError(error.TombstoneFull, store.applySignedOffer(unknown.decoded, 0, 201));
    try testing.expectEqual(@as(usize, 1), store.entryCount());
    try testing.expectEqual(@as(usize, 2), store.tombstoneCount());

    // The real revocation of the live entry is never blocked by that cap.
    const prior = store.supersededAuthority(tok, live.decoded.offer.revision.origin_node).?;
    try testing.expectEqual(@as(i64, 15_000), prior.expires_at_ms);
    const revoke = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(revoke.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(revoke.decoded, 0, 201)).disposition);
    try testing.expect(store.getOrigin(tok, live.decoded.offer.revision.origin_node) == null);
    try testing.expectEqual(@as(usize, 0), store.entryCount());
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectEqual(@as(usize, 3), store.tombstoneCount());
    const tombstone = store.getOriginTombstone(tok, live.decoded.offer.revision.origin_node).?;
    try testing.expect(tombstone.revision.eql(revoke.decoded.offer.revision));
    try testing.expectEqual(@as(i64, 15_000), tombstone.retain_until_ms);

    // The REVOKE is the exported anti-entropy object for this origin.
    var retained: [4]Store.RetainedObject = undefined;
    const exported = store.retainedObjectsInto(201, &retained);
    var revoke_exported = false;
    for (retained[0..exported]) |object| {
        if (tokenEql(object.token, tok)) {
            try testing.expectEqual(Store.RetainedKind.revoke, object.kind);
            try testing.expectEqualSlices(u8, revoke.wire, object.wire);
            revoke_exported = true;
        }
    }
    try testing.expect(revoke_exported);
    const report = store.retentionReport(201);
    try testing.expectEqual(@as(usize, 2), report.soft_capped_tombstones);
    try testing.expectEqual(@as(usize, 3), report.exported_tombstones);
    try testing.expectEqual(@as(?i64, 10_000), report.oldest_retain_until_ms);

    // A Helix image drops the exact superseded expiry, yet the restored
    // tombstone still blocks the superseded OFFER through its expiry.
    const image = try store.encodeUpgradeCheckpoint(testing.allocator, 201);
    defer testing.allocator.free(image);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, store.cfg, image, 201);
    defer restored.deinit();
    try testing.expect(restored.getOriginTombstone(tok, live.decoded.offer.revision.origin_node).?.retain_until_ms >= 15_000);
    _ = restored.sweep(15_000);
    try testing.expectEqual(ApplyDisposition.stale, (try restored.applySignedOffer(live.decoded, 9, 15_000)).disposition);
    try testing.expectEqual(@as(usize, 0), restored.entryCount());

    // Past the REVOKE's own expiry (10_000) it is no longer exported, but the
    // superseded OFFER (valid through 15_000) can still not resurrect.
    _ = store.sweep(10_001);
    try testing.expectEqual(@as(usize, 1), store.tombstoneCount());
    try testing.expectEqual(@as(usize, 0), store.retainedObjectsInto(10_001, &retained));
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(live.decoded, 9, 10_001)).disposition);
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(live.decoded, 9, 15_000)).disposition);
    try testing.expectEqual(@as(usize, 0), store.sweep(15_000).tombstones);
    try testing.expect(store.getOrigin(tok, live.decoded.offer.revision.origin_node) == null);
    try testing.expectEqual(@as(usize, 1), store.sweep(15_001).tombstones);
    // Once the block lapses the stale OFFER is itself expired.
    try testing.expectError(error.Expired, store.applySignedOffer(live.decoded, 9, 15_001));
    try testing.expectEqual(@as(usize, 0), store.entryCount());
}

test "session replica tombstone overflow is bounded by combined origin slots, and a new upsert then fails with EntryFull without mutation" {
    var kp = try testKey(0x74);
    defer kp.deinit();
    const cfg: Store.Config = .{ .max_entries = 2, .max_routes = 4, .max_tombstones = 1 };
    var store = Store.initWithConfig(testing.allocator, cfg);
    defer store.deinit();

    const unknown_a = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x74), 1, 1), &kp);
    defer testing.allocator.free(unknown_a.wire);
    const live_b = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x75), 1, 1, "b"), &kp);
    defer testing.allocator.free(live_b.wire);
    const live_c = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x76), 1, 1, "c"), &kp);
    defer testing.allocator.free(live_c.wire);
    const revoke_b = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x75), 1, 2), &kp);
    defer testing.allocator.free(revoke_b.wire);
    const revoke_c = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x76), 1, 2), &kp);
    defer testing.allocator.free(revoke_c.wire);
    const new_d = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x77), 1, 1, "d"), &kp);
    defer testing.allocator.free(new_d.wire);
    const unknown_e = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x78), 1, 1), &kp);
    defer testing.allocator.free(unknown_e.wire);
    const newer_b = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x75), 1, 3, "b2"), &kp);
    defer testing.allocator.free(newer_b.wire);

    _ = try store.applySignedOffer(unknown_a.decoded, 0, 200);
    _ = try store.applySignedOffer(live_b.decoded, 0, 200);
    _ = try store.applySignedOffer(live_c.decoded, 0, 200);
    _ = try store.applySignedOffer(revoke_b.decoded, 0, 201);
    try testing.expectEqual(@as(usize, 1), store.entryCount());
    try testing.expectEqual(@as(usize, 2), store.tombstoneCount());

    // entries < max_entries, but the combined bound is exhausted: a brand-new
    // upsert fails closed with the Store byte-identical.
    const before = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(before);
    try testing.expectError(error.EntryFull, store.applySignedOffer(new_d.decoded, 0, 202));
    const after = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
    try testing.expect(store.get(testToken(0x77)) == null);

    // Converting the last live entry reaches exactly the combined bound; an
    // unknown-token REVOKE beyond it is refused.
    _ = try store.applySignedOffer(revoke_c.decoded, 0, 203);
    try testing.expectEqual(@as(usize, 0), store.entryCount());
    try testing.expectEqual(session_replica_revocation.combinedSlots(cfg.retention()), store.tombstoneCount());
    try testing.expectError(error.TombstoneFull, store.applySignedOffer(unknown_e.decoded, 0, 204));
    try testing.expectError(error.EntryFull, store.applySignedOffer(new_d.decoded, 0, 204));
    try testing.expectEqual(@as(usize, 3), store.tombstoneCount());

    // A Helix image of the overflowed table restores under the same config
    // and keeps blocking stale replay; it is not rejected for exceeding the
    // tombstone soft cap.
    const image = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(image);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, cfg, image, 300);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 3), restored.tombstoneCount());
    const origin = live_b.decoded.offer.revision.origin_node;
    try testing.expect(restored.getOriginTombstone(testToken(0x75), origin).?.retain_until_ms >=
        store.getOriginTombstone(testToken(0x75), origin).?.retain_until_ms);
    try testing.expectEqual(ApplyDisposition.stale, (try restored.applySignedOffer(live_b.decoded, 0, 301)).disposition);
    // An image exceeding the combined bound is still refused.
    try testing.expectError(error.CapacityExceeded, Store.restoreUpgradeCheckpoint(testing.allocator, .{
        .max_entries = 1,
        .max_routes = 4,
        .max_tombstones = 1,
    }, image, 300));

    // A strictly newer OFFER may convert its own tombstone back to a live
    // entry: it frees that tombstone's slot in the same operation.
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(newer_b.decoded, 0, 205)).disposition);
    try testing.expectEqual(@as(usize, 1), store.entryCount());
    try testing.expectEqual(@as(usize, 2), store.tombstoneCount());
}

test "session replica conversion tombstones never exhaust the soft cap, so an unknown-token REVOKE still blocks its stale OFFER" {
    var kp = try testKey(0x7b);
    defer kp.deinit();
    const cfg: Store.Config = .{ .max_entries = 8, .max_routes = 8, .max_tombstones = 2 };
    var store = Store.initWithConfig(testing.allocator, cfg);
    defer store.deinit();
    const origin = revisionFor(&kp, 1, 1).origin_node;

    // Honest revocation volume: two live-entry conversions fill tombstones to
    // max_tombstones while entries stay well below max_entries.
    for ([_]u8{ 0x7b, 0x7c }) |byte| {
        const live = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(byte), 1, 1, "live"), &kp);
        defer testing.allocator.free(live.wire);
        const revoke = try signedOffer(testing.allocator, removeOffer(&kp, testToken(byte), 1, 2), &kp);
        defer testing.allocator.free(revoke.wire);
        _ = try store.applySignedOffer(live.decoded, 9, 200);
        _ = try store.applySignedOffer(revoke.decoded, 0, 201);
    }
    const bystander = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x7d), 1, 1, "bystander"), &kp);
    defer testing.allocator.free(bystander.wire);
    _ = try store.applySignedOffer(bystander.decoded, 9, 201);
    try testing.expectEqual(cfg.max_tombstones, store.tombstoneCount());
    try testing.expectEqual(@as(usize, 1), store.entryCount());
    try testing.expectEqual(@as(usize, 0), store.retentionReport(201).soft_capped_tombstones);

    // A partitioned node first receives REVOKE r2 for a token it never saw
    // live; it is retained, not refused with TombstoneFull.
    const tok = testToken(0x7e);
    const r1 = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "stale"), &kp);
    defer testing.allocator.free(r1.wire);
    const r2 = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(r2.wire);
    _ = try store.applySignedOffer(r2.decoded, 0, 202);
    try testing.expect(store.getOriginTombstone(tok, origin).?.revision.eql(r2.decoded.offer.revision));
    try testing.expectEqual(@as(usize, 1), store.retentionReport(202).soft_capped_tombstones);

    // The stale OFFER r1 later relayed by a peer that missed r2 is refused.
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(r1.decoded, 9, 203)).disposition);
    try testing.expect(store.getOrigin(tok, origin) == null);
    try testing.expectEqual(@as(usize, 1), store.entryCount());

    // A Helix image restores the soft-capped count from identity binding:
    // conversions stay uncounted, the unknown-token tombstone is counted,
    // and the soft cap still refuses pure unknown-token growth past it.
    const image = try store.encodeUpgradeCheckpoint(testing.allocator, 204);
    defer testing.allocator.free(image);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, cfg, image, 204);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), restored.retentionReport(204).soft_capped_tombstones);
    try testing.expectEqual(ApplyDisposition.stale, (try restored.applySignedOffer(r1.decoded, 9, 204)).disposition);
    const unknown_y = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x7f), 1, 1), &kp);
    defer testing.allocator.free(unknown_y.wire);
    const unknown_z = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x80), 1, 1), &kp);
    defer testing.allocator.free(unknown_z.wire);
    _ = try restored.applySignedOffer(unknown_y.decoded, 0, 205);
    try testing.expectEqual(@as(usize, 2), restored.retentionReport(205).soft_capped_tombstones);
    try testing.expectError(error.TombstoneFull, restored.applySignedOffer(unknown_z.decoded, 0, 205));
    try testing.expectEqual(@as(usize, 4), restored.tombstoneCount());
    // An image with more unbound tombstones than the soft cap is refused.
    const over_cap = try restored.encodeUpgradeCheckpoint(testing.allocator, 205);
    defer testing.allocator.free(over_cap);
    try testing.expectError(error.CapacityExceeded, Store.restoreUpgradeCheckpoint(testing.allocator, .{
        .max_entries = 8,
        .max_routes = 8,
        .max_tombstones = 1,
    }, over_cap, 205));

    // A strictly newer OFFER converting the soft-capped tombstone back to a
    // live entry releases its soft-cap slot; sweeping releases the rest.
    const r3 = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 3, "fresh"), &kp);
    defer testing.allocator.free(r3.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(r3.decoded, 9, 206)).disposition);
    try testing.expectEqual(@as(usize, 0), store.retentionReport(206).soft_capped_tombstones);
    _ = restored.sweep(std.math.maxInt(i64));
    try testing.expectEqual(@as(usize, 0), restored.tombstoneCount());
    try testing.expectEqual(@as(usize, 0), restored.retentionReport(std.math.maxInt(i64)).soft_capped_tombstones);
}

test "session replica live-entry revoke at a full tombstone table is allocation-failure atomic" {
    var kp = try testKey(0x79);
    defer kp.deinit();
    const tok = testToken(0x7a);
    const filler = try signedOffer(testing.allocator, removeOffer(&kp, testToken(0x79), 1, 1), &kp);
    defer testing.allocator.free(filler.wire);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const revoke = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(revoke.wire);

    var failures: usize = 0;
    var cut: usize = 0;
    while (true) : (cut += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var store = Store.initWithConfig(failing.allocator(), .{ .max_entries = 2, .max_routes = 4, .max_tombstones = 1 });
        defer store.deinit();
        _ = try store.applySignedOffer(filler.decoded, 0, 200);
        _ = try store.applySignedOffer(live.decoded, 9, 200);
        const before = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
        defer testing.allocator.free(before);
        failing.fail_index = failing.alloc_index + cut;
        const result = store.applySignedOffer(revoke.decoded, 0, 201);
        failing.fail_index = std.math.maxInt(usize);
        if (result) |applied| {
            try testing.expectEqual(ApplyDisposition.superseded, applied.disposition);
            try testing.expectEqual(@as(usize, 0), store.entryCount());
            try testing.expectEqual(@as(usize, 2), store.tombstoneCount());
            try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(live.decoded, 9, 202)).disposition);
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            const after = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
            defer testing.allocator.free(after);
            try testing.expectEqualSlices(u8, before, after);
            // Retry after the injected failure succeeds and is not stale.
            try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(revoke.decoded, 0, 201)).disposition);
            try testing.expectEqual(@as(usize, 2), store.tombstoneCount());
        }
    }
    try testing.expect(failures != 0);
}

test "session replica tombstone TTL expiry requires both TTL and signed expiry" {
    var kp = try testKey(0x5b);
    defer kp.deinit();

    // Signed expiry passes first: the tombstone survives until its TTL also
    // matures, and stale replay is still blocked in that window.
    var expiry_first = Store.initWithConfig(testing.allocator, .{
        .tombstone_ttl_ms = 10_000,
        .max_offer_lifetime_ms = 20_000,
    });
    defer expiry_first.deinit();
    var short_remove_offer = removeOffer(&kp, testToken(0x5e), 1, 2);
    short_remove_offer.expires_at_ms = 400;
    const short_remove = try signedOffer(testing.allocator, short_remove_offer, &kp);
    defer testing.allocator.free(short_remove.wire);
    const short_stale = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x5e), 1, 1, "stale"), &kp);
    defer testing.allocator.free(short_stale.wire);
    _ = try expiry_first.applySignedOffer(short_remove.decoded, 0, 300);
    try testing.expectEqual(@as(usize, 0), expiry_first.sweep(401).tombstones);
    try testing.expectEqual(@as(usize, 1), expiry_first.tombstoneCount());
    try testing.expectEqual(ApplyDisposition.stale, (try expiry_first.applySignedOffer(short_stale.decoded, 9, 401)).disposition);
    try testing.expect(expiry_first.get(testToken(0x5e)) == null);

    // TTL passes first: the tombstone survives until the signed REVOKE also
    // expires. At maturity both conditions remove it exactly once.
    var ttl_first = Store.initWithConfig(testing.allocator, .{
        .tombstone_ttl_ms = 100,
        .max_offer_lifetime_ms = 20_000,
    });
    defer ttl_first.deinit();
    const tok = testToken(0x5f);
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(remove.wire);
    const stale_live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "revoked-live"), &kp);
    defer testing.allocator.free(stale_live.wire);
    _ = try ttl_first.applySignedOffer(remove.decoded, 0, 300);
    try testing.expectEqual(@as(usize, 0), ttl_first.sweep(400).tombstones);
    try testing.expectEqual(@as(usize, 0), ttl_first.sweep(10_000).tombstones);
    try testing.expectEqual(@as(usize, 1), ttl_first.tombstoneCount());
    try testing.expectEqual(ApplyDisposition.stale, (try ttl_first.applySignedOffer(stale_live.decoded, 9, 10_000)).disposition);
    try testing.expectEqual(@as(usize, 1), ttl_first.sweep(10_001).tombstones);
    try testing.expectEqual(@as(usize, 0), ttl_first.tombstoneCount());

    // After maturity the old record is itself expired, so replay still cannot
    // resurrect it; only a strictly newer, unexpired authority can insert.
    try testing.expectError(error.Expired, ttl_first.applySignedOffer(stale_live.decoded, 9, 10_001));
    try testing.expect(ttl_first.get(tok) == null);
    var newer_offer = upsertOffer(&kp, tok, 1, 3, "after-ttl");
    newer_offer.expires_at_ms = 20_000;
    const newer = try signedOffer(testing.allocator, newer_offer, &kp);
    defer testing.allocator.free(newer.wire);
    try testing.expectEqual(ApplyDisposition.inserted, (try ttl_first.applySignedOffer(newer.decoded, 9, 10_002)).disposition);
    try testing.expectEqualStrings("after-ttl", ttl_first.get(tok).?.snapshot);
}

test "session replica same revision remove versus upsert picks deterministic digest" {
    var kp = try testKey(0x52);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(10);
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 2, 2, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, tok, 2, 2), &kp);
    defer testing.allocator.free(remove.wire);
    _ = try store.applySignedOffer(live.decoded, 1, 200);
    const result = try store.applySignedOffer(remove.decoded, 1, 201);
    const remove_digest = digestBytes(remove.decoded.transcript);
    const live_digest = digestBytes(live.decoded.transcript);
    const remove_wins = std.mem.order(u8, &remove_digest, &live_digest) == .lt;
    try testing.expectEqual(if (remove_wins) ApplyDisposition.conflict_replaced else ApplyDisposition.conflict, result.disposition);
    if (remove_wins) {
        try testing.expect(store.get(tok) == null);
        try testing.expect(store.getTombstone(tok) != null);
    } else {
        try testing.expectEqualStrings("live", store.get(tok).?.snapshot);
    }
}

test "session replica equivocation permutations retain the same canonical winner" {
    var kp = try testKey(0x54);
    defer kp.deinit();
    const tok = testToken(33);
    const x = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 3, 3, "X"), &kp);
    defer testing.allocator.free(x.wire);
    const y = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 3, 3, "Y"), &kp);
    defer testing.allocator.free(y.wire);
    const x_digest = digestBytes(x.decoded.transcript);
    const y_digest = digestBytes(y.decoded.transcript);
    const winner = if (std.mem.order(u8, &x_digest, &y_digest) == .lt) x else y;

    var xy = Store.init(testing.allocator);
    defer xy.deinit();
    var yx = Store.init(testing.allocator);
    defer yx.deinit();
    _ = try xy.applySignedOffer(x.decoded, 71, 200);
    _ = try xy.applySignedOffer(y.decoded, 72, 201);
    _ = try yx.applySignedOffer(y.decoded, 72, 200);
    _ = try yx.applySignedOffer(x.decoded, 71, 201);
    try testing.expectEqualStrings(winner.decoded.offer.snapshot, xy.get(tok).?.snapshot);
    try testing.expectEqualStrings(winner.decoded.offer.snapshot, yx.get(tok).?.snapshot);
    var xy_retained: [1]Store.RetainedObject = undefined;
    var yx_retained: [1]Store.RetainedObject = undefined;
    _ = xy.retainedObjectsInto(201, &xy_retained);
    _ = yx.retainedObjectsInto(201, &yx_retained);
    try testing.expectEqualSlices(u8, winner.wire, xy_retained[0].wire);
    try testing.expectEqualSlices(u8, winner.wire, yx_retained[0].wire);

    const revoke = try signedOffer(testing.allocator, removeOffer(&kp, tok, 3, 3), &kp);
    defer testing.allocator.free(revoke.wire);
    const revoke_digest = digestBytes(revoke.decoded.transcript);
    const upsert_wins = std.mem.order(u8, &x_digest, &revoke_digest) == .lt;
    var upsert_remove = Store.init(testing.allocator);
    defer upsert_remove.deinit();
    var remove_upsert = Store.init(testing.allocator);
    defer remove_upsert.deinit();
    _ = try upsert_remove.applySignedOffer(x.decoded, 73, 200);
    _ = try upsert_remove.applySignedOffer(revoke.decoded, 73, 201);
    _ = try remove_upsert.applySignedOffer(revoke.decoded, 73, 200);
    _ = try remove_upsert.applySignedOffer(x.decoded, 73, 201);
    try testing.expectEqual(upsert_wins, upsert_remove.get(tok) != null);
    try testing.expectEqual(upsert_wins, remove_upsert.get(tok) != null);
    _ = upsert_remove.retainedObjectsInto(201, &xy_retained);
    _ = remove_upsert.retainedObjectsInto(201, &yx_retained);
    const mixed_winner_wire = if (upsert_wins) x.wire else revoke.wire;
    try testing.expectEqualSlices(u8, mixed_winner_wire, xy_retained[0].wire);
    try testing.expectEqualSlices(u8, mixed_winner_wire, yx_retained[0].wire);

    const higher = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 3, 4, "resolved"), &kp);
    defer testing.allocator.free(higher.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try upsert_remove.applySignedOffer(higher.decoded, 74, 202)).disposition);
    try testing.expectEqual(ApplyDisposition.superseded, (try remove_upsert.applySignedOffer(higher.decoded, 74, 202)).disposition);
    try testing.expectEqualStrings("resolved", upsert_remove.get(tok).?.snapshot);
    try testing.expectEqualStrings("resolved", remove_upsert.get(tok).?.snapshot);
}

test "session replica entry route and tombstone bounds fail closed" {
    var kp = try testKey(0x61);
    defer kp.deinit();
    var entries = Store.initWithConfig(testing.allocator, .{ .max_entries = 1, .max_routes = 4, .max_tombstones = 4 });
    defer entries.deinit();
    const a = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(11), 1, 1, "a"), &kp);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(12), 1, 1, "b"), &kp);
    defer testing.allocator.free(b.wire);
    _ = try entries.applySignedOffer(a.decoded, 1, 200);
    try testing.expectError(error.EntryFull, entries.applySignedOffer(b.decoded, 2, 200));
    try testing.expectEqual(@as(usize, 1), entries.entryCount());
    try testing.expect(entries.get(testToken(11)) != null);

    var routes = Store.initWithConfig(testing.allocator, .{ .max_entries = 2, .max_routes = 1, .max_tombstones = 2 });
    defer routes.deinit();
    _ = try routes.applySignedOffer(a.decoded, 1, 200);
    const updated_before_full = routes.get(testToken(11)).?.updated_at_ms;
    try testing.expectError(error.RouteFull, routes.applySignedOffer(b.decoded, 2, 201));
    try testing.expectEqual(@as(usize, 1), routes.routeCount());
    try testing.expectEqual(updated_before_full, routes.get(testToken(11)).?.updated_at_ms);
    try testing.expect(routes.get(testToken(12)) == null);

    var tombs = Store.initWithConfig(testing.allocator, .{ .max_entries = 2, .max_routes = 2, .max_tombstones = 1 });
    defer tombs.deinit();
    const r1 = try signedOffer(testing.allocator, removeOffer(&kp, testToken(13), 1, 1), &kp);
    defer testing.allocator.free(r1.wire);
    const r2 = try signedOffer(testing.allocator, removeOffer(&kp, testToken(14), 1, 1), &kp);
    defer testing.allocator.free(r2.wire);
    _ = try tombs.applySignedOffer(r1.decoded, 0, 200);
    try testing.expectError(error.TombstoneFull, tombs.applySignedOffer(r2.decoded, 0, 201));
    try testing.expectEqual(@as(usize, 1), tombs.tombstoneCount());

    var other_origin = try testKey(0x63);
    defer other_origin.deinit();
    var origins = Store.initWithConfig(testing.allocator, .{ .max_entries = 1, .max_routes = 4, .max_tombstones = 4 });
    defer origins.deinit();
    const same_token_other_origin = try signedOffer(testing.allocator, upsertOffer(&other_origin, testToken(11), 1, 1, "other"), &other_origin);
    defer testing.allocator.free(same_token_other_origin.wire);
    _ = try origins.applySignedOffer(a.decoded, 1, 200);
    try testing.expectError(error.EntryFull, origins.applySignedOffer(same_token_other_origin.decoded, 2, 201));
    try testing.expectEqual(@as(usize, 1), origins.originCountForToken(testToken(11)));
    try testing.expect(origins.getOrigin(testToken(11), a.decoded.offer.revision.origin_node) != null);
    try testing.expect(origins.getOrigin(testToken(11), same_token_other_origin.decoded.offer.revision.origin_node) == null);
}

test "session replica store rejects expired overlong and far-future offers without mutation" {
    var kp = try testKey(0x62);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{ .max_offer_lifetime_ms = 100, .max_future_skew_ms = 100 });
    defer store.deinit();
    var expired_offer = upsertOffer(&kp, testToken(15), 1, 1, "x");
    expired_offer.issued_at_ms = 0;
    expired_offer.expires_at_ms = 10;
    const expired = try signedOffer(testing.allocator, expired_offer, &kp);
    defer testing.allocator.free(expired.wire);
    try testing.expectError(error.Expired, store.applySignedOffer(expired.decoded, 1, 11));
    var long_offer = upsertOffer(&kp, testToken(15), 1, 2, "x");
    long_offer.issued_at_ms = 0;
    long_offer.expires_at_ms = 101;
    const too_long = try signedOffer(testing.allocator, long_offer, &kp);
    defer testing.allocator.free(too_long.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(too_long.decoded, 1, 1));
    var extreme_offer = upsertOffer(&kp, testToken(15), 1, 3, "x");
    extreme_offer.issued_at_ms = 0;
    extreme_offer.expires_at_ms = std.math.maxInt(i64);
    const extreme = try signedOffer(testing.allocator, extreme_offer, &kp);
    defer testing.allocator.free(extreme.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(extreme.decoded, 1, 1));

    var future_offer = upsertOffer(&kp, testToken(15), 1, 4, "future");
    future_offer.issued_at_ms = 32_503_680_000_000;
    future_offer.expires_at_ms = future_offer.issued_at_ms + 100;
    const future = try signedOffer(testing.allocator, future_offer, &kp);
    defer testing.allocator.free(future.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(future.decoded, 1, 200));
    try testing.expectEqual(@as(usize, 0), store.entryCount());

    var boundary_offer = upsertOffer(&kp, testToken(15), 1, 5, "boundary");
    boundary_offer.issued_at_ms = 300;
    boundary_offer.expires_at_ms = 400;
    const boundary = try signedOffer(testing.allocator, boundary_offer, &kp);
    defer testing.allocator.free(boundary.wire);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(boundary.decoded, 0, 200)).disposition);

    var revision_future_offer = upsertOffer(&kp, testToken(0xf2), 301, 1, "revision-future");
    revision_future_offer.issued_at_ms = 200;
    revision_future_offer.expires_at_ms = 300;
    const revision_future = try signedOffer(testing.allocator, revision_future_offer, &kp);
    defer testing.allocator.free(revision_future.wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(revision_future.decoded, 0, 200));

    var revision_boundary_offer = upsertOffer(&kp, testToken(0xf3), 300, 1, "revision-boundary");
    revision_boundary_offer.issued_at_ms = 200;
    revision_boundary_offer.expires_at_ms = 300;
    const revision_boundary = try signedOffer(testing.allocator, revision_boundary_offer, &kp);
    defer testing.allocator.free(revision_boundary.wire);
    try testing.expectEqual(
        ApplyDisposition.inserted,
        (try store.applySignedOffer(revision_boundary.decoded, 0, 200)).disposition,
    );
}

test "session replica signed ACK is authenticated receipt metadata and never a route" {
    var origin = try testKey(0x71);
    defer origin.deinit();
    var receiver = try testKey(0x72);
    defer receiver.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(16);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, tok, 1, 1, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 0, 200);
    const ack = Ack{
        .status = .accepted,
        .token = tok,
        .offered_revision = offer.decoded.offer.revision,
        .observed_revision = offer.decoded.offer.revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 300,
    };
    const ack_wire = try encodeAck(testing.allocator, ack, &receiver);
    defer testing.allocator.free(ack_wire);
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(ack_wire), 99, 210));
    try testing.expect(!store.hasOriginRoute(tok, offer.decoded.offer.revision.origin_node, 99));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(ack_wire), 99, 220));

    var stale_ack = ack;
    stale_ack.status = .stale;
    const stale_wire = try encodeAck(testing.allocator, stale_ack, &receiver);
    defer testing.allocator.free(stale_wire);
    try testing.expectEqual(AckDisposition.ignored, try store.applySignedAck(try decodeAck(stale_wire), 100, 220));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
}

test "session replica ACK ignores route capacity and rejects expiry and revision mismatch" {
    var origin = try testKey(0x73);
    defer origin.deinit();
    var receiver = try testKey(0x74);
    defer receiver.deinit();
    var store = Store.initWithConfig(testing.allocator, .{ .max_routes = 0, .max_future_skew_ms = 100 });
    defer store.deinit();
    const tok = testToken(17);
    const offer = try signedOffer(testing.allocator, upsertOffer(&origin, tok, 1, 2, "state"), &origin);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 0, 200);
    var ack = Ack{
        .status = .accepted,
        .token = tok,
        .offered_revision = offer.decoded.offer.revision,
        .observed_revision = offer.decoded.offer.revision,
        .ack_node = signed_frame.originShortId(receiver.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 300,
    };
    const wire = try encodeAck(testing.allocator, ack, &receiver);
    defer testing.allocator.free(wire);
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(wire), 5, 210));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectError(error.Expired, store.applySignedAck(try decodeAck(wire), 5, 301));
    ack.observed_revision.sequence += 1;
    const mismatch = try encodeAck(testing.allocator, ack, &receiver);
    defer testing.allocator.free(mismatch);
    try testing.expectEqual(AckDisposition.stale, try store.applySignedAck(try decodeAck(mismatch), 5, 210));

    var future_ack = ack;
    future_ack.observed_revision = future_ack.offered_revision;
    future_ack.issued_at_ms = 32_503_680_000_000;
    future_ack.expires_at_ms = future_ack.issued_at_ms + 100;
    const future = try encodeAck(testing.allocator, future_ack, &receiver);
    defer testing.allocator.free(future);
    try testing.expectError(error.InvalidLifetime, store.applySignedAck(try decodeAck(future), 5, 210));

    var boundary_ack = ack;
    boundary_ack.observed_revision = boundary_ack.offered_revision;
    boundary_ack.issued_at_ms = 310;
    boundary_ack.expires_at_ms = 310;
    const boundary = try encodeAck(testing.allocator, boundary_ack, &receiver);
    defer testing.allocator.free(boundary);
    try testing.expectEqual(AckDisposition.accepted, try store.applySignedAck(try decodeAck(boundary), 5, 210));

    var revision_future_ack = ack;
    revision_future_ack.offered_revision = revisionFor(&origin, 311, 1);
    revision_future_ack.observed_revision = revision_future_ack.offered_revision;
    revision_future_ack.issued_at_ms = 210;
    revision_future_ack.expires_at_ms = 310;
    const revision_future = try encodeAck(testing.allocator, revision_future_ack, &receiver);
    defer testing.allocator.free(revision_future);
    try testing.expectError(
        error.InvalidLifetime,
        store.applySignedAck(try decodeAck(revision_future), 5, 210),
    );
}

test "session replica line and triangle reflections never create OFFER or ACK route loops" {
    var a_key = try testKey(0x75);
    defer a_key.deinit();
    var c_key = try testKey(0x76);
    defer c_key.deinit();
    const tok = testToken(27);
    const a_node = signed_frame.originShortId(a_key.public_key);
    const b_node: NodeId = 0xb0;
    const c_node = signed_frame.originShortId(c_key.public_key);
    const first = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 1, "A-1"), &a_key);
    defer testing.allocator.free(first.wire);

    var at_b = Store.init(testing.allocator);
    defer at_b.deinit();
    var at_c = Store.init(testing.allocator);
    defer at_c.deinit();
    _ = try at_b.applySignedOffer(first.decoded, a_node, 200);
    _ = try at_c.applySignedOffer(first.decoded, b_node, 201);

    // C reflects through the triangle to B, and A reaches C directly later.
    // Both nodes keep their causally first parent for this exact revision.
    try testing.expectEqual(ApplyDisposition.duplicate, (try at_b.applySignedOffer(first.decoded, c_node, 202)).disposition);
    try testing.expectEqual(ApplyDisposition.duplicate, (try at_c.applySignedOffer(first.decoded, a_node, 203)).disposition);
    try testing.expect(at_b.hasOriginRoute(tok, a_node, a_node));
    try testing.expect(!at_b.hasOriginRoute(tok, a_node, c_node));
    try testing.expect(at_c.hasOriginRoute(tok, a_node, b_node));
    try testing.expect(!at_c.hasOriginRoute(tok, a_node, a_node));

    const ack = Ack{
        .status = .accepted,
        .token = tok,
        .offered_revision = first.decoded.offer.revision,
        .observed_revision = first.decoded.offer.revision,
        .ack_node = c_node,
        .issued_at_ms = 200,
        .expires_at_ms = 500,
    };
    const ack_wire = try encodeAck(testing.allocator, ack, &c_key);
    defer testing.allocator.free(ack_wire);
    try testing.expectEqual(AckDisposition.accepted, try at_b.applySignedAck(try decodeAck(ack_wire), c_node, 204));
    try testing.expectEqual(@as(usize, 1), at_b.routeCount());
    try testing.expect(!at_b.hasOriginRoute(tok, a_node, c_node));

    // Losing the selected parent cannot silently reparent an old signed fact.
    try testing.expectEqual(@as(usize, 1), at_c.removePeer(b_node));
    try testing.expectEqual(ApplyDisposition.duplicate, (try at_c.applySignedOffer(first.decoded, a_node, 205)).disposition);
    try testing.expectEqual(@as(usize, 0), at_c.routeCount());
    const newer = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 2, "A-2"), &a_key);
    defer testing.allocator.free(newer.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try at_c.applySignedOffer(newer.decoded, a_node, 206)).disposition);
    try testing.expect(at_c.hasOriginRoute(tok, a_node, a_node));
}

test "session replica peer loss drops the pinned route and old revision cannot reparent" {
    var kp = try testKey(0x81);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(18);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 10, 200);
    _ = try store.applySignedOffer(offer.decoded, 11, 201);
    try testing.expectEqual(@as(usize, 1), store.routeCount());
    try testing.expectEqual(@as(usize, 1), store.removePeer(10));
    try testing.expect(!store.hasRoute(tok, offer.decoded.offer.revision.origin_node, 10));
    try testing.expect(!store.hasRoute(tok, offer.decoded.offer.revision.origin_node, 11));
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOffer(offer.decoded, 11, 202)).disposition);
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectEqual(@as(usize, 0), store.removePeer(77));
}

test "session replica sweep expires entries routes and tombstones at their exact boundaries" {
    var kp = try testKey(0x82);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{
        .route_ttl_ms = 50,
        .tombstone_ttl_ms = 100,
        .max_offer_lifetime_ms = 20_000,
    });
    defer store.deinit();

    var live_offer = upsertOffer(&kp, testToken(19), 1, 1, "live");
    live_offer.expires_at_ms = 250;
    const live = try signedOffer(testing.allocator, live_offer, &kp);
    defer testing.allocator.free(live.wire);
    _ = try store.applySignedOffer(live.decoded, 10, 200);
    const at_route_boundary = store.sweep(250);
    try testing.expectEqual(@as(usize, 0), at_route_boundary.entries);
    try testing.expectEqual(@as(usize, 1), at_route_boundary.routes);
    try testing.expect(store.get(testToken(19)) != null);
    const after_entry_expiry = store.sweep(251);
    try testing.expectEqual(@as(usize, 1), after_entry_expiry.entries);

    var removed_offer = removeOffer(&kp, testToken(20), 1, 2);
    removed_offer.expires_at_ms = 400;
    const removed = try signedOffer(testing.allocator, removed_offer, &kp);
    defer testing.allocator.free(removed.wire);
    _ = try store.applySignedOffer(removed.decoded, 0, 300);
    try testing.expectEqual(@as(usize, 0), store.sweep(400).tombstones);
    try testing.expectEqual(@as(usize, 1), store.tombstoneCount());
    try testing.expectEqual(@as(usize, 1), store.sweep(401).tombstones);
}

test "session replica sweep removes only the expired origin and its paths" {
    var a_key = try testKey(0x85);
    defer a_key.deinit();
    var b_key = try testKey(0x86);
    defer b_key.deinit();
    var store = Store.initWithConfig(testing.allocator, .{
        .route_ttl_ms = 10_000,
        .max_offer_lifetime_ms = 10_000,
    });
    defer store.deinit();
    const tok = testToken(25);
    var a_offer = upsertOffer(&a_key, tok, 1, 1, "A");
    a_offer.expires_at_ms = 250;
    var b_offer = upsertOffer(&b_key, tok, 1, 2, "B");
    b_offer.expires_at_ms = 500;
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(a.decoded, 41, 200);
    _ = try store.applySignedOffer(a.decoded, 42, 201);
    _ = try store.applySignedOffer(b.decoded, 43, 202);
    try testing.expect(store.hasLiveOriginOtherThan(tok, a.decoded.offer.revision.origin_node, 202));
    try testing.expect(store.hasLiveOriginOtherThan(tok, b.decoded.offer.revision.origin_node, 202));

    const swept = store.sweep(251);
    try testing.expectEqual(@as(usize, 1), swept.entries);
    try testing.expectEqual(@as(usize, 1), swept.routes);
    try testing.expect(store.getOrigin(tok, a.decoded.offer.revision.origin_node) == null);
    try testing.expect(!store.hasOriginRoute(tok, a.decoded.offer.revision.origin_node, null));
    try testing.expect(store.getOrigin(tok, b.decoded.offer.revision.origin_node) != null);
    try testing.expect(store.hasOriginRoute(tok, b.decoded.offer.revision.origin_node, 43));
    try testing.expectEqual(@as(usize, 1), store.routeCountForToken(tok));
    try testing.expect(store.hasLiveOriginOtherThan(tok, a.decoded.offer.revision.origin_node, 251));
    try testing.expect(!store.hasLiveOriginOtherThan(tok, b.decoded.offer.revision.origin_node, 251));
}

test "session replica routesInto reports bounded route values" {
    var kp = try testKey(0x83);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const tok = testToken(21);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 2, 3, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    _ = try store.applySignedOffer(offer.decoded, 10, 200);
    _ = try store.applySignedOffer(offer.decoded, 11, 201);
    var one: [1]Store.Route = undefined;
    try testing.expectEqual(@as(usize, 1), store.routesInto(tok, &one));
    try testing.expect(one[0].revision.eql(offer.decoded.offer.revision));
    try testing.expectEqual(@as(usize, 1), store.routeCountForToken(tok));
}

test "session replica insertion is leak-clean at every allocation failure" {
    var kp = try testKey(0x84);
    defer kp.deinit();
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(22), 4, 5, "state"), &kp);
    defer testing.allocator.free(offer.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, signed: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            const result = try store.applySignedOffer(signed, 10, 200);
            try testing.expectEqual(ApplyDisposition.inserted, result.disposition);
            try testing.expectEqualStrings("state", store.get(signed.offer.token).?.snapshot);
            try testing.expectEqual(@as(usize, 1), store.routeCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{offer.decoded});
}

test "session replica concurrent origin insertion is transactional at every allocation failure" {
    var a_key = try testKey(0x87);
    defer a_key.deinit();
    var b_key = try testKey(0x88);
    defer b_key.deinit();
    const tok = testToken(26);
    const a = try signedOffer(testing.allocator, upsertOffer(&a_key, tok, 1, 1, "A"), &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, upsertOffer(&b_key, tok, 1, 2, "B"), &b_key);
    defer testing.allocator.free(b.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, first: SignedOffer, second: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(first, 51, 200);
            _ = try store.applySignedOffer(second, 52, 201);
            try testing.expectEqual(@as(usize, 2), store.originCountForToken(first.offer.token));
            try testing.expect(store.getOrigin(first.offer.token, first.offer.revision.origin_node) != null);
            try testing.expect(store.getOrigin(second.offer.token, second.offer.revision.origin_node) != null);
            try testing.expectEqual(@as(usize, 2), store.routeCountForToken(first.offer.token));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ a.decoded, b.decoded });
}

test "session replica hot lookups cover max origins without allocation and filter expiry" {
    var a_key = try testKey(0x8b);
    defer a_key.deinit();
    var b_key = try testKey(0x8c);
    defer b_key.deinit();
    var c_key = try testKey(0x8d);
    defer c_key.deinit();
    var d_key = try testKey(0x8e);
    defer d_key.deinit();
    const tok = testToken(37);
    var a_offer = upsertOffer(&a_key, tok, 1, 1, "A");
    a_offer.expires_at_ms = 500;
    var b_offer = upsertOffer(&b_key, tok, 9, 9, "B");
    b_offer.expires_at_ms = 250;
    const a = try signedOffer(testing.allocator, a_offer, &a_key);
    defer testing.allocator.free(a.wire);
    const b = try signedOffer(testing.allocator, b_offer, &b_key);
    defer testing.allocator.free(b.wire);
    const c = try signedOffer(testing.allocator, upsertOffer(&c_key, tok, 1, 2, "C"), &c_key);
    defer testing.allocator.free(c.wire);
    const d = try signedOffer(testing.allocator, upsertOffer(&d_key, tok, 1, 3, "D"), &d_key);
    defer testing.allocator.free(d.wire);
    var store = Store.initWithConfig(testing.allocator, .{ .max_entries = 3, .max_routes = 3 });
    defer store.deinit();
    _ = try store.applySignedOffer(a.decoded, 101, 200);
    _ = try store.applySignedOffer(b.decoded, 102, 200);
    _ = try store.applySignedOffer(c.decoded, 103, 200);
    try testing.expectError(error.EntryFull, store.applySignedOffer(d.decoded, 104, 200));
    try testing.expect(store.hasAuthorityRouteVia(tok, 101));
    try testing.expect(store.hasAuthorityRouteVia(tok, 102));
    try testing.expect(store.hasAuthorityRouteVia(tok, 103));
    try testing.expect(!store.hasAuthorityRouteVia(tok, 104));
    try testing.expectEqualStrings("B", store.bestIdentity(tok).?.snapshot);
    try testing.expectEqualStrings("C", store.bestLiveIdentity(tok, 300).?.snapshot);
}

test "session replica unique origin nick lookup is live ambiguity and quarantine safe" {
    var origin_key = try testKey(0x91);
    defer origin_key.deinit();
    var conflicting_key = try testKey(0x92);
    defer conflicting_key.deinit();
    const origin_node = signed_frame.originShortId(origin_key.public_key);
    const first_token = testToken(39);
    const second_token = testToken(40);
    var first_offer = upsertOffer(&origin_key, first_token, 1, 1, "first");
    first_offer.expires_at_ms = 500;
    const first = try signedOffer(testing.allocator, first_offer, &origin_key);
    defer testing.allocator.free(first.wire);
    var second_offer = upsertOffer(&origin_key, second_token, 1, 2, "second");
    second_offer.expires_at_ms = 250;
    const second = try signedOffer(testing.allocator, second_offer, &origin_key);
    defer testing.allocator.free(second.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(first.decoded, 121, 200);
    _ = try store.applySignedOffer(second.decoded, 122, 200);
    // Downgrade suppression is identity-wide, ASCII-case-insensitive, and must
    // remain true when more than one exact token carries signed authority.
    try testing.expect(store.hasLiveIdentity("ALICE", "aLiCe", 200));
    try testing.expect(store.hasRetainedNick("aLiCe", 200));
    try testing.expect(!store.hasLiveIdentity("mallory", "Alice", 200));
    try testing.expect(!store.hasLiveIdentity("alice", "Alice", 501));
    try testing.expectError(error.Ambiguous, store.uniqueLiveOriginNick(origin_node, "Alice", 200));
    const unique_case_variant = (try store.uniqueLiveOriginNick(origin_node, "alice", 300)).?;
    try testing.expect(tokenEql(first_token, unique_case_variant.token));
    const unique = (try store.uniqueLiveOriginNick(origin_node, "Alice", 300)).?;
    try testing.expect(tokenEql(first_token, unique.token));
    try testing.expectEqualStrings("first", unique.entry.snapshot);

    var conflicting_offer = upsertOffer(&conflicting_key, first_token, 9, 9, "conflict");
    conflicting_offer.account = "mallory";
    const conflicting = try signedOffer(testing.allocator, conflicting_offer, &conflicting_key);
    defer testing.allocator.free(conflicting.wire);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(conflicting.decoded, 123, 301)).disposition);
    try testing.expect((try store.uniqueLiveOriginNick(origin_node, "Alice", 301)) == null);
    // Full quarantine removes ordinary entries, but both signed identities stay
    // fail-closed downgrade evidence until the shorter OFFER lifetime ends.
    try testing.expect(store.hasLiveIdentity("ALICE", "aLiCe", 301));
    try testing.expect(store.hasLiveIdentity("mallory", "ALICE", 301));
    try testing.expect(!store.hasLiveIdentity("alice", "Alice", 501));
    try testing.expect(!store.hasLiveIdentity("mallory", "Alice", 501));
    try testing.expect(!store.hasRetainedNick("Alice", 501));

    // If evidence allocation/capacity is unavailable, the embedded deny marker
    // on the surviving entry must still guard its signed identity.
    var capped = Store.initWithConfig(testing.allocator, .{ .max_quarantines = 0 });
    defer capped.deinit();
    _ = try capped.applySignedOffer(first.decoded, 121, 200);
    try testing.expectError(error.QuarantineFull, capped.applySignedOffer(conflicting.decoded, 123, 301));
    try testing.expect(capped.hasLiveIdentity("alice", "ALICE", 301));
    try testing.expect(capped.hasRetainedNick("aLiCe", 301));
    try testing.expect(!capped.hasLiveIdentity("alice", "ALICE", 501));
    try testing.expect(!capped.hasRetainedNick("Alice", 501));
}

test "session replica retained REVOKE replacement is transactional at every allocation failure" {
    var kp = try testKey(0x89);
    defer kp.deinit();
    const tok = testToken(30);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "live"), &kp);
    defer testing.allocator.free(offer.wire);
    const revoke = try signedOffer(testing.allocator, removeOffer(&kp, tok, 1, 2), &kp);
    defer testing.allocator.free(revoke.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, live: SignedOffer, removed: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(live, 61, 200);
            _ = try store.applySignedOffer(removed, 61, 201);
            try testing.expect(store.getOrigin(live.offer.token, live.offer.revision.origin_node) == null);
            try testing.expect(store.getOriginTombstone(live.offer.token, live.offer.revision.origin_node) != null);
            var retained: [1]Store.RetainedObject = undefined;
            try testing.expectEqual(@as(usize, 1), store.retainedObjectsInto(201, &retained));
            try testing.expectEqual(Store.RetainedKind.revoke, retained[0].kind);
            try verifyOffer(try decodeOffer(retained[0].wire));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ offer.decoded, revoke.decoded });
}

test "session replica deterministic equivocation replacement is transactional at every allocation failure" {
    var kp = try testKey(0x8a);
    defer kp.deinit();
    const tok = testToken(34);
    const x = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "X"), &kp);
    defer testing.allocator.free(x.wire);
    const y = try signedOffer(testing.allocator, upsertOffer(&kp, tok, 1, 1, "Y"), &kp);
    defer testing.allocator.free(y.wire);
    const x_digest = digestBytes(x.decoded.transcript);
    const y_digest = digestBytes(y.decoded.transcript);
    const winner = if (std.mem.order(u8, &x_digest, &y_digest) == .lt) x.decoded else y.decoded;
    const loser = if (std.mem.order(u8, &x_digest, &y_digest) == .lt) y.decoded else x.decoded;

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, losing: SignedOffer, winning: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(losing, 81, 200);
            try testing.expectEqual(ApplyDisposition.conflict_replaced, (try store.applySignedOffer(winning, 82, 201)).disposition);
            try testing.expectEqualStrings(winning.offer.snapshot, store.get(winning.offer.token).?.snapshot);
            var retained: [1]Store.RetainedObject = undefined;
            _ = store.retainedObjectsInto(201, &retained);
            try testing.expectEqualSlices(u8, winning.transcript, (try decodeOffer(retained[0].wire)).transcript);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ loser, winner });
}

test "session replica account quarantine is fail-closed at every allocation failure" {
    var alice_key = try testKey(0x8f);
    defer alice_key.deinit();
    var mallory_key = try testKey(0x90);
    defer mallory_key.deinit();
    const tok = testToken(38);
    const alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, tok, 1, 1, "Alice"), &alice_key);
    defer testing.allocator.free(alice.wire);
    var mallory_offer = upsertOffer(&mallory_key, tok, 1, 1, "Mallory");
    mallory_offer.account = "mallory";
    const mallory = try signedOffer(testing.allocator, mallory_offer, &mallory_key);
    defer testing.allocator.free(mallory.wire);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, first: SignedOffer, conflicting: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(first, 111, 200);
            const result = store.applySignedOffer(conflicting, 112, 201) catch |err| {
                if (err == error.OutOfMemory) {
                    try testing.expect(store.isQuarantined(first.offer.token));
                    try testing.expect(store.bestIdentity(first.offer.token) == null);
                    try testing.expectEqual(@as(usize, 0), store.routeCountForToken(first.offer.token));
                }
                return err;
            };
            try testing.expectEqual(ApplyDisposition.quarantined, result.disposition);
            try testing.expect(store.isQuarantined(first.offer.token));
            try testing.expect(store.bestIdentity(first.offer.token) == null);
            try testing.expectEqual(@as(usize, 2), store.retainedCount(201));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ alice.decoded, mallory.decoded });
}

test "session replica upgrade checkpoint preserves exact authority and deny state without routes" {
    var alice_key = try testKey(0xa1);
    defer alice_key.deinit();
    var second_key = try testKey(0xa2);
    defer second_key.deinit();
    var mallory_key = try testKey(0xa3);
    defer mallory_key.deinit();

    const live_token = testToken(0xa1);
    const tombstone_token = testToken(0xa2);
    const quarantine_token = testToken(0xa3);
    const denied_entry_token = testToken(0xa4);
    const denied_tombstone_token = testToken(0xa5);

    const live = try signedOffer(testing.allocator, upsertOffer(&alice_key, live_token, 1, 1, "live"), &alice_key);
    defer testing.allocator.free(live.wire);
    const removed_live = try signedOffer(testing.allocator, upsertOffer(&second_key, tombstone_token, 2, 1, "removed"), &second_key);
    defer testing.allocator.free(removed_live.wire);
    const removed = try signedOffer(testing.allocator, removeOffer(&second_key, tombstone_token, 3, 1), &second_key);
    defer testing.allocator.free(removed.wire);
    const quarantined_alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, quarantine_token, 4, 1, "alice-q"), &alice_key);
    defer testing.allocator.free(quarantined_alice.wire);
    var quarantined_mallory_offer = upsertOffer(&mallory_key, quarantine_token, 5, 1, "mallory-q");
    quarantined_mallory_offer.account = "mallory";
    const quarantined_mallory = try signedOffer(testing.allocator, quarantined_mallory_offer, &mallory_key);
    defer testing.allocator.free(quarantined_mallory.wire);
    const denied_entry_alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, denied_entry_token, 6, 1, "alice-denied"), &alice_key);
    defer testing.allocator.free(denied_entry_alice.wire);
    var denied_entry_mallory_offer = upsertOffer(&mallory_key, denied_entry_token, 7, 1, "mallory-denied");
    denied_entry_mallory_offer.account = "mallory";
    const denied_entry_mallory = try signedOffer(testing.allocator, denied_entry_mallory_offer, &mallory_key);
    defer testing.allocator.free(denied_entry_mallory.wire);
    const denied_tombstone_alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, denied_tombstone_token, 8, 1, "alice-removed"), &alice_key);
    defer testing.allocator.free(denied_tombstone_alice.wire);
    const denied_tombstone_remove = try signedOffer(testing.allocator, removeOffer(&alice_key, denied_tombstone_token, 9, 1), &alice_key);
    defer testing.allocator.free(denied_tombstone_remove.wire);
    var denied_tombstone_mallory_offer = upsertOffer(&mallory_key, denied_tombstone_token, 10, 1, "mallory-replay");
    denied_tombstone_mallory_offer.account = "mallory";
    const denied_tombstone_mallory = try signedOffer(testing.allocator, denied_tombstone_mallory_offer, &mallory_key);
    defer testing.allocator.free(denied_tombstone_mallory.wire);

    const cfg = Store.Config{ .max_quarantines = 1 };
    var source = Store.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    _ = try source.applySignedOffer(live.decoded, 501, 200);
    _ = try source.applySignedOffer(removed_live.decoded, 502, 201);
    _ = try source.applySignedOffer(removed.decoded, 502, 202);
    _ = try source.applySignedOffer(quarantined_alice.decoded, 503, 203);
    try testing.expectEqual(ApplyDisposition.quarantined, (try source.applySignedOffer(quarantined_mallory.decoded, 504, 204)).disposition);
    _ = try source.applySignedOffer(denied_entry_alice.decoded, 505, 205);
    try testing.expectError(error.QuarantineFull, source.applySignedOffer(denied_entry_mallory.decoded, 506, 206));
    _ = try source.applySignedOffer(denied_tombstone_alice.decoded, 507, 207);
    _ = try source.applySignedOffer(denied_tombstone_remove.decoded, 507, 208);
    try testing.expectEqual(ApplyDisposition.quarantined, (try source.applySignedOffer(denied_tombstone_mallory.decoded, 508, 209)).disposition);

    try testing.expectEqual(@as(usize, 2), source.entryCount());
    try testing.expectEqual(@as(usize, 2), source.tombstoneCount());
    try testing.expectEqual(@as(usize, 1), source.quarantineCount());
    try testing.expectEqual(@as(usize, 1), source.routeCount());
    const denied_entry_key = Store.OriginKey{ .token = denied_entry_token, .origin_node = denied_entry_alice.decoded.offer.revision.origin_node };
    const denied_tombstone_key = Store.OriginKey{ .token = denied_tombstone_token, .origin_node = denied_tombstone_remove.decoded.offer.revision.origin_node };
    try testing.expectEqual(@as(?i64, 10_000), source.entries.get(denied_entry_key).?.quarantine_until_ms);
    try testing.expectEqual(@as(?i64, 10_000), source.tombstones.get(denied_tombstone_key).?.quarantine_until_ms);
    try testing.expect(source.tombstones.get(denied_tombstone_key).?.identity_digest != null);

    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 500);
    defer testing.allocator.free(checkpoint);
    try testing.expect(Store.isUpgradeCheckpoint(checkpoint));
    try testing.expect(isUpgradeCheckpoint(checkpoint));

    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, cfg, checkpoint, 500);
    defer restored.deinit();
    try testing.expectEqual(source.entryCount(), restored.entryCount());
    try testing.expectEqual(source.tombstoneCount(), restored.tombstoneCount());
    try testing.expectEqual(source.quarantineCount(), restored.quarantineCount());
    try testing.expectEqual(@as(usize, 0), restored.routeCount());

    const restored_live = restored.entries.get(.{ .token = live_token, .origin_node = live.decoded.offer.revision.origin_node }).?;
    try testing.expectEqualSlices(u8, live.wire, restored_live.wire);
    try testing.expectEqual(@as(i64, 200), restored_live.updated_at_ms);
    try testing.expectEqual(@as(?NodeId, null), restored_live.ingress_peer);
    const restored_removed = restored.tombstones.get(.{ .token = tombstone_token, .origin_node = removed.decoded.offer.revision.origin_node }).?;
    try testing.expectEqualSlices(u8, removed.wire, restored_removed.wire);
    try testing.expectEqual(@as(i64, 202), restored_removed.removed_at_ms);
    try testing.expect(restored_removed.identity_digest != null);
    try testing.expectEqual(@as(?i64, 10_000), restored.entries.get(denied_entry_key).?.quarantine_until_ms);
    try testing.expectEqual(@as(?i64, 10_000), restored.tombstones.get(denied_tombstone_key).?.quarantine_until_ms);

    const source_quarantine = source.quarantines.get(quarantine_token).?;
    const restored_quarantine = restored.quarantines.get(quarantine_token).?;
    try testing.expectEqualSlices(u8, source_quarantine.first_wire, restored_quarantine.first_wire);
    try testing.expectEqualSlices(u8, source_quarantine.second_wire, restored_quarantine.second_wire);
    try testing.expectEqual(source_quarantine.expires_at_ms, restored_quarantine.expires_at_ms);
    try testing.expectEqual(source_quarantine.detected_at_ms, restored_quarantine.detected_at_ms);

    try testing.expectError(error.QuarantineFull, restored.applySignedOffer(denied_entry_mallory.decoded, 601, 501));
    try testing.expectEqual(ApplyDisposition.quarantined, (try restored.applySignedOffer(denied_tombstone_mallory.decoded, 602, 501)).disposition);
    try testing.expectEqual(ApplyDisposition.quarantined, (try restored.applySignedOffer(quarantined_alice.decoded, 603, 501)).disposition);
}

test "session replica upgrade checkpoint v2 preserves attachment leases and accepts v1" {
    var origin = try testKey(0xa4);
    defer origin.deinit();
    const live_token = testToken(0xa4);
    const conflicted_token = testToken(0xa5);

    const live_offer = try signedOffer(testing.allocator, upsertOffer(&origin, live_token, 200, 1, "live"), &origin);
    defer testing.allocator.free(live_offer.wire);
    const conflicted_offer = try signedOffer(testing.allocator, upsertOffer(&origin, conflicted_token, 210, 1, "conflicted"), &origin);
    defer testing.allocator.free(conflicted_offer.wire);
    const live_lease = try signedAttachmentLease(testing.allocator, .{
        .token = live_token,
        .revision = revisionFor(&origin, 201, 1),
        .issued_at_ms = 150,
        .expires_at_ms = 350,
    }, &origin);
    defer testing.allocator.free(live_lease.wire);
    const conflict_first = try signedAttachmentLease(testing.allocator, .{
        .token = conflicted_token,
        .revision = revisionFor(&origin, 211, 1),
        .issued_at_ms = 150,
        .expires_at_ms = 350,
    }, &origin);
    defer testing.allocator.free(conflict_first.wire);
    const conflict_second = try signedAttachmentLease(testing.allocator, .{
        .token = conflicted_token,
        .revision = revisionFor(&origin, 211, 1),
        .issued_at_ms = 151,
        .expires_at_ms = 350,
    }, &origin);
    defer testing.allocator.free(conflict_second.wire);

    var source = Store.init(testing.allocator);
    defer source.deinit();
    _ = try source.applySignedOffer(live_offer.decoded, 0, 200);
    _ = try source.applySignedOffer(conflicted_offer.decoded, 0, 220);
    _ = try source.applySignedAttachmentLease(live_lease.decoded, 200);
    _ = try source.applySignedAttachmentLease(conflict_first.decoded, 220);
    try testing.expectEqual(
        AttachmentLeaseDisposition.conflict,
        try source.applySignedAttachmentLease(conflict_second.decoded, 220),
    );

    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 250);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreCurrentUpgradeCheckpoint(testing.allocator, source.cfg, checkpoint, 250);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.attachmentLeaseCount());
    try testing.expect(restored.hasAttachedOriginOtherThan(live_token, 999, 250));
    try testing.expect(!restored.hasAttachedOriginOtherThan(conflicted_token, 999, 250));
    try testing.expectEqualSlices(
        u8,
        live_lease.wire,
        restored.getAttachmentLease(live_token, live_offer.decoded.offer.revision.origin_node).?.wire,
    );
    try testing.expect(restored.getAttachmentLease(
        conflicted_token,
        conflicted_offer.decoded.offer.revision.origin_node,
    ).?.conflicted);
    try testing.expectEqualSlices(
        u8,
        conflict_second.wire,
        restored.getAttachmentLease(
            conflicted_token,
            conflicted_offer.decoded.offer.revision.origin_node,
        ).?.conflict_wire.?,
    );
    try testing.expect(restored.maxAuthorityRevision().?.eql(conflict_first.decoded.lease.revision));

    try testing.expectError(
        error.CapacityExceeded,
        Store.restoreUpgradeCheckpoint(testing.allocator, .{ .max_attachment_leases = 1 }, checkpoint, 250),
    );
    var expired = try Store.restoreUpgradeCheckpoint(testing.allocator, source.cfg, checkpoint, 351);
    defer expired.deinit();
    try testing.expectEqual(@as(usize, 2), expired.attachmentLeaseCount());
    try testing.expect(expired.hasAttachedOriginOtherThan(live_token, 999, 351));
    try testing.expect(!expired.hasAttachedOriginOtherThan(live_token, 999, 10_001));
    try testing.expect(!expired.hasAttachedOriginOtherThan(conflicted_token, 999, 351));
    try testing.expectEqual(@as(usize, 2), expired.entryCount());

    var legacy_source = Store.init(testing.allocator);
    defer legacy_source.deinit();
    _ = try legacy_source.applySignedOffer(live_offer.decoded, 0, 200);
    const v2_without_leases = try legacy_source.encodeUpgradeCheckpoint(testing.allocator, 250);
    defer testing.allocator.free(v2_without_leases);
    const v1 = try testDowngradeEmptyLeaseCheckpointToV1(testing.allocator, v2_without_leases);
    defer testing.allocator.free(v1);
    try testing.expectError(
        error.UnsupportedVersion,
        Store.restoreCurrentUpgradeCheckpoint(testing.allocator, .{}, v1, 250),
    );
    var legacy = try Store.restoreColdMigrationCheckpoint(testing.allocator, .{}, v1, 250);
    defer legacy.deinit();
    try testing.expectEqual(@as(usize, 1), legacy.entryCount());
    try testing.expectEqual(@as(usize, 0), legacy.attachmentLeaseCount());
    try testing.expect(!legacy.hasAttachedOriginOtherThan(live_token, 999, 250));
}

test "session replica upgrade checkpoint strictly rejects truncation corruption duplicates and excess capacity" {
    var first_key = try testKey(0xb1);
    defer first_key.deinit();
    var second_key = try testKey(0xb2);
    defer second_key.deinit();
    const first = try signedOffer(testing.allocator, upsertOffer(&first_key, testToken(0xb1), 1, 1, "same-size"), &first_key);
    defer testing.allocator.free(first.wire);
    const second = try signedOffer(testing.allocator, upsertOffer(&second_key, testToken(0xb2), 2, 1, "same-size"), &second_key);
    defer testing.allocator.free(second.wire);
    const first_lease = try signedAttachmentLease(testing.allocator, .{
        .token = first.decoded.offer.token,
        .revision = revisionFor(&first_key, 103, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 400,
    }, &first_key);
    defer testing.allocator.free(first_lease.wire);
    const second_lease = try signedAttachmentLease(testing.allocator, .{
        .token = second.decoded.offer.token,
        .revision = revisionFor(&second_key, 104, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 400,
    }, &second_key);
    defer testing.allocator.free(second_lease.wire);

    var source = Store.init(testing.allocator);
    defer source.deinit();
    _ = try source.applySignedOffer(first.decoded, 701, 200);
    _ = try source.applySignedOffer(second.decoded, 702, 201);
    _ = try source.applySignedAttachmentLease(first_lease.decoded, 200);
    _ = try source.applySignedAttachmentLease(second_lease.decoded, 201);
    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(checkpoint);

    // Every strict prefix, including a complete body without its checksum, is
    // invalid and must remain leak-free.
    for (0..checkpoint.len) |len| try expectUpgradeCheckpointRejected(.{}, checkpoint[0..len], 300);

    // The digest covers the complete header, every record byte, and every
    // metadata flag. A one-bit fault at every possible byte position is always
    // rejected (magic faults may fail before digest verification).
    var bitflip = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(bitflip);
    for (0..bitflip.len) |index| {
        bitflip[index] ^= 1;
        try expectUpgradeCheckpointRejected(.{}, bitflip, 300);
        bitflip[index] ^= 1;
    }

    var damaged = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(damaged);
    damaged[upgrade_checkpoint_header_len] ^= 0x80;
    try testing.expectError(error.ChecksumMismatch, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    @memcpy(damaged, checkpoint);
    damaged[0] ^= 0xff;
    try testing.expectError(error.BadMagic, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    @memcpy(damaged, checkpoint);
    damaged[upgrade_checkpoint_magic.len] = upgrade_checkpoint_version + 1;
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.UnsupportedVersion, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    // The first entry's optional-marker tag follows its wire and timestamp.
    @memcpy(damaged, checkpoint);
    const first_record = upgrade_checkpoint_header_len;
    const first_wire_len: usize = std.mem.readInt(u32, damaged[first_record..][0..4], .big);
    damaged[first_record + 4 + first_wire_len + 8] = 2;
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.InvalidMetadata, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    // A body with a valid checksum but one extra unclaimed byte is rejected.
    var trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    const original_body_end = checkpoint.len - upgrade_checkpoint_checksum_len;
    @memcpy(trailing[0..original_body_end], checkpoint[0..original_body_end]);
    trailing[original_body_end] = 0;
    @memcpy(trailing[original_body_end + 1 ..], checkpoint[original_body_end..]);
    rewriteUpgradeCheckpointChecksum(trailing);
    try testing.expectError(error.TrailingBytes, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, trailing, 300));

    // Re-checksum a forged signature to prove verification is independent of
    // the arena checksum.
    @memcpy(damaged, checkpoint);
    damaged[first_record + 4 + first_wire_len - 1] ^= 1;
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.InvalidSignedObject, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    // Both canonical wires have equal size. Replacing record two with record
    // one produces an exact duplicate OriginKey that strict restore rejects.
    @memcpy(damaged, checkpoint);
    const second_record = first_record + 4 + first_wire_len + 8 + 1;
    const second_wire_len: usize = std.mem.readInt(u32, damaged[second_record..][0..4], .big);
    try testing.expectEqual(first_wire_len, second_wire_len);
    @memcpy(damaged[second_record + 4 ..][0..second_wire_len], damaged[first_record + 4 ..][0..first_wire_len]);
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.DuplicateState, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    const first_lease_record = second_record + 4 + second_wire_len + 8 + 1;
    const first_lease_wire_len: usize = std.mem.readInt(u32, checkpoint[first_lease_record..][0..4], .big);
    const first_lease_conflicted = first_lease_record + 4 + first_lease_wire_len;

    @memcpy(damaged, checkpoint);
    damaged[first_lease_conflicted] = 3;
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.InvalidMetadata, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    @memcpy(damaged, checkpoint);
    damaged[first_lease_record + 4 + first_lease_wire_len - 1] ^= 1;
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.InvalidSignedObject, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    const second_lease_record = first_lease_conflicted + 1;
    const second_lease_wire_len: usize = std.mem.readInt(u32, checkpoint[second_lease_record..][0..4], .big);
    try testing.expectEqual(first_lease_wire_len, second_lease_wire_len);
    @memcpy(damaged, checkpoint);
    @memcpy(
        damaged[second_lease_record + 4 ..][0..second_lease_wire_len],
        checkpoint[first_lease_record + 4 ..][0..first_lease_wire_len],
    );
    rewriteUpgradeCheckpointChecksum(damaged);
    try testing.expectError(error.DuplicateState, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, damaged, 300));

    try testing.expectError(
        error.CapacityExceeded,
        Store.restoreUpgradeCheckpoint(testing.allocator, .{ .max_entries = 1 }, checkpoint, 300),
    );
    try testing.expectError(
        error.CapacityExceeded,
        Store.restoreUpgradeCheckpoint(testing.allocator, .{ .max_attachment_leases = 1 }, checkpoint, 300),
    );
}

test "session replica upgrade checkpoint replacement is atomic under capacity corruption and OOM" {
    var source_key = try testKey(0xc1);
    defer source_key.deinit();
    var second_key = try testKey(0xc2);
    defer second_key.deinit();
    const first = try signedOffer(testing.allocator, upsertOffer(&source_key, testToken(0xc1), 1, 1, "first"), &source_key);
    defer testing.allocator.free(first.wire);
    const second = try signedOffer(testing.allocator, upsertOffer(&second_key, testToken(0xc2), 2, 1, "second"), &second_key);
    defer testing.allocator.free(second.wire);
    var source = Store.init(testing.allocator);
    defer source.deinit();
    _ = try source.applySignedOffer(first.decoded, 801, 200);
    _ = try source.applySignedOffer(second.decoded, 802, 201);
    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(checkpoint);

    var sentinel_key = try testKey(0xc3);
    defer sentinel_key.deinit();
    const sentinel = try signedOffer(testing.allocator, upsertOffer(&sentinel_key, testToken(0xcf), 3, 1, "sentinel"), &sentinel_key);
    defer testing.allocator.free(sentinel.wire);
    var capacity_target = Store.initWithConfig(testing.allocator, .{ .max_entries = 1 });
    defer capacity_target.deinit();
    _ = try capacity_target.applySignedOffer(sentinel.decoded, 803, 202);
    try testing.expectError(error.CapacityExceeded, capacity_target.replaceFromUpgradeCheckpoint(checkpoint, 300));
    try testing.expectEqualStrings("sentinel", capacity_target.get(sentinel.decoded.offer.token).?.snapshot);

    var corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[upgrade_checkpoint_header_len] ^= 1;
    try testing.expectError(error.ChecksumMismatch, capacity_target.replaceFromUpgradeCheckpoint(corrupt, 300));
    try testing.expectEqualStrings("sentinel", capacity_target.get(sentinel.decoded.offer.token).?.snapshot);

    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var oom_target = Store.initWithConfig(failing.allocator(), .{ .max_entries = 3 });
    defer oom_target.deinit();
    _ = try oom_target.applySignedOffer(sentinel.decoded, 803, 202);
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, oom_target.replaceFromUpgradeCheckpoint(checkpoint, 300));
    failing.fail_index = std.math.maxInt(usize);
    try testing.expectEqual(@as(usize, 1), oom_target.entryCount());
    try testing.expectEqualStrings("sentinel", oom_target.get(sentinel.decoded.offer.token).?.snapshot);
}

test "session replica upgrade checkpoint sweeps at restore time and tolerates wall rollback" {
    var alice_key = try testKey(0xd1);
    defer alice_key.deinit();
    var mallory_key = try testKey(0xd2);
    defer mallory_key.deinit();

    var live_offer = upsertOffer(&alice_key, testToken(0xd1), 1, 1, "expires");
    live_offer.expires_at_ms = 500;
    const live = try signedOffer(testing.allocator, live_offer, &alice_key);
    defer testing.allocator.free(live.wire);
    var removed_offer = upsertOffer(&alice_key, testToken(0xd2), 2, 1, "removed");
    removed_offer.expires_at_ms = 500;
    const removed_live = try signedOffer(testing.allocator, removed_offer, &alice_key);
    defer testing.allocator.free(removed_live.wire);
    var revoke_offer = removeOffer(&alice_key, testToken(0xd2), 3, 1);
    revoke_offer.expires_at_ms = 500;
    const revoke = try signedOffer(testing.allocator, revoke_offer, &alice_key);
    defer testing.allocator.free(revoke.wire);
    var quarantine_alice_offer = upsertOffer(&alice_key, testToken(0xd3), 4, 1, "q-alice");
    quarantine_alice_offer.expires_at_ms = 400;
    const quarantine_alice = try signedOffer(testing.allocator, quarantine_alice_offer, &alice_key);
    defer testing.allocator.free(quarantine_alice.wire);
    var quarantine_mallory_offer = upsertOffer(&mallory_key, testToken(0xd3), 5, 1, "q-mallory");
    quarantine_mallory_offer.account = "mallory";
    quarantine_mallory_offer.expires_at_ms = 500;
    const quarantine_mallory = try signedOffer(testing.allocator, quarantine_mallory_offer, &mallory_key);
    defer testing.allocator.free(quarantine_mallory.wire);

    // Restored tombstones retain through the accepted-authority horizon
    // (removed + lifetime + skew = 202 + 2_000) as well as the TTL window.
    const cfg = Store.Config{ .tombstone_ttl_ms = 5_000, .max_offer_lifetime_ms = 1_000, .max_future_skew_ms = 1_000 };
    var source = Store.initWithConfig(testing.allocator, cfg);
    defer source.deinit();
    _ = try source.applySignedOffer(live.decoded, 901, 200);
    _ = try source.applySignedOffer(removed_live.decoded, 902, 201);
    _ = try source.applySignedOffer(revoke.decoded, 902, 202);
    _ = try source.applySignedOffer(quarantine_alice.decoded, 903, 203);
    try testing.expectEqual(ApplyDisposition.quarantined, (try source.applySignedOffer(quarantine_mallory.decoded, 904, 204)).disposition);
    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(checkpoint);

    // Restore wall time moving backward does not make already accepted signed
    // facts look future-issued; capture time owns that validation boundary.
    var rollback = try Store.restoreUpgradeCheckpoint(testing.allocator, cfg, checkpoint, 150);
    defer rollback.deinit();
    try testing.expectEqual(@as(usize, 1), rollback.entryCount());
    try testing.expectEqual(@as(usize, 1), rollback.tombstoneCount());
    try testing.expectEqual(@as(usize, 1), rollback.quarantineCount());

    var expired = try Store.restoreUpgradeCheckpoint(testing.allocator, cfg, checkpoint, 600);
    defer expired.deinit();
    try testing.expectEqual(@as(usize, 0), expired.entryCount());
    try testing.expectEqual(@as(usize, 0), expired.quarantineCount());
    // A signed REVOKE remains replay protection after its own signed expiry
    // until the independent tombstone retention TTL also matures.
    try testing.expectEqual(@as(usize, 1), expired.tombstoneCount());
    try testing.expect(expired.getTombstone(revoke.decoded.offer.token).?.identity_digest != null);

    var mature = try Store.restoreUpgradeCheckpoint(testing.allocator, cfg, checkpoint, 6_000);
    defer mature.deinit();
    try testing.expectEqual(@as(usize, 0), mature.entryCount());
    try testing.expectEqual(@as(usize, 0), mature.tombstoneCount());
    try testing.expectEqual(@as(usize, 0), mature.quarantineCount());
}

test "session replica upgrade checkpoint restore is leak-free at every allocation failure" {
    var key = try testKey(0xe1);
    defer key.deinit();
    const offer = try signedOffer(testing.allocator, upsertOffer(&key, testToken(0xe1), 1, 1, "allocation-sweep"), &key);
    defer testing.allocator.free(offer.wire);
    const lease = try signedAttachmentLease(testing.allocator, .{
        .token = offer.decoded.offer.token,
        .revision = revisionFor(&key, 102, 1),
        .issued_at_ms = 100,
        .expires_at_ms = 500,
    }, &key);
    defer testing.allocator.free(lease.wire);
    var source = Store.init(testing.allocator);
    defer source.deinit();
    _ = try source.applySignedOffer(offer.decoded, 1_001, 200);
    _ = try source.applySignedAttachmentLease(lease.decoded, 200);
    const checkpoint = try source.encodeUpgradeCheckpoint(testing.allocator, 300);
    defer testing.allocator.free(checkpoint);

    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var restored = try Store.restoreUpgradeCheckpoint(allocator, .{}, bytes, 300);
            defer restored.deinit();
            try testing.expectEqual(@as(usize, 1), restored.entryCount());
            try testing.expectEqual(@as(usize, 1), restored.attachmentLeaseCount());
            try testing.expectEqualStrings("allocation-sweep", restored.get(testToken(0xe1)).?.snapshot);
            try testing.expect(restored.hasAttachedOriginOtherThan(testToken(0xe1), 999, 300));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{checkpoint});
}

test "session replica max authority revision scans entries tombstones quarantine and fallback rows" {
    var alice_key = try testKey(0xf1);
    defer alice_key.deinit();
    var mallory_key = try testKey(0xf2);
    defer mallory_key.deinit();
    var store = Store.initWithConfig(testing.allocator, .{ .max_quarantines = 1 });
    defer store.deinit();
    try testing.expect(store.maxAuthorityRevision() == null);

    const entry = try signedOffer(testing.allocator, upsertOffer(&alice_key, testToken(0xf1), 5, 1, "entry"), &alice_key);
    defer testing.allocator.free(entry.wire);
    _ = try store.applySignedOffer(entry.decoded, 1_101, 200);
    try testing.expect(store.maxAuthorityRevision().?.eql(entry.decoded.offer.revision));

    const tomb_live = try signedOffer(testing.allocator, upsertOffer(&alice_key, testToken(0xf2), 5, 2, "tomb"), &alice_key);
    defer testing.allocator.free(tomb_live.wire);
    const tomb = try signedOffer(testing.allocator, removeOffer(&alice_key, testToken(0xf2), 6, 1), &alice_key);
    defer testing.allocator.free(tomb.wire);
    _ = try store.applySignedOffer(tomb_live.decoded, 1_102, 201);
    _ = try store.applySignedOffer(tomb.decoded, 1_102, 202);
    try testing.expect(store.maxAuthorityRevision().?.eql(tomb.decoded.offer.revision));

    const quarantine_alice = try signedOffer(testing.allocator, upsertOffer(&alice_key, testToken(0xf3), 9, 1, "q-alice"), &alice_key);
    defer testing.allocator.free(quarantine_alice.wire);
    var quarantine_mallory_offer = upsertOffer(&mallory_key, testToken(0xf3), 15, 1, "q-mallory");
    quarantine_mallory_offer.account = "mallory";
    const quarantine_mallory = try signedOffer(testing.allocator, quarantine_mallory_offer, &mallory_key);
    defer testing.allocator.free(quarantine_mallory.wire);
    _ = try store.applySignedOffer(quarantine_alice.decoded, 1_103, 203);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(quarantine_mallory.decoded, 1_104, 204)).disposition);
    try testing.expect(store.maxAuthorityRevision().?.eql(quarantine_mallory.decoded.offer.revision));

    const fallback_entry = try signedOffer(testing.allocator, upsertOffer(&alice_key, testToken(0xf4), 12, 1, "fallback-entry"), &alice_key);
    defer testing.allocator.free(fallback_entry.wire);
    var fallback_entry_conflict_offer = upsertOffer(&mallory_key, testToken(0xf4), 13, 1, "ignored-conflict");
    fallback_entry_conflict_offer.account = "mallory";
    const fallback_entry_conflict = try signedOffer(testing.allocator, fallback_entry_conflict_offer, &mallory_key);
    defer testing.allocator.free(fallback_entry_conflict.wire);
    _ = try store.applySignedOffer(fallback_entry.decoded, 1_105, 205);
    try testing.expectError(error.QuarantineFull, store.applySignedOffer(fallback_entry_conflict.decoded, 1_106, 206));
    try testing.expect(store.entries.get(.{ .token = fallback_entry.decoded.offer.token, .origin_node = fallback_entry.decoded.offer.revision.origin_node }).?.quarantine_until_ms != null);

    const fallback_tomb_live = try signedOffer(testing.allocator, upsertOffer(&alice_key, testToken(0xf5), 13, 2, "fallback-tomb"), &alice_key);
    defer testing.allocator.free(fallback_tomb_live.wire);
    const fallback_tomb = try signedOffer(testing.allocator, removeOffer(&alice_key, testToken(0xf5), 14, 1), &alice_key);
    defer testing.allocator.free(fallback_tomb.wire);
    var fallback_tomb_conflict_offer = upsertOffer(&mallory_key, testToken(0xf5), 16, 1, "ignored-tomb-conflict");
    fallback_tomb_conflict_offer.account = "mallory";
    const fallback_tomb_conflict = try signedOffer(testing.allocator, fallback_tomb_conflict_offer, &mallory_key);
    defer testing.allocator.free(fallback_tomb_conflict.wire);
    _ = try store.applySignedOffer(fallback_tomb_live.decoded, 1_107, 207);
    _ = try store.applySignedOffer(fallback_tomb.decoded, 1_107, 208);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(fallback_tomb_conflict.decoded, 1_108, 209)).disposition);
    try testing.expect(store.tombstones.get(.{ .token = fallback_tomb.decoded.offer.token, .origin_node = fallback_tomb.decoded.offer.revision.origin_node }).?.quarantine_until_ms != null);
    try testing.expect(store.maxAuthorityRevision().?.eql(quarantine_mallory.decoded.offer.revision));

    const checkpoint = try store.encodeUpgradeCheckpoint(testing.allocator, 500);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, store.cfg, checkpoint, 500);
    defer restored.deinit();
    try testing.expect(restored.maxAuthorityRevision().?.eql(quarantine_mallory.decoded.offer.revision));
}

test "current inventory canonical metadata maximum fits negotiated secured frame" {
    var kp = try testKey(0x91);
    defer kp.deinit();
    var rows: [max_inventory_attachments]AttachmentMetadata = undefined;
    for (&rows, 0..) |*row, i| {
        var aid: [16]u8 = @splat(0);
        std.mem.writeInt(u16, aid[14..16], @intCast(i + 1), .big);
        row.* = .{ .attachment_id = aid, .signon_ms = @intCast(i), .attached = i % 2 == 0 };
    }
    var bytes: [max_inventory_attachments * inventory_row_len]u8 = undefined;
    const inventory = try encodeInventory(&bytes, &rows);
    const snapshot = try testing.allocator.alloc(u8, max_inventory_snapshot_len);
    defer testing.allocator.free(snapshot);
    @memset(snapshot, 's');
    const account: [max_account_len]u8 = @splat('a');
    const nick: [max_nick_len]u8 = @splat('n');
    const signed = try signedOffer(testing.allocator, .{
        .operation = .inventory_upsert,
        .resume_eligible = true,
        .token = testToken(0x91),
        .revision = revisionFor(&kp, 200, 0),
        .issued_at_ms = 100,
        .expires_at_ms = 10_000,
        .account = &account,
        .nick = &nick,
        .snapshot = snapshot,
        .inventory = inventory,
    }, &kp);
    defer testing.allocator.free(signed.wire);
    try verifyOffer(signed.decoded);
    try testing.expectEqual(@as(usize, 256), (Inventory{ .bytes = signed.decoded.offer.inventory }).count());
    try testing.expectEqual(rows[255], (Inventory{ .bytes = signed.decoded.offer.inventory }).at(255));
    var frame: [session_replica_transport.header_len + session_replica_transport.max_signed_payload_len]u8 = undefined;
    const encoded = try session_replica_transport.encodeCurrent(.offer, signed.wire, &frame);
    try testing.expectEqual(session_replica_transport.WireVersion.current_v4, try session_replica_transport.inspectVersion(encoded));
    try testing.expectEqualSlices(u8, signed.wire, (try session_replica_transport.decodeCurrent(.offer, encoded)).signed_payload);
    try testing.expect(encoded.len + session_replica_transport.outer_signed_envelope_len + @import("../../proto/s2s_frame.zig").header_len <= @import("../../proto/s2s_frame.zig").default_max_frame_size);
    try testing.expectError(error.InvalidPayload, session_replica_transport.encode(.offer, signed.wire, &frame));
    try testing.expectError(error.UnsupportedVersion, session_replica_transport.decode(.offer, encoded));
    const excess_snapshot = try testing.allocator.alloc(u8, snapshot.len + 1);
    defer testing.allocator.free(excess_snapshot);
    @memset(excess_snapshot, 's');
    var too_large = signed.decoded.offer;
    too_large.snapshot = excess_snapshot;
    try testing.expectError(error.TooLong, encodeOffer(testing.allocator, too_large, &kp));

    rows[1].attachment_id = rows[0].attachment_id;
    try testing.expectError(error.InvalidInventory, encodeInventory(&bytes, &rows));
    rows[1].attachment_id[15] = 2;
    rows[0].signon_ms = -1;
    try testing.expectError(error.InvalidInventory, encodeInventory(&bytes, &rows));
    rows[0].signon_ms = 0;
    const oversized_rows = try testing.allocator.alloc(AttachmentMetadata, max_inventory_attachments + 1);
    defer testing.allocator.free(oversized_rows);
    try testing.expectError(error.InvalidInventory, encodeInventory(&bytes, oversized_rows));
    const mutated = try testing.allocator.dupe(u8, signed.wire);
    defer testing.allocator.free(mutated);
    mutated[offer_fixed_len + 3 + account.len + nick.len + snapshot.len + 24] = 2;
    try testing.expectError(error.InvalidOffer, decodeOffer(mutated));
    try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.offer, mutated, &frame));
}

fn testGroupOffer(kp: *const sign.KeyPair, token: Token, account: []const u8) Offer {
    return .{ .operation = .group_revoke, .token = token, .account = account, .revision = revisionFor(kp, 300, 0), .issued_at_ms = 100, .expires_at_ms = 500 };
}

test "terminal group revoke stages atomically and fences every origin beyond expiry" {
    var a = try testKey(0x92);
    defer a.deinit();
    var b = try testKey(0x93);
    defer b.deinit();
    const token = testToken(0x92);
    const live_a = try signedOffer(testing.allocator, upsertOffer(&a, token, 200, 0, "a"), &a);
    defer testing.allocator.free(live_a.wire);
    var offer_b = upsertOffer(&b, token, 200, 0, "b");
    offer_b.account = "ALICE";
    const live_b = try signedOffer(testing.allocator, offer_b, &b);
    defer testing.allocator.free(live_b.wire);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&a, token, "Alice"), &a);
    defer testing.allocator.free(fence.wire);
    const wrong = try signedOffer(testing.allocator, testGroupOffer(&a, token, "mallory"), &a);
    defer testing.allocator.free(wrong.wire);
    var store = Store.initWithConfig(testing.allocator, .{ .max_group_revocations = 1 });
    defer store.deinit();
    _ = try store.applySignedOffer(live_a.decoded, 11, 200);
    _ = try store.applySignedOffer(live_b.decoded, 12, 200);
    try testing.expectError(error.AccountMismatch, store.prepareGroupRevoke(wrong.decoded, 300));
    var aborted = try store.prepareGroupRevoke(fence.decoded, 300);
    aborted.abort();
    aborted.deinit();
    try testing.expectEqual(@as(usize, 2), store.entryCount());
    try testing.expect(!store.isGroupRevoked("alice", token));
    var ticket = try store.prepareGroupRevoke(fence.decoded, 300);
    defer ticket.deinit();
    try testing.expectEqual(ApplyDisposition.inserted, ticket.commit());
    try testing.expect(store.isGroupRevoked("ALICE", token));
    try testing.expect(!store.isGroupRevoked("mallory", token));
    try testing.expectEqual(@as(usize, 0), store.entryCount());
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectError(error.AccountMismatch, store.prepareGroupRevoke(wrong.decoded, 300));
    var duplicate = try store.prepareGroupRevoke(fence.decoded, 999_999_999);
    defer duplicate.deinit();
    try testing.expectEqual(ApplyDisposition.duplicate, duplicate.commit());
    try testing.expectEqualSlices(u8, fence.wire, store.groupRevokeForToken(token).?.wire);
    var later = upsertOffer(&b, token, 600, 0, "later");
    later.issued_at_ms = 600;
    later.expires_at_ms = 10_000;
    const resurrection = try signedOffer(testing.allocator, later, &b);
    defer testing.allocator.free(resurrection.wire);
    try testing.expectEqual(ApplyDisposition.tombstoned, (try store.applySignedOffer(resurrection.decoded, 12, 600)).disposition);
    later.account = "mallory";
    const attacker = try signedOffer(testing.allocator, later, &b);
    defer testing.allocator.free(attacker.wire);
    try testing.expectEqual(ApplyDisposition.tombstoned, (try store.applySignedOffer(attacker.decoded, 12, 600)).disposition);
    try testing.expect(store.isGroupRevoked("alice", token));
    const another_fence = try signedOffer(testing.allocator, testGroupOffer(&b, token, "ALICE"), &b);
    defer testing.allocator.free(another_fence.wire);
    const duplicate_result = try store.applySignedOffer(another_fence.decoded, 12, 600);
    try testing.expectEqual(ApplyDisposition.duplicate, duplicate_result.disposition);
    try testing.expect(duplicate_result.current_revision.eql(fence.decoded.offer.revision));
    const lease = try signedAttachmentLease(testing.allocator, .{ .token = token, .revision = revisionFor(&b, 700, 0), .issued_at_ms = 700, .expires_at_ms = 1000 }, &b);
    defer testing.allocator.free(lease.wire);
    try testing.expectEqual(AttachmentLeaseDisposition.stale, try store.applySignedAttachmentLease(lease.decoded, 700));
    _ = store.sweep(999_999_999);
    try testing.expect(store.isGroupRevoked("alice", token));
    try testing.expect(store.bestLiveIdentity(token, 999_999_999) == null);
    var retained: [2]Store.RetainedObject = undefined;
    try testing.expectEqual(@as(usize, 1), store.retainedObjectsAfter(999_999_999, null, &retained));
    try testing.expectEqual(Store.RetainedKind.group_revoke, retained[0].kind);
    try testing.expectEqualSlices(u8, fence.wire, retained[0].wire);
    var inventory: [2]InventoryRow = undefined;
    const page = store.accountInventoryPageInto("alice", 999_999_999, null, &inventory);
    try testing.expectEqual(@as(usize, 1), page.items.len);
    try testing.expect(page.complete and page.items[0].revoked and !page.items[0].attached);
    const second = try signedOffer(testing.allocator, testGroupOffer(&a, testToken(0x93), "alice"), &a);
    defer testing.allocator.free(second.wire);
    try testing.expectError(error.GroupRevokeFull, store.prepareGroupRevoke(second.decoded, 300));
    try testing.expect(!store.isGroupRevoked("alice", testToken(0x93)));
}

test "terminal group checkpoint is mandatory current state and cannot roll back" {
    var kp = try testKey(0x94);
    defer kp.deinit();
    const token = testToken(0x94);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&kp, token, "alice"), &kp);
    defer testing.allocator.free(fence.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var ticket = try store.prepareGroupRevoke(fence.decoded, 300);
    defer ticket.deinit();
    _ = ticket.commit();
    const checkpoint = try store.encodeUpgradeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, .{}, checkpoint, 999_999_999);
    defer restored.deinit();
    try testing.expect(restored.isGroupRevoked("ALICE", token));
    try testing.expectEqualSlices(u8, fence.wire, restored.groupRevokeForToken(token).?.wire);
    var empty = Store.init(testing.allocator);
    defer empty.deinit();
    const rollback = try empty.encodeUpgradeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(rollback);
    try testing.expectError(error.InvalidMetadata, restored.replaceFromUpgradeCheckpoint(rollback, 1000));
    try testing.expect(restored.isGroupRevoked("alice", token));
    var legacy_v2 = try testing.allocator.alloc(u8, rollback.len - 4);
    defer testing.allocator.free(legacy_v2);
    @memcpy(legacy_v2[0..upgrade_checkpoint_v2_header_len], rollback[0..upgrade_checkpoint_v2_header_len]);
    legacy_v2[upgrade_checkpoint_magic.len] = upgrade_checkpoint_v2_version;
    @memcpy(legacy_v2[upgrade_checkpoint_v2_header_len..], rollback[upgrade_checkpoint_header_len..]);
    rewriteUpgradeCheckpointChecksum(legacy_v2);
    try testing.expectError(error.UnsupportedVersion, Store.restoreUpgradeCheckpoint(testing.allocator, .{}, legacy_v2, 1000));
    var migrated = try Store.restoreColdMigrationCheckpoint(testing.allocator, .{}, legacy_v2, 1000);
    defer migrated.deinit();
}

test "current inventory account index excludes unrelated origins and paginates exact rows" {
    var kp = try testKey(0x95);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    for (0..48) |i| {
        var offer = upsertOffer(&kp, testWideToken(@intCast(i + 1)), 200, 0, "unrelated");
        offer.account = "other";
        const signed = try signedOffer(testing.allocator, offer, &kp);
        defer testing.allocator.free(signed.wire);
        _ = try store.applySignedOffer(signed.decoded, 0, 200);
    }
    const metadata = [_]AttachmentMetadata{
        .{ .attachment_id = @splat(1), .signon_ms = 11, .attached = true },
        .{ .attachment_id = @splat(2), .signon_ms = 22, .attached = false },
    };
    var bytes: [50]u8 = undefined;
    var offer = upsertOffer(&kp, testToken(0xf1), 200, 0, "inventory");
    offer.operation = .inventory_upsert;
    offer.resume_eligible = true;
    offer.inventory = try encodeInventory(&bytes, &metadata);
    const signed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed.wire);
    _ = try store.applySignedOffer(signed.decoded, 0, 200);
    const legacy = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xf2), 200, 0, "legacy"), &kp);
    defer testing.allocator.free(legacy.wire);
    _ = try store.applySignedOffer(legacy.decoded, 0, 200);
    store.inventory_source_visits.store(0, .monotonic);
    var out: [2]InventoryRow = undefined;
    const first = store.accountInventoryPageInto("ALICE", 200, null, &out);
    std.debug.print("Session current inventory: rows={d}, indexed_sources={d}, unrelated_origins=48\n", .{ first.items.len, store.inventory_source_visits.load(.monotonic) });
    try testing.expectEqual(@as(usize, 2), first.items.len);
    try testing.expectEqual(@as(usize, 2), store.inventory_source_visits.load(.monotonic));
    try testing.expect(!first.complete and first.items[0].inventory_complete and first.items[0].attached and !first.items[1].attached);
    try testing.expect(!first.items[0].fresh and first.items[1].fresh);
    const lease = try signedAttachmentLease(testing.allocator, .{ .token = offer.token, .revision = revisionFor(&kp, 201, 0), .issued_at_ms = 201, .expires_at_ms = 500 }, &kp);
    defer testing.allocator.free(lease.wire);
    _ = try store.applySignedAttachmentLease(lease.decoded, 201);
    try testing.expect(store.accountInventoryPageInto("alice", 201, null, &out).items[0].fresh);
    try testing.expect(!store.accountInventoryPageInto("alice", 501, null, &out).items[0].fresh);
    const last = store.accountInventoryPageInto("alice", 200, first.next, &out);
    try testing.expectEqual(@as(usize, 1), last.items.len);
    try testing.expect(last.complete and !last.items[0].inventory_complete and last.items[0].attachment_id == null and !last.items[0].fresh);
    const absent = store.accountInventoryPageInto("absent", 200, null, &out);
    try testing.expect(absent.complete and absent.items.len == 0);
    const checkpoint = try store.encodeUpgradeCheckpoint(testing.allocator, 200);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, .{}, checkpoint, 200);
    defer restored.deinit();
    restored.inventory_source_visits.store(0, .monotonic);
    try testing.expectEqual(@as(usize, 2), restored.accountInventoryPageInto("alice", 200, null, &out).items.len);
    try testing.expectEqual(@as(usize, 2), restored.inventory_source_visits.load(.monotonic));
}

test "terminal group preparation and checkpoint restore survive every allocation failure" {
    var kp = try testKey(0x96);
    defer kp.deinit();
    const live = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0x96), 200, 0, "live"), &kp);
    defer testing.allocator.free(live.wire);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&kp, testToken(0x96), "alice"), &kp);
    defer testing.allocator.free(fence.wire);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, offered: SignedOffer, revoked: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(offered, 0, 200);
            const before = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
            defer testing.allocator.free(before);
            var ticket = store.prepareGroupRevoke(revoked, 300) catch |err| {
                const after = try store.encodeUpgradeCheckpoint(testing.allocator, 300);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                try testing.expect(!store.isGroupRevoked("alice", revoked.offer.token));
                return err;
            };
            defer ticket.deinit();
            _ = ticket.commit();
            const checkpoint = try store.encodeUpgradeCheckpoint(allocator, 1000);
            defer allocator.free(checkpoint);
            var restored = try Store.restoreUpgradeCheckpoint(allocator, .{}, checkpoint, 1000);
            defer restored.deinit();
            try testing.expect(restored.isGroupRevoked("alice", revoked.offer.token));
            restored.replaceFromUpgradeCheckpoint(checkpoint, 1000) catch |err| {
                try testing.expect(restored.isGroupRevoked("alice", revoked.offer.token));
                try testing.expectEqualSlices(u8, store.groupRevokeForToken(revoked.offer.token).?.wire, restored.groupRevokeForToken(revoked.offer.token).?.wire);
                return err;
            };
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ live.decoded, fence.decoded });
}

test "current acknowledgement readiness and group commit cannot enter frozen transport" {
    var kp = try testKey(0x97);
    defer kp.deinit();
    for ([_]AckStatus{ .current_ready, .group_revoked }) |status| {
        const wire = try encodeAck(testing.allocator, .{ .status = status, .token = testToken(0x97), .offered_revision = revisionFor(&kp, 200, 0), .observed_revision = revisionFor(&kp, 200, 0), .ack_node = signed_frame.originShortId(kp.public_key), .issued_at_ms = 200, .expires_at_ms = 1000, .membership_epoch = 7, .roster_digest = @splat(0x71) }, &kp);
        defer testing.allocator.free(wire);
        try verifyAck(try decodeAck(wire));
        var out: [512]u8 = undefined;
        const frame = try session_replica_transport.encodeCurrent(.ack, wire, &out);
        try testing.expectEqualSlices(u8, wire, (try session_replica_transport.decodeCurrent(.ack, frame)).signed_payload);
        try testing.expectError(error.InvalidPayload, session_replica_transport.encode(.ack, wire, &out));
        var store = Store.init(testing.allocator);
        defer store.deinit();
        try testing.expectEqual(AckDisposition.ignored, try store.applySignedAck(try decodeAck(wire), 1, 200));
    }
}

test "current group acknowledgement alone binds concurrent different-origin fences" {
    var a = try testKey(0x98);
    defer a.deinit();
    var b = try testKey(0x99);
    defer b.deinit();
    var ack = Ack{ .status = .group_revoked, .token = testToken(0x98), .offered_revision = revisionFor(&a, 200, 0), .observed_revision = revisionFor(&b, 201, 0), .ack_node = signed_frame.originShortId(b.public_key), .issued_at_ms = 202, .expires_at_ms = 1000, .membership_epoch = 7, .roster_digest = @splat(0x71) };
    const wire = try encodeAck(testing.allocator, ack, &b);
    defer testing.allocator.free(wire);
    try verifyAck(try decodeAck(wire));
    var out: [512]u8 = undefined;
    const frame = try session_replica_transport.encodeCurrent(.ack, wire, &out);
    try testing.expectEqualSlices(u8, wire, (try session_replica_transport.decodeCurrent(.ack, frame)).signed_payload);
    try testing.expectError(error.InvalidPayload, session_replica_transport.encode(.ack, wire, &out));
    for ([_]AckStatus{ .accepted, .duplicate, .conflict, .stale, .superseded, .tombstoned, .capacity, .current_ready }) |status| {
        ack.status = status;
        try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, ack, &b));
    }
}

test "expired origin account rebind cannot leak inventory or retain a dangling old index" {
    var kp = try testKey(0x9a);
    defer kp.deinit();
    const token = testToken(0x9a);
    var alice = upsertOffer(&kp, token, 100, 0, "expired Alice");
    alice.expires_at_ms = 200;
    const first = try signedOffer(testing.allocator, alice, &kp);
    defer testing.allocator.free(first.wire);
    var bytes: [inventory_row_len]u8 = undefined;
    const inventory = try encodeInventory(&bytes, &.{.{ .attachment_id = @splat(0x9a), .signon_ms = 201, .attached = false }});
    var bob = upsertOffer(&kp, token, 201, 0, "current Bob");
    bob.operation = .inventory_upsert;
    bob.resume_eligible = true;
    bob.account = "bob";
    bob.nick = "Bob";
    bob.issued_at_ms = 201;
    bob.inventory = inventory;
    const second = try signedOffer(testing.allocator, bob, &kp);
    defer testing.allocator.free(second.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(first.decoded, 0, 150);
    _ = try store.applySignedOffer(second.decoded, 0, 201);
    var out: [2]InventoryRow = undefined;
    store.inventory_source_visits.store(0, .monotonic);
    const private = store.accountInventoryPageInto("ALICE", 201, null, &out);
    try testing.expect(private.complete and private.items.len == 0);
    try testing.expectEqual(@as(usize, 0), store.inventory_source_visits.load(.monotonic));
    const current = store.accountInventoryPageInto("BOB", 201, null, &out);
    try testing.expect(current.complete and current.items.len == 1);
    try testing.expectEqual(@as(i64, 201), current.items[0].signon_ms);
    try testing.expectEqual(@as(usize, 1), store.account_index.count());
    const checkpoint = try store.encodeUpgradeCheckpoint(testing.allocator, 201);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, .{}, checkpoint, 201);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 0), restored.accountInventoryPageInto("alice", 201, null, &out).items.len);
    try testing.expectEqual(@as(usize, 1), restored.accountInventoryPageInto("bob", 201, null, &out).items.len);
    const removed = try signedOffer(testing.allocator, removeOffer(&kp, token, 202, 0), &kp);
    defer testing.allocator.free(removed.wire);
    _ = try store.applySignedOffer(removed.decoded, 0, 202);
    // Both accounts must remain safe to enumerate after the replacement is
    // removed; an obsolete Alice locator would now dereference a missing row.
    try testing.expectEqual(@as(usize, 0), store.accountInventoryPageInto("alice", 202, null, &out).items.len);
    try testing.expectEqual(@as(usize, 0), store.accountInventoryPageInto("bob", 202, null, &out).items.len);
    try testing.expectEqual(@as(usize, 0), store.account_index.count());
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, expired: SignedOffer, replacement: SignedOffer) !void {
            var target = Store.init(allocator);
            defer target.deinit();
            _ = try target.applySignedOffer(expired, 0, 150);
            const before = try target.encodeUpgradeCheckpoint(testing.allocator, 201);
            defer testing.allocator.free(before);
            _ = target.applySignedOffer(replacement, 0, 201) catch |err| {
                const after = try target.encodeUpgradeCheckpoint(testing.allocator, 201);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                var rows: [2]InventoryRow = undefined;
                const old = target.accountInventoryPageInto("alice", 201, null, &rows);
                try testing.expect(old.integrity_ok and old.items.len == 1);
                const absent = target.accountInventoryPageInto("bob", 201, null, &rows);
                try testing.expect(absent.integrity_ok and absent.items.len == 0);
                return err;
            };
            var rows: [2]InventoryRow = undefined;
            const old = target.accountInventoryPageInto("alice", 201, null, &rows);
            try testing.expect(old.integrity_ok and old.items.len == 0);
            const current_account = target.accountInventoryPageInto("bob", 201, null, &rows);
            try testing.expect(current_account.integrity_ok and current_account.items.len == 1);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ first.decoded, second.decoded });
}

test "inventory selector corruption reports partial without copying foreign authority" {
    var kp = try testKey(0x9b);
    defer kp.deinit();
    const token = testToken(0x9b);
    var offered = upsertOffer(&kp, token, 200, 0, "Bob private metadata");
    offered.account = "bob";
    const live = try signedOffer(testing.allocator, offered, &kp);
    defer testing.allocator.free(live.wire);
    const key = Store.OriginKey{ .token = token, .origin_node = offered.revision.origin_node };
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(live.decoded, 0, 200);
    var out: [2]InventoryRow = undefined;
    try testing.expect(try store.reserveAccountOrigin("alice", key));
    store.account_index.getPtr(accountDigest("alice")).?.origins.appendAssumeCapacity(key);
    const foreign = store.accountInventoryPageInto("alice", 200, null, &out);
    try testing.expect(!foreign.integrity_ok and !foreign.complete and foreign.items.len == 0);
    store.removeAccountOrigin("alice", key);
    const removed = store.entries.fetchRemove(key).?;
    const missing = store.accountInventoryPageInto("bob", 200, null, &out);
    try testing.expect(!missing.integrity_ok and !missing.complete and missing.items.len == 0);
    store.entries.putAssumeCapacityNoClobber(key, removed.value);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&kp, token, "bob"), &kp);
    defer testing.allocator.free(fence.wire);
    _ = try store.applySignedOffer(fence.decoded, 0, 300);
    const marker = Store.OriginKey{ .token = token, .origin_node = 0 };
    try testing.expect(try store.reserveAccountOrigin("alice", marker));
    store.account_index.getPtr(accountDigest("alice")).?.origins.appendAssumeCapacity(marker);
    const foreign_fence = store.accountInventoryPageInto("alice", 300, null, &out);
    try testing.expect(!foreign_fence.integrity_ok and !foreign_fence.complete and foreign_fence.items.len == 0);
    store.removeAccountOrigin("alice", marker);
    const removed_fence = store.group_revocations.fetchRemove(token).?;
    const missing_fence = store.accountInventoryPageInto("bob", 300, null, &out);
    try testing.expect(!missing_fence.integrity_ok and !missing_fence.complete and missing_fence.items.len == 0);
    store.group_revocations.putAssumeCapacityNoClobber(token, removed_fence.value);
    const authorized = store.accountInventoryPageInto("BOB", 300, null, &out);
    try testing.expect(authorized.integrity_ok and authorized.complete and authorized.items.len == 1 and authorized.items[0].revoked);
}

test "current ack roster context is mandatory signed canonical and absent from frozen vectors" {
    var kp = try testKey(0x9c);
    defer kp.deinit();
    const old = Ack{ .status = .accepted, .token = @splat(0x31), .offered_revision = .{ .epoch = 200, .sequence = 200 << 16, .origin_node = 1 }, .observed_revision = .{ .epoch = 201, .sequence = 201 << 16, .origin_node = 1 }, .ack_node = signed_frame.originShortId(kp.public_key), .issued_at_ms = 202, .expires_at_ms = 1000 };
    const frozen = try encodeAck(testing.allocator, old, &kp);
    defer testing.allocator.free(frozen);
    const frozen_prefix_hex = "53524132013131313131313131313131313131313100000000000000c80000000000c80000000000000000000100000000000000c90000000000c900000000000000000001";
    var prefix: [69]u8 = undefined;
    _ = try std.fmt.hexToBytes(&prefix, frozen_prefix_hex);
    try testing.expectEqualSlices(u8, &prefix, frozen[0..prefix.len]);
    try testing.expectEqual(@as(usize, 189), frozen.len);
    const frozen_decoded = try decodeAck(frozen);
    try verifyAck(frozen_decoded);
    try testing.expectEqual(@as(usize, 93), frozen_decoded.transcript.len);
    try testing.expectEqual(@as(u64, 0), frozen_decoded.ack.membership_epoch);
    try testing.expect(std.mem.allEqual(u8, &frozen_decoded.ack.roster_digest, 0));
    var transport: [512]u8 = undefined;
    _ = try session_replica_transport.encode(.ack, frozen, &transport);
    for ([_]AckStatus{ .current_ready, .group_revoked }) |status| {
        var current = old;
        current.status = status;
        try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, current, &kp));
        current.membership_epoch = 42;
        try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, current, &kp));
        current.roster_digest = @splat(0xa1);
        const wire = try encodeAck(testing.allocator, current, &kp);
        defer testing.allocator.free(wire);
        try testing.expectEqual(@as(usize, 229), wire.len);
        const decoded = try decodeAck(wire);
        try verifyAck(decoded);
        try testing.expectEqual(@as(u64, 42), decoded.ack.membership_epoch);
        try testing.expectEqual(current.roster_digest, decoded.ack.roster_digest);
        var projection = decoded;
        projection.ack.membership_epoch += 1;
        try testing.expectError(error.TranscriptMismatch, verifyAck(projection));
        projection = decoded;
        projection.ack.roster_digest[0] ^= 1;
        try testing.expectError(error.TranscriptMismatch, verifyAck(projection));
        var modified: [229]u8 = undefined;
        for ([_]usize{ 100, 101 }) |offset| {
            @memcpy(&modified, wire);
            modified[offset] ^= 1;
            try testing.expectError(error.BadSignature, verifyAck(try decodeAck(&modified)));
        }
        @memcpy(&modified, wire);
        @memset(modified[93..101], 0);
        try testing.expectError(error.InvalidAck, decodeAck(&modified));
        try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.ack, &modified, &transport));
        @memcpy(&modified, wire);
        @memset(modified[101..133], 0);
        try testing.expectError(error.InvalidAck, decodeAck(&modified));
        try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.ack, &modified, &transport));
        @memcpy(&modified, wire);
        modified[4] = @backingInt(AckStatus.accepted);
        try testing.expectError(error.TrailingBytes, decodeAck(&modified));
        try testing.expectError(error.InvalidPayload, session_replica_transport.encode(.ack, &modified, &transport));
        const trailing = try testing.allocator.alloc(u8, wire.len + 1);
        defer testing.allocator.free(trailing);
        @memcpy(trailing[0..wire.len], wire);
        trailing[wire.len] = 0;
        try testing.expectError(error.TrailingBytes, decodeAck(trailing));
        try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.ack, trailing, &transport));
        var missing: [189]u8 = undefined;
        @memcpy(&missing, frozen);
        missing[4] = @backingInt(status);
        try testing.expectError(error.Truncated, decodeAck(&missing));
        try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.ack, &missing, &transport));
        try testing.expectError(error.InvalidPayload, session_replica_transport.encode(.ack, wire, &transport));
        const frame = try session_replica_transport.encodeCurrent(.ack, wire, &transport);
        try testing.expectEqualSlices(u8, wire, (try session_replica_transport.decodeCurrent(.ack, frame)).signed_payload);
    }
    var legacy_context = old;
    legacy_context.membership_epoch = 42;
    try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, legacy_context, &kp));
    legacy_context.membership_epoch = 0;
    legacy_context.roster_digest = @splat(0xa1);
    try testing.expectError(error.InvalidAck, encodeAck(testing.allocator, legacy_context, &kp));
}

test "inventory eligibility is mandatory signed and never implicit remote authority" {
    var kp = try testKey(0xc1);
    defer kp.deinit();
    const token = testToken(0xc1);
    const origin = signed_frame.originShortId(kp.public_key);
    var offer = upsertOffer(&kp, token, 200, 0, "private-state");
    offer.operation = .inventory_upsert;
    try testing.expectError(error.InvalidOffer, encodeOffer(testing.allocator, offer, &kp));
    offer.resume_eligible = false;
    try testing.expectError(error.InvalidOffer, encodeOffer(testing.allocator, offer, &kp));
    offer.nick = "";
    offer.snapshot = "";
    const metadata = [_]AttachmentMetadata{.{ .attachment_id = @splat(1), .signon_ms = 100, .attached = true }};
    var metadata_bytes: [25]u8 = undefined;
    offer.inventory = try encodeInventory(&metadata_bytes, &metadata);
    const signed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed.wire);
    try verifyOffer(signed.decoded);
    try testing.expect(!signed.decoded.offer.allowsResume());
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(signed.decoded, 42, 200);
    const held = store.getOriginInventory(token, origin).?;
    try testing.expect(!held.resume_eligible);
    try testing.expectEqual(@as(usize, 0), held.nick.len);
    try testing.expectEqual(@as(usize, 0), held.snapshot.len);
    try testing.expect(store.getOrigin(token, origin) == null);
    try testing.expect(store.get(token) == null);
    try testing.expect(store.bestLiveIdentity(token, 201) == null);
    try testing.expect(!store.hasLiveIdentity(offer.account, "nick", 201));
    try testing.expect(!store.hasLiveOriginOtherThan(token, 0, 201));
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 0, 201));
    try testing.expect(!store.hasReplicaParent(token, origin, null));
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    var tokens: [4]Token = undefined;
    try testing.expectEqual(@as(usize, 0), store.liveTokensAfter(201, null, &tokens).len);
    try testing.expectEqual(@as(usize, 0), store.authorityTokensAfter(201, null, &tokens).len);
    var identities: [2]Store.OriginIdentity = undefined;
    try testing.expectEqual(@as(usize, 0), store.liveOriginIdentitiesAfter(token, 201, null, &identities).len);
    var rows: [2]InventoryRow = undefined;
    const page = store.accountInventoryPageInto(offer.account, 201, null, &rows);
    try testing.expect(page.integrity_ok and page.complete);
    try testing.expectEqual(@as(usize, 1), page.items.len);
    try testing.expect(page.items[0].inventory_complete);
    try testing.expectEqual(@as(usize, 1), store.retainedCount(201));
    const lease = try signedAttachmentLease(testing.allocator, .{
        .token = token,
        .revision = revisionFor(&kp, 201, 0),
        .issued_at_ms = 201,
        .expires_at_ms = 250,
    }, &kp);
    defer testing.allocator.free(lease.wire);
    _ = try store.applySignedAttachmentLease(lease.decoded, 201);
    try testing.expect(!store.hasAttachedOriginOtherThan(token, 0, 201));
    try testing.expect(store.get(token) == null);
    const fresh_page = store.accountInventoryPageInto(offer.account, 201, null, &rows);
    try testing.expect(fresh_page.items[0].fresh);
    var ack_key = try testKey(0xc3);
    defer ack_key.deinit();
    const ack_wire = try encodeAck(testing.allocator, .{
        .status = .accepted,
        .token = token,
        .offered_revision = offer.revision,
        .observed_revision = offer.revision,
        .ack_node = signed_frame.originShortId(ack_key.public_key),
        .issued_at_ms = 200,
        .expires_at_ms = 250,
    }, &ack_key);
    defer testing.allocator.free(ack_wire);
    try testing.expectEqual(AckDisposition.stale, try store.applySignedAck(try decodeAck(ack_wire), 42, 201));
    try testing.expect(store.get(token) == null);
    const checkpoint = try store.encodeUpgradeCheckpoint(testing.allocator, 201);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.restoreUpgradeCheckpoint(testing.allocator, .{}, checkpoint, 201);
    defer restored.deinit();
    try testing.expect(!restored.getOriginInventory(token, origin).?.resume_eligible);
    try testing.expectEqualSlices(u8, signed.wire, restored.getOriginInventory(token, origin).?.wire);
    try testing.expect(restored.get(token) == null);

    var frame: [session_replica_transport.header_len + session_replica_transport.max_signed_payload_len]u8 = undefined;
    _ = try session_replica_transport.encodeCurrent(.offer, signed.wire, &frame);
    try testing.expectError(error.InvalidPayload, session_replica_transport.encode(.offer, signed.wire, &frame));
    const changed = try testing.allocator.dupe(u8, signed.wire);
    defer testing.allocator.free(changed);
    changed[offer_fixed_len] = 2;
    try testing.expectError(error.InvalidOffer, decodeOffer(changed));
    try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.offer, changed, &frame));
    // Removing the mandatory byte cannot reinterpret the count/account as valid.
    const omitted = try testing.allocator.alloc(u8, signed.wire.len - 1);
    defer testing.allocator.free(omitted);
    @memcpy(omitted[0..offer_fixed_len], signed.wire[0..offer_fixed_len]);
    @memcpy(omitted[offer_fixed_len..], signed.wire[offer_fixed_len + 1 ..]);
    if (decodeOffer(omitted)) |_| return error.TestUnexpectedResult else |_| {}
    try testing.expectError(error.InvalidPayload, session_replica_transport.encodeCurrent(.offer, omitted, &frame));

    offer.resume_eligible = true;
    try testing.expectError(error.InvalidOffer, encodeOffer(testing.allocator, offer, &kp));
    offer.nick = "nick";
    offer.snapshot = "portable-state";
    offer.revision = revisionFor(&kp, 202, 0);
    const promoted = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(promoted.wire);
    _ = try store.applySignedOffer(promoted.decoded, 42, 202);
    try testing.expect(store.get(token).?.resume_eligible);
    try testing.expect(store.bestLiveIdentity(token, 202) != null);
    try testing.expect(store.hasLiveIdentity(offer.account, "nick", 202));
    try testing.expect(store.hasReplicaParent(token, origin, 42));
    // A valid-shaped semantic edit still cannot change the signed decision.
    var forged = promoted.decoded;
    forged.offer.resume_eligible = false;
    try testing.expectError(error.TranscriptMismatch, verifyOffer(forged));

    // A newer inventory-only revision removes previously eligible authority
    // and its routes, while retaining inventory and the signed replay floor.
    offer.resume_eligible = false;
    offer.nick = "";
    offer.snapshot = "";
    offer.revision = revisionFor(&kp, 203, 0);
    const demoted = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(demoted.wire);
    _ = try store.applySignedOffer(demoted.decoded, 42, 203);
    try testing.expect(store.get(token) == null);
    try testing.expectEqual(@as(usize, 0), store.routeCount());
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(promoted.decoded, 42, 203)).disposition);
    try testing.expect(!store.getOriginInventory(token, origin).?.resume_eligible);

    const legacy = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xc2), 202, 0, "legacy-state"), &kp);
    defer testing.allocator.free(legacy.wire);
    try testing.expect(legacy.decoded.offer.resume_eligible == null);
    try testing.expect(legacy.decoded.offer.allowsResume());
    _ = try session_replica_transport.encode(.offer, legacy.wire, &frame);
}

test "inventory batch hard budgets cover large accounts exactly once and advance through hidden sources" {
    var kp = try testKey(0xd1);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    // These sources produce no rows; the first call must still stop at64 work.
    for (0..80) |i| {
        const signed = try signedOffer(testing.allocator, upsertOffer(&kp, testWideToken(@intCast(i + 1)), 200, 0, "hidden"), &kp);
        defer testing.allocator.free(signed.wire);
        _ = try store.applySignedOffer(signed.decoded, 0, 200);
        store.markTokenDenied(signed.decoded.offer.token, 500);
    }
    var metadata: [256]AttachmentMetadata = undefined;
    for (&metadata, 0..) |*row, i| row.* = .{ .attachment_id = testWideToken(@intCast(i + 1)), .signon_ms = @intCast(i), .attached = false };
    var bytes: [256 * 25]u8 = undefined;
    const inventory = try encodeInventory(&bytes, &metadata);
    for (0..3) |i| {
        var offer = upsertOffer(&kp, testWideToken(@intCast(1000 + i)), 200, 0, "");
        offer.operation = .inventory_upsert;
        offer.resume_eligible = false;
        offer.nick = "";
        offer.inventory = inventory;
        const signed = try signedOffer(testing.allocator, offer, &kp);
        defer testing.allocator.free(signed.wire);
        _ = try store.applySignedOffer(signed.decoded, 0, 200);
    }
    // Unrelated accounts cannot consume even one work unit in this scan.
    for (0..40) |i| {
        var offer = upsertOffer(&kp, testWideToken(@intCast(2000 + i)), 200, 0, "other");
        offer.account = "unrelated";
        const signed = try signedOffer(testing.allocator, offer, &kp);
        defer testing.allocator.free(signed.wire);
        _ = try store.applySignedOffer(signed.decoded, 0, 200);
    }
    var out: [80]InventoryRow = undefined;
    var cursor: ?InventoryScanCursor = null;
    var seen: [3][256]bool = @splat(@splat(false));
    var total: usize = 0;
    var pages: usize = 0;
    while (true) {
        store.inventory_source_visits.store(0, .monotonic);
        store.inventory_row_visits.store(0, .monotonic);
        const page = try store.accountInventoryBatchInto("ALICE", 201, cursor, &out);
        try testing.expect(page.integrity_ok);
        try testing.expect(page.items.len <= 32 and page.work_used <= 64);
        try testing.expectEqual(page.work_used, store.inventory_source_visits.load(.monotonic) + store.inventory_row_visits.load(.monotonic));
        if (pages == 0) {
            try testing.expectEqual(@as(usize, 0), page.items.len);
            try testing.expectEqual(@as(usize, 64), page.work_used);
            try testing.expect(!page.complete and page.next != null);
            try testing.expectEqual(@as(usize, 64), page.next.?.origin_index);
        }
        for (page.items) |row| {
            const group = std.mem.readInt(u16, row.token[14..16], .big) - 1000;
            const aid = std.mem.readInt(u16, row.attachment_id.?[14..16], .big) - 1;
            try testing.expect(group < 3 and aid < 256);
            try testing.expect(!seen[group][aid]);
            seen[group][aid] = true;
            total += 1;
        }
        pages += 1;
        if (page.complete) {
            try testing.expect(page.next == null);
            break;
        }
        cursor = page.next orelse return error.TestUnexpectedResult;
        try testing.expect(pages < 40);
    }
    try testing.expectEqual(@as(usize, 768), total);
    for (seen) |group| for (group) |present| try testing.expect(present);
}

test "inventory batch generations ignore renewal and invalidate structural mutations" {
    var kp = try testKey(0xd2);
    defer kp.deinit();
    var metadata = [_]AttachmentMetadata{
        .{ .attachment_id = testToken(1), .signon_ms = 1, .attached = false },
        .{ .attachment_id = testToken(2), .signon_ms = 2, .attached = true },
    };
    var bytes: [50]u8 = undefined;
    var offer = upsertOffer(&kp, testToken(0xd2), 200, 0, "initial");
    offer.operation = .inventory_upsert;
    offer.resume_eligible = true;
    offer.inventory = try encodeInventory(&bytes, &metadata);
    const original = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(original.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOffer(original.decoded, 0, 200);
    var out: [1]InventoryRow = undefined;
    const first = try store.accountInventoryBatchInto("alice", 200, null, &out);
    const cursor = first.next.?;
    offer.revision = revisionFor(&kp, 201, 0);
    offer.snapshot = "chat state changed";
    offer.nick = "renamed";
    const renewed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(renewed.wire);
    _ = try store.applySignedOffer(renewed.decoded, 0, 201);
    const lease = try signedAttachmentLease(testing.allocator, .{ .token = offer.token, .revision = revisionFor(&kp, 202, 0), .issued_at_ms = 202, .expires_at_ms = 250 }, &kp);
    defer testing.allocator.free(lease.wire);
    _ = try store.applySignedAttachmentLease(lease.decoded, 202);
    var other = upsertOffer(&kp, testToken(0xd3), 202, 0, "other");
    other.account = "bob";
    const unrelated = try signedOffer(testing.allocator, other, &kp);
    defer testing.allocator.free(unrelated.wire);
    _ = try store.applySignedOffer(unrelated.decoded, 0, 202);
    const second = try store.accountInventoryBatchInto("ALICE", 202, cursor, &out);
    try testing.expectEqual(first.generation, second.generation);
    try testing.expect(second.complete and second.items[0].fresh);
    try testing.expectEqual(testToken(2), second.items[0].attachment_id.?);
    try testing.expectError(error.InvalidCursor, store.accountInventoryBatchInto("bob", 202, cursor, &out));
    var invalid = cursor;
    invalid.origin_index = std.math.maxInt(usize);
    try testing.expectError(error.InvalidCursor, store.accountInventoryBatchInto("alice", 202, invalid, &out));
    invalid = cursor;
    invalid.attachment_index = 2;
    try testing.expectError(error.InvalidCursor, store.accountInventoryBatchInto("alice", 202, invalid, &out));
    metadata[1].signon_ms = 3;
    offer.inventory = try encodeInventory(&bytes, &metadata);
    offer.revision = revisionFor(&kp, 203, 0);
    const changed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(changed.wire);
    _ = try store.applySignedOffer(changed.decoded, 0, 203);
    try testing.expectError(error.StaleCursor, store.accountInventoryBatchInto("alice", 203, cursor, &out));
    const current = (try store.accountInventoryBatchInto("alice", 203, null, &out)).next.?;
    store.markTokenDenied(offer.token, 204);
    try testing.expectError(error.StaleCursor, store.accountInventoryBatchInto("alice", 203, current, &out));
    const hidden = try store.accountInventoryBatchInto("alice", 203, null, &out);
    try testing.expect(hidden.complete and hidden.items.len == 0);
    _ = store.sweep(205);
    try testing.expect((try store.accountInventoryBatchInto("alice", 205, null, &out)).generation != hidden.generation);
    const before_eligibility = (try store.accountInventoryBatchInto("alice", 205, null, &out)).next.?;
    offer.resume_eligible = false;
    offer.nick = "";
    offer.snapshot = "";
    offer.revision = revisionFor(&kp, 206, 0);
    const inventory_only = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(inventory_only.wire);
    _ = try store.applySignedOffer(inventory_only.decoded, 0, 206);
    try testing.expectError(error.StaleCursor, store.accountInventoryBatchInto("alice", 206, before_eligibility, &out));
    const before_removal = (try store.accountInventoryBatchInto("alice", 206, null, &out)).next.?;
    const remove = try signedOffer(testing.allocator, removeOffer(&kp, offer.token, 207, 0), &kp);
    defer testing.allocator.free(remove.wire);
    _ = try store.applySignedOffer(remove.decoded, 0, 207);
    try testing.expectError(error.StaleCursor, store.accountInventoryBatchInto("alice", 207, before_removal, &out));
    offer.revision = revisionFor(&kp, 208, 0);
    const readded = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(readded.wire);
    _ = try store.applySignedOffer(readded.decoded, 0, 208);
    try testing.expectError(error.StaleCursor, store.accountInventoryBatchInto("alice", 208, before_removal, &out));
    const fence = try signedOffer(testing.allocator, testGroupOffer(&kp, offer.token, "alice"), &kp);
    defer testing.allocator.free(fence.wire);
    _ = try store.applySignedOffer(fence.decoded, 0, 300);
    const revoked = try store.accountInventoryBatchInto("alice", 300, null, &out);
    try testing.expect(revoked.complete and revoked.items.len == 1 and revoked.items[0].revoked);
    try testing.expectError(error.StaleCursor, store.accountInventoryBatchInto("alice", 300, current, &out));
}

test "inventory batch index integrity never authorizes foreign or missing entries" {
    var kp = try testKey(0xd4);
    defer kp.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var offer = upsertOffer(&kp, testToken(0xd4), 200, 0, "private Bob");
    offer.account = "bob";
    const signed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed.wire);
    _ = try store.applySignedOffer(signed.decoded, 0, 200);
    const key = Store.OriginKey{ .token = offer.token, .origin_node = offer.revision.origin_node };
    try testing.expect(try store.reserveAccountOrigin("alice", key));
    store.account_index.getPtr(accountDigest("alice")).?.origins.appendAssumeCapacity(key);
    store.bumpInventoryAccount("alice");
    var out: [32]InventoryRow = undefined;
    const foreign = try store.accountInventoryBatchInto("alice", 201, null, &out);
    try testing.expect(!foreign.integrity_ok and !foreign.complete and foreign.next == null and foreign.items.len == 0);
    store.account_index.getPtr(accountDigest("alice")).?.origins.items[0].token = testToken(0xff);
    const missing = try store.accountInventoryBatchInto("alice", 201, null, &out);
    try testing.expect(!missing.integrity_ok and missing.items.len == 0 and missing.work_used == 1);
    const entry = store.getOriginMutable(offer.token, offer.revision.origin_node).?;
    const wire = entry.wire;
    entry.wire = &.{0};
    defer entry.wire = wire;
    const malformed = try store.accountInventoryBatchInto("bob", 201, null, &out);
    try testing.expect(!malformed.integrity_ok and malformed.items.len == 0);
}

test "inventory batch cursor generation and checkpoint remain atomic under index insertion OOM" {
    var kp = try testKey(0xd5);
    defer kp.deinit();
    const first = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xd5), 200, 0, "first"), &kp);
    defer testing.allocator.free(first.wire);
    const added = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xd6), 201, 0, "added"), &kp);
    defer testing.allocator.free(added.wire);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, base: SignedOffer, extra: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            _ = try store.applySignedOffer(base, 0, 200);
            var out: [1]InventoryRow = undefined;
            const before_page = try store.accountInventoryBatchInto("alice", 201, null, &out);
            const before = try store.encodeUpgradeCheckpoint(testing.allocator, 201);
            defer testing.allocator.free(before);
            _ = store.applySignedOffer(extra, 0, 201) catch |err| {
                const after = try store.encodeUpgradeCheckpoint(testing.allocator, 201);
                defer testing.allocator.free(after);
                try testing.expectEqualSlices(u8, before, after);
                const after_page = try store.accountInventoryBatchInto("alice", 201, null, &out);
                try testing.expectEqual(before_page.generation, after_page.generation);
                try testing.expect(after_page.complete and after_page.items.len == 1);
                return err;
            };
            const after_page = try store.accountInventoryBatchInto("alice", 201, null, &out);
            try testing.expect(after_page.generation != before_page.generation);
            try testing.expect(!after_page.complete and after_page.next != null);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{ first.decoded, added.decoded });
}

test "session replica Core checkpoint: absent cursor token and exact SRST authority round trip" {
    var store = Store.init(testing.allocator);
    defer store.deinit();
    // A cursor is the last visited value, not a live row reference. Successful
    // REVOKE may remove that value before capture; preserve it without inventing
    // a row or forcing a restart at the first persistently failing token.
    for ([_]?Token{ null, testToken(0x85) }) |cursor| {
        const inner = try store.encodeUpgradeCheckpoint(testing.allocator, 100);
        defer testing.allocator.free(inner);
        const wire = try encodeCoreUpgradeCheckpoint(testing.allocator, &store, 100, cursor);
        defer testing.allocator.free(wire);
        const view = try decodeCoreUpgradeCheckpoint(wire);
        try testing.expectEqualDeep(cursor, view.orphan_revoke_cursor);
        try testing.expectEqualSlices(u8, inner, view.store_bytes);
        var restored = try Store.restoreCurrentUpgradeCheckpoint(testing.allocator, store.cfg, view.store_bytes, 100);
        defer restored.deinit();
        try testing.expectEqual(@as(usize, 0), restored.entryCount());
        try testing.expectError(error.BadMagic, decodeCoreUpgradeCheckpoint(inner));
    }
}

test "session replica Core checkpoint: canonical flags version checksum truncation and allocation rollback" {
    var store = Store.init(testing.allocator);
    defer store.deinit();
    const cursor = testToken(0x86);
    const wire = try encodeCoreUpgradeCheckpoint(testing.allocator, &store, 100, cursor);
    defer testing.allocator.free(wire);
    for (0..wire.len) |length| {
        if (decodeCoreUpgradeCheckpoint(wire[0..length])) |_| return error.TestUnexpectedResult else |_| {}
    }
    const damaged = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(damaged);
    damaged[4] = core_checkpoint_version + 1;
    try testing.expectError(error.UnsupportedVersion, decodeCoreUpgradeCheckpoint(damaged));
    @memcpy(damaged, wire);
    damaged[5] = 2;
    try testing.expectError(error.InvalidMetadata, decodeCoreUpgradeCheckpoint(damaged));
    @memcpy(damaged, wire);
    damaged[6] ^= 1;
    try testing.expectError(error.ChecksumMismatch, decodeCoreUpgradeCheckpoint(damaged));
    var complete = false;
    var failures: usize = 0;
    for (0..8) |cut| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = cut });
        const result = encodeCoreUpgradeCheckpoint(failing.allocator(), &store, 100, cursor);
        if (result) |owned| {
            defer failing.allocator().free(owned);
            try testing.expectEqualSlices(u8, wire, owned);
            try testing.expect(!failing.has_induced_failure);
            complete = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expect(failing.has_induced_failure);
            failures += 1;
        }
    }
    try testing.expect(complete and failures != 0);
    try testing.expectEqual(@as(usize, 0), store.entryCount());
}

test "session replica Core checkpoint: signed offers tombstones and terminal fences remain byte exact" {
    var origin = try testKey(0x85);
    defer origin.deinit();
    var source = Store.init(testing.allocator);
    defer source.deinit();
    const live = try signedOffer(testing.allocator, upsertOffer(&origin, testToken(1), 200, 0, "live"), &origin);
    defer testing.allocator.free(live.wire);
    const removed = try signedOffer(testing.allocator, removeOffer(&origin, testToken(2), 200, 1), &origin);
    defer testing.allocator.free(removed.wire);
    const terminal = try signedOffer(testing.allocator, testGroupOffer(&origin, testToken(3), "alice"), &origin);
    defer testing.allocator.free(terminal.wire);
    _ = try source.applySignedOffer(live.decoded, 0, 300);
    _ = try source.applySignedOffer(removed.decoded, 0, 300);
    _ = try source.applySignedOffer(terminal.decoded, 0, 300);
    const wire = try encodeCoreUpgradeCheckpoint(testing.allocator, &source, 300, testToken(8));
    defer testing.allocator.free(wire);
    const view = try decodeCoreUpgradeCheckpoint(wire);
    var restored = try Store.restoreCurrentUpgradeCheckpoint(testing.allocator, source.cfg, view.store_bytes, 300);
    defer restored.deinit();
    try testing.expectEqual(@as(?Token, testToken(8)), view.orphan_revoke_cursor);
    try testing.expectEqualSlices(u8, live.wire, restored.getOrigin(testToken(1), live.decoded.offer.revision.origin_node).?.wire);
    try testing.expectEqualSlices(u8, removed.wire, restored.getOriginTombstone(testToken(2), removed.decoded.offer.revision.origin_node).?.wire);
    try testing.expectEqualSlices(u8, terminal.wire, restored.groupRevokeForToken(testToken(3)).?.wire);
}

test "session replica Core checkpoint: retained tombstone keys cannot restart a later retry page" {
    var origin = try testKey(0x87);
    defer origin.deinit();
    var source = Store.init(testing.allocator);
    defer source.deinit();
    for (1..18) |i| {
        const offered = try signedOffer(testing.allocator, upsertOffer(&origin, testToken(@intCast(i)), 200, @intCast(i), "pending"), &origin);
        defer testing.allocator.free(offered.wire);
        _ = try source.applySignedOffer(offered.decoded, 0, 300);
    }
    // Token1 remains outstanding; token2..8 are tombstones and deliberately
    // remain sorted scan keys. Resetting the cursor would select that same page.
    for (2..9) |i| {
        const removed = try signedOffer(testing.allocator, removeOffer(&origin, testToken(@intCast(i)), 201, @intCast(i)), &origin);
        defer testing.allocator.free(removed.wire);
        _ = try source.applySignedOffer(removed.decoded, 0, 300);
    }
    const wire = try encodeCoreUpgradeCheckpoint(testing.allocator, &source, 300, testToken(8));
    defer testing.allocator.free(wire);
    const view = try decodeCoreUpgradeCheckpoint(wire);
    var restored = try Store.restoreCurrentUpgradeCheckpoint(testing.allocator, source.cfg, view.store_bytes, 300);
    defer restored.deinit();
    var page: [8]Token = undefined;
    const next = restored.storedTokensAfter(view.orphan_revoke_cursor, &page);
    try testing.expectEqual(@as(usize, 8), next.len);
    for (next, 9..) |token, i| try testing.expectEqual(testToken(@intCast(i)), token);
    const second = try encodeCoreUpgradeCheckpoint(testing.allocator, &restored, 300, next[7]);
    defer testing.allocator.free(second);
    const tail_view = try decodeCoreUpgradeCheckpoint(second);
    var successor = try Store.restoreCurrentUpgradeCheckpoint(testing.allocator, source.cfg, tail_view.store_bytes, 300);
    defer successor.deinit();
    const tail = successor.storedTokensAfter(tail_view.orphan_revoke_cursor, &page);
    try testing.expectEqual(@as(usize, 1), tail.len);
    try testing.expectEqual(testToken(17), tail[0]);
    try testing.expectEqualSlices(u8, source.getOrigin(testToken(1), signed_frame.originShortId(origin.public_key)).?.wire, successor.getOrigin(testToken(1), signed_frame.originShortId(origin.public_key)).?.wire);
    try testing.expectEqual(@as(usize, 7), successor.tombstoneCount());
}

test "session replica offer memo rechecks authority, expiry and terminal revocation" {
    var kp = try testKey(0xe1);
    defer kp.deinit();
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xe1), 200, 0, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&kp, testToken(0xe1), "alice"), &kp);
    defer testing.allocator.free(fence.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(7) };
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(offer.decoded, 10, 200, &memo, authority)).disposition);
    const replay = try decodeOffer(offer.wire);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOfferMemoized(replay, 10, 201, &memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
    var changed_authority = authority;
    changed_authority.epoch += 1;
    _ = try store.applySignedOfferMemoized(replay, 10, 202, &memo, changed_authority);
    try testing.expectEqual(@as(usize, 2), memo.test_signature_checks);
    changed_authority.roster_digest[0] ^= 1;
    _ = try store.applySignedOfferMemoized(replay, 10, 203, &memo, changed_authority);
    try testing.expectEqual(@as(usize, 3), memo.test_signature_checks);
    var bad = replay;
    bad.signature[0] ^= 1;
    try testing.expectError(error.BadSignature, store.applySignedOfferMemoized(bad, 10, 204, &memo, authority));
    try testing.expectEqual(@as(usize, 4), memo.test_signature_checks);
    bad = replay;
    bad.signer[0] ^= 1;
    try testing.expectError(error.OriginMismatch, store.applySignedOfferMemoized(bad, 10, 205, &memo, authority));
    _ = try store.applySignedOfferMemoized(replay, 10, 200, &memo, authority);
    try testing.expectEqual(@as(usize, 5), memo.test_signature_checks); // rollback cannot hit
    try testing.expectError(error.Expired, store.applySignedOfferMemoized(replay, 10, 10_001, &memo, authority));
    try testing.expectEqual(@as(usize, 6), memo.test_signature_checks);
    _ = try store.applySignedOfferMemoized(fence.decoded, 10, 300, &memo, authority);
    try testing.expectEqual(ApplyDisposition.tombstoned, (try store.applySignedOfferMemoized(replay, 10, 301, &memo, authority)).disposition);
}

test "session replica offer memo retains exact signed bytes and wipes bounded slots" {
    var kp = try testKey(0xe2);
    defer kp.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(3) };
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const first = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(1), 200, 0, "a"), &kp);
    defer testing.allocator.free(first.wire);
    try memo.verify(first.decoded, authority, 200);
    var changed = upsertOffer(&kp, testToken(1), 200, 0, "b");
    changed.expires_at_ms = 9_999;
    const second = try signedOffer(testing.allocator, changed, &kp);
    defer testing.allocator.free(second.wire);
    try memo.verify(second.decoded, authority, 201);
    try testing.expectEqual(@as(usize, 2), memo.test_signature_checks);
    for (2..6) |n| {
        const other = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(@intCast(n)), 200, 0, "a"), &kp);
        defer testing.allocator.free(other.wire);
        try memo.verify(other.decoded, authority, 202);
    }
    try memo.verify(first.decoded, authority, 203);
    try testing.expectEqual(@as(usize, 7), memo.test_signature_checks);
    memo.deinit();
    for (memo.slots) |slot| {
        try testing.expect(!slot.valid);
        try testing.expect(std.mem.allEqual(u8, &slot.transcript, 0));
    }
    try memo.verify(first.decoded, authority, 204);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
}

test "session replica offer memo insertion remains allocation failure atomic" {
    var kp = try testKey(0xe3);
    defer kp.deinit();
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xe3), 200, 0, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, signed: SignedOffer) !void {
            var store = Store.init(allocator);
            defer store.deinit();
            var memo: OfferSignatureMemo = .{};
            defer memo.deinit();
            const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(9) };
            const result = store.applySignedOfferMemoized(signed, 10, 200, &memo, authority) catch |err| {
                try testing.expectEqual(@as(usize, 0), store.entryCount());
                try testing.expectEqual(@as(usize, 0), store.routeCount());
                return err;
            };
            try testing.expectEqual(ApplyDisposition.inserted, result.disposition);
            try testing.expectEqualStrings("state", store.get(signed.offer.token).?.snapshot);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{offer.decoded});
}

test "session replica offer memo warmed hit respects terminal group revocation" {
    var kp = try testKey(0xe4);
    defer kp.deinit();
    const token = testToken(0xe4);
    const offer = try signedOffer(testing.allocator, upsertOffer(&kp, token, 200, 0, "state"), &kp);
    defer testing.allocator.free(offer.wire);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&kp, token, "alice"), &kp);
    defer testing.allocator.free(fence.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(7) };
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(offer.decoded, 10, 200, &memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(fence.decoded, 10, 201, &memo, authority)).disposition);
    try testing.expectEqual(ApplyDisposition.tombstoned, (try store.applySignedOfferMemoized(offer.decoded, 10, 202, &memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
}

test "session replica offer memo warmed hit respects current quarantine" {
    var alice = try testKey(0xe5);
    defer alice.deinit();
    var mallory = try testKey(0xe6);
    defer mallory.deinit();
    const token = testToken(0xe5);
    const original = try signedOffer(testing.allocator, upsertOffer(&alice, token, 200, 0, "alice"), &alice);
    defer testing.allocator.free(original.wire);
    var conflicting_offer = upsertOffer(&mallory, token, 200, 0, "mallory");
    conflicting_offer.account = "mallory";
    const conflicting = try signedOffer(testing.allocator, conflicting_offer, &mallory);
    defer testing.allocator.free(conflicting.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(7) };
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(original.decoded, 10, 200, &memo, authority)).disposition);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOffer(conflicting.decoded, 11, 201)).disposition);
    try testing.expectEqual(ApplyDisposition.quarantined, (try store.applySignedOfferMemoized(original.decoded, 10, 202, &memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
}

test "session replica offer memo inventory hit binds signed metadata and current authority" {
    var kp = try testKey(0xe7);
    defer kp.deinit();
    var inventory_buf: [inventory_row_len]u8 = undefined;
    var offer = upsertOffer(&kp, testToken(0xe7), 200, 0, "state");
    offer.operation = .inventory_upsert;
    offer.resume_eligible = true;
    offer.inventory = try encodeInventory(&inventory_buf, &.{.{ .attachment_id = @splat(1), .signon_ms = 10, .attached = true }});
    const signed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(7) };
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(signed.decoded, 10, 200, &memo, authority)).disposition);
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOfferMemoized(try decodeOffer(signed.wire), 10, 201, &memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
    var altered_projection = signed.decoded;
    altered_projection.offer.resume_eligible = false;
    try testing.expectError(error.TranscriptMismatch, store.applySignedOfferMemoized(altered_projection, 10, 202, &memo, authority));
    var changed_authority = authority;
    changed_authority.roster_digest[0] ^= 1;
    _ = try store.applySignedOfferMemoized(signed.decoded, 10, 203, &memo, changed_authority);
    try testing.expectEqual(@as(usize, 2), memo.test_signature_checks);
    changed_authority.epoch += 1;
    _ = try store.applySignedOfferMemoized(signed.decoded, 10, 204, &memo, changed_authority);
    try testing.expectEqual(@as(usize, 3), memo.test_signature_checks);
    try testing.expectError(error.Expired, store.applySignedOfferMemoized(signed.decoded, 10, 10_001, &memo, authority));
    try testing.expectEqual(@as(usize, 4), memo.test_signature_checks);
}

test "session replica offer memo inventory hit respects revoke and quarantine" {
    var alice = try testKey(0xe8);
    defer alice.deinit();
    var mallory = try testKey(0xe9);
    defer mallory.deinit();
    var inventory_buf: [inventory_row_len]u8 = undefined;
    var offer = upsertOffer(&alice, testToken(0xe8), 200, 0, "state");
    offer.operation = .inventory_upsert;
    offer.resume_eligible = false;
    offer.nick = "";
    offer.snapshot = "";
    offer.inventory = try encodeInventory(&inventory_buf, &.{.{ .attachment_id = @splat(1), .signon_ms = 10, .attached = true }});
    const signed = try signedOffer(testing.allocator, offer, &alice);
    defer testing.allocator.free(signed.wire);
    const fence = try signedOffer(testing.allocator, testGroupOffer(&alice, offer.token, "alice"), &alice);
    defer testing.allocator.free(fence.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(7) };
    _ = try store.applySignedOfferMemoized(signed.decoded, 10, 200, &memo, authority);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(fence.decoded, 10, 201, &memo, authority)).disposition);
    try testing.expectEqual(ApplyDisposition.tombstoned, (try store.applySignedOfferMemoized(signed.decoded, 10, 202, &memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), memo.test_signature_checks);
    var conflict_store = Store.init(testing.allocator);
    defer conflict_store.deinit();
    var conflict_memo: OfferSignatureMemo = .{};
    defer conflict_memo.deinit();
    var conflicting = upsertOffer(&mallory, offer.token, 200, 0, "other");
    conflicting.account = "mallory";
    const rival = try signedOffer(testing.allocator, conflicting, &mallory);
    defer testing.allocator.free(rival.wire);
    _ = try conflict_store.applySignedOfferMemoized(signed.decoded, 10, 200, &conflict_memo, authority);
    try testing.expectEqual(ApplyDisposition.quarantined, (try conflict_store.applySignedOffer(rival.decoded, 11, 201)).disposition);
    try testing.expectEqual(ApplyDisposition.quarantined, (try conflict_store.applySignedOfferMemoized(signed.decoded, 10, 202, &conflict_memo, authority)).disposition);
    try testing.expectEqual(@as(usize, 1), conflict_memo.test_signature_checks);
}

test "session replica offer memo production stats separate verification hit fallback and projection refusal" {
    var kp = try testKey(0xea);
    defer kp.deinit();
    var inventory_buf: [inventory_row_len]u8 = undefined;
    var offer = upsertOffer(&kp, testToken(0xea), 200, 0, "state");
    offer.operation = .inventory_upsert;
    offer.resume_eligible = true;
    offer.inventory = try encodeInventory(&inventory_buf, &.{.{ .attachment_id = @splat(2), .signon_ms = 10, .attached = true }});
    const signed = try signedOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(signed.wire);
    var store = Store.init(testing.allocator);
    defer store.deinit();
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const authority: OfferMemoAuthority = .{ .declared = true, .epoch = 1, .roster_digest = @splat(8) };
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{}, memo.stats());
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOfferMemoized(signed.decoded, 10, 200, &memo, authority)).disposition);
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 1 }, memo.stats());
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOfferMemoized(signed.decoded, 10, 201, &memo, authority)).disposition);
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 1, .cache_hits = 1 }, memo.stats());
    var altered = signed.decoded;
    altered.offer.resume_eligible = false;
    try testing.expectError(error.TranscriptMismatch, store.applySignedOfferMemoized(altered, 10, 202, &memo, authority));
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 1, .cache_hits = 1 }, memo.stats());
    altered = signed.decoded;
    altered.signature[0] ^= 1;
    try testing.expectError(error.BadSignature, store.applySignedOfferMemoized(altered, 10, 202, &memo, authority));
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 2, .cache_hits = 1 }, memo.stats());
    try testing.expectError(error.Expired, store.applySignedOfferMemoized(signed.decoded, 10, 10_001, &memo, authority));
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 3, .cache_hits = 1, .fallbacks = 1 }, memo.stats());
    // A backward clock must perform signature verification, even for bytes
    // still retained in a slot. Normal Store lifetime admission is unchanged.
    try testing.expectEqual(ApplyDisposition.duplicate, (try store.applySignedOfferMemoized(signed.decoded, 10, 203, &memo, authority)).disposition);
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 4, .cache_hits = 1, .fallbacks = 2 }, memo.stats());
}

test "session replica offer memo production stats saturate without changing signature decisions" {
    var kp = try testKey(0xeb);
    defer kp.deinit();
    const signed = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xeb), 200, 0, "state"), &kp);
    defer testing.allocator.free(signed.wire);
    const authority: OfferMemoAuthority = .{ .declared = false, .epoch = 0, .roster_digest = @splat(0) };
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    const maximum = std.math.maxInt(u64);
    memo.test_signature_checks = maximum - 1;
    memo.cache_hits = maximum - 1;
    memo.fallbacks = maximum - 1;
    try memo.verify(signed.decoded, authority, 200);
    try memo.verify(signed.decoded, authority, 201);
    try memo.verify(signed.decoded, authority, 202);
    var bad = signed.decoded;
    bad.signature[0] ^= 1;
    try testing.expectError(error.BadSignature, memo.verify(bad, authority, 203));
    try memo.verify(signed.decoded, authority, 10_001);
    try memo.verify(signed.decoded, authority, 10_002);
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = maximum, .cache_hits = maximum, .fallbacks = maximum }, memo.stats());
}

test "session replica offer memo production stats are value observations cold wiped and absent from checkpoint" {
    var kp = try testKey(0xec);
    defer kp.deinit();
    const signed = try signedOffer(testing.allocator, upsertOffer(&kp, testToken(0xec), 200, 0, "state"), &kp);
    defer testing.allocator.free(signed.wire);
    const authority: OfferMemoAuthority = .{ .declared = false, .epoch = 0, .roster_digest = @splat(0) };
    var memo: OfferSignatureMemo = .{};
    defer memo.deinit();
    var store = Store.init(testing.allocator);
    defer store.deinit();
    _ = try store.applySignedOfferMemoized(signed.decoded, 10, 200, &memo, authority);
    const before = try store.encodeUpgradeCheckpoint(testing.allocator, 200);
    defer testing.allocator.free(before);
    var observation = memo.stats();
    observation.signature_checks = 999;
    try testing.expectEqual(@as(u64, 999), observation.signature_checks);
    try testing.expectEqual(@as(u64, 1), memo.stats().signature_checks);
    try memo.verify(signed.decoded, authority, 201);
    try testing.expectEqual(@as(u64, 1), memo.stats().cache_hits);
    memo.deinit();
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{}, memo.stats());
    for (memo.slots) |slot| {
        try testing.expect(!slot.valid);
        try testing.expect(std.mem.allEqual(u8, &slot.transcript, 0));
    }
    const after = try store.encodeUpgradeCheckpoint(testing.allocator, 200);
    defer testing.allocator.free(after);
    try testing.expectEqualSlices(u8, before, after);
    var restored = try Store.restoreCurrentUpgradeCheckpoint(testing.allocator, store.cfg, before, 200);
    defer restored.deinit();
    var cold: OfferSignatureMemo = .{};
    defer cold.deinit();
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{}, cold.stats());
    _ = try restored.applySignedOfferMemoized(signed.decoded, 10, 201, &cold, authority);
    try testing.expectEqualDeep(OfferSignatureMemo.Stats{ .signature_checks = 1 }, cold.stats());
}

test "session replica T10 high-water: an older revision with a later window after a backward clock step stays covered by the REVOKE and its tombstone" {
    var kp = try testKey(0x7a);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_routes = 4,
        .max_tombstones = 4,
        .tombstone_ttl_ms = 100,
        .max_offer_lifetime_ms = 20_000,
    });
    defer store.deinit();
    const tok = testToken(0x7a);
    const origin = signed_frame.originShortId(kp.public_key);

    // r1 signed before the wall clock stepped back by 5 s.
    var r1_offer = upsertOffer(&kp, tok, 1, 1, "r1");
    r1_offer.issued_at_ms = 10_000;
    r1_offer.expires_at_ms = 30_000;
    const r1 = try signedOffer(testing.allocator, r1_offer, &kp);
    defer testing.allocator.free(r1.wire);
    try testing.expectEqual(ApplyDisposition.inserted, (try store.applySignedOffer(r1.decoded, 0, 10_000)).disposition);

    // r2 (newer revision) signed after the step: an earlier window.
    var r2_offer = upsertOffer(&kp, tok, 1, 2, "r2");
    r2_offer.issued_at_ms = 5_000;
    r2_offer.expires_at_ms = 25_000;
    const r2 = try signedOffer(testing.allocator, r2_offer, &kp);
    defer testing.allocator.free(r2.wire);
    _ = try store.applySignedOffer(r2.decoded, 0, 5_000);
    try testing.expect(store.getOrigin(tok, origin).?.revision.eql(r2.decoded.offer.revision));

    // The superseded window is the high-water of r1 and r2, not r2 alone.
    const sup = store.supersededAuthority(tok, origin).?;
    try testing.expectEqual(@as(i64, 10_000), sup.issued_at_ms);
    try testing.expectEqual(@as(i64, 30_000), sup.expires_at_ms);

    const lifetime = session_replica_revocation.revokeLifetime(5_001, sup, 20_000);
    try testing.expect(lifetime.expires_at_ms >= r1_offer.expires_at_ms);
    var revoke_offer = removeOffer(&kp, tok, 1, 3);
    revoke_offer.issued_at_ms = lifetime.issued_at_ms;
    revoke_offer.expires_at_ms = lifetime.expires_at_ms;
    const revoke = try signedOffer(testing.allocator, revoke_offer, &kp);
    defer testing.allocator.free(revoke.wire);
    try testing.expectEqual(ApplyDisposition.superseded, (try store.applySignedOffer(revoke.decoded, 0, 5_001)).disposition);
    const tomb = store.getOriginTombstone(tok, origin).?;
    try testing.expect(tomb.retain_until_ms >= r1_offer.expires_at_ms);

    // Once r2's window has passed, the tombstone is still retained and still
    // exportable, so replaying r1 (valid until 30 000) is refused.
    _ = store.sweep(25_001);
    try testing.expect(store.getOriginTombstone(tok, origin) != null);
    try testing.expect(session_replica_revocation.tombstoneExportable(25_001, store.getOriginTombstone(tok, origin).?.offer_expires_at_ms));
    try testing.expectEqual(ApplyDisposition.stale, (try store.applySignedOffer(r1.decoded, 9, 25_001)).disposition);
    try testing.expect(store.getOrigin(tok, origin) == null);
}

test "session replica T10 high-water: marks survive a tombstone-converting OFFER and never exceed what was accepted" {
    var kp = try testKey(0x7b);
    defer kp.deinit();
    var store = Store.initWithConfig(testing.allocator, .{
        .max_entries = 4,
        .max_routes = 4,
        .max_tombstones = 4,
        .tombstone_ttl_ms = 100,
        .max_offer_lifetime_ms = 20_000,
    });
    defer store.deinit();
    const tok = testToken(0x7b);
    const origin = signed_frame.originShortId(kp.public_key);

    var first = upsertOffer(&kp, tok, 1, 1, "a");
    first.issued_at_ms = 1_000;
    first.expires_at_ms = 21_000;
    const a = try signedOffer(testing.allocator, first, &kp);
    defer testing.allocator.free(a.wire);
    _ = try store.applySignedOffer(a.decoded, 0, 1_000);
    // Ordinary forward progress: marks equal the current window.
    try testing.expectEqual(@as(i64, 1_000), store.supersededAuthority(tok, origin).?.issued_at_ms);
    try testing.expectEqual(@as(i64, 21_000), store.supersededAuthority(tok, origin).?.expires_at_ms);

    var rm = removeOffer(&kp, tok, 1, 2);
    rm.issued_at_ms = 2_000;
    rm.expires_at_ms = 22_000;
    const r = try signedOffer(testing.allocator, rm, &kp);
    defer testing.allocator.free(r.wire);
    _ = try store.applySignedOffer(r.decoded, 0, 2_000);
    const retain = store.getOriginTombstone(tok, origin).?.retain_until_ms;

    // A newer OFFER converting the tombstone after a backward step inherits
    // the REVOKE issuance and the tombstone horizon as its marks.
    var back = upsertOffer(&kp, tok, 1, 3, "b");
    back.issued_at_ms = 500;
    back.expires_at_ms = 20_500;
    const b = try signedOffer(testing.allocator, back, &kp);
    defer testing.allocator.free(b.wire);
    _ = try store.applySignedOffer(b.decoded, 0, 500);
    const sup = store.supersededAuthority(tok, origin).?;
    try testing.expectEqual(@as(i64, 2_000), sup.issued_at_ms);
    try testing.expectEqual(retain, sup.expires_at_ms);
    try testing.expect(store.getOrigin(tok, origin).?.revision.eql(b.decoded.offer.revision));
}
