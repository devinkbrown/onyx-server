// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attachment-scoped SESSION_REPLICA v3 candidate.
//!
//! This module intentionally has no SRO2 compatibility decoder and owns no
//! sockets. It is a parallel, current-version candidate whose authority key is
//! `(session token, physical attachment id, origin node)`. Consequently two
//! clients sharing one reusable token never overwrite one another's replica,
//! lease, revocation, or equivocation state.

const std = @import("std");

const attachment_id_mod = @import("../attachment_id.zig");
const sign = @import("../../crypto/sign.zig");
const session_portability = @import("../../proto/session_portability.zig");
const mesh_clock = @import("../../substrate/undertow/mesh_clock.zig");
const signed_frame = @import("../../substrate/undertow/signed_frame.zig");

pub const Token = attachment_id_mod.SessionToken;
pub const AttachmentId = attachment_id_mod.AttachmentId;
pub const NodeId = u64;
pub const Digest = [std.crypto.hash.Blake3.digest_length]u8;

pub const offer_magic = [_]u8{ 'S', 'R', 'O', '3' };
pub const ack_magic = [_]u8{ 'S', 'R', 'A', '3' };
pub const revoke_magic = [_]u8{ 'S', 'R', 'V', '3' };
pub const attachment_lease_magic = [_]u8{ 'S', 'R', 'L', '3' };
pub const checkpoint_magic = [_]u8{ 'S', 'R', 'C', '3' };
pub const checkpoint_version: u8 = 2;

pub const offer_sign_domain = "onyx-session-replica-attachment-offer-v3";
pub const ack_sign_domain = "onyx-session-replica-attachment-ack-v3";
pub const revoke_sign_domain = "onyx-session-replica-attachment-revoke-v3";
pub const attachment_lease_sign_domain = "onyx-session-replica-attachment-lease-v3";
const checkpoint_digest_domain = "onyx-session-replica-attachment-checkpoint-v2\x00";
const account_digest_domain = "onyx-session-replica-attachment-account-v1\x00";

pub const max_account_len: usize = 64;
pub const max_nick_len: usize = 64;
/// Reuse the exact cross-version portable envelope ceiling. SRA3 does not
/// invent a larger limit that a rolling-old migration path cannot carry.
pub const max_snapshot_len: usize = session_portability.max_snapshot_len;

const revision_wire_len: usize = 8 + 8 + 8;
const signature_wire_len: usize = sign.public_key_len + sign.signature_len;
const identity_wire_len: usize = @sizeOf(Token) + @sizeOf(AttachmentId);
const offer_fixed_len: usize = offer_magic.len + identity_wire_len + revision_wire_len + 8 + 8 + 2 + 2 + 4;
const ack_fixed_len: usize = ack_magic.len + 1 + identity_wire_len + revision_wire_len + revision_wire_len + 8 + 8 + 8;
const revoke_fixed_len: usize = revoke_magic.len + 1 + identity_wire_len + revision_wire_len + 8 + 8;
const lease_fixed_len: usize = attachment_lease_magic.len + identity_wire_len + revision_wire_len + 8 + 8;
const checkpoint_header_len: usize = checkpoint_magic.len + 1 + 8 + 4 + 4 + 4;
const checkpoint_checksum_len: usize = @sizeOf(Digest);

comptime {
    std.debug.assert(@sizeOf(AttachmentId) == 16);
    std.debug.assert(offer_fixed_len + signature_wire_len + max_account_len + max_nick_len <=
        session_portability.legacy_envelope_reserve);
}

pub const Revision = struct {
    epoch: u64,
    sequence: u64,
    origin_node: NodeId,

    pub fn compare(a: Revision, b: Revision) std.math.Order {
        if (a.epoch != b.epoch) return std.math.order(a.epoch, b.epoch);
        if (a.sequence != b.sequence) return std.math.order(a.sequence, b.sequence);
        return std.math.order(a.origin_node, b.origin_node);
    }

    pub fn eql(a: Revision, b: Revision) bool {
        return a.compare(b) == .eq;
    }

    pub fn isCanonical(self: Revision) bool {
        return self.origin_node != 0 and self.epoch == mesh_clock.MeshClock.physicalOf(self.sequence);
    }
};

pub const Offer = struct {
    token: Token,
    attachment_id: AttachmentId,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
    account: []const u8,
    nick: []const u8,
    snapshot: []const u8,
};

pub const Revoke = struct {
    account: []const u8,
    token: Token,
    attachment_id: AttachmentId,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
};

pub const AckStatus = enum(u8) {
    accepted = 1,
    duplicate = 2,
    conflict = 3,
    stale = 4,
    superseded = 5,
    revoked = 6,
    capacity = 7,
};

pub const Ack = struct {
    status: AckStatus,
    token: Token,
    attachment_id: AttachmentId,
    offered_revision: Revision,
    observed_revision: Revision,
    ack_node: NodeId,
    issued_at_ms: i64,
    expires_at_ms: i64,
};

pub const AttachmentLease = struct {
    token: Token,
    attachment_id: AttachmentId,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
};

pub const SignedOffer = signedType(Offer);
pub const SignedRevoke = signedType(Revoke);
pub const SignedAck = signedType(Ack);
pub const SignedAttachmentLease = signedType(AttachmentLease);

fn signedType(comptime Semantic: type) type {
    return struct {
        value: Semantic,
        signer: sign.PublicKey,
        signature: sign.Signature,
        transcript: []const u8,
        wire: []const u8,
    };
}

pub const EncodeError = error{
    InvalidOffer,
    InvalidRevoke,
    InvalidAck,
    InvalidAttachmentLease,
    OriginMismatch,
    TooLong,
} || std.mem.Allocator.Error || sign.SignError;

pub const DecodeError = error{
    BadMagic,
    InvalidOffer,
    InvalidRevoke,
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

pub fn encodeOffer(allocator: std.mem.Allocator, value: Offer, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateOfferShape(value);
    try requireSigner(value.revision.origin_node, kp.public_key);
    const transcript_len = offer_fixed_len + value.account.len + value.nick.len + value.snapshot.len;
    var wire = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(wire);
    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&offer_magic);
    writer.writeIdentity(value.token, value.attachment_id);
    writer.writeRevision(value.revision);
    writer.writeI64(value.issued_at_ms);
    writer.writeI64(value.expires_at_ms);
    writer.writeU16(@intCast(value.account.len));
    writer.writeU16(@intCast(value.nick.len));
    writer.writeU32(@intCast(value.snapshot.len));
    writer.writeBytes(value.account);
    writer.writeBytes(value.nick);
    writer.writeBytes(value.snapshot);
    std.debug.assert(writer.pos == transcript_len);
    const signature = try kp.signCtx(offer_sign_domain, wire[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    return wire;
}

pub fn decodeOffer(wire: []const u8) DecodeError!SignedOffer {
    var reader = Reader{ .bytes = wire };
    const value = try readOffer(&reader);
    return finishSigned(Offer, wire, value, &reader);
}

pub fn verifyOffer(signed: SignedOffer) VerifyError!void {
    try verifyProjected(Offer, signed, readOffer, offerEql, offer_sign_domain, signed.value.revision.origin_node);
}

pub fn encodeRevoke(allocator: std.mem.Allocator, value: Revoke, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateRevokeShape(value);
    try requireSigner(value.revision.origin_node, kp.public_key);
    const transcript_len = revoke_fixed_len + value.account.len;
    var wire = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(wire);
    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&revoke_magic);
    writer.writeByte(@intCast(value.account.len));
    writer.writeBytes(value.account);
    writer.writeIdentity(value.token, value.attachment_id);
    writer.writeRevision(value.revision);
    writer.writeI64(value.issued_at_ms);
    writer.writeI64(value.expires_at_ms);
    const signature = try kp.signCtx(revoke_sign_domain, wire[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    return wire;
}

pub fn decodeRevoke(wire: []const u8) DecodeError!SignedRevoke {
    var reader = Reader{ .bytes = wire };
    const value = try readRevoke(&reader);
    return finishSigned(Revoke, wire, value, &reader);
}

pub fn verifyRevoke(signed: SignedRevoke) VerifyError!void {
    try verifyProjected(Revoke, signed, readRevoke, revokeEql, revoke_sign_domain, signed.value.revision.origin_node);
}

pub fn encodeAck(allocator: std.mem.Allocator, value: Ack, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateAckShape(value);
    try requireSigner(value.ack_node, kp.public_key);
    var wire = try allocator.alloc(u8, ack_fixed_len + signature_wire_len);
    errdefer allocator.free(wire);
    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&ack_magic);
    writer.writeByte(@backingInt(value.status));
    writer.writeIdentity(value.token, value.attachment_id);
    writer.writeRevision(value.offered_revision);
    writer.writeRevision(value.observed_revision);
    writer.writeU64(value.ack_node);
    writer.writeI64(value.issued_at_ms);
    writer.writeI64(value.expires_at_ms);
    const signature = try kp.signCtx(ack_sign_domain, wire[0..ack_fixed_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    return wire;
}

pub fn decodeAck(wire: []const u8) DecodeError!SignedAck {
    var reader = Reader{ .bytes = wire };
    const value = try readAck(&reader);
    return finishSigned(Ack, wire, value, &reader);
}

pub fn verifyAck(signed: SignedAck) VerifyError!void {
    try verifyProjected(Ack, signed, readAck, ackEql, ack_sign_domain, signed.value.ack_node);
}

pub fn encodeAttachmentLease(
    allocator: std.mem.Allocator,
    value: AttachmentLease,
    kp: *const sign.KeyPair,
) EncodeError![]u8 {
    try validateLeaseShape(value);
    try requireSigner(value.revision.origin_node, kp.public_key);
    var wire = try allocator.alloc(u8, lease_fixed_len + signature_wire_len);
    errdefer allocator.free(wire);
    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&attachment_lease_magic);
    writer.writeIdentity(value.token, value.attachment_id);
    writer.writeRevision(value.revision);
    writer.writeI64(value.issued_at_ms);
    writer.writeI64(value.expires_at_ms);
    const signature = try kp.signCtx(attachment_lease_sign_domain, wire[0..lease_fixed_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    return wire;
}

pub fn decodeAttachmentLease(wire: []const u8) DecodeError!SignedAttachmentLease {
    var reader = Reader{ .bytes = wire };
    const value = try readLease(&reader);
    return finishSigned(AttachmentLease, wire, value, &reader);
}

pub fn verifyAttachmentLease(signed: SignedAttachmentLease) VerifyError!void {
    try verifyProjected(
        AttachmentLease,
        signed,
        readLease,
        leaseEql,
        attachment_lease_sign_domain,
        signed.value.revision.origin_node,
    );
}

fn finishSigned(comptime T: type, wire: []const u8, value: T, reader: *Reader) DecodeError!signedType(T) {
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != wire.len) return error.TrailingBytes;
    return .{
        .value = value,
        .signer = signer,
        .signature = signature,
        .transcript = wire[0..transcript_end],
        .wire = wire,
    };
}

fn verifyProjected(
    comptime T: type,
    signed: signedType(T),
    comptime read: fn (*Reader) DecodeError!T,
    comptime eql: fn (T, T) bool,
    comptime domain: []const u8,
    origin: NodeId,
) VerifyError!void {
    const expected_wire_len = signed.transcript.len + signature_wire_len;
    if (signed.wire.len != expected_wire_len or
        !std.mem.eql(u8, signed.wire[0..signed.transcript.len], signed.transcript) or
        !std.mem.eql(u8, signed.wire[signed.transcript.len..][0..sign.public_key_len], &signed.signer) or
        !std.mem.eql(u8, signed.wire[signed.transcript.len + sign.public_key_len ..], &signed.signature))
        return error.TranscriptMismatch;
    var reader = Reader{ .bytes = signed.transcript };
    const projected = read(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !eql(projected, signed.value)) return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != origin) return error.OriginMismatch;
    const valid = sign.verifyCtx(domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}

fn readOffer(reader: *Reader) DecodeError!Offer {
    if (!std.mem.eql(u8, try reader.take(offer_magic.len), &offer_magic)) return error.BadMagic;
    const identity = try reader.readIdentity(error.InvalidOffer);
    const revision = try reader.readRevision();
    const issued_at_ms = try reader.readI64();
    const expires_at_ms = try reader.readI64();
    const account_len = try reader.readU16();
    const nick_len = try reader.readU16();
    const snapshot_len = try reader.readU32();
    if (account_len > max_account_len or nick_len > max_nick_len or snapshot_len > max_snapshot_len) return error.TooLong;
    const value = Offer{
        .token = identity.token,
        .attachment_id = identity.attachment_id,
        .revision = revision,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
        .account = try reader.take(account_len),
        .nick = try reader.take(nick_len),
        .snapshot = try reader.take(snapshot_len),
    };
    validateOfferShape(value) catch |err| return switch (err) {
        error.TooLong => error.TooLong,
        else => error.InvalidOffer,
    };
    return value;
}

fn readRevoke(reader: *Reader) DecodeError!Revoke {
    if (!std.mem.eql(u8, try reader.take(revoke_magic.len), &revoke_magic)) return error.BadMagic;
    const account_len: usize = try reader.readByte();
    if (account_len > max_account_len) return error.TooLong;
    const account = try reader.take(account_len);
    const identity = try reader.readIdentity(error.InvalidRevoke);
    const value = Revoke{
        .account = account,
        .token = identity.token,
        .attachment_id = identity.attachment_id,
        .revision = try reader.readRevision(),
        .issued_at_ms = try reader.readI64(),
        .expires_at_ms = try reader.readI64(),
    };
    validateRevokeShape(value) catch return error.InvalidRevoke;
    return value;
}

fn readAck(reader: *Reader) DecodeError!Ack {
    if (!std.mem.eql(u8, try reader.take(ack_magic.len), &ack_magic)) return error.BadMagic;
    const status: AckStatus = switch (try reader.readByte()) {
        1 => .accepted,
        2 => .duplicate,
        3 => .conflict,
        4 => .stale,
        5 => .superseded,
        6 => .revoked,
        7 => .capacity,
        else => return error.InvalidAck,
    };
    const identity = try reader.readIdentity(error.InvalidAck);
    const value = Ack{
        .status = status,
        .token = identity.token,
        .attachment_id = identity.attachment_id,
        .offered_revision = try reader.readRevision(),
        .observed_revision = try reader.readRevision(),
        .ack_node = try reader.readU64(),
        .issued_at_ms = try reader.readI64(),
        .expires_at_ms = try reader.readI64(),
    };
    validateAckShape(value) catch return error.InvalidAck;
    return value;
}

fn readLease(reader: *Reader) DecodeError!AttachmentLease {
    if (!std.mem.eql(u8, try reader.take(attachment_lease_magic.len), &attachment_lease_magic)) return error.BadMagic;
    const identity = try reader.readIdentity(error.InvalidAttachmentLease);
    const value = AttachmentLease{
        .token = identity.token,
        .attachment_id = identity.attachment_id,
        .revision = try reader.readRevision(),
        .issued_at_ms = try reader.readI64(),
        .expires_at_ms = try reader.readI64(),
    };
    validateLeaseShape(value) catch return error.InvalidAttachmentLease;
    return value;
}

fn validateOfferShape(value: Offer) error{ InvalidOffer, TooLong }!void {
    if (!identityRevisionValid(value.token, value.attachment_id, value.revision)) return error.InvalidOffer;
    if (value.issued_at_ms < 0 or value.expires_at_ms < value.issued_at_ms) return error.InvalidOffer;
    if (value.account.len > max_account_len or value.nick.len > max_nick_len or value.snapshot.len > max_snapshot_len) return error.TooLong;
    if (value.account.len == 0 or value.nick.len == 0 or value.snapshot.len == 0) return error.InvalidOffer;
    if (!validAccount(value.account)) return error.InvalidOffer;
}

fn validateRevokeShape(value: Revoke) error{InvalidRevoke}!void {
    if (!identityRevisionValid(value.token, value.attachment_id, value.revision)) return error.InvalidRevoke;
    if (!validAccount(value.account)) return error.InvalidRevoke;
    if (value.issued_at_ms < 0 or value.expires_at_ms < value.issued_at_ms) return error.InvalidRevoke;
}

fn validAccount(account: []const u8) bool {
    if (account.len == 0 or account.len > max_account_len) return false;
    for (account) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

fn validateAckShape(value: Ack) error{InvalidAck}!void {
    if (!identityValid(value.token, value.attachment_id)) return error.InvalidAck;
    if (!value.offered_revision.isCanonical() or !value.observed_revision.isCanonical()) return error.InvalidAck;
    if (value.offered_revision.origin_node != value.observed_revision.origin_node or value.ack_node == 0) return error.InvalidAck;
    if (value.issued_at_ms < 0 or value.expires_at_ms < value.issued_at_ms) return error.InvalidAck;
}

fn validateLeaseShape(value: AttachmentLease) error{InvalidAttachmentLease}!void {
    if (!identityRevisionValid(value.token, value.attachment_id, value.revision)) return error.InvalidAttachmentLease;
    if (value.issued_at_ms < 0 or value.expires_at_ms < value.issued_at_ms) return error.InvalidAttachmentLease;
}

fn identityRevisionValid(token: Token, attachment_id: AttachmentId, revision: Revision) bool {
    return identityValid(token, attachment_id) and revision.isCanonical();
}

fn identityValid(token: Token, attachment_id: AttachmentId) bool {
    return !isZeroToken(token) and !attachment_id.isZero();
}

fn requireSigner(origin: NodeId, public_key: sign.PublicKey) error{OriginMismatch}!void {
    if (origin == 0 or signed_frame.originShortId(public_key) != origin) return error.OriginMismatch;
}

pub const Key = struct {
    token: Token,
    attachment_id: AttachmentId,
    origin_node: NodeId,
};

pub const RecordKind = enum(u8) { offer = 1, revoke = 2 };

pub const Record = struct {
    kind: RecordKind,
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
    replay_until_ms: i64,
    account_digest: Digest,
    signer: sign.PublicKey,
    digest: Digest,
    conflicted: bool,
    conflict_wire: ?[]u8,
    token_quarantine_until_ms: ?i64,
    attachment_quarantine_until_ms: ?i64,
    wire: []u8,
};

pub const LeaseRecord = struct {
    revision: Revision,
    issued_at_ms: i64,
    expires_at_ms: i64,
    replay_until_ms: i64,
    signer: sign.PublicKey,
    digest: Digest,
    conflicted: bool,
    conflict_wire: ?[]u8,
    wire: []u8,
};

pub const QuarantineScope = enum(u8) { token = 1, attachment = 2 };

pub const QuarantineKey = struct {
    scope: QuarantineScope,
    token: Token,
    attachment_raw: [@sizeOf(AttachmentId)]u8,
};

pub const Quarantine = struct {
    first_wire: []u8,
    second_wire: []u8,
    replay_until_ms: i64,
};

const hard_max_checkpoint_bytes: usize = 64 * 1024 * 1024;

pub const Config = struct {
    max_records: usize = 4096,
    max_attachment_leases: usize = 8192,
    max_quarantines: usize = 1024,
    max_records_per_account: usize = 64,
    max_records_per_token: usize = 64,
    max_wire_bytes: usize = 64 * 1024 * 1024,
    max_checkpoint_bytes: usize = hard_max_checkpoint_bytes,
    max_record_lifetime_ms: u64 = 7 * 24 * 60 * 60 * 1000,
    max_attachment_lease_lifetime_ms: u64 = 10 * 60 * 1000,
    max_ack_lifetime_ms: u64 = 10 * 60 * 1000,
    max_future_skew_ms: u64 = mesh_clock.default_max_future_skew_ms,
};

/// Stable total-order cursor for bounded anti-entropy. It names one exact
/// signed fact, including an equivocation/quarantine witness with the same
/// attachment revision but a different digest. Cursors own no Store memory and
/// remain safe across hash-table compaction and hot-retry scheduling.
pub const AntiEntropyCursor = struct {
    token: Token,
    attachment_id: AttachmentId,
    revision: Revision,
    kind: AntiEntropyKind,
    digest: Digest,
};

pub const AntiEntropyKind = enum(u8) {
    offer = 1,
    revoke = 2,
    attachment_lease = 3,
};

/// One retained canonical signed wire. `wire` borrows Store ownership and is
/// valid only until the next Store mutation. Relays must copy or synchronously
/// enqueue it before applying another fact or sweeping expiry.
pub const AntiEntropyItem = struct {
    cursor: AntiEntropyCursor,
    wire: []const u8,
};

pub const AntiEntropyPage = struct {
    items: []const AntiEntropyItem,
    /// Last emitted cursor, or the caller's `after` cursor for an empty page.
    next: ?AntiEntropyCursor,
    complete: bool,
};

pub const AntiEntropyPageError = error{
    InvalidCursor,
    InvalidTime,
};

pub const AckBuildError = VerifyError || error{
    AuthorityChanged,
    InvalidAck,
    InvalidDisposition,
};

pub const AckAcceptError = VerifyError || error{
    AckNodeMismatch,
    Expired,
    FutureSkew,
    InvalidAck,
    InvalidLifetime,
    WrongAttachment,
    WrongRevision,
};

pub const ApplyDisposition = enum {
    inserted,
    duplicate,
    conflict,
    conflict_replaced,
    stale,
    superseded,
};

pub const ApplyError = VerifyError || error{
    Capacity,
    Expired,
    FutureSkew,
    InvalidLifetime,
    InvalidOffer,
    InvalidRevoke,
    InvalidAttachmentLease,
} || std.mem.Allocator.Error;

pub const Store = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    records: std.AutoHashMap(Key, Record),
    leases: std.AutoHashMap(Key, LeaseRecord),
    quarantines: std.AutoHashMap(QuarantineKey, Quarantine),
    wire_bytes: usize,

    pub fn init(allocator: std.mem.Allocator, cfg: Config) Store {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .records = std.AutoHashMap(Key, Record).init(allocator),
            .leases = std.AutoHashMap(Key, LeaseRecord).init(allocator),
            .quarantines = std.AutoHashMap(QuarantineKey, Quarantine).init(allocator),
            .wire_bytes = 0,
        };
    }

    pub fn deinit(self: *Store) void {
        var records = self.records.valueIterator();
        while (records.next()) |record| freeRecord(self.allocator, record.*);
        self.records.deinit();
        var leases = self.leases.valueIterator();
        while (leases.next()) |lease| freeLease(self.allocator, lease.*);
        self.leases.deinit();
        var quarantines = self.quarantines.valueIterator();
        while (quarantines.next()) |quarantine| freeQuarantine(self.allocator, quarantine.*);
        self.quarantines.deinit();
        self.* = undefined;
    }

    /// Enumerate every retained authority fact and equivocation/quarantine
    /// witness in a deterministic total order without allocation. Replay state
    /// remains repairable after arbitrary hash insertion order, while a small
    /// caller-owned page bounds each scheduler turn. Expired-but-retained facts
    /// remain included until their replay floor passes, preventing resurrection.
    pub fn antiEntropyPageInto(
        self: *const Store,
        after: ?AntiEntropyCursor,
        now_ms: i64,
        out: []AntiEntropyItem,
    ) AntiEntropyPageError!AntiEntropyPage {
        if (now_ms < 0) return error.InvalidTime;
        if (after) |cursor| if (!validAntiEntropyCursor(cursor)) return error.InvalidCursor;

        var emitted: usize = 0;
        var cursor = after;
        while (emitted < out.len) {
            const candidate = self.nextAntiEntropyItem(cursor, now_ms) orelse break;
            out[emitted] = candidate;
            emitted += 1;
            cursor = candidate.cursor;
        }
        return .{
            .items = out[0..emitted],
            .next = cursor,
            .complete = self.nextAntiEntropyItem(cursor, now_ms) == null,
        };
    }

    fn nextAntiEntropyItem(
        self: *const Store,
        after: ?AntiEntropyCursor,
        now_ms: i64,
    ) ?AntiEntropyItem {
        var best: ?AntiEntropyItem = null;
        var records = @constCast(&self.records).valueIterator();
        while (records.next()) |record| {
            if (record.replay_until_ms < now_ms) continue;
            considerAntiEntropyRecord(&best, after, record.wire);
            if (record.conflict_wire) |wire| considerAntiEntropyRecord(&best, after, wire);
        }
        var leases = @constCast(&self.leases).valueIterator();
        while (leases.next()) |lease| {
            if (lease.replay_until_ms < now_ms) continue;
            considerAntiEntropyLease(&best, after, lease.wire);
            if (lease.conflict_wire) |wire| considerAntiEntropyLease(&best, after, wire);
        }
        var quarantines = @constCast(&self.quarantines).valueIterator();
        while (quarantines.next()) |quarantine| {
            if (quarantine.replay_until_ms < now_ms) continue;
            considerAntiEntropyRecord(&best, after, quarantine.first_wire);
            considerAntiEntropyRecord(&best, after, quarantine.second_wire);
        }
        return best;
    }

    pub fn buildAckForOffer(
        self: *const Store,
        signed: SignedOffer,
        disposition: ApplyDisposition,
        ack_node: NodeId,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) AckBuildError!Ack {
        try verifyOffer(signed);
        return self.buildAckForRecord(
            .{ .offer = signed },
            disposition,
            ack_node,
            issued_at_ms,
            expires_at_ms,
        );
    }

    pub fn buildAckForRevoke(
        self: *const Store,
        signed: SignedRevoke,
        disposition: ApplyDisposition,
        ack_node: NodeId,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) AckBuildError!Ack {
        try verifyRevoke(signed);
        return self.buildAckForRecord(
            .{ .revoke = signed },
            disposition,
            ack_node,
            issued_at_ms,
            expires_at_ms,
        );
    }

    /// Build a retry-preserving capacity receipt after `applySigned*` returned
    /// `error.Capacity`. It intentionally does not claim Store acceptance.
    pub fn buildCapacityAckForOffer(
        self: *const Store,
        signed: SignedOffer,
        ack_node: NodeId,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) AckBuildError!Ack {
        try verifyOffer(signed);
        return self.buildCapacityAck(
            signed.value.token,
            signed.value.attachment_id,
            signed.value.revision,
            ack_node,
            issued_at_ms,
            expires_at_ms,
        );
    }

    pub fn buildCapacityAckForRevoke(
        self: *const Store,
        signed: SignedRevoke,
        ack_node: NodeId,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) AckBuildError!Ack {
        try verifyRevoke(signed);
        return self.buildCapacityAck(
            signed.value.token,
            signed.value.attachment_id,
            signed.value.revision,
            ack_node,
            issued_at_ms,
            expires_at_ms,
        );
    }

    fn buildCapacityAck(
        self: *const Store,
        token: Token,
        attachment_id: AttachmentId,
        revision: Revision,
        ack_node: NodeId,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) AckBuildError!Ack {
        const ack = makeAck(
            .capacity,
            token,
            attachment_id,
            revision,
            revision,
            ack_node,
            issued_at_ms,
            expires_at_ms,
        );
        validateAckWindow(ack, issued_at_ms, self.cfg.max_ack_lifetime_ms, self.cfg.max_future_skew_ms) catch
            return error.InvalidAck;
        return ack;
    }

    fn buildAckForRecord(
        self: *const Store,
        incoming: AnyRecord,
        disposition: ApplyDisposition,
        ack_node: NodeId,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) AckBuildError!Ack {
        const token = incoming.token();
        const attachment_id = incoming.attachmentId();
        const revision = incoming.revision();
        const key = keyFor(token, attachment_id, revision.origin_node);
        const current = self.records.get(key);
        const denied = self.hasFullQuarantine(token, attachment_id, issued_at_ms) or
            self.hasDenyMarker(token, attachment_id, issued_at_ms) or
            (if (current) |record| record.conflicted else false);
        var observed_revision = revision;
        const status: AckStatus = switch (disposition) {
            .conflict, .conflict_replaced => if (denied) .conflict else return error.InvalidDisposition,
            .stale => blk: {
                const record = current orelse return error.AuthorityChanged;
                if (record.revision.compare(revision) != .gt) return error.InvalidDisposition;
                observed_revision = record.revision;
                break :blk .stale;
            },
            .inserted, .duplicate, .superseded => blk: {
                const record = current orelse return error.AuthorityChanged;
                const incoming_kind = std.meta.activeTag(incoming);
                const incoming_wire = switch (incoming) {
                    .offer => |value| value.wire,
                    .revoke => |value| value.wire,
                };
                if (record.revision.compare(revision) != .eq or record.kind != incoming_kind or
                    !std.crypto.timing_safe.eql(Digest, record.digest, digestBytes(incoming_wire)))
                {
                    return error.AuthorityChanged;
                }
                if (denied) break :blk .conflict;
                break :blk switch (disposition) {
                    .inserted => if (incoming_kind == .revoke) .revoked else .accepted,
                    .duplicate => .duplicate,
                    .superseded => .superseded,
                    else => unreachable,
                };
            },
        };
        const ack = makeAck(
            status,
            token,
            attachment_id,
            revision,
            observed_revision,
            ack_node,
            issued_at_ms,
            expires_at_ms,
        );
        validateAckWindow(ack, issued_at_ms, self.cfg.max_ack_lifetime_ms, self.cfg.max_future_skew_ms) catch
            return error.InvalidAck;
        return ack;
    }

    /// Verify a signed receipt against one exact outstanding attachment fact.
    /// The returned status is policy, not a boolean: `capacity` and `conflict`
    /// must keep retry/equivocation work retained rather than retiring it as ACK.
    pub fn validateSignedAckFor(
        self: *const Store,
        signed: SignedAck,
        expected_token: Token,
        expected_attachment_id: AttachmentId,
        expected_revision: Revision,
        expected_ack_node: NodeId,
        now_ms: i64,
    ) AckAcceptError!AckStatus {
        try verifyAck(signed);
        const ack = signed.value;
        if (!identityEql(ack.token, ack.attachment_id, expected_token, expected_attachment_id))
            return error.WrongAttachment;
        if (!ack.offered_revision.eql(expected_revision)) return error.WrongRevision;
        if (ack.ack_node != expected_ack_node) return error.AckNodeMismatch;
        try validateAckWindow(
            ack,
            now_ms,
            self.cfg.max_ack_lifetime_ms,
            self.cfg.max_future_skew_ms,
        );
        const observed_order = ack.observed_revision.compare(ack.offered_revision);
        if ((ack.status == .stale and observed_order != .gt) or
            (ack.status != .stale and observed_order != .eq))
        {
            return error.InvalidAck;
        }
        return ack.status;
    }

    pub fn applySignedOffer(self: *Store, signed: SignedOffer, now_ms: i64) ApplyError!ApplyDisposition {
        try verifyOffer(signed);
        validateOfferShape(signed.value) catch |err| return switch (err) {
            error.TooLong => error.InvalidOffer,
            else => error.InvalidOffer,
        };
        try validateAt(signed.value.revision, signed.value.issued_at_ms, signed.value.expires_at_ms, now_ms, self.cfg.max_record_lifetime_ms, self.cfg.max_future_skew_ms);
        self.sweepExpired(now_ms);
        return self.applyRecord(
            keyFor(signed.value.token, signed.value.attachment_id, signed.value.revision.origin_node),
            .offer,
            signed.value.revision,
            signed.value.issued_at_ms,
            signed.value.expires_at_ms,
            signed.value.account,
            signed.signer,
            signed.wire,
            now_ms,
        );
    }

    pub fn applySignedRevoke(self: *Store, signed: SignedRevoke, now_ms: i64) ApplyError!ApplyDisposition {
        try verifyRevoke(signed);
        validateRevokeShape(signed.value) catch return error.InvalidRevoke;
        try validateAt(signed.value.revision, signed.value.issued_at_ms, signed.value.expires_at_ms, now_ms, self.cfg.max_record_lifetime_ms, self.cfg.max_future_skew_ms);
        self.sweepExpired(now_ms);
        return self.applyRecord(
            keyFor(signed.value.token, signed.value.attachment_id, signed.value.revision.origin_node),
            .revoke,
            signed.value.revision,
            signed.value.issued_at_ms,
            signed.value.expires_at_ms,
            signed.value.account,
            signed.signer,
            signed.wire,
            now_ms,
        );
    }

    fn applyRecord(
        self: *Store,
        key: Key,
        kind: RecordKind,
        revision: Revision,
        issued_at_ms: i64,
        expires_at_ms: i64,
        account: []const u8,
        signer: sign.PublicKey,
        wire: []const u8,
        now_ms: i64,
    ) (error{Capacity} || std.mem.Allocator.Error)!ApplyDisposition {
        const digest = digestBytes(wire);
        const account_digest = accountDigest(account);
        const replay_until_ms = retentionUntil(revision, self.cfg.max_record_lifetime_ms);
        if (self.hasFullQuarantine(key.token, key.attachment_id, now_ms)) {
            try self.updateQuarantine(key.token, key.attachment_id, account_digest, kind, revision, digest, wire, replay_until_ms);
            return .conflict;
        }
        if (self.findIdentityCollision(key.token, key.attachment_id, account_digest, now_ms)) |collision| {
            self.markDenied(collision.scope, key.token, key.attachment_id, @max(collision.replay_until_ms, replay_until_ms));
            try self.installQuarantine(collision.scope, key.token, key.attachment_id, collision.wire, wire, @max(collision.replay_until_ms, replay_until_ms));
            return .conflict;
        }
        if (self.hasDenyMarker(key.token, key.attachment_id, now_ms)) return .conflict;
        if (self.records.getPtr(key)) |current| {
            switch (revision.compare(current.revision)) {
                .lt => return .stale,
                .gt => {
                    const removed_bytes = recordWireBytes(current.*);
                    try self.requireWireReplacement(removed_bytes, wire.len);
                    const owned = try self.allocator.dupe(u8, wire);
                    const old = current.*;
                    current.* = makeRecord(kind, revision, issued_at_ms, expires_at_ms, replay_until_ms, account_digest, signer, digest, false, owned);
                    self.wire_bytes = self.wire_bytes - removed_bytes + wire.len;
                    freeRecord(self.allocator, old);
                    return .superseded;
                },
                .eq => {
                    if (kind == current.kind and std.crypto.timing_safe.eql(Digest, digest, current.digest)) return .duplicate;
                    // Publish denial and the maximum legal replay floor before
                    // any witness allocation can fail.
                    current.conflicted = true;
                    current.replay_until_ms = @max(current.replay_until_ms, replay_until_ms);
                    if (current.conflict_wire) |witness_wire| {
                        if (std.crypto.timing_safe.eql(Digest, digestBytes(witness_wire), digest)) return .duplicate;
                        return .conflict;
                    }
                    try self.requireWireAddition(wire.len);
                    const owned = try self.allocator.dupe(u8, wire);
                    self.wire_bytes += wire.len;
                    const wins = recordCandidateLess(kind, digest, current.kind, current.digest);
                    if (wins) {
                        const old_wire = current.wire;
                        current.wire = owned;
                        current.conflict_wire = old_wire;
                        current.kind = kind;
                        current.issued_at_ms = issued_at_ms;
                        current.expires_at_ms = expires_at_ms;
                        current.account_digest = account_digest;
                        current.signer = signer;
                        current.digest = digest;
                        return .conflict_replaced;
                    }
                    current.conflict_wire = owned;
                    return .conflict;
                },
            }
        }
        if (self.records.count() >= self.cfg.max_records) return error.Capacity;
        if (self.countAccount(account_digest) >= self.cfg.max_records_per_account or
            self.countToken(key.token) >= self.cfg.max_records_per_token) return error.Capacity;
        try self.requireWireAddition(wire.len);
        const owned = try self.allocator.dupe(u8, wire);
        errdefer self.allocator.free(owned);
        try self.records.put(key, makeRecord(kind, revision, issued_at_ms, expires_at_ms, replay_until_ms, account_digest, signer, digest, false, owned));
        self.wire_bytes += wire.len;
        return .inserted;
    }

    pub fn applySignedAttachmentLease(
        self: *Store,
        signed: SignedAttachmentLease,
        now_ms: i64,
    ) ApplyError!ApplyDisposition {
        try verifyAttachmentLease(signed);
        validateLeaseShape(signed.value) catch return error.InvalidAttachmentLease;
        try validateAt(
            signed.value.revision,
            signed.value.issued_at_ms,
            signed.value.expires_at_ms,
            now_ms,
            self.cfg.max_attachment_lease_lifetime_ms,
            self.cfg.max_future_skew_ms,
        );
        self.sweepExpired(now_ms);
        const key = keyFor(signed.value.token, signed.value.attachment_id, signed.value.revision.origin_node);
        if (self.hasFullQuarantine(key.token, key.attachment_id, now_ms) or self.hasDenyMarker(key.token, key.attachment_id, now_ms))
            return error.InvalidAttachmentLease;
        const authority = self.records.getPtr(key) orelse return error.InvalidAttachmentLease;
        if (authority.kind != .offer or authority.conflicted or
            !std.crypto.timing_safe.eql(sign.PublicKey, authority.signer, signed.signer) or
            signed.value.revision.compare(authority.revision) != .gt)
            return error.InvalidAttachmentLease;
        const digest = digestBytes(signed.wire);
        const replay_until_ms = retentionUntil(signed.value.revision, self.cfg.max_attachment_lease_lifetime_ms);
        if (self.leases.getPtr(key)) |current| {
            switch (signed.value.revision.compare(current.revision)) {
                .lt => return .stale,
                .gt => {
                    const removed_bytes = leaseWireBytes(current.*);
                    try self.requireWireReplacement(removed_bytes, signed.wire.len);
                    const owned = try self.allocator.dupe(u8, signed.wire);
                    const old = current.*;
                    current.* = makeLease(signed.value, signed.signer, digest, false, replay_until_ms, owned);
                    self.wire_bytes = self.wire_bytes - removed_bytes + signed.wire.len;
                    freeLease(self.allocator, old);
                    return .superseded;
                },
                .eq => {
                    if (std.crypto.timing_safe.eql(Digest, digest, current.digest)) return .duplicate;
                    current.conflicted = true;
                    current.replay_until_ms = @max(current.replay_until_ms, replay_until_ms);
                    if (current.conflict_wire) |witness_wire| {
                        if (std.crypto.timing_safe.eql(Digest, digestBytes(witness_wire), digest)) return .duplicate;
                        return .conflict;
                    }
                    try self.requireWireAddition(signed.wire.len);
                    const owned = try self.allocator.dupe(u8, signed.wire);
                    self.wire_bytes += signed.wire.len;
                    if (digestLess(digest, current.digest)) {
                        const old_wire = current.wire;
                        current.wire = owned;
                        current.conflict_wire = old_wire;
                        current.revision = signed.value.revision;
                        current.issued_at_ms = signed.value.issued_at_ms;
                        current.expires_at_ms = signed.value.expires_at_ms;
                        current.signer = signed.signer;
                        current.digest = digest;
                        return .conflict_replaced;
                    }
                    current.conflict_wire = owned;
                    return .conflict;
                },
            }
        }
        if (self.leases.count() >= self.cfg.max_attachment_leases) return error.Capacity;
        try self.requireWireAddition(signed.wire.len);
        const owned = try self.allocator.dupe(u8, signed.wire);
        errdefer self.allocator.free(owned);
        try self.leases.put(key, makeLease(signed.value, signed.signer, digest, false, replay_until_ms, owned));
        self.wire_bytes += signed.wire.len;
        return .inserted;
    }

    pub fn getLive(
        self: *const Store,
        token: Token,
        attachment_id: AttachmentId,
        origin_node: NodeId,
        now_ms: i64,
    ) ?*const Record {
        if (self.hasFullQuarantine(token, attachment_id, now_ms) or self.hasDenyMarker(token, attachment_id, now_ms)) return null;
        var it = @constCast(&self.records).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node != origin_node or
                !tokenEql(slot.key_ptr.token, token) or
                !slot.key_ptr.attachment_id.eql(attachment_id)) continue;
            const record = slot.value_ptr;
            if (record.kind != .offer or record.conflicted or now_ms > record.expires_at_ms) return null;
            return record;
        }
        return null;
    }

    pub fn getLiveAttachmentLease(
        self: *const Store,
        token: Token,
        attachment_id: AttachmentId,
        origin_node: NodeId,
        now_ms: i64,
    ) ?*const LeaseRecord {
        const live = self.getLive(token, attachment_id, origin_node, now_ms) orelse return null;
        var it = @constCast(&self.leases).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node != origin_node or
                !tokenEql(slot.key_ptr.token, token) or
                !slot.key_ptr.attachment_id.eql(attachment_id)) continue;
            const lease = slot.value_ptr;
            if (lease.conflicted or now_ms > lease.expires_at_ms or
                lease.revision.compare(live.revision) != .gt or
                !std.crypto.timing_safe.eql(sign.PublicKey, lease.signer, live.signer)) return null;
            return lease;
        }
        return null;
    }

    /// Remove expired attachment authority independently. Iterator restart is
    /// deliberate because `removeByPtr` may compact the hash map.
    pub fn sweepExpired(self: *Store, now_ms: i64) void {
        while (true) {
            var removed = false;
            var it = self.records.iterator();
            while (it.next()) |slot| {
                if (now_ms <= slot.value_ptr.replay_until_ms) continue;
                const removed_record = self.records.fetchRemove(slot.key_ptr.*).?;
                self.wire_bytes -= recordWireBytes(removed_record.value);
                freeRecord(self.allocator, removed_record.value);
                removed = true;
                break;
            }
            if (!removed) break;
        }
        while (true) {
            var removed = false;
            var it = self.leases.iterator();
            while (it.next()) |slot| {
                if (now_ms <= slot.value_ptr.replay_until_ms) continue;
                const removed_lease = self.leases.fetchRemove(slot.key_ptr.*).?;
                self.wire_bytes -= leaseWireBytes(removed_lease.value);
                freeLease(self.allocator, removed_lease.value);
                removed = true;
                break;
            }
            if (!removed) break;
        }
        while (true) {
            var victim: ?QuarantineKey = null;
            var it = self.quarantines.iterator();
            while (it.next()) |slot| {
                if (now_ms > slot.value_ptr.replay_until_ms) {
                    victim = slot.key_ptr.*;
                    break;
                }
            }
            const key = victim orelse break;
            const removed = self.quarantines.fetchRemove(key).?;
            self.wire_bytes -= quarantineWireBytes(removed.value);
            freeQuarantine(self.allocator, removed.value);
        }
        var records = self.records.valueIterator();
        while (records.next()) |record| {
            if (record.token_quarantine_until_ms) |until| {
                if (now_ms > until) record.token_quarantine_until_ms = null;
            }
            if (record.attachment_quarantine_until_ms) |until| {
                if (now_ms > until) record.attachment_quarantine_until_ms = null;
            }
        }
    }

    /// Used by create-new admission: a physical id is unavailable while any
    /// authenticated authority or collision quarantine still retains it.
    pub fn isAttachmentIdRetained(self: *const Store, attachment_id: AttachmentId, now_ms: i64) bool {
        var records = @constCast(&self.records).iterator();
        while (records.next()) |slot| {
            if (slot.key_ptr.attachment_id.eql(attachment_id) and now_ms <= slot.value_ptr.replay_until_ms) return true;
        }
        var quarantines = @constCast(&self.quarantines).iterator();
        while (quarantines.next()) |slot| {
            if (now_ms > slot.value_ptr.replay_until_ms) continue;
            if (slot.key_ptr.scope == .attachment and
                std.crypto.timing_safe.eql([@sizeOf(AttachmentId)]u8, slot.key_ptr.attachment_raw, attachment_id.raw)) return true;
            const first = decodeAnyRecord(slot.value_ptr.first_wire) catch unreachable;
            const second = decodeAnyRecord(slot.value_ptr.second_wire) catch unreachable;
            if (first.attachmentId().eql(attachment_id) or second.attachmentId().eql(attachment_id)) return true;
        }
        return false;
    }

    /// Exact restore/SRM2 authority match. Display casing is deliberately not
    /// part of identity; the canonical digest ASCII-folds the bounded account.
    pub fn matchesRetainedAuthority(
        self: *const Store,
        token: Token,
        attachment_id: AttachmentId,
        account: []const u8,
        now_ms: i64,
    ) bool {
        if (!validAccount(account) or self.hasFullQuarantine(token, attachment_id, now_ms) or self.hasDenyMarker(token, attachment_id, now_ms)) return false;
        const wanted = accountDigest(account);
        var records = @constCast(&self.records).iterator();
        while (records.next()) |slot| {
            if (!tokenEql(slot.key_ptr.token, token) or !slot.key_ptr.attachment_id.eql(attachment_id) or
                now_ms > slot.value_ptr.replay_until_ms or slot.value_ptr.conflicted) continue;
            return std.crypto.timing_safe.eql(Digest, wanted, slot.value_ptr.account_digest);
        }
        return false;
    }

    const Collision = struct {
        scope: QuarantineScope,
        wire: []const u8,
        replay_until_ms: i64,
    };

    fn findIdentityCollision(
        self: *const Store,
        token: Token,
        attachment_id: AttachmentId,
        account_digest: Digest,
        now_ms: i64,
    ) ?Collision {
        var records = @constCast(&self.records).iterator();
        while (records.next()) |slot| {
            const record = slot.value_ptr;
            if (now_ms > record.replay_until_ms) continue;
            const same_token = tokenEql(slot.key_ptr.token, token);
            const same_attachment = slot.key_ptr.attachment_id.eql(attachment_id);
            const same_account = std.crypto.timing_safe.eql(Digest, record.account_digest, account_digest);
            if (same_token and !same_account) return .{ .scope = .token, .wire = record.wire, .replay_until_ms = record.replay_until_ms };
            if (same_attachment and (!same_token or !same_account)) return .{ .scope = .attachment, .wire = record.wire, .replay_until_ms = record.replay_until_ms };
        }
        return null;
    }

    fn hasFullQuarantine(self: *const Store, token: Token, attachment_id: AttachmentId, now_ms: i64) bool {
        var it = @constCast(&self.quarantines).iterator();
        while (it.next()) |slot| {
            if (now_ms > slot.value_ptr.replay_until_ms) continue;
            switch (slot.key_ptr.scope) {
                .token => if (tokenEql(slot.key_ptr.token, token)) return true,
                .attachment => if (std.crypto.timing_safe.eql([@sizeOf(AttachmentId)]u8, slot.key_ptr.attachment_raw, attachment_id.raw)) return true,
            }
        }
        return false;
    }

    fn updateQuarantine(
        self: *Store,
        token: Token,
        attachment_id: AttachmentId,
        incoming_account: Digest,
        incoming_kind: RecordKind,
        incoming_revision: Revision,
        incoming_digest: Digest,
        incoming_wire: []const u8,
        incoming_replay_until_ms: i64,
    ) (error{Capacity} || std.mem.Allocator.Error)!void {
        var it = self.quarantines.iterator();
        while (it.next()) |slot| {
            const matches_scope = switch (slot.key_ptr.scope) {
                .token => tokenEql(slot.key_ptr.token, token),
                .attachment => std.crypto.timing_safe.eql([@sizeOf(AttachmentId)]u8, slot.key_ptr.attachment_raw, attachment_id.raw),
            };
            if (!matches_scope) continue;
            const first = decodeAnyRecord(slot.value_ptr.first_wire) catch unreachable;
            const second = decodeAnyRecord(slot.value_ptr.second_wire) catch unreachable;
            const incoming_identity = quarantineIdentityDigest(slot.key_ptr.scope, token, incoming_account);
            const first_identity = quarantineRecordIdentityDigest(slot.key_ptr.scope, first);
            const second_identity = quarantineRecordIdentityDigest(slot.key_ptr.scope, second);
            const first_matches = std.crypto.timing_safe.eql(Digest, first_identity, incoming_identity);
            const second_matches = std.crypto.timing_safe.eql(Digest, second_identity, incoming_identity);
            var replace_first = first_matches and recordSupersedes(incoming_kind, incoming_revision, incoming_digest, first);
            var replace_second = second_matches and recordSupersedes(incoming_kind, incoming_revision, incoming_digest, second);
            // More than two hostile identities cannot grow retained state. The
            // two lexicographically smallest identity classes, each at its
            // deterministic highest fact, form the convergent bounded proof.
            if (!first_matches and !second_matches) {
                if (digestLess(first_identity, second_identity)) {
                    replace_second = digestLess(incoming_identity, second_identity);
                } else {
                    replace_first = digestLess(incoming_identity, first_identity);
                }
            }
            slot.value_ptr.replay_until_ms = @max(slot.value_ptr.replay_until_ms, incoming_replay_until_ms);
            if (!replace_first and !replace_second) return;
            const old_wire = if (replace_first) slot.value_ptr.first_wire else slot.value_ptr.second_wire;
            try self.requireWireReplacement(old_wire.len, incoming_wire.len);
            const owned = try self.allocator.dupe(u8, incoming_wire);
            if (replace_first) slot.value_ptr.first_wire = owned else slot.value_ptr.second_wire = owned;
            self.wire_bytes = self.wire_bytes - old_wire.len + incoming_wire.len;
            self.allocator.free(old_wire);
            if (digestLess(digestBytes(slot.value_ptr.second_wire), digestBytes(slot.value_ptr.first_wire))) {
                const swap = slot.value_ptr.first_wire;
                slot.value_ptr.first_wire = slot.value_ptr.second_wire;
                slot.value_ptr.second_wire = swap;
            }
            return;
        }
    }

    fn hasDenyMarker(self: *const Store, token: Token, attachment_id: AttachmentId, now_ms: i64) bool {
        var it = @constCast(&self.records).iterator();
        while (it.next()) |slot| {
            if (slot.value_ptr.token_quarantine_until_ms) |until| {
                if (now_ms <= until and tokenEql(slot.key_ptr.token, token)) return true;
            }
            if (slot.value_ptr.attachment_quarantine_until_ms) |until| {
                if (now_ms <= until and slot.key_ptr.attachment_id.eql(attachment_id)) return true;
            }
        }
        return false;
    }

    fn markDenied(self: *Store, scope: QuarantineScope, token: Token, attachment_id: AttachmentId, until_ms: i64) void {
        var records = self.records.iterator();
        while (records.next()) |slot| {
            switch (scope) {
                .token => if (tokenEql(slot.key_ptr.token, token)) {
                    slot.value_ptr.token_quarantine_until_ms = maxOptional(slot.value_ptr.token_quarantine_until_ms, until_ms);
                },
                .attachment => if (slot.key_ptr.attachment_id.eql(attachment_id)) {
                    slot.value_ptr.attachment_quarantine_until_ms = maxOptional(slot.value_ptr.attachment_quarantine_until_ms, until_ms);
                },
            }
        }
    }

    fn installQuarantine(
        self: *Store,
        scope: QuarantineScope,
        token: Token,
        attachment_id: AttachmentId,
        existing_wire: []const u8,
        incoming_wire: []const u8,
        replay_until_ms: i64,
    ) (error{Capacity} || std.mem.Allocator.Error)!void {
        const key = quarantineKey(scope, token, attachment_id);
        if (self.quarantines.contains(key)) return;
        if (self.quarantines.count() >= self.cfg.max_quarantines) return error.Capacity;
        const removed_bytes = self.scopeWireBytes(scope, token, attachment_id);
        const added = std.math.add(usize, existing_wire.len, incoming_wire.len) catch return error.Capacity;
        try self.requireWireReplacement(removed_bytes, added);
        try self.quarantines.ensureUnusedCapacity(1);
        const existing_copy = try self.allocator.dupe(u8, existing_wire);
        errdefer self.allocator.free(existing_copy);
        const incoming_copy = try self.allocator.dupe(u8, incoming_wire);
        errdefer self.allocator.free(incoming_copy);
        const existing_digest = digestBytes(existing_wire);
        const incoming_digest = digestBytes(incoming_wire);
        const existing_first = digestLess(existing_digest, incoming_digest);
        self.removeScopeState(scope, token, attachment_id);
        self.quarantines.putAssumeCapacityNoClobber(key, .{
            .first_wire = if (existing_first) existing_copy else incoming_copy,
            .second_wire = if (existing_first) incoming_copy else existing_copy,
            .replay_until_ms = replay_until_ms,
        });
        self.wire_bytes += added;
    }

    fn restoreQuarantine(
        self: *Store,
        scope: QuarantineScope,
        first_wire: []const u8,
        second_wire: []const u8,
        now_ms: i64,
    ) CheckpointError!QuarantineKey {
        const first = decodeAnyRecord(first_wire) catch return error.InvalidCheckpoint;
        const second = decodeAnyRecord(second_wire) catch return error.InvalidCheckpoint;
        try verifyAnyRecord(first);
        try verifyAnyRecord(second);
        if (!digestLess(digestBytes(first_wire), digestBytes(second_wire))) return error.NonCanonical;
        const first_account = accountDigest(first.account());
        const second_account = accountDigest(second.account());
        const key = switch (scope) {
            .token => blk: {
                if (!tokenEql(first.token(), second.token()) or std.crypto.timing_safe.eql(Digest, first_account, second_account))
                    return error.InvalidCheckpoint;
                break :blk quarantineKey(.token, first.token(), first.attachmentId());
            },
            .attachment => blk: {
                if (!first.attachmentId().eql(second.attachmentId()) or
                    (tokenEql(first.token(), second.token()) and std.crypto.timing_safe.eql(Digest, first_account, second_account)))
                    return error.InvalidCheckpoint;
                break :blk quarantineKey(.attachment, first.token(), first.attachmentId());
            },
        };
        const replay_until_ms = @max(
            try validateRetainedRecord(first, now_ms, self.cfg),
            try validateRetainedRecord(second, now_ms, self.cfg),
        );
        try self.installQuarantine(scope, first.token(), first.attachmentId(), first_wire, second_wire, replay_until_ms);
        return key;
    }

    fn scopeWireBytes(self: *const Store, scope: QuarantineScope, token: Token, attachment_id: AttachmentId) usize {
        var total: usize = 0;
        var records = @constCast(&self.records).iterator();
        while (records.next()) |slot| {
            if (scopeMatches(scope, token, attachment_id, slot.key_ptr.*)) total += recordWireBytes(slot.value_ptr.*);
        }
        var leases = @constCast(&self.leases).iterator();
        while (leases.next()) |slot| {
            if (scopeMatches(scope, token, attachment_id, slot.key_ptr.*)) total += leaseWireBytes(slot.value_ptr.*);
        }
        return total;
    }

    fn removeScopeState(self: *Store, scope: QuarantineScope, token: Token, attachment_id: AttachmentId) void {
        while (true) {
            var victim: ?Key = null;
            var it = self.records.keyIterator();
            while (it.next()) |key| if (scopeMatches(scope, token, attachment_id, key.*)) {
                victim = key.*;
                break;
            };
            const key = victim orelse break;
            const removed = self.records.fetchRemove(key).?;
            self.wire_bytes -= recordWireBytes(removed.value);
            freeRecord(self.allocator, removed.value);
        }
        while (true) {
            var victim: ?Key = null;
            var it = self.leases.keyIterator();
            while (it.next()) |key| if (scopeMatches(scope, token, attachment_id, key.*)) {
                victim = key.*;
                break;
            };
            const key = victim orelse break;
            const removed = self.leases.fetchRemove(key).?;
            self.wire_bytes -= leaseWireBytes(removed.value);
            freeLease(self.allocator, removed.value);
        }
    }

    fn countAccount(self: *const Store, account_digest: Digest) usize {
        var count: usize = 0;
        var it = @constCast(&self.records).valueIterator();
        while (it.next()) |record| if (std.crypto.timing_safe.eql(Digest, record.account_digest, account_digest)) {
            count += 1;
        };
        return count;
    }

    fn countToken(self: *const Store, token: Token) usize {
        var count: usize = 0;
        var it = @constCast(&self.records).keyIterator();
        while (it.next()) |key| if (tokenEql(key.token, token)) {
            count += 1;
        };
        return count;
    }

    fn requireWireAddition(self: *const Store, added: usize) error{Capacity}!void {
        if (added > self.cfg.max_wire_bytes -| self.wire_bytes) return error.Capacity;
    }

    fn requireWireReplacement(self: *const Store, removed: usize, added: usize) error{Capacity}!void {
        const base = self.wire_bytes - removed;
        if (added > self.cfg.max_wire_bytes -| base) return error.Capacity;
    }

    pub fn encodeCheckpoint(self: *const Store, allocator: std.mem.Allocator, captured_at_ms: i64) CheckpointError![]u8 {
        if (captured_at_ms < 0) return error.InvalidCheckpoint;
        const record_storage = try allocator.alloc(RecordView, self.records.count());
        defer allocator.free(record_storage);
        var record_count: usize = 0;
        var records = @constCast(&self.records).iterator();
        while (records.next()) |slot| {
            if (slot.value_ptr.replay_until_ms < captured_at_ms) continue;
            if ((slot.value_ptr.conflicted and slot.value_ptr.conflict_wire == null) or
                slot.value_ptr.token_quarantine_until_ms != null or slot.value_ptr.attachment_quarantine_until_ms != null)
                return error.InvalidCheckpoint;
            record_storage[record_count] = .{ .key = slot.key_ptr.*, .record = slot.value_ptr };
            record_count += 1;
        }
        const record_views = record_storage[0..record_count];
        std.mem.sort(RecordView, record_views, {}, RecordView.less);

        const lease_storage = try allocator.alloc(LeaseView, self.leases.count());
        defer allocator.free(lease_storage);
        var lease_count: usize = 0;
        var leases = @constCast(&self.leases).iterator();
        while (leases.next()) |slot| {
            if (slot.value_ptr.replay_until_ms < captured_at_ms) continue;
            if (slot.value_ptr.conflicted and slot.value_ptr.conflict_wire == null) return error.InvalidCheckpoint;
            lease_storage[lease_count] = .{ .key = slot.key_ptr.*, .lease = slot.value_ptr };
            lease_count += 1;
        }
        const lease_views = lease_storage[0..lease_count];
        std.mem.sort(LeaseView, lease_views, {}, LeaseView.less);
        const quarantine_storage = try allocator.alloc(QuarantineView, self.quarantines.count());
        defer allocator.free(quarantine_storage);
        var quarantine_count: usize = 0;
        var quarantines = @constCast(&self.quarantines).iterator();
        while (quarantines.next()) |slot| {
            if (slot.value_ptr.replay_until_ms < captured_at_ms) continue;
            quarantine_storage[quarantine_count] = .{ .key = slot.key_ptr.*, .quarantine = slot.value_ptr };
            quarantine_count += 1;
        }
        const quarantine_views = quarantine_storage[0..quarantine_count];
        std.mem.sort(QuarantineView, quarantine_views, {}, QuarantineView.less);
        if (record_count > std.math.maxInt(u32) or lease_count > std.math.maxInt(u32) or
            quarantine_count > std.math.maxInt(u32)) return error.TooLarge;

        var len: usize = checkpoint_header_len + checkpoint_checksum_len;
        for (record_views) |view| {
            try addLen(&len, 1 + 4 + view.record.wire.len + 4);
            if (view.record.conflict_wire) |wire| try addLen(&len, wire.len);
        }
        for (lease_views) |view| {
            try addLen(&len, 4 + view.lease.wire.len + 4);
            if (view.lease.conflict_wire) |wire| try addLen(&len, wire.len);
        }
        for (quarantine_views) |view| try addLen(&len, 1 + 4 + view.quarantine.first_wire.len + 4 + view.quarantine.second_wire.len);
        if (len > @min(self.cfg.max_checkpoint_bytes, hard_max_checkpoint_bytes)) return error.TooLarge;
        var out = try allocator.alloc(u8, len);
        errdefer allocator.free(out);
        var writer = Writer{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeI64(captured_at_ms);
        writer.writeU32(@intCast(record_count));
        writer.writeU32(@intCast(lease_count));
        writer.writeU32(@intCast(quarantine_count));
        for (record_views) |view| {
            writer.writeByte(@backingInt(view.record.kind));
            writer.writeU32(@intCast(view.record.wire.len));
            writer.writeBytes(view.record.wire);
            const witness = view.record.conflict_wire orelse &.{};
            writer.writeU32(@intCast(witness.len));
            writer.writeBytes(witness);
        }
        for (lease_views) |view| {
            writer.writeU32(@intCast(view.lease.wire.len));
            writer.writeBytes(view.lease.wire);
            const witness = view.lease.conflict_wire orelse &.{};
            writer.writeU32(@intCast(witness.len));
            writer.writeBytes(witness);
        }
        for (quarantine_views) |view| {
            writer.writeByte(@backingInt(view.key.scope));
            writer.writeU32(@intCast(view.quarantine.first_wire.len));
            writer.writeBytes(view.quarantine.first_wire);
            writer.writeU32(@intCast(view.quarantine.second_wire.len));
            writer.writeBytes(view.quarantine.second_wire);
        }
        const checksum = digestDomain(checkpoint_digest_domain, out[0..writer.pos]);
        writer.writeBytes(&checksum);
        std.debug.assert(writer.pos == out.len);
        return out;
    }

    /// Decode into independent storage first. Callers may swap only after this
    /// returns, so allocation failure or malformed current state cannot mutate
    /// the live store.
    pub fn decodeCheckpoint(
        allocator: std.mem.Allocator,
        cfg: Config,
        bytes: []const u8,
        now_ms: i64,
    ) CheckpointError!Store {
        if (bytes.len > @min(cfg.max_checkpoint_bytes, hard_max_checkpoint_bytes)) return error.TooLarge;
        if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
        const body = bytes[0 .. bytes.len - checkpoint_checksum_len];
        const expected: Digest = bytes[body.len..][0..checkpoint_checksum_len].*;
        const actual = digestDomain(checkpoint_digest_domain, body);
        if (!std.crypto.timing_safe.eql(Digest, expected, actual)) return error.BadChecksum;
        var reader = CheckpointReader{ .bytes = body };
        if (!std.mem.eql(u8, try reader.take(checkpoint_magic.len), &checkpoint_magic)) return error.BadMagic;
        if (try reader.readByte() != checkpoint_version) return error.BadVersion;
        const captured_at_ms = try reader.readI64();
        if (captured_at_ms < 0 or now_ms < 0) return error.InvalidCheckpoint;
        if (@as(i128, captured_at_ms) > @as(i128, now_ms) + @as(i128, cfg.max_future_skew_ms)) return error.FutureSkew;
        const record_count: usize = try reader.readU32();
        const lease_count: usize = try reader.readU32();
        const quarantine_count: usize = try reader.readU32();
        if (record_count > cfg.max_records or lease_count > cfg.max_attachment_leases or quarantine_count > cfg.max_quarantines) return error.Capacity;

        var restored = Store.init(allocator, cfg);
        errdefer restored.deinit();
        var previous_record: ?Key = null;
        for (0..record_count) |_| {
            const kind: RecordKind = switch (try reader.readByte()) {
                1 => .offer,
                2 => .revoke,
                else => return error.InvalidCheckpoint,
            };
            const wire = try reader.readWire();
            const conflict_wire = try reader.readOptionalWire();
            const key = switch (kind) {
                .offer => blk: {
                    const signed = decodeOffer(wire) catch return error.InvalidCheckpoint;
                    verifyOffer(signed) catch return error.InvalidCheckpoint;
                    try validateAt(signed.value.revision, signed.value.issued_at_ms, signed.value.expires_at_ms, now_ms, cfg.max_record_lifetime_ms, cfg.max_future_skew_ms);
                    const disposition = try restored.applySignedOffer(signed, now_ms);
                    if (disposition != .inserted) return error.InvalidCheckpoint;
                    break :blk keyFor(signed.value.token, signed.value.attachment_id, signed.value.revision.origin_node);
                },
                .revoke => blk: {
                    const signed = decodeRevoke(wire) catch return error.InvalidCheckpoint;
                    verifyRevoke(signed) catch return error.InvalidCheckpoint;
                    try validateAt(signed.value.revision, signed.value.issued_at_ms, signed.value.expires_at_ms, now_ms, cfg.max_record_lifetime_ms, cfg.max_future_skew_ms);
                    const disposition = try restored.applySignedRevoke(signed, now_ms);
                    if (disposition != .inserted) return error.InvalidCheckpoint;
                    break :blk keyFor(signed.value.token, signed.value.attachment_id, signed.value.revision.origin_node);
                },
            };
            if (previous_record) |previous| if (!keyLess(previous, key)) return error.NonCanonical;
            previous_record = key;
            if (conflict_wire) |witness| {
                const witness_record = decodeAnyRecord(witness) catch return error.InvalidCheckpoint;
                const disposition = switch (witness_record) {
                    .offer => |signed| try restored.applySignedOffer(signed, now_ms),
                    .revoke => |signed| try restored.applySignedRevoke(signed, now_ms),
                };
                if (disposition == .conflict_replaced) return error.NonCanonical;
                if (disposition != .conflict) return error.InvalidCheckpoint;
            }
        }
        var previous_lease: ?Key = null;
        for (0..lease_count) |_| {
            const wire = try reader.readWire();
            const conflict_wire = try reader.readOptionalWire();
            const signed = decodeAttachmentLease(wire) catch return error.InvalidCheckpoint;
            verifyAttachmentLease(signed) catch return error.InvalidCheckpoint;
            try validateAt(signed.value.revision, signed.value.issued_at_ms, signed.value.expires_at_ms, now_ms, cfg.max_attachment_lease_lifetime_ms, cfg.max_future_skew_ms);
            const key = keyFor(signed.value.token, signed.value.attachment_id, signed.value.revision.origin_node);
            if (previous_lease) |previous| if (!keyLess(previous, key)) return error.NonCanonical;
            previous_lease = key;
            const disposition = try restored.applySignedAttachmentLease(signed, now_ms);
            if (disposition != .inserted) return error.InvalidCheckpoint;
            if (conflict_wire) |witness| {
                const witness_signed = decodeAttachmentLease(witness) catch return error.InvalidCheckpoint;
                const witness_disposition = try restored.applySignedAttachmentLease(witness_signed, now_ms);
                if (witness_disposition == .conflict_replaced) return error.NonCanonical;
                if (witness_disposition != .conflict) return error.InvalidCheckpoint;
            }
        }
        var previous_quarantine: ?QuarantineKey = null;
        for (0..quarantine_count) |_| {
            const scope: QuarantineScope = switch (try reader.readByte()) {
                1 => .token,
                2 => .attachment,
                else => return error.InvalidCheckpoint,
            };
            const first_wire = try reader.readWire();
            const second_wire = try reader.readWire();
            const key = try restored.restoreQuarantine(scope, first_wire, second_wire, now_ms);
            if (previous_quarantine) |previous| if (!quarantineKeyLess(previous, key)) return error.NonCanonical;
            previous_quarantine = key;
        }
        if (reader.pos != body.len) return error.TrailingBytes;
        return restored;
    }

    pub fn replaceFromCheckpoint(self: *Store, bytes: []const u8, now_ms: i64) CheckpointError!void {
        var replacement = try decodeCheckpoint(self.allocator, self.cfg, bytes, now_ms);
        errdefer replacement.deinit();
        try self.rejectRollback(&replacement, now_ms);
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
    }

    /// Current live authority is a high-water mark. A checkpoint may add a
    /// higher revision or more conflict knowledge, but it may not omit or
    /// regress a still-live record/lease already observed by this store.
    fn rejectRollback(self: *const Store, incoming: *const Store, now_ms: i64) CheckpointError!void {
        var records = @constCast(&self.records).iterator();
        while (records.next()) |slot| {
            const current = slot.value_ptr;
            if (current.replay_until_ms < now_ms) continue;
            const candidate = incoming.records.get(slot.key_ptr.*) orelse return error.Rollback;
            switch (candidate.revision.compare(current.revision)) {
                .lt => return error.Rollback,
                .gt => {},
                .eq => {
                    if (candidate.kind != current.kind or
                        !std.crypto.timing_safe.eql(Digest, candidate.digest, current.digest) or
                        (current.conflicted and !candidate.conflicted) or
                        candidate.replay_until_ms < current.replay_until_ms) return error.Rollback;
                },
            }
        }
        var leases = @constCast(&self.leases).iterator();
        while (leases.next()) |slot| {
            const current = slot.value_ptr;
            if (current.replay_until_ms < now_ms) continue;
            const candidate = incoming.leases.get(slot.key_ptr.*) orelse return error.Rollback;
            switch (candidate.revision.compare(current.revision)) {
                .lt => return error.Rollback,
                .gt => {},
                .eq => {
                    if (!std.crypto.timing_safe.eql(Digest, candidate.digest, current.digest) or
                        (current.conflicted and !candidate.conflicted) or
                        candidate.replay_until_ms < current.replay_until_ms) return error.Rollback;
                },
            }
        }
        var quarantines = @constCast(&self.quarantines).iterator();
        while (quarantines.next()) |slot| {
            if (slot.value_ptr.replay_until_ms < now_ms) continue;
            const candidate = incoming.quarantines.get(slot.key_ptr.*) orelse return error.Rollback;
            if (candidate.replay_until_ms < slot.value_ptr.replay_until_ms or
                !std.mem.eql(u8, candidate.first_wire, slot.value_ptr.first_wire) or
                !std.mem.eql(u8, candidate.second_wire, slot.value_ptr.second_wire)) return error.Rollback;
        }
    }
};

pub const CheckpointError = error{
    BadMagic,
    BadVersion,
    BadChecksum,
    Capacity,
    InvalidCheckpoint,
    InvalidOffer,
    InvalidRevoke,
    InvalidAttachmentLease,
    NonCanonical,
    Rollback,
    TooLarge,
    TrailingBytes,
    Truncated,
    Expired,
    FutureSkew,
    InvalidLifetime,
} || VerifyError || std.mem.Allocator.Error;

const RecordView = struct {
    key: Key,
    record: *const Record,
    fn less(_: void, a: RecordView, b: RecordView) bool {
        return keyLess(a.key, b.key);
    }
};

const LeaseView = struct {
    key: Key,
    lease: *const LeaseRecord,
    fn less(_: void, a: LeaseView, b: LeaseView) bool {
        return keyLess(a.key, b.key);
    }
};

const QuarantineView = struct {
    key: QuarantineKey,
    quarantine: *const Quarantine,
    fn less(_: void, a: QuarantineView, b: QuarantineView) bool {
        return quarantineKeyLess(a.key, b.key);
    }
};

fn makeRecord(
    kind: RecordKind,
    revision: Revision,
    issued: i64,
    expires: i64,
    replay_until_ms: i64,
    account_digest: Digest,
    signer: sign.PublicKey,
    digest: Digest,
    conflicted: bool,
    wire: []u8,
) Record {
    return .{
        .kind = kind,
        .revision = revision,
        .issued_at_ms = issued,
        .expires_at_ms = expires,
        .replay_until_ms = replay_until_ms,
        .account_digest = account_digest,
        .signer = signer,
        .digest = digest,
        .conflicted = conflicted,
        .conflict_wire = null,
        .token_quarantine_until_ms = null,
        .attachment_quarantine_until_ms = null,
        .wire = wire,
    };
}

fn makeLease(value: AttachmentLease, signer: sign.PublicKey, digest: Digest, conflicted: bool, replay_until_ms: i64, wire: []u8) LeaseRecord {
    return .{
        .revision = value.revision,
        .issued_at_ms = value.issued_at_ms,
        .expires_at_ms = value.expires_at_ms,
        .replay_until_ms = replay_until_ms,
        .signer = signer,
        .digest = digest,
        .conflicted = conflicted,
        .conflict_wire = null,
        .wire = wire,
    };
}

fn freeRecord(allocator: std.mem.Allocator, record: Record) void {
    allocator.free(record.wire);
    if (record.conflict_wire) |wire| allocator.free(wire);
}

fn freeLease(allocator: std.mem.Allocator, lease: LeaseRecord) void {
    allocator.free(lease.wire);
    if (lease.conflict_wire) |wire| allocator.free(wire);
}

fn freeQuarantine(allocator: std.mem.Allocator, quarantine: Quarantine) void {
    allocator.free(quarantine.first_wire);
    allocator.free(quarantine.second_wire);
}

fn recordWireBytes(record: Record) usize {
    return record.wire.len + if (record.conflict_wire) |wire| wire.len else 0;
}

fn leaseWireBytes(lease: LeaseRecord) usize {
    return lease.wire.len + if (lease.conflict_wire) |wire| wire.len else 0;
}

fn quarantineWireBytes(quarantine: Quarantine) usize {
    return quarantine.first_wire.len + quarantine.second_wire.len;
}

fn keyFor(token: Token, attachment_id: AttachmentId, origin_node: NodeId) Key {
    return .{ .token = token, .attachment_id = attachment_id, .origin_node = origin_node };
}

fn keyLess(a: Key, b: Key) bool {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order == .lt;
    const attachment_order = std.mem.order(u8, &a.attachment_id.raw, &b.attachment_id.raw);
    if (attachment_order != .eq) return attachment_order == .lt;
    return a.origin_node < b.origin_node;
}

fn quarantineKey(scope: QuarantineScope, token: Token, attachment_id: AttachmentId) QuarantineKey {
    return switch (scope) {
        .token => .{ .scope = .token, .token = token, .attachment_raw = @splat(0) },
        .attachment => .{ .scope = .attachment, .token = @splat(0), .attachment_raw = attachment_id.raw },
    };
}

fn quarantineKeyLess(a: QuarantineKey, b: QuarantineKey) bool {
    if (a.scope != b.scope) return @backingInt(a.scope) < @backingInt(b.scope);
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order == .lt;
    return std.mem.order(u8, &a.attachment_raw, &b.attachment_raw) == .lt;
}

fn scopeMatches(scope: QuarantineScope, token: Token, attachment_id: AttachmentId, key: Key) bool {
    return switch (scope) {
        .token => tokenEql(key.token, token),
        .attachment => key.attachment_id.eql(attachment_id),
    };
}

fn maxOptional(current: ?i64, candidate: i64) i64 {
    return if (current) |value| @max(value, candidate) else candidate;
}

fn recordCandidateLess(a_kind: RecordKind, a_digest: Digest, b_kind: RecordKind, b_digest: Digest) bool {
    // A revoke wins a cross-kind equivocation, failing the exact attachment
    // closed without affecting sibling attachment keys.
    if (a_kind != b_kind) return a_kind == .revoke;
    return digestLess(a_digest, b_digest);
}

fn digestLess(a: Digest, b: Digest) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

const AnyRecord = union(RecordKind) {
    offer: SignedOffer,
    revoke: SignedRevoke,

    fn token(self: AnyRecord) Token {
        return switch (self) {
            .offer => |signed| signed.value.token,
            .revoke => |signed| signed.value.token,
        };
    }
    fn attachmentId(self: AnyRecord) AttachmentId {
        return switch (self) {
            .offer => |signed| signed.value.attachment_id,
            .revoke => |signed| signed.value.attachment_id,
        };
    }
    fn account(self: AnyRecord) []const u8 {
        return switch (self) {
            .offer => |signed| signed.value.account,
            .revoke => |signed| signed.value.account,
        };
    }
    fn revision(self: AnyRecord) Revision {
        return switch (self) {
            .offer => |signed| signed.value.revision,
            .revoke => |signed| signed.value.revision,
        };
    }
    fn issuedAt(self: AnyRecord) i64 {
        return switch (self) {
            .offer => |signed| signed.value.issued_at_ms,
            .revoke => |signed| signed.value.issued_at_ms,
        };
    }
    fn expiresAt(self: AnyRecord) i64 {
        return switch (self) {
            .offer => |signed| signed.value.expires_at_ms,
            .revoke => |signed| signed.value.expires_at_ms,
        };
    }
};

fn validAntiEntropyCursor(cursor: AntiEntropyCursor) bool {
    return identityRevisionValid(cursor.token, cursor.attachment_id, cursor.revision);
}

fn antiEntropyCursorOrder(a: AntiEntropyCursor, b: AntiEntropyCursor) std.math.Order {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order;
    const attachment_order = std.mem.order(u8, &a.attachment_id.raw, &b.attachment_id.raw);
    if (attachment_order != .eq) return attachment_order;
    const revision_order = a.revision.compare(b.revision);
    if (revision_order != .eq) return revision_order;
    if (a.kind != b.kind) return std.math.order(@backingInt(a.kind), @backingInt(b.kind));
    return std.mem.order(u8, &a.digest, &b.digest);
}

fn considerAntiEntropyItem(
    best: *?AntiEntropyItem,
    after: ?AntiEntropyCursor,
    candidate: AntiEntropyItem,
) void {
    if (after) |cursor| {
        if (antiEntropyCursorOrder(candidate.cursor, cursor) != .gt) return;
    }
    if (best.*) |current| {
        if (antiEntropyCursorOrder(candidate.cursor, current.cursor) != .lt) return;
    }
    best.* = candidate;
}

fn considerAntiEntropyRecord(
    best: *?AntiEntropyItem,
    after: ?AntiEntropyCursor,
    wire: []const u8,
) void {
    const record = decodeAnyRecord(wire) catch unreachable;
    const kind: AntiEntropyKind = switch (record) {
        .offer => .offer,
        .revoke => .revoke,
    };
    considerAntiEntropyItem(best, after, .{
        .cursor = .{
            .token = record.token(),
            .attachment_id = record.attachmentId(),
            .revision = record.revision(),
            .kind = kind,
            .digest = digestBytes(wire),
        },
        .wire = wire,
    });
}

fn considerAntiEntropyLease(
    best: *?AntiEntropyItem,
    after: ?AntiEntropyCursor,
    wire: []const u8,
) void {
    const signed = decodeAttachmentLease(wire) catch unreachable;
    considerAntiEntropyItem(best, after, .{
        .cursor = .{
            .token = signed.value.token,
            .attachment_id = signed.value.attachment_id,
            .revision = signed.value.revision,
            .kind = .attachment_lease,
            .digest = digestBytes(wire),
        },
        .wire = wire,
    });
}

fn decodeAnyRecord(wire: []const u8) DecodeError!AnyRecord {
    if (wire.len < 4) return error.Truncated;
    if (std.mem.eql(u8, wire[0..4], &offer_magic)) return .{ .offer = try decodeOffer(wire) };
    if (std.mem.eql(u8, wire[0..4], &revoke_magic)) return .{ .revoke = try decodeRevoke(wire) };
    return error.BadMagic;
}

fn verifyAnyRecord(record: AnyRecord) VerifyError!void {
    return switch (record) {
        .offer => |signed| verifyOffer(signed),
        .revoke => |signed| verifyRevoke(signed),
    };
}

fn makeAck(
    status: AckStatus,
    token: Token,
    attachment_id: AttachmentId,
    offered_revision: Revision,
    observed_revision: Revision,
    ack_node: NodeId,
    issued_at_ms: i64,
    expires_at_ms: i64,
) Ack {
    return .{
        .status = status,
        .token = token,
        .attachment_id = attachment_id,
        .offered_revision = offered_revision,
        .observed_revision = observed_revision,
        .ack_node = ack_node,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
    };
}

fn validateAckWindow(
    ack: Ack,
    now_ms: i64,
    max_lifetime_ms: u64,
    max_future_skew_ms: u64,
) error{ Expired, FutureSkew, InvalidAck, InvalidLifetime }!void {
    validateAckShape(ack) catch return error.InvalidAck;
    if (now_ms < 0 or ack.issued_at_ms < 0 or ack.expires_at_ms < ack.issued_at_ms)
        return error.InvalidLifetime;
    if (@as(i128, ack.expires_at_ms) - @as(i128, ack.issued_at_ms) > @as(i128, max_lifetime_ms))
        return error.InvalidLifetime;
    if (@as(i128, ack.issued_at_ms) > @as(i128, now_ms) + @as(i128, max_future_skew_ms))
        return error.FutureSkew;
    if (now_ms > ack.expires_at_ms) return error.Expired;
}

fn quarantineRecordIdentityDigest(scope: QuarantineScope, record: AnyRecord) Digest {
    return quarantineIdentityDigest(scope, record.token(), accountDigest(record.account()));
}

fn quarantineIdentityDigest(scope: QuarantineScope, token: Token, account_digest: Digest) Digest {
    if (scope == .token) return account_digest;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("onyx-session-replica-attachment-quarantine-id-v1\x00");
    hasher.update(&token);
    hasher.update(&account_digest);
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

fn recordSupersedes(kind: RecordKind, revision: Revision, digest: Digest, current: AnyRecord) bool {
    return switch (revision.compare(current.revision())) {
        .lt => false,
        .gt => true,
        .eq => recordCandidateLess(kind, digest, std.meta.activeTag(current), digestBytes(switch (current) {
            .offer => |signed| signed.wire,
            .revoke => |signed| signed.wire,
        })),
    };
}

fn validateRetainedRecord(record: AnyRecord, now_ms: i64, cfg: Config) CheckpointError!i64 {
    try validateAt(record.revision(), record.issuedAt(), record.expiresAt(), now_ms, cfg.max_record_lifetime_ms, cfg.max_future_skew_ms);
    return retentionUntil(record.revision(), cfg.max_record_lifetime_ms);
}

fn retentionUntil(revision: Revision, max_lifetime_ms: u64) i64 {
    const sum = @as(u128, revision.epoch) + @as(u128, max_lifetime_ms);
    return @intCast(@min(sum, @as(u128, std.math.maxInt(i64))));
}

fn validateAt(revision: Revision, issued: i64, expires: i64, now: i64, max_lifetime: u64, max_skew: u64) error{ Expired, FutureSkew, InvalidLifetime }!void {
    if (!revision.isCanonical() or issued < 0 or expires < issued) return error.InvalidLifetime;
    if (@as(i128, issued) > @as(i128, revision.epoch)) return error.InvalidLifetime;
    if (@as(i128, expires) - @as(i128, issued) > @as(i128, max_lifetime)) return error.InvalidLifetime;
    if (now < 0) return error.InvalidLifetime;
    const future_limit = @as(i128, now) + @as(i128, max_skew);
    if (@as(i128, issued) > future_limit or @as(i128, revision.epoch) > future_limit) return error.FutureSkew;
    if (now > expires and now > retentionUntil(revision, max_lifetime)) return error.Expired;
}

fn offerEql(a: Offer, b: Offer) bool {
    return identityEql(a.token, a.attachment_id, b.token, b.attachment_id) and a.revision.eql(b.revision) and
        a.issued_at_ms == b.issued_at_ms and a.expires_at_ms == b.expires_at_ms and
        std.mem.eql(u8, a.account, b.account) and std.mem.eql(u8, a.nick, b.nick) and std.mem.eql(u8, a.snapshot, b.snapshot);
}

fn revokeEql(a: Revoke, b: Revoke) bool {
    return std.mem.eql(u8, a.account, b.account) and identityEql(a.token, a.attachment_id, b.token, b.attachment_id) and a.revision.eql(b.revision) and
        a.issued_at_ms == b.issued_at_ms and a.expires_at_ms == b.expires_at_ms;
}

fn ackEql(a: Ack, b: Ack) bool {
    return a.status == b.status and identityEql(a.token, a.attachment_id, b.token, b.attachment_id) and
        a.offered_revision.eql(b.offered_revision) and a.observed_revision.eql(b.observed_revision) and
        a.ack_node == b.ack_node and a.issued_at_ms == b.issued_at_ms and a.expires_at_ms == b.expires_at_ms;
}

fn leaseEql(a: AttachmentLease, b: AttachmentLease) bool {
    return identityEql(a.token, a.attachment_id, b.token, b.attachment_id) and a.revision.eql(b.revision) and
        a.issued_at_ms == b.issued_at_ms and a.expires_at_ms == b.expires_at_ms;
}

fn identityEql(a_token: Token, a_attachment: AttachmentId, b_token: Token, b_attachment: AttachmentId) bool {
    return tokenEql(a_token, b_token) and a_attachment.eql(b_attachment);
}

fn tokenEql(a: Token, b: Token) bool {
    return std.crypto.timing_safe.eql(Token, a, b);
}

fn isZeroToken(token: Token) bool {
    return std.mem.allEqual(u8, &token, 0);
}

fn digestBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

fn digestDomain(comptime domain: []const u8, bytes: []const u8) Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(domain);
    hasher.update(bytes);
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

fn accountDigest(account: []const u8) Digest {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(account_digest_domain);
    for (account) |byte| {
        const folded: [1]u8 = .{if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte};
        hasher.update(&folded);
    }
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

fn addLen(total: *usize, amount: usize) CheckpointError!void {
    if (amount > std.math.maxInt(usize) - total.*) return error.TooLarge;
    total.* += amount;
}

const Identity = struct { token: Token, attachment_id: AttachmentId };

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
    fn writeIdentity(self: *Writer, token: Token, attachment_id: AttachmentId) void {
        self.writeBytes(&token);
        self.writeBytes(&attachment_id.raw);
    }
    fn writeRevision(self: *Writer, value: Revision) void {
        self.writeU64(value.epoch);
        self.writeU64(value.sequence);
        self.writeU64(value.origin_node);
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,
    fn take(self: *Reader, len: usize) DecodeError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const out = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return out;
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
    fn readIdentity(self: *Reader, comptime invalid: DecodeError) DecodeError!Identity {
        const token = (try self.take(@sizeOf(Token)))[0..@sizeOf(Token)].*;
        const raw = (try self.take(@sizeOf(AttachmentId)))[0..@sizeOf(AttachmentId)].*;
        const attachment_id = AttachmentId.fromBytes(raw) catch return invalid;
        if (isZeroToken(token)) return invalid;
        return .{ .token = token, .attachment_id = attachment_id };
    }
    fn readRevision(self: *Reader) DecodeError!Revision {
        return .{ .epoch = try self.readU64(), .sequence = try self.readU64(), .origin_node = try self.readU64() };
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,
    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const out = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }
    fn readByte(self: *CheckpointReader) CheckpointError!u8 {
        return (try self.take(1))[0];
    }
    fn readU32(self: *CheckpointReader) CheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }
    fn readI64(self: *CheckpointReader) CheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
    }
    fn readBool(self: *CheckpointReader) CheckpointError!bool {
        return switch (try self.readByte()) {
            0 => false,
            1 => true,
            else => error.InvalidCheckpoint,
        };
    }
    fn readWire(self: *CheckpointReader) CheckpointError![]const u8 {
        const len: usize = try self.readU32();
        if (len == 0 or len > max_snapshot_len + session_portability.legacy_envelope_reserve) return error.InvalidCheckpoint;
        return self.take(len);
    }
    fn readOptionalWire(self: *CheckpointReader) CheckpointError!?[]const u8 {
        const len: usize = try self.readU32();
        if (len == 0) return null;
        if (len > max_snapshot_len + session_portability.legacy_envelope_reserve) return error.InvalidCheckpoint;
        return @as(?[]const u8, try self.take(len));
    }
};

fn testKey(seed: u8) !sign.KeyPair {
    return sign.KeyPair.fromSeed(@as(sign.Seed, @splat(seed)));
}

fn testAttachment(last: u8) !AttachmentId {
    var raw: [16]u8 = @splat(0);
    raw[15] = last;
    return AttachmentId.fromBytes(raw);
}

fn testRevision(origin: NodeId, physical: u64, logical: u16) Revision {
    return .{ .epoch = physical, .sequence = (physical << 16) | logical, .origin_node = origin };
}

fn testOffer(token: Token, attachment_id: AttachmentId, revision: Revision, snapshot: []const u8) Offer {
    return .{ .token = token, .attachment_id = attachment_id, .revision = revision, .issued_at_ms = @intCast(revision.epoch), .expires_at_ms = @intCast(revision.epoch + 10_000), .account = "alice", .nick = "Alice", .snapshot = snapshot };
}

test "SRA3 codecs bind token attachment revision and distinct transcript kinds" {
    const testing = std.testing;
    var kp = try testKey(7);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(0x44);
    const attachment_id = try testAttachment(1);
    const revision = testRevision(origin, 1000, 1);
    const offer = testOffer(token, attachment_id, revision, "snapshot");
    const offer_wire = try encodeOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(offer_wire);
    const signed_offer = try decodeOffer(offer_wire);
    try verifyOffer(signed_offer);
    try testing.expect(offerEql(offer, signed_offer.value));
    try testing.expectError(error.BadMagic, decodeRevoke(offer_wire));

    const revoke = Revoke{ .account = "alice", .token = token, .attachment_id = attachment_id, .revision = revision, .issued_at_ms = 1000, .expires_at_ms = 11_000 };
    const revoke_wire = try encodeRevoke(testing.allocator, revoke, &kp);
    defer testing.allocator.free(revoke_wire);
    try verifyRevoke(try decodeRevoke(revoke_wire));

    const ack = Ack{ .status = .accepted, .token = token, .attachment_id = attachment_id, .offered_revision = revision, .observed_revision = revision, .ack_node = origin, .issued_at_ms = 1000, .expires_at_ms = 2000 };
    const ack_wire = try encodeAck(testing.allocator, ack, &kp);
    defer testing.allocator.free(ack_wire);
    try verifyAck(try decodeAck(ack_wire));

    const lease = AttachmentLease{ .token = token, .attachment_id = attachment_id, .revision = revision, .issued_at_ms = 1000, .expires_at_ms = 2000 };
    const lease_wire = try encodeAttachmentLease(testing.allocator, lease, &kp);
    defer testing.allocator.free(lease_wire);
    try verifyAttachmentLease(try decodeAttachmentLease(lease_wire));

    var tampered = try testing.allocator.dupe(u8, offer_wire);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try testing.expectError(error.BadSignature, verifyOffer(try decodeOffer(tampered)));
    var detached = signed_offer;
    detached.wire = revoke_wire;
    try testing.expectError(error.TranscriptMismatch, verifyOffer(detached));
    const trailing = try std.mem.concat(testing.allocator, u8, &.{ offer_wire, "x" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.TrailingBytes, decodeOffer(trailing));
}

test "SRA3 strict decode rejects every truncation and zero attachment" {
    const testing = std.testing;
    var kp = try testKey(8);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const wire = try encodeOffer(testing.allocator, testOffer(@splat(1), try testAttachment(2), testRevision(origin, 1000, 0), "s"), &kp);
    defer testing.allocator.free(wire);
    for (0..wire.len) |end| try testing.expectError(error.Truncated, decodeOffer(wire[0..end]));
    var zero = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(zero);
    @memset(zero[offer_magic.len + @sizeOf(Token) ..][0..@sizeOf(AttachmentId)], 0);
    try testing.expectError(error.InvalidOffer, decodeOffer(zero));

    const token: Token = @splat(1);
    const attachment_id = try testAttachment(2);
    const revision = testRevision(origin, 1000, 0);
    const revoke_wire = try encodeRevoke(testing.allocator, .{
        .account = "alice",
        .token = token,
        .attachment_id = attachment_id,
        .revision = revision,
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
    }, &kp);
    defer testing.allocator.free(revoke_wire);
    var zero_revoke = try testing.allocator.dupe(u8, revoke_wire);
    defer testing.allocator.free(zero_revoke);
    const revoke_identity_offset = revoke_magic.len + 1 + "alice".len;
    @memset(zero_revoke[revoke_identity_offset..][0..@sizeOf(Token)], 0);
    try testing.expectError(error.InvalidRevoke, decodeRevoke(zero_revoke));

    const ack_wire = try encodeAck(testing.allocator, .{
        .status = .accepted,
        .token = token,
        .attachment_id = attachment_id,
        .offered_revision = revision,
        .observed_revision = revision,
        .ack_node = origin,
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
    }, &kp);
    defer testing.allocator.free(ack_wire);
    var zero_ack = try testing.allocator.dupe(u8, ack_wire);
    defer testing.allocator.free(zero_ack);
    @memset(zero_ack[ack_magic.len + 1 ..][0..@sizeOf(Token)], 0);
    try testing.expectError(error.InvalidAck, decodeAck(zero_ack));

    const lease_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = attachment_id,
        .revision = revision,
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
    }, &kp);
    defer testing.allocator.free(lease_wire);
    var zero_lease = try testing.allocator.dupe(u8, lease_wire);
    defer testing.allocator.free(zero_lease);
    @memset(zero_lease[attachment_lease_magic.len..][0..@sizeOf(Token)], 0);
    try testing.expectError(error.InvalidAttachmentLease, decodeAttachmentLease(zero_lease));
}

test "SRA3 exact portable snapshot ceiling is accepted and ceiling plus one is rejected" {
    const testing = std.testing;
    var kp = try testKey(9);
    defer kp.deinit();
    const snapshot = try testing.allocator.alloc(u8, max_snapshot_len);
    defer testing.allocator.free(snapshot);
    @memset(snapshot, 0x5a);
    const origin = signed_frame.originShortId(kp.public_key);
    const base = testOffer(@splat(2), try testAttachment(3), testRevision(origin, 1000, 0), snapshot);
    const wire = try encodeOffer(testing.allocator, base, &kp);
    defer testing.allocator.free(wire);
    try verifyOffer(try decodeOffer(wire));
    var too_large = base;
    too_large.snapshot = try testing.allocator.alloc(u8, max_snapshot_len + 1);
    defer testing.allocator.free(too_large.snapshot);
    try testing.expectError(error.TooLong, encodeOffer(testing.allocator, too_large, &kp));
}

test "SRA3 siblings survive scoped equivocation revoke expiry and replay permutations" {
    const testing = std.testing;
    var kp = try testKey(10);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(3);
    const a = try testAttachment(1);
    const b = try testAttachment(2);
    const revision = testRevision(origin, 1000, 0);
    const wa = try encodeOffer(testing.allocator, testOffer(token, a, revision, "a"), &kp);
    defer testing.allocator.free(wa);
    const wb = try encodeOffer(testing.allocator, testOffer(token, b, revision, "b"), &kp);
    defer testing.allocator.free(wb);
    var conflict_value = testOffer(token, a, revision, "conflict");
    conflict_value.expires_at_ms = 10_500;
    const wc = try encodeOffer(testing.allocator, conflict_value, &kp);
    defer testing.allocator.free(wc);

    var left = Store.init(testing.allocator, .{});
    defer left.deinit();
    _ = try left.applySignedOffer(try decodeOffer(wa), 1000);
    _ = try left.applySignedOffer(try decodeOffer(wb), 1000);
    _ = try left.applySignedOffer(try decodeOffer(wc), 1000);
    try testing.expect(left.getLive(token, a, origin, 1000) == null);
    try testing.expect(left.getLive(token, b, origin, 1000) != null);

    var right = Store.init(testing.allocator, .{});
    defer right.deinit();
    _ = try right.applySignedOffer(try decodeOffer(wc), 1000);
    _ = try right.applySignedOffer(try decodeOffer(wb), 1000);
    _ = try right.applySignedOffer(try decodeOffer(wa), 1000);
    const left_checkpoint = try left.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(left_checkpoint);
    const right_checkpoint = try right.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(right_checkpoint);
    try testing.expectEqualSlices(u8, left_checkpoint, right_checkpoint);

    const revoke_revision = testRevision(origin, 1001, 0);
    const revoke_wire = try encodeRevoke(testing.allocator, .{ .account = "alice", .token = token, .attachment_id = a, .revision = revoke_revision, .issued_at_ms = 1001, .expires_at_ms = 5000 }, &kp);
    defer testing.allocator.free(revoke_wire);
    _ = try left.applySignedRevoke(try decodeRevoke(revoke_wire), 1001);
    try testing.expect(left.getLive(token, a, origin, 1001) == null);
    try testing.expect(left.getLive(token, b, origin, 1001) != null);
    left.sweepExpired(5001);
    try testing.expect(left.getLive(token, b, origin, 5001) != null);
    left.sweepExpired(retentionUntil(revoke_revision, left.cfg.max_record_lifetime_ms) + 1);
    try testing.expectEqual(@as(usize, 0), left.records.count());
}

test "SRA3 checkpoint restore is canonical strict and replacement transactional" {
    const testing = std.testing;
    var kp = try testKey(11);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(4);
    const attachment_id = try testAttachment(4);
    const revision = testRevision(origin, 1000, 0);
    const wire = try encodeOffer(testing.allocator, testOffer(token, attachment_id, revision, "state"), &kp);
    defer testing.allocator.free(wire);
    var source = Store.init(testing.allocator, .{});
    defer source.deinit();
    _ = try source.applySignedOffer(try decodeOffer(wire), 1000);
    const checkpoint = try source.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(checkpoint);
    var restored = try Store.decodeCheckpoint(testing.allocator, .{}, checkpoint, 1000);
    defer restored.deinit();
    try testing.expect(restored.getLive(token, attachment_id, origin, 1000) != null);
    const roundtrip = try restored.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(roundtrip);
    try testing.expectEqualSlices(u8, checkpoint, roundtrip);

    var corrupt = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(corrupt);
    corrupt[checkpoint_header_len] ^= 1;
    try testing.expectError(error.BadChecksum, Store.decodeCheckpoint(testing.allocator, .{}, corrupt, 1000));
    var trailing = try testing.allocator.alloc(u8, checkpoint.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0;
    try testing.expectError(error.BadChecksum, Store.decodeCheckpoint(testing.allocator, .{}, trailing, 1000));

    const before = restored.records.count();
    try testing.expectError(error.BadChecksum, restored.replaceFromCheckpoint(corrupt, 1000));
    try testing.expectEqual(before, restored.records.count());
    try testing.expect(restored.getLive(token, attachment_id, origin, 1000) != null);
}

test "SRA3 checkpoint restore uses real time and cannot roll back record or lease high water" {
    const testing = std.testing;
    var kp = try testKey(16);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(0x16);
    const attachment_id = try testAttachment(16);
    const first_revision = testRevision(origin, 1000, 0);
    var offer = testOffer(token, attachment_id, first_revision, "old");
    offer.expires_at_ms = 11_000;
    const offer_wire = try encodeOffer(testing.allocator, offer, &kp);
    defer testing.allocator.free(offer_wire);
    const old_lease_revision = testRevision(origin, 1001, 0);
    const old_lease_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = attachment_id,
        .revision = old_lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 3000,
    }, &kp);
    defer testing.allocator.free(old_lease_wire);
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();
    _ = try store.applySignedOffer(try decodeOffer(offer_wire), 1000);
    _ = try store.applySignedAttachmentLease(try decodeAttachmentLease(old_lease_wire), 1000);
    const old_checkpoint = try store.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(old_checkpoint);

    const second_revision = testRevision(origin, 2000, 0);
    const revoke_wire = try encodeRevoke(testing.allocator, .{
        .account = "alice",
        .token = token,
        .attachment_id = attachment_id,
        .revision = second_revision,
        .issued_at_ms = 2000,
        .expires_at_ms = 12_000,
    }, &kp);
    defer testing.allocator.free(revoke_wire);
    const new_lease_revision = testRevision(origin, 2001, 0);
    const new_lease_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = attachment_id,
        .revision = new_lease_revision,
        .issued_at_ms = 2001,
        .expires_at_ms = 4000,
    }, &kp);
    defer testing.allocator.free(new_lease_wire);

    var lease_only = try Store.decodeCheckpoint(testing.allocator, .{}, old_checkpoint, 2000);
    defer lease_only.deinit();
    _ = try lease_only.applySignedAttachmentLease(try decodeAttachmentLease(new_lease_wire), 2000);
    try testing.expectError(error.Rollback, lease_only.replaceFromCheckpoint(old_checkpoint, 2001));
    try testing.expectEqual(.eq, new_lease_revision.compare(lease_only.leases.get(keyFor(token, attachment_id, origin)).?.revision));

    _ = try store.applySignedAttachmentLease(try decodeAttachmentLease(new_lease_wire), 2000);
    _ = try store.applySignedRevoke(try decodeRevoke(revoke_wire), 2000);
    try testing.expect(store.getLive(token, attachment_id, origin, 2001) == null);
    try testing.expectError(error.Rollback, store.replaceFromCheckpoint(old_checkpoint, 2001));
    try testing.expect(store.getLive(token, attachment_id, origin, 2001) == null);
    try testing.expectEqual(Revision.compare(second_revision, store.records.get(keyFor(token, attachment_id, origin)).?.revision), .eq);
    try testing.expectEqual(Revision.compare(new_lease_revision, store.leases.get(keyFor(token, attachment_id, origin)).?.revision), .eq);

    // A checkpoint's embedded capture time cannot keep expired signed state
    // admissible forever; restore is evaluated against caller-supplied time.
    try testing.expectError(error.Expired, Store.decodeCheckpoint(testing.allocator, .{}, old_checkpoint, retentionUntil(first_revision, (Config{}).max_record_lifetime_ms) + 1));

    var future_capture = try testing.allocator.dupe(u8, old_checkpoint);
    defer testing.allocator.free(future_capture);
    std.mem.writeInt(i64, future_capture[checkpoint_magic.len + 1 ..][0..8], 1_000_000, .big);
    resignCheckpoint(future_capture);
    try testing.expectError(error.FutureSkew, Store.decodeCheckpoint(testing.allocator, .{}, future_capture, 1000));
}

test "SRA3 checkpoint rejects duplicate and noncanonical attachment keys" {
    const testing = std.testing;
    var kp = try testKey(13);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(6);
    const revision = testRevision(origin, 1000, 0);
    const first_wire = try encodeOffer(testing.allocator, testOffer(token, try testAttachment(1), revision, "same"), &kp);
    defer testing.allocator.free(first_wire);
    const second_wire = try encodeOffer(testing.allocator, testOffer(token, try testAttachment(2), revision, "same"), &kp);
    defer testing.allocator.free(second_wire);
    try testing.expectEqual(first_wire.len, second_wire.len);
    var source = Store.init(testing.allocator, .{});
    defer source.deinit();
    _ = try source.applySignedOffer(try decodeOffer(second_wire), 1000);
    _ = try source.applySignedOffer(try decodeOffer(first_wire), 1000);
    const checkpoint = try source.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(checkpoint);

    const first_pos = checkpoint_header_len;
    const first_wire_len: usize = std.mem.readInt(u32, checkpoint[first_pos + 1 ..][0..4], .big);
    const first_witness_len: usize = std.mem.readInt(u32, checkpoint[first_pos + 1 + 4 + first_wire_len ..][0..4], .big);
    const first_len: usize = 1 + 4 + first_wire_len + 4 + first_witness_len;
    const second_pos = first_pos + first_len;
    const second_wire_len: usize = std.mem.readInt(u32, checkpoint[second_pos + 1 ..][0..4], .big);
    const second_witness_len: usize = std.mem.readInt(u32, checkpoint[second_pos + 1 + 4 + second_wire_len ..][0..4], .big);
    const second_len: usize = 1 + 4 + second_wire_len + 4 + second_witness_len;
    try testing.expectEqual(first_len, second_len);

    var duplicate = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(duplicate);
    @memcpy(duplicate[second_pos .. second_pos + second_len], duplicate[first_pos .. first_pos + first_len]);
    resignCheckpoint(duplicate);
    try testing.expectError(error.InvalidCheckpoint, Store.decodeCheckpoint(testing.allocator, .{}, duplicate, 1000));

    var reversed = try testing.allocator.dupe(u8, checkpoint);
    defer testing.allocator.free(reversed);
    var swap: [offer_fixed_len + max_account_len + max_nick_len + 16 + signature_wire_len]u8 = undefined;
    try testing.expect(first_len <= swap.len);
    @memcpy(swap[0..first_len], reversed[first_pos .. first_pos + first_len]);
    @memcpy(reversed[first_pos .. first_pos + first_len], reversed[second_pos .. second_pos + second_len]);
    @memcpy(reversed[second_pos .. second_pos + second_len], swap[0..first_len]);
    resignCheckpoint(reversed);
    try testing.expectError(error.NonCanonical, Store.decodeCheckpoint(testing.allocator, .{}, reversed, 1000));
}

test "SRA3 attachment leases isolate siblings converge and survive checkpoint attacks" {
    const testing = std.testing;
    var kp = try testKey(14);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(8);
    const a = try testAttachment(1);
    const b = try testAttachment(2);
    const revision = testRevision(origin, 1000, 0);
    const lease_revision = testRevision(origin, 1001, 0);
    const offer_a_wire = try encodeOffer(testing.allocator, testOffer(token, a, revision, "a"), &kp);
    defer testing.allocator.free(offer_a_wire);
    const offer_b_wire = try encodeOffer(testing.allocator, testOffer(token, b, revision, "b"), &kp);
    defer testing.allocator.free(offer_b_wire);
    const lease_a_one_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = a,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 1500,
    }, &kp);
    defer testing.allocator.free(lease_a_one_wire);
    const lease_a_two_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = a,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 1600,
    }, &kp);
    defer testing.allocator.free(lease_a_two_wire);
    const lease_b_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = b,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 3000,
    }, &kp);
    defer testing.allocator.free(lease_b_wire);

    var left = Store.init(testing.allocator, .{});
    defer left.deinit();
    _ = try left.applySignedOffer(try decodeOffer(offer_a_wire), 1000);
    _ = try left.applySignedOffer(try decodeOffer(offer_b_wire), 1000);
    _ = try left.applySignedAttachmentLease(try decodeAttachmentLease(lease_a_one_wire), 1000);
    _ = try left.applySignedAttachmentLease(try decodeAttachmentLease(lease_b_wire), 1000);
    _ = try left.applySignedAttachmentLease(try decodeAttachmentLease(lease_a_two_wire), 1000);
    try testing.expect(left.getLiveAttachmentLease(token, a, origin, 1000) == null);
    try testing.expect(left.getLiveAttachmentLease(token, b, origin, 1000) != null);

    var right = Store.init(testing.allocator, .{});
    defer right.deinit();
    _ = try right.applySignedOffer(try decodeOffer(offer_b_wire), 1000);
    _ = try right.applySignedOffer(try decodeOffer(offer_a_wire), 1000);
    _ = try right.applySignedAttachmentLease(try decodeAttachmentLease(lease_a_two_wire), 1000);
    _ = try right.applySignedAttachmentLease(try decodeAttachmentLease(lease_a_one_wire), 1000);
    _ = try right.applySignedAttachmentLease(try decodeAttachmentLease(lease_b_wire), 1000);

    const left_checkpoint = try left.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(left_checkpoint);
    const right_checkpoint = try right.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(right_checkpoint);
    try testing.expectEqualSlices(u8, left_checkpoint, right_checkpoint);
    var restored = try Store.decodeCheckpoint(testing.allocator, .{}, left_checkpoint, 1000);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.leases.count());
    try testing.expect(restored.getLiveAttachmentLease(token, a, origin, 1000) == null);
    try testing.expect(restored.getLiveAttachmentLease(token, b, origin, 1000) != null);
    const restored_checkpoint = try restored.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(restored_checkpoint);
    try testing.expectEqualSlices(u8, left_checkpoint, restored_checkpoint);

    // Find the two lease segments after the canonical record section. Record
    // rows are `kind || u32 wire_len || wire || u32 witness_len || witness`;
    // lease rows omit kind.
    var lease_pos: usize = checkpoint_header_len;
    const encoded_record_count = std.mem.readInt(u32, left_checkpoint[checkpoint_magic.len + 1 + 8 ..][0..4], .big);
    const encoded_lease_count = std.mem.readInt(u32, left_checkpoint[checkpoint_magic.len + 1 + 8 + 4 ..][0..4], .big);
    try testing.expectEqual(@as(u32, 2), encoded_record_count);
    try testing.expectEqual(@as(u32, 2), encoded_lease_count);
    for (0..encoded_record_count) |_| {
        const wire_len: usize = std.mem.readInt(u32, left_checkpoint[lease_pos + 1 ..][0..4], .big);
        const witness_len: usize = std.mem.readInt(u32, left_checkpoint[lease_pos + 1 + 4 + wire_len ..][0..4], .big);
        lease_pos += 1 + 4 + wire_len + 4 + witness_len;
    }
    const first_lease_wire_len: usize = std.mem.readInt(u32, left_checkpoint[lease_pos..][0..4], .big);
    const first_lease_witness_len: usize = std.mem.readInt(u32, left_checkpoint[lease_pos + 4 + first_lease_wire_len ..][0..4], .big);
    const first_lease_len: usize = 4 + first_lease_wire_len + 4 + first_lease_witness_len;
    const second_lease_pos = lease_pos + first_lease_len;
    const second_lease_wire_len: usize = std.mem.readInt(u32, left_checkpoint[second_lease_pos..][0..4], .big);
    const second_lease_witness_len: usize = std.mem.readInt(u32, left_checkpoint[second_lease_pos + 4 + second_lease_wire_len ..][0..4], .big);
    const second_lease_len: usize = 4 + second_lease_wire_len + 4 + second_lease_witness_len;
    var duplicate = try testing.allocator.dupe(u8, left_checkpoint);
    defer testing.allocator.free(duplicate);
    @memcpy(duplicate[second_lease_pos .. second_lease_pos + second_lease_len], duplicate[lease_pos .. lease_pos + second_lease_len]);
    resignCheckpoint(duplicate);
    try testing.expectError(error.Truncated, Store.decodeCheckpoint(testing.allocator, .{}, duplicate, 1000));

    left.sweepExpired(1601);
    try testing.expectEqual(@as(usize, 2), left.leases.count());
    try testing.expect(left.getLiveAttachmentLease(token, b, origin, 1601) != null);
}

test "SRA3 admission rejects replay skew lifetime and capacity violations" {
    const testing = std.testing;
    var kp = try testKey(15);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(9);
    const a = try testAttachment(1);
    const b = try testAttachment(2);
    const revision = testRevision(origin, 1000, 0);
    const cfg = Config{
        .max_records = 2,
        .max_attachment_leases = 1,
        .max_record_lifetime_ms = 100,
        .max_attachment_lease_lifetime_ms = 50,
        .max_future_skew_ms = 10,
    };

    var store = Store.init(testing.allocator, cfg);
    defer store.deinit();
    var expired = testOffer(token, a, revision, "expired");
    expired.expires_at_ms = 1050;
    const expired_wire = try encodeOffer(testing.allocator, expired, &kp);
    defer testing.allocator.free(expired_wire);
    var expired_store = Store.init(testing.allocator, cfg);
    defer expired_store.deinit();
    try testing.expectEqual(ApplyDisposition.inserted, try expired_store.applySignedOffer(try decodeOffer(expired_wire), 1051));
    try testing.expect(expired_store.getLive(token, a, origin, 1051) == null);

    // The exact expiry and configured lifetime boundary remains admissible.
    var boundary = testOffer(token, a, revision, "boundary");
    boundary.expires_at_ms = 1100;
    const boundary_wire = try encodeOffer(testing.allocator, boundary, &kp);
    defer testing.allocator.free(boundary_wire);
    try testing.expectEqual(ApplyDisposition.inserted, try store.applySignedOffer(try decodeOffer(boundary_wire), 1100));

    const future_revision = testRevision(origin, 2000, 0);
    const future_revoke_wire = try encodeRevoke(testing.allocator, .{
        .account = "alice",
        .token = token,
        .attachment_id = a,
        .revision = future_revision,
        .issued_at_ms = 2000,
        .expires_at_ms = 2050,
    }, &kp);
    defer testing.allocator.free(future_revoke_wire);
    try testing.expectError(error.FutureSkew, store.applySignedRevoke(try decodeRevoke(future_revoke_wire), 1000));

    var overlong = testOffer(token, b, revision, "overlong");
    overlong.expires_at_ms = 1101;
    const overlong_wire = try encodeOffer(testing.allocator, overlong, &kp);
    defer testing.allocator.free(overlong_wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedOffer(try decodeOffer(overlong_wire), 1000));

    var second = testOffer(token, b, revision, "second");
    second.expires_at_ms = 1100;
    const second_wire = try encodeOffer(testing.allocator, second, &kp);
    defer testing.allocator.free(second_wire);
    try testing.expectEqual(ApplyDisposition.inserted, try store.applySignedOffer(try decodeOffer(second_wire), 1000));
    var third = testOffer(token, try testAttachment(3), revision, "third");
    third.expires_at_ms = 1100;
    const third_wire = try encodeOffer(testing.allocator, third, &kp);
    defer testing.allocator.free(third_wire);
    try testing.expectError(error.Capacity, store.applySignedOffer(try decodeOffer(third_wire), 1000));

    const lease_revision = testRevision(origin, 1001, 0);
    const lease_a_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = a,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 1051,
    }, &kp);
    defer testing.allocator.free(lease_a_wire);
    try testing.expectEqual(ApplyDisposition.inserted, try store.applySignedAttachmentLease(try decodeAttachmentLease(lease_a_wire), 1000));
    const lease_b_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = b,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 1051,
    }, &kp);
    defer testing.allocator.free(lease_b_wire);
    try testing.expectError(error.Capacity, store.applySignedAttachmentLease(try decodeAttachmentLease(lease_b_wire), 1000));

    const overlong_lease_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = b,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 1052,
    }, &kp);
    defer testing.allocator.free(overlong_lease_wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedAttachmentLease(try decodeAttachmentLease(overlong_lease_wire), 1000));
}

test "SRA3 account binding folds ASCII and quarantines cross-account permutations through revoke and checkpoint" {
    const testing = std.testing;
    var alice_key = try testKey(21);
    defer alice_key.deinit();
    var bob_key = try testKey(22);
    defer bob_key.deinit();
    const alice_origin = signed_frame.originShortId(alice_key.public_key);
    const bob_origin = signed_frame.originShortId(bob_key.public_key);
    const token: Token = @splat(0x21);
    const a = try testAttachment(21);
    const b = try testAttachment(22);

    var alice_offer = testOffer(token, a, testRevision(alice_origin, 1000, 0), "alice-offer");
    alice_offer.account = "Alice";
    const alice_offer_wire = try encodeOffer(testing.allocator, alice_offer, &alice_key);
    defer testing.allocator.free(alice_offer_wire);
    const alice_revoke_wire = try encodeRevoke(testing.allocator, .{
        .account = "alice",
        .token = token,
        .attachment_id = a,
        .revision = testRevision(alice_origin, 1001, 0),
        .issued_at_ms = 1001,
        .expires_at_ms = 6000,
    }, &alice_key);
    defer testing.allocator.free(alice_revoke_wire);
    var bob_offer = testOffer(token, b, testRevision(bob_origin, 1002, 0), "bob-offer");
    bob_offer.account = "bob";
    bob_offer.nick = "Bob";
    const bob_offer_wire = try encodeOffer(testing.allocator, bob_offer, &bob_key);
    defer testing.allocator.free(bob_offer_wire);

    // Display-case-only changes are one canonical account identity.
    var folded = Store.init(testing.allocator, .{});
    defer folded.deinit();
    try testing.expectEqual(ApplyDisposition.inserted, try folded.applySignedOffer(try decodeOffer(alice_offer_wire), 1000));
    var folded_sibling = testOffer(token, b, testRevision(alice_origin, 1001, 0), "folded");
    folded_sibling.account = "ALICE";
    const folded_wire = try encodeOffer(testing.allocator, folded_sibling, &alice_key);
    defer testing.allocator.free(folded_wire);
    try testing.expectEqual(ApplyDisposition.inserted, try folded.applySignedOffer(try decodeOffer(folded_wire), 1001));
    try testing.expectEqual(@as(usize, 0), folded.quarantines.count());
    try testing.expect(folded.matchesRetainedAuthority(token, b, "aLiCe", 1001));

    var left = Store.init(testing.allocator, .{});
    defer left.deinit();
    _ = try left.applySignedOffer(try decodeOffer(alice_offer_wire), 1000);
    _ = try left.applySignedRevoke(try decodeRevoke(alice_revoke_wire), 1001);
    try testing.expectEqual(ApplyDisposition.conflict, try left.applySignedOffer(try decodeOffer(bob_offer_wire), 1002));

    var right = Store.init(testing.allocator, .{});
    defer right.deinit();
    _ = try right.applySignedOffer(try decodeOffer(bob_offer_wire), 1002);
    _ = try right.applySignedOffer(try decodeOffer(alice_offer_wire), 1002);
    _ = try right.applySignedRevoke(try decodeRevoke(alice_revoke_wire), 1002);

    try testing.expectEqual(@as(usize, 0), left.records.count());
    try testing.expectEqual(@as(usize, 1), left.quarantines.count());
    try testing.expect(!left.matchesRetainedAuthority(token, a, "alice", 1002));
    try testing.expect(left.isAttachmentIdRetained(a, 1002));
    try testing.expect(left.isAttachmentIdRetained(b, 1002));
    const left_checkpoint = try left.encodeCheckpoint(testing.allocator, 1002);
    defer testing.allocator.free(left_checkpoint);
    const right_checkpoint = try right.encodeCheckpoint(testing.allocator, 1002);
    defer testing.allocator.free(right_checkpoint);
    try testing.expectEqualSlices(u8, left_checkpoint, right_checkpoint);
    var restored = try Store.decodeCheckpoint(testing.allocator, .{}, left_checkpoint, 1002);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), restored.quarantines.count());
    try testing.expect(!restored.matchesRetainedAuthority(token, a, "alice", 1002));
    const roundtrip = try restored.encodeCheckpoint(testing.allocator, 1002);
    defer testing.allocator.free(roundtrip);
    try testing.expectEqualSlices(u8, left_checkpoint, roundtrip);
}

test "SRA3 globally quarantines one attachment id under another token and OOM remains denied" {
    const testing = std.testing;
    var alice_key = try testKey(23);
    defer alice_key.deinit();
    var bob_key = try testKey(24);
    defer bob_key.deinit();
    const alice_origin = signed_frame.originShortId(alice_key.public_key);
    const bob_origin = signed_frame.originShortId(bob_key.public_key);
    const alice_token: Token = @splat(0x31);
    const bob_token: Token = @splat(0x32);
    const attachment_id = try testAttachment(31);
    const alice_wire = try encodeOffer(testing.allocator, testOffer(alice_token, attachment_id, testRevision(alice_origin, 1000, 0), "alice"), &alice_key);
    defer testing.allocator.free(alice_wire);
    var bob_offer = testOffer(bob_token, attachment_id, testRevision(bob_origin, 1000, 0), "bob");
    bob_offer.account = "bob";
    bob_offer.nick = "Bob";
    const bob_wire = try encodeOffer(testing.allocator, bob_offer, &bob_key);
    defer testing.allocator.free(bob_wire);

    var left = Store.init(testing.allocator, .{});
    defer left.deinit();
    _ = try left.applySignedOffer(try decodeOffer(alice_wire), 1000);
    _ = try left.applySignedOffer(try decodeOffer(bob_wire), 1000);
    var right = Store.init(testing.allocator, .{});
    defer right.deinit();
    _ = try right.applySignedOffer(try decodeOffer(bob_wire), 1000);
    _ = try right.applySignedOffer(try decodeOffer(alice_wire), 1000);
    try testing.expectEqual(@as(usize, 1), left.quarantines.count());
    try testing.expect(left.getLive(alice_token, attachment_id, alice_origin, 1000) == null);
    try testing.expect(left.getLive(bob_token, attachment_id, bob_origin, 1000) == null);
    try testing.expect(left.isAttachmentIdRetained(attachment_id, 1000));
    const left_checkpoint = try left.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(left_checkpoint);
    const right_checkpoint = try right.encodeCheckpoint(testing.allocator, 1000);
    defer testing.allocator.free(right_checkpoint);
    try testing.expectEqualSlices(u8, left_checkpoint, right_checkpoint);

    var denied = Store.init(testing.allocator, .{});
    defer denied.deinit();
    _ = try denied.applySignedOffer(try decodeOffer(alice_wire), 1000);
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    denied.allocator = failing.allocator();
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, denied.applySignedOffer(try decodeOffer(bob_wire), 1000));
    denied.allocator = testing.allocator;
    try testing.expectEqual(@as(usize, 1), denied.records.count());
    try testing.expectEqual(@as(usize, 0), denied.quarantines.count());
    try testing.expect(denied.getLive(alice_token, attachment_id, alice_origin, 1000) == null);
    try testing.expectError(error.InvalidCheckpoint, denied.encodeCheckpoint(testing.allocator, 1000));
    try testing.expectEqual(ApplyDisposition.conflict, try denied.applySignedOffer(try decodeOffer(bob_wire), 1000));
    try testing.expectEqual(@as(usize, 1), denied.quarantines.count());
}

test "SRA3 unequal-expiry record and lease conflicts retain witnesses and converge after sweep and restore" {
    const testing = std.testing;
    var kp = try testKey(25);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(0x41);
    const attachment_id = try testAttachment(41);
    const offer_revision = testRevision(origin, 1000, 0);
    var first_offer = testOffer(token, attachment_id, offer_revision, "first");
    first_offer.expires_at_ms = 2000;
    var second_offer = testOffer(token, attachment_id, offer_revision, "second");
    second_offer.expires_at_ms = 9000;
    const first_offer_wire = try encodeOffer(testing.allocator, first_offer, &kp);
    defer testing.allocator.free(first_offer_wire);
    const second_offer_wire = try encodeOffer(testing.allocator, second_offer, &kp);
    defer testing.allocator.free(second_offer_wire);

    var record_left = Store.init(testing.allocator, .{});
    defer record_left.deinit();
    _ = try record_left.applySignedOffer(try decodeOffer(first_offer_wire), 1000);
    _ = try record_left.applySignedOffer(try decodeOffer(second_offer_wire), 1000);
    var record_right = Store.init(testing.allocator, .{});
    defer record_right.deinit();
    _ = try record_right.applySignedOffer(try decodeOffer(second_offer_wire), 1000);
    _ = try record_right.applySignedOffer(try decodeOffer(first_offer_wire), 1000);
    record_left.sweepExpired(3000);
    try testing.expectEqual(@as(usize, 1), record_left.records.count());
    try testing.expect(record_left.records.get(keyFor(token, attachment_id, origin)).?.conflict_wire != null);
    const loser_wire = if (std.mem.eql(u8, record_left.records.get(keyFor(token, attachment_id, origin)).?.wire, first_offer_wire)) second_offer_wire else first_offer_wire;
    try testing.expectEqual(ApplyDisposition.duplicate, try record_left.applySignedOffer(try decodeOffer(loser_wire), 3000));
    const record_left_checkpoint = try record_left.encodeCheckpoint(testing.allocator, 3000);
    defer testing.allocator.free(record_left_checkpoint);
    const record_right_checkpoint = try record_right.encodeCheckpoint(testing.allocator, 3000);
    defer testing.allocator.free(record_right_checkpoint);
    try testing.expectEqualSlices(u8, record_left_checkpoint, record_right_checkpoint);
    var record_restored = try Store.decodeCheckpoint(testing.allocator, .{}, record_left_checkpoint, 3000);
    defer record_restored.deinit();
    try testing.expect(record_restored.getLive(token, attachment_id, origin, 3000) == null);

    // A separate clean attachment supplies the exact signer-bound offer used
    // to admit the conflicting leases.
    const lease_attachment = try testAttachment(42);
    const lease_offer_wire = try encodeOffer(testing.allocator, testOffer(token, lease_attachment, offer_revision, "lease-offer"), &kp);
    defer testing.allocator.free(lease_offer_wire);
    const lease_revision = testRevision(origin, 1001, 0);
    const first_lease_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = lease_attachment,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 2000,
    }, &kp);
    defer testing.allocator.free(first_lease_wire);
    const second_lease_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = lease_attachment,
        .revision = lease_revision,
        .issued_at_ms = 1001,
        .expires_at_ms = 9000,
    }, &kp);
    defer testing.allocator.free(second_lease_wire);
    var lease_left = Store.init(testing.allocator, .{});
    defer lease_left.deinit();
    _ = try lease_left.applySignedOffer(try decodeOffer(lease_offer_wire), 1000);
    _ = try lease_left.applySignedAttachmentLease(try decodeAttachmentLease(first_lease_wire), 1001);
    _ = try lease_left.applySignedAttachmentLease(try decodeAttachmentLease(second_lease_wire), 1001);
    var lease_right = Store.init(testing.allocator, .{});
    defer lease_right.deinit();
    _ = try lease_right.applySignedOffer(try decodeOffer(lease_offer_wire), 1000);
    _ = try lease_right.applySignedAttachmentLease(try decodeAttachmentLease(second_lease_wire), 1001);
    _ = try lease_right.applySignedAttachmentLease(try decodeAttachmentLease(first_lease_wire), 1001);
    lease_left.sweepExpired(3000);
    try testing.expectEqual(@as(usize, 1), lease_left.leases.count());
    const lease_loser = if (std.mem.eql(u8, lease_left.leases.get(keyFor(token, lease_attachment, origin)).?.wire, first_lease_wire)) second_lease_wire else first_lease_wire;
    try testing.expectEqual(ApplyDisposition.duplicate, try lease_left.applySignedAttachmentLease(try decodeAttachmentLease(lease_loser), 3000));
    const lease_left_checkpoint = try lease_left.encodeCheckpoint(testing.allocator, 3000);
    defer testing.allocator.free(lease_left_checkpoint);
    const lease_right_checkpoint = try lease_right.encodeCheckpoint(testing.allocator, 3000);
    defer testing.allocator.free(lease_right_checkpoint);
    try testing.expectEqualSlices(u8, lease_left_checkpoint, lease_right_checkpoint);
    var lease_restored = try Store.decodeCheckpoint(testing.allocator, .{}, lease_left_checkpoint, 3000);
    defer lease_restored.deinit();
    try testing.expect(lease_restored.getLiveAttachmentLease(token, lease_attachment, origin, 3000) == null);
}

test "SRA3 lease liveness requires strict newer revision exact signer and issue clock" {
    const testing = std.testing;
    var kp = try testKey(26);
    defer kp.deinit();
    var other = try testKey(27);
    defer other.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(0x51);
    const attachment_id = try testAttachment(51);
    const offer_revision = testRevision(origin, 1000, 0);
    const offer_wire = try encodeOffer(testing.allocator, testOffer(token, attachment_id, offer_revision, "offer"), &kp);
    defer testing.allocator.free(offer_wire);
    var store = Store.init(testing.allocator, .{});
    defer store.deinit();
    _ = try store.applySignedOffer(try decodeOffer(offer_wire), 1000);

    const equal_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = attachment_id,
        .revision = offer_revision,
        .issued_at_ms = 1000,
        .expires_at_ms = 1100,
    }, &kp);
    defer testing.allocator.free(equal_wire);
    try testing.expectError(error.InvalidAttachmentLease, store.applySignedAttachmentLease(try decodeAttachmentLease(equal_wire), 1000));

    const reissued_old_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = attachment_id,
        .revision = testRevision(origin, 1001, 0),
        .issued_at_ms = 1002,
        .expires_at_ms = 1100,
    }, &kp);
    defer testing.allocator.free(reissued_old_wire);
    try testing.expectError(error.InvalidLifetime, store.applySignedAttachmentLease(try decodeAttachmentLease(reissued_old_wire), 1002));

    // Simulate two full keys sharing the same shortened origin namespace: a
    // short-id-only comparison would accept this, exact key equality rejects.
    store.records.getPtr(keyFor(token, attachment_id, origin)).?.signer = other.public_key;
    const valid_wire = try encodeAttachmentLease(testing.allocator, .{
        .token = token,
        .attachment_id = attachment_id,
        .revision = testRevision(origin, 1001, 0),
        .issued_at_ms = 1001,
        .expires_at_ms = 1100,
    }, &kp);
    defer testing.allocator.free(valid_wire);
    try testing.expectError(error.InvalidAttachmentLease, store.applySignedAttachmentLease(try decodeAttachmentLease(valid_wire), 1001));
}

test "SRA3 wire and grouping caps are transactional and conflict OOM publishes denial first" {
    const testing = std.testing;
    var kp = try testKey(28);
    defer kp.deinit();
    const origin = signed_frame.originShortId(kp.public_key);
    const token: Token = @splat(0x61);
    const a = try testAttachment(61);
    const b = try testAttachment(62);
    const revision = testRevision(origin, 1000, 0);
    const first_wire = try encodeOffer(testing.allocator, testOffer(token, a, revision, "first"), &kp);
    defer testing.allocator.free(first_wire);
    const second_wire = try encodeOffer(testing.allocator, testOffer(token, b, revision, "second"), &kp);
    defer testing.allocator.free(second_wire);

    var capped = Store.init(testing.allocator, .{ .max_wire_bytes = first_wire.len, .max_records_per_account = 1 });
    defer capped.deinit();
    _ = try capped.applySignedOffer(try decodeOffer(first_wire), 1000);
    try testing.expectEqual(first_wire.len, capped.wire_bytes);
    try testing.expectError(error.Capacity, capped.applySignedOffer(try decodeOffer(second_wire), 1000));
    try testing.expectEqual(first_wire.len, capped.wire_bytes);
    try testing.expectEqual(@as(usize, 1), capped.records.count());

    var conflict_value = testOffer(token, a, revision, "conflict");
    conflict_value.expires_at_ms = 9000;
    const conflict_wire = try encodeOffer(testing.allocator, conflict_value, &kp);
    defer testing.allocator.free(conflict_wire);
    try testing.expectError(error.Capacity, capped.applySignedOffer(try decodeOffer(conflict_wire), 1000));
    const denied = capped.records.get(keyFor(token, a, origin)).?;
    try testing.expect(denied.conflicted);
    try testing.expect(denied.conflict_wire == null);
    try testing.expect(capped.getLive(token, a, origin, 1000) == null);
    try testing.expectError(error.InvalidCheckpoint, capped.encodeCheckpoint(testing.allocator, 1000));

    var oom = Store.init(testing.allocator, .{});
    defer oom.deinit();
    _ = try oom.applySignedOffer(try decodeOffer(first_wire), 1000);
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    oom.allocator = failing.allocator();
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, oom.applySignedOffer(try decodeOffer(conflict_wire), 1000));
    oom.allocator = testing.allocator;
    try testing.expect(oom.records.get(keyFor(token, a, origin)).?.conflicted);
    try testing.expect(oom.records.get(keyFor(token, a, origin)).?.conflict_wire == null);
    const recovered = try oom.applySignedOffer(try decodeOffer(conflict_wire), 1000);
    try testing.expect(recovered == .conflict or recovered == .conflict_replaced);
    try testing.expect(oom.records.get(keyFor(token, a, origin)).?.conflict_wire != null);

    var checkpoint_capped = Store.init(testing.allocator, .{ .max_checkpoint_bytes = checkpoint_header_len + checkpoint_checksum_len });
    defer checkpoint_capped.deinit();
    _ = try checkpoint_capped.applySignedOffer(try decodeOffer(first_wire), 1000);
    try testing.expectError(error.TooLarge, checkpoint_capped.encodeCheckpoint(testing.allocator, 1000));
}

test "SRA3 store and checkpoint restore survive every allocation failure" {
    const testing = std.testing;
    const ApplySweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var kp = try testKey(12);
            defer kp.deinit();
            const origin = signed_frame.originShortId(kp.public_key);
            const wire = try encodeOffer(allocator, testOffer(@splat(5), try testAttachment(5), testRevision(origin, 1000, 0), "state"), &kp);
            defer allocator.free(wire);
            var store = Store.init(allocator, .{});
            defer store.deinit();
            _ = try store.applySignedOffer(try decodeOffer(wire), 1000);
            const checkpoint = try store.encodeCheckpoint(allocator, 1000);
            defer allocator.free(checkpoint);
            const attachment_id = try testAttachment(5);
            var restored = Store.init(allocator, .{});
            defer restored.deinit();
            _ = try restored.applySignedOffer(try decodeOffer(wire), 1000);
            restored.replaceFromCheckpoint(checkpoint, 1000) catch |err| {
                try testing.expect(restored.getLive(@splat(5), attachment_id, origin, 1000) != null);
                return err;
            };
            try testing.expect(restored.getLive(@splat(5), attachment_id, origin, 1000) != null);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, ApplySweep.run, .{});
}

test "SRA3 record lease and quarantine denial survive every allocation failure branch" {
    const testing = std.testing;
    const RecordSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var kp = try testKey(29);
            defer kp.deinit();
            const origin = signed_frame.originShortId(kp.public_key);
            const token: Token = @splat(0x71);
            const attachment_id = try testAttachment(71);
            const revision = testRevision(origin, 1000, 0);
            const first_wire = try encodeOffer(allocator, testOffer(token, attachment_id, revision, "first"), &kp);
            defer allocator.free(first_wire);
            const conflict_wire = try encodeOffer(allocator, testOffer(token, attachment_id, revision, "conflict"), &kp);
            defer allocator.free(conflict_wire);
            var store = Store.init(allocator, .{});
            defer store.deinit();
            _ = try store.applySignedOffer(try decodeOffer(first_wire), 1000);
            const disposition = store.applySignedOffer(try decodeOffer(conflict_wire), 1000) catch |err| {
                if (err == error.OutOfMemory) {
                    const denied = store.records.get(keyFor(token, attachment_id, origin)).?;
                    try testing.expect(denied.conflicted);
                    try testing.expect(store.getLive(token, attachment_id, origin, 1000) == null);
                }
                return err;
            };
            try testing.expect(disposition == .conflict or disposition == .conflict_replaced);
            try testing.expect(store.records.get(keyFor(token, attachment_id, origin)).?.conflict_wire != null);
            const checkpoint = try store.encodeCheckpoint(allocator, 1000);
            defer allocator.free(checkpoint);
            var restored = try Store.decodeCheckpoint(allocator, .{}, checkpoint, 1000);
            defer restored.deinit();
            try testing.expect(restored.getLive(token, attachment_id, origin, 1000) == null);
        }
    };
    const LeaseSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var kp = try testKey(30);
            defer kp.deinit();
            const origin = signed_frame.originShortId(kp.public_key);
            const token: Token = @splat(0x72);
            const attachment_id = try testAttachment(72);
            const offer_wire = try encodeOffer(allocator, testOffer(token, attachment_id, testRevision(origin, 1000, 0), "offer"), &kp);
            defer allocator.free(offer_wire);
            const lease_revision = testRevision(origin, 1001, 0);
            const first_wire = try encodeAttachmentLease(allocator, .{
                .token = token,
                .attachment_id = attachment_id,
                .revision = lease_revision,
                .issued_at_ms = 1001,
                .expires_at_ms = 2000,
            }, &kp);
            defer allocator.free(first_wire);
            const conflict_wire = try encodeAttachmentLease(allocator, .{
                .token = token,
                .attachment_id = attachment_id,
                .revision = lease_revision,
                .issued_at_ms = 1001,
                .expires_at_ms = 3000,
            }, &kp);
            defer allocator.free(conflict_wire);
            var store = Store.init(allocator, .{});
            defer store.deinit();
            _ = try store.applySignedOffer(try decodeOffer(offer_wire), 1000);
            _ = try store.applySignedAttachmentLease(try decodeAttachmentLease(first_wire), 1001);
            const disposition = store.applySignedAttachmentLease(try decodeAttachmentLease(conflict_wire), 1001) catch |err| {
                if (err == error.OutOfMemory) {
                    const denied = store.leases.get(keyFor(token, attachment_id, origin)).?;
                    try testing.expect(denied.conflicted);
                    try testing.expect(store.getLiveAttachmentLease(token, attachment_id, origin, 1001) == null);
                }
                return err;
            };
            try testing.expect(disposition == .conflict or disposition == .conflict_replaced);
            try testing.expect(store.leases.get(keyFor(token, attachment_id, origin)).?.conflict_wire != null);
            const checkpoint = try store.encodeCheckpoint(allocator, 1001);
            defer allocator.free(checkpoint);
            var restored = try Store.decodeCheckpoint(allocator, .{}, checkpoint, 1001);
            defer restored.deinit();
            try testing.expect(restored.getLiveAttachmentLease(token, attachment_id, origin, 1001) == null);
        }
    };
    const QuarantineSweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var alice_key = try testKey(31);
            defer alice_key.deinit();
            var bob_key = try testKey(32);
            defer bob_key.deinit();
            const token: Token = @splat(0x73);
            const alice_origin = signed_frame.originShortId(alice_key.public_key);
            const bob_origin = signed_frame.originShortId(bob_key.public_key);
            const alice_attachment = try testAttachment(73);
            const bob_attachment = try testAttachment(74);
            var alice = testOffer(token, alice_attachment, testRevision(alice_origin, 1000, 0), "alice");
            alice.account = "Alice";
            const alice_wire = try encodeOffer(allocator, alice, &alice_key);
            defer allocator.free(alice_wire);
            var bob = testOffer(token, bob_attachment, testRevision(bob_origin, 1000, 0), "bob");
            bob.account = "bob";
            bob.nick = "Bob";
            const bob_wire = try encodeOffer(allocator, bob, &bob_key);
            defer allocator.free(bob_wire);
            var store = Store.init(allocator, .{});
            defer store.deinit();
            _ = try store.applySignedOffer(try decodeOffer(alice_wire), 1000);
            _ = store.applySignedOffer(try decodeOffer(bob_wire), 1000) catch |err| {
                if (err == error.OutOfMemory) {
                    try testing.expect(store.getLive(token, alice_attachment, alice_origin, 1000) == null);
                    try testing.expect(store.hasDenyMarker(token, bob_attachment, 1000));
                }
                return err;
            };
            try testing.expectEqual(@as(usize, 1), store.quarantines.count());
            try testing.expect(store.getLive(token, alice_attachment, alice_origin, 1000) == null);
            try testing.expect(store.getLive(token, bob_attachment, bob_origin, 1000) == null);
            const checkpoint = try store.encodeCheckpoint(allocator, 1000);
            defer allocator.free(checkpoint);
            var restored = try Store.decodeCheckpoint(allocator, .{}, checkpoint, 1000);
            defer restored.deinit();
            try testing.expectEqual(@as(usize, 1), restored.quarantines.count());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, RecordSweep.run, .{});
    try testing.checkAllAllocationFailures(testing.allocator, LeaseSweep.run, .{});
    try testing.checkAllAllocationFailures(testing.allocator, QuarantineSweep.run, .{});
}

fn resignCheckpoint(bytes: []u8) void {
    const body = bytes[0 .. bytes.len - checkpoint_checksum_len];
    const checksum = digestDomain(checkpoint_digest_domain, body);
    @memcpy(bytes[body.len..], &checksum);
}
