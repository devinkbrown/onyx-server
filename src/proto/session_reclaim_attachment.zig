// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attachment-scoped cross-mesh session reclaim v2.
//!
//! SRM2 is deliberately not an SRM1 decoder. A verified legacy SRM1 credential
//! has no physical attachment identity and therefore cannot mean exact restore.
//! A cold compatibility adapter outside this module may only mint a fresh,
//! nonzero `AttachmentId` and translate it to `create_new`; it must never map
//! SRM1 to `exact_restore` or reinterpret SRM1 bytes as this schema.
//!
//! The origin signs one canonical claim. A successful destination consumes it
//! by countersigning that exact signed claim under a distinct domain. Thus a
//! consume cannot manufacture or rewrite origin authority, and both wire kinds
//! bind account, reusable group token, attachment id, origin, destination,
//! claim kind, issuance/expiry, and nonce.

const std = @import("std");

const attachment_id_mod = @import("../daemon/attachment_id.zig");
const sign = @import("../crypto/sign.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

pub const GroupToken = attachment_id_mod.SessionToken;
pub const AttachmentId = attachment_id_mod.AttachmentId;
pub const NodeId = u64;
pub const Digest = [std.crypto.hash.Blake3.digest_length]u8;

pub const claim_magic = [_]u8{ 'S', 'R', 'M', 2 };
pub const consume_magic = [_]u8{ 'S', 'R', 'C', 2 };
pub const claim_sign_domain = "onyx-session-reclaim-attachment-claim-v2";
pub const consume_sign_domain = "onyx-session-reclaim-attachment-consume-v2";

pub const max_account_len: usize = 64;
pub const default_max_lifetime_ms: u64 = 12 * 60 * 60 * 1000;
pub const default_max_future_skew_ms: u64 = mesh_clock.default_max_future_skew_ms;

const signature_wire_len: usize = sign.public_key_len + sign.signature_len;
const claim_fixed_len: usize = claim_magic.len + 1 + 1 + @sizeOf(GroupToken) +
    @sizeOf(AttachmentId) + 8 + 8 + 8 + 8 + 8;
pub const min_claim_wire_len: usize = claim_fixed_len + 1 + signature_wire_len;
pub const max_claim_wire_len: usize = claim_fixed_len + max_account_len + signature_wire_len;
const consume_fixed_len: usize = consume_magic.len + 2;
pub const min_consume_wire_len: usize = consume_fixed_len + min_claim_wire_len + signature_wire_len;
pub const max_consume_wire_len: usize = consume_fixed_len + max_claim_wire_len + signature_wire_len;

comptime {
    std.debug.assert(@sizeOf(GroupToken) == 16);
    std.debug.assert(@sizeOf(AttachmentId) == 16);
    std.debug.assert(max_claim_wire_len <= std.math.maxInt(u16));
}

pub const ClaimKind = enum(u8) {
    /// Create one new sibling attachment using this fresh claimed id. If the id
    /// already exists, fail with collision; never fall through to restoration.
    create_new = 1,
    /// Restore exactly this physical attachment. If it is absent, fail with
    /// missing; never create a replacement attachment implicitly.
    exact_restore = 2,
};

pub const Claim = struct {
    kind: ClaimKind,
    account: []const u8,
    group_token: GroupToken,
    attachment_id: AttachmentId,
    origin_node: NodeId,
    destination_node: NodeId,
    issued_at_ms: i64,
    expires_at_ms: i64,
    nonce: u64,
};

pub const SignedClaim = struct {
    claim: Claim,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
    wire: []const u8,
};

/// A destination-signed countersignature over one exact signed origin claim.
/// `claim.wire` borrows the embedded claim bytes inside `wire`.
pub const SignedConsume = struct {
    claim: SignedClaim,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
    wire: []const u8,
};

pub const EncodeError = error{
    InvalidClaim,
    TooLong,
    OriginMismatch,
    DestinationMismatch,
} || VerifyError || std.mem.Allocator.Error || sign.SignError;

pub const DecodeError = error{
    BadMagic,
    InvalidClaim,
    InvalidConsume,
    TooLong,
    TrailingBytes,
    Truncated,
};

pub const VerifyError = error{
    BadSignature,
    OriginMismatch,
    DestinationMismatch,
    TranscriptMismatch,
};

pub const AdmissionError = error{
    Expired,
    FutureSkew,
    InvalidLifetime,
};

pub const Config = struct {
    max_entries: usize = 4096,
    max_lifetime_ms: u64 = default_max_lifetime_ms,
    max_future_skew_ms: u64 = default_max_future_skew_ms,
};

/// Encode and origin-sign one canonical SRM2 claim. The caller owns the wire.
pub fn encodeClaim(
    allocator: std.mem.Allocator,
    claim: Claim,
    origin_key: *const sign.KeyPair,
) EncodeError![]u8 {
    try validateShape(claim);
    if (signed_frame.originShortId(origin_key.public_key) != claim.origin_node)
        return error.OriginMismatch;
    const transcript_len = claim_fixed_len + claim.account.len;
    var wire = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(wire);
    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&claim_magic);
    writer.writeByte(@backingInt(claim.kind));
    writer.writeByte(@intCast(claim.account.len));
    writer.writeBytes(claim.account);
    writer.writeBytes(&claim.group_token);
    writer.writeBytes(&claim.attachment_id.raw);
    writer.writeU64(claim.origin_node);
    writer.writeU64(claim.destination_node);
    writer.writeI64(claim.issued_at_ms);
    writer.writeI64(claim.expires_at_ms);
    writer.writeU64(claim.nonce);
    std.debug.assert(writer.pos == transcript_len);
    const signature = try origin_key.signCtx(claim_sign_domain, wire[0..transcript_len]);
    writer.writeBytes(&origin_key.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == wire.len);
    return wire;
}

pub fn decodeClaim(wire: []const u8) DecodeError!SignedClaim {
    var reader = Reader{ .bytes = wire };
    const claim = try readClaim(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != wire.len) return error.TrailingBytes;
    return .{
        .claim = claim,
        .signer = signer,
        .signature = signature,
        .transcript = wire[0..transcript_end],
        .wire = wire,
    };
}

pub fn verifyClaim(signed: SignedClaim) VerifyError!void {
    if (!signedWireBound(signed.wire, signed.transcript, signed.signer, signed.signature))
        return error.TranscriptMismatch;
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readClaim(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !claimEql(projected, signed.claim))
        return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.claim.origin_node)
        return error.OriginMismatch;
    const valid = sign.verifyCtx(claim_sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}

/// Verify the origin claim, then countersign its exact canonical signed wire as
/// the bound destination. The caller owns the returned consume wire.
pub fn encodeConsume(
    allocator: std.mem.Allocator,
    claim: SignedClaim,
    destination_key: *const sign.KeyPair,
) EncodeError![]u8 {
    try verifyClaim(claim);
    if (signed_frame.originShortId(destination_key.public_key) != claim.claim.destination_node)
        return error.DestinationMismatch;
    if (claim.wire.len < min_claim_wire_len or claim.wire.len > max_claim_wire_len)
        return error.InvalidClaim;
    const transcript_len = consume_fixed_len + claim.wire.len;
    var wire = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(wire);
    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&consume_magic);
    writer.writeU16(@intCast(claim.wire.len));
    writer.writeBytes(claim.wire);
    std.debug.assert(writer.pos == transcript_len);
    const signature = try destination_key.signCtx(consume_sign_domain, wire[0..transcript_len]);
    writer.writeBytes(&destination_key.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == wire.len);
    return wire;
}

pub fn decodeConsume(wire: []const u8) DecodeError!SignedConsume {
    var reader = Reader{ .bytes = wire };
    if (!std.mem.eql(u8, try reader.take(consume_magic.len), &consume_magic))
        return error.BadMagic;
    const claim_len: usize = try reader.readU16();
    if (claim_len < min_claim_wire_len or claim_len > max_claim_wire_len)
        return error.InvalidConsume;
    const claim_wire = try reader.take(claim_len);
    const claim = decodeClaim(claim_wire) catch return error.InvalidConsume;
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != wire.len) return error.TrailingBytes;
    return .{
        .claim = claim,
        .signer = signer,
        .signature = signature,
        .transcript = wire[0..transcript_end],
        .wire = wire,
    };
}

pub fn verifyConsume(signed: SignedConsume) VerifyError!void {
    if (!signedWireBound(signed.wire, signed.transcript, signed.signer, signed.signature))
        return error.TranscriptMismatch;
    var reader = Reader{ .bytes = signed.transcript };
    if (!std.mem.eql(u8, reader.take(consume_magic.len) catch return error.TranscriptMismatch, &consume_magic))
        return error.TranscriptMismatch;
    const claim_len: usize = reader.readU16() catch return error.TranscriptMismatch;
    if (claim_len != signed.claim.wire.len) return error.TranscriptMismatch;
    const embedded = reader.take(claim_len) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !std.mem.eql(u8, embedded, signed.claim.wire))
        return error.TranscriptMismatch;
    try verifyClaim(signed.claim);
    if (signed_frame.originShortId(signed.signer) != signed.claim.claim.destination_node)
        return error.DestinationMismatch;
    const valid = sign.verifyCtx(consume_sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
}

fn readClaim(reader: *Reader) DecodeError!Claim {
    if (!std.mem.eql(u8, try reader.take(claim_magic.len), &claim_magic))
        return error.BadMagic;
    const kind: ClaimKind = switch (try reader.readByte()) {
        1 => .create_new,
        2 => .exact_restore,
        else => return error.InvalidClaim,
    };
    const account_len: usize = try reader.readByte();
    if (account_len > max_account_len) return error.TooLong;
    const account = try reader.take(account_len);
    const group_token = (try reader.take(@sizeOf(GroupToken)))[0..@sizeOf(GroupToken)].*;
    const attachment_raw = (try reader.take(@sizeOf(AttachmentId)))[0..@sizeOf(AttachmentId)].*;
    const attachment_id = AttachmentId.fromBytes(attachment_raw) catch return error.InvalidClaim;
    const claim = Claim{
        .kind = kind,
        .account = account,
        .group_token = group_token,
        .attachment_id = attachment_id,
        .origin_node = try reader.readU64(),
        .destination_node = try reader.readU64(),
        .issued_at_ms = try reader.readI64(),
        .expires_at_ms = try reader.readI64(),
        .nonce = try reader.readU64(),
    };
    validateShape(claim) catch |err| return switch (err) {
        error.TooLong => error.TooLong,
        else => error.InvalidClaim,
    };
    return claim;
}

fn validateShape(claim: Claim) error{ InvalidClaim, TooLong }!void {
    if (claim.account.len > max_account_len) return error.TooLong;
    if (!validAccount(claim.account) or
        std.mem.allEqual(u8, &claim.group_token, 0) or
        claim.attachment_id.isZero() or
        claim.origin_node == 0 or
        claim.destination_node == 0 or
        claim.nonce == 0 or
        claim.issued_at_ms < 0 or
        claim.expires_at_ms < claim.issued_at_ms) return error.InvalidClaim;
}

fn validAccount(account: []const u8) bool {
    if (account.len == 0 or account.len > max_account_len) return false;
    for (account) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

pub fn validateAt(claim: Claim, now_ms: i64, cfg: Config) AdmissionError!void {
    if (now_ms < 0 or claim.issued_at_ms < 0 or claim.expires_at_ms < claim.issued_at_ms)
        return error.InvalidLifetime;
    if (@as(i128, claim.expires_at_ms) - @as(i128, claim.issued_at_ms) > @as(i128, cfg.max_lifetime_ms))
        return error.InvalidLifetime;
    if (@as(i128, claim.issued_at_ms) > @as(i128, now_ms) + @as(i128, cfg.max_future_skew_ms))
        return error.FutureSkew;
    if (now_ms > claim.expires_at_ms) return error.Expired;
}

pub const ClaimDecision = enum {
    create_new,
    restore_exact,
    deny_replay,
    deny_wrong_destination,
    deny_attachment_collision,
    deny_attachment_missing,
};

/// Decide a verified claim without ambiguous fallback between create and exact
/// restore. Only a successful action may subsequently emit/record a consume.
pub fn decideClaim(
    claim: Claim,
    local_node: NodeId,
    attachment_exists: bool,
    replayed: bool,
    now_ms: i64,
    cfg: Config,
) AdmissionError!ClaimDecision {
    try validateAt(claim, now_ms, cfg);
    if (local_node != claim.destination_node) return .deny_wrong_destination;
    if (replayed) return .deny_replay;
    return switch (claim.kind) {
        .create_new => if (attachment_exists) .deny_attachment_collision else .create_new,
        .exact_restore => if (attachment_exists) .restore_exact else .deny_attachment_missing,
    };
}

pub const ReplayKey = struct {
    group_token: GroupToken,
    attachment_id: AttachmentId,
    origin_node: NodeId,
    nonce: u64,
};

pub const ReplayRecord = struct {
    destination_node: NodeId,
    expires_at_ms: i64,
    digest: Digest,
    conflicted: bool,
    wire: []u8,
};

pub const ApplyDisposition = enum {
    inserted,
    duplicate,
    conflict,
    conflict_replaced,
};

pub const ApplyError = VerifyError || AdmissionError || error{Capacity} || std.mem.Allocator.Error;

pub const ReplayStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    records: std.AutoHashMap(ReplayKey, ReplayRecord),

    pub fn init(allocator: std.mem.Allocator, cfg: Config) ReplayStore {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .records = std.AutoHashMap(ReplayKey, ReplayRecord).init(allocator),
        };
    }

    pub fn deinit(self: *ReplayStore) void {
        var values = self.records.valueIterator();
        while (values.next()) |record| self.allocator.free(record.wire);
        self.records.deinit();
        self.* = undefined;
    }

    /// Record one verified successful consume. Failed allocation does not burn
    /// the replay key; a caller may retry the same signed consume safely.
    pub fn applySignedConsume(
        self: *ReplayStore,
        signed: SignedConsume,
        now_ms: i64,
    ) ApplyError!ApplyDisposition {
        try verifyConsume(signed);
        try validateAt(signed.claim.claim, now_ms, self.cfg);
        const key = replayKey(signed.claim.claim);
        const digest = digestBytes(signed.wire);
        if (self.records.getPtr(key)) |current| {
            if (std.crypto.timing_safe.eql(Digest, current.digest, digest)) return .duplicate;
            const replay_until_ms = @max(current.expires_at_ms, signed.claim.claim.expires_at_ms);
            if (digestLess(digest, current.digest)) {
                const owned = try self.allocator.dupe(u8, signed.wire);
                self.allocator.free(current.wire);
                current.* = makeRecord(signed, digest, true, owned);
                current.expires_at_ms = replay_until_ms;
                return .conflict_replaced;
            }
            current.conflicted = true;
            current.expires_at_ms = replay_until_ms;
            return .conflict;
        }
        if (self.records.count() >= self.cfg.max_entries) return error.Capacity;
        const owned = try self.allocator.dupe(u8, signed.wire);
        errdefer self.allocator.free(owned);
        try self.records.put(key, makeRecord(signed, digest, false, owned));
        return .inserted;
    }

    pub fn isConsumed(
        self: *const ReplayStore,
        group_token: GroupToken,
        attachment_id: AttachmentId,
        origin_node: NodeId,
        nonce: u64,
    ) bool {
        var it = @constCast(&self.records).iterator();
        while (it.next()) |slot| {
            if (slot.key_ptr.origin_node == origin_node and
                slot.key_ptr.nonce == nonce and
                std.crypto.timing_safe.eql(GroupToken, slot.key_ptr.group_token, group_token) and
                slot.key_ptr.attachment_id.eql(attachment_id)) return true;
        }
        return false;
    }

    pub fn sweepExpired(self: *ReplayStore, now_ms: i64) void {
        while (true) {
            var removed = false;
            var it = self.records.iterator();
            while (it.next()) |slot| {
                if (now_ms <= slot.value_ptr.expires_at_ms) continue;
                self.allocator.free(slot.value_ptr.wire);
                self.records.removeByPtr(slot.key_ptr);
                removed = true;
                break;
            }
            if (!removed) break;
        }
    }
};

fn replayKey(claim: Claim) ReplayKey {
    return .{
        .group_token = claim.group_token,
        .attachment_id = claim.attachment_id,
        .origin_node = claim.origin_node,
        .nonce = claim.nonce,
    };
}

fn makeRecord(signed: SignedConsume, digest: Digest, conflicted: bool, wire: []u8) ReplayRecord {
    return .{
        .destination_node = signed.claim.claim.destination_node,
        .expires_at_ms = signed.claim.claim.expires_at_ms,
        .digest = digest,
        .conflicted = conflicted,
        .wire = wire,
    };
}

fn signedWireBound(
    wire: []const u8,
    transcript: []const u8,
    signer: sign.PublicKey,
    signature: sign.Signature,
) bool {
    if (wire.len != transcript.len + signature_wire_len) return false;
    return std.mem.eql(u8, wire[0..transcript.len], transcript) and
        std.mem.eql(u8, wire[transcript.len..][0..sign.public_key_len], &signer) and
        std.mem.eql(u8, wire[transcript.len + sign.public_key_len ..], &signature);
}

fn claimEql(a: Claim, b: Claim) bool {
    return a.kind == b.kind and
        std.mem.eql(u8, a.account, b.account) and
        std.crypto.timing_safe.eql(GroupToken, a.group_token, b.group_token) and
        a.attachment_id.eql(b.attachment_id) and
        a.origin_node == b.origin_node and
        a.destination_node == b.destination_node and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms and
        a.nonce == b.nonce;
}

fn digestBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.Blake3.hash(bytes, &digest, .{});
    return digest;
}

fn digestLess(a: Digest, b: Digest) bool {
    return std.mem.order(u8, &a, &b) == .lt;
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

    fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
    }

    fn writeI64(self: *Writer, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .big);
        self.pos += 8;
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

    fn readU64(self: *Reader) DecodeError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    fn readI64(self: *Reader) DecodeError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
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

fn testClaim(origin: NodeId, destination: NodeId, attachment_id: AttachmentId) Claim {
    return .{
        .kind = .exact_restore,
        .account = "alice",
        .group_token = @splat(0x44),
        .attachment_id = attachment_id,
        .origin_node = origin,
        .destination_node = destination,
        .issued_at_ms = 1000,
        .expires_at_ms = 2000,
        .nonce = 0x0102_0304_0506_0708,
    };
}

test "SRM2 deterministic claim and consume vectors round trip" {
    const testing = std.testing;
    var origin_key = try testKey(21);
    defer origin_key.deinit();
    var destination_key = try testKey(22);
    defer destination_key.deinit();
    const claim = testClaim(
        signed_frame.originShortId(origin_key.public_key),
        signed_frame.originShortId(destination_key.public_key),
        try testAttachment(1),
    );
    const claim_wire = try encodeClaim(testing.allocator, claim, &origin_key);
    defer testing.allocator.free(claim_wire);
    const signed_claim = try decodeClaim(claim_wire);
    try verifyClaim(signed_claim);
    try testing.expect(claimEql(claim, signed_claim.claim));
    const consume_wire = try encodeConsume(testing.allocator, signed_claim, &destination_key);
    defer testing.allocator.free(consume_wire);
    const signed_consume = try decodeConsume(consume_wire);
    try verifyConsume(signed_consume);
    try testing.expect(claimEql(claim, signed_consume.claim.claim));

    try testing.expectEqualStrings(
        "3060deee227454b0aac36a47bd1423cac2157ffa15a798177fab1253d9a999f3",
        &std.fmt.bytesToHex(digestBytes(claim_wire), .lower),
    );
    try testing.expectEqualStrings(
        "4b8c9485bff31ce19b9fb5abaca4fd637ecc9a044c27045b292eb765caa2a6ae",
        &std.fmt.bytesToHex(digestBytes(consume_wire), .lower),
    );
}

test "SRM2 tamper detached wire and cross domain fail closed" {
    const testing = std.testing;
    var origin_key = try testKey(23);
    defer origin_key.deinit();
    var destination_key = try testKey(24);
    defer destination_key.deinit();
    const claim_wire = try encodeClaim(testing.allocator, testClaim(
        signed_frame.originShortId(origin_key.public_key),
        signed_frame.originShortId(destination_key.public_key),
        try testAttachment(2),
    ), &origin_key);
    defer testing.allocator.free(claim_wire);
    const signed_claim = try decodeClaim(claim_wire);
    const consume_wire = try encodeConsume(testing.allocator, signed_claim, &destination_key);
    defer testing.allocator.free(consume_wire);
    try testing.expectError(error.BadMagic, decodeClaim(consume_wire));
    try testing.expectError(error.BadMagic, decodeConsume(claim_wire));
    const wrong_domain = sign.verifyCtx(consume_sign_domain, signed_claim.transcript, signed_claim.signature, signed_claim.signer) catch false;
    try testing.expect(!wrong_domain);

    var tampered = try testing.allocator.dupe(u8, claim_wire);
    defer testing.allocator.free(tampered);
    tampered[claim_magic.len + 2] = 'b';
    try testing.expectError(error.BadSignature, verifyClaim(try decodeClaim(tampered)));
    var detached = signed_claim;
    detached.wire = consume_wire;
    try testing.expectError(error.TranscriptMismatch, verifyClaim(detached));

    var tampered_consume = try testing.allocator.dupe(u8, consume_wire);
    defer testing.allocator.free(tampered_consume);
    tampered_consume[tampered_consume.len - 1] ^= 1;
    try testing.expectError(error.BadSignature, verifyConsume(try decodeConsume(tampered_consume)));
}

test "SRM2 create and exact restore never fall through and SRM1 is rejected" {
    const testing = std.testing;
    var origin_key = try testKey(25);
    defer origin_key.deinit();
    var destination_key = try testKey(26);
    defer destination_key.deinit();
    var claim = testClaim(
        signed_frame.originShortId(origin_key.public_key),
        signed_frame.originShortId(destination_key.public_key),
        try testAttachment(3),
    );
    try testing.expectEqual(ClaimDecision.restore_exact, try decideClaim(claim, claim.destination_node, true, false, 1000, .{}));
    try testing.expectEqual(ClaimDecision.deny_attachment_missing, try decideClaim(claim, claim.destination_node, false, false, 1000, .{}));
    claim.kind = .create_new;
    try testing.expectEqual(ClaimDecision.create_new, try decideClaim(claim, claim.destination_node, false, false, 1000, .{}));
    try testing.expectEqual(ClaimDecision.deny_attachment_collision, try decideClaim(claim, claim.destination_node, true, false, 1000, .{}));
    try testing.expectEqual(ClaimDecision.deny_wrong_destination, try decideClaim(claim, claim.destination_node + 1, false, false, 1000, .{}));
    try testing.expectEqual(ClaimDecision.deny_replay, try decideClaim(claim, claim.destination_node, false, true, 1000, .{}));

    // The deployed SRM1 byte magic is rejected. Only an adapter outside this
    // module may mint a fresh attachment and map its verified semantics to
    // create_new; there is intentionally no legacy decoder/fallback here.
    var legacy: [min_claim_wire_len]u8 = @splat(0);
    legacy[0..4].* = .{ 'S', 'R', 'M', 1 };
    try testing.expectError(error.BadMagic, decodeClaim(&legacy));
}

test "SRM2 strict decode rejects truncation trailing malformed and zero fields" {
    const testing = std.testing;
    var origin_key = try testKey(27);
    defer origin_key.deinit();
    var destination_key = try testKey(28);
    defer destination_key.deinit();
    const claim = testClaim(
        signed_frame.originShortId(origin_key.public_key),
        signed_frame.originShortId(destination_key.public_key),
        try testAttachment(4),
    );
    const claim_wire = try encodeClaim(testing.allocator, claim, &origin_key);
    defer testing.allocator.free(claim_wire);
    const consume_wire = try encodeConsume(testing.allocator, try decodeClaim(claim_wire), &destination_key);
    defer testing.allocator.free(consume_wire);
    for (0..claim_wire.len) |end| try testing.expectError(error.Truncated, decodeClaim(claim_wire[0..end]));
    for (0..consume_wire.len) |end| {
        const result = decodeConsume(consume_wire[0..end]);
        if (result) |_| return error.TestUnexpectedResult else |err| switch (err) {
            error.Truncated, error.InvalidConsume => {},
            else => return err,
        }
    }

    const trailing_claim = try std.mem.concat(testing.allocator, u8, &.{ claim_wire, "x" });
    defer testing.allocator.free(trailing_claim);
    try testing.expectError(error.TrailingBytes, decodeClaim(trailing_claim));
    const trailing_consume = try std.mem.concat(testing.allocator, u8, &.{ consume_wire, "x" });
    defer testing.allocator.free(trailing_consume);
    try testing.expectError(error.TrailingBytes, decodeConsume(trailing_consume));

    const account_offset = claim_magic.len + 1 + 1;
    const token_offset = account_offset + claim.account.len;
    const attachment_offset = token_offset + @sizeOf(GroupToken);
    const origin_offset = attachment_offset + @sizeOf(AttachmentId);
    const destination_offset = origin_offset + 8;
    const nonce_offset = destination_offset + 8 + 8 + 8;
    const Mutate = struct {
        fn expectInvalid(allocator: std.mem.Allocator, original: []const u8, offset: usize, len: usize) !void {
            var copy = try allocator.dupe(u8, original);
            defer allocator.free(copy);
            @memset(copy[offset .. offset + len], 0);
            try testing.expectError(error.InvalidClaim, decodeClaim(copy));
        }
    };
    try Mutate.expectInvalid(testing.allocator, claim_wire, token_offset, @sizeOf(GroupToken));
    try Mutate.expectInvalid(testing.allocator, claim_wire, attachment_offset, @sizeOf(AttachmentId));
    try Mutate.expectInvalid(testing.allocator, claim_wire, origin_offset, 8);
    try Mutate.expectInvalid(testing.allocator, claim_wire, destination_offset, 8);
    try Mutate.expectInvalid(testing.allocator, claim_wire, nonce_offset, 8);

    var bad_kind = try testing.allocator.dupe(u8, claim_wire);
    defer testing.allocator.free(bad_kind);
    bad_kind[claim_magic.len] = 3;
    try testing.expectError(error.InvalidClaim, decodeClaim(bad_kind));
    var empty_account = try testing.allocator.dupe(u8, claim_wire);
    defer testing.allocator.free(empty_account);
    empty_account[claim_magic.len + 1] = 0;
    try testing.expectError(error.InvalidClaim, decodeClaim(empty_account));
    var too_long = try testing.allocator.dupe(u8, claim_wire);
    defer testing.allocator.free(too_long);
    too_long[claim_magic.len + 1] = max_account_len + 1;
    try testing.expectError(error.TooLong, decodeClaim(too_long));
    var invalid_account = claim;
    invalid_account.account = "bad account";
    try testing.expectError(error.InvalidClaim, encodeClaim(testing.allocator, invalid_account, &origin_key));
}

test "SRM2 account time lifetime and skew boundaries are exact" {
    const testing = std.testing;
    var origin_key = try testKey(29);
    defer origin_key.deinit();
    var destination_key = try testKey(30);
    defer destination_key.deinit();
    var claim = testClaim(
        signed_frame.originShortId(origin_key.public_key),
        signed_frame.originShortId(destination_key.public_key),
        try testAttachment(5),
    );
    const account = try testing.allocator.alloc(u8, max_account_len);
    defer testing.allocator.free(account);
    @memset(account, 'a');
    claim.account = account;
    const boundary_wire = try encodeClaim(testing.allocator, claim, &origin_key);
    defer testing.allocator.free(boundary_wire);
    try verifyClaim(try decodeClaim(boundary_wire));
    const too_long = try testing.allocator.alloc(u8, max_account_len + 1);
    defer testing.allocator.free(too_long);
    claim.account = too_long;
    try testing.expectError(error.TooLong, encodeClaim(testing.allocator, claim, &origin_key));

    claim.account = "alice";
    const cfg = Config{ .max_lifetime_ms = 100, .max_future_skew_ms = 10 };
    claim.issued_at_ms = 1010;
    claim.expires_at_ms = 1110;
    try validateAt(claim, 1000, cfg);
    try validateAt(claim, 1110, cfg);
    try testing.expectError(error.Expired, validateAt(claim, 1111, cfg));
    claim.issued_at_ms = 1011;
    claim.expires_at_ms = 1111;
    try testing.expectError(error.FutureSkew, validateAt(claim, 1000, cfg));
    claim.issued_at_ms = 1000;
    claim.expires_at_ms = 1101;
    try testing.expectError(error.InvalidLifetime, validateAt(claim, 1000, cfg));
}

test "SRM2 replay key isolates attachments and conflict permutations converge" {
    const testing = std.testing;
    var origin_key = try testKey(31);
    defer origin_key.deinit();
    var destination_a_key = try testKey(32);
    defer destination_a_key.deinit();
    var destination_b_key = try testKey(33);
    defer destination_b_key.deinit();
    const origin = signed_frame.originShortId(origin_key.public_key);
    const destination_a = signed_frame.originShortId(destination_a_key.public_key);
    const destination_b = signed_frame.originShortId(destination_b_key.public_key);
    const attachment_a = try testAttachment(6);
    const attachment_b = try testAttachment(7);
    const claim_a = testClaim(origin, destination_a, attachment_a);
    var claim_b = testClaim(origin, destination_a, attachment_b);
    claim_b.expires_at_ms = 3000;
    const claim_a_wire = try encodeClaim(testing.allocator, claim_a, &origin_key);
    defer testing.allocator.free(claim_a_wire);
    const claim_b_wire = try encodeClaim(testing.allocator, claim_b, &origin_key);
    defer testing.allocator.free(claim_b_wire);
    const consume_a_wire = try encodeConsume(testing.allocator, try decodeClaim(claim_a_wire), &destination_a_key);
    defer testing.allocator.free(consume_a_wire);
    const consume_b_wire = try encodeConsume(testing.allocator, try decodeClaim(claim_b_wire), &destination_a_key);
    defer testing.allocator.free(consume_b_wire);
    var store = ReplayStore.init(testing.allocator, .{});
    defer store.deinit();
    try testing.expectEqual(ApplyDisposition.inserted, try store.applySignedConsume(try decodeConsume(consume_a_wire), 1000));
    try testing.expectEqual(ApplyDisposition.duplicate, try store.applySignedConsume(try decodeConsume(consume_a_wire), 1000));
    try testing.expectEqual(ApplyDisposition.inserted, try store.applySignedConsume(try decodeConsume(consume_b_wire), 1000));
    try testing.expect(store.isConsumed(claim_a.group_token, attachment_a, origin, claim_a.nonce));
    try testing.expect(store.isConsumed(claim_b.group_token, attachment_b, origin, claim_b.nonce));
    store.sweepExpired(2001);
    try testing.expect(!store.isConsumed(claim_a.group_token, attachment_a, origin, claim_a.nonce));
    try testing.expect(store.isConsumed(claim_b.group_token, attachment_b, origin, claim_b.nonce));

    // Same replay key, origin and nonce, but two destination-bound claims are
    // authenticated equivocation. Reverse arrival must retain the same digest.
    var competing = claim_a;
    competing.destination_node = destination_b;
    competing.expires_at_ms = 3000;
    const competing_claim_wire = try encodeClaim(testing.allocator, competing, &origin_key);
    defer testing.allocator.free(competing_claim_wire);
    const competing_consume_wire = try encodeConsume(testing.allocator, try decodeClaim(competing_claim_wire), &destination_b_key);
    defer testing.allocator.free(competing_consume_wire);
    const signed_a = try decodeConsume(consume_a_wire);
    const signed_competing = try decodeConsume(competing_consume_wire);
    var left = ReplayStore.init(testing.allocator, .{});
    defer left.deinit();
    _ = try left.applySignedConsume(signed_a, 1000);
    _ = try left.applySignedConsume(signed_competing, 1000);
    var right = ReplayStore.init(testing.allocator, .{});
    defer right.deinit();
    _ = try right.applySignedConsume(signed_competing, 1000);
    _ = try right.applySignedConsume(signed_a, 1000);
    const key = replayKey(claim_a);
    const left_record = left.records.get(key).?;
    const right_record = right.records.get(key).?;
    try testing.expect(left_record.conflicted);
    try testing.expect(right_record.conflicted);
    try testing.expectEqual(@as(i64, 3000), left_record.expires_at_ms);
    try testing.expectEqual(@as(i64, 3000), right_record.expires_at_ms);
    try testing.expectEqual(left_record.digest, right_record.digest);
    try testing.expectEqualSlices(u8, left_record.wire, right_record.wire);
    left.sweepExpired(2001);
    try testing.expect(left.isConsumed(claim_a.group_token, attachment_a, origin, claim_a.nonce));
    left.sweepExpired(3001);
    try testing.expect(!left.isConsumed(claim_a.group_token, attachment_a, origin, claim_a.nonce));
}

test "SRM2 replay capacity and allocation failure never burn a consume" {
    const testing = std.testing;
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var origin_key = try testKey(34);
            defer origin_key.deinit();
            var destination_key = try testKey(35);
            defer destination_key.deinit();
            const attachment_id = try testAttachment(8);
            const claim = testClaim(
                signed_frame.originShortId(origin_key.public_key),
                signed_frame.originShortId(destination_key.public_key),
                attachment_id,
            );
            const claim_wire = try encodeClaim(allocator, claim, &origin_key);
            defer allocator.free(claim_wire);
            const consume_wire = try encodeConsume(allocator, try decodeClaim(claim_wire), &destination_key);
            defer allocator.free(consume_wire);
            const signed = try decodeConsume(consume_wire);
            var store = ReplayStore.init(allocator, .{ .max_entries = 1 });
            defer store.deinit();
            _ = store.applySignedConsume(signed, 1000) catch |err| {
                try testing.expect(!store.isConsumed(claim.group_token, attachment_id, claim.origin_node, claim.nonce));
                return err;
            };
            try testing.expect(store.isConsumed(claim.group_token, attachment_id, claim.origin_node, claim.nonce));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});

    var origin_key = try testKey(36);
    defer origin_key.deinit();
    var destination_key = try testKey(37);
    defer destination_key.deinit();
    const origin = signed_frame.originShortId(origin_key.public_key);
    const destination = signed_frame.originShortId(destination_key.public_key);
    const first = testClaim(origin, destination, try testAttachment(9));
    var second = testClaim(origin, destination, try testAttachment(10));
    second.nonce += 1;
    const first_claim_wire = try encodeClaim(testing.allocator, first, &origin_key);
    defer testing.allocator.free(first_claim_wire);
    const second_claim_wire = try encodeClaim(testing.allocator, second, &origin_key);
    defer testing.allocator.free(second_claim_wire);
    const first_consume_wire = try encodeConsume(testing.allocator, try decodeClaim(first_claim_wire), &destination_key);
    defer testing.allocator.free(first_consume_wire);
    const second_consume_wire = try encodeConsume(testing.allocator, try decodeClaim(second_claim_wire), &destination_key);
    defer testing.allocator.free(second_consume_wire);
    var bounded = ReplayStore.init(testing.allocator, .{ .max_entries = 1 });
    defer bounded.deinit();
    _ = try bounded.applySignedConsume(try decodeConsume(first_consume_wire), 1000);
    try testing.expectError(error.Capacity, bounded.applySignedConsume(try decodeConsume(second_consume_wire), 1000));
    try testing.expect(!bounded.isConsumed(second.group_token, second.attachment_id, second.origin_node, second.nonce));
}
