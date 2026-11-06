// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! `SESSION REVOKE group=<id> attachment=<id>` — revoke exactly one physical
//! attachment shown by `SESSION LIST MESH`, even when its origin node is not
//! this node, without disturbing any other attachment of the same reusable
//! logical session.
//!
//! This module is pure: no sockets, no `server.zig` import. It owns:
//!
//!   * `parseCommand`, an exact-grammar pre-filter in front of
//!     `session_sid.parseCommand`. It recognizes only the complete
//!     `REVOKE group=<32hex> attachment=<32hex>` form and returns `null` for
//!     every other input (including a bare `REVOKE group=...`, a nickname, or
//!     `ALL`), so `session_sid.parseCommand` remains the single authority for
//!     every other SESSION subcommand and every other malformed REVOKE;
//!   * `Resolver`, which accumulates `helix/session_replica.zig` inventory
//!     pages and resolves a `(group, attachment)` selector to at most one
//!     physical row, failing closed on any corruption (two tokens sharing one
//!     attachment id) or a group that does not match the requested one;
//!   * the signed `SAR1` cross-node revoke request, whose signer must be a
//!     configured mesh node. `target_origin` is the node the requester saw
//!     owning the row; it is a routing hint only, because an attachment id
//!     is stable across node moves and Helix, so whichever node holds the
//!     exact live row when the request arrives is the one that drops it;
//!   * `ReplayGuard`, a bounded idempotency set over `(requester_node,
//!     sequence)` bound to the signed transcript digest, so a retried request
//!     is a no-op and the same sequence over different content is reported
//!     as equivocation instead of being silently accepted or ignored;
//!   * `Denials`, a bounded `(token, attachment_id)` fence. `gateAttach`
//!     refuses resuming or mesh-reclaiming the exact revoked pair, and also
//!     refuses every admission that would bind a NEWLY minted attachment to
//!     a token with a live denial (bare-token resume, `join_existing`,
//!     legacy token reclaim). The reusable token is shared by every sibling
//!     and an attachment id is not a credential, so without that second rule
//!     the revoked device could rejoin the same logical session under a fresh
//!     attachment id. Exact resume of every OTHER attachment stays allowed;
//!   * per-account quotas in both tables (keyed by `accountKey`), so one
//!     account churning throwaway attachments exhausts only its own share and
//!     never blocks revocation for a different account;
//!   * `originDecision`, the fail-closed decision a receiving node makes
//!     before dropping a row named by an inbound signed request, and `admit`,
//!     the allocation-free transaction that applies it to `ReplayGuard` and
//!     `Denials` without consuming replay identity on any failure.
//!
//! Both tables, plus the bounded `Retained` retransmission ring, are bundled
//! in `NodeState`. It is in memory only across a cold restart. Helix carries
//! it through the strict `SARS` checkpoint (`encodeCheckpoint` /
//! `decodeCheckpoint`): the fence is security state, so a sequential upgrade
//! must not reopen the bare-token rejoin path or forget an unfinished close.

const std = @import("std");

const session_sid = @import("session_sid.zig");
const session_replica = @import("helix/session_replica.zig");
const sign = @import("../crypto/sign.zig");
const mesh_clock = @import("../substrate/undertow/mesh_clock.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

// ---------------------------------------------------------------------------
// Command grammar
// ---------------------------------------------------------------------------

/// Both fields are copied verbatim from one `SESSION LIST MESH` row; a
/// nickname or any other free-form text is never accepted in either slot.
pub const Selector = struct {
    group: session_sid.Sid,
    attachment_id: [16]u8,
};

const group_prefix = "group=";
const attachment_prefix = "attachment=";

/// Recognize only `REVOKE group=<32hex> attachment=<32hex>`, in that exact
/// order, with no extra parameters. Everything else — a bare
/// `REVOKE group=<id>` (logical-group revoke; `session_sid` owns that),
/// `ALL`, a nickname, a short/zero/non-hex id, or trailing parameters —
/// returns `null` so the caller falls through to `session_sid.parseCommand`,
/// which remains authoritative for every other SESSION subcommand and every
/// other malformed REVOKE.
pub fn parseCommand(params: []const []const u8) ?Selector {
    if (params.len != 3) return null;
    if (!std.ascii.eqlIgnoreCase(params[0], "REVOKE")) return null;
    const group_param = params[1];
    const attachment_param = params[2];
    if (!std.mem.startsWith(u8, group_param, group_prefix) or
        group_param.len != group_prefix.len + session_sid.sid_hex_len) return null;
    if (!std.mem.startsWith(u8, attachment_param, attachment_prefix) or
        attachment_param.len != attachment_prefix.len + session_sid.sid_hex_len) return null;

    var group: session_sid.Sid = undefined;
    _ = std.fmt.hexToBytes(&group, group_param[group_prefix.len..]) catch return null;
    if (session_sid.isZeroSid(group)) return null;

    var attachment_id: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&attachment_id, attachment_param[attachment_prefix.len..]) catch return null;
    if (isZero16(attachment_id)) return null;

    return .{ .group = group, .attachment_id = attachment_id };
}

fn isZero16(bytes: [16]u8) bool {
    return std.mem.allEqual(u8, &bytes, 0);
}

// ---------------------------------------------------------------------------
// Resolver: selector -> at most one physical row across paged inventory
// ---------------------------------------------------------------------------

pub const Attachment = struct {
    token: session_replica.Token,
    origin_node: session_replica.NodeId,
    attachment_id: [16]u8,
};

pub const Resolution = union(enum) {
    none,
    unique: Attachment,
    ambiguous,
    revoked,
    group_mismatch,
};

/// Feed every page returned by `Store.accountInventoryPageInto` (or an
/// equivalent batch call) through `consider`, in any order, then call
/// `resolve` once after the final page. Corrupt input (the exact attachment
/// id attached under two different tokens) fails closed to `.ambiguous`
/// regardless of which, if either, row's derived group matches the selector.
pub const Resolver = struct {
    selector: Selector,
    matched: ?Attachment = null,
    ambiguous: bool = false,
    revoked_seen: bool = false,

    pub fn init(selector: Selector) Resolver {
        return .{ .selector = selector };
    }

    pub fn consider(self: *Resolver, rows: []const session_replica.InventoryRow) void {
        for (rows) |row| {
            if (row.revoked) {
                if (session_sid.eql(session_sid.deriveGroup(row.token), self.selector.group)) self.revoked_seen = true;
                continue;
            }
            const aid = row.attachment_id orelse continue;
            if (!std.crypto.timing_safe.eql([16]u8, aid, self.selector.attachment_id)) continue;
            if (self.matched) |existing| {
                if (!std.crypto.timing_safe.eql(session_replica.Token, existing.token, row.token) or
                    existing.origin_node != row.origin_node) self.ambiguous = true;
                continue;
            }
            self.matched = .{ .token = row.token, .origin_node = row.origin_node, .attachment_id = aid };
        }
    }

    pub fn resolve(self: *const Resolver) Resolution {
        if (self.ambiguous) return .ambiguous;
        if (self.matched) |value| {
            if (!session_sid.eql(session_sid.deriveGroup(value.token), self.selector.group)) return .group_mismatch;
            return .{ .unique = value };
        }
        if (self.revoked_seen) return .revoked;
        return .none;
    }
};

// ---------------------------------------------------------------------------
// Signed cross-node request: magic "SAR1", domain
// "onyx/session-attachment-revoke/v1"
// ---------------------------------------------------------------------------

pub const magic = [_]u8{ 'S', 'A', 'R', '1' };
pub const sign_domain = "onyx/session-attachment-revoke/v1";

pub const max_account_len: usize = 128;
/// A request is a short-lived forwarded command, not a durable fact; bound
/// its own claimed lifetime well below any mesh reclaim/resume TTL so a lost
/// forward cannot be replayed far into the future.
pub const max_request_ttl_ms: u64 = 10 * 60 * 1000;
pub const max_future_skew_ms: u64 = mesh_clock.default_max_future_skew_ms;

const signature_wire_len: usize = sign.public_key_len + sign.signature_len;
const fixed_len: usize = magic.len + 2 + 16 + 16 + 8 + 8 + 8 + 8 + 8;

comptime {
    // Generous sanity bound: catches an accidental unbounded growth of this
    // wire shape without tying this leaf to any transport frame constant.
    std.debug.assert(fixed_len + max_account_len + signature_wire_len <= 1024);
}

pub const Request = struct {
    account: []const u8,
    token: [16]u8,
    attachment_id: [16]u8,
    target_origin: u64,
    requester_node: u64,
    requester_sequence: u64,
    issued_at_ms: i64,
    expires_at_ms: i64,
};

/// Decoded signed request. Variable fields and `transcript`/`wire` borrow the
/// input bytes.
pub const SignedRequest = struct {
    request: Request,
    signer: sign.PublicKey,
    signature: sign.Signature,
    transcript: []const u8,
    wire: []const u8,
};

pub const EncodeError = error{
    InvalidRequest,
    InvalidLifetime,
    TooLong,
    OriginMismatch,
} || std.mem.Allocator.Error || sign.SignError;

pub const DecodeError = error{
    BadMagic,
    InvalidRequest,
    InvalidLifetime,
    TooLong,
    Truncated,
    TrailingBytes,
};

pub const VerifyError = error{
    BadSignature,
    OriginMismatch,
    TranscriptMismatch,
    Expired,
    FutureSkew,
};

/// Inspect only the outer magic. Never treat a magic match as proof of any
/// other property; callers must still `decodeRequest` + `verifyRequest`.
pub fn hasMagic(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn encodeRequest(allocator: std.mem.Allocator, value: Request, kp: *const sign.KeyPair) EncodeError![]u8 {
    try validateRequestShape(value);
    try requireSigner(value.requester_node, kp.public_key);

    const transcript_len = fixed_len + value.account.len;
    var wire = try allocator.alloc(u8, transcript_len + signature_wire_len);
    errdefer allocator.free(wire);

    var writer = Writer{ .bytes = wire };
    writer.writeBytes(&magic);
    writer.writeU16(@intCast(value.account.len));
    writer.writeBytes(&value.token);
    writer.writeBytes(&value.attachment_id);
    writer.writeU64(value.target_origin);
    writer.writeU64(value.requester_node);
    writer.writeU64(value.requester_sequence);
    writer.writeI64(value.issued_at_ms);
    writer.writeI64(value.expires_at_ms);
    writer.writeBytes(value.account);
    std.debug.assert(writer.pos == transcript_len);

    const signature = try kp.signCtx(sign_domain, wire[0..transcript_len]);
    writer.writeBytes(&kp.public_key);
    writer.writeBytes(&signature);
    std.debug.assert(writer.pos == wire.len);
    return wire;
}

pub fn decodeRequest(wire: []const u8) DecodeError!SignedRequest {
    var reader = Reader{ .bytes = wire };
    const value = try readRequest(&reader);
    const transcript_end = reader.pos;
    const signer = (try reader.take(sign.public_key_len))[0..sign.public_key_len].*;
    const signature = (try reader.take(sign.signature_len))[0..sign.signature_len].*;
    if (reader.pos != wire.len) return error.TrailingBytes;
    return .{
        .request = value,
        .signer = signer,
        .signature = signature,
        .transcript = wire[0..transcript_end],
        .wire = wire,
    };
}

/// Verify the signature, the exact transcript projection, signer
/// self-certification against the claimed `requester_node`, and the request's
/// own time window against `now_ms`. Does not check mesh-node trust; see
/// `authorize`.
pub fn verifyRequest(signed: SignedRequest, now_ms: i64) VerifyError!void {
    const expected_wire_len = signed.transcript.len + signature_wire_len;
    if (signed.wire.len != expected_wire_len or
        !std.mem.eql(u8, signed.wire[0..signed.transcript.len], signed.transcript) or
        !std.mem.eql(u8, signed.wire[signed.transcript.len..][0..sign.public_key_len], &signed.signer) or
        !std.mem.eql(u8, signed.wire[signed.transcript.len + sign.public_key_len ..], &signed.signature))
        return error.TranscriptMismatch;
    var reader = Reader{ .bytes = signed.transcript };
    const projected = readRequest(&reader) catch return error.TranscriptMismatch;
    if (reader.pos != signed.transcript.len or !requestEql(projected, signed.request)) return error.TranscriptMismatch;
    if (signed_frame.originShortId(signed.signer) != signed.request.requester_node) return error.OriginMismatch;
    const valid = sign.verifyCtx(sign_domain, signed.transcript, signed.signature, signed.signer) catch false;
    if (!valid) return error.BadSignature;
    // Inclusive bound: `ReplayGuard` frees a slot at exactly `expires_at_ms`,
    // so accepting that instant would admit the same signed bytes twice.
    if (now_ms >= signed.request.expires_at_ms) return error.Expired;
    if (signed.request.issued_at_ms > now_ms +| @as(i64, @intCast(max_future_skew_ms))) return error.FutureSkew;
}

fn readRequest(reader: *Reader) DecodeError!Request {
    if (!std.mem.eql(u8, try reader.take(magic.len), &magic)) return error.BadMagic;
    const account_len = try reader.readU16();
    if (account_len > max_account_len) return error.TooLong;
    const token = (try reader.take(16))[0..16].*;
    const attachment_id = (try reader.take(16))[0..16].*;
    const target_origin = try reader.readU64();
    const requester_node = try reader.readU64();
    const requester_sequence = try reader.readU64();
    const issued_at_ms = try reader.readI64();
    const expires_at_ms = try reader.readI64();
    const account = try reader.take(account_len);
    const value = Request{
        .account = account,
        .token = token,
        .attachment_id = attachment_id,
        .target_origin = target_origin,
        .requester_node = requester_node,
        .requester_sequence = requester_sequence,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
    };
    try validateRequestShape(value);
    return value;
}

fn requestEql(a: Request, b: Request) bool {
    return std.mem.eql(u8, a.account, b.account) and
        std.mem.eql(u8, &a.token, &b.token) and
        std.mem.eql(u8, &a.attachment_id, &b.attachment_id) and
        a.target_origin == b.target_origin and
        a.requester_node == b.requester_node and
        a.requester_sequence == b.requester_sequence and
        a.issued_at_ms == b.issued_at_ms and
        a.expires_at_ms == b.expires_at_ms;
}

fn validateRequestShape(value: Request) error{ InvalidRequest, InvalidLifetime, TooLong }!void {
    if (isZero16(value.token) or isZero16(value.attachment_id)) return error.InvalidRequest;
    if (value.target_origin == 0 or value.requester_node == 0 or value.requester_sequence == 0) return error.InvalidRequest;
    if (value.account.len == 0) return error.InvalidRequest;
    if (value.account.len > max_account_len) return error.TooLong;
    if (!validAccount(value.account)) return error.InvalidRequest;
    if (value.issued_at_ms < 0 or value.expires_at_ms < value.issued_at_ms) return error.InvalidRequest;
    const ttl: u64 = @intCast(value.expires_at_ms - value.issued_at_ms);
    if (ttl > max_request_ttl_ms) return error.InvalidLifetime;
}

fn validAccount(account: []const u8) bool {
    for (account) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

fn requireSigner(origin: u64, public_key: sign.PublicKey) error{OriginMismatch}!void {
    if (origin == 0 or signed_frame.originShortId(public_key) != origin) return error.OriginMismatch;
}

// ---------------------------------------------------------------------------
// Mesh-node trust
// ---------------------------------------------------------------------------

/// Same shape as `session_group_revoke_durable.Trust`'s `allows` callback:
/// the caller owns the live configured-node roster and answers whether
/// `signer` is a currently configured node claiming `origin`.
pub const Trust = struct {
    ctx: *const anyopaque,
    allows: *const fn (*const anyopaque, sign.PublicKey, u64) bool,
};

pub fn authorize(signed: SignedRequest, trust: Trust) error{UntrustedOrigin}!void {
    if (!trust.allows(trust.ctx, signed.signer, signed.request.requester_node)) return error.UntrustedOrigin;
}

// ---------------------------------------------------------------------------
// ReplayGuard: bounded (requester_node, sequence) idempotency
// ---------------------------------------------------------------------------

pub const Digest = [std.crypto.hash.sha2.Sha256.digest_length]u8;

/// Quota identity for one account. A domain-separated SHA-256 prefix of the
/// ASCII-case-folded account name (the same folding `SessionStore` applies),
/// so neither table stores account names and one account cannot share, or
/// deliberately collide with, another account's quota without a 128-bit
/// preimage collision.
pub const AccountKey = [16]u8;
const account_key_domain = "onyx/session-attachment-revoke/account-quota/v1\x00";

pub fn accountKey(account: []const u8) AccountKey {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(account_key_domain);
    var folded: [64]u8 = undefined;
    var rest = account;
    while (rest.len != 0) {
        const n = @min(folded.len, rest.len);
        for (rest[0..n], folded[0..n]) |byte, *out| out.* = std.ascii.toLower(byte);
        hasher.update(folded[0..n]);
        rest = rest[n..];
    }
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest[0..16].*;
}

/// Digest of the signed transcript only. Ed25519 is deterministic, but the
/// signature bytes are deliberately excluded so the identity of a request is
/// exactly its signed content.
pub fn requestDigest(signed: SignedRequest) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(signed.transcript, &digest, .{});
    return digest;
}

pub const ReplayGuard = struct {
    pub const capacity: usize = 2048;
    /// Live slots one account may hold. A slot lives at most
    /// `max_request_ttl_ms`, so one account can admit at most this many
    /// revokes per request lifetime; exhausting it refuses only that
    /// account's further requests. Filling `capacity` needs
    /// `capacity / per_account_quota` distinct accounts at their limit.
    pub const per_account_quota: usize = 32;

    const Slot = struct {
        used: bool = false,
        requester_node: u64 = 0,
        sequence: u64 = 0,
        digest: Digest = @splat(0),
        account: AccountKey = @splat(0),
        expires_at_ms: i64 = 0,
    };

    /// `fresh` carries the free slot `commit` must use. `equivocation` is the
    /// same `(requester_node, sequence)` signed over different content.
    /// `account_quota` means this account already holds `per_account_quota`
    /// live slots; every other account is unaffected.
    pub const Lookup = union(enum) { fresh: usize, duplicate, equivocation, full, account_quota };
    pub const Outcome = enum { recorded, duplicate, equivocation, full, account_quota };

    slots: [capacity]Slot = @splat(.{}),

    /// Lazily forgets any slot whose `expires_at_ms` is at or before `now_ms`
    /// before checking for a duplicate, so an expired pair is eligible for
    /// replay (and eligible to free capacity) rather than wedged forever.
    /// Replaying an expired pair is still refused by `verifyRequest`, because
    /// every slot expires exactly when its request does. A duplicate or
    /// equivocation is reported even when the quota or table is exhausted.
    pub fn lookup(self: *ReplayGuard, requester_node: u64, sequence: u64, digest: Digest, account: AccountKey, now_ms: i64) Lookup {
        var free_index: ?usize = null;
        var account_live: usize = 0;
        for (&self.slots, 0..) |*slot, index| {
            if (slot.used and slot.expires_at_ms <= now_ms) slot.used = false;
            if (slot.used and slot.requester_node == requester_node and slot.sequence == sequence) {
                return if (std.crypto.timing_safe.eql(Digest, slot.digest, digest)) .duplicate else .equivocation;
            }
            if (slot.used and std.mem.eql(u8, &slot.account, &account)) account_live += 1;
            if (!slot.used and free_index == null) free_index = index;
        }
        if (account_live >= per_account_quota) return .account_quota;
        return if (free_index) |index| .{ .fresh = index } else .full;
    }

    /// Infallible second half of `lookup`; `index` must come from a `.fresh`
    /// lookup with no intervening mutation of this guard.
    pub fn commit(self: *ReplayGuard, index: usize, requester_node: u64, sequence: u64, digest: Digest, account: AccountKey, expires_at_ms: i64) void {
        std.debug.assert(!self.slots[index].used);
        self.slots[index] = .{
            .used = true,
            .requester_node = requester_node,
            .sequence = sequence,
            .digest = digest,
            .account = account,
            .expires_at_ms = expires_at_ms,
        };
    }

    pub fn record(self: *ReplayGuard, requester_node: u64, sequence: u64, digest: Digest, account: AccountKey, expires_at_ms: i64, now_ms: i64) Outcome {
        switch (self.lookup(requester_node, sequence, digest, account, now_ms)) {
            .fresh => |index| {
                self.commit(index, requester_node, sequence, digest, account, expires_at_ms);
                return .recorded;
            },
            .duplicate => return .duplicate,
            .equivocation => return .equivocation,
            .full => return .full,
            .account_quota => return .account_quota,
        }
    }
};

// ---------------------------------------------------------------------------
// Denials: bounded (token, attachment_id) -> expires_at fence
// ---------------------------------------------------------------------------

pub const Denials = struct {
    pub const capacity: usize = 4096;
    /// Live fences one account may hold; matches the default
    /// `sessions.Config.max_sessions_per_account`, so a user can fence every
    /// attachment they can have at once. Exhausting it refuses only that
    /// account's further fences; filling `capacity` needs
    /// `capacity / per_account_quota` distinct accounts at their limit.
    pub const per_account_quota: usize = 64;

    const Entry = struct {
        used: bool = false,
        token: [16]u8 = @splat(0),
        attachment_id: [16]u8 = @splat(0),
        account: AccountKey = @splat(0),
        expires_at_ms: i64 = 0,
    };

    pub const DenyError = error{ Full, AccountQuota, InvalidDeadline };

    /// Result of `gateAttach`.
    /// `attachment_denied`: the exact `(token, attachment_id)` pair is fenced.
    /// `new_attachment_denied`: a newly minted attachment would join a token
    /// that has a live fence, which is exactly how the revoked holder of the
    /// shared bearer token would otherwise rejoin.
    pub const Gate = enum { allow, attachment_denied, new_attachment_denied };

    entries: [capacity]Entry = @splat(.{}),

    /// Keyed by the EXACT `(token, attachment_id)` pair: denying one
    /// attachment of a token never denies exact resume of any other
    /// attachment of the same token. Re-denying the same pair before expiry
    /// only extends the deadline forward and never shrinks it or consumes a
    /// second slot or quota unit, even when the table or quota is full.
    /// A deadline at or before `now_ms` is refused rather than recorded as
    /// an already-expired (and therefore ineffective) fence. On error no
    /// live entry changes.
    pub fn deny(self: *Denials, token: [16]u8, attachment_id: [16]u8, account: AccountKey, expires_at_ms: i64, now_ms: i64) DenyError!void {
        if (expires_at_ms <= now_ms) return error.InvalidDeadline;
        var free_index: ?usize = null;
        var account_live: usize = 0;
        for (&self.entries, 0..) |*entry, index| {
            if (entry.used and entry.expires_at_ms <= now_ms) entry.used = false;
            if (entry.used and
                std.crypto.timing_safe.eql([16]u8, entry.token, token) and
                std.crypto.timing_safe.eql([16]u8, entry.attachment_id, attachment_id))
            {
                entry.expires_at_ms = @max(entry.expires_at_ms, expires_at_ms);
                return;
            }
            if (entry.used and std.mem.eql(u8, &entry.account, &account)) account_live += 1;
            if (!entry.used and free_index == null) free_index = index;
        }
        if (account_live >= per_account_quota) return error.AccountQuota;
        const index = free_index orelse return error.Full;
        self.entries[index] = .{
            .used = true,
            .token = token,
            .attachment_id = attachment_id,
            .account = account,
            .expires_at_ms = expires_at_ms,
        };
    }

    pub fn isDenied(self: *const Denials, token: [16]u8, attachment_id: [16]u8, now_ms: i64) bool {
        for (self.entries) |entry| {
            if (!entry.used or entry.expires_at_ms <= now_ms) continue;
            if (std.crypto.timing_safe.eql([16]u8, entry.token, token) and
                std.crypto.timing_safe.eql([16]u8, entry.attachment_id, attachment_id)) return true;
        }
        return false;
    }

    /// True while any attachment of `token` has a live fence.
    pub fn tokenHasDenial(self: *const Denials, token: [16]u8, now_ms: i64) bool {
        for (self.entries) |entry| {
            if (!entry.used or entry.expires_at_ms <= now_ms) continue;
            if (std.crypto.timing_safe.eql([16]u8, entry.token, token)) return true;
        }
        return false;
    }

    /// Mandatory gate in front of every admission that binds a connection to
    /// `token`, on every node (local resume, exact resume, mesh reclaim,
    /// legacy token join, certificate restore). `attachment_id` is the exact
    /// EXISTING attachment being resumed or reclaimed, or `null` when the
    /// admission would mint a new attachment id under `token` (bare-token
    /// `SESSION RESUME`, `join_existing`, SRM1 token reclaim). A new
    /// attachment is refused while any sibling is fenced, because the
    /// fenced holder still has the shared bearer token and an attachment id
    /// is not a credential; exact resume of an unfenced sibling stays allowed.
    pub fn gateAttach(self: *const Denials, token: [16]u8, attachment_id: ?[16]u8, now_ms: i64) Gate {
        if (attachment_id) |exact| {
            return if (self.isDenied(token, exact, now_ms)) .attachment_denied else .allow;
        }
        return if (self.tokenHasDenial(token, now_ms)) .new_attachment_denied else .allow;
    }

    pub const Pair = struct { token: [16]u8, attachment_id: [16]u8 };

    /// Live fenced pair at `index` (0 ..< capacity), or null when that slot is
    /// empty or expired. Lets the caller enforce every live fence against its
    /// own local rows without exposing the table layout.
    pub fn liveAt(self: *const Denials, index: usize, now_ms: i64) ?Pair {
        const entry = &self.entries[index];
        if (!entry.used or entry.expires_at_ms <= now_ms) return null;
        return .{ .token = entry.token, .attachment_id = entry.attachment_id };
    }
};

// ---------------------------------------------------------------------------
// Origin admission decision
// ---------------------------------------------------------------------------

/// `drop`: this node holds the exact live row; close exactly that attachment.
/// This holds whatever `target_origin` says: attachment ids survive node
/// moves and Helix, so a row that migrated after the requester resolved it
/// is closed by whichever node holds it now.
/// `already_absent`: this node is the named target but holds no such row.
/// `not_owner`: neither the named target nor holding the row; fence only.
/// `reject_self`: the request came back to its own requester. That node
/// already applied it through the local command path (which protects the
/// caller's own attachment), so it never acts on its own echo. A request
/// whose target is its requester (a row the requester closed locally) still
/// fences every other node, so the revoked holder cannot rejoin elsewhere
/// with the shared bearer token, and is dropped by any node the attachment
/// migrated to.
/// `account_mismatch`: the local row belongs to a different account.
pub const OriginDecision = enum { drop, already_absent, not_owner, reject_self, account_mismatch };

/// What the caller found locally for the exact `(token, attachment_id)` row:
/// a physical attachment (attached or detached-retained) held by this node.
/// Replicated inventory describing another node's row is never a `LocalRow`.
pub const LocalRow = struct {
    account: []const u8,
};

/// Pure fail-closed admission decision for an already-verified, already-
/// trusted request. `row` is the exact local `(token, attachment_id)` row,
/// or `null` when no such row exists here. `target_origin` only selects
/// between `already_absent` and `not_owner` when no row is present.
pub fn originDecision(request: Request, local_node: u64, row: ?LocalRow) OriginDecision {
    if (local_node == request.requester_node) return .reject_self;
    if (row) |present| {
        if (!std.ascii.eqlIgnoreCase(present.account, request.account)) return .account_mismatch;
        return .drop;
    }
    return if (request.target_origin == local_node) .already_absent else .not_owner;
}

/// Result of `admit`. Every value except `duplicate` corresponds to an
/// `OriginDecision`; `duplicate` is a retried request already admitted, which
/// the caller acknowledges again without any further state change.
pub const Admission = enum { drop, already_absent, not_owner, reject_self, account_mismatch, duplicate };

/// `ReplayAccountQuota` / `DenialsAccountQuota`: the request's account
/// already holds its share of that table; other accounts are unaffected.
pub const AdmitError = error{
    Equivocation,
    ReplayFull,
    ReplayAccountQuota,
    DenialsFull,
    DenialsAccountQuota,
    InvalidDenialDeadline,
};

/// Allocation-free admission transaction for one inbound request that has
/// already passed `decodeRequest`, `verifyRequest(now_ms)` and `authorize`.
///
/// Order is chosen so that every failure leaves no visible state change and
/// consumes no replay identity, keeping a retry valid:
///   1. replay lookup (duplicate / equivocation / full end the transaction);
///   2. pure origin decision; refusals (`reject_self`, `account_mismatch`)
///      return without fencing or recording;
///   3. install the exact `(token, attachment_id)` fence, which may fail;
///   4. commit the replay slot found in step 1 (infallible).
///
/// Every trusted node that receives the request fences the pair, so neither
/// local resume nor mesh reclaim on any of them can revive that attachment
/// (see `Denials.gateAttach`); only `.drop` tells the caller to close the
/// live connection, and it is returned by whichever node holds the exact
/// row, including one the attachment migrated to after resolution.
pub fn admit(
    guard: *ReplayGuard,
    denials: *Denials,
    signed: SignedRequest,
    local_node: u64,
    row: ?LocalRow,
    denial_expires_at_ms: i64,
    now_ms: i64,
) AdmitError!Admission {
    const request = signed.request;
    const digest = requestDigest(signed);
    const account = accountKey(request.account);
    const slot = switch (guard.lookup(request.requester_node, request.requester_sequence, digest, account, now_ms)) {
        .fresh => |index| index,
        .duplicate => return .duplicate,
        .equivocation => return error.Equivocation,
        .full => return error.ReplayFull,
        .account_quota => return error.ReplayAccountQuota,
    };
    const decision = originDecision(request, local_node, row);
    switch (decision) {
        .reject_self => return .reject_self,
        .account_mismatch => return .account_mismatch,
        .drop, .already_absent, .not_owner => {},
    }
    denials.deny(request.token, request.attachment_id, account, denial_expires_at_ms, now_ms) catch |err| return switch (err) {
        error.Full => error.DenialsFull,
        error.AccountQuota => error.DenialsAccountQuota,
        error.InvalidDeadline => error.InvalidDenialDeadline,
    };
    guard.commit(slot, request.requester_node, request.requester_sequence, digest, account, request.expires_at_ms);
    return switch (decision) {
        .drop => .drop,
        .already_absent => .already_absent,
        .not_owner => .not_owner,
        .reject_self, .account_mismatch => unreachable,
    };
}

// ---------------------------------------------------------------------------
// Node-local state bundle and bounded retransmission
// ---------------------------------------------------------------------------

pub const max_wire_len: usize = fixed_len + max_account_len + signature_wire_len;

/// Exact signed bytes of admitted requests, retained until each request's own
/// expiry so the caller can offer them again to a link that is established or
/// resynced later. Receivers dedupe through `ReplayGuard`, so offering again
/// is idempotent; losing an entry loses only retransmission, never safety.
pub const Retained = struct {
    pub const capacity: usize = 64;

    const Entry = struct {
        len: u16 = 0,
        expires_at_ms: i64 = 0,
        bytes: [max_wire_len]u8 = @splat(0),
    };

    entries: [capacity]Entry = @splat(.{}),
    next: usize = 0,

    /// Copy `wire` (a decoded request, so bounded by `max_wire_len`). An
    /// identical live copy is kept as is; otherwise an empty or expired slot
    /// is reused before the round-robin victim.
    pub fn retain(self: *Retained, wire: []const u8, expires_at_ms: i64, now_ms: i64) void {
        if (wire.len == 0 or wire.len > max_wire_len or expires_at_ms <= now_ms) return;
        var free_index: ?usize = null;
        for (&self.entries, 0..) |*entry, index| {
            if (entry.len != 0 and entry.expires_at_ms <= now_ms) entry.len = 0;
            if (entry.len == wire.len and std.mem.eql(u8, entry.bytes[0..entry.len], wire)) return;
            if (entry.len == 0 and free_index == null) free_index = index;
        }
        const index = free_index orelse blk: {
            const victim = self.next;
            self.next = (self.next + 1) % capacity;
            break :blk victim;
        };
        const entry = &self.entries[index];
        entry.len = @intCast(wire.len);
        entry.expires_at_ms = expires_at_ms;
        @memcpy(entry.bytes[0..wire.len], wire);
    }

    /// Live retained wire at `index` (0 ..< capacity), or null. The slice
    /// borrows the ring and is invalidated by the next `retain`.
    pub fn liveAt(self: *const Retained, index: usize, now_ms: i64) ?[]const u8 {
        const entry = &self.entries[index];
        if (entry.len == 0 or entry.expires_at_ms <= now_ms) return null;
        return entry.bytes[0..entry.len];
    }
};

/// Everything one node keeps for attachment revocation; about 450 KiB, so
/// callers keep it on the heap. Helix carries it through the strict `SARS`
/// checkpoint below (see the module header). A cold restart forgets it.
pub const NodeState = struct {
    replay: ReplayGuard = .{},
    denials: Denials = .{},
    retained: Retained = .{},
    last_sequence: u64 = 0,
    /// Set when a live fence may still have a local row the caller could not
    /// close yet (cross-owner contention); the caller's sweep clears it only
    /// after every live fence was enforced.
    enforce_pending: bool = false,

    /// Strictly increasing within a process and seeded by wall time, so a
    /// restarted node does not reuse a sequence still live in a peer's
    /// `ReplayGuard` (whose slots last at most `max_request_ttl_ms`).
    pub fn nextSequence(self: *NodeState, wall_ms: u64) u64 {
        self.last_sequence = @max(self.last_sequence +| 1, wall_ms);
        return self.last_sequence;
    }
};

// ---------------------------------------------------------------------------
// Helix checkpoint (SARS)
// ---------------------------------------------------------------------------

/// Inner payload magic inside the `.mesh_checkpoint` capsule family.
pub const checkpoint_magic = [_]u8{ 'S', 'A', 'R', 'S' };
pub const checkpoint_version: u8 = 1;
const checkpoint_flag_enforce_pending: u8 = 0x01;
const checkpoint_header_len: usize = checkpoint_magic.len + 1 + 1 + 8 + 2 + 2 + 2;
const checkpoint_denial_len: usize = 16 + 16 + 16 + 8;
const checkpoint_replay_len: usize = 8 + 8 + 32 + 16 + 8;
const checkpoint_retained_len_fixed: usize = 8 + 2;

pub const CheckpointDecodeError = error{
    BadMagic,
    UnsupportedVersion,
    InvalidFlags,
    Truncated,
    TrailingBytes,
    TooManyEntries,
    InvalidEntry,
    DuplicateEntry,
    AccountQuota,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Canonical image of every entry still live at `now_ms`, in table order,
/// plus `last_sequence` and the unfinished-close latch. Expired entries are
/// never carried; they could no longer gate or replay anything.
pub fn encodeCheckpoint(allocator: std.mem.Allocator, state: *const NodeState, now_ms: i64) std.mem.Allocator.Error![]u8 {
    var denials: usize = 0;
    for (state.denials.entries) |entry| denials += @intFromBool(entry.used and entry.expires_at_ms > now_ms);
    var replays: usize = 0;
    for (state.replay.slots) |slot| replays += @intFromBool(slot.used and slot.expires_at_ms > now_ms);
    var retained: usize = 0;
    var retained_bytes: usize = 0;
    for (state.retained.entries) |entry| if (entry.len != 0 and entry.expires_at_ms > now_ms) {
        retained += 1;
        retained_bytes += checkpoint_retained_len_fixed + entry.len;
    };
    const len = checkpoint_header_len + denials * checkpoint_denial_len + replays * checkpoint_replay_len + retained_bytes;
    const out = try allocator.alloc(u8, len);
    var w = Writer{ .bytes = out };
    w.writeBytes(&checkpoint_magic);
    w.writeBytes(&.{ checkpoint_version, if (state.enforce_pending) checkpoint_flag_enforce_pending else 0 });
    w.writeU64(state.last_sequence);
    w.writeU16(@intCast(denials));
    w.writeU16(@intCast(replays));
    w.writeU16(@intCast(retained));
    for (state.denials.entries) |entry| if (entry.used and entry.expires_at_ms > now_ms) {
        w.writeBytes(&entry.token);
        w.writeBytes(&entry.attachment_id);
        w.writeBytes(&entry.account);
        w.writeI64(entry.expires_at_ms);
    };
    for (state.replay.slots) |slot| if (slot.used and slot.expires_at_ms > now_ms) {
        w.writeU64(slot.requester_node);
        w.writeU64(slot.sequence);
        w.writeBytes(&slot.digest);
        w.writeBytes(&slot.account);
        w.writeI64(slot.expires_at_ms);
    };
    for (state.retained.entries) |entry| if (entry.len != 0 and entry.expires_at_ms > now_ms) {
        w.writeI64(entry.expires_at_ms);
        w.writeU16(entry.len);
        w.writeBytes(entry.bytes[0..entry.len]);
    };
    std.debug.assert(w.pos == out.len);
    return out;
}

const CheckpointLayout = struct {
    flags: u8,
    last_sequence: u64,
    denials: usize,
    replays: usize,
    retained: usize,
    denial_start: usize,
    replay_start: usize,
    retained_start: usize,
};

/// Strict structural validation without materializing a table. Rejects
/// unknown versions or flags, truncation, trailing bytes, counts above table
/// capacity, duplicate fence pairs or replay identities, per-account quota
/// overflow, empty or oversized retained wires, and non-positive deadlines.
pub fn validateCheckpoint(bytes: []const u8) CheckpointDecodeError!void {
    _ = try checkpointLayout(bytes);
}

fn checkpointLayout(bytes: []const u8) CheckpointDecodeError!CheckpointLayout {
    if (!isCheckpoint(bytes)) return error.BadMagic;
    var r = CheckpointReader{ .bytes = bytes, .pos = checkpoint_magic.len };
    const head = try r.take(2);
    if (head[0] != checkpoint_version) return error.UnsupportedVersion;
    if ((head[1] & ~checkpoint_flag_enforce_pending) != 0) return error.InvalidFlags;
    const last_sequence = try r.readU64();
    const denials: usize = try r.readU16();
    const replays: usize = try r.readU16();
    const retained: usize = try r.readU16();
    if (denials > Denials.capacity or replays > ReplayGuard.capacity or retained > Retained.capacity)
        return error.TooManyEntries;

    const denial_start = r.pos;
    for (0..denials) |i| {
        const entry = try r.take(checkpoint_denial_len);
        if (std.mem.readInt(i64, entry[48..56], .big) <= 0) return error.InvalidEntry;
        var account_live: usize = 1;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            const prior = bytes[denial_start + j * checkpoint_denial_len ..][0..checkpoint_denial_len];
            if (std.mem.eql(u8, prior[0..32], entry[0..32])) return error.DuplicateEntry;
            if (std.mem.eql(u8, prior[32..48], entry[32..48])) account_live += 1;
        }
        if (account_live > Denials.per_account_quota) return error.AccountQuota;
    }
    const replay_start = r.pos;
    for (0..replays) |i| {
        const slot = try r.take(checkpoint_replay_len);
        if (std.mem.readInt(i64, slot[64..72], .big) <= 0) return error.InvalidEntry;
        var account_live: usize = 1;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            const prior = bytes[replay_start + j * checkpoint_replay_len ..][0..checkpoint_replay_len];
            if (std.mem.eql(u8, prior[0..16], slot[0..16])) return error.DuplicateEntry;
            if (std.mem.eql(u8, prior[48..64], slot[48..64])) account_live += 1;
        }
        if (account_live > ReplayGuard.per_account_quota) return error.AccountQuota;
    }
    const retained_start = r.pos;
    for (0..retained) |_| {
        if (try r.readI64() <= 0) return error.InvalidEntry;
        const len = try r.readU16();
        if (len == 0 or len > max_wire_len) return error.InvalidEntry;
        _ = try r.take(len);
    }
    if (r.pos != bytes.len) return error.TrailingBytes;
    return .{
        .flags = head[1],
        .last_sequence = last_sequence,
        .denials = denials,
        .replays = replays,
        .retained = retained,
        .denial_start = denial_start,
        .replay_start = replay_start,
        .retained_start = retained_start,
    };
}

/// Strict decode into `out`, which is fully overwritten only on success (on
/// error `out` is left as the caller initialized it). Validation is exactly
/// `validateCheckpoint`.
pub fn decodeCheckpoint(bytes: []const u8, out: *NodeState) CheckpointDecodeError!void {
    const layout = try checkpointLayout(bytes);
    const denials = layout.denials;
    const replays = layout.replays;
    const retained = layout.retained;
    const denial_start = layout.denial_start;
    const replay_start = layout.replay_start;
    const retained_start = layout.retained_start;

    // Commit: infallible.
    out.* = .{};
    out.last_sequence = layout.last_sequence;
    out.enforce_pending = (layout.flags & checkpoint_flag_enforce_pending) != 0;
    for (0..denials) |i| {
        const entry = bytes[denial_start + i * checkpoint_denial_len ..][0..checkpoint_denial_len];
        out.denials.entries[i] = .{
            .used = true,
            .token = entry[0..16].*,
            .attachment_id = entry[16..32].*,
            .account = entry[32..48].*,
            .expires_at_ms = std.mem.readInt(i64, entry[48..56], .big),
        };
    }
    for (0..replays) |i| {
        const slot = bytes[replay_start + i * checkpoint_replay_len ..][0..checkpoint_replay_len];
        out.replay.slots[i] = .{
            .used = true,
            .requester_node = std.mem.readInt(u64, slot[0..8], .big),
            .sequence = std.mem.readInt(u64, slot[8..16], .big),
            .digest = slot[16..48].*,
            .account = slot[48..64].*,
            .expires_at_ms = std.mem.readInt(i64, slot[64..72], .big),
        };
    }
    var pos = retained_start;
    for (0..retained) |i| {
        const expires = std.mem.readInt(i64, bytes[pos..][0..8], .big);
        const len = std.mem.readInt(u16, bytes[pos + 8 ..][0..2], .big);
        pos += checkpoint_retained_len_fixed;
        out.retained.entries[i].len = len;
        out.retained.entries[i].expires_at_ms = expires;
        @memcpy(out.retained.entries[i].bytes[0..len], bytes[pos .. pos + len]);
        pos += len;
    }
    out.retained.next = retained % Retained.capacity;
}

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *CheckpointReader, len: usize) CheckpointDecodeError![]const u8 {
        if (len > self.bytes.len -| self.pos) return error.Truncated;
        const result = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readU16(self: *CheckpointReader) CheckpointDecodeError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn readU64(self: *CheckpointReader) CheckpointDecodeError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }

    fn readI64(self: *CheckpointReader) CheckpointDecodeError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .big);
    }
};

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseCommand accepts only the exact REVOKE group=/attachment= form" {
    const group: session_sid.Sid = @splat(0x11);
    const aid: [16]u8 = @splat(0x22);
    const group_hex = session_sid.formatSid(group);
    const aid_hex = std.fmt.bytesToHex(aid, .lower);

    var buf: [group_prefix.len + session_sid.sid_hex_len]u8 = undefined;
    const group_arg = try std.fmt.bufPrint(&buf, "group={s}", .{group_hex});
    var buf2: [attachment_prefix.len + session_sid.sid_hex_len]u8 = undefined;
    const attachment_arg = try std.fmt.bufPrint(&buf2, "attachment={s}", .{aid_hex});

    const selector = parseCommand(&.{ "REVOKE", group_arg, attachment_arg }) orelse return error.TestUnexpectedResult;
    try testing.expect(session_sid.eql(group, selector.group));
    try testing.expect(std.mem.eql(u8, &aid, &selector.attachment_id));

    // Case-insensitive verb, matching session_sid's own REVOKE grammar.
    const lower_selector = parseCommand(&.{ "revoke", group_arg, attachment_arg }) orelse return error.TestUnexpectedResult;
    try testing.expect(session_sid.eql(group, lower_selector.group));
}

test "parseCommand returns null for every non-exact or malformed form" {
    const group: session_sid.Sid = @splat(0x33);
    const aid: [16]u8 = @splat(0x44);
    const group_hex = session_sid.formatSid(group);
    const aid_hex = std.fmt.bytesToHex(aid, .lower);
    var buf: [group_prefix.len + session_sid.sid_hex_len]u8 = undefined;
    const group_arg = try std.fmt.bufPrint(&buf, "group={s}", .{group_hex});
    var buf2: [attachment_prefix.len + session_sid.sid_hex_len]u8 = undefined;
    const attachment_arg = try std.fmt.bufPrint(&buf2, "attachment={s}", .{aid_hex});

    // Bare logical-group revoke: session_sid.parseCommand owns this form.
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg }) == null);
    // A nickname instead of an attachment id.
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, "alice" }) == null);
    // ALL scope.
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, "ALL" }) == null);
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, attachment_arg, "ALL" }) == null);
    // Zero attachment id.
    const zero_attachment = "attachment=00000000000000000000000000000000";
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, zero_attachment }) == null);
    // Zero group.
    const zero_group = "group=00000000000000000000000000000000";
    try testing.expect(parseCommand(&.{ "REVOKE", zero_group, attachment_arg }) == null);
    // Short id.
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, "attachment=ab" }) == null);
    // Non-hex input.
    const non_hex = "attachment=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, non_hex }) == null);
    // Extra parameters beyond the exact three.
    try testing.expect(parseCommand(&.{ "REVOKE", group_arg, attachment_arg, "extra" }) == null);
    // Wrong verb or order.
    try testing.expect(parseCommand(&.{ "LIST", group_arg, attachment_arg }) == null);
    try testing.expect(parseCommand(&.{ "REVOKE", attachment_arg, group_arg }) == null);
}

fn makeRow(token: u8, aid: ?u8, origin: u64, revoked: bool) session_replica.InventoryRow {
    return .{
        .token = @splat(token),
        .attachment_id = if (aid) |value| @as([16]u8, @splat(value)) else null,
        .origin_node = origin,
        .signon_ms = 0,
        .attached = true,
        .fresh = true,
        .inventory_complete = true,
        .revoked = revoked,
    };
}

test "Resolver finds the unique row across several pages" {
    const token: session_replica.Token = @splat(0x55);
    const aid: [16]u8 = @splat(0x66);
    const group = session_sid.deriveGroup(token);
    var resolver = Resolver.init(.{ .group = group, .attachment_id = aid });

    // First page: unrelated noise rows only.
    resolver.consider(&.{ makeRow(0x01, 0x02, 10, false), makeRow(0x03, 0x04, 11, false) });
    try testing.expect(resolver.resolve() == .none);
    // Second page: the exact row, plus a duplicate observation of it.
    resolver.consider(&.{ makeRow(0x55, 0x66, 42, false), makeRow(0x55, 0x66, 42, false) });

    const resolved = resolver.resolve();
    switch (resolved) {
        .unique => |value| {
            try testing.expect(std.mem.eql(u8, &value.token, &token));
            try testing.expectEqual(@as(session_replica.NodeId, 42), value.origin_node);
            try testing.expect(std.mem.eql(u8, &value.attachment_id, &aid));
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Resolver reports ambiguous when one attachment id appears under two tokens" {
    const aid: [16]u8 = @splat(0x77);
    const group_a = session_sid.deriveGroup(@splat(0x10));
    var resolver = Resolver.init(.{ .group = group_a, .attachment_id = aid });
    resolver.consider(&.{ makeRow(0x10, 0x77, 1, false), makeRow(0x20, 0x77, 2, false) });
    try testing.expect(resolver.resolve() == .ambiguous);
}

test "Resolver reports group_mismatch when the row's derived group differs" {
    const aid: [16]u8 = @splat(0x99);
    const wrong_group = session_sid.deriveGroup(@splat(0xAA));
    var resolver = Resolver.init(.{ .group = wrong_group, .attachment_id = aid });
    resolver.consider(&.{makeRow(0x88, 0x99, 5, false)});
    try testing.expect(std.meta.activeTag(resolver.resolve()) == .group_mismatch);
}

test "Resolver reports revoked for fenced rows matching the requested group" {
    const token: session_replica.Token = @splat(0xBB);
    const aid: [16]u8 = @splat(0xCC);
    const group = session_sid.deriveGroup(token);
    var resolver = Resolver.init(.{ .group = group, .attachment_id = aid });
    resolver.consider(&.{makeRow(0xBB, null, 7, true)});
    try testing.expect(resolver.resolve() == .revoked);

    // A revoked row for an unrelated token/group must not taint this selector.
    var other = Resolver.init(.{ .group = group, .attachment_id = aid });
    other.consider(&.{makeRow(0xDD, null, 7, true)});
    try testing.expect(other.resolve() == .none);
}

fn testRequest(account: []const u8, token: u8, aid: u8, target_origin: u64, requester_node: u64, sequence: u64, issued_at_ms: i64, expires_at_ms: i64) Request {
    return .{
        .account = account,
        .token = @splat(token),
        .attachment_id = @splat(aid),
        .target_origin = target_origin,
        .requester_node = requester_node,
        .requester_sequence = sequence,
        .issued_at_ms = issued_at_ms,
        .expires_at_ms = expires_at_ms,
    };
}

test "a request survives encode, decode and verify" {
    var kp = try sign.KeyPair.fromSeed(@splat(1));
    defer kp.deinit();
    const node = signed_frame.originShortId(kp.public_key);
    const value = testRequest("alice", 0x01, 0x02, 999, node, 7, 1000, 2000);

    const wire = try encodeRequest(testing.allocator, value, &kp);
    defer testing.allocator.free(wire);
    try testing.expect(hasMagic(wire));

    const signed = try decodeRequest(wire);
    try testing.expectEqualStrings("alice", signed.request.account);
    try verifyRequest(signed, 1500);
}

test "a request round-trips under every allocation failure" {
    var kp = try sign.KeyPair.fromSeed(@splat(2));
    defer kp.deinit();
    const node = signed_frame.originShortId(kp.public_key);
    const value = testRequest("bob", 0x03, 0x04, 1, node, 1, 500, 1500);

    const RoundTrip = struct {
        fn run(allocator: std.mem.Allocator, kp_ref: *const sign.KeyPair, req: Request) !void {
            const wire = try encodeRequest(allocator, req, kp_ref);
            defer allocator.free(wire);
            const signed = try decodeRequest(wire);
            try verifyRequest(signed, req.issued_at_ms);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, RoundTrip.run, .{ &kp, value });
}

test "verification fails closed on tampered fields, signature, domain, and bounds" {
    var kp = try sign.KeyPair.fromSeed(@splat(3));
    defer kp.deinit();
    const node = signed_frame.originShortId(kp.public_key);
    const value = testRequest("carol", 0x05, 0x06, 2, node, 2, 1000, 2000);
    const wire = try encodeRequest(testing.allocator, value, &kp);
    defer testing.allocator.free(wire);

    // Flipping any single byte of a copy must break decode+verify.
    for (0..wire.len) |index| {
        var tampered = try testing.allocator.dupe(u8, wire);
        defer testing.allocator.free(tampered);
        tampered[index] ^= 1;
        const broke = blk: {
            const signed = decodeRequest(tampered) catch break :blk true;
            verifyRequest(signed, 1500) catch break :blk true;
            break :blk false;
        };
        try testing.expect(broke);
    }

    // Wrong domain: re-sign the identical transcript under a different label.
    const signed = try decodeRequest(wire);
    const wrong_signature = try kp.sign(signed.transcript);
    var wrong_domain_wire = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(wrong_domain_wire);
    @memcpy(wrong_domain_wire[signed.transcript.len + sign.public_key_len ..], &wrong_signature);
    const wrong_domain_signed = try decodeRequest(wrong_domain_wire);
    try testing.expectError(error.BadSignature, verifyRequest(wrong_domain_signed, 1500));

    // Account length exceeded.
    var long_account: [max_account_len + 1]u8 = @splat('a');
    const too_long = testRequest(&long_account, 1, 2, 3, node, 1, 0, 1000);
    try testing.expectError(error.TooLong, encodeRequest(testing.allocator, too_long, &kp));

    // TTL bound exceeded.
    const too_long_lived = testRequest("dave", 1, 2, 3, node, 1, 0, @as(i64, @intCast(max_request_ttl_ms)) + 1);
    try testing.expectError(error.InvalidLifetime, encodeRequest(testing.allocator, too_long_lived, &kp));

    // Future-skew bound exceeded at verify time.
    const future = testRequest("erin", 1, 2, 3, node, 1, 1_000_000, 1_000_000 + 1000);
    const future_wire = try encodeRequest(testing.allocator, future, &kp);
    defer testing.allocator.free(future_wire);
    const future_signed = try decodeRequest(future_wire);
    try testing.expectError(error.FutureSkew, verifyRequest(future_signed, 0));

    // Already expired at verify time.
    try testing.expectError(error.Expired, verifyRequest(future_signed, 1_000_000 + 2000));
}

test "configured-node trust callback rejects unknown signers" {
    var trusted = try sign.KeyPair.fromSeed(@splat(4));
    defer trusted.deinit();
    var unknown = try sign.KeyPair.fromSeed(@splat(5));
    defer unknown.deinit();

    const Ctx = struct {
        key: sign.PublicKey,
        fn allows(ctx: *const anyopaque, candidate: sign.PublicKey, origin: u64) bool {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            return std.mem.eql(u8, &self.key, &candidate) and origin == signed_frame.originShortId(candidate);
        }
    };
    const ctx = Ctx{ .key = trusted.public_key };
    const trust = Trust{ .ctx = &ctx, .allows = Ctx.allows };

    const trusted_node = signed_frame.originShortId(trusted.public_key);
    const trusted_value = testRequest("frank", 1, 2, 3, trusted_node, 1, 0, 1000);
    const trusted_wire = try encodeRequest(testing.allocator, trusted_value, &trusted);
    defer testing.allocator.free(trusted_wire);
    const trusted_signed = try decodeRequest(trusted_wire);
    try authorize(trusted_signed, trust);

    const unknown_node = signed_frame.originShortId(unknown.public_key);
    const unknown_value = testRequest("frank", 1, 2, 3, unknown_node, 1, 0, 1000);
    const unknown_wire = try encodeRequest(testing.allocator, unknown_value, &unknown);
    defer testing.allocator.free(unknown_wire);
    const unknown_signed = try decodeRequest(unknown_wire);
    try testing.expectError(error.UntrustedOrigin, authorize(unknown_signed, trust));
}

fn indexedAccount(index: usize) AccountKey {
    var key: AccountKey = @splat(0xA5);
    std.mem.writeInt(u64, key[0..8], @intCast(index + 1), .big);
    return key;
}

test "accountKey folds ASCII case and separates distinct accounts" {
    try testing.expect(std.mem.eql(u8, &accountKey("Alice"), &accountKey("aLICE")));
    try testing.expect(!std.mem.eql(u8, &accountKey("alice"), &accountKey("alice2")));
    var long_a: [max_account_len]u8 = @splat('a');
    var long_b = long_a;
    long_b[max_account_len - 1] = 'B';
    long_a[max_account_len - 1] = 'b';
    try testing.expect(std.mem.eql(u8, &accountKey(&long_a), &accountKey(&long_b)));
    long_b[0] = 'c';
    try testing.expect(!std.mem.eql(u8, &accountKey(&long_a), &accountKey(&long_b)));
}

test "ReplayGuard reports duplicates as idempotent, refuses when full, and forgets after expiry" {
    const d1: Digest = @splat(0x01);
    const d2: Digest = @splat(0x02);
    const acct = indexedAccount(0);
    var guard = ReplayGuard{};
    try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(1, 1, d1, acct, 1000, 0));
    try testing.expectEqual(ReplayGuard.Outcome.duplicate, guard.record(1, 1, d1, acct, 1000, 100));
    // Same (node, sequence) over different signed content is equivocation.
    try testing.expectEqual(ReplayGuard.Outcome.equivocation, guard.record(1, 1, d2, acct, 1000, 100));
    // A different sequence from the same node is a distinct entry.
    try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(1, 2, d1, acct, 1000, 0));

    // Fill remaining capacity with distinct pairs, one account per slot.
    var filled: usize = 2;
    var node: u64 = 2;
    while (filled < ReplayGuard.capacity) : (filled += 1) {
        node += 1;
        try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(node, 1, d1, indexedAccount(filled), 1000, 0));
    }
    try testing.expectEqual(ReplayGuard.Outcome.full, guard.record(99_999, 999, d1, indexedAccount(ReplayGuard.capacity), 1000, 0));
    // A full guard still recognizes an existing duplicate.
    try testing.expectEqual(ReplayGuard.Outcome.duplicate, guard.record(1, 1, d1, acct, 1000, 999));

    // After the original entry's expiry, its pair is forgotten, not a duplicate.
    try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(1, 1, d2, acct, 2000, 1500));
}

test "ReplayGuard account quota isolates one account from every other account" {
    const d: Digest = @splat(0x07);
    const greedy = indexedAccount(1);
    const victim = indexedAccount(2);
    var guard = ReplayGuard{};
    for (0..ReplayGuard.per_account_quota) |index| {
        try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(1, index + 1, d, greedy, 10_000, 0));
    }
    const before = guard;
    try testing.expectEqual(ReplayGuard.Outcome.account_quota, guard.record(1, 999, d, greedy, 10_000, 0));
    try testing.expect(std.meta.eql(before, guard));
    // An exhausted account's retry is still idempotent and equivocation is
    // still detected; quota never masks either.
    try testing.expectEqual(ReplayGuard.Outcome.duplicate, guard.record(1, 1, d, greedy, 10_000, 1));
    try testing.expectEqual(ReplayGuard.Outcome.equivocation, guard.record(1, 1, @splat(0x08), greedy, 10_000, 1));
    // A different account, even from the same requester node, is admitted.
    try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(1, 1_000, d, victim, 10_000, 1));
    // The greedy account's share frees once its slots expire.
    try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(1, 999, d, greedy, 20_000, 10_000));
}

test "Denials key exactly (token, attachment_id); other pairs stay undenied and denial expires" {
    const token: [16]u8 = @splat(0x11);
    const other_token: [16]u8 = @splat(0x22);
    const aid_a: [16]u8 = @splat(0xA1);
    const aid_b: [16]u8 = @splat(0xA2);

    const acct = indexedAccount(0);
    var denials = Denials{};
    try denials.deny(token, aid_a, acct, 1000, 0);

    try testing.expect(denials.isDenied(token, aid_a, 500));
    try testing.expect(!denials.isDenied(token, aid_b, 500));
    try testing.expect(!denials.isDenied(other_token, aid_a, 500));

    // Expires at its deadline.
    try testing.expect(!denials.isDenied(token, aid_a, 1000));
    try testing.expect(!denials.isDenied(token, aid_a, 1500));

    // Re-denying before expiry only extends the deadline.
    try denials.deny(token, aid_a, acct, 100, 0);
    try denials.deny(token, aid_a, acct, 2000, 50);
    try testing.expect(denials.isDenied(token, aid_a, 1999));
    try testing.expect(!denials.isDenied(token, aid_a, 2000));
}

fn indexedToken(index: usize) [16]u8 {
    var token: [16]u8 = @splat(0x5A);
    std.mem.writeInt(u64, token[0..8], @intCast(index + 1), .big);
    return token;
}

test "Denials refuses a new pair once capacity is exhausted and rejects stale deadlines" {
    const denials = try testing.allocator.create(Denials);
    defer testing.allocator.destroy(denials);
    denials.* = .{};
    for (0..Denials.capacity) |index| try denials.deny(indexedToken(index), @splat(0xFF), indexedAccount(index), 1_000_000, 0);
    const before = try testing.allocator.create(Denials);
    defer testing.allocator.destroy(before);
    before.* = denials.*;
    try testing.expectError(error.Full, denials.deny(@splat(0xEE), @splat(0xEE), indexedAccount(Denials.capacity), 1_000_000, 0));
    try testing.expect(std.meta.eql(before.*, denials.*));
    // Extending an existing pair needs no new slot even when full.
    try denials.deny(indexedToken(0), @splat(0xFF), indexedAccount(0), 2_000_000, 0);
    try testing.expect(denials.isDenied(indexedToken(0), @splat(0xFF), 1_500_000));
    // Expired entries free capacity.
    try denials.deny(@splat(0xEE), @splat(0xEE), indexedAccount(Denials.capacity), 3_000_000, 1_000_000);

    var empty = Denials{};
    try testing.expectError(error.InvalidDeadline, empty.deny(@splat(1), @splat(2), indexedAccount(0), 100, 100));
    try testing.expectError(error.InvalidDeadline, empty.deny(@splat(1), @splat(2), indexedAccount(0), 50, 100));
    try testing.expect(!empty.isDenied(@splat(1), @splat(2), 0));
}

test "Denials account quota isolates one account and re-denial costs no quota" {
    const greedy = indexedAccount(1);
    const victim = indexedAccount(2);
    var denials = Denials{};
    for (0..Denials.per_account_quota) |index| try denials.deny(indexedToken(index), @splat(0xFF), greedy, 1_000_000, 0);
    const before = denials;
    try testing.expectError(error.AccountQuota, denials.deny(@splat(0xEE), @splat(0xEE), greedy, 1_000_000, 0));
    try testing.expect(std.meta.eql(before, denials));
    // Extending an existing fence of the exhausted account still succeeds.
    try denials.deny(indexedToken(0), @splat(0xFF), greedy, 2_000_000, 0);
    try testing.expect(denials.isDenied(indexedToken(0), @splat(0xFF), 1_500_000));
    // A different account is unaffected.
    try denials.deny(@splat(0xEE), @splat(0xEE), victim, 1_000_000, 0);
    try testing.expect(denials.isDenied(@splat(0xEE), @splat(0xEE), 1));
}

test "gateAttach refuses the revoked pair and every new attachment of its token, never an exact sibling" {
    const token: [16]u8 = @splat(0x11);
    const other_token: [16]u8 = @splat(0x12);
    const revoked: [16]u8 = @splat(0xA1);
    const sibling: [16]u8 = @splat(0xA2);
    var denials = Denials{};
    try testing.expectEqual(Denials.Gate.allow, denials.gateAttach(token, null, 0));
    try denials.deny(token, revoked, indexedAccount(0), 1000, 0);

    // Exact resume of the revoked attachment is refused.
    try testing.expectEqual(Denials.Gate.attachment_denied, denials.gateAttach(token, revoked, 500));
    // The revoked holder still has the shared bearer token: a bare-token
    // resume or join that would mint a fresh attachment id is refused too.
    try testing.expectEqual(Denials.Gate.new_attachment_denied, denials.gateAttach(token, null, 500));
    // The sibling's exact resume is unaffected, as is every other token.
    try testing.expectEqual(Denials.Gate.allow, denials.gateAttach(token, sibling, 500));
    try testing.expectEqual(Denials.Gate.allow, denials.gateAttach(other_token, null, 500));
    // Both refusals end at the fence deadline.
    try testing.expectEqual(Denials.Gate.allow, denials.gateAttach(token, null, 1000));
    try testing.expectEqual(Denials.Gate.allow, denials.gateAttach(token, revoked, 1000));
}

test "originDecision returns drop, already_absent, not_owner, reject_self, and account_mismatch" {
    const req = testRequest("gina", 1, 2, 42, 7, 1, 0, 1000);
    const own_row = LocalRow{ .account = "GINA" };
    // The attachment migrated from the named target 42 to node 43 (same
    // token and attachment id) after the requester resolved it: 43 drops it.
    try testing.expectEqual(OriginDecision.drop, originDecision(req, 43, own_row));
    try testing.expectEqual(OriginDecision.account_mismatch, originDecision(req, 43, .{ .account = "mallory" }));
    try testing.expectEqual(OriginDecision.not_owner, originDecision(req, 43, null));
    try testing.expectEqual(OriginDecision.already_absent, originDecision(req, 42, null));
    try testing.expectEqual(OriginDecision.drop, originDecision(req, 42, own_row));
    try testing.expectEqual(OriginDecision.account_mismatch, originDecision(req, 42, .{ .account = "mallory" }));
    // The requester never acts on its own echo, whatever the local row says.
    try testing.expectEqual(OriginDecision.reject_self, originDecision(req, 7, own_row));
    try testing.expectEqual(OriginDecision.reject_self, originDecision(req, 7, null));
    // A request for a row its requester closed locally fences every other
    // node and drops the attachment wherever it migrated.
    const self_req = testRequest("gina", 1, 2, 7, 7, 1, 0, 1000);
    try testing.expectEqual(OriginDecision.reject_self, originDecision(self_req, 7, own_row));
    try testing.expectEqual(OriginDecision.not_owner, originDecision(self_req, 42, null));
    try testing.expectEqual(OriginDecision.drop, originDecision(self_req, 42, own_row));
}

const AdmitFixture = struct {
    kp: sign.KeyPair,
    node: u64,
    wire: []u8,

    fn init(seed: u8, account: []const u8, target_origin: u64, sequence: u64) !AdmitFixture {
        var kp = try sign.KeyPair.fromSeed(@splat(seed));
        errdefer kp.deinit();
        const node = signed_frame.originShortId(kp.public_key);
        const wire = try encodeRequest(testing.allocator, testRequest(account, 0x31, 0x41, target_origin, node, sequence, 1000, 5000), &kp);
        return .{ .kp = kp, .node = node, .wire = wire };
    }

    fn deinit(self: *AdmitFixture) void {
        testing.allocator.free(self.wire);
        self.kp.deinit();
    }

    fn signed(self: *const AdmitFixture) !SignedRequest {
        const value = try decodeRequest(self.wire);
        try verifyRequest(value, 2000);
        return value;
    }
};

test "admit drops only the exact pair, is idempotent on retry, and fences non-owners" {
    var fixture = try AdmitFixture.init(6, "hana", 42, 1);
    defer fixture.deinit();
    const signed = try fixture.signed();
    const token: [16]u8 = @splat(0x31);
    const aid: [16]u8 = @splat(0x41);
    const sibling: [16]u8 = @splat(0x42);

    var guard = ReplayGuard{};
    var denials = Denials{};
    try testing.expectEqual(Admission.drop, try admit(&guard, &denials, signed, 42, .{ .account = "hana" }, 90_000, 2000));
    try testing.expect(denials.isDenied(token, aid, 2001));
    try testing.expect(!denials.isDenied(token, sibling, 2001));
    // A retried identical request is acknowledged without a second drop.
    try testing.expectEqual(Admission.duplicate, try admit(&guard, &denials, signed, 42, null, 90_000, 2500));

    // A non-owner node fences the same pair but never drops.
    var other_guard = ReplayGuard{};
    var other_denials = Denials{};
    try testing.expectEqual(Admission.not_owner, try admit(&other_guard, &other_denials, signed, 43, null, 90_000, 2000));
    try testing.expect(other_denials.isDenied(token, aid, 2001));
    try testing.expect(!other_denials.isDenied(token, sibling, 2001));
}

test "admit closes an attachment that migrated off the named target node" {
    // Requester resolved the row on origin 42; it moved to 44 keeping the
    // same (token, attachment id) before the request arrived.
    var fixture = try AdmitFixture.init(9, "kira", 42, 3);
    defer fixture.deinit();
    const signed = try fixture.signed();
    const token: [16]u8 = @splat(0x31);
    const aid: [16]u8 = @splat(0x41);
    const sibling: [16]u8 = @splat(0x42);

    var stale_guard = ReplayGuard{};
    var stale_denials = Denials{};
    try testing.expectEqual(Admission.already_absent, try admit(&stale_guard, &stale_denials, signed, 42, null, 90_000, 2000));
    try testing.expect(stale_denials.isDenied(token, aid, 2001));

    var holder_guard = ReplayGuard{};
    var holder_denials = Denials{};
    try testing.expectEqual(Admission.drop, try admit(&holder_guard, &holder_denials, signed, 44, .{ .account = "KIRA" }, 90_000, 2000));
    try testing.expect(holder_denials.isDenied(token, aid, 2001));
    try testing.expectEqual(Denials.Gate.allow, holder_denials.gateAttach(token, sibling, 2001));
    try testing.expectEqual(Denials.Gate.new_attachment_denied, holder_denials.gateAttach(token, null, 2001));
}

test "admit: one account exhausting its quotas never blocks another account" {
    var victim = try AdmitFixture.init(10, "victim", 42, 1);
    defer victim.deinit();
    const victim_signed = try victim.signed();

    // Replay quota held entirely by another account on the victim's requester.
    var guard = ReplayGuard{};
    const greedy = accountKey("greedy");
    for (0..ReplayGuard.per_account_quota) |index| {
        try testing.expectEqual(ReplayGuard.Outcome.recorded, guard.record(victim.node, index + 100, @splat(0), greedy, 1_000_000, 0));
    }
    var denials = Denials{};
    for (0..Denials.per_account_quota) |index| try denials.deny(indexedToken(index), @splat(0xFF), greedy, 1_000_000, 0);
    try testing.expectEqual(Admission.drop, try admit(&guard, &denials, victim_signed, 42, .{ .account = "victim" }, 90_000, 2000));

    // The greedy account itself is refused by quota, consuming nothing.
    var greedy_fixture = try AdmitFixture.init(11, "Greedy", 42, 1);
    defer greedy_fixture.deinit();
    const greedy_signed = try greedy_fixture.signed();
    // (A separate table: the fixture's pair is already fenced in `denials`,
    // and re-fencing an existing pair is deliberately quota-free.)
    var greedy_denials = Denials{};
    for (0..Denials.per_account_quota) |index| try greedy_denials.deny(indexedToken(index), @splat(0xFF), greedy, 1_000_000, 0);
    var fresh_guard = ReplayGuard{};
    const fresh_before = fresh_guard;
    const greedy_before = greedy_denials;
    try testing.expectError(error.DenialsAccountQuota, admit(&fresh_guard, &greedy_denials, greedy_signed, 42, .{ .account = "greedy" }, 90_000, 2000));
    try testing.expect(std.meta.eql(fresh_before, fresh_guard));
    try testing.expect(std.meta.eql(greedy_before, greedy_denials));
    try testing.expectError(error.ReplayAccountQuota, admit(&guard, &greedy_denials, greedy_signed, 42, .{ .account = "greedy" }, 90_000, 2000));
    try testing.expect(std.meta.eql(greedy_before, greedy_denials));
    // A quota refusal consumed no replay identity: the victim's retry is
    // still recognized as a duplicate, and the greedy request is admitted
    // once its account has room.
    try testing.expectEqual(Admission.duplicate, try admit(&guard, &denials, victim_signed, 42, null, 90_000, 2001));
    var roomy = Denials{};
    try testing.expectEqual(Admission.drop, try admit(&fresh_guard, &roomy, greedy_signed, 42, .{ .account = "greedy" }, 90_000, 2000));
}

test "admit refusals and failures consume no replay identity and leave no fence" {
    var fixture = try AdmitFixture.init(7, "iris", 42, 9);
    defer fixture.deinit();
    const signed = try fixture.signed();
    const token: [16]u8 = @splat(0x31);
    const aid: [16]u8 = @splat(0x41);

    var guard = ReplayGuard{};
    var denials = Denials{};
    const guard_before = guard;

    // Account mismatch: refused, no fence, no replay slot.
    try testing.expectEqual(Admission.account_mismatch, try admit(&guard, &denials, signed, 42, .{ .account = "mallory" }, 90_000, 2000));
    try testing.expect(!denials.isDenied(token, aid, 2001));
    try testing.expect(std.meta.eql(guard_before, guard));

    // Stale denial deadline: error, nothing recorded.
    try testing.expectError(error.InvalidDenialDeadline, admit(&guard, &denials, signed, 42, .{ .account = "iris" }, 2000, 2000));
    try testing.expect(std.meta.eql(guard_before, guard));

    // Full denial table: error, nothing recorded, existing fences unchanged.
    const full = try testing.allocator.create(Denials);
    defer testing.allocator.destroy(full);
    full.* = .{};
    for (0..Denials.capacity) |index| try full.deny(indexedToken(index), @splat(0xFF), indexedAccount(index), 1_000_000, 0);
    const full_before = try testing.allocator.create(Denials);
    defer testing.allocator.destroy(full_before);
    full_before.* = full.*;
    try testing.expectError(error.DenialsFull, admit(&guard, full, signed, 42, .{ .account = "iris" }, 90_000, 2000));
    try testing.expect(std.meta.eql(guard_before, guard));
    try testing.expect(std.meta.eql(full_before.*, full.*));

    // The same request still succeeds afterwards: its identity was never consumed.
    try testing.expectEqual(Admission.drop, try admit(&guard, &denials, signed, 42, .{ .account = "iris" }, 90_000, 2000));
    try testing.expect(denials.isDenied(token, aid, 2001));
}

test "admit reports equivocation and replay exhaustion without fencing" {
    var first = try AdmitFixture.init(8, "jade", 42, 5);
    defer first.deinit();
    // Same signer and sequence over a different account: equivocation.
    var forked = try AdmitFixture.init(8, "jade2", 42, 5);
    defer forked.deinit();
    try testing.expectEqual(first.node, forked.node);

    var guard = ReplayGuard{};
    var denials = Denials{};
    try testing.expectEqual(Admission.not_owner, try admit(&guard, &denials, try first.signed(), 43, null, 90_000, 2000));
    const denials_before = denials;
    try testing.expectError(error.Equivocation, admit(&guard, &denials, try forked.signed(), 43, null, 90_000, 2000));
    try testing.expect(std.meta.eql(denials_before, denials));

    var full_guard = ReplayGuard{};
    for (0..ReplayGuard.capacity) |index| try testing.expectEqual(ReplayGuard.Outcome.recorded, full_guard.record(@intCast(index + 1_000), 1, @splat(0), indexedAccount(index), 1_000_000, 0));
    var fresh_denials = Denials{};
    try testing.expectError(error.ReplayFull, admit(&full_guard, &fresh_denials, try first.signed(), 43, null, 90_000, 2000));
    try testing.expect(!fresh_denials.isDenied(@splat(0x31), @splat(0x41), 2001));
}

test "hasMagic rejects anything not starting with SAR1" {
    try testing.expect(hasMagic("SAR1 trailing"));
    try testing.expect(!hasMagic("SRO2xxxx"));
    try testing.expect(!hasMagic("SA"));
    try testing.expect(!hasMagic(""));
}

test "verifyRequest rejects the exact expiry instant, so a freed replay slot cannot readmit the request" {
    var fixture = try AdmitFixture.init(12, "mira", 42, 9);
    defer fixture.deinit();
    const signed = try fixture.signed();
    var guard = ReplayGuard{};
    var denials = Denials{};
    try testing.expectEqual(Admission.not_owner, try admit(&guard, &denials, signed, 43, null, 90_000, 2000));
    try verifyRequest(signed, signed.request.expires_at_ms - 1);
    try testing.expectError(error.Expired, verifyRequest(signed, signed.request.expires_at_ms));
}

test "Retained keeps one live copy per wire, expires with the request, and bounds capacity" {
    var ring = Retained{};
    var fixture = try AdmitFixture.init(13, "nori", 42, 1);
    defer fixture.deinit();
    ring.retain(fixture.wire, 5000, 1000);
    ring.retain(fixture.wire, 5000, 1000);
    var live: usize = 0;
    for (0..Retained.capacity) |i| {
        if (ring.liveAt(i, 1000)) |wire| {
            try testing.expectEqualSlices(u8, fixture.wire, wire);
            live += 1;
        }
    }
    try testing.expectEqual(@as(usize, 1), live);
    for (0..Retained.capacity) |i| try testing.expect(ring.liveAt(i, 5000) == null);
    // An already-expired request is never retained.
    var empty = Retained{};
    empty.retain(fixture.wire, 1000, 1000);
    for (0..Retained.capacity) |i| try testing.expect(empty.liveAt(i, 999) == null);

    var bytes: [16]u8 = undefined;
    for (0..Retained.capacity + 3) |i| {
        std.mem.writeInt(u128, &bytes, i + 1, .little);
        ring.retain(&bytes, 9000, 6000);
    }
    live = 0;
    for (0..Retained.capacity) |i| live += @intFromBool(ring.liveAt(i, 6000) != null);
    try testing.expectEqual(Retained.capacity, live);
}

test "NodeState sequences increase strictly and never fall behind wall time" {
    const state = try testing.allocator.create(NodeState);
    defer testing.allocator.destroy(state);
    state.* = .{};
    try testing.expectEqual(@as(u64, 100), state.nextSequence(100));
    try testing.expectEqual(@as(u64, 101), state.nextSequence(100));
    try testing.expectEqual(@as(u64, 102), state.nextSequence(50));
    try testing.expectEqual(@as(u64, 500), state.nextSequence(500));
}

test "Denials.liveAt exposes exactly the live fenced pairs" {
    var denials = Denials{};
    const account = accountKey("lena");
    try denials.deny(@splat(1), @splat(2), account, 5000, 1000);
    var found: usize = 0;
    for (0..Denials.capacity) |i| if (denials.liveAt(i, 1000)) |pair| {
        try testing.expectEqualSlices(u8, &@as([16]u8, @splat(1)), &pair.token);
        try testing.expectEqualSlices(u8, &@as([16]u8, @splat(2)), &pair.attachment_id);
        found += 1;
    };
    try testing.expectEqual(@as(usize, 1), found);
    for (0..Denials.capacity) |i| try testing.expect(denials.liveAt(i, 5000) == null);
}

test "SARS checkpoint carries live fences, replay identities, retained wires and the close latch" {
    const state = try testing.allocator.create(NodeState);
    defer testing.allocator.destroy(state);
    state.* = .{};
    const account = accountKey("tess");
    try state.denials.deny(@splat(1), @splat(2), account, 50_000, 1000);
    try state.denials.deny(@splat(1), @splat(3), account, 2000, 1000); // expires before the cut
    try testing.expectEqual(ReplayGuard.Outcome.recorded, state.replay.record(9, 77, @splat(0xAB), account, 40_000, 1000));
    state.retained.retain("SAR1-wire-bytes", 30_000, 1000);
    state.last_sequence = 1234;
    state.enforce_pending = true;

    const wire = try encodeCheckpoint(testing.allocator, state, 2500);
    defer testing.allocator.free(wire);
    try testing.expect(isCheckpoint(wire));

    const restored = try testing.allocator.create(NodeState);
    defer testing.allocator.destroy(restored);
    restored.* = .{};
    try decodeCheckpoint(wire, restored);
    try testing.expect(restored.enforce_pending);
    try testing.expectEqual(@as(u64, 1234), restored.last_sequence);
    // The bare-token rejoin fence and the exact pair survive; the expired
    // sibling is not carried.
    try testing.expectEqual(Denials.Gate.new_attachment_denied, restored.denials.gateAttach(@splat(1), null, 3000));
    try testing.expectEqual(Denials.Gate.attachment_denied, restored.denials.gateAttach(@splat(1), @splat(2), 3000));
    try testing.expectEqual(Denials.Gate.allow, restored.denials.gateAttach(@splat(1), @splat(3), 3000));
    try testing.expectEqual(Denials.Gate.allow, restored.denials.gateAttach(@splat(1), null, 50_000));
    // A retried request stays a duplicate and equivocation stays detected.
    try testing.expectEqual(ReplayGuard.Outcome.duplicate, restored.replay.record(9, 77, @splat(0xAB), account, 40_000, 3000));
    try testing.expectEqual(ReplayGuard.Outcome.equivocation, restored.replay.record(9, 77, @splat(0xCD), account, 40_000, 3000));
    var carried: usize = 0;
    for (0..Retained.capacity) |i| if (restored.retained.liveAt(i, 3000)) |bytes| {
        try testing.expectEqualStrings("SAR1-wire-bytes", bytes);
        carried += 1;
    };
    try testing.expectEqual(@as(usize, 1), carried);

    // Canonical: re-encoding the restored state yields identical bytes.
    const again = try encodeCheckpoint(testing.allocator, restored, 2500);
    defer testing.allocator.free(again);
    try testing.expectEqualSlices(u8, wire, again);
}

test "SARS checkpoint decode is strict and leaves the target untouched on error" {
    const state = try testing.allocator.create(NodeState);
    defer testing.allocator.destroy(state);
    state.* = .{};
    try state.denials.deny(@splat(4), @splat(5), accountKey("uma"), 50_000, 1000);
    const wire = try encodeCheckpoint(testing.allocator, state, 1000);
    defer testing.allocator.free(wire);

    const target = try testing.allocator.create(NodeState);
    defer testing.allocator.destroy(target);
    target.* = .{};
    target.last_sequence = 99;

    // Truncation at every length and trailing bytes.
    for (0..wire.len) |cut| try testing.expect(std.meta.isError(decodeCheckpoint(wire[0..cut], target)));
    var long: [256]u8 = undefined;
    @memcpy(long[0..wire.len], wire);
    long[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeCheckpoint(long[0 .. wire.len + 1], target));

    var bad: [256]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[4] = 2;
    try testing.expectError(error.UnsupportedVersion, decodeCheckpoint(bad[0..wire.len], target));
    @memcpy(bad[0..wire.len], wire);
    bad[5] = 0x02;
    try testing.expectError(error.InvalidFlags, decodeCheckpoint(bad[0..wire.len], target));
    @memcpy(bad[0..wire.len], wire);
    std.mem.writeInt(i64, bad[checkpoint_header_len + 48 ..][0..8], 0, .big);
    try testing.expectError(error.InvalidEntry, decodeCheckpoint(bad[0..wire.len], target));

    // A duplicated fence pair is noncanonical.
    var dup: [512]u8 = undefined;
    const entry = wire[checkpoint_header_len..][0..checkpoint_denial_len];
    @memcpy(dup[0..wire.len], wire);
    @memcpy(dup[wire.len..][0..checkpoint_denial_len], entry);
    std.mem.writeInt(u16, dup[checkpoint_magic.len + 2 + 8 ..][0..2], 2, .big);
    try testing.expectError(error.DuplicateEntry, decodeCheckpoint(dup[0 .. wire.len + checkpoint_denial_len], target));

    try testing.expectEqual(@as(u64, 99), target.last_sequence);
    try testing.expectEqual(Denials.Gate.allow, target.denials.gateAttach(@splat(4), null, 2000));
}
