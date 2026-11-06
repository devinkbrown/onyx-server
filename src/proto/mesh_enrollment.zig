// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mesh enrollment: turn an expiring, single-use, signed enrollment ticket
//! into a reviewed `meshpass.Fields` grant.
//!
//! This module is pure and deterministic: no I/O, no clock reads, no durable
//! state. `review()` takes an already-decoded `SignedTicket` and
//! `SignedJoinRequest`, a caller-owned `Policy`, a duck-typed `ledger_view`
//! (satisfied by `../daemon/mesh_enrollment_ledger.zig`'s `Ledger`), and an
//! explicit `now_ms`, and returns either a `ReviewedAdmission` or the exact
//! `ReviewError` that made it fail closed. Every check in `review()` fails
//! closed: an error from an earlier check short-circuits every later one, and
//! no partial admission is ever returned.
//!
//! `review()` only reads `ledger_view`; it never mutates replay/revocation
//! state. Production callers use `mesh_enrollment_ledger.Ledger.redeem()`,
//! which runs `review()` and the single-use consume as one synchronous,
//! allocation-failure-atomic step, then persist the ledger checkpoint, and
//! only then call `issueMeshPass()` and publish the token. This keeps the
//! "may this ticket be redeemed" decision (durable, mutating) separate from
//! the deterministic "is this grant allowed" decision (pure, replayable).
//!
//! Granted authority is never wider than any of: the request, the ticket's
//! `allowed_*` fields, the issuer's configured `authorized_roles`, and the
//! set of roles/frame families this build knows. The `operator` role
//! additionally needs `Policy.allow_operator_enrollment`.
//!
//! Mesh-wide single use: the consumed/revoked ledger is local to one node,
//! so every ticket names exactly one admitting node in its signed
//! `audience_pubkey`, and `review()` rejects it (`WrongAudience`) on every
//! node whose `Policy.admitter_pubkey` differs. A ticket can therefore be
//! redeemed, revoked, and replay-checked only on one ledger. Issuer
//! revocation stops future redemptions only on the ledger it is applied to;
//! an operator revoking an issuer applies it on every admitting node.
//!
//! Revocation epochs: a ticket's `revocation_epoch` must lie inside
//! `[min_revocation_epoch, current_revocation_epoch]`. The minted pass keeps
//! the ticket's epoch, so raising the MeshPass `TrustRoot` floor past
//! `current_revocation_epoch` revokes every pass this node has minted.
//!
//! Wire format: both `EnrollmentTicket` and `JoinRequest` are encoded as a
//! domain-separated magic string, a version byte, then fixed-order
//! big-endian fields (plus a length-prefixed realm on the ticket), followed
//! by a detached Ed25519 signature. The signed payload is exactly the bytes
//! before the signature, so decode-then-reencode is what the signature
//! covers — there is no separate canonicalization step.
const std = @import("std");

const meshpass = @import("meshpass.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const public_key_len = Ed25519.PublicKey.encoded_length;
pub const signature_len = Ed25519.Signature.encoded_length;
pub const max_realm_len = meshpass.max_realm_len;

pub const PublicKeyBytes = [public_key_len]u8;
pub const SignatureBytes = [signature_len]u8;
pub const TicketId = [32]u8;
pub const NetworkId = [32]u8;

const zero_pubkey: PublicKeyBytes = @splat(0);

/// 24h, the absolute ceiling on ticket TTL regardless of `Policy` config.
pub const hard_max_ticket_ttl_ms: u64 = 24 * 60 * 60 * 1000;
pub const default_max_ticket_ttl_ms: u64 = hard_max_ticket_ttl_ms;
pub const default_skew_ms: u64 = 5 * 60 * 1000;
pub const default_pass_ttl_ms: u64 = 24 * 60 * 60 * 1000;
/// 30d, the absolute ceiling on the lifetime of an enrolled MeshPass.
pub const hard_max_pass_ttl_ms: u64 = 30 * 24 * 60 * 60 * 1000;

const ticket_magic = "ONYX-MESH-ENROLL-TICKET-v1";
const join_magic = "ONYX-MESH-ENROLL-JOIN-v1";
const ticket_version: u8 = 1;
const join_version: u8 = 1;

const ticket_fixed_tail_len: usize =
    @sizeOf(NetworkId) + 2 + @sizeOf(TicketId) + public_key_len + public_key_len +
    8 + 4 + 4 + 4 + 8 + 8 + 8 + public_key_len;

/// Worst-case signed-ticket payload size (magic + version + fixed fields +
/// the longest permitted realm).
pub const max_signed_ticket_len: usize =
    ticket_magic.len + 1 + ticket_fixed_tail_len + max_realm_len;
pub const max_ticket_len: usize = max_signed_ticket_len + signature_len;

const join_fixed_len: usize =
    @sizeOf(TicketId) + @sizeOf(NetworkId) + public_key_len + 8 + 4 + 8;
pub const max_signed_join_len: usize = join_magic.len + 1 + join_fixed_len;
pub const max_join_len: usize = max_signed_join_len + signature_len;

const network_id_domain = "onyx-mesh-enrollment-network-v1";

/// A domain-separated hash of (realm, trust-root pubkey). Local nodes compare
/// this to a ticket's and request's `network_id` so a ticket minted for a
/// different mesh can never be redeemed here, even if the realm strings
/// happen to collide.
pub fn networkId(realm: []const u8, trust_root_pubkey: PublicKeyBytes) NetworkId {
    var h = Sha256.init(.{});
    h.update(network_id_domain);
    h.update(realm);
    h.update(&trust_root_pubkey);
    var out: NetworkId = undefined;
    h.final(&out);
    return out;
}

/// Draw a fresh single-use ticket id from the system CSPRNG.
pub fn generateTicketId() TicketId {
    var out: TicketId = undefined;
    std.crypto.random.bytes(&out);
    return out;
}

/// The signed fields of an enrollment ticket. `audience_pubkey` is the
/// identity key of the one admitting node allowed to redeem it (mandatory;
/// a weak or all-zero audience never decodes and never matches a valid
/// policy). `bound_node_pubkey` of all zero bytes means unbound (any joining
/// node key is accepted, subject to every other check).
pub const EnrollmentTicket = struct {
    network_id: NetworkId,
    realm: []const u8,
    ticket_id: TicketId,
    issuer_pubkey: PublicKeyBytes,
    audience_pubkey: PublicKeyBytes,
    allowed_roles: u64 = 0,
    allowed_frame_families: u32 = 0,
    max_fanout: u32 = 0,
    media_rights: u32 = 0,
    issued_ms: u64,
    expiry_ms: u64,
    revocation_epoch: u64 = 0,
    bound_node_pubkey: PublicKeyBytes = zero_pubkey,
};

pub const SignedTicket = struct {
    ticket: EnrollmentTicket,
    signature: SignatureBytes,
};

/// Proof-of-possession request: signed by the joining node's own key, naming
/// the ticket it wants to redeem and the roles/families it is asking for.
pub const JoinRequest = struct {
    ticket_id: TicketId,
    network_id: NetworkId,
    node_pubkey: PublicKeyBytes,
    requested_roles: u64 = 0,
    requested_frame_families: u32 = 0,
    request_ms: u64,
};

pub const SignedJoinRequest = struct {
    request: JoinRequest,
    signature: SignatureBytes,
};

/// One authorized ticket issuer and the roles it is trusted to grant. An
/// issuer can be trusted for the network yet still lack authority to grant a
/// specific role (`IssuerLacksAuthority`), independent of what a ticket it
/// signed claims to allow.
pub const Issuer = struct {
    pubkey: PublicKeyBytes,
    authorized_roles: u64,
};

/// Local admission policy. `realm` is borrowed: the `meshpass.Fields.realm`
/// of every `ReviewedAdmission` aliases it, so it must outlive the admission.
pub const Policy = struct {
    network_id: NetworkId,
    realm: []const u8,
    issuers: []const Issuer,
    /// This node's own identity public key. It must be unique per node (never
    /// a key shared mesh-wide): tickets whose `audience_pubkey` differs fail
    /// `WrongAudience`, which is what confines each ticket to one ledger.
    admitter_pubkey: PublicKeyBytes,
    max_ticket_ttl_ms: u64 = default_max_ticket_ttl_ms,
    allow_operator_enrollment: bool = false,
    /// Reject unbound tickets (all-zero `bound_node_pubkey`). An unbound
    /// ticket is a bearer secret: whoever presents it first to its audience
    /// node enrolls their own key. Unbound enrollment is an explicit opt-in.
    require_bound_node: bool = true,
    skew_ms: u64 = default_skew_ms,
    min_revocation_epoch: u64 = 0,
    /// Highest ticket `revocation_epoch` this node accepts. Bounds the epoch
    /// copied into minted passes so a raised revocation floor can evict them.
    current_revocation_epoch: u64 = 0,
    pass_ttl_ms: u64 = default_pass_ttl_ms,

    /// A policy that could never admit anything, that would mint an
    /// unbounded or unrevocable pass, or that names no usable admitter is a
    /// configuration error and fails closed.
    pub fn valid(self: Policy) bool {
        return self.realm.len > 0 and self.realm.len <= max_realm_len and
            self.issuers.len > 0 and
            !isWeakPublicKey(self.admitter_pubkey) and
            self.max_ticket_ttl_ms > 0 and
            self.skew_ms <= hard_max_ticket_ttl_ms and
            self.min_revocation_epoch <= self.current_revocation_epoch and
            self.pass_ttl_ms > 0 and self.pass_ttl_ms <= hard_max_pass_ttl_ms;
    }
};

pub const ReviewedAdmission = struct {
    fields: meshpass.Fields,
    ticket_id: TicketId,
};

pub const EncodeError = error{
    BufferTooSmall,
    RealmTooLarge,
    InvalidTime,
};

pub const DecodeError = error{
    Truncated,
    TrailingBytes,
    BadMagic,
    UnsupportedVersion,
    RealmTooLarge,
    InvalidTime,
    WeakPublicKey,
};

pub const VerifyError = error{BadSignature};

pub const SignError = EncodeError ||
    std.crypto.errors.IdentityElementError ||
    std.crypto.errors.NonCanonicalError ||
    std.crypto.errors.KeyMismatchError ||
    std.crypto.errors.WeakPublicKeyError;

/// Every member fails closed: an unmatched/unauthorized/stale/replayed input
/// never falls through to a different, more permissive outcome.
pub const ReviewError = error{
    InvalidPolicy,
    BadTicketSignature,
    BadRequestSignature,
    /// The request names a different ticket than the one actually presented.
    /// Not explicitly named by the spec's check list, but required so a
    /// node cannot prove possession against ticket B while redeeming ticket
    /// A's (possibly wider or differently bound) grant.
    TicketIdMismatch,
    UntrustedIssuer,
    IssuerLacksAuthority,
    WrongNetwork,
    WrongRealm,
    /// The ticket names a different admitting node than this one.
    WrongAudience,
    NotYetValid,
    Expired,
    TtlTooLong,
    RequestStale,
    Revoked,
    /// The ticket's `revocation_epoch` is above `current_revocation_epoch`.
    EpochFromFuture,
    Replayed,
    UnboundTicket,
    NodeKeyMismatch,
    /// The request asks for no role at all; an empty grant is never minted.
    EmptyGrant,
    RoleEscalation,
    FrameFamilyEscalation,
    MissingRequiredFamilies,
};

const required_relay_families = meshpass.frameFamilies(&.{ .control, .sync, .mooring });
const known_roles = meshpass.roles(std.enums.values(meshpass.Role));
const known_frame_families = meshpass.frameFamilies(std.enums.values(meshpass.FrameFamily));
const operator_role = meshpass.roles(&.{.operator});
const relay_role = meshpass.roles(&.{.relay});
const media_role = meshpass.roles(&.{.media});
const known_media_rights = meshpass.mediaRights(std.enums.values(meshpass.MediaRight));

/// Review a decoded, still-unverified ticket and join request against
/// `policy` and `ledger_view`, as of `now_ms`. `ledger_view` only needs to
/// support `isConsumed(TicketId) bool`, `isTicketRevoked(TicketId) bool`,
/// `isIssuerRevoked(PublicKeyBytes) bool`, and `revokedEpochFloor() u64`;
/// `../daemon/mesh_enrollment_ledger.zig`'s `Ledger` satisfies this directly.
pub fn review(
    policy: Policy,
    signed_ticket: SignedTicket,
    signed_request: SignedJoinRequest,
    ledger_view: anytype,
    now_ms: u64,
) ReviewError!ReviewedAdmission {
    if (!policy.valid()) return error.InvalidPolicy;

    verifyTicketSignature(signed_ticket) catch return error.BadTicketSignature;
    verifyJoinRequestSignature(signed_request) catch return error.BadRequestSignature;

    const ticket = signed_ticket.ticket;
    const request = signed_request.request;

    if (!std.mem.eql(u8, &ticket.ticket_id, &request.ticket_id)) return error.TicketIdMismatch;

    const issuer = findIssuer(policy, ticket.issuer_pubkey) orelse return error.UntrustedIssuer;
    if (!isSubsetU64(request.requested_roles, issuer.authorized_roles)) return error.IssuerLacksAuthority;

    if (!std.mem.eql(u8, &ticket.network_id, &policy.network_id)) return error.WrongNetwork;
    if (!std.mem.eql(u8, &request.network_id, &policy.network_id)) return error.WrongNetwork;
    if (!std.mem.eql(u8, ticket.realm, policy.realm)) return error.WrongRealm;
    if (!std.mem.eql(u8, &ticket.audience_pubkey, &policy.admitter_pubkey)) return error.WrongAudience;

    // Issuer clocks may run up to `skew_ms` ahead; expiry is never extended,
    // so the consumed-ticket ledger can prune strictly after `expiry_ms`.
    if (now_ms +| policy.skew_ms < ticket.issued_ms) return error.NotYetValid;
    if (now_ms > ticket.expiry_ms) return error.Expired;
    const ttl = ticket.expiry_ms - ticket.issued_ms;
    const effective_max_ttl = @min(policy.max_ticket_ttl_ms, hard_max_ticket_ttl_ms);
    if (ttl > effective_max_ttl) return error.TtlTooLong;

    if (!withinSkew(request.request_ms, now_ms, policy.skew_ms)) return error.RequestStale;

    if (ledger_view.isTicketRevoked(ticket.ticket_id)) return error.Revoked;
    if (ledger_view.isIssuerRevoked(ticket.issuer_pubkey)) return error.Revoked;
    if (ticket.revocation_epoch < policy.min_revocation_epoch) return error.Revoked;
    if (ticket.revocation_epoch < ledger_view.revokedEpochFloor()) return error.Revoked;
    if (ticket.revocation_epoch > policy.current_revocation_epoch) return error.EpochFromFuture;

    if (ledger_view.isConsumed(ticket.ticket_id)) return error.Replayed;

    if (isUnboundKey(ticket.bound_node_pubkey)) {
        if (policy.require_bound_node) return error.UnboundTicket;
    } else if (!std.mem.eql(u8, &ticket.bound_node_pubkey, &request.node_pubkey)) {
        return error.NodeKeyMismatch;
    }

    if (request.requested_roles == 0) return error.EmptyGrant;
    if (!isSubsetU64(request.requested_roles, known_roles)) return error.RoleEscalation;
    if (!isSubsetU64(request.requested_roles, ticket.allowed_roles)) return error.RoleEscalation;
    if ((request.requested_roles & operator_role) != 0 and !policy.allow_operator_enrollment) {
        return error.RoleEscalation;
    }

    if (!isSubsetU32(request.requested_frame_families, known_frame_families)) {
        return error.FrameFamilyEscalation;
    }
    if (!isSubsetU32(request.requested_frame_families, ticket.allowed_frame_families)) {
        return error.FrameFamilyEscalation;
    }

    if ((request.requested_roles & relay_role) != 0) {
        if (!isSubsetU32(required_relay_families, request.requested_frame_families)) {
            return error.MissingRequiredFamilies;
        }
    }

    return .{
        .fields = .{
            .node_pubkey = request.node_pubkey,
            .realm = policy.realm,
            .roles = request.requested_roles,
            .issued_ms = now_ms,
            .expiry_ms = now_ms +| policy.pass_ttl_ms,
            .allowed_frame_families = request.requested_frame_families,
            .max_fanout = ticket.max_fanout,
            // Media rights only accompany a granted media role (which the
            // issuer must be authorized for), and never carry unknown bits.
            .media_rights = if ((request.requested_roles & media_role) != 0)
                ticket.media_rights & known_media_rights
            else
                0,
            // Bind the pass to the ticket's epoch, which is at most
            // `current_revocation_epoch`: raising the revocation floor past
            // it revokes the ticket and every pass minted from it.
            .revocation_epoch = ticket.revocation_epoch,
        },
        .ticket_id = ticket.ticket_id,
    };
}

/// Sign the reviewed admission's fields into a MeshPass token. `issuer_key`
/// is the local node's own MeshPass-issuing key (steady-state admission
/// authority), not the enrollment ticket's issuer.
pub fn issueMeshPass(issuer_key: Ed25519.KeyPair, admission: ReviewedAdmission) meshpass.IssueError!meshpass.Token {
    return meshpass.issue(issuer_key, admission.fields);
}

/// Sign `ticket` with the issuer's key, producing the wire-ready envelope.
pub fn signTicket(issuer_key: Ed25519.KeyPair, ticket: EnrollmentTicket) SignError!SignedTicket {
    var buf: [max_signed_ticket_len]u8 = undefined;
    const len = try encodeSignedTicketInto(&buf, ticket);
    const sig = try issuer_key.sign(buf[0..len], null);
    return .{ .ticket = ticket, .signature = sig.toBytes() };
}

/// Sign `request` with the joining node's own key (proof of possession).
pub fn signJoinRequest(node_key: Ed25519.KeyPair, request: JoinRequest) SignError!SignedJoinRequest {
    var buf: [max_signed_join_len]u8 = undefined;
    const len = try encodeSignedJoinInto(&buf, request);
    const sig = try node_key.sign(buf[0..len], null);
    return .{ .request = request, .signature = sig.toBytes() };
}

/// Verify `signed.signature` against the ticket's own `issuer_pubkey`.
pub fn verifyTicketSignature(signed: SignedTicket) VerifyError!void {
    var buf: [max_signed_ticket_len]u8 = undefined;
    const len = encodeSignedTicketInto(&buf, signed.ticket) catch return error.BadSignature;
    if (isWeakPublicKey(signed.ticket.issuer_pubkey)) return error.BadSignature;
    const pk = Ed25519.PublicKey.fromBytes(signed.ticket.issuer_pubkey) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(signed.signature);
    sig.verifyStrict(buf[0..len], pk) catch return error.BadSignature;
}

/// Verify `signed.signature` against the request's own `node_pubkey`.
pub fn verifyJoinRequestSignature(signed: SignedJoinRequest) VerifyError!void {
    var buf: [max_signed_join_len]u8 = undefined;
    const len = encodeSignedJoinInto(&buf, signed.request) catch return error.BadSignature;
    if (isWeakPublicKey(signed.request.node_pubkey)) return error.BadSignature;
    const pk = Ed25519.PublicKey.fromBytes(signed.request.node_pubkey) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(signed.signature);
    sig.verifyStrict(buf[0..len], pk) catch return error.BadSignature;
}

/// Encode the complete wire form (signed fields + detached signature).
pub fn encodeTicket(out: []u8, signed: SignedTicket) EncodeError!usize {
    const len = try encodeSignedTicketInto(out, signed.ticket);
    if (out.len - len < signature_len) return error.BufferTooSmall;
    @memcpy(out[len..][0..signature_len], &signed.signature);
    return len + signature_len;
}

/// Decode a ticket from `encodeTicket` bytes. The signature is NOT verified
/// here; call `verifyTicketSignature` (or `review`, which does) before
/// trusting the result. The returned `realm` borrows from `bytes`.
pub fn decodeTicket(bytes: []const u8) DecodeError!SignedTicket {
    const decoded = try decodeTicketFields(bytes);
    const rest = bytes[decoded.consumed..];
    if (rest.len < signature_len) return error.Truncated;
    if (rest.len > signature_len) return error.TrailingBytes;
    return .{ .ticket = decoded.ticket, .signature = rest[0..signature_len].* };
}

/// Encode the complete wire form (signed fields + detached signature).
pub fn encodeJoinRequest(out: []u8, signed: SignedJoinRequest) EncodeError!usize {
    const len = try encodeSignedJoinInto(out, signed.request);
    if (out.len - len < signature_len) return error.BufferTooSmall;
    @memcpy(out[len..][0..signature_len], &signed.signature);
    return len + signature_len;
}

/// Decode a join request from `encodeJoinRequest` bytes. The signature is
/// NOT verified here; call `verifyJoinRequestSignature` (or `review`) first.
pub fn decodeJoinRequest(bytes: []const u8) DecodeError!SignedJoinRequest {
    const decoded = try decodeJoinRequestFields(bytes);
    const rest = bytes[decoded.consumed..];
    if (rest.len < signature_len) return error.Truncated;
    if (rest.len > signature_len) return error.TrailingBytes;
    return .{ .request = decoded.request, .signature = rest[0..signature_len].* };
}

fn encodeSignedTicketInto(out: []u8, ticket: EnrollmentTicket) EncodeError!usize {
    if (ticket.realm.len == 0 or ticket.realm.len > max_realm_len) return error.RealmTooLarge;
    if (ticket.issued_ms > ticket.expiry_ms) return error.InvalidTime;
    const needed = ticket_magic.len + 1 + ticket_fixed_tail_len + ticket.realm.len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    copyBytes(out, &pos, ticket_magic);
    out[pos] = ticket_version;
    pos += 1;
    copyBytes(out, &pos, &ticket.network_id);
    writeU16(out, &pos, @intCast(ticket.realm.len));
    copyBytes(out, &pos, ticket.realm);
    copyBytes(out, &pos, &ticket.ticket_id);
    copyBytes(out, &pos, &ticket.issuer_pubkey);
    copyBytes(out, &pos, &ticket.audience_pubkey);
    writeU64(out, &pos, ticket.allowed_roles);
    writeU32(out, &pos, ticket.allowed_frame_families);
    writeU32(out, &pos, ticket.max_fanout);
    writeU32(out, &pos, ticket.media_rights);
    writeU64(out, &pos, ticket.issued_ms);
    writeU64(out, &pos, ticket.expiry_ms);
    writeU64(out, &pos, ticket.revocation_epoch);
    copyBytes(out, &pos, &ticket.bound_node_pubkey);
    std.debug.assert(pos == needed);
    return pos;
}

fn encodeSignedJoinInto(out: []u8, request: JoinRequest) EncodeError!usize {
    const needed = join_magic.len + 1 + join_fixed_len;
    if (out.len < needed) return error.BufferTooSmall;

    var pos: usize = 0;
    copyBytes(out, &pos, join_magic);
    out[pos] = join_version;
    pos += 1;
    copyBytes(out, &pos, &request.ticket_id);
    copyBytes(out, &pos, &request.network_id);
    copyBytes(out, &pos, &request.node_pubkey);
    writeU64(out, &pos, request.requested_roles);
    writeU32(out, &pos, request.requested_frame_families);
    writeU64(out, &pos, request.request_ms);
    std.debug.assert(pos == needed);
    return pos;
}

const DecodedTicket = struct { ticket: EnrollmentTicket, consumed: usize };

fn decodeTicketFields(bytes: []const u8) DecodeError!DecodedTicket {
    var r = Cursor{ .buf = bytes };
    if (!std.mem.eql(u8, try r.take(ticket_magic.len), ticket_magic)) return error.BadMagic;
    const version = (try r.take(1))[0];
    if (version != ticket_version) return error.UnsupportedVersion;

    const network_id = try r.takeArray(@sizeOf(NetworkId));
    const realm_len = try r.takeU16();
    if (realm_len == 0 or realm_len > max_realm_len) return error.RealmTooLarge;
    const realm = try r.take(realm_len);
    const ticket_id = try r.takeArray(@sizeOf(TicketId));
    const issuer_pubkey = try r.takeArray(public_key_len);
    if (isWeakPublicKey(issuer_pubkey)) return error.WeakPublicKey;
    const audience_pubkey = try r.takeArray(public_key_len);
    if (isWeakPublicKey(audience_pubkey)) return error.WeakPublicKey;
    const allowed_roles = try r.takeU64();
    const allowed_frame_families = try r.takeU32();
    const max_fanout = try r.takeU32();
    const media_rights = try r.takeU32();
    const issued_ms = try r.takeU64();
    const expiry_ms = try r.takeU64();
    if (issued_ms > expiry_ms) return error.InvalidTime;
    const revocation_epoch = try r.takeU64();
    const bound_node_pubkey = try r.takeArray(public_key_len);
    if (!isUnboundKey(bound_node_pubkey) and isWeakPublicKey(bound_node_pubkey)) return error.WeakPublicKey;

    return .{
        .ticket = .{
            .network_id = network_id,
            .realm = realm,
            .ticket_id = ticket_id,
            .issuer_pubkey = issuer_pubkey,
            .audience_pubkey = audience_pubkey,
            .allowed_roles = allowed_roles,
            .allowed_frame_families = allowed_frame_families,
            .max_fanout = max_fanout,
            .media_rights = media_rights,
            .issued_ms = issued_ms,
            .expiry_ms = expiry_ms,
            .revocation_epoch = revocation_epoch,
            .bound_node_pubkey = bound_node_pubkey,
        },
        .consumed = r.pos,
    };
}

const DecodedJoin = struct { request: JoinRequest, consumed: usize };

fn decodeJoinRequestFields(bytes: []const u8) DecodeError!DecodedJoin {
    var r = Cursor{ .buf = bytes };
    if (!std.mem.eql(u8, try r.take(join_magic.len), join_magic)) return error.BadMagic;
    const version = (try r.take(1))[0];
    if (version != join_version) return error.UnsupportedVersion;

    const ticket_id = try r.takeArray(@sizeOf(TicketId));
    const network_id = try r.takeArray(@sizeOf(NetworkId));
    const node_pubkey = try r.takeArray(public_key_len);
    if (isWeakPublicKey(node_pubkey)) return error.WeakPublicKey;
    const requested_roles = try r.takeU64();
    const requested_frame_families = try r.takeU32();
    const request_ms = try r.takeU64();

    return .{
        .request = .{
            .ticket_id = ticket_id,
            .network_id = network_id,
            .node_pubkey = node_pubkey,
            .requested_roles = requested_roles,
            .requested_frame_families = requested_frame_families,
            .request_ms = request_ms,
        },
        .consumed = r.pos,
    };
}

fn findIssuer(policy: Policy, issuer_pubkey: PublicKeyBytes) ?Issuer {
    for (policy.issuers) |issuer| {
        if (std.mem.eql(u8, &issuer.pubkey, &issuer_pubkey)) return issuer;
    }
    return null;
}

fn withinSkew(request_ms: u64, now_ms: u64, skew_ms: u64) bool {
    const diff = if (request_ms > now_ms) request_ms - now_ms else now_ms - request_ms;
    return diff <= skew_ms;
}

fn isSubsetU64(requested: u64, allowed: u64) bool {
    return (requested & ~allowed) == 0;
}

fn isSubsetU32(requested: u32, allowed: u32) bool {
    return (requested & ~allowed) == 0;
}

fn isUnboundKey(bytes: PublicKeyBytes) bool {
    return std.mem.eql(u8, &bytes, &zero_pubkey);
}

/// Reject public keys that are malformed, non-canonical, or of low order
/// (which includes the identity element). This is distinct from (and runs
/// before) any signature check.
fn isWeakPublicKey(bytes: PublicKeyBytes) bool {
    const pk = Ed25519.PublicKey.fromBytes(bytes) catch return true;
    const point = std.crypto.ecc.Edwards25519.fromBytes(pk.bytes) catch return true;
    point.rejectLowOrder() catch return true;
    return false;
}

fn copyBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.* .. pos.* + bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeU16(out: []u8, pos: *usize, value: u16) void {
    std.mem.writeInt(u16, out[pos.*..][0..2], value, .big);
    pos.* += 2;
}

fn writeU32(out: []u8, pos: *usize, value: u32) void {
    std.mem.writeInt(u32, out[pos.*..][0..4], value, .big);
    pos.* += 4;
}

fn writeU64(out: []u8, pos: *usize, value: u64) void {
    std.mem.writeInt(u64, out[pos.*..][0..8], value, .big);
    pos.* += 8;
}

const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn take(self: *Cursor, len: usize) DecodeError![]const u8 {
        if (len > self.buf.len - self.pos) return error.Truncated;
        defer self.pos += len;
        return self.buf[self.pos..][0..len];
    }

    fn takeArray(self: *Cursor, comptime len: usize) DecodeError![len]u8 {
        const bytes = try self.take(len);
        var out: [len]u8 = undefined;
        @memcpy(&out, bytes);
        return out;
    }

    fn takeU16(self: *Cursor) DecodeError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .big);
    }

    fn takeU32(self: *Cursor) DecodeError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .big);
    }

    fn takeU64(self: *Cursor) DecodeError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .big);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Minimal fake satisfying the `ledger_view` duck type for pure review()
/// tests, independent of the real (daemon-owned, stateful) ledger.
const FakeLedgerView = struct {
    consumed: []const TicketId = &.{},
    revoked_tickets: []const TicketId = &.{},
    revoked_issuers: []const PublicKeyBytes = &.{},
    epoch_floor: u64 = 0,

    fn isConsumed(self: FakeLedgerView, ticket_id: TicketId) bool {
        return containsId(self.consumed, ticket_id);
    }
    fn isTicketRevoked(self: FakeLedgerView, ticket_id: TicketId) bool {
        return containsId(self.revoked_tickets, ticket_id);
    }
    fn isIssuerRevoked(self: FakeLedgerView, pubkey: PublicKeyBytes) bool {
        return containsId(self.revoked_issuers, pubkey);
    }
    fn revokedEpochFloor(self: FakeLedgerView) u64 {
        return self.epoch_floor;
    }
};

fn containsId(haystack: []const [32]u8, needle: [32]u8) bool {
    for (haystack) |item| {
        if (std.mem.eql(u8, &item, &needle)) return true;
    }
    return false;
}

fn testIssuerKeyPair() !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x51)));
}

fn testNodeKeyPair() !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x52)));
}

/// Identity key of the admitting node that `testPolicy` and `testTicket`
/// agree on. The seed is a fixed valid scalar, so derivation cannot fail.
fn testAdmitterPubkey(seed: u8) PublicKeyBytes {
    const kp = Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed))) catch unreachable;
    return kp.public_key.toBytes();
}

const test_admitter_seed: u8 = 0x57;

/// Caller declares the returned array as a local (so its storage outlives
/// the slice stashed in a `Policy`), then passes `&issuers` to `testPolicy`.
fn testIssuerList(issuer_pubkey: PublicKeyBytes) [1]Issuer {
    return .{.{
        .pubkey = issuer_pubkey,
        .authorized_roles = meshpass.roles(&.{ .relay, .witness, .services, .media, .bridge }),
    }};
}

/// Opts into unbound tickets explicitly so every other check is exercised
/// against the most permissive binding mode; the default is covered on its own.
fn testPolicy(issuers: []const Issuer, network_id: NetworkId) Policy {
    return .{
        .network_id = network_id,
        .realm = "mesh-realm",
        .issuers = issuers,
        .admitter_pubkey = testAdmitterPubkey(test_admitter_seed),
        .require_bound_node = false,
        .max_ticket_ttl_ms = 60_000,
        .skew_ms = 1_000,
        .min_revocation_epoch = 3,
        .current_revocation_epoch = 5,
        .pass_ttl_ms = 10_000,
    };
}

fn testTicket(issuer_pubkey: PublicKeyBytes, network_id: NetworkId) EnrollmentTicket {
    return .{
        .network_id = network_id,
        .realm = "mesh-realm",
        .ticket_id = @splat(0x61),
        .issuer_pubkey = issuer_pubkey,
        .audience_pubkey = testAdmitterPubkey(test_admitter_seed),
        .allowed_roles = meshpass.roles(&.{ .relay, .witness }),
        .allowed_frame_families = meshpass.frameFamilies(&.{ .control, .sync, .mooring, .irc_app }),
        .max_fanout = 16,
        .media_rights = 0,
        .issued_ms = 1_000,
        .expiry_ms = 11_000,
        .revocation_epoch = 5,
    };
}

fn testRequest(ticket_id: TicketId, network_id: NetworkId, node_pubkey: PublicKeyBytes) JoinRequest {
    return .{
        .ticket_id = ticket_id,
        .network_id = network_id,
        .node_pubkey = node_pubkey,
        .requested_roles = meshpass.roles(&.{.relay}),
        .requested_frame_families = meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
        .request_ms = 1_500,
    };
}

test "mesh enrollment: valid ticket and request produce a MeshPass that binds with relay + required families" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    const ledger = FakeLedgerView{};
    const admission = try review(policy, signed_ticket, signed_request, ledger, 1_500);
    try testing.expectEqual(ticket.ticket_id, admission.ticket_id);

    const issuing_key = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x70)));
    const pass = try issueMeshPass(issuing_key, admission);

    var buf: [meshpass.max_token_len]u8 = undefined;
    const decoded = try meshpass.decode(buf[0..try meshpass.encode(&buf, pass)]);
    const root = meshpass.TrustRoot{
        .public_key = issuing_key.public_key.toBytes(),
        .realm = policy.realm,
        .min_revocation_epoch = policy.min_revocation_epoch,
    };
    const fields = try meshpass.bindDecodedToken(
        decoded,
        root,
        1_500,
        node.public_key.toBytes(),
        meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
    );
    try testing.expect(meshpass.hasRole(fields, .relay));
    try testing.expect(!meshpass.hasRole(fields, .witness));
    try testing.expect(!meshpass.mayUseFrameFamily(fields, .irc_app));
    try testing.expectEqual(ticket.max_fanout, fields.max_fanout);
    try testing.expectEqual(ticket.revocation_epoch, fields.revocation_epoch);

    // A different joining key cannot bind the pass.
    const other = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x53)));
    try testing.expectError(error.PeerKeyMismatch, meshpass.bindDecodedToken(
        decoded,
        root,
        1_500,
        other.public_key.toBytes(),
        meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
    ));
    // Raising the steady-state floor past the ticket epoch revokes the pass.
    var raised_root = root;
    raised_root.min_revocation_epoch = ticket.revocation_epoch + 1;
    try testing.expectError(error.Revoked, meshpass.bindDecodedToken(
        decoded,
        raised_root,
        1_500,
        node.public_key.toBytes(),
        meshpass.frameFamilies(&.{ .control, .sync, .mooring }),
    ));
}

test "mesh enrollment: review reports Replayed for an already-consumed ticket_id" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    const fresh = FakeLedgerView{};
    _ = try review(policy, signed_ticket, signed_request, fresh, 1_500);

    const replay_ledger = FakeLedgerView{ .consumed = &.{ticket.ticket_id} };
    try testing.expectError(error.Replayed, review(policy, signed_ticket, signed_request, replay_ledger, 1_500));
}

test "mesh enrollment: wrong network_id (different realm or trust root) fails WrongNetwork" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const other_root = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x55)));
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const other_realm_network = networkId("other-realm", issuer.public_key.toBytes());
    const other_root_network = networkId("mesh-realm", other_root.public_key.toBytes());
    try testing.expect(!std.mem.eql(u8, &network_id, &other_realm_network));
    try testing.expect(!std.mem.eql(u8, &network_id, &other_root_network));
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);

    for ([_]NetworkId{ other_realm_network, other_root_network }) |wrong| {
        var ticket = testTicket(issuer.public_key.toBytes(), network_id);
        ticket.network_id = wrong;
        const signed_ticket = try signTicket(issuer, ticket);
        const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
        const signed_request = try signJoinRequest(node, request);
        try testing.expectError(error.WrongNetwork, review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500));

        // A correct ticket with a request aimed at another network also fails.
        const good_ticket = try signTicket(issuer, testTicket(issuer.public_key.toBytes(), network_id));
        const wrong_request = try signJoinRequest(node, testRequest(ticket.ticket_id, wrong, node.public_key.toBytes()));
        try testing.expectError(error.WrongNetwork, review(policy, good_ticket, wrong_request, FakeLedgerView{}, 1_500));
    }
}

test "mesh enrollment: wrong realm string fails WrongRealm" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.realm = "other-realm-string";
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    try testing.expectError(error.WrongRealm, review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500));
}

test "mesh enrollment: revoked ticket, revoked issuer, and stale epoch each fail Revoked" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    try testing.expectError(
        error.Revoked,
        review(policy, signed_ticket, signed_request, FakeLedgerView{ .revoked_tickets = &.{ticket.ticket_id} }, 1_500),
    );
    try testing.expectError(
        error.Revoked,
        review(
            policy,
            signed_ticket,
            signed_request,
            FakeLedgerView{ .revoked_issuers = &.{issuer.public_key.toBytes()} },
            1_500,
        ),
    );
    try testing.expectError(
        error.Revoked,
        review(policy, signed_ticket, signed_request, FakeLedgerView{ .epoch_floor = ticket.revocation_epoch + 1 }, 1_500),
    );

    var stale_policy = policy;
    stale_policy.min_revocation_epoch = ticket.revocation_epoch + 1;
    stale_policy.current_revocation_epoch = stale_policy.min_revocation_epoch;
    try testing.expectError(error.Revoked, review(stale_policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500));
}

test "mesh enrollment: expired, not-yet-valid, and over-max-TTL tickets fail closed" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    var future_ticket = ticket;
    future_ticket.issued_ms = 5_000;
    future_ticket.expiry_ms = 6_000;
    const future_signed = try signTicket(issuer, future_ticket);
    var future_request = request;
    future_request.request_ms = 3_999;
    const future_signed_request = try signJoinRequest(node, future_request);
    // Up to `skew_ms` of issuer clock lead is tolerated; one more is not.
    _ = try review(policy, future_signed, future_signed_request, FakeLedgerView{}, 4_000);
    try testing.expectError(
        error.NotYetValid,
        review(policy, future_signed, future_signed_request, FakeLedgerView{}, 3_999),
    );
    // Expiry itself is the last valid instant (never extended by skew).
    var at_expiry_request = request;
    at_expiry_request.request_ms = ticket.expiry_ms;
    _ = try review(policy, signed_ticket, try signJoinRequest(node, at_expiry_request), FakeLedgerView{}, ticket.expiry_ms);
    try testing.expectError(
        error.Expired,
        review(policy, signed_ticket, signed_request, FakeLedgerView{}, ticket.expiry_ms + 1),
    );

    var over_ttl_ticket = ticket;
    over_ttl_ticket.expiry_ms = ticket.issued_ms + policy.max_ticket_ttl_ms + 1;
    const over_ttl_signed = try signTicket(issuer, over_ttl_ticket);
    const over_ttl_request = testRequest(over_ttl_ticket.ticket_id, network_id, node.public_key.toBytes());
    const over_ttl_signed_request = try signJoinRequest(node, over_ttl_request);
    try testing.expectError(
        error.TtlTooLong,
        review(policy, over_ttl_signed, over_ttl_signed_request, FakeLedgerView{}, 1_500),
    );

    var hard_over_policy = policy;
    hard_over_policy.max_ticket_ttl_ms = hard_max_ticket_ttl_ms + 1_000;
    var hard_over_ticket = ticket;
    hard_over_ticket.issued_ms = 0;
    hard_over_ticket.expiry_ms = hard_max_ticket_ttl_ms + 1;
    const hard_over_signed = try signTicket(issuer, hard_over_ticket);
    const hard_over_request = testRequest(hard_over_ticket.ticket_id, network_id, node.public_key.toBytes());
    const hard_over_signed_request = try signJoinRequest(node, hard_over_request);
    try testing.expectError(
        error.TtlTooLong,
        review(hard_over_policy, hard_over_signed, hard_over_signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: request outside skew window fails RequestStale" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    var request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    request.request_ms = 1_500 + policy.skew_ms + 1;
    const signed_request = try signJoinRequest(node, request);

    try testing.expectError(error.RequestStale, review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500));
}

test "mesh enrollment: requested roles beyond allowed_roles fail RoleEscalation; operator needs explicit policy opt-in" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);

    var over_request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    over_request.requested_roles = meshpass.roles(&.{ .relay, .services });
    const over_signed_request = try signJoinRequest(node, over_request);
    try testing.expectError(
        error.RoleEscalation,
        review(policy, signed_ticket, over_signed_request, FakeLedgerView{}, 1_500),
    );

    var operator_ticket = ticket;
    operator_ticket.allowed_roles = meshpass.roles(&.{.operator});
    const operator_signed_ticket = try signTicket(issuer, operator_ticket);
    var operator_policy = policy;
    const operator_issuers = [_]Issuer{.{ .pubkey = issuer.public_key.toBytes(), .authorized_roles = meshpass.roles(&.{.operator}) }};
    operator_policy.issuers = &operator_issuers;
    var operator_request = testRequest(operator_ticket.ticket_id, network_id, node.public_key.toBytes());
    operator_request.requested_roles = meshpass.roles(&.{.operator});
    operator_request.requested_frame_families = 0;
    const operator_signed_request = try signJoinRequest(node, operator_request);
    try testing.expectError(
        error.RoleEscalation,
        review(operator_policy, operator_signed_ticket, operator_signed_request, FakeLedgerView{}, 1_500),
    );

    operator_policy.allow_operator_enrollment = true;
    _ = try review(operator_policy, operator_signed_ticket, operator_signed_request, FakeLedgerView{}, 1_500);
}

test "mesh enrollment: requested frame families beyond allowed fail FrameFamilyEscalation" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.allowed_frame_families = meshpass.frameFamilies(&.{.control});
    const signed_ticket = try signTicket(issuer, ticket);
    var request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    request.requested_roles = meshpass.roles(&.{.witness});
    const signed_request = try signJoinRequest(node, request);

    try testing.expectError(
        error.FrameFamilyEscalation,
        review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: relay role missing required families fails MissingRequiredFamilies" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    var request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    request.requested_frame_families = meshpass.frameFamilies(&.{.control});
    const signed_request = try signJoinRequest(node, request);

    try testing.expectError(
        error.MissingRequiredFamilies,
        review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: issuer not in policy, or lacking authority, fails UntrustedIssuer/IssuerLacksAuthority" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());

    const stranger = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x56)));
    const stranger_issuers = testIssuerList(stranger.public_key.toBytes());
    const stranger_policy = testPolicy(&stranger_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);
    try testing.expectError(
        error.UntrustedIssuer,
        review(stranger_policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );

    const limited_issuers = [_]Issuer{.{ .pubkey = issuer.public_key.toBytes(), .authorized_roles = meshpass.roles(&.{.witness}) }};
    const limited_policy = testPolicy(&limited_issuers, network_id);
    try testing.expectError(
        error.IssuerLacksAuthority,
        review(limited_policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: bound ticket presented by a different node key fails NodeKeyMismatch" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const other_node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x54)));
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.bound_node_pubkey = node.public_key.toBytes();
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, other_node.public_key.toBytes());
    const signed_request = try signJoinRequest(other_node, request);

    try testing.expectError(
        error.NodeKeyMismatch,
        review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: a request naming a different ticket_id fails TicketIdMismatch" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    var request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    request.ticket_id = @splat(0x99);
    const signed_request = try signJoinRequest(node, request);

    try testing.expectError(
        error.TicketIdMismatch,
        review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: a tampered request proof fails BadRequestSignature" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    var signed_request = try signJoinRequest(node, request);
    signed_request.request.request_ms += 1;

    try testing.expectError(
        error.BadRequestSignature,
        review(policy, signed_ticket, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: a tampered ticket byte or signature fails BadTicketSignature" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    var tampered_field = signed_ticket;
    tampered_field.ticket.max_fanout += 1;
    try testing.expectError(
        error.BadTicketSignature,
        review(policy, tampered_field, signed_request, FakeLedgerView{}, 1_500),
    );

    var tampered_sig = signed_ticket;
    tampered_sig.signature[0] ^= 0x80;
    try testing.expectError(
        error.BadTicketSignature,
        review(policy, tampered_sig, signed_request, FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: wire round-trip preserves fields and signature validity" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);

    var ticket_buf: [max_ticket_len]u8 = undefined;
    const ticket_wire = ticket_buf[0..try encodeTicket(&ticket_buf, signed_ticket)];
    const decoded_ticket = try decodeTicket(ticket_wire);
    try verifyTicketSignature(decoded_ticket);
    try testing.expectEqualSlices(u8, ticket.realm, decoded_ticket.ticket.realm);
    try testing.expectEqual(ticket.ticket_id, decoded_ticket.ticket.ticket_id);

    const request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);
    var join_buf: [max_join_len]u8 = undefined;
    const join_wire = join_buf[0..try encodeJoinRequest(&join_buf, signed_request)];
    const decoded_join = try decodeJoinRequest(join_wire);
    try verifyJoinRequestSignature(decoded_join);
    try testing.expectEqual(request.node_pubkey, decoded_join.request.node_pubkey);
}

test "mesh enrollment decoder rejects truncation, trailing bytes, bad version, and oversized realm" {
    const issuer = try testIssuerKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    var buf: [max_ticket_len]u8 = undefined;
    const wire = buf[0..try encodeTicket(&buf, signed_ticket)];

    try testing.expectError(error.Truncated, decodeTicket(wire[0 .. wire.len - 1]));

    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decodeTicket(trailing));

    const bad_version = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(bad_version);
    bad_version[ticket_magic.len] +%= 1;
    try testing.expectError(error.UnsupportedVersion, decodeTicket(bad_version));

    const bad_magic = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try testing.expectError(error.BadMagic, decodeTicket(bad_magic));

    const oversized_realm = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(oversized_realm);
    const realm_len_offset = ticket_magic.len + 1 + @sizeOf(NetworkId);
    std.mem.writeInt(u16, oversized_realm[realm_len_offset..][0..2], max_realm_len + 1, .big);
    try testing.expectError(error.RealmTooLarge, decodeTicket(oversized_realm));
}

test "mesh enrollment decoder rejects a weak (identity-element) embedded public key" {
    const issuer = try testIssuerKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.bound_node_pubkey = @splat(0);
    ticket.bound_node_pubkey[0] = 1; // not the all-zero "unbound" sentinel
    const signed_ticket = try signTicket(issuer, ticket);
    var buf: [max_ticket_len]u8 = undefined;
    const wire = buf[0..try encodeTicket(&buf, signed_ticket)];
    try testing.expectError(error.WeakPublicKey, decodeTicket(wire));
}

test "mesh enrollment: unknown role or frame-family bits fail closed even when every signer allows them" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const all_issuers = [_]Issuer{.{ .pubkey = issuer.public_key.toBytes(), .authorized_roles = std.math.maxInt(u64) }};
    const policy = testPolicy(&all_issuers, network_id);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.allowed_roles = std.math.maxInt(u64);
    ticket.allowed_frame_families = std.math.maxInt(u32);
    const signed_ticket = try signTicket(issuer, ticket);

    var unknown_role = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    unknown_role.requested_roles |= @as(u64, 1) << 40;
    try testing.expectError(
        error.RoleEscalation,
        review(policy, signed_ticket, try signJoinRequest(node, unknown_role), FakeLedgerView{}, 1_500),
    );

    var unknown_family = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    unknown_family.requested_frame_families |= @as(u32, 1) << 20;
    try testing.expectError(
        error.FrameFamilyEscalation,
        review(policy, signed_ticket, try signJoinRequest(node, unknown_family), FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: an empty role request fails EmptyGrant" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    var request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    request.requested_roles = 0;
    try testing.expectError(
        error.EmptyGrant,
        review(policy, signed_ticket, try signJoinRequest(node, request), FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: require_bound_node rejects unbound tickets and admits the bound key" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    var policy = testPolicy(&policy_issuers, network_id);
    policy.require_bound_node = true;
    const request = testRequest(@splat(0x61), network_id, node.public_key.toBytes());
    const signed_request = try signJoinRequest(node, request);

    const unbound = try signTicket(issuer, testTicket(issuer.public_key.toBytes(), network_id));
    try testing.expectError(error.UnboundTicket, review(policy, unbound, signed_request, FakeLedgerView{}, 1_500));

    var bound_ticket = testTicket(issuer.public_key.toBytes(), network_id);
    bound_ticket.bound_node_pubkey = node.public_key.toBytes();
    const bound = try signTicket(issuer, bound_ticket);
    const admission = try review(policy, bound, signed_request, FakeLedgerView{}, 1_500);
    try testing.expectEqual(node.public_key.toBytes(), admission.fields.node_pubkey);
}

test "mesh enrollment: an invalid policy fails InvalidPolicy before any other check" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const good = testPolicy(&policy_issuers, network_id);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id);
    const signed_ticket = try signTicket(issuer, ticket);
    const signed_request = try signJoinRequest(node, testRequest(ticket.ticket_id, network_id, node.public_key.toBytes()));

    var empty_realm = good;
    empty_realm.realm = "";
    var no_issuers = good;
    no_issuers.issuers = &.{};
    var zero_ttl = good;
    zero_ttl.max_ticket_ttl_ms = 0;
    var zero_pass = good;
    zero_pass.pass_ttl_ms = 0;
    var long_pass = good;
    long_pass.pass_ttl_ms = hard_max_pass_ttl_ms + 1;
    var zero_admitter = good;
    zero_admitter.admitter_pubkey = @splat(0);
    var inverted_epochs = good;
    inverted_epochs.min_revocation_epoch = good.current_revocation_epoch + 1;
    for ([_]Policy{ empty_realm, no_issuers, zero_ttl, zero_pass, long_pass, zero_admitter, inverted_epochs }) |bad| {
        try testing.expectError(error.InvalidPolicy, review(bad, signed_ticket, signed_request, FakeLedgerView{}, 1_500));
    }
}

test "mesh enrollment: low-order embedded keys are rejected by decode and by signature verification" {
    const issuer = try testIssuerKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    // y = 0 encodes a valid curve point of order 4 (not the identity).
    const low_order: PublicKeyBytes = @splat(0);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.bound_node_pubkey = @splat(0);
    ticket.bound_node_pubkey[31] = 0x80; // y = 0 with sign bit; not the all-zero sentinel
    const signed_ticket = try signTicket(issuer, ticket);
    var buf: [max_ticket_len]u8 = undefined;
    const wire = buf[0..try encodeTicket(&buf, signed_ticket)];
    try testing.expectError(error.WeakPublicKey, decodeTicket(wire));

    const forged = SignedJoinRequest{
        .request = testRequest(@splat(0x61), network_id, low_order),
        .signature = @splat(0),
    };
    try testing.expectError(error.BadSignature, verifyJoinRequestSignature(forged));
}

test "mesh enrollment: media rights are granted only with an authorized media role" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.allowed_roles = meshpass.roles(&.{ .relay, .media });
    ticket.media_rights = meshpass.mediaRights(&.{ .voice, .video }) | (@as(u32, 1) << 30);
    const signed_ticket = try signTicket(issuer, ticket);

    const relay_only = try signJoinRequest(node, testRequest(ticket.ticket_id, network_id, node.public_key.toBytes()));
    const relay_admission = try review(policy, signed_ticket, relay_only, FakeLedgerView{}, 1_500);
    try testing.expectEqual(@as(u32, 0), relay_admission.fields.media_rights);

    var media_request = testRequest(ticket.ticket_id, network_id, node.public_key.toBytes());
    media_request.requested_roles = meshpass.roles(&.{ .relay, .media });
    const media_admission = try review(policy, signed_ticket, try signJoinRequest(node, media_request), FakeLedgerView{}, 1_500);
    try testing.expectEqual(meshpass.mediaRights(&.{ .voice, .video }), media_admission.fields.media_rights);

    // An issuer not authorized for media cannot hand out the media role.
    const no_media = [_]Issuer{.{ .pubkey = issuer.public_key.toBytes(), .authorized_roles = meshpass.roles(&.{.relay}) }};
    try testing.expectError(
        error.IssuerLacksAuthority,
        review(testPolicy(&no_media, network_id), signed_ticket, try signJoinRequest(node, media_request), FakeLedgerView{}, 1_500),
    );
}

test "mesh enrollment: a ticket is redeemable only on its audience node, so a second admitter rejects it" {
    const issuer = try testIssuerKeyPair();
    const node_x = try testNodeKeyPair();
    const node_y = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x58)));
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy_a = testPolicy(&policy_issuers, network_id);
    var policy_b = policy_a;
    policy_b.admitter_pubkey = testAdmitterPubkey(0x59);
    const ticket = testTicket(issuer.public_key.toBytes(), network_id); // unbound, audience = A
    const signed_ticket = try signTicket(issuer, ticket);

    const req_x = try signJoinRequest(node_x, testRequest(ticket.ticket_id, network_id, node_x.public_key.toBytes()));
    const req_y = try signJoinRequest(node_y, testRequest(ticket.ticket_id, network_id, node_y.public_key.toBytes()));

    // Node A admits X; node B, with its own empty ledger, never admits Y (or X).
    _ = try review(policy_a, signed_ticket, req_x, FakeLedgerView{}, 1_500);
    try testing.expectError(error.WrongAudience, review(policy_b, signed_ticket, req_y, FakeLedgerView{}, 1_500));
    try testing.expectError(error.WrongAudience, review(policy_b, signed_ticket, req_x, FakeLedgerView{}, 1_500));

    // Revoking on the audience node is therefore mesh-complete.
    const revoked_on_a = FakeLedgerView{ .revoked_tickets = &.{ticket.ticket_id} };
    try testing.expectError(error.Revoked, review(policy_a, signed_ticket, req_y, revoked_on_a, 1_500));
    try testing.expectError(error.WrongAudience, review(policy_b, signed_ticket, req_y, FakeLedgerView{}, 1_500));

    // An all-zero audience never decodes and never matches a valid policy.
    var no_audience = ticket;
    no_audience.audience_pubkey = @splat(0);
    const no_audience_signed = try signTicket(issuer, no_audience);
    var buf: [max_ticket_len]u8 = undefined;
    try testing.expectError(error.WeakPublicKey, decodeTicket(buf[0..try encodeTicket(&buf, no_audience_signed)]));
    try testing.expectError(error.WrongAudience, review(policy_a, no_audience_signed, req_x, FakeLedgerView{}, 1_500));
}

test "mesh enrollment: the default policy requires node-bound tickets" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = Policy{
        .network_id = network_id,
        .realm = "mesh-realm",
        .issuers = &policy_issuers,
        .admitter_pubkey = testAdmitterPubkey(test_admitter_seed),
    };
    try testing.expect(policy.require_bound_node);
    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    ticket.revocation_epoch = 0;
    const request = try signJoinRequest(node, testRequest(ticket.ticket_id, network_id, node.public_key.toBytes()));
    try testing.expectError(
        error.UnboundTicket,
        review(policy, try signTicket(issuer, ticket), request, FakeLedgerView{}, 1_500),
    );
    ticket.bound_node_pubkey = node.public_key.toBytes();
    _ = try review(policy, try signTicket(issuer, ticket), request, FakeLedgerView{}, 1_500);
}

test "mesh enrollment: an issuer-chosen future epoch fails EpochFromFuture, so every minted pass stays revocable" {
    const issuer = try testIssuerKeyPair();
    const node = try testNodeKeyPair();
    const network_id = networkId("mesh-realm", issuer.public_key.toBytes());
    const policy_issuers = testIssuerList(issuer.public_key.toBytes());
    const policy = testPolicy(&policy_issuers, network_id);
    const request = try signJoinRequest(node, testRequest(@splat(0x61), network_id, node.public_key.toBytes()));

    var ticket = testTicket(issuer.public_key.toBytes(), network_id);
    for ([_]u64{ std.math.maxInt(u64), policy.current_revocation_epoch + 1 }) |epoch| {
        ticket.revocation_epoch = epoch;
        try testing.expectError(
            error.EpochFromFuture,
            review(policy, try signTicket(issuer, ticket), request, FakeLedgerView{}, 1_500),
        );
    }

    ticket.revocation_epoch = policy.current_revocation_epoch;
    const admission = try review(policy, try signTicket(issuer, ticket), request, FakeLedgerView{}, 1_500);
    try testing.expectEqual(policy.current_revocation_epoch, admission.fields.revocation_epoch);

    const issuing_key = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x71)));
    var buf: [meshpass.max_token_len]u8 = undefined;
    const decoded = try meshpass.decode(buf[0..try meshpass.encode(&buf, try issueMeshPass(issuing_key, admission))]);
    const families = meshpass.frameFamilies(&.{ .control, .sync, .mooring });
    var root = meshpass.TrustRoot{
        .public_key = issuing_key.public_key.toBytes(),
        .realm = policy.realm,
        .min_revocation_epoch = policy.current_revocation_epoch,
    };
    _ = try meshpass.bindDecodedToken(decoded, root, 1_500, node.public_key.toBytes(), families);
    root.min_revocation_epoch = policy.current_revocation_epoch + 1;
    try testing.expectError(
        error.Revoked,
        meshpass.bindDecodedToken(decoded, root, 1_500, node.public_key.toBytes(), families),
    );
}
