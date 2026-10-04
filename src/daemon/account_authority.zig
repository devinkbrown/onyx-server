// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent account schema foundation. Decoded rows/chunks are structural
//! data; only configured-owner signatures and complete authenticated roots bind
//! them. No credential verification, live admission, mutation or settlement API.
//! Every variable wire length/count is unsigned64 big endian and caller-bounded.
//! Owned results use the supplied stable allocator, release once and wipe backing.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
pub const Digest = [32]u8;
pub const head_key = "account-authority/head/v1";
pub const Error = error{ InvalidName, InvalidIdentity, InvalidField, InvalidFormat, Truncated, TrailingBytes, Capacity, Overflow, Exhausted, ContextMismatch, BadSignature, BadDigest, InvalidProof };
pub const Limits = struct { max_wire_bytes: usize, max_blob_bytes: usize, max_collection_elements: usize };

pub const AccountName = struct {
    bytes: [32]u8,
    len: u8,
    pub fn init(text: []const u8) Error!AccountName {
        if (text.len == 0 or text.len > 32) return error.InvalidName;
        var out: AccountName = .{ .bytes = @splat(0), .len = @intCast(text.len) };
        for (text, 0..) |ch, i| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-' and ch != '.') return error.InvalidName;
            out.bytes[i] = std.ascii.toLower(ch);
        }
        return out;
    }
    pub fn asSlice(self: *const AccountName) []const u8 {
        return self.bytes[0..self.len];
    }
    pub fn validate(self: AccountName) Error!void {
        if (self.len == 0 or self.len > 32) return error.InvalidName;
        const canonical = try init(self.asSlice());
        if (!std.mem.eql(u8, &self.bytes, &canonical.bytes)) return error.InvalidName;
    }
};
pub const ResourceId = struct {
    bytes: [16]u8,
    pub fn generate(io: std.Io) !ResourceId {
        var bytes: [16]u8 = undefined;
        try io.randomSecure(&bytes);
        return init(bytes);
    }
    pub fn init(bytes: [16]u8) Error!ResourceId {
        if (std.mem.allEqual(u8, &bytes, 0)) return error.InvalidIdentity;
        return .{ .bytes = bytes };
    }
};
pub const Incarnation = struct {
    bytes: [32]u8,
    pub fn init(bytes: [32]u8) Error!Incarnation {
        if (std.mem.allEqual(u8, &bytes, 0)) return error.InvalidIdentity;
        return .{ .bytes = bytes };
    }
    pub fn first() Incarnation {
        var b: [32]u8 = @splat(0);
        b[31] = 1;
        return .{ .bytes = b };
    }
    pub fn next(self: Incarnation) Error!Incarnation {
        _ = try init(self.bytes);
        var result = self;
        var i: usize = 32;
        while (i != 0) {
            i -= 1;
            if (result.bytes[i] != 255) {
                result.bytes[i] += 1;
                return result;
            }
            result.bytes[i] = 0;
        }
        return error.Exhausted;
    }
};
pub fn nextRevision(value: u64) Error!u64 {
    return std.math.add(u64, value, 1) catch error.Exhausted;
}
pub const AccountIdentity = struct {
    resource: ResourceId,
    name: AccountName,
    incarnation: Incarnation,
    pub fn validate(self: AccountIdentity) Error!void {
        _ = try ResourceId.init(self.resource.bytes);
        try self.name.validate();
        _ = try Incarnation.init(self.incarnation.bytes);
    }
    pub fn eql(a: AccountIdentity, b: AccountIdentity) bool {
        return std.mem.eql(u8, &a.resource.bytes, &b.resource.bytes) and std.mem.eql(u8, &a.incarnation.bytes, &b.incarnation.bytes) and a.name.len == b.name.len and std.mem.eql(u8, &a.name.bytes, &b.name.bytes);
    }
};
pub const CredentialKind = enum(u8) { password = 1, provider = 2, scram = 3, session_token = 4, certfp = 5, webauthn = 6, totp = 7, recovery = 8, device = 9, oper = 10 };
pub const CredentialRef = struct { identity: AccountIdentity, kind: CredentialKind, revision: u64, value_digest: Digest };
pub const ProviderRef = struct { provider_id: Digest, issuer_digest: Digest, subject: []const u8, claim_epoch: u64, mapping_revision: u64 };
pub const AccountAuthorityRef = struct { identity: AccountIdentity, resource_head_digest: Digest, account_row_digest: Digest, authority_generation: u64, policy_revision: u64 };
pub const RevocationId = struct { identity: AccountIdentity, revision: u64 };
pub const WireContext = struct { realm: Digest, owner_key: sign.PublicKey, resource: ResourceId };
/// Expected pins must come from the owner's validated configured policy. This
/// codec does not validate provider configuration or mint that owner capability.
pub const Context = struct {
    realm: Digest,
    owner_key: sign.PublicKey,
    resource: ResourceId,
    provider_policy_digest: Digest,
    namespace_table_digest: Digest,
    pub fn validate(self: Context) Error!void {
        _ = try ResourceId.init(self.resource.bytes);
        try nonzero(&self.provider_policy_digest);
        try nonzero(&self.namespace_table_digest);
    }
    pub fn wire(self: Context) WireContext {
        return .{ .realm = self.realm, .owner_key = self.owner_key, .resource = self.resource };
    }
};
// Intentionally unconstructible here. Mechanism adapters and owner CAS receive
// separate grants; a parsed signature or row can never mint an admission proof.
pub const VerifiedAuthProof = opaque {};
pub const AcceptedAuth = opaque {};
pub const AdmissionReservation = opaque {};
pub const PreparedAuthBinding = opaque {};
pub const AuthorityResult = union(enum) { live: AccountAuthorityRef, revoked: RevocationId, external_bound: struct { authority: AccountAuthorityRef, provider: ProviderRef }, unknown, invalid, unavailable };

pub const SecretBytes = struct {
    allocator: std.mem.Allocator,
    bytes: ?[]u8,
    pub fn copy(allocator: std.mem.Allocator, bytes: []const u8) !SecretBytes {
        return .{ .allocator = allocator, .bytes = try allocator.dupe(u8, bytes) };
    }
    pub fn deinit(self: *SecretBytes) void {
        if (self.bytes) |b| {
            std.crypto.secureZero(u8, b);
            // Allocator.free poisons debug backing after wiping. Preserve zeroes
            // through the actual allocator release for secret-bearing owners.
            if (b.len != 0) self.allocator.rawFree(b, .fromByteUnits(1), @returnAddress());
            self.bytes = null;
        }
    }
};
pub const CredentialLease = struct {
    reference: CredentialRef,
    key_material: SecretBytes,
    challenge_context: SecretBytes,
    pub fn deinit(self: *CredentialLease) void {
        self.key_material.deinit();
        self.challenge_context.deinit();
    }
};
pub const PasswordProfile = struct { salt: [16]u8, hash: [32]u8, pbkdf2_rounds: u32 };
pub const LiveProfile = struct { flags: u32, email: []const u8, email_verified: bool, password: ?PasswordProfile };
pub const CompletionState = enum(u8) { pending = 1, joined = 2, complete = 3 };
pub const RevokedProfile = struct { revocation: RevocationId, completion: CompletionState, completed_intent_root: Digest, completion_receipt: Digest };
pub const RowKind = enum(u8) { live = 1, revoked = 2 };
pub const Row = struct {
    identity: AccountIdentity,
    row_revision: u64,
    policy_revision: u64,
    last_revocation_revision: u64,
    credential_kind: CredentialKind,
    credential_revision: u64,
    credential_digest: Digest,
    /// Previous lineage completion is mandatory even on explicit reuse.
    prior_completion: ?struct { incarnation: Incarnation, intent_root: Digest, receipt: Digest },
    profile: union(RowKind) { live: LiveProfile, revoked: RevokedProfile },
};
pub const MerkleRoot = struct { rows: u64, bytes: u64, digest: Digest };
pub const NamespaceRoot = struct { namespace: u16, family: u8, root: MerkleRoot };
pub const ManifestKind = enum(u8) { intent = 1, cohort = 2, cleanup = 3, original_work = 4, completion_history = 5 };
pub const ManifestRoot = struct { kind: ManifestKind, chunks: u64, bytes: u64, root: Digest };
pub const PresenceReceipt = struct {
    realm: Digest,
    origin: sign.PublicKey,
    store_id: ResourceId,
    head_digest: Digest,
    image_digest: Digest,
    journal_root: Digest,
    commit_generation: u64,
    image_generation: u64,
    journal_generation: u64,
    epoch: u64,
    issued_through: u64,
    frontier_revision: u64,
    frontier_through: u64,
    expiry_floor_ms: i64,
};
pub const PacketReceipt = struct { digest: Digest, first_sequence: u64, next_sequence: u64, wal_epoch: ResourceId, start_offset: u64, end_offset: u64 };
pub const JoinedAck = struct {
    intent_head_digest: Digest,
    account_packet: PacketReceipt,
    presence_packet: PacketReceipt,
    completed_presence: PresenceReceipt,
    /// null means exact anticipated receipt; nonnull identifies a mandatory
    /// authenticated dominating-completion proof, never mere epoch inequality.
    permitted_dominance_root: ?Digest,
    work_set_root: Digest,
    negative_proof_root: Digest,
    final_join_commitment: Digest,
    planned_publication_generation: u64,
    custody_transfer_root: Digest,
};
pub const JoinPhase = enum(u8) { intent = 1, acknowledged = 2, cleanup = 3 };
pub const PendingRoot = struct {
    revocation: RevocationId,
    intent_root: Digest,
    cohort_root: Digest,
    cleanup_root: Digest,
    work_root: Digest,
    manifests: [5]ManifestRoot,
    old_presence: PresenceReceipt,
    anticipated_presence: PresenceReceipt,
    phase: JoinPhase,
    ack: ?JoinedAck,
    cleanup_cursor: u64,
    cleanup_receipt_root: Digest,
};
pub const Provisioning = enum(u8) { pending = 1, active = 2 };
pub const Head = struct {
    context: WireContext,
    generation: u64,
    previous_head_digest: Digest,
    authority_sequence: u64,
    policy_revision: u64,
    provider_policy_digest: Digest,
    namespace_table_digest: Digest,
    row_roots: []const NamespaceRoot,
    pending: ?PendingRoot,
    provisioning: Provisioning,
};
pub const Chunk = struct { resource: ResourceId, revocation: RevocationId, kind: ManifestKind, index: u64, total: u64, payload: []const u8 };
pub const Intent = struct {
    context: WireContext,
    revocation: RevocationId,
    old_account_row_digest: Digest,
    old_account_head_digest: Digest,
    old_presence: PresenceReceipt,
    anticipated_presence: PresenceReceipt,
    /// Four submanifest roots only; the containing intent root is formed AFTER
    /// signing/encoding this value and activated solely by PendingRoot.
    submanifests: [4]ManifestRoot,
    cohort_root: Digest,
    cleanup_root: Digest,
    work_root: Digest,
    provider_policy_digest: Digest,
    namespace_table_digest: Digest,
    policy_revision: u64,
    transaction_ref: ResourceId,
    final_effect_root: Digest,
    intended_publication_generation: u64,
};
pub const Declaration = struct {
    context: WireContext,
    revocation: RevocationId,
    old_account_head_digest: Digest,
    old_account_row_digest: Digest,
    old_authority_generation: u64,
    /// Strict encoded membership witness is independently verified against the
    /// old signed authority root during codec validation, not inferred from name.
    old_membership_proof: MembershipProof,
    old_authority_head: []const u8,
    old_account_row: []const u8,
    policy_revision: u64,
    denial: enum(u8) { revoke_private_authority = 1 },
    scope: enum(u8) { complete_incarnation = 1 },
    transaction_ref: ResourceId,
};

pub fn hash(hash_domain: []const u8, parts: []const []const u8) Digest {
    var h = std.crypto.hash.Blake3.init(.{});
    var n: [8]u8 = undefined;
    std.mem.writeInt(u64, &n, hash_domain.len, .big);
    h.update(&n);
    h.update(hash_domain);
    for (parts) |p| {
        std.mem.writeInt(u64, &n, p.len, .big);
        h.update(&n);
        h.update(p);
    }
    var digest: Digest = undefined;
    h.final(&digest);
    return digest;
}
fn sameResource(a: ResourceId, b: ResourceId) bool {
    return std.mem.eql(u8, &a.bytes, &b.bytes);
}
fn nonzero(bytes: []const u8) Error!void {
    if (std.mem.allEqual(u8, bytes, 0)) return error.InvalidField;
}
fn revocation(id: RevocationId, resource: ResourceId) Error!void {
    try id.identity.validate();
    if (!sameResource(id.identity.resource, resource)) return error.ContextMismatch;
    if (id.revision == 0) return error.InvalidField;
}
fn presence(p: PresenceReceipt) Error!void {
    _ = try ResourceId.init(p.store_id.bytes);
    if (p.commit_generation == 0 or p.image_generation == 0 or p.image_generation > p.commit_generation or p.journal_generation == 0 or p.epoch == 0 or p.frontier_revision == 0 or p.frontier_through > p.issued_through or p.expiry_floor_ms < 0) return error.InvalidField;
    try nonzero(&p.head_digest);
    try nonzero(&p.image_digest);
    try nonzero(&p.journal_root);
}
fn presenceTransition(old: PresenceReceipt, next: PresenceReceipt, realm: Digest) Error!void {
    try presence(old);
    try presence(next);
    if (!std.mem.eql(u8, &old.realm, &realm) or !std.mem.eql(u8, &next.realm, &realm) or !std.mem.eql(u8, &old.origin, &next.origin) or !sameResource(old.store_id, next.store_id)) return error.ContextMismatch;
    if (next.commit_generation <= old.commit_generation or next.image_generation < old.image_generation or next.journal_generation < old.journal_generation or next.epoch < old.epoch or next.expiry_floor_ms < old.expiry_floor_ms) return error.InvalidField;
    if (next.epoch == old.epoch and (next.issued_through < old.issued_through or next.frontier_revision < old.frontier_revision or next.frontier_through < old.frontier_through)) return error.InvalidField;
}
fn checkManifestRoots(roots: []const ManifestRoot, first_kind: usize) Error!void {
    for (roots, first_kind..) |r, k| {
        if (@intFromEnum(r.kind) != k or ((r.chunks == 0) != (r.bytes == 0))) return error.InvalidField;
        if (r.chunks == 0 and !std.mem.eql(u8, &r.root, &emptyManifestRoot(r.kind).root)) return error.InvalidField;
        try nonzero(&r.root);
    }
}
fn packet(p: PacketReceipt) Error!void {
    _ = try ResourceId.init(p.wal_epoch.bytes);
    if (p.first_sequence == 0 or p.next_sequence <= p.first_sequence or p.end_offset <= p.start_offset) return error.InvalidField;
    try nonzero(&p.digest);
}
fn validate(comptime T: type, value: T, expected: Context) Error!void {
    try expected.validate();
    if (T == Row) {
        try value.identity.validate();
        if (!sameResource(value.identity.resource, expected.resource)) return error.ContextMismatch;
        if (value.row_revision == 0 or value.policy_revision == 0 or value.credential_revision == 0) return error.InvalidField;
        try nonzero(&value.credential_digest);
        if (!std.mem.eql(u8, &value.identity.incarnation.bytes, &Incarnation.first().bytes) and value.prior_completion == null) return error.InvalidField;
        if (value.prior_completion) |p| {
            _ = try Incarnation.init(p.incarnation.bytes);
            const next = try p.incarnation.next();
            if (!std.mem.eql(u8, &next.bytes, &value.identity.incarnation.bytes)) return error.InvalidField;
            try nonzero(&p.intent_root);
            try nonzero(&p.receipt);
        }
        switch (value.profile) {
            .live => |p| {
                if (p.email.len > 96) return error.InvalidField;
                for (p.email) |c| if (c < 32 or c == 127 or c == '|') return error.InvalidField;
                if (p.password) |secret| {
                    if (secret.pbkdf2_rounds == 0 or value.credential_kind != .password) return error.InvalidField;
                } else if (value.credential_kind == .password) return error.InvalidField;
            },
            .revoked => |p| {
                try revocation(p.revocation, expected.resource);
                if (!p.revocation.identity.eql(value.identity) or p.revocation.revision != value.last_revocation_revision) return error.InvalidField;
                if (p.completion != .pending) {
                    try nonzero(&p.completed_intent_root);
                    try nonzero(&p.completion_receipt);
                } else if (!std.mem.allEqual(u8, &p.completed_intent_root, 0) or !std.mem.allEqual(u8, &p.completion_receipt, 0)) return error.InvalidField;
            },
        }
    } else if (T == Chunk) {
        try revocation(value.revocation, expected.resource);
        if (!sameResource(value.resource, expected.resource)) return error.ContextMismatch;
        if (value.total == 0 or value.index >= value.total or value.payload.len == 0) return error.InvalidField;
    } else {
        if (!std.mem.eql(u8, &value.context.realm, &expected.realm) or !std.mem.eql(u8, &value.context.owner_key, &expected.owner_key) or !sameResource(value.context.resource, expected.resource)) return error.ContextMismatch;
        if (T == Head) {
            if (!std.mem.eql(u8, &value.provider_policy_digest, &expected.provider_policy_digest) or !std.mem.eql(u8, &value.namespace_table_digest, &expected.namespace_table_digest)) return error.ContextMismatch;
            if (value.generation == 0 or value.authority_sequence == 0 or value.policy_revision == 0 or ((value.generation == 1) != std.mem.allEqual(u8, &value.previous_head_digest, 0))) return error.InvalidField;
            try nonzero(&value.provider_policy_digest);
            try nonzero(&value.namespace_table_digest);
            if (value.row_roots.len == 0) return error.InvalidField;
            for (value.row_roots, 0..) |r, i| {
                if (r.namespace == 0 or r.family > 7) return error.InvalidField;
                try nonzero(&r.root.digest);
                if (r.root.rows == 0) {
                    if (!std.meta.eql(r.root, emptyRoot())) return error.InvalidField;
                } else if (r.root.bytes < r.root.rows) return error.InvalidField;
                if (i != 0) {
                    const old = value.row_roots[i - 1];
                    if (old.namespace > r.namespace or (old.namespace == r.namespace and old.family >= r.family)) return error.InvalidField;
                }
            }
            if (value.pending) |p| {
                try revocation(p.revocation, expected.resource);
                try checkManifestRoots(&p.manifests, 1);
                if (p.manifests[0].chunks == 0 or !std.mem.eql(u8, &p.intent_root, &p.manifests[0].root)) return error.InvalidField;
                try presenceTransition(p.old_presence, p.anticipated_presence, expected.realm);
                try nonzero(&p.intent_root);
                try nonzero(&p.cohort_root);
                try nonzero(&p.cleanup_root);
                try nonzero(&p.work_root);
                if ((p.phase == .intent) != (p.ack == null)) return error.InvalidField;
                if (p.ack) |a| {
                    try packet(a.account_packet);
                    try packet(a.presence_packet);
                    try presenceTransition(p.old_presence, a.completed_presence, expected.realm);
                    try nonzero(&a.intent_head_digest);
                    if (!std.mem.eql(u8, &a.work_set_root, &p.work_root)) return error.InvalidField;
                    try nonzero(&a.final_join_commitment);
                    try nonzero(&a.work_set_root);
                    try nonzero(&a.negative_proof_root);
                    try nonzero(&a.custody_transfer_root);
                    if (a.planned_publication_generation == 0) return error.InvalidField;
                    if (a.permitted_dominance_root) |root| {
                        try nonzero(&root);
                    } else if (!std.meta.eql(a.completed_presence, p.anticipated_presence)) return error.InvalidField;
                }
            }
        } else if (T == Intent) {
            if (!std.mem.eql(u8, &value.provider_policy_digest, &expected.provider_policy_digest) or !std.mem.eql(u8, &value.namespace_table_digest, &expected.namespace_table_digest)) return error.ContextMismatch;
            try revocation(value.revocation, expected.resource);
            try presenceTransition(value.old_presence, value.anticipated_presence, expected.realm);
            try checkManifestRoots(&value.submanifests, 2);
            _ = try ResourceId.init(value.transaction_ref.bytes);
            if (value.policy_revision == 0 or value.intended_publication_generation == 0) return error.InvalidField;
            inline for (.{ "old_account_row_digest", "old_account_head_digest", "cohort_root", "cleanup_root", "work_root", "provider_policy_digest", "namespace_table_digest", "final_effect_root" }) |name| try nonzero(&@field(value, name));
        } else if (T == Declaration) {
            try revocation(value.revocation, expected.resource);
            _ = try ResourceId.init(value.transaction_ref.bytes);
            if (value.old_authority_generation == 0 or value.policy_revision == 0 or value.old_authority_head.len == 0 or value.old_account_row.len == 0) return error.InvalidField;
            try nonzero(&value.old_account_head_digest);
            try nonzero(&value.old_account_row_digest);
        }
    }
}

fn magic(comptime T: type) []const u8 {
    return if (T == Row) "OACC1" else if (T == Head) "OACH1" else if (T == Chunk) "OACM1" else if (T == Intent) "OARI1" else if (T == Declaration) "OPAD1" else @compileError("unsupported schema");
}
fn domain(comptime T: type) []const u8 {
    return if (T == Head) "onyx-account-authority-head-v1" else if (T == Intent) "onyx-account-revocation-intent-v1" else if (T == Declaration) "onyx-account-revocation-declaration-v1" else if (T == Chunk) "onyx-account-revocation-chunk-v1" else "onyx-account-row-v1";
}
fn signed(comptime T: type) bool {
    return T == Head or T == Intent or T == Declaration;
}
pub const Wire = struct {
    allocator: std.mem.Allocator,
    bytes: ?[]u8,
    pub fn asSlice(self: *const Wire) []const u8 {
        return self.bytes orelse &.{};
    }
    pub fn deinit(self: *Wire) void {
        if (self.bytes) |b| {
            std.crypto.secureZero(u8, b);
            // Allocator.free poisons debug backing after wiping. Preserve zeroes
            // through the actual allocator release for secret-bearing owners.
            if (b.len != 0) self.allocator.rawFree(b, .fromByteUnits(1), @returnAddress());
            self.bytes = null;
        }
    }
};
pub fn Owned(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        wire: []u8,
        value: T,
        alive: bool,
        pub fn deinit(self: *@This()) void {
            if (!self.alive) return;
            std.crypto.secureZero(u8, self.wire);
            std.crypto.secureZero(u8, std.mem.asBytes(&self.value));
            self.arena.deinit();
            self.alive = false;
        }
    };
}
const Writer = struct {
    bytes: ?[]u8 = null,
    offset: usize = 0,
    limits: Limits,
    fn put(w: *Writer, b: []const u8) !void {
        const end = std.math.add(usize, w.offset, b.len) catch return error.Overflow;
        if (end > w.limits.max_wire_bytes) return error.Capacity;
        if (w.bytes) |buf| {
            if (end > buf.len) return error.Capacity;
            @memcpy(buf[w.offset..end], b);
        }
        w.offset = end;
    }
    fn int(w: *Writer, comptime T: type, n: T) !void {
        var buf: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buf, n, .big);
        try w.put(&buf);
    }
};
fn write(w: *Writer, comptime T: type, value: T) anyerror!void {
    if (T == AccountName) {
        try value.validate();
        try w.int(u8, value.len);
        return w.put(value.asSlice());
    }
    switch (@typeInfo(T)) {
        .int => try w.int(T, value),
        .bool => try w.int(u8, @intFromBool(value)),
        .@"enum" => try w.int(@typeInfo(T).@"enum".tag_type, @intFromEnum(value)),
        .array => |a| {
            if (a.child == u8) try w.put(&value) else for (value) |v| try write(w, a.child, v);
        },
        .@"struct" => |s| inline for (s.field_names) |name| try write(w, @FieldType(T, name), @field(value, name)),
        .optional => |o| {
            try w.int(u8, @intFromBool(value != null));
            if (value) |v| try write(w, o.child, v);
        },
        .pointer => |p| {
            if (p.size != .slice) @compileError("schema pointers must be slices");
            if (value.len > w.limits.max_collection_elements and p.child != u8) return error.Capacity;
            if (p.child == u8 and value.len > w.limits.max_blob_bytes) return error.Capacity;
            try w.int(u64, value.len);
            if (p.child == u8) try w.put(value) else for (value) |v| try write(w, p.child, v);
        },
        .@"union" => |u| {
            const tag = std.meta.activeTag(value);
            try write(w, u.tag_type.?, tag);
            inline for (u.field_names) |name| {
                if (tag == @field(u.tag_type.?, name)) try write(w, @FieldType(T, name), @field(value, name));
            }
        },
        else => @compileError("unsupported schema field"),
    }
}
fn minimum(comptime T: type) usize {
    if (T == AccountName) return 2;
    return switch (@typeInfo(T)) {
        .int => @sizeOf(T),
        .bool => 1,
        .@"enum" => @sizeOf(@typeInfo(T).@"enum".tag_type),
        .optional => 1,
        .pointer => 8,
        .array => |a| a.len * minimum(a.child),
        .@"struct" => |s| blk: {
            var n: usize = 0;
            inline for (s.field_names) |name| n += minimum(@FieldType(T, name));
            break :blk n;
        },
        .@"union" => |u| @sizeOf(u.tag_type.?),
        else => @compileError("unsupported schema field"),
    };
}
const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,
    allocator: std.mem.Allocator,
    limits: Limits,
    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (n > r.bytes.len - r.offset) return error.Truncated;
        const b = r.bytes[r.offset..][0..n];
        r.offset += n;
        return b;
    }
    fn int(r: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
};
fn read(r: *Reader, comptime T: type) anyerror!T {
    if (T == AccountName) {
        const raw = try r.take(try r.int(u8));
        const n = try AccountName.init(raw);
        if (!std.mem.eql(u8, raw, n.asSlice())) return error.InvalidName;
        return n;
    }
    return switch (@typeInfo(T)) {
        .int => try r.int(T),
        .bool => switch (try r.int(u8)) {
            0 => false,
            1 => true,
            else => return error.InvalidField,
        },
        .@"enum" => |e| std.enums.fromInt(T, try r.int(e.tag_type)) orelse return error.InvalidField,
        .array => |a| blk: {
            var out: T = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&out));
            if (a.child == u8) @memcpy(&out, try r.take(a.len)) else for (&out) |*v| v.* = try read(r, a.child);
            break :blk out;
        },
        .@"struct" => |s| blk: {
            var out: T = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&out));
            inline for (s.field_names) |name| @field(out, name) = try read(r, @FieldType(T, name));
            break :blk out;
        },
        .optional => |o| switch (try r.int(u8)) {
            0 => null,
            1 => try read(r, o.child),
            else => return error.InvalidField,
        },
        .pointer => |p| blk: {
            if (p.size != .slice or !p.attrs.@"const") @compileError("only immutable schema slices");
            const wide = try r.int(u64);
            const n = std.math.cast(usize, wide) orelse return error.Overflow;
            if (p.child == u8) {
                if (n > r.limits.max_blob_bytes) return error.Capacity;
                break :blk try r.take(n);
            }
            if (n > r.limits.max_collection_elements) return error.Capacity;
            const bytes_needed = std.math.mul(usize, n, minimum(p.child)) catch return error.Overflow;
            if (bytes_needed > r.bytes.len - r.offset) return error.Truncated;
            const out = try r.allocator.alloc(p.child, n);
            for (out) |*v| v.* = try read(r, p.child);
            break :blk out;
        },
        .@"union" => |u| blk: {
            const tag = try read(r, u.tag_type.?);
            inline for (u.field_names) |name| {
                if (tag == @field(u.tag_type.?, name)) {
                    var out: T = @unionInit(T, name, try read(r, @FieldType(T, name)));
                    defer std.crypto.secureZero(u8, std.mem.asBytes(&out));
                    break :blk out;
                }
            }
            return error.InvalidField;
        },
        else => @compileError("unsupported schema field"),
    };
}

/// Signed schemas require actual configured-owner signing, unsigned row/chunk
/// encodings need subsequent membership under an authenticated owner head.
pub fn encode(comptime T: type, allocator: std.mem.Allocator, value: T, expected: Context, key: ?*const sign.KeyPair, limits: Limits) !Wire {
    try validate(T, value, expected);
    if (T == Declaration) try verifyDeclarationEvidence(allocator, value, expected, limits);
    if (signed(T)) {
        const k = key orelse return error.ContextMismatch;
        if (!std.mem.eql(u8, &expected.owner_key, &k.public_key)) return error.ContextMismatch;
    }
    var counter: Writer = .{ .limits = limits };
    try counter.put(magic(T));
    try counter.int(u8, 1);
    try write(&counter, T, value);
    const body_len = counter.offset;
    const trailer_len: usize = if (signed(T)) sign.signature_len else if (T == Chunk) 32 else 0;
    const length = std.math.add(usize, body_len, trailer_len) catch return error.Overflow;
    if (length > limits.max_wire_bytes) return error.Capacity;
    var out: Wire = .{ .allocator = allocator, .bytes = try allocator.alloc(u8, length) };
    errdefer out.deinit();
    var w: Writer = .{ .bytes = out.bytes.?, .limits = limits };
    try w.put(magic(T));
    try w.int(u8, 1);
    try write(&w, T, value);
    if (signed(T)) {
        const sig = try key.?.signCtx(domain(T), out.bytes.?[0..body_len]);
        try w.put(&sig);
    }
    if (T == Chunk) {
        const sum = hash(domain(T), &.{out.bytes.?[0..body_len]});
        try w.put(&sum);
    }
    std.debug.assert(w.offset == length);
    return out;
}
/// Verify configured full-key signature BEFORE allocation/variable parsing.
/// The returned owned view is data, not a VerifiedAuthProof/admission capability.
pub fn decode(comptime T: type, allocator: std.mem.Allocator, raw: []const u8, expected: Context, limits: Limits) !Owned(T) {
    try expected.validate();
    if (raw.len > limits.max_wire_bytes) return error.Capacity;
    const trailer: usize = if (signed(T)) sign.signature_len else if (T == Chunk) 32 else 0;
    if (raw.len < 6 + minimum(T) + trailer) return error.Truncated;
    const body = raw[0 .. raw.len - trailer];
    if (signed(T)) {
        const sig: sign.Signature = raw[body.len..][0..64].*;
        if (!(sign.verifyCtx(domain(T), body, sig, expected.owner_key) catch false)) return error.BadSignature;
    }
    if (T == Chunk) {
        const sum = hash(domain(T), &.{body});
        if (!std.mem.eql(u8, &sum, raw[body.len..])) return error.BadDigest;
    }
    if (!std.mem.eql(u8, body[0..5], magic(T)) or body[5] != 1) return error.InvalidFormat;
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const wire = try arena.allocator().dupe(u8, raw);
    errdefer std.crypto.secureZero(u8, wire);
    var r: Reader = .{ .bytes = wire[6..body.len], .allocator = arena.allocator(), .limits = limits };
    var value = try read(&r, T);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&value));
    if (r.offset != r.bytes.len) return error.TrailingBytes;
    try validate(T, value, expected);
    if (T == Declaration) try verifyDeclarationEvidence(allocator, value, expected, limits);
    return .{ .arena = arena, .wire = wire, .value = value, .alive = true };
}

pub const LeafKey = struct { namespace: u16, family: u8, key: []const u8 };
pub const Leaf = struct { namespace: u16, family: u8, key: []const u8, value: []const u8 };
pub const LeafCommitment = struct { namespace: u16, family: u8, key: []const u8, value_len: u64, value_digest: Digest };
pub const MembershipProof = struct { leaf: LeafCommitment, index: u64, siblings: []const Digest };
pub const IndexLimits = struct { max_rows: usize, max_bytes: u64 };
fn keyOrder(a: anytype, b: anytype) std.math.Order {
    if (a.namespace != b.namespace) return std.math.order(a.namespace, b.namespace);
    if (a.family != b.family) return std.math.order(a.family, b.family);
    return std.mem.order(u8, a.key, b.key);
}
fn validateLeaf(leaf: anytype) Error!void {
    if (leaf.namespace == 0 or leaf.family > 7 or leaf.key.len == 0) return error.InvalidProof;
}
fn leafHash(leaf: LeafCommitment) Digest {
    var ns: [2]u8 = undefined;
    std.mem.writeInt(u16, &ns, leaf.namespace, .big);
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, leaf.value_len, .big);
    return hash("onyx-account-merkle-leaf-v1", &.{ &ns, &.{leaf.family}, leaf.key, &len, &leaf.value_digest });
}
fn branchHash(a: Digest, b: Digest) Digest {
    return hash("onyx-account-merkle-node-v1", &.{ &a, &b });
}
fn wrapRoot(count: u64, bytes: u64, tree: Digest) MerkleRoot {
    var n: [8]u8 = undefined;
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &n, count, .big);
    std.mem.writeInt(u64, &b, bytes, .big);
    return .{ .rows = count, .bytes = bytes, .digest = hash("onyx-account-merkle-root-v1", &.{ &n, &b, &tree }) };
}
pub fn emptyRoot() MerkleRoot {
    return wrapRoot(0, 0, hash("onyx-account-merkle-empty-v1", &.{}));
}
fn treeWidth(count: usize) Error!usize {
    var width: usize = 1;
    while (width < count) width = std.math.mul(usize, width, 2) catch return error.Overflow;
    return width;
}
pub const MerkleIndex = struct {
    arena: std.heap.ArenaAllocator,
    rows: []const LeafCommitment,
    nodes: []const Digest,
    width: usize,
    root: MerkleRoot,
    alive: bool,
    /// Boot/build over a COMPLETE already ordered source snapshot. No silent
    /// sorting or omitted-row inference; includes arbitrary raw key/value bytes.
    pub fn init(allocator: std.mem.Allocator, rows: []const Leaf, limits: IndexLimits) !MerkleIndex {
        if (rows.len > limits.max_rows) return error.Capacity;
        var bytes: u64 = 0;
        for (rows, 0..) |row, i| {
            try validateLeaf(row);
            if (i != 0 and keyOrder(rows[i - 1], row) != .lt) return error.InvalidProof;
            bytes = std.math.add(u64, bytes, row.key.len) catch return error.Overflow;
            bytes = std.math.add(u64, bytes, row.value.len) catch return error.Overflow;
            if (bytes > limits.max_bytes) return error.Capacity;
        }
        const width = try treeWidth(rows.len);
        const count = std.math.mul(usize, width, 2) catch return error.Overflow;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const leaves = try arena.allocator().alloc(LeafCommitment, rows.len);
        const nodes = try arena.allocator().alloc(Digest, count);
        @memset(nodes, hash("onyx-account-merkle-empty-v1", &.{}));
        for (rows, 0..) |row, i| {
            leaves[i] = .{ .namespace = row.namespace, .family = row.family, .key = try arena.allocator().dupe(u8, row.key), .value_len = row.value.len, .value_digest = hash("onyx-account-value-v1", &.{row.value}) };
            nodes[width + i] = leafHash(leaves[i]);
        }
        var i = width;
        while (i > 1) {
            i -= 1;
            nodes[i] = branchHash(nodes[i * 2], nodes[i * 2 + 1]);
        }
        const root = if (rows.len == 0) emptyRoot() else wrapRoot(rows.len, bytes, nodes[1]);
        return .{ .arena = arena, .rows = leaves, .nodes = nodes, .width = width, .root = root, .alive = true };
    }
    pub fn deinit(self: *MerkleIndex) void {
        if (!self.alive) return;
        self.arena.deinit();
        self.alive = false;
    }
    pub fn proof(self: *const MerkleIndex, allocator: std.mem.Allocator, index: usize) !OwnedProof {
        if (!self.alive or index >= self.rows.len) return error.InvalidProof;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        var n = self.width;
        var depth: usize = 0;
        while (n > 1) {
            n /= 2;
            depth += 1;
        }
        const siblings = try arena.allocator().alloc(Digest, depth);
        var cursor = self.width + index;
        for (siblings) |*sibling| {
            sibling.* = self.nodes[cursor ^ 1];
            cursor /= 2;
        }
        var leaf = self.rows[index];
        leaf.key = try arena.allocator().dupe(u8, leaf.key);
        return .{ .arena = arena, .value = .{ .leaf = leaf, .index = index, .siblings = siblings }, .alive = true };
    }
};
pub const OwnedProof = struct {
    arena: std.heap.ArenaAllocator,
    value: MembershipProof,
    alive: bool,
    pub fn deinit(self: *OwnedProof) void {
        if (!self.alive) return;
        self.arena.deinit();
        self.alive = false;
    }
};
pub fn verifyMembership(root: MerkleRoot, proof: MembershipProof) Error!void {
    try validateLeaf(proof.leaf);
    if (root.rows == 0 or proof.index >= root.rows or proof.leaf.value_len > root.bytes or proof.leaf.key.len > root.bytes - proof.leaf.value_len) return error.InvalidProof;
    const count = std.math.cast(usize, root.rows) orelse return error.Overflow;
    const width = try treeWidth(count);
    var cursor = width + (std.math.cast(usize, proof.index) orelse return error.Overflow);
    var depth: usize = 0;
    var n = width;
    while (n > 1) {
        depth += 1;
        n /= 2;
    }
    if (proof.siblings.len != depth) return error.InvalidProof;
    var value = leafHash(proof.leaf);
    for (proof.siblings) |sibling| {
        value = if (cursor & 1 == 0) branchHash(value, sibling) else branchHash(sibling, value);
        cursor /= 2;
    }
    if (!std.mem.eql(u8, &root.digest, &wrapRoot(root.rows, root.bytes, value).digest)) return error.InvalidProof;
}
pub fn verifyValue(root: MerkleRoot, proof: MembershipProof, value: []const u8) Error!void {
    if (proof.leaf.value_len != value.len or !std.mem.eql(u8, &proof.leaf.value_digest, &hash("onyx-account-value-v1", &.{value}))) return error.InvalidProof;
    try verifyMembership(root, proof);
}
/// Complete adjacent-neighbor or edge proof. A root signature alone is not a
/// nonmembership proof; no namespace/name fallback or absent-row inference.
fn verifyAbsence(root: MerkleRoot, query: LeafKey, lower: ?MembershipProof, upper: ?MembershipProof) Error!void {
    try validateLeaf(query);
    if (root.rows == 0) {
        if (lower != null or upper != null or !std.meta.eql(root, emptyRoot())) return error.InvalidProof;
        return;
    }
    if (lower) |lo| {
        try verifyMembership(root, lo);
        if (keyOrder(lo.leaf, query) != .lt) return error.InvalidProof;
    }
    if (upper) |hi| {
        try verifyMembership(root, hi);
        if (keyOrder(query, hi.leaf) != .lt) return error.InvalidProof;
    }
    if (lower) |lo| {
        if (upper) |hi| {
            if (lo.index + 1 != hi.index) return error.InvalidProof;
        } else if (lo.index != root.rows - 1) return error.InvalidProof;
    } else if (upper) |hi| {
        if (hi.index != 0) return error.InvalidProof;
    } else return error.InvalidProof;
}

/// Scope remains explicit even for the empty root, whose digest has no leaf
/// from which namespace/family could be inferred.
pub fn verifyNamespaceMembership(root: NamespaceRoot, proof: MembershipProof, value: []const u8) Error!void {
    if (root.namespace != proof.leaf.namespace or root.family != proof.leaf.family) return error.InvalidProof;
    try verifyValue(root.root, proof, value);
}
pub fn verifyNamespaceAbsence(root: NamespaceRoot, query: LeafKey, lower: ?MembershipProof, upper: ?MembershipProof) Error!void {
    if (root.namespace != query.namespace or root.family != query.family) return error.InvalidProof;
    if (lower) |p| if (p.leaf.namespace != root.namespace or p.leaf.family != root.family) return error.InvalidProof;
    if (upper) |p| if (p.leaf.namespace != root.namespace or p.leaf.family != root.family) return error.InvalidProof;
    try verifyAbsence(root.root, query, lower, upper);
}

pub fn validateCredentialReference(reference: CredentialRef) Error!void {
    try reference.identity.validate();
    if (reference.revision == 0) return error.InvalidField;
    try nonzero(&reference.value_digest);
}
pub fn validateAuthorityReference(reference: AccountAuthorityRef) Error!void {
    try reference.identity.validate();
    if (reference.authority_generation == 0 or reference.policy_revision == 0) return error.InvalidField;
    try nonzero(&reference.resource_head_digest);
    try nonzero(&reference.account_row_digest);
}
pub fn validateProviderReference(reference: ProviderRef) Error!void {
    try nonzero(&reference.provider_id);
    try nonzero(&reference.issuer_digest);
    if (reference.subject.len == 0 or reference.claim_epoch == 0 or reference.mapping_revision == 0) return error.InvalidField;
}

/// Exact complete map/namespace validation follows signature verification; no
/// declaration of a root or successful checksum is a boot authority shortcut.
pub fn verifyCompleteHead(allocator: std.mem.Allocator, raw_head: []const u8, context: Context, rows: []const Leaf, limits: Limits, index_limits: IndexLimits) !Owned(Head) {
    var head = try decode(Head, allocator, raw_head, context, limits);
    errdefer head.deinit();
    var previous: ?Leaf = null;
    for (rows) |row| {
        try validateLeaf(row);
        if (previous) |p| if (keyOrder(p, row) != .lt) return error.InvalidProof;
        previous = row;
    }
    var offset: usize = 0;
    var total_bytes: u64 = 0;
    if (rows.len > index_limits.max_rows) return error.Capacity;
    for (head.value.row_roots) |root| {
        const start = offset;
        while (offset < rows.len and rows[offset].namespace == root.namespace and rows[offset].family == root.family) : (offset += 1) {}
        var index = try MerkleIndex.init(allocator, rows[start..offset], index_limits);
        defer index.deinit();
        if (!std.meta.eql(index.root, root.root)) return error.InvalidProof;
        total_bytes = std.math.add(u64, total_bytes, index.root.bytes) catch return error.Overflow;
        if (total_bytes > index_limits.max_bytes) return error.Capacity;
    }
    if (offset != rows.len) return error.InvalidProof;
    return head;
}
fn verifyDeclarationEvidence(allocator: std.mem.Allocator, declaration: Declaration, context: Context, limits: Limits) !void {
    var head = try decode(Head, allocator, declaration.old_authority_head, context, limits);
    defer head.deinit();
    var row = try decode(Row, allocator, declaration.old_account_row, context, limits);
    defer row.deinit();
    if (!std.mem.eql(u8, &declaration.old_account_head_digest, &hash(domain(Head), &.{declaration.old_authority_head})) or !std.mem.eql(u8, &declaration.old_account_row_digest, &hash(domain(Row), &.{declaration.old_account_row}))) return error.InvalidProof;
    if (head.value.policy_revision != declaration.policy_revision or head.value.generation != declaration.old_authority_generation or !row.value.identity.eql(declaration.revocation.identity) or row.value.profile != .live or declaration.revocation.revision != try nextRevision(row.value.last_revocation_revision)) return error.InvalidProof;
    const proof = declaration.old_membership_proof;
    if (proof.leaf.family != 0 or !std.mem.eql(u8, proof.leaf.key, row.value.identity.name.asSlice())) return error.InvalidProof;
    var found = false;
    for (head.value.row_roots) |root| if (root.namespace == proof.leaf.namespace and root.family == proof.leaf.family) {
        try verifyNamespaceMembership(root, proof, declaration.old_account_row);
        found = true;
    };
    if (!found) return error.InvalidProof;
}
pub fn emptyManifestRoot(kind: ManifestKind) ManifestRoot {
    return .{ .kind = kind, .chunks = 0, .bytes = 0, .root = hash("onyx-account-manifest-empty-v1", &.{&.{@intFromEnum(kind)}}) };
}
/// Root of complete, strictly indexed chunk wires. The resulting root still
/// needs activation by a signed head; inert chunks never create revocation.
pub fn manifestRoot(allocator: std.mem.Allocator, wires: []const []const u8, kind: ManifestKind, id: RevocationId, context: Context, limits: Limits) !ManifestRoot {
    try revocation(id, context.resource);
    if (wires.len == 0) return emptyManifestRoot(kind);
    if (wires.len > limits.max_collection_elements) return error.Capacity;
    const width = try treeWidth(wires.len);
    const node_count = std.math.mul(usize, width, 2) catch return error.Overflow;
    const nodes = try allocator.alloc(Digest, node_count);
    defer allocator.free(nodes);
    @memset(nodes, hash("onyx-account-manifest-padding-v1", &.{}));
    var bytes: u64 = 0;
    for (wires, 0..) |wire, i| {
        var chunk = try decode(Chunk, allocator, wire, context, limits);
        defer chunk.deinit();
        if (!chunk.value.revocation.identity.eql(id.identity) or chunk.value.revocation.revision != id.revision or chunk.value.kind != kind or chunk.value.index != i or chunk.value.total != wires.len) return error.InvalidProof;
        bytes = std.math.add(u64, bytes, chunk.value.payload.len) catch return error.Overflow;
        nodes[width + i] = wire[wire.len - 32 ..][0..32].*;
    }
    var cursor = width;
    while (cursor > 1) {
        cursor -= 1;
        nodes[cursor] = hash("onyx-account-manifest-node-v1", &.{ &nodes[cursor * 2], &nodes[cursor * 2 + 1] });
    }
    var count_bytes: [8]u8 = undefined;
    var payload_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &count_bytes, wires.len, .big);
    std.mem.writeInt(u64, &payload_bytes, bytes, .big);
    return .{ .kind = kind, .chunks = wires.len, .bytes = bytes, .root = hash("onyx-account-manifest-root-v1", &.{ &.{@intFromEnum(kind)}, &count_bytes, &payload_bytes, &nodes[1] }) };
}
pub fn verifyManifest(allocator: std.mem.Allocator, wires: []const []const u8, expected_root: ManifestRoot, id: RevocationId, context: Context, limits: Limits) !void {
    if (!std.meta.eql(expected_root, try manifestRoot(allocator, wires, expected_root.kind, id, context, limits))) return error.InvalidProof;
}
/// Strict acyclic D4 -> exact chunks -> D5 activation/reassembly. This verifies
/// signed configured Head/Intent and their manifest/receipt joins, returning
/// owned DATA. Complete account maps, P proofs and final CAS remain owner work.
pub fn decodeActivatedIntent(allocator: std.mem.Allocator, raw_head: []const u8, intent_chunks: []const []const u8, context: Context, limits: Limits) !Owned(Intent) {
    var head = try decode(Head, allocator, raw_head, context, limits);
    defer head.deinit();
    const pending = head.value.pending orelse return error.InvalidProof;
    // Authenticate the descriptor, then reject impossible assembly budgets or
    // missing chunks before constructing a tree or touching every chunk.
    const expected_manifest = pending.manifests[0];
    if (expected_manifest.chunks > limits.max_collection_elements) return error.Capacity;
    const expected_count = std.math.cast(usize, expected_manifest.chunks) orelse return error.Overflow;
    const total = std.math.cast(usize, expected_manifest.bytes) orelse return error.Overflow;
    if (total > limits.max_wire_bytes) return error.Capacity;
    if (expected_count != intent_chunks.len) return error.InvalidProof;
    try verifyManifest(allocator, intent_chunks, expected_manifest, pending.revocation, context, limits);
    const joined = try allocator.alloc(u8, total);
    defer {
        std.crypto.secureZero(u8, joined);
        if (joined.len != 0) allocator.rawFree(joined, .fromByteUnits(1), @returnAddress());
    }
    var offset: usize = 0;
    for (intent_chunks) |wire| {
        var chunk = try decode(Chunk, allocator, wire, context, limits);
        defer chunk.deinit();
        if (chunk.value.payload.len > joined.len - offset) return error.InvalidProof;
        @memcpy(joined[offset..][0..chunk.value.payload.len], chunk.value.payload);
        offset += chunk.value.payload.len;
    }
    if (offset != joined.len) return error.InvalidProof;
    var intent = try decode(Intent, allocator, joined, context, limits);
    errdefer intent.deinit();
    if (!intent.value.revocation.identity.eql(pending.revocation.identity) or intent.value.revocation.revision != pending.revocation.revision or intent.value.policy_revision != head.value.policy_revision or !std.meta.eql(intent.value.old_presence, pending.old_presence) or !std.meta.eql(intent.value.anticipated_presence, pending.anticipated_presence)) return error.InvalidProof;
    if (!std.mem.eql(u8, &intent.value.cohort_root, &pending.cohort_root) or !std.mem.eql(u8, &intent.value.cleanup_root, &pending.cleanup_root) or !std.mem.eql(u8, &intent.value.work_root, &pending.work_root)) return error.InvalidProof;
    for (intent.value.submanifests, pending.manifests[1..5]) |subroot, activated| if (!std.meta.eql(subroot, activated)) return error.InvalidProof;
    return intent;
}

pub fn chunkKey(buffer: []u8, chunk: Chunk) ![]const u8 {
    try revocation(chunk.revocation, chunk.resource);
    var bytes: [128]u8 = undefined;
    var writer: Writer = .{ .bytes = &bytes, .limits = .{ .max_wire_bytes = bytes.len, .max_blob_bytes = 32, .max_collection_elements = 0 } };
    try write(&writer, RevocationId, chunk.revocation);
    const id = hash("onyx-account-revocation-id-v1", &.{bytes[0..writer.offset]});
    return std.fmt.bufPrint(buffer, "account-revocation/chunk/v1/{s}/{s}/{s}/{d}", .{ std.fmt.bytesToHex(chunk.resource.bytes, .lower), std.fmt.bytesToHex(id, .lower), @tagName(chunk.kind), chunk.index });
}

const test_limits: Limits = .{ .max_wire_bytes = 1 << 20, .max_blob_bytes = 1 << 18, .max_collection_elements = 8192 };
fn fixtureIdentity() AccountIdentity {
    return .{ .resource = .{ .bytes = @splat(11) }, .name = AccountName.init("Alice.Example-1") catch unreachable, .incarnation = Incarnation.first() };
}
fn fixtureContext(key: *const sign.KeyPair) Context {
    return .{ .realm = @splat(12), .owner_key = key.public_key, .resource = fixtureIdentity().resource, .provider_policy_digest = @splat(25), .namespace_table_digest = @splat(26) };
}
fn fixtureRow() Row {
    return .{ .identity = fixtureIdentity(), .row_revision = 1, .policy_revision = 2, .last_revocation_revision = 0, .credential_kind = .password, .credential_revision = 1, .credential_digest = @splat(22), .prior_completion = null, .profile = .{ .live = .{ .flags = 0xffffffff, .email = "Alice@example.test", .email_verified = true, .password = .{ .salt = @splat(23), .hash = @splat(24), .pbkdf2_rounds = 100_000 } } } };
}
fn fixtureHead(context: Context, roots: []const NamespaceRoot) Head {
    return .{ .context = context.wire(), .generation = 1, .previous_head_digest = @splat(0), .authority_sequence = 1, .policy_revision = 2, .provider_policy_digest = @splat(25), .namespace_table_digest = @splat(26), .row_roots = roots, .pending = null, .provisioning = .active };
}
fn fixturePresence(context: Context) PresenceReceipt {
    return .{ .realm = context.realm, .origin = context.owner_key, .store_id = .{ .bytes = @splat(27) }, .head_digest = @splat(28), .image_digest = @splat(29), .journal_root = @splat(30), .commit_generation = 1, .image_generation = 1, .journal_generation = 1, .epoch = 1, .issued_through = 0, .frontier_revision = 1, .frontier_through = 0, .expiry_floor_ms = 0 };
}
fn fixtureManifests() [5]ManifestRoot {
    var roots: [5]ManifestRoot = undefined;
    for (&roots, 1..) |*r, k| r.* = emptyManifestRoot(@enumFromInt(k));
    return roots;
}
fn fixtureSubmanifests() [4]ManifestRoot {
    const all = fixtureManifests();
    return all[1..5].*;
}
fn fixtureTarget(context: Context) PresenceReceipt {
    var target = fixturePresence(context);
    target.commit_generation = 2;
    target.image_generation = 2;
    target.journal_generation = 2;
    target.head_digest = @splat(45);
    target.image_digest = @splat(46);
    target.journal_root = @splat(47);
    return target;
}
fn fixtureIntent(context: Context) Intent {
    return .{ .context = context.wire(), .revocation = .{ .identity = fixtureIdentity(), .revision = 1 }, .old_account_row_digest = @splat(31), .old_account_head_digest = @splat(32), .old_presence = fixturePresence(context), .anticipated_presence = fixtureTarget(context), .submanifests = fixtureSubmanifests(), .cohort_root = @splat(33), .cleanup_root = @splat(34), .work_root = @splat(35), .provider_policy_digest = @splat(25), .namespace_table_digest = @splat(26), .policy_revision = 2, .transaction_ref = .{ .bytes = @splat(36) }, .final_effect_root = @splat(37), .intended_publication_generation = 1 };
}
fn fixtureDeclaration(context: Context, head: []const u8, row: []const u8, proof: MembershipProof) Declaration {
    return .{ .context = context.wire(), .revocation = .{ .identity = fixtureIdentity(), .revision = 1 }, .old_account_head_digest = hash(domain(Head), &.{head}), .old_account_row_digest = hash(domain(Row), &.{row}), .old_authority_generation = 1, .old_membership_proof = proof, .old_authority_head = head, .old_account_row = row, .policy_revision = 2, .denial = .revoke_private_authority, .scope = .complete_incarnation, .transaction_ref = .{ .bytes = @splat(36) } };
}
fn roundTripAll(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    const context = fixtureContext(key);
    var row = try encode(Row, allocator, fixtureRow(), context, null, test_limits);
    defer row.deinit();
    var index = try MerkleIndex.init(allocator, &.{.{ .namespace = 1, .family = 0, .key = fixtureIdentity().name.asSlice(), .value = row.asSlice() }}, .{ .max_rows = 8192, .max_bytes = 1 << 20 });
    defer index.deinit();
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = index.root }};
    var head = try encode(Head, allocator, fixtureHead(context, &roots), context, key, test_limits);
    defer head.deinit();
    var checked = try verifyCompleteHead(allocator, head.asSlice(), context, &.{.{ .namespace = 1, .family = 0, .key = fixtureIdentity().name.asSlice(), .value = row.asSlice() }}, test_limits, .{ .max_rows = 8192, .max_bytes = 1 << 20 });
    defer checked.deinit();
    var membership = try index.proof(allocator, 0);
    defer membership.deinit();
    var declaration = try encode(Declaration, allocator, fixtureDeclaration(context, head.asSlice(), row.asSlice(), membership.value), context, key, test_limits);
    defer declaration.deinit();
    var d = try decode(Declaration, allocator, declaration.asSlice(), context, test_limits);
    defer d.deinit();
    try std.testing.expect(d.value.revocation.identity.eql(fixtureIdentity()));
    var intent = try encode(Intent, allocator, fixtureIntent(context), context, key, test_limits);
    defer intent.deinit();
    var i = try decode(Intent, allocator, intent.asSlice(), context, test_limits);
    defer i.deinit();
    const chunk_fields: Chunk = .{ .resource = context.resource, .revocation = fixtureIntent(context).revocation, .kind = .intent, .index = 0, .total = 1, .payload = intent.asSlice() };
    var chunk = try encode(Chunk, allocator, chunk_fields, context, null, test_limits);
    defer chunk.deinit();
    var c = try decode(Chunk, allocator, chunk.asSlice(), context, test_limits);
    defer c.deinit();
    const root = try manifestRoot(allocator, &.{chunk.asSlice()}, .intent, chunk_fields.revocation, context, test_limits);
    try verifyManifest(allocator, &.{chunk.asSlice()}, root, chunk_fields.revocation, context, test_limits);
    var key_buf: [256]u8 = undefined;
    const locator = try chunkKey(&key_buf, chunk_fields);
    try std.testing.expect(std.mem.startsWith(u8, locator, "account-revocation/chunk/v1/"));
    try std.testing.expect(std.mem.endsWith(u8, locator, "/intent/0"));
}

test "account authority canonical service name and nonwrapping identities" {
    const name = try AccountName.init("Alice.EXAMPLE-1");
    try std.testing.expectEqualStrings("alice.example-1", name.asSlice());
    for ([_][]const u8{ "", "bad account", "x:y", "x/y", "x\x80", "123456789012345678901234567890123" }) |bad| try std.testing.expectError(error.InvalidName, AccountName.init(bad));
    var malformed = name;
    malformed.bytes[31] = 1;
    try std.testing.expectError(error.InvalidName, malformed.validate());
    try std.testing.expectError(error.InvalidIdentity, ResourceId.init(@splat(0)));
    try std.testing.expectError(error.InvalidIdentity, Incarnation.init(@splat(0)));
    try std.testing.expectError(error.Exhausted, (try Incarnation.init(@splat(255))).next());
    var carry = Incarnation.first();
    carry.bytes[31] = 255;
    carry = try carry.next();
    try std.testing.expectEqual(@as(u8, 1), carry.bytes[30]);
    try std.testing.expectEqual(@as(u8, 0), carry.bytes[31]);
    try std.testing.expectError(error.Exhausted, nextRevision(std.math.maxInt(u64)));
    try std.testing.expect(!@hasDecl(VerifiedAuthProof, "init") and !@hasDecl(AcceptedAuth, "init"));
}
test "account authority complete schemas roundtrip and exhaustive allocation rollback retry" {
    var key = try sign.KeyPair.fromSeed(@splat(197));
    defer key.deinit();
    try roundTripAll(std.testing.allocator, &key);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, roundTripAll, .{&key});
}
test "account authority owned decode survives input release and secret owners wipe before free" {
    var key = try sign.KeyPair.fromSeed(@splat(198));
    defer key.deinit();
    const context = fixtureContext(&key);
    var wire = try encode(Row, std.testing.allocator, fixtureRow(), context, null, test_limits);
    var owned = try decode(Row, std.testing.allocator, wire.asSlice(), context, test_limits);
    defer owned.deinit();
    wire.deinit();
    try std.testing.expectEqualStrings("Alice@example.test", owned.value.profile.live.email);
    try std.testing.expectEqual(@as(u32, 100_000), owned.value.profile.live.password.?.pbkdf2_rounds);
    var storage: [64]u8 = @splat(0);
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var secret = try SecretBytes.copy(fixed.allocator(), "private fixture");
    const held = secret.bytes.?;
    secret.deinit();
    try std.testing.expect(std.mem.allEqual(u8, held, 0));
    secret.deinit();
}
test "account authority signed head strict context signature domain lengths and ownership" {
    var key = try sign.KeyPair.fromSeed(@splat(199));
    defer key.deinit();
    var other = try sign.KeyPair.fromSeed(@splat(200));
    defer other.deinit();
    const context = fixtureContext(&key);
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
    var wire = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer wire.deinit();
    var decoded = try decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits);
    decoded.deinit();
    for (0..wire.asSlice().len) |offset| {
        wire.bytes.?[offset] ^= 1;
        try std.testing.expectError(error.BadSignature, decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits));
        wire.bytes.?[offset] ^= 1;
    }
    for (0..wire.asSlice().len) |length| {
        if (decode(Head, std.testing.allocator, wire.asSlice()[0..length], context, test_limits)) |valid| {
            var o = valid;
            o.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    var wrong = context;
    wrong.realm[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, decode(Head, std.testing.allocator, wire.asSlice(), wrong, test_limits));
    wrong = context;
    wrong.resource.bytes[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, decode(Head, std.testing.allocator, wire.asSlice(), wrong, test_limits));
    wrong = context;
    wrong.owner_key = other.public_key;
    try std.testing.expectError(error.BadSignature, decode(Head, std.testing.allocator, wire.asSlice(), wrong, test_limits));
    try std.testing.expectError(error.ContextMismatch, encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &other, test_limits));
    const body_len = wire.asSlice().len - 64;
    wire.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Intent), wire.asSlice()[0..body_len]);
    try std.testing.expectError(error.BadSignature, decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits));
}
test "account authority strict locally signed malformed head and row reject before publication" {
    var key = try sign.KeyPair.fromSeed(@splat(201));
    defer key.deinit();
    const context = fixtureContext(&key);
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
    var wire = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer wire.deinit();
    const body_len = wire.asSlice().len - 64;
    wire.bytes.?[5] = 2;
    wire.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Head), wire.asSlice()[0..body_len]);
    try std.testing.expectError(error.InvalidFormat, decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits));
    var row = fixtureRow();
    row.profile.live.password.?.pbkdf2_rounds = 0;
    try std.testing.expectError(error.InvalidField, encode(Row, std.testing.allocator, row, context, null, test_limits));
    row = fixtureRow();
    row.identity.incarnation = try row.identity.incarnation.next();
    try std.testing.expectError(error.InvalidField, encode(Row, std.testing.allocator, row, context, null, test_limits));
    row = fixtureRow();
    row.identity.name.bytes[0] = 'A';
    try std.testing.expectError(error.InvalidName, encode(Row, std.testing.allocator, row, context, null, test_limits));
    var too_small = test_limits;
    too_small.max_wire_bytes = 6;
    try std.testing.expectError(error.Capacity, encode(Row, std.testing.allocator, fixtureRow(), context, null, too_small));
}

// Tests bypass structural validation only to create genuinely owner-signed
// malformed inputs. This helper is private and never mints an admission proof.
fn uncheckedWire(comptime T: type, value: T, key: *const sign.KeyPair) !Wire {
    var w: Writer = .{ .limits = test_limits };
    try w.put(magic(T));
    try w.int(u8, 1);
    try write(&w, T, value);
    const body_len = w.offset;
    const trailer: usize = if (signed(T)) 64 else if (T == Chunk) 32 else 0;
    var result: Wire = .{ .allocator = std.testing.allocator, .bytes = try std.testing.allocator.alloc(u8, body_len + trailer) };
    errdefer result.deinit();
    w = .{ .bytes = result.bytes.?, .limits = test_limits };
    try w.put(magic(T));
    try w.int(u8, 1);
    try write(&w, T, value);
    if (signed(T)) try w.put(&(try key.signCtx(domain(T), result.asSlice()[0..body_len])));
    if (T == Chunk) try w.put(&hash(domain(T), &.{result.asSlice()[0..body_len]}));
    return result;
}

test "account authority signed declaration requires exact old account identity revision and membership" {
    var key = try sign.KeyPair.fromSeed(@splat(202));
    defer key.deinit();
    const context = fixtureContext(&key);
    var row_wire = try encode(Row, std.testing.allocator, fixtureRow(), context, null, test_limits);
    defer row_wire.deinit();
    var index = try MerkleIndex.init(std.testing.allocator, &.{.{ .namespace = 1, .family = 0, .key = fixtureIdentity().name.asSlice(), .value = row_wire.asSlice() }}, .{ .max_rows = 10, .max_bytes = 4096 });
    defer index.deinit();
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = index.root }};
    var head_wire = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer head_wire.deinit();
    var proof = try index.proof(std.testing.allocator, 0);
    defer proof.deinit();
    const original = fixtureDeclaration(context, head_wire.asSlice(), row_wire.asSlice(), proof.value);
    for (0..8) |case| {
        var bad = original;
        switch (case) {
            0 => bad.revocation.identity.name = try AccountName.init("bob"),
            1 => bad.revocation.identity.incarnation = try bad.revocation.identity.incarnation.next(),
            2 => bad.revocation.revision += 1,
            3 => bad.old_membership_proof.leaf.value_digest[0] ^= 1,
            4 => bad.old_authority_generation += 1,
            5 => bad.old_membership_proof.leaf.key = "bob",
            6 => bad.old_account_head_digest[0] ^= 1,
            7 => bad.policy_revision += 1,
            else => unreachable,
        }
        var signed_bad = try uncheckedWire(Declaration, bad, &key);
        defer signed_bad.deinit();
        try std.testing.expectError(error.InvalidProof, decode(Declaration, std.testing.allocator, signed_bad.asSlice(), context, test_limits));
    }
    var valid = try encode(Declaration, std.testing.allocator, original, context, &key, test_limits);
    defer valid.deinit();
    const body_len = valid.asSlice().len - 64;
    valid.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Head), valid.asSlice()[0..body_len]);
    try std.testing.expectError(error.BadSignature, decode(Declaration, std.testing.allocator, valid.asSlice(), context, test_limits));
    valid.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Declaration), valid.asSlice()[0..body_len]);
    var owned = try decode(Declaration, std.testing.allocator, valid.asSlice(), context, test_limits);
    defer owned.deinit();
    head_wire.deinit();
    row_wire.deinit();
    proof.deinit();
    try verifyDeclarationEvidence(std.testing.allocator, owned.value, context, test_limits);
}

test "account authority complete roots adjacent absence and proof tamper refusal" {
    const rows = [_]Leaf{
        .{ .namespace = 1, .family = 0, .key = "alice", .value = "row-a" },
        .{ .namespace = 1, .family = 0, .key = "carol", .value = "row-c" },
        .{ .namespace = 1, .family = 0, .key = "eve", .value = "row-e" },
    };
    var index = try MerkleIndex.init(std.testing.allocator, &rows, .{ .max_rows = 8192, .max_bytes = 4096 });
    defer index.deinit();
    var a = try index.proof(std.testing.allocator, 0);
    defer a.deinit();
    var c = try index.proof(std.testing.allocator, 1);
    defer c.deinit();
    var e = try index.proof(std.testing.allocator, 2);
    defer e.deinit();
    try verifyValue(index.root, c.value, "row-c");
    try verifyAbsence(index.root, .{ .namespace = 1, .family = 0, .key = "bob" }, a.value, c.value);
    try verifyAbsence(index.root, .{ .namespace = 1, .family = 0, .key = "z" }, e.value, null);
    try std.testing.expectError(error.InvalidProof, verifyAbsence(index.root, .{ .namespace = 1, .family = 0, .key = "bob" }, a.value, e.value));
    try std.testing.expectError(error.InvalidProof, verifyAbsence(index.root, .{ .namespace = 1, .family = 0, .key = "carol" }, a.value, c.value));
    try std.testing.expectError(error.InvalidProof, verifyValue(index.root, c.value, "wrong"));
    var bad = c.value;
    bad.index = 0;
    try std.testing.expectError(error.InvalidProof, verifyMembership(index.root, bad));
    var wrong_root = index.root;
    wrong_root.bytes += 1;
    try std.testing.expectError(error.InvalidProof, verifyMembership(wrong_root, c.value));
    try verifyAbsence(emptyRoot(), .{ .namespace = 1, .family = 0, .key = "alice" }, null, null);
    try std.testing.expectError(error.InvalidProof, MerkleIndex.init(std.testing.allocator, &.{ rows[0], rows[0] }, .{ .max_rows = 10, .max_bytes = 4096 }));
    var key = try sign.KeyPair.fromSeed(@splat(203));
    defer key.deinit();
    const context = fixtureContext(&key);
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = index.root }};
    var wire = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer wire.deinit();
    try std.testing.expectError(error.InvalidProof, verifyCompleteHead(std.testing.allocator, wire.asSlice(), context, rows[0..2], test_limits, .{ .max_rows = 8192, .max_bytes = 4096 }));
    var complete = try verifyCompleteHead(std.testing.allocator, wire.asSlice(), context, &rows, test_limits, .{ .max_rows = 8192, .max_bytes = 4096 });
    complete.deinit();
    try std.testing.expectError(error.Overflow, treeWidth(std.math.maxInt(usize)));
}

fn fixturePending(context: Context) PendingRoot {
    const intent = fixtureIntent(context);
    var roots = fixtureManifests();
    roots[0] = .{ .kind = .intent, .chunks = 1, .bytes = 200, .root = @splat(50) };
    const receipt: PacketReceipt = .{ .digest = @splat(48), .first_sequence = 1, .next_sequence = 5, .wal_epoch = .{ .bytes = @splat(49) }, .start_offset = 25, .end_offset = 100 };
    return .{ .revocation = intent.revocation, .intent_root = @splat(50), .cohort_root = intent.cohort_root, .cleanup_root = intent.cleanup_root, .work_root = intent.work_root, .manifests = roots, .old_presence = intent.old_presence, .anticipated_presence = intent.anticipated_presence, .phase = .acknowledged, .ack = .{ .intent_head_digest = @splat(51), .account_packet = receipt, .presence_packet = receipt, .completed_presence = intent.anticipated_presence, .permitted_dominance_root = null, .work_set_root = intent.work_root, .negative_proof_root = @splat(52), .final_join_commitment = @splat(53), .planned_publication_generation = 1, .custody_transfer_root = @splat(54) }, .cleanup_cursor = 0, .cleanup_receipt_root = @splat(55) };
}
fn nestedRoundtrip(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    const context = fixtureContext(key);
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
    var head = fixtureHead(context, &roots);
    head.pending = fixturePending(context);
    var wire = try encode(Head, allocator, head, context, key, test_limits);
    defer wire.deinit();
    var result = try decode(Head, allocator, wire.asSlice(), context, test_limits);
    defer result.deinit();
    try std.testing.expectEqual(@as(u64, 2), result.value.pending.?.ack.?.completed_presence.commit_generation);
}

test "account authority nested joined ACK exact and dominating receipts allocation atomic" {
    var key = try sign.KeyPair.fromSeed(@splat(204));
    defer key.deinit();
    try nestedRoundtrip(std.testing.allocator, &key);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, nestedRoundtrip, .{&key});
    const context = fixtureContext(&key);
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
    const original = fixtureHead(context, &roots);
    for (0..6) |case| {
        var bad = original;
        bad.pending = fixturePending(context);
        switch (case) {
            0 => bad.pending.?.ack = null,
            1 => bad.pending.?.ack.?.completed_presence.head_digest[0] ^= 1,
            2 => bad.pending.?.anticipated_presence.store_id.bytes[0] ^= 1,
            3 => bad.pending.?.anticipated_presence.expiry_floor_ms = -1,
            4 => bad.pending.?.ack.?.work_set_root[0] ^= 1,
            5 => bad.pending.?.manifests[1].kind = .intent,
            else => unreachable,
        }
        var wire = try uncheckedWire(Head, bad, &key);
        defer wire.deinit();
        if (case == 2) {
            try std.testing.expectError(error.ContextMismatch, decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits));
        } else try std.testing.expectError(error.InvalidField, decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits));
    }
    var head = original;
    head.pending = fixturePending(context);
    head.pending.?.ack.?.completed_presence.commit_generation = 3;
    head.pending.?.ack.?.permitted_dominance_root = @splat(56);
    var wire = try encode(Head, std.testing.allocator, head, context, &key, test_limits);
    defer wire.deinit();
    var decoded = try decode(Head, std.testing.allocator, wire.asSlice(), context, test_limits);
    defer decoded.deinit();
    // Structural data names the mandatory proof. Only the later joined owner
    // can verify domination; this decode never issues an admission capability.
    try std.testing.expect(decoded.value.pending.?.ack.?.permitted_dominance_root != null);
}

test "account authority chunk Merkle manifest complete order count identity and digest" {
    var key = try sign.KeyPair.fromSeed(@splat(205));
    defer key.deinit();
    const context = fixtureContext(&key);
    const id = fixtureIntent(context).revocation;
    const original: Chunk = .{ .resource = context.resource, .revocation = id, .kind = .cleanup, .index = 0, .total = 3, .payload = "first" };
    var chunks: [3]Wire = undefined;
    var made: usize = 0;
    defer for (chunks[0..made]) |*wire| wire.deinit();
    for (&chunks, 0..) |*wire, i| {
        var fields = original;
        fields.index = i;
        fields.payload = switch (i) {
            0 => "first",
            1 => "second",
            2 => "third",
            else => unreachable,
        };
        wire.* = try encode(Chunk, std.testing.allocator, fields, context, null, test_limits);
        made += 1;
    }
    const wires = [_][]const u8{ chunks[0].asSlice(), chunks[1].asSlice(), chunks[2].asSlice() };
    const root = try manifestRoot(std.testing.allocator, &wires, .cleanup, id, context, test_limits);
    try std.testing.expectEqual(@as(u64, 16), root.bytes);
    try verifyManifest(std.testing.allocator, &wires, root, id, context, test_limits);
    try std.testing.expectError(error.InvalidProof, verifyManifest(std.testing.allocator, wires[0..2], root, id, context, test_limits));
    try std.testing.expectError(error.InvalidProof, manifestRoot(std.testing.allocator, &.{ wires[1], wires[0], wires[2] }, .cleanup, id, context, test_limits));
    try std.testing.expectError(error.InvalidProof, manifestRoot(std.testing.allocator, &.{ wires[0], wires[0], wires[2] }, .cleanup, id, context, test_limits));
    var reused = id;
    reused.identity.incarnation = try reused.identity.incarnation.next();
    try std.testing.expectError(error.InvalidProof, manifestRoot(std.testing.allocator, &wires, .cleanup, reused, context, test_limits));
    var wrong = root;
    wrong.bytes += 1;
    try std.testing.expectError(error.InvalidProof, verifyManifest(std.testing.allocator, &wires, wrong, id, context, test_limits));
    for (0..chunks[0].asSlice().len) |offset| {
        chunks[0].bytes.?[offset] ^= 1;
        try std.testing.expectError(error.BadDigest, decode(Chunk, std.testing.allocator, chunks[0].asSlice(), context, test_limits));
        chunks[0].bytes.?[offset] ^= 1;
    }
    try verifyManifest(std.testing.allocator, &.{}, emptyManifestRoot(.cleanup), id, context, test_limits);
    var wrong_empty = emptyManifestRoot(.intent);
    wrong_empty.kind = .cleanup;
    try std.testing.expectError(error.InvalidProof, verifyManifest(std.testing.allocator, &.{}, wrong_empty, id, context, test_limits));
}

test "account authority checked wire counts trailing enum optional boolean and limits" {
    var key = try sign.KeyPair.fromSeed(@splat(206));
    defer key.deinit();
    const context = fixtureContext(&key);
    var wire = try encode(Row, std.testing.allocator, fixtureRow(), context, null, test_limits);
    defer wire.deinit();
    const extra = try std.testing.allocator.alloc(u8, wire.asSlice().len + 1);
    defer std.testing.allocator.free(extra);
    @memcpy(extra[0..wire.asSlice().len], wire.asSlice());
    extra[extra.len - 1] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(Row, std.testing.allocator, extra, context, test_limits));
    // Walk canonical fixed fields to test genuine parser boundaries rather than
    // relying on absolute offset literals that drift when schema fields change.
    var reader: Reader = .{ .bytes = wire.asSlice()[6..], .allocator = std.testing.allocator, .limits = test_limits };
    _ = try read(&reader, AccountIdentity);
    _ = try read(&reader, u64); // row
    _ = try read(&reader, u64); // policy
    _ = try read(&reader, u64); // last revocation
    const kind_offset = 6 + reader.offset;
    _ = try read(&reader, CredentialKind);
    _ = try read(&reader, u64);
    _ = try read(&reader, Digest);
    const optional_offset = 6 + reader.offset;
    _ = try read(&reader, @FieldType(Row, "prior_completion"));
    const tag_offset = 6 + reader.offset;
    _ = try read(&reader, RowKind);
    _ = try read(&reader, u32);
    const blob_offset = 6 + reader.offset;
    _ = try read(&reader, []const u8);
    const bool_offset = 6 + reader.offset;
    for ([_]usize{ kind_offset, optional_offset, tag_offset, bool_offset }) |offset| {
        const saved = wire.bytes.?[offset];
        wire.bytes.?[offset] = 255;
        try std.testing.expectError(error.InvalidField, decode(Row, std.testing.allocator, wire.asSlice(), context, test_limits));
        wire.bytes.?[offset] = saved;
    }
    const saved = wire.bytes.?[blob_offset..][0..8].*;
    @memset(wire.bytes.?[blob_offset..][0..8], 255);
    try std.testing.expectError(error.Capacity, decode(Row, std.testing.allocator, wire.asSlice(), context, test_limits));
    wire.bytes.?[blob_offset..][0..8].* = saved;
    var limited = test_limits;
    limited.max_blob_bytes = 1;
    try std.testing.expectError(error.Capacity, decode(Row, std.testing.allocator, wire.asSlice(), context, limited));
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
    var head = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer head.deinit();
    reader = .{ .bytes = head.asSlice()[6 .. head.asSlice().len - 64], .allocator = std.testing.allocator, .limits = test_limits };
    _ = try read(&reader, WireContext);
    _ = try read(&reader, u64);
    _ = try read(&reader, Digest);
    _ = try read(&reader, u64);
    _ = try read(&reader, u64);
    _ = try read(&reader, Digest);
    _ = try read(&reader, Digest);
    const count_offset = 6 + reader.offset;
    @memset(head.bytes.?[count_offset..][0..8], 255);
    const body_len = head.asSlice().len - 64;
    head.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Head), head.asSlice()[0..body_len]);
    try std.testing.expectError(error.Capacity, decode(Head, std.testing.allocator, head.asSlice(), context, test_limits));
    // Checked multiplication rejects overflow before allocating any collection.
    var overflow_reader: Reader = .{ .bytes = &(@as([8]u8, @splat(255))), .allocator = std.testing.allocator, .limits = .{ .max_wire_bytes = std.math.maxInt(usize), .max_blob_bytes = std.math.maxInt(usize), .max_collection_elements = std.math.maxInt(usize) } };
    try std.testing.expectError(error.Overflow, read(&overflow_reader, []const NamespaceRoot));
}

test "account authority explicit revoked and reused lineage never infers live authority" {
    var key = try sign.KeyPair.fromSeed(@splat(207));
    defer key.deinit();
    const context = fixtureContext(&key);
    var row = fixtureRow();
    row.row_revision = 2;
    row.last_revocation_revision = 1;
    row.profile = .{ .revoked = .{ .revocation = .{ .identity = row.identity, .revision = 1 }, .completion = .complete, .completed_intent_root = @splat(57), .completion_receipt = @splat(58) } };
    var wire = try encode(Row, std.testing.allocator, row, context, null, test_limits);
    defer wire.deinit();
    var revoked = try decode(Row, std.testing.allocator, wire.asSlice(), context, test_limits);
    defer revoked.deinit();
    try std.testing.expect(revoked.value.profile == .revoked);
    row.profile = fixtureRow().profile;
    row.identity.incarnation = try row.identity.incarnation.next();
    row.prior_completion = .{ .incarnation = fixtureIdentity().incarnation, .intent_root = @splat(57), .receipt = @splat(58) };
    var reused_wire = try encode(Row, std.testing.allocator, row, context, null, test_limits);
    defer reused_wire.deinit();
    var reused = try decode(Row, std.testing.allocator, reused_wire.asSlice(), context, test_limits);
    defer reused.deinit();
    try std.testing.expect(!reused.value.identity.eql(revoked.value.identity));
    // Identical names/password material do not collapse incarnation identity.
    try std.testing.expectEqualStrings(reused.value.identity.name.asSlice(), revoked.value.identity.name.asSlice());
    var ref: CredentialRef = .{ .identity = row.identity, .kind = .password, .revision = 1, .value_digest = row.credential_digest };
    try validateCredentialReference(ref);
    ref.revision = 0;
    try std.testing.expectError(error.InvalidField, validateCredentialReference(ref));
    try std.testing.expectError(error.InvalidField, validateProviderReference(.{ .provider_id = @splat(1), .issuer_digest = @splat(2), .subject = "", .claim_epoch = 1, .mapping_revision = 1 }));
}

test "account authority configured populations above 4096 have no implicit codec ceiling" {
    const count = 8192;
    const keys = try std.testing.allocator.alloc([8]u8, count);
    defer std.testing.allocator.free(keys);
    const rows = try std.testing.allocator.alloc(Leaf, count);
    defer std.testing.allocator.free(rows);
    for (rows, 0..) |*row, i| {
        std.mem.writeInt(u64, &keys[i], i, .big);
        row.* = .{ .namespace = 1, .family = 0, .key = &keys[i], .value = "x" };
    }
    var index = try MerkleIndex.init(std.testing.allocator, rows, .{ .max_rows = count, .max_bytes = count * 9 });
    defer index.deinit();
    var proof = try index.proof(std.testing.allocator, count - 1);
    defer proof.deinit();
    try verifyValue(index.root, proof.value, "x");
    try std.testing.expectEqual(@as(u64, count), index.root.rows);
    try std.testing.expectError(error.Capacity, MerkleIndex.init(std.testing.allocator, rows, .{ .max_rows = 4096, .max_bytes = count * 9 }));
}

test "account authority configured policy and namespace pins reject owner signed substitutions" {
    var key = try sign.KeyPair.fromSeed(@splat(208));
    defer key.deinit();
    const context = fixtureContext(&key);
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
    for (0..2) |case| {
        var head = fixtureHead(context, &roots);
        if (case == 0) head.provider_policy_digest[0] ^= 1 else head.namespace_table_digest[0] ^= 1;
        var bad = try uncheckedWire(Head, head, &key);
        defer bad.deinit();
        try std.testing.expectError(error.ContextMismatch, decode(Head, std.testing.allocator, bad.asSlice(), context, test_limits));
        var intent = fixtureIntent(context);
        if (case == 0) intent.provider_policy_digest[0] ^= 1 else intent.namespace_table_digest[0] ^= 1;
        var bad_intent = try uncheckedWire(Intent, intent, &key);
        defer bad_intent.deinit();
        try std.testing.expectError(error.ContextMismatch, decode(Intent, std.testing.allocator, bad_intent.asSlice(), context, test_limits));
    }
    var wire = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer wire.deinit();
    var wrong = context;
    wrong.namespace_table_digest[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, decode(Head, std.testing.allocator, wire.asSlice(), wrong, test_limits));
    wrong = context;
    wrong.provider_policy_digest[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, decode(Head, std.testing.allocator, wire.asSlice(), wrong, test_limits));
}

test "account authority OPAD old head independently verifies configured policy and owner" {
    var key = try sign.KeyPair.fromSeed(@splat(209));
    defer key.deinit();
    const context = fixtureContext(&key);
    var row = try encode(Row, std.testing.allocator, fixtureRow(), context, null, test_limits);
    defer row.deinit();
    var index = try MerkleIndex.init(std.testing.allocator, &.{.{ .namespace = 1, .family = 0, .key = fixtureIdentity().name.asSlice(), .value = row.asSlice() }}, .{ .max_rows = 10, .max_bytes = 4096 });
    defer index.deinit();
    var proof = try index.proof(std.testing.allocator, 0);
    defer proof.deinit();
    const roots = [_]NamespaceRoot{.{ .namespace = 1, .family = 0, .root = index.root }};
    for (0..3) |case| {
        var head = fixtureHead(context, &roots);
        if (case == 0) head.provider_policy_digest[0] ^= 1;
        if (case == 1) head.namespace_table_digest[0] ^= 1;
        var other_key = try sign.KeyPair.fromSeed(@splat(210));
        defer other_key.deinit();
        if (case == 2) head.context.owner_key = other_key.public_key;
        var head_wire = try uncheckedWire(Head, head, if (case == 2) &other_key else &key);
        defer head_wire.deinit();
        const declaration = fixtureDeclaration(context, head_wire.asSlice(), row.asSlice(), proof.value);
        var wire = try uncheckedWire(Declaration, declaration, &key);
        defer wire.deinit();
        if (case == 2) {
            try std.testing.expectError(error.BadSignature, decode(Declaration, std.testing.allocator, wire.asSlice(), context, test_limits));
        } else try std.testing.expectError(error.ContextMismatch, decode(Declaration, std.testing.allocator, wire.asSlice(), context, test_limits));
    }
}

test "account authority every signed schema binds its domain and trailing bytes" {
    var key = try sign.KeyPair.fromSeed(@splat(211));
    defer key.deinit();
    const context = fixtureContext(&key);
    var intent = try encode(Intent, std.testing.allocator, fixtureIntent(context), context, &key, test_limits);
    defer intent.deinit();
    const body_len = intent.asSlice().len - 64;
    intent.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Declaration), intent.asSlice()[0..body_len]);
    try std.testing.expectError(error.BadSignature, decode(Intent, std.testing.allocator, intent.asSlice(), context, test_limits));
    // A genuinely signed extra body byte cannot be ignored by a strict reader.
    const extra = try std.testing.allocator.alloc(u8, intent.asSlice().len + 1);
    defer std.testing.allocator.free(extra);
    @memcpy(extra[0..body_len], intent.asSlice()[0..body_len]);
    extra[body_len] = 0;
    extra[body_len + 1 ..][0..64].* = try key.signCtx(domain(Intent), extra[0 .. body_len + 1]);
    try std.testing.expectError(error.TrailingBytes, decode(Intent, std.testing.allocator, extra, context, test_limits));
    var row = fixtureRow();
    row.identity.incarnation = try (try row.identity.incarnation.next()).next();
    row.prior_completion = .{ .incarnation = Incarnation.first(), .intent_root = @splat(1), .receipt = @splat(2) };
    var gap = try uncheckedWire(Row, row, &key);
    defer gap.deinit();
    try std.testing.expectError(error.InvalidField, decode(Row, std.testing.allocator, gap.asSlice(), context, test_limits));
}

test "account authority namespace proof scope includes empty roots and all actual Store families" {
    const empty: NamespaceRoot = .{ .namespace = 2, .family = 6, .root = emptyRoot() };
    try verifyNamespaceAbsence(empty, .{ .namespace = 2, .family = 6, .key = "credential" }, null, null);
    try std.testing.expectError(error.InvalidProof, verifyNamespaceAbsence(empty, .{ .namespace = 1, .family = 0, .key = "alice" }, null, null));
    var key = try sign.KeyPair.fromSeed(@splat(212));
    defer key.deinit();
    const context = fixtureContext(&key);
    const roots = [_]NamespaceRoot{
        .{ .namespace = 1, .family = 0, .root = emptyRoot() },
        .{ .namespace = 2, .family = 6, .root = emptyRoot() },
        .{ .namespace = 3, .family = 7, .root = emptyRoot() },
    };
    var head = try encode(Head, std.testing.allocator, fixtureHead(context, &roots), context, &key, test_limits);
    defer head.deinit();
    var complete = try verifyCompleteHead(std.testing.allocator, head.asSlice(), context, &.{}, test_limits, .{ .max_rows = 8192, .max_bytes = 4096 });
    defer complete.deinit();
    try std.testing.expectEqual(@as(usize, 3), complete.value.row_roots.len);
    var bad = roots;
    bad[2].family = 8;
    var invalid = try uncheckedWire(Head, fixtureHead(context, &bad), &key);
    defer invalid.deinit();
    try std.testing.expectError(error.InvalidField, decode(Head, std.testing.allocator, invalid.asSlice(), context, test_limits));
}

test "account authority allocation census balanced complete and nested owned decodes" {
    var key = try sign.KeyPair.fromSeed(@splat(213));
    defer key.deinit();
    var complete = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try roundTripAll(complete.allocator(), &key);
    try std.testing.expectEqual(complete.allocated_bytes, complete.freed_bytes);
    var nested = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try nestedRoundtrip(nested.allocator(), &key);
    try std.testing.expectEqual(nested.allocated_bytes, nested.freed_bytes);
    std.debug.print("account authority allocation census: complete={d}, nested={d}; every index swept in dedicated tests\n", .{ complete.allocations, nested.allocations });
}

const AcyclicFixture = struct {
    allocator: std.mem.Allocator,
    subchunks: [4]Wire,
    intent: Wire,
    intent_chunks: [2]Wire,
    head: Wire,
    fields: Intent,
    head_fields: Head,
    roots: [1]NamespaceRoot,
    fn deinit(self: *AcyclicFixture) void {
        self.head.deinit();
        for (&self.intent_chunks) |*wire| wire.deinit();
        self.intent.deinit();
        for (&self.subchunks) |*wire| wire.deinit();
    }
    fn init(allocator: std.mem.Allocator, key: *const sign.KeyPair) !AcyclicFixture {
        const context = fixtureContext(key);
        var fixture: AcyclicFixture = undefined;
        fixture.allocator = allocator;
        fixture.fields = fixtureIntent(context);
        var submade: usize = 0;
        errdefer for (fixture.subchunks[0..submade]) |*wire| wire.deinit();
        for (&fixture.subchunks, 0..) |*wire, i| {
            const kind: ManifestKind = @enumFromInt(i + 2);
            wire.* = try encode(Chunk, allocator, .{ .resource = context.resource, .revocation = fixture.fields.revocation, .kind = kind, .index = 0, .total = 1, .payload = "exact independently owned submanifest facts" }, context, null, test_limits);
            submade += 1;
            fixture.fields.submanifests[i] = try manifestRoot(allocator, &.{wire.asSlice()}, kind, fixture.fields.revocation, context, test_limits);
        }
        // D4 signature has four real subroots, and no containing intent root.
        fixture.intent = try encode(Intent, allocator, fixture.fields, context, key, test_limits);
        errdefer fixture.intent.deinit();
        const split = fixture.intent.asSlice().len / 2;
        var intentmade: usize = 0;
        errdefer for (fixture.intent_chunks[0..intentmade]) |*wire| wire.deinit();
        for (&fixture.intent_chunks, 0..) |*wire, i| {
            const payload = if (i == 0) fixture.intent.asSlice()[0..split] else fixture.intent.asSlice()[split..];
            wire.* = try encode(Chunk, allocator, .{ .resource = context.resource, .revocation = fixture.fields.revocation, .kind = .intent, .index = i, .total = 2, .payload = payload }, context, null, test_limits);
            intentmade += 1;
        }
        // D5 computes/activates the real outer root only after encoded D4 exists.
        const outer = try manifestRoot(allocator, &.{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() }, .intent, fixture.fields.revocation, context, test_limits);
        var pending = fixturePending(context);
        pending.phase = .intent;
        pending.ack = null;
        pending.intent_root = outer.root;
        pending.manifests[0] = outer;
        @memcpy(pending.manifests[1..5], &fixture.fields.submanifests);
        fixture.roots = .{.{ .namespace = 1, .family = 0, .root = emptyRoot() }};
        fixture.head_fields = fixtureHead(context, &fixture.roots);
        fixture.head_fields.pending = pending;
        fixture.head = try encode(Head, allocator, fixture.head_fields, context, key, test_limits);
        return fixture;
    }
};
fn acyclicRoundtrip(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    var fixture = try AcyclicFixture.init(allocator, key);
    defer fixture.deinit();
    // A stored pointer into the initializer's local roots must not escape; only
    // the serialized Head does. Test mutation rebuilds explicitly rebind below.
    fixture.head_fields.row_roots = &fixture.roots;
    const context = fixtureContext(key);
    for (fixture.subchunks, 0..) |wire, i| try verifyManifest(allocator, &.{wire.asSlice()}, fixture.fields.submanifests[i], fixture.fields.revocation, context, test_limits);
    var activated = try decodeActivatedIntent(allocator, fixture.head.asSlice(), &.{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() }, context, test_limits);
    defer activated.deinit();
    fixture.deinit();
    try std.testing.expectEqual(@as(usize, 4), activated.value.submanifests.len);
    try std.testing.expectEqual(@as(u64, 1), activated.value.submanifests[0].chunks);
}

test "account authority acyclic real four subroots signed intent exact chunks activated head OOM" {
    var key = try sign.KeyPair.fromSeed(@splat(215));
    defer key.deinit();
    try acyclicRoundtrip(std.testing.allocator, &key);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, acyclicRoundtrip, .{&key});
    var census = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try acyclicRoundtrip(census.allocator(), &key);
    try std.testing.expectEqual(census.allocated_bytes, census.freed_bytes);
    std.debug.print("account authority acyclic allocation census: {d}; every index swept\n", .{census.allocations});
}

test "account authority acyclic activation refuses every root identity signature and order substitution" {
    var key = try sign.KeyPair.fromSeed(@splat(216));
    defer key.deinit();
    const context = fixtureContext(&key);
    var fixture = try AcyclicFixture.init(std.testing.allocator, &key);
    defer fixture.deinit();
    fixture.head_fields.row_roots = &fixture.roots;
    const chunks = [_][]const u8{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() };
    try std.testing.expectError(error.InvalidProof, decodeActivatedIntent(std.testing.allocator, fixture.head.asSlice(), &.{ chunks[1], chunks[0] }, context, test_limits));
    try std.testing.expectError(error.InvalidProof, decodeActivatedIntent(std.testing.allocator, fixture.head.asSlice(), chunks[0..1], context, test_limits));
    for (0..7) |case| {
        var bad = fixture.head_fields;
        switch (case) {
            0...3 => bad.pending.?.manifests[case + 1].root[0] ^= 1,
            4 => bad.pending.?.cohort_root[0] ^= 1,
            5 => bad.pending.?.work_root[0] ^= 1,
            6 => bad.pending.?.revocation.identity.incarnation = try bad.pending.?.revocation.identity.incarnation.next(),
            else => unreachable,
        }
        var wire = try encode(Head, std.testing.allocator, bad, context, &key, test_limits);
        defer wire.deinit();
        try std.testing.expectError(error.InvalidProof, decodeActivatedIntent(std.testing.allocator, wire.asSlice(), &chunks, context, test_limits));
    }
    var malformed = fixture.fields;
    malformed.submanifests[0].kind = .intent;
    var signed_bad = try uncheckedWire(Intent, malformed, &key);
    defer signed_bad.deinit();
    try std.testing.expectError(error.InvalidField, decode(Intent, std.testing.allocator, signed_bad.asSlice(), context, test_limits));
    // Change D4 domain, then recompute honest D5 chunk/root/head. Outer signatures
    // and checksums cannot rescue the invalid inner intent signature.
    const body_len = fixture.intent.asSlice().len - 64;
    fixture.intent.bytes.?[body_len..][0..64].* = try key.signCtx(domain(Head), fixture.intent.asSlice()[0..body_len]);
    for (&fixture.intent_chunks, 0..) |*wire, i| {
        wire.deinit();
        const split = fixture.intent.asSlice().len / 2;
        wire.* = try encode(Chunk, std.testing.allocator, .{ .resource = context.resource, .revocation = fixture.fields.revocation, .kind = .intent, .index = i, .total = 2, .payload = if (i == 0) fixture.intent.asSlice()[0..split] else fixture.intent.asSlice()[split..] }, context, null, test_limits);
    }
    const altered = [_][]const u8{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() };
    var rebuilt = fixture.head_fields;
    rebuilt.pending.?.manifests[0] = try manifestRoot(std.testing.allocator, &altered, .intent, fixture.fields.revocation, context, test_limits);
    rebuilt.pending.?.intent_root = rebuilt.pending.?.manifests[0].root;
    var head = try encode(Head, std.testing.allocator, rebuilt, context, &key, test_limits);
    defer head.deinit();
    try std.testing.expectError(error.BadSignature, decodeActivatedIntent(std.testing.allocator, head.asSlice(), &altered, context, test_limits));
}

test "account authority reassembly causal preserves legitimate individually bounded chunks" {
    var key = try sign.KeyPair.fromSeed(@splat(217));
    defer key.deinit();
    const context = fixtureContext(&key);
    var fixture = try AcyclicFixture.init(std.testing.allocator, &key);
    defer fixture.deinit();
    var limits = test_limits;
    limits.max_blob_bytes = fixture.intent.asSlice().len - 1;
    var head = try decode(Head, std.testing.allocator, fixture.head.asSlice(), context, limits);
    defer head.deinit();
    var intent = try decode(Intent, std.testing.allocator, fixture.intent.asSlice(), context, limits);
    defer intent.deinit();
    for (fixture.intent_chunks) |wire| {
        var chunk = try decode(Chunk, std.testing.allocator, wire.asSlice(), context, limits);
        defer chunk.deinit();
        try std.testing.expect(chunk.value.payload.len <= limits.max_blob_bytes);
    }
    const chunks = [_][]const u8{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() };
    try verifyManifest(std.testing.allocator, &chunks, head.value.pending.?.manifests[0], fixture.fields.revocation, context, limits);
    var restored = try decodeActivatedIntent(std.testing.allocator, fixture.head.asSlice(), &chunks, context, limits);
    defer restored.deinit();
}

fn boundedReassemblyRoundtrip(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    var fixture = try AcyclicFixture.init(allocator, key);
    defer fixture.deinit();
    var limits = test_limits;
    limits.max_blob_bytes = fixture.intent.asSlice().len - 1;
    var result = try decodeActivatedIntent(allocator, fixture.head.asSlice(), &.{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() }, fixtureContext(key), limits);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 4), result.value.submanifests.len);
}

test "account authority reassembly budgets preflight before chunk work and every OOM retry" {
    var key = try sign.KeyPair.fromSeed(@splat(218));
    defer key.deinit();
    const context = fixtureContext(&key);
    try boundedReassemblyRoundtrip(std.testing.allocator, &key);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, boundedReassemblyRoundtrip, .{&key});
    var census = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try boundedReassemblyRoundtrip(census.allocator(), &key);
    try std.testing.expectEqual(census.allocated_bytes, census.freed_bytes);
    std.debug.print("account authority bounded reassembly allocation census: {d}; every index swept\n", .{census.allocations});
    var fixture = try AcyclicFixture.init(std.testing.allocator, &key);
    defer fixture.deinit();
    fixture.head_fields.row_roots = &fixture.roots;
    for (0..2) |case| {
        var head = fixture.head_fields;
        if (case == 0) {
            head.pending.?.manifests[0].bytes = test_limits.max_wire_bytes + 1;
        } else head.pending.?.manifests[0].chunks = test_limits.max_collection_elements + 1;
        var wire = try encode(Head, std.testing.allocator, head, context, &key, test_limits);
        defer wire.deinit();
        var control = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var decoded = try decode(Head, control.allocator(), wire.asSlice(), context, test_limits);
        decoded.deinit();
        // Exactly enough for authenticated Head decode; any later allocation
        // would fail OOM. Capacity must precede manifest/tree/assembly work.
        var bounded = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = control.allocations });
        try std.testing.expectError(error.Capacity, decodeActivatedIntent(bounded.allocator(), wire.asSlice(), &.{ fixture.intent_chunks[0].asSlice(), fixture.intent_chunks[1].asSlice() }, context, test_limits));
        try std.testing.expect(!bounded.has_induced_failure);
        try std.testing.expectEqual(control.allocations, bounded.allocations);
        try std.testing.expectEqual(bounded.allocated_bytes, bounded.freed_bytes);
    }
}
