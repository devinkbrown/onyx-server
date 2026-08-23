// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free operator-session provenance and OCG2 projection rules.
//!
//! This leaf deliberately contains no I/O, locks, logging, or runtime grant
//! consumer.  Services supplies a copied durable lookup and callers decide
//! when (or whether) to apply the returned projection to a live session.

const std = @import("std");
const oper = @import("oper.zig");
const oper_cred_share = @import("../proto/oper_cred_share.zig");

pub const digest_len: usize = 32;
pub const max_account_len: usize = oper_cred_share.ocg2_max_account_len;
pub const max_class_len: usize = @max(oper_cred_share.ocg2_max_class_len, oper.default_params.max_class_len);
pub const max_title_len: usize = oper_cred_share.ocg2_max_title_len;
pub const max_projection_account_len: usize = @max(max_account_len, oper.default_params.max_account_len);
pub const wire_max_len: usize = oper_cred_share.ocg2_max_wire_len;
pub const authority_pubkey_len: usize = oper_cred_share.ocg2_pubkey_len;

const ReplacementSeal = struct { pin: u8 = 1 };
const LocalBindingSeal = struct { pin: u8 = 1 };
const MintPermitSeal = struct { pin: u8 = 1 };
var replacement_seal: ReplacementSeal = .{};
var local_binding_seal: LocalBindingSeal = .{};
var mint_permit_seal: MintPermitSeal = .{};

/// Why a previously projected authority must be removed.  This is deliberately
/// a small stable taxonomy: authority-unavailable is represented by the
/// dedicated reconciliation outcome below, not duplicated as a clear reason.
pub const ClearReason = enum {
    account_changed,
    absent,
    not_yet_valid,
    expired,
    tombstone,
    equivocation,
    revision_changed,
    digest_changed,
    non_exportable,
    authority_unavailable,
};

/// Origin of a session's current operator projection.
pub const Source = enum {
    none,
    configured_local,
    legacy_ocg1,
    ocg2,
};

/// The minimum OCG2 identity needed to bind a session projection to one
/// durable record.  The digest is over the exact signed OCG2 wire bytes.
pub const Ocg2Stamp = struct {
    revision: u64,
    /// Digest persisted in the durable authority tuple (BLAKE3 today).  It
    /// remains separate from `wire_sha256`: the latter is the application
    /// proof over the exact signed bytes and is recomputed at the session
    /// boundary.
    digest: [digest_len]u8,
    wire_sha256: [digest_len]u8,
    authority_node_id: u64,
    authority_pubkey: [authority_pubkey_len]u8,
    issued_ms: u64,
    expiry_ms: u64,
};

/// Session provenance carries source only; operator privileges remain in the
/// session projection and are never duplicated in this authority stamp.
pub const Provenance = union(Source) {
    none: void,
    configured_local: void,
    legacy_ocg1: void,
    ocg2: Ocg2Stamp,
};

/// A live configured-local binding.  The registry pointer and the expected
/// binding are private so a caller cannot turn an arbitrary `OperGrant` value
/// into local authority.  `reconcile` and application re-check the pointed
/// registry, which also makes a rehash/config replacement invalidate a stale
/// capability.
pub const ConfiguredLocalBinding = struct {
    registry: *const oper.OperRegistry,
    account_buf: [max_projection_account_len]u8 = @splat(0),
    account_len: usize = 0,
    class_buf: [max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    privilege_bits: u64 = 0,
    presubscribe_bits: u64 = 0,
    seal: *const LocalBindingSeal,

    pub fn account(self: *const ConfiguredLocalBinding) []const u8 {
        return self.account_buf[0..self.account_len];
    }

    pub fn className(self: *const ConfiguredLocalBinding) []const u8 {
        return self.class_buf[0..self.class_len];
    }

    pub fn titleText(self: *const ConfiguredLocalBinding) []const u8 {
        return self.title_buf[0..self.title_len];
    }

    pub fn privileges(self: *const ConfiguredLocalBinding) oper.OperPrivileges {
        return oper.OperPrivileges.fromBits(self.privilege_bits);
    }

    pub fn presubscribeBits(self: *const ConfiguredLocalBinding) u64 {
        return self.presubscribe_bits;
    }

    fn fieldsBounded(self: *const ConfiguredLocalBinding) bool {
        return self.account_len <= self.account_buf.len and
            self.class_len <= self.class_buf.len and
            self.title_len <= self.title_buf.len;
    }

    fn valid(self: *const ConfiguredLocalBinding, authenticated_account: []const u8) bool {
        if (self.seal != &local_binding_seal) return false;
        if (!self.fieldsBounded()) return false;
        const account_text = self.account();
        if (!std.mem.eql(u8, authenticated_account, account_text)) return false;
        const binding = self.registry.lookup(account_text) orelse return false;
        return std.mem.eql(u8, binding.account_name, account_text) and
            std.mem.eql(u8, binding.class_name, self.className()) and
            std.mem.eql(u8, binding.title, self.titleText()) and
            binding.privileges.toBits() == self.privilege_bits and
            binding.presubscribe_bits == self.presubscribe_bits;
    }
};

/// Build a capability from the live operator registry.  The returned value is
/// intentionally the only production path for configured-local authority.
pub fn configuredLocalBinding(
    registry: *const oper.OperRegistry,
    account: []const u8,
) ?ConfiguredLocalBinding {
    const binding = registry.lookup(account) orelse return null;
    if (binding.account_name.len > max_projection_account_len or
        binding.class_name.len > max_class_len or binding.title.len > max_title_len)
        return null;
    var out = ConfiguredLocalBinding{
        .registry = registry,
        .privilege_bits = binding.privileges.toBits(),
        .presubscribe_bits = binding.presubscribe_bits,
        .seal = &local_binding_seal,
    };
    @memcpy(out.account_buf[0..binding.account_name.len], binding.account_name);
    out.account_len = binding.account_name.len;
    @memcpy(out.class_buf[0..binding.class_name.len], binding.class_name);
    out.class_len = binding.class_name.len;
    @memcpy(out.title_buf[0..binding.title.len], binding.title);
    out.title_len = binding.title.len;
    return out;
}

fn liveOperGrant(registry: *const oper.OperRegistry, account: []const u8) bool {
    const live = registry.lookup(account) orelse return false;
    return live.privileges.has(.oper_grant);
}

/// Sealed mint capability.  The only production constructor is
/// `configuredLocalMintPermit`, which requires a currently live configured-local
/// binding, the exact authenticated account, and a live `oper_grant` bit.
/// OCG2, legacy OCG1, snapshot, remote, non-oper, fabricated, and stale
/// bindings cannot obtain one.
pub const ConfiguredLocalMintPermit = struct {
    binding: ConfiguredLocalBinding,
    seal: *const MintPermitSeal,

    pub fn account(self: *const ConfiguredLocalMintPermit) []const u8 {
        return self.binding.account();
    }

    /// Synchronous revalidation against the issuer's expected live registry.
    /// Pointer identity is required: a genuine seal from a private attacker
    /// registry is rejected even when the copied bindings are identical.
    pub fn valid(
        self: *const ConfiguredLocalMintPermit,
        expected_registry: *const oper.OperRegistry,
    ) bool {
        if (!self.binding.fieldsBounded()) return false;
        return validMintPermit(self.binding, expected_registry, self.account(), self.seal);
    }
};

fn validMintPermit(
    binding: ConfiguredLocalBinding,
    expected_registry: *const oper.OperRegistry,
    authenticated_account: []const u8,
    seal: *const MintPermitSeal,
) bool {
    if (seal != &mint_permit_seal) return false;
    if (binding.registry != expected_registry) return false;
    if (!binding.valid(authenticated_account)) return false;
    if (!binding.privileges().has(.oper_grant)) return false;
    return liveOperGrant(expected_registry, authenticated_account);
}

/// Build a mint permit from a live configured-local binding revalidated against
/// the current operator registry.  This is the only production constructor.
pub fn configuredLocalMintPermit(
    registry: *const oper.OperRegistry,
    binding: ConfiguredLocalBinding,
    authenticated_account: []const u8,
) ?ConfiguredLocalMintPermit {
    if (!validMintPermit(binding, registry, authenticated_account, &mint_permit_seal))
        return null;
    return .{
        .binding = binding,
        .seal = &mint_permit_seal,
    };
}

comptime {
    if (@hasDecl(@This(), "mintPermitFromOcg2") or
        @hasDecl(@This(), "mintPermitFromLegacy") or
        @hasDecl(@This(), "mintPermitFromSnapshot") or
        @hasDecl(@This(), "mintPermitFromRemote") or
        @hasDecl(@This(), "mintPermitFromGrant") or
        @hasDecl(ConfiguredLocalMintPermit, "fromOcg2") or
        @hasDecl(ConfiguredLocalMintPermit, "fromLegacy") or
        @hasDecl(ConfiguredLocalMintPermit, "fromSnapshot") or
        @hasDecl(ConfiguredLocalMintPermit, "fromRemote") or
        @hasDecl(ConfiguredLocalMintPermit, "fromOperGrant") or
        @hasDecl(ConfiguredLocalMintPermit, "fromDurable"))
        @compileError("ConfiguredLocalMintPermit has exactly one production constructor");
}

/// A copied durable grant.  All variable-length fields live inline so a
/// Services lookup remains valid after the Services lock is released and after
/// a later durable merge.  No slice in this type borrows authority state.
pub const DurableOperGrantCopy = struct {
    account_buf: [max_account_len]u8 = @splat(0),
    account_len: usize = 0,
    class_buf: [max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    privilege_bits: u64 = 0,
    revision: u64 = 0,
    digest: [digest_len]u8 = @splat(0),
    wire_sha256: [digest_len]u8 = @splat(0),
    authority_node_id: u64 = 0,
    authority_pubkey: [authority_pubkey_len]u8 = @splat(0),
    issued_ms: u64 = 0,
    expiry_ms: u64 = 0,
    kind: oper_cred_share.Ocg2Kind = .grant,
    equivocation: bool = false,
    wire_buf: [wire_max_len]u8 = @splat(0),
    wire_len: usize = 0,

    pub fn account(self: *const DurableOperGrantCopy) []const u8 {
        return self.account_buf[0..self.account_len];
    }

    pub fn class(self: *const DurableOperGrantCopy) []const u8 {
        return self.class_buf[0..self.class_len];
    }

    pub fn title(self: *const DurableOperGrantCopy) []const u8 {
        return self.title_buf[0..self.title_len];
    }

    pub fn privileges(self: *const DurableOperGrantCopy) oper.OperPrivileges {
        return oper.OperPrivileges.fromBits(self.privilege_bits);
    }

    pub fn stamp(self: *const DurableOperGrantCopy) Ocg2Stamp {
        return .{
            .revision = self.revision,
            .digest = self.digest,
            .wire_sha256 = self.wire_sha256,
            .authority_node_id = self.authority_node_id,
            .authority_pubkey = self.authority_pubkey,
            .issued_ms = self.issued_ms,
            .expiry_ms = self.expiry_ms,
        };
    }

    pub fn signedWire(self: *const DurableOperGrantCopy) []const u8 {
        return self.wire_buf[0..self.wire_len];
    }

    pub fn copyFrom(
        account_name: []const u8,
        class_name: []const u8,
        title_text: []const u8,
        privilege_bits: u64,
        revision: u64,
        digest: [digest_len]u8,
        issued_ms: u64,
        expiry_ms: u64,
    ) ?DurableOperGrantCopy {
        if (account_name.len > max_account_len or class_name.len > max_class_len or title_text.len > max_title_len)
            return null;
        var out = DurableOperGrantCopy{
            .privilege_bits = privilege_bits,
            .revision = revision,
            .digest = digest,
            .issued_ms = issued_ms,
            .expiry_ms = expiry_ms,
        };
        @memcpy(out.account_buf[0..account_name.len], account_name);
        out.account_len = account_name.len;
        @memcpy(out.class_buf[0..class_name.len], class_name);
        out.class_len = class_name.len;
        @memcpy(out.title_buf[0..title_text.len], title_text);
        out.title_len = title_text.len;
        return out;
    }

    /// Copy a verified active OCG2 record, including the exact signed bytes and
    /// configured authority.  `null` means the durable tuple and wire do not
    /// agree; callers must fail closed rather than manufacture a projection.
    pub fn copyFromVerified(
        account_name: []const u8,
        class_name: []const u8,
        title_text: []const u8,
        privilege_bits: u64,
        revision: u64,
        digest: [digest_len]u8,
        authority_node_id: u64,
        authority_pubkey: [authority_pubkey_len]u8,
        issued_ms: u64,
        expiry_ms: u64,
        kind: oper_cred_share.Ocg2Kind,
        equivocation: bool,
        wire: []const u8,
    ) ?DurableOperGrantCopy {
        if (kind != .grant or equivocation or wire.len == 0 or wire.len > wire_max_len) return null;
        if (account_name.len > max_account_len or class_name.len > max_class_len or title_text.len > max_title_len)
            return null;
        var blake3_digest: [digest_len]u8 = undefined;
        std.crypto.hash.Blake3.hash(wire, &blake3_digest, .{});
        if (!std.mem.eql(u8, &blake3_digest, &digest)) return null;
        var sha256_digest: [digest_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(wire, &sha256_digest, .{});
        var out = DurableOperGrantCopy{
            .privilege_bits = privilege_bits,
            .revision = revision,
            .digest = digest,
            .wire_sha256 = sha256_digest,
            .authority_node_id = authority_node_id,
            .authority_pubkey = authority_pubkey,
            .issued_ms = issued_ms,
            .expiry_ms = expiry_ms,
            .kind = kind,
            .equivocation = equivocation,
        };
        @memcpy(out.account_buf[0..account_name.len], account_name);
        out.account_len = account_name.len;
        @memcpy(out.class_buf[0..class_name.len], class_name);
        out.class_len = class_name.len;
        @memcpy(out.title_buf[0..title_text.len], title_text);
        out.title_len = title_text.len;
        @memcpy(out.wire_buf[0..wire.len], wire);
        out.wire_len = wire.len;
        return out;
    }
};

/// Services' copied read result.  Rejected states intentionally carry no
/// record metadata, avoiding accidental exposure of stale or equivocated data.
pub const DurableOperLookup = union(enum) {
    disabled,
    unavailable,
    absent,
    not_yet_valid,
    expired,
    tombstone,
    equivocation,
    active: DurableOperGrantCopy,
};

pub const Inputs = struct {
    current: Provenance = .none,
    authenticated_account: ?[]const u8 = null,
    /// Secure configured-local capability.  It is resolved against the live
    /// registry at reconciliation and application time.
    configured_binding: ?ConfiguredLocalBinding = null,
    /// Legacy source-compatibility field.  It is deliberately untrusted and is
    /// never used to construct authority; callers must migrate to
    /// `configured_binding`.
    configured_local: ?oper.OperGrant = null,
    durable: DurableOperLookup = .disabled,
    now_ms: u64 = 0,
};

const ProjectedGrant = struct {
    privileges: oper.OperPrivileges,
    class_buf: [max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    presubscribe_bits: u64 = 0,

    pub fn className(self: *const ProjectedGrant) []const u8 {
        return self.class_buf[0..self.class_len];
    }

    pub fn titleText(self: *const ProjectedGrant) []const u8 {
        return self.title_buf[0..self.title_len];
    }

    fn fromSlices(
        privileges: oper.OperPrivileges,
        class_name: []const u8,
        title: []const u8,
        presubscribe_bits: u64,
    ) ?ProjectedGrant {
        if (class_name.len > max_class_len or title.len > max_title_len) return null;
        var out = ProjectedGrant{ .privileges = privileges, .presubscribe_bits = presubscribe_bits };
        @memcpy(out.class_buf[0..class_name.len], class_name);
        out.class_len = class_name.len;
        @memcpy(out.title_buf[0..title.len], title);
        out.title_len = title.len;
        return out;
    }
};

const ProjectionState = struct {
    account_buf: [max_projection_account_len]u8 = @splat(0),
    account_len: usize = 0,
    grant: ProjectedGrant,
    provenance: Provenance,
    configured_binding: ?ConfiguredLocalBinding,
    wire_buf: [wire_max_len]u8 = @splat(0),
    wire_len: usize = 0,
    seal: *const ReplacementSeal = &replacement_seal,
};

pub const ProjectionData = struct {
    account_buf: [max_projection_account_len]u8 = @splat(0),
    account_len: usize = 0,
    privileges: oper.OperPrivileges = .{},
    class_buf: [max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    presubscribe_bits: u64 = 0,
    provenance: Provenance = .none,

    pub fn account(self: *const ProjectionData) []const u8 {
        return self.account_buf[0..self.account_len];
    }

    pub fn className(self: *const ProjectionData) []const u8 {
        return self.class_buf[0..self.class_len];
    }

    pub fn titleText(self: *const ProjectionData) []const u8 {
        return self.title_buf[0..self.title_len];
    }
};

pub const Visitor = struct {
    context: *anyopaque,
    apply: *const fn (*anyopaque, ProjectionData) void,
    clear: *const fn (*anyopaque, ClearReason) void,
    unavailable: *const fn (*anyopaque) void,
};

pub const ReconcileOutcome = enum {
    unchanged,
    replaced,
    clear,
    authority_unavailable,
};

/// Validate the private projection proof and copy only non-authoritative
/// projection data into the synchronous visitor.  No proof pointer or authority
/// constructor crosses the module boundary.
fn validateProjection(
    state: *const ProjectionState,
    authenticated_account: []const u8,
    now_ms: u64,
) ?ProjectionData {
    if (state.seal != &replacement_seal or state.account_len == 0 or
        state.account_len > max_projection_account_len or
        !std.mem.eql(u8, authenticated_account, state.account_buf[0..state.account_len]) or
        state.grant.privileges.count() == 0)
        return null;

    switch (state.provenance) {
        .none, .legacy_ocg1 => return null,
        .configured_local => {
            const binding = state.configured_binding orelse return null;
            if (!binding.valid(authenticated_account) or
                binding.privilege_bits != state.grant.privileges.toBits() or
                !std.mem.eql(u8, binding.className(), state.grant.className()) or
                !std.mem.eql(u8, binding.titleText(), state.grant.titleText()) or
                binding.presubscribeBits() != state.grant.presubscribe_bits)
                return null;
        },
        .ocg2 => |stamp| {
            if (state.grant.className().len == 0 or
                state.grant.privileges.toBits() == 0 or
                state.grant.privileges.toBits() & ~oper.ocg2_exportable_bits != 0 or
                stamp.revision == 0 or stamp.issued_ms >= stamp.expiry_ms or
                stamp.issued_ms > now_ms or now_ms >= stamp.expiry_ms or
                stamp.authority_node_id == 0 or state.wire_len == 0 or
                state.wire_len > wire_max_len)
                return null;
            const public_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(stamp.authority_pubkey) catch return null;
            const wire = state.wire_buf[0..state.wire_len];
            const fields = oper_cred_share.verifyOcg2(wire, public_key, stamp.authority_node_id, now_ms) catch return null;
            if (fields.kind != .grant or !std.mem.eql(u8, fields.account, authenticated_account) or
                fields.revision != stamp.revision or fields.issued_ms != stamp.issued_ms or
                fields.expiry_ms != stamp.expiry_ms or fields.authority_node_id != stamp.authority_node_id or
                !std.mem.eql(u8, &fields.authority_pubkey, &stamp.authority_pubkey) or
                fields.privilege_bits != state.grant.privileges.toBits() or
                fields.privilege_bits & ~oper.ocg2_exportable_bits != 0 or
                !std.mem.eql(u8, fields.class, state.grant.className()) or
                !std.mem.eql(u8, fields.title, state.grant.titleText()))
                return null;
            var sha256_digest: [digest_len]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(wire, &sha256_digest, .{});
            if (!std.mem.eql(u8, &sha256_digest, &stamp.wire_sha256)) return null;
            var blake3_digest: [digest_len]u8 = undefined;
            std.crypto.hash.Blake3.hash(wire, &blake3_digest, .{});
            if (!std.mem.eql(u8, &blake3_digest, &stamp.digest)) return null;
        },
    }

    var out = ProjectionData{
        .privileges = state.grant.privileges,
        .presubscribe_bits = state.grant.presubscribe_bits,
        .provenance = state.provenance,
    };
    @memcpy(out.account_buf[0..state.account_len], state.account_buf[0..state.account_len]);
    out.account_len = state.account_len;
    @memcpy(out.class_buf[0..state.grant.class_len], state.grant.class_buf[0..state.grant.class_len]);
    out.class_len = state.grant.class_len;
    @memcpy(out.title_buf[0..state.grant.title_len], state.grant.title_buf[0..state.grant.title_len]);
    out.title_len = state.grant.title_len;
    return out;
}

fn sameAccount(a: ?[]const u8, b: []const u8) bool {
    return if (a) |value| std.mem.eql(u8, value, b) else false;
}

fn currentIsOper(current: Provenance) bool {
    return current != .none;
}

fn emitProjection(visitor: Visitor, state: *const ProjectionState, now_ms: u64) ReconcileOutcome {
    const account = state.account_buf[0..state.account_len];
    const data = validateProjection(state, account, now_ms) orelse {
        visitor.clear(visitor.context, .non_exportable);
        return .clear;
    };
    visitor.apply(visitor.context, data);
    return .replaced;
}

fn emitLocal(visitor: Visitor, binding: ConfiguredLocalBinding, now_ms: u64) ReconcileOutcome {
    const projected = ProjectedGrant.fromSlices(
        binding.privileges(),
        binding.className(),
        binding.titleText(),
        binding.presubscribeBits(),
    ) orelse {
        visitor.clear(visitor.context, .non_exportable);
        return .clear;
    };
    var state = ProjectionState{ .grant = projected, .provenance = .configured_local, .configured_binding = binding };
    @memcpy(state.account_buf[0..binding.account().len], binding.account());
    state.account_len = binding.account().len;
    return emitProjection(visitor, &state, now_ms);
}

fn emitDurable(visitor: Visitor, copy: DurableOperGrantCopy, now_ms: u64) ReconcileOutcome {
    const projected = ProjectedGrant.fromSlices(copy.privileges(), copy.class(), copy.title(), 0) orelse {
        visitor.clear(visitor.context, .non_exportable);
        return .clear;
    };
    if (copy.wire_len == 0 or copy.wire_len > wire_max_len) {
        visitor.clear(visitor.context, .non_exportable);
        return .clear;
    }
    var state = ProjectionState{ .grant = projected, .provenance = .{ .ocg2 = copy.stamp() }, .configured_binding = null };
    @memcpy(state.account_buf[0..copy.account().len], copy.account());
    state.account_len = copy.account().len;
    @memcpy(state.wire_buf[0..copy.wire_len], copy.signedWire());
    state.wire_len = copy.wire_len;
    return emitProjection(visitor, &state, now_ms);
}

/// Pure, allocation-free authority reconciliation.  Configured-local grants
/// have precedence over every durable result.  Legacy OCG1 provenance remains
/// distinguishable and is never treated as an OCG2 stamp.
pub fn reconcile(inputs: Inputs, visitor: Visitor) ReconcileOutcome {
    _ = inputs.authenticated_account orelse {
        if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .account_changed);
        return if (currentIsOper(inputs.current)) .clear else .unchanged;
    };

    if (inputs.configured_binding) |binding| {
        if (!sameAccount(inputs.authenticated_account, binding.account()))
            return if (currentIsOper(inputs.current)) blk: {
                visitor.clear(visitor.context, .account_changed);
                break :blk .clear;
            } else .unchanged;
        if (!binding.valid(inputs.authenticated_account.?))
            return if (currentIsOper(inputs.current)) blk: {
                visitor.clear(visitor.context, .non_exportable);
                break :blk .clear;
            } else .unchanged;
        // A configured binding with no privileges is not an operator
        // projection.  Keep the fail-closed outcome explicit so callers never
        // observe a non-empty provenance paired with an empty privilege set.
        if (binding.privileges().count() == 0) {
            visitor.clear(visitor.context, .non_exportable);
            return .clear;
        }
        // The supplied binding is the authority, not historical session
        // provenance. Always replace so a live config change cannot retain an
        // older privilege/class/title projection.
        return emitLocal(visitor, binding, inputs.now_ms);
    }

    // Do not accept a by-value OperGrant as configured authority.  Keeping the
    // field only avoids an abrupt source break for older callers; it is an
    // explicit fail-closed migration signal until they pass a live binding.
    if (inputs.configured_local != null) {
        if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .non_exportable);
        return if (currentIsOper(inputs.current)) .clear else .unchanged;
    }

    switch (inputs.durable) {
        .disabled => {
            if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .absent);
            return if (currentIsOper(inputs.current)) .clear else .unchanged;
        },
        .unavailable => {
            visitor.unavailable(visitor.context);
            return .authority_unavailable;
        },
        .absent => {
            if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .absent);
            return if (currentIsOper(inputs.current)) .clear else .unchanged;
        },
        .not_yet_valid => {
            if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .not_yet_valid);
            return if (currentIsOper(inputs.current)) .clear else .unchanged;
        },
        .expired => {
            if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .expired);
            return if (currentIsOper(inputs.current)) .clear else .unchanged;
        },
        .tombstone => {
            if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .tombstone);
            return if (currentIsOper(inputs.current)) .clear else .unchanged;
        },
        .equivocation => {
            if (currentIsOper(inputs.current)) visitor.clear(visitor.context, .equivocation);
            return if (currentIsOper(inputs.current)) .clear else .unchanged;
        },
        .active => |copy| {
            if (!sameAccount(inputs.authenticated_account, copy.account()))
                return if (currentIsOper(inputs.current)) blk: {
                    visitor.clear(visitor.context, .account_changed);
                    break :blk .clear;
                } else .unchanged;
            if (copy.privilege_bits == 0 or copy.privilege_bits & ~oper.ocg2_exportable_bits != 0)
                return if (currentIsOper(inputs.current)) blk: {
                    visitor.clear(visitor.context, .non_exportable);
                    break :blk .clear;
                } else .unchanged;
            if (copy.issued_ms > inputs.now_ms)
                return if (currentIsOper(inputs.current)) blk: {
                    visitor.clear(visitor.context, .not_yet_valid);
                    break :blk .clear;
                } else .unchanged;
            if (inputs.now_ms >= copy.expiry_ms)
                return if (currentIsOper(inputs.current)) blk: {
                    visitor.clear(visitor.context, .expired);
                    break :blk .clear;
                } else .unchanged;

            switch (inputs.current) {
                .ocg2 => |stamp| {
                    if (stamp.revision != copy.revision or stamp.issued_ms != copy.issued_ms or stamp.expiry_ms != copy.expiry_ms) {
                        visitor.clear(visitor.context, .revision_changed);
                        return .clear;
                    }
                    if (!std.mem.eql(u8, &stamp.digest, &copy.digest)) {
                        visitor.clear(visitor.context, .digest_changed);
                        return .clear;
                    }
                    return emitDurable(visitor, copy, inputs.now_ms);
                },
                // With no live configured binding above, historical local or
                // legacy provenance has no precedence. Replace it from the
                // exact active OCG2 record.
                .none, .configured_local, .legacy_ocg1 => return emitDurable(visitor, copy, inputs.now_ms),
            }
        },
    }
}

const TestVisitorState = struct {
    applied: bool = false,
    cleared: ?ClearReason = null,
    unavailable_seen: bool = false,
    data: ProjectionData = .{},

    fn apply(ctx: *anyopaque, data: ProjectionData) void {
        const self: *TestVisitorState = @ptrCast(@alignCast(ctx));
        self.data = data;
        self.applied = true;
    }

    fn clear(ctx: *anyopaque, reason: ClearReason) void {
        const self: *TestVisitorState = @ptrCast(@alignCast(ctx));
        self.cleared = reason;
    }

    fn unavailable(ctx: *anyopaque) void {
        const self: *TestVisitorState = @ptrCast(@alignCast(ctx));
        self.unavailable_seen = true;
    }

    fn visitor(self: *TestVisitorState) Visitor {
        return .{
            .context = self,
            .apply = apply,
            .clear = clear,
            .unavailable = unavailable,
        };
    }
};

test "OCG2PROV reconciliation is synchronous and local binding is live" {
    const bindings = [_]oper.OperBinding{.{
        .account_name = "alice",
        .class_name = "local",
        .privileges = oper.OperPrivileges.initMany(&.{.client_moderate}),
    }};
    const registry = try oper.OperRegistry.init(&bindings);
    const capability = configuredLocalBinding(&registry, "alice") orelse return error.TestUnexpectedResult;
    var sink = TestVisitorState{};
    try std.testing.expectEqual(ReconcileOutcome.replaced, reconcile(.{
        .authenticated_account = "alice",
        .configured_binding = capability,
    }, sink.visitor()));
    try std.testing.expect(sink.applied);
    try std.testing.expectEqualStrings("local", sink.data.className());

    var forged = sink.data;
    forged.privileges = oper.OperPrivileges.full;
    try std.testing.expectEqual(@as(usize, 5), forged.account().len);
    // ProjectionData is only a copied view; it cannot be fed back to any
    // authority sink.  The registry capability remains the source of truth.
    try std.testing.expect(capability.valid("alice"));
}

test "OCG2PROV by-value OperGrant compatibility field fails closed" {
    var sink = TestVisitorState{};
    const result = reconcile(.{
        .authenticated_account = "alice",
        .configured_local = .{
            .account_name = "alice",
            .class_name = "forged",
            .privileges = oper.OperPrivileges.full,
        },
    }, sink.visitor());
    try std.testing.expectEqual(ReconcileOutcome.unchanged, result);
    try std.testing.expect(!sink.applied);
}

test "OCG2PROV lookup states clear and unavailable through visitor" {
    const states = .{
        .{ DurableOperLookup{ .absent = {} }, ClearReason.absent },
        .{ DurableOperLookup{ .not_yet_valid = {} }, ClearReason.not_yet_valid },
        .{ DurableOperLookup{ .expired = {} }, ClearReason.expired },
        .{ DurableOperLookup{ .tombstone = {} }, ClearReason.tombstone },
        .{ DurableOperLookup{ .equivocation = {} }, ClearReason.equivocation },
    };
    inline for (states) |row| {
        var sink = TestVisitorState{};
        const result = reconcile(.{
            .current = .{ .ocg2 = .{ .revision = 1, .digest = @splat(1), .wire_sha256 = @splat(2), .authority_node_id = 1, .authority_pubkey = @splat(3), .issued_ms = 1, .expiry_ms = 2 } },
            .authenticated_account = "alice",
            .durable = row[0],
        }, sink.visitor());
        try std.testing.expectEqual(ReconcileOutcome.clear, result);
        try std.testing.expectEqual(row[1], sink.cleared.?);
    }
    var unavailable_sink = TestVisitorState{};
    try std.testing.expectEqual(ReconcileOutcome.authority_unavailable, reconcile(.{
        .current = .{ .ocg2 = .{ .revision = 1, .digest = @splat(1), .wire_sha256 = @splat(2), .authority_node_id = 1, .authority_pubkey = @splat(3), .issued_ms = 1, .expiry_ms = 2 } },
        .authenticated_account = "alice",
        .durable = .unavailable,
    }, unavailable_sink.visitor()));
    try std.testing.expect(unavailable_sink.unavailable_seen);
}

test "OCG2PROV exact signed wire and projection fields are reverified" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xC1)));
    const authority_pubkey = kp.public_key.toBytes();
    const authority_node_id = @import("../crypto/node_short_id.zig").shortId(@import("node_identity.zig").nodeIdFromPublicKey(authority_pubkey));
    var wire: [wire_max_len]u8 = undefined;
    const wire_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 9,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Network Guardian",
        .authority_node_id = authority_node_id,
        .authority_pubkey = authority_pubkey,
        .issued_ms = 100,
        .expiry_ms = 500,
    }, 100, &wire);
    var digest: [digest_len]u8 = undefined;
    std.crypto.hash.Blake3.hash(wire[0..wire_len], &digest, .{});
    const copy = DurableOperGrantCopy.copyFromVerified(
        "alice",
        "moderator",
        "Network Guardian",
        1 << 3,
        9,
        digest,
        authority_node_id,
        authority_pubkey,
        100,
        500,
        .grant,
        false,
        wire[0..wire_len],
    ) orelse return error.TestUnexpectedResult;
    var sink = TestVisitorState{};
    try std.testing.expectEqual(ReconcileOutcome.replaced, reconcile(.{
        .authenticated_account = "alice",
        .now_ms = 100,
        .durable = .{ .active = copy },
    }, sink.visitor()));
    try std.testing.expect(sink.applied);
    try std.testing.expectEqualStrings("Network Guardian", sink.data.titleText());

    // Mutating copied projection fields cannot bypass the private proof; the
    // exact signed wire and every signed projection field are reverified before
    // the visitor sees any data.
    var forged = copy;
    forged.title_buf[0] = 'X';
    var forged_sink = TestVisitorState{};
    _ = reconcile(.{
        .authenticated_account = "alice",
        .now_ms = 100,
        .durable = .{ .active = forged },
    }, forged_sink.visitor());
    try std.testing.expect(!forged_sink.applied);
}

test "OCG2PROV mint permit requires live configured-local oper_grant" {
    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        .title = "Authority",
    }};
    const registry = try oper.OperRegistry.init(&bindings);
    const capability = configuredLocalBinding(&registry, "root") orelse return error.TestUnexpectedResult;
    const permit = configuredLocalMintPermit(&registry, capability, "root") orelse return error.TestUnexpectedResult;
    try std.testing.expect(permit.valid(&registry));
    try std.testing.expectEqualStrings("root", permit.account());
    try std.testing.expect(permit.binding.privileges().has(.oper_grant));
}

test "OCG2PROV mint permit rejects stale REHASH binding" {
    var bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        .title = "Authority",
    }};
    var registry = try oper.OperRegistry.init(&bindings);
    const capability = configuredLocalBinding(&registry, "root") orelse return error.TestUnexpectedResult;
    const permit = configuredLocalMintPermit(&registry, capability, "root") orelse return error.TestUnexpectedResult;

    const replaced = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{.client_moderate}),
        .title = "Authority",
    }};
    registry.bindings = &replaced;
    try std.testing.expect(configuredLocalMintPermit(&registry, capability, "root") == null);
    try std.testing.expect(!permit.valid(&registry));

    const successor = try oper.OperRegistry.init(&replaced);
    try std.testing.expect(configuredLocalMintPermit(&successor, capability, "root") == null);
    try std.testing.expect(!permit.valid(&successor));
}

test "OCG2PROV mint permit rejects account mismatch" {
    const bindings = [_]oper.OperBinding{
        .{
            .account_name = "root",
            .class_name = "netadmin",
            .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        },
        .{
            .account_name = "alice",
            .class_name = "local",
            .privileges = oper.OperPrivileges.initMany(&.{.client_moderate}),
        },
    };
    const registry = try oper.OperRegistry.init(&bindings);
    const root_binding = configuredLocalBinding(&registry, "root") orelse return error.TestUnexpectedResult;
    try std.testing.expect(configuredLocalMintPermit(&registry, root_binding, "alice") == null);
    try std.testing.expect(configuredLocalMintPermit(&registry, root_binding, "mallory") == null);
}

test "OCG2PROV mint permit rejects missing oper_grant" {
    const bindings = [_]oper.OperBinding{.{
        .account_name = "alice",
        .class_name = "local",
        .privileges = oper.OperPrivileges.initMany(&.{.client_moderate}),
    }};
    const registry = try oper.OperRegistry.init(&bindings);
    const capability = configuredLocalBinding(&registry, "alice") orelse return error.TestUnexpectedResult;
    try std.testing.expect(capability.valid("alice"));
    try std.testing.expect(configuredLocalMintPermit(&registry, capability, "alice") == null);
}

test "OCG2PROV mint permit rejects OCG2 OCG1 snapshot remote nonoper and fabrication" {
    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
    }};
    const registry = try oper.OperRegistry.init(&bindings);
    const live = configuredLocalBinding(&registry, "root") orelse return error.TestUnexpectedResult;
    const permit = configuredLocalMintPermit(&registry, live, "root") orelse return error.TestUnexpectedResult;

    try std.testing.expect(configuredLocalBinding(&registry, "mallory") == null);
    try std.testing.expect(configuredLocalMintPermit(&registry, live, "mallory") == null);

    var fake_binding_seal = LocalBindingSeal{};
    var forged_binding = live;
    forged_binding.seal = &fake_binding_seal;
    try std.testing.expect(configuredLocalMintPermit(&registry, forged_binding, "root") == null);

    var fake_permit_seal = MintPermitSeal{};
    var forged_permit = permit;
    forged_permit.seal = &fake_permit_seal;
    try std.testing.expect(!forged_permit.valid(&registry));

    const ocg1 = oper.OperGrant{
        .account_name = "root",
        .class_name = "forged",
        .privileges = oper.OperPrivileges.full,
    };
    _ = ocg1;
    const ocg2 = DurableOperGrantCopy{};
    _ = ocg2;

    try std.testing.expect(@hasDecl(@This(), "configuredLocalMintPermit"));
    inline for (.{
        "mintPermitFromOcg2",
        "mintPermitFromLegacy",
        "mintPermitFromSnapshot",
        "mintPermitFromRemote",
        "mintPermitFromGrant",
    }) |name| try std.testing.expect(!@hasDecl(@This(), name));
    inline for (.{
        "fromOcg2",
        "fromLegacy",
        "fromSnapshot",
        "fromRemote",
        "fromOperGrant",
        "fromDurable",
    }) |name| try std.testing.expect(!@hasDecl(ConfiguredLocalMintPermit, name));
}

test "OCG2PROV mint permit rejects attacker registry with identical bindings" {
    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        .title = "Authority",
    }};
    const canonical = try oper.OperRegistry.init(&bindings);
    const attacker = try oper.OperRegistry.init(&bindings);
    try std.testing.expect(&canonical != &attacker);

    const attacker_binding = configuredLocalBinding(&attacker, "root") orelse return error.TestUnexpectedResult;
    const attacker_permit = configuredLocalMintPermit(&attacker, attacker_binding, "root") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(attacker_permit.valid(&attacker));
    try std.testing.expect(!attacker_permit.valid(&canonical));
    try std.testing.expect(configuredLocalMintPermit(&canonical, attacker_binding, "root") == null);

    const canonical_binding = configuredLocalBinding(&canonical, "root") orelse return error.TestUnexpectedResult;
    const canonical_permit = configuredLocalMintPermit(&canonical, canonical_binding, "root") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(canonical_permit.valid(&canonical));
    try std.testing.expect(!canonical_permit.valid(&attacker));
}

test "OCG2PROV mint permit rejects mutated max+1 field lengths" {
    const bindings = [_]oper.OperBinding{.{
        .account_name = "root",
        .class_name = "netadmin",
        .privileges = oper.OperPrivileges.initMany(&.{ .oper_grant, .client_moderate }),
        .title = "Authority",
    }};
    const registry = try oper.OperRegistry.init(&bindings);
    const live = configuredLocalBinding(&registry, "root") orelse return error.TestUnexpectedResult;
    const permit = configuredLocalMintPermit(&registry, live, "root") orelse return error.TestUnexpectedResult;
    try std.testing.expect(permit.valid(&registry));

    const cases = [_]struct { account: bool = false, class: bool = false, title: bool = false }{
        .{ .account = true },
        .{ .class = true },
        .{ .title = true },
        .{ .account = true, .class = true, .title = true },
    };
    for (cases) |case| {
        var mutated = permit;
        if (case.account) mutated.binding.account_len = max_projection_account_len + 1;
        if (case.class) mutated.binding.class_len = max_class_len + 1;
        if (case.title) mutated.binding.title_len = max_title_len + 1;
        try std.testing.expect(!mutated.valid(&registry));
        try std.testing.expect(!mutated.binding.valid("root"));
        try std.testing.expect(configuredLocalMintPermit(&registry, mutated.binding, "root") == null);
    }
}
