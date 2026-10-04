// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Multi-session registry: account -> set of live client sessions (Phase 3).
//!
//! Onyx Server treats an *account* as the durable identity, a reclaim token as one
//! logical resumable session, and each connection as an attachment to that
//! session. Multiple attached rows may therefore deliberately carry the SAME
//! token: presenting a valid token joins the logical session; it does not steal
//! it from another live client. This store tracks, per account, the attachments
//! (client id + logical-session token + signon time) so the daemon can list a
//! user's devices, resume a dropped attachment, and route per-session fan-out.
//! Pure and self-contained: the caller keys attachments by the
//! flat `u64` client id (the same packed id used by MONITOR / activity subs) and
//! supplies the reclaim token (generated from the daemon CSPRNG). A flat per-
//! account list keeps ownership trivial (one owned account-name key per account).
const std = @import("std");
const builtin = @import("builtin");
const rwlock = @import("../substrate/rwlock.zig");
const attachment_id_mod = @import("attachment_id.zig");

pub const ClientId = u64;
pub const Token = [16]u8;
pub const AttachmentId = attachment_id_mod.AttachmentId;

/// The all-zero value records a locally tracked session when no CSPRNG was
/// available. It is deliberately not a reclaim credential and therefore must
/// never acquire global token-group or cross-account capability semantics.
fn tokenIsSentinel(token: Token) bool {
    return std.mem.allEqual(u8, &token, 0);
}

pub const snapshot_capacity: usize = 64;
/// The configuration parser caps CHANNELLEN at 200 bytes. Keeping each complete
/// name inline makes replacement/read/clear allocation-free once a row journal
/// exists; first-arm allocation is staged before any generation or row changes.
pub const local_channel_name_capacity: usize = 200;
/// Capacity is the number of concurrently unresolved channel mutations, not a
/// joined-channel limit. The command boundary must arm before mutating World;
/// a ninth distinct pending channel therefore fails closed and can be retried
/// after the projector clears a slot. Re-arming a pending case-insensitive
/// channel replaces it even while all eight slots are occupied.
pub const local_channel_projection_capacity: usize = 8;

pub const Error = std.mem.Allocator.Error || error{
    TooManyAccounts,
    TooManySessions,
    TokenAccountMismatch,
    InvalidAttachmentId,
    DuplicateAttachmentId,
    AttachmentIdMismatch,
    SessionDropReserved,
    ClientAlreadyTracked,
    InvalidToken,
};

pub const BootstrapAttachError = Error || attachment_id_mod.MintError;

pub const BootstrapAttachment = struct {
    session: Session,
    attachment_id: AttachmentId,
};

const AttachMode = enum {
    compatibility,
    bootstrap_no_evict,
};

const attachment_mint_attempts: usize = 4;

pub const Config = struct {
    max_accounts: usize = 65536,
    max_sessions_per_account: usize = snapshot_capacity,
};

/// One durable desired channel image within an exact reusable-token group.
///
/// Every local row bearing the token carries the same bounded set. That
/// deliberate duplication lets any sibling detach or disappear without taking
/// the retry source with it. A newer same-channel arm receives a generation, so
/// an older in-flight retry cannot clear the replacement.
pub const LocalChannelProjection = struct {
    generation: u64 = 0,
    channel_len: u8 = 0,
    channel_bytes: [local_channel_name_capacity]u8 = @splat(0),
    present: bool = false,
    member_mode_bits: u8 = 0,

    pub fn channel(self: *const LocalChannelProjection) []const u8 {
        return self.channel_bytes[0..self.channel_len];
    }
};

/// Canonically sorted, fixed-capacity pending work for one exact token group.
/// Rows acquire an owned copy lazily on the first pending mutation. Arm stages
/// every missing allocation before publishing any pointer, generation, or count;
/// read/retry/CAS-clear remain allocation-free.
const LocalChannelProjectionSet = struct {
    revision: u64 = 0,
    len: u8 = 0,
    items: [local_channel_projection_capacity]LocalChannelProjection = @splat(.{}),

    fn slice(self: *const LocalChannelProjectionSet) []const LocalChannelProjection {
        return self.items[0..self.len];
    }

    fn isEmpty(self: *const LocalChannelProjectionSet) bool {
        return self.len == 0;
    }
};

pub const LocalChannelProjectionWork = struct {
    token: Token,
    projection: LocalChannelProjection,
};

pub const AttachmentReplicaWork = struct {
    token: Token,
    attachment_id: AttachmentId,
};

pub const AttachmentLocalChannelProjectionWork = struct {
    token: Token,
    attachment_id: AttachmentId,
    projection: LocalChannelProjection,
};

/// One accepted arm plus the exact same-channel intent it replaced. Producers
/// that can still reject before their first live mutation use this to restore
/// older accepted work instead of accidentally erasing it.
pub const LocalChannelProjectionArm = struct {
    intent: LocalChannelProjection,
    previous: ?LocalChannelProjection,
};

pub const LocalProjectionArmError = std.mem.Allocator.Error || error{
    InvalidChannel,
    NoSuchToken,
    NoSuchAttachment,
    TooManyPendingChannels,
};

/// Transient owner-protocol identity. Zero is never a valid reservation and is
/// therefore safe as the inline "not reserved" Session value.
pub const DropReservationId = u64;

/// Exact physical row selector used by the reserved cross-owner DROP protocol.
/// It deliberately mirrors the LIST/CAS identity; a recyclable client handle
/// alone can never reserve or remove a different later attachment.
pub const ExactSelector = struct {
    client: ClientId,
    token: Token,
    signon_ms: i64,
    attachment_id: ?AttachmentId = null,
};

pub const ReserveDropResult = enum {
    reserved,
    already_reserved,
    reserved_by_other,
    stale,
    invalid_id,
};

pub const Session = struct {
    client: ClientId,
    /// Reclaim credential for this logical session. Multiple physical rows may
    /// share these bytes. The public LIST/DROP `sid` is derived from the token
    /// plus this row's stable non-null attachment id (`session_sid.zig`)
    /// and is never stored here or in Helix.
    token: Token,
    /// Stable identity of this physical attachment across reconnects, node
    /// moves, and Helix upgrades. Null marks a legacy row created through the
    /// compatibility API; current attachment-aware protocols must reject it
    /// rather than deriving identity from `client`, fd, or the reusable token.
    attachment_id: ?AttachmentId = null,
    signon_ms: i64,
    /// True while the underlying connection is attached; false when the client
    /// dropped but the session is retained for reclaim/bouncer buffering.
    attached: bool = true,
    /// Optional server-owned encoded restore snapshot for detached sessions.
    snapshot: ?[]u8 = null,
    /// Durable group-portability bit. Once any sibling reveals a portable
    /// credential, every exact-token row carries true so issuer removal cannot
    /// silently disable renewal or detached publication.
    portable_resume: bool = false,
    /// A local state mutation for this reusable token has not yet been accepted
    /// by the signed replica store. Dirty is a token-group property: whenever
    /// one row is dirty, every local row bearing the exact token is dirty.
    replica_dirty: bool = false,
    /// A signed replica was accepted but has not yet been projected into every
    /// local attachment's live state. This receive-side retry lane is separate
    /// from `replica_dirty` so projection never mints or republishes a replica.
    replica_projection_dirty: bool = false,
    /// Current-generation SRA3 retry lanes are exact-row properties. They stay
    /// separate from the legacy token-group bits above so compatibility replay
    /// cannot clear or deduplicate sibling attachment work.
    attachment_replica_dirty: bool = false,
    attachment_replica_projection_dirty: bool = false,
    /// Lazily allocated retry journal. Each row owns a complete copy so sibling
    /// removal cannot erase pending work; null means no channel is pending.
    local_channel_projections: ?*LocalChannelProjectionSet = null,
    /// SRA3/local current projection journal for this physical attachment only.
    /// It must never be copied to siblings sharing the reusable token.
    attachment_channel_projections: ?*LocalChannelProjectionSet = null,
    /// Ephemeral two-owner DROP reservation. Never serialized into Helix or a
    /// replica; every lifecycle mutation must leave an owned reservation alone
    /// until its owner commits or cancels.
    drop_reservation: DropReservationId = 0,
};

fn sessionMatchesExact(session: Session, expected: ExactSelector) bool {
    const attachment_matches = if (expected.attachment_id) |attachment|
        session.attachment_id != null and attachment.eql(session.attachment_id.?)
    else
        session.attachment_id == null;
    return session.client == expected.client and
        session.signon_ms == expected.signon_ms and
        attachment_matches and
        std.crypto.timing_safe.eql(Token, session.token, expected.token);
}

fn sessionMatchesAttachment(session: Session, token: Token, attachment_id: AttachmentId) bool {
    const current = session.attachment_id orelse return false;
    return std.crypto.timing_safe.eql(Token, session.token, token) and
        current.eql(attachment_id);
}

pub const ResumeHandle = struct {
    token: Token,
    attachment_id: ?AttachmentId = null,
    portable: bool,
};

pub const EvictedSession = struct {
    client: ClientId,
    token: Token,
    attachment_id: ?AttachmentId = null,
    portable: bool,

    pub fn resumeHandle(self: EvictedSession) ResumeHandle {
        return .{
            .token = self.token,
            .attachment_id = self.attachment_id,
            .portable = self.portable,
        };
    }
};

pub const AttachOutcome = struct {
    session: Session,
    /// Authority silently displaced to make room for the new live attachment.
    /// The daemon uses this to publish a mesh REVOKE if this was the last local
    /// row for an opted-in portable token.
    evicted: ?EvictedSession = null,
};

pub const DetachedSnapshot = struct {
    client: ClientId,
    signon_ms: i64,
    snapshot: []u8,
};

pub const PortableDetachedSnapshot = struct {
    account: []u8,
    token: Token,
    snapshot: []u8,

    pub fn deinit(self: *PortableDetachedSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.snapshot);
        self.* = undefined;
    }
};

/// One exact current-generation detached attachment for SRA3 publication.
/// Unlike the legacy token-group snapshot above, siblings are never deduped.
pub const PortableDetachedAttachmentSnapshot = struct {
    account: []u8,
    token: Token,
    attachment_id: AttachmentId,
    snapshot: []u8,

    pub fn deinit(self: *PortableDetachedAttachmentSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.snapshot);
        self.* = undefined;
    }
};

const SessionList = struct {
    items: std.ArrayListUnmanaged(Session) = .empty,

    fn deinit(self: *SessionList, allocator: std.mem.Allocator) void {
        for (self.items.items) |*session| freeSessionOwned(allocator, session);
        self.items.deinit(allocator);
    }

    fn indexOfClient(self: *const SessionList, client: ClientId) ?usize {
        for (self.items.items, 0..) |s, i| {
            if (s.client == client) return i;
        }
        return null;
    }
};

const AttachmentLocator = struct {
    /// Store-owned account key. The index entry is removed before this slice is
    /// freed by account deletion.
    account: []const u8,
    client: ClientId,
};

/// One indexed reusable-token group. Row locators borrow store-owned account
/// keys and remain valid across SessionList reallocations because client id, not
/// an array index or pointer, is the join key. The cached state is the exact OR
/// (or newest local-projection image) of the listed rows.
const TokenIndexEntry = struct {
    rows: std.ArrayListUnmanaged(AttachmentLocator) = .empty,
    portable_rows: usize = 0,
    dirty_rows: usize = 0,
    projection_dirty_rows: usize = 0,
    drop_reserved_rows: usize = 0,
    local_projections: LocalChannelProjectionSet = .{},

    fn deinit(self: *TokenIndexEntry, allocator: std.mem.Allocator) void {
        self.rows.deinit(allocator);
        self.* = undefined;
    }
};

/// Deterministic complexity evidence used by high-cardinality tests. These
/// counters measure index operations and exact group-row visits, never wall
/// time, so slow or contended builders cannot make the assertions flaky.
pub const TokenIndexComplexity = struct {
    lookups: usize = 0,
    group_row_visits: usize = 0,
};

/// Current lifecycle selectors additionally pin the attached state. The legacy
/// DROP selector remains unchanged for existing callers and checkpoint formats.
pub const LifecycleSelector = struct {
    account: []const u8,
    exact: ExactSelector,
    attached: bool,
};

pub const LifecycleError = BootstrapAttachError || error{
    Busy,
    InvalidRequest,
    OverlappingIntent,
    StaleSelector,
    MissingRow,
    AlreadyAttached,
    AmbiguousPhysicalBinding,
    TokenCollisionExhausted,
    AttachmentCollisionExhausted,
    TooManyPendingChannels,
    ProjectionConflict,
    GenerationExhausted,
    CandidateLimitExceeded,
    InvalidTicket,
};

pub const LifecycleRemoval = enum { physical_close, logout, untrack, garbage_collect, reserved_drop, account_revocation, cap_eviction, claimant_replacement, token_rebind };
pub const LifecycleSnapshot = union(enum) { keep, clear, replace: []const u8 };
pub const LifecycleCap = union(enum) { fail, untracked, evict_detached, evict_exact: LifecycleSelector };
pub const LifecycleAdmissionKind = union(enum) {
    fresh,
    join_existing: Token,
    /// This is a caller-authenticated grant, not authentication by SessionStore.
    adopt_verified: struct { token: Token, portable: bool },
    no_row,
    sentinel,
};
pub const LifecycleAdmission = struct {
    account: []const u8,
    client: ClientId,
    signon_ms: i64,
    kind: LifecycleAdmissionKind,
    cap: LifecycleCap = .fail,
    /// Explicit OLD pristine sentinel replacement only. A legacy nonzero token
    /// with missing attachment identity cannot be upgraded by this API.
    replace_sentinel: ?LifecycleSelector = null,
};
pub const LifecycleRequest = struct {
    request_id: u64,
    intent: union(enum) {
        admit: LifecycleAdmission,
        detach: struct { source: LifecycleSelector, snapshot: LifecycleSnapshot = .keep },
        remove: struct { source: LifecycleSelector, reason: LifecycleRemoval },
        remove_account: []const u8,
        reconnect: struct {
            source: LifecycleSelector,
            claimant_client: ClientId,
            claimant: ?LifecycleSelector = null,
            /// A pristine provisional claimant needs no authority retirement;
            /// any other claimant requires this explicit outer obligation.
            retire_claimant: bool = false,
            consume_snapshot: bool = true,
        },
        rebind: struct {
            source: LifecycleSelector,
            target_account: []const u8,
            target_token: Token,
            kind: TokenBindKind,
            /// Changing token retires, never retags, attachment receive work.
            retire_attachment_work: bool = false,
        },
    },
};
pub const LifecycleDropPermit = struct { source: LifecycleSelector, owner: DropReservationId };
pub const LifecycleObservation = struct { account: []const u8, client: ClientId, expected: ?LifecycleSelector = null };
pub const LifecycleLimits = struct {
    max_operations: usize = 4096,
    max_discovery_rows: usize = 4 * 1024 * 1024,
    max_candidate_rows: usize = 1024 * 1024,
    max_payload_bytes: usize = 256 * 1024 * 1024,
    max_preview_bytes: usize = 256 * 1024 * 1024,
    /// Sum of owned account-key bytes plus fixed token bytes queried by the
    /// private candidate indexes. Overflow or excess rejects before publication.
    max_candidate_lookup_work: usize = 64 * 1024 * 1024,
};
pub const LifecycleBatchSpec = struct {
    io: std.Io,
    operations: []const LifecycleRequest,
    drop_permits: []const LifecycleDropPermit = &.{},
    /// Named, no-mutation observation is the only accepted empty batch.
    observation_only: ?LifecycleObservation = null,
    limits: LifecycleLimits = .{},
};

/// Complete immutable row image. Account text is ticket-owned, snapshot bytes
/// are immutable under the retained lock, and journals are inline values.
pub const LifecycleRow = struct {
    account: []const u8,
    client: ClientId,
    token: Token,
    attachment_id: ?AttachmentId,
    signon_ms: i64,
    attached: bool,
    snapshot: ?[]const u8,
    portable_resume: bool,
    replica_dirty: bool,
    replica_projection_dirty: bool,
    attachment_replica_dirty: bool,
    attachment_replica_projection_dirty: bool,
    drop_reservation: DropReservationId,
    group_journal: LocalChannelProjectionSet,
    attachment_journal: LocalChannelProjectionSet,
};
pub const LifecycleAdmissionResult = struct {
    request_id: u64,
    account: []const u8,
    client: ClientId,
    result: union(enum) {
        tracked: struct { token: Token, attachment_id: ?AttachmentId },
        untracked: enum { explicit, accounts_capacity, sessions_capacity },
    },
};
pub const LifecyclePhysicalReason = enum { admission, detach, removal, reconnect_source, reconnect_target, rebind, group_propagation };
pub const LifecyclePhysicalFacts = struct {
    account: []const u8,
    client: ClientId,
    token: Token,
    attachment_id: ?AttachmentId,
    signon_ms: i64,
    attached: bool,
    portable_resume: bool,
    has_snapshot: bool,
    replica_dirty: bool,
    replica_projection_dirty: bool,
    attachment_replica_dirty: bool,
    attachment_replica_projection_dirty: bool,
    drop_reservation: DropReservationId,
    group_journal: LocalChannelProjectionSet,
    attachment_journal: LocalChannelProjectionSet,
};
pub const LifecycleAffectedPhysical = struct {
    client: ClientId,
    before: ?LifecyclePhysicalFacts,
    after: ?LifecyclePhysicalFacts,
    historical_only: bool = false,
    reason: LifecyclePhysicalReason,
};
pub const LifecycleRetiredAttachment = struct { row: LifecycleRow, reason: LifecycleRemoval, attachment_work_retired: bool };
pub const LifecycleRemap = struct { token: Token, attachment_id: AttachmentId, old_client: ClientId, new_client: ClientId };
pub const LifecycleTokenDelta = struct {
    token: Token,
    account: []const u8,
    old_rows: usize,
    final_rows: usize,
    old_attached: usize,
    final_attached: usize,
    old_portable: usize,
    final_portable: usize,
    old_journal: LocalChannelProjectionSet,
    final_journal: LocalChannelProjectionSet,
};
pub const LifecycleCounts = struct {
    replica: usize = 0,
    projection: usize = 0,
    attachment_replica: usize = 0,
    attachment_projection: usize = 0,
    group_journal: usize = 0,
    attachment_journal: usize = 0,
};
pub const LifecycleComplexity = struct {
    discovery_row_visits: usize = 0,
    /// Rows cloned into affected lists; the additional fields count subsequent
    /// actual traversals so this metric cannot hide a per-token census.
    candidate_row_visits: usize = 0,
    operation_row_visits: usize = 0,
    group_source_row_visits: usize = 0,
    closure_row_visits: usize = 0,
    proof_row_reads: usize = 0,
    final_mapping_row_visits: usize = 0,
    quota_rows_checked: usize = 0,
    normalization_row_visits: usize = 0,
    index_row_visits: usize = 0,
    preview_row_visits: usize = 0,
    copied_payload_bytes: usize = 0,
    candidate_key_lookups: usize = 0,
    candidate_group_lookups: usize = 0,
    candidate_key_lookup_work: usize = 0,
    candidate_group_lookup_work: usize = 0,
};
pub const LifecyclePreview = struct {
    before: []const LifecycleRow = &.{},
    after: []const LifecycleRow = &.{},
    affected_physical: []const LifecycleAffectedPhysical = &.{},
    admissions: []const LifecycleAdmissionResult = &.{},
    retired_attachments: []const LifecycleRetiredAttachment = &.{},
    remaps: []const LifecycleRemap = &.{},
    token_groups: []const LifecycleTokenDelta = &.{},
    final_accounts: usize = 0,
    final_rows: usize = 0,
    counts: LifecycleCounts = .{},
    projection_generation: u64 = 0,
    complexity: LifecycleComplexity = .{},
};

/// Linear lock-owning ticket. Until finish/abort ONLY preview may be read; do
/// not reenter SessionStore, copy ownership, dispatch asynchronously, or cross
/// a hot safe point. Validate before the outer durable cut. Commit is trusted
/// and void; all allocations and quota/proof decisions precede validation.
pub const PreparedLifecycleBatch = struct {
    owned: ?*LifecycleOwned,

    pub fn preview(self: *const PreparedLifecycleBatch) *const LifecyclePreview {
        const o = self.owned orelse unreachable;
        std.debug.assert(o.state == .prepared or o.state == .validated or o.state == .committed);
        return &o.preview_value;
    }
    pub fn validateForCut(self: *PreparedLifecycleBatch) LifecycleError!void {
        const o = self.owned orelse return error.InvalidTicket;
        if ((o.state != .prepared and o.state != .validated) or
            o.store.active_lifecycle != o or o.store.next_lifecycle_serial != o.serial or
            (o.handle != null and o.handle.? != self)) return error.InvalidTicket;
        if (!std.mem.eql(u8, &o.seal, &o.candidateDigest()) or
            !std.mem.eql(u8, &o.predecessor, &o.oldDigest())) return error.InvalidTicket;
        o.handle = self;
        o.state = .validated;
    }
    pub fn commit(self: *PreparedLifecycleBatch) void {
        const o = self.owned orelse unreachable;
        std.debug.assert(o.state == .validated and o.handle == self and o.store.active_lifecycle == o);
        o.publish();
        o.state = .committed;
    }
    pub fn finish(self: *PreparedLifecycleBatch) void {
        const o = self.owned orelse unreachable;
        std.debug.assert(o.state == .committed and o.handle == self and o.store.active_lifecycle == o);
        o.store.active_lifecycle = null;
        o.state = .finished;
        o.store.lock.unlockExclusive();
    }
    pub fn abort(self: *PreparedLifecycleBatch) void {
        const o = self.owned orelse return;
        if (o.state == .aborted or o.state == .finished) return;
        std.debug.assert((o.state == .prepared or o.state == .validated) and o.store.active_lifecycle == o);
        std.debug.assert(o.handle == null or o.handle == self);
        o.store.active_lifecycle = null;
        o.state = .aborted;
        o.store.lock.unlockExclusive();
    }
    pub fn deinit(self: *PreparedLifecycleBatch) void {
        const o = self.owned orelse return;
        if (o.state == .prepared or o.state == .validated) self.abort();
        if (o.state == .committed) self.finish();
        self.owned = null;
        o.destroy();
    }
};

/// Authority used to bind one already-tracked attachment to a reusable token.
/// `join_existing` requires that the exact account already contains a row with
/// the target token. `adopt_verified` is reserved for callers that established
/// the token outside this store (for example, a verified mesh credential); its
/// payload is the portable-resume state to install on the claimant row.
pub const TokenBindKind = union(enum) {
    join_existing,
    adopt_verified: bool,
};

/// Pointer-free account-row image captured by `PreparedTokenBind` while its
/// retained exclusive lock freezes every ASCII-fold-equivalent account key.
/// Restore planners may safely inspect this slice without borrowing Session or
/// snapshot storage that another attachment could replace or free.
pub const TokenBindRowSnapshot = struct {
    client: ClientId,
    token: Token,
    attachment_id: ?AttachmentId,
    attached: bool,
    portable_resume: bool,
};

pub const BootstrapDetachedSource = struct {
    client: ClientId,
    snapshot: []const u8,
};

/// Prepared insertion of a new runtime claimant directly into a preselected
/// reusable-token group. Unlike `attachReportingEviction`, preparation never
/// removes a detached row: all map/list/index capacity and per-row journal
/// storage is reserved first, then the retained exclusive lock freezes the
/// selected local source until the caller's restore staging is complete.
pub const PreparedBootstrapTokenAttach = struct {
    const State = enum { prepared, committed, aborted, finished };

    store: *SessionStore,
    account: []const u8,
    list: *SessionList,
    client: ClientId,
    token: Token,
    signon_ms: i64,
    kind: TokenBindKind,
    target_portable: bool,
    target_dirty: bool,
    target_projection_dirty: bool,
    target_local_projections: LocalChannelProjectionSet,
    locked_account_rows: []TokenBindRowSnapshot,
    projection_storage: ?*LocalChannelProjectionSet = null,
    staged_target_token_entry: ?TokenIndexEntry = null,
    staged_account_key: ?[]u8 = null,
    staged_account_list: ?*SessionList = null,
    evict_index: ?usize,
    detached_source_list: ?*SessionList,
    detached_source_index: ?usize,
    state: State = .prepared,

    pub fn accountRows(self: *const PreparedBootstrapTokenAttach) []const TokenBindRowSnapshot {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        return self.locked_account_rows;
    }

    pub fn resultPortable(self: *const PreparedBootstrapTokenAttach) bool {
        return switch (self.kind) {
            .join_existing => self.target_portable,
            .adopt_verified => |portable| portable or self.target_portable,
        };
    }

    pub fn mergedLocalChannelProjectionsInto(
        self: *const PreparedBootstrapTokenAttach,
        out: []LocalChannelProjection,
    ) []const LocalChannelProjection {
        const source = self.target_local_projections.slice();
        std.debug.assert(out.len >= source.len);
        if (out.len < source.len) return out[0..0];
        @memcpy(out[0..source.len], source);
        return out[0..source.len];
    }

    /// Borrow the newest exact-token detached image while the ticket retains
    /// the store lock. This source is never consumed before `commit`.
    pub fn detachedSource(self: *const PreparedBootstrapTokenAttach) ?BootstrapDetachedSource {
        if (self.state != .prepared) return null;
        const index = self.detached_source_index orelse return null;
        const row = self.detached_source_list.?.items.items[index];
        return .{ .client = row.client, .snapshot = row.snapshot orelse return null };
    }

    /// Publish the already-reserved row insertion and optional cap eviction.
    /// No allocation or failure remains after preparation.
    pub fn commit(self: *PreparedBootstrapTokenAttach) AttachOutcome {
        std.debug.assert(self.state == .prepared);
        const account_list = if (self.staged_account_list) |staged| blk: {
            const key = self.staged_account_key.?;
            self.store.accounts.putAssumeCapacity(key, staged.*);
            self.store.allocator.destroy(staged);
            self.staged_account_list = null;
            self.staged_account_key = null;
            self.list = self.store.accounts.getPtr(key).?;
            self.account = self.store.accounts.getEntry(key).?.key_ptr.*;
            break :blk self.list;
        } else self.list;

        var evicted: ?EvictedSession = null;
        if (self.evict_index) |index| {
            const displaced = account_list.items.items[index];
            evicted = .{
                .client = displaced.client,
                .token = displaced.token,
                .attachment_id = displaced.attachment_id,
                .portable = displaced.portable_resume,
            };
            self.store.removeDirtyRowLocked(&account_list.items.items[index]);
            self.store.removeTokenRowLocked(
                self.account,
                displaced,
                std.crypto.timing_safe.eql(Token, displaced.token, self.token),
            );
            self.store.removeAttachmentIndexLocked(displaced);
            freeSessionOwned(self.store.allocator, &account_list.items.items[index]);
            _ = account_list.items.swapRemove(index);
        }

        const session = Session{
            .client = self.client,
            .token = self.token,
            .signon_ms = self.signon_ms,
            .portable_resume = self.resultPortable(),
            .replica_dirty = self.target_dirty,
            .replica_projection_dirty = self.target_projection_dirty,
            .local_channel_projections = self.projection_storage,
        };
        self.projection_storage = null;
        account_list.items.appendAssumeCapacity(session);
        if (session.replica_dirty) self.store.dirty_replica_rows += 1;
        if (session.replica_projection_dirty) self.store.dirty_projection_rows += 1;
        if (session.local_channel_projections != null) self.store.dirty_local_projection_rows += 1;
        self.store.addTokenRowLocked(self.account, session, &self.staged_target_token_entry);
        self.state = .committed;
        return .{ .session = session, .evicted = evicted };
    }

    pub fn finish(self: *PreparedBootstrapTokenAttach) void {
        if (self.state == .finished) return;
        std.debug.assert(self.state == .committed);
        if (self.state != .committed) return;
        self.destroyLockedRows();
        self.state = .finished;
        self.store.lock.unlockExclusive();
    }

    pub fn abort(self: *PreparedBootstrapTokenAttach) void {
        if (self.state == .aborted or self.state == .finished) return;
        std.debug.assert(self.state == .prepared);
        if (self.state != .prepared) return;
        self.destroyStaged();
        self.destroyLockedRows();
        self.state = .aborted;
        self.store.lock.unlockExclusive();
    }

    pub fn deinit(self: *PreparedBootstrapTokenAttach) void {
        switch (self.state) {
            .prepared => self.abort(),
            .committed => {
                self.destroyStaged();
                self.destroyLockedRows();
                self.state = .finished;
                self.store.lock.unlockExclusive();
                std.debug.assert(false);
            },
            .aborted, .finished => {},
        }
    }

    fn destroyStaged(self: *PreparedBootstrapTokenAttach) void {
        if (self.projection_storage) |storage| self.store.allocator.destroy(storage);
        self.projection_storage = null;
        if (self.staged_target_token_entry) |*entry| entry.deinit(self.store.allocator);
        self.staged_target_token_entry = null;
        if (self.staged_account_list) |list| {
            list.deinit(self.store.allocator);
            self.store.allocator.destroy(list);
        }
        self.staged_account_list = null;
        if (self.staged_account_key) |key| self.store.allocator.free(key);
        self.staged_account_key = null;
    }

    fn destroyLockedRows(self: *PreparedBootstrapTokenAttach) void {
        if (self.locked_account_rows.len != 0) self.store.allocator.free(self.locked_account_rows);
        self.locked_account_rows = &.{};
    }
};

/// A token bind prepared while holding the store's exclusive lock. Preparation
/// captures every value needed by the commit, so `commit` performs no allocation
/// and cannot expose a half-applied token-group merge. The lock remains held after
/// commit so a caller can finish its World/connection commit before calling
/// `finish`; an uncommitted plan must use `abort`.
///
/// This type is logically non-copyable and single-use: keep one mutable instance
/// and call lifecycle methods through its pointer. Install `defer plan.deinit()`
/// immediately after preparation; it aborts an uncommitted plan and asserts if a
/// committed plan escaped without the required explicit `finish`.
pub const PreparedTokenBind = struct {
    const State = enum { prepared, committed, aborted, finished };

    store: *SessionStore,
    /// Store-owned account key for the claimant. The exclusive lock keeps this
    /// slice alive through commit/abort, so defensive commit revalidation can
    /// enforce the same folded-account token boundary as preparation.
    account: []const u8,
    list: *SessionList,
    index: usize,
    client: ClientId,
    expected_token: Token,
    expected_portable: bool,
    expected_dirty: bool,
    expected_projection_dirty: bool,
    expected_local_projection_revision: u64,
    target_token: Token,
    kind: TokenBindKind,
    target_portable: bool,
    target_dirty: bool,
    target_projection_dirty: bool,
    target_local_projection_revision: u64,
    merged_local_projections: LocalChannelProjectionSet,
    /// Complete, deterministically ordered folded-account view captured under
    /// the retained exclusive lock. Freed immediately before that lock is
    /// released on every lifecycle exit.
    locked_account_rows: []TokenBindRowSnapshot,
    /// Missing per-row journals allocated during preparation. They remain
    /// detached from store state until commit and are destroyed on abort.
    staged_local_projection_sets: ?[]*LocalChannelProjectionSet = null,
    /// A rowless target token cannot publish an empty index entry during
    /// preparation. Its fully reserved entry stays ticket-owned until commit.
    staged_target_token_entry: ?TokenIndexEntry = null,
    result_portable: bool,
    state: State = .prepared,

    /// Return the complete folded-account row image frozen by this ticket. The
    /// slice remains valid through commit and until finish/abort releases the
    /// retained SessionStore lock.
    pub fn accountRows(self: *const PreparedTokenBind) []const TokenBindRowSnapshot {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        if (self.state != .prepared and self.state != .committed) return &.{};
        return self.locked_account_rows;
    }

    /// Portable authority that commit will install on the claimant's target
    /// group, derived under the same retained lock as `accountRows`.
    pub fn resultPortable(self: *const PreparedTokenBind) bool {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        return self.result_portable;
    }

    /// Preview the exact bounded local-channel image that commit will install on
    /// the target token. Callers use this while the ticket retains the exclusive
    /// lock so World/output restore plans cannot be built from a stale detached
    /// snapshot that the no-fail commit would immediately override.
    pub fn mergedLocalChannelProjectionsInto(
        self: *const PreparedTokenBind,
        out: []LocalChannelProjection,
    ) []const LocalChannelProjection {
        std.debug.assert(self.state == .prepared);
        const source = self.merged_local_projections.slice();
        std.debug.assert(out.len >= source.len);
        if (out.len < source.len) return out[0..0];
        @memcpy(out[0..source.len], source);
        return out[0..source.len];
    }

    /// Commit the prepared bind without allocating or releasing the exclusive
    /// lock. Defensive revalidation rejects a stale/corrupted ticket without
    /// applying the target token. Ordinary store users cannot make it stale
    /// because the ticket owns the exclusive lock, but keeping this check at the
    /// commit boundary prevents a future refactor from weakening that guarantee.
    pub fn commit(self: *PreparedTokenBind) bool {
        if (self.state != .prepared) return false;

        if (self.index >= self.list.items.items.len) return false;
        const claimant = &self.list.items.items[self.index];
        if (claimant.client != self.client or
            claimant.drop_reservation != 0 or
            !std.crypto.timing_safe.eql(Token, claimant.token, self.expected_token) or
            claimant.portable_resume != self.expected_portable or
            claimant.replica_dirty != self.expected_dirty or
            claimant.replica_projection_dirty != self.expected_projection_dirty or
            localProjectionSetRevision(claimant.local_channel_projections) != self.expected_local_projection_revision)
        {
            return false;
        }

        const current_target_account = self.store.tokenGroupStateForAccountLocked(
            self.account,
            self.target_token,
        ) orelse return false;
        if (self.kind == .join_existing and
            (!current_target_account.found or current_target_account.portable != self.target_portable))
        {
            return false;
        }
        const current_target = self.store.tokenGroupStateLocked(self.target_token);
        if (self.store.tokenGroupHasDropReservationLocked(self.target_token)) return false;
        if (current_target.dirty != self.target_dirty or
            current_target.projection_dirty != self.target_projection_dirty or
            current_target.local_projections.revision != self.target_local_projection_revision)
        {
            return false;
        }

        var staged_index: usize = 0;
        if (!self.merged_local_projections.isEmpty()) {
            if (self.store.tokenEntryLocked(self.target_token)) |target_entry| {
                for (target_entry.rows.items) |locator| {
                    const session = self.store.sessionForTokenLocatorLocked(locator) orelse unreachable;
                    if (session.local_channel_projections != null) continue;
                    session.local_channel_projections = self.staged_local_projection_sets.?[staged_index];
                    staged_index += 1;
                }
            }
            if (!std.crypto.timing_safe.eql(Token, claimant.token, self.target_token) and
                claimant.local_channel_projections == null)
            {
                claimant.local_channel_projections = self.staged_local_projection_sets.?[staged_index];
                staged_index += 1;
            }
        }
        if (self.staged_local_projection_sets) |staged| {
            std.debug.assert(staged_index == staged.len);
            self.store.allocator.free(staged);
            self.staged_local_projection_sets = null;
        }

        const previous_claimant = claimant.*;
        const keep_empty_target = !tokenIsSentinel(previous_claimant.token) and
            std.crypto.timing_safe.eql(Token, previous_claimant.token, self.target_token);
        self.store.removeTokenRowLocked(self.account, previous_claimant, keep_empty_target);
        claimant.token = self.target_token;
        claimant.portable_resume = self.result_portable;
        self.store.addTokenRowLocked(
            self.account,
            claimant.*,
            &self.staged_target_token_entry,
        );
        if (self.result_portable) {
            self.store.setTokenGroupPortableLocked(self.target_token, true);
            if (!self.target_portable) {
                _ = self.store.markTokenAttachmentReplicasDirtyLocked(self.target_token);
            } else if (claimant.attachment_id != null) {
                self.store.setAttachmentReplicaDirtyLocked(claimant, true);
            }
        }
        self.store.setTokenGroupDirtyLocked(
            self.target_token,
            self.expected_dirty or self.target_dirty,
        );
        self.store.setTokenGroupProjectionDirtyLocked(
            self.target_token,
            self.expected_projection_dirty or self.target_projection_dirty,
        );
        // A token bind merges both bounded channel sets. Distinct channels are
        // retained; a case-insensitive collision keeps the newer generation.
        // Preparation already proved the union fits, so commit cannot fail.
        if (!self.merged_local_projections.isEmpty())
            self.merged_local_projections.revision = self.store.nextLocalProjectionGenerationLocked();
        self.store.setTokenGroupLocalProjectionsLocked(
            self.target_token,
            &self.merged_local_projections,
        );
        self.state = .committed;
        return true;
    }

    /// Release the exclusive lock after the caller has completed every other
    /// no-fail authority mutation. Calling this before commit is a lifecycle bug.
    pub fn finish(self: *PreparedTokenBind) void {
        if (self.state == .finished) return;
        std.debug.assert(self.state == .committed);
        if (self.state != .committed) return;
        self.destroyLockedAccountRows();
        self.state = .finished;
        self.store.lock.unlockExclusive();
    }

    /// Discard an uncommitted plan and release the exclusive lock. Calling this
    /// after commit is a lifecycle bug; committed plans require `finish`.
    pub fn abort(self: *PreparedTokenBind) void {
        if (self.state == .aborted or self.state == .finished) return;
        std.debug.assert(self.state == .prepared);
        if (self.state != .prepared) return;
        self.destroyStagedLocalProjectionSets();
        self.destroyStagedTargetTokenEntry();
        self.destroyLockedAccountRows();
        self.state = .aborted;
        self.store.lock.unlockExclusive();
    }

    /// Lifecycle guard for deferred cleanup. An uncommitted plan is safely
    /// aborted. A committed-but-unfinished plan is unlocked to avoid poisoning
    /// the store, then asserted so tests/debug builds catch the missing finish.
    pub fn deinit(self: *PreparedTokenBind) void {
        switch (self.state) {
            .prepared => self.abort(),
            .committed => {
                self.destroyStagedTargetTokenEntry();
                self.destroyLockedAccountRows();
                self.state = .finished;
                self.store.lock.unlockExclusive();
                std.debug.assert(false);
            },
            .aborted, .finished => {},
        }
    }

    fn destroyStagedLocalProjectionSets(self: *PreparedTokenBind) void {
        const staged = self.staged_local_projection_sets orelse return;
        for (staged) |set| self.store.allocator.destroy(set);
        self.store.allocator.free(staged);
        self.staged_local_projection_sets = null;
    }

    fn destroyStagedTargetTokenEntry(self: *PreparedTokenBind) void {
        if (self.staged_target_token_entry) |*entry| entry.deinit(self.store.allocator);
        self.staged_target_token_entry = null;
    }

    fn destroyLockedAccountRows(self: *PreparedTokenBind) void {
        if (self.locked_account_rows.len == 0) return;
        self.store.allocator.free(self.locked_account_rows);
        self.locked_account_rows = &.{};
    }
};

pub const AttachmentClientRemap = struct {
    old_client: ClientId,
    new_client: ClientId,
};

/// Prepared replacement of one exact detached physical attachment by a new
/// runtime connection. Preparation retains the exclusive store lock and borrows
/// the ghost snapshot; commit is allocation-free and cannot partially consume
/// identity. This is intentionally separate from create-new/token-group join.
pub const PreparedAttachmentRebind = struct {
    const State = enum { prepared, committed, aborted, finished };

    store: *SessionStore,
    /// A compatibility bootstrap may already exist, but exact resume also
    /// supports a genuinely untracked claimant so a full account never needs
    /// to evict the detached authority it is about to reclaim.
    claimant_list: ?*SessionList,
    claimant_account: ?[]const u8,
    ghost_list: *SessionList,
    /// Store-owned source account key, stable while the retained lock is held.
    ghost_account: []const u8,
    claimant_index: ?usize,
    ghost_index: usize,
    claimant_client: ClientId,
    ghost_client: ClientId,
    token: Token,
    attachment_id: AttachmentId,
    /// Complete folded-account view captured while the retained lock excludes
    /// concurrent sibling changes. This gives the generic restore planner the
    /// same stable input shape as token-bind tickets.
    locked_account_rows: []TokenBindRowSnapshot,
    target_local_projections: LocalChannelProjectionSet,
    result_portable: bool,
    state: State = .prepared,

    pub fn accountRows(self: *const PreparedAttachmentRebind) []const TokenBindRowSnapshot {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        if (self.state != .prepared and self.state != .committed) return &.{};
        return self.locked_account_rows;
    }

    pub fn resultPortable(self: *const PreparedAttachmentRebind) bool {
        std.debug.assert(self.state == .prepared or self.state == .committed);
        return self.result_portable;
    }

    /// Preview the exact target attachment's pending local-channel journal.
    /// The detached snapshot may be older than these accepted intents, so the
    /// generic restore planner must overlay this same image before commit.
    pub fn mergedLocalChannelProjectionsInto(
        self: *const PreparedAttachmentRebind,
        out: []LocalChannelProjection,
    ) []const LocalChannelProjection {
        std.debug.assert(self.state == .prepared);
        const source = self.target_local_projections.slice();
        std.debug.assert(out.len >= source.len);
        if (out.len < source.len) return out[0..0];
        @memcpy(out[0..source.len], source);
        return out[0..source.len];
    }

    /// Borrowed exact restore bytes. The retained store lock keeps them stable
    /// until commit/abort; commit consumes/frees the stored snapshot.
    pub fn snapshot(self: *const PreparedAttachmentRebind) ?[]const u8 {
        std.debug.assert(self.state == .prepared);
        if (self.state != .prepared) return null;
        return self.ghost_list.items.items[self.ghost_index].snapshot;
    }

    pub fn remap(self: *const PreparedAttachmentRebind) AttachmentClientRemap {
        return .{ .old_client = self.ghost_client, .new_client = self.claimant_client };
    }

    /// Replace an optional clean bootstrap row, or remap the detached row in
    /// place for an untracked claimant. Both paths retain token, stable id,
    /// signon, portability and retry journals. The stored snapshot is retired
    /// only at this no-fail commit boundary.
    pub fn commit(self: *PreparedAttachmentRebind) bool {
        if (self.state != .prepared) return false;
        if (self.ghost_index >= self.ghost_list.items.items.len) return false;
        const ghost = &self.ghost_list.items.items[self.ghost_index];
        if (ghost.drop_reservation != 0 or ghost.client != self.ghost_client or ghost.attached or
            !sessionMatchesAttachment(ghost.*, self.token, self.attachment_id))
        {
            return false;
        }

        const claimant_list = self.claimant_list orelse {
            // No row is inserted: exact physical authority is simply rebound to
            // the new runtime handle in place, so account-cap and allocation
            // pressure cannot destroy a sibling or strand the target.
            freeSnapshot(self.store.allocator, ghost);
            ghost.client = self.claimant_client;
            ghost.attached = true;
            const ghost_locator = self.store.attachment_index.getPtr(self.attachment_id.raw) orelse unreachable;
            ghost_locator.* = .{ .account = self.ghost_account, .client = self.claimant_client };
            self.store.remapTokenRowLocatorLocked(
                self.token,
                self.ghost_account,
                self.ghost_client,
                self.ghost_account,
                self.claimant_client,
            );
            self.state = .committed;
            return true;
        };
        const claimant_index = self.claimant_index orelse return false;
        const claimant_account = self.claimant_account orelse return false;
        if (claimant_index >= claimant_list.items.items.len or
            (claimant_list == self.ghost_list and claimant_index == self.ghost_index)) return false;
        const claimant = &claimant_list.items.items[claimant_index];
        if (claimant.client != self.claimant_client or claimant.drop_reservation != 0) return false;
        const claimant_attachment_id = claimant.attachment_id orelse return false;

        // Remove both rows from exact scheduler counts before ownership moves.
        // The replacement contributes the ghost's flags once, below.
        self.store.removeDirtyRowLocked(claimant);
        self.store.removeDirtyRowLocked(ghost);
        self.store.removeTokenRowLocked(claimant_account, claimant.*, false);

        var replacement = ghost.*;
        replacement.client = self.claimant_client;
        replacement.attached = true;
        replacement.snapshot = null;

        // Discard the claimant bootstrap state. The target ghost's journal is
        // moved, never copied, so no allocation or failure remains.
        freeSessionOwned(self.store.allocator, claimant);
        freeSnapshot(self.store.allocator, ghost);
        ghost.local_channel_projections = null;
        ghost.attachment_channel_projections = null;

        const removed_claimant_index = self.store.attachment_index.remove(claimant_attachment_id.raw);
        std.debug.assert(removed_claimant_index);
        const ghost_locator = self.store.attachment_index.getPtr(self.attachment_id.raw) orelse unreachable;
        ghost_locator.* = .{ .account = claimant_account, .client = self.claimant_client };
        self.store.remapTokenRowLocatorLocked(
            self.token,
            self.ghost_account,
            self.ghost_client,
            claimant_account,
            self.claimant_client,
        );

        claimant_list.items.items[claimant_index] = replacement;
        _ = self.ghost_list.items.swapRemove(self.ghost_index);
        self.store.addDirtyRowLocked(&replacement);
        if (self.ghost_list.items.items.len == 0) {
            const entry = self.store.accounts.getEntry(self.ghost_account) orelse unreachable;
            self.store.dropAccount(entry);
        }
        self.state = .committed;
        return true;
    }

    pub fn finish(self: *PreparedAttachmentRebind) void {
        if (self.state == .finished) return;
        std.debug.assert(self.state == .committed);
        if (self.state != .committed) return;
        self.destroyLockedAccountRows();
        self.state = .finished;
        self.store.lock.unlockExclusive();
    }

    pub fn abort(self: *PreparedAttachmentRebind) void {
        if (self.state == .aborted or self.state == .finished) return;
        std.debug.assert(self.state == .prepared);
        if (self.state != .prepared) return;
        self.destroyLockedAccountRows();
        self.state = .aborted;
        self.store.lock.unlockExclusive();
    }

    pub fn deinit(self: *PreparedAttachmentRebind) void {
        switch (self.state) {
            .prepared => self.abort(),
            .committed => {
                self.destroyLockedAccountRows();
                self.state = .finished;
                self.store.lock.unlockExclusive();
                std.debug.assert(false);
            },
            .aborted, .finished => {},
        }
    }

    fn destroyLockedAccountRows(self: *PreparedAttachmentRebind) void {
        if (self.locked_account_rows.len != 0) self.store.allocator.free(self.locked_account_rows);
        self.locked_account_rows = &.{};
    }
};

const LifecycleAccount = struct {
    key: []const u8,
    display: []u8,
    key_owned: bool,
    old: ?SessionList,
    final: SessionList = .{},
    published: bool = false,
    retired_key: bool = false,
    remove_when_empty: bool = false,
};
const LifecycleOldBinding = struct { account: []const u8, index: usize, duplicates: bool = false };
const LifecycleGroup = struct {
    token: Token,
    portable: bool = false,
    was_portable: bool = false,
    dirty: bool = false,
    projection: bool = false,
    journal: LocalChannelProjectionSet = .{},
    changed: bool = false,
    closure_included: bool = false,
    old_owner: ?[]const u8 = null,
    old_dirty: bool = false,
    old_projection: bool = false,
    old_journal: LocalChannelProjectionSet = .{},
    reserved_client: ?ClientId = null,
    reserved_count: usize = 0,
};
const LifecycleIndex = struct { token: Token, entry: TokenIndexEntry = .{} };
const LifecycleFoldIndex = std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8));

fn lifecycleFold(a: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    const copy = try a.dupe(u8, text);
    for (copy) |*c| c.* = std.ascii.toLower(c.*);
    return copy;
}

fn lifecycleRow(account: []const u8, s: Session) LifecycleRow {
    return .{
        .account = account,
        .client = s.client,
        .token = s.token,
        .attachment_id = s.attachment_id,
        .signon_ms = s.signon_ms,
        .attached = s.attached,
        .snapshot = s.snapshot,
        .portable_resume = s.portable_resume,
        .replica_dirty = s.replica_dirty,
        .replica_projection_dirty = s.replica_projection_dirty,
        .attachment_replica_dirty = s.attachment_replica_dirty,
        .attachment_replica_projection_dirty = s.attachment_replica_projection_dirty,
        .drop_reservation = s.drop_reservation,
        .group_journal = if (s.local_channel_projections) |p| p.* else .{},
        .attachment_journal = if (s.attachment_channel_projections) |p| p.* else .{},
    };
}

fn lifecycleFacts(row: LifecycleRow) LifecyclePhysicalFacts {
    return .{ .account = row.account, .client = row.client, .token = row.token, .attachment_id = row.attachment_id, .signon_ms = row.signon_ms, .attached = row.attached, .portable_resume = row.portable_resume, .has_snapshot = row.snapshot != null, .replica_dirty = row.replica_dirty, .replica_projection_dirty = row.replica_projection_dirty, .attachment_replica_dirty = row.attachment_replica_dirty, .attachment_replica_projection_dirty = row.attachment_replica_projection_dirty, .drop_reservation = row.drop_reservation, .group_journal = row.group_journal, .attachment_journal = row.attachment_journal };
}

/// Equal generation is an authenticated state conflict, not a tie broken by
/// request/list order. Validate the bounded journal before taking any slice.
fn lifecycleMerge(out: *LocalChannelProjectionSet, add: LocalChannelProjectionSet) LifecycleError!void {
    if (add.len > local_channel_projection_capacity) return error.ProjectionConflict;
    for (add.items[0..add.len], 0..) |p, i| {
        if (p.channel_len == 0 or p.channel_len > local_channel_name_capacity or p.generation == 0)
            return error.ProjectionConflict;
        if (i != 0 and localChannelOrder(add.items[i - 1].channel(), p.channel()) != .lt)
            return error.ProjectionConflict;
        if (localProjectionIndex(out, p.channel())) |index| {
            const old = out.items[index];
            if (p.generation == old.generation and
                (p.present != old.present or p.member_mode_bits != old.member_mode_bits))
                return error.ProjectionConflict;
            if (p.generation > old.generation or (p.generation == old.generation and
                std.mem.order(u8, p.channel(), old.channel()) == .lt)) out.items[index] = p;
        } else try localProjectionUpsert(out, p);
    }
    out.revision = @max(out.revision, add.revision);
}

/// Fully owned payloads ONLY for the affected exact lists. OLD lists remain
/// borrowed while prepared and move into this retirement ledger on commit.
/// This bounded alternative deliberately copies affected snapshots/journals;
/// copied_payload_bytes and candidate_row_visits expose that cost to callers.
const LifecycleOwned = struct {
    store: *SessionStore,
    allocation: std.mem.Allocator,
    serial: u64,
    limits: LifecycleLimits,
    handle: ?*PreparedLifecycleBatch = null,
    state: enum { prepared, validated, committed, finished, aborted } = .prepared,
    accounts: std.ArrayListUnmanaged(LifecycleAccount) = .empty,
    groups: std.ArrayListUnmanaged(LifecycleGroup) = .empty,
    indexes: std.ArrayListUnmanaged(LifecycleIndex) = .empty,
    before: std.ArrayListUnmanaged(LifecycleRow) = .empty,
    after: std.ArrayListUnmanaged(LifecycleRow) = .empty,
    admissions: std.ArrayListUnmanaged(LifecycleAdmissionResult) = .empty,
    retired: std.ArrayListUnmanaged(LifecycleRetiredAttachment) = .empty,
    remaps: std.ArrayListUnmanaged(LifecycleRemap) = .empty,
    physical: std.ArrayListUnmanaged(LifecycleAffectedPhysical) = .empty,
    deltas: std.ArrayListUnmanaged(LifecycleTokenDelta) = .empty,
    reasons: std.AutoHashMapUnmanaged(ClientId, LifecyclePhysicalReason) = .empty,
    removed_reasons: std.AutoHashMapUnmanaged(ClientId, LifecycleRemoval) = .empty,
    final_lookup: std.AutoHashMapUnmanaged(ClientId, struct { account: usize, row: usize }) = .empty,
    final_lookup_ready: bool = false,
    preview_value: LifecyclePreview = .{},
    predecessor: [32]u8 = @splat(0),
    seal: [32]u8 = @splat(0),
    total_old_rows: usize = 0,
    payload_bytes: usize = 0,
    preview_bytes: usize = 0,
    observation_client: ?ClientId = null,
    old_bindings: std.AutoHashMapUnmanaged(ClientId, LifecycleOldBinding) = .empty,
    account_lookup: std.StringHashMapUnmanaged(usize) = .empty,
    group_lookup: std.AutoHashMapUnmanaged(Token, usize) = .empty,
    lookup_budget_exhausted: bool = false,

    fn allocator(self: *LifecycleOwned) std.mem.Allocator {
        return self.allocation;
    }

    fn charge(self: *LifecycleOwned, bytes: usize) LifecycleError!void {
        self.payload_bytes = std.math.add(usize, self.payload_bytes, bytes) catch return error.CandidateLimitExceeded;
        if (self.payload_bytes > self.limits.max_payload_bytes) return error.CandidateLimitExceeded;
        self.preview_value.complexity.copied_payload_bytes = self.payload_bytes;
    }

    fn chargePreview(self: *LifecycleOwned, bytes: usize) LifecycleError!void {
        self.preview_bytes = std.math.add(usize, self.preview_bytes, bytes) catch return error.CandidateLimitExceeded;
        if (self.preview_bytes > self.limits.max_preview_bytes) return error.CandidateLimitExceeded;
    }
    fn appendView(self: *LifecycleOwned, comptime T: type, list: *std.ArrayListUnmanaged(T), value: T) LifecycleError!void {
        try self.chargePreview(@sizeOf(T));
        try list.append(self.allocator(), value);
    }

    fn copySession(self: *LifecycleOwned, old: Session) LifecycleError!Session {
        if (old.local_channel_projections) |journal| {
            var checked: LocalChannelProjectionSet = .{};
            try lifecycleMerge(&checked, journal.*);
        }
        if (old.attachment_channel_projections) |journal| {
            var checked: LocalChannelProjectionSet = .{};
            try lifecycleMerge(&checked, journal.*);
        }
        var s = old;
        s.snapshot = null;
        s.local_channel_projections = null;
        s.attachment_channel_projections = null;
        errdefer freeSessionOwned(self.allocator(), &s);
        if (old.snapshot) |bytes| {
            try self.charge(bytes.len);
            s.snapshot = try self.allocator().dupe(u8, bytes);
        }
        if (old.local_channel_projections) |p| {
            try self.charge(@sizeOf(LocalChannelProjectionSet));
            s.local_channel_projections = try self.allocator().create(LocalChannelProjectionSet);
            s.local_channel_projections.?.* = p.*;
        }
        if (old.attachment_channel_projections) |p| {
            try self.charge(@sizeOf(LocalChannelProjectionSet));
            s.attachment_channel_projections = try self.allocator().create(LocalChannelProjectionSet);
            s.attachment_channel_projections.?.* = p.*;
        }
        return s;
    }

    fn chargeLookup(self: *LifecycleOwned, key: bool, bytes: usize) void {
        const metric = &self.preview_value.complexity;
        const work = if (key) &metric.candidate_key_lookup_work else &metric.candidate_group_lookup_work;
        const count = if (key) &metric.candidate_key_lookups else &metric.candidate_group_lookups;
        work.* = std.math.add(usize, work.*, bytes) catch {
            self.lookup_budget_exhausted = true;
            return;
        };
        count.* = std.math.add(usize, count.*, 1) catch {
            self.lookup_budget_exhausted = true;
            return;
        };
        const total = std.math.add(usize, metric.candidate_key_lookup_work, metric.candidate_group_lookup_work) catch {
            self.lookup_budget_exhausted = true;
            return;
        };
        if (total > self.limits.max_candidate_lookup_work) self.lookup_budget_exhausted = true;
    }

    fn checkLookupBudget(self: *const LifecycleOwned) LifecycleError!void {
        if (self.lookup_budget_exhausted) return error.CandidateLimitExceeded;
    }

    fn accountIndex(self: *LifecycleOwned, key: []const u8) ?usize {
        const bytes = std.math.add(usize, key.len, 1) catch {
            self.lookup_budget_exhausted = true;
            return null;
        };
        self.chargeLookup(true, bytes);
        return self.account_lookup.get(key);
    }

    fn addAccount(self: *LifecycleOwned, key: []const u8) LifecycleError!usize {
        const existing = self.accountIndex(key);
        try self.checkLookupBudget();
        if (existing) |i| return i;
        try self.account_lookup.ensureUnusedCapacity(self.allocator(), 1);
        const old = self.store.accounts.getEntry(key);
        try self.chargePreview(std.math.add(usize, key.len, @sizeOf(LifecycleAccount)) catch return error.CandidateLimitExceeded);
        if (old == null) try self.chargePreview(key.len);
        const display = try self.allocator().dupe(u8, key);
        errdefer self.allocator().free(display);
        const candidate_key = if (old) |entry| entry.key_ptr.* else try self.allocator().dupe(u8, key);
        errdefer if (old == null) self.allocator().free(candidate_key);
        try self.accounts.append(self.allocator(), .{
            .key = candidate_key,
            .display = display,
            .key_owned = old == null,
            .old = if (old) |entry| entry.value_ptr.* else null,
        });
        const index = self.accounts.items.len - 1;
        self.account_lookup.putAssumeCapacityNoClobber(candidate_key, index);
        return index;
    }

    fn group(self: *LifecycleOwned, token: Token) LifecycleError!*LifecycleGroup {
        std.debug.assert(!tokenIsSentinel(token));
        self.chargeLookup(false, @sizeOf(Token) + 1);
        try self.checkLookupBudget();
        if (self.group_lookup.get(token)) |index| return &self.groups.items[index];
        try self.group_lookup.ensureUnusedCapacity(self.allocator(), 1);
        try self.groups.append(self.allocator(), .{ .token = token });
        const index = self.groups.items.len - 1;
        self.group_lookup.putAssumeCapacityNoClobber(token, index);
        return &self.groups.items[index];
    }

    fn oldRow(self: *LifecycleOwned, loc: AttachmentLocator) LifecycleError!*const Session {
        self.preview_value.complexity.proof_row_reads += 1;
        const binding = self.old_bindings.get(loc.client) orelse return error.InvalidRequest;
        if (binding.duplicates) return error.AmbiguousPhysicalBinding;
        if (!std.mem.eql(u8, binding.account, loc.account)) return error.InvalidRequest;
        return &self.store.accounts.getPtr(binding.account).?.items.items[binding.index];
    }

    fn includeGroup(self: *LifecycleOwned, token: Token) LifecycleError!void {
        if (tokenIsSentinel(token)) return;
        const g = try self.group(token);
        if (g.closure_included) return;
        g.closure_included = true;
        if (self.store.token_index.get(token)) |entry| {
            if (entry.rows.items.len == 0) return error.InvalidRequest;
            g.old_owner = entry.rows.items[0].account;
            var portable: usize = 0;
            var dirty: usize = 0;
            var projection: usize = 0;
            var seen: std.AutoHashMapUnmanaged(ClientId, void) = .empty;
            defer seen.deinit(self.allocator());
            for (entry.rows.items) |loc| {
                self.preview_value.complexity.group_source_row_visits += 1;
                if (!std.ascii.eqlIgnoreCase(g.old_owner.?, loc.account)) return error.TokenAccountMismatch;
                const unique = try seen.getOrPut(self.allocator(), loc.client);
                if (unique.found_existing) return error.AmbiguousPhysicalBinding;
                const row = try self.oldRow(loc);
                if (!std.mem.eql(u8, &row.token, &token)) return error.InvalidRequest;
                if (row.portable_resume) portable += 1;
                if (row.replica_dirty) dirty += 1;
                if (row.replica_projection_dirty) projection += 1;
                if (row.drop_reservation != 0) {
                    g.reserved_count += 1;
                    g.reserved_client = row.client;
                }
                g.portable = g.portable or row.portable_resume;
                g.dirty = g.dirty or row.replica_dirty;
                g.projection = g.projection or row.replica_projection_dirty;
                if (row.local_channel_projections) |journal| try lifecycleMerge(&g.journal, journal.*);
                if (row.attachment_channel_projections) |journal| {
                    var checked: LocalChannelProjectionSet = .{};
                    try lifecycleMerge(&checked, journal.*);
                }
                _ = try self.addAccount(loc.account);
            }
            // A completed journal retains its cache revision after row-owned
            // empty sets are freed. Preserve that legitimate empty CAS clock.
            if (g.journal.len == 0 and entry.local_projections.len == 0) g.journal = entry.local_projections;
            if (!std.meta.eql(g.journal, entry.local_projections)) return error.ProjectionConflict;
            if (portable != entry.portable_rows or dirty != entry.dirty_rows or
                projection != entry.projection_dirty_rows or g.reserved_count != entry.drop_reserved_rows)
                return error.InvalidRequest;
        }
        g.was_portable = g.portable;
        g.old_dirty = g.dirty;
        g.old_projection = g.projection;
        g.old_journal = g.journal;
    }

    fn source(self: *LifecycleOwned, clients: *const std.AutoHashMapUnmanaged(ClientId, LifecycleOldBinding), sel: LifecycleSelector) LifecycleError!Session {
        const loc = clients.get(sel.exact.client) orelse return error.MissingRow;
        if (loc.duplicates) return error.AmbiguousPhysicalBinding;
        if (!std.mem.eql(u8, loc.account, sel.account)) return error.StaleSelector;
        self.preview_value.complexity.proof_row_reads += 1;
        const s = self.store.accounts.get(loc.account).?.items.items[loc.index];
        if (!sessionMatchesExact(s, sel.exact) or s.attached != sel.attached) return error.StaleSelector;
        return s;
    }

    fn permit(spec: LifecycleBatchSpec, account: []const u8, s: Session) bool {
        for (spec.drop_permits) |p| {
            if (p.owner != 0 and p.owner == s.drop_reservation and std.mem.eql(u8, p.source.account, account) and
                p.source.attached == s.attached and sessionMatchesExact(s, p.source.exact)) return true;
        }
        return false;
    }

    fn checkReservation(self: *LifecycleOwned, spec: LifecycleBatchSpec, account: []const u8, row: Session) LifecycleError!void {
        if (row.drop_reservation != 0 and !permit(spec, account, row)) return error.SessionDropReserved;
        if (tokenIsSentinel(row.token)) return;
        try self.includeGroup(row.token);
        const g = try self.group(row.token);
        // OLD group custody is checked once, not rescanned for every sibling.
        if (g.reserved_count > 1 or (g.reserved_count == 1 and
            (g.reserved_client.? != row.client or !permit(spec, account, row)))) return error.SessionDropReserved;
    }

    fn target(self: *LifecycleOwned, account: []const u8, token: Token, kind: TokenBindKind) LifecycleError!void {
        if (tokenIsSentinel(token)) return error.InvalidToken;
        try self.includeGroup(token);
        const g = try self.group(token);
        if (g.old_owner) |owner| {
            if (!std.ascii.eqlIgnoreCase(account, owner)) return error.TokenAccountMismatch;
            if (g.reserved_count != 0) return error.SessionDropReserved;
        } else if (kind == .join_existing) return error.InvalidToken;
    }

    fn claim(claims: *std.AutoHashMapUnmanaged(ClientId, void), a: std.mem.Allocator, client: ClientId) LifecycleError!void {
        const entry = try claims.getOrPut(a, client);
        if (entry.found_existing) return error.OverlappingIntent;
    }

    fn build(self: *LifecycleOwned, spec: LifecycleBatchSpec) LifecycleError!void {
        if (spec.operations.len > spec.limits.max_operations) return error.CandidateLimitExceeded;
        if ((spec.operations.len == 0) != (spec.observation_only != null)) return error.InvalidRequest;
        var ids: std.AutoHashMapUnmanaged(u64, void) = .empty;
        defer ids.deinit(self.allocator());
        const clients = &self.old_bindings;
        var claims: std.AutoHashMapUnmanaged(ClientId, void) = .empty;
        defer claims.deinit(self.allocator());
        var folded: LifecycleFoldIndex = .empty;
        defer {
            var groups = folded.iterator();
            while (groups.next()) |group_entry| {
                self.allocator().free(group_entry.key_ptr.*);
                group_entry.value_ptr.deinit(self.allocator());
            }
            folded.deinit(self.allocator());
        }
        var removed_accounts: std.StringHashMapUnmanaged(void) = .empty;
        defer {
            var keys = removed_accounts.keyIterator();
            while (keys.next()) |key| self.allocator().free(key.*);
            removed_accounts.deinit(self.allocator());
        }
        for (spec.operations) |op| if (op.intent == .remove_account) {
            const key = try lifecycleFold(self.allocator(), op.intent.remove_account);
            const result = removed_accounts.getOrPut(self.allocator(), key) catch |err| {
                self.allocator().free(key);
                return err;
            };
            if (result.found_existing) {
                self.allocator().free(key);
                return error.OverlappingIntent;
            }
        };
        for (spec.operations) |op| {
            if (op.intent == .remove_account) continue;
            const account = switch (op.intent) {
                .admit => |a| a.account,
                .detach => |d| d.source.account,
                .remove => |r| r.source.account,
                .reconnect => |r| r.source.account,
                .rebind => |r| r.source.account,
                else => unreachable,
            };
            const key = try lifecycleFold(self.allocator(), account);
            defer self.allocator().free(key);
            if (removed_accounts.contains(key)) return error.OverlappingIntent;
            if (op.intent == .rebind) {
                const target_key = try lifecycleFold(self.allocator(), op.intent.rebind.target_account);
                defer self.allocator().free(target_key);
                if (removed_accounts.contains(target_key)) return error.OverlappingIntent;
            }
        }
        // Exactly one global physical discovery. No request/token repeats it.
        var it = self.store.accounts.iterator();
        while (it.next()) |entry| {
            const folded_key = try lifecycleFold(self.allocator(), entry.key_ptr.*);
            const alias = folded.getOrPut(self.allocator(), folded_key) catch |err| {
                self.allocator().free(folded_key);
                return err;
            };
            if (alias.found_existing) self.allocator().free(folded_key) else alias.value_ptr.* = .empty;
            try alias.value_ptr.append(self.allocator(), entry.key_ptr.*);
            for (entry.value_ptr.items.items, 0..) |s, index| {
                self.total_old_rows = std.math.add(usize, self.total_old_rows, 1) catch return error.CandidateLimitExceeded;
                if (self.total_old_rows > spec.limits.max_discovery_rows) return error.CandidateLimitExceeded;
                const loc = try clients.getOrPut(self.allocator(), s.client);
                if (loc.found_existing) loc.value_ptr.duplicates = true else loc.value_ptr.* = .{ .account = entry.key_ptr.*, .index = index };
            }
        }
        self.preview_value.complexity.discovery_row_visits = self.total_old_rows;
        for (spec.drop_permits, 0..) |p, i| {
            if (p.owner == 0) return error.InvalidRequest;
            const s = try self.source(clients, p.source);
            if (s.drop_reservation != p.owner) return error.SessionDropReserved;
            for (spec.drop_permits[0..i]) |old| if (old.source.exact.client == p.source.exact.client) return error.OverlappingIntent;
        }
        // First pass is OLD-only proof and closure discovery; no candidate edits.
        for (spec.operations) |op| {
            const unique = try ids.getOrPut(self.allocator(), op.request_id);
            if (unique.found_existing) return error.OverlappingIntent;
            switch (op.intent) {
                .admit => |ad| {
                    if (ad.account.len == 0) return error.InvalidRequest;
                    try claim(&claims, self.allocator(), ad.client);
                    if (ad.replace_sentinel) |sel| {
                        if (sel.exact.client != ad.client or !std.mem.eql(u8, sel.account, ad.account)) return error.InvalidRequest;
                        const old = try self.source(clients, sel);
                        if (!old.attached or !tokenIsSentinel(old.token) or old.attachment_id != null or !lifecyclePristine(old)) return error.InvalidRequest;
                        try self.checkReservation(spec, sel.account, old);
                    } else if (clients.contains(ad.client)) return error.AmbiguousPhysicalBinding;
                    _ = try self.addAccount(ad.account);
                    switch (ad.kind) {
                        .join_existing => |token| try self.target(ad.account, token, .join_existing),
                        .adopt_verified => |grant| try self.target(ad.account, grant.token, .{ .adopt_verified = grant.portable }),
                        else => {},
                    }
                    if (ad.cap == .evict_exact) {
                        const victim = try self.source(clients, ad.cap.evict_exact);
                        if (victim.attached or !std.mem.eql(u8, ad.cap.evict_exact.account, ad.account)) return error.InvalidRequest;
                        try self.checkReservation(spec, ad.account, victim);
                        try claim(&claims, self.allocator(), victim.client);
                    }
                    if (ad.cap == .evict_exact or ad.cap == .evict_detached) {
                        if (self.store.accounts.get(ad.account)) |old| for (old.items.items) |row| {
                            if (!row.attached) try self.includeGroup(row.token);
                        };
                    }
                },
                .remove_account => |account| {
                    if (account.len == 0) return error.InvalidRequest;
                    const folded_key = try lifecycleFold(self.allocator(), account);
                    defer self.allocator().free(folded_key);
                    const aliases = folded.get(folded_key) orelse return error.MissingRow;
                    for (aliases.items) |key| {
                        _ = try self.addAccount(key);
                        for (self.store.accounts.get(key).?.items.items) |s| {
                            if (clients.get(s.client).?.duplicates) return error.AmbiguousPhysicalBinding;
                            try claim(&claims, self.allocator(), s.client);
                            try self.checkReservation(spec, key, s);
                            try self.includeGroup(s.token);
                        }
                    }
                },
                else => {
                    const sel = switch (op.intent) {
                        .detach => |d| d.source,
                        .remove => |r| r.source,
                        .reconnect => |r| r.source,
                        .rebind => |r| r.source,
                        else => unreachable,
                    };
                    const s = try self.source(clients, sel);
                    try claim(&claims, self.allocator(), s.client);
                    try self.checkReservation(spec, sel.account, s);
                    _ = try self.addAccount(sel.account);
                    try self.includeGroup(s.token);
                    switch (op.intent) {
                        .detach => if (!s.attached) return error.AlreadyAttached,
                        .remove => |r| if (r.reason == .reserved_drop and (s.drop_reservation == 0 or !permit(spec, sel.account, s))) return error.SessionDropReserved,
                        .reconnect => |r| {
                            if (s.attached) return error.AlreadyAttached;
                            if (tokenIsSentinel(s.token) or s.attachment_id == null or s.attachment_id.?.isZero()) return error.InvalidAttachmentId;
                            try claim(&claims, self.allocator(), r.claimant_client);
                            if (r.claimant) |sel_target| {
                                if (sel_target.exact.client != r.claimant_client or !std.ascii.eqlIgnoreCase(sel.account, sel_target.account)) return error.InvalidRequest;
                                const claimant = try self.source(clients, sel_target);
                                try self.checkReservation(spec, sel_target.account, claimant);
                                if (!claimant.attached) return error.InvalidRequest;
                                if (!lifecyclePristine(claimant) and !r.retire_claimant) return error.InvalidRequest;
                                _ = try self.addAccount(sel_target.account);
                                try self.includeGroup(claimant.token);
                            } else if (clients.contains(r.claimant_client)) return error.AmbiguousPhysicalBinding;
                        },
                        .rebind => |r| {
                            if (!s.attached or s.attachment_id == null or s.attachment_id.?.isZero()) return error.InvalidAttachmentId;
                            if (std.mem.eql(u8, &s.token, &r.target_token) and !std.ascii.eqlIgnoreCase(sel.account, r.target_account)) return error.TokenAccountMismatch;
                            try self.target(r.target_account, r.target_token, r.kind);
                            _ = try self.addAccount(r.target_account);
                            if (!std.mem.eql(u8, &s.token, &r.target_token) and lifecycleAttachmentWork(s) and !r.retire_attachment_work) return error.InvalidRequest;
                        },
                        else => {},
                    }
                },
            }
        }
        if (spec.observation_only) |observe| {
            self.observation_client = observe.client;
            if (observe.expected) |expected| {
                if (expected.exact.client != observe.client or !std.mem.eql(u8, observe.account, expected.account)) return error.InvalidRequest;
                _ = try self.source(clients, expected);
            } else if (clients.contains(observe.client)) return error.AmbiguousPhysicalBinding;
            _ = try self.addAccount(observe.account);
        }
        // Include folded display aliases once; they remain distinct map keys.
        const requested_count = self.accounts.items.len;
        for (0..requested_count) |i| {
            const folded_key = try lifecycleFold(self.allocator(), self.accounts.items[i].key);
            defer self.allocator().free(folded_key);
            if (folded.get(folded_key)) |aliases| for (aliases.items) |key| {
                _ = try self.addAccount(key);
            };
        }
        // Every token whose exact list is rebuilt gets one indexed OLD proof.
        // Folded aliases were already discovered; no global registry pass repeats.
        var closure_index: usize = 0;
        while (closure_index < self.accounts.items.len) : (closure_index += 1) {
            if (self.accounts.items[closure_index].old) |old| for (old.items.items) |row| {
                self.preview_value.complexity.closure_row_visits += 1;
                try self.includeGroup(row.token);
            };
        }
        var candidate_rows: usize = 0;
        for (self.accounts.items) |*a| {
            if (a.old) |old| {
                candidate_rows = std.math.add(usize, candidate_rows, old.items.items.len) catch return error.CandidateLimitExceeded;
                if (candidate_rows > self.limits.max_candidate_rows) return error.CandidateLimitExceeded;
                try a.final.items.ensureTotalCapacity(self.allocator(), old.items.items.len);
                for (old.items.items) |s| {
                    if (clients.get(s.client).?.duplicates) return error.AmbiguousPhysicalBinding;
                    if (s.attachment_id) |attachment| {
                        if (attachment.isZero()) return error.InvalidAttachmentId;
                        const loc = self.store.attachment_index.get(attachment.raw) orelse return error.InvalidRequest;
                        if (loc.client != s.client or !std.mem.eql(u8, loc.account, a.key)) return error.InvalidRequest;
                    }
                    a.final.items.appendAssumeCapacity(try self.copySession(s));
                    self.preview_value.complexity.candidate_row_visits += 1;
                }
            }
        }
        // Apply all proved destructive/replacement operations before admission.
        // This is candidate-only normalization, never sequential live commits.
        for (spec.operations) |op| switch (op.intent) {
            .detach => |d| {
                const s = self.finalRow(d.source.account, d.source.exact.client).?;
                switch (d.snapshot) {
                    .keep => {},
                    .clear => freeSnapshot(self.allocator(), s),
                    .replace => |bytes| {
                        try self.charge(bytes.len);
                        const copy = try self.allocator().dupe(u8, bytes);
                        freeSnapshot(self.allocator(), s);
                        s.snapshot = copy;
                    },
                }
                s.attached = false;
                try self.reasons.put(self.allocator(), s.client, .detach);
            },
            .remove => |r| try self.removeFinal(r.source.account, r.source.exact.client, r.reason),
            .remove_account => |name| {
                for (self.accounts.items) |*a| {
                    if (!std.ascii.eqlIgnoreCase(name, a.key)) continue;
                    a.remove_when_empty = true;
                    while (a.final.items.items.len != 0) try self.removeFinalAt(a, a.final.items.items.len - 1, .account_revocation);
                }
            },
            .reconnect => |r| {
                if (r.claimant) |c| try self.removeFinal(c.account, c.exact.client, .claimant_replacement);
                const s = self.finalRow(r.source.account, r.source.exact.client).?;
                const attachment = s.attachment_id.?;
                try self.appendView(LifecycleRemap, &self.remaps, .{ .token = s.token, .attachment_id = attachment, .old_client = s.client, .new_client = r.claimant_client });
                try self.reasons.put(self.allocator(), s.client, .reconnect_source);
                s.client = r.claimant_client;
                s.attached = true;
                s.drop_reservation = 0;
                if (r.consume_snapshot) freeSnapshot(self.allocator(), s);
                try self.reasons.put(self.allocator(), s.client, .reconnect_target);
            },
            .rebind => |r| {
                const source_row = self.finalRow(r.source.account, r.source.exact.client).?;
                const old_token = source_row.token;
                const old_group = if (!tokenIsSentinel(old_token)) (try self.group(old_token)).* else LifecycleGroup{ .token = old_token };
                const g = try self.group(r.target_token);
                g.portable = g.portable or old_group.was_portable or (r.kind == .adopt_verified and r.kind.adopt_verified);
                g.dirty = g.dirty or old_group.old_dirty;
                g.projection = g.projection or old_group.old_projection;
                try lifecycleMerge(&g.journal, old_group.old_journal);
                g.changed = true;
                source_row.token = r.target_token;
                source_row.drop_reservation = 0;
                if (!std.mem.eql(u8, &old_token, &r.target_token)) {
                    source_row.attachment_replica_dirty = false;
                    source_row.attachment_replica_projection_dirty = false;
                    if (source_row.attachment_channel_projections) |p| self.allocator().destroy(p);
                    source_row.attachment_channel_projections = null;
                }
                if (!std.mem.eql(u8, r.source.account, r.target_account)) {
                    const source_account = &self.accounts.items[self.accountIndex(r.source.account).?];
                    const index = self.finalIndex(source_account, r.source.exact.client).?;
                    const moved = source_account.final.items.orderedRemove(index);
                    source_account.remove_when_empty = true;
                    const dest = &self.accounts.items[self.accountIndex(r.target_account).?];
                    dest.final.items.append(self.allocator(), moved) catch |err| {
                        var rollback_owned = moved;
                        freeSessionOwned(self.allocator(), &rollback_owned);
                        return err;
                    };
                }
                try self.reasons.put(self.allocator(), r.source.exact.client, .rebind);
            },
            .admit => |ad| if (ad.replace_sentinel) |sel| try self.removeFinal(sel.account, sel.exact.client, .untrack),
        };
        for (spec.operations) |op| if (op.intent == .admit) try self.admit(spec, op.request_id, op.intent.admit, &claims);
        try self.normalize();
        for (self.accounts.items, 0..) |a, ai| for (a.final.items.items, 0..) |row, ri| {
            self.preview_value.complexity.final_mapping_row_visits += 1;
            const loc = try self.final_lookup.getOrPut(self.allocator(), row.client);
            if (loc.found_existing) return error.AmbiguousPhysicalBinding;
            loc.value_ptr.* = .{ .account = ai, .row = ri };
        };
        self.final_lookup_ready = true;
        try self.makeIndexes();
        try self.makePreview();
        try self.checkLookupBudget();
        try self.reserveMaps();
    }

    fn finalRow(self: *LifecycleOwned, account: []const u8, client: ClientId) ?*Session {
        if (self.final_lookup_ready) {
            const loc = self.final_lookup.get(client) orelse return null;
            const a = &self.accounts.items[loc.account];
            if (!std.mem.eql(u8, a.key, account)) return null;
            return &a.final.items.items[loc.row];
        }
        const a = &self.accounts.items[self.accountIndex(account) orelse return null];
        for (a.final.items.items) |*row| {
            self.preview_value.complexity.operation_row_visits += 1;
            if (row.client == client) return row;
        }
        return null;
    }

    fn finalIndex(self: *LifecycleOwned, account: *const LifecycleAccount, client: ClientId) ?usize {
        for (account.final.items.items, 0..) |row, index| {
            self.preview_value.complexity.operation_row_visits += 1;
            if (row.client == client) return index;
        }
        return null;
    }

    fn removeFinal(self: *LifecycleOwned, account: []const u8, client: ClientId, reason: LifecycleRemoval) LifecycleError!void {
        const a = &self.accounts.items[self.accountIndex(account).?];
        const index = self.finalIndex(a, client) orelse return error.OverlappingIntent;
        try self.removeFinalAt(a, index, reason);
    }

    fn removeFinalAt(self: *LifecycleOwned, a: *LifecycleAccount, index: usize, reason: LifecycleRemoval) LifecycleError!void {
        const client = a.final.items.items[index].client;
        a.remove_when_empty = true;
        try self.removed_reasons.put(self.allocator(), client, reason);
        try self.reasons.put(self.allocator(), client, .removal);
        var s = a.final.items.orderedRemove(index);
        freeSessionOwned(self.allocator(), &s);
    }

    fn finalAccountCount(self: *const LifecycleOwned) usize {
        var count: usize = self.store.accounts.count();
        for (self.accounts.items) |a| {
            if (a.old != null and a.final.items.items.len == 0 and a.remove_when_empty) count -= 1;
            if (a.old == null and a.final.items.items.len != 0) count += 1;
        }
        return count;
    }

    fn mintedToken(self: *LifecycleOwned, io: std.Io) LifecycleError!Token {
        var nonzero = false;
        for (0..attachment_mint_attempts) |_| {
            var token: Token = undefined;
            io.random(&token);
            if (tokenIsSentinel(token)) continue;
            nonzero = true;
            if (self.store.token_index.contains(token)) continue;
            self.chargeLookup(false, @sizeOf(Token) + 1);
            try self.checkLookupBudget();
            var duplicate = self.group_lookup.contains(token);
            for (self.admissions.items) |ad| if (ad.result == .tracked and std.mem.eql(u8, &ad.result.tracked.token, &token)) {
                duplicate = true;
                break;
            };
            if (!duplicate) return token;
        }
        return if (nonzero) error.TokenCollisionExhausted else error.ZeroEntropy;
    }

    fn mintedAttachment(self: *LifecycleOwned, io: std.Io) LifecycleError!AttachmentId {
        for (0..attachment_mint_attempts) |_| {
            const attachment = try AttachmentId.mint(io);
            if (self.store.attachment_index.contains(attachment.raw)) continue;
            var duplicate = false;
            for (self.admissions.items) |ad| if (ad.result == .tracked and ad.result.tracked.attachment_id != null and ad.result.tracked.attachment_id.?.eql(attachment)) {
                duplicate = true;
                break;
            };
            if (!duplicate) return attachment;
        }
        return error.AttachmentCollisionExhausted;
    }

    fn admit(self: *LifecycleOwned, spec: LifecycleBatchSpec, id: u64, ad: LifecycleAdmission, claims: *std.AutoHashMapUnmanaged(ClientId, void)) LifecycleError!void {
        const a = &self.accounts.items[self.accountIndex(ad.account).?];
        if (ad.kind == .no_row) {
            try self.appendView(LifecycleAdmissionResult, &self.admissions, .{ .request_id = id, .account = a.display, .client = ad.client, .result = .{ .untracked = .explicit } });
            return;
        }
        const accounts_full = a.final.items.items.len == 0 and (a.old == null or a.remove_when_empty) and self.finalAccountCount() >= self.store.cfg.max_accounts;
        var sessions_full = a.final.items.items.len >= self.store.cfg.max_sessions_per_account;
        if (sessions_full and (ad.cap == .evict_detached or ad.cap == .evict_exact)) {
            var victim: ?Session = null;
            if (a.old) |old| for (old.items.items) |s| {
                self.preview_value.complexity.operation_row_visits += 1;
                const exact_victim = ad.cap == .evict_exact and sessionMatchesExact(s, ad.cap.evict_exact.exact);
                if (s.attached or (claims.contains(s.client) and !exact_victim) or self.removed_reasons.contains(s.client)) continue;
                if (ad.cap == .evict_exact and !sessionMatchesExact(s, ad.cap.evict_exact.exact)) continue;
                if (victim == null or lifecycleVictimLess(s, victim.?)) victim = s;
            };
            if (victim) |s| {
                try self.checkReservation(spec, a.key, s);
                if (ad.cap != .evict_exact) try claim(claims, self.allocator(), s.client);
                try self.removeFinal(a.key, s.client, .cap_eviction);
                sessions_full = false;
            }
        }
        if (accounts_full or sessions_full) {
            if (ad.cap == .untracked) {
                try self.appendView(LifecycleAdmissionResult, &self.admissions, .{ .request_id = id, .account = a.display, .client = ad.client, .result = .{ .untracked = if (accounts_full) .accounts_capacity else .sessions_capacity } });
                return;
            }
            return if (accounts_full) error.TooManyAccounts else error.TooManySessions;
        }
        const token: Token = switch (ad.kind) {
            .fresh => try self.mintedToken(spec.io),
            .join_existing => |t| t,
            .adopt_verified => |g| g.token,
            .sentinel => @splat(0),
            .no_row => unreachable,
        };
        const attachment: ?AttachmentId = if (ad.kind == .sentinel) null else try self.mintedAttachment(spec.io);
        if (ad.kind == .fresh) _ = try self.group(token);
        if (ad.kind == .adopt_verified) (try self.group(token)).portable = (try self.group(token)).portable or ad.kind.adopt_verified.portable;
        const new = Session{ .client = ad.client, .token = token, .attachment_id = attachment, .signon_ms = ad.signon_ms };
        try a.final.items.append(self.allocator(), new);
        try self.reasons.put(self.allocator(), ad.client, .admission);
        try self.appendView(LifecycleAdmissionResult, &self.admissions, .{ .request_id = id, .account = a.display, .client = ad.client, .result = .{ .tracked = .{ .token = token, .attachment_id = attachment } } });
    }

    fn normalize(self: *LifecycleOwned) LifecycleError!void {
        // Generation assignment is canonical as well as merge provenance;
        // permutation of independent OLD-proved intents cannot change clocks.
        std.mem.sort(LifecycleGroup, self.groups.items, {}, struct {
            fn less(_: void, left: LifecycleGroup, right: LifecycleGroup) bool {
                return std.mem.order(u8, &left.token, &right.token) == .lt;
            }
        }.less);
        for (self.groups.items, 0..) |g, index| self.group_lookup.putAssumeCapacity(g.token, index);
        var generation = self.store.next_local_projection_generation;
        for (self.groups.items) |*g| {
            if (g.changed and !g.journal.isEmpty()) {
                generation = @max(generation, g.journal.revision);
                for (g.journal.slice()) |p| generation = @max(generation, p.generation);
                generation = std.math.add(u64, generation, 1) catch return error.GenerationExhausted;
                g.journal.revision = generation;
            }
        }
        var groups: std.AutoHashMapUnmanaged(Token, usize) = .empty;
        defer groups.deinit(self.allocator());
        for (self.groups.items, 0..) |g, i| try groups.put(self.allocator(), g.token, i);
        for (self.accounts.items) |*a| for (a.final.items.items) |*s| {
            self.preview_value.complexity.normalization_row_visits += 1;
            const index = groups.get(s.token) orelse continue;
            const g = &self.groups.items[index];
            s.portable_resume = g.portable;
            s.replica_dirty = g.dirty;
            s.replica_projection_dirty = g.projection;
            const reason = self.reasons.get(s.client);
            if (g.portable and s.attachment_id != null and (!g.was_portable or
                (reason != null and (reason.? == .admission or reason.? == .rebind)))) s.attachment_replica_dirty = true;
            if (!g.journal.isEmpty()) {
                if (s.local_channel_projections == null) {
                    try self.charge(@sizeOf(LocalChannelProjectionSet));
                    s.local_channel_projections = try self.allocator().create(LocalChannelProjectionSet);
                }
                s.local_channel_projections.?.* = g.journal;
            }
        };

        self.preview_value.projection_generation = generation;
        if (self.finalAccountCount() > self.store.cfg.max_accounts) return error.TooManyAccounts;
        var rows: usize = 0;
        for (self.accounts.items) |a| {
            self.preview_value.complexity.quota_rows_checked += a.final.items.items.len;
            if (a.final.items.items.len > self.store.cfg.max_sessions_per_account) return error.TooManySessions;
            rows = std.math.add(usize, rows, a.final.items.items.len) catch return error.CandidateLimitExceeded;
        }
        if (rows > self.limits.max_candidate_rows) return error.CandidateLimitExceeded;
    }

    fn makeIndexes(self: *LifecycleOwned) LifecycleError!void {
        var tokens: std.AutoHashMapUnmanaged(Token, usize) = .empty;
        defer tokens.deinit(self.allocator());
        for (self.accounts.items) |a| {
            if (a.old) |old| for (old.items.items) |row| {
                self.preview_value.complexity.index_row_visits += 1;
                if (!tokenIsSentinel(row.token)) try tokens.put(self.allocator(), row.token, 0);
            };
            for (a.final.items.items) |row| {
                self.preview_value.complexity.index_row_visits += 1;
                if (!tokenIsSentinel(row.token)) try tokens.put(self.allocator(), row.token, 0);
            }
        }
        var it = tokens.iterator();
        while (it.next()) |t| {
            t.value_ptr.* = self.indexes.items.len;
            try self.indexes.append(self.allocator(), .{ .token = t.key_ptr.* });
            const index = &self.indexes.items[self.indexes.items.len - 1].entry;
            if (self.store.token_index.get(t.key_ptr.*)) |old| index.local_projections.revision = old.local_projections.revision;
            if (self.store.token_index.get(t.key_ptr.*)) |old| for (old.rows.items) |loc| {
                if (self.accountIndex(loc.account) != null) continue;
                self.preview_value.complexity.index_row_visits += 1;
                const row = try self.oldRow(loc);
                try lifecycleIndexAppend(index, self.allocator(), loc.account, row.*);
            };
        }
        // One final-row traversal, rather than one candidate census per token.
        for (self.accounts.items) |a| for (a.final.items.items) |row| {
            self.preview_value.complexity.index_row_visits += 1;
            if (tokenIsSentinel(row.token)) continue;
            const index = &self.indexes.items[tokens.get(row.token).?].entry;
            try lifecycleIndexAppend(index, self.allocator(), a.key, row);
        };
        for (self.indexes.items) |*i| {
            const index = &i.entry;
            std.mem.sort(AttachmentLocator, index.rows.items, {}, struct {
                fn less(_: void, a: AttachmentLocator, b: AttachmentLocator) bool {
                    const order = std.mem.order(u8, a.account, b.account);
                    return if (order == .eq) a.client < b.client else order == .lt;
                }
            }.less);
            if (index.rows.items.len != 0) {
                const account = index.rows.items[0].account;
                for (index.rows.items) |loc| if (!std.ascii.eqlIgnoreCase(account, loc.account)) return error.TokenAccountMismatch;
            }
        }
    }

    fn makePreview(self: *LifecycleOwned) LifecycleError!void {
        var counts = LifecycleCounts{
            .replica = self.store.dirty_replica_rows,
            .projection = self.store.dirty_projection_rows,
            .attachment_replica = self.store.dirty_attachment_replica_rows,
            .attachment_projection = self.store.dirty_attachment_projection_rows,
            .group_journal = self.store.dirty_local_projection_rows,
            .attachment_journal = self.store.dirty_attachment_local_projection_rows,
        };
        var final_rows = self.total_old_rows;
        for (self.accounts.items) |a| {
            if (a.old) |old| {
                final_rows -= old.items.items.len;
                for (old.items.items) |s| {
                    self.preview_value.complexity.preview_row_visits += 1;
                    try lifecycleAdjustCounts(&counts, s, false);
                    try self.appendView(LifecycleRow, &self.before, lifecycleRow(a.display, s));
                }
            }
            final_rows = std.math.add(usize, final_rows, a.final.items.items.len) catch return error.CandidateLimitExceeded;
            for (a.final.items.items) |s| {
                self.preview_value.complexity.preview_row_visits += 1;
                try lifecycleAdjustCounts(&counts, s, true);
                try self.appendView(LifecycleRow, &self.after, lifecycleRow(a.display, s));
            }
        }
        const Less = struct {
            fn less(_: void, a: LifecycleRow, b: LifecycleRow) bool {
                if (a.client != b.client) return a.client < b.client;
                return std.mem.order(u8, a.account, b.account) == .lt;
            }
        };
        std.mem.sort(LifecycleRow, self.before.items, {}, Less.less);
        std.mem.sort(LifecycleRow, self.after.items, {}, Less.less);
        // A touched closure must have exact physical identities even if legacy
        // display aliases made an ambiguous row outside an explicit selector.
        for (self.before.items, 0..) |row, i| if (i != 0 and self.before.items[i - 1].client == row.client) return error.AmbiguousPhysicalBinding;
        for (self.after.items, 0..) |row, i| if (i != 0 and self.after.items[i - 1].client == row.client) return error.AmbiguousPhysicalBinding;
        for (self.before.items) |row| {
            const after = lifecycleFindRow(self.after.items, row.client);
            const reason = self.reasons.get(row.client) orelse .group_propagation;
            const live = row.attached or (after != null and after.?.attached);
            if (live or reason == .reconnect_source) {
                try self.appendView(LifecycleAffectedPhysical, &self.physical, .{ .client = row.client, .before = lifecycleFacts(row), .after = if (after) |r| lifecycleFacts(r) else null, .historical_only = !live, .reason = reason });
            }
            if (after == null or !std.mem.eql(u8, &row.token, &after.?.token) or
                !std.meta.eql(row.attachment_id, after.?.attachment_id))
            {
                // Runtime remapping retains the exact attachment; it is not a
                // revoke merely because its OLD client id no longer occurs.
                var remapped = false;
                for (self.remaps.items) |r| if (r.old_client == row.client) {
                    remapped = true;
                    break;
                };
                if (!remapped) try self.appendView(LifecycleRetiredAttachment, &self.retired, .{ .row = row, .reason = self.removed_reasons.get(row.client) orelse .token_rebind, .attachment_work_retired = row.attachment_replica_dirty or row.attachment_replica_projection_dirty or !row.attachment_journal.isEmpty() });
            }
        }
        for (self.after.items) |row| if (row.attached and lifecycleFindRow(self.before.items, row.client) == null) {
            try self.appendView(LifecycleAffectedPhysical, &self.physical, .{ .client = row.client, .before = null, .after = lifecycleFacts(row), .reason = self.reasons.get(row.client) orelse .group_propagation });
        };
        for (self.admissions.items) |ad| if (ad.result == .untracked) {
            if (lifecycleFindRow(self.before.items, ad.client) == null)
                try self.appendView(LifecycleAffectedPhysical, &self.physical, .{ .client = ad.client, .before = null, .after = null, .reason = .admission });
        };
        if (self.observation_client) |client| {
            if (lifecycleFindRow(self.before.items, client) == null and lifecycleFindRow(self.after.items, client) == null)
                try self.appendView(LifecycleAffectedPhysical, &self.physical, .{ .client = client, .before = null, .after = null, .reason = .admission });
        }
        std.mem.sort(LifecycleAffectedPhysical, self.physical.items, {}, struct {
            fn less(_: void, a: LifecycleAffectedPhysical, b: LifecycleAffectedPhysical) bool {
                return a.client < b.client;
            }
        }.less);
        for (self.indexes.items) |index| {
            var delta = LifecycleTokenDelta{ .token = index.token, .account = "", .old_rows = 0, .final_rows = index.entry.rows.items.len, .old_attached = 0, .final_attached = 0, .old_portable = 0, .final_portable = index.entry.portable_rows, .old_journal = .{}, .final_journal = index.entry.local_projections };
            if (self.store.token_index.get(index.token)) |old| {
                delta.old_rows = old.rows.items.len;
                delta.old_portable = old.portable_rows;
                delta.old_journal = old.local_projections;
                for (old.rows.items) |loc| {
                    if ((try self.oldRow(loc)).attached) delta.old_attached += 1;
                    if (self.accountIndex(loc.account)) |i| delta.account = self.accounts.items[i].display;
                }
            }
            for (index.entry.rows.items) |loc| {
                self.preview_value.complexity.preview_row_visits += 1;
                const row = if (self.accountIndex(loc.account) != null) self.finalRow(loc.account, loc.client).? else (try self.oldRow(loc));
                if (row.attached) delta.final_attached += 1;
                if (self.accountIndex(loc.account)) |i| delta.account = self.accounts.items[i].display;
            }
            try self.appendView(LifecycleTokenDelta, &self.deltas, delta);
        }
        self.preview_value.before = self.before.items;
        self.preview_value.after = self.after.items;
        self.preview_value.affected_physical = self.physical.items;
        self.preview_value.admissions = self.admissions.items;
        self.preview_value.retired_attachments = self.retired.items;
        self.preview_value.remaps = self.remaps.items;
        self.preview_value.token_groups = self.deltas.items;
        self.preview_value.final_accounts = self.finalAccountCount();
        self.preview_value.final_rows = final_rows;
        self.preview_value.counts = counts;
    }

    fn reserveMaps(self: *LifecycleOwned) LifecycleError!void {
        const max_accounts = @max(self.store.accounts.count(), self.preview_value.final_accounts);
        const max_rows = @max(self.total_old_rows, self.preview_value.final_rows);
        if (max_accounts > std.math.maxInt(u32) or max_rows > std.math.maxInt(u32)) return error.CandidateLimitExceeded;
        try self.store.accounts.ensureTotalCapacity(@intCast(max_accounts));
        try self.store.attachment_index.ensureTotalCapacity(@intCast(max_rows));
        try self.store.token_index.ensureTotalCapacity(@intCast(max_rows));
    }

    fn oldDigest(self: *LifecycleOwned) [32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (self.accounts.items) |a| {
            std.hash.autoHashStrat(&h, a.key, .DeepRecursive);
            const old = self.store.accounts.get(a.key);
            if (old) |list| {
                for (list.items.items) |row| {
                    std.hash.autoHashStrat(&h, lifecycleRow(a.display, row), .DeepRecursive);
                    if (row.attachment_id) |id| std.hash.autoHashStrat(&h, self.store.attachment_index.get(id.raw), .DeepRecursive);
                }
            }
            std.hash.autoHash(&h, old != null);
        }
        const s = self.store;
        for (self.indexes.items) |i| {
            const entry = s.token_index.get(i.token);
            std.hash.autoHash(&h, entry != null);
            if (entry) |e| std.hash.autoHashStrat(&h, .{ i.token, e.rows.items, e.portable_rows, e.dirty_rows, e.projection_dirty_rows, e.drop_reserved_rows, e.local_projections }, .DeepRecursive);
        }
        std.hash.autoHashStrat(&h, .{ s.cfg, s.accounts.count(), s.attachment_index.count(), s.token_index.count(), s.dirty_replica_rows, s.dirty_projection_rows, s.dirty_attachment_replica_rows, s.dirty_attachment_projection_rows, s.dirty_local_projection_rows, s.dirty_attachment_local_projection_rows, s.next_local_projection_generation, s.dirty_scan_cursor, s.projection_scan_cursor, s.attachment_replica_scan_cursor, s.attachment_projection_scan_cursor, s.local_projection_scan_cursor, s.attachment_local_projection_scan_cursor }, .DeepRecursive);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        return digest;
    }

    fn candidateDigest(self: *LifecycleOwned) [32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (self.accounts.items) |a| {
            std.hash.autoHashStrat(&h, .{ a.key, a.display, a.key_owned, a.published, a.retired_key, a.remove_when_empty }, .DeepRecursive);
            for (a.final.items.items) |s| std.hash.autoHashStrat(&h, lifecycleRow(a.display, s), .DeepRecursive);
        }
        for (self.indexes.items) |i| std.hash.autoHashStrat(&h, .{ i.token, i.entry.rows.items, i.entry.portable_rows, i.entry.dirty_rows, i.entry.projection_dirty_rows, i.entry.drop_reserved_rows, i.entry.local_projections }, .DeepRecursive);
        std.hash.autoHashStrat(&h, self.preview_value, .DeepRecursive);
        var digest: [32]u8 = undefined;
        h.final(&digest);
        return digest;
    }

    fn publish(self: *LifecycleOwned) void {
        const s = self.store;
        // Remove every old locator before any emptied account key can retire.
        for (self.indexes.items) |index| if (s.token_index.fetchRemove(index.token)) |old| {
            var entry = old.value;
            entry.deinit(s.allocator);
        };
        for (self.accounts.items) |a| if (a.old) |old| for (old.items.items) |row| {
            if (row.attachment_id) |id| std.debug.assert(s.attachment_index.remove(id.raw));
        };
        for (self.accounts.items) |*a| {
            if (a.old != null) {
                const old = s.accounts.fetchRemove(a.key).?;
                a.old = old.value;
                a.retired_key = a.final.items.items.len == 0 and a.remove_when_empty;
            }
        }
        for (self.accounts.items) |*a| {
            if (a.final.items.items.len != 0 or (a.old != null and !a.remove_when_empty)) {
                s.accounts.putAssumeCapacityNoClobber(a.key, a.final);
                a.published = true;
                a.key_owned = false;
                for (a.final.items.items) |row| if (row.attachment_id) |id| {
                    s.attachment_index.putAssumeCapacityNoClobber(id.raw, .{ .account = a.key, .client = row.client });
                };
            }
        }
        for (self.indexes.items) |*index| if (index.entry.rows.items.len != 0) {
            s.token_index.putAssumeCapacityNoClobber(index.token, index.entry);
            index.entry = .{};
        };
        const c = self.preview_value.counts;
        s.dirty_replica_rows = c.replica;
        s.dirty_projection_rows = c.projection;
        s.dirty_attachment_replica_rows = c.attachment_replica;
        s.dirty_attachment_projection_rows = c.attachment_projection;
        s.dirty_local_projection_rows = c.group_journal;
        s.dirty_attachment_local_projection_rows = c.attachment_journal;
        s.next_local_projection_generation = self.preview_value.projection_generation;
        // Cursors contain values, never storage pointers. Keeping the old value
        // is intentional: sorted wraparound scans select its next surviving key.
    }

    fn destroy(self: *LifecycleOwned) void {
        const a = self.allocator();
        const committed = self.state == .finished or self.state == .committed;
        for (self.accounts.items) |*account| {
            if (!account.published) account.final.deinit(a);
            if (committed) {
                if (account.old) |*old| old.deinit(a);
                if (account.retired_key) a.free(account.key);
            }
            if (account.key_owned) a.free(account.key);
            a.free(account.display);
        }
        for (self.indexes.items) |*index| index.entry.deinit(a);
        self.accounts.deinit(a);
        self.groups.deinit(a);
        self.indexes.deinit(a);
        self.before.deinit(a);
        self.after.deinit(a);
        self.admissions.deinit(a);
        self.retired.deinit(a);
        self.remaps.deinit(a);
        self.physical.deinit(a);
        self.deltas.deinit(a);
        self.reasons.deinit(a);
        self.removed_reasons.deinit(a);
        self.final_lookup.deinit(a);
        self.old_bindings.deinit(a);
        self.account_lookup.deinit(a);
        self.group_lookup.deinit(a);
        a.destroy(self);
    }
};

fn lifecycleFindRow(rows: []const LifecycleRow, client: ClientId) ?LifecycleRow {
    var lo: usize = 0;
    var hi = rows.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (rows[mid].client < client) lo = mid + 1 else hi = mid;
    }
    return if (lo < rows.len and rows[lo].client == client) rows[lo] else null;
}
fn lifecyclePristine(s: Session) bool {
    return s.snapshot == null and !s.portable_resume and !s.replica_dirty and !s.replica_projection_dirty and
        !lifecycleAttachmentWork(s) and (s.local_channel_projections == null or s.local_channel_projections.?.isEmpty());
}
fn lifecycleAttachmentWork(s: Session) bool {
    return s.attachment_replica_dirty or s.attachment_replica_projection_dirty or
        (s.attachment_channel_projections != null and !s.attachment_channel_projections.?.isEmpty());
}
fn lifecycleVictimLess(a: Session, b: Session) bool {
    if (a.signon_ms != b.signon_ms) return a.signon_ms < b.signon_ms;
    if ((a.attachment_id == null) != (b.attachment_id == null)) return a.attachment_id == null;
    if (a.attachment_id) |id| {
        const order = std.mem.order(u8, &id.raw, &b.attachment_id.?.raw);
        if (order != .eq) return order == .lt;
    }
    return a.client < b.client;
}
fn lifecycleIndexAppend(entry: *TokenIndexEntry, a: std.mem.Allocator, account: []const u8, s: Session) LifecycleError!void {
    try entry.rows.append(a, .{ .account = account, .client = s.client });
    if (s.portable_resume) entry.portable_rows += 1;
    if (s.replica_dirty) entry.dirty_rows += 1;
    if (s.replica_projection_dirty) entry.projection_dirty_rows += 1;
    if (s.drop_reservation != 0) entry.drop_reserved_rows += 1;
    if (s.local_channel_projections) |p| try lifecycleMerge(&entry.local_projections, p.*);
}
fn lifecycleAdjustCounts(c: *LifecycleCounts, s: Session, add: bool) LifecycleError!void {
    const flags = .{ s.replica_dirty, s.replica_projection_dirty, s.attachment_replica_dirty, s.attachment_replica_projection_dirty, s.local_channel_projections != null and !s.local_channel_projections.?.isEmpty(), s.attachment_channel_projections != null and !s.attachment_channel_projections.?.isEmpty() };
    inline for (.{ "replica", "projection", "attachment_replica", "attachment_projection", "group_journal", "attachment_journal" }, 0..) |name, i| {
        if (flags[i]) @field(c, name) = if (add) std.math.add(usize, @field(c, name), 1) catch return error.CandidateLimitExceeded else std.math.sub(usize, @field(c, name), 1) catch return error.InvalidRequest;
    }
}

pub const SessionStore = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    accounts: std.StringHashMap(SessionList),
    attachment_index: std.AutoHashMap([attachment_id_mod.byte_len]u8, AttachmentLocator),
    token_index: std.AutoHashMap(Token, TokenIndexEntry),
    lock: rwlock.RwLock = .{},
    token_index_lookups: std.atomic.Value(usize) = .init(0),
    token_index_group_row_visits: std.atomic.Value(usize) = .init(0),
    /// Number of rows carrying `replica_dirty`, maintained under `lock`. This is
    /// deliberately a row count (not a token count), so every mutation remains
    /// O(1) once the affected row is known and collection can skip an empty
    /// store without allocating an auxiliary token set.
    dirty_replica_rows: usize = 0,
    /// Last token returned by the bounded dirty scan. Advancing from this
    /// caller-owned-value cursor prevents one permanently failing first token
    /// from starving later groups without retaining pointers into the hash map.
    dirty_scan_cursor: ?Token = null,
    /// Projection retry bookkeeping mirrors the publish lane but advances
    /// independently; a blocked local projection cannot perturb publish order.
    dirty_projection_rows: usize = 0,
    projection_scan_cursor: ?Token = null,
    /// SRA3 retry bookkeeping is keyed by (token, stable attachment id), never
    /// by token alone. This lets two siblings independently publish/revoke and
    /// prevents one successful row from clearing the other's work.
    dirty_attachment_replica_rows: usize = 0,
    attachment_replica_scan_cursor: ?AttachmentReplicaWork = null,
    dirty_attachment_projection_rows: usize = 0,
    attachment_projection_scan_cursor: ?AttachmentReplicaWork = null,
    /// Local exact-token channel projection is a third, independent retry lane.
    /// It is row-backed so removing one sibling cannot erase pending work while
    /// another exact attachment remains.
    dirty_local_projection_rows: usize = 0,
    /// Value cursor for the last returned (token, folded channel) work item.
    /// Keeping the full owned channel makes removal and re-arm safe without a
    /// pointer into the account map.
    local_projection_scan_cursor: ?LocalChannelProjectionWork = null,
    dirty_attachment_local_projection_rows: usize = 0,
    attachment_local_projection_scan_cursor: ?AttachmentLocalChannelProjectionWork = null,
    /// Generation zero is reserved for "never armed". Wrap is practically
    /// unreachable, but skipping zero keeps the invariant total even under a
    /// synthetic overflow test.
    next_local_projection_generation: u64 = 0,
    /// Ephemeral linear-owner guards; never serialized or used as credentials.
    next_lifecycle_serial: u64 = 0,
    active_lifecycle: ?*LifecycleOwned = null,

    /// Synchronous World -> SessionStore transaction member. No disk I/O or
    /// external authority checks occur here. Every request is admitted from
    /// OLD, and one normalized FINAL candidate owns the entire RAM cut.
    pub fn prepareLifecycleBatch(self: *SessionStore, spec: LifecycleBatchSpec) LifecycleError!PreparedLifecycleBatch {
        if (!self.lock.tryLockExclusive()) return error.Busy;
        var retained = false;
        defer if (!retained) self.lock.unlockExclusive();
        if (self.active_lifecycle != null) return error.Busy;
        if (self.next_lifecycle_serial == std.math.maxInt(u64)) return error.GenerationExhausted;
        self.next_lifecycle_serial += 1;
        const o = try self.allocator.create(LifecycleOwned);
        o.* = .{ .store = self, .allocation = self.allocator, .serial = self.next_lifecycle_serial, .limits = spec.limits };
        errdefer o.destroy();
        try o.build(spec);
        o.predecessor = o.oldDigest();
        o.seal = o.candidateDigest();
        self.active_lifecycle = o;
        retained = true;
        return .{ .owned = o };
    }

    pub fn init(allocator: std.mem.Allocator) SessionStore {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) SessionStore {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .accounts = std.StringHashMap(SessionList).init(allocator),
            .attachment_index = std.AutoHashMap([attachment_id_mod.byte_len]u8, AttachmentLocator).init(allocator),
            .token_index = std.AutoHashMap(Token, TokenIndexEntry).init(allocator),
        };
    }

    const AttachmentOwner = struct {
        account: []const u8,
        client: ClientId,
    };

    /// Lock-held, allocation-free uniqueness probe. Attachment ids identify one
    /// physical row across the whole local store, including account case aliases.
    fn attachmentOwnerLocked(self: *const SessionStore, attachment_id: AttachmentId) ?AttachmentOwner {
        const locator = self.attachment_index.get(attachment_id.raw) orelse return null;
        return .{ .account = locator.account, .client = locator.client };
    }

    fn removeAttachmentIndexLocked(self: *SessionStore, session: Session) void {
        const attachment_id = session.attachment_id orelse return;
        const removed = self.attachment_index.remove(attachment_id.raw);
        std.debug.assert(removed);
    }

    fn noteTokenIndexLookup(self: *const SessionStore) void {
        if (builtin.is_test) _ = @constCast(&self.token_index_lookups).fetchAdd(1, .monotonic);
    }

    fn noteTokenGroupRowVisit(self: *const SessionStore) void {
        if (builtin.is_test) _ = @constCast(&self.token_index_group_row_visits).fetchAdd(1, .monotonic);
    }

    /// Reset deterministic index-work instrumentation. Production builds keep
    /// the counters dormant; tests may call this between bounded operations.
    pub fn resetTokenIndexComplexity(self: *SessionStore) void {
        if (!builtin.is_test) return;
        self.token_index_lookups.store(0, .monotonic);
        self.token_index_group_row_visits.store(0, .monotonic);
    }

    pub fn tokenIndexComplexitySnapshot(self: *const SessionStore) TokenIndexComplexity {
        if (!builtin.is_test) return .{};
        return .{
            .lookups = self.token_index_lookups.load(.monotonic),
            .group_row_visits = self.token_index_group_row_visits.load(.monotonic),
        };
    }

    fn tokenEntryLocked(self: *const SessionStore, token: Token) ?*const TokenIndexEntry {
        if (tokenIsSentinel(token)) return null;
        self.noteTokenIndexLookup();
        return @constCast(&self.token_index).getPtr(token);
    }

    fn tokenEntryMutLocked(self: *SessionStore, token: Token) ?*TokenIndexEntry {
        if (tokenIsSentinel(token)) return null;
        self.noteTokenIndexLookup();
        return self.token_index.getPtr(token);
    }

    fn tokenLocatorIndex(
        self: *const SessionStore,
        entry: *const TokenIndexEntry,
        account: []const u8,
        client: ClientId,
    ) ?usize {
        for (entry.rows.items, 0..) |locator, index| {
            self.noteTokenGroupRowVisit();
            if (locator.client == client and std.mem.eql(u8, locator.account, account)) return index;
        }
        return null;
    }

    fn sessionForTokenLocatorLocked(self: *SessionStore, locator: AttachmentLocator) ?*Session {
        const list = self.accounts.getPtr(locator.account) orelse return null;
        const index = list.indexOfClient(locator.client) orelse return null;
        return &list.items.items[index];
    }

    /// Reserve every allocation needed to add one row to `token`. A rowless
    /// token returns a staged entry that the caller owns until the no-fail commit
    /// edge; an existing entry merely retains one unused locator slot.
    fn reserveTokenRowInsertLocked(self: *SessionStore, token: Token) std.mem.Allocator.Error!?TokenIndexEntry {
        if (tokenIsSentinel(token)) return null;
        if (self.tokenEntryMutLocked(token)) |entry| {
            try entry.rows.ensureUnusedCapacity(self.allocator, 1);
            return null;
        }
        try self.token_index.ensureUnusedCapacity(1);
        var staged: TokenIndexEntry = .{};
        errdefer staged.deinit(self.allocator);
        try staged.rows.ensureUnusedCapacity(self.allocator, 1);
        return staged;
    }

    fn addTokenRowLocked(
        self: *SessionStore,
        account: []const u8,
        session: Session,
        staged: *?TokenIndexEntry,
    ) void {
        if (tokenIsSentinel(session.token)) return;
        var entry = self.tokenEntryMutLocked(session.token);
        if (entry == null) {
            var fresh = staged.* orelse unreachable;
            staged.* = null;
            fresh.rows.appendAssumeCapacity(.{ .account = account, .client = session.client });
            self.token_index.putAssumeCapacity(session.token, fresh);
            entry = self.token_index.getPtr(session.token).?;
        } else {
            entry.?.rows.appendAssumeCapacity(.{ .account = account, .client = session.client });
        }
        const group = entry.?;
        if (session.portable_resume) group.portable_rows += 1;
        if (session.replica_dirty) group.dirty_rows += 1;
        if (session.replica_projection_dirty) group.projection_dirty_rows += 1;
        if (session.drop_reservation != 0) group.drop_reserved_rows += 1;
        if (session.local_channel_projections) |set| {
            if (set.revision >= group.local_projections.revision)
                group.local_projections = set.*;
        }
    }

    fn removeTokenRowLocked(
        self: *SessionStore,
        account: []const u8,
        session: Session,
        keep_empty: bool,
    ) void {
        if (tokenIsSentinel(session.token)) return;
        const entry = self.tokenEntryMutLocked(session.token) orelse unreachable;
        const index = self.tokenLocatorIndex(entry, account, session.client) orelse unreachable;
        if (session.portable_resume) {
            std.debug.assert(entry.portable_rows != 0);
            entry.portable_rows -= 1;
        }
        if (session.replica_dirty) {
            std.debug.assert(entry.dirty_rows != 0);
            entry.dirty_rows -= 1;
        }
        if (session.replica_projection_dirty) {
            std.debug.assert(entry.projection_dirty_rows != 0);
            entry.projection_dirty_rows -= 1;
        }
        if (session.drop_reservation != 0) {
            std.debug.assert(entry.drop_reserved_rows != 0);
            entry.drop_reserved_rows -= 1;
        }
        _ = entry.rows.swapRemove(index);
        if (entry.rows.items.len != 0) return;
        entry.portable_rows = 0;
        entry.dirty_rows = 0;
        entry.projection_dirty_rows = 0;
        entry.drop_reserved_rows = 0;
        entry.local_projections = .{};
        if (keep_empty) return;
        entry.deinit(self.allocator);
        const removed = self.token_index.remove(session.token);
        std.debug.assert(removed);
    }

    fn remapTokenRowLocatorLocked(
        self: *SessionStore,
        token: Token,
        old_account: []const u8,
        old_client: ClientId,
        new_account: []const u8,
        new_client: ClientId,
    ) void {
        if (tokenIsSentinel(token)) return;
        const entry = self.tokenEntryMutLocked(token) orelse unreachable;
        const index = self.tokenLocatorIndex(entry, old_account, old_client) orelse unreachable;
        entry.rows.items[index] = .{ .account = new_account, .client = new_client };
    }

    pub fn deinit(self: *SessionStore) void {
        {
            self.lock.lockExclusive();
            defer self.lock.unlockExclusive();

            self.attachment_index.deinit();
            var token_entries = self.token_index.valueIterator();
            while (token_entries.next()) |entry| entry.deinit(self.allocator);
            self.token_index.deinit();
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.accounts.deinit();
        }
        self.* = undefined;
    }

    /// Register a live session for `account`. Idempotent on `client` (re-attach
    /// refreshes its token/signon and marks it attached). Returns the session.
    ///
    /// Compatibility-only: the resulting row has no stable attachment id and
    /// is therefore ineligible for attachment-aware replica/reclaim protocols.
    /// Production callers should use `attachWithAttachment`.
    pub fn attach(self: *SessionStore, account: []const u8, client: ClientId, token: Token, signon_ms: i64) Error!Session {
        return (try self.attachReportingEviction(account, client, token, signon_ms)).session;
    }

    /// Register a current physical attachment with its independently minted,
    /// stable identity. The id is never inferred from the reusable token or the
    /// ephemeral runtime client handle.
    pub fn attachWithAttachment(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        attachment_id: AttachmentId,
        signon_ms: i64,
    ) Error!Session {
        return (try self.attachWithAttachmentReportingEviction(
            account,
            client,
            token,
            attachment_id,
            signon_ms,
        )).session;
    }

    /// `attach`, plus the portable authority of an oldest detached row evicted
    /// at the per-account cap. Keeping the legacy `attach` wrapper makes pure
    /// callers simple while letting the live daemon close the mesh lifecycle.
    pub fn attachReportingEviction(self: *SessionStore, account: []const u8, client: ClientId, token: Token, signon_ms: i64) Error!AttachOutcome {
        return self.attachReportingEvictionInternal(account, client, token, null, signon_ms, .compatibility);
    }

    pub fn attachWithAttachmentReportingEviction(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        attachment_id: AttachmentId,
        signon_ms: i64,
    ) Error!AttachOutcome {
        if (attachment_id.isZero()) return error.InvalidAttachmentId;
        return self.attachReportingEvictionInternal(
            account,
            client,
            token,
            attachment_id,
            signon_ms,
            .compatibility,
        );
    }

    /// Publish a fresh, clean bootstrap row for an exact attachment rebind.
    /// Unlike compatibility attach, this never refreshes an existing client and
    /// never evicts a detached row at the account cap. The supplied token and
    /// stable physical id must both be nonzero. On success the row satisfies
    /// `prepareExactAttachmentRebind`'s claimant preconditions.
    pub fn attachBootstrapWithAttachmentNoEvict(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        attachment_id: AttachmentId,
        signon_ms: i64,
    ) Error!Session {
        if (tokenIsSentinel(token)) return error.InvalidToken;
        if (attachment_id.isZero()) return error.InvalidAttachmentId;
        return (try self.attachReportingEvictionInternal(
            account,
            client,
            token,
            attachment_id,
            signon_ms,
            .bootstrap_no_evict,
        )).session;
    }

    /// Mint and atomically publish a stable bootstrap attachment. A globally
    /// colliding random id is retried a bounded number of times; zero entropy
    /// and allocator/capacity failures publish no row and evict no authority.
    pub fn mintBootstrapAttachmentNoEvict(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        signon_ms: i64,
        io: std.Io,
    ) BootstrapAttachError!BootstrapAttachment {
        if (tokenIsSentinel(token)) return error.InvalidToken;
        for (0..attachment_mint_attempts) |_| {
            const candidate = try AttachmentId.mint(io);
            const session = self.attachBootstrapWithAttachmentNoEvict(
                account,
                client,
                token,
                candidate,
                signon_ms,
            ) catch |err| switch (err) {
                error.DuplicateAttachmentId => continue,
                else => return err,
            };
            return .{ .session = session, .attachment_id = candidate };
        }
        return error.DuplicateAttachmentId;
    }

    fn attachReportingEvictionInternal(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        attachment_id: ?AttachmentId,
        signon_ms: i64,
        mode: AttachMode,
    ) Error!AttachOutcome {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        // DROP freezes exact-token membership until its owner transaction
        // either commits or cancels. Reject a distinct sibling attach before
        // reserving index/list storage so ignored allocation failures cannot
        // obscure the protocol conflict or publish a partially joined group.
        const inherited = self.tokenGroupStateForAccountLocked(account, token) orelse
            return error.TokenAccountMismatch;
        if (inherited.drop_reserved)
            return error.SessionDropReserved;
        if (self.accounts.getPtr(account)) |existing_list| {
            if (existing_list.indexOfClient(client)) |existing_index| {
                if (mode == .bootstrap_no_evict) return error.ClientAlreadyTracked;
                const source = existing_list.items.items[existing_index];
                if (source.drop_reservation != 0 or
                    (!std.crypto.timing_safe.eql(Token, source.token, token) and
                        self.tokenGroupHasDropReservationLocked(source.token)))
                    return error.SessionDropReserved;
            } else if (existing_list.items.items.len >= self.cfg.max_sessions_per_account) {
                if (mode == .bootstrap_no_evict) return error.TooManySessions;
                if (oldestDetached(existing_list)) |evict_index| {
                    const victim = existing_list.items.items[evict_index];
                    if (victim.drop_reservation != 0 or
                        (!std.crypto.timing_safe.eql(Token, victim.token, token) and
                            self.tokenGroupHasDropReservationLocked(victim.token)))
                        return error.SessionDropReserved;
                }
            }
        }

        var insert_attachment_index = false;
        if (attachment_id) |candidate| {
            if (self.attachmentOwnerLocked(candidate)) |owner| {
                // Permit only an idempotent refresh of the exact existing map
                // row. A case-variant account key is a distinct row here and
                // must not duplicate the stable identity.
                if (!std.mem.eql(u8, owner.account, account) or owner.client != client)
                    return error.DuplicateAttachmentId;
            } else {
                // Reserve before any row replacement/eviction. Publication into
                // the index is then allocation-free at the same commit edge.
                try self.attachment_index.ensureUnusedCapacity(1);
                insert_attachment_index = true;
            }
        }

        // An exact reusable token is a global capability. Bind it to exactly one
        // ASCII-casefolded account before ensureAccount can allocate/publish an
        // empty map entry or replacement can merge dirty/journal state.
        const account_preexisting = self.accounts.contains(account);
        const list = try self.ensureAccount(account);
        errdefer if (!account_preexisting) {
            const empty_entry = self.accounts.getEntry(account) orelse unreachable;
            std.debug.assert(empty_entry.value_ptr.items.items.len == 0);
            self.dropAccount(empty_entry);
        };
        const account_key = self.accounts.getEntry(account).?.key_ptr.*;
        var staged_token_entry = try self.reserveTokenRowInsertLocked(token);
        defer if (staged_token_entry) |*entry| entry.deinit(self.allocator);
        if (list.indexOfClient(client)) |idx| {
            if (mode == .bootstrap_no_evict) return error.ClientAlreadyTracked;
            const displaced = list.items.items[idx];
            if (displaced.drop_reservation != 0) return error.SessionDropReserved;
            if (attachment_id) |requested| {
                if (displaced.attachment_id) |current| {
                    if (!current.eql(requested)) return error.AttachmentIdMismatch;
                }
            }
            // A compatibility refresh of an already-current row must not erase
            // the stable id. Only an explicit current attach may replace it,
            // and global uniqueness was checked above while holding the lock.
            const effective_attachment_id = attachment_id orelse displaced.attachment_id;
            const same_attachment = if (effective_attachment_id) |effective|
                if (displaced.attachment_id) |prior| effective.eql(prior) else false
            else
                false;
            const preserve_attachment_authority = same_attachment and
                std.crypto.timing_safe.eql(Token, displaced.token, token);
            const attachment_projection_storage = if (preserve_attachment_authority)
                displaced.attachment_channel_projections
            else
                null;
            const old_projection_storage = list.items.items[idx].local_channel_projections;
            var projection_storage = old_projection_storage;
            if (!inherited.local_projections.isEmpty() and projection_storage == null) {
                projection_storage = try self.allocator.create(LocalChannelProjectionSet);
            }
            if (projection_storage) |storage| {
                if (inherited.local_projections.isEmpty()) {
                    projection_storage = null;
                } else {
                    storage.* = inherited.local_projections;
                }
            }
            self.removeDirtyRowLocked(&list.items.items[idx]);
            self.removeTokenRowLocked(
                account_key,
                displaced,
                !tokenIsSentinel(token) and std.crypto.timing_safe.eql(Token, displaced.token, token),
            );
            if (projection_storage == null) {
                if (old_projection_storage) |storage| self.allocator.destroy(storage);
            }
            if (!preserve_attachment_authority) {
                if (displaced.attachment_channel_projections) |storage| self.allocator.destroy(storage);
            }
            freeSnapshot(self.allocator, &list.items.items[idx]);
            list.items.items[idx] = .{
                .client = client,
                .token = token,
                .attachment_id = effective_attachment_id,
                .signon_ms = signon_ms,
                .attached = true,
                .portable_resume = inherited.portable,
                .replica_dirty = inherited.dirty,
                .replica_projection_dirty = inherited.projection_dirty,
                .attachment_replica_dirty = (preserve_attachment_authority and displaced.attachment_replica_dirty) or
                    (effective_attachment_id != null and inherited.portable),
                .attachment_replica_projection_dirty = preserve_attachment_authority and displaced.attachment_replica_projection_dirty,
                .local_channel_projections = projection_storage,
                .attachment_channel_projections = attachment_projection_storage,
            };
            if (inherited.dirty) self.dirty_replica_rows += 1;
            if (inherited.projection_dirty) self.dirty_projection_rows += 1;
            if (list.items.items[idx].attachment_replica_dirty) self.dirty_attachment_replica_rows += 1;
            if (list.items.items[idx].attachment_replica_projection_dirty) self.dirty_attachment_projection_rows += 1;
            if (projection_storage != null) self.dirty_local_projection_rows += 1;
            if (attachment_projection_storage) |storage| {
                if (!storage.isEmpty()) self.dirty_attachment_local_projection_rows += 1;
            }
            self.addTokenRowLocked(account_key, list.items.items[idx], &staged_token_entry);
            if (insert_attachment_index) {
                const current = list.items.items[idx].attachment_id orelse unreachable;
                self.attachment_index.putAssumeCapacity(current.raw, .{
                    .account = account_key,
                    .client = client,
                });
            }
            return .{
                .session = list.items.items[idx],
                .evicted = .{
                    .client = displaced.client,
                    .token = displaced.token,
                    .attachment_id = displaced.attachment_id,
                    .portable = displaced.portable_resume,
                },
            };
        }
        // Capture destination retry state before capacity eviction: if the new
        // attachment replaces the only detached row of this same exact token,
        // its pending publish/projection work must move with the logical group.
        const projection_storage = if (!inherited.local_projections.isEmpty()) blk: {
            const storage = try self.allocator.create(LocalChannelProjectionSet);
            storage.* = inherited.local_projections;
            break :blk storage;
        } else null;
        errdefer if (projection_storage) |storage| self.allocator.destroy(storage);
        var evicted: ?EvictedSession = null;
        if (list.items.items.len >= self.cfg.max_sessions_per_account) {
            if (mode == .bootstrap_no_evict) return error.TooManySessions;
            // At cap: evict the oldest *detached* ghost to make room for the live
            // session. Never evict an attached session (that would drop a peer).
            if (oldestDetached(list)) |evict| {
                const displaced = list.items.items[evict];
                if (displaced.drop_reservation != 0) return error.SessionDropReserved;
                evicted = .{
                    .client = displaced.client,
                    .token = displaced.token,
                    .attachment_id = displaced.attachment_id,
                    .portable = displaced.portable_resume,
                };
                self.removeDirtyRowLocked(&list.items.items[evict]);
                self.removeTokenRowLocked(
                    account_key,
                    displaced,
                    !tokenIsSentinel(token) and std.crypto.timing_safe.eql(Token, displaced.token, token),
                );
                self.removeAttachmentIndexLocked(list.items.items[evict]);
                freeSessionOwned(self.allocator, &list.items.items[evict]);
                _ = list.items.swapRemove(evict);
            } else return error.TooManySessions;
        }
        const session = Session{
            .client = client,
            .token = token,
            .attachment_id = attachment_id,
            .signon_ms = signon_ms,
            .attached = true,
            .portable_resume = inherited.portable,
            .replica_dirty = inherited.dirty,
            .replica_projection_dirty = inherited.projection_dirty,
            .attachment_replica_dirty = attachment_id != null and inherited.portable,
            .local_channel_projections = projection_storage,
        };
        try list.items.append(self.allocator, session);
        if (inherited.dirty) self.dirty_replica_rows += 1;
        if (inherited.projection_dirty) self.dirty_projection_rows += 1;
        if (session.attachment_replica_dirty) self.dirty_attachment_replica_rows += 1;
        if (projection_storage != null) self.dirty_local_projection_rows += 1;
        self.addTokenRowLocked(account_key, session, &staged_token_entry);
        if (insert_attachment_index) {
            const current = session.attachment_id orelse unreachable;
            self.attachment_index.putAssumeCapacity(current.raw, .{
                .account = account_key,
                .client = client,
            });
        }
        return .{ .session = session, .evicted = evicted };
    }

    /// Index of the oldest (lowest signon) detached session in `list`, or null.
    fn oldestDetached(list: *const SessionList) ?usize {
        var best: ?usize = null;
        for (list.items.items, 0..) |s, i| {
            if (s.attached) continue;
            if (best) |b| {
                if (s.signon_ms < list.items.items[b].signon_ms) best = i;
            } else best = i;
        }
        return best;
    }

    /// Mark a session detached (connection dropped) but retain it for reclaim/
    /// bouncer. A previously-owned snapshot is deliberately preserved: callers
    /// use this no-allocation fallback when encoding a fresher disconnect image
    /// fails, and erasing the last retry source would strand a dirty portable
    /// token after ConnState is freed. Returns true if the row was present.
    pub fn markDetached(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        if (self.sessionOrTokenGroupHasDropReservationLocked(list.items.items[idx])) return false;
        list.items.items[idx].attached = false;
        return true;
    }

    /// Mark a session detached and persist an optional encoded restore snapshot.
    /// The snapshot is copied into the store and freed when the session is
    /// reattached, removed, evicted, or the account is dropped.
    pub fn markDetachedWithSnapshot(self: *SessionStore, account: []const u8, client: ClientId, snapshot: ?[]const u8) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        const session = &list.items.items[idx];
        if (self.sessionOrTokenGroupHasDropReservationLocked(session.*)) return false;
        const copied = if (snapshot) |bytes|
            if (bytes.len != 0) self.allocator.dupe(u8, bytes) catch {
                // Transport loss still detaches the row, but snapshot replacement
                // is transactional: retain the previous retry source and every
                // token-group flag when allocation pressure prevents the update.
                // Returning false lets interested callers surface the degraded
                // capture while legacy disconnect callers remain fail-safe.
                session.attached = false;
                return false;
            } else null
        else
            null;
        freeSnapshot(self.allocator, session);
        session.snapshot = copied;
        session.attached = false;
        return true;
    }

    /// Mark that this session's portable resume credential was successfully
    /// emitted to its owner. Idempotent; never creates a session implicitly.
    pub fn markPortableResumeIssued(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        const session = list.items.items[idx];
        if (tokenIsSentinel(session.token)) return false;
        self.setTokenGroupPortableLocked(session.token, true);
        // The first portable credential exposes the reusable group. Every
        // current physical sibling therefore needs its own initial SRA3 OFFER.
        _ = self.markTokenAttachmentReplicasDirtyLocked(session.token);
        return true;
    }

    /// Restore the carried portable-resume bit during a Helix adoption. This is
    /// deliberately separate from `attach`: a normal re-attach rotates the local
    /// token and resets portability, while an in-place upgrade preserves both.
    pub fn restorePortableResumeIssued(self: *SessionStore, account: []const u8, client: ClientId, issued: bool) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        const session = &list.items.items[idx];
        if (tokenIsSentinel(session.token)) {
            list.items.items[idx].portable_resume = false;
            return !issued;
        }
        self.setPortableLocked(session, issued);
        if (issued and session.attachment_id != null)
            self.setAttachmentReplicaDirtyLocked(session, true);
        return true;
    }

    /// One O(N) post-adoption normalization pass for legacy/Helix row images.
    /// Per-row restore stays O(1); after all rows are staged this propagates each
    /// observed portable token and arms every stable sibling exactly once. The
    /// maintained index makes this allocation-free and visits each indexed row
    /// at most once, so an OOM cannot expose a partially normalized registry.
    pub fn normalizePortableGroupsAfterRestore(self: *SessionStore) Error!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var entries = self.token_index.valueIterator();
        while (entries.next()) |entry| {
            if (entry.portable_rows == 0) continue;
            for (entry.rows.items) |locator| {
                self.noteTokenGroupRowVisit();
                const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
                session.portable_resume = true;
                if (session.attachment_id != null) {
                    self.setAttachmentReplicaDirtyLocked(session, true);
                }
            }
            entry.portable_rows = entry.rows.items.len;
        }
    }

    /// Return the stable local token and portability state for one tracked
    /// connection. Used by detach to decide whether a peer snapshot is owed.
    pub fn resumeHandleForClient(self: *const SessionStore, account: []const u8, client: ClientId) ?ResumeHandle {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        const idx = list.indexOfClient(client) orelse return null;
        const session = list.items.items[idx];
        // The durable bit is propagated to every sibling when portability is
        // issued; the group read remains defensive for restored legacy rows.
        return .{
            .token = session.token,
            .attachment_id = session.attachment_id,
            .portable = self.tokenGroupStateLocked(session.token).portable,
        };
    }

    /// Join `client` to the logical session identified by `token`. The client
    /// must already be tracked under `account`; this only rebinds its generated
    /// first-login token to the presented stable session credential. Other live
    /// attachments keep the same token and remain connected. Portable issuance
    /// is group-wide: a newly joined attachment inherits it from any sibling so
    /// its later detach is replicated too.
    pub fn joinTokenGroup(self: *SessionStore, account: []const u8, client: ClientId, token: Token) bool {
        var prepared = self.prepareTokenBind(account, client, token, .join_existing) orelse return false;
        defer prepared.deinit();
        if (!prepared.commit()) {
            prepared.abort();
            return false;
        }
        prepared.finish();
        return true;
    }

    /// Bind a tracked client to a token whose authority was established outside
    /// the local store (for example by a verified mesh credential + signed
    /// migration replica). Unlike `joinTokenGroup`, this does not require a
    /// pre-existing local attachment bearing the token.
    pub fn adoptTokenGroup(self: *SessionStore, account: []const u8, client: ClientId, token: Token, portable: bool) bool {
        var prepared = self.prepareTokenBind(account, client, token, .{ .adopt_verified = portable }) orelse return false;
        defer prepared.deinit();
        if (!prepared.commit()) {
            prepared.abort();
            return false;
        }
        prepared.finish();
        return true;
    }

    /// Prepare exact physical-attachment restoration. The selected id must own
    /// one detached row under the caller's folded account and exact token. The
    /// reconnecting runtime client may be untracked (preferred at account cap)
    /// or may own one separate, clean compatibility bootstrap row. No token-only
    /// or newest-sibling fallback is performed.
    pub fn prepareExactAttachmentRebind(
        self: *SessionStore,
        account: []const u8,
        claimant_client: ClientId,
        token: Token,
        attachment_id: AttachmentId,
    ) ?PreparedAttachmentRebind {
        if (tokenIsSentinel(token) or attachment_id.isZero()) return null;
        self.lock.lockExclusive();
        var keep_locked = false;
        defer if (!keep_locked) self.lock.unlockExclusive();

        var claimant_list: ?*SessionList = null;
        var claimant_account: ?[]const u8 = null;
        var claimant_index: ?usize = null;
        var claimant_it = self.accounts.iterator();
        while (claimant_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) continue;
            const index = entry.value_ptr.indexOfClient(claimant_client) orelse continue;
            if (claimant_list != null) return null;
            claimant_list = entry.value_ptr;
            claimant_account = entry.key_ptr.*;
            claimant_index = index;
        }
        if (claimant_list) |list| {
            const claimant = list.items.items[claimant_index.?];
            // Existing authority/retry state needs an explicit revoke/transfer
            // transaction, never silent destruction as a bootstrap side effect.
            if (claimant.drop_reservation != 0 or !claimant.attached or claimant.attachment_id == null or claimant.snapshot != null or
                claimant.portable_resume or claimant.replica_dirty or claimant.replica_projection_dirty or
                claimant.attachment_replica_dirty or claimant.attachment_replica_projection_dirty or
                claimant.local_channel_projections != null or claimant.attachment_channel_projections != null)
            {
                return null;
            }
            if (self.tokenGroupHasDropReservationLocked(claimant.token)) return null;
            if (!tokenIsSentinel(claimant.token)) {
                const claimant_group = self.tokenEntryLocked(claimant.token) orelse return null;
                if (claimant_group.rows.items.len != 1) return null;
            }
        }
        if (self.tokenGroupHasDropReservationLocked(token)) return null;
        // The maintained stable-id index makes exact reconnect independent of
        // global account/session cardinality. Folded account and token checks
        // still fail closed at the located row.
        const ghost_locator = self.attachment_index.get(attachment_id.raw) orelse return null;
        if (!std.ascii.eqlIgnoreCase(ghost_locator.account, account)) return null;
        const target_list = self.accounts.getPtr(ghost_locator.account) orelse return null;
        const target_index = target_list.indexOfClient(ghost_locator.client) orelse return null;
        if (!sessionMatchesAttachment(target_list.items.items[target_index], token, attachment_id) or
            target_list.items.items[target_index].drop_reservation != 0) return null;
        if ((claimant_list != null and target_list == claimant_list.? and target_index == claimant_index.?) or
            target_list.items.items[target_index].attached)
        {
            return null;
        }

        const ghost = target_list.items.items[target_index];
        const group_local_projections = if (ghost.local_channel_projections) |set| set.* else LocalChannelProjectionSet{};
        const attachment_local_projections = if (ghost.attachment_channel_projections) |set| set.* else LocalChannelProjectionSet{};
        var target_local_projections: LocalChannelProjectionSet = .{};
        if (!mergeLocalProjectionSets(
            &target_local_projections,
            &group_local_projections,
            &attachment_local_projections,
        )) return null;

        // Freeze the complete folded-account row image for the generic restore
        // planner. Allocation happens before the ticket is published; failure
        // releases the lock without consuming either bootstrap or ghost.
        var locked_row_count: usize = 0;
        var count_it = self.accounts.iterator();
        while (count_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) continue;
            locked_row_count = std.math.add(
                usize,
                locked_row_count,
                entry.value_ptr.items.items.len,
            ) catch return null;
        }
        const locked_account_rows = self.allocator.alloc(
            TokenBindRowSnapshot,
            locked_row_count,
        ) catch return null;
        var rows_transferred = false;
        defer if (!rows_transferred) self.allocator.free(locked_account_rows);
        var locked_row_index: usize = 0;
        var rows_it = self.accounts.iterator();
        while (rows_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) continue;
            for (entry.value_ptr.items.items) |row| {
                locked_account_rows[locked_row_index] = .{
                    .client = row.client,
                    .token = row.token,
                    .attachment_id = row.attachment_id,
                    .attached = row.attached,
                    .portable_resume = row.portable_resume,
                };
                locked_row_index += 1;
            }
        }
        std.debug.assert(locked_row_index == locked_account_rows.len);
        const RowOrder = struct {
            fn lessThan(_: void, a: TokenBindRowSnapshot, b: TokenBindRowSnapshot) bool {
                return a.client < b.client;
            }
        };
        std.mem.sort(TokenBindRowSnapshot, locked_account_rows, {}, RowOrder.lessThan);
        for (locked_account_rows[1..], 1..) |row, row_index| {
            if (locked_account_rows[row_index - 1].client == row.client) return null;
        }

        keep_locked = true;
        rows_transferred = true;
        return .{
            .store = self,
            .claimant_list = claimant_list,
            .claimant_account = claimant_account,
            .ghost_list = target_list,
            .ghost_account = ghost_locator.account,
            .claimant_index = claimant_index,
            .ghost_index = target_index,
            .claimant_client = claimant_client,
            .ghost_client = target_list.items.items[target_index].client,
            .token = token,
            .attachment_id = attachment_id,
            .locked_account_rows = locked_account_rows,
            .target_local_projections = target_local_projections,
            .result_portable = ghost.portable_resume,
        };
    }

    /// Prepare a brand-new claimant directly under a caller-selected token.
    /// This is the bootstrap counterpart to `prepareTokenBind`: no provisional
    /// generated-token row is published, and an account-cap victim remains
    /// fully live in the store until the caller has staged its restore.
    pub fn prepareBootstrapTokenAttach(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        kind: TokenBindKind,
        signon_ms: i64,
    ) ?PreparedBootstrapTokenAttach {
        if (tokenIsSentinel(token)) return null;
        self.lock.lockExclusive();
        var keep_locked = false;
        defer if (!keep_locked) self.lock.unlockExclusive();

        const target = self.tokenGroupStateForAccountLocked(account, token) orelse return null;
        if (kind == .join_existing and !target.found) return null;
        if (self.tokenGroupHasDropReservationLocked(token)) return null;

        // Reject a duplicate runtime id even when case-variant account keys
        // exist. The ticket must represent a genuinely new claimant.
        var folded_row_count: usize = 0;
        var count_it = self.accounts.iterator();
        while (count_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) continue;
            folded_row_count = std.math.add(
                usize,
                folded_row_count,
                entry.value_ptr.items.items.len,
            ) catch return null;
            if (entry.value_ptr.indexOfClient(client) != null) return null;
        }

        const existing_entry = self.accounts.getEntry(account);
        var staged_account_key: ?[]u8 = null;
        defer if (staged_account_key) |key| self.allocator.free(key);
        var staged_account_list: ?*SessionList = null;
        defer if (staged_account_list) |list| {
            list.deinit(self.allocator);
            self.allocator.destroy(list);
        };
        var list: *SessionList = undefined;
        var evict_index: ?usize = null;
        if (existing_entry) |entry| {
            list = entry.value_ptr;
            if (list.items.items.len >= self.cfg.max_sessions_per_account) {
                evict_index = oldestDetached(list) orelse return null;
            } else {
                list.items.ensureUnusedCapacity(self.allocator, 1) catch return null;
            }
        } else {
            if (self.accounts.count() >= self.cfg.max_accounts or
                self.cfg.max_sessions_per_account == 0) return null;
            self.accounts.ensureUnusedCapacity(1) catch return null;
            staged_account_key = self.allocator.dupe(u8, account) catch return null;
            staged_account_list = self.allocator.create(SessionList) catch return null;
            staged_account_list.?.* = .{};
            staged_account_list.?.items.ensureUnusedCapacity(self.allocator, 1) catch return null;
            list = staged_account_list.?;
        }

        if (evict_index) |index| {
            if (self.sessionOrTokenGroupHasDropReservationLocked(list.items.items[index])) return null;
        }

        var staged_target_token_entry = self.reserveTokenRowInsertLocked(token) catch return null;
        defer if (staged_target_token_entry) |*entry| entry.deinit(self.allocator);
        var projection_storage: ?*LocalChannelProjectionSet = null;
        defer if (projection_storage) |storage| self.allocator.destroy(storage);
        if (!target.local_projections.isEmpty()) {
            projection_storage = self.allocator.create(LocalChannelProjectionSet) catch return null;
            projection_storage.?.* = target.local_projections;
        }

        const preview_count = std.math.add(usize, folded_row_count, 1) catch return null;
        const locked_account_rows = self.allocator.alloc(TokenBindRowSnapshot, preview_count) catch return null;
        var rows_transferred = false;
        defer if (!rows_transferred) self.allocator.free(locked_account_rows);
        var preview_index: usize = 0;
        var rows_it = self.accounts.iterator();
        while (rows_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) continue;
            for (entry.value_ptr.items.items) |row| {
                locked_account_rows[preview_index] = .{
                    .client = row.client,
                    .token = row.token,
                    .attachment_id = row.attachment_id,
                    .attached = row.attached,
                    .portable_resume = row.portable_resume,
                };
                preview_index += 1;
            }
        }
        locked_account_rows[preview_index] = .{
            .client = client,
            .token = token,
            .attachment_id = null,
            .attached = true,
            .portable_resume = switch (kind) {
                .join_existing => target.portable,
                .adopt_verified => |portable| portable or target.portable,
            },
        };

        var detached_source_list: ?*SessionList = null;
        var detached_source_index: ?usize = null;
        var detached_signon: i64 = std.math.minInt(i64);
        if (existing_entry != null) {
            for (list.items.items, 0..) |row, row_index| {
                if (row.attached or row.snapshot == null or
                    !std.crypto.timing_safe.eql(Token, row.token, token)) continue;
                if (detached_source_index == null or row.signon_ms > detached_signon or
                    (row.signon_ms == detached_signon and
                        row.client > list.items.items[detached_source_index.?].client))
                {
                    detached_source_list = list;
                    detached_source_index = row_index;
                    detached_signon = row.signon_ms;
                }
            }
        }
        // A detached exact-token restore replaces that selected ghost even when
        // the account has spare capacity. This transfers, rather than
        // duplicates, the retained physical authority. At cap it is also the
        // only victim; no unrelated detached session is sacrificed.
        if (detached_source_index) |source_index| evict_index = source_index;

        rows_transferred = true;
        const transferred_projection = projection_storage;
        projection_storage = null;
        const transferred_token_entry = staged_target_token_entry;
        staged_target_token_entry = null;
        const transferred_key = staged_account_key;
        staged_account_key = null;
        const transferred_list = staged_account_list;
        staged_account_list = null;
        keep_locked = true;
        return .{
            .store = self,
            .account = if (existing_entry) |entry| entry.key_ptr.* else account,
            .list = list,
            .client = client,
            .token = token,
            .signon_ms = signon_ms,
            .kind = kind,
            .target_portable = target.portable,
            .target_dirty = target.dirty,
            .target_projection_dirty = target.projection_dirty,
            .target_local_projections = target.local_projections,
            .locked_account_rows = locked_account_rows,
            .projection_storage = transferred_projection,
            .staged_target_token_entry = transferred_token_entry,
            .staged_account_key = transferred_key,
            .staged_account_list = transferred_list,
            .evict_index = evict_index,
            .detached_source_list = detached_source_list,
            .detached_source_index = detached_source_index,
        };
    }

    /// Prepare an exact account/client/token bind and retain the exclusive lock
    /// through its later commit/abort boundary. Missing destination journals are
    /// staged here and freed on abort, so `commit` remains allocation-free. A
    /// daemon restore transaction prepares this ticket first, previews the exact
    /// merged local-channel image while its lock excludes stale snapshot races,
    /// then prepares World/output and commits with no error path remaining.
    pub fn prepareTokenBind(
        self: *SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        kind: TokenBindKind,
    ) ?PreparedTokenBind {
        self.lock.lockExclusive();
        var keep_locked = false;
        defer if (!keep_locked) self.lock.unlockExclusive();

        const account_entry = self.accounts.getEntry(account) orelse return null;
        const account_key = account_entry.key_ptr.*;
        const list = account_entry.value_ptr;
        const index = list.indexOfClient(client) orelse return null;
        const claimant = list.items.items[index];
        if (claimant.drop_reservation != 0) return null;
        if (tokenIsSentinel(token)) return null;
        if (self.tokenGroupHasDropReservationLocked(claimant.token)) return null;
        if (self.tokenGroupHasDropReservationLocked(token)) return null;

        // `adopt_verified` proves possession, not permission to relabel another
        // account's exact capability. Case variants remain one account, and
        // join_existing may therefore find its target in an equivalent key.
        const target = self.tokenGroupStateForAccountLocked(account_key, token) orelse return null;
        if (kind == .join_existing and !target.found) return null;
        const claimant_set = if (claimant.local_channel_projections) |set| set.* else LocalChannelProjectionSet{};
        const target_set = target.local_projections;
        var merged_local_projections: LocalChannelProjectionSet = .{};
        // A bind that would exceed the fixed retry budget is refused before the
        // caller stages World changes. No pending channel may be discarded.
        if (!mergeLocalProjectionSets(&merged_local_projections, &claimant_set, &target_set)) return null;
        var staged_target_token_entry = self.reserveTokenRowInsertLocked(token) catch return null;
        var target_token_entry_transferred = false;
        defer if (!target_token_entry_transferred) {
            if (staged_target_token_entry) |*entry| entry.deinit(self.allocator);
        };

        // Capture every row under every ASCII-fold-equivalent account key, not
        // merely `account_entry`'s exact spelling. Account maps intentionally
        // retain display casing, while reusable-token authority is folded; a
        // restore plan built from only one spelling can otherwise miss a live
        // attachment that joins or leaves immediately before this ticket.
        var locked_row_count: usize = 0;
        var count_it = self.accounts.iterator();
        while (count_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account_key)) continue;
            locked_row_count = std.math.add(
                usize,
                locked_row_count,
                entry.value_ptr.items.items.len,
            ) catch return null;
        }
        std.debug.assert(locked_row_count != 0);
        const locked_account_rows = self.allocator.alloc(
            TokenBindRowSnapshot,
            locked_row_count,
        ) catch return null;
        var rows_transferred = false;
        defer if (!rows_transferred) self.allocator.free(locked_account_rows);
        var locked_row_index: usize = 0;
        var rows_it = self.accounts.iterator();
        while (rows_it.next()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.key_ptr.*, account_key)) continue;
            for (entry.value_ptr.items.items) |session| {
                locked_account_rows[locked_row_index] = .{
                    .client = session.client,
                    .token = session.token,
                    .attachment_id = session.attachment_id,
                    .attached = session.attached,
                    .portable_resume = session.portable_resume,
                };
                locked_row_index += 1;
            }
        }
        std.debug.assert(locked_row_index == locked_account_rows.len);
        const RowOrder = struct {
            fn lessThan(_: void, a: TokenBindRowSnapshot, b: TokenBindRowSnapshot) bool {
                return a.client < b.client;
            }
        };
        std.mem.sort(
            TokenBindRowSnapshot,
            locked_account_rows,
            {},
            RowOrder.lessThan,
        );
        // Exact-case account lists enforce unique clients internally, but
        // independently-created case variants can contain the same packed id
        // with conflicting authority. Sorting makes the fail-closed duplicate
        // check linear even if many case spellings reach their individual caps.
        for (locked_account_rows[1..], 1..) |row, row_index| {
            if (locked_account_rows[row_index - 1].client == row.client) return null;
        }

        var staged_local_projection_sets: ?[]*LocalChannelProjectionSet = null;
        if (!merged_local_projections.isEmpty()) {
            var missing: usize = 0;
            if (self.tokenEntryLocked(token)) |target_entry| {
                for (target_entry.rows.items) |locator| {
                    const session = self.sessionForTokenLocatorLocked(locator) orelse return null;
                    if (session.local_channel_projections == null) missing += 1;
                }
            }
            if (!std.crypto.timing_safe.eql(Token, claimant.token, token) and
                claimant.local_channel_projections == null)
            {
                missing += 1;
            }
            if (missing != 0) {
                const staged = self.allocator.alloc(*LocalChannelProjectionSet, missing) catch return null;
                var created: usize = 0;
                while (created < missing) : (created += 1) {
                    staged[created] = self.allocator.create(LocalChannelProjectionSet) catch {
                        for (staged[0..created]) |set| self.allocator.destroy(set);
                        self.allocator.free(staged);
                        return null;
                    };
                    staged[created].* = .{};
                }
                staged_local_projection_sets = staged;
            }
        }
        const result_portable = switch (kind) {
            .join_existing => claimant.portable_resume or target.portable,
            .adopt_verified => |portable| portable or target.portable,
        };
        keep_locked = true;
        rows_transferred = true;
        target_token_entry_transferred = true;
        return .{
            .store = self,
            .account = account_key,
            .list = list,
            .index = index,
            .client = client,
            .expected_token = claimant.token,
            .expected_portable = claimant.portable_resume,
            .expected_dirty = claimant.replica_dirty,
            .expected_projection_dirty = claimant.replica_projection_dirty,
            .expected_local_projection_revision = claimant_set.revision,
            .target_token = token,
            .kind = kind,
            .target_portable = target.portable,
            .target_dirty = target.dirty,
            .target_projection_dirty = target.projection_dirty,
            .target_local_projection_revision = target_set.revision,
            .merged_local_projections = merged_local_projections,
            .locked_account_rows = locked_account_rows,
            .staged_local_projection_sets = staged_local_projection_sets,
            .staged_target_token_entry = staged_target_token_entry,
            .result_portable = result_portable,
        };
    }

    /// Mark an opted-in logical session dirty before publishing its next signed
    /// replica. The operation is all-or-nothing: a token with no portable local
    /// row is rejected and no row is modified. Once eligible, every exact-token
    /// row is marked so a mutation from any sibling survives that sibling's
    /// removal or migration.
    pub fn markTokenReplicaDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found or !state.portable) return false;
        self.setTokenGroupDirtyLocked(token, true);
        return true;
    }

    /// Clear an exact token group only after the caller's signed replica was
    /// synchronously accepted. Returns false only when no local row bears the
    /// token; clearing an already-clean group is idempotent.
    pub fn clearTokenReplicaDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return false;
        self.setTokenGroupDirtyLocked(token, false);
        return true;
    }

    /// Whether an exact token group still has an unpublished local mutation.
    /// Deferred mesh sidecars consult this after checking their bound token so
    /// an older same-origin Store row can never masquerade as acceptance of the
    /// current restored snapshot.
    pub fn tokenReplicaDirty(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.tokenGroupStateLocked(token).dirty;
    }

    pub fn tokenReplicaProjectionDirty(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.tokenGroupStateLocked(token).projection_dirty;
    }

    /// Copy at most `out.len` unique dirty portable tokens into caller storage.
    /// `replica_dirty` can only be minted after group portability was verified,
    /// so it remains the durable eligibility proof if the issuing sibling is
    /// removed before retry. No allocation occurs and the returned slice borrows
    /// `out`; a dirty token remains visible until explicitly cleared.
    pub fn dirtyPortableTokensInto(self: *SessionStore, out: []Token) []const Token {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        return self.dirtyTokensIntoLocked(out, .publish);
    }

    /// Mark one exact current attachment for SRA3 publication. Group
    /// portability remains the credential gate, but retry ownership is per row.
    pub fn markAttachmentReplicaDirty(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (attachment_id.isZero() or !self.tokenGroupStateLocked(token).portable) return false;
        const session = self.findAttachmentLocked(token, attachment_id) orelse return false;
        if (!session.attachment_replica_dirty) {
            session.attachment_replica_dirty = true;
            self.dirty_attachment_replica_rows += 1;
        }
        return true;
    }

    /// Arm every current physical sibling when a group first becomes portable.
    /// Allocation-free and idempotent; legacy null-id rows are deliberately
    /// skipped because they cannot be represented by SRA3.
    pub fn markTokenAttachmentReplicasDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        return self.markTokenAttachmentReplicasDirtyLocked(token);
    }

    pub fn clearAttachmentReplicaDirty(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const session = self.findAttachmentLocked(token, attachment_id) orelse return false;
        if (session.attachment_replica_dirty) {
            session.attachment_replica_dirty = false;
            std.debug.assert(self.dirty_attachment_replica_rows != 0);
            self.dirty_attachment_replica_rows -= 1;
        }
        return true;
    }

    pub fn dirtyPortableAttachmentsInto(
        self: *SessionStore,
        out: []AttachmentReplicaWork,
    ) []const AttachmentReplicaWork {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        return self.dirtyAttachmentsIntoLocked(out, .publish);
    }

    pub fn markAttachmentReplicaProjectionDirty(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const session = self.findAttachmentLocked(token, attachment_id) orelse return false;
        if (!session.attachment_replica_projection_dirty) {
            session.attachment_replica_projection_dirty = true;
            self.dirty_attachment_projection_rows += 1;
        }
        return true;
    }

    pub fn clearAttachmentReplicaProjectionDirty(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const session = self.findAttachmentLocked(token, attachment_id) orelse return false;
        if (session.attachment_replica_projection_dirty) {
            session.attachment_replica_projection_dirty = false;
            std.debug.assert(self.dirty_attachment_projection_rows != 0);
            self.dirty_attachment_projection_rows -= 1;
        }
        return true;
    }

    pub fn dirtyAttachmentProjectionsInto(
        self: *SessionStore,
        out: []AttachmentReplicaWork,
    ) []const AttachmentReplicaWork {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        return self.dirtyAttachmentsIntoLocked(out, .projection);
    }

    /// Arm one physical attachment's channel projection journal. Siblings with
    /// the same reusable token are deliberately untouched.
    pub fn armAttachmentLocalChannelProjectionWithPrevious(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
        channel: []const u8,
        present: bool,
        member_mode_bits: u8,
    ) LocalProjectionArmError!LocalChannelProjectionArm {
        if (channel.len == 0 or channel.len > local_channel_name_capacity)
            return error.InvalidChannel;
        if (attachment_id.isZero()) return error.NoSuchAttachment;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const session = self.findAttachmentLocked(token, attachment_id) orelse
            return error.NoSuchAttachment;
        var next = if (session.attachment_channel_projections) |set| set.* else LocalChannelProjectionSet{};
        const existing_index = localProjectionIndex(&next, channel);
        const previous = if (existing_index) |index| next.items[index] else null;
        if (existing_index == null and next.len == local_channel_projection_capacity)
            return error.TooManyPendingChannels;

        // Allocate the first journal before consuming a generation or changing
        // counters. Replacement and later retry/clear remain allocation-free.
        const staged = if (session.attachment_channel_projections == null) blk: {
            const storage = try self.allocator.create(LocalChannelProjectionSet);
            storage.* = .{};
            break :blk storage;
        } else null;
        errdefer if (staged) |storage| self.allocator.destroy(storage);

        const generation = self.nextLocalProjectionGenerationLocked();
        var intent = LocalChannelProjection{
            .generation = generation,
            .channel_len = @intCast(channel.len),
            .channel_bytes = @splat(0),
            .present = present,
            .member_mode_bits = member_mode_bits,
        };
        @memcpy(intent.channel_bytes[0..channel.len], channel);
        localProjectionUpsert(&next, intent) catch unreachable;
        next.revision = generation;
        if (staged) |storage| session.attachment_channel_projections = storage;
        self.setAttachmentLocalProjectionsLocked(session, &next);
        return .{ .intent = intent, .previous = previous };
    }

    pub fn armAttachmentLocalChannelProjection(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
        channel: []const u8,
        present: bool,
        member_mode_bits: u8,
    ) LocalProjectionArmError!LocalChannelProjection {
        return (try self.armAttachmentLocalChannelProjectionWithPrevious(
            token,
            attachment_id,
            channel,
            present,
            member_mode_bits,
        )).intent;
    }

    pub fn attachmentLocalChannelProjection(
        self: *const SessionStore,
        token: Token,
        attachment_id: AttachmentId,
        channel: []const u8,
    ) ?LocalChannelProjection {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const session = @constCast(self).findAttachmentLocked(token, attachment_id) orelse return null;
        const set = session.attachment_channel_projections orelse return null;
        const index = localProjectionIndex(set, channel) orelse return null;
        return set.items[index];
    }

    pub fn clearAttachmentLocalChannelProjection(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
        channel: []const u8,
        generation: u64,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const session = self.findAttachmentLocked(token, attachment_id) orelse return false;
        const storage = session.attachment_channel_projections orelse return false;
        var next = storage.*;
        const index = localProjectionIndex(&next, channel) orelse return false;
        if (next.items[index].generation != generation) return false;
        localProjectionRemoveAt(&next, index);
        next.revision = self.nextLocalProjectionGenerationLocked();
        self.setAttachmentLocalProjectionsLocked(session, &next);
        return true;
    }

    pub fn rollbackAttachmentLocalChannelProjectionArm(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
        armed_generation: u64,
        previous: ?LocalChannelProjection,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const session = self.findAttachmentLocked(token, attachment_id) orelse return false;
        const storage = session.attachment_channel_projections orelse return false;
        var next = storage.*;
        const armed_channel = if (previous) |prior| prior.channel() else blk: {
            for (next.slice()) |projection| {
                if (projection.generation == armed_generation) break :blk projection.channel();
            }
            return false;
        };
        const index = localProjectionIndex(&next, armed_channel) orelse return false;
        if (next.items[index].generation != armed_generation) return false;
        if (previous) |prior| {
            if (!std.ascii.eqlIgnoreCase(prior.channel(), next.items[index].channel())) return false;
            next.items[index] = prior;
        } else {
            localProjectionRemoveAt(&next, index);
        }
        next.revision = self.nextLocalProjectionGenerationLocked();
        self.setAttachmentLocalProjectionsLocked(session, &next);
        return true;
    }

    pub fn dirtyAttachmentLocalProjectionsInto(
        self: *SessionStore,
        out: []AttachmentLocalChannelProjectionWork,
    ) []const AttachmentLocalChannelProjectionWork {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.dirty_attachment_local_projection_rows == 0 or out.len == 0) return out[0..0];

        var n: usize = 0;
        const original_cursor = self.attachment_local_projection_scan_cursor;
        var wrapped = original_cursor == null;
        var lower_bound = original_cursor;
        while (n < out.len) {
            var candidate: ?AttachmentLocalChannelProjectionWork = null;
            var accounts = self.accounts.valueIterator();
            while (accounts.next()) |list| {
                for (list.items.items) |session| {
                    const attachment_id = session.attachment_id orelse continue;
                    const set = session.attachment_channel_projections orelse continue;
                    for (set.slice()) |projection| {
                        const work = AttachmentLocalChannelProjectionWork{
                            .token = session.token,
                            .attachment_id = attachment_id,
                            .projection = projection,
                        };
                        if (attachmentLocalWorkInSlice(out[0..n], work)) continue;
                        if (lower_bound) |lower| {
                            if (attachmentLocalWorkOrder(work, lower) != .gt) continue;
                        }
                        if (wrapped) {
                            if (original_cursor) |upper| {
                                if (attachmentLocalWorkOrder(work, upper) == .gt) continue;
                            }
                        }
                        if (candidate == null or attachmentLocalWorkOrder(work, candidate.?) == .lt)
                            candidate = work;
                    }
                }
            }
            if (candidate) |work| {
                out[n] = work;
                n += 1;
                lower_bound = work;
                continue;
            }
            if (wrapped) break;
            wrapped = true;
            lower_bound = null;
        }
        if (n != 0) self.attachment_local_projection_scan_cursor = out[n - 1];
        return out[0..n];
    }

    /// Mark receive-side projection pending after a signed replica was accepted.
    /// Store acceptance is the authority, so unlike publish dirtiness this does
    /// not require a locally issued portable credential.
    pub fn markTokenReplicaProjectionDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return false;
        self.setTokenGroupProjectionDirtyLocked(token, true);
        return true;
    }

    /// Clear receive-side projection retry only after every applicable local
    /// attachment accepted the snapshot. Idempotent for an existing group.
    pub fn clearTokenReplicaProjectionDirty(self: *SessionStore, token: Token) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return false;
        self.setTokenGroupProjectionDirtyLocked(token, false);
        return true;
    }

    /// Fair, bounded, allocation-free projection retry collection. This cursor
    /// is independent from `dirtyPortableTokensInto`.
    pub fn dirtyProjectionTokensInto(self: *SessionStore, out: []Token) []const Token {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        return self.dirtyTokensIntoLocked(out, .projection);
    }

    /// Arm or replace one desired local channel image for every row bearing
    /// `token`. This accepts non-portable groups: same-node multi-client
    /// convergence must not depend on a mesh-sealed credential.
    ///
    /// Missing per-row journals are allocated transactionally. Invalid input,
    /// OOM, or a ninth distinct unresolved channel leaves every row, generation,
    /// and counter unchanged. A case-insensitive replacement always succeeds at
    /// capacity once the journals exist.
    pub fn armTokenLocalChannelProjection(
        self: *SessionStore,
        token: Token,
        channel: []const u8,
        present: bool,
        member_mode_bits: u8,
    ) LocalProjectionArmError!LocalChannelProjection {
        return (try self.armTokenLocalChannelProjectionWithPrevious(
            token,
            channel,
            present,
            member_mode_bits,
        )).intent;
    }

    /// Arm exactly like `armTokenLocalChannelProjection`, atomically returning
    /// the prior same-channel intent for allocation-free pre-mutation rollback.
    pub fn armTokenLocalChannelProjectionWithPrevious(
        self: *SessionStore,
        token: Token,
        channel: []const u8,
        present: bool,
        member_mode_bits: u8,
    ) LocalProjectionArmError!LocalChannelProjectionArm {
        if (channel.len == 0 or channel.len > local_channel_name_capacity)
            return error.InvalidChannel;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const state = self.tokenGroupStateLocked(token);
        if (!state.found) return error.NoSuchToken;
        var next = state.local_projections;
        const existing_index = localProjectionIndex(&next, channel);
        const previous = if (existing_index) |index| next.items[index] else null;
        if (existing_index == null and next.len == local_channel_projection_capacity)
            return error.TooManyPendingChannels;

        const token_entry = self.tokenEntryMutLocked(token) orelse return error.NoSuchToken;
        var missing: usize = 0;
        for (token_entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
            if (session.local_channel_projections == null) missing += 1;
        }

        var staged: ?[]*LocalChannelProjectionSet = null;
        var staged_transferred = false;
        defer if (staged) |sets| {
            if (!staged_transferred) for (sets) |set| self.allocator.destroy(set);
            self.allocator.free(sets);
        };
        if (missing != 0) {
            const sets = try self.allocator.alloc(*LocalChannelProjectionSet, missing);
            errdefer self.allocator.free(sets);
            var created: usize = 0;
            errdefer for (sets[0..created]) |set| self.allocator.destroy(set);
            while (created < missing) : (created += 1) {
                sets[created] = try self.allocator.create(LocalChannelProjectionSet);
                sets[created].* = .{};
            }
            staged = sets;
        }

        const generation = self.nextLocalProjectionGenerationLocked();
        var intent = LocalChannelProjection{
            .generation = generation,
            .channel_len = @intCast(channel.len),
            .channel_bytes = @splat(0),
            .present = present,
            .member_mode_bits = member_mode_bits,
        };
        @memcpy(intent.channel_bytes[0..channel.len], channel);
        localProjectionUpsert(&next, intent) catch unreachable;
        next.revision = generation;

        if (staged) |sets| {
            var staged_index: usize = 0;
            for (token_entry.rows.items) |locator| {
                self.noteTokenGroupRowVisit();
                const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
                if (session.local_channel_projections != null) continue;
                session.local_channel_projections = sets[staged_index];
                staged_index += 1;
            }
            std.debug.assert(staged_index == sets.len);
            staged_transferred = true;
        }
        self.setTokenGroupLocalProjectionsLocked(token, &next);
        return .{ .intent = intent, .previous = previous };
    }

    /// Copy one pending channel image. Matching uses the daemon's current ASCII
    /// case-insensitive channel semantics; the returned value owns its bytes.
    pub fn tokenLocalChannelProjection(
        self: *const SessionStore,
        token: Token,
        channel: []const u8,
    ) ?LocalChannelProjection {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const set = self.tokenGroupStateLocked(token).local_projections;
        const index = localProjectionIndex(&set, channel) orelse return null;
        return set.items[index];
    }

    /// Copy every pending image for one token into caller-owned storage.
    pub fn tokenLocalChannelProjectionsInto(
        self: *const SessionStore,
        token: Token,
        out: []LocalChannelProjection,
    ) []const LocalChannelProjection {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const set = self.tokenGroupStateLocked(token).local_projections;
        const count = @min(out.len, set.len);
        @memcpy(out[0..count], set.items[0..count]);
        return out[0..count];
    }

    /// Compare-and-clear a completed local projection. A stale retry cannot
    /// erase a newer replacement or another channel's pending intent.
    pub fn clearTokenLocalChannelProjection(
        self: *SessionStore,
        token: Token,
        channel: []const u8,
        generation: u64,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var next = self.tokenGroupStateLocked(token).local_projections;
        const index = localProjectionIndex(&next, channel) orelse return false;
        if (next.items[index].generation != generation) return false;
        localProjectionRemoveAt(&next, index);
        next.revision = self.nextLocalProjectionGenerationLocked();
        self.setTokenGroupLocalProjectionsLocked(token, &next);
        return true;
    }

    /// Undo one still-current arm before its producer mutates live state. The
    /// generation CAS prevents a failed older producer from overwriting newer
    /// accepted work. Arm already allocated every row journal, so restoring a
    /// previous value (or removing a newly-added channel) cannot allocate.
    pub fn rollbackTokenLocalChannelProjectionArm(
        self: *SessionStore,
        token: Token,
        armed_generation: u64,
        previous: ?LocalChannelProjection,
    ) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var next = self.tokenGroupStateLocked(token).local_projections;
        const armed_channel = if (previous) |prior| prior.channel() else blk: {
            for (next.slice()) |projection| {
                if (projection.generation == armed_generation) break :blk projection.channel();
            }
            return false;
        };
        const index = localProjectionIndex(&next, armed_channel) orelse return false;
        if (next.items[index].generation != armed_generation) return false;
        if (previous) |prior| {
            std.debug.assert(std.ascii.eqlIgnoreCase(prior.channel(), next.items[index].channel()));
            next.items[index] = prior;
        } else {
            localProjectionRemoveAt(&next, index);
        }
        next.revision = self.nextLocalProjectionGenerationLocked();
        self.setTokenGroupLocalProjectionsLocked(token, &next);
        return true;
    }

    /// Fair, bounded, allocation-free collection of exact (token, channel)
    /// work. Its value cursor is independent from both signed-replica lanes.
    pub fn dirtyLocalProjectionsInto(
        self: *SessionStore,
        out: []LocalChannelProjectionWork,
    ) []const LocalChannelProjectionWork {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        if (self.dirty_local_projection_rows == 0 or out.len == 0) return out[0..0];

        var n: usize = 0;
        const original_cursor = self.local_projection_scan_cursor;
        var wrapped = original_cursor == null;
        var lower_bound = original_cursor;
        while (n < out.len) {
            var candidate: ?LocalChannelProjectionWork = null;
            var accounts = self.accounts.iterator();
            while (accounts.next()) |entry| {
                for (entry.value_ptr.items.items) |session| {
                    const set = session.local_channel_projections orelse continue;
                    for (set.slice()) |projection| {
                        const work = LocalChannelProjectionWork{ .token = session.token, .projection = projection };
                        if (localWorkInSlice(out[0..n], work)) continue;
                        if (lower_bound) |lower| {
                            if (localWorkOrder(work, lower) != .gt) continue;
                        }
                        if (wrapped) {
                            if (original_cursor) |upper| {
                                if (localWorkOrder(work, upper) == .gt) continue;
                            }
                        }
                        if (candidate == null or localWorkOrder(work, candidate.?) == .lt)
                            candidate = work;
                    }
                }
            }
            if (candidate) |work| {
                out[n] = work;
                n += 1;
                lower_bound = work;
                continue;
            }
            if (wrapped) break;
            wrapped = true;
            lower_bound = null;
        }
        if (n != 0) self.local_projection_scan_cursor = out[n - 1];
        return out[0..n];
    }

    const DirtyKind = enum { publish, projection };
    const AttachmentDirtyKind = enum { publish, projection };

    fn findAttachmentLocked(
        self: *SessionStore,
        token: Token,
        attachment_id: AttachmentId,
    ) ?*Session {
        const locator = self.attachment_index.get(attachment_id.raw) orelse return null;
        const list = self.accounts.getPtr(locator.account) orelse return null;
        const index = list.indexOfClient(locator.client) orelse return null;
        const session = &list.items.items[index];
        if (!sessionMatchesAttachment(session.*, token, attachment_id)) return null;
        return session;
    }

    fn dirtyAttachmentsIntoLocked(
        self: *SessionStore,
        out: []AttachmentReplicaWork,
        kind: AttachmentDirtyKind,
    ) []const AttachmentReplicaWork {
        const dirty_rows = switch (kind) {
            .publish => self.dirty_attachment_replica_rows,
            .projection => self.dirty_attachment_projection_rows,
        };
        if (dirty_rows == 0 or out.len == 0) return out[0..0];
        const cursor = switch (kind) {
            .publish => &self.attachment_replica_scan_cursor,
            .projection => &self.attachment_projection_scan_cursor,
        };

        var n: usize = 0;
        const original_cursor = cursor.*;
        var wrapped = original_cursor == null;
        var lower_bound = original_cursor;
        while (n < out.len) {
            var candidate: ?AttachmentReplicaWork = null;
            var accounts = self.accounts.valueIterator();
            while (accounts.next()) |list| {
                for (list.items.items) |session| {
                    const attachment_id = session.attachment_id orelse continue;
                    const dirty = switch (kind) {
                        .publish => session.attachment_replica_dirty,
                        .projection => session.attachment_replica_projection_dirty,
                    };
                    if (!dirty) continue;
                    const work = AttachmentReplicaWork{
                        .token = session.token,
                        .attachment_id = attachment_id,
                    };
                    if (attachmentWorkInSlice(out[0..n], work)) continue;
                    if (lower_bound) |lower| {
                        if (attachmentWorkOrder(work, lower) != .gt) continue;
                    }
                    if (wrapped) {
                        if (original_cursor) |upper| {
                            if (attachmentWorkOrder(work, upper) == .gt) continue;
                        }
                    }
                    if (candidate == null or attachmentWorkOrder(work, candidate.?) == .lt)
                        candidate = work;
                }
            }
            if (candidate) |work| {
                out[n] = work;
                n += 1;
                lower_bound = work;
                continue;
            }
            if (wrapped) break;
            wrapped = true;
            lower_bound = null;
        }
        if (n != 0) cursor.* = out[n - 1];
        return out[0..n];
    }

    fn dirtyTokensIntoLocked(self: *SessionStore, out: []Token, kind: DirtyKind) []const Token {
        const dirty_rows = switch (kind) {
            .publish => self.dirty_replica_rows,
            .projection => self.dirty_projection_rows,
        };
        if (dirty_rows == 0 or out.len == 0) return out[0..0];

        const cursor_ptr = switch (kind) {
            .publish => &self.dirty_scan_cursor,
            .projection => &self.projection_scan_cursor,
        };
        var n: usize = 0;
        const original_cursor = cursor_ptr.*;
        var wrapped = original_cursor == null;
        var lower_bound = original_cursor;
        while (n < out.len) {
            var candidate: ?Token = null;
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                for (entry.value_ptr.items.items) |session| {
                    if (!sessionDirty(session, kind)) continue;
                    if (tokenInSlice(out[0..n], session.token)) continue;

                    if (lower_bound) |lower| {
                        if (std.mem.order(u8, &session.token, &lower) != .gt) continue;
                    }
                    if (wrapped) {
                        if (original_cursor) |upper| {
                            if (std.mem.order(u8, &session.token, &upper) == .gt) continue;
                        }
                    }
                    if (candidate == null or std.mem.order(u8, &session.token, &candidate.?) == .lt) {
                        candidate = session.token;
                    }
                }
            }

            if (candidate) |token| {
                out[n] = token;
                n += 1;
                lower_bound = token;
                continue;
            }
            if (wrapped) break;
            // Complete the circular scan at the smallest token. The ordering is
            // by token value, not hash-map position, so this remains fair even
            // when the previous cursor token was removed between calls.
            wrapped = true;
            lower_bound = null;
        }

        if (n != 0) cursor_ptr.* = out[n - 1];
        return out[0..n];
    }

    fn sessionDirty(session: Session, kind: DirtyKind) bool {
        return switch (kind) {
            .publish => session.replica_dirty,
            .projection => session.replica_projection_dirty,
        };
    }

    fn tokenInSlice(tokens: []const Token, needle: Token) bool {
        for (tokens) |token| {
            if (std.crypto.timing_safe.eql(Token, token, needle)) return true;
        }
        return false;
    }

    /// Exact count of dirty rows. Exposed for scheduling/diagnostics; callers
    /// needing unique tokens must use `dirtyPortableTokensInto`.
    pub fn dirtyReplicaRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_replica_rows;
    }

    pub fn dirtyReplicaProjectionRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_projection_rows;
    }

    pub fn dirtyLocalProjectionRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_local_projection_rows;
    }

    pub fn dirtyAttachmentLocalProjectionRowCount(self: *const SessionStore) usize {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        return self.dirty_attachment_local_projection_rows;
    }

    /// Whether this exact attached client already belongs to `token`'s logical
    /// session. Kept separate from token lookup because duplicate tokens across
    /// live attachments are intentional.
    pub fn clientHasToken(self: *const SessionStore, account: []const u8, client: ClientId, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        return std.crypto.timing_safe.eql(Token, list.items.items[idx].token, token);
    }

    /// Exact current-identity probe. Unlike `clientHasToken`, this cannot
    /// collapse two sibling physical attachments sharing one reusable token.
    pub fn clientHasAttachment(
        self: *const SessionStore,
        account: []const u8,
        client: ClientId,
        token: Token,
        attachment_id: AttachmentId,
    ) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        if (attachment_id.isZero()) return false;
        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(client) orelse return false;
        return sessionMatchesAttachment(list.items.items[idx], token, attachment_id);
    }

    /// Whether this stable id is already owned anywhere in the local store.
    /// Current claim/create paths use this to distinguish exact restore from an
    /// identity collision without exposing the owning account or token.
    pub fn containsAttachment(self: *const SessionStore, attachment_id: AttachmentId) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        if (attachment_id.isZero()) return false;
        return self.attachmentOwnerLocked(attachment_id) != null;
    }

    /// Whether any live attachment currently holds this exact logical token.
    /// Positive mesh attachment leases must cross this allocation-free boundary
    /// instead of trusting a caller that may already have detached its row.
    pub fn tokenHasAttachedPortable(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const entry = self.tokenEntryLocked(token) orelse return false;
        if (entry.portable_rows == 0) return false;
        for (entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = @constCast(self).sessionForTokenLocatorLocked(locator) orelse unreachable;
            if (session.attached) return true;
        }
        return false;
    }

    /// Whether any attached or detached row still owns this exact token.
    /// The daemon uses this allocation-free probe to retry a local-origin REVOKE
    /// after the final row has already been deleted and can no longer carry a
    /// row-backed dirty bit.
    pub fn containsToken(self: *const SessionStore, token: Token) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        return self.tokenEntryLocked(token) != null;
    }

    /// Exact client membership probe that does not truncate at the public list
    /// snapshot size. Session tracking uses this so high configured caps cannot
    /// accidentally mint a second token for an already-tracked client.
    pub fn containsClient(self: *const SessionStore, account: []const u8, client: ClientId) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return false;
        return list.indexOfClient(client) != null;
    }

    /// Fully remove a session (e.g. explicit logout / reclaim consumed). Prunes
    /// the account when its last session goes. Returns true if removed.
    pub fn remove(self: *SessionStore, account: []const u8, client: ClientId) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOfClient(client) orelse return false;
        if (self.sessionOrTokenGroupHasDropReservationLocked(entry.value_ptr.items.items[idx])) return false;
        self.removeDirtyRowLocked(&entry.value_ptr.items.items[idx]);
        self.removeTokenRowLocked(entry.key_ptr.*, entry.value_ptr.items.items[idx], false);
        self.removeAttachmentIndexLocked(entry.value_ptr.items.items[idx]);
        freeSessionOwned(self.allocator, &entry.value_ptr.items.items[idx]);
        _ = entry.value_ptr.items.swapRemove(idx);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return true;
    }

    /// Remove exactly the physical row observed by SESSION LIST. A recycled
    /// client id, rotated token, reminted attachment, or changed signon cannot
    /// turn a stale selector into a different revoke target.
    pub fn removeExact(self: *SessionStore, account: []const u8, expected: Session) ?ResumeHandle {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.accounts.getEntry(account) orelse return null;
        const idx = entry.value_ptr.indexOfClient(expected.client) orelse return null;
        const row = entry.value_ptr.items.items[idx];
        if (self.sessionOrTokenGroupHasDropReservationLocked(row)) return null;
        const attachment_matches = if (expected.attachment_id) |attachment|
            row.attachment_id != null and attachment.eql(row.attachment_id.?)
        else
            row.attachment_id == null;
        if (row.signon_ms != expected.signon_ms or
            !std.crypto.timing_safe.eql(Token, row.token, expected.token) or
            !attachment_matches) return null;
        const handle = ResumeHandle{ .token = row.token, .attachment_id = row.attachment_id, .portable = row.portable_resume };
        self.removeDirtyRowLocked(&entry.value_ptr.items.items[idx]);
        self.removeTokenRowLocked(entry.key_ptr.*, entry.value_ptr.items.items[idx], false);
        self.removeAttachmentIndexLocked(entry.value_ptr.items.items[idx]);
        freeSessionOwned(self.allocator, &entry.value_ptr.items.items[idx]);
        _ = entry.value_ptr.items.swapRemove(idx);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return handle;
    }

    /// Reserve one exact physical row for the short-lived two-owner DROP
    /// transaction. Reservation is idempotent for its owner and exclusive for
    /// competitors; stale selectors never mutate a current row.
    pub fn reserveDrop(self: *SessionStore, account: []const u8, expected: ExactSelector, id: DropReservationId) ReserveDropResult {
        if (id == 0) return .invalid_id;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.accounts.getEntry(account) orelse return .stale;
        const idx = entry.value_ptr.indexOfClient(expected.client) orelse return .stale;
        const row = &entry.value_ptr.items.items[idx];
        if (!sessionMatchesExact(row.*, expected)) return .stale;
        if (row.drop_reservation == 0) {
            row.drop_reservation = id;
            if (self.tokenEntryMutLocked(row.token)) |group| group.drop_reserved_rows += 1;
            return .reserved;
        }
        return if (row.drop_reservation == id) .already_reserved else .reserved_by_other;
    }

    pub fn validateDropReservation(self: *const SessionStore, account: []const u8, expected: ExactSelector, id: DropReservationId) bool {
        if (id == 0) return false;
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(expected.client) orelse return false;
        const row = list.items.items[idx];
        return row.drop_reservation == id and sessionMatchesExact(row, expected);
    }

    pub fn hasDropReservation(self: *const SessionStore, account: []const u8, expected: ExactSelector) bool {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();
        const list = self.accounts.getPtr(account) orelse return false;
        const idx = list.indexOfClient(expected.client) orelse return false;
        const row = list.items.items[idx];
        return row.drop_reservation != 0 and sessionMatchesExact(row, expected);
    }

    /// Cancel is owner-only and idempotent for an already absent/stale row.
    /// A competing transaction can never clear another owner's reservation.
    pub fn cancelDropReservation(self: *SessionStore, account: []const u8, expected: ExactSelector, id: DropReservationId) bool {
        if (id == 0) return false;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.accounts.getEntry(account) orelse return false;
        const idx = entry.value_ptr.indexOfClient(expected.client) orelse return false;
        const row = &entry.value_ptr.items.items[idx];
        if (!sessionMatchesExact(row.*, expected) or row.drop_reservation != id) return false;
        row.drop_reservation = 0;
        if (self.tokenEntryMutLocked(row.token)) |group| {
            std.debug.assert(group.drop_reserved_rows != 0);
            group.drop_reserved_rows -= 1;
        }
        return true;
    }

    /// Commit the exact row only when the owning transaction still holds its
    /// reservation. Cleanup matches `removeExact`; no other reservation or
    /// stale selector can remove/mutate the row.
    pub fn commitDropReservation(self: *SessionStore, account: []const u8, expected: ExactSelector, id: DropReservationId) ?ResumeHandle {
        if (id == 0) return null;
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.accounts.getEntry(account) orelse return null;
        const idx = entry.value_ptr.indexOfClient(expected.client) orelse return null;
        const row = entry.value_ptr.items.items[idx];
        if (row.drop_reservation != id or !sessionMatchesExact(row, expected)) return null;
        const handle = ResumeHandle{ .token = row.token, .attachment_id = row.attachment_id, .portable = row.portable_resume };
        self.removeDirtyRowLocked(&entry.value_ptr.items.items[idx]);
        self.removeTokenRowLocked(entry.key_ptr.*, entry.value_ptr.items.items[idx], false);
        self.removeAttachmentIndexLocked(entry.value_ptr.items.items[idx]);
        freeSessionOwned(self.allocator, &entry.value_ptr.items.items[idx]);
        _ = entry.value_ptr.items.swapRemove(idx);
        if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
        return handle;
    }

    /// Drop a client from whatever account holds it (disconnect path, when the
    /// caller may not know the account). Returns the account name match count (0/1).
    pub fn removeClient(self: *SessionStore, client: ClientId) usize {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();

        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.indexOfClient(client)) |idx| {
                if (self.sessionOrTokenGroupHasDropReservationLocked(entry.value_ptr.items.items[idx])) return 0;
                self.removeDirtyRowLocked(&entry.value_ptr.items.items[idx]);
                self.removeTokenRowLocked(entry.key_ptr.*, entry.value_ptr.items.items[idx], false);
                self.removeAttachmentIndexLocked(entry.value_ptr.items.items[idx]);
                freeSessionOwned(self.allocator, &entry.value_ptr.items.items[idx]);
                _ = entry.value_ptr.items.swapRemove(idx);
                if (entry.value_ptr.items.items.len == 0) self.dropAccount(entry);
                return 1;
            }
        }
        return 0;
    }

    /// Copy a snapshot of the session list for `account` into caller-owned
    /// storage (empty if none). The returned slice borrows `out`, not the store;
    /// every store-owned snapshot/journal pointer is stripped.
    pub fn sessionsInto(self: *const SessionStore, account: []const u8, out: []Session) []const Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return out[0..0];
        const n = @min(list.items.items.len, out.len);
        @memcpy(out[0..n], list.items.items[0..n]);
        for (out[0..n]) |*session| sanitizeCopiedSession(session);
        return out[0..n];
    }

    /// Allocate an exact, complete snapshot for callers whose correctness cannot
    /// depend on a fixed stack buffer. All owned payload/journal pointers are
    /// stripped; use the dedicated copy/value APIs for their state.
    pub fn copySessionsAlloc(self: *const SessionStore, allocator: std.mem.Allocator, account: []const u8) std.mem.Allocator.Error![]Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return try allocator.alloc(Session, 0);
        const out = try allocator.alloc(Session, list.items.items.len);
        @memcpy(out, list.items.items);
        for (out) |*session| sanitizeCopiedSession(session);
        return out;
    }

    pub const Match = struct { account: []const u8, client: ClientId };

    pub const TokenMatch = struct { account: []const u8, token: Token };

    pub const TokenPredicate = struct {
        context: *const anyopaque,
        matches_fn: *const fn (context: *const anyopaque, token: Token) bool,

        pub fn matches(self: TokenPredicate, token: Token) bool {
            return self.matches_fn(self.context, token);
        }
    };

    /// Select one exact portable token by an opaque caller-owned capability
    /// predicate. Multiple attachment rows carrying the SAME token are one
    /// logical session; two distinct matching tokens are ambiguous and fail
    /// closed. The returned account borrows `account_out`, never store memory.
    pub fn findUniquePortableTokenInto(
        self: *const SessionStore,
        predicate: TokenPredicate,
        account_out: []u8,
    ) ?TokenMatch {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        var matched_token: ?Token = null;
        var matched_account_len: usize = 0;
        var it = self.token_index.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.portable_rows == 0 or !predicate.matches(entry.key_ptr.*)) continue;
            if (matched_token != null) return null;
            const account = entry.value_ptr.rows.items[0].account;
            if (account.len > account_out.len) return null;
            @memcpy(account_out[0..account.len], account);
            matched_account_len = account.len;
            matched_token = entry.key_ptr.*;
        }
        return .{
            .account = account_out[0..matched_account_len],
            .token = matched_token orelse return null,
        };
    }

    /// Find the session bearing `token` (for reclaim). The returned `account`
    /// borrows `account_out`, not the store.
    pub fn findByTokenInto(self: *const SessionStore, token: Token, account_out: []u8) ?Match {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const entry = self.tokenEntryLocked(token) orelse return null;
        const locator = entry.rows.items[0];
        if (locator.account.len > account_out.len) return null;
        @memcpy(account_out[0..locator.account.len], locator.account);
        return .{ .account = account_out[0..locator.account.len], .client = locator.client };
    }

    /// Look up a session by token *within* `account` (reclaim is scoped to the
    /// caller's own account — a token never reaches across accounts). Returns the
    /// matched client id, or null if no session in `account` bears the token.
    pub fn findTokenInAccount(self: *const SessionStore, account: []const u8, token: Token) ?ClientId {
        return if (self.findTokenSessionInAccount(account, token)) |s| s.client else null;
    }

    /// Look up a session by token *within* `account`, returning a copied snapshot
    /// so callers can distinguish attached live sessions from detached ghosts.
    pub fn findTokenSessionInAccount(self: *const SessionStore, account: []const u8, token: Token) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |s| {
            if (std.crypto.timing_safe.eql(Token, s.token, token)) {
                var copied = s;
                sanitizeCopiedSession(&copied);
                return copied;
            }
        }
        return null;
    }

    /// Look up one exact physical attachment within a reusable token group.
    /// Legacy rows (no id) never match and must use the compatibility APIs.
    pub fn findAttachmentSessionInAccount(
        self: *const SessionStore,
        account: []const u8,
        token: Token,
        attachment_id: AttachmentId,
    ) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        if (attachment_id.isZero()) return null;
        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |session| {
            if (!sessionMatchesAttachment(session, token, attachment_id)) continue;
            var copied = session;
            sanitizeCopiedSession(&copied);
            return copied;
        }
        return null;
    }

    /// Find the exact detached attachment selected by a current resume claim.
    /// No newest/oldest heuristic is permitted: sibling rows are independent.
    pub fn findDetachedAttachmentSessionInAccount(
        self: *const SessionStore,
        account: []const u8,
        token: Token,
        attachment_id: AttachmentId,
    ) ?Session {
        const session = self.findAttachmentSessionInAccount(account, token, attachment_id) orelse return null;
        return if (!session.attached) session else null;
    }

    /// Find a LIVE attachment to `token`, excluding the caller. A stable session
    /// credential is reusable, so this is the source from which a second client
    /// clones current state and joins the same live token group.
    pub fn findAttachedTokenSessionInAccount(
        self: *const SessionStore,
        account: []const u8,
        token: Token,
        exclude_client: ClientId,
    ) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |s| {
            if (s.client == exclude_client or !s.attached) continue;
            if (!std.crypto.timing_safe.eql(Token, s.token, token)) continue;
            var copied = s;
            sanitizeCopiedSession(&copied);
            return copied;
        }
        return null;
    }

    /// Find the newest detached attachment to `token`. Attached rows bearing the
    /// same group token are skipped instead of hiding a valid detached snapshot.
    pub fn findDetachedTokenSessionInAccount(self: *const SessionStore, account: []const u8, token: Token) ?Session {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        var best: ?Session = null;
        for (list.items.items) |s| {
            if (s.attached or !std.crypto.timing_safe.eql(Token, s.token, token)) continue;
            if (best == null or s.signon_ms >= best.?.signon_ms) {
                best = s;
                sanitizeCopiedSession(&best.?);
            }
        }
        return best;
    }

    /// Detached lookup within a reusable logical-session token group. Attached
    /// siblings bearing the same token do not mask the detached row.
    pub fn findDetachedTokenInAccount(self: *const SessionStore, account: []const u8, token: Token) ?ClientId {
        const s = self.findDetachedTokenSessionInAccount(account, token) orelse return null;
        return s.client;
    }

    /// Copy the encoded restore snapshot for a detached token in `account`.
    /// Returns null when the token is unknown, still attached, or has no snapshot.
    pub fn copyDetachedSnapshotInAccount(
        self: *const SessionStore,
        allocator: std.mem.Allocator,
        account: []const u8,
        token: Token,
    ) std.mem.Allocator.Error!?[]u8 {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        var matched: ?*const Session = null;
        for (list.items.items) |*s| {
            if (!std.crypto.timing_safe.eql(Token, s.token, token)) continue;
            if (s.attached or s.snapshot == null) continue;
            if (matched == null or s.signon_ms >= matched.?.signon_ms) matched = s;
        }
        const bytes = (matched orelse return null).snapshot.?;
        return try allocator.dupe(u8, bytes);
    }

    /// Copy only the snapshot owned by the requested physical attachment.
    /// This is the restore primitive for SRM2 `exact_restore`; it never falls
    /// back to another detached sibling bearing the same group token.
    pub fn copyDetachedAttachmentSnapshotInAccount(
        self: *const SessionStore,
        allocator: std.mem.Allocator,
        account: []const u8,
        token: Token,
        attachment_id: AttachmentId,
    ) std.mem.Allocator.Error!?[]u8 {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        if (attachment_id.isZero()) return null;
        const list = self.accounts.getPtr(account) orelse return null;
        for (list.items.items) |session| {
            if (!sessionMatchesAttachment(session, token, attachment_id)) continue;
            if (session.attached) return null;
            const bytes = session.snapshot orelse return null;
            return try allocator.dupe(u8, bytes);
        }
        return null;
    }

    /// Copy the newest detached restore snapshot for `account`, excluding the
    /// caller's current live client id. Used by login-time auto-restore so a
    /// reconnecting web client does not autojoin channels under a generated nick
    /// while waiting for an explicit SESSION RESUME round trip.
    pub fn copyNewestDetachedSnapshotInAccount(
        self: *const SessionStore,
        allocator: std.mem.Allocator,
        account: []const u8,
        exclude_client: ClientId,
    ) std.mem.Allocator.Error!?DetachedSnapshot {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const list = self.accounts.getPtr(account) orelse return null;
        var matched_client: ClientId = 0;
        var matched_signon: i64 = std.math.minInt(i64);
        var matched_snapshot: ?[]u8 = null;
        for (list.items.items) |s| {
            if (s.client == exclude_client or s.attached) continue;
            const bytes = s.snapshot orelse continue;
            if (matched_snapshot == null or s.signon_ms >= matched_signon) {
                matched_client = s.client;
                matched_signon = s.signon_ms;
                matched_snapshot = bytes;
            }
        }
        const bytes = matched_snapshot orelse return null;
        return .{
            .client = matched_client,
            .signon_ms = matched_signon,
            .snapshot = try allocator.dupe(u8, bytes),
        };
    }

    /// Deep-copy one canonical detached snapshot per portable exact-token group.
    /// Used when a secured peer (re)establishes after missing the detach-time
    /// broadcast. Group portability is redundantly carried by every row; selection is
    /// newest signon, then highest client id, so insertion/hash iteration order
    /// cannot make anti-entropy sign an arbitrary older ghost. The returned
    /// records and outer slice are caller-owned.
    pub fn copyPortableDetachedSnapshots(self: *const SessionStore, allocator: std.mem.Allocator) std.mem.Allocator.Error![]PortableDetachedSnapshot {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        const Selection = struct {
            account: []const u8,
            session: ?*const Session = null,
            portable: bool = false,
        };
        var selections: std.AutoHashMapUnmanaged(Token, Selection) = .empty;
        defer selections.deinit(allocator);
        var row_count: usize = 0;
        var count_it = self.accounts.valueIterator();
        while (count_it.next()) |list| row_count += list.items.items.len;
        const selection_capacity = std.math.cast(u32, row_count) orelse return error.OutOfMemory;
        try selections.ensureTotalCapacity(allocator, selection_capacity);

        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items.items) |*session| {
                const selected = selections.getOrPutAssumeCapacity(session.token);
                if (!selected.found_existing) selected.value_ptr.* = .{ .account = entry.key_ptr.* };
                selected.value_ptr.portable = selected.value_ptr.portable or session.portable_resume;
                if (session.attached or session.snapshot == null) continue;
                const current = selected.value_ptr.session;
                if (current == null or session.signon_ms > current.?.signon_ms or
                    (session.signon_ms == current.?.signon_ms and session.client > current.?.client))
                {
                    selected.value_ptr.account = entry.key_ptr.*;
                    selected.value_ptr.session = session;
                }
            }
        }

        var count: usize = 0;
        var selected_count = selections.valueIterator();
        while (selected_count.next()) |selection| {
            if (selection.portable and selection.session != null) count += 1;
        }

        const out = try allocator.alloc(PortableDetachedSnapshot, count);
        errdefer allocator.free(out);
        var n: usize = 0;
        errdefer for (out[0..n]) |*record| record.deinit(allocator);
        var selected_it = selections.iterator();
        while (selected_it.next()) |entry| {
            const selection = entry.value_ptr;
            if (!selection.portable) continue;
            const session = selection.session orelse continue;
            const account = try allocator.dupe(u8, selection.account);
            errdefer allocator.free(account);
            const copied = try allocator.dupe(u8, session.snapshot.?);
            out[n] = .{ .account = account, .token = entry.key_ptr.*, .snapshot = copied };
            n += 1;
        }
        return out;
    }

    /// Deep-copy every detached current-generation physical attachment. Sibling
    /// rows sharing one token remain distinct and carry their stable ids.
    pub fn copyPortableDetachedAttachmentSnapshots(
        self: *const SessionStore,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]PortableDetachedAttachmentSnapshot {
        @constCast(&self.lock).lockShared();
        defer @constCast(&self.lock).unlockShared();

        // Build group portability once. Calling tokenGroupStateLocked per row
        // would rescan the whole store and turn peer anti-entropy into O(N^2).
        var portable_tokens: std.AutoHashMapUnmanaged(Token, void) = .empty;
        defer portable_tokens.deinit(allocator);
        var row_count: usize = 0;
        var rows = self.accounts.valueIterator();
        while (rows.next()) |list| row_count = std.math.add(usize, row_count, list.items.items.len) catch return error.OutOfMemory;
        const set_capacity = std.math.cast(u32, row_count) orelse return error.OutOfMemory;
        try portable_tokens.ensureTotalCapacity(allocator, set_capacity);
        var portable_it = self.accounts.valueIterator();
        while (portable_it.next()) |list| {
            for (list.items.items) |session| {
                if (session.portable_resume)
                    portable_tokens.putAssumeCapacity(session.token, {});
            }
        }

        var count: usize = 0;
        var count_it = self.accounts.valueIterator();
        while (count_it.next()) |list| {
            for (list.items.items) |session| {
                if (session.attached or session.snapshot == null or session.attachment_id == null) continue;
                if (!portable_tokens.contains(session.token)) continue;
                count = std.math.add(usize, count, 1) catch return error.OutOfMemory;
            }
        }

        const out = try allocator.alloc(PortableDetachedAttachmentSnapshot, count);
        errdefer allocator.free(out);
        var n: usize = 0;
        errdefer for (out[0..n]) |*record| record.deinit(allocator);
        var accounts = self.accounts.iterator();
        while (accounts.next()) |entry| {
            for (entry.value_ptr.items.items) |session| {
                const attachment_id = session.attachment_id orelse continue;
                const snapshot = session.snapshot orelse continue;
                if (session.attached or !portable_tokens.contains(session.token)) continue;
                const account = try allocator.dupe(u8, entry.key_ptr.*);
                errdefer allocator.free(account);
                const copied = try allocator.dupe(u8, snapshot);
                out[n] = .{
                    .account = account,
                    .token = session.token,
                    .attachment_id = attachment_id,
                    .snapshot = copied,
                };
                n += 1;
            }
        }
        std.debug.assert(n == out.len);
        return out;
    }

    fn ensureAccount(self: *SessionStore, account: []const u8) Error!*SessionList {
        if (self.accounts.getPtr(account)) |list| return list;
        if (self.accounts.count() >= self.cfg.max_accounts) return error.TooManyAccounts;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.accounts.putNoClobber(owned, .{});
        return self.accounts.getPtr(account).?;
    }

    const TokenGroupState = struct {
        found: bool = false,
        portable: bool = false,
        dirty: bool = false,
        projection_dirty: bool = false,
        drop_reserved: bool = false,
        local_projections: LocalChannelProjectionSet = .{},
    };

    /// Caller holds `lock` exclusively or shared. Cached group state makes this
    /// lookup independent of total registry cardinality.
    fn tokenGroupStateLocked(self: *const SessionStore, token: Token) TokenGroupState {
        const entry = self.tokenEntryLocked(token) orelse return .{};
        return .{
            .found = entry.rows.items.len != 0,
            .portable = entry.portable_rows != 0,
            .dirty = entry.dirty_rows != 0,
            .projection_dirty = entry.projection_dirty_rows != 0,
            .drop_reserved = entry.drop_reserved_rows != 0,
            .local_projections = entry.local_projections,
        };
    }

    /// Reservation freezes token-wide state and membership changes for the
    /// exact indexed group. This never scans unrelated accounts or tokens.
    fn tokenGroupHasDropReservationLocked(self: *SessionStore, token: Token) bool {
        const entry = self.tokenEntryLocked(token) orelse return false;
        return entry.drop_reserved_rows != 0;
    }

    fn sessionOrTokenGroupHasDropReservationLocked(
        self: *SessionStore,
        session: Session,
    ) bool {
        return session.drop_reservation != 0 or
            self.tokenGroupHasDropReservationLocked(session.token);
    }

    /// Return exact-token group state only when every matching row belongs to
    /// `account` under ASCII case-folding. `null` is a fail-closed ownership
    /// conflict; an empty non-null state means the token is currently rowless.
    /// Caller holds the store lock for the complete scan.
    fn tokenGroupStateForAccountLocked(
        self: *const SessionStore,
        account: []const u8,
        token: Token,
    ) ?TokenGroupState {
        // The sentinel is a per-row absence marker, not a bearer capability.
        // Returning an empty non-conflicting state lets independent accounts be
        // tracked without merging their retry/portable state or authorizing a
        // later token-group bind.
        if (tokenIsSentinel(token)) return .{};
        const entry = self.tokenEntryLocked(token) orelse return .{};
        const representative = entry.rows.items[0];
        if (!std.ascii.eqlIgnoreCase(representative.account, account)) return null;
        return .{
            .found = true,
            .portable = entry.portable_rows != 0,
            .dirty = entry.dirty_rows != 0,
            .projection_dirty = entry.projection_dirty_rows != 0,
            .drop_reserved = entry.drop_reserved_rows != 0,
            .local_projections = entry.local_projections,
        };
    }

    /// Apply token-group dirty state and keep `dirty_replica_rows` exact. Caller
    /// holds `lock` exclusively. Portability is a durable group property carried
    /// redundantly by every row.
    fn setTokenGroupDirtyLocked(self: *SessionStore, token: Token, dirty: bool) void {
        const entry = self.tokenEntryMutLocked(token) orelse return;
        for (entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
            self.setReplicaDirtyLocked(session, dirty);
        }
    }

    fn setTokenGroupProjectionDirtyLocked(self: *SessionStore, token: Token, dirty: bool) void {
        const entry = self.tokenEntryMutLocked(token) orelse return;
        for (entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
            self.setReplicaProjectionDirtyLocked(session, dirty);
        }
    }

    fn setTokenGroupLocalProjectionsLocked(
        self: *SessionStore,
        token: Token,
        projections: *const LocalChannelProjectionSet,
    ) void {
        const entry = self.tokenEntryMutLocked(token) orelse return;
        for (entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
            self.setLocalProjectionsLocked(session, projections);
        }
        entry.local_projections = projections.*;
    }

    fn nextLocalProjectionGenerationLocked(self: *SessionStore) u64 {
        self.next_local_projection_generation +%= 1;
        if (self.next_local_projection_generation == 0)
            self.next_local_projection_generation = 1;
        return self.next_local_projection_generation;
    }

    fn setReplicaDirtyLocked(self: *SessionStore, session: *Session, dirty: bool) void {
        if (session.replica_dirty == dirty) return;
        const entry = self.tokenEntryMutLocked(session.token);
        session.replica_dirty = dirty;
        if (dirty) {
            self.dirty_replica_rows += 1;
            if (entry) |group| group.dirty_rows += 1;
        } else {
            std.debug.assert(self.dirty_replica_rows != 0);
            self.dirty_replica_rows -= 1;
            if (entry) |group| {
                std.debug.assert(group.dirty_rows != 0);
                group.dirty_rows -= 1;
            }
        }
    }

    fn setAttachmentReplicaDirtyLocked(self: *SessionStore, session: *Session, dirty: bool) void {
        if (session.attachment_replica_dirty == dirty) return;
        session.attachment_replica_dirty = dirty;
        if (dirty) {
            self.dirty_attachment_replica_rows += 1;
        } else {
            std.debug.assert(self.dirty_attachment_replica_rows != 0);
            self.dirty_attachment_replica_rows -= 1;
        }
    }

    fn setPortableLocked(self: *SessionStore, session: *Session, portable: bool) void {
        if (session.portable_resume == portable) return;
        const entry = self.tokenEntryMutLocked(session.token);
        session.portable_resume = portable;
        if (portable) {
            if (entry) |group| group.portable_rows += 1;
        } else if (entry) |group| {
            std.debug.assert(group.portable_rows != 0);
            group.portable_rows -= 1;
        }
    }

    fn setTokenGroupPortableLocked(self: *SessionStore, token: Token, portable: bool) void {
        const entry = self.tokenEntryMutLocked(token) orelse return;
        for (entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
            self.setPortableLocked(session, portable);
        }
    }

    fn markTokenAttachmentReplicasDirtyLocked(self: *SessionStore, token: Token) bool {
        if (!self.tokenGroupStateLocked(token).portable) return false;
        var marked = false;
        const entry = self.tokenEntryMutLocked(token) orelse return false;
        for (entry.rows.items) |locator| {
            self.noteTokenGroupRowVisit();
            const session = self.sessionForTokenLocatorLocked(locator) orelse unreachable;
            if (session.attachment_id == null) continue;
            self.setAttachmentReplicaDirtyLocked(session, true);
            marked = true;
        }
        return marked;
    }

    fn removeDirtyRowLocked(self: *SessionStore, session: *const Session) void {
        if (session.replica_dirty) {
            std.debug.assert(self.dirty_replica_rows != 0);
            self.dirty_replica_rows -= 1;
        }
        if (session.replica_projection_dirty) {
            std.debug.assert(self.dirty_projection_rows != 0);
            self.dirty_projection_rows -= 1;
        }
        if (session.attachment_replica_dirty) {
            std.debug.assert(self.dirty_attachment_replica_rows != 0);
            self.dirty_attachment_replica_rows -= 1;
        }
        if (session.attachment_replica_projection_dirty) {
            std.debug.assert(self.dirty_attachment_projection_rows != 0);
            self.dirty_attachment_projection_rows -= 1;
        }
        if (session.local_channel_projections) |set| {
            if (!set.isEmpty()) {
                std.debug.assert(self.dirty_local_projection_rows != 0);
                self.dirty_local_projection_rows -= 1;
            }
        }
        if (session.attachment_channel_projections) |set| {
            if (!set.isEmpty()) {
                std.debug.assert(self.dirty_attachment_local_projection_rows != 0);
                self.dirty_attachment_local_projection_rows -= 1;
            }
        }
    }

    fn addDirtyRowLocked(self: *SessionStore, session: *const Session) void {
        if (session.replica_dirty) self.dirty_replica_rows += 1;
        if (session.replica_projection_dirty) self.dirty_projection_rows += 1;
        if (session.attachment_replica_dirty) self.dirty_attachment_replica_rows += 1;
        if (session.attachment_replica_projection_dirty) self.dirty_attachment_projection_rows += 1;
        if (session.local_channel_projections) |set| {
            if (!set.isEmpty()) self.dirty_local_projection_rows += 1;
        }
        if (session.attachment_channel_projections) |set| {
            if (!set.isEmpty()) self.dirty_attachment_local_projection_rows += 1;
        }
    }

    fn setReplicaProjectionDirtyLocked(self: *SessionStore, session: *Session, dirty: bool) void {
        if (session.replica_projection_dirty == dirty) return;
        const entry = self.tokenEntryMutLocked(session.token);
        session.replica_projection_dirty = dirty;
        if (dirty) {
            self.dirty_projection_rows += 1;
            if (entry) |group| group.projection_dirty_rows += 1;
        } else {
            std.debug.assert(self.dirty_projection_rows != 0);
            self.dirty_projection_rows -= 1;
            if (entry) |group| {
                std.debug.assert(group.projection_dirty_rows != 0);
                group.projection_dirty_rows -= 1;
            }
        }
    }

    fn setLocalProjectionsLocked(
        self: *SessionStore,
        session: *Session,
        projections: *const LocalChannelProjectionSet,
    ) void {
        const was_dirty = if (session.local_channel_projections) |set| !set.isEmpty() else false;
        const now_dirty = !projections.isEmpty();
        if (now_dirty) {
            const storage = session.local_channel_projections orelse unreachable;
            storage.* = projections.*;
        } else if (session.local_channel_projections) |storage| {
            self.allocator.destroy(storage);
            session.local_channel_projections = null;
        }
        if (was_dirty == now_dirty) return;
        if (now_dirty) {
            self.dirty_local_projection_rows += 1;
        } else {
            std.debug.assert(self.dirty_local_projection_rows != 0);
            self.dirty_local_projection_rows -= 1;
        }
    }

    fn setAttachmentLocalProjectionsLocked(
        self: *SessionStore,
        session: *Session,
        projections: *const LocalChannelProjectionSet,
    ) void {
        const was_dirty = if (session.attachment_channel_projections) |set| !set.isEmpty() else false;
        const now_dirty = !projections.isEmpty();
        if (now_dirty) {
            const storage = session.attachment_channel_projections orelse unreachable;
            storage.* = projections.*;
        } else if (session.attachment_channel_projections) |storage| {
            self.allocator.destroy(storage);
            session.attachment_channel_projections = null;
        }
        if (was_dirty == now_dirty) return;
        if (now_dirty) {
            self.dirty_attachment_local_projection_rows += 1;
        } else {
            std.debug.assert(self.dirty_attachment_local_projection_rows != 0);
            self.dirty_attachment_local_projection_rows -= 1;
        }
    }

    fn dropAccount(self: *SessionStore, entry: std.StringHashMap(SessionList).Entry) void {
        const owned_key = entry.key_ptr.*;
        for (entry.value_ptr.items.items) |session| {
            self.removeDirtyRowLocked(&session);
            self.removeTokenRowLocked(owned_key, session, false);
            self.removeAttachmentIndexLocked(session);
        }
        entry.value_ptr.deinit(self.allocator);
        self.accounts.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }
};

fn localProjectionSetRevision(set: ?*const LocalChannelProjectionSet) u64 {
    return if (set) |value| value.revision else 0;
}

fn localChannelOrder(a: []const u8, b: []const u8) std.math.Order {
    const shared = @min(a.len, b.len);
    for (a[0..shared], b[0..shared]) |a_byte, b_byte| {
        const a_folded = std.ascii.toLower(a_byte);
        const b_folded = std.ascii.toLower(b_byte);
        if (a_folded < b_folded) return .lt;
        if (a_folded > b_folded) return .gt;
    }
    return std.math.order(a.len, b.len);
}

fn localProjectionIndex(set: *const LocalChannelProjectionSet, channel: []const u8) ?usize {
    for (set.slice(), 0..) |projection, index| {
        if (std.ascii.eqlIgnoreCase(projection.channel(), channel)) return index;
    }
    return null;
}

fn localProjectionUpsert(
    set: *LocalChannelProjectionSet,
    projection: LocalChannelProjection,
) error{TooManyPendingChannels}!void {
    if (localProjectionIndex(set, projection.channel())) |index| {
        set.items[index] = projection;
        return;
    }
    if (set.len == local_channel_projection_capacity) return error.TooManyPendingChannels;

    var insert_at: usize = 0;
    while (insert_at < set.len and
        localChannelOrder(set.items[insert_at].channel(), projection.channel()) == .lt)
    {
        insert_at += 1;
    }
    var cursor: usize = set.len;
    while (cursor > insert_at) : (cursor -= 1)
        set.items[cursor] = set.items[cursor - 1];
    set.items[insert_at] = projection;
    set.len += 1;
}

fn localProjectionRemoveAt(set: *LocalChannelProjectionSet, index: usize) void {
    std.debug.assert(index < set.len);
    var cursor = index;
    while (cursor + 1 < set.len) : (cursor += 1)
        set.items[cursor] = set.items[cursor + 1];
    set.len -= 1;
    set.items[set.len] = .{};
}

fn mergeLocalProjectionSets(
    out: *LocalChannelProjectionSet,
    a: *const LocalChannelProjectionSet,
    b: *const LocalChannelProjectionSet,
) bool {
    out.* = .{};
    for (a.slice()) |projection|
        localProjectionUpsert(out, projection) catch return false;
    for (b.slice()) |projection| {
        if (localProjectionIndex(out, projection.channel())) |index| {
            if (projection.generation > out.items[index].generation)
                out.items[index] = projection;
            continue;
        }
        localProjectionUpsert(out, projection) catch return false;
    }
    out.revision = @max(a.revision, b.revision);
    return true;
}

fn localWorkOrder(a: LocalChannelProjectionWork, b: LocalChannelProjectionWork) std.math.Order {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order;
    return localChannelOrder(a.projection.channel(), b.projection.channel());
}

fn localWorkInSlice(
    work: []const LocalChannelProjectionWork,
    needle: LocalChannelProjectionWork,
) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            std.ascii.eqlIgnoreCase(candidate.projection.channel(), needle.projection.channel()))
        {
            return true;
        }
    }
    return false;
}

fn attachmentWorkOrder(a: AttachmentReplicaWork, b: AttachmentReplicaWork) std.math.Order {
    const token_order = std.mem.order(u8, &a.token, &b.token);
    if (token_order != .eq) return token_order;
    return std.mem.order(u8, &a.attachment_id.raw, &b.attachment_id.raw);
}

fn attachmentWorkInSlice(work: []const AttachmentReplicaWork, needle: AttachmentReplicaWork) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            candidate.attachment_id.eql(needle.attachment_id))
        {
            return true;
        }
    }
    return false;
}

fn attachmentLocalWorkOrder(
    a: AttachmentLocalChannelProjectionWork,
    b: AttachmentLocalChannelProjectionWork,
) std.math.Order {
    const attachment_order = attachmentWorkOrder(
        .{ .token = a.token, .attachment_id = a.attachment_id },
        .{ .token = b.token, .attachment_id = b.attachment_id },
    );
    if (attachment_order != .eq) return attachment_order;
    return localChannelOrder(a.projection.channel(), b.projection.channel());
}

fn attachmentLocalWorkInSlice(
    work: []const AttachmentLocalChannelProjectionWork,
    needle: AttachmentLocalChannelProjectionWork,
) bool {
    for (work) |candidate| {
        if (std.crypto.timing_safe.eql(Token, candidate.token, needle.token) and
            candidate.attachment_id.eql(needle.attachment_id) and
            std.ascii.eqlIgnoreCase(candidate.projection.channel(), needle.projection.channel()))
        {
            return true;
        }
    }
    return false;
}

fn freeSnapshot(allocator: std.mem.Allocator, session: *Session) void {
    if (session.snapshot) |bytes| allocator.free(bytes);
    session.snapshot = null;
}

fn sanitizeCopiedSession(session: *Session) void {
    // Public Session values own no store memory. Dedicated snapshot/projection
    // APIs copy or inline the required state while holding the appropriate lock.
    session.snapshot = null;
    session.local_channel_projections = null;
    session.attachment_channel_projections = null;
    // Cross-owner DROP tickets never survive an exported snapshot/Helix image.
    session.drop_reservation = 0;
}

fn freeSessionOwned(allocator: std.mem.Allocator, session: *Session) void {
    freeSnapshot(allocator, session);
    if (session.local_channel_projections) |set| allocator.destroy(set);
    session.local_channel_projections = null;
    if (session.attachment_channel_projections) |set| allocator.destroy(set);
    session.attachment_channel_projections = null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tok(b: u8) Token {
    return @as([16]u8, @splat(b));
}

fn aid(b: u8) AttachmentId {
    return AttachmentId.fromBytes(@as([16]u8, @splat(b))) catch unreachable;
}

fn aidNumber(value: u64) AttachmentId {
    var raw: [16]u8 = @splat(0);
    std.mem.writeInt(u64, raw[8..16], value, .big);
    return AttachmentId.fromBytes(raw) catch unreachable;
}

fn tokenNumber(value: u64) Token {
    std.debug.assert(value != 0);
    var raw: Token = @splat(0);
    std.mem.writeInt(u64, raw[8..16], value, .big);
    return raw;
}

fn lifecycleSelector(account: []const u8, s: Session) LifecycleSelector {
    return .{ .account = account, .exact = .{ .client = s.client, .token = s.token, .signon_ms = s.signon_ms, .attachment_id = s.attachment_id }, .attached = s.attached };
}

test "Session lifecycle batch owns mixed candidate and commits without allocation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_accounts = 3, .max_sessions_per_account = 4 });
    defer s.deinit();
    const a = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const b = try s.attachWithAttachment("Alice", 2, tok(1), aid(2), 20);
    _ = try s.attachWithAttachment("Bob", 3, tok(3), aid(3), 30);
    try testing.expect(s.markDetachedWithSnapshot("Bob", 3, "ghost-restore"));
    const ghost = s.findDetachedAttachmentSessionInAccount("Bob", tok(3), aid(3)).?;
    var input = try testing.allocator.dupe(u8, "new-snapshot");
    const operations = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", a), .snapshot = .{ .replace = input } } } },
        .{ .request_id = 2, .intent = .{ .remove = .{ .source = lifecycleSelector("Alice", b), .reason = .logout } } },
        .{ .request_id = 3, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Bob", ghost), .claimant_client = 4 } } },
        .{ .request_id = 4, .intent = .{ .admit = .{ .account = "Carol", .client = 5, .signon_ms = 40, .kind = .fresh } } },
    };
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &operations });
    defer ticket.deinit();
    @memset(input, 0);
    testing.allocator.free(input);
    input = &.{};
    const p = ticket.preview();
    try testing.expectEqual(@as(usize, 3), p.before.len);
    try testing.expectEqual(@as(usize, 3), p.after.len);
    try testing.expectEqual(@as(usize, 1), p.remaps.len);
    try testing.expectEqual(@as(usize, 1), p.retired_attachments.len);
    try testing.expectEqualStrings("new-snapshot", lifecycleFindRow(p.after, 1).?.snapshot.?);
    try testing.expect(p.admissions[0].result.tracked.attachment_id != null);
    try testing.expect(!tokenIsSentinel(p.admissions[0].result.tracked.token));
    try testing.expectEqual(@as(usize, 3), p.complexity.discovery_row_visits);
    try testing.expectError(error.Busy, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &operations }));
    try ticket.validateForCut();
    failing.fail_index = failing.alloc_index;
    ticket.commit();
    ticket.finish();
    try testing.expect(!s.containsClient("Alice", 2));
    try testing.expect(s.clientHasAttachment("Bob", 4, tok(3), aid(3)));
    try testing.expect(!s.containsClient("Bob", 3));
    try expectTokenIndexCoherent(&s);
    ticket.deinit();
}

test "Session lifecycle batch snapshot copy OOM leaves OLD attached and exact retry succeeds" {
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.init(failing.allocator());
        defer s.deinit();
        const old = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
        const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", old), .snapshot = .{ .replace = "complete-new-image" } } } }};
        failing.fail_index = failing.alloc_index + index;
        var ticket = s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expect(s.findAttachmentSessionInAccount("Alice", tok(1), aid(1)).?.attached);
            try testing.expect(s.active_lifecycle == null);
            failing.fail_index = std.math.maxInt(usize);
            var retry = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
            defer retry.deinit();
            try retry.validateForCut();
            retry.commit();
            retry.finish();
            continue;
        };
        defer ticket.deinit();
        try ticket.validateForCut();
        ticket.commit();
        ticket.finish();
        try testing.expect(!s.findAttachmentSessionInAccount("Alice", tok(1), aid(1)).?.attached);
        try testing.expect(index > 5);
        break;
    }
}

test "Session lifecycle batch immutable OLD proof refuses joining a newly created token" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const ops = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 1, .signon_ms = 1, .kind = .{ .adopt_verified = .{ .token = tok(9), .portable = false } } } } },
        .{ .request_id = 2, .intent = .{ .admit = .{ .account = "Alice", .client = 2, .signon_ms = 2, .kind = .{ .join_existing = tok(9) } } } },
    };
    try testing.expectError(error.InvalidToken, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(@as(u32, 0), s.accounts.count());
}

fn lifecycleCanonical(store: *SessionStore) ![32]u8 {
    store.lock.lockShared();
    defer store.lock.unlockShared();
    var h = std.crypto.hash.Blake3.init(.{});
    var keys: std.ArrayListUnmanaged([]const u8) = .empty;
    defer keys.deinit(testing.allocator);
    var iter = store.accounts.keyIterator();
    while (iter.next()) |key| try keys.append(testing.allocator, key.*);
    std.mem.sort([]const u8, keys.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    for (keys.items) |key| {
        std.hash.autoHashStrat(&h, key, .DeepRecursive);
        for (store.accounts.get(key).?.items.items) |row| std.hash.autoHashStrat(&h, lifecycleRow(key, row), .DeepRecursive);
    }
    var tokens: std.ArrayListUnmanaged(Token) = .empty;
    defer tokens.deinit(testing.allocator);
    var token_it = store.token_index.keyIterator();
    while (token_it.next()) |t| try tokens.append(testing.allocator, t.*);
    std.mem.sort(Token, tokens.items, {}, struct {
        fn less(_: void, a: Token, b: Token) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.less);
    for (tokens.items) |t| {
        const e = store.token_index.get(t).?;
        std.hash.autoHashStrat(&h, .{ t, e.rows.items, e.portable_rows, e.dirty_rows, e.projection_dirty_rows, e.drop_reserved_rows, e.local_projections }, .DeepRecursive);
    }
    var attachments: std.ArrayListUnmanaged([16]u8) = .empty;
    defer attachments.deinit(testing.allocator);
    var attachment_it = store.attachment_index.keyIterator();
    while (attachment_it.next()) |id| try attachments.append(testing.allocator, id.*);
    std.mem.sort([16]u8, attachments.items, {}, struct {
        fn less(_: void, a: [16]u8, b: [16]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.less);
    for (attachments.items) |id| std.hash.autoHashStrat(&h, .{ id, store.attachment_index.get(id).? }, .DeepRecursive);
    std.hash.autoHashStrat(&h, .{ store.cfg, store.dirty_replica_rows, store.dirty_projection_rows, store.dirty_attachment_replica_rows, store.dirty_attachment_projection_rows, store.dirty_local_projection_rows, store.dirty_attachment_local_projection_rows, store.dirty_scan_cursor, store.projection_scan_cursor, store.attachment_replica_scan_cursor, store.attachment_projection_scan_cursor, store.local_projection_scan_cursor, store.attachment_local_projection_scan_cursor, store.next_local_projection_generation }, .DeepRecursive);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return digest;
}

fn lifecycleMixedFixture(s: *SessionStore) ![7]LifecycleRequest {
    const first = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const sibling = try s.attachWithAttachment("Alice", 2, tok(1), aid(2), 20);
    const binding = try s.attachWithAttachment("ALICE", 3, tok(3), aid(3), 30);
    _ = try s.attachWithAttachment("Bob", 4, tok(4), aid(4), 40);
    _ = try s.attachWithAttachment("Carol", 5, tok(5), aid(5), 50);
    _ = try s.attachWithAttachment("Carol", 6, tok(5), aid(6), 60);
    try testing.expect(s.markDetachedWithSnapshot("Bob", 4, "OLD exact ghost snapshot"));
    try testing.expect(s.markDetachedWithSnapshot("Carol", 6, "OLD retired snapshot"));
    const ghost = s.findDetachedAttachmentSessionInAccount("Bob", tok(4), aid(4)).?;
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markPortableResumeIssued("ALICE", 3));
    try testing.expect(s.markTokenReplicaDirty(tok(1)));
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(1)));
    try testing.expect(s.markAttachmentReplicaDirty(tok(3), aid(3)));
    try testing.expect(s.markAttachmentReplicaProjectionDirty(tok(3), aid(3)));
    _ = try s.armTokenLocalChannelProjection(tok(1), "#group", true, 1);
    _ = try s.armTokenLocalChannelProjection(tok(3), "#source", false, 0);
    _ = try s.armAttachmentLocalChannelProjection(tok(3), aid(3), "#exact", true, 2);
    s.dirty_scan_cursor = tok(1);
    s.projection_scan_cursor = tok(1);
    s.attachment_replica_scan_cursor = .{ .token = tok(3), .attachment_id = aid(3) };
    s.attachment_projection_scan_cursor = s.attachment_replica_scan_cursor;
    var group_cursor: [1]LocalChannelProjectionWork = undefined;
    var attachment_cursor: [1]AttachmentLocalChannelProjectionWork = undefined;
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionsInto(&group_cursor).len);
    try testing.expectEqual(@as(usize, 1), s.dirtyAttachmentLocalProjectionsInto(&attachment_cursor).len);
    return .{
        .{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", first), .snapshot = .{ .replace = "NEW exact snapshot" } } } },
        .{ .request_id = 2, .intent = .{ .remove = .{ .source = lifecycleSelector("Alice", sibling), .reason = .logout } } },
        .{ .request_id = 3, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Bob", ghost), .claimant_client = 40 } } },
        .{ .request_id = 4, .intent = .{ .rebind = .{ .source = lifecycleSelector("ALICE", binding), .target_account = "Alice", .target_token = tok(1), .kind = .join_existing, .retire_attachment_work = true } } },
        .{ .request_id = 5, .intent = .{ .remove_account = "cArOl" } },
        .{ .request_id = 6, .intent = .{ .admit = .{ .account = "Dan", .client = 7, .signon_ms = 70, .kind = .fresh } } },
        .{ .request_id = 7, .intent = .{ .admit = .{ .account = "Alice", .client = 8, .signon_ms = 80, .kind = .{ .join_existing = tok(1) } } } },
    };
}

test "Session lifecycle batch every mixed allocation aborts canonical OLD and retries one nofail cut" {
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_accounts = 4, .max_sessions_per_account = 4 });
        defer s.deinit();
        const ops = try lifecycleMixedFixture(&s);
        const old = try lifecycleCanonical(&s);
        failing.fail_index = failing.alloc_index + index;
        var ticket = s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(old, try lifecycleCanonical(&s));
            try testing.expect(s.active_lifecycle == null);
            failing.fail_index = std.math.maxInt(usize);
            var retry = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
            defer retry.deinit();
            retry.abort();
            try testing.expectEqual(old, try lifecycleCanonical(&s));
            retry.deinit();
            retry = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
            try retry.validateForCut();
            failing.fail_index = failing.alloc_index;
            retry.commit();
            retry.finish();
            try testing.expect(s.clientHasAttachment("Alice", 3, tok(1), aid(3)));
            try testing.expect(s.clientHasAttachment("Bob", 40, tok(4), aid(4)));
            try testing.expect(!s.accounts.contains("Carol"));
            try expectTokenIndexCoherent(&s);
            try expectLifecycleCountsAndAttachments(&s);
            continue;
        };
        defer ticket.deinit();
        const p = ticket.preview();
        try testing.expectEqual(@as(usize, 6), p.before.len);
        try testing.expectEqual(@as(usize, 5), p.after.len);
        try testing.expectEqual(@as(usize, 3), p.final_accounts);
        var final_token_retirements: usize = 0;
        for (p.token_groups) |d| if (d.old_rows != 0 and d.final_rows == 0) {
            final_token_retirements += 1;
        };
        try testing.expectEqual(@as(usize, 2), final_token_retirements);
        try testing.expectEqual(@as(usize, 4), p.retired_attachments.len);
        try testing.expect(p.retired_attachments[1].row.snapshot != null or p.retired_attachments[2].row.snapshot != null or p.retired_attachments[3].row.snapshot != null);
        try ticket.validateForCut();
        failing.fail_index = failing.alloc_index;
        ticket.commit();
        ticket.finish();
        try expectTokenIndexCoherent(&s);
        try expectLifecycleCountsAndAttachments(&s);
        try testing.expect(index > 30);
        std.debug.print("Session lifecycle mixed allocation sweep: {d} failures before success\n", .{index});
        break;
    }
}

test "Session lifecycle batch folded account removal has complete capacity above 64" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 129 });
    defer s.deinit();
    for (0..129) |i| _ = try s.attachWithAttachment(if (i % 2 == 0) "Alice" else "ALICE", @intCast(i + 1), tok(1), aidNumber(i + 1), @intCast(i));
    _ = try s.attachWithAttachment("Unrelated", 1000, tok(2), aid(2), 1);
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .remove_account = "aLiCe" } }};
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const p = ticket.preview();
    try testing.expectEqual(@as(usize, 129), p.before.len);
    try testing.expectEqual(@as(usize, 129), p.retired_attachments.len);
    try testing.expectEqual(@as(usize, 129), p.affected_physical.len);
    try testing.expectEqual(@as(usize, 1), p.token_groups.len);
    try testing.expectEqual(@as(usize, 130), p.complexity.discovery_row_visits);
    try testing.expectEqual(@as(usize, 129), p.complexity.candidate_row_visits);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(s.clientHasAttachment("Unrelated", 1000, tok(2), aid(2)));
    try testing.expectEqual(@as(u32, 1), s.accounts.count());
    try expectTokenIndexCoherent(&s);
}

test "Session lifecycle batch final account and per-list replacement quotas apply once" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_accounts = 1, .max_sessions_per_account = 1 });
    defer s.deinit();
    const old = try s.attachWithAttachment("OLD", 1, tok(1), aid(1), 10);
    const ops = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .admit = .{ .account = "NEW", .client = 2, .signon_ms = 20, .kind = .fresh } } },
        .{ .request_id = 2, .intent = .{ .remove = .{ .source = lifecycleSelector("OLD", old), .reason = .logout } } },
    };
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expectEqual(@as(u32, 1), s.accounts.count());
    try testing.expect(s.accounts.contains("NEW"));
    try expectTokenIndexCoherent(&s);
}

const LifecycleRandom = struct {
    blocks: []const Token,
    calls: usize = 0,
    fn random(userdata: ?*anyopaque, out: []u8) void {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        const block = self.blocks[@min(self.calls, self.blocks.len - 1)];
        self.calls += 1;
        std.debug.assert(out.len == 16);
        @memcpy(out, &block);
    }
};

test "Session lifecycle batch entropy and global collisions cannot select capacity fallback" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();
    _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    var vtable = testing.io.vtable.*;
    vtable.random = LifecycleRandom.random;
    var rng = LifecycleRandom{ .blocks = &.{@splat(0)} };
    const io = std.Io{ .userdata = &rng, .vtable = &vtable };
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Bob", .client = 2, .signon_ms = 20, .kind = .fresh, .cap = .untracked } } }};
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.ZeroEntropy, s.prepareLifecycleBatch(.{ .io = io, .operations = &ops }));
    try testing.expectEqual(@as(usize, 4), rng.calls);
    rng = .{ .blocks = &.{tok(1)} };
    ops[0].intent.admit.account = "Alice";
    // No saturation while minting: replace capacity with an explicit removal.
    s.cfg.max_sessions_per_account = 2;
    try testing.expectError(error.TokenCollisionExhausted, s.prepareLifecycleBatch(.{ .io = io, .operations = &ops }));
    try testing.expectEqual(@as(usize, 4), rng.calls);
    rng = .{ .blocks = &.{aid(1).raw} };
    ops[0].intent.admit.kind = .{ .join_existing = tok(1) };
    try testing.expectError(error.AttachmentCollisionExhausted, s.prepareLifecycleBatch(.{ .io = io, .operations = &ops }));
    try testing.expectEqual(@as(usize, 4), rng.calls);
    s.cfg.max_sessions_per_account = 1;
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    const fresh = [_]LifecycleRequest{
        .{ .request_id = 2, .intent = .{ .admit = .{ .account = "Bob", .client = 2, .signon_ms = 20, .kind = .fresh } } },
        .{ .request_id = 3, .intent = .{ .admit = .{ .account = "Bob", .client = 3, .signon_ms = 30, .kind = .fresh } } },
    };
    s.cfg.max_sessions_per_account = 4;
    rng = .{ .blocks = &.{ tok(2), aid(2).raw, tok(2) } };
    try testing.expectError(error.TokenCollisionExhausted, s.prepareLifecycleBatch(.{ .io = io, .operations = &fresh }));
    try testing.expect(!s.accounts.contains("Bob"));
}

test "Session lifecycle batch only named final capacity admits explicit untracked facts" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_accounts = 1, .max_sessions_per_account = 1 });
    defer s.deinit();
    const row = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 2, .signon_ms = 20, .kind = .fresh, .cap = .untracked } } }};
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    try testing.expectEqual(@as(usize, 2), ticket.preview().affected_physical.len);
    try testing.expectEqual(.sessions_capacity, ticket.preview().admissions[0].result.untracked);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    ticket.deinit();
    try testing.expect(!s.containsClient("Alice", 2));
    ops[0].intent.admit.account = "Bob";
    ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    try testing.expectEqual(.accounts_capacity, ticket.preview().admissions[0].result.untracked);
    ticket.abort();
    ticket.deinit();
    ops[0].intent.admit.kind = .{ .adopt_verified = .{ .token = tok(1), .portable = true } };
    try testing.expectError(error.TokenAccountMismatch, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    ops[0].intent.admit.account = "Alice";
    try testing.expectEqual(ReserveDropResult.reserved, s.reserveDrop("Alice", lifecycleSelector("Alice", row).exact, 99));
    try testing.expectError(error.SessionDropReserved, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expect(s.cancelDropReservation("Alice", lifecycleSelector("Alice", row).exact, 99));
    ops[0].intent.admit.kind = .no_row;
    ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    try testing.expectEqual(.explicit, ticket.preview().admissions[0].result.untracked);
    ticket.deinit();
    ops[0].intent.admit.account = "Bob";
    ops[0].intent.admit.kind = .sentinel;
    ops[0].intent.admit.cap = .fail;
    try testing.expectError(error.TooManyAccounts, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
}

test "Session lifecycle batch exact proofs overlap DROP owner and stale ticket fail before cut" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var other = SessionStore.init(testing.allocator);
    defer other.deinit();
    const row = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const source = lifecycleSelector("Alice", row);
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .remove = .{ .source = source, .reason = .physical_close } } }};
    const old = try lifecycleCanonical(&s);
    ops[0].intent.remove.source.exact.signon_ms += 1;
    try testing.expectError(error.StaleSelector, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    ops[0].intent.remove.source = source;
    ops[0].intent.remove.source.attached = false;
    try testing.expectError(error.StaleSelector, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    ops[0].intent.remove.source = source;
    const overlap = [_]LifecycleRequest{ ops[0], .{ .request_id = 2, .intent = .{ .detach = .{ .source = source } } } };
    try testing.expectError(error.OverlappingIntent, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &overlap }));
    const account_overlap = [_]LifecycleRequest{ .{ .request_id = 2, .intent = .{ .remove_account = "ALICE" } }, ops[0] };
    try testing.expectError(error.OverlappingIntent, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &account_overlap }));
    const hidden = [_]LifecycleRequest{.{ .request_id = 2, .intent = .{ .admit = .{ .account = "Foreign", .client = 1, .signon_ms = 10, .kind = .fresh } } }};
    try testing.expectError(error.AmbiguousPhysicalBinding, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &hidden }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    try testing.expectEqual(ReserveDropResult.reserved, s.reserveDrop("Alice", source.exact, 91));
    try testing.expectError(error.SessionDropReserved, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    var permits = [_]LifecycleDropPermit{.{ .source = source, .owner = 90 }};
    try testing.expectError(error.SessionDropReserved, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .drop_permits = &permits }));
    permits[0].owner = 91;
    const reserved = try lifecycleCanonical(&s);
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .drop_permits = &permits });
    ticket.abort();
    ticket.deinit();
    try testing.expectEqual(reserved, try lifecycleCanonical(&s));
    ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .drop_permits = &permits });
    defer ticket.deinit();
    const owner = ticket.owned.?.store;
    ticket.owned.?.store = &other;
    try testing.expectError(error.InvalidTicket, ticket.validateForCut());
    ticket.owned.?.store = owner;
    const cached = ticket.owned.?.preview_value.final_rows;
    ticket.owned.?.preview_value.final_rows += 1;
    try testing.expectError(error.InvalidTicket, ticket.validateForCut());
    ticket.owned.?.preview_value.final_rows = cached;
    try ticket.validateForCut();
    var borrowed_copy = ticket;
    try testing.expectError(error.InvalidTicket, borrowed_copy.validateForCut());
    ticket.commit();
    ticket.finish();
    try testing.expectError(error.InvalidTicket, ticket.validateForCut());
    try testing.expect(!s.containsClient("Alice", 1));
    try testing.expectEqual(@as(u32, 0), s.token_index.count());
}

test "Session lifecycle batch cap eviction is OLD detached deterministic and rollback atomic" {
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_sessions_per_account = 3 });
        defer s.deinit();
        _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 100);
        _ = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 10);
        _ = try s.attachWithAttachment("Alice", 3, tok(3), aid(3), 10);
        try testing.expect(s.markDetachedWithSnapshot("Alice", 2, "victim payload"));
        try testing.expect(s.markDetached("Alice", 3));
        const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 4, .signon_ms = 40, .kind = .fresh, .cap = .evict_detached } } }};
        const old = try lifecycleCanonical(&s);
        failing.fail_index = failing.alloc_index + index;
        var ticket = s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(old, try lifecycleCanonical(&s));
            failing.fail_index = std.math.maxInt(usize);
            var retry = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
            defer retry.deinit();
            try retry.validateForCut();
            retry.commit();
            retry.finish();
            try testing.expect(!s.containsClient("Alice", 2));
            try testing.expect(s.containsClient("Alice", 3));
            continue;
        };
        defer ticket.deinit();
        try testing.expectEqual(@as(ClientId, 2), ticket.preview().retired_attachments[0].row.client);
        for (ticket.preview().affected_physical) |effect| try testing.expect(effect.client != 2);
        try ticket.validateForCut();
        ticket.commit();
        ticket.finish();
        try expectTokenIndexCoherent(&s);
        break;
    }
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();
    const live = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const ops = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", live) } } },
        .{ .request_id = 2, .intent = .{ .admit = .{ .account = "Alice", .client = 2, .signon_ms = 20, .kind = .fresh, .cap = .evict_detached } } },
    };
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.TooManySessions, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
}

test "Session lifecycle batch exact reconnect preserves ghost authority at cap and folded keys" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();
    _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const claimant = try s.attachWithAttachment("ALICE", 2, tok(2), aid(2), 20);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "exact old snapshot"));
    _ = try s.armAttachmentLocalChannelProjection(tok(1), aid(1), "#exact", true, 3);
    const source = s.findDetachedAttachmentSessionInAccount("Alice", tok(1), aid(1)).?;
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Alice", source), .claimant_client = 2, .claimant = lifecycleSelector("ALICE", claimant) } } }};
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const p = ticket.preview();
    const final = lifecycleFindRow(p.after, 2).?;
    try testing.expectEqual(tok(1), final.token);
    try testing.expect(final.attachment_id.?.eql(aid(1)));
    try testing.expectEqual(@as(i64, 10), final.signon_ms);
    try testing.expectEqual(@as(u8, 1), final.attachment_journal.len);
    try testing.expect(final.snapshot == null);
    try testing.expectEqualStrings("exact old snapshot", p.before[0].snapshot.?);
    try testing.expectEqual(@as(usize, 1), p.retired_attachments.len);
    try testing.expectEqual(@as(usize, 1), p.remaps.len);
    try testing.expect(p.affected_physical[0].historical_only);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(s.clientHasAttachment("Alice", 2, tok(1), aid(1)));
    try testing.expect(!s.accounts.contains("ALICE"));
    try expectTokenIndexCoherent(&s);
    ticket.deinit();
    ops[0].intent.reconnect.source.exact.client = 2;
    ops[0].intent.reconnect.source.attached = true;
    ops[0].intent.reconnect.claimant = null;
    ops[0].intent.reconnect.claimant_client = 3;
    try testing.expectError(error.AlreadyAttached, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
}

test "Session lifecycle batch journals union eight refuse nine and reject equal-generation contradiction" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const source = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    _ = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    for (0..4) |i| {
        var channel: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&channel, "#source{d}", .{i});
        _ = try s.armTokenLocalChannelProjection(tok(1), text, true, 1);
    }
    for (0..4) |i| {
        var channel: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&channel, "#target{d}", .{i});
        _ = try s.armTokenLocalChannelProjection(tok(2), text, false, 0);
    }
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", source), .target_account = "Alice", .target_token = tok(2), .kind = .join_existing, .retire_attachment_work = true } } }};
    const old = try lifecycleCanonical(&s);
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    try testing.expectEqual(@as(u8, 8), lifecycleFindRow(ticket.preview().after, 1).?.group_journal.len);
    try testing.expect(lifecycleFindRow(ticket.preview().after, 2).?.portable_resume);
    try testing.expect(lifecycleFindRow(ticket.preview().after, 2).?.attachment_replica_dirty);
    ticket.abort();
    ticket.deinit();
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    _ = try s.armTokenLocalChannelProjection(tok(1), "#ninth", true, 2);
    const nine = try lifecycleCanonical(&s);
    try testing.expectError(error.TooManyPendingChannels, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(nine, try lifecycleCanonical(&s));
    // Same signed retry generation with conflicting payload is a corruption
    // witness, never request-order-dependent membership authority.
    s.lock.lockExclusive();
    const left = s.accounts.getPtr("Alice").?.items.items[0].local_channel_projections.?;
    const right = s.accounts.getPtr("Alice").?.items.items[1].local_channel_projections.?;
    left.* = .{ .len = 1, .revision = 99 };
    right.* = .{ .len = 1, .revision = 99 };
    left.items[0] = .{ .generation = 99, .channel_len = 5, .present = true, .member_mode_bits = 1 };
    right.items[0] = .{ .generation = 99, .channel_len = 5, .present = false };
    @memcpy(left.items[0].channel_bytes[0..5], "#Same");
    @memcpy(right.items[0].channel_bytes[0..5], "#same");
    s.lock.unlockExclusive();
    try testing.expectError(error.ProjectionConflict, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    ops[0].intent.rebind.kind = .{ .adopt_verified = true };
    try testing.expectError(error.ProjectionConflict, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
}

test "Session lifecycle batch newest folded journal and attachment retirement remain exact" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const source = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    _ = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    const earlier = try s.armTokenLocalChannelProjection(tok(1), "#Case", false, 0);
    const latest = try s.armTokenLocalChannelProjection(tok(2), "#case", true, 7);
    _ = try s.armAttachmentLocalChannelProjection(tok(1), aid(1), "#old-exact", true, 3);
    _ = try s.armAttachmentLocalChannelProjection(tok(2), aid(2), "#sibling-only", true, 4);
    try testing.expect(s.markAttachmentReplicaProjectionDirty(tok(1), aid(1)));
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", source), .target_account = "Alice", .target_token = tok(2), .kind = .join_existing } } }};
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.InvalidRequest, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    ops[0].intent.rebind.retire_attachment_work = true;
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const p = ticket.preview();
    try testing.expectEqual(@as(usize, 1), p.retired_attachments.len);
    try testing.expect(p.retired_attachments[0].attachment_work_retired);
    try testing.expectEqual(@as(u8, 1), p.retired_attachments[0].row.attachment_journal.len);
    try testing.expectEqual(@as(u8, 0), lifecycleFindRow(p.after, 1).?.attachment_journal.len);
    try testing.expectEqual(@as(u8, 1), lifecycleFindRow(p.after, 2).?.attachment_journal.len);
    const merged = lifecycleFindRow(p.after, 1).?.group_journal;
    try testing.expectEqual(@as(u8, 1), merged.len);
    try testing.expectEqual(latest.generation, merged.items[0].generation);
    try testing.expectEqual(@as(u8, 7), merged.items[0].member_mode_bits);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(!s.clearTokenLocalChannelProjection(tok(2), "#CASE", earlier.generation));
    try testing.expectEqual(latest.generation, s.tokenLocalChannelProjection(tok(2), "#case").?.generation);
    try testing.expect(s.attachmentLocalChannelProjection(tok(2), aid(2), "#sibling-only") != null);
    try testing.expect(s.attachmentLocalChannelProjection(tok(2), aid(1), "#old-exact") == null);
    try expectTokenIndexCoherent(&s);
}

test "Session lifecycle batch same token exact movement preserves attachment work and checked generations" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const row = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    _ = try s.armAttachmentLocalChannelProjection(tok(1), aid(1), "#exact", true, 1);
    _ = try s.armTokenLocalChannelProjection(tok(1), "#group", true, 2);
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", row), .target_account = "ALICE", .target_token = tok(1), .kind = .join_existing } } }};
    s.next_local_projection_generation = std.math.maxInt(u64);
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.GenerationExhausted, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    s.next_local_projection_generation = 2;
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    try testing.expectEqual(@as(usize, 0), ticket.preview().retired_attachments.len);
    try testing.expectEqual(@as(u8, 1), lifecycleFindRow(ticket.preview().after, 1).?.attachment_journal.len);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(s.clientHasAttachment("ALICE", 1, tok(1), aid(1)));
    try testing.expect(s.attachmentLocalChannelProjection(tok(1), aid(1), "#exact") != null);
    ticket.deinit();
    s.next_lifecycle_serial = std.math.maxInt(u64);
    try testing.expectError(error.GenerationExhausted, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &.{}, .observation_only = .{ .account = "ALICE", .client = 2 } }));
    ops[0].intent.rebind.target_account = "Foreign";
}

test "Session lifecycle batch explicit sentinel replacement owns inputs and refuses reusable null IDs" {
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_sessions_per_account = 1 });
        defer s.deinit();
        const old = try s.attach("Alice", 1, @splat(0), 10);
        const account = try testing.allocator.dupe(u8, "Alice");
        var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = account, .client = 1, .signon_ms = 20, .kind = .fresh, .replace_sentinel = lifecycleSelector(account, old) } } }};
        const canonical = try lifecycleCanonical(&s);
        failing.fail_index = failing.alloc_index + index;
        var ticket = s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }) catch |err| {
            testing.allocator.free(account);
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(canonical, try lifecycleCanonical(&s));
            failing.fail_index = std.math.maxInt(usize);
            ops[0].intent.admit.account = "Alice";
            ops[0].intent.admit.replace_sentinel.?.account = "Alice";
            var retry = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
            defer retry.deinit();
            try retry.validateForCut();
            retry.commit();
            retry.finish();
            continue;
        };
        defer ticket.deinit();
        @memset(account, 0);
        testing.allocator.free(account);
        const result = ticket.preview().admissions[0].result.tracked;
        try testing.expect(result.attachment_id != null);
        try testing.expect(!tokenIsSentinel(result.token));
        try ticket.validateForCut();
        ticket.commit();
        ticket.finish();
        try testing.expect(s.clientHasAttachment("Alice", 1, result.token, result.attachment_id.?));
        break;
    }
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const legacy = try s.attach("Alice", 1, tok(1), 10);
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 1, .signon_ms = 20, .kind = .fresh, .replace_sentinel = lifecycleSelector("Alice", legacy) } } }};
    try testing.expectError(error.InvalidRequest, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    ops[0].intent.admit.replace_sentinel.?.exact.signon_ms += 1;
    try testing.expectError(error.StaleSelector, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    ops[0].intent.admit.replace_sentinel = lifecycleSelector("Alice", legacy);
    ops[0].intent.admit.client = 2;
    try testing.expectError(error.InvalidRequest, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
}

test "Session lifecycle batch observes absence without pruning legacy empty keys and effects own retirement" {
    var s = SessionStore.init(testing.allocator);
    _ = try s.ensureAccount("Empty");
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &.{}, .observation_only = .{ .account = "Empty", .client = 1 } });
    try testing.expectEqual(@as(usize, 1), ticket.preview().affected_physical.len);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    ticket.deinit();
    try testing.expect(s.accounts.contains("Empty"));
    _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "retained retirement bytes"));
    const row = s.findDetachedAttachmentSessionInAccount("Alice", tok(1), aid(1)).?;
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .remove = .{ .source = lifecycleSelector("Alice", row), .reason = .garbage_collect } } }};
    ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    const retired = ticket.preview().retired_attachments;
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    // Recreate/remove the same display key, then even destroy the live store;
    // ticket retirement owns the OLD key/list/snapshot independently.
    _ = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    s.deinit();
    try testing.expectEqualStrings("Alice", retired[0].row.account);
    try testing.expectEqualStrings("retained retirement bytes", retired[0].row.snapshot.?);
    ticket.deinit();
    ticket.deinit();
}

test "Session lifecycle batch bounded payload work excludes unrelated registry snapshots" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const payload = try testing.allocator.alloc(u8, 8192);
    defer testing.allocator.free(payload);
    @memset(payload, 'x');
    for (0..128) |i| {
        var account: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&account, "Unrelated{d}", .{i});
        _ = try s.attachWithAttachment(name, @intCast(i + 10), tokenNumber(i + 10), aidNumber(i + 10), 1);
        try testing.expect(s.markDetachedWithSnapshot(name, @intCast(i + 10), payload));
    }
    _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "KEEP"));
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 2, .signon_ms = 20, .kind = .{ .join_existing = tok(1) } } } }};
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .limits = .{ .max_payload_bytes = 4 } });
    defer ticket.deinit();
    const metric = ticket.preview().complexity;
    try testing.expectEqual(@as(usize, 129), metric.discovery_row_visits);
    try testing.expectEqual(@as(usize, 1), metric.candidate_row_visits);
    try testing.expectEqual(@as(usize, 4), metric.copied_payload_bytes);
    try testing.expectEqual(@as(usize, 2), metric.normalization_row_visits);
    try testing.expectEqual(@as(usize, 5), metric.index_row_visits);
    ticket.abort();
    ticket.deinit();
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .limits = .{ .max_payload_bytes = 3 } }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
}

fn expectTokenIndexCoherent(store: *SessionStore) !void {
    store.lock.lockShared();
    defer store.lock.unlockShared();

    var indexed_rows: usize = 0;
    var entries = store.token_index.iterator();
    while (entries.next()) |map_entry| {
        const token = map_entry.key_ptr.*;
        const entry = map_entry.value_ptr;
        try testing.expect(!tokenIsSentinel(token));
        try testing.expect(entry.rows.items.len != 0);
        indexed_rows += entry.rows.items.len;

        var portable_rows: usize = 0;
        var dirty_rows: usize = 0;
        var projection_dirty_rows: usize = 0;
        var drop_reserved_rows: usize = 0;
        const owner = entry.rows.items[0].account;
        for (entry.rows.items, 0..) |locator, locator_index| {
            try testing.expect(std.ascii.eqlIgnoreCase(owner, locator.account));
            const session = store.sessionForTokenLocatorLocked(locator) orelse
                return error.TestUnexpectedResult;
            try testing.expectEqual(token, session.token);
            if (session.portable_resume) portable_rows += 1;
            if (session.replica_dirty) dirty_rows += 1;
            if (session.replica_projection_dirty) projection_dirty_rows += 1;
            if (session.drop_reservation != 0) drop_reserved_rows += 1;
            if (session.local_channel_projections) |set| {
                try testing.expectEqualDeep(entry.local_projections, set.*);
            } else {
                try testing.expect(entry.local_projections.isEmpty());
            }
            for (entry.rows.items[locator_index + 1 ..]) |later| {
                try testing.expect(locator.client != later.client or
                    !std.mem.eql(u8, locator.account, later.account));
            }
        }
        try testing.expectEqual(portable_rows, entry.portable_rows);
        try testing.expectEqual(dirty_rows, entry.dirty_rows);
        try testing.expectEqual(projection_dirty_rows, entry.projection_dirty_rows);
        try testing.expectEqual(drop_reserved_rows, entry.drop_reserved_rows);
    }

    var registry_rows: usize = 0;
    var accounts = store.accounts.iterator();
    while (accounts.next()) |account_entry| {
        for (account_entry.value_ptr.items.items) |session| {
            if (tokenIsSentinel(session.token)) continue;
            registry_rows += 1;
            const entry = store.token_index.getPtr(session.token) orelse
                return error.TestUnexpectedResult;
            try testing.expect(store.tokenLocatorIndex(
                entry,
                account_entry.key_ptr.*,
                session.client,
            ) != null);
        }
    }
    try testing.expectEqual(registry_rows, indexed_rows);
}

test "token index keeps distinct-token attachment work bounded at high cardinality" {
    const row_count = 512;
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    s.resetTokenIndexComplexity();

    for (0..row_count) |index| {
        var account_buf: [32]u8 = undefined;
        const account = try std.fmt.bufPrint(&account_buf, "account-{d}", .{index});
        _ = try s.attach(account, @intCast(index + 1), tokenNumber(index + 1), @intCast(index));
    }

    const complexity = s.tokenIndexComplexitySnapshot();
    try testing.expectEqual(@as(usize, row_count * 3), complexity.lookups);
    try testing.expectEqual(@as(usize, 0), complexity.group_row_visits);
    try testing.expectEqual(@as(usize, row_count), s.token_index.count());
    try expectTokenIndexCoherent(&s);
}

test "token index reconstruction normalizes one high-cardinality group linearly without allocation" {
    const sibling_count = 257;
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_sessions_per_account = sibling_count });
    defer s.deinit();
    const token = tokenNumber(0xA11CE);
    s.resetTokenIndexComplexity();

    for (0..sibling_count) |index| {
        _ = try s.attachWithAttachment(
            "Alice",
            @intCast(index + 1),
            token,
            aidNumber(index + 1),
            @intCast(index),
        );
    }
    const reconstruction = s.tokenIndexComplexitySnapshot();
    try testing.expectEqual(@as(usize, sibling_count * 3), reconstruction.lookups);
    try testing.expectEqual(@as(usize, 0), reconstruction.group_row_visits);
    try testing.expect(s.restorePortableResumeIssued("Alice", 1, true));

    s.resetTokenIndexComplexity();
    failing.fail_index = failing.alloc_index;
    try s.normalizePortableGroupsAfterRestore();
    try testing.expect(!failing.has_induced_failure);
    const complexity = s.tokenIndexComplexitySnapshot();
    try testing.expectEqual(@as(usize, 0), complexity.lookups);
    try testing.expectEqual(@as(usize, sibling_count), complexity.group_row_visits);

    var rows: [sibling_count]Session = undefined;
    const restored = s.sessionsInto("Alice", &rows);
    try testing.expectEqual(@as(usize, sibling_count), restored.len);
    for (restored) |session| try testing.expect(session.portable_resume);
    var work: [sibling_count]AttachmentReplicaWork = undefined;
    try testing.expectEqual(@as(usize, sibling_count), s.dirtyPortableAttachmentsInto(&work).len);
}

test "token index reservation OOM never publishes a row or empty account" {
    var saw_success = false;
    for (0..8) |failure_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.init(failing.allocator());
        defer s.deinit();
        _ = try s.attach("seed", 1, @as(Token, @splat(0)), 1);

        const target = tokenNumber(0xB1AD);
        failing.fail_index = failing.alloc_index + failure_offset;
        const result = s.attach("fresh", 2, target, 2);
        if (result) |_| {
            try testing.expect(!failing.has_induced_failure);
            try testing.expect(s.containsToken(target));
            saw_success = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expect(failing.has_induced_failure);
            try testing.expect(!s.containsToken(target));
            try testing.expect(s.accounts.getPtr("fresh") == null);
            var rows: [1]Session = undefined;
            try testing.expectEqual(@as(usize, 1), s.sessionsInto("seed", &rows).len);
        }
    }
    try testing.expect(saw_success);
}

test "token index stays coherent across eviction replacement bind and removal" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();
    const evicted_token = tokenNumber(0xE01);
    const sibling_token = tokenNumber(0xE02);
    const target_token = tokenNumber(0xE03);
    const replacement_token = tokenNumber(0xE04);

    _ = try s.attach("alice", 1, evicted_token, 1);
    _ = try s.attach("alice", 2, sibling_token, 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetached("alice", 1));
    try expectTokenIndexCoherent(&s);

    const outcome = try s.attachReportingEviction("alice", 3, target_token, 3);
    try testing.expectEqual(evicted_token, outcome.evicted.?.token);
    try testing.expect(!s.containsToken(evicted_token));
    try testing.expect(s.containsToken(sibling_token));
    try testing.expect(s.containsToken(target_token));
    try expectTokenIndexCoherent(&s);

    _ = try s.attach("alice", 2, replacement_token, 4);
    try testing.expect(!s.containsToken(sibling_token));
    try testing.expect(s.containsToken(replacement_token));
    try expectTokenIndexCoherent(&s);

    try testing.expect(s.joinTokenGroup("alice", 2, target_token));
    try testing.expect(!s.containsToken(replacement_token));
    try testing.expect(s.containsToken(target_token));
    try expectTokenIndexCoherent(&s);

    try testing.expect(s.remove("alice", 3));
    try testing.expect(s.containsToken(target_token));
    try expectTokenIndexCoherent(&s);
    try testing.expect(s.remove("alice", 2));
    try testing.expect(!s.containsToken(target_token));
    try expectTokenIndexCoherent(&s);
}

test "rowless token-index adoption is leak-clean at every allocation boundary" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const source = tokenNumber(0xA0A0);
            const target = tokenNumber(0xB0B0);
            _ = try s.attach("alice", 1, source, 1);
            try testing.expect(s.markPortableResumeIssued("alice", 1));
            _ = try s.armTokenLocalChannelProjection(source, "#pending", true, 3);

            var prepared = s.prepareTokenBind(
                "alice",
                1,
                target,
                .{ .adopt_verified = true },
            ) orelse return error.OutOfMemory;
            defer prepared.deinit();
            try testing.expect(prepared.commit());
            prepared.finish();
            try testing.expect(!s.containsToken(source));
            try testing.expect(s.containsToken(target));
            try testing.expect(s.tokenLocalChannelProjection(target, "#pending") != null);
            try expectTokenIndexCoherent(&s);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "exact rebind token-index work ignores unrelated registry cardinality" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const resume_token = tokenNumber(0xCA11);
    const bootstrap_token = tokenNumber(0xCA12);
    const stable = aidNumber(0xCA11);
    _ = try s.attachWithAttachment("Alice", 9001, resume_token, stable, 1);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 9001, "state"));
    _ = try s.attachWithAttachment("alice", 9002, bootstrap_token, aidNumber(0xCA12), 2);
    for (0..512) |index| {
        var account_buf: [32]u8 = undefined;
        const account = try std.fmt.bufPrint(&account_buf, "unrelated-{d}", .{index});
        _ = try s.attach(
            account,
            @intCast(index + 1),
            tokenNumber(0xD000 + index),
            @intCast(index),
        );
    }

    s.resetTokenIndexComplexity();
    var prepared = s.prepareExactAttachmentRebind("alice", 9002, resume_token, stable) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expect(prepared.commit());
    prepared.finish();
    const complexity = s.tokenIndexComplexitySnapshot();
    // Three identity/remap lookups plus the two O(1) source/target reservation
    // guards required to freeze both token groups during exact rebind.
    try testing.expectEqual(@as(usize, 5), complexity.lookups);
    try testing.expectEqual(@as(usize, 2), complexity.group_row_visits);
    try expectTokenIndexCoherent(&s);
}

test "stable attachment ids isolate sibling restore state within one token" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x51);
    const first_id = aid(0xA1);
    const second_id = aid(0xB2);
    _ = try s.attachWithAttachment("alice", 1, token, first_id, 10);
    _ = try s.attachWithAttachment("alice", 2, token, second_id, 20);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "first-state"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "second-state"));

    const first = s.findDetachedAttachmentSessionInAccount("alice", token, first_id) orelse
        return error.TestUnexpectedResult;
    const second = s.findDetachedAttachmentSessionInAccount("alice", token, second_id) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(ClientId, 1), first.client);
    try testing.expectEqual(@as(ClientId, 2), second.client);
    try testing.expect(first.attachment_id.?.eql(first_id));
    try testing.expect(second.attachment_id.?.eql(second_id));

    const first_snapshot = (try s.copyDetachedAttachmentSnapshotInAccount(
        testing.allocator,
        "alice",
        token,
        first_id,
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(first_snapshot);
    const second_snapshot = (try s.copyDetachedAttachmentSnapshotInAccount(
        testing.allocator,
        "alice",
        token,
        second_id,
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(second_snapshot);
    try testing.expectEqualStrings("first-state", first_snapshot);
    try testing.expectEqualStrings("second-state", second_snapshot);

    // Removing one exact ghost never consumes or aliases its sibling.
    try testing.expect(s.remove("alice", first.client));
    try testing.expect(s.findAttachmentSessionInAccount("alice", token, first_id) == null);
    try testing.expect(s.findDetachedAttachmentSessionInAccount("alice", token, second_id) != null);
}

test "stable attachment id uniqueness fails before eviction or row mutation" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();

    const stable = aid(0xCC);
    _ = try s.attachWithAttachment("alice", 1, tok(1), stable, 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "retained"));

    try testing.expectError(
        error.DuplicateAttachmentId,
        s.attachWithAttachment("alice", 2, tok(2), stable, 20),
    );
    try testing.expectError(
        error.DuplicateAttachmentId,
        s.attachWithAttachment("ALICE", 1, tok(1), stable, 30),
    );
    var rows: [2]Session = undefined;
    try testing.expectEqual(@as(usize, 1), s.sessionsInto("alice", &rows).len);
    const retained = (try s.copyDetachedAttachmentSnapshotInAccount(
        testing.allocator,
        "alice",
        tok(1),
        stable,
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(retained);
    try testing.expectEqualStrings("retained", retained);

    const zero = AttachmentId{ .raw = @splat(0) };
    try testing.expectError(
        error.InvalidAttachmentId,
        s.attachWithAttachment("bob", 7, tok(7), zero, 1),
    );
    try testing.expect(!s.containsAttachment(zero));
}

test "stable attachment index reservation OOM publishes no partial row" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0xCD);
    const stable = aid(0xCD);
    _ = try s.attach("alice", 1, token, 10);
    failing.fail_index = failing.alloc_index;
    try testing.expectError(
        error.OutOfMemory,
        s.attachWithAttachment("alice", 1, token, stable, 20),
    );
    const unchanged = s.findTokenSessionInAccount("alice", token).?;
    try testing.expectEqual(@as(ClientId, 1), unchanged.client);
    try testing.expectEqual(@as(i64, 10), unchanged.signon_ms);
    try testing.expect(unchanged.attachment_id == null);
    try testing.expect(!s.containsAttachment(stable));

    failing.fail_index = std.math.maxInt(usize);
    _ = try s.attachWithAttachment("alice", 1, token, stable, 20);
    try testing.expect(s.clientHasAttachment("alice", 1, token, stable));
    try testing.expect(s.remove("alice", 1));
    try testing.expect(!s.containsAttachment(stable));
}

test "legacy refresh preserves an already-current attachment id" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const stable = aid(0xD4);
    _ = try s.attachWithAttachment("alice", 9, tok(9), stable, 1);
    _ = try s.attach("alice", 9, tok(8), 2);
    const refreshed = s.findAttachmentSessionInAccount("alice", tok(8), stable) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(ClientId, 9), refreshed.client);
    try testing.expect(s.clientHasAttachment("alice", 9, tok(8), stable));
    try testing.expect(s.resumeHandleForClient("alice", 9).?.attachment_id.?.eql(stable));
}

test "idempotent current attach rejects stable identity rotation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const stable = aid(0xD5);
    const reminted = aid(0xD6);
    _ = try s.attachWithAttachment("alice", 9, tok(9), stable, 1);
    try testing.expectError(
        error.AttachmentIdMismatch,
        s.attachWithAttachment("alice", 9, tok(8), reminted, 2),
    );
    try testing.expect(s.clientHasAttachment("alice", 9, tok(9), stable));
    try testing.expect(!s.containsAttachment(reminted));

    // Explicit current adoption may upgrade a legacy null-id row once.
    _ = try s.attach("bob", 10, tok(10), 1);
    _ = try s.attachWithAttachment("bob", 10, tok(10), reminted, 2);
    try testing.expect(s.clientHasAttachment("bob", 10, tok(10), reminted));
}

test {
    _ = @import("session_sid.zig");
}

test "same attachment token rotation never rekeys receive projection work" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const old_token = tok(0xD7);
    const new_token = tok(0xD8);
    const stable = aid(0xD7);
    _ = try s.attachWithAttachment("alice", 1, old_token, stable, 1);
    try testing.expect(s.markAttachmentReplicaProjectionDirty(old_token, stable));
    _ = try s.armAttachmentLocalChannelProjection(old_token, stable, "#old", true, 3);

    _ = try s.attachWithAttachment("alice", 1, new_token, stable, 2);
    var work: [1]AttachmentReplicaWork = undefined;
    try testing.expectEqual(@as(usize, 0), s.dirtyAttachmentProjectionsInto(&work).len);
    try testing.expect(s.attachmentLocalChannelProjection(new_token, stable, "#old") == null);
    try testing.expect(s.attachmentLocalChannelProjection(old_token, stable, "#old") == null);
    try testing.expect(s.clientHasAttachment("alice", 1, new_token, stable));
}

test "public Session copies never expose store-owned journal pointers" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const token = tok(0xD9);
    const stable = aid(0xD9);
    _ = try s.attachWithAttachment("alice", 1, token, stable, 1);
    _ = try s.armTokenLocalChannelProjection(token, "#group", true, 1);
    _ = try s.armAttachmentLocalChannelProjection(token, stable, "#exact", true, 2);

    var rows: [1]Session = undefined;
    const listed = s.sessionsInto("alice", &rows);
    try testing.expect(listed[0].local_channel_projections == null);
    try testing.expect(listed[0].attachment_channel_projections == null);
    const exact = s.findAttachmentSessionInAccount("alice", token, stable).?;
    try testing.expect(exact.local_channel_projections == null);
    try testing.expect(exact.attachment_channel_projections == null);
    const allocated = try s.copySessionsAlloc(testing.allocator, "alice");
    defer testing.allocator.free(allocated);
    try testing.expect(allocated[0].local_channel_projections == null);
    try testing.expect(allocated[0].attachment_channel_projections == null);

    // Dedicated value APIs remain usable after the copies leave the lock.
    try testing.expect(s.tokenLocalChannelProjection(token, "#group") != null);
    try testing.expect(s.attachmentLocalChannelProjection(token, stable, "#exact") != null);
}

test "prepared exact attachment rebind aborts cleanly then commits without allocation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const resume_token = tok(0x31);
    const bootstrap_token = tok(0x32);
    const stable = aid(0xE1);
    const bootstrap_id = aid(0xE2);
    _ = try s.attachWithAttachment("alice", 10, resume_token, stable, 100);
    try testing.expect(s.markPortableResumeIssued("alice", 10));
    try testing.expect(s.markTokenReplicaDirty(resume_token));
    _ = try s.armTokenLocalChannelProjection(resume_token, "#pending", true, 3);
    const attachment_intent = try s.armAttachmentLocalChannelProjection(
        resume_token,
        stable,
        "#only-this-client",
        true,
        5,
    );
    try testing.expect(s.markDetachedWithSnapshot("alice", 10, "exact-state"));
    _ = try s.attachWithAttachment("alice", 20, bootstrap_token, bootstrap_id, 200);
    try expectTokenIndexCoherent(&s);

    var aborted = s.prepareExactAttachmentRebind("alice", 20, resume_token, stable) orelse
        return error.TestUnexpectedResult;
    defer aborted.deinit();
    try testing.expectEqualStrings("exact-state", aborted.snapshot().?);
    try testing.expectEqual(@as(ClientId, 10), aborted.remap().old_client);
    try testing.expectEqual(@as(ClientId, 20), aborted.remap().new_client);
    aborted.abort();

    // Abort consumes nothing and leaves both identities independently owned.
    try testing.expect(s.findDetachedAttachmentSessionInAccount("alice", resume_token, stable) != null);
    try testing.expect(s.clientHasAttachment("alice", 20, bootstrap_token, bootstrap_id));

    var committed = s.prepareExactAttachmentRebind("alice", 20, resume_token, stable) orelse
        return error.TestUnexpectedResult;
    defer committed.deinit();
    try testing.expect(committed.commit());
    committed.finish();

    var rows: [2]Session = undefined;
    const current = s.sessionsInto("alice", &rows);
    try testing.expectEqual(@as(usize, 1), current.len);
    try testing.expectEqual(@as(ClientId, 20), current[0].client);
    try testing.expect(current[0].attached);
    try testing.expectEqual(resume_token, current[0].token);
    try testing.expect(current[0].attachment_id.?.eql(stable));
    try testing.expect(current[0].snapshot == null);
    try testing.expect(current[0].portable_resume);
    try testing.expect(!s.containsAttachment(bootstrap_id));
    try testing.expect(!s.containsToken(bootstrap_token));
    try testing.expect(s.containsToken(resume_token));
    try testing.expect(s.clientHasAttachment("alice", 20, resume_token, stable));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionRowCount());
    try testing.expect(s.tokenLocalChannelProjection(resume_token, "#pending") != null);
    try testing.expectEqual(@as(usize, 1), s.dirtyAttachmentLocalProjectionRowCount());
    try testing.expectEqual(
        attachment_intent.generation,
        s.attachmentLocalChannelProjection(resume_token, stable, "#only-this-client").?.generation,
    );
    try expectTokenIndexCoherent(&s);
}

test "stable bootstrap attachment retries collisions and never evicts at capacity" {
    const ScriptedRandom = struct {
        calls: usize = 0,

        fn random(userdata: ?*anyopaque, out: []u8) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            @memset(out, if (self.calls == 1) 0xa1 else 0xa2);
        }
    };

    var vtable = std.testing.io.vtable.*;
    vtable.random = ScriptedRandom.random;
    var scripted = ScriptedRandom{};
    const scripted_io = std.Io{ .userdata = &scripted, .vtable = &vtable };

    var unique = SessionStore.init(testing.allocator);
    defer unique.deinit();
    _ = try unique.attachWithAttachment("seed", 1, tok(0x91), aid(0xa1), 1);
    const bootstrap = try unique.mintBootstrapAttachmentNoEvict(
        "alice",
        2,
        tok(0x92),
        2,
        scripted_io,
    );
    try testing.expectEqual(@as(usize, 2), scripted.calls);
    try testing.expect(bootstrap.attachment_id.eql(aid(0xa2)));
    try testing.expect(bootstrap.session.attachment_id.?.eql(aid(0xa2)));
    try testing.expect(unique.clientHasAttachment("alice", 2, tok(0x92), aid(0xa2)));
    try testing.expectError(
        error.ClientAlreadyTracked,
        unique.attachBootstrapWithAttachmentNoEvict("alice", 2, tok(0x93), aid(0xa3), 3),
    );
    try testing.expectError(
        error.InvalidToken,
        unique.attachBootstrapWithAttachmentNoEvict("alice", 3, @splat(0), aid(0xa3), 3),
    );
    try expectTokenIndexCoherent(&unique);

    var capped = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer capped.deinit();
    const preserved_token = tok(0xb1);
    const preserved_id = aid(0xb1);
    _ = try capped.attachWithAttachment("alice", 10, preserved_token, preserved_id, 10);
    try testing.expect(capped.markDetachedWithSnapshot("alice", 10, "preserved"));
    try testing.expectError(
        error.TooManySessions,
        capped.attachBootstrapWithAttachmentNoEvict("alice", 20, tok(0xb2), aid(0xb2), 20),
    );
    try testing.expect(capped.findDetachedAttachmentSessionInAccount(
        "alice",
        preserved_token,
        preserved_id,
    ) != null);
    const preserved = (try capped.copyDetachedAttachmentSnapshotInAccount(
        testing.allocator,
        "alice",
        preserved_token,
        preserved_id,
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(preserved);
    try testing.expectEqualStrings("preserved", preserved);
    try testing.expect(!capped.containsAttachment(aid(0xb2)));
    try testing.expect(!capped.containsToken(tok(0xb2)));
    try expectTokenIndexCoherent(&capped);
}

test "exact attachment ticket previews frozen rows and journal then preserves sibling under OOM" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_sessions_per_account = 4 });
    defer s.deinit();

    const token = tok(0xc1);
    const exact_id = aid(0xc1);
    const sibling_id = aid(0xc2);
    const bootstrap_token = tok(0xc3);
    const bootstrap_id = aid(0xc3);
    _ = try s.attachWithAttachment("alice", 1, token, exact_id, 1);
    _ = try s.attachWithAttachment("alice", 2, token, sibling_id, 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    _ = try s.armTokenLocalChannelProjection(token, "#resume", true, 7);
    _ = try s.armAttachmentLocalChannelProjection(token, exact_id, "#exact", false, 0);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "exact"));
    _ = try s.attachBootstrapWithAttachmentNoEvict(
        "alice",
        3,
        bootstrap_token,
        bootstrap_id,
        3,
    );

    var aborted = s.prepareExactAttachmentRebind("alice", 3, token, exact_id) orelse
        return error.TestUnexpectedResult;
    defer aborted.deinit();
    try testing.expectEqual(@as(usize, 3), aborted.accountRows().len);
    try testing.expect(aborted.resultPortable());
    var preview_buf: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    const preview = aborted.mergedLocalChannelProjectionsInto(&preview_buf);
    try testing.expectEqual(@as(usize, 2), preview.len);
    try testing.expectEqualStrings("#exact", preview[0].channel());
    try testing.expect(!preview[0].present);
    try testing.expectEqualStrings("#resume", preview[1].channel());
    aborted.abort();
    try testing.expect(s.clientHasAttachment("alice", 1, token, exact_id));
    try testing.expect(s.clientHasAttachment("alice", 2, token, sibling_id));
    try testing.expect(s.clientHasAttachment("alice", 3, bootstrap_token, bootstrap_id));

    var committed = s.prepareExactAttachmentRebind("alice", 3, token, exact_id) orelse
        return error.TestUnexpectedResult;
    defer committed.deinit();
    failing.fail_index = failing.alloc_index;
    try testing.expect(committed.commit());
    committed.finish();
    try testing.expect(!failing.has_induced_failure);

    try testing.expect(s.clientHasAttachment("alice", 3, token, exact_id));
    try testing.expect(s.clientHasAttachment("alice", 2, token, sibling_id));
    try testing.expect(!s.containsClient("alice", 1));
    try testing.expect(!s.containsAttachment(bootstrap_id));
    try testing.expect(!s.containsToken(bootstrap_token));
    try testing.expect(s.tokenLocalChannelProjection(token, "#resume") != null);
    try expectTokenIndexCoherent(&s);
}

test "exact attachment rebind remaps an untracked claimant in place at account cap" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.initWithConfig(failing.allocator(), .{ .max_sessions_per_account = 2 });
    defer s.deinit();

    const token = tok(0xd1);
    const exact_id = aid(0xd1);
    const sibling_id = aid(0xd2);
    _ = try s.attachWithAttachment("alice", 1, token, exact_id, 10);
    _ = try s.attachWithAttachment("alice", 2, token, sibling_id, 20);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "at-cap"));

    var prepared = s.prepareExactAttachmentRebind("alice", 3, token, exact_id) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expectEqual(@as(usize, 2), prepared.accountRows().len);
    try testing.expectEqualStrings("at-cap", prepared.snapshot().?);
    try testing.expectEqual(@as(ClientId, 1), prepared.remap().old_client);
    try testing.expectEqual(@as(ClientId, 3), prepared.remap().new_client);

    failing.fail_index = failing.alloc_index;
    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expect(!failing.has_induced_failure);

    var rows: [2]Session = undefined;
    const current = s.sessionsInto("alice", &rows);
    try testing.expectEqual(@as(usize, 2), current.len);
    try testing.expect(!s.containsClient("alice", 1));
    try testing.expect(s.clientHasAttachment("alice", 3, token, exact_id));
    try testing.expect(s.clientHasAttachment("alice", 2, token, sibling_id));
    const rebound = s.findAttachmentSessionInAccount("alice", token, exact_id) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(i64, 10), rebound.signon_ms);
    try testing.expect(rebound.attached);
    try expectTokenIndexCoherent(&s);
}

test "exact attachment rebind rejects live wrong-token and sibling selectors" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x41);
    const first = aid(0xF1);
    const second = aid(0xF2);
    _ = try s.attachWithAttachment("alice", 1, token, first, 1);
    _ = try s.attachWithAttachment("alice", 2, token, second, 2);
    _ = try s.attachWithAttachment("alice", 3, tok(0x43), aid(0xF3), 3);

    // An exact restore never steals a live sibling.
    try testing.expect(s.prepareExactAttachmentRebind("alice", 3, token, first) == null);
    try testing.expect(s.markDetached("alice", 1));
    try testing.expect(s.prepareExactAttachmentRebind("alice", 3, tok(0x44), first) == null);
    try testing.expect(s.prepareExactAttachmentRebind("alice", 3, token, second) == null);
    try testing.expect(s.clientHasAttachment("alice", 1, token, first));
    try testing.expect(s.clientHasAttachment("alice", 2, token, second));
}

test "exact attachment rebind refuses non-bootstrap claimant authority" {
    const Cases = struct {
        fn seed(store: *SessionStore) !void {
            _ = try store.attachWithAttachment("alice", 1, tok(0x45), aid(0x45), 1);
            try testing.expect(store.markDetachedWithSnapshot("alice", 1, "ghost"));
            _ = try store.attachWithAttachment("alice", 2, tok(0x46), aid(0x46), 2);
        }
    };

    {
        var s = SessionStore.init(testing.allocator);
        defer s.deinit();
        try Cases.seed(&s);
        try testing.expect(s.markDetached("alice", 2));
        try testing.expect(s.prepareExactAttachmentRebind("alice", 2, tok(0x45), aid(0x45)) == null);
    }
    {
        var s = SessionStore.init(testing.allocator);
        defer s.deinit();
        try Cases.seed(&s);
        try testing.expect(s.markPortableResumeIssued("alice", 2));
        try testing.expect(s.prepareExactAttachmentRebind("alice", 2, tok(0x45), aid(0x45)) == null);
    }
    {
        var s = SessionStore.init(testing.allocator);
        defer s.deinit();
        try Cases.seed(&s);
        _ = try s.armAttachmentLocalChannelProjection(tok(0x46), aid(0x46), "#bootstrap", true, 1);
        try testing.expect(s.prepareExactAttachmentRebind("alice", 2, tok(0x45), aid(0x45)) == null);
    }
}

test "exact attachment rebind crosses folded account display aliases atomically" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x61);
    const stable = aid(0x61);
    _ = try s.attachWithAttachment("alice", 1, token, stable, 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "folded-state"));
    _ = try s.attachWithAttachment("ALICE", 2, tok(0x62), aid(0x62), 20);

    var prepared = s.prepareExactAttachmentRebind("ALICE", 2, token, stable) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expectEqualStrings("folded-state", prepared.snapshot().?);
    try testing.expect(prepared.commit());
    prepared.finish();

    var old_rows: [1]Session = undefined;
    try testing.expectEqual(@as(usize, 0), s.sessionsInto("alice", &old_rows).len);
    try testing.expect(s.clientHasAttachment("ALICE", 2, token, stable));
    try testing.expect(!s.containsClient("ALICE", 1));
    try testing.expect(!s.containsToken(tok(0x62)));
    var account_buf: [16]u8 = undefined;
    const match = s.findByTokenInto(token, &account_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("ALICE", match.account);
    try testing.expectEqual(@as(ClientId, 2), match.client);
    try expectTokenIndexCoherent(&s);
}

test "portable group arms and retries every stable sibling independently" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x71);
    const first = aid(0x71);
    const second = aid(0x72);
    const third = aid(0x73);
    _ = try s.attachWithAttachment("alice", 1, token, first, 1);
    _ = try s.attachWithAttachment("alice", 2, token, second, 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));

    var work: [4]AttachmentReplicaWork = undefined;
    const initial = s.dirtyPortableAttachmentsInto(&work);
    try testing.expectEqual(@as(usize, 2), initial.len);
    try testing.expectEqual(token, initial[0].token);
    try testing.expectEqual(token, initial[1].token);
    try testing.expect(!initial[0].attachment_id.eql(initial[1].attachment_id));

    try testing.expect(s.clearAttachmentReplicaDirty(token, first));
    const retained = s.dirtyPortableAttachmentsInto(&work);
    try testing.expectEqual(@as(usize, 1), retained.len);
    try testing.expect(retained[0].attachment_id.eql(second));

    // A later create-new sibling entering an already-portable token is armed at
    // bind commit without re-dirtying or consuming its existing siblings.
    _ = try s.attachWithAttachment("alice", 3, tok(0x74), third, 3);
    try testing.expect(s.joinTokenGroup("alice", 3, token));
    const after_join = s.dirtyPortableAttachmentsInto(&work);
    try testing.expectEqual(@as(usize, 2), after_join.len);
    var saw_second = false;
    var saw_third = false;
    for (after_join) |item| {
        saw_second = saw_second or item.attachment_id.eql(second);
        saw_third = saw_third or item.attachment_id.eql(third);
    }
    try testing.expect(saw_second and saw_third);
}

test "portable authority survives issuer removal on every sibling row" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x75);
    const issuer = aid(0x75);
    const sibling = aid(0x76);
    _ = try s.attachWithAttachment("alice", 1, token, issuer, 1);
    _ = try s.attachWithAttachment("alice", 2, token, sibling, 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.resumeHandleForClient("alice", 1).?.portable);
    try testing.expect(s.resumeHandleForClient("alice", 2).?.portable);
    try testing.expect(s.clearAttachmentReplicaDirty(token, issuer));
    try testing.expect(s.clearAttachmentReplicaDirty(token, sibling));

    try testing.expect(s.remove("alice", 1));
    try testing.expect(s.resumeHandleForClient("alice", 2).?.portable);
    try testing.expect(s.markAttachmentReplicaDirty(token, sibling));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "sibling-state"));
    const copies = try s.copyPortableDetachedAttachmentSnapshots(testing.allocator);
    defer {
        for (copies) |*copy| copy.deinit(testing.allocator);
        testing.allocator.free(copies);
    }
    try testing.expectEqual(@as(usize, 1), copies.len);
    try testing.expect(copies[0].attachment_id.eql(sibling));
}

test "portable claimant joining a nonportable group arms every target sibling" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const source = tok(0x79);
    const target = tok(0x7A);
    const claimant_id = aid(0x79);
    const target_a = aid(0x7A);
    const target_b = aid(0x7B);
    _ = try s.attachWithAttachment("alice", 1, source, claimant_id, 1);
    _ = try s.attachWithAttachment("alice", 2, target, target_a, 2);
    _ = try s.attachWithAttachment("alice", 3, target, target_b, 3);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.clearAttachmentReplicaDirty(source, claimant_id));

    try testing.expect(s.joinTokenGroup("alice", 1, target));
    var work: [3]AttachmentReplicaWork = undefined;
    const dirty = s.dirtyPortableAttachmentsInto(&work);
    try testing.expectEqual(@as(usize, 3), dirty.len);
    var saw_claimant = false;
    var saw_a = false;
    var saw_b = false;
    for (dirty) |item| {
        try testing.expectEqual(target, item.token);
        saw_claimant = saw_claimant or item.attachment_id.eql(claimant_id);
        saw_a = saw_a or item.attachment_id.eql(target_a);
        saw_b = saw_b or item.attachment_id.eql(target_b);
    }
    try testing.expect(saw_claimant and saw_a and saw_b);
}

test "post-restore portability normalization is linear transactional and complete" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0x77);
    const first = aid(0x77);
    const second = aid(0x78);
    _ = try s.attachWithAttachment("alice", 1, token, first, 1);
    _ = try s.attachWithAttachment("alice", 2, token, second, 2);
    try testing.expect(s.restorePortableResumeIssued("alice", 1, true));
    try testing.expect(s.restorePortableResumeIssued("alice", 2, false));

    s.resetTokenIndexComplexity();
    failing.fail_index = failing.alloc_index;
    try s.normalizePortableGroupsAfterRestore();
    try testing.expect(!failing.has_induced_failure);
    const complexity = s.tokenIndexComplexitySnapshot();
    try testing.expectEqual(@as(usize, 0), complexity.lookups);
    try testing.expectEqual(@as(usize, 2), complexity.group_row_visits);
    try testing.expect(s.findAttachmentSessionInAccount("alice", token, first).?.portable_resume);
    try testing.expect(s.findAttachmentSessionInAccount("alice", token, second).?.portable_resume);
    var work: [2]AttachmentReplicaWork = undefined;
    try testing.expectEqual(@as(usize, 2), s.dirtyPortableAttachmentsInto(&work).len);
}

test "portable detached attachment enumeration never dedupes same-token siblings" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x81);
    const first = aid(0x81);
    const second = aid(0x82);
    _ = try s.attachWithAttachment("Alice", 1, token, first, 1);
    _ = try s.attachWithAttachment("Alice", 2, token, second, 2);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "first"));
    try testing.expect(s.markDetachedWithSnapshot("Alice", 2, "second"));

    const copies = try s.copyPortableDetachedAttachmentSnapshots(testing.allocator);
    defer {
        for (copies) |*copy| copy.deinit(testing.allocator);
        testing.allocator.free(copies);
    }
    try testing.expectEqual(@as(usize, 2), copies.len);
    var saw_first = false;
    var saw_second = false;
    for (copies) |copy| {
        try testing.expectEqualStrings("Alice", copy.account);
        try testing.expectEqual(token, copy.token);
        if (copy.attachment_id.eql(first)) {
            saw_first = true;
            try testing.expectEqualStrings("first", copy.snapshot);
        } else if (copy.attachment_id.eql(second)) {
            saw_second = true;
            try testing.expectEqualStrings("second", copy.snapshot);
        } else return error.TestUnexpectedResult;
    }
    try testing.expect(saw_first and saw_second);
}

test "portable detached attachment enumeration is complete at high cardinality" {
    const sibling_count = 257;
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = sibling_count });
    defer s.deinit();
    const token = tok(0x83);

    for (0..sibling_count) |index| {
        const client: ClientId = @intCast(index + 1);
        _ = try s.attachWithAttachment("wide", client, token, aidNumber(index + 1), @intCast(index));
        try testing.expect(s.markDetachedWithSnapshot("wide", client, "x"));
    }
    try testing.expect(s.markPortableResumeIssued("wide", 1));

    const copies = try s.copyPortableDetachedAttachmentSnapshots(testing.allocator);
    defer {
        for (copies) |*copy| copy.deinit(testing.allocator);
        testing.allocator.free(copies);
    }
    try testing.expectEqual(@as(usize, sibling_count), copies.len);
    var seen: [sibling_count]bool = @splat(false);
    for (copies) |copy| {
        const value = std.mem.readInt(u64, copy.attachment_id.raw[8..16], .big);
        if (value == 0 or value > sibling_count) return error.TestUnexpectedResult;
        try testing.expect(!seen[value - 1]);
        seen[value - 1] = true;
    }
    for (seen) |present| try testing.expect(present);
}

test "attachment channel projection journals preserve divergent siblings" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x91);
    const first = aid(0x91);
    const second = aid(0x92);
    _ = try s.attachWithAttachment("alice", 1, token, first, 1);
    _ = try s.attachWithAttachment("alice", 2, token, second, 2);

    const first_same = try s.armAttachmentLocalChannelProjection(token, first, "#same", true, 0x01);
    _ = try s.armAttachmentLocalChannelProjection(token, first, "#first", true, 0x02);
    const second_same = try s.armAttachmentLocalChannelProjection(token, second, "#same", false, 0x40);
    _ = try s.armAttachmentLocalChannelProjection(token, second, "#second", true, 0x20);

    const second_before = s.attachmentLocalChannelProjection(token, second, "#same").?;
    try testing.expect(second_before.generation == second_same.generation);
    try testing.expect(!second_before.present);
    try testing.expectEqual(@as(u8, 0x40), second_before.member_mode_bits);
    try testing.expect(s.tokenLocalChannelProjection(token, "#same") == null);

    // Completing A cannot clear, replace, or even change B's generation.
    try testing.expect(s.clearAttachmentLocalChannelProjection(
        token,
        first,
        "#same",
        first_same.generation,
    ));
    try testing.expect(s.attachmentLocalChannelProjection(token, first, "#same") == null);
    const second_after = s.attachmentLocalChannelProjection(token, second, "#same").?;
    try testing.expectEqualDeep(second_before, second_after);

    var work: [4]AttachmentLocalChannelProjectionWork = undefined;
    const pending = s.dirtyAttachmentLocalProjectionsInto(&work);
    try testing.expectEqual(@as(usize, 3), pending.len);
    var first_count: usize = 0;
    var second_count: usize = 0;
    for (pending) |item| {
        if (item.attachment_id.eql(first)) first_count += 1;
        if (item.attachment_id.eql(second)) second_count += 1;
    }
    try testing.expectEqual(@as(usize, 1), first_count);
    try testing.expectEqual(@as(usize, 2), second_count);
    try testing.expectEqual(@as(usize, 2), s.dirtyAttachmentLocalProjectionRowCount());
}

test "attachment channel projection first-arm OOM is isolated and retryable" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0x93);
    const first = aid(0x93);
    const second = aid(0x94);
    _ = try s.attachWithAttachment("alice", 1, token, first, 1);
    _ = try s.attachWithAttachment("alice", 2, token, second, 2);
    const generation_before = s.next_local_projection_generation;
    failing.fail_index = failing.alloc_index;
    try testing.expectError(
        error.OutOfMemory,
        s.armAttachmentLocalChannelProjection(token, first, "#oom", true, 1),
    );
    try testing.expectEqual(generation_before, s.next_local_projection_generation);
    try testing.expectEqual(@as(usize, 0), s.dirtyAttachmentLocalProjectionRowCount());
    try testing.expect(s.attachmentLocalChannelProjection(token, first, "#oom") == null);
    try testing.expect(s.attachmentLocalChannelProjection(token, second, "#oom") == null);

    failing.fail_index = std.math.maxInt(usize);
    const armed = try s.armAttachmentLocalChannelProjection(token, first, "#oom", true, 1);
    try testing.expectEqual(@as(usize, 1), s.dirtyAttachmentLocalProjectionRowCount());
    failing.has_induced_failure = false;
    failing.fail_index = failing.alloc_index;
    const replaced = try s.armAttachmentLocalChannelProjectionWithPrevious(
        token,
        first,
        "#OOM",
        false,
        7,
    );
    try testing.expectEqual(armed.generation, replaced.previous.?.generation);
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.rollbackAttachmentLocalChannelProjectionArm(
        token,
        first,
        replaced.intent.generation,
        replaced.previous,
    ));
    const restored = s.attachmentLocalChannelProjection(token, first, "#oom").?;
    try testing.expect(restored.present);
    try testing.expectEqual(@as(u8, 1), restored.member_mode_bits);
}

test "local channel projection journals overlapping channels and CAS clears independently" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x31);
    const too_long: [local_channel_name_capacity + 1]u8 = @splat('x');
    try testing.expectError(error.InvalidChannel, s.armTokenLocalChannelProjection(token, &too_long, true, 0));
    try testing.expectError(error.NoSuchToken, s.armTokenLocalChannelProjection(token, "#missing", true, 0));
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    const a = try s.armTokenLocalChannelProjection(token, "#a", true, 0x0D);
    const b = try s.armTokenLocalChannelProjection(token, "#b", false, 0x02);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(a.generation, s.tokenLocalChannelProjection(token, "#A").?.generation);
    try testing.expectEqual(b.generation, s.tokenLocalChannelProjection(token, "#b").?.generation);

    var all: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    try testing.expectEqual(@as(usize, 2), s.tokenLocalChannelProjectionsInto(token, &all).len);
    try testing.expect(!s.clearTokenLocalChannelProjection(token, "#a", b.generation));
    try testing.expect(s.clearTokenLocalChannelProjection(token, "#A", a.generation));
    try testing.expect(s.tokenLocalChannelProjection(token, "#a") == null);
    try testing.expect(s.tokenLocalChannelProjection(token, "#b") != null);
    try testing.expect(s.clearTokenLocalChannelProjection(token, "#b", b.generation));
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "local channel projection rejected arm restores prior intent without erasing newer work" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x30);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    _ = try s.attach("alice", 3, token, 3);
    const prior = try s.armTokenLocalChannelProjection(token, "#keep", true, 0x0D);
    const replacement = try s.armTokenLocalChannelProjectionWithPrevious(token, "#KEEP", false, 0);
    try testing.expectEqual(prior.generation, replacement.previous.?.generation);
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
        token,
        replacement.intent.generation,
        replacement.previous,
    ));
    const restored = s.tokenLocalChannelProjection(token, "#keep").?;
    try testing.expectEqual(prior.generation, restored.generation);
    try testing.expect(restored.present);
    try testing.expectEqual(@as(u8, 0x0D), restored.member_mode_bits);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
    var rows: [3]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |row| {
        try testing.expect(row.local_channel_projections == null);
        try testing.expect(row.attachment_channel_projections == null);
    }

    const prior_absent = try s.armTokenLocalChannelProjection(token, "#absent", false, 0x06);
    const replacement_present = try s.armTokenLocalChannelProjectionWithPrevious(token, "#ABSENT", true, 0x03);
    try testing.expectEqual(prior_absent.generation, replacement_present.previous.?.generation);
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
        token,
        replacement_present.intent.generation,
        replacement_present.previous,
    ));
    const restored_absent = s.tokenLocalChannelProjection(token, "#absent").?;
    try testing.expectEqual(prior_absent.generation, restored_absent.generation);
    try testing.expect(!restored_absent.present);
    try testing.expectEqual(@as(u8, 0x06), restored_absent.member_mode_bits);

    const stale = try s.armTokenLocalChannelProjectionWithPrevious(token, "#keep", false, 0);
    const newest = try s.armTokenLocalChannelProjection(token, "#keep", true, 0x03);
    try testing.expect(!s.rollbackTokenLocalChannelProjectionArm(token, stale.intent.generation, stale.previous));
    try testing.expectEqual(newest.generation, s.tokenLocalChannelProjection(token, "#keep").?.generation);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "local channel projection prior-null rollback removes every exact row and preserves CAS" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0x2F);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    _ = try s.attach("alice", 3, token, 3);
    const newly_added = try s.armTokenLocalChannelProjectionWithPrevious(token, "#new", true, 1);
    try testing.expect(newly_added.previous == null);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(token, newly_added.intent.generation, null));
    try testing.expect(s.tokenLocalChannelProjection(token, "#new") == null);
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
    var rows: [3]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |row|
        try testing.expect(row.local_channel_projections == null);
    try testing.expect(!s.rollbackTokenLocalChannelProjectionArm(token, newly_added.intent.generation, null));

    const stale = try s.armTokenLocalChannelProjectionWithPrevious(token, "#new", false, 2);
    const newest = try s.armTokenLocalChannelProjection(token, "#NEW", true, 7);
    try testing.expect(!s.rollbackTokenLocalChannelProjectionArm(token, stale.intent.generation, null));
    const retained = s.tokenLocalChannelProjection(token, "#new").?;
    try testing.expectEqual(newest.generation, retained.generation);
    try testing.expect(retained.present);
    try testing.expectEqual(@as(u8, 7), retained.member_mode_bits);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "local channel projection arm OOM is transactional and retryable" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0x32);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    const generation_before = s.next_local_projection_generation;
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, s.armTokenLocalChannelProjection(token, "#oom", true, 1));
    try testing.expectEqual(generation_before, s.next_local_projection_generation);
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
    try testing.expect(s.tokenLocalChannelProjection(token, "#oom") == null);

    failing.fail_index = std.math.maxInt(usize);
    const armed = try s.armTokenLocalChannelProjection(token, "#oom", true, 1);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    // Once journals exist, same-channel replacement/read/scan/clear allocate nothing.
    failing.has_induced_failure = false;
    failing.fail_index = failing.alloc_index;
    const replaced = try s.armTokenLocalChannelProjection(token, "#OOM", false, 3);
    try testing.expect(replaced.generation > armed.generation);
    var work_buf: [2]LocalChannelProjectionWork = undefined;
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionsInto(&work_buf).len);
    try testing.expect(s.clearTokenLocalChannelProjection(token, "#oom", replaced.generation));
    try testing.expect(!failing.has_induced_failure);
}

test "local channel projection capacity fails closed and full same-channel arm coalesces" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const token = tok(0x33);
    _ = try s.attach("alice", 1, token, 1);

    var first_generation: u64 = 0;
    for (0..local_channel_projection_capacity) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#c{d}", .{index});
        const intent = try s.armTokenLocalChannelProjection(token, channel, true, @intCast(index));
        if (index == 0) first_generation = intent.generation;
    }
    const generation_before = s.next_local_projection_generation;
    try testing.expectError(
        error.TooManyPendingChannels,
        s.armTokenLocalChannelProjection(token, "#overflow", true, 0),
    );
    try testing.expectEqual(generation_before, s.next_local_projection_generation);

    failing.fail_index = failing.alloc_index;
    const replacement = try s.armTokenLocalChannelProjection(token, "#C0", false, 7);
    try testing.expect(replacement.generation > first_generation);
    try testing.expect(!s.tokenLocalChannelProjection(token, "#c0").?.present);
    try testing.expect(!failing.has_induced_failure);
    var all: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    try testing.expectEqual(local_channel_projection_capacity, s.tokenLocalChannelProjectionsInto(token, &all).len);
}

test "local channel projection reversible replacement remains allocation-free at capacity" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const token = tok(0x2E);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);

    var edge_generation: u64 = 0;
    for (0..local_channel_projection_capacity) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#r{d}", .{index});
        const intent = try s.armTokenLocalChannelProjection(token, channel, true, @intCast(index));
        if (index == local_channel_projection_capacity - 1) edge_generation = intent.generation;
    }
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

    failing.fail_index = failing.alloc_index;
    const replacement = try s.armTokenLocalChannelProjectionWithPrevious(token, "#R7", false, 0x7F);
    try testing.expectEqual(edge_generation, replacement.previous.?.generation);
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
        token,
        replacement.intent.generation,
        replacement.previous,
    ));
    try testing.expect(!failing.has_induced_failure);
    const restored = s.tokenLocalChannelProjection(token, "#r7").?;
    try testing.expectEqual(edge_generation, restored.generation);
    try testing.expect(restored.present);
    try testing.expectEqual(@as(u8, 7), restored.member_mode_bits);
    var all: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    try testing.expectEqual(local_channel_projection_capacity, s.tokenLocalChannelProjectionsInto(token, &all).len);
    try testing.expectError(
        error.TooManyPendingChannels,
        s.armTokenLocalChannelProjectionWithPrevious(token, "#overflow", true, 0),
    );
    try testing.expect(!failing.has_induced_failure);
}

test "local channel projection survives detach and sibling removal until final row" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const token = tok(0x34);
    _ = try s.attach("alice", 1, token, 1);
    _ = try s.attach("alice", 2, token, 2);
    const intent = try s.armTokenLocalChannelProjection(token, "#durable", true, 3);
    try testing.expect(s.markDetached("alice", 1));
    try testing.expect(s.remove("alice", 1));
    try testing.expectEqual(intent.generation, s.tokenLocalChannelProjection(token, "#durable").?.generation);
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(@as(usize, 1), s.removeClient(2));
    try testing.expect(s.tokenLocalChannelProjection(token, "#durable") == null);
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "attach inheritance stages lazy journals before append or replacement mutation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const target = tok(0x35);
    const clean = tok(0x36);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, clean, 2);
    const intent = try s.armTokenLocalChannelProjection(target, "#inherit", true, 1);

    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, s.attach("alice", 3, target, 3));
    try testing.expect(!s.containsClient("alice", 3));
    try testing.expectEqual(@as(usize, 1), s.dirtyLocalProjectionRowCount());

    failing.fail_index = std.math.maxInt(usize);
    _ = try s.attach("alice", 3, target, 3);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(intent.generation, s.tokenLocalChannelProjection(target, "#inherit").?.generation);

    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, s.attach("alice", 2, target, 4));
    try testing.expect(s.clientHasToken("alice", 2, clean));
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind preserves channel union and newest case-insensitive collision" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x41);
    const source = tok(0x42);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, source, 2);
    _ = try s.attach("alice", 3, source, 3);
    _ = try s.armTokenLocalChannelProjection(target, "#a", true, 1);
    const target_same = try s.armTokenLocalChannelProjection(target, "#same", true, 1);
    _ = try s.armTokenLocalChannelProjection(source, "#b", false, 2);
    const newest = try s.armTokenLocalChannelProjection(source, "#SAME", false, 7);

    // Aborting a prepared merge must not rewrite either token group's source
    // image or consume the staged target rows.
    var aborted = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    aborted.abort();
    aborted.deinit();
    try testing.expectEqual(target_same.generation, s.tokenLocalChannelProjection(target, "#same").?.generation);
    try testing.expectEqual(newest.generation, s.tokenLocalChannelProjection(source, "#same").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(target, "#b") == null);
    try testing.expect(s.tokenLocalChannelProjection(source, "#a") == null);

    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    var preview_buf: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    const preview = prepared.mergedLocalChannelProjectionsInto(&preview_buf);
    try testing.expectEqual(@as(usize, 3), preview.len);
    try testing.expect(std.ascii.eqlIgnoreCase(preview[0].channel(), "#a"));
    try testing.expect(std.ascii.eqlIgnoreCase(preview[1].channel(), "#b"));
    try testing.expect(std.ascii.eqlIgnoreCase(preview[2].channel(), "#same"));
    try testing.expectEqual(newest.generation, preview[2].generation);
    try testing.expect(!preview[2].present);
    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expect(s.tokenLocalChannelProjection(target, "#a") != null);
    try testing.expect(s.tokenLocalChannelProjection(target, "#b") != null);
    try testing.expectEqual(newest.generation, s.tokenLocalChannelProjection(target, "#same").?.generation);
    // The surviving source sibling retains its source-token journal only.
    try testing.expect(s.tokenLocalChannelProjection(source, "#a") == null);
    try testing.expect(s.tokenLocalChannelProjection(source, "#b") != null);
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind preview is complete at capacity and keeps newest target collision" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x3C);
    const source = tok(0x3D);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, source, 2);

    const older_collision = try s.armTokenLocalChannelProjection(source, "#case", false, 1);
    for (0..3) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#s{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(source, channel, index % 2 == 0, @intCast(index));
    }
    const newer_collision = try s.armTokenLocalChannelProjection(target, "#CASE", true, 0x7F);
    try testing.expect(newer_collision.generation > older_collision.generation);
    for (0..4) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#t{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(target, channel, index % 2 != 0, @intCast(index + 8));
    }

    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    var preview_buf: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    const preview = prepared.mergedLocalChannelProjectionsInto(&preview_buf);
    try testing.expectEqual(local_channel_projection_capacity, preview.len);
    for (preview[1..], 1..) |projection, index|
        try testing.expect(localChannelOrder(preview[index - 1].channel(), projection.channel()) == .lt);
    var collision_count: usize = 0;
    for (preview) |projection| {
        if (!std.ascii.eqlIgnoreCase(projection.channel(), "#case")) continue;
        collision_count += 1;
        try testing.expectEqualStrings("#CASE", projection.channel());
        try testing.expectEqual(newer_collision.generation, projection.generation);
        try testing.expect(projection.present);
        try testing.expectEqual(@as(u8, 0x7F), projection.member_mode_bits);
    }
    try testing.expectEqual(@as(usize, 1), collision_count);

    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    var rows: [2]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |row| {
        try testing.expect(std.crypto.timing_safe.eql(Token, row.token, target));
        try testing.expect(row.local_channel_projections == null);
        try testing.expect(row.attachment_channel_projections == null);
    }
    var committed_projection_buf: [local_channel_projection_capacity]LocalChannelProjection = undefined;
    const committed_projections = s.tokenLocalChannelProjectionsInto(target, &committed_projection_buf);
    try testing.expectEqual(local_channel_projection_capacity, committed_projections.len);
    const committed_index = localProjectionIndex(&prepared.merged_local_projections, "#case") orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(newer_collision.generation, committed_projections[committed_index].generation);
}

test "prepared token bind row snapshot supersedes stale exact-case copy and freezes folded account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x3A);
    const generated = tok(0x3B);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, generated, 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));

    const stale = try s.copySessionsAlloc(testing.allocator, "alice");
    defer testing.allocator.free(stale);
    try testing.expectEqual(@as(usize, 2), stale.len);
    try testing.expect(stale[0].attached);

    // Deterministically model the old race window between copySessionsAlloc and
    // prepareTokenBind: one target row detaches and another attaches under a
    // case-variant spelling before the retained ticket acquires its lock.
    try testing.expect(s.markDetached("alice", 1));
    _ = try s.attach("ALICE", 3, target, 3);

    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    const rows = prepared.accountRows();
    try testing.expectEqual(@as(usize, 3), rows.len);
    try testing.expectEqual(@as(ClientId, 1), rows[0].client);
    try testing.expectEqual(@as(ClientId, 2), rows[1].client);
    try testing.expectEqual(@as(ClientId, 3), rows[2].client);
    try testing.expect(!rows[0].attached);
    try testing.expect(rows[0].portable_resume);
    try testing.expectEqual(target, rows[0].token);
    try testing.expect(rows[1].attached);
    try testing.expectEqual(generated, rows[1].token);
    try testing.expect(rows[2].attached);
    try testing.expectEqual(target, rows[2].token);
    try testing.expect(prepared.resultPortable());
    try testing.expect(!s.lock.tryLockExclusive());

    // The stale exact-case copy cannot see C3 and still reports C1 attached;
    // only the ticket snapshot is complete/current enough for World planning.
    try testing.expect(stale[0].attached);
    for (stale) |row| try testing.expect(row.client != 3);

    try testing.expect(prepared.commit());
    try testing.expectEqual(@as(usize, 3), prepared.accountRows().len);
    prepared.finish();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, target));
    try testing.expect(s.clientHasToken("ALICE", 3, target));
}

test "prepared token bind rejects duplicate client ids across folded account keys" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x38);
    const generated = tok(0x39);
    const conflicting = tok(0x37);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, generated, 2);
    _ = try s.attach("ALICE", 1, conflicting, 3);

    try testing.expect(s.prepareTokenBind("alice", 2, target, .join_existing) == null);
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 1, target));
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(s.clientHasToken("ALICE", 1, conflicting));
    try testing.expect(!s.clientHasToken("alice", 2, target));
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind locked row allocation OOM is transactional and retryable" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();
    const target = tok(0x35);
    const generated = tok(0x36);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, generated, 2);

    failing.fail_index = failing.alloc_index;
    try testing.expect(s.prepareTokenBind("alice", 2, target, .join_existing) == null);
    try testing.expect(failing.has_induced_failure);
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(!s.clientHasToken("alice", 2, target));

    failing.fail_index = std.math.maxInt(usize);
    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expectEqual(@as(usize, 2), prepared.accountRows().len);
    prepared.abort();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, generated));
}

test "prepared token bind folded row and staged journal tickets are leak-clean on every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const target = tok(0x33);
            _ = try s.attach("alice", 1, target, 1);
            const intent = try s.armTokenLocalChannelProjection(target, "#locked", true, 3);
            _ = try s.attach("ALICE", 3, target, 3);
            _ = try s.attach("alice", 2, tok(0x34), 2);

            // Implicit prepared deinit and explicit abort must both release the
            // row snapshot plus the claimant's staged lazy journal unchanged.
            var implicit = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            try testing.expectEqual(@as(usize, 3), implicit.accountRows().len);
            implicit.deinit();
            var aborted = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            try testing.expectEqual(@as(usize, 3), aborted.accountRows().len);
            aborted.abort();
            aborted.deinit();
            try testing.expect(s.lock.tryLockExclusive());
            s.lock.unlockExclusive();
            try testing.expect(s.clientHasToken("alice", 2, tok(0x34)));
            try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

            // Success commits the same prepared resources without allocating,
            // then finish frees the locked rows before releasing the lock.
            var committed = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            defer committed.deinit();
            try testing.expect(committed.commit());
            committed.finish();
            try testing.expect(s.clientHasToken("alice", 2, target));
            try testing.expectEqual(intent.generation, s.tokenLocalChannelProjection(target, "#locked").?.generation);
            try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "prepared token adopt carries the journal and abort frees staged rows" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x45);
    const source = tok(0x46);
    _ = try s.attach("alice", 1, source, 1);
    _ = try s.attach("alice", 2, source, 2);
    const a = try s.armTokenLocalChannelProjection(source, "#a", true, 1);
    const b = try s.armTokenLocalChannelProjection(source, "#b", false, 2);

    var adopt = s.prepareTokenBind("alice", 1, target, .{ .adopt_verified = false }) orelse
        return error.TestUnexpectedResult;
    defer adopt.deinit();
    try testing.expect(adopt.commit());
    adopt.finish();
    try testing.expectEqual(a.generation, s.tokenLocalChannelProjection(target, "#a").?.generation);
    try testing.expectEqual(b.generation, s.tokenLocalChannelProjection(target, "#b").?.generation);
    try testing.expectEqual(a.generation, s.tokenLocalChannelProjection(source, "#a").?.generation);
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

    // A clean claimant joining the dirty target requires a staged journal. An
    // abort must destroy it and leave the claimant/token/count untouched.
    const clean = tok(0x47);
    _ = try s.attach("alice", 3, clean, 3);
    var aborted = s.prepareTokenBind("alice", 3, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    aborted.abort();
    aborted.deinit();
    try testing.expect(s.clientHasToken("alice", 3, clean));
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind rejects an over-capacity union without mutation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const target = tok(0x43);
    const source = tok(0x44);
    _ = try s.attach("alice", 1, target, 1);
    _ = try s.attach("alice", 2, source, 2);
    for (0..5) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#t{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(target, channel, true, 0);
    }
    for (0..4) |index| {
        var channel_buf: [8]u8 = undefined;
        const channel = try std.fmt.bufPrint(&channel_buf, "#s{d}", .{index});
        _ = try s.armTokenLocalChannelProjection(source, channel, true, 0);
    }
    try testing.expect(s.prepareTokenBind("alice", 2, target, .join_existing) == null);
    try testing.expect(s.clientHasToken("alice", 2, source));
    try testing.expect(s.tokenLocalChannelProjection(target, "#t0") != null);
    try testing.expect(s.tokenLocalChannelProjection(source, "#s0") != null);
}

test "bounded local projection work scan rotates across channels and tokens" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const a = tok(0x50);
    const b = tok(0x51);
    _ = try s.attach("a", 1, a, 1);
    _ = try s.attach("b", 2, b, 2);
    _ = try s.armTokenLocalChannelProjection(a, "#a", true, 0);
    _ = try s.armTokenLocalChannelProjection(a, "#b", true, 0);
    _ = try s.armTokenLocalChannelProjection(b, "#a", true, 0);

    var first_buf: [2]LocalChannelProjectionWork = undefined;
    const first = s.dirtyLocalProjectionsInto(&first_buf);
    try testing.expectEqual(@as(usize, 2), first.len);
    var second_buf: [2]LocalChannelProjectionWork = undefined;
    const second = s.dirtyLocalProjectionsInto(&second_buf);
    try testing.expectEqual(@as(usize, 2), second.len);
    try testing.expect(!localWorkInSlice(first, second[0]));
    try testing.expect(localWorkInSlice(first, second[1])); // wrapped fairly
}

test "local projection arm and prepared bind allocation failures are leak-clean" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const target = tok(0x71);
            _ = try s.attach("sweep", 1, target, 1);
            _ = try s.attach("sweep", 2, tok(0x72), 2);
            const intent = try s.armTokenLocalChannelProjection(target, "#sweep", true, 0x0F);
            var prepared = s.prepareTokenBind("sweep", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            defer prepared.deinit();
            try testing.expect(prepared.commit());
            prepared.finish();
            try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
            try testing.expect(s.clearTokenLocalChannelProjection(target, "#sweep", intent.generation));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "reversible local projection arm and rollback are leak-clean across every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const token = tok(0x70);
            _ = try s.attach("rollback-sweep", 1, token, 1);
            _ = try s.attach("rollback-sweep", 2, token, 2);
            _ = try s.attach("rollback-sweep", 3, token, 3);

            const prior = try s.armTokenLocalChannelProjection(token, "#prior", false, 0x06);
            const replacement = try s.armTokenLocalChannelProjectionWithPrevious(token, "#PRIOR", true, 0x03);
            try testing.expectEqual(prior.generation, replacement.previous.?.generation);
            try testing.expect(s.rollbackTokenLocalChannelProjectionArm(
                token,
                replacement.intent.generation,
                replacement.previous,
            ));
            const restored = s.tokenLocalChannelProjection(token, "#prior").?;
            try testing.expectEqual(prior.generation, restored.generation);
            try testing.expect(!restored.present);
            try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());

            const added = try s.armTokenLocalChannelProjectionWithPrevious(token, "#new", true, 1);
            try testing.expect(added.previous == null);
            try testing.expect(s.rollbackTokenLocalChannelProjectionArm(token, added.intent.generation, null));
            try testing.expect(s.tokenLocalChannelProjection(token, "#new") == null);
            try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "local projection arm rolls back every lazy journal allocation boundary" {
    for (0..3) |failure_offset| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.init(failing.allocator());
        defer s.deinit();
        const token = tok(@intCast(0x78 + failure_offset));
        _ = try s.attach("rollback", 1, token, 1);
        _ = try s.attach("rollback", 2, token, 2);

        failing.fail_index = failing.alloc_index + failure_offset;
        try testing.expectError(
            error.OutOfMemory,
            s.armTokenLocalChannelProjection(token, "#rollback", true, 1),
        );
        try testing.expectEqual(@as(u64, 0), s.next_local_projection_generation);
        try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
        try testing.expect(s.tokenLocalChannelProjection(token, "#rollback") == null);

        failing.fail_index = std.math.maxInt(usize);
        _ = try s.armTokenLocalChannelProjection(token, "#rollback", true, 1);
        try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());
    }
}

test "attach lists a multi-device account; idempotent re-attach" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var out: [64]Session = undefined;
    _ = try s.attach("alice", 1, tok(1), 100);
    _ = try s.attach("alice", 2, tok(2), 200);
    try testing.expectEqual(@as(usize, 2), s.sessionsInto("alice", &out).len);
    // Re-attaching the same client refreshes, not duplicates.
    _ = try s.attach("alice", 1, tok(9), 300);
    try testing.expectEqual(@as(usize, 2), s.sessionsInto("alice", &out).len);
}

test "markDetached retains the session; remove prunes; empty account drops" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var out: [64]Session = undefined;
    _ = try s.attach("bob", 7, tok(7), 1);
    try testing.expect(s.markDetached("bob", 7));
    const retained = s.sessionsInto("bob", &out);
    try testing.expectEqual(@as(usize, 1), retained.len); // retained
    try testing.expect(!retained[0].attached);
    try testing.expect(s.remove("bob", 7));
    try testing.expectEqual(@as(usize, 0), s.sessionsInto("bob", &out).len); // account pruned
}

test "detached session snapshots are copied and released across lifecycle paths" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "nick=alice;channels=#root,#ops"));

    const copied = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(1))).?;
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("nick=alice;channels=#root,#ops", copied);

    _ = try s.attach("alice", 2, tok(2), 20); // evicts detached client 1 and its snapshot
    try testing.expect((try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(1))) == null);
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "second"));
    _ = try s.attach("alice", 2, tok(3), 30); // reattach same client frees old snapshot
    try testing.expect((try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(3))) == null);
}

test "allocation-free detach preserves the last owned portable snapshot" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const token = tok(0x6d);
    _ = try s.attach("alice", 1, token, 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "last-publishable-state"));

    // Models encodeMigrationSnapshot failing during the later close path.
    try testing.expect(s.markDetached("alice", 1));
    const copied = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", token)).?;
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("last-publishable-state", copied);
}

test "portable resume issuance is explicit and resets on a normal re-attach" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expectEqual(false, s.resumeHandleForClient("alice", 1).?.portable);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expectEqual(true, s.resumeHandleForClient("alice", 1).?.portable);

    // A normal same-client attach rotates the token and requires the client to
    // request a fresh portable credential.
    _ = try s.attach("alice", 1, tok(2), 20);
    const refreshed = s.resumeHandleForClient("alice", 1).?;
    try testing.expectEqualSlices(u8, &tok(2), &refreshed.token);
    try testing.expectEqual(false, refreshed.portable);

    // Helix adoption is the exceptional path: it restores the carried bit.
    try testing.expect(s.restorePortableResumeIssued("alice", 1, true));
    try testing.expectEqual(true, s.resumeHandleForClient("alice", 1).?.portable);
}

test "attach reports portable authority displaced by same-client replacement" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    const outcome = try s.attachReportingEviction("alice", 1, tok(2), 20);
    const evicted = outcome.evicted orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(ClientId, 1), evicted.client);
    try testing.expectEqualSlices(u8, &tok(1), &evicted.token);
    try testing.expect(evicted.portable);
    try testing.expectEqualSlices(u8, &tok(2), &outcome.session.token);
}

test "attach reports portable detached authority evicted at account cap" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 1 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetached("alice", 1));
    const outcome = try s.attachReportingEviction("alice", 2, tok(2), 20);
    const evicted = outcome.evicted orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(ClientId, 1), evicted.client);
    try testing.expectEqualSlices(u8, &tok(1), &evicted.token);
    try testing.expect(evicted.portable);
    try testing.expectEqualSlices(u8, &tok(2), &outcome.session.token);
}

test "portable detached anti-entropy copies only opted-in snapshots" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "portable"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "local-only"));

    const copies = try s.copyPortableDetachedSnapshots(testing.allocator);
    defer {
        for (copies) |*copy| copy.deinit(testing.allocator);
        testing.allocator.free(copies);
    }
    try testing.expectEqual(@as(usize, 1), copies.len);
    try testing.expectEqualStrings("alice", copies[0].account);
    try testing.expectEqualStrings("portable", copies[0].snapshot);
    try testing.expectEqualSlices(u8, &tok(1), &copies[0].token);
}

test "portable detached anti-entropy selects one newest snapshot independent of insertion order" {
    const token = tok(0x2a);
    var stores = [_]SessionStore{
        SessionStore.init(testing.allocator),
        SessionStore.init(testing.allocator),
    };
    defer for (&stores) |*store| store.deinit();

    // Same logical rows, reversed insertion order. Only the older row receives
    // the credential, proving portability is group-wide while snapshot choice
    // remains newest signon rather than "portable row" or hash order.
    _ = try stores[0].attach("Alice", 10, token, 100);
    _ = try stores[0].attach("aLiCe", 20, token, 200);
    _ = try stores[1].attach("aLiCe", 20, token, 200);
    _ = try stores[1].attach("Alice", 10, token, 100);
    for (&stores) |*store| {
        try testing.expect(store.markPortableResumeIssued("Alice", 10));
        try testing.expect(store.markDetachedWithSnapshot("Alice", 10, "older"));
        try testing.expect(store.markDetachedWithSnapshot("aLiCe", 20, "newest"));
        const copies = try store.copyPortableDetachedSnapshots(testing.allocator);
        defer {
            for (copies) |*copy| copy.deinit(testing.allocator);
            testing.allocator.free(copies);
        }
        try testing.expectEqual(@as(usize, 1), copies.len);
        try testing.expectEqualSlices(u8, &token, &copies[0].token);
        try testing.expectEqualStrings("aLiCe", copies[0].account);
        try testing.expectEqualStrings("newest", copies[0].snapshot);
    }
}

test "portable detached canonical copy is leak-clean at every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();
            const token = tok(0x2b);
            _ = try s.attach("alice", 1, token, 10);
            _ = try s.attach("alice", 2, token, 20);
            try testing.expect(s.markPortableResumeIssued("alice", 1));
            if (!s.markDetachedWithSnapshot("alice", 1, "old")) return error.OutOfMemory;
            if (!s.markDetachedWithSnapshot("alice", 2, "new")) return error.OutOfMemory;
            const copies = try s.copyPortableDetachedSnapshots(allocator);
            defer {
                for (copies) |*copy| copy.deinit(allocator);
                allocator.free(copies);
            }
            try testing.expectEqual(@as(usize, 1), copies.len);
            try testing.expectEqualStrings("new", copies[0].snapshot);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "copyNewestDetachedSnapshotInAccount ignores current client and returns newest ghost" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(1), 10);
    _ = try s.attach("alice", 2, tok(2), 30);
    _ = try s.attach("alice", 3, tok(3), 20);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "old"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "new"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 3, "current"));

    const copied = (try s.copyNewestDetachedSnapshotInAccount(testing.allocator, "alice", 3)).?;
    defer testing.allocator.free(copied.snapshot);
    try testing.expectEqual(@as(ClientId, 2), copied.client);
    try testing.expectEqual(@as(i64, 30), copied.signon_ms);
    try testing.expectEqualStrings("new", copied.snapshot);

    _ = try s.attach("alice", 4, tok(4), 40);
    const copied_again = (try s.copyNewestDetachedSnapshotInAccount(testing.allocator, "alice", 4)).?;
    defer testing.allocator.free(copied_again.snapshot);
    try testing.expectEqual(@as(ClientId, 2), copied_again.client);
}

test "findByTokenInto locates a session for reclaim" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var account_buf: [64]u8 = undefined;
    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("carol", 2, tok(0xCD), 1);
    const m = s.findByTokenInto(tok(0xCD), &account_buf).?;
    try testing.expectEqualStrings("carol", m.account);
    try testing.expectEqual(@as(ClientId, 2), m.client);
    try testing.expect(s.findByTokenInto(tok(0xEE), &account_buf) == null);
}

test "tokenHasAttachedPortable distinguishes live siblings from final detached token" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(0x21), 1);
    _ = try s.attach("alice", 2, tok(0x21), 2);
    _ = try s.attach("bob", 3, tok(0x22), 3);
    try testing.expect(!s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markPortableResumeIssued("alice", 2));
    try testing.expect(s.markPortableResumeIssued("bob", 3));
    try testing.expect(s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "one"));
    try testing.expect(s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "two"));
    try testing.expect(!s.tokenHasAttachedPortable(tok(0x21)));
    try testing.expect(s.tokenHasAttachedPortable(tok(0x22)));
    try testing.expect(!s.tokenHasAttachedPortable(tok(0xff)));
    try testing.expect(s.containsToken(tok(0x21)));
    try testing.expect(s.containsToken(tok(0x22)));
    try testing.expect(!s.containsToken(tok(0xff)));
}

test "removeClient drops a client without knowing its account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    var out: [64]Session = undefined;
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 1);
    try testing.expectEqual(@as(usize, 1), s.removeClient(1));
    try testing.expectEqual(@as(usize, 1), s.sessionsInto("alice", &out).len);
    try testing.expectEqual(@as(usize, 0), s.removeClient(999)); // unknown
}

test "per-account session cap is enforced for attached sessions" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);
    _ = try s.attach("alice", 2, tok(2), 1);
    try testing.expectError(error.TooManySessions, s.attach("alice", 3, tok(3), 1));
}

test "at cap, attach evicts the oldest detached ghost instead of failing" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();
    var out: [2]Session = undefined;
    _ = try s.attach("alice", 1, tok(1), 10); // older
    _ = try s.attach("alice", 2, tok(2), 20);
    try testing.expect(s.markDetached("alice", 1)); // client 1 is the ghost
    // New live session evicts the detached ghost (client 1), not client 2.
    _ = try s.attach("alice", 3, tok(3), 30);
    try testing.expectEqual(@as(usize, 2), s.sessionsInto("alice", &out).len);
    try testing.expect(s.findTokenInAccount("alice", tok(1)) == null); // evicted
    try testing.expectEqual(@as(ClientId, 2), s.findTokenInAccount("alice", tok(2)).?);
    try testing.expectEqual(@as(ClientId, 3), s.findTokenInAccount("alice", tok(3)).?);
}

test "findTokenInAccount is scoped to the account" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("bob", 2, tok(0xCD), 1);
    try testing.expectEqual(@as(ClientId, 1), s.findTokenInAccount("alice", tok(0xAB)).?);
    // bob's token must not resolve under alice.
    try testing.expect(s.findTokenInAccount("alice", tok(0xCD)) == null);
}

test "detached token lookup ignores attached members of the same token group" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0xAB), 1);
    _ = try s.attach("alice", 2, tok(0xCD), 2);
    try testing.expect(s.findDetachedTokenInAccount("alice", tok(0xCD)) == null);

    try testing.expect(s.markDetached("alice", 2));
    try testing.expectEqual(@as(ClientId, 2), s.findDetachedTokenInAccount("alice", tok(0xCD)).?);
    const snap = s.findTokenSessionInAccount("alice", tok(0xCD)).?;
    try testing.expect(!snap.attached);
}

test "multiple live clients join one reusable token group" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0xAA), 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    _ = try s.attach("alice", 2, tok(0xBB), 20);
    try testing.expect(s.joinTokenGroup("alice", 2, tok(0xAA)));

    try testing.expect(s.clientHasToken("alice", 1, tok(0xAA)));
    try testing.expect(s.clientHasToken("alice", 2, tok(0xAA)));
    try testing.expectEqual(true, s.resumeHandleForClient("alice", 2).?.portable);
    try testing.expectEqual(@as(ClientId, 1), s.findAttachedTokenSessionInAccount("alice", tok(0xAA), 2).?.client);

    // A detached member remains discoverable even while another attachment to
    // the same logical session is live.
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "shared-state"));
    try testing.expectEqual(@as(ClientId, 1), s.findDetachedTokenInAccount("alice", tok(0xAA)).?);
    const copied = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", tok(0xAA))).?;
    defer testing.allocator.free(copied);
    try testing.expectEqualStrings("shared-state", copied);
}

test "token group stays portable when issuing sibling detaches" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0xac);
    _ = try s.attach("alice", 1, token, 10);
    _ = try s.attach("alice", 2, token, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetached("alice", 1));

    // Portability is copied to every row so removing the issuer cannot disable
    // a surviving attachment's lease or detach publication.
    var rows: [2]Session = undefined;
    const sessions = s.sessionsInto("alice", &rows);
    try testing.expectEqual(@as(usize, 2), sessions.len);
    for (sessions) |session| {
        try testing.expect(session.portable_resume);
    }

    // Group-facing APIs combine "any portable" with "any attached". Client B
    // can therefore renew the lease and detach into mesh resume state even
    // though client A was the attachment that received the credential.
    const b = s.resumeHandleForClient("alice", 2) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &token, &b.token);
    try testing.expect(b.portable);
    try testing.expect(s.tokenHasAttachedPortable(token));

    try testing.expect(s.markDetached("alice", 2));
    try testing.expect(!s.tokenHasAttachedPortable(token));
    try testing.expect(s.resumeHandleForClient("alice", 2).?.portable);
}

test "prepared token join aborts cleanly then prepared commit needs no allocation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const target = tok(0xA1);
    const generated = tok(0xB2);
    _ = try s.attach("alice", 1, target, 10);
    _ = try s.attach("alice", 2, generated, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(target));
    try testing.expect(s.markTokenReplicaProjectionDirty(target));

    // Abort is a true no-op and releases the lock for ordinary store calls.
    var abandoned = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer abandoned.deinit();
    try testing.expect(!s.lock.tryLockExclusive());
    abandoned.abort();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(!s.clientHasToken("alice", 2, target));

    // Preparation intentionally allocates the complete folded-account snapshot
    // and any missing projection journals while holding the lock. Once that
    // plan exists, fail the allocator's very next request: commit itself must
    // remain allocation-free and publish the exact group transition in one step.
    var prepared = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    failing.fail_index = failing.alloc_index;
    try testing.expect(prepared.commit());
    try testing.expect(!failing.has_induced_failure);
    // Commit publishes the row change but deliberately retains the lock until
    // the enclosing World/Conn transaction calls finish.
    try testing.expect(!s.lock.tryLockExclusive());
    try testing.expect(std.crypto.timing_safe.eql(Token, prepared.list.items.items[prepared.index].token, target));
    prepared.finish();
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();

    try testing.expect(s.clientHasToken("alice", 1, target));
    try testing.expect(s.clientHasToken("alice", 2, target));
    const joined = s.findTokenSessionInAccount("alice", target) orelse
        return error.TestUnexpectedResult;
    try testing.expect(joined.portable_resume);
    try testing.expect(s.tokenReplicaDirty(target));
    try testing.expect(s.tokenReplicaProjectionDirty(target));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
}

test "prepared bootstrap joins a live token without publishing before commit" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const token = tok(0xD1);
    _ = try s.attach("alice", 1, token, 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));

    var prepared = s.prepareBootstrapTokenAttach(
        "alice",
        2,
        token,
        .join_existing,
        20,
    ) orelse return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expectEqual(@as(usize, 2), prepared.accountRows().len);
    try testing.expect(prepared.resultPortable());
    try testing.expect(prepared.detachedSource() == null);
    try testing.expect(!s.lock.tryLockExclusive());

    const outcome = prepared.commit();
    try testing.expect(outcome.evicted == null);
    prepared.finish();
    try testing.expect(s.clientHasToken("alice", 1, token));
    try testing.expect(s.clientHasToken("alice", 2, token));
    try expectTokenIndexCoherent(&s);
}

test "prepared bootstrap abort preserves detached cap victim and exact snapshot" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();

    const target = tok(0xD2);
    const unrelated = tok(0xD3);
    _ = try s.attach("alice", 1, target, 20);
    _ = try s.attach("alice", 2, unrelated, 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "selected-snapshot"));
    try testing.expect(s.markDetachedWithSnapshot("alice", 2, "unrelated-snapshot"));

    var abandoned = s.prepareBootstrapTokenAttach(
        "alice",
        3,
        target,
        .join_existing,
        30,
    ) orelse return error.TestUnexpectedResult;
    defer abandoned.deinit();
    const source = abandoned.detachedSource() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(ClientId, 1), source.client);
    try testing.expectEqualStrings("selected-snapshot", source.snapshot);
    abandoned.abort();

    var rows: [2]Session = undefined;
    const unchanged = s.sessionsInto("alice", &rows);
    try testing.expectEqual(@as(usize, 2), unchanged.len);
    try testing.expect(s.findDetachedTokenSessionInAccount("alice", target) != null);
    const selected = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", target)).?;
    defer testing.allocator.free(selected);
    try testing.expectEqualStrings("selected-snapshot", selected);
    const other = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", unrelated)).?;
    defer testing.allocator.free(other);
    try testing.expectEqualStrings("unrelated-snapshot", other);

    var committed = s.prepareBootstrapTokenAttach(
        "alice",
        3,
        target,
        .join_existing,
        30,
    ) orelse return error.TestUnexpectedResult;
    defer committed.deinit();
    const outcome = committed.commit();
    try testing.expectEqual(@as(ClientId, 1), outcome.evicted.?.client);
    try testing.expectEqual(target, outcome.evicted.?.token);
    committed.finish();
    try testing.expect(s.clientHasToken("alice", 3, target));
    try testing.expect(s.findDetachedTokenSessionInAccount("alice", unrelated) != null);
    try expectTokenIndexCoherent(&s);
}

test "prepared bootstrap replaces selected detached ghost below account cap" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 3 });
    defer s.deinit();

    const target = tok(0xDA);
    _ = try s.attach("alice", 1, target, 10);
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "retained"));
    var prepared = s.prepareBootstrapTokenAttach(
        "alice",
        2,
        target,
        .join_existing,
        20,
    ) orelse return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expectEqual(@as(ClientId, 1), prepared.detachedSource().?.client);
    const outcome = prepared.commit();
    try testing.expectEqual(@as(ClientId, 1), outcome.evicted.?.client);
    prepared.finish();

    var rows: [3]Session = undefined;
    const current = s.sessionsInto("alice", &rows);
    try testing.expectEqual(@as(usize, 1), current.len);
    try testing.expectEqual(@as(ClientId, 2), current[0].client);
    try testing.expect(current[0].attached);
    try testing.expectEqual(target, current[0].token);
    try expectTokenIndexCoherent(&s);
}

test "prepared bootstrap verified mesh token creates a rowless account atomically" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const verified = tok(0xD4);
    var abandoned = s.prepareBootstrapTokenAttach(
        "mesh-account",
        9,
        verified,
        .{ .adopt_verified = true },
        40,
    ) orelse return error.TestUnexpectedResult;
    defer abandoned.deinit();
    try testing.expect(s.accounts.getPtr("mesh-account") == null);
    abandoned.abort();
    try testing.expect(s.accounts.getPtr("mesh-account") == null);
    try testing.expect(!s.containsToken(verified));

    var committed = s.prepareBootstrapTokenAttach(
        "mesh-account",
        9,
        verified,
        .{ .adopt_verified = true },
        40,
    ) orelse return error.TestUnexpectedResult;
    defer committed.deinit();
    const outcome = committed.commit();
    try testing.expect(outcome.evicted == null);
    committed.finish();
    try testing.expect(s.clientHasToken("mesh-account", 9, verified));
    try testing.expect(s.resumeHandleForClient("mesh-account", 9).?.portable);
    try expectTokenIndexCoherent(&s);
}

test "prepared bootstrap is leak-clean and non-destructive at every allocation failure" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.initWithConfig(allocator, .{ .max_sessions_per_account = 2 });
            defer s.deinit();

            const target = tok(0xD5);
            const unrelated = tok(0xD6);
            _ = try s.attach("alice", 1, target, 10);
            _ = try s.attach("alice", 2, unrelated, 20);
            if (!s.markDetachedWithSnapshot("alice", 1, "target-state")) return error.OutOfMemory;
            if (!s.markDetachedWithSnapshot("alice", 2, "other-state")) return error.OutOfMemory;

            var prepared = s.prepareBootstrapTokenAttach(
                "alice",
                3,
                target,
                .join_existing,
                30,
            ) orelse {
                var rows: [2]Session = undefined;
                const unchanged = s.sessionsInto("alice", &rows);
                try testing.expectEqual(@as(usize, 2), unchanged.len);
                try testing.expect(s.findDetachedTokenSessionInAccount("alice", target) != null);
                try testing.expect(s.findDetachedTokenSessionInAccount("alice", unrelated) != null);
                return error.OutOfMemory;
            };
            defer prepared.deinit();
            _ = prepared.commit();
            prepared.finish();
            try testing.expect(s.clientHasToken("alice", 3, target));
            try testing.expect(s.findDetachedTokenSessionInAccount("alice", unrelated) != null);
            try expectTokenIndexCoherent(&s);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "prepared verified adopt rejects cross-account tokens and preserves rowless retry state" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const generated = tok(0x11);
    const foreign = tok(0x99);
    const verified = tok(0x98);
    _ = try s.attach("alice", 1, generated, 10);
    _ = try s.attach("bob", 2, foreign, 20);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(generated));
    try testing.expect(s.markTokenReplicaProjectionDirty(generated));

    // A row in another account never authorizes join_existing.
    try testing.expect(s.prepareTokenBind("alice", 1, foreign, .join_existing) == null);
    // External verification cannot relabel a token already owned by a different
    // account either. The chosen token must remain globally account-bound.
    try testing.expect(s.prepareTokenBind("alice", 1, foreign, .{ .adopt_verified = false }) == null);
    try testing.expect(s.clientHasToken("alice", 1, generated));

    // Verified mesh authority may adopt a rowless token. Its explicit portable
    // bit replaces the claimant's old issuance bit, while pending retry work is
    // carried across to the new exact group.
    var prepared = s.prepareTokenBind("alice", 1, verified, .{ .adopt_verified = false }) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expect(prepared.commit());
    try testing.expect(!s.lock.tryLockExclusive());
    prepared.finish();
    const adopted = s.resumeHandleForClient("alice", 1) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &verified, &adopted.token);
    try testing.expect(!adopted.portable);
    try testing.expect(s.tokenReplicaDirty(verified));
    try testing.expect(s.tokenReplicaProjectionDirty(verified));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
}

test "attach rejects cross-account token collision before dirty journal mutation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const target = tok(0x9a);
    const source = tok(0x9b);
    _ = try s.attach("Alice", 1, target, 10);
    _ = try s.attach("bob", 2, source, 20);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markTokenReplicaDirty(target));
    try testing.expect(s.markTokenReplicaProjectionDirty(target));
    const target_intent = try s.armTokenLocalChannelProjection(target, "#target", true, 3);
    const source_intent = try s.armTokenLocalChannelProjection(source, "#source", false, 7);
    const dirty_rows = s.dirtyReplicaRowCount();
    const projection_rows = s.dirtyReplicaProjectionRowCount();
    const local_rows = s.dirtyLocalProjectionRowCount();

    // Collision detection is allocation-free and precedes replacement, dirty
    // propagation, and journal union. Even an allocator armed to fail remains
    // untouched because the chosen token already belongs to another account.
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.TokenAccountMismatch, s.attach("bob", 2, target, 30));
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.clientHasToken("bob", 2, source));
    try testing.expect(!s.clientHasToken("bob", 2, target));
    try testing.expectEqual(dirty_rows, s.dirtyReplicaRowCount());
    try testing.expectEqual(projection_rows, s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(local_rows, s.dirtyLocalProjectionRowCount());
    try testing.expectEqual(target_intent.generation, s.tokenLocalChannelProjection(target, "#target").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(target, "#source") == null);
    try testing.expectEqual(source_intent.generation, s.tokenLocalChannelProjection(source, "#source").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(source, "#target") == null);

    // ASCII case variants are the same account boundary and may share the
    // exact token. The new row inherits the target group's durable retry state.
    failing.fail_index = std.math.maxInt(usize);
    _ = try s.attach("aLiCe", 3, target, 40);
    try testing.expect(s.clientHasToken("aLiCe", 3, target));
    try testing.expect(s.tokenReplicaDirty(target));
    try testing.expect(s.tokenReplicaProjectionDirty(target));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "sentinel tracks independent accounts without becoming a token group" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const sentinel: Token = @splat(0);
    _ = try s.attach("alice", 1, sentinel, 10);
    _ = try s.attach("bob", 2, sentinel, 20);
    _ = try s.attach("alice", 3, sentinel, 30);

    const alice = s.resumeHandleForClient("alice", 1) orelse
        return error.TestUnexpectedResult;
    const bob = s.resumeHandleForClient("bob", 2) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(sentinel, alice.token);
    try testing.expectEqual(sentinel, bob.token);
    try testing.expect(!alice.portable);
    try testing.expect(!bob.portable);

    const reserved = ExactSelector{
        .client = 1,
        .token = sentinel,
        .signon_ms = 10,
        .attachment_id = null,
    };
    try testing.expectEqual(ReserveDropResult.reserved, s.reserveDrop("alice", reserved, 77));
    try testing.expect(!s.markDetached("alice", 1));
    try testing.expect(!s.markDetachedWithSnapshot("alice", 1, "reserved-sentinel"));
    try testing.expect(!s.remove("alice", 1));
    try testing.expect(s.removeExact("alice", .{
        .client = 1,
        .token = sentinel,
        .signon_ms = 10,
        .attachment_id = null,
    }) == null);
    try testing.expectEqual(@as(usize, 0), s.removeClient(1));
    try testing.expect(s.cancelDropReservation("alice", reserved, 77));

    // The absence marker cannot be issued, joined, adopted, dirtied, or given
    // a channel-projection journal as though it were a reusable credential.
    try testing.expect(!s.markPortableResumeIssued("alice", 1));
    try testing.expect(!s.restorePortableResumeIssued("bob", 2, true));
    try testing.expect(s.prepareTokenBind("alice", 3, sentinel, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("alice", 3, sentinel, .{ .adopt_verified = true }) == null);
    try testing.expect(!s.markTokenReplicaDirty(sentinel));
    try testing.expect(!s.containsToken(sentinel));
    var account_buf: [16]u8 = undefined;
    try testing.expect(s.findByTokenInto(sentinel, &account_buf) == null);
    try testing.expectError(
        error.NoSuchToken,
        s.armTokenLocalChannelProjection(sentinel, "#sentinel", true, 0),
    );
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 0), s.dirtyLocalProjectionRowCount());
    try expectTokenIndexCoherent(&s);
}

test "prepared bind enforces folded token account and rolls back staged case-variant journal OOM" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const target = tok(0xa8);
    const same_account_source = tok(0xa9);
    const foreign_source = tok(0xaa);
    _ = try s.attach("Alice", 1, target, 10);
    _ = try s.attach("ALICE", 2, same_account_source, 20);
    _ = try s.attach("bob", 3, foreign_source, 30);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markTokenReplicaDirty(target));
    try testing.expect(s.markTokenReplicaProjectionDirty(target));
    const target_intent = try s.armTokenLocalChannelProjection(target, "#target", true, 1);
    const foreign_intent = try s.armTokenLocalChannelProjection(foreign_source, "#foreign", false, 2);

    // Both join and externally verified adoption reject a chosen token already
    // owned by a non-equivalent account, without merging either retry journal.
    failing.fail_index = failing.alloc_index;
    try testing.expect(s.prepareTokenBind("bob", 3, target, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("bob", 3, target, .{ .adopt_verified = true }) == null);
    try testing.expect(!failing.has_induced_failure);
    try testing.expect(s.clientHasToken("bob", 3, foreign_source));
    try testing.expectEqual(target_intent.generation, s.tokenLocalChannelProjection(target, "#target").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(target, "#foreign") == null);
    try testing.expectEqual(foreign_intent.generation, s.tokenLocalChannelProjection(foreign_source, "#foreign").?.generation);
    try testing.expect(s.tokenLocalChannelProjection(foreign_source, "#target") == null);

    // Joining through a case-variant account is valid, but the clean claimant
    // needs a staged journal allocation. Injected OOM aborts before mutation.
    failing.fail_index = failing.alloc_index;
    try testing.expect(s.prepareTokenBind("ALICE", 2, target, .join_existing) == null);
    try testing.expect(failing.has_induced_failure);
    try testing.expect(s.clientHasToken("ALICE", 2, same_account_source));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyLocalProjectionRowCount());

    failing.fail_index = std.math.maxInt(usize);
    var prepared = s.prepareTokenBind("ALICE", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit();
    try testing.expect(prepared.commit());
    prepared.finish();
    try testing.expect(s.clientHasToken("ALICE", 2, target));
    try testing.expect(s.tokenReplicaDirty(target));
    try testing.expect(s.tokenReplicaProjectionDirty(target));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 3), s.dirtyLocalProjectionRowCount());
}

test "prepared token bind rejects invalid and stale preconditions without mutation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    const target = tok(0x44);
    const generated = tok(0x55);
    _ = try s.attach("alice", 1, target, 10);
    _ = try s.attach("alice", 2, generated, 20);

    try testing.expect(s.prepareTokenBind("missing", 2, target, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("alice", 99, target, .join_existing) == null);
    try testing.expect(s.prepareTokenBind("alice", 2, tok(0xEE), .join_existing) == null);
    try testing.expect(s.clientHasToken("alice", 2, generated));

    var stale = s.prepareTokenBind("alice", 2, target, .join_existing) orelse
        return error.TestUnexpectedResult;
    defer stale.deinit();
    // Model a stale/corrupted ticket at the commit boundary. Revalidation must
    // reject it and leave every live row untouched until explicit abort.
    stale.expected_token = tok(0xFE);
    try testing.expect(!stale.commit());
    // Rejection keeps the plan prepared and the lock held until explicit abort.
    try testing.expect(!s.lock.tryLockExclusive());
    stale.abort();
    try testing.expect(!stale.commit());
    try testing.expect(s.lock.tryLockExclusive());
    s.lock.unlockExclusive();
    try testing.expect(s.clientHasToken("alice", 1, target));
    try testing.expect(s.clientHasToken("alice", 2, generated));
    try testing.expect(!s.clientHasToken("alice", 2, target));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());
}

test "prepared token bind commit remains no-allocation after exhaustive preparation failures" {
    const Exercise = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var s = SessionStore.init(allocator);
            defer s.deinit();

            const target = tok(0x71);
            _ = try s.attach("sweep", 1, target, 1);
            _ = try s.attach("sweep", 2, tok(0x72), 2);
            try testing.expect(s.markPortableResumeIssued("sweep", 1));

            var prepared = s.prepareTokenBind("sweep", 2, target, .join_existing) orelse
                return error.OutOfMemory;
            defer prepared.deinit();
            try testing.expect(prepared.commit());
            try testing.expect(!s.lock.tryLockExclusive());
            prepared.finish();
            try testing.expect(s.clientHasToken("sweep", 1, target));
            try testing.expect(s.clientHasToken("sweep", 2, target));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Exercise.run, .{});
}

test "detached snapshot replacement OOM preserves prior retry state" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var s = SessionStore.init(failing.allocator());
    defer s.deinit();

    const token = tok(0xAD);
    _ = try s.attach("alice", 1, token, 10);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(token));
    try testing.expect(s.markTokenReplicaProjectionDirty(token));
    try testing.expect(s.markDetachedWithSnapshot("alice", 1, "last-good-snapshot"));

    // Fail exactly the replacement copy. The row must still be detached and
    // publishable from its previous owned snapshot; OOM must not erase either
    // token-group durability bit or the portable credential.
    failing.fail_index = failing.alloc_index;
    try testing.expect(!s.markDetachedWithSnapshot("alice", 1, "newer-snapshot"));
    try testing.expect(failing.has_induced_failure);

    const row = s.findTokenSessionInAccount("alice", token) orelse
        return error.TestUnexpectedResult;
    try testing.expect(!row.attached);
    try testing.expect(row.portable_resume);
    try testing.expect(row.replica_dirty);
    try testing.expect(row.replica_projection_dirty);
    try testing.expect(s.tokenReplicaDirty(token));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());

    const retained = (try s.copyDetachedSnapshotInAccount(testing.allocator, "alice", token)) orelse
        return error.TestUnexpectedResult;
    defer testing.allocator.free(retained);
    try testing.expectEqualStrings("last-good-snapshot", retained);
}

test "portable and dirty state remain durable token group properties" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0xA1), 1);
    _ = try s.attach("alice", 2, tok(0xA1), 2);
    _ = try s.attach("bob", 3, tok(0xB2), 3);
    _ = try s.attach("carol", 4, tok(0xC3), 4);

    // Issuance durably propagates to every exact-token row.
    try testing.expect(s.markPortableResumeIssued("alice", 2));
    try testing.expect(s.markPortableResumeIssued("bob", 3));
    var alice_rows: [4]Session = undefined;
    for (s.sessionsInto("alice", &alice_rows)) |session| {
        try testing.expect(session.portable_resume);
    }

    // A non-portable token is rejected without leaving a partial dirty mark.
    try testing.expect(!s.markTokenReplicaDirty(tok(0xC3)));
    try testing.expect(!s.tokenReplicaDirty(tok(0xC3)));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    // A mutation from either sibling marks every row in that group.
    try testing.expect(s.markTokenReplicaDirty(tok(0xA1)));
    try testing.expect(s.markTokenReplicaDirty(tok(0xB2)));
    try testing.expect(s.tokenReplicaDirty(tok(0xA1)));
    try testing.expect(s.tokenReplicaDirty(tok(0xB2)));
    try testing.expectEqual(@as(usize, 3), s.dirtyReplicaRowCount());
    for (s.sessionsInto("alice", &alice_rows)) |session| {
        try testing.expect(session.replica_dirty);
    }

    // Removing the original issuer leaves both the group credential and pending
    // publication durable on the surviving sibling.
    try testing.expect(s.remove("alice", 2));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    const surviving = s.sessionsInto("alice", &alice_rows);
    try testing.expectEqual(@as(usize, 1), surviving.len);
    try testing.expect(surviving[0].portable_resume);
    try testing.expect(surviving[0].replica_dirty);

    // Collection is caller-bounded, allocation-free, and unique even though
    // token A's original credential-issuing row has already disappeared.
    var one: [1]Token = undefined;
    try testing.expectEqual(@as(usize, 1), s.dirtyPortableTokensInto(&one).len);
    var all: [4]Token = undefined;
    const dirty = s.dirtyPortableTokensInto(&all);
    try testing.expectEqual(@as(usize, 2), dirty.len);
    var saw_a = false;
    var saw_b = false;
    for (dirty) |token| {
        saw_a = saw_a or std.mem.eql(u8, &token, &tok(0xA1));
        saw_b = saw_b or std.mem.eql(u8, &token, &tok(0xB2));
    }
    try testing.expect(saw_a and saw_b);

    // Acceptance clears only its exact group; failed/unaccepted work remains.
    try testing.expect(s.clearTokenReplicaDirty(tok(0xA1)));
    try testing.expect(!s.tokenReplicaDirty(tok(0xA1)));
    try testing.expect(s.tokenReplicaDirty(tok(0xB2)));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    const retained = s.dirtyPortableTokensInto(&all);
    try testing.expectEqual(@as(usize, 1), retained.len);
    try testing.expectEqualSlices(u8, &tok(0xB2), &retained[0]);
    try testing.expect(s.clearTokenReplicaDirty(tok(0xA1))); // idempotent
    try testing.expect(!s.clearTokenReplicaDirty(tok(0xEE)));
}

test "join and adopt OR dirty portable state across token groups" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x11), 1);
    _ = try s.attach("alice", 2, tok(0x22), 2);
    _ = try s.attach("alice", 3, tok(0x33), 3);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(tok(0x11)));

    // Moving the dirty source into an existing clean group dirties every
    // destination sibling without losing its pending retry. Portability becomes
    // durable on the whole destination group.
    try testing.expect(s.joinTokenGroup("alice", 1, tok(0x22)));
    var rows: [8]Session = undefined;
    const joined = s.sessionsInto("alice", &rows);
    for (joined) |session| {
        if (!std.mem.eql(u8, &session.token, &tok(0x22))) continue;
        try testing.expect(session.portable_resume);
        try testing.expect(session.replica_dirty);
    }
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());

    // A clean adopted attachment inherits the destination group's OR state.
    try testing.expect(s.adoptTokenGroup("alice", 3, tok(0x22), false));
    try testing.expectEqual(@as(usize, 3), s.dirtyReplicaRowCount());
    for (s.sessionsInto("alice", &rows)) |session| {
        try testing.expectEqualSlices(u8, &tok(0x22), &session.token);
        try testing.expect(session.portable_resume);
        try testing.expect(session.replica_dirty);
    }
}

test "bounded dirty collection rotates past an uncleared failing token" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    for (0..9) |i| {
        var account_buf: [16]u8 = undefined;
        const account = try std.fmt.bufPrint(&account_buf, "rotate-{d}", .{i});
        const token = tok(@intCast(0x60 + i));
        _ = try s.attach(account, @intCast(i + 1), token, @intCast(i));
        try testing.expect(s.markPortableResumeIssued(account, @intCast(i + 1)));
        try testing.expect(s.markTokenReplicaDirty(token));
    }

    var first_buf: [4]Token = undefined;
    const first = s.dirtyPortableTokensInto(&first_buf);
    try testing.expectEqual(@as(usize, 4), first.len);

    // Nothing is cleared: model all four publications failing. The next batch
    // still advances to four other unique groups instead of returning the same
    // stable hash-map prefix forever.
    var second_buf: [4]Token = undefined;
    const second = s.dirtyPortableTokensInto(&second_buf);
    try testing.expectEqual(@as(usize, 4), second.len);
    for (second) |token| try testing.expect(!SessionStore.tokenInSlice(first, token));

    // Remove the cursor token itself. Ordering by the retained token value (not
    // a hash-map position) still advances to 0x68 before wrapping to 0x60.
    try testing.expect(s.remove("rotate-7", 8));
    var third_buf: [4]Token = undefined;
    const third = s.dirtyPortableTokensInto(&third_buf);
    try testing.expectEqual(@as(usize, 4), third.len);
    try testing.expectEqualSlices(u8, &tok(0x68), &third[0]);
    try testing.expectEqualSlices(u8, &tok(0x60), &third[1]);
    try testing.expectEqualSlices(u8, &tok(0x61), &third[2]);
    try testing.expectEqualSlices(u8, &tok(0x62), &third[3]);
    try testing.expectEqual(@as(usize, 8), s.dirtyReplicaRowCount());
}

test "projection retry is group-wide durable and independent from publish retry" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x71), 1);
    _ = try s.attach("alice", 2, tok(0x71), 2);

    // Signed Store acceptance, not local token issuance, authorizes projection.
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(0x71)));
    try testing.expect(!s.markTokenReplicaProjectionDirty(tok(0x72)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    var rows: [4]Session = undefined;
    for (s.sessionsInto("alice", &rows)) |session| {
        try testing.expect(session.replica_projection_dirty);
        try testing.expect(!session.replica_dirty);
    }
    var projection_buf: [2]Token = undefined;
    const projection = s.dirtyProjectionTokensInto(&projection_buf);
    try testing.expectEqual(@as(usize, 1), projection.len);
    try testing.expectEqualSlices(u8, &tok(0x71), &projection[0]);

    // Removing one sibling and attaching another to its exact token preserves
    // the pending projection and the exact row count.
    try testing.expect(s.remove("alice", 1));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    _ = try s.attach("alice", 3, tok(0x73), 3);
    try testing.expect(s.adoptTokenGroup("alice", 3, tok(0x71), false));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());

    // Publish dirtiness can coexist, and clearing projection cannot clear it.
    try testing.expect(s.markPortableResumeIssued("alice", 2));
    try testing.expect(s.markTokenReplicaDirty(tok(0x71)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expect(s.clearTokenReplicaProjectionDirty(tok(0x71)));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());
    try testing.expect(!s.clearTokenReplicaProjectionDirty(tok(0xEE)));
}

test "bounded projection collection rotates independently without allocation" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();

    for (0..9) |i| {
        var account_buf: [20]u8 = undefined;
        const account = try std.fmt.bufPrint(&account_buf, "projection-{d}", .{i});
        const token = tok(@intCast(0x80 + i));
        _ = try s.attach(account, @intCast(i + 1), token, @intCast(i));
        try testing.expect(s.markTokenReplicaProjectionDirty(token));
    }

    var first_buf: [4]Token = undefined;
    const first = s.dirtyProjectionTokensInto(&first_buf);
    try testing.expectEqual(@as(usize, 4), first.len);
    var second_buf: [4]Token = undefined;
    const second = s.dirtyProjectionTokensInto(&second_buf);
    try testing.expectEqual(@as(usize, 4), second.len);
    for (second) |token| try testing.expect(!SessionStore.tokenInSlice(first, token));

    // Advancing projection did not move or populate the independent publish
    // cursor/lane.
    var publish_buf: [4]Token = undefined;
    try testing.expectEqual(@as(usize, 0), s.dirtyPortableTokensInto(&publish_buf).len);
    try testing.expectEqual(@as(usize, 9), s.dirtyReplicaProjectionRowCount());
}

test "projection dirty count tracks replacement eviction and drop paths" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x91), 1);
    _ = try s.attach("alice", 2, tok(0x91), 2);
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(0x91)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());

    // A new token resets the replaced row while the surviving old-token group
    // remains pending.
    _ = try s.attach("alice", 1, tok(0x92), 3);
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    // Replacing it back into the dirty token inherits the destination OR state.
    _ = try s.attach("alice", 1, tok(0x91), 4);
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaProjectionRowCount());

    try testing.expect(s.markDetached("alice", 1));
    _ = try s.attach("alice", 3, tok(0x93), 5); // evicts dirty detached row 1
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    try testing.expectEqual(@as(usize, 1), s.removeClient(2));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());

    _ = try s.attach("drop", 9, tok(0x99), 9);
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(0x99)));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaProjectionRowCount());
    try testing.expect(s.remove("drop", 9)); // prunes the now-empty account
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaProjectionRowCount());
}

test "dirty row count survives removal replacement and detached eviction" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 2 });
    defer s.deinit();

    _ = try s.attach("alice", 1, tok(0x41), 1);
    _ = try s.attach("alice", 2, tok(0x41), 2);
    try testing.expect(s.markPortableResumeIssued("alice", 1));
    try testing.expect(s.markTokenReplicaDirty(tok(0x41)));
    try testing.expectEqual(@as(usize, 2), s.dirtyReplicaRowCount());

    try testing.expect(s.remove("alice", 1));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    try testing.expectEqual(@as(usize, 1), s.removeClient(2));
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    _ = try s.attach("evict", 10, tok(0x51), 10);
    try testing.expect(s.markPortableResumeIssued("evict", 10));
    try testing.expect(s.markTokenReplicaDirty(tok(0x51)));
    try testing.expect(s.markDetached("evict", 10));
    _ = try s.attach("evict", 11, tok(0x52), 20);
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    _ = try s.attach("evict", 12, tok(0x53), 30); // evicts dirty client 10
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());

    try testing.expect(s.markPortableResumeIssued("evict", 11));
    try testing.expect(s.markTokenReplicaDirty(tok(0x52)));
    try testing.expectEqual(@as(usize, 1), s.dirtyReplicaRowCount());
    _ = try s.attach("evict", 11, tok(0x54), 40); // same-client replacement
    try testing.expectEqual(@as(usize, 0), s.dirtyReplicaRowCount());
}

test "sessionsInto and findByTokenInto do not retain snapshots" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("alice", 1, tok(1), 1);

    var out: [64]Session = undefined;
    var account_buf: [64]u8 = undefined;
    for (0..10_000) |_| {
        const list = s.sessionsInto("alice", &out);
        try testing.expectEqual(@as(usize, 1), list.len);
        try testing.expectEqual(@as(ClientId, 1), list[0].client);
        const found = s.findByTokenInto(tok(1), &account_buf).?;
        try testing.expectEqualStrings("alice", found.account);
        try testing.expectEqual(@as(ClientId, 1), found.client);
    }
}

test "allocated session snapshot is complete above the legacy stack capacity" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = snapshot_capacity + 8 });
    defer s.deinit();
    for (0..snapshot_capacity + 8) |i| {
        var token: Token = @splat(0);
        std.mem.writeInt(u64, token[0..8], i, .little);
        _ = try s.attach("wide", @intCast(i + 1), token, @intCast(i));
    }

    const all = try s.copySessionsAlloc(testing.allocator, "wide");
    defer testing.allocator.free(all);
    try testing.expectEqual(snapshot_capacity + 8, all.len);
    try testing.expect(s.containsClient("wide", snapshot_capacity + 8));
}

const SessionMtCtx = struct {
    store: *SessionStore,
    writer_id: usize,
    iters: usize,
    failures: *std.atomic.Value(u32),

    fn account(out: *[16]u8, writer_id: usize) []const u8 {
        return std.fmt.bufPrint(out, "acct{d}", .{writer_id}) catch unreachable;
    }

    fn tempAccount(out: *[24]u8, writer_id: usize, i: usize) []const u8 {
        return std.fmt.bufPrint(out, "tmp{d}_{d}", .{ writer_id, i }) catch unreachable;
    }

    fn client(writer_id: usize, i: usize) ClientId {
        return @intCast(1000 + writer_id * 100 + i);
    }

    fn tempClient(writer_id: usize, i: usize) ClientId {
        return @intCast(10000 + writer_id * 100 + i);
    }

    fn token(writer_id: usize, i: usize, lane: u8) Token {
        var value: Token = @splat(0);
        value[0] = @intCast(writer_id + 1);
        value[1] = @intCast(i);
        value[2] = lane;
        return value;
    }

    fn writer(ctx: *SessionMtCtx) void {
        var acct_buf: [16]u8 = undefined;
        var tmp_buf: [24]u8 = undefined;
        const acct = account(&acct_buf, ctx.writer_id);
        var i: usize = 0;
        while (i < ctx.iters) : (i += 1) {
            const cid = client(ctx.writer_id, i);
            _ = ctx.store.attach(acct, cid, token(ctx.writer_id, i, 1), @intCast(i)) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if ((i & 1) == 0) {
                if (!ctx.store.markDetached(acct, cid)) {
                    _ = ctx.failures.fetchAdd(1, .monotonic);
                    return;
                }
                _ = ctx.store.attach(acct, cid, token(ctx.writer_id, i, 2), @intCast(i + 1000)) catch {
                    _ = ctx.failures.fetchAdd(1, .monotonic);
                    return;
                };
            }

            const tmp = tempAccount(&tmp_buf, ctx.writer_id, i);
            const tmp_cid = tempClient(ctx.writer_id, i);
            _ = ctx.store.attach(tmp, tmp_cid, token(ctx.writer_id, i, 3), @intCast(i)) catch {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            const removed = if ((i & 1) == 0)
                ctx.store.remove(tmp, tmp_cid)
            else
                ctx.store.removeClient(tmp_cid) == 1;
            if (!removed) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }

    fn reader(ctx: *SessionMtCtx) void {
        var i: usize = 0;
        while (i < ctx.iters * 4) : (i += 1) {
            var out: [64]Session = undefined;
            var account_buf: [64]u8 = undefined;
            const seed_sessions = ctx.store.sessionsInto("seed", &out);
            if (seed_sessions.len != 1 or seed_sessions[0].client != 1) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            const found = ctx.store.findByTokenInto(tok(1), &account_buf) orelse {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            };
            if (!std.mem.eql(u8, found.account, "seed") or found.client != 1) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
            if (ctx.store.findTokenInAccount("seed", tok(1)) != 1) {
                _ = ctx.failures.fetchAdd(1, .monotonic);
                return;
            }
        }
    }
};

test "drop reservation is exact exclusive and transient" {
    var store = SessionStore.init(testing.allocator);
    defer store.deinit();
    const first = aid(0x91);
    const second = aid(0x92);
    const sibling = aid(0x93);
    _ = try store.attachWithAttachment("alice", 10, tok(0x81), first, 100);
    _ = try store.attachWithAttachment("alice", 11, tok(0x82), second, 101);
    _ = try store.attachWithAttachment("alice", 12, tok(0x81), sibling, 102);
    const selector = ExactSelector{ .client = 10, .token = tok(0x81), .signon_ms = 100, .attachment_id = first };

    try testing.expectEqual(ReserveDropResult.invalid_id, store.reserveDrop("alice", selector, 0));
    try testing.expectEqual(ReserveDropResult.stale, store.reserveDrop("alice", .{ .client = 10, .token = tok(0x81), .signon_ms = 99, .attachment_id = first }, 7));
    try testing.expectEqual(ReserveDropResult.reserved, store.reserveDrop("alice", selector, 7));
    try testing.expectEqual(ReserveDropResult.already_reserved, store.reserveDrop("alice", selector, 7));
    try testing.expectEqual(ReserveDropResult.reserved_by_other, store.reserveDrop("alice", selector, 8));
    try testing.expect(store.validateDropReservation("alice", selector, 7));
    try testing.expect(store.hasDropReservation("alice", selector));
    try testing.expect(!store.markDetached("alice", 10));
    try testing.expect(!store.markDetachedWithSnapshot("alice", 10, "frozen"));
    // Retry/portability journals are not identity or liveness mutations. They
    // must remain writable while DROP holds the exact row; suppressing them
    // after a live mutation would create permanent replica desynchronization.
    try testing.expect(store.markPortableResumeIssued("alice", 12));
    try testing.expect(store.restorePortableResumeIssued("alice", 12, true));
    try testing.expect(store.markTokenReplicaProjectionDirty(tok(0x81)));
    try testing.expect(store.markAttachmentReplicaProjectionDirty(tok(0x81), first));
    _ = try store.armTokenLocalChannelProjection(tok(0x81), "#frozen", true, 0);
    _ = try store.armAttachmentLocalChannelProjection(tok(0x81), first, "#frozen", true, 0);
    try testing.expectError(
        error.SessionDropReserved,
        store.attachWithAttachment("alice", 13, tok(0x81), aid(0x94), 103),
    );
    try testing.expect(!store.containsClient("alice", 13));
    try testing.expect(!store.markDetached("alice", 12));
    try testing.expect(!store.markDetachedWithSnapshot("alice", 12, "sibling-frozen"));
    try testing.expect(!store.remove("alice", 12));
    try testing.expect(store.removeExact("alice", .{
        .client = 12,
        .token = tok(0x81),
        .signon_ms = 102,
        .attachment_id = sibling,
    }) == null);
    try testing.expectEqual(@as(usize, 0), store.removeClient(12));
    try testing.expectError(
        error.SessionDropReserved,
        store.attachWithAttachment("alice", 12, tok(0x82), sibling, 104),
    );
    try testing.expectError(error.SessionDropReserved, store.attachWithAttachment("alice", 10, tok(0x83), first, 102));
    try testing.expect(!store.joinTokenGroup("alice", 10, tok(0x82)));
    try testing.expect(!store.joinTokenGroup("alice", 12, tok(0x82)));
    try testing.expect(store.prepareTokenBind("alice", 11, tok(0x81), .join_existing) == null);
    try testing.expect(store.prepareBootstrapTokenAttach("alice", 13, tok(0x81), .join_existing, 103) == null);
    try testing.expect(store.removeExact("alice", .{ .client = 10, .token = tok(0x81), .signon_ms = 100, .attachment_id = first }) == null);
    try testing.expect(!store.cancelDropReservation("alice", selector, 8));
    try testing.expect(store.cancelDropReservation("alice", selector, 7));
    try testing.expect(!store.hasDropReservation("alice", selector));

    try testing.expectEqual(ReserveDropResult.reserved, store.reserveDrop("alice", selector, 9));
    var copied: [3]Session = undefined;
    const copied_rows = store.sessionsInto("alice", &copied);
    const copied_first = for (copied_rows) |row| {
        if (row.client == 10) break row;
    } else return error.TestUnexpectedResult;
    try testing.expectEqual(@as(DropReservationId, 0), copied_first.drop_reservation);
    try testing.expect(store.commitDropReservation("alice", .{ .client = 10, .token = tok(0x81), .signon_ms = 100, .attachment_id = second }, 9) == null);
    const handle = store.commitDropReservation("alice", selector, 9) orelse return error.TestUnexpectedResult;
    try testing.expect(std.crypto.timing_safe.eql(Token, handle.token, tok(0x81)));
    try testing.expect(!store.containsClient("alice", 10));
    try testing.expect(store.containsClient("alice", 11));
    try testing.expect(store.containsClient("alice", 12));
}

test "SessionStore concurrent writers and readers preserve sessions" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("seed", 1, tok(1), 1);

    const writers = 4;
    const readers = 4;
    const iters = 64;
    var failures = std.atomic.Value(u32).init(0);
    var ctxs: [writers]SessionMtCtx = undefined;
    for (0..writers) |i| {
        ctxs[i] = .{ .store = &s, .writer_id = i, .iters = iters, .failures = &failures };
    }

    var threads: [writers + readers]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();
    for (0..writers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, SessionMtCtx.writer, .{&ctxs[i]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (0..readers) |i| {
        threads[spawned] = std.Thread.spawn(.{}, SessionMtCtx.reader, .{&ctxs[i % writers]}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();
    // Prevent the error cleanup from joining already-consumed thread handles if
    // a post-join invariant fails; double-join obscures the actual assertion.
    spawned = 0;

    try testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    var seed_out: [64]Session = undefined;
    try testing.expectEqual(@as(usize, 1), s.sessionsInto("seed", &seed_out).len);
    var acct_buf: [16]u8 = undefined;
    for (0..writers) |w| {
        const acct = SessionMtCtx.account(&acct_buf, w);
        var out: [64]Session = undefined;
        const list = s.sessionsInto(acct, &out);
        try testing.expectEqual(@as(usize, iters), list.len);
        for (list) |session| try testing.expect(session.attached);
    }
}

const LifecycleConcurrency = struct {
    store: *SessionStore,
    reader_entered: std.atomic.Value(bool) = .init(false),
    reader_done: std.atomic.Value(bool) = .init(false),
    writer_done: std.atomic.Value(bool) = .init(false),
    failures: std.atomic.Value(u32) = .init(0),

    fn reader(self: *@This()) void {
        self.reader_entered.store(true, .release);
        self.store.lock.lockShared();
        defer self.store.lock.unlockShared();
        const rows = self.store.accounts.get("Alice").?.items.items;
        if (rows.len != 2 or rows[0].attached or rows[0].snapshot == null or
            !std.mem.eql(u8, rows[0].snapshot.?, "NEW owned snapshot") or rows[1].attached)
            _ = self.failures.fetchAdd(1, .monotonic);
        self.reader_done.store(true, .release);
    }
    fn writer(self: *@This()) void {
        if (!self.store.clearTokenReplicaDirty(tok(1))) _ = self.failures.fetchAdd(1, .monotonic);
        self.writer_done.store(true, .release);
    }
};

fn lifecycleAwait(flag: *const std.atomic.Value(bool)) !void {
    for (0..1_000_000) |_| {
        if (flag.load(.acquire)) return;
        try std.Thread.yield();
    }
    return error.TestBarrierTimeout;
}

test "Session lifecycle batch readers and legacy writers wait for complete cut" {
    if (builtin.single_threaded) return error.SkipZigTest;
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const first = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const second = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    var old: [2]Session = undefined;
    const before = s.sessionsInto("Alice", &old);
    try testing.expectEqual(@as(usize, 2), before.len);
    try testing.expect(before[0].attached and before[1].attached and before[0].snapshot == null);
    const ops = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", first), .snapshot = .{ .replace = "NEW owned snapshot" } } } },
        .{ .request_id = 2, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", second) } } },
    };
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    var ctx = LifecycleConcurrency{ .store = &s };
    var reader: ?std.Thread = null;
    var writer: ?std.Thread = null;
    // Every assertion/spawn/barrier failure releases custody before joining.
    defer {
        ticket.deinit();
        if (reader) |thread| thread.join();
        if (writer) |thread| thread.join();
    }
    reader = try std.Thread.spawn(.{}, LifecycleConcurrency.reader, .{&ctx});
    writer = try std.Thread.spawn(.{}, LifecycleConcurrency.writer, .{&ctx});
    try lifecycleAwait(&ctx.reader_entered);
    var queued = false;
    for (0..1_000_000) |_| {
        if (s.lock.writers_waiting.load(.acquire) != 0) {
            queued = true;
            break;
        }
        try std.Thread.yield();
    }
    try testing.expect(queued); // Actual legacy lock waiter, not a sleep guess.
    try testing.expect(!ctx.reader_done.load(.acquire) and !ctx.writer_done.load(.acquire));
    try testing.expectError(error.Busy, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try ticket.validateForCut();
    ticket.commit();
    try testing.expect(!ctx.reader_done.load(.acquire) and !ctx.writer_done.load(.acquire));
    ticket.finish();
    reader.?.join();
    reader = null;
    writer.?.join();
    writer = null;
    try testing.expect(ctx.reader_done.load(.acquire) and ctx.writer_done.load(.acquire));
    try testing.expectEqual(@as(u32, 0), ctx.failures.load(.acquire));
    try expectTokenIndexCoherent(&s);
}

// This oracle exercises storage effects against the existing signed chronology;
// it deliberately supplies outer auth/subject facts and does not activate daemon
// routing or infer a presence subject from a reusable token/attachment.
fn lifecycleOracleRecord(class: @import("../proto/mesh_presence_v2.zig").RoutingClass) @import("../proto/mesh_presence_v2.zig").Record {
    const v2 = @import("../proto/mesh_presence_v2.zig");
    return .{ .operation = .present, .origin = @splat(1), .guest = (v2.guestId(.{ .epoch = 1, .counter = 1 }) catch unreachable), .revision = 1, .routing_class = class, .class_revision = 1, .claim_hlc = 10, .claim_revision = 1, .issued_ms = 10, .expires_ms = 100, .nick = "Alice", .username = "u", .host = "h", .realname = "r", .server = "s", .description = "d" };
}

test "Session lifecycle batch physical effects obey independent v2 class and terminal chronology" {
    const v2 = @import("../proto/mesh_presence_v2.zig");
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const one = lifecycleOracleRecord(.true_guest);
    var two = one;
    two.revision = 2;
    two.routing_class = .authenticated_untracked;
    two.class_revision = 2;
    const absent = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 1, .signon_ms = 10, .kind = .no_row } } }};
    var t = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &absent });
    try testing.expectEqual(@as(usize, 1), t.preview().affected_physical.len);
    try testing.expect(t.preview().affected_physical[0].after == null);
    try testing.expect(try v2.consistentProgress(one, two));
    try t.validateForCut();
    t.commit();
    t.finish();
    t.deinit();
    const fresh = [_]LifecycleRequest{.{ .request_id = 2, .intent = .{ .admit = .{ .account = "Alice", .client = 1, .signon_ms = 10, .kind = .fresh } } }};
    t = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &fresh });
    const exact = t.preview().affected_physical[0].after.?;
    try testing.expect(exact.attached and !tokenIsSentinel(exact.token) and exact.attachment_id != null);
    var three = two;
    three.revision = 3;
    three.routing_class = .exact_reusable_attachment;
    three.class_revision = 3;
    try testing.expect(try v2.consistentProgress(two, three));
    try testing.expectEqual(one.claim_revision, three.claim_revision);
    try t.validateForCut();
    t.commit();
    t.finish();
    t.deinit();
    const live = s.findAttachedTokenSessionInAccount("Alice", exact.token, 0).?;
    const rekey = [_]LifecycleRequest{.{ .request_id = 3, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", live), .target_account = "Alice", .target_token = tok(77), .kind = .{ .adopt_verified = false } } } }};
    t = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &rekey });
    defer t.deinit();
    try testing.expect(!std.mem.eql(u8, &t.preview().affected_physical[0].before.?.token, &t.preview().affected_physical[0].after.?.token));
    var same_class = three;
    same_class.revision = 4;
    try testing.expect(try v2.consistentProgress(three, same_class));
    try testing.expectEqual(three.class_revision, same_class.class_revision);
    t.abort();
    t.deinit();
    const detach = [_]LifecycleRequest{.{ .request_id = 4, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", live) } } }};
    t = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &detach });
    const physical = t.preview().affected_physical[0];
    try testing.expect(physical.before.?.attached and !physical.after.?.attached);
    var quit = three;
    quit.operation = .quit;
    quit.revision = 5;
    try testing.expect(try v2.consistentProgress(three, quit));
    try testing.expectEqual(three.class_revision, quit.class_revision);
    var invalid_quit = quit;
    invalid_quit.class_revision = invalid_quit.revision;
    try testing.expectError(error.InvalidField, v2.consistentProgress(three, invalid_quit));
    try t.validateForCut();
    t.commit();
    t.finish();
    t.deinit();
    const ghost = s.findDetachedAttachmentSessionInAccount("Alice", exact.token, exact.attachment_id.?).?;
    const reconnect = [_]LifecycleRequest{.{ .request_id = 5, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Alice", ghost), .claimant_client = 2 } } }};
    t = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &reconnect });
    try testing.expectEqual(@as(usize, 2), t.preview().affected_physical.len);
    try testing.expectEqual(@as(ClientId, 1), t.preview().remaps[0].old_client);
    try testing.expectEqual(@as(ClientId, 2), t.preview().remaps[0].new_client);
    var claimant = lifecycleOracleRecord(.exact_reusable_attachment);
    claimant.guest = try v2.guestId(.{ .epoch = 1, .counter = 2 }); // New physical subject, same stable attachment.
    claimant.revision = 2;
    var resurrection = quit;
    resurrection.revision = 6;
    resurrection.operation = .present;
    try testing.expect(!try v2.consistentProgress(quit, resurrection));
    try testing.expectError(error.InvalidField, v2.consistentProgress(quit, claimant));
    t.abort();
    t.deinit();
    var logout = three;
    logout.revision = 4;
    logout.routing_class = .true_guest;
    logout.class_revision = 4;
    try testing.expect(try v2.consistentProgress(three, logout));
    try testing.expectEqual(one.claim_hlc, logout.claim_hlc);
    var nickname = logout;
    nickname.revision = 5;
    nickname.nick = "Renamed";
    nickname.claim_hlc = 11;
    nickname.claim_revision = 5;
    try testing.expect(try v2.consistentProgress(logout, nickname));
    try testing.expectEqual(logout.class_revision, nickname.class_revision);
}

test "Session lifecycle batch complete stale proof and reserved sibling refusal" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const first = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const sibling = try s.attachWithAttachment("ALICE", 2, tok(1), aid(2), 20);
    var selector = lifecycleSelector("Alice", first);
    var ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .remove = .{ .source = selector, .reason = .logout } } }};
    const old = try lifecycleCanonical(&s);
    selector.exact.token = tok(9);
    ops[0].intent.remove.source = selector;
    try testing.expectError(error.StaleSelector, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    selector = lifecycleSelector("Alice", first);
    selector.exact.attachment_id = aid(9);
    ops[0].intent.remove.source = selector;
    try testing.expectError(error.StaleSelector, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    const sibling_selector = lifecycleSelector("ALICE", sibling);
    try testing.expectEqual(ReserveDropResult.reserved, s.reserveDrop("ALICE", sibling_selector.exact, 7));
    ops[0].intent.remove.source = lifecycleSelector("Alice", first);
    const reserved = try lifecycleCanonical(&s);
    try testing.expectError(error.SessionDropReserved, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .drop_permits = &.{.{ .source = sibling_selector, .owner = 7 }} }));
    try testing.expectEqual(reserved, try lifecycleCanonical(&s));
    try testing.expect(s.validateDropReservation("ALICE", sibling_selector.exact, 7));
    try testing.expect(s.cancelDropReservation("ALICE", sibling_selector.exact, 7));
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const locator = s.attachment_index.getPtr(aid(1).raw).?;
    locator.client = 999; // Same map size must not evade exact-cut validation.
    try testing.expectError(error.InvalidTicket, ticket.validateForCut());
    locator.client = 1;
    try ticket.validateForCut();
    ticket.abort();
}

test "Session lifecycle batch final removal avoids detached cap eviction and preserves cursor fairness" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_accounts = 1, .max_sessions_per_account = 2 });
    defer s.deinit();
    const removed = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    _ = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 2, "keeper ghost"));
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markPortableResumeIssued("Alice", 2));
    try testing.expect(s.markTokenReplicaDirty(tok(1)) and s.markTokenReplicaDirty(tok(2)));
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(1)) and s.markTokenReplicaProjectionDirty(tok(2)));
    try testing.expect(s.markAttachmentReplicaDirty(tok(1), aid(1)) and s.markAttachmentReplicaDirty(tok(2), aid(2)));
    try testing.expect(s.markAttachmentReplicaProjectionDirty(tok(1), aid(1)) and s.markAttachmentReplicaProjectionDirty(tok(2), aid(2)));
    _ = try s.armTokenLocalChannelProjection(tok(1), "#removed", true, 1);
    _ = try s.armTokenLocalChannelProjection(tok(2), "#surviving", false, 0);
    _ = try s.armAttachmentLocalChannelProjection(tok(1), aid(1), "#removed", true, 1);
    _ = try s.armAttachmentLocalChannelProjection(tok(2), aid(2), "#surviving", false, 0);
    s.dirty_scan_cursor = tok(1);
    s.projection_scan_cursor = tok(1);
    s.attachment_replica_scan_cursor = .{ .token = tok(1), .attachment_id = aid(1) };
    s.attachment_projection_scan_cursor = s.attachment_replica_scan_cursor;
    s.local_projection_scan_cursor = .{ .token = tok(1), .projection = s.token_index.get(tok(1)).?.local_projections.items[0] };
    s.attachment_local_projection_scan_cursor = .{ .token = tok(1), .attachment_id = aid(1), .projection = s.accounts.get("Alice").?.items.items[0].attachment_channel_projections.?.items[0] };
    const ops = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 3, .signon_ms = 30, .kind = .fresh, .cap = .evict_detached } } },
        .{ .request_id = 2, .intent = .{ .remove = .{ .source = lifecycleSelector("Alice", removed), .reason = .logout } } },
    };
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    try testing.expectEqual(@as(usize, 1), ticket.preview().retired_attachments.len);
    try testing.expectEqual(LifecycleRemoval.logout, ticket.preview().retired_attachments[0].reason);
    try testing.expectEqualStrings("keeper ghost", lifecycleFindRow(ticket.preview().after, 2).?.snapshot.?);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    var tokens: [4]Token = undefined;
    try testing.expectEqual(tok(2), s.dirtyPortableTokensInto(&tokens)[0]);
    try testing.expectEqual(tok(2), s.dirtyProjectionTokensInto(&tokens)[0]);
    var attachments: [4]AttachmentReplicaWork = undefined;
    try testing.expectEqual(aid(2), s.dirtyPortableAttachmentsInto(&attachments)[0].attachment_id);
    try testing.expectEqual(aid(2), s.dirtyAttachmentProjectionsInto(&attachments)[0].attachment_id);
    var group_work: [4]LocalChannelProjectionWork = undefined;
    try testing.expectEqual(tok(2), s.dirtyLocalProjectionsInto(&group_work)[0].token);
    var attachment_work: [4]AttachmentLocalChannelProjectionWork = undefined;
    try testing.expectEqual(aid(2), s.dirtyAttachmentLocalProjectionsInto(&attachment_work)[0].attachment_id);
    try expectTokenIndexCoherent(&s);
}

test "Session lifecycle batch limits refuse entire plan and existing empty account remains capacity" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_accounts = 1, .max_sessions_per_account = 2 });
    defer s.deinit();
    const key = try testing.allocator.dupe(u8, "Alice");
    try s.accounts.put(key, .{});
    const old = try lifecycleCanonical(&s);
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 1, .signon_ms = 10, .kind = .fresh } } }};
    try testing.expectError(error.InvalidRequest, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &.{} }));
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .limits = .{ .max_operations = 0 } }));
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .limits = .{ .max_preview_bytes = 0 } }));
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .limits = .{ .max_candidate_rows = 0 } }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    try testing.expectEqual(@as(usize, 1), ticket.preview().final_accounts);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(s.clientHasAttachment("Alice", 1, s.accounts.get("Alice").?.items.items[0].token, s.accounts.get("Alice").?.items.items[0].attachment_id.?));
    const after = try lifecycleCanonical(&s);
    ticket.deinit();
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops, .limits = .{ .max_discovery_rows = 0 } }));
    try testing.expectEqual(after, try lifecycleCanonical(&s));
}

fn expectLifecycleCountsAndAttachments(s: *SessionStore) !void {
    s.lock.lockShared();
    defer s.lock.unlockShared();
    var counts = LifecycleCounts{};
    var attachments: usize = 0;
    var rows = s.accounts.iterator();
    while (rows.next()) |account| for (account.value_ptr.items.items) |row| {
        // Independent cardinality assertions for each scheduler lane.
        counts.replica += @intFromBool(row.replica_dirty);
        counts.projection += @intFromBool(row.replica_projection_dirty);
        counts.attachment_replica += @intFromBool(row.attachment_replica_dirty);
        counts.attachment_projection += @intFromBool(row.attachment_replica_projection_dirty);
        counts.group_journal += @intFromBool(row.local_channel_projections != null and row.local_channel_projections.?.len != 0);
        counts.attachment_journal += @intFromBool(row.attachment_channel_projections != null and row.attachment_channel_projections.?.len != 0);
        if (row.attachment_id) |id| {
            attachments += 1;
            const loc = s.attachment_index.get(id.raw).?;
            try testing.expectEqual(row.client, loc.client);
            try testing.expectEqualStrings(account.key_ptr.*, loc.account);
        }
    };
    try testing.expectEqual(attachments, s.attachment_index.count());
    try testing.expectEqual(counts.replica, s.dirty_replica_rows);
    try testing.expectEqual(counts.projection, s.dirty_projection_rows);
    try testing.expectEqual(counts.attachment_replica, s.dirty_attachment_replica_rows);
    try testing.expectEqual(counts.attachment_projection, s.dirty_attachment_projection_rows);
    try testing.expectEqual(counts.group_journal, s.dirty_local_projection_rows);
    try testing.expectEqual(counts.attachment_journal, s.dirty_attachment_local_projection_rows);
}

test "Session lifecycle batch ambiguous aliases and dirty claimant require exact explicit replacement" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const first = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    _ = try s.attachWithAttachment("ALICE", 1, tok(2), aid(2), 20);
    const duplicate = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .remove = .{ .source = lifecycleSelector("Alice", first), .reason = .logout } } }};
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.AmbiguousPhysicalBinding, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &duplicate }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    try testing.expect(s.remove("ALICE", 1));
    _ = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "exact ghost snapshot"));
    const ghost = s.findDetachedAttachmentSessionInAccount("Alice", tok(1), aid(1)).?;
    const claimant = s.findAttachedTokenSessionInAccount("Alice", tok(2), 0).?;
    _ = try s.armAttachmentLocalChannelProjection(tok(2), aid(2), "#claimant", true, 7);
    var ops = [_]LifecycleRequest{.{ .request_id = 2, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Alice", ghost), .claimant_client = 2, .claimant = lifecycleSelector("Alice", claimant) } } }};
    const dirty = try lifecycleCanonical(&s);
    try testing.expectError(error.InvalidRequest, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
    try testing.expectEqual(dirty, try lifecycleCanonical(&s));
    ops[0].intent.reconnect.retire_claimant = true;
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    try testing.expectEqual(@as(usize, 1), ticket.preview().retired_attachments.len);
    try testing.expectEqual(@as(u8, 1), ticket.preview().retired_attachments[0].row.attachment_journal.len);
    try testing.expectEqualStrings("#claimant", ticket.preview().retired_attachments[0].row.attachment_journal.items[0].channel());
    try testing.expectEqual(@as(usize, 1), ticket.preview().remaps.len);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(s.clientHasAttachment("Alice", 2, tok(1), aid(1)));
    try expectTokenIndexCoherent(&s);
    try expectLifecycleCountsAndAttachments(&s);
}

test "Session lifecycle batch preserves completed empty journal clock and explicit sentinel facts" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const live = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const armed = try s.armTokenLocalChannelProjection(tok(1), "#done", true, 1);
    try testing.expect(s.clearTokenLocalChannelProjection(tok(1), "#done", armed.generation));
    const revision = s.token_index.get(tok(1)).?.local_projections.revision;
    try testing.expect(revision != 0);
    try testing.expect(s.accounts.get("Alice").?.items.items[0].local_channel_projections == null);
    const ops = [_]LifecycleRequest{
        .{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", live) } } },
        .{ .request_id = 2, .intent = .{ .admit = .{ .account = "Bob", .client = 2, .signon_ms = 20, .kind = .sentinel } } },
    };
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const absence = lifecycleFindRow(ticket.preview().after, 2).?;
    try testing.expect(tokenIsSentinel(absence.token) and absence.attachment_id == null and absence.attached);
    try testing.expectEqual(@as(usize, 2), ticket.preview().affected_physical.len);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expectEqual(revision, s.token_index.get(tok(1)).?.local_projections.revision);
    try testing.expect(!s.token_index.contains(tok(0)));
    try expectTokenIndexCoherent(&s);
    try expectLifecycleCountsAndAttachments(&s);
    ticket.deinit();
    const sentinel = s.accounts.get("Bob").?.items.items[0];
    var changed = [_]LifecycleRequest{.{ .request_id = 3, .intent = .{ .admit = .{ .account = "Bob", .client = 2, .signon_ms = 30, .kind = .fresh, .replace_sentinel = lifecycleSelector("Bob", sentinel) } } }};
    try testing.expect(s.markDetachedWithSnapshot("Bob", 2, "dirty sentinel"));
    const old = try lifecycleCanonical(&s);
    try testing.expectError(error.StaleSelector, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &changed }));
    changed[0].intent.admit.replace_sentinel.?.attached = false;
    try testing.expectError(error.InvalidRequest, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &changed }));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
}

fn lifecycleSameTokenClaimantRetirement(pending: bool) !void {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const claimant = try s.attachWithAttachment("ALICE", 2, tok(1), aid(2), 20);
    try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "ghost snapshot"));
    const ghost = s.findDetachedAttachmentSessionInAccount("Alice", tok(1), aid(1)).?;
    if (pending) _ = try s.armAttachmentLocalChannelProjection(tok(1), aid(2), "#claimant work", true, 3);
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Alice", ghost), .claimant_client = 2, .claimant = lifecycleSelector("ALICE", claimant), .retire_claimant = pending } } }};
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const p = ticket.preview();
    try testing.expectEqual(@as(usize, 1), p.remaps.len);
    try testing.expectEqual(aid(1), p.remaps[0].attachment_id);
    try testing.expectEqual(@as(usize, 1), p.retired_attachments.len);
    try testing.expectEqual(aid(2), p.retired_attachments[0].row.attachment_id.?);
    try testing.expectEqual(LifecycleRemoval.claimant_replacement, p.retired_attachments[0].reason);
    try testing.expectEqual(pending, p.retired_attachments[0].attachment_work_retired);
    if (pending) try testing.expectEqualStrings("#claimant work", p.retired_attachments[0].row.attachment_journal.items[0].channel());
    try testing.expectEqual(@as(usize, 1), p.token_groups.len);
    try testing.expectEqual(@as(usize, 1), p.token_groups[0].final_rows);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try testing.expect(s.clientHasAttachment("Alice", 2, tok(1), aid(1)));
    try expectLifecycleCountsAndAttachments(&s);
}

test "Session lifecycle batch causal same token pristine claimant still retires displaced stable attachment" {
    try lifecycleSameTokenClaimantRetirement(false);
}
test "Session lifecycle batch causal same token claimant work retires separately from ghost remap" {
    try lifecycleSameTokenClaimantRetirement(true);
}

fn lifecyclePermutation(reverse: bool) !struct { state: [32]u8, effects: [32]u8 } {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const x = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const y = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
    _ = try s.attachWithAttachment("Alice", 3, tok(3), aid(3), 30);
    try testing.expect(s.markPortableResumeIssued("Alice", 1));
    try testing.expect(s.markTokenReplicaDirty(tok(1)));
    try testing.expect(s.markTokenReplicaProjectionDirty(tok(1)));
    _ = try s.armTokenLocalChannelProjection(tok(1), "#x", true, 1);
    _ = try s.armTokenLocalChannelProjection(tok(2), "#y", false, 0);
    _ = try s.armTokenLocalChannelProjection(tok(3), "#z", true, 2);
    const xy = LifecycleRequest{ .request_id = 1, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", x), .target_account = "Alice", .target_token = tok(2), .kind = .join_existing, .retire_attachment_work = true } } };
    const yz = LifecycleRequest{ .request_id = 2, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", y), .target_account = "Alice", .target_token = tok(3), .kind = .join_existing, .retire_attachment_work = true } } };
    const ops = if (reverse) [_]LifecycleRequest{ yz, xy } else [_]LifecycleRequest{ xy, yz };
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const p = ticket.preview();
    try testing.expect(!lifecycleFindRow(p.after, 2).?.portable_resume);
    try testing.expect(!lifecycleFindRow(p.after, 3).?.replica_dirty);
    try testing.expectEqual(@as(u8, 2), lifecycleFindRow(p.after, 3).?.group_journal.len);
    var h = std.crypto.hash.Blake3.init(.{});
    std.hash.autoHashStrat(&h, .{ p.before, p.after, p.affected_physical, p.retired_attachments, p.remaps, p.token_groups, p.final_accounts, p.final_rows, p.counts, p.projection_generation }, .DeepRecursive);
    var effects: [32]u8 = undefined;
    h.final(&effects);
    try ticket.validateForCut();
    ticket.commit();
    ticket.finish();
    try expectTokenIndexCoherent(&s);
    try expectLifecycleCountsAndAttachments(&s);
    return .{ .state = try lifecycleCanonical(&s), .effects = effects };
}

test "Session lifecycle batch causal chained rebinds are immutable OLD proof and permutation equivalent" {
    const forward = try lifecyclePermutation(false);
    const reverse = try lifecyclePermutation(true);
    try testing.expectEqual(forward.state, reverse.state);
    try testing.expectEqual(forward.effects, reverse.effects);
}

test "Session lifecycle batch causal included sentinel rejects hidden foreign physical duplicate" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    _ = try s.attach("Alice", 1, tok(0), 10);
    _ = try s.attach("Foreign", 1, tok(0), 20);
    const old = try lifecycleCanonical(&s);
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .admit = .{ .account = "Alice", .client = 2, .signon_ms = 30, .kind = .fresh } } }};
    if (s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops })) |prepared| {
        var ticket = prepared;
        defer ticket.deinit();
        return error.TestExpectedAmbiguousPhysicalRefusal;
    } else |err| try testing.expectEqual(error.AmbiguousPhysicalBinding, err);
    try testing.expectEqual(old, try lifecycleCanonical(&s));
}

test "Session lifecycle batch causal single operation distinct token closure has indexed lookup work" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_sessions_per_account = 256 });
    defer s.deinit();
    for (0..129) |i| _ = try s.attachWithAttachment("Alice", @intCast(i + 1), tokenNumber(i + 1), aidNumber(i + 1), @intCast(i));
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &.{}, .observation_only = .{ .account = "Alice", .client = 999 } });
    defer ticket.deinit();
    const metric = ticket.preview().complexity;
    std.debug.print("Session causal private indexed lookups: groups={d} keys={d}\n", .{ metric.candidate_group_lookups, metric.candidate_key_lookups });
    try testing.expect(metric.candidate_group_lookups <= 3 * 129);
    try testing.expectEqual(@as(usize, 129), metric.group_source_row_visits);
}

test "Session lifecycle batch private folded key index and checked lookup budgets are bounded" {
    var s = SessionStore.initWithConfig(testing.allocator, .{ .max_accounts = 256 });
    defer s.deinit();
    for (0..129) |i| {
        var key: [8]u8 = "abcdefgh".*;
        for (&key, 0..) |*char, bit| if (i & (@as(usize, 1) << @intCast(bit)) != 0) {
            char.* = std.ascii.toUpper(char.*);
        };
        _ = try s.attachWithAttachment(&key, @intCast(i + 1), tok(1), aidNumber(i + 1), @intCast(i));
    }
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &.{}, .observation_only = .{ .account = "abcdefgh", .client = 999 } });
    defer ticket.deinit();
    const p = ticket.preview();
    try testing.expectEqual(@as(usize, 129), p.before.len);
    try testing.expectEqual(@as(usize, 129), p.after.len);
    try testing.expect(p.complexity.candidate_key_lookups <= 20 * 129);
    try testing.expect(p.complexity.candidate_group_lookups <= 3 * 129);
    const work = p.complexity.candidate_key_lookup_work + p.complexity.candidate_group_lookup_work;
    try testing.expect(work > 0 and work < 64 * 1024);
    ticket.abort();
    ticket.deinit();
    const old = try lifecycleCanonical(&s);
    const spec = LifecycleBatchSpec{ .io = testing.io, .operations = &.{}, .observation_only = .{ .account = "abcdefgh", .client = 999 }, .limits = .{ .max_candidate_lookup_work = work - 1 } };
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(spec));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
    var enough = spec;
    enough.limits.max_candidate_lookup_work = work;
    ticket = try s.prepareLifecycleBatch(enough);
    try testing.expectEqual(work, ticket.preview().complexity.candidate_key_lookup_work + ticket.preview().complexity.candidate_group_lookup_work);
    ticket.abort();
    ticket.deinit();
    var tiny = spec;
    tiny.limits.max_candidate_lookup_work = 0;
    try testing.expectError(error.CandidateLimitExceeded, s.prepareLifecycleBatch(tiny));
    try testing.expectEqual(old, try lifecycleCanonical(&s));
}

test "Session lifecycle batch recursive seal validates caller independent nested snapshot contents" {
    var s = SessionStore.init(testing.allocator);
    defer s.deinit();
    const live = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
    const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .detach = .{ .source = lifecycleSelector("Alice", live), .snapshot = .{ .replace = "owned payload" } } } }};
    var ticket = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
    defer ticket.deinit();
    const payload = ticket.owned.?.accounts.items[0].final.items.items[0].snapshot.?;
    payload[0] = 'X';
    try testing.expectError(error.InvalidTicket, ticket.validateForCut());
    payload[0] = 'o';
    try ticket.validateForCut();
    ticket.abort();
}

test "Session lifecycle batch same token reconnect every allocation owns distinct retirement and retry" {
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{});
        var s = SessionStore.init(failing.allocator());
        defer s.deinit();
        _ = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
        const claimant = try s.attachWithAttachment("ALICE", 2, tok(1), aid(2), 20);
        try testing.expect(s.markDetachedWithSnapshot("Alice", 1, "OLD ghost snapshot"));
        _ = try s.armAttachmentLocalChannelProjection(tok(1), aid(2), "#claimant pending", true, 3);
        const ghost = s.findDetachedAttachmentSessionInAccount("Alice", tok(1), aid(1)).?;
        const ops = [_]LifecycleRequest{.{ .request_id = 1, .intent = .{ .reconnect = .{ .source = lifecycleSelector("Alice", ghost), .claimant_client = 2, .claimant = lifecycleSelector("ALICE", claimant), .retire_claimant = true } } }};
        const old = try lifecycleCanonical(&s);
        failing.fail_index = failing.alloc_index + index;
        var ticket = s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqual(old, try lifecycleCanonical(&s));
            failing.fail_index = std.math.maxInt(usize);
            var retry = try s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops });
            defer retry.deinit();
            try testing.expectEqual(@as(usize, 1), retry.preview().retired_attachments.len);
            try testing.expectEqual(aid(2), retry.preview().retired_attachments[0].row.attachment_id.?);
            try testing.expectEqual(@as(usize, 1), retry.preview().remaps.len);
            try retry.validateForCut();
            failing.fail_index = failing.alloc_index;
            retry.commit();
            retry.finish();
            try expectTokenIndexCoherent(&s);
            try expectLifecycleCountsAndAttachments(&s);
            continue;
        };
        defer ticket.deinit();
        try ticket.validateForCut();
        failing.fail_index = failing.alloc_index;
        ticket.commit();
        ticket.finish();
        try testing.expect(s.clientHasAttachment("Alice", 2, tok(1), aid(1)));
        try testing.expect(index > 20);
        std.debug.print("Session same-token reconnect allocation sweep: {d} failures before success\n", .{index});
        break;
    }
}

test "Session lifecycle batch contradictory chained journal intents refuse every permutation before cut" {
    for (0..2) |permutation| {
        var s = SessionStore.init(testing.allocator);
        defer s.deinit();
        const x = try s.attachWithAttachment("Alice", 1, tok(1), aid(1), 10);
        const y = try s.attachWithAttachment("Alice", 2, tok(2), aid(2), 20);
        _ = try s.attachWithAttachment("Alice", 3, tok(3), aid(3), 30);
        const first = try s.armTokenLocalChannelProjection(tok(1), "#same", true, 7);
        _ = try s.armTokenLocalChannelProjection(tok(2), "#SAME", false, 0);
        // Two individually coherent OLD groups with contradictory same-clock
        // work cannot be merged by either compound request order.
        s.lock.lockExclusive();
        const conflicting = s.accounts.getPtr("Alice").?.items.items[1].local_channel_projections.?;
        conflicting.revision = first.generation;
        conflicting.items[0].generation = first.generation;
        s.token_index.getPtr(tok(2)).?.local_projections = conflicting.*;
        s.lock.unlockExclusive();
        const xy = LifecycleRequest{ .request_id = 1, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", x), .target_account = "Alice", .target_token = tok(2), .kind = .join_existing } } };
        const yz = LifecycleRequest{ .request_id = 2, .intent = .{ .rebind = .{ .source = lifecycleSelector("Alice", y), .target_account = "Alice", .target_token = tok(3), .kind = .join_existing } } };
        const ops = if (permutation == 0) [_]LifecycleRequest{ xy, yz } else [_]LifecycleRequest{ yz, xy };
        const old = try lifecycleCanonical(&s);
        try testing.expectError(error.ProjectionConflict, s.prepareLifecycleBatch(.{ .io = testing.io, .operations = &ops }));
        try testing.expectEqual(old, try lifecycleCanonical(&s));
        try testing.expect(s.active_lifecycle == null);
    }
}
