// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Append-only ledger of explicitly reversible moderation changes.
//!
//! Roadmap item Q05: undo is a *new*, authorized event with conflict
//! detection. It never deletes or rewrites history:
//!
//!   * `record` appends one `ChangeRecord` describing a moderation change
//!     (a channel-list +b/+e/+I/+Z fact, a ward, or a shun) and returns a
//!     stable `change_id`. KLINE/DLINE/XLINE are wards on the mask, address
//!     and realname facets, exactly as the live store keeps them. Every
//!     recorded state carries the fact's full content (ward scope, action,
//!     reason and expiry; shun reason and expiry), so an undo can rebuild
//!     the exact fact it reverses. Only actions in the reversible
//!     allowlist (`isReversible`) whose kind and direction match the fact
//!     family can be recorded.
//!   * `planUndo` decides, without mutating anything, whether a change can
//!     be undone now. Checks run in this order: the change is still
//!     retained; the requester *currently* holds the privilege the fact's
//!     scope needs (checked before any state is disclosed); the change has
//!     not already been undone; no later live record touched the same fact;
//!     no external (mesh) write touched the fact; the live fact still
//!     equals the record's `after` state; and the state being restored has
//!     not already passed its own expiry.
//!   * `prepareUndo` repeats that decision and allocates every byte the
//!     undo record needs. `finishUndo` then appends it without allocating,
//!     so a caller can mutate `World` between the two and never strand a
//!     half-applied undo on allocation failure. `abortUndo` releases a
//!     prepared undo that will not be committed.
//!   * The undo record has `undoes = original` and `before`/`after`
//!     swapped. The only mutation to the original is setting its
//!     `undone_by`, which moves exactly once from `null` to a value.
//!     Undoing an undo ("redo") is one more record under the same rules.
//!
//! Channel-list keys carry the channel's incarnation (`FactKey.epoch`) so a
//! destroyed and re-created channel is a different fact. The daemon keeps
//! channel-list records in a second ring whose ids start at
//! `channel_list_id_base`, so chanop list churn cannot evict ward/shun
//! records. AKILL and GLINE are explicitly non-reversible
//! (`nonReversibleReason`).
//!
//! The ring is bounded (`OperAudit.cap`), owns every string it stores, and
//! frees them on eviction or `deinit`. An evicted change id resolves to
//! `.unknown_or_evicted`, the same as a change id that never existed. The
//! authoritative permanent history is the paired `OperAudit` entry
//! (`audit_seq`/`proof_id`); `PreparedUndo.auditReason` renders the reason
//! the undo's own `.undo` audit entry must carry so the audit ring links the
//! reversal to the original entry even after this ring evicts it.
//!
//! This module is a pure leaf. Callers read live fact state, apply the
//! inverse to `World`, mint a fresh mesh HLC, announce the fact, and report
//! inbound mesh writes through `observeExternal`.

const std = @import("std");
const svc_operaudit = @import("svc_operaudit.zig");
const proofmark = @import("proofmark.zig");
const channel_list_event = @import("../proto/channel_list_event.zig");
const warden = @import("warden.zig");
const shun_store = @import("shun.zig");

const Action = svc_operaudit.Action;

/// Explicit allowlist of actions that set or clear a stored moderation fact
/// with a meaningful prior state. Every other action is refused: kills and
/// kicks have no fact to restore; die/restart/connect/squit are process or
/// link lifecycle events; redact is a content takedown; the force* actions
/// act on live membership or session state; jupe, oper_up, rehash, the
/// IRCX access actions, and `other` are not modelled by `Family`; akill and
/// gline are legacy audit labels that no live path records and no store
/// models apart from wards (see `nonReversibleReason`). The switch is
/// exhaustive so a new `Action` variant cannot become reversible by default.
pub fn isReversible(action: Action) bool {
    return switch (action) {
        .mode,
        .kline,
        .unkline,
        .shun,
        .unshun,
        .ward_add,
        .ward_del,
        .undo,
        => true,
        .akill,
        .gline,
        .kill,
        .kick,
        .die,
        .restart,
        .squit,
        .redact,
        .connect,
        .forcejoin,
        .forcepart,
        .forceop,
        .forcedeop,
        .forcetopic,
        .jupe,
        .oper_up,
        .rehash,
        .access_add,
        .access_delete,
        .access_clear,
        .access_copy,
        .other,
        => false,
    };
}

/// Why `action` is refused by `isReversible`, as operator-facing text, or
/// null when the action is reversible. The AKILL/GLINE text is the
/// documented product decision for Q05: Onyx keeps no AKILL or GLINE store
/// and no command records those labels, so there is no prior state to
/// capture. The network-ban role is a `mesh`-scope ward (`WARD ADD <facet>
/// <pattern> mesh`), which is recorded and undoable under the two-person
/// rule. Adding a separate AKILL/GLINE store would need its own versioned,
/// capability-gated mesh fact before an undo of it could be ordered against
/// peer writes, so the labels stay explicitly non-reversible.
pub fn nonReversibleReason(action: Action) ?[]const u8 {
    if (isReversible(action)) return null;
    return switch (action) {
        .akill, .gline => "no AKILL/GLINE store exists on this network; network bans are mesh-scope WARDs, undo those by change id (two-person rule applies)",
        .kill, .kick, .forcejoin, .forcepart, .forceop, .forcedeop, .forcetopic => "it acts on live connections or membership and leaves no stored fact to restore",
        .die, .restart, .squit, .connect, .rehash, .oper_up => "it is a process, link or privilege lifecycle event",
        .redact => "a content takedown is not reversed by moderation undo",
        .jupe, .access_add, .access_delete, .access_clear, .access_copy, .other => "its prior state is not recorded by the moderation ledger",
        else => "it is not on the reversible allowlist",
    };
}

/// Change ids at or above this value belong to the channel-list ledger;
/// smaller ids belong to the ward/shun ledger. The two rings are separate so
/// churn on one channel's +b/+e/+I/+Z lists (any chanop can produce it) can
/// never evict operator ward/shun records, and the id spaces never overlap:
/// both rings seed from the wall clock in milliseconds, far below 2^62.
pub const channel_list_id_base: u64 = 1 << 62;

/// The first id a fresh ledger of the given kind mints at `now_ms`.
pub fn seedFor(channel_lists: bool, now_ms: i64) u64 {
    const ms: u64 = @intCast(std.math.clamp(now_ms, 1, @as(i64, @intCast(channel_list_id_base - 1))));
    return if (channel_lists) channel_list_id_base + ms else ms;
}

/// Whether `change_id` names a channel-list ledger entry.
pub fn isChannelListId(change_id: u64) bool {
    return change_id >= channel_list_id_base;
}

/// The family of moderation fact a `FactKey` identifies.
pub const Family = union(enum) {
    /// A +b/+e/+I/+Z channel-list entry. Reuses the wire `ListKind` so there
    /// is one source of truth for which list a fact belongs to.
    channel_list: channel_list_event.ListKind,
    /// A ward, identified like `warden.Registry` by (match facet, pattern).
    /// KLINE, DLINE and XLINE are wards on `.mask`, `.address` and
    /// `.realname`, so they share keys with the equivalent WARD commands.
    ward: warden.Match,
    /// A shun, identified like `shun.ShunList` by its mask.
    shun,
};

fn familyEql(a: Family, b: Family) bool {
    return switch (a) {
        .channel_list => |ak| switch (b) {
            .channel_list => |bk| ak == bk,
            else => false,
        },
        .ward => |am| switch (b) {
            .ward => |bm| am == bm,
            else => false,
        },
        .shun => b == .shun,
    };
}

/// Which direction an action may move a fact.
const Direction = enum { either, set, clear };

/// The direction `action` must move a fact of `family`, or null when the
/// action does not belong to that family. `.undo` belongs to no family: it
/// is only ever appended by `finishUndo`.
fn directionFor(action: Action, family: Family) ?Direction {
    return switch (family) {
        .channel_list => if (action == .mode) .either else null,
        // The live KLINE/DLINE/XLINE aliases record `.kline` for an add and
        // `.ward_del` for a delete; `.unkline` is the matching legacy label.
        .ward => switch (action) {
            .ward_add, .kline => .set,
            .ward_del, .unkline => .clear,
            else => null,
        },
        .shun => switch (action) {
            .shun => .set,
            .unshun => .clear,
            else => null,
        },
    };
}

/// Identifies one moderation fact. `scope` is the channel name for a
/// channel-list fact and must be empty for a global fact (ward/shun).
/// `mask` is the exact mask/pattern bytes the fact applies to.
pub const FactKey = struct {
    family: Family,
    scope: []const u8,
    mask: []const u8,
    /// Channel incarnation for a channel-list fact (the caller derives it
    /// from the channel's object id and creation time), so a channel that
    /// was destroyed and re-created under the same name is a different
    /// fact and an old change cannot be replayed into it. Always 0 for
    /// ward and shun facts.
    epoch: u64 = 0,

    /// The key of the ward `warden.Registry` identifies by (match, pattern).
    pub fn ofWard(match: warden.Match, pattern: []const u8) FactKey {
        return .{ .family = .{ .ward = match }, .scope = "", .mask = pattern };
    }

    /// The key of the shun `shun.ShunList` identifies by `mask`.
    pub fn ofShun(mask: []const u8) FactKey {
        return .{ .family = .shun, .scope = "", .mask = mask };
    }

    /// The key of one +b/+e/+I/+Z entry of `channel` in incarnation `epoch`.
    pub fn ofChannelList(kind: channel_list_event.ListKind, channel: []const u8, mask: []const u8, epoch: u64) FactKey {
        return .{ .family = .{ .channel_list = kind }, .scope = channel, .mask = mask, .epoch = epoch };
    }
};

/// Channel scopes compare under the daemon's default ASCII casemapping, so
/// `#Chan` and `#chan` are one fact; masks compare byte-exact like
/// `World.removeBan`, `warden.Registry` and `shun.ShunList`.
fn keyEql(a: FactKey, b: FactKey) bool {
    return familyEql(a.family, b.family) and
        a.epoch == b.epoch and
        std.ascii.eqlIgnoreCase(a.scope, b.scope) and
        std.mem.eql(u8, a.mask, b.mask);
}

/// A ward's enforcement policy. Together with the key's match facet and
/// pattern and the state's reason, setter, set time and expiry, it is every
/// field of a `warden.Ward`.
pub const WardPolicy = struct {
    scope: warden.Scope,
    action: warden.Action,
};

/// The state of one fact at a point in time. `version` is the mesh HLC that
/// produced it (`server.nextMeshHlc`), ordering writes like the
/// `CHANNEL_LIST` wire fact.
///
/// A present state carries the fact's full stored content so an undo can
/// rebuild it exactly: `reason` and `expires_ms` for wards and shuns, and
/// `ward` for wards. Channel-list facts must leave all three at their
/// defaults, a present ward must carry `ward`, and a shun must not. An
/// absent fact has no content: the ledger stores it with every content
/// field at its default and ignores them when comparing absent states.
pub const FactState = struct {
    present: bool,
    setter: []const u8,
    set_at: i64,
    version: u64,
    /// Ward/shun reason text.
    reason: []const u8 = "",
    /// Ward/shun absolute expiry in epoch milliseconds; 0 means permanent.
    expires_ms: i64 = 0,
    /// Ward enforcement policy; null for every other family.
    ward: ?WardPolicy = null,

    /// The present state of a live ward.
    pub fn ofWard(w: warden.Ward, version: u64) FactState {
        return .{
            .present = true,
            .setter = w.set_by,
            .set_at = w.created_ms,
            .version = version,
            .reason = w.reason,
            .expires_ms = w.expires_ms,
            .ward = .{ .scope = w.scope, .action = w.action },
        };
    }

    /// The present state of a live shun.
    pub fn ofShun(s: shun_store.Shun, version: u64) FactState {
        return .{
            .present = true,
            .setter = s.set_by,
            .set_at = s.created_ms,
            .version = version,
            .reason = s.reason,
            .expires_ms = s.expires_ms,
        };
    }

    /// Rebuild the ward this present state describes under `key`. The
    /// strings borrow `key` and `self`.
    pub fn asWard(self: FactState, key: FactKey) ?warden.Ward {
        const match = switch (key.family) {
            .ward => |m| m,
            else => return null,
        };
        const policy = self.ward orelse return null;
        if (!self.present) return null;
        return .{
            .match = match,
            .pattern = key.mask,
            .scope = policy.scope,
            .action = policy.action,
            .reason = self.reason,
            .set_by = self.setter,
            .created_ms = self.set_at,
            .expires_ms = self.expires_ms,
        };
    }

    /// Rebuild the shun this present state describes under `key`. The
    /// strings borrow `key` and `self`.
    pub fn asShun(self: FactState, key: FactKey) ?shun_store.Shun {
        if (key.family != .shun or !self.present) return null;
        return .{
            .mask = key.mask,
            .reason = self.reason,
            .set_by = self.setter,
            .created_ms = self.set_at,
            .expires_ms = self.expires_ms,
        };
    }

    /// True when this present state has a finite expiry at or before `now_ms`.
    fn expiredAt(self: FactState, now_ms: i64) bool {
        return self.present and self.expires_ms != 0 and self.expires_ms <= now_ms;
    }
};

fn wardPolicyEql(a: ?WardPolicy, b: ?WardPolicy) bool {
    const ap = a orelse return b == null;
    const bp = b orelse return false;
    return ap.scope == bp.scope and ap.action == bp.action;
}

/// Fact content equality, excluding `version`.
fn sameFact(a: FactState, b: FactState) bool {
    if (a.present != b.present) return false;
    if (!a.present) return true;
    return a.set_at == b.set_at and
        a.expires_ms == b.expires_ms and
        wardPolicyEql(a.ward, b.ward) and
        std.mem.eql(u8, a.setter, b.setter) and
        std.mem.eql(u8, a.reason, b.reason);
}

/// Bound on a stored ward/shun reason; the live stores' default bound.
pub const max_reason_len: usize = 512;

comptime {
    std.debug.assert((warden.Params{}).max_reason <= max_reason_len);
    std.debug.assert((shun_store.Params{}).max_reason <= max_reason_len);
    std.debug.assert((warden.Params{}).max_pattern <= channel_list_event.max_mask_len);
    std.debug.assert((shun_store.Params{}).max_mask <= channel_list_event.max_mask_len);
    std.debug.assert((warden.Params{}).max_setter <= channel_list_event.max_setter_len);
    std.debug.assert((shun_store.Params{}).max_setter <= channel_list_event.max_setter_len);
}

pub const proof_id_len: usize = proofmark.proof_id_hex_len;
pub const max_actor_len: usize = proofmark.max_actor_len;

/// One ledger entry. Strings are owned by the ledger. Entries are never
/// mutated after creation except `undone_by` (null to one value, once) and
/// `externally_changed` (false to true, once).
pub const ChangeRecord = struct {
    change_id: u64,
    audit_seq: u64,
    proof_id_buf: [proof_id_len]u8,
    has_proof_id: bool,
    actor: []const u8,
    action: Action,
    key: FactKey,
    before: FactState,
    after: FactState,
    /// Set when this record is itself an undo: the change it reverses.
    undoes: ?u64,
    /// Set once another record undoes this one. Never cleared.
    undone_by: ?u64,
    /// Set once an inbound mesh write touched this record's fact.
    externally_changed: bool,
    at_ms: i64,

    pub fn proofId(self: *const ChangeRecord) []const u8 {
        return if (self.has_proof_id) self.proof_id_buf[0..] else "";
    }
};

/// Caller description of a new moderation change to record.
pub const ChangeInput = struct {
    action: Action,
    /// `OperAudit.Entry.seq` of the paired audit entry.
    audit_seq: u64,
    /// The paired audit entry's ProofMark id: empty, or exactly
    /// `proof_id_len` lowercase hex characters.
    proof_id: []const u8,
    actor: []const u8,
    key: FactKey,
    before: FactState,
    after: FactState,
    at_ms: i64,
};

pub const RecordError = error{
    /// `action` is not in the reversible allowlist.
    NotReversible,
    /// `action` does not belong to the key's family, or moves the fact in
    /// the wrong direction (for example `.unshun` producing a present fact).
    /// `.undo` is always refused here; only `finishUndo` appends undos.
    ActionFamilyMismatch,
    /// Empty or oversized mask, missing channel scope, a scope or epoch on
    /// a global fact, or an oversized scope.
    InvalidKey,
    /// Empty or oversized actor, or oversized setter.
    InvalidActor,
    /// A state's content does not fit the key's family: a channel-list
    /// state with a reason, expiry or ward policy; a present ward without a
    /// ward policy; a shun with one; a negative expiry; or an oversized
    /// reason.
    InvalidState,
    /// `proof_id` is neither empty nor `proof_id_len` lowercase hex.
    InvalidProofId,
    /// `before` and `after` describe the same fact content.
    NoOpChange,
    /// `after.version` is not strictly newer than `before.version`.
    VersionNotAdvanced,
    /// The change id space is exhausted; refusing rather than reusing ids.
    LedgerExhausted,
} || std.mem.Allocator.Error;

pub const PrepareError = error{
    /// `new_version` is not strictly newer than the fact's current version.
    VersionNotAdvanced,
    /// Empty or oversized requester identity.
    InvalidActor,
    LedgerExhausted,
} || std.mem.Allocator.Error;

pub const FinishError = error{
    /// The ledger changed between `prepareUndo` and `finishUndo`; nothing
    /// was appended and the prepared undo was released. The original stays
    /// un-undone, and because the caller already changed the live fact any
    /// later `planUndo` of it refuses with `.conflict_state_drift`.
    StalePrepared,
    /// `proof_id` is neither empty nor `proof_id_len` lowercase hex.
    InvalidProofId,
};

/// Why a requested undo was refused, in `planUndo` check order.
pub const Refusal = enum {
    /// Never recorded, or evicted from the bounded ring.
    unknown_or_evicted,
    /// The requester does not currently hold the needed privilege. Global
    /// facts (ward/shun) require oper. Channel facts require oper or
    /// current chanop of that exact channel. Having been the original actor
    /// is not sufficient.
    unauthorized,
    /// This change already has an `undone_by` link.
    already_undone,
    /// A later record on the same fact is still in effect. Undo applies only
    /// to the newest effective change of a fact.
    conflict_superseded,
    /// The live fact no longer equals this record's `after` state, its
    /// version moved past it, or an inbound mesh write touched it.
    conflict_state_drift,
    /// The state the undo would restore has a finite expiry at or before
    /// the undo time. Restoring it would either be pruned at once or, if
    /// published as permanent, be harsher than the fact that was reversed.
    target_expired,
};

/// A requester's privilege, evaluated by the caller at undo time.
pub const Requester = struct {
    /// Recorded as the undo record's `actor`.
    identity: []const u8,
    is_oper: bool,
    /// The channel the caller verified the requester is currently a chanop
    /// of, or empty. Compared against the record's own scope so a chanop
    /// check made on the wrong channel cannot authorize an undo.
    chanop_of: []const u8,
};

/// The outcome of `planUndo`. `.ok` strings borrow ledger storage and are
/// valid only until the next ledger mutation.
pub const Decision = union(enum) {
    ok: struct {
        key: FactKey,
        /// The state an undo re-establishes. `version` is a floor: the undo
        /// must be published with a version strictly greater than it.
        target: FactState,
    },
    refusal: Refusal,
};

/// A fully allocated, not yet appended undo record. Own it until exactly one
/// of `finishUndo` or `abortUndo` consumes it.
pub const PreparedUndo = struct {
    record: ChangeRecord,
    generation: u64,
    /// The original's `audit_seq` and ProofMark id, captured at prepare time
    /// for `auditReason`.
    original_audit_seq: u64,
    original_proof_buf: [proof_id_len]u8,
    original_has_proof: bool,

    /// The fact key the caller must change. Borrows the prepared record.
    pub fn key(self: *const PreparedUndo) FactKey {
        return self.record.key;
    }

    /// The fact state the caller must publish, including the new version.
    pub fn target(self: *const PreparedUndo) FactState {
        return self.record.after;
    }

    pub fn originalId(self: *const PreparedUndo) u64 {
        return self.record.undoes.?;
    }

    /// Reason text for the undo's own `.undo` `OperAudit` entry. It names
    /// the original change id, audit sequence and ProofMark id ("-" when
    /// unsigned), so the permanent audit chain references the reversed
    /// entry after this ring evicts it.
    pub fn auditReason(self: *const PreparedUndo, buf: *[max_undo_reason_len]u8) []const u8 {
        const proof: []const u8 = if (self.original_has_proof) self.original_proof_buf[0..] else "-";
        return std.fmt.bufPrint(buf, "undo change={d} audit_seq={d} proof={s}", .{
            self.originalId(),
            self.original_audit_seq,
            proof,
        }) catch unreachable; // The bound covers two u64s and a full proof id.
    }
};

pub const PrepareResult = union(enum) {
    prepared: PreparedUndo,
    refused: Refusal,
};

/// Maximum length of `PreparedUndo.auditReason` output.
pub const max_undo_reason_len: usize = "undo change= audit_seq= proof=".len + 2 * 20 + proof_id_len;

fn validProofId(proof_id: []const u8) bool {
    if (proof_id.len == 0) return true;
    if (proof_id.len != proof_id_len) return false;
    for (proof_id) |c| switch (c) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn validActor(actor: []const u8) bool {
    return actor.len != 0 and actor.len <= max_actor_len;
}

fn validKey(key: FactKey) bool {
    if (key.mask.len == 0 or key.mask.len > channel_list_event.max_mask_len) return false;
    return switch (key.family) {
        .channel_list => key.scope.len != 0 and key.scope.len <= channel_list_event.max_channel_len,
        .ward, .shun => key.scope.len == 0 and key.epoch == 0,
    };
}

fn validSetter(state: FactState) bool {
    return !state.present or state.setter.len <= channel_list_event.max_setter_len;
}

/// Content fits the family. Absent states are normalized on ownership, so
/// only present states are checked.
fn validState(family: Family, state: FactState) bool {
    if (!state.present) return true;
    if (state.expires_ms < 0 or state.reason.len > max_reason_len) return false;
    return switch (family) {
        .channel_list => state.reason.len == 0 and state.expires_ms == 0 and state.ward == null,
        .ward => state.ward != null,
        .shun => state.ward == null,
    };
}

/// Fixed-capacity, oldest-evicted, append-only ledger of reversible
/// moderation changes.
pub const Ledger = struct {
    /// Every recorded change pairs 1:1 with an `OperAudit` entry, so both
    /// rings keep the same bound.
    pub const cap: usize = svc_operaudit.OperAudit.cap;

    allocator: std.mem.Allocator,
    slots: [cap]?ChangeRecord,
    start: usize,
    count: usize,
    next_id: u64,
    /// Bumped by every mutation; `finishUndo` refuses a stale preparation.
    generation: u64,

    pub fn init(allocator: std.mem.Allocator) Ledger {
        return .{
            .allocator = allocator,
            .slots = @as([cap]?ChangeRecord, @splat(null)),
            .start = 0,
            .count = 0,
            .next_id = 1,
            .generation = 0,
        };
    }

    /// Start a fresh, empty ledger's change ids at `first_id` (at least 1),
    /// so ids a restarted process mints do not repeat ids an earlier process
    /// already reported.
    pub fn seedFirstId(self: *Ledger, first_id: u64) void {
        std.debug.assert(self.count == 0 and self.next_id == 1);
        self.next_id = std.math.clamp(first_id, 1, std.math.maxInt(u64) - 1);
    }

    pub fn deinit(self: *Ledger) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.start + i) % cap;
            if (self.slots[idx]) |rec| freeRecord(self.allocator, rec);
            self.slots[idx] = null;
        }
        self.count = 0;
        self.start = 0;
    }

    fn freeRecord(allocator: std.mem.Allocator, rec: ChangeRecord) void {
        allocator.free(rec.actor);
        allocator.free(rec.key.scope);
        allocator.free(rec.key.mask);
        freeState(allocator, rec.before);
        freeState(allocator, rec.after);
    }

    pub fn len(self: *const Ledger) usize {
        return self.count;
    }

    /// Borrow the entry at logical position `i` (0 == oldest).
    pub fn at(self: *const Ledger, i: usize) ?*const ChangeRecord {
        if (i >= self.count) return null;
        return &(self.slots[(self.start + i) % cap].?);
    }

    /// Borrow the retained entry with `change_id`, if any.
    pub fn find(self: *const Ledger, change_id: u64) ?*const ChangeRecord {
        const idx = self.indexOf(change_id) orelse return null;
        return &(self.slots[idx].?);
    }

    fn indexOf(self: *const Ledger, change_id: u64) ?usize {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.start + i) % cap;
            if (self.slots[idx].?.change_id == change_id) return idx;
        }
        return null;
    }

    /// Record one moderation change and return its `change_id`. Validation
    /// happens before any allocation; allocation failure leaves the ledger
    /// byte-identical.
    pub fn record(self: *Ledger, input: ChangeInput) RecordError!u64 {
        if (!isReversible(input.action)) return error.NotReversible;
        const direction = directionFor(input.action, input.key.family) orelse return error.ActionFamilyMismatch;
        switch (direction) {
            .either => {},
            .set => if (!input.after.present) return error.ActionFamilyMismatch,
            .clear => if (input.after.present) return error.ActionFamilyMismatch,
        }
        if (!validKey(input.key)) return error.InvalidKey;
        if (!validActor(input.actor)) return error.InvalidActor;
        if (!validSetter(input.before) or !validSetter(input.after)) return error.InvalidActor;
        if (!validState(input.key.family, input.before) or !validState(input.key.family, input.after)) return error.InvalidState;
        if (!validProofId(input.proof_id)) return error.InvalidProofId;
        if (sameFact(input.before, input.after)) return error.NoOpChange;
        if (input.after.version <= input.before.version) return error.VersionNotAdvanced;
        if (self.next_id == std.math.maxInt(u64)) return error.LedgerExhausted;

        var rec = try ownRecord(self.allocator, input.actor, input.key, input.before, input.after);
        rec.action = input.action;
        rec.audit_seq = input.audit_seq;
        rec.at_ms = input.at_ms;
        setProofId(&rec, input.proof_id);
        return self.push(rec);
    }

    /// Dupe every string a record needs. On failure nothing stays allocated.
    fn ownRecord(
        allocator: std.mem.Allocator,
        actor: []const u8,
        key: FactKey,
        before: FactState,
        after: FactState,
    ) std.mem.Allocator.Error!ChangeRecord {
        const owned_actor = try allocator.dupe(u8, actor);
        errdefer allocator.free(owned_actor);
        const owned_scope = try allocator.dupe(u8, key.scope);
        errdefer allocator.free(owned_scope);
        const owned_mask = try allocator.dupe(u8, key.mask);
        errdefer allocator.free(owned_mask);
        const owned_before = try ownState(allocator, before);
        errdefer freeState(allocator, owned_before);
        const owned_after = try ownState(allocator, after);
        return .{
            .change_id = 0,
            .audit_seq = 0,
            .proof_id_buf = @splat(0),
            .has_proof_id = false,
            .actor = owned_actor,
            .action = .undo,
            .key = .{ .family = key.family, .scope = owned_scope, .mask = owned_mask, .epoch = key.epoch },
            .before = owned_before,
            .after = owned_after,
            .undoes = null,
            .undone_by = null,
            .externally_changed = false,
            .at_ms = 0,
        };
    }

    fn ownState(allocator: std.mem.Allocator, state: FactState) std.mem.Allocator.Error!FactState {
        // An absent state keeps no content; its empty strings are still
        // owned so `freeState` never needs to know which kind it frees.
        const setter = try allocator.dupe(u8, if (state.present) state.setter else "");
        errdefer allocator.free(setter);
        const reason = try allocator.dupe(u8, if (state.present) state.reason else "");
        if (!state.present) return .{ .present = false, .setter = setter, .set_at = 0, .version = state.version, .reason = reason };
        return .{
            .present = true,
            .setter = setter,
            .set_at = state.set_at,
            .version = state.version,
            .reason = reason,
            .expires_ms = state.expires_ms,
            .ward = state.ward,
        };
    }

    fn freeState(allocator: std.mem.Allocator, state: FactState) void {
        allocator.free(state.setter);
        allocator.free(state.reason);
    }

    fn setProofId(rec: *ChangeRecord, proof_id: []const u8) void {
        rec.has_proof_id = proof_id.len != 0;
        if (rec.has_proof_id) @memcpy(rec.proof_id_buf[0..], proof_id);
    }

    /// Append an already-owned record. Never allocates or fails; the caller
    /// has already refused an exhausted id space.
    fn push(self: *Ledger, rec_in: ChangeRecord) u64 {
        std.debug.assert(self.next_id != std.math.maxInt(u64));
        var rec = rec_in;
        rec.change_id = self.next_id;
        self.next_id += 1;
        const idx = if (self.count < cap) blk: {
            const i = (self.start + self.count) % cap;
            self.count += 1;
            break :blk i;
        } else blk: {
            const i = self.start;
            freeRecord(self.allocator, self.slots[i].?);
            self.start = (self.start + 1) % cap;
            break :blk i;
        };
        self.slots[idx] = rec;
        self.generation +%= 1;
        return rec.change_id;
    }

    /// Mark every retained record of `key` as touched by an inbound mesh
    /// write. Call for each applied remote change whose origin is not this
    /// node; later undos of those records refuse `.conflict_state_drift`.
    pub fn observeExternal(self: *Ledger, key: FactKey) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const rec = &(self.slots[(self.start + i) % cap].?);
            if (!rec.externally_changed and keyEql(rec.key, key)) {
                rec.externally_changed = true;
                self.generation +%= 1;
            }
        }
    }

    /// Decide whether `change_id` can be undone at `now_ms` (epoch millis,
    /// the clock ward/shun expiries use). Never allocates or mutates.
    /// `current` is the live fact as the caller reads it, with its full
    /// content (`FactState.ofWard`/`ofShun`); a `current.version` newer than
    /// the record's `after.version` is drift, while an older or zero version
    /// means the caller has no newer write.
    pub fn planUndo(self: *const Ledger, change_id: u64, requester: Requester, current: FactState, now_ms: i64) Decision {
        const idx = self.indexOf(change_id) orelse return .{ .refusal = .unknown_or_evicted };
        const orig = &self.slots[idx].?;

        const authorized = switch (orig.key.family) {
            .ward, .shun => requester.is_oper,
            .channel_list => requester.is_oper or
                (requester.chanop_of.len != 0 and std.ascii.eqlIgnoreCase(requester.chanop_of, orig.key.scope)),
        };
        if (!authorized) return .{ .refusal = .unauthorized };
        if (orig.undone_by != null) return .{ .refusal = .already_undone };
        if (self.hasLaterLive(orig.change_id, orig.key)) return .{ .refusal = .conflict_superseded };
        if (orig.externally_changed or
            current.version > orig.after.version or
            !sameFact(current, orig.after))
        {
            return .{ .refusal = .conflict_state_drift };
        }
        if (orig.before.expiredAt(now_ms)) return .{ .refusal = .target_expired };

        // The full prior content, so the caller rebuilds the exact fact.
        var target = orig.before;
        target.version = orig.after.version;
        return .{ .ok = .{ .key = orig.key, .target = target } };
    }

    /// True when a retained record newer than `after_id` on `key` has not
    /// itself been undone. An undo of a later change counts: once a fact has
    /// moved past this record, only the newest effective change is undoable.
    fn hasLaterLive(self: *const Ledger, after_id: u64, key: FactKey) bool {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const e = &(self.slots[(self.start + i) % cap].?);
            if (e.change_id > after_id and e.undone_by == null and keyEql(e.key, key)) return true;
        }
        return false;
    }

    /// Re-run `planUndo` at `at_ms` and allocate the undo record.
    /// `new_version` must be strictly newer than the fact's version; mint it
    /// before preparing. Nothing in the ledger changes until `finishUndo`.
    pub fn prepareUndo(
        self: *Ledger,
        change_id: u64,
        requester: Requester,
        current: FactState,
        new_version: u64,
        at_ms: i64,
    ) PrepareError!PrepareResult {
        if (!validActor(requester.identity)) return error.InvalidActor;
        const target = switch (self.planUndo(change_id, requester, current, at_ms)) {
            .refusal => |r| return .{ .refused = r },
            .ok => |ok| ok.target,
        };
        if (new_version <= target.version or new_version <= current.version) return error.VersionNotAdvanced;
        if (self.next_id == std.math.maxInt(u64)) return error.LedgerExhausted;

        const orig = self.find(change_id).?;
        var after = target;
        after.version = new_version;
        var rec = try ownRecord(self.allocator, requester.identity, orig.key, orig.after, after);
        rec.action = .undo;
        rec.undoes = change_id;
        rec.at_ms = at_ms;
        return .{ .prepared = .{
            .record = rec,
            .generation = self.generation,
            .original_audit_seq = orig.audit_seq,
            .original_proof_buf = orig.proof_id_buf,
            .original_has_proof = orig.has_proof_id,
        } };
    }

    /// Append a prepared undo with its paired `.undo` audit entry and link
    /// the original's `undone_by`. Never allocates. Consumes `prepared` on
    /// every path.
    pub fn finishUndo(self: *Ledger, prepared: *PreparedUndo, audit_seq: u64, proof_id: []const u8) FinishError!u64 {
        defer prepared.* = undefined;
        if (prepared.generation != self.generation) {
            freeRecord(self.allocator, prepared.record);
            return error.StalePrepared;
        }
        if (!validProofId(proof_id)) {
            freeRecord(self.allocator, prepared.record);
            return error.InvalidProofId;
        }
        const original_id = prepared.record.undoes.?;
        var rec = prepared.record;
        rec.audit_seq = audit_seq;
        setProofId(&rec, proof_id);
        // The generation match proves the original is still retained and not
        // undone. Link before pushing: the push may evict the original when
        // it is the oldest entry of a full ring.
        self.slots[self.indexOf(original_id).?].?.undone_by = self.next_id;
        return self.push(rec);
    }

    /// Release a prepared undo that will not be committed.
    pub fn abortUndo(self: *Ledger, prepared: *PreparedUndo) void {
        freeRecord(self.allocator, prepared.record);
        prepared.* = undefined;
    }
};

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = std.testing;

/// A comptime string of `n` copies of `c`.
fn repeat(comptime c: u8, comptime n: usize) *const [n]u8 {
    const S = struct {
        const bytes: [n]u8 = @splat(c);
    };
    return &S.bytes;
}

const proof_a = repeat('a', proof_id_len);
const proof_b = repeat('b', proof_id_len);
const chan = "#chan";
const ban_mask = "*!*@bad.example";

const oper: Requester = .{ .identity = "Oper!o@h", .is_oper = true, .chanop_of = "" };
/// The undo time `undoNow` and the `planUndo` calls below share.
const test_now: i64 = 2000;

fn banKey() FactKey {
    return .{ .family = .{ .channel_list = .ban }, .scope = chan, .mask = ban_mask };
}

fn banAdd(setter: []const u8, set_at: i64, version: u64) ChangeInput {
    return .{
        .action = .mode,
        .audit_seq = 10,
        .proof_id = proof_a,
        .actor = setter,
        .key = banKey(),
        .before = .{ .present = false, .setter = "", .set_at = 0, .version = version - 1 },
        .after = .{ .present = true, .setter = setter, .set_at = set_at, .version = version },
        .at_ms = set_at,
    };
}

fn present(setter: []const u8, set_at: i64, version: u64) FactState {
    return .{ .present = true, .setter = setter, .set_at = set_at, .version = version };
}

fn absent(version: u64) FactState {
    return .{ .present = false, .setter = "", .set_at = 0, .version = version };
}

fn expectRefusal(expected: Refusal, decision: Decision) !void {
    switch (decision) {
        .ok => return error.TestUnexpectedResult,
        .refusal => |r| try testing.expectEqual(expected, r),
    }
}

fn expectOk(decision: Decision) !FactState {
    return switch (decision) {
        .ok => |ok| ok.target,
        .refusal => error.TestUnexpectedResult,
    };
}

/// prepare + finish, failing the test on refusal.
fn undoNow(ledger: *Ledger, id: u64, requester: Requester, current: FactState, new_version: u64, audit_seq: u64) !u64 {
    var prepared = switch (try ledger.prepareUndo(id, requester, current, new_version, test_now)) {
        .prepared => |p| p,
        .refused => return error.TestUnexpectedResult,
    };
    return ledger.finishUndo(&prepared, audit_seq, proof_b);
}

test "moderation_undo: record then planUndo of a +b add returns .ok with target present=false and requires version > current" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    const target = try expectOk(ledger.planUndo(id, oper, present("Op!o@h", 1000, 5), test_now));
    try testing.expect(!target.present);
    try testing.expectEqual(@as(u64, 5), target.version);

    // A new version equal to the floor is refused without allocating.
    try testing.expectError(error.VersionNotAdvanced, ledger.prepareUndo(id, oper, present("Op!o@h", 1000, 5), 5, 2000));
    try testing.expectEqual(@as(usize, 1), ledger.len());
}

test "moderation_undo: undo commit appends a new record with undoes=id, sets undone_by on the original, and leaves the original's actor/before/after/audit_seq/proof_id unchanged" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    const snap = ledger.find(id).?.*;
    const actor = try testing.allocator.dupe(u8, snap.actor);
    defer testing.allocator.free(actor);

    var prepared = switch (try ledger.prepareUndo(id, .{ .identity = "Op2!o@h", .is_oper = false, .chanop_of = "#CHAN" }, present("Op!o@h", 1000, 5), 6, 2000)) {
        .prepared => |p| p,
        .refused => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(id, prepared.originalId());
    try testing.expect(!prepared.target().present);
    try testing.expectEqual(@as(u64, 6), prepared.target().version);
    // Preparing does not change the ledger.
    try testing.expectEqual(@as(usize, 1), ledger.len());
    try testing.expectEqual(@as(?u64, null), ledger.find(id).?.undone_by);

    var reason_buf: [max_undo_reason_len]u8 = undefined;
    try testing.expectEqualStrings(
        "undo change=1 audit_seq=10 proof=" ++ proof_a,
        prepared.auditReason(&reason_buf),
    );

    const new_id = try ledger.finishUndo(&prepared, 11, proof_b);
    try testing.expect(new_id > id);
    try testing.expectEqual(@as(usize, 2), ledger.len());

    const original = ledger.find(id).?;
    try testing.expectEqual(@as(?u64, new_id), original.undone_by);
    try testing.expectEqual(@as(?u64, null), original.undoes);
    try testing.expectEqual(snap.audit_seq, original.audit_seq);
    try testing.expectEqual(snap.action, original.action);
    try testing.expectEqual(snap.at_ms, original.at_ms);
    try testing.expectEqualStrings(proof_a, original.proofId());
    try testing.expectEqualStrings(actor, original.actor);
    try testing.expect(sameFact(snap.before, original.before) and snap.before.version == original.before.version);
    try testing.expect(sameFact(snap.after, original.after) and snap.after.version == original.after.version);

    const undo_rec = ledger.find(new_id).?;
    try testing.expectEqual(@as(?u64, id), undo_rec.undoes);
    try testing.expectEqual(Action.undo, undo_rec.action);
    try testing.expectEqual(@as(u64, 11), undo_rec.audit_seq);
    try testing.expectEqualStrings(proof_b, undo_rec.proofId());
    try testing.expectEqualStrings("Op2!o@h", undo_rec.actor);
    try testing.expect(sameFact(undo_rec.before, original.after));
    try testing.expect(!undo_rec.after.present);
    try testing.expectEqual(@as(u64, 6), undo_rec.after.version);
}

test "moderation_undo: second undo of same change returns already_undone" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    _ = try undoNow(&ledger, id, oper, present("Op!o@h", 1000, 5), 6, 11);

    // Replaying the identical request (same pre-undo view) is refused.
    try expectRefusal(.already_undone, ledger.planUndo(id, oper, present("Op!o@h", 1000, 5), test_now));
    const replay = try ledger.prepareUndo(id, oper, present("Op!o@h", 1000, 5), 7, 3000);
    try testing.expectEqual(PrepareResult{ .refused = .already_undone }, replay);
    try testing.expectEqual(@as(usize, 2), ledger.len());
}

test "moderation_undo: later unrelated change on same key (not undone) yields conflict_superseded" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const first = try ledger.record(banAdd("Op!o@h", 1000, 5));
    // The ban is removed by someone else, then nobody undoes that removal.
    const removal = try ledger.record(.{
        .action = .mode,
        .audit_seq = 12,
        .proof_id = "",
        .actor = "Op3!o@h",
        .key = .{ .family = .{ .channel_list = .ban }, .scope = "#CHAN", .mask = ban_mask },
        .before = present("Op!o@h", 1000, 5),
        .after = absent(7),
        .at_ms = 1500,
    });
    try expectRefusal(.conflict_superseded, ledger.planUndo(first, oper, absent(7), test_now));

    // A different mask, list kind or channel is not the same fact.
    var other = banAdd("Op!o@h", 1000, 5);
    other.key.mask = "*!*@other.example";
    _ = try ledger.record(other);
    other = banAdd("Op!o@h", 1000, 5);
    other.key.family = .{ .channel_list = .quiet };
    _ = try ledger.record(other);
    other = banAdd("Op!o@h", 1000, 5);
    other.key.scope = "#elsewhere";
    _ = try ledger.record(other);
    _ = try expectOk(ledger.planUndo(removal, oper, absent(7), test_now));

    // Once the later removal is itself undone, the fact still moved past
    // `first` (the undo is now the newest effective change), so `first`
    // stays refused rather than silently clobbering the restoration.
    _ = try undoNow(&ledger, removal, oper, absent(7), 8, 13);
    try expectRefusal(.conflict_superseded, ledger.planUndo(first, oper, present("Op!o@h", 1000, 8), test_now));
}

test "moderation_undo: current state drift (setter/set_at/present differ or version newer from mesh) yields conflict_state_drift" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const id = try ledger.record(banAdd("Op!o@h", 1000, 5));

    try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, present("SomeoneElse!o@h", 1000, 5), test_now));
    try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, absent(5), test_now));
    try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, present("Op!o@h", 1001, 5), test_now));
    try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, present("Op!o@h", 1000, 9), test_now));
    // A caller without a newer version for the fact may pass an older one.
    _ = try expectOk(ledger.planUndo(id, oper, present("Op!o@h", 1000, 0), test_now));

    // A refused prepare allocates nothing and appends nothing.
    try testing.expectEqual(PrepareResult{ .refused = .conflict_state_drift }, try ledger.prepareUndo(id, oper, absent(5), 10, 2000));

    // An inbound mesh write to the same fact (even one that left identical
    // content behind) poisons undo of every retained record of that fact.
    ledger.observeExternal(.{ .family = .{ .channel_list = .ban }, .scope = "#Chan", .mask = ban_mask });
    try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, present("Op!o@h", 1000, 5), test_now));
    try testing.expectEqual(@as(usize, 1), ledger.len());
}

test "moderation_undo: global-scope (ward, KLINE ward, shun) undo by non-oper is unauthorized; channel scope allows current chanop or oper; original actor without current privilege is unauthorized" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const node_expel: WardPolicy = .{ .scope = .node, .action = .expel };
    const globals = [_]struct { family: Family, action: Action, ward: ?WardPolicy }{
        .{ .family = .{ .ward = .mask }, .action = .kline, .ward = node_expel },
        .{ .family = .{ .ward = .host }, .action = .ward_add, .ward = node_expel },
        .{ .family = .shun, .action = .shun, .ward = null },
    };
    for (globals) |g| {
        var live = present("Op!o@h", 1000, 2);
        live.ward = g.ward;
        const id = try ledger.record(.{
            .action = g.action,
            .audit_seq = 1,
            .proof_id = "",
            .actor = "Op!o@h",
            .key = .{ .family = g.family, .scope = "", .mask = "*@bad.example" },
            .before = absent(1),
            .after = live,
            .at_ms = 1000,
        });
        // The original actor, now de-opered, is refused even as a chanop.
        try expectRefusal(.unauthorized, ledger.planUndo(id, .{ .identity = "Op!o@h", .is_oper = false, .chanop_of = chan }, live, test_now));
        try testing.expectEqual(PrepareResult{ .refused = .unauthorized }, try ledger.prepareUndo(id, .{ .identity = "Op!o@h", .is_oper = false, .chanop_of = chan }, live, 3, 2000));
        _ = try expectOk(ledger.planUndo(id, .{ .identity = "Anyone!a@h", .is_oper = true, .chanop_of = "" }, live, test_now));
    }

    const chan_id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    const live = present("Op!o@h", 1000, 5);
    try expectRefusal(.unauthorized, ledger.planUndo(chan_id, .{ .identity = "Op!o@h", .is_oper = false, .chanop_of = "" }, live, test_now));
    // Chanop of a different channel cannot authorize this channel's undo.
    try expectRefusal(.unauthorized, ledger.planUndo(chan_id, .{ .identity = "Op!o@h", .is_oper = false, .chanop_of = "#other" }, live, test_now));
    _ = try expectOk(ledger.planUndo(chan_id, .{ .identity = "Other!x@h", .is_oper = false, .chanop_of = "#Chan" }, live, test_now));
    _ = try expectOk(ledger.planUndo(chan_id, .{ .identity = "AnyOper!x@h", .is_oper = true, .chanop_of = "" }, live, test_now));

    // Authorization is checked before undo state is disclosed.
    _ = try undoNow(&ledger, chan_id, oper, live, 6, 11);
    try expectRefusal(.unauthorized, ledger.planUndo(chan_id, .{ .identity = "Nobody!x@h", .is_oper = false, .chanop_of = "" }, live, test_now));

    // A requester identity must be present and bounded.
    try testing.expectError(error.InvalidActor, ledger.prepareUndo(chan_id, .{ .identity = "", .is_oper = true, .chanop_of = "" }, live, 7, 2000));
}

test "moderation_undo: non-reversible actions (kill, kick, die, redact, force*) are rejected by isReversible and record()" {
    const non_reversible = [_]Action{
        .kill,      .kick,      .die,        .restart,       .squit,        .redact,      .connect,
        .forcejoin, .forcepart, .forceop,    .forcedeop,     .forcetopic,   .jupe,        .oper_up,
        .rehash,    .other,     .access_add, .access_delete, .access_clear, .access_copy, .akill,
        .gline,
    };
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();
    for (non_reversible) |action| {
        try testing.expect(!isReversible(action));
        var input = banAdd("Op!o@h", 1000, 5);
        input.action = action;
        try testing.expectError(error.NotReversible, ledger.record(input));
    }
    const reversible = [_]Action{ .mode, .kline, .unkline, .shun, .unshun, .ward_add, .ward_del, .undo };
    for (reversible) |action| try testing.expect(isReversible(action));

    // Reversible actions outside their family or direction are refused, and
    // `.undo` cannot be forged through `record`.
    var input = banAdd("Op!o@h", 1000, 5);
    input.action = .undo;
    try testing.expectError(error.ActionFamilyMismatch, ledger.record(input));
    input.action = .kline;
    try testing.expectError(error.ActionFamilyMismatch, ledger.record(input));
    try testing.expectError(error.ActionFamilyMismatch, ledger.record(.{
        .action = .unshun,
        .audit_seq = 1,
        .proof_id = "",
        .actor = "Op!o@h",
        .key = .{ .family = .shun, .scope = "", .mask = "*@x" },
        .before = absent(1),
        .after = present("Op!o@h", 1, 2),
        .at_ms = 1,
    }));
    try testing.expectEqual(@as(usize, 0), ledger.len());
}

test "moderation_undo: hostile record inputs are refused before allocation" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    var input = banAdd("Op!o@h", 1000, 5);
    input.key.scope = "";
    try testing.expectError(error.InvalidKey, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.key.mask = "";
    try testing.expectError(error.InvalidKey, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.key.mask = repeat('x', channel_list_event.max_mask_len + 1);
    try testing.expectError(error.InvalidKey, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.key.scope = repeat('#', channel_list_event.max_channel_len + 1);
    try testing.expectError(error.InvalidKey, ledger.record(input));
    try testing.expectError(error.InvalidKey, ledger.record(.{
        .action = .kline,
        .audit_seq = 1,
        .proof_id = "",
        .actor = "Op!o@h",
        .key = .{ .family = .{ .ward = .mask }, .scope = chan, .mask = "*@x" },
        .before = absent(1),
        .after = present("Op!o@h", 1, 2),
        .at_ms = 1,
    }));
    input = banAdd("", 1000, 5);
    try testing.expectError(error.InvalidActor, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.actor = repeat('a', max_actor_len + 1);
    try testing.expectError(error.InvalidActor, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.after.setter = repeat('s', channel_list_event.max_setter_len + 1);
    try testing.expectError(error.InvalidActor, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.proof_id = "deadbeef";
    try testing.expectError(error.InvalidProofId, ledger.record(input));
    input.proof_id = repeat('A', proof_id_len);
    try testing.expectError(error.InvalidProofId, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.before = input.after;
    input.before.version = 4;
    try testing.expectError(error.NoOpChange, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.after.version = input.before.version;
    try testing.expectError(error.VersionNotAdvanced, ledger.record(input));
    try testing.expectEqual(@as(usize, 0), ledger.len());

    // An absent before-state with junk setter/set_at is normalized.
    input = banAdd("Op!o@h", 1000, 5);
    input.before = .{ .present = false, .setter = "junk", .set_at = 77, .version = 4 };
    const id = try ledger.record(input);
    try testing.expectEqualStrings("", ledger.find(id).?.before.setter);
    try testing.expectEqual(@as(i64, 0), ledger.find(id).?.before.set_at);

    // The id space is never reused.
    ledger.next_id = std.math.maxInt(u64);
    try testing.expectError(error.LedgerExhausted, ledger.record(banAdd("Op!o@h", 1000, 5)));
    try testing.expectError(error.LedgerExhausted, ledger.prepareUndo(id, oper, present("Op!o@h", 1000, 5), 6, 2000));
}

test "moderation_undo: unknown or evicted change id returns unknown_or_evicted after ring wraps past cap" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const first_id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    var i: usize = 0;
    while (i < Ledger.cap) : (i += 1) {
        var input = banAdd("Op!o@h", 1000, 5);
        var mask_buf: [32]u8 = undefined;
        input.key.mask = try std.fmt.bufPrint(&mask_buf, "*!*@h{d}", .{i});
        _ = try ledger.record(input);
    }
    try testing.expectEqual(Ledger.cap, ledger.len());
    try testing.expect(ledger.find(first_id) == null);

    const live = present("Op!o@h", 1000, 5);
    try expectRefusal(.unknown_or_evicted, ledger.planUndo(999_999, oper, live, test_now));
    try expectRefusal(.unknown_or_evicted, ledger.planUndo(first_id, oper, live, test_now));
    try testing.expectEqual(PrepareResult{ .refused = .unknown_or_evicted }, try ledger.prepareUndo(first_id, oper, live, 6, 2000));
}

test "moderation_undo: undoing the oldest entry of a full ring commits and evicts it" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    var first: u64 = 0;
    var i: usize = 0;
    while (i < Ledger.cap) : (i += 1) {
        var input = banAdd("Op!o@h", 1000, 5);
        var mask_buf: [32]u8 = undefined;
        input.key.mask = try std.fmt.bufPrint(&mask_buf, "*!*@h{d}", .{i});
        const id = try ledger.record(input);
        if (i == 0) first = id;
    }
    // The strings the prepared record copied outlive the evicted original.
    const new_id = try undoNow(&ledger, first, oper, present("Op!o@h", 1000, 5), 6, 11);
    try testing.expect(ledger.find(first) == null);
    const undo_rec = ledger.find(new_id).?;
    try testing.expectEqualStrings("*!*@h0", undo_rec.key.mask);
    try testing.expectEqualStrings("Op!o@h", undo_rec.before.setter);
    try testing.expectEqual(Ledger.cap, ledger.len());
}

test "moderation_undo: undo of an undo (redo) is a third record and obeys the same rules" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const id1 = try ledger.record(banAdd("Op!o@h", 1000, 5));
    const id2 = try undoNow(&ledger, id1, oper, present("Op!o@h", 1000, 5), 6, 11);

    const after_undo = absent(6);
    const redo_target = try expectOk(ledger.planUndo(id2, oper, after_undo, test_now));
    try testing.expect(redo_target.present);
    try testing.expectEqualStrings("Op!o@h", redo_target.setter);
    try expectRefusal(.unauthorized, ledger.planUndo(id2, .{ .identity = "Nobody!x@h", .is_oper = false, .chanop_of = "" }, after_undo, test_now));

    const id3 = try undoNow(&ledger, id2, oper, after_undo, 7, 12);
    try testing.expectEqual(@as(usize, 3), ledger.len());
    try testing.expectEqual(@as(?u64, id3), ledger.find(id2).?.undone_by);
    try testing.expectEqual(@as(?u64, id2), ledger.find(id1).?.undone_by);
    try testing.expectEqual(@as(?u64, id2), ledger.find(id3).?.undoes);
    try testing.expect(ledger.find(id3).?.after.present);
    try expectRefusal(.already_undone, ledger.planUndo(id2, oper, after_undo, test_now));
    try expectRefusal(.already_undone, ledger.planUndo(id1, oper, present("Op!o@h", 1000, 7), test_now));
}

test "moderation_undo: finishUndo refuses a stale preparation and an invalid proof without appending" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    const live = present("Op!o@h", 1000, 5);

    // Two racing preparations: only the first commit wins.
    var p1 = (try ledger.prepareUndo(id, oper, live, 6, 2000)).prepared;
    var p2 = (try ledger.prepareUndo(id, oper, live, 6, 2000)).prepared;
    _ = try ledger.finishUndo(&p1, 11, proof_b);
    try testing.expectError(error.StalePrepared, ledger.finishUndo(&p2, 12, proof_b));
    try testing.expectEqual(@as(usize, 2), ledger.len());

    // An unrelated append also invalidates a pending preparation.
    const other = try ledger.record(banAdd("Op9!o@h", 3000, 20));
    var p3 = (try ledger.prepareUndo(other, oper, present("Op9!o@h", 3000, 20), 21, 4000)).prepared;
    var unrelated = banAdd("Op!o@h", 1000, 5);
    unrelated.key.mask = "*!*@unrelated";
    _ = try ledger.record(unrelated);
    try testing.expectError(error.StalePrepared, ledger.finishUndo(&p3, 13, ""));
    try testing.expectEqual(@as(?u64, null), ledger.find(other).?.undone_by);

    var p4 = (try ledger.prepareUndo(other, oper, present("Op9!o@h", 3000, 20), 21, 4000)).prepared;
    try testing.expectError(error.InvalidProofId, ledger.finishUndo(&p4, 14, "not-a-proof"));
    try testing.expectEqual(@as(?u64, null), ledger.find(other).?.undone_by);

    var p5 = (try ledger.prepareUndo(other, oper, present("Op9!o@h", 3000, 20), 21, 4000)).prepared;
    ledger.abortUndo(&p5);
    try testing.expectEqual(@as(?u64, null), ledger.find(other).?.undone_by);
    _ = try undoNow(&ledger, other, oper, present("Op9!o@h", 3000, 20), 21, 15);
}

const ward_t0: i64 = 1_000_000;

fn quarantineWard() warden.Ward {
    return .{
        .match = .address,
        .pattern = "192.0.2.0/24",
        .scope = .node,
        .action = .quarantine,
        .reason = "R",
        .set_by = "Op!o@h",
        .created_ms = ward_t0,
        .expires_ms = ward_t0 + 600_000,
    };
}

fn globalChange(action: Action, key: FactKey, before: FactState, after: FactState) ChangeInput {
    return .{
        .action = action,
        .audit_seq = 1,
        .proof_id = "",
        .actor = "Op!o@h",
        .key = key,
        .before = before,
        .after = after,
        .at_ms = ward_t0,
    };
}

fn expectWardEql(expected: warden.Ward, actual: warden.Ward) !void {
    try testing.expectEqual(expected.match, actual.match);
    try testing.expectEqualStrings(expected.pattern, actual.pattern);
    try testing.expectEqual(expected.scope, actual.scope);
    try testing.expectEqual(expected.action, actual.action);
    try testing.expectEqualStrings(expected.reason, actual.reason);
    try testing.expectEqualStrings(expected.set_by, actual.set_by);
    try testing.expectEqual(expected.created_ms, actual.created_ms);
    try testing.expectEqual(expected.expires_ms, actual.expires_ms);
}

test "moderation_undo: undoing ward_del restores the exact ward (match, scope, action, reason, expiry) and refuses once that ward has expired" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const w = quarantineWard();
    const key = FactKey.ofWard(w.match, w.pattern);
    _ = try ledger.record(globalChange(.ward_add, key, absent(1), FactState.ofWard(w, 2)));
    const del = try ledger.record(globalChange(.ward_del, key, FactState.ofWard(w, 2), absent(3)));

    // Thirty minutes later the deleted ten-minute ward has expired: restoring
    // it is refused instead of resurrecting a ward that no longer applies.
    const late = ward_t0 + 1_800_000;
    try expectRefusal(.target_expired, ledger.planUndo(del, oper, absent(3), late));
    try testing.expectEqual(PrepareResult{ .refused = .target_expired }, try ledger.prepareUndo(del, oper, absent(3), 4, late));
    // Exactly at the expiry instant the ward is already expired, as in warden.
    try expectRefusal(.target_expired, ledger.planUndo(del, oper, absent(3), w.expires_ms));
    try testing.expectEqual(@as(usize, 2), ledger.len());

    // Before expiry the target rebuilds every field of the deleted ward.
    const early = ward_t0 + 60_000;
    var prepared = (try ledger.prepareUndo(del, oper, absent(3), 4, early)).prepared;
    const restored = prepared.target().asWard(prepared.key()).?;
    try expectWardEql(w, restored);
    try testing.expectEqual(@as(?shun_store.Shun, null), prepared.target().asShun(prepared.key()));
    const undo_id = try ledger.finishUndo(&prepared, 5, "");

    // The ledger's own copy survives the caller's strings and matches too.
    const undo_rec = ledger.find(undo_id).?;
    try expectWardEql(w, undo_rec.after.asWard(undo_rec.key).?);
    try testing.expect(!undo_rec.before.present);
    try testing.expectEqual(@as(u64, 4), undo_rec.after.version);
}

test "moderation_undo: wards with the same pattern on different match facets are distinct facts, and KLINE shares the WARD mask key" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    var acct = quarantineWard();
    acct.match = .account;
    acct.pattern = "x";
    acct.expires_ms = 0;
    var real = acct;
    real.match = .realname;

    const acct_key = FactKey.ofWard(.account, "x");
    const real_key = FactKey.ofWard(.realname, "x");
    const acct_id = try ledger.record(globalChange(.ward_add, acct_key, absent(1), FactState.ofWard(acct, 2)));
    const real_id = try ledger.record(globalChange(.ward_add, real_key, absent(1), FactState.ofWard(real, 2)));

    // Neither later record supersedes the other, and a mesh write to one
    // facet does not poison the other.
    ledger.observeExternal(real_key);
    _ = try expectOk(ledger.planUndo(acct_id, oper, FactState.ofWard(acct, 2), test_now));
    try expectRefusal(.conflict_state_drift, ledger.planUndo(real_id, oper, FactState.ofWard(real, 2), test_now));
    var p = (try ledger.prepareUndo(acct_id, oper, FactState.ofWard(acct, 2), 3, test_now)).prepared;
    try testing.expect(!p.target().present);
    try testing.expectEqual(warden.Match.account, p.key().family.ward);
    _ = try ledger.finishUndo(&p, 2, "");

    // KLINE <mask> is a ward on `.mask`; the WARD DEL that live KLINE DEL
    // records afterwards supersedes it on the same key.
    var kl = quarantineWard();
    kl.match = .mask;
    kl.pattern = "*!*@bad.example";
    kl.action = .expel;
    kl.expires_ms = 0;
    const kl_key = FactKey.ofWard(.mask, kl.pattern);
    const kline_id = try ledger.record(globalChange(.kline, kl_key, absent(5), FactState.ofWard(kl, 6)));
    const kdel_id = try ledger.record(globalChange(.ward_del, kl_key, FactState.ofWard(kl, 6), absent(7)));
    try expectRefusal(.conflict_superseded, ledger.planUndo(kline_id, oper, absent(7), test_now));
    try expectWardEql(kl, (try expectOk(ledger.planUndo(kdel_id, oper, absent(7), test_now))).asWard(kl_key).?);
}

test "moderation_undo: undoing a ward_add that replaced a ward restores the replaced ward, and any content drift refuses" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const old = quarantineWard();
    var new = old;
    new.scope = .mesh;
    new.action = .expel;
    new.reason = "harsher";
    new.set_by = "Op2!o@h";
    new.created_ms = ward_t0 + 10;
    new.expires_ms = 0;
    const key = FactKey.ofWard(old.match, old.pattern);
    const id = try ledger.record(globalChange(.ward_add, key, FactState.ofWard(old, 2), FactState.ofWard(new, 3)));

    // Every content field of the live ward participates in drift detection.
    const variants = [_]warden.Ward{
        blk: {
            var v = new;
            v.scope = .node;
            break :blk v;
        },
        blk: {
            var v = new;
            v.action = .refuse;
            break :blk v;
        },
        blk: {
            var v = new;
            v.reason = "other";
            break :blk v;
        },
        blk: {
            var v = new;
            v.expires_ms = ward_t0 + 5;
            break :blk v;
        },
    };
    for (variants) |v| try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, FactState.ofWard(v, 3), test_now));
    var no_policy = FactState.ofWard(new, 3);
    no_policy.ward = null;
    try expectRefusal(.conflict_state_drift, ledger.planUndo(id, oper, no_policy, test_now));

    const target = try expectOk(ledger.planUndo(id, oper, FactState.ofWard(new, 3), ward_t0 + 60_000));
    try expectWardEql(old, target.asWard(key).?);
}

test "moderation_undo: undoing unshun restores the shun's reason and expiry; an expired temporary shun is refused and a permanent one never expires" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const temp: shun_store.Shun = .{
        .mask = "bad!*@*",
        .reason = "flood",
        .set_by = "Op!o@h",
        .created_ms = ward_t0,
        .expires_ms = ward_t0 + 600_000,
    };
    const key = FactKey.ofShun(temp.mask);
    _ = try ledger.record(globalChange(.shun, key, absent(1), FactState.ofShun(temp, 2)));
    const unshun = try ledger.record(globalChange(.unshun, key, FactState.ofShun(temp, 2), absent(3)));
    try expectRefusal(.target_expired, ledger.planUndo(unshun, oper, absent(3), ward_t0 + 1_800_000));
    const target = try expectOk(ledger.planUndo(unshun, oper, absent(3), ward_t0 + 1));
    const restored = target.asShun(key).?;
    try testing.expectEqualStrings(temp.mask, restored.mask);
    try testing.expectEqualStrings(temp.reason, restored.reason);
    try testing.expectEqualStrings(temp.set_by, restored.set_by);
    try testing.expectEqual(temp.created_ms, restored.created_ms);
    try testing.expectEqual(temp.expires_ms, restored.expires_ms);
    try testing.expect(target.asWard(key) == null);

    var perm = temp;
    perm.mask = "worse!*@*";
    perm.expires_ms = 0;
    const perm_key = FactKey.ofShun(perm.mask);
    _ = try ledger.record(globalChange(.shun, perm_key, absent(1), FactState.ofShun(perm, 2)));
    const perm_un = try ledger.record(globalChange(.unshun, perm_key, FactState.ofShun(perm, 2), absent(3)));
    const perm_target = try expectOk(ledger.planUndo(perm_un, oper, absent(3), std.math.maxInt(i64)));
    try testing.expectEqual(@as(i64, 0), perm_target.asShun(perm_key).?.expires_ms);
    try testing.expectEqualStrings("flood", perm_target.reason);
}

test "moderation_undo: state content that does not fit the family is refused before allocation" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();

    const ward_key = FactKey.ofWard(.host, "*.bad.example");
    var w = quarantineWard();
    w.match = .host;
    w.pattern = ward_key.mask;

    // A channel-list fact carries no reason, expiry or ward policy.
    var input = banAdd("Op!o@h", 1000, 5);
    input.after.reason = "r";
    try testing.expectError(error.InvalidState, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.after.expires_ms = 1;
    try testing.expectError(error.InvalidState, ledger.record(input));
    input = banAdd("Op!o@h", 1000, 5);
    input.after.ward = .{ .scope = .node, .action = .expel };
    try testing.expectError(error.InvalidState, ledger.record(input));

    // A present ward needs its policy; a shun must not have one.
    var no_policy = FactState.ofWard(w, 2);
    no_policy.ward = null;
    try testing.expectError(error.InvalidState, ledger.record(globalChange(.ward_add, ward_key, absent(1), no_policy)));
    try testing.expectError(error.InvalidState, ledger.record(globalChange(.ward_del, ward_key, no_policy, absent(3))));
    try testing.expectError(error.InvalidState, ledger.record(globalChange(.shun, FactKey.ofShun("m"), absent(1), FactState.ofWard(w, 2))));

    var bad = FactState.ofWard(w, 2);
    bad.expires_ms = -1;
    try testing.expectError(error.InvalidState, ledger.record(globalChange(.ward_add, ward_key, absent(1), bad)));
    bad = FactState.ofWard(w, 2);
    bad.reason = repeat('r', max_reason_len + 1);
    try testing.expectError(error.InvalidState, ledger.record(globalChange(.ward_add, ward_key, absent(1), bad)));

    // Ward and shun actions stay inside their own family.
    try testing.expectError(error.ActionFamilyMismatch, ledger.record(globalChange(.unshun, ward_key, FactState.ofWard(w, 2), absent(3))));
    try testing.expectError(error.ActionFamilyMismatch, ledger.record(globalChange(.ward_del, FactKey.ofShun("m"), present("Op!o@h", 1, 2), absent(3))));
    try testing.expectEqual(@as(usize, 0), ledger.len());

    // An absent state's leftover content is dropped, not stored.
    var junk = absent(1);
    junk.reason = "stale";
    junk.expires_ms = 9;
    junk.ward = .{ .scope = .mesh, .action = .refuse };
    const id = try ledger.record(globalChange(.ward_add, ward_key, junk, FactState.ofWard(w, 2)));
    const rec = ledger.find(id).?;
    try testing.expectEqualStrings("", rec.before.reason);
    try testing.expectEqual(@as(i64, 0), rec.before.expires_ms);
    try testing.expectEqual(@as(?WardPolicy, null), rec.before.ward);
    try testing.expect(rec.before.asWard(rec.key) == null);
}

fn allocationProbe(allocator: std.mem.Allocator) !void {
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();

    const id = try ledger.record(banAdd("Op!o@h", 1000, 5));
    const before_len = ledger.len();
    const before_gen = ledger.generation;
    const result = ledger.prepareUndo(id, oper, present("Op!o@h", 1000, 5), 6, 2000) catch |err| {
        // A failed preparation leaves the ledger untouched.
        try testing.expectEqual(before_len, ledger.len());
        try testing.expectEqual(before_gen, ledger.generation);
        try testing.expectEqual(@as(?u64, null), ledger.find(id).?.undone_by);
        return err;
    };
    var prepared = result.prepared;
    const new_id = try ledger.finishUndo(&prepared, 11, proof_b);
    try testing.expectEqual(@as(?u64, new_id), ledger.find(id).?.undone_by);
}

fn wardAllocationProbe(allocator: std.mem.Allocator) !void {
    var ledger = Ledger.init(allocator);
    defer ledger.deinit();

    const w = quarantineWard();
    const key = FactKey.ofWard(w.match, w.pattern);
    _ = try ledger.record(globalChange(.ward_add, key, absent(1), FactState.ofWard(w, 2)));
    const before_len = ledger.len();
    const del = ledger.record(globalChange(.ward_del, key, FactState.ofWard(w, 2), absent(3))) catch |err| {
        try testing.expectEqual(before_len, ledger.len());
        return err;
    };
    const before_gen = ledger.generation;
    const result = ledger.prepareUndo(del, oper, absent(3), 4, ward_t0) catch |err| {
        try testing.expectEqual(before_len + 1, ledger.len());
        try testing.expectEqual(before_gen, ledger.generation);
        try testing.expectEqual(@as(?u64, null), ledger.find(del).?.undone_by);
        return err;
    };
    var prepared = result.prepared;
    const new_id = try ledger.finishUndo(&prepared, 5, "");
    try expectWardEql(w, ledger.find(new_id).?.after.asWard(key).?);
}

test "moderation_undo: allocation-failure sweep over record/prepareUndo/finishUndo is atomic and leaks nothing" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationProbe, .{});
    try testing.checkAllAllocationFailures(testing.allocator, wardAllocationProbe, .{});
}

test "moderation_undo: a seeded ledger mints ids from its seed and an earlier id stays unknown" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();
    ledger.seedFirstId(1_000_000);
    const id = try ledger.record(banAdd("Op!o@h", 1000, 1));
    try testing.expectEqual(@as(u64, 1_000_000), id);
    try testing.expectEqual(Refusal.unknown_or_evicted, ledger.planUndo(1, oper, present("Op!o@h", 1000, 1), test_now).refusal);
}

test "moderation_undo: channel-list keys carry the channel incarnation, so a re-created channel is a different fact" {
    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();
    ledger.seedFirstId(seedFor(true, 5));

    // A -b removal in incarnation 7 records the removed entry's setter/set_at.
    const key7 = FactKey.ofChannelList(.ban, chan, ban_mask, 7);
    const removal = try ledger.record(.{
        .action = .mode,
        .audit_seq = 0,
        .proof_id = "",
        .actor = "Op",
        .key = key7,
        .before = present("Setter!s@h", 100, 0),
        .after = absent(1),
        .at_ms = 1000,
    });
    try testing.expect(isChannelListId(removal));
    try testing.expectEqual(@as(u64, 7), ledger.find(removal).?.key.epoch);

    // Undo restores the original setter and set time.
    const target = try expectOk(ledger.planUndo(removal, oper, absent(0), test_now));
    try testing.expect(target.present);
    try testing.expectEqualStrings("Setter!s@h", target.setter);
    try testing.expectEqual(@as(i64, 100), target.set_at);

    // A mesh write observed on the same name in another incarnation does not
    // touch the record; one in the same incarnation does.
    ledger.observeExternal(FactKey.ofChannelList(.ban, chan, ban_mask, 8));
    try testing.expect(!ledger.find(removal).?.externally_changed);
    ledger.observeExternal(FactKey.ofChannelList(.ban, "#CHAN", ban_mask, 7));
    try expectRefusal(.conflict_state_drift, ledger.planUndo(removal, oper, absent(0), test_now));

    // Different list kinds on the same mask are different facts.
    const exempt = try ledger.record(.{
        .action = .mode,
        .audit_seq = 0,
        .proof_id = "",
        .actor = "Op",
        .key = FactKey.ofChannelList(.exempt, chan, ban_mask, 7),
        .before = absent(0),
        .after = present("Op!o@h", 200, 1),
        .at_ms = 1000,
    });
    _ = try expectOk(ledger.planUndo(exempt, oper, present("Op!o@h", 200, 0), test_now));

    // A chanop of a different channel is not authorized; a chanop of this one is.
    try expectRefusal(.unauthorized, ledger.planUndo(exempt, .{ .identity = "C", .is_oper = false, .chanop_of = "#other" }, present("Op!o@h", 200, 0), test_now));
    _ = try expectOk(ledger.planUndo(exempt, .{ .identity = "C", .is_oper = false, .chanop_of = "#Chan" }, present("Op!o@h", 200, 0), test_now));

    // Ward and shun keys never carry an epoch.
    var bad_ward = FactKey.ofWard(.host, "x.example");
    bad_ward.epoch = 1;
    const w = quarantineWard();
    try testing.expectError(error.InvalidKey, ledger.record(globalChange(.ward_add, bad_ward, absent(1), FactState.ofWard(w, 2))));
}

test "moderation_undo: channel-list and ward/shun id spaces never overlap" {
    try testing.expect(!isChannelListId(seedFor(false, 1_800_000_000_000)));
    try testing.expect(isChannelListId(seedFor(true, 1_800_000_000_000)));
    try testing.expect(!isChannelListId(seedFor(false, std.math.maxInt(i64))));
    try testing.expect(isChannelListId(seedFor(true, -5)));
    try testing.expectEqual(@as(u64, 1), seedFor(false, -5));
}

test "moderation_undo: AKILL and GLINE are explicitly non-reversible with a stated reason" {
    try testing.expect(!isReversible(.akill));
    try testing.expect(!isReversible(.gline));
    const akill = nonReversibleReason(.akill) orelse return error.TestUnexpectedResult;
    try testing.expect(std.mem.indexOf(u8, akill, "mesh-scope WARD") != null);
    try testing.expectEqualStrings(akill, nonReversibleReason(.gline).?);
    try testing.expect(nonReversibleReason(.kill) != null);
    try testing.expect(nonReversibleReason(.ward_del) == null);
    try testing.expect(nonReversibleReason(.mode) == null);
    // Every action has exactly one answer: reversible, or a reason.
    for (std.enums.values(Action)) |a| {
        try testing.expect(isReversible(a) == (nonReversibleReason(a) == null));
    }

    var ledger = Ledger.init(testing.allocator);
    defer ledger.deinit();
    const w = quarantineWard();
    const key = FactKey.ofWard(w.match, w.pattern);
    try testing.expectError(error.NotReversible, ledger.record(globalChange(.akill, key, absent(1), FactState.ofWard(w, 2))));
    try testing.expectError(error.NotReversible, ledger.record(globalChange(.gline, key, absent(1), FactState.ofWard(w, 2))));
    try testing.expectEqual(@as(usize, 0), ledger.len());
}
