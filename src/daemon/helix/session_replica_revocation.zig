// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure revocation / tombstone-retention policy for SESSION_REPLICA.
//!
//! This leaf owns no Store state and performs no allocation. It is the one
//! place that states, independent of any particular hash-map shape:
//!
//!   * a live session can always be revoked: converting a live entry into a
//!     tombstone frees exactly the slot the tombstone now occupies, so it
//!     can never be blocked by tombstone-table capacity pressure (fixes the
//!     defect where a full tombstone table silently dropped the origin's own
//!     REVOKE and NAKed a peer's REVOKE with `TombstoneFull`, leaving the
//!     live OFFER authoritative and replayable);
//!   * the `max_tombstones` soft cap counts only *soft-capped* tombstones
//!     (installed without converting a live entry), never conversions, so
//!     ordinary revocation volume can never crowd out a REVOKE that arrives
//!     ahead of (or instead of) its OFFER and let that stale OFFER install;
//!   * how long a tombstone blocks resurrection locally (`tombstoneRetainUntil`)
//!     is the latest of its own TTL window, the signed REVOKE's own expiry,
//!     and the expiry of whatever authority it superseded, so a node that
//!     missed the REVOKE can never accept a stale OFFER for longer than the
//!     tombstone blocks it;
//!   * how long that same tombstone is still sent to peers for anti-entropy
//!     (`tombstoneExportable`) depends only on the signed REVOKE's own
//!     validity window, never on the (possibly much longer) local retention
//!     horizon above -- an already-expired signed REVOKE is never forwarded;
//!   * the resulting hard memory bound is explicit: every origin slot (live
//!     entry or tombstone) stays within `max_entries + max_tombstones`, and
//!     `worstCaseRetainedBytes` turns that bound into bytes.
//!
//! `session_replica.zig` owns the Store and wires these rules in; this module
//! only imports `std` and the transport module that defines the signed-object
//! size ceiling, so it is trivially unit-testable without any Store.

const std = @import("std");
const session_replica_transport = @import("../../proto/session_replica_frame.zig");

/// Mirrors the subset of `session_replica.Store.Config` this leaf reasons
/// about. Kept as its own type so this module never imports the Store.
pub const RetentionConfig = struct {
    max_entries: usize,
    max_tombstones: usize,
    tombstone_ttl_ms: u64,
    max_offer_lifetime_ms: u64,
    max_future_skew_ms: u64,
};

pub const RetentionConfigError = error{InvalidRetentionConfig};

/// Rejects a configuration that cannot keep every retention invariant:
///
///  * both caps must be nonzero -- a zero-sized table can never admit even
///    one live session, and every accounting path below assumes a slot can
///    exist;
///  * `tombstone_ttl_ms` must be at least `max_offer_lifetime_ms`, or a node
///    whose wall clock has not stepped back could still have a signed OFFER
///    that outlives the tombstone blocking it, for a window after the
///    REVOKE's own signed validity (and the anti-entropy export predicate)
///    has already elapsed;
///  * every millisecond span must fit the `i64` domain shared with wall-clock
///    timestamps, and the combined-slot accounting `worstCaseRetainedBytes`
///    performs must not overflow `usize`.
pub fn validateRetentionConfig(cfg: RetentionConfig) RetentionConfigError!void {
    if (cfg.max_entries == 0 or cfg.max_tombstones == 0) return error.InvalidRetentionConfig;
    if (cfg.tombstone_ttl_ms < cfg.max_offer_lifetime_ms) return error.InvalidRetentionConfig;
    const i64_max_u64: u64 = @intCast(std.math.maxInt(i64));
    if (cfg.tombstone_ttl_ms > i64_max_u64 or
        cfg.max_offer_lifetime_ms > i64_max_u64 or
        cfg.max_future_skew_ms > i64_max_u64) return error.InvalidRetentionConfig;
    // `acceptedAuthorityHorizon` adds these two spans to a timestamp.
    const accepted_span = std.math.add(u64, cfg.max_offer_lifetime_ms, cfg.max_future_skew_ms) catch
        return error.InvalidRetentionConfig;
    if (accepted_span > i64_max_u64) return error.InvalidRetentionConfig;
    const combined_slots = std.math.add(usize, cfg.max_entries, cfg.max_tombstones) catch
        return error.InvalidRetentionConfig;
    _ = std.math.mul(usize, combined_slots, session_replica_transport.max_signed_payload_len) catch
        return error.InvalidRetentionConfig;
}

/// Combined origin-slot bound (`entries + tombstones`). Saturating so the
/// admission predicates stay total for configs that skipped
/// `validateRetentionConfig` (tests, cold tooling).
pub fn combinedSlots(caps: RetentionConfig) usize {
    return caps.max_entries +| caps.max_tombstones;
}

fn saturateToI64(value: i128) i64 {
    if (value > std.math.maxInt(i64)) return std.math.maxInt(i64);
    if (value < std.math.minInt(i64)) return std.math.minInt(i64);
    return @intCast(value);
}

/// Local retention horizon for one tombstone, inclusive: the tombstone is
/// retained (and keeps blocking stale replay) while `now_ms <= retain_until`.
/// It is the latest of (a) its own removal time plus the configured TTL,
/// (b) the signed REVOKE's own expiry, and (c) the expiry of the authority it
/// superseded, if any. Using the max
/// of all three means the local resurrection block always outlives whatever
/// it replaced, independent of which of the three happens to be largest for
/// a given config or clock skew. i128 intermediates make the sum exact for
/// every legal `i64` timestamp and `u64` TTL; the final `i64` result
/// saturates rather than wraps.
pub fn tombstoneRetainUntil(
    removed_at_ms: i64,
    revoke_expires_at_ms: i64,
    superseded_expires_at_ms: ?i64,
    ttl_ms: u64,
) i64 {
    var best: i128 = @as(i128, removed_at_ms) + @as(i128, ttl_ms);
    best = @max(best, @as(i128, revoke_expires_at_ms));
    if (superseded_expires_at_ms) |superseded| best = @max(best, @as(i128, superseded));
    return saturateToI64(best);
}

/// Upper bound on the signed expiry of any authority a Store could have
/// accepted at or before `removed_at_ms`: acceptance requires
/// `issued <= now + max_future_skew_ms` and
/// `expires - issued <= max_offer_lifetime_ms`. Used as the superseded term
/// of `tombstoneRetainUntil` when the exact superseded expiry is not
/// recorded (Helix checkpoint restore), so restoring never shortens the
/// resurrection block below what the live Store would have kept. It
/// over-retains by at most `max_future_skew_ms`; saturates at `i64` max.
pub fn acceptedAuthorityHorizon(removed_at_ms: i64, caps: RetentionConfig) i64 {
    return saturateToI64(@as(i128, removed_at_ms) +
        @as(i128, caps.max_offer_lifetime_ms) +
        @as(i128, caps.max_future_skew_ms));
}

/// Retention predicate paired with `tombstoneRetainUntil`. A backward wall
/// clock step only lengthens retention; it never sweeps early.
pub fn tombstoneRetained(now_ms: i64, retain_until_ms: i64) bool {
    return now_ms <= retain_until_ms;
}

/// The explicit anti-entropy export rule: a tombstone is forwarded to a peer
/// only while that peer could still independently, cryptographically accept
/// the signed REVOKE on its own merits -- i.e. the REVOKE has not itself
/// expired. The (possibly much longer) local retention horizon computed by
/// `tombstoneRetainUntil` is deliberately never used here: extending how long
/// a resurrection attempt is blocked locally must never extend how long an
/// already-expired signed REVOKE is replayed onto the wire.
pub fn tombstoneExportable(now_ms: i64, revoke_expires_at_ms: i64) bool {
    return now_ms <= revoke_expires_at_ms;
}

/// Inputs to `admitTombstone`, read from the Store's live table shape at the
/// moment a REVOKE is about to be installed, before any mutation.
pub const TombstoneAdmission = struct {
    /// `entries.count()` before this operation.
    entries: usize,
    /// `tombstones.count()` before this operation.
    tombstones: usize,
    /// How many of `tombstones` are soft-capped: installed without
    /// converting a live entry of their own origin. Conversions are never
    /// counted here, so they can never exhaust the soft cap.
    soft_capped_tombstones: usize,
    /// This origin key already holds a tombstone being superseded in place
    /// (a newer REVOKE replacing an older one for the same token+origin).
    replacing: bool,
    /// This origin key currently holds a *live* entry that this REVOKE is
    /// converting into a tombstone. Mutually exclusive with `replacing`.
    converting_live_entry: bool,
};

/// Admission control for installing a tombstone. Converting a live entry
/// into a tombstone can never fail on capacity: the entry slot it frees
/// exactly matches the tombstone slot it now occupies, so a live session can
/// always be revoked regardless of how full the tombstone table otherwise
/// is. A brand-new tombstone for a token this origin holds no live authority
/// for (unknown-token churn, or a REVOKE delivered by anti-entropy ahead of
/// its OFFER) is soft-capped: at most `max_tombstones` such tombstones,
/// counted apart from conversions, preserving today's
/// fail-closed-without-eviction policy against pure attacker-controlled
/// growth without letting honest revocation volume refuse it. Either way the
/// combined `entries + tombstones` total can never exceed
/// `max_entries + max_tombstones`.
pub fn admitTombstone(state: TombstoneAdmission, caps: RetentionConfig) error{TombstoneFull}!void {
    std.debug.assert(!(state.replacing and state.converting_live_entry));
    std.debug.assert(state.soft_capped_tombstones <= state.tombstones);
    if (state.replacing) return;
    const combined_cap = combinedSlots(caps);
    if (state.converting_live_entry) {
        // The caller removes one entry as it adds one tombstone, so the
        // combined total is unchanged. This defensive restatement can only
        // trip if some other invariant was already violated.
        if (state.entries == 0 or state.entries +| state.tombstones > combined_cap) return error.TombstoneFull;
        return;
    }
    if (state.soft_capped_tombstones >= caps.max_tombstones) return error.TombstoneFull;
    if (state.entries +| state.tombstones >= combined_cap) return error.TombstoneFull;
}

/// Inputs to `admitNewEntry`, read from the Store's live table shape at the
/// moment an OFFER is about to be installed, before any mutation.
pub const EntryAdmission = struct {
    /// `entries.count()` before this operation.
    entries: usize,
    /// `tombstones.count()` before this operation.
    tombstones: usize,
    /// This origin key already holds a live entry being superseded in place.
    replacing_entry: bool,
    /// This origin key currently holds a tombstone that this OFFER is
    /// converting back into a live entry (a legitimate strictly-newer
    /// revision reconnecting after a REVOKE). Mutually exclusive with
    /// `replacing_entry`.
    converting_tombstone: bool,
};

/// Admission control for installing a new entry. `max_entries` is always a
/// hard cap on the entries table by itself. When this upsert also removes
/// the same key's tombstone, that tombstone's slot is not double-counted
/// against the combined bound -- it is freed in the same operation. A
/// brand-new entry (no tombstone being converted) must additionally respect
/// the combined `entries + tombstones <= max_entries + max_tombstones`
/// bound, because tombstone-table pressure from `admitTombstone`'s live-entry
/// conversions can otherwise grow past the tombstone soft cap alone.
pub fn admitNewEntry(state: EntryAdmission, caps: RetentionConfig) error{EntryFull}!void {
    std.debug.assert(!(state.replacing_entry and state.converting_tombstone));
    if (state.replacing_entry) return;
    if (state.entries >= caps.max_entries) return error.EntryFull;
    if (state.converting_tombstone) return;
    if (state.entries +| state.tombstones >= combinedSlots(caps)) return error.EntryFull;
}

/// The authority a freshly minted REVOKE is replacing, if any.
pub const SupersededAuthority = struct {
    issued_at_ms: i64,
    expires_at_ms: i64,
};

pub const RevokeLifetime = struct {
    issued_at_ms: i64,
    expires_at_ms: i64,
};

/// REVOKE issuance timestamps for the origin's own revocation. The signed
/// span `expires - issued` is exactly `lifetime_ms` (clamped to the `i64`
/// domain), so the REVOKE always passes the Store's own
/// `max_offer_lifetime_ms` check when `lifetime_ms` is that value -- a REVOKE
/// that its own node would reject is never minted. `issued_at_ms` never
/// regresses behind the superseded authority's issuance, including under a
/// backward wall-clock step. Because every accepted superseded authority has
/// `expires - issued <= max_offer_lifetime_ms`, this yields
/// `expires_at_ms >= superseded.expires_at_ms`: a peer that observed the
/// superseded OFFER is never left holding one whose signed validity outlasts
/// the REVOKE removing it. A superseded span longer than `lifetime_ms` cannot
/// have been accepted under the same config; local retention still covers it
/// through `tombstoneRetainUntil`'s superseded term.
pub fn revokeLifetime(now_wall_ms: u64, superseded: ?SupersededAuthority, lifetime_ms: u64) RevokeLifetime {
    const i64_max: i64 = std.math.maxInt(i64);
    const span: i64 = @intCast(@min(lifetime_ms, @as(u64, @intCast(i64_max))));
    var issued_at_ms: i64 = @intCast(@min(now_wall_ms, @as(u64, @intCast(i64_max))));
    if (superseded) |prior| issued_at_ms = @max(issued_at_ms, prior.issued_at_ms);
    issued_at_ms = @min(issued_at_ms, i64_max - span);
    return .{ .issued_at_ms = issued_at_ms, .expires_at_ms = issued_at_ms + span };
}

/// Worst-case bytes retained by signed OFFER/REVOKE wires alone: every slot
/// in the combined `max_entries + max_tombstones` bound, at the largest
/// signed payload the transport will carry. Saturates at `maxInt(u64)`
/// instead of overflowing so a pathological config still returns a (very
/// large) finite number rather than undefined behavior.
pub fn worstCaseRetainedBytes(caps: RetentionConfig) u64 {
    const combined: u128 = @as(u128, caps.max_entries) + @as(u128, caps.max_tombstones);
    const bytes: u128 = combined * @as(u128, session_replica_transport.max_signed_payload_len);
    if (bytes > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(bytes);
}

/// Turns the current table shape and the memory bound into reportable
/// numbers, e.g. for STATS/metrics. Assembling this from live counts is the
/// caller's job (this leaf owns no Store); the derived `worst_case_bytes`
/// figure is computed in exactly one place so callers never recompute the
/// bound inconsistently.
pub const Report = struct {
    entries: usize,
    tombstones: usize,
    max_entries: usize,
    max_tombstones: usize,
    /// Tombstones counted against the `max_tombstones` soft cap (installed
    /// without converting a live entry); the rest are conversions.
    soft_capped_tombstones: usize,
    /// Smallest `retain_until_ms` among all currently retained tombstones
    /// (the next one eligible for sweep), or `null` when there are none.
    oldest_retain_until_ms: ?i64,
    /// Currently exportable to peers under `tombstoneExportable`.
    exported_tombstones: usize,
    /// Retained locally only: the signed REVOKE itself already expired, but
    /// the superseded authority's expiry (or the configured TTL) has not.
    local_only_tombstones: usize,
    worst_case_bytes: u64,

    pub fn build(
        entries: usize,
        tombstones: usize,
        soft_capped_tombstones: usize,
        oldest_retain_until_ms: ?i64,
        exported_tombstones: usize,
        caps: RetentionConfig,
    ) Report {
        const local_only = if (exported_tombstones > tombstones) 0 else tombstones - exported_tombstones;
        return .{
            .entries = entries,
            .tombstones = tombstones,
            .max_entries = caps.max_entries,
            .max_tombstones = caps.max_tombstones,
            .soft_capped_tombstones = soft_capped_tombstones,
            .oldest_retain_until_ms = oldest_retain_until_ms,
            .exported_tombstones = exported_tombstones,
            .local_only_tombstones = local_only,
            .worst_case_bytes = worstCaseRetainedBytes(caps),
        };
    }
};

const testing = std.testing;

fn testCaps() RetentionConfig {
    return .{
        .max_entries = 4096,
        .max_tombstones = 4096,
        .tombstone_ttl_ms = 24 * 60 * 60 * 1000,
        .max_offer_lifetime_ms = 24 * 60 * 60 * 1000,
        .max_future_skew_ms = 5 * 60 * 1000,
    };
}

test "session_replica_revocation: validateRetentionConfig rejects tombstone_ttl_ms < max_offer_lifetime_ms, zero caps, and i64 overflow sums" {
    try validateRetentionConfig(testCaps());

    var short_ttl = testCaps();
    short_ttl.tombstone_ttl_ms = short_ttl.max_offer_lifetime_ms - 1;
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(short_ttl));

    var equal_ttl = testCaps();
    equal_ttl.tombstone_ttl_ms = equal_ttl.max_offer_lifetime_ms;
    try validateRetentionConfig(equal_ttl);

    var zero_entries = testCaps();
    zero_entries.max_entries = 0;
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(zero_entries));

    var zero_tombstones = testCaps();
    zero_tombstones.max_tombstones = 0;
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(zero_tombstones));

    var huge_ttl = testCaps();
    huge_ttl.tombstone_ttl_ms = @as(u64, std.math.maxInt(u64));
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(huge_ttl));

    // Addition overflow in the combined-slot accounting.
    var overflowing_add = testCaps();
    overflowing_add.max_entries = std.math.maxInt(usize);
    overflowing_add.max_tombstones = 1;
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(overflowing_add));

    // Lifetime + skew is added to timestamps by acceptedAuthorityHorizon.
    var overflowing_span = testCaps();
    overflowing_span.max_offer_lifetime_ms = @intCast(std.math.maxInt(i64));
    overflowing_span.tombstone_ttl_ms = overflowing_span.max_offer_lifetime_ms;
    overflowing_span.max_future_skew_ms = 1;
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(overflowing_span));

    // Multiplication overflow in the worst-case byte accounting, without
    // tripping the addition check above.
    var overflowing_mul = testCaps();
    overflowing_mul.max_entries = std.math.maxInt(usize) / session_replica_transport.max_signed_payload_len + 2;
    overflowing_mul.max_tombstones = 1;
    try testing.expectError(error.InvalidRetentionConfig, validateRetentionConfig(overflowing_mul));
}

test "session_replica_revocation: tombstoneRetainUntil takes the max of removed+ttl, revoke expiry, and superseded expiry, and saturates at i64 max" {
    // TTL window dominates.
    try testing.expectEqual(@as(i64, 1_300), tombstoneRetainUntil(1_000, 1_100, null, 300));
    // Signed REVOKE expiry dominates.
    try testing.expectEqual(@as(i64, 5_000), tombstoneRetainUntil(1_000, 5_000, null, 300));
    // Superseded authority's own expiry dominates both of the above.
    try testing.expectEqual(@as(i64, 9_000), tombstoneRetainUntil(1_000, 5_000, 9_000, 300));
    // A smaller superseded expiry never pulls the result down.
    try testing.expectEqual(@as(i64, 5_000), tombstoneRetainUntil(1_000, 5_000, 1_200, 300));
    // Saturates instead of wrapping when every term is pushed to the i64/u64
    // extremes.
    try testing.expectEqual(
        @as(i64, std.math.maxInt(i64)),
        tombstoneRetainUntil(std.math.maxInt(i64), 0, null, std.math.maxInt(u64)),
    );
    try testing.expectEqual(
        @as(i64, std.math.maxInt(i64)),
        tombstoneRetainUntil(0, 0, std.math.maxInt(i64), 0),
    );
}

test "session_replica_revocation: admitTombstone always admits a live-entry conversion, rejects a new unknown-token tombstone at the soft cap, and never goes past the combined slot bound" {
    const caps: RetentionConfig = .{
        .max_entries = 4,
        .max_tombstones = 3,
        .tombstone_ttl_ms = 10,
        .max_offer_lifetime_ms = 10,
        .max_future_skew_ms = 0,
    };

    // At the soft cap, a brand-new tombstone for an unrelated token is
    // rejected -- fail-closed without eviction, matching today's policy.
    try testing.expectError(error.TombstoneFull, admitTombstone(.{
        .entries = 0,
        .tombstones = 3,
        .soft_capped_tombstones = 3,
        .replacing = false,
        .converting_live_entry = false,
    }, caps));

    // Converting a live entry at that same soft cap always succeeds: one
    // entry slot is freed as one tombstone slot is used.
    try admitTombstone(.{
        .entries = 1,
        .tombstones = 3,
        .soft_capped_tombstones = 3,
        .replacing = false,
        .converting_live_entry = true,
    }, caps);

    // Replacing an already-retained tombstone at the cap needs no new slot.
    try admitTombstone(.{
        .entries = 0,
        .tombstones = 3,
        .soft_capped_tombstones = 3,
        .replacing = true,
        .converting_live_entry = false,
    }, caps);

    // Repeated live-entry conversions can legitimately push the tombstone
    // table past its soft cap, but never past the combined bound.
    var tombstones: usize = 3;
    var entries: usize = 4;
    while (entries > 0) {
        try admitTombstone(.{
            .entries = entries,
            .tombstones = tombstones,
            .soft_capped_tombstones = 3,
            .replacing = false,
            .converting_live_entry = true,
        }, caps);
        tombstones += 1;
        entries -= 1;
    }
    try testing.expectEqual(@as(usize, 7), tombstones);
    try testing.expectEqual(caps.max_entries + caps.max_tombstones, tombstones);

    // One further conversion would overrun the combined bound -- this can
    // only happen if some other invariant was already violated, but the
    // defensive check still fails closed rather than growing unbounded.
    try testing.expectError(error.TombstoneFull, admitTombstone(.{
        .entries = 1,
        .tombstones = tombstones,
        .soft_capped_tombstones = 3,
        .replacing = false,
        .converting_live_entry = true,
    }, caps));
}

test "session_replica_revocation: the soft cap counts only soft-capped tombstones, so honest revocation volume never refuses an unknown-token REVOKE" {
    const caps: RetentionConfig = .{
        .max_entries = 4,
        .max_tombstones = 3,
        .tombstone_ttl_ms = 10,
        .max_offer_lifetime_ms = 10,
        .max_future_skew_ms = 0,
    };

    // Three live-entry conversions fill tombstones to max_tombstones; none
    // is soft-capped, so an unknown-token REVOKE is still admitted.
    try admitTombstone(.{
        .entries = 1,
        .tombstones = 3,
        .soft_capped_tombstones = 0,
        .replacing = false,
        .converting_live_entry = false,
    }, caps);
    // Conversions past the soft cap leave the soft-capped budget untouched.
    try admitTombstone(.{
        .entries = 0,
        .tombstones = 6,
        .soft_capped_tombstones = 2,
        .replacing = false,
        .converting_live_entry = false,
    }, caps);
    // Soft-capped tombstones alone at max_tombstones are still refused.
    try testing.expectError(error.TombstoneFull, admitTombstone(.{
        .entries = 0,
        .tombstones = 4,
        .soft_capped_tombstones = 3,
        .replacing = false,
        .converting_live_entry = false,
    }, caps));
    // The combined origin-slot bound still holds below the soft cap.
    try testing.expectError(error.TombstoneFull, admitTombstone(.{
        .entries = 1,
        .tombstones = 6,
        .soft_capped_tombstones = 0,
        .replacing = false,
        .converting_live_entry = false,
    }, caps));
}

test "session_replica_revocation: admitNewEntry exempts converting the same key's tombstone and enforces the combined bound" {
    const caps: RetentionConfig = .{
        .max_entries = 2,
        .max_tombstones = 1,
        .tombstone_ttl_ms = 10,
        .max_offer_lifetime_ms = 10,
        .max_future_skew_ms = 0,
    };

    // Plain replace: no capacity question at all.
    try admitNewEntry(.{ .entries = 2, .tombstones = 1, .replacing_entry = true, .converting_tombstone = false }, caps);

    // At max_entries, converting this key's own tombstone back into an entry
    // is still bound by max_entries itself.
    try testing.expectError(error.EntryFull, admitNewEntry(.{
        .entries = 2,
        .tombstones = 1,
        .replacing_entry = false,
        .converting_tombstone = true,
    }, caps));

    // Below max_entries, converting this key's own tombstone succeeds even
    // when tombstones has already grown past max_tombstones (a live-entry
    // conversion overflow elsewhere) to exactly the combined bound -- the
    // tombstone being converted here is not double-counted.
    try admitNewEntry(.{
        .entries = 1,
        .tombstones = 2,
        .replacing_entry = false,
        .converting_tombstone = true,
    }, caps);

    // A brand-new entry (no tombstone of its own being converted) at the
    // same counts is rejected: admitting it would occupy a slot beyond the
    // combined bound without freeing one.
    try testing.expectError(error.EntryFull, admitNewEntry(.{
        .entries = 1,
        .tombstones = 2,
        .replacing_entry = false,
        .converting_tombstone = false,
    }, caps));

    // A brand-new entry with room under both bounds is admitted.
    try admitNewEntry(.{
        .entries = 0,
        .tombstones = 1,
        .replacing_entry = false,
        .converting_tombstone = false,
    }, caps);
}

test "session_replica_revocation: revokeLifetime keeps REVOKE expiry >= superseded expiry under a backward wall-clock step and lifetime <= max" {
    const lifetime_ms: u64 = 1_000;
    const span: i64 = @intCast(lifetime_ms);

    // Forward clock, no superseded authority: the ordinary case.
    const fresh = revokeLifetime(10_000, null, lifetime_ms);
    try testing.expectEqual(@as(i64, 10_000), fresh.issued_at_ms);
    try testing.expectEqual(@as(i64, 11_000), fresh.expires_at_ms);

    // Forward clock, with a superseded authority well inside the window:
    // the target lifetime applies exactly.
    const forward = revokeLifetime(10_000, .{ .issued_at_ms = 9_000, .expires_at_ms = 9_500 }, lifetime_ms);
    try testing.expectEqual(@as(i64, 10_000), forward.issued_at_ms);
    try testing.expectEqual(@as(i64, 11_000), forward.expires_at_ms);
    try testing.expect(forward.expires_at_ms >= 9_500);

    // Backward wall-clock step: now regresses behind the superseded
    // authority's own issuance. issued_at_ms does not regress, and every
    // legal superseded span (<= lifetime) stays covered.
    var prior_issued: i64 = 10_000;
    while (prior_issued <= 10_000 + span) : (prior_issued += 250) {
        var prior_span: i64 = 0;
        while (prior_span <= span) : (prior_span += 125) {
            const superseded: SupersededAuthority = .{ .issued_at_ms = prior_issued, .expires_at_ms = prior_issued + prior_span };
            const backward = revokeLifetime(9_000, superseded, lifetime_ms);
            try testing.expectEqual(prior_issued, backward.issued_at_ms);
            try testing.expect(backward.expires_at_ms >= superseded.expires_at_ms);
            try testing.expectEqual(span, backward.expires_at_ms - backward.issued_at_ms);
        }
    }

    // A superseded span longer than the configured maximum could never have
    // been accepted; the REVOKE still never exceeds the maximum lifetime, so
    // it is never one its own Store would reject as InvalidOffer.
    const illegal_superseded: SupersededAuthority = .{ .issued_at_ms = 10_000, .expires_at_ms = 50_000 };
    const bounded = revokeLifetime(10_000, illegal_superseded, lifetime_ms);
    try testing.expectEqual(@as(i64, 10_000), bounded.issued_at_ms);
    try testing.expectEqual(span, bounded.expires_at_ms - bounded.issued_at_ms);

    // Extreme wall clock and lifetime clamp into the i64 domain without
    // overflow, still with expires - issued <= lifetime.
    const extreme = revokeLifetime(std.math.maxInt(u64), null, lifetime_ms);
    try testing.expectEqual(@as(i64, std.math.maxInt(i64)), extreme.expires_at_ms);
    try testing.expectEqual(span, extreme.expires_at_ms - extreme.issued_at_ms);
    const huge_lifetime = revokeLifetime(5, null, std.math.maxInt(u64));
    try testing.expectEqual(@as(i64, 0), huge_lifetime.issued_at_ms);
    try testing.expectEqual(@as(i64, std.math.maxInt(i64)), huge_lifetime.expires_at_ms);
}

test "session_replica_revocation: acceptedAuthorityHorizon bounds every acceptable superseded expiry and saturates" {
    const caps = testCaps();
    const removed_at: i64 = 1_000_000;
    const horizon = acceptedAuthorityHorizon(removed_at, caps);
    // The latest-expiring authority acceptable at removal: issued at the
    // future-skew limit with the maximum lifetime.
    const latest_issued = removed_at + @as(i64, @intCast(caps.max_future_skew_ms));
    const latest_expiry = latest_issued + @as(i64, @intCast(caps.max_offer_lifetime_ms));
    try testing.expectEqual(latest_expiry, horizon);
    try testing.expect(tombstoneRetainUntil(removed_at, removed_at, horizon, caps.tombstone_ttl_ms) >= latest_expiry);
    try testing.expectEqual(@as(i64, std.math.maxInt(i64)), acceptedAuthorityHorizon(std.math.maxInt(i64) - 1, caps));
}

test "session_replica_revocation: retention predicate is inclusive and a backward clock step never sweeps early" {
    const retain_until = tombstoneRetainUntil(1_000, 1_100, null, 300);
    try testing.expect(tombstoneRetained(1_300, retain_until));
    try testing.expect(!tombstoneRetained(1_301, retain_until));
    try testing.expect(tombstoneRetained(std.math.minInt(i64), retain_until));
    // Export follows only the signed REVOKE window, never local retention.
    try testing.expect(tombstoneExportable(1_100, 1_100));
    try testing.expect(!tombstoneExportable(1_101, 1_100));
    try testing.expect(tombstoneRetained(1_101, retain_until));
}

test "session_replica_revocation: admission predicates saturate for unvalidated caps" {
    const caps: RetentionConfig = .{
        .max_entries = std.math.maxInt(usize),
        .max_tombstones = 2,
        .tombstone_ttl_ms = 10,
        .max_offer_lifetime_ms = 10,
        .max_future_skew_ms = 0,
    };
    try testing.expectEqual(@as(usize, std.math.maxInt(usize)), combinedSlots(caps));
    try admitTombstone(.{ .entries = 7, .tombstones = 1, .soft_capped_tombstones = 1, .replacing = false, .converting_live_entry = false }, caps);
    try testing.expectError(error.TombstoneFull, admitTombstone(.{ .entries = 7, .tombstones = 2, .soft_capped_tombstones = 2, .replacing = false, .converting_live_entry = false }, caps));
    // A "conversion" with no live entry to free is an invariant violation.
    try testing.expectError(error.TombstoneFull, admitTombstone(.{ .entries = 0, .tombstones = 2, .soft_capped_tombstones = 2, .replacing = false, .converting_live_entry = true }, caps));
    try admitNewEntry(.{ .entries = 7, .tombstones = 2, .replacing_entry = false, .converting_tombstone = false }, caps);
}

test "session_replica_revocation: worstCaseRetainedBytes equals the caps times max_signed_payload_len, with no overflow" {
    const caps: RetentionConfig = .{
        .max_entries = 10,
        .max_tombstones = 5,
        .tombstone_ttl_ms = 10,
        .max_offer_lifetime_ms = 10,
        .max_future_skew_ms = 0,
    };
    try testing.expectEqual(
        @as(u64, 15) * @as(u64, session_replica_transport.max_signed_payload_len),
        worstCaseRetainedBytes(caps),
    );

    const huge: RetentionConfig = .{
        .max_entries = std.math.maxInt(usize),
        .max_tombstones = std.math.maxInt(usize),
        .tombstone_ttl_ms = 10,
        .max_offer_lifetime_ms = 10,
        .max_future_skew_ms = 0,
    };
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), worstCaseRetainedBytes(huge));
}
