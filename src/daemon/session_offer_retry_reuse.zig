// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SESSION_REPLICA OFFER retry decision: distinguish a required credential
//! rotation from a duplicate publication, including on declared-cohort nodes.
//!
//! `publishSessionReplicaUpsertFor` (server.zig) may finish an interrupted
//! publication by reusing this node's already accepted origin OFFER instead
//! of signing a new revision. That fast path is gated off whenever a replica
//! issuer cohort is declared, because OFFER carries no activation epoch of
//! its own. This module supplies the missing process-local observation
//! without inferring an epoch from the signed object: `StampTable` remembers
//! the exact revision this node's Store accepted and the cohort stamp
//! (declared, activation epoch, roster digest) current at that instant.
//!
//! `decide` is pure value logic over fields the caller already reads from the
//! Store, its signing identity, the receipt ring, and the clock. For an
//! undeclared cohort it is exactly the existing server.zig predicate. For a
//! declared cohort it additionally requires: a stamp for exactly the current
//! OFFER revision, that stamp equal to the current cohort, and (when
//! readiness receipts are enabled) a live self `current_ready` receipt for
//! that revision whose refresh is not yet due. Reuse therefore never skips a
//! signature, receipt, or epoch transition that the new-publication path
//! would have produced.
//!
//! Safety rules:
//!   * Every missing observation (no stamp, stamp for another revision, no
//!     receipt, stale receipt) is a fresh publication, never a reuse.
//!   * Clock arithmetic is checked: hostile or overflowing timestamps fail
//!     closed to a fresh publication instead of trapping or wrapping.
//!   * The evaluation order is fixed, so the `Reason` for any candidate is
//!     deterministic.
//!   * `decide` has no side effects; `record`/`forget`/`reset` converge to
//!     the same table state when repeated (idempotent retries).
//!   * Nothing here allocates. `StampTable` holds bearer tokens: lookups use
//!     constant-time comparison and removal wipes the slot.
//!   * `StampTable` is single-owner (World's serialized publication lane);
//!     `RetryReasonStats` is atomic and may be rendered from any reactor.

const std = @import("std");

const session_replica = @import("helix/session_replica.zig");

pub const Token = session_replica.Token;
pub const Revision = session_replica.Revision;

/// Process-local snapshot of the declared replica-issuer cohort. `declared`
/// mirrors `LinuxServer.hasSessionReplicaCohort()`; `epoch`/`roster_digest`
/// mirror `relay_v2_activation_state`. It describes the caller's validated
/// cohort; issuer authorization itself stays in `ReplicaIssuerView`.
pub const CohortStamp = struct {
    declared: bool,
    epoch: u64,
    roster_digest: [32]u8,

    pub const none: CohortStamp = .{ .declared = false, .epoch = 0, .roster_digest = @splat(0) };

    pub fn eql(a: CohortStamp, b: CohortStamp) bool {
        // Evaluate all three fields unconditionally: no early exit.
        const digest_eq = std.crypto.timing_safe.eql([32]u8, a.roster_digest, b.roster_digest);
        return (a.declared == b.declared) and (a.epoch == b.epoch) and digest_eq;
    }
};

/// What this node remembered when its Store accepted its own OFFER.
pub const Slot = struct {
    revision: Revision,
    stamp: CohortStamp,
};

/// This node's own `current_ready` receipt as currently retained in the
/// receipt ring for the token, if any.
pub const OwnReceipt = struct {
    offered: Revision,
    expires_at_ms: i64,
};

/// Exhaustive reason a retry could not reuse the existing OFFER, listed in
/// the exact precedence `decide` evaluates them.
pub const Reason = enum {
    no_prior,
    lease_already_paired,
    renewal_window_elapsed,
    expired,
    ttl_mismatch,
    untrusted_issuer,
    signer_changed,
    origin_mismatch,
    content_changed,
    cohort_changed,
    cohort_unstamped,
    cohort_receipt_missing,
    cohort_receipt_stale,
    reuse_path_ineligible,

    pub const Class = enum { required_rotation, duplicate_publication, unproven };

    /// `duplicate_publication`: the existing OFFER is byte-for-byte still the
    /// right authority under the proven current cohort, but this node lacks a
    /// live receipt needed to reuse it, or the retry is outside the reuse path
    /// (detached, or no dirty replica bit), so it republishes identical
    /// content under a new revision. `unproven`: no stamp exists for the
    /// current OFFER revision (never recorded, evicted, or reset on exec), so
    /// whether the cohort changed since acceptance is unknown; counting it as
    /// either rotation or duplicate would misreport. Every other reason is a
    /// real change in content, clock state, signing/issuer authority, origin,
    /// or cohort membership.
    pub fn class(self: Reason) Class {
        return switch (self) {
            .cohort_unstamped => .unproven,
            .cohort_receipt_missing,
            .cohort_receipt_stale,
            .reuse_path_ineligible,
            => .duplicate_publication,
            .no_prior,
            .lease_already_paired,
            .renewal_window_elapsed,
            .expired,
            .ttl_mismatch,
            .untrusted_issuer,
            .signer_changed,
            .origin_mismatch,
            .content_changed,
            .cohort_changed,
            => .required_rotation,
        };
    }
};

pub const reason_count: usize = @typeInfo(Reason).@"enum".field_names.len;

pub const Decision = union(enum) {
    reuse,
    publish_new: Reason,
};

/// Plain values the daemon computes at the OFFER retry site. This module
/// performs no decoding or I/O.
pub const Candidate = struct {
    /// False when the Store holds no origin OFFER for this node and token.
    prior_present: bool,
    /// Revision of this node's current attachment lease for the token, if any.
    lease_revision: ?Revision,
    /// Current mesh wall clock (the `issued` value a new OFFER would carry).
    issued_ms: i64,
    offer_issued_ms: i64,
    offer_expires_ms: i64,
    refresh_interval_ms: i64,
    ttl_ms: i64,
    /// `sessionReplicaEntryTrusted(entry)` under the current issuer view.
    entry_trusted: bool,
    /// Prior signer equals the current signing public key.
    signer_matches: bool,
    /// `offer.revision.origin_node == config.node_id`.
    origin_matches: bool,
    operation_matches: bool,
    resume_eligible_matches: bool,
    /// Account, nick, snapshot, and inventory bytes all equal the prior OFFER.
    content_matches: bool,
    offer_revision: Revision,
    current_cohort: CohortStamp,
    /// `StampTable.lookup(token)`.
    stamp: ?Slot,
    /// True when the new-publication path would emit a `current_ready`
    /// receipt (`sessionGroupEnabled()`).
    receipt_required: bool,
    own_receipt: ?OwnReceipt,
    /// Remaining-lifetime threshold below which the publication path would
    /// refresh the receipt (`session_group_readiness_ttl_ms / 2`).
    receipt_refresh_margin_ms: i64,
    /// The existing reuse-path gate besides the cohort: `attached and
    /// sessions.tokenReplicaDirty(token)`. Evaluated last so a real change
    /// is always reported as such.
    reuse_path_eligible: bool,
};

/// Fixed order: no prior, lease pairing, clock state, signing/issuer
/// authority, content, cohort observation, then reuse-path eligibility.
pub fn decide(candidate: Candidate) Decision {
    if (!candidate.prior_present) return .{ .publish_new = .no_prior };
    if (candidate.lease_revision) |lease| {
        if (lease.compare(candidate.offer_revision) == .gt) return .{ .publish_new = .lease_already_paired };
    }

    if (candidate.issued_ms < candidate.offer_issued_ms) return .{ .publish_new = .renewal_window_elapsed };
    const age = std.math.sub(i64, candidate.issued_ms, candidate.offer_issued_ms) catch
        return .{ .publish_new = .renewal_window_elapsed };
    if (age >= candidate.refresh_interval_ms) return .{ .publish_new = .renewal_window_elapsed };
    if (candidate.offer_expires_ms <= candidate.issued_ms) return .{ .publish_new = .expired };
    const lifetime = std.math.sub(i64, candidate.offer_expires_ms, candidate.offer_issued_ms) catch
        return .{ .publish_new = .ttl_mismatch };
    if (lifetime != candidate.ttl_ms) return .{ .publish_new = .ttl_mismatch };

    // A declared cohort without a validated activation epoch never authorizes
    // any issuer (mirrors `ReplicaIssuerView.allows`).
    if (!candidate.entry_trusted or (candidate.current_cohort.declared and candidate.current_cohort.epoch == 0))
        return .{ .publish_new = .untrusted_issuer };
    if (!candidate.signer_matches) return .{ .publish_new = .signer_changed };
    if (!candidate.origin_matches) return .{ .publish_new = .origin_mismatch };

    if (!candidate.operation_matches or !candidate.resume_eligible_matches or !candidate.content_matches)
        return .{ .publish_new = .content_changed };

    if (candidate.current_cohort.declared) {
        const slot = candidate.stamp orelse return .{ .publish_new = .cohort_unstamped };
        if (!slot.revision.eql(candidate.offer_revision)) return .{ .publish_new = .cohort_unstamped };
        if (!slot.stamp.eql(candidate.current_cohort)) return .{ .publish_new = .cohort_changed };
        if (candidate.receipt_required) {
            const receipt = candidate.own_receipt orelse return .{ .publish_new = .cohort_receipt_missing };
            if (!receipt.offered.eql(candidate.offer_revision)) return .{ .publish_new = .cohort_receipt_missing };
            if (receipt.expires_at_ms <= candidate.issued_ms +| candidate.receipt_refresh_margin_ms)
                return .{ .publish_new = .cohort_receipt_stale };
        }
    }

    if (!candidate.reuse_path_eligible) return .{ .publish_new = .reuse_path_ineligible };
    return .reuse;
}

/// Fixed-capacity, process-local, allocation-free token -> `Slot` table.
/// Never checkpointed: it resets on exec. A miss (never recorded, evicted,
/// forgotten, or reset) only ever yields `cohort_unstamped`, never reuse.
pub const StampTable = struct {
    pub const capacity: usize = 256;

    const Entry = struct {
        occupied: bool = false,
        token: Token = @splat(0),
        slot: Slot = .{ .revision = .{ .epoch = 0, .sequence = 0, .origin_node = 0 }, .stamp = .none },
    };

    entries: [capacity]Entry = @splat(.{}),
    /// Round-robin victim cursor, consumed only when every slot is occupied
    /// by another token.
    next: usize = 0,

    fn indexOf(self: *const StampTable, token: Token) ?usize {
        var found: ?usize = null;
        // Scan every slot so lookup time does not depend on token position.
        for (&self.entries, 0..) |*entry, i| {
            if (entry.occupied and std.crypto.timing_safe.eql(Token, entry.token, token) and found == null) found = i;
        }
        return found;
    }

    /// Call after the Store accepted this node's own OFFER for `token` at
    /// `revision` (any cause), with the cohort stamp current at that instant.
    /// Overwrites the token's slot in place; else takes a free slot; else
    /// evicts the round-robin victim.
    pub fn record(self: *StampTable, token: Token, revision: Revision, stamp: CohortStamp) void {
        const idx = self.indexOf(token) orelse self.freeIndex() orelse blk: {
            const victim = self.next;
            self.next = (self.next + 1) % capacity;
            break :blk victim;
        };
        self.entries[idx] = .{ .occupied = true, .token = token, .slot = .{ .revision = revision, .stamp = stamp } };
    }

    fn freeIndex(self: *const StampTable) ?usize {
        for (&self.entries, 0..) |*entry, i| if (!entry.occupied) return i;
        return null;
    }

    /// Returns a copy, never a reference into the table.
    pub fn lookup(self: *const StampTable, token: Token) ?Slot {
        const idx = self.indexOf(token) orelse return null;
        return self.entries[idx].slot;
    }

    /// Call on revoke, tombstone, or group revoke so a stamp never outlives
    /// the authority it described. Wipes the bearer token bytes.
    pub fn forget(self: *StampTable, token: Token) void {
        const idx = self.indexOf(token) orelse return;
        std.crypto.secureZero(u8, &self.entries[idx].token);
        self.entries[idx] = .{};
    }

    /// Forget (and wipe) every stamp for which `keep(context, token,
    /// revision)` is false, e.g. after a Store sweep removed or tombstoned
    /// the authority a stamp described. Allocation-free, O(capacity).
    pub fn retainIf(
        self: *StampTable,
        context: anytype,
        comptime keep: fn (@TypeOf(context), Token, Revision) bool,
    ) usize {
        var forgotten: usize = 0;
        for (&self.entries) |*entry| {
            if (!entry.occupied) continue;
            if (keep(context, entry.token, entry.slot.revision)) continue;
            std.crypto.secureZero(u8, &entry.token);
            entry.* = .{};
            forgotten += 1;
        }
        return forgotten;
    }

    pub fn reset(self: *StampTable) void {
        for (&self.entries) |*entry| std.crypto.secureZero(u8, &entry.token);
        self.* = .{};
    }

    pub fn occupiedCount(self: *const StampTable) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| n += @intFromBool(entry.occupied);
        return n;
    }
};

fn saturatingIncrement(counter: *std.atomic.Value(u64)) void {
    var old = counter.load(.monotonic);
    while (old != std.math.maxInt(u64)) {
        old = counter.cmpxchgWeak(old, old + 1, .monotonic, .monotonic) orelse return;
    }
}

/// Saturating, process-local retry-reason counters. Reset on exec; never
/// checkpointed. Call `note` only at the two existing accepted-publication
/// counter sites so a failed attempt counts nothing and
/// `required + duplicate + unproven == onyx_session_offer_retry_new_total`
/// holds.
pub const RetryReasonStats = struct {
    reason_counts: [reason_count]std.atomic.Value(u64) = @splat(.init(0)),
    reused_no_cohort: std.atomic.Value(u64) = .init(0),
    reused_cohort: std.atomic.Value(u64) = .init(0),

    /// `declared` is the cohort declaration at decision time; it selects
    /// which reuse counter a `.reuse` credits.
    pub fn note(self: *RetryReasonStats, decision: Decision, declared: bool) void {
        switch (decision) {
            .reuse => saturatingIncrement(if (declared) &self.reused_cohort else &self.reused_no_cohort),
            .publish_new => |reason| saturatingIncrement(&self.reason_counts[@backingInt(reason)]),
        }
    }

    pub const Snapshot = struct {
        reasons: [reason_count]u64,
        reused_no_cohort: u64,
        reused_cohort: u64,

        pub fn count(self: Snapshot, reason: Reason) u64 {
            return self.reasons[@backingInt(reason)];
        }

        pub fn classTotal(self: Snapshot, class: Reason.Class) u64 {
            var total: u64 = 0;
            for (self.reasons, 0..) |n, i| {
                const reason: Reason = @fromBackingInt(@intCast(i));
                if (reason.class() == class) total +|= n;
            }
            return total;
        }
    };

    pub fn snapshot(self: *const RetryReasonStats) Snapshot {
        var out: Snapshot = .{
            .reasons = undefined,
            .reused_no_cohort = self.reused_no_cohort.load(.monotonic),
            .reused_cohort = self.reused_cohort.load(.monotonic),
        };
        for (&out.reasons, &self.reason_counts) |*dst, *src| dst.* = src.load(.monotonic);
        return out;
    }

    const help_suffix = "; resets on exec";
    const fixed_metrics = [_]struct { name: []const u8, help: []const u8 }{
        .{ .name = "onyx_session_offer_retry_new_required_total", .help = "Retry OFFERs re-signed for a required content, clock, authority, or cohort change" },
        .{ .name = "onyx_session_offer_retry_new_duplicate_total", .help = "Retry OFFERs re-signed with unchanged content because a local observation was missing" },
        .{ .name = "onyx_session_offer_retry_new_unproven_total", .help = "Retry OFFERs re-signed because no cohort stamp proved whether the accepted OFFER predates a cohort change" },
        .{ .name = "onyx_session_offer_retry_reused_cohort_total", .help = "Accepted OFFERs reused to finish a retry under a declared cohort" },
    };
    const reason_prefix = "onyx_session_offer_retry_new_reason_";

    /// Upper bound of `renderPrometheus` output for any counter values.
    pub const max_render_len: usize = blk: {
        const per_line_overhead = "# HELP  \n# TYPE  counter\n \n".len + help_suffix.len + 20; // 20 = max u64 digits
        var n: usize = 0;
        for (fixed_metrics) |m| n += per_line_overhead + 2 * m.name.len + m.name.len + m.help.len;
        for (@typeInfo(Reason).@"enum".field_names) |name| {
            const metric_len = reason_prefix.len + name.len + "_total".len;
            n += per_line_overhead + 3 * metric_len + "Retry OFFERs re-signed for reason ".len + name.len;
        }
        break :blk n;
    };

    /// Fixed, unlabeled HELP/TYPE/sample blocks in the existing
    /// `onyx_session_*_total` style. Render into a stack buffer of
    /// `max_render_len` and append once, so an allocation failure in the
    /// caller never publishes a partial block.
    pub fn renderPrometheus(self: *const RetryReasonStats, out: []u8) error{NoSpaceLeft}![]const u8 {
        const snap = self.snapshot();
        const fixed_values = [fixed_metrics.len]u64{
            snap.classTotal(.required_rotation),
            snap.classTotal(.duplicate_publication),
            snap.classTotal(.unproven),
            snap.reused_cohort,
        };
        var n: usize = 0;
        inline for (fixed_metrics, fixed_values) |m, value| {
            n += (try std.fmt.bufPrint(out[n..], "# HELP {s} {s}" ++ help_suffix ++ "\n# TYPE {s} counter\n{s} {d}\n", .{
                m.name, m.help, m.name, m.name, value,
            })).len;
        }
        inline for (@typeInfo(Reason).@"enum".field_names, 0..) |name, i| {
            const metric = reason_prefix ++ name ++ "_total";
            n += (try std.fmt.bufPrint(out[n..], "# HELP " ++ metric ++ " Retry OFFERs re-signed for reason " ++ name ++ help_suffix ++ "\n# TYPE " ++ metric ++ " counter\n" ++ metric ++ " {d}\n", .{
                snap.reasons[i],
            })).len;
        }
        return out[0..n];
    }
};

const testing = std.testing;

const day_ms: i64 = 24 * 60 * 60 * 1000;

fn baseCandidate() Candidate {
    return .{
        .prior_present = true,
        .lease_revision = null,
        .issued_ms = 1_000,
        .offer_issued_ms = 1_000,
        .offer_expires_ms = 1_000 + day_ms / 2,
        .refresh_interval_ms = day_ms / 6,
        .ttl_ms = day_ms / 2,
        .entry_trusted = true,
        .signer_matches = true,
        .origin_matches = true,
        .operation_matches = true,
        .resume_eligible_matches = true,
        .content_matches = true,
        .offer_revision = .{ .epoch = 7, .sequence = 7, .origin_node = 1 },
        .current_cohort = .none,
        .stamp = null,
        .receipt_required = false,
        .own_receipt = null,
        .receipt_refresh_margin_ms = 45_000,
        .reuse_path_eligible = true,
    };
}

const test_cohort: CohortStamp = .{ .declared = true, .epoch = 3, .roster_digest = @splat(0xaa) };

fn cohortCandidate() Candidate {
    var c = baseCandidate();
    c.current_cohort = test_cohort;
    c.stamp = .{ .revision = c.offer_revision, .stamp = test_cohort };
    c.receipt_required = true;
    c.own_receipt = .{ .offered = c.offer_revision, .expires_at_ms = c.issued_ms + 90_000 };
    return c;
}

/// Literal transcription of the server.zig no-cohort reuse predicate
/// (`unpaired and fresh and trusted and signer and origin and content`).
fn legacyNoCohortReuses(c: Candidate) bool {
    const unpaired = c.lease_revision == null or c.lease_revision.?.compare(c.offer_revision) != .gt;
    const fresh = c.issued_ms >= c.offer_issued_ms and
        c.issued_ms - c.offer_issued_ms < c.refresh_interval_ms and
        c.offer_expires_ms > c.issued_ms and
        c.offer_expires_ms - c.offer_issued_ms == c.ttl_ms;
    return c.reuse_path_eligible and c.prior_present and unpaired and fresh and c.entry_trusted and c.signer_matches and
        c.origin_matches and c.operation_matches and c.resume_eligible_matches and c.content_matches;
}

const Flip = struct { apply: *const fn (*Candidate) void, reason: Reason };

const no_cohort_flips = [_]Flip{
    .{ .reason = .no_prior, .apply = struct {
        fn f(c: *Candidate) void {
            c.prior_present = false;
        }
    }.f },
    .{ .reason = .lease_already_paired, .apply = struct {
        fn f(c: *Candidate) void {
            c.lease_revision = .{ .epoch = c.offer_revision.epoch, .sequence = c.offer_revision.sequence + 1, .origin_node = 1 };
        }
    }.f },
    .{ .reason = .renewal_window_elapsed, .apply = struct {
        fn f(c: *Candidate) void {
            c.issued_ms = c.offer_issued_ms - 1;
        }
    }.f },
    .{ .reason = .renewal_window_elapsed, .apply = struct {
        fn f(c: *Candidate) void {
            c.issued_ms = c.offer_issued_ms + c.refresh_interval_ms;
        }
    }.f },
    .{ .reason = .expired, .apply = struct {
        fn f(c: *Candidate) void {
            c.offer_expires_ms = c.issued_ms;
        }
    }.f },
    .{ .reason = .ttl_mismatch, .apply = struct {
        fn f(c: *Candidate) void {
            c.ttl_ms += 1;
        }
    }.f },
    .{ .reason = .untrusted_issuer, .apply = struct {
        fn f(c: *Candidate) void {
            c.entry_trusted = false;
        }
    }.f },
    .{ .reason = .signer_changed, .apply = struct {
        fn f(c: *Candidate) void {
            c.signer_matches = false;
        }
    }.f },
    .{ .reason = .origin_mismatch, .apply = struct {
        fn f(c: *Candidate) void {
            c.origin_matches = false;
        }
    }.f },
    .{ .reason = .content_changed, .apply = struct {
        fn f(c: *Candidate) void {
            c.operation_matches = false;
        }
    }.f },
    .{ .reason = .content_changed, .apply = struct {
        fn f(c: *Candidate) void {
            c.resume_eligible_matches = false;
        }
    }.f },
    .{ .reason = .content_changed, .apply = struct {
        fn f(c: *Candidate) void {
            c.content_matches = false;
        }
    }.f },
    .{ .reason = .reuse_path_ineligible, .apply = struct {
        fn f(c: *Candidate) void {
            c.reuse_path_eligible = false;
        }
    }.f },
};

test "session_offer_retry_reuse: no-cohort decide matches existing server.zig predicate for every single-field flip" {
    try testing.expect(legacyNoCohortReuses(baseCandidate()));
    try testing.expectEqual(Decision{ .reuse = {} }, decide(baseCandidate()));

    for (no_cohort_flips) |flip| {
        var candidate = baseCandidate();
        flip.apply(&candidate);
        try testing.expect(!legacyNoCohortReuses(candidate));
        try testing.expectEqual(Decision{ .publish_new = flip.reason }, decide(candidate));
        try testing.expectEqual(if (flip.reason == .reuse_path_ineligible) Reason.Class.duplicate_publication else .required_rotation, flip.reason.class());
    }

    // An equal or older lease is still unpaired; cohort-only inputs are inert
    // without a declared cohort, exactly like the existing predicate.
    var candidate = baseCandidate();
    candidate.lease_revision = candidate.offer_revision;
    candidate.receipt_required = true;
    candidate.own_receipt = null;
    try testing.expect(legacyNoCohortReuses(candidate));
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));
    candidate.lease_revision = .{ .epoch = 6, .sequence = 99, .origin_node = 9 };
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));
}

test "session_offer_retry_reuse: declared cohort with matching stamp, revision and receipt returns reuse; repeated decide is idempotent" {
    const candidate = cohortCandidate();
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));

    // Receipts disabled: the stamp alone proves the epoch.
    var no_receipts = cohortCandidate();
    no_receipts.receipt_required = false;
    no_receipts.own_receipt = null;
    try testing.expectEqual(Decision{ .reuse = {} }, decide(no_receipts));

    // The same flips still fail as required rotations under a cohort.
    for (no_cohort_flips) |flip| {
        var flipped = cohortCandidate();
        flip.apply(&flipped);
        try testing.expectEqual(Decision{ .publish_new = flip.reason }, decide(flipped));
    }
}

test "session_offer_retry_reuse: declared cohort epoch or roster digest change returns publish_new(cohort_changed) classified required_rotation" {
    const changes = [_]CohortStamp{
        .{ .declared = true, .epoch = 4, .roster_digest = test_cohort.roster_digest },
        .{ .declared = true, .epoch = test_cohort.epoch, .roster_digest = @splat(0xbb) },
        // Recorded while undeclared, now declared.
        .none,
    };
    for (changes) |recorded| {
        var candidate = cohortCandidate();
        candidate.stamp.?.stamp = recorded;
        const decision = decide(candidate);
        try testing.expectEqual(Decision{ .publish_new = .cohort_changed }, decision);
        try testing.expectEqual(Reason.Class.required_rotation, decision.publish_new.class());
    }

    // Declared without a validated epoch never trusts any issuer.
    var unvalidated = cohortCandidate();
    unvalidated.current_cohort.epoch = 0;
    unvalidated.stamp.?.stamp.epoch = 0;
    try testing.expectEqual(Decision{ .publish_new = .untrusted_issuer }, decide(unvalidated));
}

test "session_offer_retry_reuse: missing stamp or stamp for older revision returns cohort_unstamped classified unproven, never reuse" {
    var candidate = cohortCandidate();
    candidate.stamp = null;
    const decision = decide(candidate);
    try testing.expectEqual(Decision{ .publish_new = .cohort_unstamped }, decision);
    // An evicted or exec-reset stamp cannot prove the cohort is unchanged, so
    // it is neither a required rotation nor a duplicate publication.
    try testing.expectEqual(Reason.Class.unproven, decision.publish_new.class());

    const others = [_]Revision{
        .{ .epoch = 6, .sequence = 7, .origin_node = 1 },
        .{ .epoch = 7, .sequence = 6, .origin_node = 1 },
        .{ .epoch = 7, .sequence = 7, .origin_node = 2 },
        .{ .epoch = 8, .sequence = 8, .origin_node = 1 },
    };
    for (others) |revision| {
        candidate = cohortCandidate();
        candidate.stamp.?.revision = revision;
        try testing.expectEqual(Decision{ .publish_new = .cohort_unstamped }, decide(candidate));
    }
}

test "session_offer_retry_reuse: receipt missing, for another revision, or refresh-due never reuses" {
    var candidate = cohortCandidate();
    candidate.own_receipt = null;
    var decision = decide(candidate);
    try testing.expectEqual(Decision{ .publish_new = .cohort_receipt_missing }, decision);
    try testing.expectEqual(Reason.Class.duplicate_publication, decision.publish_new.class());

    candidate = cohortCandidate();
    candidate.own_receipt.?.offered = .{ .epoch = 6, .sequence = 6, .origin_node = 1 };
    try testing.expectEqual(Decision{ .publish_new = .cohort_receipt_missing }, decide(candidate));

    // Boundary: expiry exactly at issued + margin is due for refresh.
    candidate = cohortCandidate();
    candidate.own_receipt.?.expires_at_ms = candidate.issued_ms + candidate.receipt_refresh_margin_ms;
    decision = decide(candidate);
    try testing.expectEqual(Decision{ .publish_new = .cohort_receipt_stale }, decision);
    try testing.expectEqual(Reason.Class.duplicate_publication, decision.publish_new.class());
    candidate.own_receipt.?.expires_at_ms += 1;
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));

    // Already expired receipt; saturating margin never wraps into reuse.
    candidate = cohortCandidate();
    candidate.own_receipt.?.expires_at_ms = candidate.issued_ms - 1;
    try testing.expectEqual(Decision{ .publish_new = .cohort_receipt_stale }, decide(candidate));
    candidate = cohortCandidate();
    candidate.receipt_refresh_margin_ms = std.math.maxInt(i64);
    candidate.own_receipt.?.expires_at_ms = std.math.maxInt(i64);
    try testing.expectEqual(Decision{ .publish_new = .cohort_receipt_stale }, decide(candidate));
}

test "session_offer_retry_reuse: reason precedence is deterministic (lease_paired before clock before authority before content before cohort)" {
    var all_fail = cohortCandidate();
    all_fail.lease_revision = .{ .epoch = 99, .sequence = 99, .origin_node = 1 };
    all_fail.issued_ms = all_fail.offer_issued_ms + all_fail.refresh_interval_ms;
    all_fail.entry_trusted = false;
    all_fail.content_matches = false;
    all_fail.stamp = null;
    all_fail.own_receipt = null;
    all_fail.reuse_path_eligible = false;

    const expected = [_]Reason{ .lease_already_paired, .renewal_window_elapsed, .untrusted_issuer, .content_changed, .cohort_unstamped, .cohort_receipt_missing, .reuse_path_ineligible };
    var candidate = all_fail;
    for (expected, 0..) |reason, step| {
        try testing.expectEqual(Decision{ .publish_new = reason }, decide(candidate));
        switch (step) {
            0 => candidate.lease_revision = null,
            1 => candidate.issued_ms = candidate.offer_issued_ms,
            2 => candidate.entry_trusted = true,
            3 => candidate.content_matches = true,
            4 => candidate.stamp = .{ .revision = candidate.offer_revision, .stamp = test_cohort },
            5 => candidate.own_receipt = .{ .offered = candidate.offer_revision, .expires_at_ms = candidate.issued_ms + 90_000 },
            6 => candidate.reuse_path_eligible = true,
            else => unreachable,
        }
    }
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));

    // Within the cohort tier: stamp revision before stamp equality.
    candidate = cohortCandidate();
    candidate.stamp = .{ .revision = .{ .epoch = 1, .sequence = 1, .origin_node = 1 }, .stamp = .none };
    try testing.expectEqual(Decision{ .publish_new = .cohort_unstamped }, decide(candidate));
}

test "session_offer_retry_reuse: hostile timestamps fail closed without overflow" {
    var candidate = baseCandidate();
    candidate.issued_ms = std.math.maxInt(i64);
    candidate.offer_issued_ms = std.math.minInt(i64);
    try testing.expectEqual(Decision{ .publish_new = .renewal_window_elapsed }, decide(candidate));

    candidate = baseCandidate();
    candidate.offer_issued_ms = std.math.minInt(i64);
    candidate.issued_ms = std.math.minInt(i64);
    candidate.offer_expires_ms = std.math.maxInt(i64);
    try testing.expectEqual(Decision{ .publish_new = .ttl_mismatch }, decide(candidate));

    // Negative refresh interval never permits reuse.
    candidate = baseCandidate();
    candidate.refresh_interval_ms = -1;
    try testing.expectEqual(Decision{ .publish_new = .renewal_window_elapsed }, decide(candidate));
}

fn testToken(i: usize) Token {
    var token: Token = @splat(0x5a);
    token[0] = @intCast(i & 0xff);
    token[1] = @intCast((i >> 8) & 0xff);
    return token;
}

fn testRevision(i: usize) Revision {
    return .{ .epoch = @intCast(i), .sequence = @intCast(i), .origin_node = 1 };
}

test "session_offer_retry_reuse: StampTable bounded capacity evicts round-robin, forget removes, reset clears, eviction miss never authorizes reuse" {
    var table: StampTable = .{};
    for (0..StampTable.capacity) |i| table.record(testToken(i), testRevision(i), test_cohort);
    try testing.expectEqual(StampTable.capacity, table.occupiedCount());

    // Idempotent re-record of a present token updates in place, no eviction.
    table.record(testToken(3), testRevision(3), test_cohort);
    table.record(testToken(3), testRevision(3), test_cohort);
    try testing.expectEqual(StampTable.capacity, table.occupiedCount());
    try testing.expectEqual(@as(usize, 0), table.next);
    for (0..StampTable.capacity) |i| try testing.expect(table.lookup(testToken(i)) != null);

    // Overflow evicts slots 0, 1 in round-robin order.
    table.record(testToken(1000), testRevision(1000), test_cohort);
    try testing.expect(table.lookup(testToken(0)) == null);
    try testing.expect(table.lookup(testToken(1)) != null);
    table.record(testToken(1001), testRevision(1001), test_cohort);
    try testing.expect(table.lookup(testToken(1)) == null);
    try testing.expectEqual(StampTable.capacity, table.occupiedCount());

    // The evicted token now yields cohort_unstamped, never reuse.
    var candidate = cohortCandidate();
    candidate.offer_revision = testRevision(0);
    candidate.own_receipt.?.offered = candidate.offer_revision;
    candidate.stamp = table.lookup(testToken(0));
    try testing.expectEqual(Decision{ .publish_new = .cohort_unstamped }, decide(candidate));
    // A surviving token with the exact revision does reuse.
    candidate.offer_revision = testRevision(5);
    candidate.own_receipt.?.offered = candidate.offer_revision;
    candidate.stamp = table.lookup(testToken(5));
    try testing.expectEqual(Decision{ .reuse = {} }, decide(candidate));

    // forget removes and wipes; a free slot is preferred over eviction.
    table.forget(testToken(5));
    table.forget(testToken(5));
    try testing.expect(table.lookup(testToken(5)) == null);
    try testing.expectEqual(StampTable.capacity - 1, table.occupiedCount());
    try testing.expect(std.mem.allEqual(u8, &table.entries[5].token, 0));
    const cursor = table.next;
    table.record(testToken(2000), testRevision(2000), test_cohort);
    try testing.expectEqual(cursor, table.next);
    try testing.expect(table.lookup(testToken(2)) != null);
    try testing.expectEqual(testRevision(2000), table.lookup(testToken(2000)).?.revision);

    // Re-record with a newer revision overwrites the slot.
    table.record(testToken(2000), testRevision(2001), .none);
    const slot = table.lookup(testToken(2000)).?;
    try testing.expectEqual(testRevision(2001), slot.revision);
    try testing.expect(slot.stamp.eql(.none));

    table.reset();
    try testing.expectEqual(@as(usize, 0), table.occupiedCount());
    try testing.expect(table.lookup(testToken(2000)) == null);
    for (&table.entries) |*entry| try testing.expect(std.mem.allEqual(u8, &entry.token, 0));
}

test "session_offer_retry_reuse: RetryReasonStats required vs duplicate vs reused totals are distinct and saturating; renderPrometheus emits fixed unlabeled lines and returns NoSpaceLeft on a short buffer" {
    var stats: RetryReasonStats = .{};
    stats.note(.{ .publish_new = .content_changed }, false);
    stats.note(.{ .publish_new = .cohort_changed }, true);
    stats.note(.{ .publish_new = .cohort_unstamped }, true);
    stats.note(.{ .publish_new = .cohort_receipt_missing }, true);
    stats.note(.{ .publish_new = .cohort_receipt_stale }, true);
    stats.note(.reuse, false);
    stats.note(.reuse, true);
    stats.note(.reuse, true);

    const snap = stats.snapshot();
    try testing.expectEqual(@as(u64, 1), snap.count(.content_changed));
    try testing.expectEqual(@as(u64, 1), snap.count(.cohort_unstamped));
    try testing.expectEqual(@as(u64, 0), snap.count(.no_prior));
    try testing.expectEqual(@as(u64, 1), snap.reused_no_cohort);
    try testing.expectEqual(@as(u64, 2), snap.reused_cohort);
    try testing.expectEqual(@as(u64, 2), snap.classTotal(.required_rotation));
    try testing.expectEqual(@as(u64, 2), snap.classTotal(.duplicate_publication));
    try testing.expectEqual(@as(u64, 1), snap.classTotal(.unproven));

    var buf: [RetryReasonStats.max_render_len]u8 = undefined;
    const rendered = try stats.renderPrometheus(&buf);
    const expected_lines = [_][]const u8{
        "# TYPE onyx_session_offer_retry_new_required_total counter\nonyx_session_offer_retry_new_required_total 2\n",
        "# TYPE onyx_session_offer_retry_new_duplicate_total counter\nonyx_session_offer_retry_new_duplicate_total 2\n",
        "# TYPE onyx_session_offer_retry_new_unproven_total counter\nonyx_session_offer_retry_new_unproven_total 1\n",
        "\nonyx_session_offer_retry_reused_cohort_total 2\n",
        "\nonyx_session_offer_retry_new_reason_content_changed_total 1\n",
        "\nonyx_session_offer_retry_new_reason_cohort_receipt_stale_total 1\n",
        "\nonyx_session_offer_retry_new_reason_no_prior_total 0\n",
    };
    for (expected_lines) |line| try testing.expect(std.mem.indexOf(u8, rendered, line) != null);
    try testing.expect(std.mem.indexOfScalar(u8, rendered, '{') == null); // unlabeled
    try testing.expectEqual(@as(usize, 4 + reason_count), std.mem.count(u8, rendered, "# TYPE "));

    // Every value saturated still fits the advertised bound.
    var saturated: RetryReasonStats = .{};
    for (&saturated.reason_counts) |*c| c.* = .init(std.math.maxInt(u64));
    saturated.reused_cohort = .init(std.math.maxInt(u64));
    saturated.note(.{ .publish_new = .content_changed }, false);
    saturated.note(.reuse, true);
    const full = saturated.snapshot();
    try testing.expectEqual(std.math.maxInt(u64), full.count(.content_changed));
    try testing.expectEqual(std.math.maxInt(u64), full.reused_cohort);
    try testing.expectEqual(std.math.maxInt(u64), full.classTotal(.required_rotation));
    const big = try saturated.renderPrometheus(&buf);
    try testing.expect(big.len <= RetryReasonStats.max_render_len);

    var tiny: [64]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, stats.renderPrometheus(&tiny));
    try testing.expectError(error.NoSpaceLeft, saturated.renderPrometheus(buf[0 .. big.len - 1]));
}

test "session_offer_retry_reuse: CohortStamp.eql compares declared, epoch, and digest" {
    try testing.expect(test_cohort.eql(test_cohort));
    try testing.expect(!test_cohort.eql(.{ .declared = false, .epoch = 3, .roster_digest = @splat(0xaa) }));
    try testing.expect(!test_cohort.eql(.{ .declared = true, .epoch = 2, .roster_digest = @splat(0xaa) }));
    var digest: [32]u8 = @splat(0xaa);
    digest[31] = 0xab;
    try testing.expect(!test_cohort.eql(.{ .declared = true, .epoch = 3, .roster_digest = digest }));
}

test "session_offer_retry_reuse: retainIf forgets exactly the stamps the predicate rejects and wipes their tokens" {
    var table: StampTable = .{};
    var tokens: [4]Token = undefined;
    for (&tokens, 0..) |*t, i| {
        t.* = @splat(0);
        t.*[0] = @intCast(i + 1);
        table.record(t.*, .{ .epoch = 1, .sequence = i + 1, .origin_node = 7 }, .none);
    }
    const Keep = struct {
        fn even(_: void, _: Token, revision: Revision) bool {
            return revision.sequence % 2 == 0;
        }
    };
    try std.testing.expectEqual(@as(usize, 2), table.retainIf({}, Keep.even));
    try std.testing.expect(table.lookup(tokens[0]) == null);
    try std.testing.expect(table.lookup(tokens[1]) != null);
    try std.testing.expect(table.lookup(tokens[2]) == null);
    try std.testing.expect(table.lookup(tokens[3]) != null);
    var occupied: usize = 0;
    for (table.entries) |entry| {
        if (entry.occupied) {
            occupied += 1;
        } else try std.testing.expect(std.mem.allEqual(u8, &entry.token, 0));
    }
    try std.testing.expectEqual(@as(usize, 2), occupied);
    // Idempotent.
    try std.testing.expectEqual(@as(usize, 0), table.retainIf({}, Keep.even));
}
