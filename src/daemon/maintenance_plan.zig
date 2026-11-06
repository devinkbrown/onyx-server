// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure, allocation-free Maintenance drain / session-preserving upgrade
//! planner (roadmap M10).
//!
//! `server.zig` owns two independent maintenance actions: an operator DRAIN
//! (refuse new connections; `oper_cmd.handleDrain`) and a Helix in-place
//! UPGRADE (`handleUpgradeCommand`). Both ultimately answer the same
//! question for every physically connected attachment: does it keep its
//! live file descriptor through the maintenance action (Helix carry), does
//! it lose the fd but keep a resumable session token so the client
//! reconnects into the same session, or does it lose everything?
//!
//! This module answers that question in one place, as a pure partition over
//! a caller-supplied attachment inventory, so the UPGRADE PLAN dry-run
//! command, the real UPGRADE execution path, and any future DRAIN-plan
//! reporting all account for every attachment the same way and all refuse
//! to claim "seamless" under the same conditions.
//!
//! This module is std-only and never allocates. Callers (the daemon) supply
//! every buffer; `physical_connection_relation.Entry`/`Role` (also std-only,
//! no `server.zig` import) are reused so `reconcileSealed` can check a plan
//! against the real sealed Helix relation without any translation layer.
//!
//! Coverage against the M10 acceptance criterion ("every physical
//! attachment is accounted for; incompatibility explicitly blocks a
//! seamless-upgrade claim"):
//!   - `build` partitions every row into exactly one `Disposition`, with no
//!     row silently dropped (fail-closed on duplicate/oversized/malformed
//!     input), and `verifyAccounting` re-proves the partition is exhaustive.
//!   - `reconcileSealed` proves the *sealed* Helix relation (the actual wire
//!     the successor will adopt) contains exactly the rows this plan
//!     promised to carry, each once, with the matching role — not just that
//!     the plan *claims* so.
//!   - `summarize`'s verdict lattice makes every blocker, and an unproven or
//!     incompatible target, explicitly incompatible with a `seamless` claim;
//!     `.unproven` (the only state a dry run can honestly report before the
//!     real exec-time capability probe runs) degrades to the same drain
//!     accounting an incompatible target would get, never to an optimistic
//!     carry.
//!
//! Open beyond this leaf (reported to the integrator, not implemented here):
//!   daemon wiring of the `UPGRADE PLAN` dry-run command and a seal-time
//!   `reconcileSealed` assertion in `sealPhysicalConnectionRelation`, and a
//!   live sequential-upgrade rehearsal (release gate).

const std = @import("std");
const physical_connection_relation = @import("helix/physical_connection_relation.zig");

/// Upper bound on the number of attachments one plan can describe. Matches
/// `helix_live.max_inherited_state_fds`: the physical relation a plan is
/// reconciled against can never carry more rows than that either.
pub const max_rows: usize = 4096;

/// How Core classifies a physical attachment's role for Helix carry
/// purposes. `unregistered` is neither a plain client slot nor a proven
/// canonical mesh link (for example: an S2S socket mid-handshake, closing,
/// collision-waiting, or otherwise failing `canonicalMeshCaptureOwner`) and
/// can never be carried through `physical_connection_relation`, whose wire
/// `Role` has only `client` and `canonical_mesh`.
pub const Role = enum(u8) { client, canonical_mesh, unregistered };

/// The physical transport backing one attachment.
pub const Transport = enum(u8) { plain, tls, ws, webtransport, native_media, s2s };

/// Caller-supplied diagnostic for why a row is not `helix_carriable`. Purely
/// informational: `build` does not branch on it, so a caller that does not
/// yet know the precise reason may leave it `null` even on a non-carriable
/// row. Future richer per-attachment reporting can render it; today's
/// `renderLines` only summarizes at the `Plan` level.
pub const CarryGap = enum(u8) {
    /// `role == .unregistered`: never a `physical_connection_relation` row.
    unregistered_attachment,
    /// An S2S link present but not a proven canonical mesh capture owner.
    non_canonical_mesh_owner,
    /// Pending physical delivery without a mandatory HSSN mapping.
    unmapped_attachment_delivery,
    /// Any other caller-known reason not listed above.
    other,
};

/// One physical attachment to account for. `old_client` is the monitor id
/// (`monitorIdFromClient`) of the live connection's `ClientId` — the same
/// value `physical_connection_relation.Entry.old_client` carries.
pub const AttachmentRow = struct {
    old_client: u64,
    role: Role,
    transport: Transport,
    registered: bool,
    /// A session-token resume handle exists (`SessionStore.resumeHandleForClient`
    /// returned non-null): on drain, the client reconnects and resumes.
    resumable: bool,
    /// This row's fd, in isolation, is eligible to be adopted through
    /// `physical_connection_relation` (independent of whether the target
    /// binary or the rest of the process state actually permits a carry).
    helix_carriable: bool,
    carry_gap: ?CarryGap = null,
};

/// Mirrors `server.zig`'s `UpgradeContinuityBlocker` one-to-one (the first
/// 15 tags, in its declaration order) plus the preflight and target-probe
/// refusals that have no continuity-blocker counterpart because they stop
/// the command before any continuity inventory is even taken.
pub const Blocker = enum(u8) {
    // --- mirrors server.zig UpgradeContinuityBlocker, one-to-one ---
    session_drop_transaction,
    relay_v2_deferred,
    webpush_overflow_delivery,
    webtransport_listener,
    acme_companion,
    media_recording,
    media_rooms,
    media_plane,
    native_media,
    media_bridge,
    local_guest_issuer,
    remote_visible_identity,
    pending_remote_membership,
    pending_fabric_output,
    unmappable_attachment_delivery,
    // --- preflight / target-probe refusals with no continuity-blocker twin ---
    /// `upgradeRefusedForListenerChange`: the on-disk listener set changed.
    listener_change,
    /// The retired session-group fence policy changed; cold restart required.
    retired_fence_change,
    /// `validateProspectiveSessionReplicaAuthority` refused the target identity
    /// or cohort as unable to preserve carried session authority.
    prospective_authority,
    /// Dry-run only: the exec-time capability probe has not run yet.
    target_probe_unproven,
    /// The target binary failed the exact Helix handoff capability probe.
    target_probe_incompatible,
    /// The on-disk config could not be read to compare listeners.
    config_unreadable,
};

/// Stable human-readable text for a blocker, used in rendered NOTICE lines
/// and oper-event summaries. Mirrors the style (not the exact wording, since
/// six of these have no continuity-blocker twin) of `upgradeContinuityBlockerName`.
pub fn blockerName(b: Blocker) []const u8 {
    return switch (b) {
        .session_drop_transaction => "SESSION DROP transaction",
        .relay_v2_deferred => "deferred MESSAGE_V2 authority",
        .webpush_overflow_delivery => "accepted Webpush overflow delivery",
        .webtransport_listener => "WebTransport listener",
        .acme_companion => "ACME renewal companion",
        .media_recording => "media recording journal or pending manifest",
        .media_rooms => "media room control state",
        .media_plane => "WebRTC media transport state",
        .native_media => "native media transport state",
        .media_bridge => "cross-leg media bridge state",
        .local_guest_issuer => "local guest issuer and unpublished physical bindings",
        .remote_visible_identity => "remote visible identity and physical notification frontiers",
        .pending_remote_membership => "pending authenticated membership proposal",
        .pending_fabric_output => "accepted fabric delivery awaiting physical custody",
        .unmappable_attachment_delivery => "pending physical delivery without a mandatory HSSN mapping",
        .listener_change => "on-disk listener set changed",
        .retired_fence_change => "retired session fence policy changed",
        .prospective_authority => "target identity or cohort cannot preserve carried session authority",
        .target_probe_unproven => "target exact Helix capability probe has not run",
        .target_probe_incompatible => "target binary failed the exact Helix capability probe",
        .config_unreadable => "config file could not be read to compare listeners",
    };
}

/// Whether the prospective target binary/process can accept an exact Helix
/// handoff. `.unproven` is the only honest answer a dry run (no exec-time
/// probe performed) can give; `build` never produces `.carry_helix` for
/// anything but `.compatible`.
pub const Target = enum(u8) { unproven, compatible, incompatible };

pub fn targetName(t: Target) []const u8 {
    return switch (t) {
        .unproven => "unproven",
        .compatible => "compatible",
        .incompatible => "incompatible",
    };
}

pub const Compatibility = struct {
    target: Target,
    blockers: []const Blocker = &.{},
};

pub const CompatibilityError = error{
    /// The same blocker was listed twice; the list must be a set so the
    /// rendered reasons and `Plan.blocker_count` describe distinct causes.
    DuplicateBlocker,
    /// `target` disagrees with the target-probe blockers: `.unproven` must
    /// list exactly `target_probe_unproven`, `.incompatible` exactly
    /// `target_probe_incompatible`, and `.compatible` neither. This makes an
    /// unproven or incompatible target always appear as an explicit reason.
    TargetProbeMismatch,
};

/// Fail-closed consistency check for `compat`, run by both `build` and
/// `summarize`. Distinctness bounds `blockers.len` by the tag count.
pub fn validateCompatibility(compat: Compatibility) CompatibilityError!void {
    var seen: std.EnumSet(Blocker) = .empty;
    for (compat.blockers) |b| {
        if (seen.contains(b)) return error.DuplicateBlocker;
        seen.insert(b);
    }
    const unproven_listed = seen.contains(.target_probe_unproven);
    const incompatible_listed = seen.contains(.target_probe_incompatible);
    const consistent = switch (compat.target) {
        .unproven => unproven_listed and !incompatible_listed,
        .compatible => !unproven_listed and !incompatible_listed,
        .incompatible => incompatible_listed and !unproven_listed,
    };
    if (!consistent) return error.TargetProbeMismatch;
}

/// The one outcome `build` assigns to every attachment row.
pub const Disposition = enum(u8) {
    /// The fd is adopted through `physical_connection_relation`.
    carry_helix,
    /// No fd carry; the session token survives so the client reconnects and
    /// resumes the same session.
    drain_resume,
    /// No fd carry and no reusable session: state is lost.
    drain_drop,
};

pub const BuildError = CompatibilityError || error{
    /// `rows.len` exceeded `max_rows`.
    TooMany,
    /// `out.len` was smaller than `rows.len`.
    OutputTooSmall,
    /// Two rows shared the same `old_client`: one physical attachment counted twice.
    DuplicateOldClient,
    /// `role == .canonical_mesh` but `transport != .s2s`.
    InvalidCanonicalMeshTransport,
    /// `role == .client` but `transport == .s2s`: a server link is never a
    /// client slot.
    InvalidClientTransport,
    /// `role == .unregistered` but `helix_carriable == true`: an unregistered
    /// attachment has no legal role in `physical_connection_relation` at all.
    UnregisteredCannotCarry,
    /// `resumable` on a non-client role or on an unregistered client: a
    /// SessionStore resume handle exists only for a registered client's
    /// account session, so the row would overstate session preservation.
    InvalidResumable,
};

/// Partition `rows` into exactly one `Disposition` each, written into the
/// prefix of `out`. Validation (of `compat` and of every row) happens fully
/// before any write to `out`, so a rejected call leaves `out` untouched and
/// is safe to retry after the caller fixes its input.
///
/// Cost is O(rows²) for the duplicate check, bounded by `max_rows`.
///
/// A row carries only when the target is proven `.compatible` and the row
/// itself is `helix_carriable`; any other target state (including the
/// dry-run-honest `.unproven`) degrades every row to resume-or-drop. This is
/// independent of `compat.blockers`: a continuity blocker (for example an
/// in-flight media recording) does not change what an individual fd carry
/// would look like, it only ever prevents `summarize` from calling the
/// overall result `seamless`.
pub fn build(rows: []const AttachmentRow, compat: Compatibility, out: []Disposition) BuildError![]Disposition {
    if (rows.len > max_rows) return error.TooMany;
    if (out.len < rows.len) return error.OutputTooSmall;
    try validateCompatibility(compat);

    for (rows, 0..) |row, i| {
        try checkRow(row);
        for (rows[0..i]) |prior| if (prior.old_client == row.old_client) return error.DuplicateOldClient;
    }

    for (rows, 0..) |row, i| out[i] = dispositionFor(row, compat.target);
    return out[0..rows.len];
}

/// Per-row consistency rules shared by `build` and `reconcileSealed`.
fn checkRow(row: AttachmentRow) BuildError!void {
    if (row.role == .canonical_mesh and row.transport != .s2s) return error.InvalidCanonicalMeshTransport;
    if (row.role == .client and row.transport == .s2s) return error.InvalidClientTransport;
    if (row.role == .unregistered and row.helix_carriable) return error.UnregisteredCannotCarry;
    if (row.resumable and (row.role != .client or !row.registered)) return error.InvalidResumable;
}

/// The single disposition rule shared by `build` and `reconcileSealed`.
fn dispositionFor(row: AttachmentRow, target: Target) Disposition {
    return if (target == .compatible and row.helix_carriable)
        .carry_helix
    else if (row.resumable)
        .drain_resume
    else
        .drain_drop;
}

/// The verdict lattice `summarize` assigns to a plan.
pub const Verdict = enum(u8) {
    /// Every attachment carries; nothing is lost or even reconnects.
    seamless,
    /// Not seamless, but every lost attachment has a resumable session.
    session_preserving_drain,
    /// At least one attachment has neither a carry nor a resumable session.
    lossy_drain,
    /// A preflight/config blocker makes the rest of the accounting
    /// untrustworthy: fix the blocker before acting on this plan at all.
    blocked,
};

pub fn verdictName(v: Verdict) []const u8 {
    return switch (v) {
        .seamless => "seamless",
        .session_preserving_drain => "session_preserving_drain",
        .lossy_drain => "lossy_drain",
        .blocked => "blocked",
    };
}

/// Preflight/config blockers that make the rest of the accounting
/// untrustworthy rather than merely incomplete: these stop the real command
/// before any continuity inventory is even taken.
fn isHardBlock(b: Blocker) bool {
    return switch (b) {
        .listener_change, .retired_fence_change, .prospective_authority, .config_unreadable => true,
        else => false,
    };
}

pub const AccountingError = error{
    /// `total != carry + resume + drop`, or the counts exceed `max_rows`.
    AccountingMismatch,
    /// A non-`.compatible` target claims carried rows.
    CarryWithoutCompatibleTarget,
    /// `seamless` claimed without a compatible target, with blockers, or with
    /// any row not carried.
    SeamlessClaimInvalid,
};

pub const Plan = struct {
    total: usize,
    carry: usize,
    @"resume": usize,
    drop: usize,
    target: Target,
    /// `compat.blockers.len`; `renderLines` must list exactly this many.
    blocker_count: usize,
    verdict: Verdict,

    /// `summarize` always returns a `Plan` satisfying these, but `Plan`
    /// values can also be reconstructed elsewhere (hand-built in a test, or
    /// copied through daemon state); this re-proves the invariants
    /// independently of how the `Plan` was produced. Overflow-safe: each
    /// count is bounded by `max_rows` before summing.
    pub fn verifyAccounting(self: Plan) AccountingError!void {
        if (self.total > max_rows or self.carry > max_rows or self.@"resume" > max_rows or self.drop > max_rows)
            return error.AccountingMismatch;
        if (self.total != self.carry + self.@"resume" + self.drop) return error.AccountingMismatch;
        if (self.target != .compatible and self.carry != 0) return error.CarryWithoutCompatibleTarget;
        if (self.verdict == .seamless and
            (self.target != .compatible or self.blocker_count != 0 or self.carry != self.total))
            return error.SeamlessClaimInvalid;
    }
};

pub const SummarizeError = CompatibilityError || error{
    /// `dispositions.len` exceeded `max_rows`.
    TooMany,
    /// A `carry_helix` disposition was supplied with a non-`.compatible`
    /// target (that is, `dispositions` was not produced by `build` for this
    /// same `compat`).
    CarryWithoutCompatibleTarget,
};

/// Fold `dispositions` (as produced by `build`) and `compat` into a `Plan`.
///
/// `seamless` requires all of: `compat.target == .compatible`, `compat.blockers`
/// empty, and every row `carry_helix` (`carry == total`). An incompatible or
/// unproven target produces no `carry_helix` row at all (enforced here too,
/// not only in `build`), so those states can only ever reach
/// `session_preserving_drain`, `lossy_drain` or `blocked` (never `seamless`),
/// and `validateCompatibility` guarantees their probe blocker is listed as an
/// explicit reason. `blocked` is reserved for the preflight/config blockers
/// that make the whole accounting unreliable, independent of how the rows
/// resolved.
pub fn summarize(dispositions: []const Disposition, compat: Compatibility) SummarizeError!Plan {
    if (dispositions.len > max_rows) return error.TooMany;
    try validateCompatibility(compat);
    var carry: usize = 0;
    var drained_resume: usize = 0;
    var drop: usize = 0;
    for (dispositions) |d| switch (d) {
        .carry_helix => carry += 1,
        .drain_resume => drained_resume += 1,
        .drain_drop => drop += 1,
    };
    if (compat.target != .compatible and carry != 0) return error.CarryWithoutCompatibleTarget;
    const total = dispositions.len;
    const seamless = compat.target == .compatible and compat.blockers.len == 0 and carry == total;
    var hard_blocked = false;
    for (compat.blockers) |b| if (isHardBlock(b)) {
        hard_blocked = true;
        break;
    };
    const verdict: Verdict = if (seamless)
        .seamless
    else if (hard_blocked)
        .blocked
    else if (drop != 0)
        .lossy_drain
    else
        .session_preserving_drain;
    return .{
        .total = total,
        .carry = carry,
        .@"resume" = drained_resume,
        .drop = drop,
        .target = compat.target,
        .blocker_count = compat.blockers.len,
        .verdict = verdict,
    };
}

pub const ReconcileError = AccountingError || BuildError || error{
    /// A row's disposition is not the one `build(rows, compat)` assigns.
    InconsistentDisposition,
    /// `plan` is not `summarize(dispositions, compat)`: a count, the target,
    /// the blocker count or the verdict was not derived from these inputs.
    PlanMismatch,
    /// `rows.len != dispositions.len`, or `plan.total != rows.len`.
    LengthMismatch,
    /// `scratch.len != relation_entries.len`.
    ScratchSize,
    /// A `carry_helix` row's `old_client` is absent from `relation_entries`.
    MissingFromRelation,
    /// A `carry_helix` row's `old_client` appears more than once in `relation_entries`.
    DuplicateRelationRow,
    /// A `relation_entries` row's role does not match the attachment's role.
    RoleMismatch,
    /// `relation_entries` contains a row this plan never promised to carry.
    ExtraRelationRow,
    /// The number of relation rows actually matched did not equal `plan.carry`.
    AccountingMismatch,
};

/// Prove that the *sealed* Helix physical-connection relation contains
/// exactly the rows this plan promised to carry, each exactly once, with the
/// matching role — not merely that the plan claims so. A `seamless` verdict
/// is only trustworthy once this has passed against the relation actually
/// written at seal time.
///
/// Defence in depth: the plan and dispositions are re-derived rather than
/// trusted. Every row must pass `build`'s row rules, carry a distinct
/// `old_client`, and hold exactly the disposition `build(rows, compat)`
/// assigns; `plan` must equal `summarize(dispositions, compat)` field for
/// field. A plan copied through daemon state with swapped resume/drop
/// counts, a forged verdict, or a carry on an unregistered or uncarriable
/// row is rejected before the relation is consulted.
///
/// `scratch` is caller-owned, allocation-free working memory sized exactly
/// `relation_entries.len`; its contents on entry are ignored and it is fully
/// overwritten. Cost is O(carry × relation rows), both bounded by `max_rows`.
pub fn reconcileSealed(
    plan: Plan,
    compat: Compatibility,
    rows: []const AttachmentRow,
    dispositions: []const Disposition,
    relation_entries: []const physical_connection_relation.Entry,
    scratch: []bool,
) ReconcileError!void {
    try plan.verifyAccounting();
    if (rows.len != dispositions.len or plan.total != rows.len) return error.LengthMismatch;
    if (rows.len > max_rows) return error.TooMany;
    if (scratch.len != relation_entries.len) return error.ScratchSize;
    try validateCompatibility(compat);
    for (rows, dispositions, 0..) |row, disp, i| {
        try checkRow(row);
        for (rows[0..i]) |prior| if (prior.old_client == row.old_client) return error.DuplicateOldClient;
        if (disp != dispositionFor(row, compat.target)) return error.InconsistentDisposition;
    }
    const derived = summarize(dispositions, compat) catch |err| switch (err) {
        error.TooMany => return error.TooMany,
        error.CarryWithoutCompatibleTarget => return error.CarryWithoutCompatibleTarget,
        error.DuplicateBlocker => return error.DuplicateBlocker,
        error.TargetProbeMismatch => return error.TargetProbeMismatch,
    };
    if (!std.meta.eql(derived, plan)) return error.PlanMismatch;
    @memset(scratch, false);

    var matched: usize = 0;
    for (rows, dispositions) |row, disp| {
        if (disp != .carry_helix) continue;
        const expected_role: physical_connection_relation.Role = if (row.role == .canonical_mesh) .canonical_mesh else .client;
        var found = false;
        for (relation_entries, 0..) |entry, i| {
            if (entry.old_client != row.old_client) continue;
            if (found) return error.DuplicateRelationRow;
            found = true;
            if (entry.role != expected_role) return error.RoleMismatch;
            if (scratch[i]) return error.DuplicateRelationRow;
            scratch[i] = true;
        }
        if (!found) return error.MissingFromRelation;
        matched += 1;
    }
    if (matched != plan.carry) return error.AccountingMismatch;
    for (scratch) |seen| if (!seen) return error.ExtraRelationRow;
}

/// Maximum number of lines `renderLines` can return. Generous for the fixed
/// `Blocker` enum (21 tags today): one summary line plus continuation lines
/// for however many blocker names do not fit on it.
pub const max_rendered_lines: usize = 8;

/// Per-line length budget `renderLines` wraps at, comfortably under the
/// traditional 512-byte raw IRC line once the daemon's own
/// `:server NOTICE <target> :` prefix is added on top. Independent of
/// `buf.len`: `buf` is scratch capacity for every returned line combined,
/// this is the cap on any single one of them.
pub const max_line_len: usize = 400;

pub const RenderError = error{
    /// A line (or the first line's fixed prefix) does not fit in the
    /// remainder of `buf`.
    BufferTooSmall,
    /// More than `max_rendered_lines` lines would be needed.
    TooManyLines,
    /// `reasons.len != plan.blocker_count`: rendering would under- or
    /// over-report why the plan is not seamless.
    ReasonCountMismatch,
};

/// Bounded output of `renderLines`: up to `max_rendered_lines` slices into
/// the caller's `buf`, each free of CR/LF/NUL and safe to send as one NOTICE.
pub const Lines = struct {
    items: [max_rendered_lines][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Lines) []const []const u8 {
        return self.items[0..self.len];
    }

    fn push(self: *Lines, line: []const u8) RenderError!void {
        if (self.len == max_rendered_lines) return error.TooManyLines;
        self.items[self.len] = line;
        self.len += 1;
    }
};

fn appendStr(buf: []u8, pos: *usize, s: []const u8) RenderError!void {
    if (buf.len - pos.* < s.len) return error.BufferTooSmall;
    @memcpy(buf[pos.*..][0..s.len], s);
    pos.* += s.len;
}

fn appendUsize(buf: []u8, pos: *usize, value: usize) RenderError!void {
    var tmp: [20]u8 = undefined;
    const s = std.fmt.bufPrint(&tmp, "{d}", .{value}) catch return error.BufferTooSmall;
    try appendStr(buf, pos, s);
}

/// Render `plan` and `reasons` (typically `compat.blockers`) as bounded,
/// CR/LF/NUL-free lines suitable for an `UPGRADE PLAN` dry-run NOTICE, for
/// example:
///
///   UPGRADE PLAN: total=5 carry=3 resume=1 drop=1 target=compatible verdict=lossy_drain blockers=none
///
/// When `reasons` does not fit on the first line, continuation lines of the
/// form `UPGRADE PLAN (cont): blockers=...` carry the rest. Every reason is
/// always listed somewhere: this fails closed (`BufferTooSmall` /
/// `TooManyLines` / `ReasonCountMismatch`) rather than silently truncating
/// the blocker list, since a dropped reason would misreport why a plan is
/// not seamless.
pub fn renderLines(plan: Plan, reasons: []const Blocker, buf: []u8) RenderError!Lines {
    if (reasons.len != plan.blocker_count) return error.ReasonCountMismatch;
    var lines: Lines = .{};
    var line_start: usize = 0;
    var pos: usize = 0;

    try appendStr(buf, &pos, "UPGRADE PLAN: total=");
    try appendUsize(buf, &pos, plan.total);
    try appendStr(buf, &pos, " carry=");
    try appendUsize(buf, &pos, plan.carry);
    try appendStr(buf, &pos, " resume=");
    try appendUsize(buf, &pos, plan.@"resume");
    try appendStr(buf, &pos, " drop=");
    try appendUsize(buf, &pos, plan.drop);
    try appendStr(buf, &pos, " target=");
    try appendStr(buf, &pos, targetName(plan.target));
    try appendStr(buf, &pos, " verdict=");
    try appendStr(buf, &pos, verdictName(plan.verdict));
    try appendStr(buf, &pos, " blockers=");

    if (reasons.len == 0) {
        try appendStr(buf, &pos, "none");
    }
    // Every reason, including the first, is subject to the same "does it fit
    // on the current line" test: a header too long to hold even the first
    // blocker name still wraps onto a continuation line instead of failing.
    var wrote_reason = false;
    for (reasons) |b| {
        const name = blockerName(b);
        const sep_len: usize = if (wrote_reason) 1 else 0;
        const current_line_len = pos - line_start;
        const fits_current_line = current_line_len + sep_len + name.len <= max_line_len and
            buf.len - pos >= sep_len + name.len;
        if (fits_current_line) {
            if (wrote_reason) try appendStr(buf, &pos, ",");
            try appendStr(buf, &pos, name);
        } else {
            try lines.push(buf[line_start..pos]);
            line_start = pos;
            try appendStr(buf, &pos, "UPGRADE PLAN (cont): blockers=");
            try appendStr(buf, &pos, name);
        }
        wrote_reason = true;
    }
    try lines.push(buf[line_start..pos]);
    return lines;
}

// --- tests -------------------------------------------------------------

const testing = std.testing;

/// The only target `validateCompatibility` accepts alongside `b` alone.
fn targetForSoleBlocker(b: Blocker) Target {
    return switch (b) {
        .target_probe_unproven => .unproven,
        .target_probe_incompatible => .incompatible,
        else => .compatible,
    };
}

fn carryableRow(old_client: u64) AttachmentRow {
    return .{ .old_client = old_client, .role = .client, .transport = .tls, .registered = true, .resumable = true, .helix_carriable = true };
}

test "maintenance plan: every attachment gets exactly one disposition and total == carry + resume + drop" {
    const rows = [_]AttachmentRow{
        carryableRow(1),
        .{ .old_client = 2, .role = .client, .transport = .ws, .registered = true, .resumable = true, .helix_carriable = false, .carry_gap = .other },
        .{ .old_client = 3, .role = .client, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = false, .carry_gap = .other },
        .{ .old_client = 4, .role = .canonical_mesh, .transport = .s2s, .registered = true, .resumable = false, .helix_carriable = true },
    };
    var out: [8]Disposition = undefined;
    const dispositions = try build(&rows, .{ .target = .compatible }, &out);
    try testing.expectEqual(@as(usize, 4), dispositions.len);
    try testing.expectEqual(Disposition.carry_helix, dispositions[0]);
    try testing.expectEqual(Disposition.drain_resume, dispositions[1]);
    try testing.expectEqual(Disposition.drain_drop, dispositions[2]);
    try testing.expectEqual(Disposition.carry_helix, dispositions[3]);

    const plan = try summarize(dispositions, .{ .target = .compatible });
    try testing.expectEqual(@as(usize, 4), plan.total);
    try testing.expectEqual(@as(usize, 2), plan.carry);
    try testing.expectEqual(@as(usize, 1), plan.@"resume");
    try testing.expectEqual(@as(usize, 1), plan.drop);
    try plan.verifyAccounting();
}

test "maintenance plan: duplicate old_client rejected" {
    const rows = [_]AttachmentRow{ carryableRow(7), carryableRow(7) };
    var out: [4]Disposition = undefined;
    const sentinel: Disposition = .drain_drop;
    out = @splat(sentinel);
    try testing.expectError(error.DuplicateOldClient, build(&rows, .{ .target = .compatible }, &out));
    for (out) |d| try testing.expectEqual(sentinel, d);
}

test "maintenance plan: canonical_mesh row with non-s2s transport rejected" {
    const rows = [_]AttachmentRow{
        .{ .old_client = 1, .role = .canonical_mesh, .transport = .tls, .registered = true, .resumable = false, .helix_carriable = true },
    };
    var out: [4]Disposition = undefined;
    try testing.expectError(error.InvalidCanonicalMeshTransport, build(&rows, .{ .target = .compatible }, &out));
}

test "maintenance plan: unregistered role can never be marked carry-eligible" {
    const rows = [_]AttachmentRow{
        .{ .old_client = 1, .role = .unregistered, .transport = .s2s, .registered = false, .resumable = false, .helix_carriable = true },
    };
    var out: [4]Disposition = undefined;
    try testing.expectError(error.UnregisteredCannotCarry, build(&rows, .{ .target = .compatible }, &out));
}

test "maintenance plan: row count over the cap rejected" {
    // The count check runs before any row is inspected, so an oversized
    // `undefined` backing array is enough to prove the boundary: build()
    // never reads an element when it rejects on `rows.len` alone.
    var rows: [max_rows + 1]AttachmentRow = undefined;
    var out: [1]Disposition = undefined;
    try testing.expectError(error.TooMany, build(&rows, .{ .target = .compatible }, &out));
}

test "maintenance plan: output buffer smaller than row count rejected" {
    const rows = [_]AttachmentRow{ carryableRow(1), carryableRow(2) };
    var out: [1]Disposition = undefined;
    try testing.expectError(error.OutputTooSmall, build(&rows, .{ .target = .compatible }, &out));
}

test "maintenance plan: all carriable + compatible target + no blockers => seamless" {
    const rows = [_]AttachmentRow{ carryableRow(1), carryableRow(2), carryableRow(3) };
    var out: [8]Disposition = undefined;
    const compat = Compatibility{ .target = .compatible };
    const dispositions = try build(&rows, compat, &out);
    const plan = try summarize(dispositions, compat);
    try testing.expectEqual(Verdict.seamless, plan.verdict);
    try testing.expectEqual(@as(usize, 3), plan.carry);
    try plan.verifyAccounting();
}

test "maintenance plan: target incompatible blocks seamless and no row is carry_helix" {
    const rows = [_]AttachmentRow{ carryableRow(1), carryableRow(2) };
    var out: [8]Disposition = undefined;
    const compat = Compatibility{ .target = .incompatible, .blockers = &.{.target_probe_incompatible} };
    const dispositions = try build(&rows, compat, &out);
    for (dispositions) |d| try testing.expect(d != .carry_helix);
    const plan = try summarize(dispositions, compat);
    try testing.expect(plan.verdict != .seamless);
    try testing.expectEqual(@as(usize, 0), plan.carry);
}

test "maintenance plan: target unproven never yields seamless" {
    const rows = [_]AttachmentRow{carryableRow(1)};
    var out: [8]Disposition = undefined;
    const compat = Compatibility{ .target = .unproven, .blockers = &.{.target_probe_unproven} };
    const dispositions = try build(&rows, compat, &out);
    try testing.expectEqual(Disposition.drain_resume, dispositions[0]);
    const plan = try summarize(dispositions, compat);
    try testing.expect(plan.verdict != .seamless);
    try testing.expectEqual(@as(usize, 0), plan.carry);
}

test "maintenance plan: any single continuity blocker (each enum value, exhaustive inline for) blocks seamless with that reason listed" {
    const rows = [_]AttachmentRow{carryableRow(1)};
    var out: [8]Disposition = undefined;
    inline for (std.meta.tags(Blocker)) |b| {
        const compat = Compatibility{ .target = targetForSoleBlocker(b), .blockers = &.{b} };
        const dispositions = try build(&rows, compat, &out);
        const plan = try summarize(dispositions, compat);
        try testing.expect(plan.verdict != .seamless);

        var buf: [512]u8 = undefined;
        const lines = try renderLines(plan, compat.blockers, &buf);
        var found = false;
        for (lines.slice()) |line| {
            if (std.mem.indexOf(u8, line, blockerName(b)) != null) found = true;
        }
        try testing.expect(found);
    }
}

test "maintenance plan: preflight blocker category forces blocked verdict" {
    const preflight = [_]Blocker{ .listener_change, .retired_fence_change, .prospective_authority, .config_unreadable };
    const rows = [_]AttachmentRow{carryableRow(1)};
    var out: [8]Disposition = undefined;
    for (preflight) |b| {
        const compat = Compatibility{ .target = .compatible, .blockers = &.{b} };
        const dispositions = try build(&rows, compat, &out);
        const plan = try summarize(dispositions, compat);
        try testing.expectEqual(Verdict.blocked, plan.verdict);
    }
}

test "maintenance plan: non-carriable resumable attachment => drain_resume, verdict session_preserving_drain" {
    const rows = [_]AttachmentRow{
        .{ .old_client = 1, .role = .client, .transport = .plain, .registered = true, .resumable = true, .helix_carriable = false, .carry_gap = .other },
    };
    var out: [4]Disposition = undefined;
    const compat = Compatibility{ .target = .compatible };
    const dispositions = try build(&rows, compat, &out);
    try testing.expectEqual(Disposition.drain_resume, dispositions[0]);
    const plan = try summarize(dispositions, compat);
    try testing.expectEqual(Verdict.session_preserving_drain, plan.verdict);
}

test "maintenance plan: non-resumable uncarried attachment => drain_drop, verdict lossy_drain" {
    const rows = [_]AttachmentRow{
        .{ .old_client = 1, .role = .client, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = false, .carry_gap = .other },
    };
    var out: [4]Disposition = undefined;
    const compat = Compatibility{ .target = .compatible };
    const dispositions = try build(&rows, compat, &out);
    try testing.expectEqual(Disposition.drain_drop, dispositions[0]);
    const plan = try summarize(dispositions, compat);
    try testing.expectEqual(Verdict.lossy_drain, plan.verdict);
}

test "maintenance plan: reconcileSealed accepts exact carry set, rejects missing/extra/role-mismatched relation rows" {
    const rows = [_]AttachmentRow{
        carryableRow(1),
        .{ .old_client = 2, .role = .canonical_mesh, .transport = .s2s, .registered = true, .resumable = false, .helix_carriable = true },
        .{ .old_client = 3, .role = .client, .transport = .plain, .registered = true, .resumable = true, .helix_carriable = false, .carry_gap = .other },
    };
    var out: [4]Disposition = undefined;
    const compat = Compatibility{ .target = .compatible };
    const dispositions = try build(&rows, compat, &out);
    const plan = try summarize(dispositions, compat);
    try testing.expectEqual(@as(usize, 2), plan.carry);

    const exact = [_]physical_connection_relation.Entry{
        .{ .old_client = 1, .fd_index = 0, .role = .client },
        .{ .old_client = 2, .fd_index = 1, .role = .canonical_mesh },
    };
    var scratch: [2]bool = undefined;
    try reconcileSealed(plan, compat, &rows, dispositions, &exact, &scratch);

    // Missing: drop the canonical_mesh carry row.
    const missing = exact[0..1];
    var scratch1: [1]bool = undefined;
    try testing.expectError(error.MissingFromRelation, reconcileSealed(plan, compat, &rows, dispositions, missing, &scratch1));

    // Extra: an unrelated row the plan never promised to carry.
    const extra = [_]physical_connection_relation.Entry{
        exact[0],                                             exact[1],
        .{ .old_client = 3, .fd_index = 2, .role = .client },
    };
    var scratch2: [3]bool = undefined;
    try testing.expectError(error.ExtraRelationRow, reconcileSealed(plan, compat, &rows, dispositions, &extra, &scratch2));

    // Role mismatch: the canonical_mesh row sealed under the wrong role.
    const wrong_role = [_]physical_connection_relation.Entry{
        exact[0],
        .{ .old_client = 2, .fd_index = 1, .role = .client },
    };
    var scratch3: [2]bool = undefined;
    try testing.expectError(error.RoleMismatch, reconcileSealed(plan, compat, &rows, dispositions, &wrong_role, &scratch3));

    // Duplicate: the same carried client sealed twice.
    const duplicated = [_]physical_connection_relation.Entry{
        exact[0], exact[0], exact[1],
    };
    var scratch4: [3]bool = undefined;
    try testing.expectError(error.DuplicateRelationRow, reconcileSealed(plan, compat, &rows, dispositions, &duplicated, &scratch4));

    // Scratch size mismatch is checked before anything else.
    var scratch_wrong: [1]bool = undefined;
    try testing.expectError(error.ScratchSize, reconcileSealed(plan, compat, &rows, dispositions, &exact, &scratch_wrong));
}

test "maintenance plan: verifyAccounting rejects a tampered plan" {
    const tampered = Plan{ .total = 5, .carry = 1, .@"resume" = 1, .drop = 1, .target = .compatible, .blocker_count = 0, .verdict = .lossy_drain };
    try testing.expectError(error.AccountingMismatch, tampered.verifyAccounting());

    // Counts large enough to overflow the sum are rejected, not wrapped.
    const huge = Plan{ .total = 1, .carry = std.math.maxInt(usize), .@"resume" = 2, .drop = 0, .target = .compatible, .blocker_count = 0, .verdict = .lossy_drain };
    try testing.expectError(error.AccountingMismatch, huge.verifyAccounting());

    // A non-compatible target can never claim a carried row.
    const phantom_carry = Plan{ .total = 1, .carry = 1, .@"resume" = 0, .drop = 0, .target = .incompatible, .blocker_count = 1, .verdict = .lossy_drain };
    try testing.expectError(error.CarryWithoutCompatibleTarget, phantom_carry.verifyAccounting());

    // Forged seamless claims: unproven target, listed blockers, uncarried row.
    const forged = [_]Plan{
        .{ .total = 0, .carry = 0, .@"resume" = 0, .drop = 0, .target = .unproven, .blocker_count = 1, .verdict = .seamless },
        .{ .total = 1, .carry = 1, .@"resume" = 0, .drop = 0, .target = .compatible, .blocker_count = 1, .verdict = .seamless },
        .{ .total = 2, .carry = 1, .@"resume" = 1, .drop = 0, .target = .compatible, .blocker_count = 0, .verdict = .seamless },
    };
    for (forged) |plan| try testing.expectError(error.SeamlessClaimInvalid, plan.verifyAccounting());
}

test "maintenance plan: renderLines output bounded and free of CR/LF/NUL" {
    const reasons = [_]Blocker{ .media_recording, .webtransport_listener, .listener_change };
    const plan = Plan{ .total = 5, .carry = 3, .@"resume" = 1, .drop = 1, .target = .compatible, .blocker_count = reasons.len, .verdict = .lossy_drain };
    var buf: [4096]u8 = undefined;
    const lines = try renderLines(plan, &reasons, &buf);
    try testing.expect(lines.len >= 1);
    for (lines.slice()) |line| {
        try testing.expect(line.len <= buf.len);
        for (line) |byte| {
            try testing.expect(byte != '\r' and byte != '\n' and byte != 0);
        }
    }
    try testing.expect(std.mem.indexOf(u8, lines.slice()[0], "UPGRADE PLAN: total=5 carry=3 resume=1 drop=1 target=compatible verdict=lossy_drain blockers=") != null);

    // A buffer too small for even the fixed header fails closed rather than
    // silently truncating.
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, renderLines(plan, &reasons, &tiny));

    // A blocker list long enough to exceed one line's `max_line_len` budget
    // (every tag, not just three) wraps onto continuation lines instead of
    // either dropping a reason or exceeding the per-line bound. `buf` here
    // is ample total scratch; only the per-line budget forces the wrap.
    const all_blockers = std.meta.tags(Blocker);
    var wide: [4096]u8 = undefined;
    var all_plan = plan;
    all_plan.blocker_count = all_blockers.len;
    const wrapped = try renderLines(all_plan, all_blockers, &wide);
    try testing.expect(wrapped.len >= 2);
    for (wrapped.slice()) |line| try testing.expect(line.len <= max_line_len);
    var all_text: [4096]u8 = undefined;
    var all_len: usize = 0;
    for (wrapped.slice()) |line| {
        @memcpy(all_text[all_len..][0..line.len], line);
        all_len += line.len;
    }
    for (all_blockers) |b| try testing.expect(std.mem.indexOf(u8, all_text[0..all_len], blockerName(b)) != null);
}

test "maintenance plan: four held attachments on one session token plus one fresh attachment all accounted (shared-session gate shape)" {
    // Four physically distinct attachments share one logical session's
    // resumability (modeled here as four independent AttachmentRows, each
    // with its own old_client but the same resumable/carriable shape,
    // mirroring four held connections under one reusable session token),
    // plus one freshly connected, not-yet-resumable attachment.
    const rows = [_]AttachmentRow{
        .{ .old_client = 101, .role = .client, .transport = .tls, .registered = true, .resumable = true, .helix_carriable = true },
        .{ .old_client = 102, .role = .client, .transport = .ws, .registered = true, .resumable = true, .helix_carriable = true },
        .{ .old_client = 103, .role = .client, .transport = .plain, .registered = true, .resumable = true, .helix_carriable = true },
        .{ .old_client = 104, .role = .client, .transport = .webtransport, .registered = true, .resumable = true, .helix_carriable = true },
        .{ .old_client = 105, .role = .client, .transport = .native_media, .registered = false, .resumable = false, .helix_carriable = false, .carry_gap = .other },
    };
    var out: [8]Disposition = undefined;
    const compat = Compatibility{ .target = .compatible };
    const dispositions = try build(&rows, compat, &out);
    const plan = try summarize(dispositions, compat);
    try testing.expectEqual(@as(usize, 5), plan.total);
    try testing.expectEqual(@as(usize, 4), plan.carry);
    try testing.expectEqual(@as(usize, 0), plan.@"resume");
    try testing.expectEqual(@as(usize, 1), plan.drop);
    try plan.verifyAccounting();
    try testing.expectEqual(Verdict.lossy_drain, plan.verdict);

    var scratch: [4]bool = undefined;
    const relation = [_]physical_connection_relation.Entry{
        .{ .old_client = 101, .fd_index = 0, .role = .client },
        .{ .old_client = 102, .fd_index = 1, .role = .client },
        .{ .old_client = 103, .fd_index = 2, .role = .client },
        .{ .old_client = 104, .fd_index = 3, .role = .client },
    };
    try reconcileSealed(plan, compat, &rows, dispositions, &relation, &scratch);
}

test "maintenance plan: target state inconsistent with probe blockers or duplicate blocker rejected before any write" {
    const rows = [_]AttachmentRow{carryableRow(1)};
    const hostile = [_]Compatibility{
        // Incompatible target with no explicit reason: would hide why.
        .{ .target = .incompatible },
        // Unproven target with no explicit reason.
        .{ .target = .unproven, .blockers = &.{.media_plane} },
        // Compatible target that also claims a failed or missing probe.
        .{ .target = .compatible, .blockers = &.{.target_probe_incompatible} },
        .{ .target = .compatible, .blockers = &.{.target_probe_unproven} },
        // Both probe outcomes at once.
        .{ .target = .incompatible, .blockers = &.{ .target_probe_incompatible, .target_probe_unproven } },
    };
    for (hostile) |compat| {
        var out: [2]Disposition = @splat(.drain_drop);
        try testing.expectError(error.TargetProbeMismatch, build(&rows, compat, &out));
        for (out) |d| try testing.expectEqual(Disposition.drain_drop, d);
        const forged = [_]Disposition{.drain_resume};
        try testing.expectError(error.TargetProbeMismatch, summarize(&forged, compat));
    }

    const dup = Compatibility{ .target = .compatible, .blockers = &.{ .media_rooms, .media_rooms } };
    var out: [2]Disposition = @splat(.drain_drop);
    try testing.expectError(error.DuplicateBlocker, build(&rows, dup, &out));
    for (out) |d| try testing.expectEqual(Disposition.drain_drop, d);
    try testing.expectError(error.DuplicateBlocker, summarize(&.{}, dup));

    // Retry after fixing the input succeeds on the same untouched buffer.
    const fixed = try build(&rows, .{ .target = .compatible, .blockers = &.{.media_rooms} }, &out);
    try testing.expectEqual(Disposition.carry_helix, fixed[0]);
}

test "maintenance plan: rows overstating transport or session resumability rejected" {
    const Case = struct { row: AttachmentRow, err: BuildError };
    const cases = [_]Case{
        .{ .row = .{ .old_client = 1, .role = .client, .transport = .s2s, .registered = true, .resumable = false, .helix_carriable = true }, .err = error.InvalidClientTransport },
        .{ .row = .{ .old_client = 1, .role = .client, .transport = .tls, .registered = false, .resumable = true, .helix_carriable = false }, .err = error.InvalidResumable },
        .{ .row = .{ .old_client = 1, .role = .canonical_mesh, .transport = .s2s, .registered = true, .resumable = true, .helix_carriable = true }, .err = error.InvalidResumable },
        .{ .row = .{ .old_client = 1, .role = .unregistered, .transport = .plain, .registered = true, .resumable = true, .helix_carriable = false }, .err = error.InvalidResumable },
    };
    for (cases) |case| {
        const rows = [_]AttachmentRow{ carryableRow(9), case.row };
        var out: [2]Disposition = @splat(.drain_drop);
        try testing.expectError(case.err, build(&rows, .{ .target = .compatible }, &out));
        for (out) |d| try testing.expectEqual(Disposition.drain_drop, d);
    }
}

test "maintenance plan: summarize rejects carried dispositions under a non-compatible target" {
    const forged = [_]Disposition{ .carry_helix, .drain_resume };
    try testing.expectError(error.CarryWithoutCompatibleTarget, summarize(&forged, .{ .target = .incompatible, .blockers = &.{.target_probe_incompatible} }));
    try testing.expectError(error.CarryWithoutCompatibleTarget, summarize(&forged, .{ .target = .unproven, .blockers = &.{.target_probe_unproven} }));
}

test "maintenance plan: incompatible target renders the target state and its probe reason, mesh link accounted as drop" {
    const rows = [_]AttachmentRow{
        carryableRow(1),
        .{ .old_client = 2, .role = .canonical_mesh, .transport = .s2s, .registered = true, .resumable = false, .helix_carriable = true },
        .{ .old_client = 3, .role = .unregistered, .transport = .s2s, .registered = false, .resumable = false, .helix_carriable = false, .carry_gap = .unregistered_attachment },
    };
    const compat = Compatibility{ .target = .incompatible, .blockers = &.{ .media_bridge, .target_probe_incompatible } };
    var out: [3]Disposition = undefined;
    const dispositions = try build(&rows, compat, &out);
    const plan = try summarize(dispositions, compat);
    try plan.verifyAccounting();
    try testing.expectEqual(@as(usize, 3), plan.total);
    try testing.expectEqual(@as(usize, 0), plan.carry);
    try testing.expectEqual(@as(usize, 1), plan.@"resume");
    try testing.expectEqual(@as(usize, 2), plan.drop);
    try testing.expectEqual(Verdict.lossy_drain, plan.verdict);

    var buf: [512]u8 = undefined;
    const lines = try renderLines(plan, compat.blockers, &buf);
    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings(
        "UPGRADE PLAN: total=3 carry=0 resume=1 drop=2 target=incompatible verdict=lossy_drain blockers=cross-leg media bridge state,target binary failed the exact Helix capability probe",
        lines.slice()[0],
    );

    // Rendering with fewer (or more) reasons than the plan counted fails closed.
    try testing.expectError(error.ReasonCountMismatch, renderLines(plan, compat.blockers[0..1], &buf));
    try testing.expectError(error.ReasonCountMismatch, renderLines(plan, &.{ .media_bridge, .target_probe_incompatible, .media_plane }, &buf));

    // Nothing may be sealed for carry under an incompatible target.
    var scratch0: [0]bool = .{};
    try reconcileSealed(plan, compat, &rows, dispositions, &.{}, &scratch0);
    const smuggled = [_]physical_connection_relation.Entry{.{ .old_client = 1, .fd_index = 0, .role = .client }};
    var scratch1: [1]bool = undefined;
    try testing.expectError(error.ExtraRelationRow, reconcileSealed(plan, compat, &rows, dispositions, &smuggled, &scratch1));
}

test "maintenance plan: reconcileSealed rejects a plan that does not describe these rows" {
    const rows = [_]AttachmentRow{ carryableRow(1), carryableRow(2) };
    const compat = Compatibility{ .target = .compatible };
    var out: [2]Disposition = undefined;
    const dispositions = try build(&rows, compat, &out);
    const plan = try summarize(dispositions, compat);
    const relation = [_]physical_connection_relation.Entry{
        .{ .old_client = 1, .fd_index = 0, .role = .client },
        .{ .old_client = 2, .fd_index = 1, .role = .client },
    };
    var scratch: [2]bool = undefined;
    try reconcileSealed(plan, compat, &rows, dispositions, &relation, &scratch);

    var short = plan;
    short.total = 1;
    short.carry = 1;
    try testing.expectError(error.LengthMismatch, reconcileSealed(short, compat, &rows, dispositions, &relation, &scratch));

    var tampered = plan;
    tampered.drop = 1;
    try testing.expectError(error.AccountingMismatch, reconcileSealed(tampered, compat, &rows, dispositions, &relation, &scratch));

    var downgraded = plan;
    downgraded.target = .unproven;
    try testing.expectError(error.CarryWithoutCompatibleTarget, reconcileSealed(downgraded, compat, &rows, dispositions, &relation, &scratch));

    try testing.expectError(error.LengthMismatch, reconcileSealed(plan, compat, rows[0..1], dispositions, &relation, &scratch));
}

test "maintenance plan: empty inventory is seamless only with a compatible unblocked target" {
    var out: [1]Disposition = undefined;
    const ok = try summarize(try build(&.{}, .{ .target = .compatible }, &out), .{ .target = .compatible });
    try testing.expectEqual(Verdict.seamless, ok.verdict);
    try testing.expectEqual(@as(usize, 0), ok.total);
    const unproven = Compatibility{ .target = .unproven, .blockers = &.{.target_probe_unproven} };
    const not_ok = try summarize(try build(&.{}, unproven, &out), unproven);
    try testing.expectEqual(Verdict.session_preserving_drain, not_ok.verdict);
}

test "maintenance plan: exactly max_rows distinct attachments accepted and fully accounted" {
    var rows: [max_rows]AttachmentRow = undefined;
    for (&rows, 0..) |*row, i| row.* = if (i % 2 == 0)
        carryableRow(@intCast(i + 1))
    else
        .{ .old_client = @intCast(i + 1), .role = .client, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = false };
    var out: [max_rows]Disposition = undefined;
    const unproven = Compatibility{ .target = .unproven, .blockers = &.{.target_probe_unproven} };
    const dispositions = try build(&rows, unproven, &out);
    const plan = try summarize(dispositions, unproven);
    try plan.verifyAccounting();
    try testing.expectEqual(@as(usize, max_rows), plan.total);
    try testing.expectEqual(@as(usize, 0), plan.carry);
    try testing.expectEqual(@as(usize, max_rows / 2), plan.@"resume");
    try testing.expectEqual(@as(usize, max_rows / 2), plan.drop);

    // Over the cap via summarize too.
    var many: [max_rows + 1]Disposition = @splat(.drain_drop);
    try testing.expectError(error.TooMany, summarize(&many, .{ .target = .compatible }));
}

test "maintenance plan: reconcileSealed re-derives dispositions and plan instead of trusting them" {
    const rows = [_]AttachmentRow{
        carryableRow(1),
        .{ .old_client = 2, .role = .client, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = false, .carry_gap = .other },
    };
    const compat = Compatibility{ .target = .compatible };
    var out: [2]Disposition = undefined;
    const dispositions = try build(&rows, compat, &out);
    const plan = try summarize(dispositions, compat);
    const relation = [_]physical_connection_relation.Entry{.{ .old_client = 1, .fd_index = 0, .role = .client }};
    var scratch: [1]bool = undefined;
    try reconcileSealed(plan, compat, &rows, dispositions, &relation, &scratch);

    // Reviewer counterexample: resume and drop swapped in a plan copied
    // through daemon state. Totals still add up, so verifyAccounting passes;
    // only re-derivation catches the lie that attachment 2 survives.
    var swapped = plan;
    swapped.@"resume" = 1;
    swapped.drop = 0;
    swapped.verdict = .session_preserving_drain;
    try swapped.verifyAccounting();
    try testing.expectError(error.PlanMismatch, reconcileSealed(swapped, compat, &rows, dispositions, &relation, &scratch));

    // A forged seamless verdict with blockers hidden from the plan.
    const blocked = Compatibility{ .target = .compatible, .blockers = &.{.media_recording} };
    const honest = try summarize(dispositions, blocked);
    try testing.expectEqual(@as(usize, 1), honest.blocker_count);
    var hidden = honest;
    hidden.blocker_count = 0;
    try testing.expectError(error.PlanMismatch, reconcileSealed(hidden, blocked, &rows, dispositions, &relation, &scratch));
    try reconcileSealed(honest, blocked, &rows, dispositions, &relation, &scratch);

    // A carry disposition on an uncarriable row is not what build assigns.
    const forged = [_]Disposition{ .carry_helix, .carry_helix };
    var forged_plan = plan;
    forged_plan.carry = 2;
    forged_plan.drop = 0;
    const both = [_]physical_connection_relation.Entry{
        .{ .old_client = 1, .fd_index = 0, .role = .client },
        .{ .old_client = 2, .fd_index = 1, .role = .client },
    };
    var scratch2: [2]bool = undefined;
    try testing.expectError(error.InconsistentDisposition, reconcileSealed(forged_plan, compat, &rows, &forged, &both, &scratch2));

    // An unregistered row marked carriable is refused by the shared row rules
    // (and could never be sealed under the client role).
    const smuggled_rows = [_]AttachmentRow{
        carryableRow(1),
        .{ .old_client = 2, .role = .unregistered, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = true },
    };
    try testing.expectError(error.UnregisteredCannotCarry, reconcileSealed(forged_plan, compat, &smuggled_rows, &forged, &both, &scratch2));

    // Duplicate attachments are refused even when neither carries.
    const dup_rows = [_]AttachmentRow{
        .{ .old_client = 5, .role = .client, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = false },
        .{ .old_client = 5, .role = .client, .transport = .plain, .registered = false, .resumable = false, .helix_carriable = false },
    };
    const drops = [_]Disposition{ .drain_drop, .drain_drop };
    const drop_plan = try summarize(&drops, compat);
    var scratch0: [0]bool = .{};
    try testing.expectError(error.DuplicateOldClient, reconcileSealed(drop_plan, compat, &dup_rows, &drops, &.{}, &scratch0));

    // The compat itself is validated: a target that disagrees with the plan's.
    try testing.expectError(error.TargetProbeMismatch, reconcileSealed(plan, .{ .target = .unproven }, &rows, dispositions, &relation, &scratch));
}
