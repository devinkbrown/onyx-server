// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TEST-ONLY deterministic OCG2 transaction/expiry conformance model.
//!
//! Allocation-free abstract state machine for the Step 6 sequence:
//! authorize configured-local live root -> prevalidate -> durable revision
//! reservation -> exact canonical signed-wire durable commit -> fresh
//! Services-style reinspection -> attachment reconciliation -> one
//! account-wide event/mesh/reply decision.
//!
//! Two durable boundaries are modeled separately:
//! 1. reserve-cut advances the revision floor to `revision_reserved`
//! 2. exact-wire-cut advances that reserved revision to `wire_committed`
//!
//! Sync at either OroStore boundary is ambiguous, not a definite failure.
//! A failed/short write is a definite failure of that cut only. Any
//! ambiguity (explicit `.ambiguity` or `.sync`) marks authority
//! unavailable, emits zero external effects, and prohibits ordinary retry
//! until an explicit recovery/reinspection. Fail closed: a reserved
//! revision is consumed even when the later wire cut fails or is
//! ambiguous, and is never reused.
//!
//! Completing `prior_cut=revision_reserved` with `explicit_recovery` and
//! `revision=same` requires `wire=identical`. A divergent completion is
//! durable equivocation: the reserved revision is consumed, authority is
//! unavailable, and no reply/session/event/mesh effects are emitted.
//!
//! Lifecycle at a durable cut is load-bearing:
//! - `login` is same-account re-authentication. It preserves configured-
//!   local live-root authorization and does not itself mint, reserve, or
//!   emit effects.
//! - `logout` or `account_switch` before reserve or before the exact-wire
//!   cut invalidates live-root authorization and yields zero external
//!   effects.
//! Competing grant/revoke on one reserved revision serialize to one
//! exact-wire winner. `interleave` chooses that reservation/wire owner
//! (`.competing_grant` vs `.competing_revoke`); the loser is then applied
//! against the winner's durable successor. Identical successor bytes are
//! stale/no-op; divergent exact-wire bytes are durable equivocation.
//! The loser emits no external effect. Reactors and interleave also change
//! attachment visitation order; they never create a second account-wide
//! decision.
//!
//! Expiry scheduling (`expire_scan`) does not mutate. Expiry
//! reconciliation (`expire_reconcile`) must traverse fresh reinspect,
//! attachment reconcile, and decide.
//!
//! This leaf is not a production caller, runtime authority, session
//! projector, or mesh/Helix/event transmitter. Runtime activation remains
//! on explicit HOLD.

const std = @import("std");
const testing = std.testing;

const many_attachments: u8 = 3;
const many_reactors: u8 = 3;

const Actor = enum(u8) {
    configured_local_live_root,
    ocg1,
    remote_claim,
    carried_state,
    ocg2_granted_account,
};

const Intent = enum(u8) {
    grant,
    narrow,
    replace,
    revoke,
    expire_scan,
    expire_reconcile,
};

const Fault = enum(u8) {
    none,
    oom,
    capacity,
    busy,
    exhaustion,
    write,
    sync,
    ambiguity,
};

const Observe = enum(u8) {
    match,
    mismatch,
    store_unavailable,
    ambiguity,
    account_switch,
    logout,
    successor_adoption,
};

const View = enum(u8) {
    absent,
    active,
    tombstone,
    expired,
    equivocated,
};

const Rel = enum(u8) {
    next,
    same,
    lower,
};

const Wire = enum(u8) {
    identical,
    divergent,
};

const Nicks = enum(u8) {
    none,
    single,
    shared,
    distinct,
};

const Cut = enum(u8) {
    none,
    revision_reserved,
    wire_committed,
    ambiguous,
};

const Lifecycle = enum(u8) {
    none,
    login,
    logout,
    account_switch,
};

const Reactors = enum(u8) {
    one,
    many,
};

const Interleave = enum(u8) {
    none,
    competing_grant,
    competing_revoke,
};

const Outcome = enum(u8) {
    unauthorized,
    precommit_rejected,
    recovery_required,
    replay,
    stale,
    equivocation,
    committed,
    reinspect_fail_closed,
    expiry_scheduled,
    expiry_reconciled,
};

const Serving = enum(u8) {
    none,
    configured_local,
    ocg2_active,
};

pub const Phase = enum(u8) {
    idle,
    authorize,
    prevalidate,
    reserve,
    commit,
    reinspect,
    reconcile,
    decide,
    terminal,
};

pub const Input = struct {
    actor: Actor = .configured_local_live_root,
    intent: Intent = .grant,
    reserve_fault: Fault = .none,
    commit_fault: Fault = .none,
    observe: Observe = .match,
    prior: View = .absent,
    revision: Rel = .next,
    wire: Wire = .identical,
    nicks: Nicks = .none,
    configured_local_binding: bool = false,
    prior_cut: Cut = .none,
    prior_unavailable: bool = false,
    explicit_recovery: bool = false,
    before_reserve: Lifecycle = .none,
    before_commit: Lifecycle = .none,
    reactors: Reactors = .one,
    interleave: Interleave = .none,
};

pub const Output = struct {
    outcome: Outcome = .unauthorized,
    cut: Cut = .none,
    committed: bool = false,
    unavailable: bool = false,
    ordinary_retry: bool = false,
    revision_consumed: bool = false,
    scheduled_reinspect: bool = false,
    cached_privilege_mutated: bool = false,
    used_ocg1_fallback: bool = false,
    used_cached_fallback: bool = false,
    used_predecessor_fallback: bool = false,
    reply: bool = false,
    session: bool = false,
    event: bool = false,
    mesh: bool = false,
    plus_o: u8 = 0,
    plus_a: u8 = 0,
    plus_j: u8 = 0,
    plus_y: u8 = 0,
    account_wide_decisions: u8 = 0,
    reactor_shards: u8 = 0,
    attachment_order: u8 = 0,
    serving: Serving = .none,
};

pub const World = struct {
    phase: Phase = .idle,
    input: Input = .{},
    output: Output = .{},
};

comptime {
    const run_info = @typeInfo(@TypeOf(run)).@"fn";
    if (run_info.param_types.len != 1)
        @compileError("run has a fixed (input) surface");
    if (run_info.param_types[0] != Input)
        @compileError("run consumes Input by value");
    if (run_info.return_type != Output)
        @compileError("run returns Output by value");

    const step_info = @typeInfo(@TypeOf(step)).@"fn";
    if (step_info.param_types.len != 1)
        @compileError("step has a fixed (world) surface");
    if (step_info.param_types[0] != World)
        @compileError("step consumes World by value");
    if (step_info.return_type != World)
        @compileError("step returns World by value");

    for (.{ run_info, step_info }) |info| {
        for (info.param_types) |param_type| {
            if (param_type == std.mem.Allocator)
                @compileError("S6-C6 transitions must stay allocation-free");
        }
    }

    rejectPointers(Input);
    rejectPointers(Output);
    rejectPointers(World);
    if (@typeInfo(Input).@"struct".decl_names.len != 0)
        @compileError("Input must not expose methods or nested public declarations");
    if (@typeInfo(Output).@"struct".decl_names.len != 0)
        @compileError("Output must not expose methods or nested public declarations");
    if (@typeInfo(World).@"struct".decl_names.len != 0)
        @compileError("World must not expose methods or nested public declarations");

    const allowed_public_decls = .{
        "Phase", "Input", "Output", "World", "step", "run",
    };
    const module_decls = @typeInfo(@This()).@"struct".decl_names;
    if (module_decls.len != allowed_public_decls.len)
        @compileError("S6-C6 public surface is an exact six-declaration allowlist");
    for (module_decls) |name| {
        var allowed = false;
        for (allowed_public_decls) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) allowed = true;
        }
        if (!allowed)
            @compileError("S6-C6 public surface rejected an undeclared public declaration");
    }

    for (.{
        "apply",               "execute",        "grant",
        "revoke",              "mint",           "transmit",
        "session",             "callback",       "executeAuthorized",
        "Visitor",             "ProjectionData", "DurableOperLookup",
        "Services",            "Store",          "reconcile",
        "issue",               "issueGrant",     "issueRevoke",
        "executeGrant",        "executeRevoke",  "LinuxServer",
        "Ocg2AuthorityIssuer", "buildAlloc",
    }) |name| {
        if (@hasDecl(@This(), name))
            @compileError("OCG2 transaction DST must not expose a runtime privilege surface");
    }
}

/// One explicit transition. External mint effects are written only in
/// `decide` after a successful exact-wire cut and matching reinspection.
/// Expiry reconciliation may reach `decide` without a new wire cut.
pub fn step(world: World) World {
    var next = world;
    switch (world.phase) {
        .idle => advanceIdle(&next),
        .authorize => advanceAuthorize(&next),
        .prevalidate => {
            next.phase = .reserve;
        },
        .reserve => advanceReserve(&next),
        .commit => advanceCommit(&next),
        .reinspect => advanceReinspect(&next),
        .reconcile => {
            next.phase = .decide;
        },
        .decide => advanceDecide(&next),
        .terminal => {},
    }
    if (next.phase == .terminal) stampServing(&next);
    return next;
}

pub fn run(input: Input) Output {
    return evaluate(settleRace(input));
}

fn evaluate(input: Input) Output {
    var world = World{
        .input = input,
        .output = .{
            .cut = input.prior_cut,
            .revision_consumed = revisionAlreadyConsumed(input.prior_cut),
            .unavailable = input.prior_unavailable,
        },
    };
    var guard: u8 = 0;
    while (world.phase != .terminal) : (guard += 1) {
        if (guard >= 16) break;
        world = step(world);
    }
    return world.output;
}

fn rejectPointers(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("S6-C6 public values must not hold pointers or slices"),
        .optional => |info| rejectPointers(info.child),
        .array => |info| rejectPointers(info.child),
        .@"struct" => |info| {
            for (info.field_types) |field_type| rejectPointers(field_type);
        },
        .@"union" => |info| {
            for (info.field_types) |field_type| rejectPointers(field_type);
        },
        else => {},
    }
}

fn isMint(intent: Intent) bool {
    return switch (intent) {
        .grant, .narrow, .replace, .revoke => true,
        .expire_scan, .expire_reconcile => false,
    };
}

fn preadmissionFault(fault: Fault) bool {
    return switch (fault) {
        .oom, .capacity, .busy, .exhaustion => true,
        else => false,
    };
}

fn definiteWriteFault(fault: Fault) bool {
    return fault == .write;
}

/// Sync is ambiguous: the process cannot tell whether the prepared put
/// became durable. Explicit store ambiguity is the same class. Fail closed.
fn ambiguousCutFault(fault: Fault) bool {
    return switch (fault) {
        .sync, .ambiguity => true,
        else => false,
    };
}

fn revisionAlreadyConsumed(cut: Cut) bool {
    return switch (cut) {
        .none => false,
        .revision_reserved, .wire_committed, .ambiguous => true,
    };
}

fn completingReservedAttempt(in: Input) bool {
    return in.explicit_recovery and in.prior_cut == .revision_reserved and in.revision == .same;
}

fn completingReserved(in: Input) bool {
    return completingReservedAttempt(in) and in.wire == .identical;
}

fn liveRootInvalidated(life: Lifecycle) bool {
    return switch (life) {
        .logout, .account_switch => true,
        .none, .login => false,
    };
}

fn interleaveBias(interleave: Interleave) u8 {
    return switch (interleave) {
        .none => 0,
        .competing_grant => 1,
        .competing_revoke => 2,
    };
}

/// Causal owner of a shared grant/revoke race. `.none` is not a race.
fn raceOwner(interleave: Interleave) ?Intent {
    return switch (interleave) {
        .none => null,
        .competing_grant => .grant,
        .competing_revoke => .revoke,
    };
}

fn raceCompetitor(owner: Intent) Intent {
    return switch (owner) {
        .grant => .revoke,
        .revoke => .grant,
        else => owner,
    };
}

/// Non-owner grant/revoke on a shared initial scenario. Reserved recovery,
/// lifecycle invalidation, expiry, and non-root actors stay on their own path.
fn isCompetingNonOwner(in: Input) bool {
    const owner = raceOwner(in.interleave) orelse return false;
    if (in.intent != .grant and in.intent != .revoke) return false;
    if (in.intent == owner) return false;
    if (in.explicit_recovery) return false;
    if (in.actor != .configured_local_live_root) return false;
    if (liveRootInvalidated(in.before_reserve) or liveRootInvalidated(in.before_commit))
        return false;
    return true;
}

fn winnerHoldsDurableCut(out: Output) bool {
    return switch (out.cut) {
        .revision_reserved, .wire_committed, .ambiguous => true,
        .none => false,
    };
}

fn viewAfterWinner(winner: Output, fallback: View) View {
    if (winner.outcome == .equivocation) return .equivocated;
    if (winner.committed) return .active;
    return fallback;
}

/// Apply the interleave-chosen owner first. If that owner holds a durable
/// reserve/wire/ambiguous cut, the loser sees that successor (same revision).
/// Clearing `interleave` after settlement keeps this a single rewrite.
fn settleRace(in: Input) Input {
    if (!isCompetingNonOwner(in)) return in;
    var winner_in = in;
    winner_in.intent = raceOwner(in.interleave).?;
    const winner = evaluate(winner_in);
    var next = in;
    next.interleave = .none;
    if (!winnerHoldsDurableCut(winner)) return next;
    next.prior_cut = winner.cut;
    next.prior_unavailable = winner.unavailable;
    next.prior = viewAfterWinner(winner, in.prior);
    next.revision = .same;
    return next;
}

const RaceResult = struct {
    owner: Intent,
    winner_in: Input,
    winner: Output,
    loser_identical: Output,
    loser_divergent: Output,
};

/// One shared initial scenario, two exact-wire loser probes. Interleave
/// picks the reservation/wire owner; both losers observe that successor.
fn contend(shared: Input) RaceResult {
    const owner = raceOwner(shared.interleave) orelse .grant;
    var winner_in = shared;
    winner_in.intent = owner;
    var identical_in = shared;
    identical_in.intent = raceCompetitor(owner);
    identical_in.wire = .identical;
    var divergent_in = identical_in;
    divergent_in.wire = .divergent;
    return .{
        .owner = owner,
        .winner_in = winner_in,
        .winner = run(winner_in),
        .loser_identical = run(identical_in),
        .loser_divergent = run(divergent_in),
    };
}

/// Reactor-major attachment visitation with a competitor start offset.
/// Distinct (shards, interleave, attachments) triples stay distinct so a
/// discarded reactors/interleave input cannot satisfy the order check.
fn orderFingerprint(in: Input) u8 {
    return reactorCount(in.reactors) *% 17 +%
        interleaveBias(in.interleave) *% 5 +%
        attachmentCount(in.nicks);
}

fn attachmentCount(nicks: Nicks) u8 {
    return switch (nicks) {
        .none => 0,
        .single => 1,
        .shared, .distinct => many_attachments,
    };
}

fn distinctNickCount(nicks: Nicks) u8 {
    return switch (nicks) {
        .none => 0,
        .single, .shared => 1,
        .distinct => many_attachments,
    };
}

fn reactorCount(reactors: Reactors) u8 {
    return switch (reactors) {
        .one => 1,
        .many => many_reactors,
    };
}

fn hasExternal(out: Output) bool {
    return out.reply or out.session or out.event or out.mesh or
        out.plus_o != 0 or out.plus_a != 0 or out.plus_j != 0 or out.plus_y != 0;
}

fn stampServing(world: *World) void {
    if (world.input.intent == .expire_scan) return;
    if (world.input.configured_local_binding)
        world.output.serving = .configured_local;
}

fn rejectPrecommit(world: *World, cut: Cut, retry: bool) void {
    world.output.outcome = .precommit_rejected;
    world.output.cut = cut;
    world.output.ordinary_retry = retry;
    world.output.committed = false;
    world.phase = .terminal;
}

fn rejectRecovery(world: *World, cut: Cut) void {
    world.output.outcome = .recovery_required;
    world.output.cut = cut;
    world.output.unavailable = true;
    world.output.ordinary_retry = false;
    world.output.revision_consumed = true;
    world.output.committed = false;
    world.phase = .terminal;
}

fn rejectIdentity(world: *World) void {
    world.output.outcome = .reinspect_fail_closed;
    world.output.unavailable = true;
    world.output.ordinary_retry = false;
    world.output.committed = false;
    world.output.used_ocg1_fallback = false;
    world.output.used_cached_fallback = false;
    world.output.used_predecessor_fallback = false;
    world.phase = .terminal;
}

fn advanceIdle(world: *World) void {
    world.input = settleRace(world.input);
    world.output.cut = world.input.prior_cut;
    if (revisionAlreadyConsumed(world.input.prior_cut))
        world.output.revision_consumed = true;
    if (world.input.prior == .equivocated or world.input.prior_unavailable)
        world.output.unavailable = true;

    if (isMint(world.input.intent) and
        !world.input.explicit_recovery and
        (world.input.prior_unavailable or world.input.prior_cut == .ambiguous))
    {
        rejectRecovery(world, if (world.input.prior_cut == .none) .ambiguous else world.input.prior_cut);
        return;
    }
    world.phase = .authorize;
}

fn advanceAuthorize(world: *World) void {
    if (world.input.intent == .expire_scan) {
        world.output.outcome = .expiry_scheduled;
        world.output.scheduled_reinspect = true;
        world.output.ordinary_retry = false;
        world.phase = .terminal;
        return;
    }
    if (world.input.intent == .expire_reconcile) {
        world.phase = .reinspect;
        return;
    }
    if (world.input.actor != .configured_local_live_root) {
        world.output.outcome = .unauthorized;
        world.phase = .terminal;
        return;
    }
    world.phase = .prevalidate;
}

fn advanceReserve(world: *World) void {
    world.input = settleRace(world.input);
    if (completingReservedAttempt(world.input)) {
        world.output.cut = .revision_reserved;
        world.output.revision_consumed = true;
        world.phase = .commit;
        return;
    }
    if (liveRootInvalidated(world.input.before_reserve)) {
        rejectIdentity(world);
        return;
    }

    if ((world.input.prior_cut == .revision_reserved or world.input.prior_cut == .ambiguous) and
        world.input.revision == .same)
    {
        world.output.outcome = .stale;
        world.output.revision_consumed = true;
        world.output.ordinary_retry = false;
        world.phase = .terminal;
        return;
    }

    if (preadmissionFault(world.input.reserve_fault)) {
        rejectPrecommit(world, world.output.cut, true);
        return;
    }
    if (definiteWriteFault(world.input.reserve_fault)) {
        rejectPrecommit(world, world.output.cut, true);
        return;
    }
    if (ambiguousCutFault(world.input.reserve_fault)) {
        rejectRecovery(world, .ambiguous);
        return;
    }
    if (world.input.revision == .lower) {
        world.output.outcome = .stale;
        world.phase = .terminal;
        return;
    }
    if (world.input.revision == .same and world.input.wire == .identical) {
        world.output.outcome = .replay;
        world.phase = .terminal;
        return;
    }
    if (world.input.prior == .equivocated and world.input.revision == .next) {
        world.output.outcome = .equivocation;
        world.output.unavailable = true;
        world.phase = .terminal;
        return;
    }

    world.output.cut = .revision_reserved;
    world.output.revision_consumed = true;
    world.output.ordinary_retry = false;
    world.phase = .commit;
}

fn advanceCommit(world: *World) void {
    if (liveRootInvalidated(world.input.before_commit)) {
        world.output.cut = .revision_reserved;
        world.output.revision_consumed = true;
        rejectIdentity(world);
        return;
    }
    if (preadmissionFault(world.input.commit_fault)) {
        rejectPrecommit(world, .revision_reserved, false);
        world.output.revision_consumed = true;
        return;
    }
    if (definiteWriteFault(world.input.commit_fault)) {
        rejectPrecommit(world, .revision_reserved, false);
        world.output.revision_consumed = true;
        return;
    }
    if (ambiguousCutFault(world.input.commit_fault)) {
        // Last known durable success is the reserve cut. The wire cut is
        // unresolved; do not claim wire_committed and do not roll the floor
        // back to none.
        rejectRecovery(world, .revision_reserved);
        return;
    }
    if (world.input.revision == .same and world.input.wire == .divergent) {
        world.output.committed = true;
        world.output.cut = .wire_committed;
        world.output.revision_consumed = true;
        world.output.outcome = .equivocation;
        world.output.unavailable = true;
        world.phase = .terminal;
        return;
    }

    world.output.committed = true;
    world.output.cut = .wire_committed;
    world.output.revision_consumed = true;
    world.phase = .reinspect;
}

fn advanceReinspect(world: *World) void {
    if (world.input.observe != .match) {
        world.output.outcome = .reinspect_fail_closed;
        world.output.unavailable = true;
        world.output.ordinary_retry = false;
        world.phase = .terminal;
        return;
    }
    world.phase = .reconcile;
}

fn advanceDecide(world: *World) void {
    const in = world.input;
    if (in.intent == .expire_reconcile) {
        world.output.outcome = .expiry_reconciled;
        if (in.configured_local_binding) {
            world.output.serving = .configured_local;
            if (in.prior == .expired) {
                world.output.account_wide_decisions = 1;
                world.output.reactor_shards = reactorCount(in.reactors);
                world.output.attachment_order = orderFingerprint(in);
            }
            world.phase = .terminal;
            return;
        }
        if (in.prior == .expired) {
            applyAccountWide(world, .none);
        }
        world.phase = .terminal;
        return;
    }

    world.output.outcome = .committed;
    if (in.configured_local_binding) {
        applyAccountWide(world, .configured_local);
        world.output.plus_o = 0;
        world.output.plus_a = 0;
        world.output.plus_j = 0;
        world.output.plus_y = 0;
        world.phase = .terminal;
        return;
    }
    applyAccountWide(world, switch (in.intent) {
        .revoke => .none,
        .grant, .narrow, .replace => .ocg2_active,
        .expire_scan, .expire_reconcile => .none,
    });
    world.phase = .terminal;
}

fn applyAccountWide(world: *World, serving: Serving) void {
    const in = world.input;
    world.output.account_wide_decisions = 1;
    world.output.reply = true;
    world.output.session = true;
    world.output.event = true;
    world.output.mesh = true;
    world.output.plus_o = attachmentCount(in.nicks);
    world.output.plus_a = attachmentCount(in.nicks);
    world.output.plus_j = attachmentCount(in.nicks);
    world.output.plus_y = distinctNickCount(in.nicks);
    world.output.serving = serving;
    world.output.reactor_shards = reactorCount(in.reactors);
    world.output.attachment_order = orderFingerprint(in);
}

fn expectedOutcome(in: Input) Outcome {
    return expectedOutcomeAfter(settleRace(in));
}

fn expectedOutcomeAfter(in: Input) Outcome {
    if (isMint(in.intent) and !in.explicit_recovery and
        (in.prior_unavailable or in.prior_cut == .ambiguous))
        return .recovery_required;
    if (in.intent == .expire_scan) return .expiry_scheduled;
    if (in.intent == .expire_reconcile) {
        if (in.observe != .match) return .reinspect_fail_closed;
        return .expiry_reconciled;
    }
    if (in.actor != .configured_local_live_root) return .unauthorized;

    if (completingReservedAttempt(in)) {
        if (liveRootInvalidated(in.before_commit)) return .reinspect_fail_closed;
        if (preadmissionFault(in.commit_fault) or definiteWriteFault(in.commit_fault))
            return .precommit_rejected;
        if (ambiguousCutFault(in.commit_fault)) return .recovery_required;
        if (in.wire == .divergent) return .equivocation;
        if (in.observe != .match) return .reinspect_fail_closed;
        return .committed;
    }

    if (liveRootInvalidated(in.before_reserve)) return .reinspect_fail_closed;
    if ((in.prior_cut == .revision_reserved or in.prior_cut == .ambiguous) and
        in.revision == .same)
        return .stale;
    if (preadmissionFault(in.reserve_fault) or definiteWriteFault(in.reserve_fault))
        return .precommit_rejected;
    if (ambiguousCutFault(in.reserve_fault)) return .recovery_required;
    if (in.revision == .lower) return .stale;
    if (in.revision == .same and in.wire == .identical) return .replay;
    if (in.prior == .equivocated and in.revision == .next) return .equivocation;

    if (liveRootInvalidated(in.before_commit)) return .reinspect_fail_closed;
    if (preadmissionFault(in.commit_fault) or definiteWriteFault(in.commit_fault))
        return .precommit_rejected;
    if (ambiguousCutFault(in.commit_fault)) return .recovery_required;
    if (in.revision == .same and in.wire == .divergent) return .equivocation;
    if (in.observe != .match) return .reinspect_fail_closed;
    return .committed;
}

fn expectedCut(in: Input) Cut {
    return expectedCutAfter(settleRace(in));
}

fn expectedCutAfter(in: Input) Cut {
    if (isMint(in.intent) and !in.explicit_recovery and
        (in.prior_unavailable or in.prior_cut == .ambiguous))
    {
        return if (in.prior_cut == .none) .ambiguous else in.prior_cut;
    }
    if (in.intent == .expire_scan or in.intent == .expire_reconcile)
        return in.prior_cut;
    if (in.actor != .configured_local_live_root) return in.prior_cut;

    if (completingReservedAttempt(in)) {
        if (liveRootInvalidated(in.before_commit) or
            preadmissionFault(in.commit_fault) or
            definiteWriteFault(in.commit_fault) or
            ambiguousCutFault(in.commit_fault))
            return .revision_reserved;
        return .wire_committed;
    }

    if (liveRootInvalidated(in.before_reserve)) return in.prior_cut;
    if ((in.prior_cut == .revision_reserved or in.prior_cut == .ambiguous) and
        in.revision == .same)
        return in.prior_cut;
    if (preadmissionFault(in.reserve_fault) or definiteWriteFault(in.reserve_fault))
        return in.prior_cut;
    if (ambiguousCutFault(in.reserve_fault)) return .ambiguous;
    if (in.revision == .lower) return in.prior_cut;
    if (in.revision == .same and in.wire == .identical) return in.prior_cut;
    if (in.prior == .equivocated and in.revision == .next) return in.prior_cut;

    if (liveRootInvalidated(in.before_commit) or
        preadmissionFault(in.commit_fault) or
        definiteWriteFault(in.commit_fault) or
        ambiguousCutFault(in.commit_fault))
        return .revision_reserved;
    return .wire_committed;
}

fn checkProperties(in: Input, out: Output) !void {
    const settled = settleRace(in);
    try testing.expectEqual(expectedOutcome(in), out.outcome);
    try testing.expectEqual(expectedCut(in), out.cut);
    try testing.expect(!out.used_ocg1_fallback);
    try testing.expect(!out.used_cached_fallback);
    try testing.expect(!out.used_predecessor_fallback);
    try testing.expect(!out.cached_privilege_mutated);
    try testing.expect(out.account_wide_decisions <= 1);
    try testing.expect(out.plus_y <= distinctNickCount(in.nicks));
    try testing.expect(out.plus_o <= attachmentCount(in.nicks));
    try testing.expect(out.plus_a == out.plus_o);
    try testing.expect(out.plus_j == out.plus_o);
    if (out.account_wide_decisions == 1) {
        try testing.expectEqual(reactorCount(settled.reactors), out.reactor_shards);
        try testing.expectEqual(orderFingerprint(settled), out.attachment_order);
    } else {
        try testing.expectEqual(@as(u8, 0), out.reactor_shards);
        try testing.expectEqual(@as(u8, 0), out.attachment_order);
    }
    if (in.configured_local_binding and in.intent != .expire_scan)
        try testing.expectEqual(Serving.configured_local, out.serving);

    const external = hasExternal(out);
    if (external) {
        try testing.expect(out.outcome == .committed or out.outcome == .expiry_reconciled);
        try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
        if (out.outcome == .committed) try testing.expect(out.committed);
    }
    if (out.plus_y != 0) {
        try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
    }

    if (out.cut == .ambiguous or out.outcome == .recovery_required) {
        try testing.expect(out.unavailable);
        try testing.expect(!out.ordinary_retry);
        try testing.expect(!external);
        try testing.expect(!out.committed);
    }
    if (out.cut == .revision_reserved) {
        try testing.expect(out.revision_consumed);
        try testing.expect(!out.committed);
    }
    if (out.cut == .wire_committed) {
        try testing.expect(out.revision_consumed);
        if (settled.prior_cut != .wire_committed)
            try testing.expect(out.committed);
    }
    if (out.committed) try testing.expectEqual(Cut.wire_committed, out.cut);

    if (in.intent == .expire_scan) {
        try testing.expect(out.scheduled_reinspect);
        try testing.expect(!out.committed);
        try testing.expect(!external);
        try testing.expectEqual(in.prior_cut, out.cut);
        return;
    }
    if (in.intent == .expire_reconcile) {
        if (out.outcome == .reinspect_fail_closed) {
            try testing.expect(out.unavailable);
            try testing.expect(!external);
            try testing.expect(!out.committed);
            return;
        }
        try testing.expectEqual(Outcome.expiry_reconciled, out.outcome);
        try testing.expect(!out.committed);
        try testing.expect(!out.scheduled_reinspect);
        if (in.prior == .expired and !in.configured_local_binding) {
            try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
            try testing.expect(external);
        } else {
            try testing.expect(!external or in.configured_local_binding);
        }
        return;
    }
    if (in.actor != .configured_local_live_root) {
        try testing.expect(!out.committed);
        try testing.expect(!external);
        try testing.expect(!out.scheduled_reinspect);
        return;
    }
    if (out.outcome == .precommit_rejected or
        out.outcome == .recovery_required or
        out.outcome == .replay or
        out.outcome == .stale)
    {
        try testing.expect(!out.committed);
        try testing.expect(!external);
        if (out.outcome == .precommit_rejected and out.cut == .none)
            try testing.expect(out.ordinary_retry);
        if (out.outcome == .precommit_rejected and out.cut == .revision_reserved)
            try testing.expect(!out.ordinary_retry);
        return;
    }
    if (out.outcome == .equivocation) {
        try testing.expect(out.unavailable);
        try testing.expect(!external);
        if (settled.revision == .same and settled.wire == .divergent and
            !ambiguousCutFault(settled.reserve_fault) and !ambiguousCutFault(settled.commit_fault) and
            !preadmissionFault(settled.reserve_fault) and !preadmissionFault(settled.commit_fault) and
            !definiteWriteFault(settled.reserve_fault) and !definiteWriteFault(settled.commit_fault) and
            !liveRootInvalidated(settled.before_commit) and
            (completingReservedAttempt(settled) or !liveRootInvalidated(settled.before_reserve)))
        {
            try testing.expect(out.committed);
            try testing.expectEqual(Cut.wire_committed, out.cut);
        } else try testing.expect(!out.committed);
        return;
    }
    if (out.outcome == .reinspect_fail_closed) {
        try testing.expect(out.unavailable);
        try testing.expect(!external);
        if (liveRootInvalidated(settled.before_reserve) and !completingReservedAttempt(settled)) {
            try testing.expect(!out.committed);
        } else if (liveRootInvalidated(settled.before_commit)) {
            try testing.expect(!out.committed);
            try testing.expectEqual(Cut.revision_reserved, out.cut);
        } else {
            try testing.expect(out.committed);
            try testing.expectEqual(Cut.wire_committed, out.cut);
        }
        return;
    }

    try testing.expectEqual(Outcome.committed, out.outcome);
    try testing.expect(out.committed);
    try testing.expectEqual(Cut.wire_committed, out.cut);
    try testing.expect(out.reply);
    try testing.expect(out.session);
    try testing.expect(out.event);
    try testing.expect(out.mesh);
    try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
    if (settled.configured_local_binding) {
        try testing.expectEqual(Serving.configured_local, out.serving);
        try testing.expectEqual(@as(u8, 0), out.plus_o);
        try testing.expectEqual(@as(u8, 0), out.plus_y);
    } else {
        try testing.expectEqual(attachmentCount(settled.nicks), out.plus_o);
        try testing.expectEqual(distinctNickCount(settled.nicks), out.plus_y);
        try testing.expectEqual(reactorCount(settled.reactors), out.reactor_shards);
        try testing.expectEqual(orderFingerprint(settled), out.attachment_order);
        try testing.expectEqual(
            if (settled.intent == .revoke) Serving.none else Serving.ocg2_active,
            out.serving,
        );
    }
}

fn walk(in: Input) !Output {
    var world = World{
        .input = in,
        .output = .{
            .cut = in.prior_cut,
            .revision_consumed = revisionAlreadyConsumed(in.prior_cut),
            .unavailable = in.prior_unavailable,
        },
    };
    var guard: u8 = 0;
    while (world.phase != .terminal) : (guard += 1) {
        try testing.expect(guard < 16);
        if (world.phase != .commit and
            world.phase != .reinspect and
            world.phase != .reconcile and
            world.phase != .decide and
            world.phase != .terminal)
        {
            try testing.expect(!world.output.committed);
            try testing.expect(!hasExternal(world.output));
        }
        if (world.phase == .commit) {
            try testing.expect(!world.output.committed);
            try testing.expect(!hasExternal(world.output));
            if (completingReservedAttempt(in) or world.output.cut == .revision_reserved)
                try testing.expectEqual(Cut.revision_reserved, world.output.cut);
        }
        if (hasExternal(world.output)) {
            try testing.expectEqual(Phase.terminal, world.phase);
            try testing.expect(world.output.committed or world.output.outcome == .expiry_reconciled);
        }
        world = step(world);
    }
    return world.output;
}

const exhaustive_fault_pairs: usize =
    @typeInfo(Fault).@"enum".field_names.len + @typeInfo(Fault).@"enum".field_names.len - 1;

const exhaustive_count: usize =
    @typeInfo(Actor).@"enum".field_names.len *
    @typeInfo(Intent).@"enum".field_names.len *
    exhaustive_fault_pairs *
    @typeInfo(Observe).@"enum".field_names.len *
    @typeInfo(View).@"enum".field_names.len *
    @typeInfo(Rel).@"enum".field_names.len *
    @typeInfo(Wire).@"enum".field_names.len *
    @typeInfo(Nicks).@"enum".field_names.len *
    2;

const covering_mint_intents = [_]Intent{ .grant, .revoke };
const covering_lifecycle_count: usize = @typeInfo(Lifecycle).@"enum".field_names.len;

/// Full cartesian of the named concurrency/recovery dimensions. That is
/// stronger than pairwise: every pair (and every higher tuple) of
/// before_reserve, before_commit, reactors, interleave, prior_cut,
/// explicit_recovery, revision, wire, and mint intent in {grant,revoke}
/// appears. Count = 4*4*2*3*4*2*3*2*2 = 9216.
const covering_count: usize =
    covering_lifecycle_count *
    covering_lifecycle_count *
    @typeInfo(Reactors).@"enum".field_names.len *
    @typeInfo(Interleave).@"enum".field_names.len *
    @typeInfo(Cut).@"enum".field_names.len *
    2 *
    @typeInfo(Rel).@"enum".field_names.len *
    @typeInfo(Wire).@"enum".field_names.len *
    covering_mint_intents.len;

const reserved_recovery_mint_intents = [_]Intent{ .grant, .narrow, .replace, .revoke };
const reserved_recovery_count: usize =
    reserved_recovery_mint_intents.len *
    @typeInfo(Wire).@"enum".field_names.len *
    @typeInfo(Nicks).@"enum".field_names.len *
    2 *
    @typeInfo(Interleave).@"enum".field_names.len *
    @typeInfo(Reactors).@"enum".field_names.len *
    covering_lifecycle_count;

fn forEachInput(visitor: anytype) !usize {
    var count: usize = 0;
    for (std.meta.tags(Actor)) |actor| {
        for (std.meta.tags(Intent)) |intent| {
            for (std.meta.tags(Fault)) |reserve_fault| {
                for (std.meta.tags(Fault)) |commit_fault| {
                    if (reserve_fault != .none and commit_fault != .none) continue;
                    for (std.meta.tags(Observe)) |observe| {
                        for (std.meta.tags(View)) |prior| {
                            for (std.meta.tags(Rel)) |revision| {
                                for (std.meta.tags(Wire)) |wire| {
                                    for (std.meta.tags(Nicks)) |nicks| {
                                        for ([_]bool{ false, true }) |binding| {
                                            try visitor(Input{
                                                .actor = actor,
                                                .intent = intent,
                                                .reserve_fault = reserve_fault,
                                                .commit_fault = commit_fault,
                                                .observe = observe,
                                                .prior = prior,
                                                .revision = revision,
                                                .wire = wire,
                                                .nicks = nicks,
                                                .configured_local_binding = binding,
                                            });
                                            count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return count;
}

fn forEachCovering(visitor: anytype) !usize {
    var count: usize = 0;
    for (covering_mint_intents) |intent| {
        for (std.meta.tags(Lifecycle)) |before_reserve| {
            for (std.meta.tags(Lifecycle)) |before_commit| {
                for (std.meta.tags(Reactors)) |reactors| {
                    for (std.meta.tags(Interleave)) |interleave| {
                        for (std.meta.tags(Cut)) |prior_cut| {
                            for ([_]bool{ false, true }) |explicit_recovery| {
                                for (std.meta.tags(Rel)) |revision| {
                                    for (std.meta.tags(Wire)) |wire| {
                                        try visitor(Input{
                                            .intent = intent,
                                            .nicks = .distinct,
                                            .prior_cut = prior_cut,
                                            .prior_unavailable = prior_cut == .ambiguous,
                                            .explicit_recovery = explicit_recovery,
                                            .revision = revision,
                                            .wire = wire,
                                            .before_reserve = before_reserve,
                                            .before_commit = before_commit,
                                            .reactors = reactors,
                                            .interleave = interleave,
                                        });
                                        count += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return count;
}

const covering_dim_count: usize = 9;
const covering_dim_levels = [_]u8{ 4, 4, 2, 3, 4, 2, 3, 2, 2 };

fn coveringDim(in: Input, dim: u8) u8 {
    return switch (dim) {
        0 => @intFromEnum(in.before_reserve),
        1 => @intFromEnum(in.before_commit),
        2 => @intFromEnum(in.reactors),
        3 => @intFromEnum(in.interleave),
        4 => @intFromEnum(in.prior_cut),
        5 => if (in.explicit_recovery) 1 else 0,
        6 => @intFromEnum(in.revision),
        7 => @intFromEnum(in.wire),
        8 => if (in.intent == .grant) 0 else 1,
        else => unreachable,
    };
}

fn visitCoveringPairwise(in: Input, seen: *[covering_dim_count][covering_dim_count][4][4]bool) void {
    var i: u8 = 0;
    while (i < covering_dim_count) : (i += 1) {
        var j: u8 = i + 1;
        while (j < covering_dim_count) : (j += 1) {
            seen[i][j][coveringDim(in, i)][coveringDim(in, j)] = true;
        }
    }
}

fn visitExhaustive(in: Input) !void {
    const walked = try walk(in);
    const out = run(in);
    try testing.expectEqual(walked.outcome, out.outcome);
    try testing.expectEqual(walked.committed, out.committed);
    try testing.expectEqual(walked.unavailable, out.unavailable);
    try testing.expectEqual(walked.scheduled_reinspect, out.scheduled_reinspect);
    try testing.expectEqual(walked.serving, out.serving);
    try testing.expectEqual(walked.cut, out.cut);
    try testing.expectEqual(walked.ordinary_retry, out.ordinary_retry);
    try testing.expectEqual(walked.revision_consumed, out.revision_consumed);
    try testing.expectEqual(walked.plus_o, out.plus_o);
    try testing.expectEqual(walked.plus_y, out.plus_y);
    try testing.expectEqual(walked.reactor_shards, out.reactor_shards);
    try testing.expectEqual(walked.attachment_order, out.attachment_order);
    try checkProperties(in, out);
}

test "S6C6 only live configured-local root can mint" {
    for (std.meta.tags(Actor)) |actor| {
        for ([_]Intent{ .grant, .narrow, .replace, .revoke }) |intent| {
            const out = run(.{ .actor = actor, .intent = intent });
            if (actor == .configured_local_live_root) {
                try testing.expectEqual(Outcome.committed, out.outcome);
                try testing.expect(out.committed);
                try testing.expectEqual(Cut.wire_committed, out.cut);
            } else {
                try testing.expectEqual(Outcome.unauthorized, out.outcome);
                try testing.expect(!out.committed);
                try testing.expect(!hasExternal(out));
                try testing.expectEqual(Cut.none, out.cut);
            }
        }
    }
}

test "S6C6 OCG1 remote carried and OCG2-granted cannot delegate" {
    const forbidden = [_]Actor{ .ocg1, .remote_claim, .carried_state, .ocg2_granted_account };
    for (forbidden) |actor| {
        for (std.meta.tags(View)) |prior| {
            for ([_]bool{ false, true }) |binding| {
                const out = run(.{
                    .actor = actor,
                    .intent = .grant,
                    .prior = prior,
                    .configured_local_binding = binding,
                });
                try testing.expectEqual(Outcome.unauthorized, out.outcome);
                try testing.expectEqual(
                    if (binding) Serving.configured_local else Serving.none,
                    out.serving,
                );
                try testing.expect(!out.committed);
                try testing.expect(!hasExternal(out));
                try testing.expect(!out.used_ocg1_fallback);
                try testing.expect(!out.used_cached_fallback);
                try testing.expect(!out.used_predecessor_fallback);
            }
        }
    }
}

test "S6C6 no reply session prefix event or mesh before durable commit" {
    const cases = [_]Input{
        .{ .actor = .ocg1 },
        .{ .reserve_fault = .oom },
        .{ .reserve_fault = .capacity },
        .{ .reserve_fault = .busy },
        .{ .reserve_fault = .exhaustion },
        .{ .reserve_fault = .write },
        .{ .reserve_fault = .sync },
        .{ .reserve_fault = .ambiguity },
        .{ .commit_fault = .write },
        .{ .commit_fault = .sync },
        .{ .commit_fault = .ambiguity },
        .{ .revision = .lower },
        .{ .revision = .same, .wire = .identical },
        .{ .intent = .expire_scan },
        .{ .revision = .same, .wire = .divergent },
        .{ .observe = .mismatch },
    };
    for (cases) |in| {
        var world = World{ .input = in };
        while (world.phase != .terminal) {
            if (!world.output.committed)
                try testing.expect(!hasExternal(world.output));
            world = step(world);
        }
        if (world.output.outcome != .committed)
            try testing.expect(!hasExternal(world.output));
    }
}

test "S6C6 preadmission faults yield zero external effects" {
    const faults = [_]Fault{ .oom, .capacity, .busy, .exhaustion };
    for (faults) |fault| {
        for ([_]Intent{ .grant, .narrow, .replace, .revoke }) |intent| {
            for (std.meta.tags(Nicks)) |nicks| {
                const reserve_out = run(.{
                    .intent = intent,
                    .reserve_fault = fault,
                    .nicks = nicks,
                });
                try testing.expectEqual(Outcome.precommit_rejected, reserve_out.outcome);
                try testing.expectEqual(Cut.none, reserve_out.cut);
                try testing.expect(reserve_out.ordinary_retry);
                try testing.expect(!reserve_out.committed);
                try testing.expect(!hasExternal(reserve_out));
                try testing.expectEqual(@as(u8, 0), reserve_out.account_wide_decisions);

                const commit_out = run(.{
                    .intent = intent,
                    .commit_fault = fault,
                    .nicks = nicks,
                });
                try testing.expectEqual(Outcome.precommit_rejected, commit_out.outcome);
                try testing.expectEqual(Cut.revision_reserved, commit_out.cut);
                try testing.expect(commit_out.revision_consumed);
                try testing.expect(!commit_out.ordinary_retry);
                try testing.expect(!commit_out.committed);
                try testing.expect(!hasExternal(commit_out));
            }
        }
    }
}

test "S6C6 reserve and wire cuts split definite write from ambiguous sync" {
    const reserve_write = run(.{ .reserve_fault = .write });
    try testing.expectEqual(Outcome.precommit_rejected, reserve_write.outcome);
    try testing.expectEqual(Cut.none, reserve_write.cut);
    try testing.expect(reserve_write.ordinary_retry);
    try testing.expect(!reserve_write.unavailable);
    try testing.expect(!reserve_write.committed);
    try testing.expect(!hasExternal(reserve_write));

    const reserve_sync = run(.{ .reserve_fault = .sync });
    try testing.expectEqual(Outcome.recovery_required, reserve_sync.outcome);
    try testing.expectEqual(Cut.ambiguous, reserve_sync.cut);
    try testing.expect(reserve_sync.unavailable);
    try testing.expect(reserve_sync.revision_consumed);
    try testing.expect(!reserve_sync.ordinary_retry);
    try testing.expect(!reserve_sync.committed);
    try testing.expect(!hasExternal(reserve_sync));

    const reserve_amb = run(.{ .reserve_fault = .ambiguity });
    try testing.expectEqual(Outcome.recovery_required, reserve_amb.outcome);
    try testing.expectEqual(Cut.ambiguous, reserve_amb.cut);
    try testing.expect(reserve_amb.unavailable);
    try testing.expect(!reserve_amb.ordinary_retry);

    const wire_write = run(.{ .commit_fault = .write });
    try testing.expectEqual(Outcome.precommit_rejected, wire_write.outcome);
    try testing.expectEqual(Cut.revision_reserved, wire_write.cut);
    try testing.expect(wire_write.revision_consumed);
    try testing.expect(!wire_write.ordinary_retry);
    try testing.expect(!wire_write.committed);
    try testing.expect(!hasExternal(wire_write));

    const wire_sync = run(.{ .commit_fault = .sync });
    try testing.expectEqual(Outcome.recovery_required, wire_sync.outcome);
    try testing.expectEqual(Cut.revision_reserved, wire_sync.cut);
    try testing.expect(wire_sync.unavailable);
    try testing.expect(wire_sync.revision_consumed);
    try testing.expect(!wire_sync.ordinary_retry);
    try testing.expect(!wire_sync.committed);
    try testing.expect(!hasExternal(wire_sync));

    const wire_amb = run(.{ .commit_fault = .ambiguity });
    try testing.expectEqual(Outcome.recovery_required, wire_amb.outcome);
    try testing.expectEqual(Cut.revision_reserved, wire_amb.cut);
    try testing.expect(wire_amb.unavailable);
    try testing.expect(!wire_amb.ordinary_retry);
}

test "S6C6 replay of identical revision is idempotent no-op" {
    for (std.meta.tags(View)) |prior| {
        const out = run(.{
            .prior = prior,
            .revision = .same,
            .wire = .identical,
            .nicks = .distinct,
        });
        try testing.expectEqual(Outcome.replay, out.outcome);
        try testing.expect(!out.committed);
        try testing.expect(!hasExternal(out));
        try testing.expectEqual(Serving.none, out.serving);
        try testing.expectEqual(Cut.none, out.cut);
    }
}

test "S6C6 stale lower revision is idempotent no-op" {
    for (std.meta.tags(View)) |prior| {
        const out = run(.{
            .prior = prior,
            .revision = .lower,
            .wire = .divergent,
            .nicks = .shared,
        });
        try testing.expectEqual(Outcome.stale, out.outcome);
        try testing.expect(!out.committed);
        try testing.expect(!hasExternal(out));
    }
}

test "S6C6 same-revision divergent bytes is durable equivocation" {
    for (std.meta.tags(View)) |prior| {
        const out = run(.{
            .prior = prior,
            .revision = .same,
            .wire = .divergent,
            .nicks = .distinct,
        });
        try testing.expectEqual(Outcome.equivocation, out.outcome);
        try testing.expect(out.committed);
        try testing.expectEqual(Cut.wire_committed, out.cut);
        try testing.expect(out.unavailable);
        try testing.expect(!hasExternal(out));
        try testing.expectEqual(Serving.none, out.serving);
        try testing.expect(!out.used_predecessor_fallback);
    }
}

test "S6C6 expiry schedules reinspect without mutating cached privilege" {
    for (std.meta.tags(Actor)) |actor| {
        for (std.meta.tags(View)) |prior| {
            for ([_]bool{ false, true }) |binding| {
                const out = run(.{
                    .actor = actor,
                    .intent = .expire_scan,
                    .prior = prior,
                    .configured_local_binding = binding,
                    .nicks = .distinct,
                });
                try testing.expectEqual(Outcome.expiry_scheduled, out.outcome);
                try testing.expect(out.scheduled_reinspect);
                try testing.expect(!out.cached_privilege_mutated);
                try testing.expect(!out.committed);
                try testing.expect(!hasExternal(out));
                try testing.expectEqual(Serving.none, out.serving);
                try testing.expectEqual(Cut.none, out.cut);
            }
        }
    }
}

test "S6C6 expiry reconciliation traverses reinspect reconcile decide" {
    var world = World{ .input = .{
        .intent = .expire_reconcile,
        .prior = .expired,
        .nicks = .distinct,
        .reactors = .many,
    } };
    const expected = [_]Phase{
        .idle,
        .authorize,
        .reinspect,
        .reconcile,
        .decide,
        .terminal,
    };
    for (expected, 0..) |phase, index| {
        try testing.expectEqual(phase, world.phase);
        try testing.expect(!world.output.committed);
        if (index + 1 == expected.len) break;
        try testing.expect(!hasExternal(world.output));
        world = step(world);
    }
    try testing.expectEqual(Outcome.expiry_reconciled, world.output.outcome);
    try testing.expect(!world.output.committed);
    try testing.expect(!world.output.scheduled_reinspect);
    try testing.expectEqual(@as(u8, 1), world.output.account_wide_decisions);
    try testing.expectEqual(attachmentCount(.distinct), world.output.plus_o);
    try testing.expect(hasExternal(world.output));

    const still_active = run(.{
        .intent = .expire_reconcile,
        .prior = .active,
        .nicks = .distinct,
    });
    try testing.expectEqual(Outcome.expiry_reconciled, still_active.outcome);
    try testing.expect(!still_active.committed);
    try testing.expect(!hasExternal(still_active));
    try testing.expectEqual(@as(u8, 0), still_active.account_wide_decisions);
}

test "S6C6 reinspect faults fail closed without OCG1 cached or predecessor fallback" {
    const observes = [_]Observe{
        .mismatch,
        .store_unavailable,
        .ambiguity,
        .account_switch,
        .logout,
        .successor_adoption,
    };
    for (observes) |observe| {
        for ([_]Intent{ .grant, .revoke }) |intent| {
            const out = run(.{
                .intent = intent,
                .observe = observe,
                .nicks = .shared,
            });
            try testing.expectEqual(Outcome.reinspect_fail_closed, out.outcome);
            try testing.expect(out.committed);
            try testing.expectEqual(Cut.wire_committed, out.cut);
            try testing.expect(out.unavailable);
            try testing.expect(!hasExternal(out));
            try testing.expect(!out.used_ocg1_fallback);
            try testing.expect(!out.used_cached_fallback);
            try testing.expect(!out.used_predecessor_fallback);
            try testing.expectEqual(Serving.none, out.serving);
        }
    }
}

test "S6C6 configured-local outranks active tombstoned expired and equivocated OCG2" {
    const priors = [_]View{ .active, .tombstone, .expired, .equivocated, .absent };
    for (priors) |prior| {
        for ([_]Intent{ .grant, .narrow, .replace, .revoke }) |intent| {
            const out = run(.{
                .intent = intent,
                .prior = prior,
                .configured_local_binding = true,
                .nicks = .distinct,
            });
            if (prior == .equivocated) {
                try testing.expectEqual(Outcome.equivocation, out.outcome);
                try testing.expect(out.unavailable);
                try testing.expect(!hasExternal(out));
                try testing.expectEqual(Serving.configured_local, out.serving);
            } else {
                try testing.expectEqual(Outcome.committed, out.outcome);
                try testing.expectEqual(Serving.configured_local, out.serving);
                try testing.expectEqual(@as(u8, 0), out.plus_o);
                try testing.expectEqual(@as(u8, 0), out.plus_a);
                try testing.expectEqual(@as(u8, 0), out.plus_j);
                try testing.expectEqual(@as(u8, 0), out.plus_y);
                try testing.expect(out.mesh);
            }
        }
    }
}

test "S6C6 zero one and many attachments share one account-wide decision" {
    const layouts = [_]Nicks{ .none, .single, .shared, .distinct };
    for (layouts) |nicks| {
        for ([_]Intent{ .grant, .revoke }) |intent| {
            const out = run(.{ .intent = intent, .nicks = nicks });
            try testing.expectEqual(Outcome.committed, out.outcome);
            try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
            try testing.expectEqual(attachmentCount(nicks), out.plus_o);
            try testing.expectEqual(attachmentCount(nicks), out.plus_a);
            try testing.expectEqual(attachmentCount(nicks), out.plus_j);
            try testing.expectEqual(distinctNickCount(nicks), out.plus_y);
        }
    }
}

test "S6C6 shared and distinct display nicks" {
    const shared = run(.{ .nicks = .shared });
    try testing.expectEqual(@as(u8, many_attachments), shared.plus_o);
    try testing.expectEqual(@as(u8, 1), shared.plus_y);
    try testing.expectEqual(@as(u8, 1), shared.account_wide_decisions);

    const distinct = run(.{ .nicks = .distinct });
    try testing.expectEqual(@as(u8, many_attachments), distinct.plus_o);
    try testing.expectEqual(@as(u8, many_attachments), distinct.plus_y);
    try testing.expectEqual(@as(u8, 1), distinct.account_wide_decisions);
}

test "S6C6 replay cannot resurrect expired tombstoned or equivocated records" {
    for ([_]View{ .expired, .tombstone, .equivocated }) |prior| {
        const out = run(.{
            .prior = prior,
            .revision = .same,
            .wire = .identical,
            .nicks = .distinct,
            .configured_local_binding = false,
        });
        try testing.expectEqual(Outcome.replay, out.outcome);
        try testing.expectEqual(Serving.none, out.serving);
        try testing.expect(!hasExternal(out));
        if (prior == .equivocated) try testing.expect(out.unavailable);
    }
}

test "S6C6 concurrent switch logout and successor adoption fail closed" {
    for ([_]Observe{ .account_switch, .logout, .successor_adoption }) |observe| {
        const out = run(.{ .observe = observe, .nicks = .distinct });
        try testing.expectEqual(Outcome.reinspect_fail_closed, out.outcome);
        try testing.expect(out.unavailable);
        try testing.expect(!hasExternal(out));
        try testing.expect(!out.used_cached_fallback);
        try testing.expect(!out.used_predecessor_fallback);
    }
}

test "S6C6 happy-path phase order is authorize through decide" {
    var world = World{ .input = .{ .nicks = .single } };
    const expected = [_]Phase{
        .idle,
        .authorize,
        .prevalidate,
        .reserve,
        .commit,
        .reinspect,
        .reconcile,
        .decide,
        .terminal,
    };
    for (expected, 0..) |phase, index| {
        try testing.expectEqual(phase, world.phase);
        if (index + 1 == expected.len) break;
        if (index < 5) {
            try testing.expect(!world.output.committed);
            try testing.expect(!hasExternal(world.output));
        }
        if (phase == .commit) {
            try testing.expectEqual(Cut.revision_reserved, world.output.cut);
            try testing.expect(world.output.revision_consumed);
        }
        world = step(world);
    }
    try testing.expectEqual(Outcome.committed, world.output.outcome);
    try testing.expect(world.output.committed);
    try testing.expectEqual(Cut.wire_committed, world.output.cut);
    try testing.expect(hasExternal(world.output));
}

test "S6C6 crash reopen reserved revision is consumed and never reused" {
    var reserved = World{ .input = .{ .nicks = .single, .commit_fault = .write } };
    while (reserved.phase != .terminal) {
        reserved = step(reserved);
    }
    try testing.expectEqual(Cut.revision_reserved, reserved.output.cut);
    try testing.expect(reserved.output.revision_consumed);
    try testing.expectEqual(Outcome.precommit_rejected, reserved.output.outcome);

    const reuse_same = run(.{
        .prior_cut = .revision_reserved,
        .revision = .same,
        .wire = .identical,
        .nicks = .single,
    });
    try testing.expectEqual(Outcome.stale, reuse_same.outcome);
    try testing.expect(reuse_same.revision_consumed);
    try testing.expectEqual(Cut.revision_reserved, reuse_same.cut);
    try testing.expect(!reuse_same.committed);
    try testing.expect(!hasExternal(reuse_same));
    try testing.expect(!reuse_same.ordinary_retry);

    const next_after_reserve = run(.{
        .prior_cut = .revision_reserved,
        .revision = .next,
        .nicks = .single,
    });
    try testing.expectEqual(Outcome.committed, next_after_reserve.outcome);
    try testing.expectEqual(Cut.wire_committed, next_after_reserve.cut);
    try testing.expect(next_after_reserve.revision_consumed);

    const complete_reserved = run(.{
        .prior_cut = .revision_reserved,
        .revision = .same,
        .wire = .identical,
        .explicit_recovery = true,
        .nicks = .single,
    });
    try testing.expectEqual(Outcome.committed, complete_reserved.outcome);
    try testing.expectEqual(Cut.wire_committed, complete_reserved.cut);
    try testing.expect(complete_reserved.committed);
    try testing.expectEqual(@as(u8, 1), complete_reserved.account_wide_decisions);
}

test "S6C6 recovery from an ambiguous reserve cut never reuses that revision" {
    const first = run(.{ .reserve_fault = .sync, .nicks = .shared });
    try testing.expectEqual(Outcome.recovery_required, first.outcome);
    try testing.expectEqual(Cut.ambiguous, first.cut);
    try testing.expect(first.unavailable);
    try testing.expect(!first.ordinary_retry);

    const ordinary = run(.{
        .prior_cut = .ambiguous,
        .prior_unavailable = true,
        .revision = .next,
        .nicks = .shared,
    });
    try testing.expectEqual(Outcome.recovery_required, ordinary.outcome);
    try testing.expectEqual(Cut.ambiguous, ordinary.cut);
    try testing.expect(ordinary.unavailable);
    try testing.expect(!ordinary.ordinary_retry);
    try testing.expect(!hasExternal(ordinary));

    const reuse_same = run(.{
        .prior_cut = .ambiguous,
        .prior_unavailable = true,
        .explicit_recovery = true,
        .revision = .same,
        .wire = .identical,
        .nicks = .shared,
    });
    try testing.expectEqual(Outcome.stale, reuse_same.outcome);
    try testing.expect(reuse_same.revision_consumed);
    try testing.expect(!reuse_same.committed);
    try testing.expect(!hasExternal(reuse_same));

    const recover_next = run(.{
        .prior_cut = .ambiguous,
        .prior_unavailable = true,
        .explicit_recovery = true,
        .revision = .next,
        .nicks = .shared,
    });
    try testing.expectEqual(Outcome.committed, recover_next.outcome);
    try testing.expectEqual(Cut.wire_committed, recover_next.cut);
    try testing.expectEqual(@as(u8, 1), recover_next.account_wide_decisions);
}

test "S6C6 ambiguous wire cut keeps revision_reserved and blocks ordinary retry" {
    const first = run(.{ .commit_fault = .sync, .nicks = .distinct });
    try testing.expectEqual(Cut.revision_reserved, first.cut);
    try testing.expect(first.unavailable);
    try testing.expectEqual(Outcome.recovery_required, first.outcome);

    const blocked = run(.{
        .prior_cut = .revision_reserved,
        .prior_unavailable = true,
        .revision = .next,
        .nicks = .distinct,
    });
    try testing.expectEqual(Outcome.recovery_required, blocked.outcome);
    try testing.expect(!hasExternal(blocked));
    try testing.expect(!blocked.ordinary_retry);

    const recovered = run(.{
        .prior_cut = .revision_reserved,
        .prior_unavailable = true,
        .explicit_recovery = true,
        .revision = .same,
        .wire = .identical,
        .nicks = .distinct,
    });
    try testing.expectEqual(Outcome.committed, recovered.outcome);
    try testing.expectEqual(Cut.wire_committed, recovered.cut);
}

test "S6C6 reserved recovery requires identical wire" {
    var count: usize = 0;
    for (reserved_recovery_mint_intents) |intent| {
        for (std.meta.tags(Wire)) |wire| {
            for (std.meta.tags(Nicks)) |nicks| {
                for ([_]bool{ false, true }) |binding| {
                    for (std.meta.tags(Interleave)) |interleave| {
                        for (std.meta.tags(Reactors)) |reactors| {
                            for (std.meta.tags(Lifecycle)) |before_commit| {
                                const in = Input{
                                    .intent = intent,
                                    .prior_cut = .revision_reserved,
                                    .explicit_recovery = true,
                                    .revision = .same,
                                    .wire = wire,
                                    .nicks = nicks,
                                    .configured_local_binding = binding,
                                    .interleave = interleave,
                                    .reactors = reactors,
                                    .before_commit = before_commit,
                                };
                                const out = run(in);
                                try checkProperties(in, out);
                                if (liveRootInvalidated(before_commit)) {
                                    try testing.expectEqual(Outcome.reinspect_fail_closed, out.outcome);
                                    try testing.expectEqual(Cut.revision_reserved, out.cut);
                                    try testing.expect(!out.committed);
                                    try testing.expect(!hasExternal(out));
                                    try testing.expect(out.unavailable);
                                    try testing.expectEqual(@as(u8, 0), out.account_wide_decisions);
                                } else if (wire == .identical) {
                                    try testing.expectEqual(Outcome.committed, out.outcome);
                                    try testing.expectEqual(Cut.wire_committed, out.cut);
                                    try testing.expect(out.committed);
                                    try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
                                } else {
                                    try testing.expectEqual(Outcome.equivocation, out.outcome);
                                    try testing.expectEqual(Cut.wire_committed, out.cut);
                                    try testing.expect(out.committed);
                                    try testing.expect(out.unavailable);
                                    try testing.expect(!hasExternal(out));
                                    try testing.expect(!out.ordinary_retry);
                                    try testing.expectEqual(@as(u8, 0), out.account_wide_decisions);
                                }
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    try testing.expectEqual(reserved_recovery_count, count);
}

test "S6C6 reserved recovery divergent wire is exhaustive fail-closed" {
    for (std.meta.tags(Intent)) |intent| {
        if (!isMint(intent)) continue;
        const out = run(.{
            .intent = intent,
            .prior_cut = .revision_reserved,
            .explicit_recovery = true,
            .revision = .same,
            .wire = .divergent,
            .nicks = .distinct,
            .reactors = .many,
            .interleave = .competing_revoke,
        });
        try testing.expectEqual(Outcome.equivocation, out.outcome);
        try testing.expect(out.unavailable);
        try testing.expect(out.committed);
        try testing.expectEqual(Cut.wire_committed, out.cut);
        try testing.expect(!hasExternal(out));
        try testing.expectEqual(@as(u8, 0), out.account_wide_decisions);
        try testing.expectEqual(@as(u8, 0), out.reactor_shards);
        try testing.expectEqual(@as(u8, 0), out.attachment_order);
    }
}

test "S6C6 login preserves live-root and logout or switch invalidates it" {
    for ([_]Lifecycle{ .none, .login }) |life| {
        const before_reserve = run(.{
            .before_reserve = life,
            .nicks = .distinct,
            .reactors = .many,
        });
        try testing.expectEqual(Outcome.committed, before_reserve.outcome);
        try testing.expectEqual(@as(u8, 1), before_reserve.account_wide_decisions);
        try testing.expectEqual(Cut.wire_committed, before_reserve.cut);
        try testing.expectEqual(reactorCount(.many), before_reserve.reactor_shards);

        const before_commit = run(.{
            .before_commit = life,
            .nicks = .distinct,
            .reactors = .many,
        });
        try testing.expectEqual(Outcome.committed, before_commit.outcome);
        try testing.expectEqual(@as(u8, 1), before_commit.account_wide_decisions);
    }

    for ([_]Lifecycle{ .logout, .account_switch }) |life| {
        const before_reserve = run(.{
            .before_reserve = life,
            .nicks = .distinct,
            .reactors = .many,
            .interleave = .competing_grant,
        });
        try testing.expectEqual(Outcome.reinspect_fail_closed, before_reserve.outcome);
        try testing.expectEqual(Cut.none, before_reserve.cut);
        try testing.expect(!before_reserve.committed);
        try testing.expect(!hasExternal(before_reserve));
        try testing.expect(before_reserve.unavailable);
        try testing.expectEqual(@as(u8, 0), before_reserve.account_wide_decisions);

        const before_commit = run(.{
            .before_commit = life,
            .nicks = .distinct,
            .reactors = .many,
        });
        try testing.expectEqual(Outcome.reinspect_fail_closed, before_commit.outcome);
        try testing.expectEqual(Cut.revision_reserved, before_commit.cut);
        try testing.expect(before_commit.revision_consumed);
        try testing.expect(!before_commit.committed);
        try testing.expect(!hasExternal(before_commit));
        try testing.expect(before_commit.unavailable);
        try testing.expectEqual(@as(u8, 0), before_commit.account_wide_decisions);
    }

    const login_then_logout = run(.{
        .before_reserve = .login,
        .before_commit = .logout,
        .nicks = .distinct,
    });
    try testing.expectEqual(Outcome.reinspect_fail_closed, login_then_logout.outcome);
    try testing.expectEqual(Cut.revision_reserved, login_then_logout.cut);
    try testing.expect(!hasExternal(login_then_logout));

    for ([_]Actor{ .ocg1, .remote_claim, .carried_state, .ocg2_granted_account }) |actor| {
        const out = run(.{
            .actor = actor,
            .before_reserve = .login,
            .before_commit = .login,
            .nicks = .distinct,
        });
        try testing.expectEqual(Outcome.unauthorized, out.outcome);
        try testing.expect(!out.committed);
        try testing.expect(!hasExternal(out));
    }
}

test "S6C6 reactors and interleave change attachment order not decision count" {
    const baseline = run(.{
        .nicks = .distinct,
        .reactors = .one,
        .interleave = .none,
    });
    const many = run(.{
        .nicks = .distinct,
        .reactors = .many,
        .interleave = .none,
    });
    const grant_race = run(.{
        .nicks = .distinct,
        .reactors = .one,
        .interleave = .competing_grant,
    });
    const revoke_race = run(.{
        .intent = .revoke,
        .nicks = .distinct,
        .reactors = .one,
        .interleave = .competing_revoke,
    });
    try testing.expectEqual(Outcome.committed, baseline.outcome);
    try testing.expectEqual(@as(u8, 1), baseline.account_wide_decisions);
    try testing.expectEqual(baseline.account_wide_decisions, many.account_wide_decisions);
    try testing.expectEqual(baseline.plus_o, many.plus_o);
    try testing.expectEqual(baseline.plus_y, many.plus_y);
    try testing.expect(baseline.attachment_order != many.attachment_order);
    try testing.expect(baseline.attachment_order != grant_race.attachment_order);
    try testing.expect(grant_race.attachment_order != revoke_race.attachment_order);
    try testing.expectEqual(reactorCount(.one), baseline.reactor_shards);
    try testing.expectEqual(reactorCount(.many), many.reactor_shards);
    try testing.expectEqual(orderFingerprint(.{
        .nicks = .distinct,
        .reactors = .many,
        .interleave = .none,
    }), many.attachment_order);
}

test "S6C6 competing grant revoke serialize to one exact-wire winner" {
    const shared = Input{
        .nicks = .distinct,
        .reactors = .many,
        .before_reserve = .login,
    };
    for ([_]Interleave{ .competing_grant, .competing_revoke }) |interleave| {
        var initial = shared;
        initial.interleave = interleave;
        const raced = contend(initial);
        try testing.expectEqual(raceOwner(interleave).?, raced.owner);
        try testing.expectEqual(raced.owner, raced.winner_in.intent);
        try testing.expectEqual(Outcome.committed, raced.winner.outcome);
        try testing.expect(raced.winner.committed);
        try testing.expectEqual(Cut.wire_committed, raced.winner.cut);
        try testing.expectEqual(@as(u8, 1), raced.winner.account_wide_decisions);
        try testing.expect(hasExternal(raced.winner));
        try testing.expect(raced.winner.event);
        try testing.expect(raced.winner.mesh);
        try testing.expectEqual(orderFingerprint(.{
            .intent = raced.owner,
            .nicks = .distinct,
            .reactors = .many,
            .interleave = interleave,
        }), raced.winner.attachment_order);
        try testing.expectEqual(
            if (raced.owner == .revoke) Serving.none else Serving.ocg2_active,
            raced.winner.serving,
        );

        try testing.expect(raced.loser_identical.outcome == .replay or
            raced.loser_identical.outcome == .stale);
        try testing.expect(!raced.loser_identical.committed);
        try testing.expect(!hasExternal(raced.loser_identical));
        try testing.expect(!raced.loser_identical.event);
        try testing.expect(!raced.loser_identical.mesh);
        try testing.expectEqual(@as(u8, 0), raced.loser_identical.account_wide_decisions);

        try testing.expectEqual(Outcome.equivocation, raced.loser_divergent.outcome);
        try testing.expect(raced.loser_divergent.unavailable);
        try testing.expect(!hasExternal(raced.loser_divergent));
        try testing.expect(!raced.loser_divergent.event);
        try testing.expect(!raced.loser_divergent.mesh);
        try testing.expectEqual(@as(u8, 0), raced.loser_divergent.account_wide_decisions);

        try testing.expectEqual(
            @as(u8, 1),
            raced.winner.account_wide_decisions + raced.loser_identical.account_wide_decisions,
        );
        try testing.expectEqual(
            @as(u8, 1),
            raced.winner.account_wide_decisions + raced.loser_divergent.account_wide_decisions,
        );
    }

    for ([_]Interleave{ .none, .competing_grant, .competing_revoke }) |interleave| {
        for ([_]Reactors{ .one, .many }) |reactors| {
            for ([_]Intent{ .grant, .revoke }) |intent| {
                const in = Input{
                    .intent = intent,
                    .nicks = .distinct,
                    .reactors = reactors,
                    .interleave = interleave,
                    .before_reserve = .login,
                    .before_commit = .login,
                };
                const out = run(in);
                const owner = raceOwner(interleave);
                const loser = owner != null and intent != owner.?;
                if (loser) {
                    try testing.expect(out.outcome == .replay or out.outcome == .stale);
                    try testing.expect(!hasExternal(out));
                    try testing.expectEqual(@as(u8, 0), out.account_wide_decisions);
                    try testing.expect(!out.event);
                } else {
                    try testing.expectEqual(Outcome.committed, out.outcome);
                    try testing.expectEqual(@as(u8, 1), out.account_wide_decisions);
                    try testing.expectEqual(attachmentCount(.distinct), out.plus_o);
                    try testing.expectEqual(distinctNickCount(.distinct), out.plus_y);
                    try testing.expectEqual(reactorCount(reactors), out.reactor_shards);
                    try testing.expectEqual(orderFingerprint(.{
                        .nicks = .distinct,
                        .reactors = reactors,
                        .interleave = interleave,
                    }), out.attachment_order);
                    try testing.expectEqual(Cut.wire_committed, out.cut);
                }
            }
        }
    }
}

test "S6C6 exhaustive transition properties" {
    const count = try forEachInput(visitExhaustive);
    try testing.expectEqual(exhaustive_count, count);
}

test "S6C6 covering array pairwise concurrency and recovery" {
    var seen: [covering_dim_count][covering_dim_count][4][4]bool = undefined;
    for (&seen) |*left| {
        for (left) |*right| {
            for (right) |*row| {
                @memset(row, false);
            }
        }
    }

    const Holder = struct {
        var pairs: *[covering_dim_count][covering_dim_count][4][4]bool = undefined;
        fn visit(in: Input) !void {
            visitCoveringPairwise(in, pairs);
            try visitExhaustive(in);
        }
    };
    Holder.pairs = &seen;

    const count = try forEachCovering(Holder.visit);
    try testing.expectEqual(covering_count, count);
    try testing.expectEqual(@as(usize, 9216), covering_count);

    var i: u8 = 0;
    while (i < covering_dim_count) : (i += 1) {
        var j: u8 = i + 1;
        while (j < covering_dim_count) : (j += 1) {
            var left: u8 = 0;
            while (left < covering_dim_levels[i]) : (left += 1) {
                var right: u8 = 0;
                while (right < covering_dim_levels[j]) : (right += 1) {
                    try testing.expect(seen[i][j][left][right]);
                }
            }
        }
    }
}

test "S6C6 public surface is sealed" {
    const allowed = .{
        "Phase", "Input", "Output", "World", "step", "run",
    };
    const names = @typeInfo(@This()).@"struct".decl_names;
    try testing.expectEqual(@as(usize, allowed.len), names.len);
    inline for (names) |name| {
        var found = false;
        inline for (allowed) |allowed_name| {
            if (std.mem.eql(u8, name, allowed_name)) found = true;
        }
        try testing.expect(found);
    }
    try testing.expectEqual(@as(usize, 0), @typeInfo(Input).@"struct".decl_names.len);
    try testing.expectEqual(@as(usize, 0), @typeInfo(Output).@"struct".decl_names.len);
    try testing.expectEqual(@as(usize, 0), @typeInfo(World).@"struct".decl_names.len);
    inline for (.{
        "apply",               "execute",        "grant",
        "revoke",              "mint",           "transmit",
        "session",             "callback",       "executeAuthorized",
        "Visitor",             "ProjectionData", "DurableOperLookup",
        "Services",            "Store",          "reconcile",
        "issue",               "issueGrant",     "issueRevoke",
        "executeGrant",        "executeRevoke",  "LinuxServer",
        "Ocg2AuthorityIssuer",
    }) |name| {
        try testing.expect(!@hasDecl(@This(), name));
    }
}

test "S6C6 step and run are allocation-free" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    _ = failing.allocator();
    const run_info = @typeInfo(@TypeOf(run)).@"fn";
    const step_info = @typeInfo(@TypeOf(step)).@"fn";
    try testing.expectEqual(@as(usize, 1), run_info.param_types.len);
    try testing.expectEqual(Input, run_info.param_types[0]);
    try testing.expectEqual(Output, run_info.return_type);
    try testing.expectEqual(@as(usize, 1), step_info.param_types.len);
    try testing.expectEqual(World, step_info.param_types[0]);
    try testing.expectEqual(World, step_info.return_type);
    inline for (run_info.param_types ++ step_info.param_types) |param_type| {
        try testing.expect(param_type != std.mem.Allocator);
    }
    const out = run(.{ .nicks = .distinct });
    try testing.expectEqual(Outcome.committed, out.outcome);
}
