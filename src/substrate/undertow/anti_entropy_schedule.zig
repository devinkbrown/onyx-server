// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! M02: adaptive bounded anti-entropy scheduling.
//!
//! Pure, clock-free leaf built on `anti_entropy.zig`'s divergence/backoff
//! primitives (`nextRepairIntervalMs`, `scheduleRepairs`, `repair_backoff_factor`).
//! It adds the pieces anti-entropy's fixed-constant scheduler does not have:
//! caller-configurable `Bounds`, a per-peer send-backlog/global-load stretch on
//! top of the quiet-peer exponential backoff, a bounded-per-round admission
//! plan, a daemon wakeup floor, and a closed-form quiet-mesh burst ceiling used
//! to PROVE the "quiet mesh idle cost is bounded" acceptance criterion.
//!
//! Every function here is pure: no allocation, no clock reads, no I/O. The
//! caller supplies `now_ms` and owns `PeerState` across rounds.
const std = @import("std");

const anti_entropy = @import("anti_entropy.zig");

/// Caller-configurable cadence bounds. `min_interval_ms`, `max_interval_ms`,
/// and `tick_ms` default to the same constants `anti_entropy.zig` uses for its
/// fixed-constant scheduler, so a caller that only needs the quiet/divergence
/// backoff gets byte-identical behavior. The remaining fields have no default:
/// a caller must make an explicit choice about per-round burst budget and
/// backlog/load stretch, matching the "explicit bounds" acceptance wording.
///
/// Callers must `validate()` once at configuration time. The pure functions
/// below never panic or loop on an unvalidated value (they clamp and floor
/// defensively) but only a validated config carries the documented guarantees.
pub const Bounds = struct {
    min_interval_ms: u64 = anti_entropy.min_repair_interval_ms,
    max_interval_ms: u64 = anti_entropy.max_repair_interval_ms,
    tick_ms: u64 = anti_entropy.min_repair_interval_ms,
    /// Cap on anti-entropy bursts admitted per `planRound` call. Bounds the
    /// client-traffic-starvation risk of a round with many due peers at once.
    max_bursts_per_round: usize,
    /// Send-backlog at/above which `nextIntervalMs` starts stretching the
    /// interval toward `max_interval_ms`.
    backlog_soft_bytes: u64,
    /// Send-backlog at/above which `planRound` defers the peer entirely
    /// (unless it is already stale; see `planRound`).
    backlog_hard_bytes: u64,
    /// Multiplier reached when backlog hits the hard limit or global load
    /// reaches 1000 permille. Values of 0 and 1 mean "no stretch".
    load_stretch_factor: u32,

    pub const Error = error{
        MinIntervalZero,
        MinExceedsMax,
        TickZero,
        TickExceedsMin,
        BurstBudgetZero,
        BacklogHardBelowSoft,
    };

    /// Production-sized defaults for every field.
    pub fn default() Bounds {
        return .{
            .max_bursts_per_round = 4,
            .backlog_soft_bytes = 256 * 1024,
            .backlog_hard_bytes = 4 * 1024 * 1024,
            .load_stretch_factor = 4,
        };
    }

    /// Reject a config that cannot produce a sane cadence. Zero `min` would
    /// collapse the backoff to a zero-wait busy loop; `min > max` makes every
    /// clamp ambiguous; zero `tick` lets the daemon wake with no floor and
    /// `tick > min` would let it sleep past the fastest divergence-driven
    /// repair; a zero burst budget would starve every peer forever; a hard
    /// backlog below the soft one inverts the stretch ramp.
    pub fn validate(self: Bounds) Error!void {
        if (self.min_interval_ms == 0) return error.MinIntervalZero;
        if (self.min_interval_ms > self.max_interval_ms) return error.MinExceedsMax;
        if (self.tick_ms == 0) return error.TickZero;
        if (self.tick_ms > self.min_interval_ms) return error.TickExceedsMin;
        if (self.max_bursts_per_round == 0) return error.BurstBudgetZero;
        if (self.backlog_hard_bytes < self.backlog_soft_bytes) return error.BacklogHardBelowSoft;
    }
};

/// Per-peer scheduling memory the caller owns across rounds. One instance per
/// physical link (not per peer name) so two links to one peer never share a
/// quiet streak.
pub const PeerState = struct {
    /// Monotonic ms of this peer's last admitted anti-entropy burst, or null
    /// before the first one.
    last_burst_ms: ?u64 = null,
    /// Consecutive rounds observed with no divergence advance. Zero means
    /// "divergence just observed" (or never observed at all), which always
    /// yields the minimum interval: fast repair for a real gap.
    quiet_streak: u32 = 0,
    /// Last-seen value of the caller's divergence counter (e.g.
    /// `S2sPeer.membership_divergence_applied`).
    divergence_mark: u64 = 0,
};

/// Fold one round's divergence observation into `state`. Any change of the
/// caller's counter since the last observed mark (including a counter that
/// restarted lower after a reconnect) means a real gap may have been filled,
/// so the quiet streak resets: unknown is treated as divergent, the fail-fast
/// direction. No change means another quiet round; the streak saturates and
/// never wraps to a false "just diverged" reading.
pub fn observeRound(state: *PeerState, divergence_counter_now: u64) void {
    if (divergence_counter_now != state.divergence_mark) {
        state.divergence_mark = divergence_counter_now;
        state.quiet_streak = 0;
        return;
    }
    state.quiet_streak +|= 1;
}

/// Fixed-point stretch scale: 1000 == x1.0.
const stretch_one: u64 = 1000;

/// A burst cannot lie in the future. A `last_burst_ms` after `now_ms` (the
/// caller's clock stepped back, or the value came from another clock scale) is
/// unknown, not "just now": clamping it to `now_ms` would re-arm the wait on
/// every call and starve the peer until the clock catches up. Treating it as
/// never-bursted makes the peer due, stale and first in line; the caller's
/// next admission overwrites `last_burst_ms` with the current `now_ms`, which
/// re-baselines it so no peer waits longer than `max_interval_ms`.
fn effectiveLast(last_burst_ms: ?u64, now_ms: u64) ?u64 {
    const last = last_burst_ms orelse return null;
    if (last > now_ms) return null;
    return last;
}

/// Interval until this peer's next repair, given `bounds` and the caller's
/// backlog/load snapshot. Pure integer math, no clock reads.
///
/// - Divergence (`quiet_streak == 0`) always yields `min_interval_ms`,
///   regardless of load. (Whether the peer is ADMITTED under hard backlog is
///   a `planRound` decision.)
/// - Otherwise the interval backs off exponentially by `quiet_streak`
///   (`anti_entropy.repair_backoff_factor`), then backlog and global load
///   stretch it toward `max_interval_ms` (the larger stretch wins; they do not
///   compound).
/// - The result is always within `[min_interval_ms, max_interval_ms]` for a
///   validated `bounds`.
pub fn nextIntervalMs(bounds: Bounds, state: PeerState, send_backlog_bytes: u64, global_load_permille: u32) u64 {
    const floor = @max(bounds.min_interval_ms, 1);
    if (state.quiet_streak == 0) return clampInterval(bounds, floor);

    var base: u64 = floor;
    var i: u32 = 0;
    while (i < state.quiet_streak and base < bounds.max_interval_ms) : (i += 1) {
        base = @min(bounds.max_interval_ms, base *| anti_entropy.repair_backoff_factor);
    }

    const stretch = @max(backlogStretch(bounds, send_backlog_bytes), loadStretch(bounds, global_load_permille));
    return clampInterval(bounds, stretchSaturating(base, stretch));
}

fn clampInterval(bounds: Bounds, value: u64) u64 {
    return @min(bounds.max_interval_ms, @max(@max(bounds.min_interval_ms, 1), value));
}

fn stretchFactor(bounds: Bounds) u64 {
    return @as(u64, @max(bounds.load_stretch_factor, 1)) * stretch_one;
}

/// Linear ramp from x1 at `backlog_soft_bytes` to the full factor at
/// `backlog_hard_bytes`, in fixed point.
fn backlogStretch(bounds: Bounds, send_backlog_bytes: u64) u64 {
    const full = stretchFactor(bounds);
    if (send_backlog_bytes < bounds.backlog_soft_bytes) return stretch_one;
    if (bounds.backlog_hard_bytes <= bounds.backlog_soft_bytes) return full;
    if (send_backlog_bytes >= bounds.backlog_hard_bytes) return full;

    const range: u128 = bounds.backlog_hard_bytes - bounds.backlog_soft_bytes;
    const over: u128 = send_backlog_bytes - bounds.backlog_soft_bytes;
    const extra: u128 = (@as(u128, full - stretch_one) * over) / range;
    return stretch_one + @as(u64, @intCast(extra));
}

fn loadStretch(bounds: Bounds, global_load_permille: u32) u64 {
    const full = stretchFactor(bounds);
    const clamped: u64 = @min(global_load_permille, 1000);
    return stretch_one + (full - stretch_one) * clamped / 1000;
}

fn stretchSaturating(base: u64, stretch: u64) u64 {
    if (stretch <= stretch_one) return base;
    const scaled = @as(u128, base) * stretch / stretch_one;
    return @intCast(@min(scaled, std.math.maxInt(u64)));
}

/// One `planRound` input: a peer identity, its scheduling memory, and its
/// current outbound send backlog.
pub const PeerInput = struct {
    peer_id: u64,
    state: PeerState,
    send_backlog_bytes: u64 = 0,
};

/// One `planRound` decision for a peer, emitted in ascending `peer_id` order.
pub const Decision = struct {
    peer_id: u64,
    interval_ms: u64,
    due_ms: u64,
    /// This peer's natural due time (before any deferral) has been reached.
    due: bool,
    /// Admitted this round: due, not held back by load, and within budget.
    admitted: bool,
    /// Due, but held back because its send backlog is at/above the hard
    /// limit and it is not yet stale.
    deferred_load: bool,
    /// Due and not load-deferred, but held back by `max_bursts_per_round`.
    deferred_budget: bool,
};

/// Upper bound on peers `planRound` handles per call. A pure stack-bounded
/// function cannot size scratch from a runtime length. Callers with more live
/// peers must plan in `max_round_peers`-sized slices and MUST check the
/// returned count against `peers.len`: peers beyond the cap are not decided.
pub const max_round_peers: usize = 1024;

/// Decide anti-entropy admission for `peers` at `now_ms`, writing at most
/// `min(peers.len, out.len, max_round_peers)` decisions in ascending `peer_id`
/// order (input order breaks id ties). Returns the number written.
///
/// Admission is capped at `bounds.max_bursts_per_round`. When more peers are
/// eligible than the budget allows, never-bursted peers and then the most overdue win (ties by
/// ascending peer id) so a low peer id can never starve a higher one under
/// sustained divergence. A peer whose backlog is at/above
/// `bounds.backlog_hard_bytes` is held back (`deferred_load`) UNLESS it is
/// stale (no burst for at least `max_interval_ms`, or never bursted); stale
/// peers bypass the load gate, which is the convergence-delay bound under
/// backlog (the per-round budget still applies, and being longest overdue they
/// are ranked first).
pub fn planRound(peers: []const PeerInput, now_ms: u64, bounds: Bounds, global_load_permille: u32, out: []Decision) usize {
    const count = @min(@min(peers.len, out.len), max_round_peers);
    if (count == 0) return 0;

    var decisions: [max_round_peers]Decision = undefined;
    var overdue: [max_round_peers]u64 = undefined;
    var eligible: [max_round_peers]bool = undefined;

    for (peers[0..count], 0..) |p, i| {
        const last = effectiveLast(p.state.last_burst_ms, now_ms);
        const interval = nextIntervalMs(bounds, p.state, p.send_backlog_bytes, global_load_permille);
        const due_ms = if (last) |l| l +| interval else now_ms;
        const due = due_ms <= now_ms;
        const stale = if (last) |l| (now_ms - l) >= bounds.max_interval_ms else true;
        const deferred_load = due and p.send_backlog_bytes >= bounds.backlog_hard_bytes and !stale;
        decisions[i] = .{
            .peer_id = p.peer_id,
            .interval_ms = interval,
            .due_ms = due_ms,
            .due = due,
            .admitted = false,
            .deferred_load = deferred_load,
            .deferred_budget = false,
        };
        // Never-bursted peers outrank every overdue peer: a new link is
        // repaired before an established one gets another turn.
        overdue[i] = if (last == null) std.math.maxInt(u64) else now_ms -| due_ms;
        eligible[i] = due and !deferred_load;
    }

    var admitted: usize = 0;
    while (admitted < bounds.max_bursts_per_round) : (admitted += 1) {
        var best: ?usize = null;
        for (0..count) |i| {
            if (!eligible[i]) continue;
            const b = best orelse {
                best = i;
                continue;
            };
            if (overdue[i] > overdue[b] or (overdue[i] == overdue[b] and decisions[i].peer_id < decisions[b].peer_id)) best = i;
        }
        const idx = best orelse break;
        eligible[idx] = false;
        decisions[idx].admitted = true;
    }
    for (0..count) |i| {
        if (eligible[i]) decisions[i].deferred_budget = true;
    }

    std.mem.sort(Decision, decisions[0..count], {}, decisionLessThan);
    @memcpy(out[0..count], decisions[0..count]);
    return count;
}

fn decisionLessThan(_: void, a: Decision, b: Decision) bool {
    return a.peer_id < b.peer_id;
}

/// Earliest time `planRound` can admit `p` (budget aside), using the same
/// stretched interval and hard-backlog gate as `planRound`. A never-bursted
/// (or unknown-burst) peer is eligible now. A peer under hard backlog is held
/// until it is stale, i.e. `max_interval_ms` after its last burst; its
/// stretched `due_ms` never exceeds that, so the stale time is its eligibility.
fn eligibleAtMs(p: PeerInput, now_ms: u64, bounds: Bounds, global_load_permille: u32) u64 {
    const last = effectiveLast(p.state.last_burst_ms, now_ms) orelse return now_ms;
    const interval = nextIntervalMs(bounds, p.state, p.send_backlog_bytes, global_load_permille);
    const due_ms = last +| interval;
    if (p.send_backlog_bytes < bounds.backlog_hard_bytes) return due_ms;
    return @max(due_ms, last +| bounds.max_interval_ms);
}

/// Minimum time any peer in `peers` can next be admitted, clamped to
/// `[now_ms + tick_ms, now_ms + max_interval_ms]`. The daemon sleeps until
/// this time and re-evaluates; it never sleeps past `max_interval_ms` (a
/// quiet peer is still due by then) and never wakes faster than one
/// `tick_ms`. It takes the same per-peer backlog and global load as
/// `planRound`, so a peer whose interval is stretched, or that is held back by
/// hard backlog, does not cause a wakeup that admits nothing. A peer with an
/// unknown or future `last_burst_ms` is eligible now (see `effectiveLast`).
pub fn nextWakeupMs(peers: []const PeerInput, now_ms: u64, bounds: Bounds, global_load_permille: u32) u64 {
    const floor = now_ms +| @max(bounds.tick_ms, 1);
    const ceiling = @max(floor, now_ms +| bounds.max_interval_ms);
    var min_due: u64 = std.math.maxInt(u64);
    for (peers) |p| {
        min_due = @min(min_due, eligibleAtMs(p, now_ms, bounds, global_load_permille));
    }
    return @min(ceiling, @max(floor, min_due));
}

/// Closed-form upper bound on the number of anti-entropy bursts a quiet mesh
/// of `peer_count` peers can issue over `horizon_ms`, starting fresh (every
/// peer's streak at 0) under `bounds` with no backlog/load stretch. Per peer:
/// one burst per backoff doubling from `min` up to `max` (the ramp, including
/// the first), plus `ceil(horizon_ms / max_interval_ms)` bursts at the
/// saturated cadence. This is the proof obligation for "quiet mesh idle cost
/// is bounded": the deterministic simulator test checks planned bursts and
/// wakeups never exceed it. Saturating; zero for an empty mesh.
pub fn quietIdleBurstUpperBound(bounds: Bounds, peer_count: usize, horizon_ms: u64) u64 {
    if (peer_count == 0 or bounds.max_interval_ms == 0) return 0;

    var ramp_steps: u64 = 1;
    var interval = @max(bounds.min_interval_ms, 1);
    while (interval < bounds.max_interval_ms) {
        interval = @min(bounds.max_interval_ms, interval *| anti_entropy.repair_backoff_factor);
        ramp_steps += 1;
    }

    const extra: u64 = std.math.divCeil(u64, horizon_ms, bounds.max_interval_ms) catch unreachable;
    const per_peer = ramp_steps +| extra;
    return @as(u64, @intCast(peer_count)) *| per_peer;
}

test "anti-entropy schedule: Bounds.validate rejects zero min, min>max, tick>min and degenerate budgets" {
    var b = Bounds.default();
    b.min_interval_ms = 0;
    try std.testing.expectError(error.MinIntervalZero, b.validate());

    b = Bounds.default();
    b.min_interval_ms = 100;
    b.max_interval_ms = 50;
    try std.testing.expectError(error.MinExceedsMax, b.validate());

    b = Bounds.default();
    b.tick_ms = 2_000;
    b.min_interval_ms = 1_000;
    try std.testing.expectError(error.TickExceedsMin, b.validate());

    b = Bounds.default();
    b.tick_ms = 0;
    try std.testing.expectError(error.TickZero, b.validate());

    b = Bounds.default();
    b.max_bursts_per_round = 0;
    try std.testing.expectError(error.BurstBudgetZero, b.validate());

    b = Bounds.default();
    b.backlog_soft_bytes = 10;
    b.backlog_hard_bytes = 9;
    try std.testing.expectError(error.BacklogHardBelowSoft, b.validate());

    try Bounds.default().validate();
}

test "anti-entropy schedule: unvalidated bounds never hang, panic, or escape the clamp" {
    var b = Bounds.default();
    b.min_interval_ms = 0; // invalid: must not spin 2^32 iterations
    const v = nextIntervalMs(b, .{ .quiet_streak = std.math.maxInt(u32) }, 0, 0);
    try std.testing.expect(v >= 1 and v <= b.max_interval_ms);

    b = Bounds.default();
    b.min_interval_ms = 100;
    b.max_interval_ms = 50; // invalid: min>max must not panic
    try std.testing.expectEqual(@as(u64, 50), nextIntervalMs(b, .{ .quiet_streak = 3 }, 0, 0));

    b = Bounds.default();
    b.tick_ms = 0; // invalid: wakeup must still move forward
    try std.testing.expect(nextWakeupMs(&.{}, 5, b, 0) > 5);

    // Hostile u64 backlog / u32 load cannot overflow the stretch.
    b = Bounds.default();
    b.load_stretch_factor = std.math.maxInt(u32);
    b.max_interval_ms = std.math.maxInt(u64);
    const huge = nextIntervalMs(b, .{ .quiet_streak = 62 }, std.math.maxInt(u64), std.math.maxInt(u32));
    try std.testing.expect(huge <= b.max_interval_ms);
}

test "anti-entropy schedule: divergence counter advance resets quiet streak and yields min interval" {
    const bounds = Bounds.default();
    var state = PeerState{ .quiet_streak = 7, .divergence_mark = 10 };

    observeRound(&state, 10); // unchanged -> quiet streak advances
    try std.testing.expectEqual(@as(u32, 8), state.quiet_streak);

    observeRound(&state, 11); // moved -> reset
    try std.testing.expectEqual(@as(u32, 0), state.quiet_streak);
    try std.testing.expectEqual(@as(u64, 11), state.divergence_mark);
    try std.testing.expectEqual(bounds.min_interval_ms, nextIntervalMs(bounds, state, 0, 0));
}

test "anti-entropy schedule: quiet streak backs off exponentially and saturates at max interval" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;

    try std.testing.expectEqual(@as(u64, 1_000), nextIntervalMs(bounds, .{ .quiet_streak = 0 }, 0, 0));
    try std.testing.expectEqual(@as(u64, 2_000), nextIntervalMs(bounds, .{ .quiet_streak = 1 }, 0, 0));
    try std.testing.expectEqual(@as(u64, 4_000), nextIntervalMs(bounds, .{ .quiet_streak = 2 }, 0, 0));
    try std.testing.expectEqual(@as(u64, 60_000), nextIntervalMs(bounds, .{ .quiet_streak = 10 }, 0, 0));
    try std.testing.expectEqual(@as(u64, 60_000), nextIntervalMs(bounds, .{ .quiet_streak = std.math.maxInt(u32) }, 0, 0));
}

test "anti-entropy schedule: send backlog above soft limit stretches interval but never beyond max" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.backlog_soft_bytes = 1_000;
    bounds.backlog_hard_bytes = 2_000;
    bounds.load_stretch_factor = 4;

    const quiet = PeerState{ .quiet_streak = 1 }; // base interval 2_000ms
    const base = nextIntervalMs(bounds, quiet, 0, 0);
    try std.testing.expectEqual(@as(u64, 2_000), base);

    const mid = nextIntervalMs(bounds, quiet, 1_500, 0); // halfway soft->hard
    try std.testing.expect(mid > base);
    try std.testing.expect(mid <= bounds.max_interval_ms);

    const at_hard = nextIntervalMs(bounds, quiet, 2_000, 0);
    try std.testing.expectEqual(@as(u64, 8_000), at_hard); // 2_000 * factor(4)

    const past_hard = nextIntervalMs(bounds, quiet, 1_000_000, 0);
    try std.testing.expectEqual(at_hard, past_hard); // capped, no further growth

    // Global load alone can also stretch, same cap.
    const loaded = nextIntervalMs(bounds, quiet, 0, 1_000);
    try std.testing.expectEqual(@as(u64, 8_000), loaded);

    // And divergence always overrides any stretch.
    const divergent = nextIntervalMs(bounds, .{ .quiet_streak = 0 }, 1_000_000, 1_000);
    try std.testing.expectEqual(bounds.min_interval_ms, divergent);
}

test "anti-entropy schedule: hard limit defers non-stale peers only, stale peers are always admitted" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.backlog_soft_bytes = 1_000;
    bounds.backlog_hard_bytes = 2_000;
    bounds.max_bursts_per_round = 8;

    const now: u64 = 100_000;

    const peers = [_]PeerInput{
        // Divergent, due now, hard backlog, recently bursted -> deferred_load.
        .{ .peer_id = 1, .state = .{ .last_burst_ms = now - 1_000, .quiet_streak = 0 }, .send_backlog_bytes = 5_000 },
        // Divergent, due now, hard backlog, but stale (no burst in >= max) -> admitted anyway.
        .{ .peer_id = 2, .state = .{ .last_burst_ms = now - 70_000, .quiet_streak = 0 }, .send_backlog_bytes = 5_000 },
        // Never bursted + hard backlog -> treated as maximally stale -> admitted.
        .{ .peer_id = 3, .state = .{ .last_burst_ms = null, .quiet_streak = 0 }, .send_backlog_bytes = 5_000 },
    };
    var out: [peers.len]Decision = undefined;
    const n = planRound(&peers, now, bounds, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), n);

    try std.testing.expectEqual(@as(u64, 1), out[0].peer_id);
    try std.testing.expect(out[0].due);
    try std.testing.expect(out[0].deferred_load);
    try std.testing.expect(!out[0].admitted);

    try std.testing.expectEqual(@as(u64, 2), out[1].peer_id);
    try std.testing.expect(out[1].due);
    try std.testing.expect(!out[1].deferred_load);
    try std.testing.expect(out[1].admitted);

    try std.testing.expectEqual(@as(u64, 3), out[2].peer_id);
    try std.testing.expect(out[2].due);
    try std.testing.expect(!out[2].deferred_load);
    try std.testing.expect(out[2].admitted);
}

test "anti-entropy schedule: planRound admits at most max_bursts_per_round and defers the rest deterministically by peer id" {
    var bounds = Bounds.default();
    bounds.max_bursts_per_round = 2;
    const now: u64 = 50_000;

    var peers: [5]PeerInput = undefined;
    // Descending peer_id input order to prove selection is by id, not input order.
    for (0..5) |i| {
        peers[4 - i] = .{ .peer_id = @intCast(i + 1), .state = .{ .last_burst_ms = null, .quiet_streak = 0 } };
    }
    var out: [5]Decision = undefined;
    const n = planRound(&peers, now, bounds, 0, &out);
    try std.testing.expectEqual(@as(usize, 5), n);

    for (out[0..n], 1..) |d, expected_id| {
        try std.testing.expectEqual(@as(u64, expected_id), d.peer_id);
    }
    var admitted: usize = 0;
    var deferred_budget: usize = 0;
    for (out[0..n]) |d| {
        try std.testing.expect(d.due);
        if (d.admitted) admitted += 1;
        if (d.deferred_budget) deferred_budget += 1;
    }
    try std.testing.expectEqual(bounds.max_bursts_per_round, admitted);
    try std.testing.expectEqual(@as(usize, 3), deferred_budget);
    try std.testing.expect(out[0].admitted and out[1].admitted);
    try std.testing.expect(out[2].deferred_budget and out[3].deferred_budget and out[4].deferred_budget);
}

test "anti-entropy schedule: nextWakeupMs clamped to [now+tick, now+max] and future bursts are eligible now" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    const now: u64 = 10_000;

    // No peers -> ceiling.
    try std.testing.expectEqual(now + 60_000, nextWakeupMs(&.{}, now, bounds, 0));

    // A long-overdue peer is due "now", but the result never goes below now+tick.
    const overdue = [_]PeerInput{.{ .peer_id = 1, .state = .{ .last_burst_ms = 0, .quiet_streak = 0 } }};
    try std.testing.expectEqual(now + bounds.tick_ms, nextWakeupMs(&overdue, now, bounds, 0));

    // A quiet peer scheduled far in the future is clamped to the ceiling.
    const quiet = [_]PeerInput{.{ .peer_id = 1, .state = .{ .last_burst_ms = now, .quiet_streak = std.math.maxInt(u32) } }};
    try std.testing.expectEqual(now + bounds.max_interval_ms, nextWakeupMs(&quiet, now, bounds, 0));

    // Clock regression: a future last_burst_ms is unknown, so the peer is
    // eligible now (wakeup at the tick floor), never pushed to the ceiling.
    const regressed = [_]PeerInput{.{ .peer_id = 1, .state = .{ .last_burst_ms = std.math.maxInt(u64), .quiet_streak = std.math.maxInt(u32) } }};
    try std.testing.expectEqual(now + bounds.tick_ms, nextWakeupMs(&regressed, now, bounds, 0));
    const regressed_div = [_]PeerInput{.{ .peer_id = 1, .state = .{ .last_burst_ms = now + 1_000_000, .quiet_streak = 0 } }};
    try std.testing.expectEqual(now + bounds.tick_ms, nextWakeupMs(&regressed_div, now, bounds, 0));

    // Near-overflow now saturates instead of wrapping.
    try std.testing.expectEqual(std.math.maxInt(u64), nextWakeupMs(&.{}, std.math.maxInt(u64) - 1, bounds, 0));
}

test "anti-entropy schedule: nextWakeupMs honors backlog and load stretch instead of waking early" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    bounds.backlog_soft_bytes = 1_000;
    bounds.backlog_hard_bytes = 2_000;
    bounds.load_stretch_factor = 4;

    // quiet_streak 5 -> 32s unstretched base; stretched x4 clamps to 60s.
    const state = PeerState{ .last_burst_ms = 0, .quiet_streak = 5 };
    const calm = [_]PeerInput{.{ .peer_id = 1, .state = state }};
    try std.testing.expectEqual(@as(u64, 32_000), nextWakeupMs(&calm, 0, bounds, 0));

    const hard = [_]PeerInput{.{ .peer_id = 1, .state = state, .send_backlog_bytes = 2_000 }};
    try std.testing.expectEqual(@as(u64, 60_000), nextWakeupMs(&hard, 0, bounds, 0));
    try std.testing.expectEqual(@as(u64, 60_000), nextWakeupMs(&hard, 32_000, bounds, 0));

    const loaded = [_]PeerInput{.{ .peer_id = 1, .state = state }};
    try std.testing.expectEqual(@as(u64, 60_000), nextWakeupMs(&loaded, 0, bounds, 1_000));

    // A divergent hard-backlog peer is due after min but held until stale.
    const divergent = [_]PeerInput{.{ .peer_id = 1, .state = .{ .last_burst_ms = 5_000, .quiet_streak = 0 }, .send_backlog_bytes = 9_000 }};
    try std.testing.expectEqual(@as(u64, 65_000), nextWakeupMs(&divergent, 6_000, bounds, 0));

    // The wakeup is exactly when planRound admits, and not earlier.
    var out: [1]Decision = undefined;
    _ = planRound(&hard, 59_999, bounds, 0, &out);
    try std.testing.expect(!out[0].admitted);
    _ = planRound(&hard, 60_000, bounds, 0, &out);
    try std.testing.expect(out[0].admitted);
}

test "anti-entropy schedule: sustained divergence cannot starve high peer ids under a small budget" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.tick_ms = 1_000;
    bounds.max_bursts_per_round = 2;

    const peer_count = 8;
    var states: [peer_count]PeerState = @splat(.{});
    var bursts: [peer_count]u32 = @splat(0);
    var now: u64 = 0;
    // 40 ticks at 2 admissions/tick: round-robin by overdue gives each peer 10.
    for (0..40) |_| {
        var inputs: [peer_count]PeerInput = undefined;
        for (0..peer_count) |i| inputs[i] = .{ .peer_id = @intCast(i), .state = states[i] };
        var out: [peer_count]Decision = undefined;
        const n = planRound(&inputs, now, bounds, 0, &out);
        var admitted: usize = 0;
        for (out[0..n]) |d| {
            if (!d.admitted) continue;
            admitted += 1;
            const idx: usize = @intCast(d.peer_id);
            states[idx].last_burst_ms = now;
            bursts[idx] += 1;
        }
        try std.testing.expect(admitted <= bounds.max_bursts_per_round);
        now += bounds.tick_ms;
    }
    for (bursts) |b| try std.testing.expect(b >= 8 and b <= 12);
}

test "anti-entropy schedule: planRound clock regression and hostile peer states stay bounded" {
    var bounds = Bounds.default();
    bounds.max_bursts_per_round = 8;
    const now: u64 = 1_000;
    const peers = [_]PeerInput{
        .{ .peer_id = 9, .state = .{ .last_burst_ms = std.math.maxInt(u64), .quiet_streak = std.math.maxInt(u32), .divergence_mark = std.math.maxInt(u64) }, .send_backlog_bytes = std.math.maxInt(u64) },
        .{ .peer_id = 3, .state = .{ .last_burst_ms = 0, .quiet_streak = std.math.maxInt(u32) }, .send_backlog_bytes = std.math.maxInt(u64) },
    };
    var out: [2]Decision = undefined;
    try std.testing.expectEqual(@as(usize, 2), planRound(&peers, now, bounds, std.math.maxInt(u32), &out));
    try std.testing.expectEqual(@as(u64, 3), out[0].peer_id);
    try std.testing.expectEqual(@as(u64, 9), out[1].peer_id);
    // A future burst time is unknown: peer 9 is due, stale and admitted, even
    // under hard backlog, instead of being starved until the clock catches up.
    try std.testing.expect(out[1].due and out[1].admitted and !out[1].deferred_load);
    try std.testing.expectEqual(now, out[1].due_ms);
    // Peer 3 has backlog at hard limit and is not due (60s interval, last=0, now=1s).
    try std.testing.expect(!out[0].admitted);

    // Output capacity smaller than input truncates; zero capacity writes none.
    var one: [1]Decision = undefined;
    try std.testing.expectEqual(@as(usize, 1), planRound(&peers, now, bounds, 0, &one));
    try std.testing.expectEqual(@as(usize, 0), planRound(&peers, now, bounds, 0, out[0..0]));
}

test "anti-entropy schedule: quiet mesh 1h simulation of N peers issues <= quietIdleBurstUpperBound bursts and wakeups" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    bounds.max_bursts_per_round = 64;

    const peer_count = 20;
    const horizon_ms: u64 = 3_600_000; // 1h

    var states: [peer_count]PeerState = @splat(.{});
    var now: u64 = 0;
    var total_bursts: u64 = 0;
    var wakeups: u64 = 0;

    while (now < horizon_ms) {
        var inputs: [peer_count]PeerInput = undefined;
        for (0..peer_count) |i| inputs[i] = .{ .peer_id = @intCast(i), .state = states[i] };
        var decisions: [peer_count]Decision = undefined;
        const n = planRound(&inputs, now, bounds, 0, &decisions);
        wakeups += 1;

        for (decisions[0..n]) |d| {
            if (!d.admitted) continue;
            total_bursts += 1;
            const idx: usize = @intCast(d.peer_id);
            states[idx].last_burst_ms = now;
            observeRound(&states[idx], states[idx].divergence_mark); // quiet: no divergence
        }

        var wake_inputs: [peer_count]PeerInput = undefined;
        for (0..peer_count) |i| wake_inputs[i] = .{ .peer_id = @intCast(i), .state = states[i] };
        const wake = nextWakeupMs(&wake_inputs, now, bounds, 0);
        if (wake <= now) break; // safety: must always move forward
        now = wake;
    }

    const bound = quietIdleBurstUpperBound(bounds, peer_count, horizon_ms);
    // Non-vacuous: every peer burst at least once and the bound is not absurdly loose.
    try std.testing.expect(total_bursts >= peer_count);
    try std.testing.expect(total_bursts <= bound);
    try std.testing.expect(total_bursts * 4 >= bound);
    try std.testing.expect(wakeups <= bound);
}

test "anti-entropy schedule: active mesh with continuous divergence converges each peer within min interval subject to per-round budget" {
    var bounds = Bounds.default();
    // min_interval_ms is deliberately well above tick_ms * the number of
    // rounds this round-robin needs: once a peer is admitted, it must not
    // become due again before every other due peer has had a turn, or a
    // low peer_id would perpetually starve higher ids under the
    // deterministic ascending-id selection.
    bounds.min_interval_ms = 10_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    bounds.max_bursts_per_round = 3;

    const peer_count = 10;
    var states: [peer_count]PeerState = @splat(.{});
    var divergence_counters: [peer_count]u64 = @splat(0);

    var now: u64 = 0;
    var serviced: [peer_count]bool = @splat(false);
    var serviced_count: usize = 0;
    const max_rounds = (peer_count + bounds.max_bursts_per_round - 1) / bounds.max_bursts_per_round + 1;
    var round: usize = 0;

    while (serviced_count < peer_count and round < max_rounds) : (round += 1) {
        // Continuous divergence: every peer's gap counter advances every
        // round, so each peer's quiet streak keeps resetting to the
        // fast-repair floor instead of backing off.
        for (0..peer_count) |i| {
            divergence_counters[i] += 1;
            observeRound(&states[i], divergence_counters[i]);
        }

        var inputs: [peer_count]PeerInput = undefined;
        for (0..peer_count) |i| inputs[i] = .{ .peer_id = @intCast(i), .state = states[i] };
        var decisions: [peer_count]Decision = undefined;
        const n = planRound(&inputs, now, bounds, 0, &decisions);
        try std.testing.expectEqual(@as(usize, peer_count), n);

        var admitted_this_round: usize = 0;
        for (decisions[0..n]) |d| {
            if (!d.admitted) continue;
            admitted_this_round += 1;
            const idx: usize = @intCast(d.peer_id);
            states[idx].last_burst_ms = now;
            if (!serviced[idx]) {
                serviced[idx] = true;
                serviced_count += 1;
            }
        }
        try std.testing.expect(admitted_this_round <= bounds.max_bursts_per_round);
        now += bounds.tick_ms;
    }

    try std.testing.expectEqual(peer_count, serviced_count);
    try std.testing.expect(round <= max_rounds);
}

test "anti-entropy schedule: future last_burst_ms re-baselines and is repaired within max_interval_ms" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    const now: u64 = 5_000;

    for ([_]u64{ now + 3_600_000, std.math.maxInt(u64) }) |future| {
        for ([_]u32{ 0, std.math.maxInt(u32) }) |streak| {
            var state = PeerState{ .last_burst_ms = future, .quiet_streak = streak };
            var input = [_]PeerInput{.{ .peer_id = 1, .state = state }};
            var out: [1]Decision = undefined;
            try std.testing.expectEqual(@as(usize, 1), planRound(&input, now, bounds, 0, &out));
            try std.testing.expect(out[0].due and out[0].admitted);

            // Caller re-baselines on admission; the peer is then due no later
            // than now + max_interval_ms.
            state.last_burst_ms = now;
            input[0].state = state;
            _ = planRound(&input, now + bounds.max_interval_ms - 1, bounds, 0, &out);
            _ = planRound(&input, now + bounds.max_interval_ms, bounds, 0, &out);
            try std.testing.expect(out[0].admitted);
            try std.testing.expect(nextWakeupMs(&input, now, bounds, 0) <= now + bounds.max_interval_ms);
        }
    }
}

test "anti-entropy schedule: clock regression simulation admits every peer within max_interval_ms" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    bounds.max_bursts_per_round = 64;

    const peer_count = 20;
    const regression_ms: u64 = 100_000;
    var states: [peer_count]PeerState = undefined;
    for (&states, 0..) |*st, i| {
        // Stamped by a clock that was ahead of the regressed one by up to 1h+.
        st.* = .{ .last_burst_ms = regression_ms + 3_600_000 + i * 7, .quiet_streak = @intCast(i % 9) };
    }
    var admitted_at: [peer_count]?u64 = @splat(null);

    var now = regression_ms;
    while (now <= regression_ms + bounds.max_interval_ms) {
        var inputs: [peer_count]PeerInput = undefined;
        for (0..peer_count) |i| inputs[i] = .{ .peer_id = @intCast(i), .state = states[i] };
        var out: [peer_count]Decision = undefined;
        const n = planRound(&inputs, now, bounds, 0, &out);
        for (out[0..n]) |d| {
            if (!d.admitted) continue;
            const idx: usize = @intCast(d.peer_id);
            if (admitted_at[idx] == null) admitted_at[idx] = now;
            states[idx].last_burst_ms = now;
            observeRound(&states[idx], states[idx].divergence_mark);
        }
        for (0..peer_count) |i| inputs[i].state = states[i];
        const wake = nextWakeupMs(&inputs, now, bounds, 0);
        try std.testing.expect(wake > now);
        now = wake;
    }
    for (admitted_at) |at| {
        try std.testing.expect(at != null);
        try std.testing.expect(at.? - regression_ms <= bounds.max_interval_ms);
    }
}

test "anti-entropy schedule: loaded or hard-backlog mesh never wakes without admitting anyone" {
    var bounds = Bounds.default();
    bounds.min_interval_ms = 1_000;
    bounds.max_interval_ms = 60_000;
    bounds.tick_ms = 1_000;
    bounds.max_bursts_per_round = 64;
    bounds.backlog_soft_bytes = 1_000;
    bounds.backlog_hard_bytes = 2_000;
    bounds.load_stretch_factor = 4;

    const peer_count = 20;
    const horizon_ms: u64 = 3_600_000;
    const Case = struct { backlog: u64, load: u32 };
    for ([_]Case{ .{ .backlog = 2_000, .load = 0 }, .{ .backlog = 0, .load = 1_000 }, .{ .backlog = 2_000, .load = 1_000 } }) |c| {
        var states: [peer_count]PeerState = undefined;
        for (&states, 0..) |*st, i| {
            st.* = .{ .last_burst_ms = i * 997, .quiet_streak = @intCast(1 + i % 6) };
        }
        var now: u64 = 60_000;
        var wakeups: u64 = 0;
        var idle_wakeups: u64 = 0;
        var bursts: u64 = 0;
        while (now < horizon_ms) {
            var inputs: [peer_count]PeerInput = undefined;
            for (0..peer_count) |i| inputs[i] = .{ .peer_id = @intCast(i), .state = states[i], .send_backlog_bytes = c.backlog };
            var out: [peer_count]Decision = undefined;
            const n = planRound(&inputs, now, bounds, c.load, &out);
            wakeups += 1;
            var admitted: u64 = 0;
            for (out[0..n]) |d| {
                if (!d.admitted) continue;
                admitted += 1;
                const idx: usize = @intCast(d.peer_id);
                states[idx].last_burst_ms = now;
                observeRound(&states[idx], states[idx].divergence_mark);
            }
            bursts += admitted;
            if (admitted == 0) idle_wakeups += 1;
            for (0..peer_count) |i| inputs[i].state = states[i];
            const wake = nextWakeupMs(&inputs, now, bounds, c.load);
            try std.testing.expect(wake > now);
            now = wake;
        }
        try std.testing.expectEqual(@as(u64, 0), idle_wakeups);
        try std.testing.expect(bursts >= peer_count);
        try std.testing.expect(wakeups <= quietIdleBurstUpperBound(bounds, peer_count, horizon_ms));
    }
}
