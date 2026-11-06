// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-class scheduling budgets for one connection's shared SendQ FIFO.
//!
//! The daemon's SendQ (`sendq.zig`) is a single FIFO with one byte cap per
//! connection. Control lines (PING, session repair), chat fan-out, CHATHISTORY
//! replay and binary WS media frames all compete for that one pool. Left
//! unguarded, a slow media or replay consumer fills the whole queue and the
//! next control line either poisons the connection or is silently dropped.
//!
//! Two independent budgets apply:
//!
//! * Per connection, `admit` gives each class a nested ceiling on the total
//!   backlog (`sendq.backlog`) after the append. Classes form a strict
//!   priority ladder control > chat > replay > media, and each rung keeps a
//!   reserve that no lower rung may occupy. Because the FIFO drains oldest
//!   first, while every resident byte belongs to classes below X the backlog
//!   is at most the ceiling of the most recently admitted resident class,
//!   which is at most `ceiling(X) - reserve(X)`. So media can never starve
//!   replay, chat or control; replay can never starve chat or control; and
//!   chat can never starve control. A single FIFO total cannot also keep a
//!   higher rung from crowding a lower one; that direction is bounded by the
//!   higher rung's own ceiling, by replay paging (`replayAllowance`) and by
//!   media being lossy.
//! * Per reactor turn, `TurnLedger` holds separate byte credits for replay
//!   and media, so neither class can monopolize one reactor turn's copy work
//!   across many connections. Control and chat are not turn-bounded: refusing
//!   them would lose an accepted event or poison an innocent recipient.
//!
//! The module is pure: it never imports the daemon, never touches a
//! connection, and allocates only inside `Counters.writePrometheus`, which
//! rolls its output back on allocation failure. `TurnLedger` is two-phase:
//! `decide` is side-effect free, and state only changes in `commit` after
//! the physical enqueue succeeded, or in `record` for a refusal.

const std = @import("std");

/// Output traffic class sharing one connection's SendQ, highest priority first.
pub const Class = enum(u2) {
    control,
    chat,
    replay,
    media,
};

/// Admission outcome for one append of `len` bytes to a class.
pub const Decision = enum(u2) {
    /// Append fits under the class ceiling and the turn credit; proceed.
    admit,
    /// Media only: a lossy datagram. Drop it; never poison the recipient.
    shed,
    /// Replay only: ask the client to page again later; never close.
    defer_retry,
    /// Control or chat over their ceiling: keep the existing poison policy.
    overflow,
};

/// The refusal a class receives when it does not fit.
pub fn refusal(class: Class) Decision {
    return switch (class) {
        .control, .chat => .overflow,
        .replay => .defer_retry,
        .media => .shed,
    };
}

/// Reserves per priority rung, as permille (parts per 1000) of the
/// connection's SendQ cap, each with an absolute floor. Reserves apply
/// cumulatively: each class ceiling keeps the reserves of every rung above it
/// free, at least their permille sum of the cap and, where the cap allows it,
/// at least the sum of their floors (see `ceilings`).
pub const Policy = struct {
    /// Free space only control may use (above the chat ceiling).
    control_reserve_permille: u16 = 64,
    /// Free space chat may use and replay/media may not.
    chat_reserve_permille: u16 = 128,
    /// Free space replay may use and media may not.
    replay_reserve_permille: u16 = 64,
    control_floor_bytes: u64 = 16 * 1024,
    chat_floor_bytes: u64 = 8 * 1024,
    replay_floor_bytes: u64 = 4 * 1024,

    pub const default: Policy = .{};

    /// Every rung must keep a nonzero proportional reserve (floors yield on
    /// small caps, so a zero permille would erase the guarantee there), and
    /// the reserves must leave media a nonzero share.
    pub fn validate(self: Policy) error{InvalidPolicy}!void {
        if (self.control_reserve_permille == 0 or
            self.chat_reserve_permille == 0 or
            self.replay_reserve_permille == 0) return error.InvalidPolicy;
        const sum = @as(u32, self.control_reserve_permille) +
            self.chat_reserve_permille + self.replay_reserve_permille;
        if (sum >= 1000) return error.InvalidPolicy;
    }

    /// Config-load check for one SendQ cap: the policy validates, and the
    /// replay and media ceilings each carry at least one largest item, so
    /// neither class is refused forever on an idle connection. Ceilings never
    /// decrease as the cap grows, so a cap that passes keeps passing for
    /// every larger cap.
    pub fn validateCap(self: Policy, cap: u64, max_replay_item: u64, max_media_frame: u64) error{InvalidPolicy}!void {
        try self.validate();
        const c = ceilings(self, cap);
        if (c.replay < max_replay_item or c.media < max_media_frame) return error.InvalidPolicy;
    }
};

/// `permille` of `cap`, rounded down and clamped to `cap`. Widened through
/// u128 so no caller-supplied combination can overflow before division.
fn permilleOf(permille: u32, cap: u64) u64 {
    const product: u128 = @as(u128, cap) * permille;
    return @intCast(@min(product / 1000, cap));
}

/// Floors may shrink a proportional ceiling to no less than this fraction of
/// it, so on caps too small for the floors every lower rung keeps a share
/// that still grows with the cap instead of collapsing to zero.
const floor_shrink_divisor = 2;

/// Ceiling of the rung below a cumulative reserve of `reserve_permille` and
/// `reserve_floor` bytes. Each term is non-decreasing in `cap` (the floored
/// permille rises by at most one per unit of cap while the permille sum is at
/// most 1000, and is clamped to `cap` above it), so the result is too.
fn rungCeiling(cap: u64, reserve_permille: u32, reserve_floor: u64) u64 {
    const proportional = cap - permilleOf(reserve_permille, cap);
    const floored = @min(proportional, cap -| reserve_floor);
    return @max(floored, proportional / floor_shrink_divisor);
}

/// Per-class ceilings for one SendQ cap: the maximum total backlog (queued
/// plus this append) the class may reach. Always control >= chat >= replay
/// >= media.
pub const Ceilings = struct {
    control: u64,
    chat: u64,
    replay: u64,
    media: u64,

    pub fn forClass(self: Ceilings, class: Class) u64 {
        return switch (class) {
            .control => self.control,
            .chat => self.chat,
            .replay => self.replay,
            .media => self.media,
        };
    }
};

/// Nested ceilings for `cap` under `policy`. Each rung's ceiling is its
/// proportional ceiling, lowered by the cumulative floors above it but never
/// below half the proportional ceiling, so every ceiling is non-decreasing in
/// `cap`. A zero cap yields all-zero ceilings, so every nonempty append is
/// refused.
pub fn ceilings(policy: Policy, cap: u64) Ceilings {
    const control_permille: u32 = policy.control_reserve_permille;
    const chat_permille = control_permille + policy.chat_reserve_permille;
    const replay_permille = chat_permille + policy.replay_reserve_permille;
    const control_floor = policy.control_floor_bytes;
    const chat_floor = control_floor +| policy.chat_floor_bytes;
    const replay_floor = chat_floor +| policy.replay_floor_bytes;
    return .{
        .control = cap,
        .chat = rungCeiling(cap, control_permille, control_floor),
        .replay = rungCeiling(cap, chat_permille, chat_floor),
        .media = rungCeiling(cap, replay_permille, replay_floor),
    };
}

/// Per-connection decision for appending `len` bytes of `class` when the
/// SendQ already carries `queued` bytes against `cap`. An overflowing
/// `queued + len` fails closed to the class refusal.
pub fn admit(policy: Policy, class: Class, queued: u64, cap: u64, len: u64) Decision {
    const total = std.math.add(u64, queued, len) catch return refusal(class);
    return if (total <= ceilings(policy, cap).forClass(class)) .admit else refusal(class);
}

/// How many replay items of at most `per_item_upper` bytes fit under the
/// replay ceiling, capped at `max_items`. Zero when the ceiling is already
/// reached or either bound is zero.
pub fn replayAllowance(policy: Policy, queued: u64, cap: u64, per_item_upper: u64, max_items: usize) usize {
    if (per_item_upper == 0 or max_items == 0) return 0;
    const headroom = ceilings(policy, cap).replay -| queued;
    return @intCast(@min(headroom / per_item_upper, max_items));
}

/// Cumulative saturating outcome counters, one per class and decision.
pub const Counters = struct {
    values: [class_count][decision_count]u64 = @splat(@splat(0)),

    const class_count = std.enums.values(Class).len;
    const decision_count = std.enums.values(Decision).len;

    pub fn bump(self: *Counters, class: Class, decision: Decision) void {
        const slot = &self.values[@backingInt(class)][@backingInt(decision)];
        slot.* +|= 1;
    }

    pub fn get(self: *const Counters, class: Class, decision: Decision) u64 {
        return self.values[@backingInt(class)][@backingInt(decision)];
    }

    /// Saturating sum, for aggregating per-reactor ledgers into one scrape.
    pub fn merge(self: *Counters, other: *const Counters) void {
        for (&self.values, other.values) |*row, other_row| {
            for (row, other_row) |*v, o| v.* +|= o;
        }
    }

    const families = [_]struct { decision: Decision, name: []const u8, help: []const u8 }{
        .{ .decision = .admit, .name = "onyx_output_class_admitted_total", .help = "SendQ appends admitted under their output class budget" },
        .{ .decision = .shed, .name = "onyx_output_class_shed_total", .help = "Media frames dropped by the media output budget" },
        .{ .decision = .defer_retry, .name = "onyx_output_class_deferred_total", .help = "Replay output deferred by the replay output budget" },
        .{ .decision = .overflow, .name = "onyx_output_class_overflow_total", .help = "Control or chat appends over their output class ceiling" },
    };

    /// Prometheus counters, one family per decision with a `class` label.
    /// On allocation failure `out` is restored to its prior length.
    pub fn writePrometheus(self: *const Counters, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) error{OutOfMemory}!void {
        const start = out.items.len;
        errdefer out.shrinkRetainingCapacity(start);
        for (families) |family| {
            try out.print(allocator, "# HELP {s} {s}\n# TYPE {s} counter\n", .{ family.name, family.help, family.name });
            for (std.enums.values(Class)) |class| {
                try out.print(allocator, "{s}{{class=\"{s}\"}} {d}\n", .{ family.name, @tagName(class), self.get(class, family.decision) });
            }
        }
    }
};

/// Per-reactor-turn byte credit for each turn-bounded class.
pub const TurnLimits = struct {
    replay_bytes: u64 = 4 * 1024 * 1024,
    media_bytes: u64 = 32 * 1024 * 1024,

    pub const default: TurnLimits = .{};

    /// Each turn must be able to carry at least one largest item, or that
    /// class would be refused forever.
    pub fn validate(self: TurnLimits, max_replay_item: u64, max_media_frame: u64) error{InvalidPolicy}!void {
        if (self.replay_bytes == 0 or self.media_bytes == 0) return error.InvalidPolicy;
        if (self.replay_bytes < max_replay_item or self.media_bytes < max_media_frame) return error.InvalidPolicy;
    }
};

/// One reactor's per-turn class credit plus cumulative counters. Owned and
/// mutated by exactly one reactor thread.
pub const TurnLedger = struct {
    limits: TurnLimits,
    replay_remaining: u64,
    media_remaining: u64,
    counters: Counters = .{},

    pub fn init(limits: TurnLimits) TurnLedger {
        return .{ .limits = limits, .replay_remaining = limits.replay_bytes, .media_remaining = limits.media_bytes };
    }

    /// Restore full credit. Call once at the start of each reactor turn.
    /// Counters are cumulative and survive.
    pub fn beginTurn(self: *TurnLedger) void {
        self.replay_remaining = self.limits.replay_bytes;
        self.media_remaining = self.limits.media_bytes;
    }

    /// Side-effect-free decision: the per-connection ceiling first, then this
    /// turn's credit for replay and media.
    pub fn decide(self: *const TurnLedger, policy: Policy, class: Class, queued: u64, cap: u64, len: u64) Decision {
        const per_conn = admit(policy, class, queued, cap, len);
        if (per_conn != .admit) return per_conn;
        const credit = switch (class) {
            .control, .chat => return .admit,
            .replay => self.replay_remaining,
            .media => self.media_remaining,
        };
        return if (len <= credit) .admit else refusal(class);
    }

    /// Record a successful physical enqueue of `len` bytes that `decide`
    /// admitted: debit turn credit (saturating) and count the admit.
    pub fn commit(self: *TurnLedger, class: Class, len: u64) void {
        switch (class) {
            .control, .chat => {},
            .replay => self.replay_remaining -|= len,
            .media => self.media_remaining -|= len,
        }
        self.counters.bump(class, .admit);
    }

    /// Record a refusal, whether from `decide` or from a later physical
    /// enqueue failure. Turn credit is untouched.
    pub fn record(self: *TurnLedger, class: Class, decision: Decision) void {
        std.debug.assert(decision != .admit);
        self.counters.bump(class, decision);
    }

    /// `replayAllowance` further clamped by this turn's replay credit.
    pub fn replayPageAllowance(self: *const TurnLedger, policy: Policy, queued: u64, cap: u64, per_item_upper: u64, max_items: usize) usize {
        const by_queue = replayAllowance(policy, queued, cap, per_item_upper, max_items);
        if (by_queue == 0) return 0;
        return @intCast(@min(by_queue, self.replay_remaining / per_item_upper));
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;
const mib: u64 = 1024 * 1024;
const priority = [_]Class{ .control, .chat, .replay, .media };

fn expectNested(c: Ceilings, cap: u64) !void {
    try testing.expectEqual(cap, c.control);
    try testing.expect(c.control >= c.chat);
    try testing.expect(c.chat >= c.replay);
    try testing.expect(c.replay >= c.media);
}

test "output class budget: default policy validates and ceilings nest control >= chat >= replay >= media" {
    try Policy.default.validate();
    const c = ceilings(.default, mib);
    try expectNested(c, mib);
    // Every rung keeps a strictly positive reserve over the next rung.
    try testing.expect(c.control > c.chat and c.chat > c.replay and c.replay > c.media and c.media > 0);
    // The control floor dominates its proportional share on a small cap.
    const small = ceilings(.default, 128 * 1024);
    try testing.expectEqual(@as(u64, 128 * 1024 - 16 * 1024), small.chat);
}

test "output class budget: policy validate rejects reserves summing past cap, zero reserves and zero cap ceilings" {
    try testing.expectError(error.InvalidPolicy, (Policy{ .control_reserve_permille = 600, .chat_reserve_permille = 300, .replay_reserve_permille = 100 }).validate());
    try testing.expectError(error.InvalidPolicy, (Policy{ .control_reserve_permille = 0 }).validate());
    try testing.expectError(error.InvalidPolicy, (Policy{ .chat_reserve_permille = 0 }).validate());
    try testing.expectError(error.InvalidPolicy, (Policy{ .replay_reserve_permille = 0 }).validate());
    try testing.expectError(error.InvalidPolicy, (Policy{ .control_reserve_permille = std.math.maxInt(u16) }).validate());

    // A zero cap refuses every nonempty append with the class refusal.
    for (priority) |class| try testing.expectEqual(refusal(class), admit(.default, class, 0, 0, 1));
}

test "output class budget: every cap keeps nesting and every ceiling is non-decreasing in the cap" {
    // Step-1 sweep past every default floor/proportional crossover (replay
    // 112000, chat 128000, control 256000). Small caps (config allows e.g.
    // `sendq = 9`) shrink each lower ceiling to at most half rather than to
    // zero, and raising the cap never lowers any class budget.
    var prev = ceilings(.default, 0);
    try expectNested(prev, 0);
    var cap: u64 = 1;
    while (cap <= 300_000) : (cap += 1) {
        errdefer std.debug.print("cap={d}\n", .{cap});
        const c = ceilings(.default, cap);
        try expectNested(c, cap);
        try testing.expect(c.chat >= prev.chat and c.replay >= prev.replay and c.media >= prev.media);
        try testing.expect(c.media >= (cap - permilleOf(256, cap)) / 2);
        prev = c;
    }
    try testing.expectEqual(@as(u64, 4), ceilings(.default, 9).chat);
    try testing.expectEqual(@as(u64, (10_000 - 640) / 2), ceilings(.default, 10_000).chat);

    // The former cliff just above the summed floors (28 KiB) is gone.
    try testing.expectEqualDeep(Ceilings{ .control = 28672, .chat = 13418, .replay = 11583, .media = 10666 }, ceilings(.default, 28672));
    try testing.expectEqualDeep(Ceilings{ .control = 28673, .chat = 13419, .replay = 11584, .media = 10666 }, ceilings(.default, 28673));
    try testing.expectEqualDeep(Ceilings{ .control = 32768, .chat = 16384, .replay = 13238, .media = 12190 }, ceilings(.default, 32768));
    // Floors bind where they fit above half the proportional ceiling.
    try testing.expectEqualDeep(Ceilings{ .control = 65536, .chat = 65536 - 16384, .replay = 65536 - 24576, .media = 65536 - 28672 }, ceilings(.default, 65536));

    // An unvalidated policy (permille sums past 1000, saturating floors)
    // still nests and stays monotone.
    const bad: Policy = .{ .control_reserve_permille = 900, .chat_reserve_permille = 900, .replay_reserve_permille = 900, .chat_floor_bytes = std.math.maxInt(u64) };
    var bad_prev = ceilings(bad, 0);
    for ([_]u64{ 1, 9, 1000, mib, std.math.maxInt(u64) - 1, std.math.maxInt(u64) }) |big| {
        const c = ceilings(bad, big);
        try expectNested(c, big);
        try testing.expect(c.chat >= bad_prev.chat and c.replay >= bad_prev.replay and c.media >= bad_prev.media);
        bad_prev = c;
    }
    try expectNested(ceilings(.default, std.math.maxInt(u64)), std.math.maxInt(u64));
}

test "output class budget: replay always pages and validateCap rejects caps that cannot carry one item" {
    // Every cap from 24 KiB up carries one 9000-byte replay item (an IRCv3
    // tagged line is about 8.7 KiB) on an idle connection; the first such
    // cap is below 24 KiB and monotonicity keeps it paging above.
    const max_replay_item: u64 = 9000;
    var first_paging: ?u64 = null;
    var cap: u64 = 0;
    while (cap <= 300_000) : (cap += 1) {
        errdefer std.debug.print("cap={d}\n", .{cap});
        const pages = replayAllowance(.default, 0, cap, max_replay_item, 64);
        var ledger: TurnLedger = .init(.default);
        if (first_paging) |_| {
            try testing.expect(pages > 0);
            try testing.expect(ledger.replayPageAllowance(.default, 0, cap, max_replay_item, 64) > 0);
            try testing.expectEqual(Decision.admit, ledger.decide(.default, .replay, 0, cap, max_replay_item));
        } else if (pages > 0) first_paging = cap;
    }
    try testing.expect(first_paging.? <= 24 * 1024);
    for ([_]u64{ 28672, 28673, 32768 }) |c| {
        try testing.expect(replayAllowance(.default, 0, c, max_replay_item, 64) > 0);
        try testing.expectEqual(Decision.admit, admit(.default, .media, 0, c, 4097));
    }

    // validateCap: below the first paging cap replay is refused forever.
    try Policy.default.validateCap(first_paging.?, max_replay_item, 1200);
    try testing.expectError(error.InvalidPolicy, Policy.default.validateCap(first_paging.? - 1, max_replay_item, 1200));
    // The default 1 MiB SendQ carries a 64 KiB media frame; 64 KiB does not.
    try Policy.default.validateCap(mib, max_replay_item, 64 * 1024);
    try testing.expectError(error.InvalidPolicy, Policy.default.validateCap(64 * 1024, max_replay_item, 64 * 1024));
    try testing.expectError(error.InvalidPolicy, Policy.default.validateCap(0, 1, 1));
    try testing.expectError(error.InvalidPolicy, (Policy{ .chat_reserve_permille = 0 }).validateCap(mib, 1, 1));
}

test "output class budget: media over ceiling sheds instead of overflow; control admitted to full cap" {
    const c = ceilings(.default, mib);
    try testing.expectEqual(Decision.shed, admit(.default, .media, c.media, mib, 1));
    try testing.expectEqual(Decision.admit, admit(.default, .media, c.media - 1, mib, 1));
    // A frame larger than the media ceiling is shed even on an empty queue.
    try testing.expectEqual(Decision.shed, admit(.default, .media, 0, mib, c.media + 1));
    try testing.expectEqual(Decision.admit, admit(.default, .control, mib - 1, mib, 1));
    try testing.expectEqual(Decision.overflow, admit(.default, .control, mib, mib, 1));
}

test "output class budget: replay over ceiling returns defer_retry never overflow" {
    const cap: u64 = 512 * 1024;
    const c = ceilings(.default, cap);
    try testing.expectEqual(Decision.defer_retry, admit(.default, .replay, c.replay, cap, 1));
    try testing.expectEqual(Decision.admit, admit(.default, .replay, c.replay - 1, cap, 1));
    // Replay still fits when media sits exactly at its ceiling.
    try testing.expectEqual(Decision.admit, admit(.default, .replay, c.media, cap, c.replay - c.media));
}

test "output class budget: chat over its ceiling overflows while control still admits within reserve" {
    const c = ceilings(.default, mib);
    try testing.expectEqual(Decision.overflow, admit(.default, .chat, c.chat, mib, 1));
    try testing.expectEqual(Decision.admit, admit(.default, .chat, c.chat - 1, mib, 1));
    try testing.expectEqual(Decision.admit, admit(.default, .control, c.chat, mib, mib - c.chat));
    // Chat still fits when replay sits exactly at its ceiling.
    try testing.expectEqual(Decision.admit, admit(.default, .chat, c.replay, mib, c.chat - c.replay));
}

test "output class budget: checked arithmetic fails closed at u64 max queued/len" {
    const max = std.math.maxInt(u64);
    for (priority) |class| {
        try testing.expectEqual(refusal(class), admit(.default, class, max, mib, max));
        try testing.expectEqual(refusal(class), admit(.default, class, max, mib, 1));
        try testing.expectEqual(refusal(class), admit(.default, class, 1, max, max));
    }
    var ledger: TurnLedger = .init(.default);
    try testing.expectEqual(Decision.shed, ledger.decide(.default, .media, 0, max, max));
}

test "output class budget: replayAllowance clamps page count to replay headroom and returns 0 when saturated" {
    const c = ceilings(.default, mib);
    try testing.expectEqual(@as(usize, 0), replayAllowance(.default, c.replay, mib, 4096, 64));
    try testing.expectEqual(@as(usize, 0), replayAllowance(.default, c.replay + 1, mib, 4096, 64));
    try testing.expectEqual(@as(usize, 0), replayAllowance(.default, 0, mib, 0, 64));
    try testing.expectEqual(@as(usize, 0), replayAllowance(.default, 0, mib, 4096, 0));
    try testing.expectEqual(@as(usize, 3), replayAllowance(.default, 0, mib, 4096, 3));
    try testing.expectEqual(@as(usize, @intCast(@min(c.replay / 9000, 64))), replayAllowance(.default, 0, mib, 9000, 64));
    // Exactly the allowance fits; one more item would defer.
    const n = replayAllowance(.default, 100, 64 * 1024, 4096, 64);
    try testing.expect(n > 0);
    try testing.expectEqual(Decision.admit, admit(.default, .replay, 100, 64 * 1024, n * 4096));
    try testing.expectEqual(Decision.defer_retry, admit(.default, .replay, 100, 64 * 1024, (n + 1) * 4096));

    var ledger: TurnLedger = .init(.{ .replay_bytes = 8192 });
    try testing.expectEqual(@as(usize, 2), ledger.replayPageAllowance(.default, 0, mib, 4096, 64));
    ledger.commit(.replay, 8192);
    try testing.expectEqual(@as(usize, 0), ledger.replayPageAllowance(.default, 0, mib, 4096, 64));
}

const Segment = struct { class: Class, len: u64 };

test "output class budget: simulated slow consumer (deterministic PRNG mix of media/replay/chat appends, slow drain) always leaves control_reserve free and every PING admits" {
    for ([_]u64{ 0xC0FFEE, 1, 0x5EED_0005, 0xDEAD_BEEF }) |seed| {
        for ([_]u64{ 64 * 1024, mib, 4 * mib }) |cap| {
            errdefer std.debug.print("seed={x} cap={d}\n", .{ seed, cap });
            // Rooms derived from the policy fields, independent of `ceilings`.
            // Reserves are cumulative; at these caps the floors fit above
            // half the proportional ceiling, so no shrink clamp applies.
            const p = Policy.default;
            const above_chat = @max(cap * p.control_reserve_permille / 1000, p.control_floor_bytes);
            const above_replay = @max(cap * (p.control_reserve_permille + p.chat_reserve_permille) / 1000, p.control_floor_bytes + p.chat_floor_bytes);
            const above_media = @max(cap * (p.control_reserve_permille + p.chat_reserve_permille + p.replay_reserve_permille) / 1000, p.control_floor_bytes + p.chat_floor_bytes + p.replay_floor_bytes);
            const control_room = above_chat;
            const room = [_]u64{ control_room, above_replay - above_chat, above_media - above_replay, cap - above_media };
            var prng = std.Random.DefaultPrng.init(seed);
            const rand = prng.random();
            // Exact FIFO model: append order, oldest drains first.
            var fifo: [8192]Segment = undefined;
            var head: usize = 0;
            var tail: usize = 0;
            var queued: u64 = 0;
            var admitted: [4]u64 = @splat(0);
            var refused: u64 = 0;

            for (0..20_000) |step| {
                const class = priority[1 + rand.uintLessThan(u8, 3)];
                const len: u64 = 1 + rand.uintLessThan(u64, cap / 8);
                if (admit(.default, class, queued, cap, len) == .admit and tail < fifo.len) {
                    fifo[tail] = .{ .class = class, .len = len };
                    tail += 1;
                    queued += len;
                    admitted[@backingInt(class)] += 1;
                } else refused += 1;
                // Control headroom is never consumed by chat, replay or media.
                try testing.expect(cap - queued >= control_room);
                try testing.expectEqual(Decision.admit, admit(.default, .control, queued, cap, control_room));

                // Each rung above every resident class keeps its own reserve.
                var top: u2 = @backingInt(Class.media);
                for (fifo[head..tail]) |seg| top = @min(top, @backingInt(seg.class));
                for (priority[1..]) |x| {
                    const xi = @backingInt(x);
                    if (head != tail and xi >= top) continue;
                    try testing.expectEqual(Decision.admit, admit(.default, x, queued, cap, room[xi]));
                }

                // Slow drain: release at most cap/32 bytes every third step.
                if (step % 3 == 0) {
                    var budget: u64 = rand.uintLessThan(u64, cap / 32) + 1;
                    while (budget > 0 and head < tail) {
                        const take = @min(budget, fifo[head].len);
                        fifo[head].len -= take;
                        queued -= take;
                        budget -= take;
                        if (fifo[head].len == 0) head += 1;
                    }
                    if (head == tail) {
                        head = 0;
                        tail = 0;
                    }
                }
            }
            // Non-vacuous: every class was admitted and the queue hit pressure.
            for (admitted[1..]) |n| try testing.expect(n > 0);
            try testing.expect(refused > 0);
        }
    }
}

test "output class budget: media flood never blocks replay, chat or control" {
    const cap: u64 = 2 * mib;
    // Expected cumulative reserves at 2 MiB: proportional shares exceed every
    // floor.
    const control_room = cap * 64 / 1000;
    const chat_room = cap * 192 / 1000 - control_room;
    const replay_room = cap * 256 / 1000 - control_room - chat_room;
    var queued: u64 = 0;
    var shed: usize = 0;
    for (0..10_000) |_| {
        if (admit(.default, .media, queued, cap, 4096) == .admit) queued += 4096 else shed += 1;
        try testing.expectEqual(Decision.admit, admit(.default, .replay, queued, cap, replay_room));
        try testing.expectEqual(Decision.admit, admit(.default, .chat, queued, cap, replay_room + chat_room));
        try testing.expectEqual(Decision.admit, admit(.default, .control, queued, cap, replay_room + chat_room + control_room));
    }
    try testing.expect(shed > 0);
    try testing.expect(cap - queued < control_room + chat_room + replay_room + 4096);
}

test "output class budget: TurnLedger bounds per-turn replay/media bytes, control and chat unbounded, beginTurn restores credit" {
    try TurnLimits.default.validate(9000, 4 * mib + 10);
    try testing.expectError(error.InvalidPolicy, (TurnLimits{ .media_bytes = 0 }).validate(1, 1));
    try testing.expectError(error.InvalidPolicy, (TurnLimits{ .media_bytes = mib }).validate(9000, 4 * mib));
    try testing.expectError(error.InvalidPolicy, (TurnLimits{ .replay_bytes = 100 }).validate(9000, 1));

    const cap: u64 = 64 * mib;
    var ledger: TurnLedger = .init(.{ .replay_bytes = 50, .media_bytes = 10 });
    try testing.expectEqual(Decision.shed, ledger.decide(.default, .media, 0, cap, 11));
    try testing.expectEqual(Decision.admit, ledger.decide(.default, .media, 0, cap, 10));
    ledger.commit(.media, 10);
    try testing.expectEqual(Decision.shed, ledger.decide(.default, .media, 0, cap, 1));
    // Replay credit is separate from media credit.
    try testing.expectEqual(Decision.admit, ledger.decide(.default, .replay, 0, cap, 50));
    ledger.commit(.replay, 50);
    try testing.expectEqual(Decision.defer_retry, ledger.decide(.default, .replay, 0, cap, 1));
    // Chat and control are never refused by turn credit.
    for (0..100) |_| {
        try testing.expectEqual(Decision.admit, ledger.decide(.default, .chat, 0, cap, mib));
        ledger.commit(.chat, mib);
        try testing.expectEqual(Decision.admit, ledger.decide(.default, .control, 0, cap, mib));
        ledger.commit(.control, mib);
    }
    // A per-connection refusal outranks available credit.
    ledger.beginTurn();
    try testing.expectEqual(Decision.shed, ledger.decide(.default, .media, ceilings(.default, cap).media, cap, 1));
    try testing.expectEqual(Decision.admit, ledger.decide(.default, .media, 0, cap, 10));
    try testing.expectEqual(Decision.admit, ledger.decide(.default, .replay, 0, cap, 50));
    try testing.expectEqual(@as(u64, 100), ledger.counters.get(.chat, .admit));
    try testing.expectEqual(@as(u64, 1), ledger.counters.get(.media, .admit));
}

test "output class budget: decide is side-effect free so a failed physical enqueue leaves the ledger unchanged" {
    var ledger: TurnLedger = .init(.{ .replay_bytes = 100, .media_bytes = 100 });
    const before = ledger;
    for (priority) |class| _ = ledger.decide(.default, class, 0, mib, 60);
    try testing.expectEqualDeep(before, ledger);
    // Enqueue failed after an admit: record the refusal, credit untouched.
    ledger.record(.media, .shed);
    try testing.expectEqual(@as(u64, 100), ledger.media_remaining);
    try testing.expectEqual(@as(u64, 1), ledger.counters.get(.media, .shed));
    try testing.expectEqual(@as(u64, 0), ledger.counters.get(.media, .admit));
    // Commit past remaining credit saturates at zero.
    ledger.commit(.media, 1000);
    try testing.expectEqual(@as(u64, 0), ledger.media_remaining);
}

test "output class budget: counters merge saturating and render one Prometheus family per decision" {
    var a: Counters = .{};
    a.bump(.media, .shed);
    a.bump(.media, .shed);
    a.bump(.replay, .defer_retry);
    var b: Counters = .{};
    b.bump(.control, .admit);
    b.values[@backingInt(Class.media)][@backingInt(Decision.shed)] = std.math.maxInt(u64);
    a.merge(&b);
    try testing.expectEqual(std.math.maxInt(u64), a.get(.media, .shed));

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try out.appendSlice(testing.allocator, "prefix\n");
    try a.writePrometheus(testing.allocator, &out);
    const text = out.items;
    try testing.expect(std.mem.indexOf(u8, text, "onyx_output_class_deferred_total{class=\"replay\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_output_class_admitted_total{class=\"control\"} 1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "onyx_output_class_admitted_total{class=\"chat\"} 0\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "# TYPE onyx_output_class_shed_total counter\n") != null);
    try testing.expectEqual(@as(usize, 1 + 4 * (2 + 4)), std.mem.count(u8, text, "\n"));
}

test "output class budget: metrics render rolls back on every allocation failure" {
    var counters: Counters = .{};
    counters.bump(.chat, .overflow);
    // Sweep every arena size: each failure point must leave only the prefix,
    // and the first size that fits must render completely.
    var storage: [8192]u8 = undefined;
    var failures: usize = 0;
    for (2..storage.len + 1) |size| {
        var fixed = std.heap.FixedBufferAllocator.init(storage[0..size]);
        const gpa = fixed.allocator();
        var out = try std.ArrayList(u8).initCapacity(gpa, 2);
        out.appendSliceAssumeCapacity("p\n");
        if (counters.writePrometheus(gpa, &out)) |_| {
            try testing.expect(std.mem.indexOf(u8, out.items, "onyx_output_class_overflow_total{class=\"chat\"} 1\n") != null);
            try testing.expect(std.mem.startsWith(u8, out.items, "p\n# HELP "));
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            try testing.expectEqualStrings("p\n", out.items);
            failures += 1;
        }
    } else return error.TestUnexpectedResult;
    try testing.expect(failures > 100);
}
