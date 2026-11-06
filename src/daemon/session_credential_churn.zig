// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recovery without credential churn (roadmap T09): a pure, deterministic
//! decision/budget leaf for the "reuse instead of reissue" half of resume and
//! the "counted and bounded" half of churn.
//!
//! `classify` is the single checked decision a caller makes once it knows
//! what credential a reconnecting client presented and whether the
//! connection has *independently* proven ownership of a parked row: any
//! still-valid credential is always reused, never replaced; a revoked or
//! malformed one is always rejected; an expired one never reattaches
//! anything and only ever mints fresh; a credential-less connection reuses
//! a row only on separate proof of ownership, never on the row's mere
//! existence.
//!
//! `Budget` turns that decision into a bounded resource: a fixed-capacity,
//! open-addressed (linear-probing) table keyed by a per-process-salted
//! SipHash of the ASCII-case-folded account name — the same folding
//! `SessionStore` applies to account keys. The raw account string is never
//! stored. Each occupied slot carries one fixed window of fresh-mint and
//! rotation counts for that account. Both kinds of churn are bounded the
//! same way: a pure pre-commit admission check (`admitFresh`/
//! `admitRotation`) the caller must obey, and a post-commit record
//! (`noteFresh`/`noteRotation`) that always counts what actually happened.
//! Removal uses backward-shift deletion,
//! so no tombstones exist and every live key stays reachable from its home
//! slot; a removal can therefore never make a spent budget look unseen.
//!
//! When `capacity` distinct accounts are tracked and a never-seen account
//! needs a slot, the table first reclaims the oldest slot whose window has
//! already elapsed (it carries no budget information, so this is silent).
//! A live slot is never evicted: dropping it would make that account's
//! spent budget look unseen and grant it a fresh allowance inside the same
//! window. Instead, while every tracked window is live, untracked accounts
//! are charged to one shared over-capacity window (`overflow_*` limits) and
//! each such charge counts `table_overflow`. Churn therefore stays bounded
//! per tracked account and globally for all untracked accounts together.
//! Every counter saturates at its type's max instead of wrapping.
//!
//! `init` performs the table's one allocation; every other method is
//! allocation-free and infallible, so a caller can invoke `admitFresh`/
//! `admitRotation`/`noteFresh`/`noteRotation`/`noteReuse`/`noteRefused` from
//! a hot connection path with no failure mode to handle. `renderPrometheus` is likewise
//! allocation-free and only ever fails with `NoSpaceLeft` on a too-small
//! caller buffer.
//!
//! `Budget` is not internally synchronized. A multi-reactor caller must
//! serialize every method call (including the read-only admission checks)
//! under one lock. Admission and recording are deliberately separate so a
//! mint or rotation that fails after admission is not charged; the
//! resulting check-then-record window can over-admit by at most the number
//! of concurrently admitted operations for one account, never unboundedly.
//! A committed rotation past the cap (that race, or a caller that ignored
//! `admitRotation`) is still counted in `rotations` and additionally in
//! `rotations_over_budget`, so the metrics never hide issued credentials.
//!
//! This module has no knowledge of `sessions.zig`, `server.zig`, or the wire
//! protocol. A caller (the daemon) is expected to: gate a bootstrap mint
//! through `admitFresh` and record a committed mint with `noteFresh`; gate a
//! credential rotation through `admitRotation` *before* committing it, keep
//! the current (still valid) credential on `.defer_ms`, and record a
//! committed rotation with `noteRotation` (e.g. when `SessionStore`'s
//! `rotations_required` increased across the commit); count a successful
//! resume, an unchanged re-emitted handle token, or a preserved resume
//! credential as `noteReuse()`; and call `noteRefused()` whenever a fresh
//! mint or rotation is withheld because admission deferred it. Only
//! authenticated account names may be passed; guests never reach a reusable
//! row.

const std = @import("std");
const crypto_random = @import("../crypto/random.zig");

/// What credential (if any) a reconnecting/resuming client presented.
pub const Presented = enum {
    /// No credential presented at all (e.g. a brand-new connection).
    none,
    /// A credential that is valid and names exactly one resumable row.
    valid_exact,
    /// A credential that is valid and names a portable group of rows.
    valid_group,
    /// A credential that parsed but is past its validity window.
    expired,
    /// A credential that parsed but has been explicitly revoked.
    revoked,
    /// A credential that failed to parse or decode.
    malformed,
};

/// What the caller should do about a presented credential.
pub const Decision = enum {
    /// Reuse the existing credential/row; never mint or publish a new one.
    reuse_existing,
    /// Mint a fresh credential; there is nothing valid to reuse.
    mint_fresh,
    /// Refuse outright: the credential is actively untrustworthy.
    reject,
};

/// Proof, independent of the presented credential, that this connection
/// may resume a parked row.
pub const RowOwnership = enum {
    /// No independent proof (or no parked row). The mere existence of a
    /// parked row named by the presented credential is *not* proof; a
    /// caller must never derive `authenticated_owner` from that credential.
    unproven,
    /// The connection completed account authentication of its own (e.g.
    /// SASL bound to this connection) and that authenticated account owns a
    /// parked, resumable row.
    authenticated_owner,
};

/// Total function: every `Presented` value maps to exactly one `Decision`
/// for every `RowOwnership` value. A valid credential is its own proof and
/// is always reused, never replaced with a fresh mint. A revoked or
/// malformed credential is always rejected, even for an authenticated
/// owner. An expired credential never reattaches a row: it always mints
/// fresh, so expiry keeps bounding credential lifetime. A connection that
/// presented nothing reuses a parked row only on independent proof of
/// ownership; otherwise it mints fresh.
pub fn classify(presented: Presented, ownership: RowOwnership) Decision {
    return switch (presented) {
        .valid_exact, .valid_group => .reuse_existing,
        .revoked, .malformed => .reject,
        .expired => .mint_fresh,
        .none => switch (ownership) {
            .authenticated_owner => .reuse_existing,
            .unproven => .mint_fresh,
        },
    };
}

/// Tunable policy for `Budget`.
pub const Params = struct {
    /// Maximum number of distinct accounts tracked at once. Must be > 0.
    capacity: usize,
    /// Width of the fixed window, in injected monotonic ms. Must be > 0.
    window_ms: i64,
    /// Fresh bootstrap mints allowed per account per window. Zero refuses
    /// every fresh mint, including for a never-seen account.
    max_fresh_per_window: u32,
    /// Credential rotations allowed per account per window.
    max_rotations_per_window: u32,
    /// Fresh mints allowed per window, summed over every account that could
    /// not get its own slot because the table was full of live windows.
    overflow_fresh_per_window: u32 = 64,
    /// Rotations allowed per window under the same shared over-capacity
    /// window.
    overflow_rotations_per_window: u32 = 64,
};

/// Production policy: 4096 tracked accounts, a one-minute window, eight
/// fresh bootstrap mints and eight rotations per account per window.
pub const default_params: Params = .{
    .capacity = 4096,
    .window_ms = 60_000,
    .max_fresh_per_window = 8,
    .max_rotations_per_window = 8,
};

/// Monotonic (saturating) counters for the whole budget, taken as a single
/// consistent snapshot.
pub const ChurnStats = struct {
    fresh_minted: u64 = 0,
    reused: u64 = 0,
    /// Every committed rotation, within budget or not.
    rotations: u64 = 0,
    /// Committed rotations that exceeded the per-account cap (subset of
    /// `rotations`); nonzero means admission was raced or ignored.
    rotations_over_budget: u64 = 0,
    /// Fresh mints or rotations actually withheld after admission deferred
    /// them; never counts an operation that happened.
    refused_over_budget: u64 = 0,
    /// Committed mints or rotations charged to the shared over-capacity
    /// window because every tracked account window was live.
    table_overflow: u64 = 0,
};

/// Result of a fresh-mint or rotation admission check.
pub const Admit = union(enum) {
    /// The account has headroom in the current window; proceeding is allowed.
    allow,
    /// Over budget for the current window; retry after this many ms. Always
    /// in `[1, window_ms]`.
    defer_ms: i64,
};

pub const InitError = std.mem.Allocator.Error || crypto_random.Error || error{InvalidChurnParams};

/// Fixed-capacity, open-addressed, per-account churn budget. Pure and
/// deterministic: every notion of time is the `now_ms` the caller injects.
/// Allocates exactly once, in `init`.
pub const Budget = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// Per-process random SipHash key so account-name hashes are not
    /// predictable or reproducible across restarts.
    key: [16]u8,
    /// Power-of-two table at least twice `params.capacity`, keeping the load
    /// factor at or below one half so probes for absent keys stay short.
    slots: []Slot,
    /// Occupied slots; never exceeds `params.capacity`.
    len: usize = 0,
    stats: ChurnStats = .{},
    /// Shared window for accounts that cannot get a slot while every
    /// tracked window is live. `account_key` and `occupied` are unused.
    overflow: Slot = .{},

    const Slot = struct {
        occupied: bool = false,
        account_key: u64 = 0,
        window_start_ms: i64 = 0,
        fresh_count: u32 = 0,
        rotation_count: u32 = 0,
        last_touched_ms: i64 = 0,
    };

    /// Validate `params`, draw the per-process SipHash key from the OS
    /// CSPRNG (a guessable key would let a remote peer force every account
    /// into one probe chain), and allocate the slot table. On any error
    /// nothing is retained. The only allocation this type ever performs.
    pub fn init(allocator: std.mem.Allocator, params: Params) InitError!Budget {
        if (params.capacity == 0 or params.window_ms <= 0) return error.InvalidChurnParams;
        const doubled = std.math.mul(usize, params.capacity, 2) catch return error.InvalidChurnParams;
        const table_len = std.math.ceilPowerOfTwo(usize, doubled) catch return error.InvalidChurnParams;
        var key: [16]u8 = undefined;
        try crypto_random.fillOsEntropy(&key);
        errdefer std.crypto.secureZero(u8, &key);
        const slots = try allocator.alloc(Slot, table_len);
        @memset(slots, .{});
        return .{ .allocator = allocator, .params = params, .key = key, .slots = slots };
    }

    pub fn deinit(self: *Budget) void {
        self.allocator.free(self.slots);
        std.crypto.secureZero(u8, &self.key);
        self.* = undefined;
    }

    /// Drop every slot whose window has fully elapsed. Such a slot carries
    /// no budget information (its next touch would reset it), so pruning is
    /// observably equivalent to not pruning; it only frees headroom ahead of
    /// the lazy reclaim-on-full path.
    pub fn prune(self: *Budget, now_ms: i64) void {
        var i: usize = 0;
        while (i < self.slots.len) {
            const slot = &self.slots[i];
            if (slot.occupied and windowElapsed(slot.*, now_ms, self.params.window_ms)) {
                // Backward shift may move a not-yet-visited key into `i`;
                // re-examine the same index.
                self.removeAt(i);
                continue;
            }
            i += 1;
        }
    }

    pub fn snapshot(self: *const Budget) ChurnStats {
        return self.stats;
    }

    pub fn noteReuse(self: *Budget) void {
        self.stats.reused +|= 1;
    }

    pub fn noteRefused(self: *Budget) void {
        self.stats.refused_over_budget +|= 1;
    }

    /// Pure read: never creates a row, never mutates state or counters.
    pub fn admitFresh(self: *const Budget, account: []const u8, now_ms: i64) Admit {
        return self.admit(account, now_ms, .fresh);
    }

    /// Pure pre-commit check for a credential rotation. On `.defer_ms` the
    /// caller must not rotate: it keeps the current (still valid)
    /// credential and calls `noteRefused()`. Never mutates state.
    pub fn admitRotation(self: *const Budget, account: []const u8, now_ms: i64) Admit {
        return self.admit(account, now_ms, .rotation);
    }

    const Kind = enum { fresh, rotation };

    fn admit(self: *const Budget, account: []const u8, now_ms: i64, kind: Kind) Admit {
        const window_ms = self.params.window_ms;
        const max = switch (kind) {
            .fresh => self.params.max_fresh_per_window,
            .rotation => self.params.max_rotations_per_window,
        };
        const idx = self.findIndex(self.foldKey(account)) orelse {
            if (max == 0) return .{ .defer_ms = window_ms };
            if (self.len < self.params.capacity or self.reclaimableIndex(now_ms) != null) return .allow;
            // Table full of live windows: this account would be charged to
            // the shared over-capacity window, so admission follows it.
            const overflow_max = switch (kind) {
                .fresh => self.params.overflow_fresh_per_window,
                .rotation => self.params.overflow_rotations_per_window,
            };
            return self.admitSlot(self.overflow, now_ms, kind, overflow_max);
        };
        return self.admitSlot(self.slots[idx], now_ms, kind, max);
    }

    fn admitSlot(self: *const Budget, slot: Slot, now_ms: i64, kind: Kind, max: u32) Admit {
        const window_ms = self.params.window_ms;
        if (windowElapsed(slot, now_ms, window_ms))
            return if (max == 0) .{ .defer_ms = window_ms } else .allow;
        const used = switch (kind) {
            .fresh => slot.fresh_count,
            .rotation => slot.rotation_count,
        };
        if (used < max) return .allow;
        const resume_at = slot.window_start_ms +| window_ms;
        // A clock behind the anchor never earns an early reset, and a defer
        // is never zero (a caller must not spin) nor longer than one window.
        return .{ .defer_ms = std.math.clamp(resume_at -| now_ms, 1, window_ms) };
    }

    /// Record one committed fresh bootstrap mint for `account` at `now_ms`.
    pub fn noteFresh(self: *Budget, account: []const u8, now_ms: i64) void {
        const slot = self.touch(account, now_ms);
        slot.fresh_count +|= 1;
        self.stats.fresh_minted +|= 1;
    }

    fn rotationCap(self: *const Budget, slot: *const Slot) u32 {
        return if (slot == &self.overflow)
            self.params.overflow_rotations_per_window
        else
            self.params.max_rotations_per_window;
    }

    /// Record one committed credential rotation for `account` at `now_ms`.
    /// The rotation already happened, so it is always counted in
    /// `rotations`. Returns `false` (and counts `rotations_over_budget`)
    /// when it exceeded the window's cap, which only a raced or ignored
    /// `admitRotation` can cause; the caller should log/alert on `false`.
    pub fn noteRotation(self: *Budget, account: []const u8, now_ms: i64) bool {
        const slot = self.touch(account, now_ms);
        const within = slot.rotation_count < self.rotationCap(slot);
        slot.rotation_count +|= 1;
        self.stats.rotations +|= 1;
        if (!within) self.stats.rotations_over_budget +|= 1;
        return within;
    }

    /// Get or create `account`'s slot (or the shared over-capacity slot when
    /// the table is full of live windows), reset its window if elapsed, and
    /// stamp it as touched at `now_ms`.
    fn touch(self: *Budget, account: []const u8, now_ms: i64) *Slot {
        const slot = self.getOrCreate(self.foldKey(account), now_ms);
        if (slot == &self.overflow) self.stats.table_overflow +|= 1;
        if (windowElapsed(slot.*, now_ms, self.params.window_ms)) {
            slot.window_start_ms = now_ms;
            slot.fresh_count = 0;
            slot.rotation_count = 0;
        }
        slot.last_touched_ms = now_ms;
        return slot;
    }

    /// ASCII-case-fold and hash `account` with the per-process key. Bytes
    /// are folded through a fixed stack chunk, so there is no length limit
    /// and no allocation; non-ASCII bytes hash unchanged.
    fn foldKey(self: *const Budget, account: []const u8) u64 {
        var hasher = std.hash.SipHash64(2, 4).init(&self.key);
        var chunk: [64]u8 = undefined;
        var rest = account;
        while (rest.len != 0) {
            const take = @min(rest.len, chunk.len);
            for (rest[0..take], chunk[0..take]) |c, *d| d.* = std.ascii.toLower(c);
            hasher.update(chunk[0..take]);
            rest = rest[take..];
        }
        return hasher.finalInt();
    }

    fn home(self: *const Budget, key: u64) usize {
        return @as(usize, @truncate(key)) & (self.slots.len - 1);
    }

    /// Pure lookup: probe from `key`'s home slot, stopping at the first
    /// empty slot (absent) or a matching occupied slot (found). The load
    /// factor bound guarantees an empty slot exists, so the probe ends.
    fn findIndex(self: *const Budget, key: u64) ?usize {
        const mask = self.slots.len - 1;
        var idx = self.home(key);
        while (self.slots[idx].occupied) : (idx = (idx + 1) & mask) {
            if (self.slots[idx].account_key == key) return idx;
        }
        return null;
    }

    /// Return the existing slot for `key`, or insert a fresh one. At
    /// capacity, first reclaim an elapsed slot; if every tracked window is
    /// live, return the shared over-capacity slot instead of evicting one.
    /// The table never holds more than `params.capacity` keys.
    fn getOrCreate(self: *Budget, key: u64, now_ms: i64) *Slot {
        if (self.findIndex(key)) |idx| return &self.slots[idx];
        if (self.len >= self.params.capacity) {
            const victim = self.reclaimableIndex(now_ms) orelse return &self.overflow;
            self.removeAt(victim);
        }
        const mask = self.slots.len - 1;
        var idx = self.home(key);
        while (self.slots[idx].occupied) idx = (idx + 1) & mask;
        self.slots[idx] = .{
            .occupied = true,
            .account_key = key,
            .window_start_ms = now_ms,
            .last_touched_ms = now_ms,
        };
        self.len += 1;
        return &self.slots[idx];
    }

    /// The oldest-touched slot whose window has elapsed (information-free,
    /// so reclaiming it is silent), or null when every tracked window is
    /// live. Ties resolve to the lowest index, so the choice is
    /// deterministic. Cost is one bounded linear scan of the table (8192
    /// slots at `default_params`), paid only when an untracked account
    /// arrives while the table is full; callers should `prune` periodically
    /// so that path stays rare.
    fn reclaimableIndex(self: *const Budget, now_ms: i64) ?usize {
        var oldest_elapsed: ?usize = null;
        for (self.slots, 0..) |slot, i| {
            if (!slot.occupied) continue;
            if (windowElapsed(slot, now_ms, self.params.window_ms) and
                (oldest_elapsed == null or slot.last_touched_ms < self.slots[oldest_elapsed.?].last_touched_ms))
                oldest_elapsed = i;
        }
        return oldest_elapsed;
    }

    /// Backward-shift deletion for linear probing: after vacating `start`,
    /// move each following key whose probe path crosses the hole back into
    /// it, until an empty slot ends the cluster. Leaves no tombstones and
    /// keeps every remaining key reachable from its home slot.
    fn removeAt(self: *Budget, start: usize) void {
        std.debug.assert(self.slots[start].occupied);
        const mask = self.slots.len - 1;
        var hole = start;
        var j = (start + 1) & mask;
        while (self.slots[j].occupied) : (j = (j + 1) & mask) {
            const h = self.home(self.slots[j].account_key);
            // Probe path of `j` is h, h+1, ..., j; it crosses the hole iff
            // the hole is strictly closer to `h` than `j` is.
            if (((hole -% h) & mask) < ((j -% h) & mask)) {
                self.slots[hole] = self.slots[j];
                hole = j;
            }
        }
        self.slots[hole] = .{};
        self.len -= 1;
    }
};

/// A window has elapsed once `window_ms` has fully passed since its anchor.
/// A clock that appears to move backward relative to the anchor is treated
/// conservatively as "still inside the window" rather than granting an
/// early reset.
fn windowElapsed(slot: Budget.Slot, now_ms: i64, window_ms: i64) bool {
    if (now_ms < slot.window_start_ms) return false;
    return now_ms -| slot.window_start_ms >= window_ms;
}

/// Render all six churn counters as Prometheus text, each with HELP/TYPE
/// lines. Pure formatting; fails only when `out` is too small.
pub fn renderPrometheus(out: []u8, stats: ChurnStats) error{NoSpaceLeft}![]const u8 {
    const Row = struct { name: []const u8, help: []const u8, value: u64 };
    const rows = [_]Row{
        .{ .name = "onyx_session_credential_fresh_minted_total", .help = "Fresh bootstrap session credentials minted", .value = stats.fresh_minted },
        .{ .name = "onyx_session_credential_reused_total", .help = "Reconnects or resumes that reused an existing valid credential instead of minting a new one", .value = stats.reused },
        .{ .name = "onyx_session_credential_rotations_total", .help = "Committed session credential rotations, within budget or not", .value = stats.rotations },
        .{ .name = "onyx_session_credential_rotations_over_budget_total", .help = "Committed credential rotations that exceeded the per-account budget because admission was raced or ignored", .value = stats.rotations_over_budget },
        .{ .name = "onyx_session_credential_refused_over_budget_total", .help = "Fresh mints or rotations withheld because the per-account churn budget was spent", .value = stats.refused_over_budget },
        .{ .name = "onyx_session_credential_table_overflow_total", .help = "Committed mints or rotations charged to the shared over-capacity churn window because every tracked account window was live", .value = stats.table_overflow },
    };
    var n: usize = 0;
    for (rows) |row| {
        n += (try std.fmt.bufPrint(out[n..], "# HELP {s} {s}\n# TYPE {s} counter\n{s} {d}\n", .{
            row.name, row.help, row.name, row.name, row.value,
        })).len;
    }
    return out[0..n];
}

const testing = std.testing;

fn occupiedCount(budget: *const Budget) usize {
    var occupied: usize = 0;
    for (budget.slots) |slot| {
        if (slot.occupied) occupied += 1;
    }
    return occupied;
}

/// Every occupied key is reachable from its home slot and appears once.
fn expectTableInvariant(budget: *const Budget) !void {
    try testing.expectEqual(budget.len, occupiedCount(budget));
    try testing.expect(budget.len <= budget.params.capacity);
    for (budget.slots, 0..) |slot, i| {
        if (!slot.occupied) continue;
        try testing.expectEqual(@as(?usize, i), budget.findIndex(slot.account_key));
    }
}

test "session credential churn: classify maps valid_exact and valid_group to reuse_existing for every ownership value (exhaustive over the Presented enum)" {
    inline for (.{ Presented.valid_exact, Presented.valid_group }) |presented| {
        try testing.expectEqual(Decision.reuse_existing, classify(presented, .unproven));
        try testing.expectEqual(Decision.reuse_existing, classify(presented, .authenticated_owner));
    }
    // Exhaustive: walk every Presented tag for every ownership value so a
    // newly added tag must be classified here before it can compile into a
    // reuse. Reuse requires a valid credential or, for a credential-less
    // connection only, independent proof of ownership.
    inline for (@typeInfo(Presented).@"enum".field_names) |name| {
        const presented: Presented = @field(Presented, name);
        inline for (@typeInfo(RowOwnership).@"enum".field_names) |own_name| {
            const ownership: RowOwnership = @field(RowOwnership, own_name);
            const decision = classify(presented, ownership);
            if (std.mem.startsWith(u8, name, "valid_")) {
                try testing.expectEqual(Decision.reuse_existing, decision);
            } else if (decision == .reuse_existing) {
                try testing.expectEqual(Presented.none, presented);
                try testing.expectEqual(RowOwnership.authenticated_owner, ownership);
            }
            if (decision == .mint_fresh) {
                try testing.expect(presented == .none or presented == .expired);
            }
        }
    }
}

test "session credential churn: classify rejects revoked/malformed, never reuses on an expired credential, and reuses credential-less only on independent ownership proof" {
    inline for (.{ Presented.revoked, Presented.malformed }) |presented| {
        try testing.expectEqual(Decision.reject, classify(presented, .unproven));
        try testing.expectEqual(Decision.reject, classify(presented, .authenticated_owner));
    }
    // An expired credential must not reattach a parked row, even when that
    // row exists and the account later authenticates: expiry bounds lifetime.
    try testing.expectEqual(Decision.mint_fresh, classify(.expired, .unproven));
    try testing.expectEqual(Decision.mint_fresh, classify(.expired, .authenticated_owner));
    // No credential: the row's existence alone is never proof.
    try testing.expectEqual(Decision.mint_fresh, classify(.none, .unproven));
    try testing.expectEqual(Decision.reuse_existing, classify(.none, .authenticated_owner));
}

test "session credential churn: admitFresh allows max_fresh_per_window then defers with exact retry ms, and recovers after window_ms elapses" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 4,
        .window_ms = 1000,
        .max_fresh_per_window = 2,
        .max_rotations_per_window = 0,
    });
    defer budget.deinit();

    try testing.expectEqual(Admit.allow, budget.admitFresh("eve", 0));
    budget.noteFresh("eve", 0);
    try testing.expectEqual(Admit.allow, budget.admitFresh("eve", 0));
    budget.noteFresh("eve", 0);

    // Budget spent at t=0 for the window [0, 1000).
    try testing.expectEqual(Admit{ .defer_ms = 900 }, budget.admitFresh("eve", 100));
    try testing.expectEqual(Admit{ .defer_ms = 1 }, budget.admitFresh("eve", 999));
    // admitFresh is a pure read: repeated checks charge nothing.
    try testing.expectEqual(@as(u64, 2), budget.snapshot().fresh_minted);
    try testing.expectEqual(@as(u64, 0), budget.snapshot().refused_over_budget);

    // The window fully resets once window_ms has elapsed, granting a full
    // fresh budget again (not just one slot back).
    try testing.expectEqual(Admit.allow, budget.admitFresh("eve", 1000));
    budget.noteFresh("eve", 1000);
    try testing.expectEqual(Admit.allow, budget.admitFresh("eve", 1000));
    budget.noteFresh("eve", 1000);
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitFresh("eve", 1000));

    // A different account is independent.
    try testing.expectEqual(Admit.allow, budget.admitFresh("mallory", 1000));
}

test "session credential churn: admitFresh never grants an early reset when the clock moves backward and clamps defer to one window" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 2,
        .window_ms = 1000,
        .max_fresh_per_window = 1,
        .max_rotations_per_window = 1,
    });
    defer budget.deinit();

    budget.noteFresh("eve", 5000);
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitFresh("eve", 0));
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitFresh("eve", std.math.minInt(i64)));
    // A backward touch neither resets the window nor refunds the budget.
    budget.noteFresh("eve", 10);
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitFresh("eve", 4999));
    try testing.expectEqual(Admit.allow, budget.admitRotation("eve", 10));
    try testing.expect(budget.noteRotation("eve", 10));
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitRotation("eve", 4000));
    try testing.expect(!budget.noteRotation("eve", 4000));
    // Extreme forward time saturates instead of overflowing.
    try testing.expectEqual(Admit.allow, budget.admitFresh("eve", std.math.maxInt(i64)));
}

test "session credential churn: zero fresh budget refuses even a never-seen account" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 2,
        .window_ms = 250,
        .max_fresh_per_window = 0,
        .max_rotations_per_window = 0,
    });
    defer budget.deinit();
    try testing.expectEqual(Admit{ .defer_ms = 250 }, budget.admitFresh("ghost", 0));
    try testing.expectEqual(Admit{ .defer_ms = 250 }, budget.admitRotation("ghost", 0));
    try testing.expectEqual(Admit{ .defer_ms = 250 }, budget.admitFresh("ghost", 10_000));
}

test "session credential churn: admitRotation defers past max_rotations_per_window with exact retry ms, is a pure read, and recovers after the window" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 4,
        .window_ms = 1000,
        .max_fresh_per_window = 0,
        .max_rotations_per_window = 2,
    });
    defer budget.deinit();

    try testing.expectEqual(Admit.allow, budget.admitRotation("carol", 0));
    try testing.expect(budget.noteRotation("carol", 0));
    try testing.expectEqual(Admit.allow, budget.admitRotation("carol", 0));
    try testing.expect(budget.noteRotation("carol", 0));

    try testing.expectEqual(Admit{ .defer_ms = 900 }, budget.admitRotation("CAROL", 100));
    try testing.expectEqual(Admit{ .defer_ms = 1 }, budget.admitRotation("carol", 999));
    // Rotation and fresh budgets are independent; reads charge nothing.
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitFresh("carol", 0));
    const stats = budget.snapshot();
    try testing.expectEqual(@as(u64, 2), stats.rotations);
    try testing.expectEqual(@as(u64, 0), stats.rotations_over_budget);
    try testing.expectEqual(@as(u64, 0), stats.refused_over_budget);

    // A fresh window grants a fresh rotation budget.
    try testing.expectEqual(Admit.allow, budget.admitRotation("carol", 1000));
    try testing.expect(budget.noteRotation("carol", 1000));
    try testing.expectEqual(@as(u64, 3), budget.snapshot().rotations);
}

test "session credential churn: nine committed rotations in one default window are all counted, the ninth as over budget, never as refused" {
    var budget = try Budget.init(testing.allocator, default_params);
    defer budget.deinit();

    // Caller ignores (or races) admission: every rotation is committed and
    // must show up in `rotations`; the overflow is flagged separately.
    for (0..9) |i| {
        const within = budget.noteRotation("dave", @intCast(i));
        try testing.expectEqual(i < default_params.max_rotations_per_window, within);
    }
    const stats = budget.snapshot();
    try testing.expectEqual(@as(u64, 9), stats.rotations);
    try testing.expectEqual(@as(u64, 1), stats.rotations_over_budget);
    try testing.expectEqual(@as(u64, 0), stats.refused_over_budget);
}

test "session credential churn: a caller obeying admitRotation holds off the ninth rotation and keeps the current credential" {
    var budget = try Budget.init(testing.allocator, default_params);
    defer budget.deinit();

    // Model: the caller rotates only on `.allow`; on `.defer_ms` the still
    // valid current credential is kept and the withheld rotation is refused.
    var credential_generation: u32 = 0;
    for (0..9) |i| {
        const now: i64 = @intCast(i);
        switch (budget.admitRotation("dave", now)) {
            .allow => {
                credential_generation += 1;
                try testing.expect(budget.noteRotation("dave", now));
            },
            .defer_ms => |ms| {
                try testing.expectEqual(@as(usize, 8), i);
                try testing.expectEqual(default_params.window_ms - now, ms);
                budget.noteRefused();
            },
        }
    }
    try testing.expectEqual(@as(u32, 8), credential_generation);
    const stats = budget.snapshot();
    try testing.expectEqual(@as(u64, 8), stats.rotations);
    try testing.expectEqual(@as(u64, 0), stats.rotations_over_budget);
    try testing.expectEqual(@as(u64, 1), stats.refused_over_budget);

    // Once the window elapses the held-off rotation is admitted.
    try testing.expectEqual(Admit.allow, budget.admitRotation("dave", default_params.window_ms));
}

test "session credential churn: counters saturate at maxInt(u64) without wrapping" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 1,
        .window_ms = 1000,
        .max_fresh_per_window = std.math.maxInt(u32),
        .max_rotations_per_window = std.math.maxInt(u32),
    });
    defer budget.deinit();

    budget.stats = .{
        .fresh_minted = std.math.maxInt(u64),
        .reused = std.math.maxInt(u64),
        .rotations = std.math.maxInt(u64),
        .rotations_over_budget = std.math.maxInt(u64),
        .refused_over_budget = std.math.maxInt(u64),
        .table_overflow = std.math.maxInt(u64),
    };

    budget.noteFresh("sat", 0);
    try testing.expect(budget.noteRotation("sat", 0));
    budget.noteReuse();
    budget.noteRefused();
    budget.noteFresh("other", 1); // over-capacity charge; "sat" stays live

    var stats = budget.snapshot();
    try testing.expectEqual(std.math.maxInt(u64), stats.fresh_minted);
    try testing.expectEqual(std.math.maxInt(u64), stats.reused);
    try testing.expectEqual(std.math.maxInt(u64), stats.rotations);
    try testing.expectEqual(std.math.maxInt(u64), stats.refused_over_budget);
    try testing.expectEqual(std.math.maxInt(u64), stats.table_overflow);

    // Per-slot counters saturate too; a rotation at the saturated cap is
    // over budget and its counter saturates as well.
    const idx = budget.findIndex(budget.foldKey("sat")).?;
    budget.slots[idx].fresh_count = std.math.maxInt(u32);
    budget.slots[idx].rotation_count = std.math.maxInt(u32);
    budget.noteFresh("sat", 2);
    try testing.expect(!budget.noteRotation("sat", 2));
    try testing.expectEqual(std.math.maxInt(u32), budget.slots[idx].fresh_count);
    try testing.expectEqual(std.math.maxInt(u32), budget.slots[idx].rotation_count);
    stats = budget.snapshot();
    try testing.expectEqual(std.math.maxInt(u64), stats.rotations);
    try testing.expectEqual(std.math.maxInt(u64), stats.rotations_over_budget);
}

test "session credential churn: a full table of live windows never evicts, charges the shared overflow window, and stays bounded under a 10k-account storm" {
    const capacity = 37;
    const overflow_fresh = 5;
    var budget = try Budget.init(testing.allocator, .{
        .capacity = capacity,
        // Every window stays live for the whole storm.
        .window_ms = 1_000_000,
        .max_fresh_per_window = 1,
        .max_rotations_per_window = 0,
        .overflow_fresh_per_window = overflow_fresh,
        .overflow_rotations_per_window = 0,
    });
    defer budget.deinit();

    const storm = 10_000;
    var buf: [32]u8 = undefined;
    var minted: u64 = 0;
    for (0..storm) |i| {
        const name = std.fmt.bufPrint(&buf, "acct-{d}", .{i}) catch unreachable;
        const now: i64 = @intCast(i);
        // A caller that obeys admission mints at most capacity * 1 tracked
        // plus overflow_fresh untracked credentials in one window.
        if (budget.admitFresh(name, now) == .allow) {
            budget.noteFresh(name, now);
            minted += 1;
        } else budget.noteRefused();
        try testing.expect(budget.len <= capacity);
    }
    try expectTableInvariant(&budget);
    try testing.expectEqual(@as(usize, capacity), budget.len);
    try testing.expectEqual(@as(u64, capacity + overflow_fresh), minted);
    try testing.expectEqual(@as(u64, overflow_fresh), budget.snapshot().table_overflow);
    try testing.expectEqual(@as(u64, storm - capacity - overflow_fresh), budget.snapshot().refused_over_budget);

    // The first `capacity` accounts were never displaced and stay spent.
    for (0..capacity) |i| {
        const name = std.fmt.bufPrint(&buf, "acct-{d}", .{i}) catch unreachable;
        try testing.expect(budget.findIndex(budget.foldKey(name)) != null);
        try testing.expect(budget.admitFresh(name, storm) == .defer_ms);
    }
}

test "session credential churn: a spent account stays spent when the table fills with live windows (T09 regression)" {
    const capacity = 4;
    var budget = try Budget.init(testing.allocator, .{
        .capacity = capacity,
        .window_ms = 60_000,
        .max_fresh_per_window = 8,
        .max_rotations_per_window = 2,
        .overflow_fresh_per_window = 3,
        .overflow_rotations_per_window = 1,
    });
    defer budget.deinit();

    // Account A spends its full fresh and rotation budget at t=0.
    for (0..8) |_| budget.noteFresh("victim-a", 0);
    try testing.expect(budget.noteRotation("victim-a", 0));
    try testing.expect(budget.noteRotation("victim-a", 0));
    try testing.expect(budget.admitFresh("victim-a", 0) == .defer_ms);

    // Other accounts fill the table in the same window, then many more
    // untracked accounts mint. Under the old oldest-touched eviction, A
    // was dropped here and regained 8 mints.
    var buf: [32]u8 = undefined;
    for (0..capacity - 1) |i| {
        const name = std.fmt.bufPrint(&buf, "fill-{d}", .{i}) catch unreachable;
        budget.noteFresh(name, 1);
    }
    for (0..100) |i| {
        const name = std.fmt.bufPrint(&buf, "storm-{d}", .{i}) catch unreachable;
        if (budget.admitFresh(name, 2) == .allow) budget.noteFresh(name, 2);
    }
    try testing.expectEqual(@as(u64, 3), budget.snapshot().table_overflow);
    try testing.expect(budget.findIndex(budget.foldKey("victim-a")) != null);
    try testing.expectEqual(Admit{ .defer_ms = 60_000 - 1000 }, budget.admitFresh("victim-a", 1000));
    try testing.expect(budget.admitRotation("victim-a", 1000) == .defer_ms);

    // Untracked accounts are now bounded by the spent shared window too.
    try testing.expect(budget.admitFresh("late-newcomer", 1000) == .defer_ms);
    try testing.expectEqual(Admit.allow, budget.admitRotation("late-newcomer", 1000));
    try testing.expect(budget.noteRotation("late-newcomer", 1000));
    try testing.expect(budget.admitRotation("late-other", 1000) == .defer_ms);
    // A raced rotation past the shared cap is still counted, never hidden.
    try testing.expect(!budget.noteRotation("late-other", 1000));
    try testing.expectEqual(@as(u64, 1), budget.snapshot().rotations_over_budget);

    // Once the windows elapse, A recovers its normal per-account allowance
    // exactly at the window boundary and a newcomer reclaims an elapsed slot.
    try testing.expectEqual(Admit.allow, budget.admitFresh("victim-a", 60_000));
    try testing.expectEqual(Admit.allow, budget.admitFresh("late-newcomer", 60_001));
    budget.noteFresh("late-newcomer", 60_001);
    try testing.expect(budget.findIndex(budget.foldKey("late-newcomer")) != null);
    try expectTableInvariant(&budget);
}

test "session credential churn: a full table reclaims an elapsed window, never evicts a live one, and counts only overflow charges" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 2,
        .window_ms = 1000,
        .max_fresh_per_window = 1,
        .max_rotations_per_window = 0,
    });
    defer budget.deinit();

    // "stale" was anchored at 0 and last touched at 999 (no reset); "live"
    // was anchored and touched at 500. At 1200 "live" is the oldest-touched
    // slot, but only "stale" has an elapsed window, so it is reclaimed.
    budget.noteFresh("stale", 0);
    budget.noteFresh("live", 500);
    budget.noteFresh("stale", 999);

    budget.noteFresh("newcomer", 1200);
    try testing.expectEqual(@as(u64, 0), budget.snapshot().table_overflow);
    try testing.expectEqual(@as(?usize, null), budget.findIndex(budget.foldKey("stale")));
    try testing.expect(budget.admitFresh("live", 1200) == .defer_ms);
    try testing.expect(budget.findIndex(budget.foldKey("newcomer")) != null);

    // With every window live, nothing is evicted: "third" is charged to the
    // shared over-capacity window and "live" keeps its spent budget.
    budget.noteFresh("third", 1300);
    try testing.expectEqual(@as(u64, 1), budget.snapshot().table_overflow);
    try testing.expect(budget.findIndex(budget.foldKey("live")) != null);
    try testing.expectEqual(@as(?usize, null), budget.findIndex(budget.foldKey("third")));
    try testing.expect(budget.admitFresh("live", 1300) == .defer_ms);
    try expectTableInvariant(&budget);
}

test "session credential churn: removal keeps colliding keys reachable so a spent budget never looks unseen" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 4,
        .window_ms = 100,
        .max_fresh_per_window = 1,
        .max_rotations_per_window = 0,
    });
    defer budget.deinit();
    budget.key = @splat(0x5a);

    // Find three names sharing one home slot so they form a probe chain.
    var names: [3][16]u8 = undefined;
    var lens: [3]usize = undefined;
    var found: usize = 0;
    var target_home: ?usize = null;
    var n: usize = 0;
    while (found < names.len) : (n += 1) {
        const name = std.fmt.bufPrint(&names[found], "c{d}", .{n}) catch unreachable;
        const h = budget.home(budget.foldKey(name));
        if (target_home == null) target_home = h;
        if (h != target_home.?) continue;
        lens[found] = name.len;
        found += 1;
    }
    const a = names[0][0..lens[0]];
    const b = names[1][0..lens[1]];
    const c = names[2][0..lens[2]];

    budget.noteFresh(a, 0);
    budget.noteFresh(b, 50);
    budget.noteFresh(c, 60);
    try expectTableInvariant(&budget);

    // Only `a` (head of the chain) has an elapsed window at 120.
    budget.prune(120);
    try testing.expectEqual(@as(usize, 2), budget.len);
    try expectTableInvariant(&budget);
    try testing.expect(budget.admitFresh(b, 120) == .defer_ms);
    try testing.expect(budget.admitFresh(c, 120) == .defer_ms);

    // Re-noting `c` must hit its existing slot, never create a duplicate.
    budget.noteFresh(c, 121);
    try testing.expectEqual(@as(usize, 2), budget.len);
    try expectTableInvariant(&budget);
}

test "session credential churn: randomized operations match a reference model and keep the probe invariant" {
    const pool = [_][]const u8{ "a", "B", "c", "D", "e", "F", "g", "H", "i", "J", "k", "L" };
    inline for (.{ 0x7091, 0xC0FFEE, 0xDEADBEEF }) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        var budget = try Budget.init(testing.allocator, .{
            .capacity = 5,
            .window_ms = 40,
            .max_fresh_per_window = 2,
            .max_rotations_per_window = 1,
            .overflow_fresh_per_window = 3,
            .overflow_rotations_per_window = 2,
        });
        defer budget.deinit();
        budget.key = @splat(@truncate(seed));

        const Entry = struct { name: u8, start: i64, fresh: u32, rot: u32, touched: i64 };
        var model: [5]Entry = undefined;
        var model_len: usize = 0;
        // Shared over-capacity window; `name` is unused.
        var overflow: Entry = .{ .name = 0, .start = 0, .fresh = 0, .rot = 0, .touched = 0 };
        var model_overflow: u64 = 0;
        var model_rotations: u64 = 0;
        var model_over: u64 = 0;
        var now: i64 = 0;

        for (0..4000) |_| {
            now += random.intRangeAtMost(i64, 1, 7);
            const who: u8 = random.uintLessThan(u8, pool.len);
            // Model lookup (ASCII fold: pool names differ beyond case).
            var at: ?usize = null;
            for (model[0..model_len], 0..) |e, i| {
                if (e.name == who) at = i;
            }
            const elapsed = struct {
                fn f(e: Entry, t: i64) bool {
                    return t - e.start >= 40;
                }
            }.f;
            var victim: ?usize = null;
            if (model_len == 5) {
                for (model[0..model_len], 0..) |e, k| {
                    if (elapsed(e, now) and (victim == null or e.touched < model[victim.?].touched)) victim = k;
                }
            }
            const to_overflow = at == null and model_len == 5 and victim == null;
            switch (random.uintLessThan(u8, 4)) {
                0 => {
                    const expect_fresh = if (at) |i|
                        elapsed(model[i], now) or model[i].fresh < 2
                    else if (to_overflow) elapsed(overflow, now) or overflow.fresh < 3 else true;
                    try testing.expectEqual(expect_fresh, budget.admitFresh(pool[who], now) == .allow);
                    const expect_rot = if (at) |i|
                        elapsed(model[i], now) or model[i].rot < 1
                    else if (to_overflow) elapsed(overflow, now) or overflow.rot < 2 else true;
                    try testing.expectEqual(expect_rot, budget.admitRotation(pool[who], now) == .allow);
                },
                1, 2 => {
                    const is_fresh = random.boolean();
                    const e: *Entry = if (at) |i| &model[i] else if (to_overflow) blk: {
                        model_overflow += 1;
                        break :blk &overflow;
                    } else blk: {
                        if (victim) |v| {
                            model[v] = model[model_len - 1];
                            model_len -= 1;
                        }
                        model[model_len] = .{ .name = who, .start = now, .fresh = 0, .rot = 0, .touched = now };
                        model_len += 1;
                        break :blk &model[model_len - 1];
                    };
                    const rot_cap: u32 = if (to_overflow) 2 else 1;
                    if (elapsed(e.*, now)) e.* = .{ .name = e.name, .start = now, .fresh = 0, .rot = 0, .touched = now };
                    e.touched = now;
                    if (is_fresh) {
                        e.fresh += 1;
                        budget.noteFresh(pool[who], now);
                    } else {
                        const ok = e.rot < rot_cap;
                        e.rot += 1;
                        model_rotations += 1;
                        if (!ok) model_over += 1;
                        try testing.expectEqual(ok, budget.noteRotation(pool[who], now));
                    }
                },
                else => {
                    budget.prune(now);
                    var k: usize = 0;
                    while (k < model_len) {
                        if (elapsed(model[k], now)) {
                            model[k] = model[model_len - 1];
                            model_len -= 1;
                        } else k += 1;
                    }
                },
            }
            try testing.expectEqual(model_len, budget.len);
            try testing.expectEqual(model_overflow, budget.snapshot().table_overflow);
            try testing.expectEqual(model_rotations, budget.snapshot().rotations);
            try testing.expectEqual(model_over, budget.snapshot().rotations_over_budget);
            try testing.expectEqual(@as(u64, 0), budget.snapshot().refused_over_budget);
            try expectTableInvariant(&budget);
        }
    }
}

test "session credential churn: account keys are case-folded so ALICE and alice share one budget" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 8,
        .window_ms = 1000,
        .max_fresh_per_window = 2,
        .max_rotations_per_window = 0,
    });
    defer budget.deinit();

    budget.noteFresh("ALICE", 0);
    try testing.expectEqual(Admit.allow, budget.admitFresh("alice", 0));
    budget.noteFresh("Alice", 0);
    try testing.expectEqual(Admit{ .defer_ms = 1000 }, budget.admitFresh("aLiCe", 0));
    try testing.expectEqual(@as(usize, 1), budget.len);

    // Folding spans the stack chunk boundary for long names.
    const long_upper: [200]u8 = @splat('X');
    const long_lower: [200]u8 = @splat('x');
    try testing.expectEqual(budget.foldKey(&long_upper), budget.foldKey(&long_lower));
    try testing.expect(budget.foldKey(&long_lower) != budget.foldKey(long_lower[0..199]));
    // Only ASCII is folded; distinct non-ASCII bytes stay distinct budgets.
    try testing.expect(budget.foldKey("\xc3\x89") != budget.foldKey("\xc3\xa9"));
}

test "session credential churn: init rejects invalid params without allocating" {
    const bad = [_]Params{
        .{ .capacity = 0, .window_ms = 1, .max_fresh_per_window = 1, .max_rotations_per_window = 1 },
        .{ .capacity = 1, .window_ms = 0, .max_fresh_per_window = 1, .max_rotations_per_window = 1 },
        .{ .capacity = 1, .window_ms = -5, .max_fresh_per_window = 1, .max_rotations_per_window = 1 },
        .{ .capacity = std.math.maxInt(usize), .window_ms = 1, .max_fresh_per_window = 1, .max_rotations_per_window = 1 },
        .{ .capacity = std.math.maxInt(usize) / 4 + 2, .window_ms = 1, .max_fresh_per_window = 1, .max_rotations_per_window = 1 },
    };
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    for (bad) |params| {
        try testing.expectError(error.InvalidChurnParams, Budget.init(failing.allocator(), params));
    }
    try testing.expectEqual(@as(usize, 0), failing.allocations);

    var budget = try Budget.init(testing.allocator, default_params);
    defer budget.deinit();
    try testing.expect(budget.slots.len >= 2 * default_params.capacity);
    try testing.expect(std.math.isPowerOfTwo(budget.slots.len));
}

test "session credential churn: renderPrometheus emits all six _total series and returns NoSpaceLeft on a short buffer" {
    const stats = ChurnStats{
        .fresh_minted = 1,
        .reused = 2,
        .rotations = 3,
        .rotations_over_budget = 4,
        .refused_over_budget = 5,
        .table_overflow = 6,
    };
    var out: [2048]u8 = undefined;
    const text = try renderPrometheus(&out, stats);
    const names = [_][]const u8{
        "onyx_session_credential_fresh_minted_total",
        "onyx_session_credential_reused_total",
        "onyx_session_credential_rotations_total",
        "onyx_session_credential_rotations_over_budget_total",
        "onyx_session_credential_refused_over_budget_total",
        "onyx_session_credential_table_overflow_total",
    };
    var line: [128]u8 = undefined;
    for (names, 1..) |name, value| {
        try testing.expect(std.mem.indexOf(u8, text, try std.fmt.bufPrint(&line, "# HELP {s} ", .{name})) != null);
        try testing.expect(std.mem.indexOf(u8, text, try std.fmt.bufPrint(&line, "# TYPE {s} counter\n", .{name})) != null);
        try testing.expect(std.mem.indexOf(u8, text, try std.fmt.bufPrint(&line, "\n{s} {d}\n", .{ name, value })) != null);
    }
    try testing.expectEqual(@as(usize, 18), std.mem.count(u8, text, "\n"));

    try testing.expectError(error.NoSpaceLeft, renderPrometheus(out[0..4], stats));
    try testing.expectError(error.NoSpaceLeft, renderPrometheus(out[0 .. text.len - 1], stats));
    try testing.expectEqualStrings(text, try renderPrometheus(out[0..text.len], stats));
}

test "session credential churn: reconnect storm simulation (N reconnects with valid credential) yields fresh_minted == 1 and reused == N-1" {
    var budget = try Budget.init(testing.allocator, .{
        .capacity = 8,
        .window_ms = 60_000,
        .max_fresh_per_window = 4,
        .max_rotations_per_window = 4,
    });
    defer budget.deinit();

    const n_reconnects = 500;
    var now: i64 = 0;
    var has_row = false;
    for (0..n_reconnects) |_| {
        now += 1;
        // Only the first connection lacks a credential and a row; every later
        // reconnect presents the credential minted then.
        const presented: Presented = if (has_row) .valid_exact else .none;
        switch (classify(presented, .unproven)) {
            .mint_fresh => {
                try testing.expectEqual(Admit.allow, budget.admitFresh("storm-account", now));
                budget.noteFresh("storm-account", now);
                has_row = true;
            },
            .reuse_existing => budget.noteReuse(),
            .reject => return error.TestUnexpectedResult,
        }
    }

    const stats = budget.snapshot();
    try testing.expectEqual(@as(u64, 1), stats.fresh_minted);
    try testing.expectEqual(@as(u64, n_reconnects - 1), stats.reused);
    try testing.expectEqual(@as(u64, 0), stats.rotations);
}

test "session credential churn: init allocation failures leave nothing to clean up" {
    const Run = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var budget = try Budget.init(allocator, .{
                .capacity = 16,
                .window_ms = 1000,
                .max_fresh_per_window = 1,
                .max_rotations_per_window = 1,
            });
            defer budget.deinit();
            budget.noteFresh("acct", 0);
            try testing.expectEqual(@as(u64, 1), budget.snapshot().fresh_minted);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Run.run, .{});
}

test "session credential churn: prune drops only elapsed windows and is observably equivalent to not pruning" {
    var pruned = try Budget.init(testing.allocator, .{
        .capacity = 4,
        .window_ms = 100,
        .max_fresh_per_window = 1,
        .max_rotations_per_window = 0,
    });
    defer pruned.deinit();
    var plain = try Budget.init(testing.allocator, pruned.params);
    defer plain.deinit();
    plain.key = pruned.key;

    for ([_]*Budget{ &pruned, &plain }) |b| {
        b.noteFresh("stale", 0);
        b.noteFresh("live", 50);
    }

    pruned.prune(99); // window not yet elapsed: retained
    try testing.expect(pruned.findIndex(pruned.foldKey("stale")) != null);

    pruned.prune(100); // stale window [0, 100) elapsed; live [50, 150) not
    try testing.expectEqual(@as(?usize, null), pruned.findIndex(pruned.foldKey("stale")));
    try testing.expect(pruned.findIndex(pruned.foldKey("live")) != null);
    try expectTableInvariant(&pruned);

    for ([_][]const u8{ "stale", "live" }) |name| {
        try testing.expectEqual(plain.admitFresh(name, 100), pruned.admitFresh(name, 100));
    }
}
