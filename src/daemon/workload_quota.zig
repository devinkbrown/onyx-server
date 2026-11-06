// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Workload-aware admission and recovery quota governor.
//!
//! This module is pure, deterministic and allocation-free: callers supply
//! time in milliseconds, the governor reads no clock and performs no I/O,
//! and all state lives in fixed-size arrays bounded by `max_pool_capacity`.
//! `Governor` is large (~210 KiB), so it is initialised in place
//! (`Governor.init(self, config)`) and should be embedded in a
//! heap-resident owner rather than returned through reactor stacks.
//!
//! ## Problem
//!
//! A single per-shard `clients.len() >= max_clients` cap treats a brand new
//! client connection and a mesh redial that is trying to recover a
//! partitioned link identically. A client reconnect storm can fill every
//! slot, after which mesh redials fail (`SocketUnavailable`) and recovery
//! starves. Nothing bounds concurrent handshake/verification work (TLS,
//! Mooring AKE, session-resume token verification) across classes either.
//!
//! ## Model
//!
//! Three work classes:
//!   - `client_admission` — new, unregistered client connections/handshakes.
//!   - `session_recovery` — RESUME/reclaim token verification.
//!   - `mesh_recovery` — outbound redials, inbound S2S accept + AKE, and
//!     inherited redials.
//!
//! Two pooled resources, each tracked per class with a generation-checked
//! ticket per in-flight unit:
//!   - `slot` — connection slots, capacity = `max_clients` for the shard.
//!   - `verify` — in-flight verification slots, capacity = `verify_slots`.
//!
//! Static guarantees per resource, with capacity `C`, recovery reserve `R`,
//! mesh sub-reserve `Rm` (`1 <= Rm < R`) and admission floor `F`
//! (`F <= C - R`):
//!   - `client_admission` never holds more than `C - R` units, so the
//!     recovery reserve is never consumed by admission.
//!   - `client_admission + session_recovery` never hold more than `C - Rm`
//!     units, and `mesh_recovery` may always take units while it holds
//!     fewer than `Rm` (independent of the adaptive recovery share), so a
//!     RESUME storm can never starve mesh link recovery.
//!   - `Rm < R`, so `session_recovery` always keeps at least `R - Rm`
//!     units of its own, even on an idle pool with no recovery backlog.
//!   - `session_recovery + mesh_recovery` never hold more than `C - F`
//!     units, so admission is never starved below its floor.
//!   - A per-(class, peer) cap (`max_recovery_inflight_per_peer`) stops one
//!     flapping peer from consuming every recovery/verification unit. The
//!     peer table holds one row per distinct in-flight (class, peer), so it
//!     can never fill while the pool still has a free unit.
//!
//! `observe()` applies an AIMD rule once per sweep tick: under pressure
//! (high occupancy, high verify queue, high p99 admit latency, or a
//! recovery backlog that actually contended for capacity since the last
//! tick) `admission_share` shrinks multiplicatively down to `F`; otherwise
//! it grows additively back toward `C - R`. A backlog alone (e.g. one
//! configured peer that is simply down) is not pressure: only a recovery
//! acquire refused for `.reserve`/`.class_share` proves recovery competes
//! with admission for units. `recovery_share` rises with backlog but is
//! clamped to `[R, C - F]`.
//!
//! ## Rate limits
//!
//! A per-class `Gcra` (see `substrate/gcra.zig`) bounds each class's total
//! rate; under admission pressure the cost charged per admission rises, so
//! the effective admission rate shrinks together with its share. Init
//! rejects an admission burst that could never cover the maximum pressured
//! cost, so admission is throttled but never permanently zero.
//!
//! Recovery classes are also rate-limited per (class, peer_key), and each
//! per-peer rate/burst must be strictly below its class rate/burst, so one
//! churning key (acquire, fail fast, release) exhausts only its own bucket
//! and can never drain the class budget. `mesh_recovery` grants inside the
//! mesh sub-reserve (`used < Rm`) skip the class GCRA and are bounded only
//! by their own per-peer bucket: the sub-reserve guarantees rate as well as
//! concurrency, so neither a flapping peer nor a flood of unidentified
//! inbound attempts can starve a healthy peer's redial. Inbound S2S
//! attempts are keyed by their kernel source address before the AKE; only
//! an attempt whose address cannot be read shares `unidentified_peer_key`
//! and therefore one bucket. The daemon closes an inbound handshake that
//! has not established within its deadline, so idle sockets cannot hold
//! units indefinitely. Per-peer rows outlive their tickets until the bucket is idle;
//! the class GCRA bounds how many rows it can keep busy (validated against
//! half the table), the other half is headroom for distinct identified
//! peers granted inside the mesh sub-reserve, and a full table of busy rows
//! refuses a new key (`.rate`) rather than forgetting another key's state.
//!
//! Session-recovery keys should identify the request source (for example a
//! client address bucket), not the presented token: freshly minted keys
//! each get a fresh bucket and are bounded only by the class GCRA, which is
//! the intended aggregate CPU bound for unauthenticated verification work.

const std = @import("std");
const Gcra = @import("../substrate/gcra.zig").Gcra;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Work classes tracked by the governor.
pub const Class = enum(u2) {
    client_admission,
    session_recovery,
    mesh_recovery,
};

/// Pooled resources each class draws from.
pub const Resource = enum(u1) {
    slot,
    verify,
};

/// Why a `tryAcquire` was refused.
pub const RefusalReason = enum(u8) {
    /// The remaining units are reserved for a higher-priority class: the
    /// recovery reserve (for `client_admission`) or the mesh sub-reserve
    /// (for `client_admission`/`session_recovery`), or the pool is full.
    reserve,
    /// The class's own adaptive share (shrunk by AIMD, or recovery's
    /// backlog-driven share) was exhausted.
    class_share,
    /// The requesting (class, peer) already holds
    /// `max_recovery_inflight_per_peer` in-flight tickets for this resource.
    per_peer,
    /// The class's GCRA rate limiter has no budget left.
    rate,
};

pub const Refusal = struct {
    reason: RefusalReason,
    /// Milliseconds until a retry might succeed. Only `.rate` refusals carry
    /// a meaningful (GCRA-derived) wait; every other reason is zero because
    /// the right time to retry is "after the next `release` or `observe`",
    /// not a fixed clock offset.
    retry_after_ms: u64,
};

/// A generation-checked claim on one unit of a pooled resource.
///
/// `index` identifies the slot record backing this ticket; `generation` is
/// bumped by the governor every time that record transitions from free to
/// in-use, so a stale or already-released ticket can never affect the
/// record a later ticket now owns.
pub const Ticket = struct {
    class: Class,
    resource: Resource,
    index: u32,
    generation: u32,
};

pub const Decision = union(enum) {
    granted: Ticket,
    refused: Refusal,
};

/// Load signal fed to `observe()` once per sweep tick.
pub const Load = struct {
    /// Current connection occupancy (e.g. `clients.len()`).
    occupancy: u32,
    /// Outstanding recovery work (mesh dials not yet linked, remaining
    /// inherited redials, ...). Grows `recovery_share`; counts as admission
    /// pressure only when some recovery acquire was refused for `.reserve`
    /// or `.class_share` since the previous `observe()`.
    recovery_backlog: u32,
    /// Pending verification work queued behind the in-flight `verify` pool.
    verify_queue: u32,
    /// p99 admission latency observed this tick, in milliseconds.
    p99_admit_latency_ms: u64,
};

pub const ConfigError = error{
    ZeroCapacity,
    CapacityTooLarge,
    /// A zero recovery reserve would let a client storm starve recovery.
    ZeroReserve,
    ReserveExceedsCapacity,
    /// `mesh_reserve_*` must be in `[1, recovery_reserve_*)`: an equal value
    /// would leave `session_recovery` no units on an idle pool.
    InvalidMeshReserve,
    ZeroFloor,
    FloorExceedsShareCeiling,
    ZeroPerPeerCap,
    ZeroRate,
    ZeroBurst,
    InvalidPercent,
    /// `admission_burst` is smaller than the highest cost `gcraCost()` can
    /// ever charge `client_admission` (`1 + max_pressure_steps`). GCRA
    /// refuses any cost greater than its burst for every `now_us`, so a
    /// smaller burst would let sustained pressure drive admission to
    /// permanent zero instead of merely throttling it.
    AdmissionBurstBelowPressureCeiling,
    /// A recovery per-peer rate must be strictly below its class rate, so
    /// one churning key can never consume the whole class budget.
    PeerRateNotBelowClassRate,
    /// A recovery per-peer burst must be strictly below its class burst.
    PeerBurstNotBelowClassBurst,
    /// The class GCRA could keep more per-peer rows busy than
    /// `gated_rate_rows`, which could exhaust the per-peer row table.
    RecoveryRateRowsExceeded,
};

pub const Config = struct {
    /// Total connection slots for this shard (== `max_clients`).
    capacity: u32,
    /// Total in-flight verification slots for this shard.
    verify_slots: u32,

    /// Connection slots only `session_recovery`/`mesh_recovery` may use.
    recovery_reserve_slots: u32,
    /// Verification slots only `session_recovery`/`mesh_recovery` may use.
    recovery_reserve_verify: u32,
    /// Part of `recovery_reserve_slots` only `mesh_recovery` may use.
    mesh_reserve_slots: u32,
    /// Part of `recovery_reserve_verify` only `mesh_recovery` may use.
    mesh_reserve_verify: u32,

    /// Minimum connection-slot share `client_admission` always keeps.
    admission_floor_slots: u32,
    /// Minimum verify-slot share `client_admission` always keeps.
    admission_floor_verify: u32,

    /// Per-(class, peer) concurrent in-flight cap for `session_recovery`/
    /// `mesh_recovery` acquisitions, keyed by an opaque `u64` peer key.
    max_recovery_inflight_per_peer: u32,

    admission_rate_per_sec: u64,
    admission_burst: u64,
    session_recovery_rate_per_sec: u64,
    session_recovery_burst: u64,
    mesh_recovery_rate_per_sec: u64,
    mesh_recovery_burst: u64,

    /// Per-(class, peer_key) GCRA for `session_recovery`; strictly below the
    /// class rate/burst.
    session_recovery_peer_rate_per_sec: u64,
    session_recovery_peer_burst: u64,
    /// Per-(class, peer_key) GCRA for `mesh_recovery`; strictly below the
    /// class rate/burst.
    mesh_recovery_peer_rate_per_sec: u64,
    mesh_recovery_peer_burst: u64,

    /// Multiplicative shrink factor (percent, 1-100) applied to the
    /// admission share each pressured `observe()` tick.
    shrink_percent: u32 = 50,
    /// Additive growth factor (percent of the admission ceiling, 1-100,
    /// at least 1 unit) applied to the admission share each idle tick.
    grow_percent: u32 = 10,
    /// How many extra shared units the recovery share gains per unit of
    /// `recovery_backlog`.
    recovery_growth_per_backlog_unit: u32 = 1,
    /// Occupancy percent (of `capacity`) at/above which admission is
    /// considered to be under pressure (1-100).
    occupancy_pressure_target_percent: u32 = 80,
    /// Verify-queue percent (of `verify_slots`) at/above which admission is
    /// considered to be under pressure (1-100).
    verify_pressure_target_percent: u32 = 80,
    /// p99 admit latency, in milliseconds, at/above which admission is
    /// considered to be under pressure. Zero disables this signal.
    admit_latency_pressure_ms: u64 = 0,
};

pub const ResourceSnapshot = struct {
    capacity: u32,
    reserve: u32,
    mesh_reserve: u32,
    admission_share: u32,
    recovery_share: u32,
    used_client_admission: u32,
    used_session_recovery: u32,
    used_mesh_recovery: u32,
    used_total: u32,
};

pub const Snapshot = struct {
    slots: ResourceSnapshot,
    verify: ResourceSnapshot,
    grants_total: u64,
    refusals_total: u64,
    releases_total: u64,
    refusals_reserve: u64,
    refusals_class_share: u64,
    refusals_per_peer: u64,
    refusals_rate: u64,
    admission_pressure_steps: u32,
};

/// Fixed array bound for both the `slot` and `verify` pools. Runtime
/// capacity is validated against this bound by `validateConfig`, which
/// keeps the governor allocation-free.
pub const max_pool_capacity: u32 = 2048;

/// Ceiling on the admission GCRA cost multiplier applied under sustained
/// pressure.
const max_pressure_steps: u32 = 8;

/// Per-recovery-class bound on per-peer rate rows.
pub const max_rate_rows: u32 = 1024;

/// How many rows the class GCRA may keep busy at once (validated); the rest
/// of `max_rate_rows` is headroom for identified peers granted inside the
/// mesh sub-reserve, which bypass the class GCRA.
pub const gated_rate_rows: u32 = max_rate_rows / 2;

/// `mesh_recovery` key for inbound S2S attempts with no attributable
/// identity yet. All such attempts share one per-peer bucket and one
/// per-peer in-flight cap, so they cannot spend identified peers' budgets.
pub const unidentified_peer_key: u64 = 0;

/// Validate `config` without constructing a governor. Config loading should
/// call this so an invalid quota fails `--check-config` rather than boot.
pub fn validateConfig(config: Config) ConfigError!void {
    try validatePool(config.capacity, config.recovery_reserve_slots, config.mesh_reserve_slots, config.admission_floor_slots);
    try validatePool(config.verify_slots, config.recovery_reserve_verify, config.mesh_reserve_verify, config.admission_floor_verify);
    if (config.max_recovery_inflight_per_peer == 0) return error.ZeroPerPeerCap;
    if (config.admission_rate_per_sec == 0 or config.session_recovery_rate_per_sec == 0 or
        config.mesh_recovery_rate_per_sec == 0) return error.ZeroRate;
    if (config.admission_burst == 0 or config.session_recovery_burst == 0 or
        config.mesh_recovery_burst == 0) return error.ZeroBurst;
    if (config.admission_burst < 1 + max_pressure_steps) return error.AdmissionBurstBelowPressureCeiling;
    try validatePeerRate(config.session_recovery_rate_per_sec, config.session_recovery_burst, config.session_recovery_peer_rate_per_sec, config.session_recovery_peer_burst);
    try validatePeerRate(config.mesh_recovery_rate_per_sec, config.mesh_recovery_burst, config.mesh_recovery_peer_rate_per_sec, config.mesh_recovery_peer_burst);
    try validatePercent(config.shrink_percent);
    try validatePercent(config.grow_percent);
    try validatePercent(config.occupancy_pressure_target_percent);
    try validatePercent(config.verify_pressure_target_percent);
}

fn validatePool(capacity: u32, reserve: u32, mesh_reserve: u32, floor: u32) ConfigError!void {
    if (capacity == 0) return error.ZeroCapacity;
    if (capacity > max_pool_capacity) return error.CapacityTooLarge;
    if (reserve == 0) return error.ZeroReserve;
    if (reserve >= capacity) return error.ReserveExceedsCapacity;
    if (mesh_reserve == 0 or mesh_reserve >= reserve) return error.InvalidMeshReserve;
    if (floor == 0) return error.ZeroFloor;
    if (floor > capacity - reserve) return error.FloorExceedsShareCeiling;
}

/// Requires the class rate/burst to be non-zero (checked by the caller).
fn validatePeerRate(rate: u64, burst: u64, peer_rate: u64, peer_burst: u64) ConfigError!void {
    if (peer_rate == 0) return error.ZeroRate;
    if (peer_burst == 0) return error.ZeroBurst;
    if (peer_rate >= rate) return error.PeerRateNotBelowClassRate;
    if (peer_burst >= burst) return error.PeerBurstNotBelowClassBurst;
    // A charge leaves a per-peer bucket busy for at most
    // `peer_burst / peer_rate` seconds; in any window that long the class
    // GCRA admits at most `burst + rate * window` charges.
    const window_rows = (@as(u128, rate) * peer_burst + peer_rate - 1) / peer_rate;
    if (@as(u128, burst) + window_rows > gated_rate_rows) return error.RecoveryRateRowsExceeded;
}

fn validatePercent(percent: u32) ConfigError!void {
    if (percent == 0 or percent > 100) return error.InvalidPercent;
}

// ---------------------------------------------------------------------------
// Operator overrides (`[quota]`) and the derived defaults
// ---------------------------------------------------------------------------

/// Explicit operator settings for one shard's governor (`[quota]` in the
/// daemon config). Every null field takes the value derived from
/// `max_clients` (see `resolve`). The verify pool mirrors the slot pool, as
/// the derived defaults always have.
pub const Overrides = struct {
    /// `false` turns the governor off for every shard. Explicit fields are
    /// then a contradiction and `resolve` refuses them.
    enabled: bool = true,
    recovery_reserve_slots: ?u32 = null,
    mesh_reserve_slots: ?u32 = null,
    admission_floor_slots: ?u32 = null,
    max_recovery_inflight_per_peer: ?u32 = null,
    admission_rate_per_sec: ?u64 = null,
    admission_burst: ?u64 = null,
    session_recovery_rate_per_sec: ?u64 = null,
    session_recovery_burst: ?u64 = null,
    session_recovery_peer_rate_per_sec: ?u64 = null,
    session_recovery_peer_burst: ?u64 = null,
    mesh_recovery_rate_per_sec: ?u64 = null,
    mesh_recovery_burst: ?u64 = null,
    mesh_recovery_peer_rate_per_sec: ?u64 = null,
    mesh_recovery_peer_burst: ?u64 = null,

    /// True when any quota value was set explicitly.
    pub fn anyExplicit(self: Overrides) bool {
        inline for (@typeInfo(Overrides).@"struct".field_names) |name| {
            if (comptime std.mem.eql(u8, name, "enabled")) continue;
            if (@field(self, name) != null) return true;
        }
        return false;
    }
};

pub const ResolveError = ConfigError || error{
    /// `enabled = false` together with explicit quota values.
    ExplicitFieldsWhileDisabled,
};

/// Why a shard runs without a governor.
pub const DisabledReason = enum {
    /// `[quota] enabled = false`.
    operator_disabled,
    /// No explicit values and `max_clients` is too small for the derived
    /// recovery reserve (at most 4 slots). Reported as a warning by
    /// `--check-config`; explicit values on such a table are refused instead.
    table_too_small,
};

pub const Resolution = union(enum) {
    enabled: Config,
    disabled: DisabledReason,
};

/// Derived defaults: a recovery reserve of 1/32 of the table (at least 4),
/// half of it kept for mesh recovery, and an admission floor of a quarter of
/// the admission ceiling.
pub const derived_min_reserve: u32 = 4;

/// The governor configuration for one shard of `max_clients` slots under
/// `overrides`. Fails closed: any explicit value that does not validate is
/// an error, never a silently disabled governor. Only an explicit
/// `enabled = false` or an override-free table too small for the derived
/// reserve resolves to `.disabled`, and both name their reason.
pub fn resolve(max_clients: u32, overrides: Overrides) ResolveError!Resolution {
    const explicit = overrides.anyExplicit();
    if (!overrides.enabled) {
        if (explicit) return error.ExplicitFieldsWhileDisabled;
        return .{ .disabled = .operator_disabled };
    }
    const capacity: u32 = @min(max_clients, max_pool_capacity);
    const derived_reserve: u32 = @max(derived_min_reserve, capacity / 32);
    if (!explicit and capacity <= derived_reserve) return .{ .disabled = .table_too_small };
    const reserve = overrides.recovery_reserve_slots orelse derived_reserve;
    const mesh_reserve = overrides.mesh_reserve_slots orelse reserve / 2;
    const floor = overrides.admission_floor_slots orelse @max(1, (capacity -| reserve) / 4);
    const config: Config = .{
        .capacity = capacity,
        .verify_slots = capacity,
        .recovery_reserve_slots = reserve,
        .recovery_reserve_verify = reserve,
        .mesh_reserve_slots = mesh_reserve,
        .mesh_reserve_verify = mesh_reserve,
        .admission_floor_slots = floor,
        .admission_floor_verify = floor,
        .max_recovery_inflight_per_peer = overrides.max_recovery_inflight_per_peer orelse @max(1, mesh_reserve),
        .admission_rate_per_sec = overrides.admission_rate_per_sec orelse 1024,
        .admission_burst = overrides.admission_burst orelse 1024,
        .session_recovery_rate_per_sec = overrides.session_recovery_rate_per_sec orelse 128,
        .session_recovery_burst = overrides.session_recovery_burst orelse 256,
        .session_recovery_peer_rate_per_sec = overrides.session_recovery_peer_rate_per_sec orelse 64,
        .session_recovery_peer_burst = overrides.session_recovery_peer_burst orelse 128,
        .mesh_recovery_rate_per_sec = overrides.mesh_recovery_rate_per_sec orelse 128,
        .mesh_recovery_burst = overrides.mesh_recovery_burst orelse 256,
        .mesh_recovery_peer_rate_per_sec = overrides.mesh_recovery_peer_rate_per_sec orelse 64,
        .mesh_recovery_peer_burst = overrides.mesh_recovery_peer_burst orelse 128,
    };
    try validateConfig(config);
    return .{ .enabled = config };
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

const SlotRecord = struct {
    generation: u32,
    in_use: bool,
    class: Class,
    /// Per-peer key; tracked only for recovery classes.
    peer_key: u64,
};

/// One row per distinct (class, peer_key) holding at least one in-flight
/// recovery ticket. Rows are dense in `Pool.peers[0..peer_len]` and are
/// swap-removed when their count reaches zero, so `peer_len` never exceeds
/// the number of in-flight recovery tickets (`< capacity`).
const PeerEntry = struct {
    peer_key: u64,
    count: u32,
    class: Class,
};

fn classIndex(class: Class) usize {
    return @backingInt(class);
}

const Pool = struct {
    capacity: u32,
    reserve: u32,
    mesh_reserve: u32,
    max_admission_ceiling: u32,
    max_recovery_ceiling: u32,
    admission_share: u32,
    recovery_share: u32,
    used_by_class: [3]u32,
    free_top: u32,
    peer_len: u32,
    /// Only `[0..capacity]` is initialised and ever read.
    records: [max_pool_capacity]SlotRecord,
    /// Only `[0..free_top]` is meaningful.
    free_stack: [max_pool_capacity]u32,
    /// Only `[0..peer_len]` is meaningful.
    peers: [max_pool_capacity]PeerEntry,

    fn init(pool: *Pool, capacity: u32, reserve: u32, mesh_reserve: u32, admission_floor: u32) void {
        pool.capacity = capacity;
        pool.reserve = reserve;
        pool.mesh_reserve = mesh_reserve;
        pool.max_admission_ceiling = capacity - reserve;
        pool.max_recovery_ceiling = capacity - admission_floor;
        pool.admission_share = capacity - reserve;
        pool.recovery_share = reserve;
        pool.used_by_class = .{ 0, 0, 0 };
        pool.free_top = capacity;
        pool.peer_len = 0;
        for (pool.records[0..capacity], pool.free_stack[0..capacity], 0..) |*rec, *free, i| {
            rec.* = .{ .generation = 0, .in_use = false, .class = .client_admission, .peer_key = 0 };
            free.* = @intCast(i);
        }
    }

    fn used(self: *const Pool, class: Class) u32 {
        return self.used_by_class[classIndex(class)];
    }

    fn usedTotal(self: *const Pool) u32 {
        return self.used_by_class[0] + self.used_by_class[1] + self.used_by_class[2];
    }

    fn recoveryUsed(self: *const Pool) u32 {
        return self.used(.session_recovery) + self.used(.mesh_recovery);
    }

    fn peerIndex(self: *const Pool, class: Class, peer_key: u64) ?u32 {
        for (self.peers[0..self.peer_len], 0..) |p, i| {
            if (p.class == class and p.peer_key == peer_key) return @intCast(i);
        }
        return null;
    }

    fn peerRelease(self: *Pool, class: Class, peer_key: u64) void {
        const i = self.peerIndex(class, peer_key) orelse return;
        const row = &self.peers[i];
        row.count -= 1;
        if (row.count == 0) {
            self.peer_len -= 1;
            self.peers[i] = self.peers[self.peer_len];
        }
    }

    /// Returns the refusal reason the pool-level share/reserve rules impose
    /// on one more `class` unit, or `null` when the unit fits.
    fn ceilingRefusal(self: *const Pool, class: Class) ?RefusalReason {
        if (self.usedTotal() >= self.capacity) {
            return if (class == .mesh_recovery) .class_share else .reserve;
        }
        const non_mesh = self.used(.client_admission) + self.used(.session_recovery);
        switch (class) {
            .client_admission => {
                if (self.used(.client_admission) >= self.admission_share) {
                    return if (self.admission_share < self.max_admission_ceiling) .class_share else .reserve;
                }
                if (non_mesh >= self.capacity - self.mesh_reserve) return .reserve;
            },
            .session_recovery => {
                if (non_mesh >= self.capacity - self.mesh_reserve) return .reserve;
                // Always leave room in the recovery share for the mesh
                // sub-reserve, whether or not mesh currently holds it.
                const mesh_claim = @max(self.used(.mesh_recovery), self.mesh_reserve);
                if (self.used(.session_recovery) + mesh_claim >= self.recovery_share) return .class_share;
            },
            .mesh_recovery => {
                // The mesh sub-reserve is guaranteed regardless of the
                // adaptive share; above it mesh competes in the share.
                if (self.used(.mesh_recovery) >= self.mesh_reserve and
                    self.recoveryUsed() >= self.recovery_share) return .class_share;
            },
        }
        return null;
    }

    fn popFree(self: *Pool) u32 {
        std.debug.assert(self.free_top > 0);
        self.free_top -= 1;
        return self.free_stack[self.free_top];
    }

    fn pushFree(self: *Pool, index: u32) void {
        std.debug.assert(self.free_top < self.capacity);
        self.free_stack[self.free_top] = index;
        self.free_top += 1;
    }
};

/// Per-peer GCRA state for one recovery class. A row outlives the peer's
/// tickets and is dropped only once its bucket is idle (`tat <= now`); the
/// governor's rate clock never runs backwards, so an idle row behaves
/// exactly like a fresh bucket for every later request.
const RateRow = struct {
    tat_scaled: u128,
    peer_key: u64,
};

const RateTable = struct {
    rate_per_sec: u64,
    burst: u64,
    len: u32,
    /// Only `[0..len]` is meaningful; keys are distinct.
    rows: [max_rate_rows]RateRow,

    fn init(table: *RateTable, rate_per_sec: u64, burst: u64) void {
        table.rate_per_sec = rate_per_sec;
        table.burst = burst;
        table.len = 0;
    }

    fn find(table: *const RateTable, peer_key: u64) ?u32 {
        for (table.rows[0..table.len], 0..) |row, i| {
            if (row.peer_key == peer_key) return @intCast(i);
        }
        return null;
    }

    fn bucket(table: *const RateTable, tat_scaled: u128) Gcra {
        return .{ .rate_per_sec = table.rate_per_sec, .burst = table.burst, .tat_scaled = tat_scaled };
    }

    fn nowScaled(table: *const RateTable, now_us: u64) u128 {
        return @as(u128, now_us) * table.rate_per_sec;
    }

    /// Microseconds before `peer_key` may be charged one unit at `now_us`.
    /// A key without a row is charged against a fresh bucket, but only once
    /// some row is free: a table full of busy rows refuses new keys until
    /// the soonest row turns idle.
    fn retryAfter(table: *const RateTable, peer_key: u64, now_us: u64) u64 {
        if (table.find(peer_key)) |i| return table.bucket(table.rows[i].tat_scaled).retryAfterCost(now_us, 1);
        if (table.len < max_rate_rows) return 0;
        const now_scaled = table.nowScaled(now_us);
        var soonest: u128 = std.math.maxInt(u128);
        for (table.rows[0..table.len]) |row| {
            if (row.tat_scaled <= now_scaled) return 0;
            soonest = @min(soonest, row.tat_scaled - now_scaled);
        }
        const wait_us = (soonest - 1) / table.rate_per_sec + 1;
        return @intCast(@min(wait_us, std.math.maxInt(u64)));
    }

    /// Charge one unit. `retryAfter(peer_key, now_us)` must have returned 0.
    fn charge(table: *RateTable, peer_key: u64, now_us: u64) void {
        const i = table.find(peer_key) orelse blk: {
            table.dropIdle(now_us);
            std.debug.assert(table.len < max_rate_rows);
            table.rows[table.len] = .{ .tat_scaled = 0, .peer_key = peer_key };
            table.len += 1;
            break :blk table.len - 1;
        };
        var limiter = table.bucket(table.rows[i].tat_scaled);
        const allowed = limiter.allow(now_us, 1);
        std.debug.assert(allowed);
        table.rows[i].tat_scaled = limiter.tat_scaled;
    }

    fn dropIdle(table: *RateTable, now_us: u64) void {
        const now_scaled = table.nowScaled(now_us);
        var i: u32 = 0;
        while (i < table.len) {
            if (table.rows[i].tat_scaled <= now_scaled) {
                table.len -= 1;
                table.rows[i] = table.rows[table.len];
            } else i += 1;
        }
    }
};

fn percentOf(numerator: u32, denominator: u32) u32 {
    if (denominator == 0) return 0;
    return @intCast(@min(@as(u64, numerator) * 100 / denominator, std.math.maxInt(u32)));
}

fn shrinkMultiplicative(current: u32, percent: u32, floor: u32) u32 {
    const shrunk: u32 = @intCast(@as(u64, current) * percent / 100);
    return @max(shrunk, floor);
}

fn growAdditive(current: u32, ceiling: u32, percent: u32) u32 {
    const raw: u32 = @intCast(@as(u64, ceiling) * percent / 100);
    const step = @max(@as(u32, 1), raw);
    return @min(ceiling, current +| step);
}

fn msToUs(now_ms: u64) u64 {
    return now_ms *| 1000;
}

fn usToMsCeil(us: u64) u64 {
    if (us == 0) return 0;
    return us / 1000 + @intFromBool(us % 1000 != 0);
}

// ---------------------------------------------------------------------------
// Governor
// ---------------------------------------------------------------------------

pub const Governor = struct {
    config: Config,
    admission_gcra: Gcra,
    session_recovery_gcra: Gcra,
    mesh_recovery_gcra: Gcra,
    session_recovery_peer_rates: RateTable,
    mesh_recovery_peer_rates: RateTable,
    /// Highest `now` ever committed; rate decisions use
    /// `max(rate_clock_us, now)` so per-peer rows can be dropped safely.
    rate_clock_us: u64,
    /// A recovery acquire was refused for `.reserve`/`.class_share` since
    /// the previous `observe()`.
    recovery_contended: bool,
    admission_pressure_steps: u32,
    grants_total: u64,
    refusals_total: u64,
    releases_total: u64,
    refusals_by_reason: [4]u64,
    slots: Pool,
    verify: Pool,

    /// Initialise in place. On error `self` is left untouched.
    pub fn init(self: *Governor, config: Config) ConfigError!void {
        try validateConfig(config);
        self.config = config;
        self.admission_gcra = Gcra.init(config.admission_rate_per_sec, config.admission_burst);
        self.session_recovery_gcra = Gcra.init(config.session_recovery_rate_per_sec, config.session_recovery_burst);
        self.mesh_recovery_gcra = Gcra.init(config.mesh_recovery_rate_per_sec, config.mesh_recovery_burst);
        self.session_recovery_peer_rates.init(config.session_recovery_peer_rate_per_sec, config.session_recovery_peer_burst);
        self.mesh_recovery_peer_rates.init(config.mesh_recovery_peer_rate_per_sec, config.mesh_recovery_peer_burst);
        self.rate_clock_us = 0;
        self.recovery_contended = false;
        self.admission_pressure_steps = 0;
        self.grants_total = 0;
        self.refusals_total = 0;
        self.releases_total = 0;
        self.refusals_by_reason = .{ 0, 0, 0, 0 };
        self.slots.init(config.capacity, config.recovery_reserve_slots, config.mesh_reserve_slots, config.admission_floor_slots);
        self.verify.init(config.verify_slots, config.recovery_reserve_verify, config.mesh_reserve_verify, config.admission_floor_verify);
    }

    fn poolFor(self: *Governor, resource: Resource) *Pool {
        return switch (resource) {
            .slot => &self.slots,
            .verify => &self.verify,
        };
    }

    fn gcraFor(self: *Governor, class: Class) *Gcra {
        return switch (class) {
            .client_admission => &self.admission_gcra,
            .session_recovery => &self.session_recovery_gcra,
            .mesh_recovery => &self.mesh_recovery_gcra,
        };
    }

    fn peerRatesFor(self: *Governor, class: Class) ?*RateTable {
        return switch (class) {
            .client_admission => null,
            .session_recovery => &self.session_recovery_peer_rates,
            .mesh_recovery => &self.mesh_recovery_peer_rates,
        };
    }

    fn gcraCost(self: *const Governor, class: Class) u64 {
        return switch (class) {
            .client_admission => 1 + self.admission_pressure_steps,
            .session_recovery, .mesh_recovery => 1,
        };
    }

    fn refuse(self: *Governor, reason: RefusalReason, retry_after_ms: u64) Decision {
        self.refusals_total += 1;
        self.refusals_by_reason[@backingInt(reason)] += 1;
        return .{ .refused = .{ .reason = reason, .retry_after_ms = retry_after_ms } };
    }

    /// Attempt to claim one in-flight unit of `resource` for `class`.
    ///
    /// All checks run before any mutation: a refusal changes only the
    /// refusal counters and the recovery-contention signal, never pool,
    /// peer or rate state.
    ///
    /// `peer_key` is ignored for `client_admission` (pass `0`). For recovery
    /// classes it selects the per-(class, peer_key) in-flight cap and rate
    /// bucket. `unidentified_peer_key` (`0`) is capped and rate-limited
    /// like any other key, so unidentified attempts share one budget and
    /// cannot bypass either limit by all passing `0`.
    ///
    /// `now_ms` should be monotonic; an earlier `now_ms` than one already
    /// committed is treated as the committed time.
    pub fn tryAcquire(self: *Governor, class: Class, resource: Resource, peer_key: u64, now_ms: u64) Decision {
        const pool = self.poolFor(resource);
        const tracked = class != .client_admission;

        if (pool.ceilingRefusal(class)) |reason| {
            if (tracked) self.recovery_contended = true;
            return self.refuse(reason, 0);
        }

        var peer_row: ?u32 = null;
        if (tracked) {
            peer_row = pool.peerIndex(class, peer_key);
            if (peer_row) |i| {
                if (pool.peers[i].count >= self.config.max_recovery_inflight_per_peer) {
                    return self.refuse(.per_peer, 0);
                }
            }
            // Rows never outnumber in-flight recovery tickets, and the
            // ceiling check guarantees a free unit, so a new row always fits.
            std.debug.assert(peer_row != null or pool.peer_len < pool.capacity);
        }

        const now_us = @max(self.rate_clock_us, msToUs(now_ms));
        const peer_rates = self.peerRatesFor(class);
        if (peer_rates) |table| {
            const wait_us = table.retryAfter(peer_key, now_us);
            if (wait_us > 0) return self.refuse(.rate, usToMsCeil(wait_us));
        }
        // The mesh sub-reserve guarantees rate as well as concurrency.
        const class_rated = !(class == .mesh_recovery and pool.used(.mesh_recovery) < pool.mesh_reserve);
        const gcra = self.gcraFor(class);
        const cost = self.gcraCost(class);
        if (class_rated) {
            const wait_us = gcra.retryAfterCost(now_us, cost);
            if (wait_us > 0) return self.refuse(.rate, usToMsCeil(wait_us));
        }

        // Commit. Nothing below can fail.
        self.rate_clock_us = now_us;
        if (class_rated) {
            const allowed = gcra.allow(now_us, cost);
            std.debug.assert(allowed);
        }
        if (peer_rates) |table| table.charge(peer_key, now_us);

        if (tracked) {
            if (peer_row) |i| {
                pool.peers[i].count += 1;
            } else {
                pool.peers[pool.peer_len] = .{ .peer_key = peer_key, .count = 1, .class = class };
                pool.peer_len += 1;
            }
        }

        const idx = pool.popFree();
        const rec = &pool.records[idx];
        rec.generation +%= 1;
        rec.in_use = true;
        rec.class = class;
        rec.peer_key = if (tracked) peer_key else 0;
        pool.used_by_class[classIndex(class)] += 1;

        self.grants_total += 1;
        return .{ .granted = .{
            .class = class,
            .resource = resource,
            .index = idx,
            .generation = rec.generation,
        } };
    }

    /// Release a ticket. Idempotent: a stale, already-released or forged
    /// ticket (out-of-range index, generation or class mismatch, or the
    /// record is not in use) is a silent no-op.
    pub fn release(self: *Governor, ticket: Ticket) void {
        const pool = self.poolFor(ticket.resource);
        if (ticket.index >= pool.capacity) return;

        const rec = &pool.records[ticket.index];
        if (!rec.in_use or rec.generation != ticket.generation or rec.class != ticket.class) return;

        rec.in_use = false;
        pool.used_by_class[classIndex(rec.class)] -= 1;
        if (rec.class != .client_admission) pool.peerRelease(rec.class, rec.peer_key);
        rec.peer_key = 0;
        pool.pushFree(ticket.index);
        self.releases_total += 1;
    }

    /// Apply one AIMD adaptation step from a sweep-tick load sample.
    pub fn observe(self: *Governor, load: Load) void {
        const occupancy_percent = percentOf(load.occupancy, self.slots.capacity);
        const verify_percent = percentOf(load.verify_queue, self.verify.capacity);
        const latency_pressured = self.config.admit_latency_pressure_ms > 0 and
            load.p99_admit_latency_ms >= self.config.admit_latency_pressure_ms;
        // A backlog that never had to compete for units (e.g. a peer that is
        // simply down) is not admission pressure.
        const backlog_pressured = load.recovery_backlog > 0 and self.recovery_contended;
        self.recovery_contended = false;
        const pressured = backlog_pressured or
            occupancy_percent >= self.config.occupancy_pressure_target_percent or
            verify_percent >= self.config.verify_pressure_target_percent or
            latency_pressured;

        if (pressured) {
            self.admission_pressure_steps = @min(max_pressure_steps, self.admission_pressure_steps + 1);
        } else {
            self.admission_pressure_steps -|= 1;
        }
        const backlog_growth: u32 = load.recovery_backlog *| self.config.recovery_growth_per_backlog_unit;
        self.adaptPool(&self.slots, pressured, self.config.admission_floor_slots, backlog_growth);
        self.adaptPool(&self.verify, pressured, self.config.admission_floor_verify, backlog_growth);
    }

    fn adaptPool(self: *const Governor, pool: *Pool, pressured: bool, floor: u32, backlog_growth: u32) void {
        pool.admission_share = if (pressured)
            shrinkMultiplicative(pool.admission_share, self.config.shrink_percent, floor)
        else
            growAdditive(pool.admission_share, pool.max_admission_ceiling, self.config.grow_percent);
        pool.recovery_share = std.math.clamp(pool.reserve +| backlog_growth, pool.reserve, pool.max_recovery_ceiling);
    }

    pub fn snapshot(self: *const Governor) Snapshot {
        return .{
            .slots = snapshotPool(&self.slots),
            .verify = snapshotPool(&self.verify),
            .grants_total = self.grants_total,
            .refusals_total = self.refusals_total,
            .releases_total = self.releases_total,
            .refusals_reserve = self.refusals_by_reason[@backingInt(RefusalReason.reserve)],
            .refusals_class_share = self.refusals_by_reason[@backingInt(RefusalReason.class_share)],
            .refusals_per_peer = self.refusals_by_reason[@backingInt(RefusalReason.per_peer)],
            .refusals_rate = self.refusals_by_reason[@backingInt(RefusalReason.rate)],
            .admission_pressure_steps = self.admission_pressure_steps,
        };
    }
};

fn snapshotPool(pool: *const Pool) ResourceSnapshot {
    return .{
        .capacity = pool.capacity,
        .reserve = pool.reserve,
        .mesh_reserve = pool.mesh_reserve,
        .admission_share = pool.admission_share,
        .recovery_share = pool.recovery_share,
        .used_client_admission = pool.used(.client_admission),
        .used_session_recovery = pool.used(.session_recovery),
        .used_mesh_recovery = pool.used(.mesh_recovery),
        .used_total = pool.usedTotal(),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn baseConfig() Config {
    return .{
        .capacity = 10,
        .verify_slots = 6,
        .recovery_reserve_slots = 2,
        .recovery_reserve_verify = 2,
        .mesh_reserve_slots = 1,
        .mesh_reserve_verify = 1,
        .admission_floor_slots = 2,
        .admission_floor_verify = 2,
        .max_recovery_inflight_per_peer = 2,
        .admission_rate_per_sec = 1000,
        .admission_burst = 1000,
        .session_recovery_rate_per_sec = 200,
        .session_recovery_burst = 200,
        .mesh_recovery_rate_per_sec = 200,
        .mesh_recovery_burst = 200,
        .session_recovery_peer_rate_per_sec = 50,
        .session_recovery_peer_burst = 50,
        .mesh_recovery_peer_rate_per_sec = 50,
        .mesh_recovery_peer_burst = 50,
    };
}

fn initGov(gov: *Governor, cfg: Config) !void {
    try gov.init(cfg);
}

fn expectGranted(d: Decision) !Ticket {
    return switch (d) {
        .granted => |t| t,
        .refused => |r| {
            std.debug.print("unexpected refusal: {s}\n", .{@tagName(r.reason)});
            return error.TestUnexpectedResult;
        },
    };
}

fn expectRefused(d: Decision, reason: RefusalReason) !void {
    switch (d) {
        .granted => return error.TestUnexpectedResult,
        .refused => |r| try testing.expectEqual(reason, r.reason),
    }
}

/// Checks every static pool invariant that must hold after any sequence.
fn expectPoolInvariants(pool: *const Pool, cfg_floor: u32) !void {
    const adm = pool.used(.client_admission);
    const sess = pool.used(.session_recovery);
    const mesh = pool.used(.mesh_recovery);
    try testing.expect(adm + sess + mesh <= pool.capacity);
    try testing.expect(adm <= pool.capacity - pool.reserve);
    try testing.expect(adm + sess <= pool.capacity - pool.mesh_reserve);
    try testing.expect(sess + mesh <= pool.capacity - cfg_floor);
    try testing.expectEqual(pool.capacity - (adm + sess + mesh), pool.free_top);
    try testing.expect(pool.peer_len <= sess + mesh);
    var peer_sum: u32 = 0;
    for (pool.peers[0..pool.peer_len]) |p| {
        try testing.expect(p.count > 0);
        peer_sum += p.count;
    }
    try testing.expectEqual(sess + mesh, peer_sum);
}

fn expectRateTableInvariants(table: *const RateTable) !void {
    try testing.expect(table.len <= max_rate_rows);
    for (table.rows[0..table.len], 0..) |a, i| {
        for (table.rows[i + 1 .. table.len]) |b| try testing.expect(a.peer_key != b.peer_key);
    }
}

test "workload_quota: client admission can never consume the recovery slot reserve" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    var granted: u32 = 0;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        switch (gov.tryAcquire(.client_admission, .slot, 0, 0)) {
            .granted => granted += 1,
            .refused => |r| {
                try testing.expectEqual(RefusalReason.reserve, r.reason);
                break;
            },
        }
    }
    // capacity(10) - reserve(2) = 8.
    try testing.expectEqual(@as(u32, 8), granted);

    // The 2 reserved slots must still be acquirable by recovery.
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 111, 0));
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 222, 0));
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, 333, 0), .class_share);
    try expectPoolInvariants(&gov.slots, 2);
}

test "workload_quota: mesh_recovery can use reserve and shared slots up to its share" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    // Without backlog pressure, recovery_share starts at the reserve.
    try testing.expectEqual(@as(u32, 2), gov.snapshot().slots.recovery_share);

    gov.observe(.{ .occupancy = 0, .recovery_backlog = 3, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    // reserve(2) + backlog(3) * growth(1) = 5.
    try testing.expectEqual(@as(u32, 5), gov.snapshot().slots.recovery_share);

    var granted: u32 = 0;
    var peer: u64 = 1;
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        const d = gov.tryAcquire(.mesh_recovery, .slot, peer, 0);
        peer += 1; // distinct peers so the per-peer cap never trips here
        switch (d) {
            .granted => granted += 1,
            .refused => |r| {
                try testing.expectEqual(RefusalReason.class_share, r.reason);
                break;
            },
        }
    }
    try testing.expectEqual(@as(u32, 5), granted);

    // The backlog-driven share is clamped to capacity - admission_floor.
    gov.observe(.{ .occupancy = 0, .recovery_backlog = 1000, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    try testing.expectEqual(@as(u32, 8), gov.snapshot().slots.recovery_share);
    try expectPoolInvariants(&gov.slots, 2);
}

test "workload_quota: session recovery storm can never starve the mesh sub-reserve" {
    var cfg = baseConfig();
    cfg.capacity = 20;
    cfg.recovery_reserve_slots = 6;
    cfg.mesh_reserve_slots = 2;
    cfg.admission_floor_slots = 2;
    cfg.max_recovery_inflight_per_peer = 1;
    var gov: Governor = undefined;
    try initGov(&gov, cfg);

    // Grow the recovery share as far as it goes, then flood with admission
    // and distinct-peer session recovery until both refuse.
    gov.observe(.{ .occupancy = 0, .recovery_backlog = 1000, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    var peer: u64 = 1;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        _ = gov.tryAcquire(.client_admission, .slot, 0, 0);
        _ = gov.tryAcquire(.session_recovery, .slot, peer, 0);
        peer += 1;
    }
    var snap = gov.snapshot().slots;
    try testing.expectEqual(cfg.capacity - cfg.mesh_reserve_slots, snap.used_client_admission + snap.used_session_recovery);

    // Now shrink the recovery share back to the reserve: mesh must still get
    // exactly its sub-reserve even though session holds more than the share.
    gov.observe(.{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 900, 0));
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 901, 0));
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, 902, 0), .class_share);
    snap = gov.snapshot().slots;
    try testing.expectEqual(cfg.capacity, snap.used_total);
    try expectPoolInvariants(&gov.slots, cfg.admission_floor_slots);
}

test "workload_quota: session recovery keeps its own reserve share against an admission storm" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    var i: u32 = 0;
    while (i < 20) : (i += 1) _ = gov.tryAcquire(.client_admission, .slot, 0, 0);
    // reserve(2) - mesh_reserve(1) = 1 unit guaranteed to session recovery.
    _ = try expectGranted(gov.tryAcquire(.session_recovery, .slot, 5, 0));
    try expectRefused(gov.tryAcquire(.session_recovery, .slot, 6, 0), .reserve);
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 7, 0));
    try expectPoolInvariants(&gov.slots, 2);
}

test "workload_quota: per-peer cap stops one failing peer from taking every verification slot" {
    var cfg = baseConfig();
    cfg.verify_slots = 6;
    cfg.recovery_reserve_verify = 4;
    cfg.mesh_reserve_verify = 3;
    cfg.admission_floor_verify = 2;
    cfg.max_recovery_inflight_per_peer = 2;
    var gov: Governor = undefined;
    try initGov(&gov, cfg);

    const peer: u64 = 42;
    var granted: u32 = 0;
    var i: u32 = 0;
    while (i < 6) : (i += 1) {
        switch (gov.tryAcquire(.mesh_recovery, .verify, peer, 0)) {
            .granted => granted += 1,
            .refused => |r| {
                try testing.expectEqual(RefusalReason.per_peer, r.reason);
                break;
            },
        }
    }
    // Share allows 4 (the reserve), but the per-peer cap stops it at 2.
    try testing.expectEqual(@as(u32, 2), granted);

    // A different peer can still get a verify slot.
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .verify, 99, 0));
    // The same key in the other recovery class is a distinct identity.
    _ = try expectGranted(gov.tryAcquire(.session_recovery, .slot, peer, 0));
    try expectPoolInvariants(&gov.verify, 2);
}

test "workload_quota: per-peer cap also bounds peer_key == 0 for recovery classes (unverified-identity attempts)" {
    var cfg = baseConfig();
    cfg.verify_slots = 6;
    cfg.recovery_reserve_verify = 4;
    cfg.admission_floor_verify = 2;
    cfg.max_recovery_inflight_per_peer = 2;
    var gov: Governor = undefined;
    try initGov(&gov, cfg);

    var granted: u32 = 0;
    var i: u32 = 0;
    while (i < 6) : (i += 1) {
        switch (gov.tryAcquire(.mesh_recovery, .verify, 0, 0)) {
            .granted => granted += 1,
            .refused => |r| {
                try testing.expectEqual(RefusalReason.per_peer, r.reason);
                break;
            },
        }
    }
    try testing.expectEqual(@as(u32, 2), granted);
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .verify, 99, 0));
}

test "workload_quota: releasing a peer_key == 0 recovery ticket frees its per-peer slot (no leak)" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 0, 0)));
    try testing.expectEqual(@as(u32, 0), gov.slots.peer_len);

    var granted: u32 = 0;
    var i: u32 = 0;
    while (i < baseConfig().max_recovery_inflight_per_peer) : (i += 1) {
        gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 0, 0)));
        granted += 1;
    }
    try testing.expectEqual(baseConfig().max_recovery_inflight_per_peer, granted);
    try testing.expectEqual(@as(u32, 0), gov.slots.peer_len);
}

test "workload_quota: peer table tracks every distinct in-flight recovery peer without refusing" {
    // More distinct peers than any small fixed table: every one must be
    // granted up to the recovery share, refused only by the share itself.
    var cfg = baseConfig();
    cfg.capacity = 1000;
    cfg.recovery_reserve_slots = 500;
    cfg.mesh_reserve_slots = 250;
    cfg.admission_floor_slots = 100;
    cfg.max_recovery_inflight_per_peer = 1;
    // 250 distinct session keys at one instant need a class burst >= 250.
    cfg.session_recovery_rate_per_sec = 100;
    cfg.session_recovery_burst = 300;
    var gov: Governor = undefined;
    try initGov(&gov, cfg);

    var tickets: [500]Ticket = undefined;
    var n: usize = 0;
    var peer: u64 = 1;
    while (n < 250) : (n += 1) {
        tickets[n] = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, peer, 0));
        peer += 1;
    }
    while (n < 500) : (n += 1) {
        tickets[n] = try expectGranted(gov.tryAcquire(.session_recovery, .slot, peer, 0));
        peer += 1;
    }
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, peer, 0), .class_share);
    try testing.expectEqual(@as(u32, 500), gov.slots.peer_len);
    try expectPoolInvariants(&gov.slots, cfg.admission_floor_slots);

    // Releasing in an interleaved order keeps the dense table consistent.
    var i: usize = 0;
    while (i < 500) : (i += 2) gov.release(tickets[i]);
    try expectPoolInvariants(&gov.slots, cfg.admission_floor_slots);
    i = 1;
    while (i < 500) : (i += 2) gov.release(tickets[i]);
    try testing.expectEqual(@as(u32, 0), gov.slots.peer_len);
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_total);
}

test "workload_quota: release is idempotent and generation-checked (stale or double release is a no-op)" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    const ticket = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, 0));
    try testing.expectEqual(@as(u32, 1), gov.snapshot().slots.used_client_admission);

    gov.release(ticket);
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_client_admission);

    gov.release(ticket); // double release
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_client_admission);
    try testing.expectEqual(@as(u64, 1), gov.snapshot().releases_total);

    // Reacquire reuses the freed slot with a fresh generation; the stale
    // ticket must not be able to release the new occupant.
    const ticket2 = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, 0));
    try testing.expectEqual(ticket.index, ticket2.index);
    try testing.expect(ticket.generation != ticket2.generation);

    gov.release(ticket);
    try testing.expectEqual(@as(u32, 1), gov.snapshot().slots.used_client_admission);

    gov.release(ticket2);
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_client_admission);
}

test "workload_quota: forged tickets (out of range, wrong class, wrong resource) are no-ops" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    const t = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 7, 0));
    const before = gov.snapshot();

    var forged = t;
    forged.index = max_pool_capacity + 5;
    gov.release(forged);
    forged = t;
    forged.index = gov.slots.capacity; // just past the configured capacity
    gov.release(forged);
    forged = t;
    forged.class = .client_admission;
    gov.release(forged);
    forged = t;
    forged.resource = .verify; // no verify record is in use
    gov.release(forged);
    forged = t;
    forged.generation +%= 1;
    gov.release(forged);

    const after = gov.snapshot();
    try testing.expectEqual(before.releases_total, after.releases_total);
    try testing.expectEqual(before.slots.used_mesh_recovery, after.slots.used_mesh_recovery);
    try testing.expectEqual(@as(u32, 1), gov.slots.peer_len);

    gov.release(t);
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_total);
    try testing.expectEqual(@as(u32, 0), gov.slots.peer_len);
}

test "workload_quota: refusal never mutates pool, peer or rate state" {
    var cfg = baseConfig();
    cfg.mesh_recovery_rate_per_sec = 2;
    cfg.mesh_recovery_burst = 2;
    cfg.mesh_recovery_peer_rate_per_sec = 1;
    cfg.mesh_recovery_peer_burst = 1;
    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    // Grow the recovery share so only rate limits refuse below.
    gov.observe(.{ .occupancy = 0, .recovery_backlog = 5, .verify_queue = 0, .p99_admit_latency_ms = 0 });

    // Key 3 fills the mesh sub-reserve (class GCRA untouched); keys 4 and 5
    // spend the whole class burst.
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 3, 0));
    try testing.expectEqual(@as(u128, 0), gov.mesh_recovery_gcra.tat_scaled);
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 4, 0));
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 5, 0));
    const tat = gov.mesh_recovery_gcra.tat_scaled;
    const free_top = gov.slots.free_top;
    const peer_len = gov.slots.peer_len;
    const rate_rows = gov.mesh_recovery_peer_rates.len;
    const row3 = gov.mesh_recovery_peer_rates.rows[gov.mesh_recovery_peer_rates.find(3).?];
    const contended = gov.recovery_contended;

    // Class-rate refusal for a brand-new peer creates no peer or rate row.
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, 6, 0), .rate);
    // Per-peer rate refusal leaves that peer's bucket untouched.
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, 3, 0), .rate);
    try testing.expectEqual(tat, gov.mesh_recovery_gcra.tat_scaled);
    try testing.expectEqual(free_top, gov.slots.free_top);
    try testing.expectEqual(peer_len, gov.slots.peer_len);
    try testing.expectEqual(rate_rows, gov.mesh_recovery_peer_rates.len);
    try testing.expectEqual(row3, gov.mesh_recovery_peer_rates.rows[gov.mesh_recovery_peer_rates.find(3).?]);
    // Rate refusals are a class's own budget, not capacity contention.
    try testing.expectEqual(contended, gov.recovery_contended);
    try expectPoolInvariants(&gov.slots, cfg.admission_floor_slots);
    try expectRateTableInvariants(&gov.mesh_recovery_peer_rates);

    // A time that runs backwards is clamped to the committed time: refused,
    // not a crash or a free grant.
    gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 7, 5000)));
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, 7, 0), .rate);
    try testing.expectEqual(@as(u64, 5000 * 1000), gov.rate_clock_us);
    try testing.expectEqual(peer_len, gov.slots.peer_len);
}

test "workload_quota: AIMD shrinks admission share under pressure and recovers additively when idle" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    try testing.expectEqual(@as(u32, 8), gov.snapshot().slots.admission_share);

    // occupancy 8 of 10 = the 80% default target.
    const busy: Load = .{ .occupancy = 8, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 0 };
    const idle: Load = .{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 0 };
    gov.observe(busy);
    try testing.expectEqual(@as(u32, 4), gov.snapshot().slots.admission_share);
    try testing.expectEqual(@as(u32, 1), gov.snapshot().admission_pressure_steps);
    gov.observe(busy);
    try testing.expectEqual(@as(u32, 2), gov.snapshot().slots.admission_share);
    gov.observe(busy);
    try testing.expectEqual(@as(u32, 2), gov.snapshot().slots.admission_share); // clamped to the floor

    // Shrunk share refuses admission with class_share, not reserve.
    _ = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, 0));
    _ = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, 0));
    try expectRefused(gov.tryAcquire(.client_admission, .slot, 0, 0), .class_share);

    // Idle: step = max(1, ceiling(8) * grow_percent(10) / 100) = 1.
    gov.observe(idle);
    try testing.expectEqual(@as(u32, 3), gov.snapshot().slots.admission_share);
    gov.observe(idle);
    try testing.expectEqual(@as(u32, 4), gov.snapshot().slots.admission_share);
    try testing.expectEqual(@as(u32, 1), gov.snapshot().admission_pressure_steps);

    // Each other pressure signal also shrinks the share.
    var g2: Governor = undefined;
    var cfg = baseConfig();
    cfg.admit_latency_pressure_ms = 250;
    try initGov(&g2, cfg);
    g2.observe(.{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 5, .p99_admit_latency_ms = 0 });
    try testing.expectEqual(@as(u32, 4), g2.snapshot().slots.admission_share);
    g2.observe(idle);
    g2.observe(.{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 250 });
    try testing.expectEqual(@as(u32, 2), g2.snapshot().slots.admission_share);
    g2.observe(.{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 249 });
    try testing.expectEqual(@as(u32, 3), g2.snapshot().slots.admission_share);
}

test "workload_quota: recovery backlog is admission pressure only when recovery contended for capacity" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());
    const backlog: Load = .{ .occupancy = 0, .recovery_backlog = 1, .verify_queue = 0, .p99_admit_latency_ms = 0 };

    // A mesh_recovery refusal for capacity since the last tick makes the
    // backlog count: hold the whole recovery share, then get refused.
    var held: [8]Ticket = undefined;
    var held_n: usize = 0;
    var key: u64 = 1;
    var tick: u32 = 0;
    while (tick < max_pressure_steps + 2) : (tick += 1) {
        while (true) : (key += 1) switch (gov.tryAcquire(.mesh_recovery, .slot, key, 0)) {
            .granted => |t| {
                held[held_n] = t;
                held_n += 1;
            },
            .refused => |r| {
                try testing.expectEqual(RefusalReason.class_share, r.reason);
                break;
            },
        };
        gov.observe(backlog);
    }
    try testing.expectEqual(baseConfig().admission_floor_slots, gov.snapshot().slots.admission_share);
    try testing.expectEqual(max_pressure_steps, gov.snapshot().admission_pressure_steps);
    for (held[0..held_n]) |t| gov.release(t);

    // One configured peer stays down for 100 ticks: the backlog persists
    // but every recovery attempt is granted (and fails remotely), so
    // admission regrows to its full ceiling and the cost multiplier decays.
    var now_ms: u64 = 1000;
    while (tick < 110) : (tick += 1) {
        gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 777, now_ms)));
        gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .verify, 777, now_ms)));
        gov.observe(backlog);
        now_ms += 1000;
    }
    const snap = gov.snapshot();
    try testing.expectEqual(gov.slots.max_admission_ceiling, snap.slots.admission_share);
    try testing.expectEqual(gov.verify.max_admission_ceiling, snap.verify.admission_share);
    try testing.expectEqual(@as(u32, 0), snap.admission_pressure_steps);
    // The backlog still grows the recovery share.
    try testing.expectEqual(baseConfig().recovery_reserve_slots + 1, snap.slots.recovery_share);

    // Per-peer refusals are the peer's own limit, not contention.
    var g2: Governor = undefined;
    var cfg = baseConfig();
    cfg.max_recovery_inflight_per_peer = 1;
    try initGov(&g2, cfg);
    _ = try expectGranted(g2.tryAcquire(.mesh_recovery, .slot, 9, 0));
    try expectRefused(g2.tryAcquire(.mesh_recovery, .slot, 9, 0), .per_peer);
    g2.observe(backlog);
    try testing.expectEqual(@as(u32, 0), g2.snapshot().admission_pressure_steps);
    // Contention without backlog is not pressure either, and is consumed.
    // The backlog tick above grew the share to 3, so two more mesh units fit.
    _ = try expectGranted(g2.tryAcquire(.mesh_recovery, .slot, 10, 0));
    _ = try expectGranted(g2.tryAcquire(.mesh_recovery, .slot, 11, 0));
    try expectRefused(g2.tryAcquire(.mesh_recovery, .slot, 12, 0), .class_share);
    g2.observe(.{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    try testing.expectEqual(@as(u32, 0), g2.snapshot().admission_pressure_steps);
    g2.observe(backlog);
    try testing.expectEqual(@as(u32, 0), g2.snapshot().admission_pressure_steps);
}

test "workload_quota: admission share never drops below admission_floor and recovery never below reserve (no starvation either way)" {
    const cfg = baseConfig();
    var gov: Governor = undefined;
    try initGov(&gov, cfg);

    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        gov.observe(.{ .occupancy = 100, .recovery_backlog = 5, .verify_queue = 100, .p99_admit_latency_ms = 0 });
    }
    var snap = gov.snapshot();
    try testing.expectEqual(cfg.admission_floor_slots, snap.slots.admission_share);
    try testing.expect(snap.slots.recovery_share >= cfg.recovery_reserve_slots);
    try testing.expect(snap.slots.recovery_share <= gov.slots.max_recovery_ceiling);
    try testing.expectEqual(cfg.admission_floor_verify, snap.verify.admission_share);
    try testing.expect(snap.verify.recovery_share >= cfg.recovery_reserve_verify);

    // Fill recovery to its share, then admission must still get its floor.
    var peer: u64 = 1;
    while (i < 200) : (i += 1) {
        _ = gov.tryAcquire(.session_recovery, .slot, peer, 0);
        _ = gov.tryAcquire(.mesh_recovery, .slot, peer, 0);
        peer += 1;
    }
    var adm: u32 = 0;
    while (adm < cfg.admission_floor_slots) : (adm += 1) {
        _ = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, 0));
    }
    try expectPoolInvariants(&gov.slots, cfg.admission_floor_slots);

    i = 0;
    while (i < 50) : (i += 1) {
        gov.observe(.{ .occupancy = 0, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    }
    snap = gov.snapshot();
    try testing.expectEqual(gov.slots.max_admission_ceiling, snap.slots.admission_share);
    try testing.expectEqual(cfg.recovery_reserve_slots, snap.slots.recovery_share);
    try testing.expectEqual(@as(u32, 0), snap.admission_pressure_steps);
}

test "workload_quota: GCRA rate refusal reports a deterministic retry_after_ms" {
    var cfg = baseConfig();
    cfg.mesh_recovery_rate_per_sec = 4;
    cfg.mesh_recovery_burst = 2;
    cfg.mesh_recovery_peer_rate_per_sec = 2;
    cfg.mesh_recovery_peer_burst = 1;

    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 0, 0)));

    const d2 = gov.tryAcquire(.mesh_recovery, .slot, 0, 0);
    try expectRefused(d2, .rate);
    try testing.expectEqual(@as(u64, 500), d2.refused.retry_after_ms);
    // Partial-millisecond waits round up, never down to zero.
    const d_late = gov.tryAcquire(.mesh_recovery, .slot, 0, 499);
    try expectRefused(d_late, .rate);
    try testing.expectEqual(@as(u64, 1), d_late.refused.retry_after_ms);
    // Exactly at retry_after the next unit is granted.
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 0, 500));

    var gov2: Governor = undefined;
    try initGov(&gov2, cfg);
    _ = gov2.tryAcquire(.mesh_recovery, .slot, 0, 0);
    const d3 = gov2.tryAcquire(.mesh_recovery, .slot, 0, 0);
    try testing.expectEqual(d2.refused.retry_after_ms, d3.refused.retry_after_ms);
    try testing.expectEqual(@as(u64, 1), gov2.snapshot().refusals_rate);

    // The class GCRA reports its own wait outside the sub-reserve:
    // burst 2 spent at t=0, next unit at 1/4 s.
    var gov3: Governor = undefined;
    try initGov(&gov3, cfg);
    gov3.observe(.{ .occupancy = 0, .recovery_backlog = 5, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    _ = try expectGranted(gov3.tryAcquire(.mesh_recovery, .slot, 1, 0)); // sub-reserve
    _ = try expectGranted(gov3.tryAcquire(.mesh_recovery, .slot, 2, 0));
    _ = try expectGranted(gov3.tryAcquire(.mesh_recovery, .slot, 3, 0));
    const d4 = gov3.tryAcquire(.mesh_recovery, .slot, 4, 0);
    try expectRefused(d4, .rate);
    try testing.expectEqual(@as(u64, 250), d4.refused.retry_after_ms);
}

test "workload_quota: init rejects admission_burst too small for the pressure-step cost ceiling" {
    var cfg = baseConfig();
    cfg.admission_burst = max_pressure_steps;
    var gov: Governor = undefined;
    try testing.expectError(error.AdmissionBurstBelowPressureCeiling, gov.init(cfg));

    cfg.admission_burst = 1 + max_pressure_steps;
    try gov.init(cfg);
}

test "workload_quota: admission is never driven to permanent zero by sustained pressure, even at the minimum valid burst" {
    var cfg = baseConfig();
    cfg.admission_burst = 1 + max_pressure_steps;
    var gov: Governor = undefined;
    try initGov(&gov, cfg);

    var i: u32 = 0;
    while (i < max_pressure_steps + 2) : (i += 1) {
        gov.observe(.{ .occupancy = cfg.capacity, .recovery_backlog = 0, .verify_queue = 0, .p99_admit_latency_ms = 0 });
    }
    try testing.expectEqual(max_pressure_steps, gov.admission_pressure_steps);

    _ = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, 0));
    // Next admission must wait, but a finite wait always suffices.
    const d = gov.tryAcquire(.client_admission, .slot, 0, 0);
    try expectRefused(d, .rate);
    try testing.expect(d.refused.retry_after_ms > 0);
    _ = try expectGranted(gov.tryAcquire(.client_admission, .slot, 0, d.refused.retry_after_ms));
}

test "workload_quota: init rejects invalid config (reserve >= capacity, zero floors)" {
    const Case = struct { err: ConfigError, cfg: Config };
    var cases: [31]Case = undefined;
    var n: usize = 0;
    const base = baseConfig();
    inline for (.{
        .{ error.ReserveExceedsCapacity, "recovery_reserve_slots", base.capacity },
        .{ error.ReserveExceedsCapacity, "recovery_reserve_verify", base.verify_slots },
        .{ error.ZeroReserve, "recovery_reserve_slots", 0 },
        .{ error.ZeroReserve, "recovery_reserve_verify", 0 },
        .{ error.InvalidMeshReserve, "mesh_reserve_slots", 0 },
        .{ error.InvalidMeshReserve, "mesh_reserve_verify", 0 },
        .{ error.InvalidMeshReserve, "mesh_reserve_slots", base.recovery_reserve_slots + 1 },
        .{ error.InvalidMeshReserve, "mesh_reserve_slots", base.recovery_reserve_slots },
        .{ error.InvalidMeshReserve, "mesh_reserve_verify", base.recovery_reserve_verify },
        .{ error.ZeroFloor, "admission_floor_slots", 0 },
        .{ error.ZeroFloor, "admission_floor_verify", 0 },
        .{ error.FloorExceedsShareCeiling, "admission_floor_slots", base.capacity - base.recovery_reserve_slots + 1 },
        .{ error.ZeroCapacity, "capacity", 0 },
        .{ error.ZeroCapacity, "verify_slots", 0 },
        .{ error.CapacityTooLarge, "capacity", max_pool_capacity + 1 },
        .{ error.ZeroPerPeerCap, "max_recovery_inflight_per_peer", 0 },
        .{ error.ZeroRate, "admission_rate_per_sec", 0 },
        .{ error.ZeroRate, "mesh_recovery_rate_per_sec", 0 },
        .{ error.ZeroBurst, "session_recovery_burst", 0 },
        .{ error.ZeroRate, "session_recovery_peer_rate_per_sec", 0 },
        .{ error.ZeroBurst, "mesh_recovery_peer_burst", 0 },
        .{ error.PeerRateNotBelowClassRate, "mesh_recovery_peer_rate_per_sec", base.mesh_recovery_rate_per_sec },
        .{ error.PeerRateNotBelowClassRate, "session_recovery_peer_rate_per_sec", base.session_recovery_rate_per_sec + 1 },
        .{ error.PeerBurstNotBelowClassBurst, "session_recovery_peer_burst", base.session_recovery_burst },
        .{ error.PeerBurstNotBelowClassBurst, "mesh_recovery_peer_burst", base.mesh_recovery_burst },
        // 200 + ceil(200 * 50 / 1) rows could be busy at once.
        .{ error.RecoveryRateRowsExceeded, "mesh_recovery_peer_rate_per_sec", 1 },
        .{ error.InvalidPercent, "shrink_percent", 0 },
        .{ error.InvalidPercent, "grow_percent", 101 },
        .{ error.InvalidPercent, "occupancy_pressure_target_percent", 0 },
        .{ error.InvalidPercent, "verify_pressure_target_percent", 101 },
        .{ error.InvalidPercent, "shrink_percent", 101 },
    }) |c| {
        var cfg = base;
        @field(cfg, c[1]) = c[2];
        cases[n] = .{ .err = c[0], .cfg = cfg };
        n += 1;
    }
    try testing.expectEqual(cases.len, n);

    // A failed init must leave a previously valid governor untouched.
    var gov: Governor = undefined;
    try initGov(&gov, base);
    const held = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 1, 0));
    for (cases) |c| {
        try testing.expectError(c.err, validateConfig(c.cfg));
        try testing.expectError(c.err, gov.init(c.cfg));
        try testing.expectEqual(base.capacity, gov.slots.capacity);
        try testing.expectEqual(@as(u32, 1), gov.snapshot().slots.used_mesh_recovery);
    }
    gov.release(held);
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_total);

    // The maximum supported capacity initialises.
    var big = base;
    big.capacity = max_pool_capacity;
    big.verify_slots = max_pool_capacity;
    try gov.init(big);
}

// ---------------------------------------------------------------------------
// Deterministic storm simulation (test only)
// ---------------------------------------------------------------------------

const max_storm_concurrent_attempts: u32 = 64;

const StormConfig = struct {
    ticks: u32,
    clients_per_tick: u32,
    resumes_per_tick: u32,
    failing_peer_key: u64,
    failing_peer_attempts_per_tick: u32,
    /// Release each failing-peer grant immediately (acquire, fail fast,
    /// release) instead of holding it to the end of the tick.
    failing_peer_churns: bool = false,
    /// Unidentified inbound S2S attempts per tick, each released at once.
    unidentified_attempts_per_tick: u32 = 0,
    legit_peer_key: u64,
};

const StormResult = struct {
    ticks_run: u32 = 0,
    admission_granted_total: u64 = 0,
    admission_refused_total: u64 = 0,
    resume_granted_total: u64 = 0,
    failing_peer_granted_total: u64 = 0,
    failing_peer_refused_total: u64 = 0,
    unidentified_granted_total: u64 = 0,
    legit_recovery_granted_total: u64 = 0,
    ticks_with_legit_recovery_progress: u32 = 0,
    max_verify_in_flight: u32 = 0,
};

fn heldVerify(gov: *const Governor) u32 {
    return gov.snapshot().verify.used_total;
}

/// Each tick: churns `clients_per_tick` admission slots, holds
/// `resumes_per_tick` concurrent distinct-peer session-recovery verify
/// tickets (a RESUME storm), drives one flapping mesh peer to its per-peer
/// cap, then requires a distinct healthy mesh peer to make progress.
fn simulateStorm(gov: *Governor, cfg: StormConfig) !StormResult {
    std.debug.assert(cfg.failing_peer_attempts_per_tick <= max_storm_concurrent_attempts);
    std.debug.assert(cfg.resumes_per_tick <= max_storm_concurrent_attempts);

    var result: StormResult = .{};
    var now_ms: u64 = 0;
    var resume_peer: u64 = 1_000_000;
    var tick: u32 = 0;
    while (tick < cfg.ticks) : (tick += 1) {
        result.ticks_run += 1;

        var c: u32 = 0;
        while (c < cfg.clients_per_tick) : (c += 1) {
            switch (gov.tryAcquire(.client_admission, .slot, 0, now_ms)) {
                .granted => |t| {
                    result.admission_granted_total += 1;
                    gov.release(t);
                },
                .refused => result.admission_refused_total += 1,
            }
        }

        var held: [2 * max_storm_concurrent_attempts]Ticket = undefined;
        var held_count: usize = 0;
        var r: u32 = 0;
        while (r < cfg.resumes_per_tick) : (r += 1) {
            resume_peer += 1;
            switch (gov.tryAcquire(.session_recovery, .verify, resume_peer, now_ms)) {
                .granted => |t| {
                    result.resume_granted_total += 1;
                    held[held_count] = t;
                    held_count += 1;
                },
                .refused => {},
            }
        }

        var a: u32 = 0;
        while (a < cfg.failing_peer_attempts_per_tick) : (a += 1) {
            switch (gov.tryAcquire(.mesh_recovery, .verify, cfg.failing_peer_key, now_ms)) {
                .granted => |t| {
                    result.failing_peer_granted_total += 1;
                    if (cfg.failing_peer_churns) {
                        gov.release(t);
                    } else {
                        held[held_count] = t;
                        held_count += 1;
                    }
                },
                .refused => result.failing_peer_refused_total += 1,
            }
        }
        var u: u32 = 0;
        while (u < cfg.unidentified_attempts_per_tick) : (u += 1) {
            switch (gov.tryAcquire(.mesh_recovery, .verify, unidentified_peer_key, now_ms)) {
                .granted => |t| {
                    result.unidentified_granted_total += 1;
                    gov.release(t);
                },
                .refused => {},
            }
        }
        result.max_verify_in_flight = @max(result.max_verify_in_flight, heldVerify(gov));

        var legit_progressed = false;
        const slot_t = gov.tryAcquire(.mesh_recovery, .slot, cfg.legit_peer_key, now_ms);
        const verify_t = gov.tryAcquire(.mesh_recovery, .verify, cfg.legit_peer_key, now_ms);
        if (slot_t == .granted and verify_t == .granted) {
            legit_progressed = true;
            result.legit_recovery_granted_total += 1;
        }
        result.max_verify_in_flight = @max(result.max_verify_in_flight, heldVerify(gov));
        if (slot_t == .granted) gov.release(slot_t.granted);
        if (verify_t == .granted) gov.release(verify_t.granted);
        if (legit_progressed) result.ticks_with_legit_recovery_progress += 1;

        for (held[0..held_count]) |t| gov.release(t);
        try expectPoolInvariants(&gov.slots, gov.config.admission_floor_slots);
        try expectPoolInvariants(&gov.verify, gov.config.admission_floor_verify);
        try expectRateTableInvariants(&gov.session_recovery_peer_rates);
        try expectRateTableInvariants(&gov.mesh_recovery_peer_rates);

        gov.observe(.{
            .occupancy = cfg.clients_per_tick,
            .recovery_backlog = if (legit_progressed) 0 else 1,
            .verify_queue = @intCast(held_count),
            .p99_admit_latency_ms = 0,
        });

        now_ms +|= 1000;
    }
    return result;
}

test "workload_quota: deterministic reconnect-storm simulation (N clients/tick + failed peer flapping) keeps recovery progressing every tick and holds verify in-flight at or below verify_slots" {
    var cfg = baseConfig();
    cfg.capacity = 100;
    cfg.verify_slots = 8;
    cfg.recovery_reserve_slots = 10;
    cfg.recovery_reserve_verify = 4;
    cfg.mesh_reserve_slots = 4;
    cfg.mesh_reserve_verify = 2;
    cfg.admission_floor_slots = 5;
    cfg.admission_floor_verify = 2;
    cfg.max_recovery_inflight_per_peer = 1;
    cfg.session_recovery_burst = 64;

    const storm: StormConfig = .{
        .ticks = 50,
        .clients_per_tick = 200,
        .resumes_per_tick = 32,
        .failing_peer_key = 777,
        .failing_peer_attempts_per_tick = 10,
        .legit_peer_key = 888,
    };

    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    const result = try simulateStorm(&gov, storm);

    try testing.expectEqual(@as(u32, 50), result.ticks_run);
    try testing.expectEqual(result.ticks_run, result.ticks_with_legit_recovery_progress);
    try testing.expect(result.max_verify_in_flight <= cfg.verify_slots);
    // The flapping peer is held to its per-peer cap every tick.
    try testing.expectEqual(@as(u64, 50 * 1), result.failing_peer_granted_total);
    try testing.expect(result.resume_granted_total > 0);
    try testing.expect(result.admission_refused_total > 0);
    try testing.expect(result.admission_granted_total > 0);

    // Replaying the same inputs reproduces the same outcome exactly.
    var gov2: Governor = undefined;
    try initGov(&gov2, cfg);
    const result2 = try simulateStorm(&gov2, storm);
    try testing.expectEqualDeep(result, result2);
}

test "workload_quota: churning reconnect-storm simulation (fail-fast peer + unidentified inbound flood at a tight mesh rate) still recovers the healthy peer every tick" {
    var cfg = baseConfig();
    cfg.capacity = 100;
    cfg.verify_slots = 8;
    cfg.recovery_reserve_slots = 10;
    cfg.recovery_reserve_verify = 4;
    cfg.mesh_reserve_slots = 4;
    cfg.mesh_reserve_verify = 2;
    cfg.admission_floor_slots = 5;
    cfg.admission_floor_verify = 2;
    cfg.max_recovery_inflight_per_peer = 1;
    cfg.session_recovery_burst = 64;
    cfg.mesh_recovery_rate_per_sec = 10;
    cfg.mesh_recovery_burst = 10;
    cfg.mesh_recovery_peer_rate_per_sec = 2;
    cfg.mesh_recovery_peer_burst = 2;

    const storm: StormConfig = .{
        .ticks = 50,
        .clients_per_tick = 200,
        .resumes_per_tick = 32,
        .failing_peer_key = 777,
        .failing_peer_attempts_per_tick = 10,
        .failing_peer_churns = true,
        .unidentified_attempts_per_tick = 10,
        .legit_peer_key = 888,
    };

    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    const result = try simulateStorm(&gov, storm);

    try testing.expectEqual(result.ticks_run, result.ticks_with_legit_recovery_progress);
    try testing.expect(result.max_verify_in_flight <= cfg.verify_slots);
    // Each churning key is held to its own bucket: 2 per 1 s tick.
    try testing.expectEqual(@as(u64, 2 * 50), result.failing_peer_granted_total);
    try testing.expectEqual(@as(u64, 2 * 50), result.unidentified_granted_total);
    try testing.expectEqual(@as(u64, 8 * 50), result.failing_peer_refused_total);
    try testing.expect(result.resume_granted_total > 0);

    var gov2: Governor = undefined;
    try initGov(&gov2, cfg);
    try testing.expectEqualDeep(result, try simulateStorm(&gov2, storm));
}

test "workload_quota: a churning mesh peer or unidentified inbound flood cannot spend a healthy peer's rate budget" {
    var cfg = baseConfig();
    cfg.mesh_recovery_rate_per_sec = 10;
    cfg.mesh_recovery_burst = 10;
    cfg.mesh_recovery_peer_rate_per_sec = 2;
    cfg.mesh_recovery_peer_burst = 2;
    cfg.max_recovery_inflight_per_peer = 1;

    // Inside the mesh sub-reserve: 777 flaps 10 times at t=0, then 0 does.
    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    for ([_]u64{ 777, unidentified_peer_key }) |flapper| {
        var granted: u32 = 0;
        var i: u32 = 0;
        while (i < 10) : (i += 1) switch (gov.tryAcquire(.mesh_recovery, .verify, flapper, 0)) {
            .granted => |t| {
                granted += 1;
                gov.release(t);
            },
            .refused => |r| try testing.expectEqual(RefusalReason.rate, r.reason),
        };
        try testing.expectEqual(@as(u32, 2), granted);
    }
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 888, 0));
    _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .verify, 888, 0));
    try testing.expectEqual(@as(u128, 0), gov.mesh_recovery_gcra.tat_scaled);

    // Above the sub-reserve the class GCRA applies, but a churning key
    // still spends only its own burst of it.
    var g2: Governor = undefined;
    try initGov(&g2, cfg);
    _ = try expectGranted(g2.tryAcquire(.mesh_recovery, .slot, 555, 0)); // holds Rm
    var i: u32 = 0;
    while (i < 10) : (i += 1) switch (g2.tryAcquire(.mesh_recovery, .slot, 777, 0)) {
        .granted => |t| g2.release(t),
        .refused => |r| try testing.expectEqual(RefusalReason.rate, r.reason),
    };
    _ = try expectGranted(g2.tryAcquire(.mesh_recovery, .slot, 888, 0));
    try expectPoolInvariants(&g2.slots, cfg.admission_floor_slots);
}

test "workload_quota: one churning session-recovery source cannot starve another source; minted keys hit only the class bound" {
    var cfg = baseConfig();
    cfg.session_recovery_rate_per_sec = 10;
    cfg.session_recovery_burst = 10;
    cfg.session_recovery_peer_rate_per_sec = 2;
    cfg.session_recovery_peer_burst = 2;

    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    var granted: u32 = 0;
    var i: u32 = 0;
    while (i < 10) : (i += 1) switch (gov.tryAcquire(.session_recovery, .verify, 4242, 0)) {
        .granted => |t| {
            granted += 1;
            gov.release(t);
        },
        .refused => |r| try testing.expectEqual(RefusalReason.rate, r.reason),
    };
    try testing.expectEqual(@as(u32, 2), granted);
    _ = try expectGranted(gov.tryAcquire(.session_recovery, .verify, 5, 0));

    // Freshly minted keys are indistinguishable from legitimate ones; the
    // class GCRA is the aggregate verification bound they share.
    var g2: Governor = undefined;
    try initGov(&g2, cfg);
    var key: u64 = 1;
    while (key <= 10) : (key += 1) g2.release(try expectGranted(g2.tryAcquire(.session_recovery, .verify, key, 0)));
    const d = g2.tryAcquire(.session_recovery, .verify, key, 0);
    try expectRefused(d, .rate);
    try testing.expectEqual(@as(u64, 100), d.refused.retry_after_ms);
}

test "workload_quota: session recovery always gets a slot and a verify unit on a fresh governor for any valid config" {
    var prng = std.Random.DefaultPrng.init(0x5eed_0012_0002);
    const rnd = prng.random();
    var gov: Governor = undefined;
    var rejected: u32 = 0;
    var case: u32 = 0;
    while (case < 200) : (case += 1) {
        var cfg = baseConfig();
        inline for (.{
            .{ "capacity", "recovery_reserve_slots", "mesh_reserve_slots", "admission_floor_slots" },
            .{ "verify_slots", "recovery_reserve_verify", "mesh_reserve_verify", "admission_floor_verify" },
        }) |f| {
            const capacity = rnd.intRangeAtMost(u32, 3, if (case < 100) 64 else max_pool_capacity);
            const reserve = rnd.intRangeAtMost(u32, 2, capacity - 1);
            @field(cfg, f[0]) = capacity;
            @field(cfg, f[1]) = reserve;
            // Include the rejected `Rm == R` edge so the property covers
            // exactly what validation accepts.
            @field(cfg, f[2]) = rnd.intRangeAtMost(u32, 1, reserve);
            @field(cfg, f[3]) = rnd.intRangeAtMost(u32, 1, capacity - reserve);
        }
        validateConfig(cfg) catch |err| {
            try testing.expectEqual(error.InvalidMeshReserve, err);
            rejected += 1;
            continue;
        };
        try initGov(&gov, cfg);
        _ = try expectGranted(gov.tryAcquire(.session_recovery, .slot, 1, 0));
        _ = try expectGranted(gov.tryAcquire(.session_recovery, .verify, 1, 0));

        // Still true after an admission storm fills its whole share.
        try initGov(&gov, cfg);
        var i: u32 = 0;
        while (i < cfg.capacity + cfg.verify_slots) : (i += 1) {
            _ = gov.tryAcquire(.client_admission, .slot, 0, 0);
            _ = gov.tryAcquire(.client_admission, .verify, 0, 0);
        }
        _ = try expectGranted(gov.tryAcquire(.session_recovery, .slot, 1, 0));
        _ = try expectGranted(gov.tryAcquire(.session_recovery, .verify, 1, 0));
        _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 2, 0));
        _ = try expectGranted(gov.tryAcquire(.mesh_recovery, .verify, 2, 0));
    }
    // Non-vacuous: both accepted and rejected configs were generated.
    try testing.expect(rejected > 0 and rejected < 150);
}

test "workload_quota: a full per-peer rate table refuses new keys fail-closed until a row turns idle" {
    var cfg = baseConfig();
    cfg.mesh_recovery_peer_rate_per_sec = 1;
    cfg.mesh_recovery_peer_burst = 1;
    cfg.mesh_recovery_rate_per_sec = 256;
    cfg.mesh_recovery_burst = 256;
    // 256 + ceil(256 * 1 / 1) = 512 = gated_rate_rows: the largest valid.
    try validateConfig(cfg);
    var over = cfg;
    over.mesh_recovery_burst = 257;
    try testing.expectError(error.RecoveryRateRowsExceeded, validateConfig(over));

    var gov: Governor = undefined;
    try initGov(&gov, cfg);
    // Distinct keys churned inside the mesh sub-reserve bypass the class
    // GCRA, so only the table bound stops them.
    var key: u64 = 1;
    while (key <= max_rate_rows) : (key += 1) {
        gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, key, 0)));
    }
    try testing.expectEqual(max_rate_rows, gov.mesh_recovery_peer_rates.len);
    const d = gov.tryAcquire(.mesh_recovery, .slot, key, 0);
    try expectRefused(d, .rate);
    try testing.expectEqual(@as(u64, 1000), d.refused.retry_after_ms);
    try testing.expectEqual(max_rate_rows, gov.mesh_recovery_peer_rates.len);
    // A key that already has a row is unaffected by the full table.
    try expectRefused(gov.tryAcquire(.mesh_recovery, .slot, 1, 999), .rate);
    gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, 1, 1000)));

    // Once rows turn idle, inserting a new key drops every idle row.
    gov.release(try expectGranted(gov.tryAcquire(.mesh_recovery, .slot, key, 1000)));
    try testing.expectEqual(@as(u32, 2), gov.mesh_recovery_peer_rates.len);
    try expectRateTableInvariants(&gov.mesh_recovery_peer_rates);
    try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_total);
}

test "workload_quota: snapshot counters match grants and refusals" {
    var gov: Governor = undefined;
    try initGov(&gov, baseConfig());

    var tickets: [8]Ticket = undefined;
    var granted: usize = 0;
    var refused: u64 = 0;
    var i: u32 = 0;
    while (i < 20) : (i += 1) {
        switch (gov.tryAcquire(.client_admission, .slot, 0, 0)) {
            .granted => |t| {
                tickets[granted] = t;
                granted += 1;
            },
            .refused => refused += 1,
        }
    }

    var snap = gov.snapshot();
    try testing.expectEqual(@as(u64, granted), snap.grants_total);
    try testing.expectEqual(refused, snap.refusals_total);
    try testing.expectEqual(refused, snap.refusals_reserve);
    try testing.expectEqual(@as(u64, 0), snap.refusals_class_share);
    try testing.expectEqual(@as(u64, 0), snap.refusals_per_peer);
    try testing.expectEqual(@as(u64, 0), snap.refusals_rate);
    try testing.expectEqual(@as(u64, 0), snap.releases_total);
    try testing.expectEqual(@as(u32, 8), snap.slots.used_total);

    for (tickets[0..granted]) |t| gov.release(t);

    snap = gov.snapshot();
    try testing.expectEqual(@as(u64, granted), snap.releases_total);
    try testing.expectEqual(@as(u32, 0), snap.slots.used_total);
}

test "workload_quota: randomized acquire/release sequences preserve every pool invariant" {
    var cfg = baseConfig();
    cfg.capacity = 40;
    cfg.verify_slots = 12;
    cfg.recovery_reserve_slots = 10;
    cfg.recovery_reserve_verify = 4;
    cfg.mesh_reserve_slots = 3;
    cfg.mesh_reserve_verify = 2;
    cfg.admission_floor_slots = 4;
    cfg.admission_floor_verify = 2;
    cfg.max_recovery_inflight_per_peer = 3;

    var seed: u64 = 0x5eed_0012;
    while (seed < 0x5eed_0012 + 8) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var gov: Governor = undefined;
        try initGov(&gov, cfg);
        var held: [128]Ticket = undefined;
        var held_n: usize = 0;
        var now_ms: u64 = 0;
        var step: u32 = 0;
        while (step < 4000) : (step += 1) {
            now_ms += rnd.uintLessThan(u64, 3);
            switch (rnd.uintLessThan(u8, 10)) {
                0...4 => if (held_n < held.len) {
                    const class = rnd.enumValue(Class);
                    const resource = rnd.enumValue(Resource);
                    switch (gov.tryAcquire(class, resource, rnd.uintLessThan(u64, 6), now_ms)) {
                        .granted => |t| {
                            held[held_n] = t;
                            held_n += 1;
                        },
                        .refused => {},
                    }
                },
                5...7 => if (held_n > 0) {
                    const k = rnd.uintLessThan(usize, held_n);
                    const t = held[k];
                    gov.release(t);
                    gov.release(t); // double release stays a no-op
                    held_n -= 1;
                    held[k] = held[held_n];
                },
                // Mostly idle with occasional backlog, so admission shares
                // both shrink and regrow to their reserve-pinned ceiling.
                else => gov.observe(.{
                    .occupancy = rnd.uintLessThan(u32, 30),
                    .recovery_backlog = if (rnd.uintLessThan(u8, 4) == 0) rnd.uintLessThan(u32, 8) else 0,
                    .verify_queue = rnd.uintLessThan(u32, 9),
                    .p99_admit_latency_ms = 0,
                }),
            }
            expectPoolInvariants(&gov.slots, cfg.admission_floor_slots) catch |err| {
                std.debug.print("seed=0x{x} step={d}\n", .{ seed, step });
                return err;
            };
            expectPoolInvariants(&gov.verify, cfg.admission_floor_verify) catch |err| {
                std.debug.print("seed=0x{x} step={d}\n", .{ seed, step });
                return err;
            };
        }
        // Non-vacuous: grants and every capacity refusal reason occur.
        const snap = gov.snapshot();
        try testing.expect(snap.grants_total > 500);
        try testing.expect(snap.refusals_reserve > 0);
        try testing.expect(snap.refusals_class_share > 0);
        try testing.expect(snap.refusals_per_peer > 0);
        for (held[0..held_n]) |t| gov.release(t);
        try testing.expectEqual(@as(u32, 0), gov.snapshot().slots.used_total);
        try testing.expectEqual(@as(u32, 0), gov.snapshot().verify.used_total);
        try testing.expectEqual(@as(u32, 0), gov.slots.peer_len);
        try testing.expectEqual(@as(u32, 0), gov.verify.peer_len);
    }
}

test "workload_quota: resolve derives today's defaults from max_clients" {
    const r = try resolve(1024, .{});
    const c = r.enabled;
    try testing.expectEqual(@as(u32, 1024), c.capacity);
    try testing.expectEqual(@as(u32, 32), c.recovery_reserve_slots);
    try testing.expectEqual(@as(u32, 16), c.mesh_reserve_slots);
    try testing.expectEqual(@as(u32, (1024 - 32) / 4), c.admission_floor_slots);
    try testing.expectEqual(@as(u32, 16), c.max_recovery_inflight_per_peer);
    try testing.expectEqual(c.recovery_reserve_slots, c.recovery_reserve_verify);
    // Above the pool bound the table clamps, as before.
    try testing.expectEqual(max_pool_capacity, (try resolve(1 << 20, .{})).enabled.capacity);
    // Every derivable table validates.
    for (5..max_pool_capacity + 2) |n| _ = (try resolve(@intCast(n), .{})).enabled;
}

test "workload_quota: resolve reports small tables and operator disable by reason" {
    for (0..5) |n| try testing.expectEqual(Resolution{ .disabled = .table_too_small }, try resolve(@intCast(n), .{}));
    try testing.expectEqual(Resolution{ .disabled = .operator_disabled }, try resolve(1024, .{ .enabled = false }));
    try testing.expectError(error.ExplicitFieldsWhileDisabled, resolve(1024, .{ .enabled = false, .admission_burst = 64 }));
}

test "workload_quota: invalid explicit overrides fail closed instead of disabling the governor" {
    // Explicit values on a table too small for any reserve are refused.
    try testing.expectError(error.ReserveExceedsCapacity, resolve(4, .{ .recovery_reserve_slots = 4 }));
    try testing.expectError(error.ZeroCapacity, resolve(0, .{ .admission_burst = 64 }));
    // A reserve of one leaves no mesh sub-reserve.
    try testing.expectError(error.InvalidMeshReserve, resolve(1024, .{ .recovery_reserve_slots = 1 }));
    try testing.expectError(error.InvalidMeshReserve, resolve(1024, .{ .mesh_reserve_slots = 32 }));
    try testing.expectError(error.FloorExceedsShareCeiling, resolve(1024, .{ .admission_floor_slots = 1000 }));
    try testing.expectError(error.AdmissionBurstBelowPressureCeiling, resolve(1024, .{ .admission_burst = 8 }));
    try testing.expectError(error.PeerRateNotBelowClassRate, resolve(1024, .{ .session_recovery_peer_rate_per_sec = 128 }));
    try testing.expectError(error.PeerBurstNotBelowClassBurst, resolve(1024, .{ .mesh_recovery_burst = 128 }));
    try testing.expectError(error.RecoveryRateRowsExceeded, resolve(1024, .{ .session_recovery_burst = 511, .session_recovery_peer_burst = 510, .session_recovery_peer_rate_per_sec = 1 }));
}

test "workload_quota: valid explicit overrides take effect and keep unset fields derived" {
    const c = (try resolve(256, .{ .recovery_reserve_slots = 20, .admission_burst = 64, .admission_rate_per_sec = 32 })).enabled;
    try testing.expectEqual(@as(u32, 20), c.recovery_reserve_slots);
    try testing.expectEqual(@as(u32, 10), c.mesh_reserve_slots);
    try testing.expectEqual(@as(u32, (256 - 20) / 4), c.admission_floor_slots);
    try testing.expectEqual(@as(u64, 64), c.admission_burst);
    try testing.expectEqual(@as(u64, 32), c.admission_rate_per_sec);
    try testing.expectEqual(@as(u64, 128), c.mesh_recovery_rate_per_sec);
    // Explicit values make a small table governed rather than silently off.
    const small = (try resolve(4, .{ .recovery_reserve_slots = 2, .mesh_reserve_slots = 1 })).enabled;
    try testing.expectEqual(@as(u32, 4), small.capacity);
    var gov: Governor = undefined;
    try gov.init(small);
}
