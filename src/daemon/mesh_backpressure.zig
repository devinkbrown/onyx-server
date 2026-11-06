// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded mesh-wide backpressure: paced resends plus watermark admission.
//!
//! The durable per-hop retransmission authorities (`relay_v2_event_log`,
//! `relay_v2_outbox`) already retain every accepted MESSAGE_V2 event until
//! the neighbour ACKs, bounded and checkpointed. What they do not do is turn
//! a slow neighbour into *bounded, paced* resends, or turn local backlog
//! into an *early* signal before transit forwarding is starved. This leaf
//! supplies exactly those two pieces, as a pure, allocation-free-after-init
//! module with no server.zig dependency:
//!
//!   * `PeerWindows` paces resends per (peer, RelayId) with an exponential
//!     RTO, so a stalled downstream produces a bounded number of duplicate
//!     frames instead of one per reactor-0 loop iteration.
//!   * `AdmissionGate` partitions RVL2 capacity by signed origin: a row is
//!     admitted only while its origin's retained share is below
//!     `OriginQuota` (1/membership of the rows and bytes), with hysteresis
//!     for local authoring. RVL2 keeps every row until all required nodes
//!     confirm it, so a pool shared across origins can fill every node with
//!     rows that each need another full node; per-origin shares cannot.
//!   * `classifyAdmitFailure` turns a raw admission error into a
//!     `RejectCause`, so a transit `CapacityExceeded` can be handled as
//!     "withhold the ACK, let the sender re-pace" instead of a permanent,
//!     unrecoverable drop.
//!
//! Both `PeerWindows` and `AdmissionGate` allocate only inside `init`
//! (`PeerWindows`) or not at all (`AdmissionGate` is a plain value type).
//! Every table is hard-bounded: once full, further growth is refused
//! without disturbing any entry already tracked — bounded state, never
//! corrupted state.
//!
//! `PeerWindows` tracks at most one in-flight attempt per (peer, RelayId):
//! a resend for a given head is never issued while the previous attempt's
//! RTO has not elapsed. That is the "window of 1 per origin head" the mesh
//! already relies on (`relay_v2_event_log.collectPageForNode` hands out one
//! outstanding head per origin at a time) — this leaf does not introduce a
//! separate configurable window size because nothing upstream emits more
//! than one outstanding attempt per (peer, RelayId) to pace.
//!
//! Pacing state is advisory and never an authority: the durable event log
//! still decides what is owed. A tracked entry whose head was retired by a
//! path that did not call `noteAck` (node retirement, adopt, pruning) would
//! otherwise pin a window slot forever and starve every later head to that
//! peer. An entry that has been eligible yet unsent for a further
//! `retry_cap_ms` is therefore reclaimable by a new head when the window is
//! full. A live head is re-presented as soon as it is due, so reclaim costs
//! at most one early resend per head per `retry_cap_ms`, never per poll.

const std = @import("std");
const message_relay_v2 = @import("../substrate/undertow/message_relay_v2.zig");
const relay_v2_event_log = @import("relay_v2_event_log.zig");
const cursor_entry_len = @import("relay_v2_event_log/checkpoint_wire.zig").cursor_entry_len;
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

pub const RelayId = message_relay_v2.RelayId;
const EventLog = relay_v2_event_log.EventLog;

// ---------------------------------------------------------------------------
// PeerWindows: bounded, paced resend tracking per immediate peer.
// ---------------------------------------------------------------------------

/// Matches `relay_v2_event_log.hard_max_cursor_nodes`: the mesh never has
/// more distinct node identities than this, so a table sized to it can
/// never be legitimately exhausted by real membership growth.
pub const hard_max_peers: usize = 4096;
/// Matches `relay_v2_event_log.default_max_confirmed_nodes_per_row`, the
/// bound on durable MESSAGE_V2 membership. The daemon should size the table
/// to its actual required-node count instead (see `PeerWindows.init`).
pub const default_max_peers: usize = 256;

/// Bounded count of distinct (origin) heads concurrently paced to one peer.
/// Fixed, not a runtime knob: this slice's contract is "one outstanding
/// resend window per origin head", and 32 concurrently stalled origins to a
/// single peer is already a large multiple of ordinary mesh fan-in.
pub const per_peer_window_cap: usize = 32;

/// Resend pacing policy: matches `relay_v2_initial_retry_ms` /
/// `relay_v2_outbox`'s receipt-retry shift so the same stalled-peer signal
/// looks the same everywhere in the mesh stack.
pub const default_base_retry_ms: u64 = 1000;
pub const max_retry_shift: u5 = 5; // 1000 << 5 == 32_000ms == 32s cap.
pub const retry_cap_ms: u64 = default_base_retry_ms << max_retry_shift;

pub const EmitDecision = union(enum) {
    /// Send now: either never sent before, or the RTO has elapsed.
    emit,
    /// Already in flight and the RTO has not elapsed; resend at `until_ms`.
    wait: struct { until_ms: u64 },
    /// This peer's in-flight set is at `per_peer_window_cap`; cannot track
    /// another concurrent head for this peer right now.
    window_full,
};

pub const Pressure = enum { open, slow, stalled };

const InFlight = struct {
    relay_id: RelayId,
    first_sent_ms: u64,
    last_sent_ms: u64,
    attempts: u32,
};

const PeerSlot = struct {
    peer: u64,
    inflight_len: usize,
    inflight: [per_peer_window_cap]InFlight,
};

/// Per-immediate-peer resend pacing. Sorted-array table over `peer`, hard
/// bounded at `max_peers`; each peer's in-flight set is a fixed-size array,
/// hard bounded at `per_peer_window_cap`. The only allocation in this type
/// happens in `init`; every other operation is pure bookkeeping over the
/// preallocated backing storage and can never fail or corrupt existing
/// entries.
pub const PeerWindows = struct {
    allocator: std.mem.Allocator,
    max_peers: usize,
    slots: []PeerSlot,
    len: usize = 0,

    /// Observability counters, safe to read directly for metrics wiring.
    /// `shouldEmit` maintains them; callers must not count again.
    resend_emitted: u64 = 0,
    resend_suppressed: u64 = 0,
    window_full_deferred: u64 = 0,
    idle_reclaimed: u64 = 0,

    pub const Config = struct {
        max_peers: usize = default_max_peers,
    };

    pub const InitError = error{InvalidConfig} || std.mem.Allocator.Error;

    pub fn init(allocator: std.mem.Allocator, config: Config) InitError!PeerWindows {
        if (config.max_peers == 0 or config.max_peers > hard_max_peers) return error.InvalidConfig;
        const slots = try allocator.alloc(PeerSlot, config.max_peers);
        return .{ .allocator = allocator, .max_peers = config.max_peers, .slots = slots };
    }

    pub fn deinit(self: *PeerWindows) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn peerCount(self: *const PeerWindows) usize {
        return self.len;
    }

    pub fn inFlightCount(self: *const PeerWindows, peer: u64) usize {
        const idx = self.find(peer) orelse return 0;
        return self.slots[idx].inflight_len;
    }

    pub fn containsInFlight(self: *const PeerWindows, peer: u64, relay_id: RelayId) bool {
        const idx = self.find(peer) orelse return false;
        return findInFlight(&self.slots[idx], relay_id) != null;
    }

    /// Decide whether `relay_id` may be sent to `peer` right now. Never
    /// mutates in-flight state (see `noteEmitted`); updates only the
    /// observability counters.
    pub fn shouldEmit(self: *PeerWindows, peer: u64, relay_id: RelayId, now_ms: u64) EmitDecision {
        const idx = self.find(peer) orelse return .emit;
        const slot = &self.slots[idx];
        const fidx = findInFlight(slot, relay_id) orelse {
            if (slot.inflight_len < per_peer_window_cap) return .emit;
            if (reclaimableIndex(slot, now_ms) != null) return .emit;
            self.window_full_deferred +|= 1;
            return .window_full;
        };
        const earliest = dueMs(slot.inflight[fidx]);
        if (now_ms >= earliest) {
            self.resend_emitted +|= 1;
            return .emit;
        }
        self.resend_suppressed +|= 1;
        return .{ .wait = .{ .until_ms = earliest } };
    }

    /// Record that `relay_id` was just sent to `peer`. Lazily creates the
    /// peer slot and/or the in-flight entry. A full window first reclaims
    /// the idle entry `shouldEmit` would have used to say `.emit`. If the
    /// peer table or the peer's in-flight set is still at its hard bound,
    /// this is a best-effort no-op: the send still happened (the caller
    /// already decided that via `shouldEmit`), but pacing state for it is
    /// not tracked. Live peers and entries are never disturbed.
    pub fn noteEmitted(self: *PeerWindows, peer: u64, relay_id: RelayId, now_ms: u64) void {
        const slot = self.ensureSlot(peer) orelse return;
        if (findInFlight(slot, relay_id)) |fidx| {
            slot.inflight[fidx].attempts +|= 1;
            slot.inflight[fidx].last_sent_ms = now_ms;
            return;
        }
        const fresh: InFlight = .{
            .relay_id = relay_id,
            .first_sent_ms = now_ms,
            .last_sent_ms = now_ms,
            .attempts = 0,
        };
        if (slot.inflight_len < per_peer_window_cap) {
            slot.inflight[slot.inflight_len] = fresh;
            slot.inflight_len += 1;
            return;
        }
        const idle = reclaimableIndex(slot, now_ms) orelse return;
        slot.inflight[idle] = fresh;
        self.idle_reclaimed +|= 1;
    }

    /// Clear the in-flight entry for `(peer, relay_id)`, resetting backoff
    /// so a later resend of the same RelayId (e.g. after a future re-admit)
    /// starts fresh. An ack for an unknown peer, or a relay_id not tracked
    /// for a known peer (unknown or already-cleared/duplicate), is a no-op.
    pub fn noteAck(self: *PeerWindows, peer: u64, relay_id: RelayId) void {
        const idx = self.find(peer) orelse return;
        const slot = &self.slots[idx];
        const fidx = findInFlight(slot, relay_id) orelse return;
        const last = slot.inflight_len - 1;
        slot.inflight[fidx] = slot.inflight[last];
        slot.inflight_len = last;
    }

    /// Clear every in-flight entry for `peer`: on link (re)establishment any
    /// retained head is immediately eligible again rather than waiting out
    /// whatever backoff had accumulated before the disconnect. A reset for
    /// an unknown peer is a no-op.
    pub fn notePeerReset(self: *PeerWindows, peer: u64) void {
        const idx = self.find(peer) orelse return;
        self.slots[idx].inflight_len = 0;
    }

    /// Drop all pacing state for `peer` (e.g. SQUIT/teardown), freeing its
    /// table slot for a different peer.
    pub fn forgetPeer(self: *PeerWindows, peer: u64) void {
        const idx = self.find(peer) orelse return;
        var i = idx;
        while (i + 1 < self.len) : (i += 1) self.slots[i] = self.slots[i + 1];
        self.len -= 1;
    }

    /// Coarse signal derived purely from tracked attempts: `.open` means no
    /// in-flight head has ever needed a resend; `.slow` means at least one
    /// resend has happened but backoff has not maxed out; `.stalled` means
    /// some head has hit the backoff cap and is still unconfirmed.
    pub fn pressure(self: *const PeerWindows, peer: u64) Pressure {
        const idx = self.find(peer) orelse return .open;
        const slot = &self.slots[idx];
        if (slot.inflight_len == 0) return .open;
        var max_attempts: u32 = 0;
        for (slot.inflight[0..slot.inflight_len]) |entry| max_attempts = @max(max_attempts, entry.attempts);
        if (max_attempts == 0) return .open;
        if (max_attempts >= max_retry_shift) return .stalled;
        return .slow;
    }

    /// Gauge: number of currently tracked peers classified `.stalled`.
    pub fn stalledPeerCount(self: *const PeerWindows) usize {
        var count: usize = 0;
        for (self.slots[0..self.len]) |slot| {
            if (slot.inflight_len == 0) continue;
            var max_attempts: u32 = 0;
            for (slot.inflight[0..slot.inflight_len]) |entry| max_attempts = @max(max_attempts, entry.attempts);
            if (max_attempts >= max_retry_shift) count += 1;
        }
        return count;
    }

    fn find(self: *const PeerWindows, peer: u64) ?usize {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            const p = self.slots[mid].peer;
            if (p == peer) return mid;
            if (p < peer) lo = mid + 1 else hi = mid;
        }
        return null;
    }

    fn lowerBound(self: *const PeerWindows, peer: u64) usize {
        var lo: usize = 0;
        var hi: usize = self.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.slots[mid].peer < peer) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Returns the slot for `peer`, creating it (sorted insert) if there is
    /// room; `null` only when the table is already at `max_peers` and
    /// `peer` is not already tracked.
    fn ensureSlot(self: *PeerWindows, peer: u64) ?*PeerSlot {
        if (self.find(peer)) |idx| return &self.slots[idx];
        if (self.len >= self.max_peers) return null;
        const at = self.lowerBound(peer);
        var i = self.len;
        while (i > at) : (i -= 1) self.slots[i] = self.slots[i - 1];
        self.slots[at] = .{ .peer = peer, .inflight_len = 0, .inflight = undefined };
        self.len += 1;
        return &self.slots[at];
    }
};

/// Earliest time the next attempt for `entry` may be sent.
fn dueMs(entry: InFlight) u64 {
    const shift: u6 = @intCast(@min(entry.attempts, max_retry_shift));
    return entry.last_sent_ms +| (default_base_retry_ms << shift);
}

/// The entry that has stayed eligible but unsent for at least
/// `retry_cap_ms` past its due time, earliest due first (lowest index on a
/// tie), so reclaim is deterministic. `null` while every entry is live.
fn reclaimableIndex(slot: *const PeerSlot, now_ms: u64) ?usize {
    var best: ?usize = null;
    var best_due: u64 = 0;
    for (slot.inflight[0..slot.inflight_len], 0..) |entry, i| {
        const due = dueMs(entry);
        if (now_ms -| due < retry_cap_ms) continue;
        if (best == null or due < best_due) {
            best = i;
            best_due = due;
        }
    }
    return best;
}

fn findInFlight(slot: *const PeerSlot, relay_id: RelayId) ?usize {
    for (slot.inflight[0..slot.inflight_len], 0..) |entry, i| {
        if (std.mem.eql(u8, &entry.relay_id, &relay_id)) return i;
    }
    return null;
}

// ---------------------------------------------------------------------------
// AdmissionGate: RVL2 capacity partitioned per signed origin.
// ---------------------------------------------------------------------------

/// Whole-store bounds of every retention authority an admission must not
/// overrun. Every `*_max`/`*_cap` field is the configured bound, so the gate
/// checks the real numbers. A dimension that does not apply to a given
/// caller should be left at its non-tripping default (`len < max`). These
/// totals are a fail-closed backstop only; they never decide liveness (see
/// `AdmissionGate`).
pub const Occupancy = struct {
    log_rows: usize = 0,
    log_max_rows: usize = 1,
    log_bytes: usize = 0,
    log_max_bytes: usize = 1,
    outbox_len: usize = 0,
    outbox_max: usize = 1,
    /// The daemon leaves the deferred dimension at its non-tripping default:
    /// its deferred queue drains only through this gate, so a hard cap here
    /// would shed every retry from a full queue and never drain it (see the
    /// daemon's `relayV2BackpressureAdmits`). Callers whose queue drains
    /// elsewhere may fill it in.
    deferred_len: usize = 0,
    deferred_cap: usize = 1,
};

/// Retained RVL2 rows of one origin, with bytes charged at `rowFootprint`.
pub const Usage = struct {
    rows: usize = 0,
    bytes: usize = 0,
};

/// Upper bound on the RVL2 aggregate bytes one row can ever account for:
/// the wire plus its required list, plus the confirmed and excluded-once
/// lists, which are disjoint subsets of the required list. Charging
/// admission at this bound means later ACK confirmations and ingress
/// exclusions never need bytes the origin's quota did not already hold.
pub fn rowFootprint(wire_len: usize, required_len: usize) usize {
    return wire_len +| (required_len *| (2 * @sizeOf(u64)));
}

/// Per-origin share of one node's RVL2 bounds: `1/origins` of the rows and of
/// the aggregate bytes left after the worst-case cursor table. With `origins`
/// equal to the required-node membership size, the shares of all origins sum
/// to at most the store's bounds.
pub const OriginQuota = struct {
    rows: usize,
    bytes: usize,

    pub const Input = struct {
        log_max_rows: usize,
        log_max_aggregate_bytes: usize,
        log_max_cursor_nodes: usize,
        /// Required-node membership size; every origin is a member.
        origins: usize,
    };

    pub fn init(input: Input) error{InvalidConfig}!OriginQuota {
        if (input.origins == 0) return error.InvalidConfig;
        const cursor_reserve = input.log_max_cursor_nodes *| cursor_entry_len;
        if (cursor_reserve >= input.log_max_aggregate_bytes) return error.InvalidConfig;
        const rows = input.log_max_rows / input.origins;
        const bytes = (input.log_max_aggregate_bytes - cursor_reserve) / input.origins;
        if (rows == 0 or bytes == 0) return error.InvalidConfig;
        return .{ .rows = rows, .bytes = bytes };
    }

    pub fn forLog(log: *const EventLog, origins: usize) error{InvalidConfig}!OriginQuota {
        return init(.{
            .log_max_rows = log.config.max_rows,
            .log_max_aggregate_bytes = log.config.max_aggregate_bytes,
            .log_max_cursor_nodes = log.config.max_cursor_nodes,
            .origins = origins,
        });
    }
};

/// One linear pass over `log`: the rows whose signed origin is `origin_node`,
/// each charged at the footprint of its own event-time required set. The log
/// stays the only authority, so no counter can drift from it across adopt,
/// node retirement or checkpoint restore.
pub fn originUsage(log: *const EventLog, origin_node: u64) Usage {
    var usage: Usage = .{};
    for (0..log.len()) |index| {
        const row = log.viewAt(index);
        if (row.origin_node != origin_node) continue;
        usage.rows += 1;
        usage.bytes +|= rowFootprint(row.wire.len, row.required_nodes.len);
    }
    return usage;
}

/// The RVL2 dimensions of `log`. The RVO2 and deferred dimensions keep
/// their non-tripping defaults for the caller to fill in.
pub fn logOccupancy(log: *const EventLog) Occupancy {
    return .{
        .log_rows = log.len(),
        .log_max_rows = log.config.max_rows,
        .log_bytes = log.aggregate_bytes,
        .log_max_bytes = log.config.max_aggregate_bytes,
    };
}

/// Inputs to one admission decision for a row of a single origin.
pub const Request = struct {
    quota: OriginQuota,
    /// The row origin's share already retained here (`originUsage`).
    origin: Usage,
    total: Occupancy,
    /// `rowFootprint` of the row asking for admission.
    incoming_bytes: usize,
};

pub const AdmitDecision = union(enum) {
    admit,
    shed: struct { retry_after_ms: u64 },
};

pub const default_high_watermark_num: u64 = 7;
pub const default_high_watermark_den: u64 = 8;
pub const default_low_watermark_num: u64 = 3;
pub const default_low_watermark_den: u64 = 4;
pub const default_shed_retry_ms: u64 = 2000;

/// Pure classifier, no allocation ever. A row of origin O is admitted only
/// while O's retained share is below its `OriginQuota`; the occupancy of
/// other origins never matters. RVL2 keeps every row until all required
/// nodes confirm it, so one pool shared by all origins lets rows that each
/// need a different full node fill every node at once and retire nothing.
///
/// Why the partition stays live. Let S_O be O's own rows that O has not yet
/// retired. O's local admission keeps |S_O| and their footprint within the
/// quota. Every other retained O row was retired at O, so every required node
/// has durably accepted it and re-ACKs it without a new row. Those rows drain
/// wherever they are held. A node W that is missing some r in S_O holds at
/// most |S_O| - 1 rows of S_O. If W's O share is at quota anyway, it holds an
/// O row that is draining, and it admits r once that row retires. Each row
/// therefore reaches every node and retires.
///
/// Preconditions the caller must keep: every node derives the same quota
/// (same RVL2 bounds and membership size); a node that durably accepted a
/// RelayId re-ACKs a re-presentation from its retained row or RVO2 receipt
/// without a fresh RVL2 row; retained origins never outnumber `origins`; and
/// RVO2 and the deferred queue are sized so that they never bind first. The
/// `Occupancy` totals stay a fail-closed backstop for every case outside
/// these preconditions.
///
/// `classifyLocal` (own origin only) adds a high watermark with hysteresis
/// down to a low watermark, so authoring stops before the quota and only
/// resumes once the share has drained. `classifyTransit` is stateless and
/// admits up to the quota.
pub const AdmissionGate = struct {
    high_num: u64 = default_high_watermark_num,
    high_den: u64 = default_high_watermark_den,
    low_num: u64 = default_low_watermark_num,
    low_den: u64 = default_low_watermark_den,
    shed_retry_ms: u64 = default_shed_retry_ms,

    /// Hysteresis state for `classifyLocal` only.
    shedding: bool = false,

    local_shed: u64 = 0,
    transit_shed: u64 = 0,
    transit_capacity_withheld: u64 = 0,
    peak: Occupancy = .{},
    peak_origin: Usage = .{},

    pub fn classifyLocal(self: *AdmissionGate, req: Request) AdmitDecision {
        self.observePeak(req);
        if (self.shedding) {
            if (!usageRatioAtLeast(req.origin, req.quota, self.low_num, self.low_den)) self.shedding = false;
        } else if (usageRatioAtLeast(req.origin, req.quota, self.high_num, self.high_den)) {
            self.shedding = true;
        }
        if (self.shedding or !fits(req)) {
            self.local_shed +|= 1;
            return .{ .shed = .{ .retry_after_ms = self.shed_retry_ms } };
        }
        return .admit;
    }

    pub fn classifyTransit(self: *AdmissionGate, req: Request) AdmitDecision {
        self.observePeak(req);
        if (!fits(req)) {
            self.transit_shed +|= 1;
            return .{ .shed = .{ .retry_after_ms = self.shed_retry_ms } };
        }
        return .admit;
    }

    /// Call when a transit admission attempt actually failed with
    /// `RejectCause.capacity` after this gate already said `.admit` (a
    /// race against concurrent admissions). Pure bookkeeping for metrics.
    pub fn noteTransitCapacityWithheld(self: *AdmissionGate) void {
        self.transit_capacity_withheld +|= 1;
    }

    pub fn occupancyPeak(self: *const AdmissionGate) Occupancy {
        return self.peak;
    }

    fn observePeak(self: *AdmissionGate, req: Request) void {
        const occ = req.total;
        self.peak.log_rows = @max(self.peak.log_rows, occ.log_rows);
        self.peak.log_bytes = @max(self.peak.log_bytes, occ.log_bytes);
        self.peak.outbox_len = @max(self.peak.outbox_len, occ.outbox_len);
        self.peak.deferred_len = @max(self.peak.deferred_len, occ.deferred_len);
        self.peak.log_max_rows = occ.log_max_rows;
        self.peak.log_max_bytes = occ.log_max_bytes;
        self.peak.outbox_max = occ.outbox_max;
        self.peak.deferred_cap = occ.deferred_cap;
        self.peak_origin.rows = @max(self.peak_origin.rows, req.origin.rows);
        self.peak_origin.bytes = @max(self.peak_origin.bytes, req.origin.bytes);
    }
};

/// True when one more row of `incoming_bytes` stays inside the origin's
/// quota and inside every whole-store hard bound.
fn fits(req: Request) bool {
    if (req.origin.rows >= req.quota.rows) return false;
    if (req.origin.bytes +| req.incoming_bytes > req.quota.bytes) return false;
    if (anyAtHardCap(req.total)) return false;
    return req.total.log_bytes +| req.incoming_bytes <= req.total.log_max_bytes;
}

fn ratioAtLeast(value: usize, max: usize, num: u64, den: u64) bool {
    if (max == 0 or den == 0) return false;
    const v: u128 = value;
    const m: u128 = max;
    return v * den >= m * num;
}

fn usageRatioAtLeast(usage: Usage, quota: OriginQuota, num: u64, den: u64) bool {
    return ratioAtLeast(usage.rows, quota.rows, num, den) or
        ratioAtLeast(usage.bytes, quota.bytes, num, den);
}

fn anyAtHardCap(occ: Occupancy) bool {
    return occ.log_rows >= occ.log_max_rows or
        occ.log_bytes >= occ.log_max_bytes or
        occ.outbox_len >= occ.outbox_max or
        occ.deferred_len >= occ.deferred_cap;
}

// ---------------------------------------------------------------------------
// RejectCause: classify a raw admission failure for retry handling.
// ---------------------------------------------------------------------------

pub const RejectCause = enum { capacity, transient, permanent };

/// Maps a raw admission error from `relay_v2_event_log`/`relay_v2_outbox`
/// into a cause the daemon can act on. `CapacityExceeded` is always
/// `.capacity` — retryable pressure, never a permanent drop. `OutOfMemory`
/// is `.transient`. Everything else (malformed input, policy, protocol
/// violations) is `.permanent`, matching today's fail-closed behavior for
/// genuinely bad input.
pub fn classifyAdmitFailure(err: anyerror) RejectCause {
    return switch (err) {
        error.CapacityExceeded => .capacity,
        error.OutOfMemory => .transient,
        else => .permanent,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn testRelayId(seed: u32) RelayId {
    var id: RelayId = @splat(0);
    std.mem.writeInt(u32, id[0..4], seed, .big);
    return id;
}

test "mesh backpressure: first emit immediate, resend only after exponential RTO capped at 32s" {
    const allocator = std.testing.allocator;
    var pw = try PeerWindows.init(allocator, .{});
    defer pw.deinit();
    const peer: u64 = 42;
    const rid = testRelayId(1);

    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, rid, 0));
    pw.noteEmitted(peer, rid, 0);

    switch (pw.shouldEmit(peer, rid, 999)) {
        .wait => |w| try std.testing.expectEqual(@as(u64, 1000), w.until_ms),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, rid, 1000));
    pw.noteEmitted(peer, rid, 1000); // attempts=1 -> shift1 -> 2000ms -> eligible 3000

    switch (pw.shouldEmit(peer, rid, 2999)) {
        .wait => |w| try std.testing.expectEqual(@as(u64, 3000), w.until_ms),
        else => return error.TestUnexpectedResult,
    }
    pw.noteEmitted(peer, rid, 3000); // attempts=2 -> shift2 -> 4000ms -> eligible 7000
    switch (pw.shouldEmit(peer, rid, 6999)) {
        .wait => |w| try std.testing.expectEqual(@as(u64, 7000), w.until_ms),
        else => return error.TestUnexpectedResult,
    }

    pw.noteEmitted(peer, rid, 7000); // attempts=3 -> 8000 -> eligible 15000
    pw.noteEmitted(peer, rid, 15000); // attempts=4 -> 16000 -> eligible 31000
    pw.noteEmitted(peer, rid, 31000); // attempts=5 -> 32000 (capped) -> eligible 63000
    pw.noteEmitted(peer, rid, 63000); // attempts=6, shift still capped at 5 -> 32000 -> eligible 95000
    switch (pw.shouldEmit(peer, rid, 94999)) {
        .wait => |w| try std.testing.expectEqual(@as(u64, 95000), w.until_ms),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, rid, 95000));
}

test "mesh backpressure: ack clears in-flight and resets backoff; duplicate/unknown ack is a no-op" {
    const allocator = std.testing.allocator;
    var pw = try PeerWindows.init(allocator, .{});
    defer pw.deinit();
    const peer: u64 = 7;
    const rid = testRelayId(2);

    pw.noteEmitted(peer, rid, 0);
    pw.noteEmitted(peer, rid, 1000); // attempts=1 -> next eligible 3000

    pw.noteAck(999, rid); // unknown peer
    pw.noteAck(peer, testRelayId(250)); // unknown relay_id for a known peer
    try std.testing.expectEqual(@as(usize, 1), pw.inFlightCount(peer));

    pw.noteAck(peer, rid);
    try std.testing.expectEqual(@as(usize, 0), pw.inFlightCount(peer));
    pw.noteAck(peer, rid); // duplicate ack after clearing
    try std.testing.expectEqual(@as(usize, 0), pw.inFlightCount(peer));

    // Treated as brand new: immediate emit, backoff reset to the base RTO.
    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, rid, 1000));
    pw.noteEmitted(peer, rid, 1000);
    switch (pw.shouldEmit(peer, rid, 1999)) {
        .wait => |w| try std.testing.expectEqual(@as(u64, 2000), w.until_ms),
        else => return error.TestUnexpectedResult,
    }
}

test "mesh backpressure: peer reset makes retained head immediately eligible after reconnect" {
    const allocator = std.testing.allocator;
    var pw = try PeerWindows.init(allocator, .{});
    defer pw.deinit();
    const peer: u64 = 3;
    const rid = testRelayId(5);

    pw.noteEmitted(peer, rid, 0);
    pw.noteEmitted(peer, rid, 1000); // attempts=1 -> next eligible 3000
    switch (pw.shouldEmit(peer, rid, 2000)) {
        .wait => {},
        else => return error.TestUnexpectedResult,
    }

    pw.notePeerReset(peer);
    try std.testing.expectEqual(@as(usize, 0), pw.inFlightCount(peer));
    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, rid, 2000));

    pw.notePeerReset(123456); // unknown peer: no-op, never a crash or corruption
}

test "mesh backpressure: peer table and per-peer in-flight set are hard-bounded and fail closed without corrupting existing peers" {
    const allocator = std.testing.allocator;

    const InitSweep = struct {
        fn run(failing: std.mem.Allocator) !void {
            var pw = try PeerWindows.init(failing, .{ .max_peers = 4 });
            defer pw.deinit();
            try std.testing.expectEqual(@as(usize, 0), pw.peerCount());
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, InitSweep.run, .{});

    try std.testing.expectError(error.InvalidConfig, PeerWindows.init(allocator, .{ .max_peers = 0 }));
    try std.testing.expectError(
        error.InvalidConfig,
        PeerWindows.init(allocator, .{ .max_peers = hard_max_peers + 1 }),
    );

    var pw = try PeerWindows.init(allocator, .{ .max_peers = 2 });
    defer pw.deinit();
    pw.noteEmitted(1, testRelayId(1), 0);
    pw.noteEmitted(2, testRelayId(1), 0);
    try std.testing.expectEqual(@as(usize, 2), pw.peerCount());

    // A third distinct peer cannot be tracked while the table is full: the
    // send is still permitted (no tracked state to withhold it) but no slot
    // is created, and the first two peers are untouched.
    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(3, testRelayId(1), 0));
    pw.noteEmitted(3, testRelayId(1), 0);
    try std.testing.expectEqual(@as(usize, 2), pw.peerCount());
    try std.testing.expectEqual(@as(usize, 1), pw.inFlightCount(1));
    try std.testing.expectEqual(@as(usize, 1), pw.inFlightCount(2));

    // Forgetting a peer frees its slot for a genuinely new one.
    pw.forgetPeer(1);
    try std.testing.expectEqual(@as(usize, 1), pw.peerCount());
    pw.noteEmitted(3, testRelayId(1), 0);
    try std.testing.expectEqual(@as(usize, 2), pw.peerCount());
    try std.testing.expectEqual(@as(usize, 1), pw.inFlightCount(3));
    try std.testing.expectEqual(@as(usize, 1), pw.inFlightCount(2)); // untouched by the churn

    // Per-peer in-flight set hard bound: more than per_peer_window_cap
    // distinct relay_ids for one peer is refused without losing earlier ones.
    var small = try PeerWindows.init(allocator, .{ .max_peers = 1 });
    defer small.deinit();
    var seed: u32 = 0;
    while (seed < per_peer_window_cap) : (seed += 1) small.noteEmitted(9, testRelayId(seed), 0);
    try std.testing.expectEqual(per_peer_window_cap, small.inFlightCount(9));
    try std.testing.expectEqual(
        EmitDecision.window_full,
        small.shouldEmit(9, testRelayId(per_peer_window_cap), 0),
    );
    small.noteEmitted(9, testRelayId(per_peer_window_cap), 0); // dropped silently
    try std.testing.expectEqual(per_peer_window_cap, small.inFlightCount(9));
    seed = 0;
    while (seed < per_peer_window_cap) : (seed += 1) {
        try std.testing.expect(small.containsInFlight(9, testRelayId(seed)));
    }
}

test "mesh backpressure: over-cap head stays deterministically window_full across repeated polls and becomes eligible only after capacity frees" {
    const allocator = std.testing.allocator;
    var pw = try PeerWindows.init(allocator, .{ .max_peers = 1 });
    defer pw.deinit();
    const peer: u64 = 9;

    // Fill the per-peer window to its hard cap with distinct heads.
    var seed: u32 = 0;
    while (seed < per_peer_window_cap) : (seed += 1) pw.noteEmitted(peer, testRelayId(seed), 0);
    try std.testing.expectEqual(per_peer_window_cap, pw.inFlightCount(peer));

    const over_cap_rid = testRelayId(per_peer_window_cap);

    // Drive many poll iterations forward in time while the tracked heads
    // stay live (each is re-sent as soon as it is due, as the retry sweep
    // does for retained heads): a never-tracked head at the cap must return
    // .window_full every single time -- never .emit without tracking, and
    // never oscillate. A caller that only resends on .emit therefore cannot
    // be made to reproduce the one-send-per-poll-tick amplification this
    // module exists to prevent, no matter how long the window stays
    // saturated by live heads.
    var now: u64 = 0;
    var poll: usize = 0;
    while (poll < 10_000) : (poll += 1) {
        seed = 0;
        while (seed < per_peer_window_cap) : (seed += 1) {
            const live = testRelayId(seed);
            switch (pw.shouldEmit(peer, live, now)) {
                .emit => pw.noteEmitted(peer, live, now),
                .wait => {},
                .window_full => return error.TestUnexpectedResult,
            }
        }
        switch (pw.shouldEmit(peer, over_cap_rid, now)) {
            .window_full => {},
            .emit, .wait => return error.TestUnexpectedResult,
        }
        // noteEmitted for an over-cap head must stay a no-op: it never
        // starts accruing attempts/backoff state it cannot actually pace.
        pw.noteEmitted(peer, over_cap_rid, now);
        try std.testing.expectEqual(per_peer_window_cap, pw.inFlightCount(peer));
        try std.testing.expect(!pw.containsInFlight(peer, over_cap_rid));
        now += 1000;
    }
    try std.testing.expectEqual(@as(u64, 0), pw.idle_reclaimed);
    try std.testing.expectEqual(@as(u64, 10_000), pw.window_full_deferred);

    // Capacity frees only when an existing tracked head is acked (or the
    // peer is reset/forgotten) -- never spontaneously.
    pw.noteAck(peer, testRelayId(0));
    try std.testing.expectEqual(per_peer_window_cap - 1, pw.inFlightCount(peer));

    // The previously over-cap head is now trackable and paces normally:
    // immediate first emit, then the standard exponential backoff.
    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, over_cap_rid, now));
    pw.noteEmitted(peer, over_cap_rid, now);
    try std.testing.expect(pw.containsInFlight(peer, over_cap_rid));
    switch (pw.shouldEmit(peer, over_cap_rid, now + 999)) {
        .wait => |w| try std.testing.expectEqual(now + 1000, w.until_ms),
        else => return error.TestUnexpectedResult,
    }
}

test "mesh backpressure: stale in-flight entry never starves a live head; reclaim waits a full cap period past due" {
    const allocator = std.testing.allocator;
    var pw = try PeerWindows.init(allocator, .{ .max_peers = 1 });
    defer pw.deinit();
    const peer: u64 = 5;

    // Fill the window at t=0; these heads are then retired by a path that
    // never calls noteAck, so they are never presented again (stale).
    var seed: u32 = 0;
    while (seed < per_peer_window_cap) : (seed += 1) pw.noteEmitted(peer, testRelayId(seed), 0);
    const first_new = testRelayId(1000);
    const second_new = testRelayId(1001);

    // Every stale entry is due at 1000; reclaim needs a further retry_cap_ms.
    const reclaim_at = default_base_retry_ms + retry_cap_ms;
    try std.testing.expectEqual(EmitDecision.window_full, pw.shouldEmit(peer, first_new, reclaim_at - 1));
    pw.noteEmitted(peer, first_new, reclaim_at - 1); // still a no-op before reclaim
    try std.testing.expect(!pw.containsInFlight(peer, first_new));
    try std.testing.expectEqual(@as(u64, 0), pw.idle_reclaimed);

    try std.testing.expectEqual(EmitDecision.emit, pw.shouldEmit(peer, first_new, reclaim_at));
    pw.noteEmitted(peer, first_new, reclaim_at);
    try std.testing.expect(pw.containsInFlight(peer, first_new));
    // Deterministic victim: earliest due, lowest index on a tie.
    try std.testing.expect(!pw.containsInFlight(peer, testRelayId(0)));
    try std.testing.expectEqual(per_peer_window_cap, pw.inFlightCount(peer));
    try std.testing.expectEqual(@as(u64, 1), pw.idle_reclaimed);

    // The freshly tracked head is live and never itself the next victim.
    pw.noteEmitted(peer, second_new, reclaim_at);
    try std.testing.expect(pw.containsInFlight(peer, first_new));
    try std.testing.expect(pw.containsInFlight(peer, second_new));
    try std.testing.expect(!pw.containsInFlight(peer, testRelayId(1)));
    try std.testing.expectEqual(per_peer_window_cap, pw.inFlightCount(peer));

    // The reclaimed head paces normally from its fresh first send.
    switch (pw.shouldEmit(peer, first_new, reclaim_at + 999)) {
        .wait => |w| try std.testing.expectEqual(reclaim_at + 1000, w.until_ms),
        else => return error.TestUnexpectedResult,
    }
}

test "mesh backpressure: rotating heads beyond the window to a stalled peer stay bounded and none starves under slow rotation" {
    const allocator = std.testing.allocator;
    const head_count: u32 = per_peer_window_cap + 1;
    const peer: u64 = 11;

    // Fast rotation (every head presented every 100ms): live tracked heads
    // never go idle, so the extra head is held back and every tracked head
    // follows the capped backoff schedule — bounded, never per poll.
    {
        var pw = try PeerWindows.init(allocator, .{ .max_peers = 1 });
        defer pw.deinit();
        var sends: [head_count]u32 = @splat(0);
        var now: u64 = 0;
        while (now <= 300_000) : (now += 100) {
            var seed: u32 = 0;
            while (seed < head_count) : (seed += 1) {
                const rid = testRelayId(seed);
                if (pw.shouldEmit(peer, rid, now) == .emit) {
                    pw.noteEmitted(peer, rid, now);
                    sends[seed] += 1;
                }
            }
        }
        // 0,1,3,7,15,31,63 s then every 32 s: 15 sends inside 300 s.
        for (sends[0..per_peer_window_cap]) |count| try std.testing.expect(count <= 15);
        try std.testing.expectEqual(@as(u32, 0), sends[per_peer_window_cap]);
        try std.testing.expectEqual(@as(u64, 0), pw.idle_reclaimed);
    }

    // Slow rotation (one head per 2 s, a 66 s cycle): tracked heads idle
    // past the cap, so reclaim lets every head through while sends never
    // exceed presentations.
    {
        var pw = try PeerWindows.init(allocator, .{ .max_peers = 1 });
        defer pw.deinit();
        var sends: [head_count]u32 = @splat(0);
        var presentations: u32 = 0;
        var now: u64 = 0;
        var turn: u32 = 0;
        while (now <= 600_000) : ({
            now += 2000;
            turn += 1;
        }) {
            const seed = turn % head_count;
            presentations += 1;
            const rid = testRelayId(seed);
            if (pw.shouldEmit(peer, rid, now) == .emit) {
                pw.noteEmitted(peer, rid, now);
                sends[seed] += 1;
            }
            try std.testing.expect(pw.inFlightCount(peer) <= per_peer_window_cap);
        }
        var total: u32 = 0;
        for (sends) |count| {
            try std.testing.expect(count >= 1);
            total += count;
        }
        try std.testing.expect(total <= presentations);
        try std.testing.expect(pw.idle_reclaimed > 0);
    }
}

fn testRequest(quota_rows: usize, origin_rows: usize, total_rows: usize) Request {
    return .{
        .quota = .{ .rows = quota_rows, .bytes = 1 << 20 },
        .origin = .{ .rows = origin_rows, .bytes = origin_rows * 100 },
        .total = .{ .log_rows = total_rows, .log_max_rows = 64, .log_max_bytes = 1 << 24 },
        .incoming_bytes = 100,
    };
}

test "mesh backpressure: local admission sheds at the own-origin high watermark with hysteresis and returns retry_after hint" {
    var gate: AdmissionGate = .{};
    const at = struct {
        fn req(rows: usize) Request {
            return testRequest(8, rows, rows);
        }
    }.req;

    try std.testing.expectEqual(AdmitDecision.admit, gate.classifyLocal(at(6)));
    switch (gate.classifyLocal(at(7))) {
        .shed => |s| try std.testing.expect(s.retry_after_ms > 0),
        else => return error.TestUnexpectedResult,
    }
    // Hysteresis: still at/above the low watermark (3/4 of 8 == 6) keeps
    // shedding even though the share dropped below the high watermark.
    switch (gate.classifyLocal(at(6))) {
        .shed => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(AdmitDecision.admit, gate.classifyLocal(at(5)));
    switch (gate.classifyLocal(at(7))) {
        .shed => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 3), gate.local_shed);
    try std.testing.expectEqual(@as(usize, 7), gate.peak_origin.rows);
}

test "mesh backpressure: transit admission is partitioned by origin, independent of other origins' occupancy" {
    var gate: AdmissionGate = .{};
    // 60 of 64 rows retained by other origins: far past any aggregate
    // watermark, yet this origin is below its quota, so its row is admitted.
    try std.testing.expectEqual(AdmitDecision.admit, gate.classifyTransit(testRequest(16, 15, 60)));
    // The origin at its quota sheds even though the store has free rows.
    switch (gate.classifyTransit(testRequest(16, 16, 20))) {
        .shed => {},
        else => return error.TestUnexpectedResult,
    }
    // The incoming footprint must fit the origin's byte share too.
    var too_big = testRequest(16, 1, 1);
    too_big.quota.bytes = 150;
    switch (gate.classifyTransit(too_big)) {
        .shed => {},
        else => return error.TestUnexpectedResult,
    }
    // Whole-store hard bounds stay a fail-closed backstop.
    var outbox_full = testRequest(16, 0, 1);
    outbox_full.total.outbox_len = 1;
    switch (gate.classifyTransit(outbox_full)) {
        .shed => {},
        else => return error.TestUnexpectedResult,
    }
    var log_bytes_full = testRequest(16, 0, 1);
    log_bytes_full.total.log_bytes = log_bytes_full.total.log_max_bytes - 50;
    switch (gate.classifyTransit(log_bytes_full)) {
        .shed => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 4), gate.transit_shed);
    gate.noteTransitCapacityWithheld();
    try std.testing.expectEqual(@as(u64, 1), gate.transit_capacity_withheld);
}

test "mesh backpressure: origin quota splits rows and cursor-reserved bytes by membership and rejects unusable bounds" {
    const quota = try OriginQuota.init(.{
        .log_max_rows = 8,
        .log_max_aggregate_bytes = 10 * cursor_entry_len + 3000,
        .log_max_cursor_nodes = 10,
        .origins = 3,
    });
    try std.testing.expectEqual(@as(usize, 2), quota.rows);
    try std.testing.expectEqual(@as(usize, 1000), quota.bytes);
    // Shares of every member fit inside the store bounds.
    try std.testing.expect(quota.rows * 3 <= 8);

    try std.testing.expectError(error.InvalidConfig, OriginQuota.init(.{
        .log_max_rows = 8,
        .log_max_aggregate_bytes = 1 << 20,
        .log_max_cursor_nodes = 4,
        .origins = 0,
    }));
    try std.testing.expectError(error.InvalidConfig, OriginQuota.init(.{
        .log_max_rows = 2,
        .log_max_aggregate_bytes = 1 << 20,
        .log_max_cursor_nodes = 4,
        .origins = 3,
    }));
    try std.testing.expectError(error.InvalidConfig, OriginQuota.init(.{
        .log_max_rows = 8,
        .log_max_aggregate_bytes = 4 * cursor_entry_len,
        .log_max_cursor_nodes = 4,
        .origins = 2,
    }));

    // Footprint covers required + confirmed + excluded-once node lists.
    try std.testing.expectEqual(@as(usize, 100 + 3 * 16), rowFootprint(100, 3));
    try std.testing.expectEqual(std.math.maxInt(usize), rowFootprint(std.math.maxInt(usize), 3));
}

test "mesh backpressure: capacity failure classifies as retryable capacity, never permanent" {
    try std.testing.expectEqual(RejectCause.capacity, classifyAdmitFailure(error.CapacityExceeded));
    try std.testing.expectEqual(RejectCause.transient, classifyAdmitFailure(error.OutOfMemory));
    try std.testing.expectEqual(RejectCause.permanent, classifyAdmitFailure(error.InvalidWire));
    try std.testing.expectEqual(RejectCause.permanent, classifyAdmitFailure(error.Truncated));
}

test "mesh backpressure: resend count per head under sustained stall is bounded by the backoff schedule" {
    const allocator = std.testing.allocator;
    var pw = try PeerWindows.init(allocator, .{});
    defer pw.deinit();
    const peer: u64 = 1;
    const rid = testRelayId(1);

    var now: u64 = 0;
    var sends: usize = 0;
    const horizon_ms: u64 = 100_000;
    while (now <= horizon_ms) {
        switch (pw.shouldEmit(peer, rid, now)) {
            .emit => {
                pw.noteEmitted(peer, rid, now);
                sends += 1;
                try std.testing.expect(sends <= 64); // guards against a real amplification regression
                // The entry is now in flight; the very next decision at this
                // same instant must be .wait — jump straight to it.
                switch (pw.shouldEmit(peer, rid, now)) {
                    .wait => |w| now = w.until_ms,
                    else => unreachable,
                }
            },
            .wait => |w| now = w.until_ms,
            .window_full => unreachable,
        }
    }
    // Schedule: 0, 1000, 3000, 7000, 15000, 31000, 63000, 95000 — 8 sends
    // inside [0, 100000]. Never one-send-per-poll-iteration amplification.
    try std.testing.expectEqual(@as(usize, 8), sends);
}

// ---------------------------------------------------------------------------
// Three-node retained-row DST over real RVL2 event logs.
// ---------------------------------------------------------------------------

const DstPolicy = enum { per_origin, aggregate_legacy };

/// Test-only replica of the superseded gate: one shared pool, local
/// hysteresis at 7/8..3/4 of the whole log, transit admitted to the hard cap.
/// The DST keeps it as the negative control that must wedge.
const LegacyAggregateGate = struct {
    shedding: bool = false,

    fn local(self: *LegacyAggregateGate, rows: usize, max: usize) bool {
        if (self.shedding) {
            if (!ratioAtLeast(rows, max, 3, 4)) self.shedding = false;
        } else if (ratioAtLeast(rows, max, 7, 8)) {
            self.shedding = true;
        }
        return !self.shedding;
    }

    fn transit(rows: usize, max: usize) bool {
        return rows < max;
    }
};

const dst_node_count = 3;
const dst_tick_ms: u64 = 250;
const dst_page_len = 4;
/// Every DST wire is at most this long (asserted), so local admission can
/// be decided before paying for a signature.
const dst_wire_bound: usize = 512;

const DstSchedule = struct {
    seed: u64,
    /// Every link is down before this instant (partition).
    heal_at_ms: u64 = 0,
    /// The reverse ring direction (B->A, C->B, A->C) stays down this much
    /// longer than the forward ring after the heal.
    reverse_skew_ms: u64 = 0,
    /// Every frame to or from this node is dropped before `slow_until_ms`.
    slow_node: ?usize = null,
    slow_until_ms: u64 = 0,
    /// Independent loss applied to every data frame and every ACK frame.
    loss_percent: u8 = 0,
    authored_per_node: u32,
    horizon_ms: u64,
};

const DstResult = struct {
    converged: bool,
    final_rows: [dst_node_count]usize,
    authored: [dst_node_count]u32,
    last_progress_ms: u64,
    end_ms: u64,
    local_admit_at_end: bool,
    /// Gate pressure summed over nodes; proves the quota actually bound.
    local_shed: u64 = 0,
    transit_shed: u64 = 0,
    /// Rows first accepted from a peer rather than authored.
    transit_inserted: u64 = 0,
    peak_origin_rows: usize = 0,
};

const DstNode = struct {
    kp: sign.KeyPair,
    id: u64,
    log: EventLog,
    gate: AdmissionGate = .{},
    legacy: LegacyAggregateGate = .{},
    pacing: PeerWindows,
    /// Durable acceptance memory (RVG2 retained replay + RVO2 receipt): a
    /// node that ever accepted a RelayId re-ACKs it without a new RVL2 row.
    accepted: std.AutoHashMapUnmanaged(RelayId, void) = .empty,
    /// Highest HLC first accepted per origin index, for order checking.
    last_hlc: [dst_node_count]u64 = @splat(0),
    next_hlc: u64 = 1,
    authored: u32 = 0,
};

const DstAttempt = struct {
    from: usize,
    to: usize,
    relay_id: RelayId,
    origin_node: u64,
    hlc: u64,
    wire: []const u8,
};

fn dstOriginIndex(nodes: *const [dst_node_count]DstNode, origin_node: u64) usize {
    for (nodes, 0..) |node, index| if (node.id == origin_node) return index;
    unreachable;
}

fn dstLinkUp(sched: DstSchedule, rng: std.Random, from: usize, to: usize, now: u64) bool {
    if (now < sched.heal_at_ms) return false;
    if (to == (from + dst_node_count - 1) % dst_node_count and now < sched.heal_at_ms +| sched.reverse_skew_ms)
        return false;
    if (sched.slow_node) |slow| if ((from == slow or to == slow) and now < sched.slow_until_ms) return false;
    if (sched.loss_percent != 0 and rng.uintLessThan(u8, 100) < sched.loss_percent) return false;
    return true;
}

fn dstMakeWire(allocator: std.mem.Allocator, node: *const DstNode, hlc: u64) !struct { id: RelayId, wire: []u8 } {
    var text_buf: [48]u8 = undefined;
    const text = try std.fmt.bufPrint(&text_buf, "backpressure {x} {d}", .{ node.id, hlc });
    var pubkey: [message_relay_v2.pubkey_len]u8 = undefined;
    var signature: [message_relay_v2.sig_len]u8 = undefined;
    var msg = message_relay_v2.RelayMessage{
        .verb = .privmsg,
        .target = "#backpressure",
        .source_prefix = "alice!u@mesh.test",
        .text = text,
        .scope_kind = .channel,
        .origin_node = node.id,
        .hlc = hlc,
    };
    try message_relay_v2.stampOrigin(allocator, &msg, &node.kp, &pubkey, &signature);
    const id = switch (try message_relay_v2.verifyAndRelayId(allocator, msg)) {
        .verified => |verified| verified,
        else => return error.TestUnexpectedResult,
    };
    return .{ .id = id, .wire = try message_relay_v2.encode(allocator, msg) };
}

fn dstAdmitLocal(policy: DstPolicy, node: *DstNode, quota: OriginQuota) bool {
    return switch (policy) {
        .per_origin => node.gate.classifyLocal(.{
            .quota = quota,
            .origin = originUsage(&node.log, node.id),
            .total = logOccupancy(&node.log),
            .incoming_bytes = rowFootprint(dst_wire_bound, dst_node_count),
        }) == .admit,
        .aggregate_legacy => node.legacy.local(node.log.len(), node.log.config.max_rows),
    };
}

fn dstAdmitTransit(policy: DstPolicy, node: *DstNode, quota: OriginQuota, attempt: DstAttempt) bool {
    return switch (policy) {
        .per_origin => node.gate.classifyTransit(.{
            .quota = quota,
            .origin = originUsage(&node.log, attempt.origin_node),
            .total = logOccupancy(&node.log),
            .incoming_bytes = rowFootprint(attempt.wire.len, dst_node_count),
        }) == .admit,
        .aggregate_legacy => LegacyAggregateGate.transit(node.log.len(), node.log.config.max_rows),
    };
}

/// Record a first durable acceptance: exactly once per (node, RelayId) and,
/// for each origin, in strictly increasing HLC order.
fn dstRecordAccept(nodes: *[dst_node_count]DstNode, to: usize, relay_id: RelayId, origin_node: u64, hlc: u64) !void {
    const node = &nodes[to];
    const gop = try node.accepted.getOrPut(std.testing.allocator, relay_id);
    try std.testing.expect(!gop.found_existing);
    const origin = dstOriginIndex(nodes, origin_node);
    try std.testing.expect(hlc > node.last_hlc[origin]);
    node.last_hlc[origin] = hlc;
}

fn runRetainedRowDst(policy: DstPolicy, sched: DstSchedule) !DstResult {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(sched.seed);
    const rng = prng.random();

    var nodes: [dst_node_count]DstNode = undefined;
    var ready: usize = 0;
    defer for (nodes[0..ready]) |*node| {
        node.accepted.deinit(allocator);
        node.pacing.deinit();
        node.log.deinit();
        node.kp.deinit();
    };
    for (&nodes, 0..) |*node, index| {
        var kp = try sign.KeyPair.fromSeed(@as([sign.seed_len]u8, @splat(@intCast(0x61 + index))));
        errdefer kp.deinit();
        var log = try EventLog.init(allocator, .{
            .max_rows = 8,
            .max_confirmed_nodes_per_row = dst_node_count,
            .max_cursor_nodes = dst_node_count,
        });
        errdefer log.deinit();
        const pacing = try PeerWindows.init(allocator, .{ .max_peers = dst_node_count });
        node.* = .{
            .kp = kp,
            .id = signed_frame.originShortId(kp.public_key),
            .log = log,
            .pacing = pacing,
        };
        ready += 1;
    }
    var required: [dst_node_count]u64 = undefined;
    for (nodes, 0..) |node, index| required[index] = node.id;
    std.mem.sort(u64, &required, {}, std.sort.asc(u64));
    const quota = try OriginQuota.forLog(&nodes[0].log, dst_node_count);
    try std.testing.expectEqual(@as(usize, 2), quota.rows);

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    var last_progress: u64 = 0;
    var transit_inserted: u64 = 0;
    var now: u64 = 0;
    var converged = false;
    while (now <= sched.horizon_ms) : (now += dst_tick_ms) {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();

        // 1. Every node keeps authoring while it has demand left.
        for (&nodes, 0..) |*node, self_index| {
            if (node.authored >= sched.authored_per_node) continue;
            if (!dstAdmitLocal(policy, node, quota)) continue;
            const hlc = node.next_hlc;
            const made = try dstMakeWire(allocator, node, hlc);
            defer allocator.free(made.wire);
            try std.testing.expect(made.wire.len <= dst_wire_bound);
            // The gate must never be more permissive than the store.
            try std.testing.expectEqual(
                relay_v2_event_log.ReserveOutcome.inserted,
                try node.log.reserveAccepted(made.id, made.wire, node.id, null, &required),
            );
            try dstRecordAccept(&nodes, self_index, made.id, node.id, hlc);
            node.next_hlc += 1;
            node.authored += 1;
            last_progress = now;
        }

        // 2. Snapshot every link's paced page first: frames on different
        // links are concurrently in flight, so each sees pre-tick state.
        var attempts: std.ArrayList(DstAttempt) = .empty;
        for (&nodes, 0..) |*sender, from| {
            for (0..dst_node_count) |to| {
                if (to == from) continue;
                var page: [dst_page_len]relay_v2_event_log.PageItem = undefined;
                const count = try sender.log.collectPageForNode(nodes[to].id, &page);
                for (page[0..count]) |item| {
                    if (sender.pacing.shouldEmit(nodes[to].id, item.relay_id, now) != .emit) continue;
                    sender.pacing.noteEmitted(nodes[to].id, item.relay_id, now);
                    try attempts.append(arena, .{
                        .from = from,
                        .to = to,
                        .relay_id = item.relay_id,
                        .origin_node = item.origin_node,
                        .hlc = item.hlc,
                        .wire = try arena.dupe(u8, item.wire),
                    });
                }
            }
        }

        // 3. Deliver, admit or withhold, and return durable ACKs.
        for (attempts.items) |attempt| {
            if (!dstLinkUp(sched, rng, attempt.from, attempt.to, now)) continue;
            const receiver = &nodes[attempt.to];
            const sender = &nodes[attempt.from];
            var acked = false;
            if (receiver.accepted.contains(attempt.relay_id)) {
                if (receiver.log.contains(attempt.relay_id)) {
                    const outcome = receiver.log.reserveAccepted(
                        attempt.relay_id,
                        attempt.wire,
                        receiver.id,
                        sender.id,
                        &required,
                    ) catch |err| switch (err) {
                        error.CapacityExceeded => if (policy == .per_origin) return err else continue,
                        else => return err,
                    };
                    try std.testing.expectEqual(relay_v2_event_log.ReserveOutcome.exact_duplicate, outcome);
                }
                acked = true;
            } else if (dstAdmitTransit(policy, receiver, quota, attempt)) {
                const outcome = receiver.log.reserveAccepted(
                    attempt.relay_id,
                    attempt.wire,
                    receiver.id,
                    sender.id,
                    &required,
                ) catch |err| switch (err) {
                    error.CapacityExceeded => {
                        // Per-origin admission must never outrun the store.
                        if (policy == .per_origin) return err;
                        receiver.gate.noteTransitCapacityWithheld();
                        continue;
                    },
                    else => return err,
                };
                try std.testing.expectEqual(relay_v2_event_log.ReserveOutcome.inserted, outcome);
                try dstRecordAccept(&nodes, attempt.to, attempt.relay_id, attempt.origin_node, attempt.hlc);
                if (policy == .per_origin)
                    try std.testing.expect(originUsage(&receiver.log, attempt.origin_node).rows <= quota.rows);
                transit_inserted += 1;
                acked = true;
                last_progress = now;
            }
            if (!acked or !dstLinkUp(sched, rng, attempt.to, attempt.from, now)) continue;
            const confirmed = try sender.log.confirmAuthenticatedDurableAck(attempt.relay_id, receiver.id);
            if (confirmed == .confirmed_and_retired) last_progress = now;
            sender.pacing.noteAck(receiver.id, attempt.relay_id);
        }

        for (nodes) |node| try std.testing.expect(node.log.len() <= node.log.config.max_rows);
        var done = true;
        for (nodes) |node| {
            if (node.authored < sched.authored_per_node or node.log.len() != 0) done = false;
        }
        if (done) {
            converged = true;
            break;
        }
    }

    var result: DstResult = .{
        .converged = converged,
        .final_rows = undefined,
        .authored = undefined,
        .last_progress_ms = last_progress,
        .end_ms = @min(now, sched.horizon_ms),
        .local_admit_at_end = true,
        .transit_inserted = transit_inserted,
    };
    for (&nodes, 0..) |*node, index| {
        result.final_rows[index] = node.log.len();
        result.authored[index] = node.authored;
        result.local_shed += node.gate.local_shed;
        result.transit_shed += node.gate.transit_shed;
        result.peak_origin_rows = @max(result.peak_origin_rows, node.gate.peak_origin.rows);
        if (converged) {
            // Every authored event reached every node exactly once.
            try std.testing.expectEqual(
                @as(usize, dst_node_count * sched.authored_per_node),
                node.accepted.count(),
            );
        }
        if (policy == .per_origin and !dstAdmitLocal(policy, node, quota))
            result.local_admit_at_end = false;
    }
    return result;
}

/// Non-vacuity: every node relayed every peer's rows (2 x 3 x authored
/// first transit accepts), and both the local and transit quotas bound.
fn dstExpectPressure(result: DstResult, sched: DstSchedule) !void {
    try std.testing.expectEqual(
        @as(u64, (dst_node_count - 1) * dst_node_count * sched.authored_per_node),
        result.transit_inserted,
    );
    try std.testing.expect(result.local_shed > 0);
    try std.testing.expect(result.transit_shed > 0);
    try std.testing.expectEqual(@as(usize, 2), result.peak_origin_rows);
}

/// Partition every link while each node fills its own share, then heal the
/// forward ring (A->B, B->C, C->A) a minute before the reverse ring. Under a
/// shared pool each node takes the one foreign row that still needs the next
/// node, reaches 8/8 and nothing can ever retire.
const ring_heal_schedule: DstSchedule = .{
    .seed = 0x5eed_0001,
    .heal_at_ms = 10_000,
    .reverse_skew_ms = 60_000,
    .authored_per_node = 16,
    .horizon_ms = 30 * 60 * 1000,
};

test "mesh backpressure: retained-row DST negative control: the shared aggregate pool wedges every node at 8/8 after a ring heal" {
    const result = try runRetainedRowDst(.aggregate_legacy, ring_heal_schedule);
    try std.testing.expect(!result.converged);
    for (result.final_rows) |rows| try std.testing.expectEqual(@as(usize, 8), rows);
    for (result.authored) |authored| try std.testing.expect(authored < ring_heal_schedule.authored_per_node);
    // Wedged, not slow: nothing was admitted or retired for the last ~29 min.
    try std.testing.expect(result.end_ms - result.last_progress_ms >= 25 * 60 * 1000);
}

test "mesh backpressure: retained-row DST: per-origin quota drains the same ring heal, every row retires and local authoring resumes" {
    const result = try runRetainedRowDst(.per_origin, ring_heal_schedule);
    try std.testing.expect(result.converged);
    for (result.final_rows) |rows| try std.testing.expectEqual(@as(usize, 0), rows);
    for (result.authored) |authored| try std.testing.expectEqual(ring_heal_schedule.authored_per_node, authored);
    try std.testing.expect(result.local_admit_at_end);
    try dstExpectPressure(result, ring_heal_schedule);
}

test "mesh backpressure: retained-row DST: slow C withholding ACKs under seeded loss converges on every node with the per-origin quota" {
    const seeds = [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    for (seeds) |seed| {
        const sched: DstSchedule = .{
            .seed = seed,
            .slow_node = 2,
            .slow_until_ms = 20_000 + seed * 1_750,
            .loss_percent = 20,
            .authored_per_node = 16,
            .horizon_ms = 60 * 60 * 1000,
        };
        const result = runRetainedRowDst(.per_origin, sched) catch |err| {
            std.debug.print("retained-row DST failed: seed={d} err={s}\n", .{ seed, @errorName(err) });
            return err;
        };
        if (!result.converged) std.debug.print("retained-row DST stuck: seed={d} rows={any}\n", .{ seed, result.final_rows });
        try std.testing.expect(result.converged);
        for (result.final_rows) |rows| try std.testing.expectEqual(@as(usize, 0), rows);
        try std.testing.expect(result.local_admit_at_end);
        try dstExpectPressure(result, sched);
    }
}
