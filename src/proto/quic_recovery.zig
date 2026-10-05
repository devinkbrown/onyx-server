// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC loss recovery + congestion control (RFC 9002) — layer 5b of the
//! from-scratch QUIC stack. This is the controller `quic_conn.zig` drives:
//! it records every ack-eliciting / in-flight packet on send, consumes the
//! newly-acked packet numbers the ack manager (`quic_conn_state`) returns on an
//! inbound ACK, samples the RTT, declares losses, computes the loss-detection
//! and PTO timers, and runs a NewReno congestion window so the driver can gate
//! its sends.
//!
//! It is socketless and clockless: the driver passes the `now` (a nanosecond
//! value in its own clock domain) into every call; nothing here reads a clock
//! or a socket. All time is integer nanoseconds; RFC ratios (9/8, 3/4, 7/8,
//! 1/2) are applied with integer math, never floats.
//!
//! What maps to which RFC 9002 section:
//!   * `SentPacket` + `SentRegistry` — the sent-packets bookkeeping of §A.1
//!     ("Tracking Sent Packets"): one registry per packet-number space, each
//!     entry carrying the timing/in-flight/size and the frame ranges the driver
//!     must be able to re-queue on loss.
//!   * `RttEstimator` — §5 ("Estimating the Round-Trip Time"): latest_rtt,
//!     min_rtt, smoothed_rtt, rttvar, with the first-sample initialization and
//!     the ack_delay subtraction (§5.3).
//!   * loss detection (`onAckReceived` → `detectLost`) — §6.1: the packet
//!     threshold (kPacketThreshold = 3) and the time threshold
//!     (kTimeThreshold = 9/8 × max(smoothed_rtt, latest_rtt), floored at
//!     kGranularity).
//!   * PTO (`ptoTimeout`, `onPtoExpired`) — §6.2: pto = smoothed_rtt +
//!     max(4×rttvar, kGranularity) + (handshake_confirmed ? max_ack_delay : 0),
//!     scaled by 2^pto_count.
//!   * `Congestion` — §7 (NewReno): kInitialWindow = 10 × max_datagram, a
//!     min window of 2 × max_datagram, slow start, congestion avoidance, and a
//!     recovery period that ignores losses already in the current recovery.
//!
//!   * persistent congestion (`detectLost` → `Congestion.onPersistentCongestion`)
//!     — §7.6: a span of only-lost ack-eliciting packets longer than the
//!     persistent-congestion duration collapses the window to the minimum and
//!     re-enters slow start.
//!
//! Deferred (typed gaps, called out in the driver's docs too): ECN and pacing.
//! Everything else here is the real RFC algorithm.

const std = @import("std");
const Allocator = std.mem.Allocator;

const quic_protect = @import("quic_protect.zig");

pub const EncryptionLevel = quic_protect.EncryptionLevel;

// ===========================================================================
// RFC 9002 constants (§6.1.1, §6.1.2, §6.2.1, §7.2)
// ===========================================================================

/// kPacketThreshold (§6.1.1): a packet is lost if a packet at least this many
/// packet numbers higher in the same space has been acknowledged.
pub const packet_threshold: u64 = 3;

/// kGranularity (§6.1.2 / §A.4): the timer granularity. The time threshold and
/// the PTO are both floored at this value so a tiny RTT cannot make the timers
/// degenerate. 1 ms.
pub const granularity_ns: u64 = 1 * std.time.ns_per_ms;

/// kTimeThreshold (§6.1.2) is 9/8; we apply it as a ×9/8 integer scaling.
pub const time_threshold_num: u64 = 9;
pub const time_threshold_den: u64 = 8;

/// kInitialWindow (§7.2): the initial congestion window is the smaller of
/// 10×max_datagram and 14720 bytes; we use 10×max_datagram which is < 14720 for
/// our 1252-byte datagram.
pub const initial_window_packets: u64 = 10;

/// kMinimumWindow (§7.2): the congestion window never falls below 2×max_datagram.
pub const minimum_window_packets: u64 = 2;

/// kLossReductionFactor (§7.3.2): on congestion the window is multiplied by 1/2.
pub const loss_reduction_num: u64 = 1;
pub const loss_reduction_den: u64 = 2;

/// kPersistentCongestionThreshold (§7.6): 3. Multiplies the per-PTO base to give
/// the persistent-congestion duration in `detectLost`.
pub const persistent_congestion_threshold: u64 = 3;

/// Default max_ack_delay (§6.2.1 / RFC 9000 §18.2): 25 ms. Used in the PTO once
/// the handshake is confirmed. The driver can override from the peer's
/// transport parameters.
pub const default_max_ack_delay_ns: u64 = 25 * std.time.ns_per_ms;

/// Defensive cap on the sent-packet registry per space. A well-behaved path has
/// O(cwnd / max_datagram) outstanding packets; this bound keeps a buggy or
/// hostile peer from forcing unbounded growth. On overflow we drop the oldest
/// (lowest packet number) entry — which only risks a missed retransmit for a
/// packet so old it would have timed out anyway.
pub const default_max_sent: usize = 4096;

// ===========================================================================
// Re-queueable frame description (§A.1: "the frames it sent")
// ===========================================================================

/// What a lost packet carried that the driver must be able to re-send. The
/// recovery layer does not re-encode frames; it returns these descriptors and
/// the driver rewinds its CRYPTO send buffer / re-queues its STREAM data.
///
/// We keep this small and copyable (no owned slices): CRYPTO is an absolute
/// (offset,len) range on the per-level CRYPTO stream, STREAM names a stream id +
/// (offset,len,fin) so the driver re-queues from its own send map, and `ping`
/// means the packet was a bare probe (a fresh PING covers it).
pub const LostFrame = union(enum) {
    crypto: struct { offset: u64, len: u64 },
    stream: struct { stream_id: u64, offset: u64, len: u64, fin: bool },
    /// A pure probe / PING — retransmitted as a fresh PING by the driver.
    ping,
};

/// A bounded inline list of re-queueable frame descriptors for one sent packet.
/// A handshake or app packet carries only a handful of ack-eliciting frames; we
/// store up to `cap` inline and silently coalesce beyond that (the driver's
/// CRYPTO rewind is offset-based and idempotent, so a dropped descriptor at
/// worst costs a slightly larger retransmit, never correctness).
pub const FrameList = struct {
    pub const cap: usize = 8;
    items: [cap]LostFrame = undefined,
    len: u8 = 0,

    pub fn append(self: *FrameList, f: LostFrame) void {
        if (self.len >= cap) return;
        self.items[self.len] = f;
        self.len += 1;
    }

    pub fn slice(self: *const FrameList) []const LostFrame {
        return self.items[0..self.len];
    }
};

// ===========================================================================
// Sent-packet registry (§A.1)
// ===========================================================================

/// One sent packet's recovery metadata (RFC 9002 §A.1, the SentPacket struct).
pub const SentPacket = struct {
    packet_number: u64,
    /// Time the packet was sent, in the driver's nanosecond clock.
    time_sent_ns: u64,
    /// Whether the packet counts toward `bytes_in_flight` and triggers timers.
    /// Per §2, ACK-only / PADDING-only packets are not in flight.
    in_flight: bool,
    /// Whether the packet is ack-eliciting (carries anything other than ACK /
    /// PADDING / CONNECTION_CLOSE). Drives the PTO and the RTT sample eligibility.
    ack_eliciting: bool,
    /// Bytes the packet occupied on the wire (for congestion accounting).
    sent_bytes: u64,
    /// The re-queueable frames the driver must resend if this packet is lost.
    frames: FrameList = .{},
    /// Set once the packet is acked or declared lost, so we account it exactly
    /// once and can compact the registry.
    retired: bool = false,
};

/// Per-space record of every still-tracked sent packet, kept sorted ascending
/// by packet number (packets are assigned monotonically by the space, so a
/// plain append keeps it sorted). Bounded by `max_sent`.
pub const SentRegistry = struct {
    packets: std.ArrayList(SentPacket) = .empty,
    max_sent: usize,
    /// Largest packet number recorded as ack-eliciting (for PTO bookkeeping).
    largest_sent_ack_eliciting: ?u64 = null,
    /// The time the most recent ack-eliciting packet was sent — §6.2 arms the
    /// PTO relative to this.
    last_ack_eliciting_sent_ns: ?u64 = null,

    pub fn init(max_sent: usize) SentRegistry {
        std.debug.assert(max_sent > 0);
        return .{ .max_sent = max_sent };
    }

    pub fn deinit(self: *SentRegistry, allocator: Allocator) void {
        self.packets.deinit(allocator);
        self.* = undefined;
    }

    /// Record a freshly-sent packet. The driver supplies the metadata; the
    /// registry keeps it for ACK/loss/PTO processing. Drops the oldest entry if
    /// at capacity (defensive bound).
    pub fn record(self: *SentRegistry, allocator: Allocator, p: SentPacket) Allocator.Error!void {
        if (self.packets.items.len >= self.max_sent) {
            _ = self.packets.orderedRemove(0);
        }
        try self.packets.append(allocator, p);
        if (p.ack_eliciting) {
            if (self.largest_sent_ack_eliciting == null or p.packet_number > self.largest_sent_ack_eliciting.?) {
                self.largest_sent_ack_eliciting = p.packet_number;
            }
            self.last_ack_eliciting_sent_ns = p.time_sent_ns;
        }
    }

    /// Find a still-live (not retired) sent packet by number, or null.
    pub fn find(self: *SentRegistry, pn: u64) ?*SentPacket {
        for (self.packets.items) |*p| {
            if (p.packet_number == pn and !p.retired) return p;
        }
        return null;
    }

    /// Whether any unretired ack-eliciting packet is still outstanding.
    pub fn hasInFlightAckEliciting(self: *const SentRegistry) bool {
        for (self.packets.items) |p| {
            if (!p.retired and p.ack_eliciting and p.in_flight) return true;
        }
        return false;
    }

    /// The earliest (smallest time_sent) unretired ack-eliciting packet still in
    /// flight — the candidate for the loss-detection time threshold.
    pub fn earliestInFlightSent(self: *const SentRegistry) ?u64 {
        var earliest: ?u64 = null;
        for (self.packets.items) |p| {
            if (p.retired or !p.in_flight) continue;
            if (earliest == null or p.time_sent_ns < earliest.?) earliest = p.time_sent_ns;
        }
        return earliest;
    }

    /// Remove all retired packets, compacting the list. Called after each
    /// ACK/loss pass so the registry stays bounded by the in-flight window.
    pub fn compact(self: *SentRegistry) void {
        var w: usize = 0;
        for (self.packets.items) |p| {
            if (!p.retired) {
                self.packets.items[w] = p;
                w += 1;
            }
        }
        self.packets.shrinkRetainingCapacity(w);
    }
};

// ===========================================================================
// RTT estimation (RFC 9002 §5)
// ===========================================================================

/// The RTT estimator state (§5). All values are nanoseconds. `smoothed_rtt`
/// and `rttvar` are valid only after `has_sample`.
pub const RttEstimator = struct {
    has_sample: bool = false,
    latest_rtt: u64 = 0,
    min_rtt: u64 = 0,
    smoothed_rtt: u64 = 0,
    rttvar: u64 = 0,

    pub fn init() RttEstimator {
        return .{};
    }

    /// Update the RTT from a measured ack of the largest newly-acked
    /// ack-eliciting packet (§5.1–5.3).
    ///
    ///   * `rtt_sample_ns` = now − time_sent of that packet (the raw sample).
    ///   * `ack_delay_ns`  = the peer's reported ACK delay, already decoded from
    ///     its ack-delay exponent. It is capped at `max_ack_delay` once the
    ///     handshake is confirmed (§5.3), and only subtracted while the adjusted
    ///     sample stays at or above `min_rtt` (the min_rtt floor).
    pub fn update(
        self: *RttEstimator,
        rtt_sample_ns: u64,
        ack_delay_ns: u64,
        max_ack_delay_ns: u64,
        handshake_confirmed: bool,
    ) void {
        self.latest_rtt = rtt_sample_ns;

        if (!self.has_sample) {
            // First sample (§5.2): min_rtt = latest, smoothed = latest,
            // rttvar = latest/2. ack_delay is NOT applied to the first sample.
            self.min_rtt = rtt_sample_ns;
            self.smoothed_rtt = rtt_sample_ns;
            self.rttvar = rtt_sample_ns / 2;
            self.has_sample = true;
            return;
        }

        // min_rtt tracks the lowest raw sample observed (§5.2).
        if (rtt_sample_ns < self.min_rtt) self.min_rtt = rtt_sample_ns;

        // Adjust for ack delay (§5.3): cap the delay at max_ack_delay once the
        // handshake is confirmed, and only subtract it if the result stays
        // >= min_rtt (so the estimate never drops below the floor).
        var adjusted = rtt_sample_ns;
        var delay = ack_delay_ns;
        if (handshake_confirmed and delay > max_ack_delay_ns) delay = max_ack_delay_ns;
        if (adjusted >= self.min_rtt + delay) {
            adjusted -= delay;
        }

        // rttvar = 3/4·rttvar + 1/4·|smoothed − adjusted|  (§5.3)
        const rttvar_sample = if (self.smoothed_rtt > adjusted)
            self.smoothed_rtt - adjusted
        else
            adjusted - self.smoothed_rtt;
        self.rttvar = (3 * self.rttvar + rttvar_sample) / 4;

        // smoothed_rtt = 7/8·smoothed_rtt + 1/8·adjusted  (§5.3)
        self.smoothed_rtt = (7 * self.smoothed_rtt + adjusted) / 8;
    }

    /// The loss-detection time threshold (§6.1.2):
    ///   max(9/8 × max(smoothed_rtt, latest_rtt), kGranularity).
    pub fn lossDelay(self: *const RttEstimator) u64 {
        const base = @max(self.smoothed_rtt, self.latest_rtt);
        const scaled = (base * time_threshold_num) / time_threshold_den;
        return @max(scaled, granularity_ns);
    }
};

// ===========================================================================
// NewReno congestion control (RFC 9002 §7)
// ===========================================================================

pub const Congestion = struct {
    max_datagram: u64,
    congestion_window: u64,
    ssthresh: u64,
    bytes_in_flight: u64 = 0,
    /// Start time of the current recovery period (§7.3.2); a loss whose packet
    /// was sent before this is already accounted for and does not re-halve the
    /// window. Null when not in recovery.
    recovery_start_ns: ?u64 = null,

    pub fn init(max_datagram: u64) Congestion {
        return .{
            .max_datagram = max_datagram,
            .congestion_window = initial_window_packets * max_datagram,
            .ssthresh = std.math.maxInt(u64),
        };
    }

    fn minWindow(self: *const Congestion) u64 {
        return minimum_window_packets * self.max_datagram;
    }

    /// Whether a packet sent at `sent_ns` falls inside the current recovery
    /// period (§7.3.2) — if so a loss from it must not re-trigger a window cut.
    fn inRecovery(self: *const Congestion, sent_ns: u64) bool {
        const start = self.recovery_start_ns orelse return false;
        return sent_ns <= start;
    }

    /// Account a newly-sent in-flight packet of `bytes` (§7).
    pub fn onPacketSent(self: *Congestion, bytes: u64) void {
        self.bytes_in_flight += bytes;
    }

    /// Apply a newly-acked in-flight packet of `bytes` (§7.3.1). Grows the
    /// window via slow start (cwnd < ssthresh) or congestion avoidance.
    pub fn onPacketAcked(self: *Congestion, bytes: u64) void {
        self.bytes_in_flight -|= bytes;
        if (self.congestion_window < self.ssthresh) {
            // Slow start: cwnd += acked bytes.
            self.congestion_window += bytes;
        } else {
            // Congestion avoidance: cwnd += max_datagram × acked / cwnd.
            const inc = (self.max_datagram * bytes) / self.congestion_window;
            self.congestion_window += @max(inc, 1);
        }
    }

    /// Enter (or stay within) a congestion recovery period for a packet sent at
    /// `sent_ns`, detected at `now_ns` (§7.3.2). Halves the window once per
    /// recovery period; subsequent losses in the same period are ignored.
    pub fn onCongestionEvent(self: *Congestion, sent_ns: u64, now_ns: u64) void {
        if (self.inRecovery(sent_ns)) return; // already accounted
        self.recovery_start_ns = now_ns;
        self.ssthresh = @max(
            (self.congestion_window * loss_reduction_num) / loss_reduction_den,
            self.minWindow(),
        );
        self.congestion_window = self.ssthresh;
    }

    /// Remove a lost packet's bytes from flight (§7.3.2). The window cut is
    /// handled separately by `onCongestionEvent` (once per recovery period).
    pub fn onPacketLost(self: *Congestion, bytes: u64) void {
        self.bytes_in_flight -|= bytes;
    }

    /// Collapse the congestion window to the minimum and re-enter slow start
    /// (RFC 9002 §7.6, "Persistent Congestion"). This is invoked when a span of
    /// only-lost ack-eliciting packets exceeds the persistent-congestion
    /// duration. Resetting `ssthresh` to max forces slow start; `recovery_start`
    /// is cleared so the next loss can still cut the (now-minimal) window.
    pub fn onPersistentCongestion(self: *Congestion) void {
        self.congestion_window = self.minWindow();
        self.ssthresh = std.math.maxInt(u64);
        self.recovery_start_ns = null;
    }

    /// Remove a discarded packet's bytes from flight when a packet-number space
    /// is dropped (§6.4 / §A.4 — "OnPacketNumberSpaceDiscarded").
    pub fn onPacketDiscarded(self: *Congestion, bytes: u64) void {
        self.bytes_in_flight -|= bytes;
    }

    /// Whether `bytes` more may be sent under the window (§7). The driver gates
    /// its sends by this. We allow a send when the window is not yet full; a
    /// single send may briefly exceed the window by less than one packet, which
    /// RFC 9002 §7 permits (cwnd is a soft limit checked before, not after).
    pub fn canSend(self: *const Congestion, bytes: u64) bool {
        _ = bytes;
        return self.bytes_in_flight < self.congestion_window;
    }
};

// ===========================================================================
// The recovery controller — one per connection, spanning all three spaces
// ===========================================================================

/// Which timer the driver should arm next, and when (§6).
pub const TimerKind = enum { none, loss, pto };

pub const Timer = struct {
    kind: TimerKind = .none,
    deadline_ns: u64 = 0,
};

/// The result of feeding an inbound ACK to the controller: the packets that
/// were newly lost (their frames need re-queuing) and whether the RTT advanced.
pub const AckOutcome = struct {
    /// Re-queueable frames from packets just declared lost, in ascending packet
    /// order. Borrows the controller's scratch list — valid until the next call.
    lost_frames: []const LostFrame,
    /// Frames carried by packets that were just newly acknowledged. The driver
    /// uses the STREAM entries to reclaim acknowledged send-buffer bytes. Borrows
    /// the controller's scratch list — valid until the next call.
    acked_frames: []const LostFrame = &.{},
    /// True if this ACK produced a new RTT sample (so the driver resets pto_count).
    rtt_updated: bool = false,
};

/// Tracks the time span of an unbroken run of declared-lost ack-eliciting
/// packets for the persistent-congestion check (RFC 9002 §7.6). The run is built
/// up as `detectLost` walks the registry in (ascending packet-number) order;
/// any packet that is NOT declared lost calls `breakRun`, which resets the run
/// (a persistent-congestion window must contain *no* surviving packet between its
/// two bounding ack-eliciting losses). `span` is the time between the first and
/// last lost ack-eliciting packet of the current run, or null if fewer than two
/// ack-eliciting packets are in it (a single loss can never be persistent).
const PersistentCongestionRun = struct {
    first_ns: ?u64 = null,
    last_ns: ?u64 = null,
    count: u32 = 0,

    fn extend(self: *PersistentCongestionRun, time_sent_ns: u64) void {
        if (self.first_ns == null) self.first_ns = time_sent_ns;
        self.last_ns = time_sent_ns;
        self.count += 1;
    }

    fn breakRun(self: *PersistentCongestionRun) void {
        self.first_ns = null;
        self.last_ns = null;
        self.count = 0;
    }

    /// The span between the first and last lost ack-eliciting packet, requiring
    /// at least two such packets (a window is bounded by two ack-eliciting
    /// losses, §7.6). Null otherwise.
    fn span(self: *const PersistentCongestionRun) ?u64 {
        if (self.count < 2) return null;
        const f = self.first_ns orelse return null;
        const l = self.last_ns orelse return null;
        return if (l >= f) l - f else null;
    }

    /// Whether this run's span strictly exceeds `duration_ns` (§7.6 uses a strict
    /// "greater than" comparison).
    fn exceeds(self: *const PersistentCongestionRun, duration_ns: u64) bool {
        const s = self.span() orelse return false;
        return s > duration_ns;
    }
};

/// Indexes a per-space registry by encryption level.
const SpaceIndex = enum(u2) { initial = 0, handshake = 1, application = 2 };

fn spaceIndex(level: EncryptionLevel) SpaceIndex {
    return switch (level) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application,
    };
}

/// The loss-recovery + congestion controller (RFC 9002). Owns the three
/// per-space sent registries, the shared RTT estimator, the PTO backoff
/// counter, and the NewReno congestion window. The driver calls:
///   * `onPacketSent` after sealing each packet,
///   * `onAckReceived` after the ack manager returns newly-acked PNs,
///   * `ptoTimeout` / `lossTimeout` to compute timers, and the matching
///     `onPtoExpired` / `onLossDetectionTimeout` when one fires,
///   * `discardSpace` when a packet-number space's keys are dropped,
///   * `canSend` to gate the next send.
pub const Recovery = struct {
    allocator: Allocator,
    rtt: RttEstimator,
    cc: Congestion,
    max_ack_delay_ns: u64,
    handshake_confirmed: bool = false,

    /// PTO exponential-backoff counter (§6.2.1): pto is scaled by 2^pto_count.
    pto_count: u32 = 0,

    sent: [3]SentRegistry,

    /// Scratch reused by `onAckReceived` / timeout handlers to return lost frames
    /// without per-call allocation churn.
    lost_scratch: std.ArrayList(LostFrame) = .empty,
    /// Scratch reused by `onAckReceived` to return the frames of newly-acked
    /// packets (so the driver can reclaim acknowledged STREAM send-buffer bytes).
    acked_scratch: std.ArrayList(LostFrame) = .empty,

    pub const Options = struct {
        max_datagram: u64,
        max_ack_delay_ns: u64 = default_max_ack_delay_ns,
        max_sent: usize = default_max_sent,
    };

    pub fn init(allocator: Allocator, opts: Options) Recovery {
        return .{
            .allocator = allocator,
            .rtt = RttEstimator.init(),
            .cc = Congestion.init(opts.max_datagram),
            .max_ack_delay_ns = opts.max_ack_delay_ns,
            .sent = .{
                SentRegistry.init(opts.max_sent),
                SentRegistry.init(opts.max_sent),
                SentRegistry.init(opts.max_sent),
            },
        };
    }

    pub fn deinit(self: *Recovery) void {
        for (&self.sent) |*r| r.deinit(self.allocator);
        self.lost_scratch.deinit(self.allocator);
        self.acked_scratch.deinit(self.allocator);
        self.* = undefined;
    }

    fn registry(self: *Recovery, level: EncryptionLevel) *SentRegistry {
        return &self.sent[@intFromEnum(spaceIndex(level))];
    }

    /// The driver tells us the handshake is confirmed (1-RTT keys in use and the
    /// handshake complete). After this the PTO includes max_ack_delay and the
    /// RTT estimator caps ack_delay (§6.2.1 / §5.3).
    pub fn setHandshakeConfirmed(self: *Recovery) void {
        self.handshake_confirmed = true;
    }

    /// Update the peer-advertised max_ack_delay (from its transport parameters).
    pub fn setMaxAckDelay(self: *Recovery, ns: u64) void {
        self.max_ack_delay_ns = ns;
    }

    /// Reset congestion control and the RTT estimator to their initial defaults
    /// on a confirmed migration to a NEW path (RFC 9000 §9.4). The old path's
    /// congestion window and RTT estimate describe a different network route and
    /// MUST NOT be carried over, so the controller re-enters slow start with a
    /// fresh window and the RTT estimator is re-seeded from the next sample. The
    /// per-space sent registries and PTO backoff are left intact: outstanding
    /// packets are still legitimately outstanding, only the path's capacity
    /// assumptions are discarded.
    pub fn onPathMigration(self: *Recovery) void {
        const max_datagram = self.cc.max_datagram;
        self.cc = Congestion.init(max_datagram);
        self.rtt = RttEstimator.init();
        self.pto_count = 0;
    }

    // -----------------------------------------------------------------------
    // On send (§A.1: OnPacketSent)
    // -----------------------------------------------------------------------

    pub fn onPacketSent(self: *Recovery, level: EncryptionLevel, p: SentPacket) Allocator.Error!void {
        try self.registry(level).record(self.allocator, p);
        if (p.in_flight) self.cc.onPacketSent(p.sent_bytes);
    }

    // -----------------------------------------------------------------------
    // On ACK (§5 RTT, §6.1 loss, §7.3 cc)
    // -----------------------------------------------------------------------

    /// Process an inbound ACK for `level`. `newly_acked` are the packet numbers
    /// the ack manager reported as freshly acknowledged in this space.
    /// `largest_acked` is the ACK frame's Largest Acknowledged; `ack_delay_ns`
    /// is its decoded ACK Delay. `now_ns` is the current clock.
    ///
    /// Returns the frames from newly-lost packets (for the driver to re-queue)
    /// and whether an RTT sample was taken (so the driver can reset pto_count).
    pub fn onAckReceived(
        self: *Recovery,
        level: EncryptionLevel,
        newly_acked: []const u64,
        largest_acked: u64,
        ack_delay_ns: u64,
        now_ns: u64,
    ) Allocator.Error!AckOutcome {
        self.lost_scratch.clearRetainingCapacity();
        self.acked_scratch.clearRetainingCapacity();
        const reg = self.registry(level);

        // Find the largest newly-acked packet that is ack-eliciting; only such a
        // packet yields an RTT sample (§5.1). Track its send time.
        var rtt_updated = false;
        var largest_newly_acked: ?u64 = null;
        var largest_send_ns: u64 = 0;
        var largest_is_ack_eliciting = false;

        for (newly_acked) |pn| {
            const sp = reg.find(pn) orelse continue;
            sp.retired = true;
            if (sp.in_flight) self.cc.onPacketAcked(sp.sent_bytes);
            // Surface this packet's frames so the driver can reclaim acknowledged
            // STREAM send-buffer bytes. Best-effort: an append OOM just skips the
            // reclaim (memory stays retained, never incorrect).
            for (sp.frames.slice()) |fr| self.acked_scratch.append(self.allocator, fr) catch {};
            if (largest_newly_acked == null or pn > largest_newly_acked.?) {
                largest_newly_acked = pn;
                largest_send_ns = sp.time_sent_ns;
                largest_is_ack_eliciting = sp.ack_eliciting;
            }
        }

        // RTT sample (§5.1): only when the largest newly-acked packet equals the
        // ACK's Largest Acknowledged AND that packet was ack-eliciting.
        if (largest_newly_acked) |lna| {
            if (lna == largest_acked and largest_is_ack_eliciting and now_ns >= largest_send_ns) {
                const sample = now_ns - largest_send_ns;
                self.rtt.update(sample, ack_delay_ns, self.max_ack_delay_ns, self.handshake_confirmed);
                rtt_updated = true;
            }
        }

        // Loss detection (§6.1) against the new largest_acked for this space.
        const space_largest_acked = self.spaceLargestAcked(reg, largest_acked, newly_acked);
        try self.detectLost(reg, space_largest_acked, now_ns);

        reg.compact();

        // A new RTT sample means the PTO timer is RTT-driven again; reset backoff.
        if (rtt_updated) self.pto_count = 0;

        return .{
            .lost_frames = self.lost_scratch.items,
            .acked_frames = self.acked_scratch.items,
            .rtt_updated = rtt_updated,
        };
    }

    /// The effective largest-acked for loss detection: the max of the ACK's
    /// declared largest and any newly-acked PN (defensive — they should agree).
    fn spaceLargestAcked(self: *Recovery, reg: *SentRegistry, largest_acked: u64, newly_acked: []const u64) u64 {
        _ = self;
        _ = reg;
        var hi = largest_acked;
        for (newly_acked) |pn| {
            if (pn > hi) hi = pn;
        }
        return hi;
    }

    /// Declare lost any unretired packet that is either (a) at least
    /// kPacketThreshold below the largest acked, or (b) older than the time
    /// threshold (§6.1.1, §6.1.2). Appends each lost packet's frames to
    /// `lost_scratch` and removes its bytes from flight + the congestion window.
    ///
    /// Also runs the persistent-congestion check (§7.6): an unbroken run of
    /// declared-lost packets bounded by two lost *ack-eliciting* packets whose
    /// time span exceeds the persistent-congestion duration collapses the
    /// congestion window to the minimum and re-enters slow start. The registry
    /// holds only still-in-doubt packets at entry (acked packets were compacted
    /// out after their ACK pass), so any packet here that is NOT declared lost in
    /// this pass is still in flight and therefore *breaks* the run.
    fn detectLost(self: *Recovery, reg: *SentRegistry, largest_acked: u64, now_ns: u64) Allocator.Error!void {
        const loss_delay = self.rtt.lossDelay();
        // A packet sent at or before this instant is past the time threshold.
        const lost_send_time = if (now_ns >= loss_delay) now_ns - loss_delay else 0;

        // Persistent-congestion run tracking (§7.6): the earliest/latest send
        // times of lost *ack-eliciting* packets within the current unbroken run.
        // The threshold is computed once. We evaluate the run both when it is
        // broken by a surviving packet and after the final packet, so a run that
        // ends mid-registry is still detected.
        const pc_duration = self.persistentCongestionDuration();
        var pc = PersistentCongestionRun{};
        var persistent = false;

        for (reg.packets.items) |*p| {
            if (p.retired or p.packet_number > largest_acked) {
                // Acked/retired or not-yet-loseable → a surviving packet that
                // breaks any persistent-congestion run.
                if (pc.exceeds(pc_duration)) persistent = true;
                pc.breakRun();
                continue;
            }

            const beyond_threshold = (largest_acked - p.packet_number) >= packet_threshold;
            const past_time = p.time_sent_ns <= lost_send_time;
            if (!beyond_threshold and !past_time) {
                // Still in flight (in doubt) → breaks any persistent-congestion run.
                if (pc.exceeds(pc_duration)) persistent = true;
                pc.breakRun();
                continue;
            }

            // Packet is lost.
            p.retired = true;
            if (p.in_flight) {
                self.cc.onPacketLost(p.sent_bytes);
                self.cc.onCongestionEvent(p.time_sent_ns, now_ns);
            }
            if (p.ack_eliciting) pc.extend(p.time_sent_ns);
            for (p.frames.slice()) |f| try self.lost_scratch.append(self.allocator, f);
        }

        // Evaluate the final run (§7.6).
        if (pc.exceeds(pc_duration)) persistent = true;
        if (persistent) self.cc.onPersistentCongestion();
    }

    /// The persistent-congestion duration (RFC 9002 §7.6):
    ///   (smoothed_rtt + max(4·rttvar, kGranularity) + max_ack_delay)
    ///     × kPersistentCongestionThreshold(3).
    /// Uses the RFC's initial-RTT defaults before the first sample so the check
    /// is well-defined. `max_ack_delay` is included only once the handshake is
    /// confirmed (it applies to the 1-RTT space where persistent congestion is
    /// meaningful), mirroring the PTO computation.
    fn persistentCongestionDuration(self: *const Recovery) u64 {
        const smoothed = if (self.rtt.has_sample) self.rtt.smoothed_rtt else default_initial_rtt_ns;
        const rttvar = if (self.rtt.has_sample) self.rtt.rttvar else default_initial_rtt_ns / 2;
        var base = smoothed + @max(4 * rttvar, granularity_ns);
        if (self.handshake_confirmed) base += self.max_ack_delay_ns;
        return base * persistent_congestion_threshold;
    }

    // -----------------------------------------------------------------------
    // Timers (§6.1.2 loss timer, §6.2 PTO)
    // -----------------------------------------------------------------------

    /// The PTO duration for the current backoff (§6.2.1):
    ///   pto = smoothed_rtt + max(4·rttvar, kGranularity)
    ///         + (handshake_confirmed ? max_ack_delay : 0)
    ///   then × 2^pto_count.
    /// Before the first RTT sample the RFC uses an initial RTT of 333 ms; we use
    /// `granularity`-floored defaults so the timer is still well-defined.
    pub fn ptoDuration(self: *const Recovery) u64 {
        const smoothed = if (self.rtt.has_sample) self.rtt.smoothed_rtt else default_initial_rtt_ns;
        const rttvar = if (self.rtt.has_sample) self.rtt.rttvar else default_initial_rtt_ns / 2;
        var pto = smoothed + @max(4 * rttvar, granularity_ns);
        if (self.handshake_confirmed) pto += self.max_ack_delay_ns;
        // × 2^pto_count, saturating.
        const shift: u6 = @intCast(@min(self.pto_count, 32));
        const factor = @as(u64, 1) << shift;
        return std.math.mul(u64, pto, factor) catch std.math.maxInt(u64);
    }

    /// Compute the next timer to arm (§6.1.2 vs §6.2.1). Returns the loss timer
    /// when a packet is still in doubt under the time threshold, otherwise the
    /// PTO when ack-eliciting data is in flight (or, before handshake completion,
    /// unconditionally so a lost first flight is recovered).
    pub fn nextTimer(self: *Recovery, now_ns: u64) Timer {
        // Loss timer: earliest send time across spaces + loss_delay.
        var earliest_loss: ?u64 = null;
        for (&self.sent) |*reg| {
            // The loss timer only applies once we have an acked packet to compare
            // against; but the earliest-in-flight send time is a sound, slightly
            // conservative basis here (the driver re-runs detectLost on its fire).
            if (reg.earliestInFlightSent()) |t| {
                if (earliest_loss == null or t < earliest_loss.?) earliest_loss = t;
            }
        }

        const loss_delay = self.rtt.lossDelay();
        if (self.hasLossCandidate()) {
            if (earliest_loss) |t| {
                return .{ .kind = .loss, .deadline_ns = t + loss_delay };
            }
        }

        // PTO timer (§6.2.1): armed when ack-eliciting data is in flight, or
        // unconditionally before the handshake is confirmed (so a lost initial
        // flight is still probed).
        const ack_eliciting_in_flight = self.anyAckElicitingInFlight();
        if (!ack_eliciting_in_flight and self.handshake_confirmed) {
            return .{ .kind = .none };
        }
        const base = self.earliestAckElicitingSent() orelse now_ns;
        return .{ .kind = .pto, .deadline_ns = base + self.ptoDuration() };
    }

    fn anyAckElicitingInFlight(self: *Recovery) bool {
        for (&self.sent) |*reg| {
            if (reg.hasInFlightAckEliciting()) return true;
        }
        return false;
    }

    /// Whether any space holds a packet that could be declared lost by the time
    /// threshold (i.e. there is something still outstanding to watch).
    fn hasLossCandidate(self: *Recovery) bool {
        for (&self.sent) |*reg| {
            for (reg.packets.items) |p| {
                if (!p.retired and p.in_flight) return true;
            }
        }
        return false;
    }

    fn earliestAckElicitingSent(self: *Recovery) ?u64 {
        var earliest: ?u64 = null;
        for (&self.sent) |*reg| {
            if (reg.last_ack_eliciting_sent_ns) |_| {
                // Use the earliest still-in-flight ack-eliciting send time.
                for (reg.packets.items) |p| {
                    if (p.retired or !p.ack_eliciting or !p.in_flight) continue;
                    if (earliest == null or p.time_sent_ns < earliest.?) earliest = p.time_sent_ns;
                }
            }
        }
        return earliest;
    }

    /// Run the loss-detection timeout (§6.1.2): re-detect losses at `now_ns`
    /// against the highest acked PN per space. Returns lost frames to re-queue.
    pub fn onLossDetectionTimeout(self: *Recovery, now_ns: u64) Allocator.Error![]const LostFrame {
        self.lost_scratch.clearRetainingCapacity();
        for (&self.sent) |*reg| {
            // Largest acked is implicit in the registry: any packet ≤ a retired
            // (acked/lost) higher one. We use the largest unretired-below logic by
            // passing the largest packet number known so the time threshold drives
            // detection. The driver typically only fires this when a real ACK gap
            // exists; the time threshold handles the rest.
            const largest = self.largestTrackedPn(reg);
            try self.detectLost(reg, largest, now_ns);
            reg.compact();
        }
        return self.lost_scratch.items;
    }

    fn largestTrackedPn(self: *Recovery, reg: *SentRegistry) u64 {
        _ = self;
        var hi: u64 = 0;
        for (reg.packets.items) |p| {
            if (p.packet_number > hi) hi = p.packet_number;
        }
        return hi;
    }

    /// Run the PTO expiry (§6.2.1): increment the backoff counter. The driver
    /// then sends one or two probe packets (retransmitting the oldest
    /// ack-eliciting data, or a PING). Returns the oldest still-in-flight
    /// ack-eliciting frames across spaces for the driver to resend, or an empty
    /// slice (the driver then sends a bare PING probe).
    pub fn onPtoExpired(self: *Recovery) Allocator.Error![]const LostFrame {
        self.pto_count += 1;
        self.lost_scratch.clearRetainingCapacity();

        // Gather the oldest outstanding ack-eliciting packet's frames as the
        // probe content (§6.2.4 — "Sending Probe Packets"). We do NOT retire the
        // packet (it is not lost), so it is still subject to normal ACK/loss.
        var oldest: ?*SentPacket = null;
        for (&self.sent) |*reg| {
            for (reg.packets.items) |*p| {
                if (p.retired or !p.ack_eliciting or !p.in_flight) continue;
                if (oldest == null or p.time_sent_ns < oldest.?.time_sent_ns) oldest = p;
            }
        }
        if (oldest) |p| {
            for (p.frames.slice()) |f| try self.lost_scratch.append(self.allocator, f);
        }
        return self.lost_scratch.items;
    }

    // -----------------------------------------------------------------------
    // Space discard (§6.4 / §A.4: OnPacketNumberSpaceDiscarded)
    // -----------------------------------------------------------------------

    /// Drop all sent-packet state for a space whose keys were discarded (Initial
    /// after Handshake; Handshake after handshake-confirmed). Removes the
    /// in-flight bytes from the congestion window and resets pto_count (§6.4).
    pub fn discardSpace(self: *Recovery, level: EncryptionLevel) void {
        const reg = self.registry(level);
        for (reg.packets.items) |p| {
            if (!p.retired and p.in_flight) self.cc.onPacketDiscarded(p.sent_bytes);
        }
        reg.packets.clearRetainingCapacity();
        reg.largest_sent_ack_eliciting = null;
        reg.last_ack_eliciting_sent_ns = null;
        // §6.2.2: reset the PTO backoff when a space is discarded.
        self.pto_count = 0;
    }

    // -----------------------------------------------------------------------
    // Send gating (§7)
    // -----------------------------------------------------------------------

    pub fn canSend(self: *const Recovery, bytes: u64) bool {
        return self.cc.canSend(bytes);
    }

    pub fn bytesInFlight(self: *const Recovery) u64 {
        return self.cc.bytes_in_flight;
    }

    pub fn congestionWindow(self: *const Recovery) u64 {
        return self.cc.congestion_window;
    }

    pub fn smoothedRtt(self: *const Recovery) u64 {
        return self.rtt.smoothed_rtt;
    }

    /// Capture only logical recovery state. Packet frame tails are normalized so
    /// no uninitialized inline storage escapes into a later wire encoder.
    /// The caller must own an operation boundary: scratch slices returned by an
    /// ACK/timeout call cannot be borrowed while this snapshot is taken.
    pub fn captureSnapshot(self: *const Recovery, allocator: Allocator) SnapshotError!Snapshot {
        var owned: [3]?RegistrySnapshot = .{ null, null, null };
        errdefer for (&owned) |*part| if (part.*) |value| allocator.free(value.packets);

        for (&self.sent, 0..) |*reg, i| {
            if (reg.max_sent == 0 or reg.max_sent > snapshot_max_packets_per_space or
                reg.packets.items.len > reg.max_sent) return error.InvalidSnapshot;
            for (reg.packets.items) |packet| {
                if (packet.frames.len > FrameList.cap) return error.InvalidSnapshot;
            }
            const packets = try allocator.alloc(SentPacket, reg.packets.items.len);
            for (reg.packets.items, packets) |source, *dst| {
                dst.* = canonicalPacket(source);
            }
            owned[i] = .{
                .max_sent = reg.max_sent,
                .packets = packets,
                .largest_sent_ack_eliciting = reg.largest_sent_ack_eliciting,
                .last_ack_eliciting_sent_ns = reg.last_ack_eliciting_sent_ns,
            };
        }
        if (self.lost_scratch.items.len > snapshot_max_scratch_frames or
            self.acked_scratch.items.len > snapshot_max_scratch_frames)
            return error.SnapshotTooLarge;
        const lost = try allocator.dupe(LostFrame, self.lost_scratch.items);
        errdefer allocator.free(lost);
        const acked = try allocator.dupe(LostFrame, self.acked_scratch.items);
        errdefer allocator.free(acked);

        const snapshot: Snapshot = .{
            .rtt = self.rtt,
            .cc = self.cc,
            .max_ack_delay_ns = self.max_ack_delay_ns,
            .handshake_confirmed = self.handshake_confirmed,
            .pto_count = self.pto_count,
            .sent = .{ owned[0].?, owned[1].?, owned[2].? },
            .lost_scratch = lost,
            .acked_scratch = acked,
        };
        try snapshot.validate();
        return snapshot;
    }

    /// Build an independent controller before publication. No source field is
    /// touched on validation or allocation failure.
    pub fn restoreSnapshot(allocator: Allocator, snapshot: *const Snapshot) SnapshotError!Recovery {
        try snapshot.validate();
        var restored = Recovery.init(allocator, .{
            .max_datagram = snapshot.cc.max_datagram,
            .max_ack_delay_ns = snapshot.max_ack_delay_ns,
        });
        errdefer restored.deinit();
        for (snapshot.sent, 0..) |part, i| {
            restored.sent[i].max_sent = part.max_sent;
            restored.sent[i].largest_sent_ack_eliciting = part.largest_sent_ack_eliciting;
            restored.sent[i].last_ack_eliciting_sent_ns = part.last_ack_eliciting_sent_ns;
            try restored.sent[i].packets.appendSlice(allocator, part.packets);
        }
        try restored.lost_scratch.appendSlice(allocator, snapshot.lost_scratch);
        try restored.acked_scratch.appendSlice(allocator, snapshot.acked_scratch);
        restored.rtt = snapshot.rtt;
        restored.cc = snapshot.cc;
        restored.handshake_confirmed = snapshot.handshake_confirmed;
        restored.pto_count = snapshot.pto_count;
        return restored;
    }

    /// Atomic replacement for an owner whose caller-held recovery views have
    /// already been quiesced. The old controller is released only after the new
    /// one is fully validated and allocated.
    pub fn replaceFromSnapshot(self: *Recovery, snapshot: *const Snapshot) SnapshotError!void {
        const replacement = try restoreSnapshot(self.allocator, snapshot);
        var prior = self.*;
        self.* = replacement;
        prior.deinit();
    }
};

/// The DTO is bounded independently of a caller's tunable registry capacity.
/// Larger live states fail capture and leave the source controller untouched.
pub const snapshot_max_packets_per_space: usize = default_max_sent;
pub const snapshot_max_scratch_frames: usize = 3 * snapshot_max_packets_per_space * FrameList.cap;
pub const SnapshotError = error{ InvalidSnapshot, SnapshotTooLarge } || Allocator.Error;

pub const RegistrySnapshot = struct {
    max_sent: usize,
    packets: []SentPacket,
    largest_sent_ack_eliciting: ?u64,
    last_ack_eliciting_sent_ns: ?u64,
};

/// Owned, logically canonical recovery state. A future wire codec must encode
/// fields, never raw struct memory or allocator-dependent slice pointers.
pub const Snapshot = struct {
    rtt: RttEstimator,
    cc: Congestion,
    max_ack_delay_ns: u64,
    handshake_confirmed: bool,
    pto_count: u32,
    sent: [3]RegistrySnapshot,
    lost_scratch: []LostFrame,
    acked_scratch: []LostFrame,

    pub fn deinit(self: *Snapshot, allocator: Allocator) void {
        for (self.sent) |part| allocator.free(part.packets);
        allocator.free(self.lost_scratch);
        allocator.free(self.acked_scratch);
        self.* = undefined;
    }

    pub fn validate(self: *const Snapshot) SnapshotError!void {
        if (self.cc.max_datagram == 0 or self.cc.max_datagram > 65_535) return error.InvalidSnapshot;
        const min_window = minimum_window_packets * self.cc.max_datagram;
        if (self.cc.congestion_window < min_window or self.cc.ssthresh < min_window)
            return error.InvalidSnapshot;
        // The sent registry can drop old packets, and path migration resets CC
        // while retaining them. Its byte count therefore cannot be derived from
        // the registries, but each scalar must remain safe for its next update.
        if (self.cc.congestion_window > std.math.maxInt(u64) - self.cc.max_datagram or
            self.cc.bytes_in_flight > std.math.maxInt(u64) - self.cc.max_datagram or
            self.pto_count == std.math.maxInt(u32)) return error.InvalidSnapshot;
        if (self.cc.recovery_start_ns) |start| {
            if (start > snapshot_max_clock_ns) return error.InvalidSnapshot;
        }
        if (!self.rtt.has_sample) {
            if (self.rtt.latest_rtt != 0 or self.rtt.min_rtt != 0 or
                self.rtt.smoothed_rtt != 0 or self.rtt.rttvar != 0) return error.InvalidSnapshot;
        } else if (self.rtt.min_rtt > self.rtt.latest_rtt or
            self.rtt.min_rtt > self.rtt.smoothed_rtt) return error.InvalidSnapshot;
        try validateSnapshotTimers(self);

        for (self.sent) |part| {
            if (part.max_sent == 0 or part.max_sent > snapshot_max_packets_per_space or
                part.packets.len > part.max_sent) return error.InvalidSnapshot;
            if ((part.largest_sent_ack_eliciting == null) != (part.last_ack_eliciting_sent_ns == null))
                return error.InvalidSnapshot;
            if (part.largest_sent_ack_eliciting) |pn| {
                if (pn > max_quic_varint or part.last_ack_eliciting_sent_ns.? > snapshot_max_clock_ns)
                    return error.InvalidSnapshot;
            }
            var prior_pn: ?u64 = null;
            var prior_time: ?u64 = null;
            for (part.packets) |packet| {
                if (packet.packet_number > max_quic_varint or packet.time_sent_ns > snapshot_max_clock_ns or
                    packet.sent_bytes == 0 or
                    packet.sent_bytes > self.cc.max_datagram or packet.frames.len > FrameList.cap or
                    (!packet.ack_eliciting and packet.frames.len != 0))
                    return error.InvalidSnapshot;
                if (prior_pn) |pn| if (packet.packet_number <= pn) return error.InvalidSnapshot;
                if (prior_time) |time| if (packet.time_sent_ns < time) return error.InvalidSnapshot;
                prior_pn = packet.packet_number;
                prior_time = packet.time_sent_ns;
                if (packet.ack_eliciting) {
                    if (part.largest_sent_ack_eliciting == null or
                        packet.packet_number > part.largest_sent_ack_eliciting.? or
                        packet.time_sent_ns > part.last_ack_eliciting_sent_ns.?) return error.InvalidSnapshot;
                }
                for (packet.frames.items[0..packet.frames.len]) |frame| try validateSnapshotFrame(frame);
                for (packet.frames.items[packet.frames.len..]) |frame| {
                    if (std.meta.activeTag(frame) != .ping) return error.InvalidSnapshot;
                }
            }
        }
        if (self.lost_scratch.len > snapshot_max_scratch_frames or
            self.acked_scratch.len > snapshot_max_scratch_frames)
            return error.SnapshotTooLarge;
        for (self.lost_scratch) |frame| try validateSnapshotFrame(frame);
        for (self.acked_scratch) |frame| try validateSnapshotFrame(frame);
    }
};

const max_quic_varint: u64 = (1 << 62) - 1;
// A sent timestamp plus either validated loss/PTO duration cannot overflow.
// This still permits nearly 292 years of nanosecond-clock uptime.
const snapshot_max_clock_ns: u64 = std.math.maxInt(u64) / 2;

fn validateSnapshotTimers(snapshot: *const Snapshot) SnapshotError!void {
    const rtt = snapshot.rtt;
    const smoothed = if (rtt.has_sample) rtt.smoothed_rtt else default_initial_rtt_ns;
    const rttvar = if (rtt.has_sample) rtt.rttvar else default_initial_rtt_ns / 2;
    // RttEstimator.update uses 7*smoothed and 3*rttvar before averaging.
    if (smoothed > std.math.maxInt(u64) / 7) return error.InvalidSnapshot;
    const loss_base = @max(rtt.smoothed_rtt, rtt.latest_rtt);
    const loss_scaled = std.math.mul(u64, loss_base, time_threshold_num) catch return error.InvalidSnapshot;
    if (@max(loss_scaled / time_threshold_den, granularity_ns) > snapshot_max_clock_ns)
        return error.InvalidSnapshot;
    const variance = std.math.mul(u64, rttvar, 4) catch return error.InvalidSnapshot;
    var pto_base = std.math.add(u64, smoothed, @max(variance, granularity_ns)) catch return error.InvalidSnapshot;
    // Include max_ack_delay even before handshake confirmation: that transition
    // must not turn an accepted snapshot into an overflowing timer.
    pto_base = std.math.add(u64, pto_base, snapshot.max_ack_delay_ns) catch return error.InvalidSnapshot;
    _ = std.math.mul(u64, pto_base, persistent_congestion_threshold) catch return error.InvalidSnapshot;
    const shift: u6 = @intCast(@min(snapshot.pto_count, 32));
    const factor = @as(u64, 1) << shift;
    const pto = std.math.mul(u64, pto_base, factor) catch return error.InvalidSnapshot;
    if (pto > snapshot_max_clock_ns) return error.InvalidSnapshot;
}

fn canonicalPacket(source: SentPacket) SentPacket {
    var frames: FrameList = .{ .items = @splat(.ping), .len = source.frames.len };
    @memcpy(frames.items[0..source.frames.len], source.frames.items[0..source.frames.len]);
    return .{
        .packet_number = source.packet_number,
        .time_sent_ns = source.time_sent_ns,
        .in_flight = source.in_flight,
        .ack_eliciting = source.ack_eliciting,
        .sent_bytes = source.sent_bytes,
        .frames = frames,
        .retired = source.retired,
    };
}

fn validateSnapshotFrame(frame: LostFrame) SnapshotError!void {
    switch (frame) {
        .crypto => |range| {
            if (range.offset > max_quic_varint or range.len > max_quic_varint - range.offset)
                return error.InvalidSnapshot;
        },
        .stream => |range| {
            if (range.stream_id > max_quic_varint or range.offset > max_quic_varint or
                range.len > max_quic_varint - range.offset) return error.InvalidSnapshot;
        },
        .ping => {},
    }
}

/// RFC 9002 §6.2.2 kInitialRtt — the assumed RTT before the first sample.
pub const default_initial_rtt_ns: u64 = 333 * std.time.ns_per_ms;

// ===========================================================================
// Tests (RFC 9002 §5 / §6.1 / §6.2 / §7)
// ===========================================================================

const testing = std.testing;
const ms: u64 = std.time.ns_per_ms;

test "recovery RTT — first sample initializes smoothed and rttvar per §5.2" {
    var rtt = RttEstimator.init();
    rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    try testing.expect(rtt.has_sample);
    try testing.expectEqual(@as(u64, 100 * ms), rtt.smoothed_rtt);
    try testing.expectEqual(@as(u64, 50 * ms), rtt.rttvar);
    try testing.expectEqual(@as(u64, 100 * ms), rtt.min_rtt);
    try testing.expectEqual(@as(u64, 100 * ms), rtt.latest_rtt);
}

test "recovery RTT — subsequent samples apply 7/8 and 3/4 EWMA (§5.3)" {
    var rtt = RttEstimator.init();
    rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    // Second sample 200ms, no ack delay.
    rtt.update(200 * ms, 0, default_max_ack_delay_ns, false);
    // rttvar_sample = |100 - 200| = 100; rttvar = (3*50 + 100)/4 = 62.5 → 62ms (ns).
    const expect_rttvar = (3 * (50 * ms) + (100 * ms)) / 4;
    try testing.expectEqual(expect_rttvar, rtt.rttvar);
    // smoothed = (7*100 + 200)/8 = 112.5 → 112ms.
    const expect_smoothed = (7 * (100 * ms) + (200 * ms)) / 8;
    try testing.expectEqual(expect_smoothed, rtt.smoothed_rtt);
    try testing.expectEqual(@as(u64, 100 * ms), rtt.min_rtt);
}

test "recovery RTT — ack_delay subtracted but min_rtt floor respected (§5.3)" {
    var rtt = RttEstimator.init();
    rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    // min_rtt is now 100ms. A sample of 110ms with ack_delay 20ms: adjusted
    // would be 90ms which is < min_rtt(100) so the delay is NOT subtracted.
    rtt.update(110 * ms, 20 * ms, default_max_ack_delay_ns, false);
    // adjusted stays 110 (110 >= 100 + 20? no → not subtracted). smoothed uses 110.
    const expect_smoothed = (7 * (100 * ms) + (110 * ms)) / 8;
    try testing.expectEqual(expect_smoothed, rtt.smoothed_rtt);

    // A larger sample where the floor permits subtraction: 200ms with 20ms delay.
    var rtt2 = RttEstimator.init();
    rtt2.update(100 * ms, 0, default_max_ack_delay_ns, false);
    rtt2.update(200 * ms, 20 * ms, default_max_ack_delay_ns, false);
    // 200 >= 100 + 20 → adjusted = 180.
    const expect2 = (7 * (100 * ms) + (180 * ms)) / 8;
    try testing.expectEqual(expect2, rtt2.smoothed_rtt);
}

test "recovery RTT — ack_delay capped at max_ack_delay once handshake confirmed (§5.3)" {
    var rtt = RttEstimator.init();
    rtt.update(50 * ms, 0, 25 * ms, true);
    // Sample 200ms, ack_delay 100ms, but max_ack_delay is 25ms → delay capped 25.
    rtt.update(200 * ms, 100 * ms, 25 * ms, true);
    // adjusted = 200 - 25 = 175 (175 >= min_rtt(50)+25 → yes).
    const expect = (7 * (50 * ms) + (175 * ms)) / 8;
    try testing.expectEqual(expect, rtt.smoothed_rtt);
}

test "recovery PTO — formula and exponential backoff (§6.2.1)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    rec.rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    // pto = smoothed(100) + max(4*rttvar(50)=200, 1) = 100 + 200 = 300ms
    // (handshake not confirmed → no max_ack_delay term).
    const base_pto = (100 * ms) + @max(4 * (50 * ms), granularity_ns);
    try testing.expectEqual(base_pto, rec.ptoDuration());

    // Each consecutive PTO doubles it.
    rec.pto_count = 1;
    try testing.expectEqual(base_pto * 2, rec.ptoDuration());
    rec.pto_count = 3;
    try testing.expectEqual(base_pto * 8, rec.ptoDuration());

    // Handshake-confirmed adds max_ack_delay.
    rec.pto_count = 0;
    rec.setHandshakeConfirmed();
    try testing.expectEqual(base_pto + default_max_ack_delay_ns, rec.ptoDuration());
}

test "recovery PTO — a new RTT sample resets pto_count" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    // Send an ack-eliciting app packet at t=0.
    try rec.onPacketSent(.application, .{
        .packet_number = 0,
        .time_sent_ns = 0,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 1200,
    });
    // Two PTOs expire, backoff climbs.
    _ = try rec.onPtoExpired();
    _ = try rec.onPtoExpired();
    try testing.expectEqual(@as(u32, 2), rec.pto_count);

    // An ACK of packet 0 with an RTT sample resets pto_count.
    const out = try rec.onAckReceived(.application, &.{0}, 0, 0, 50 * ms);
    try testing.expect(out.rtt_updated);
    try testing.expectEqual(@as(u32, 0), rec.pto_count);
}

test "recovery loss — packet threshold: acking N+3 declares N lost (§6.1.1)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    // Send packets 0..3, packet 0 carries a CRYPTO range we expect back on loss.
    var fl0 = FrameList{};
    fl0.append(.{ .crypto = .{ .offset = 0, .len = 16 } });
    try rec.onPacketSent(.handshake, .{
        .packet_number = 0,
        .time_sent_ns = 0,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 200,
        .frames = fl0,
    });
    for (1..4) |i| {
        try rec.onPacketSent(.handshake, .{
            .packet_number = i,
            .time_sent_ns = @intCast(i),
            .in_flight = true,
            .ack_eliciting = true,
            .sent_bytes = 200,
        });
    }

    // ACK only packet 3 (largest=3). Packet 0 is 3 below → lost by threshold.
    const out = try rec.onAckReceived(.handshake, &.{3}, 3, 0, 10 * ms);
    try testing.expectEqual(@as(usize, 1), out.lost_frames.len);
    switch (out.lost_frames[0]) {
        .crypto => |c| {
            try testing.expectEqual(@as(u64, 0), c.offset);
            try testing.expectEqual(@as(u64, 16), c.len);
        },
        else => return error.WrongFrame,
    }
}

test "recovery loss — time threshold declares an old packet lost (§6.1.2)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    // Establish an RTT so lossDelay is meaningful: smoothed=100ms → loss_delay
    // = 9/8 * 100 = 112.5ms.
    rec.rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    const loss_delay = rec.rtt.lossDelay();
    try testing.expectEqual((100 * ms * 9) / 8, loss_delay);

    // Packet 0 sent at t=0 (old), packet 1 sent much later and acked.
    var fl0 = FrameList{};
    fl0.append(.ping);
    try rec.onPacketSent(.application, .{
        .packet_number = 0,
        .time_sent_ns = 0,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 200,
        .frames = fl0,
    });
    try rec.onPacketSent(.application, .{
        .packet_number = 1,
        .time_sent_ns = 200 * ms,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 200,
    });

    // ACK packet 1 at now = 200ms + a bit. Packet 0 (sent at 0) is older than
    // now - loss_delay = ~87ms, so it is lost by the time threshold (it is only
    // 1 below largest, so NOT lost by packet threshold).
    const now = 200 * ms + ms;
    const out = try rec.onAckReceived(.application, &.{1}, 1, 0, now);
    try testing.expectEqual(@as(usize, 1), out.lost_frames.len);
    try testing.expect(out.lost_frames[0] == .ping);
}

test "recovery NewReno — slow start grows window by acked bytes (§7.3.1)" {
    var cc = Congestion.init(1252);
    const w0 = cc.congestion_window;
    try testing.expectEqual(initial_window_packets * 1252, w0);
    cc.onPacketSent(1200);
    try testing.expectEqual(@as(u64, 1200), cc.bytes_in_flight);
    cc.onPacketAcked(1200);
    // Slow start: cwnd += acked.
    try testing.expectEqual(w0 + 1200, cc.congestion_window);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
}

test "recovery NewReno — loss halves to ssthresh and clamps to min window (§7.3.2)" {
    var cc = Congestion.init(1252);
    cc.onPacketSent(1200);
    const w0 = cc.congestion_window;
    cc.onPacketLost(1200);
    cc.onCongestionEvent(0, 100 * ms);
    try testing.expectEqual(w0 / 2, cc.ssthresh);
    try testing.expectEqual(w0 / 2, cc.congestion_window);
    try testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);

    // A second loss in the SAME recovery period (sent before recovery_start)
    // does not re-halve.
    const after_first = cc.congestion_window;
    cc.onCongestionEvent(0, 100 * ms);
    try testing.expectEqual(after_first, cc.congestion_window);

    // The window never drops below 2×max_datagram regardless of repeated cuts.
    var tiny = Congestion.init(1252);
    tiny.ssthresh = 3 * 1252;
    tiny.congestion_window = 3 * 1252;
    tiny.onCongestionEvent(0, 1);
    try testing.expect(tiny.congestion_window >= minimum_window_packets * 1252);
}

test "recovery NewReno — congestion avoidance grows by max_datagram*acked/cwnd (§7.3.1)" {
    var cc = Congestion.init(1252);
    // Force into congestion avoidance: cwnd == ssthresh.
    cc.ssthresh = cc.congestion_window;
    const w0 = cc.congestion_window;
    cc.onPacketSent(1252);
    cc.onPacketAcked(1252);
    // inc = max_datagram*acked/cwnd = 1252*1252/w0.
    const inc = (1252 * 1252) / w0;
    try testing.expectEqual(w0 + @max(inc, 1), cc.congestion_window);
}

test "recovery NewReno — canSend gates on bytes_in_flight vs window (§7)" {
    var cc = Congestion.init(1252);
    // Initially the window is open.
    try testing.expect(cc.canSend(1200));
    // Fill the window.
    cc.bytes_in_flight = cc.congestion_window;
    try testing.expect(!cc.canSend(1));
    // Acking frees room.
    cc.onPacketAcked(1200);
    try testing.expect(cc.canSend(1));
}

test "recovery — discardSpace removes in-flight bytes and clears the registry (§6.4)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    try rec.onPacketSent(.initial, .{
        .packet_number = 0,
        .time_sent_ns = 0,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 1200,
    });
    try testing.expectEqual(@as(u64, 1200), rec.bytesInFlight());
    rec.discardSpace(.initial);
    try testing.expectEqual(@as(u64, 0), rec.bytesInFlight());
    try testing.expectEqual(@as(usize, 0), rec.registry(.initial).packets.items.len);
}

test "recovery persistent congestion — a long loss burst collapses cwnd to min and re-enters slow start (§7.6)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    // Seed an RTT so the persistent-congestion duration is well-defined:
    // smoothed=100ms, rttvar=50ms → base = 100 + max(4*50,1)=300ms; ×3 = 900ms.
    rec.rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    try testing.expectEqual(@as(u64, 900 * ms), rec.persistentCongestionDuration());

    // Send packets 0..6 ack-eliciting/in-flight. Packets 0..3 span > 900ms; 4,5
    // are recent; 6 is the one we ACK. 1200 bytes each.
    const times = [_]u64{ 0, 1000 * ms, 1001 * ms, 1002 * ms, 1003 * ms, 1004 * ms, 1005 * ms };
    for (times, 0..) |t, i| {
        try rec.onPacketSent(.application, .{
            .packet_number = @intCast(i),
            .time_sent_ns = t,
            .in_flight = true,
            .ack_eliciting = true,
            .sent_bytes = 1200,
        });
    }
    const min_window = minimum_window_packets * 1252;
    try testing.expect(rec.congestionWindow() > min_window);

    // ACK packet 6 at now=1010ms. Packets 0..3 are ≥3 below largest → lost by
    // the packet threshold and form an unbroken ack-eliciting run spanning
    // 0..1002ms = 1002ms > 900ms → persistent congestion. Packets 4,5 are recent
    // and within the packet threshold, so they survive and bound the run.
    const out = try rec.onAckReceived(.application, &.{6}, 6, 0, 1010 * ms);
    // At least packets 0..3 were declared lost (their frames are empty here, so
    // lost_frames may be empty; the collapse is the observable effect).
    _ = out;

    // The window collapsed to the minimum and ssthresh reset → slow start.
    try testing.expectEqual(min_window, rec.congestionWindow());
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), rec.cc.ssthresh);
}

test "recovery persistent congestion — a single loss only halves, never collapses (§7.6 vs §7.3.2)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    rec.rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    const w0 = rec.congestionWindow();
    const min_window = minimum_window_packets * 1252;

    // Send packets 0..4 close together; only packet 0 will be lost (by the packet
    // threshold when we ACK packet 4), the rest survive. One lost ack-eliciting
    // packet can never form a two-packet run → no persistent congestion.
    for (0..5) |i| {
        try rec.onPacketSent(.application, .{
            .packet_number = @intCast(i),
            .time_sent_ns = @intCast(i * ms),
            .in_flight = true,
            .ack_eliciting = true,
            .sent_bytes = 1200,
        });
    }
    const out = try rec.onAckReceived(.application, &.{4}, 4, 0, 10 * ms);
    _ = out;

    // The window took a single NewReno congestion cut (≈halving) but did NOT
    // collapse to the minimum, proving the single loss did not trip persistent
    // congestion. (The exact value depends on slow-start growth from the ack, so
    // we assert the band rather than a precise number.)
    try testing.expect(rec.congestionWindow() < w0); // a cut happened
    try testing.expect(rec.congestionWindow() > min_window); // not a collapse
    // ssthresh was set to the halved window (finite), not reset to max as a
    // persistent-congestion collapse would.
    try testing.expect(rec.cc.ssthresh != std.math.maxInt(u64));
}

test "recovery persistent congestion — a short burst under the duration does not collapse (§7.6)" {
    const alloc = testing.allocator;
    var rec = Recovery.init(alloc, .{ .max_datagram = 1252 });
    defer rec.deinit();

    // Duration = 900ms (as above). A burst of lost ack-eliciting packets spanning
    // only 100ms must NOT collapse — it only halves (one congestion event).
    rec.rtt.update(100 * ms, 0, default_max_ack_delay_ns, false);
    const w0 = rec.congestionWindow();
    const min_window = minimum_window_packets * 1252;

    const times = [_]u64{ 0, 50 * ms, 100 * ms, 101 * ms, 102 * ms, 103 * ms, 104 * ms };
    for (times, 0..) |t, i| {
        try rec.onPacketSent(.application, .{
            .packet_number = @intCast(i),
            .time_sent_ns = t,
            .in_flight = true,
            .ack_eliciting = true,
            .sent_bytes = 1200,
        });
    }
    // ACK packet 6: packets 0..3 are lost by the packet threshold, span 0..101ms
    // = 101ms < 900ms → not persistent. A single congestion cut applies.
    _ = try rec.onAckReceived(.application, &.{6}, 6, 0, 110 * ms);
    try testing.expect(rec.congestionWindow() < w0); // a cut happened
    try testing.expect(rec.congestionWindow() > min_window); // not a collapse
    try testing.expect(rec.cc.ssthresh != std.math.maxInt(u64));
}

test "recovery — sent registry bounds and drops oldest on overflow" {
    const alloc = testing.allocator;
    var reg = SentRegistry.init(4);
    defer reg.deinit(alloc);
    for (0..6) |i| {
        try reg.record(alloc, .{
            .packet_number = i,
            .time_sent_ns = @intCast(i),
            .in_flight = true,
            .ack_eliciting = true,
            .sent_bytes = 100,
        });
    }
    // Capped at 4; the two oldest (0,1) were dropped.
    try testing.expectEqual(@as(usize, 4), reg.packets.items.len);
    try testing.expectEqual(@as(u64, 2), reg.packets.items[0].packet_number);
    try testing.expectEqual(@as(u64, 5), reg.packets.items[3].packet_number);
}

fn snapshotFixture(allocator: Allocator) !Recovery {
    var rec = Recovery.init(allocator, .{ .max_datagram = 1252 });
    errdefer rec.deinit();
    rec.setHandshakeConfirmed();
    rec.setMaxAckDelay(15 * ms);
    rec.rtt.update(50 * ms, 0, 15 * ms, true);

    var first_frames = FrameList{};
    first_frames.append(.{ .stream = .{ .stream_id = 4, .offset = 20, .len = 80, .fin = false } });
    try rec.onPacketSent(.application, .{
        .packet_number = 1,
        .time_sent_ns = 100 * ms,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 1200,
        .frames = first_frames,
    });
    var second_frames = FrameList{};
    second_frames.append(.ping);
    try rec.onPacketSent(.application, .{
        .packet_number = 4,
        .time_sent_ns = 110 * ms,
        .in_flight = true,
        .ack_eliciting = true,
        .sent_bytes = 1200,
        .frames = second_frames,
    });
    rec.cc.onCongestionEvent(100 * ms, 120 * ms);
    _ = try rec.onPtoExpired();
    return rec;
}

test "Recovery snapshot preserves retransmission, timers, congestion and canonical frame tails" {
    const allocator = testing.allocator;
    var source = try snapshotFixture(allocator);
    defer source.deinit();
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);
    try snapshot.validate();
    try testing.expectEqual(@as(usize, 1), snapshot.sent[2].packets[0].frames.len);
    for (snapshot.sent[2].packets[0].frames.items[1..]) |unused|
        try testing.expectEqual(@as(std.meta.Tag(LostFrame), .ping), std.meta.activeTag(unused));

    var restored = try Recovery.restoreSnapshot(allocator, &snapshot);
    defer restored.deinit();
    var recaptured = try restored.captureSnapshot(allocator);
    defer recaptured.deinit(allocator);
    try testing.expectEqualDeep(snapshot, recaptured);
    try testing.expectEqualDeep(source.nextTimer(130 * ms), restored.nextTimer(130 * ms));

    const expected = try source.onAckReceived(.application, &.{4}, 4, 0, 150 * ms);
    const actual = try restored.onAckReceived(.application, &.{4}, 4, 0, 150 * ms);
    try testing.expectEqualDeep(expected.lost_frames, actual.lost_frames);
    try testing.expectEqualDeep(expected.acked_frames, actual.acked_frames);
    try testing.expectEqual(@as(usize, 1), actual.lost_frames.len);
    try testing.expectEqual(@as(u64, 4), actual.lost_frames[0].stream.stream_id);
    try testing.expectEqual(source.bytesInFlight(), restored.bytesInFlight());
    try testing.expectEqual(source.congestionWindow(), restored.congestionWindow());
    try testing.expectEqual(source.pto_count, restored.pto_count);
}

test "Recovery snapshot rejects duplicate packets, malformed frames and bad counters" {
    const allocator = testing.allocator;
    var source = try snapshotFixture(allocator);
    defer source.deinit();
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);

    const original_pn = snapshot.sent[2].packets[1].packet_number;
    snapshot.sent[2].packets[1].packet_number = snapshot.sent[2].packets[0].packet_number;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.sent[2].packets[1].packet_number = original_pn;

    snapshot.sent[2].packets[0].frames.len = @intCast(FrameList.cap + 1);
    try testing.expectError(error.InvalidSnapshot, Recovery.restoreSnapshot(allocator, &snapshot));
    snapshot.sent[2].packets[0].frames.len = 1;

    snapshot.sent[2].packets[0].frames.items[7] = .{ .crypto = .{ .offset = 0, .len = 1 } };
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.sent[2].packets[0].frames.items[7] = .ping;

    const original_frame = snapshot.sent[2].packets[0].frames.items[0];
    snapshot.sent[2].packets[0].frames.items[0] = .{ .stream = .{ .stream_id = 4, .offset = max_quic_varint, .len = 1, .fin = false } };
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.sent[2].packets[0].frames.items[0] = original_frame;

    const original_window = snapshot.cc.congestion_window;
    snapshot.cc.congestion_window = 1;
    var target = Recovery.init(allocator, .{ .max_datagram = 1252 });
    defer target.deinit();
    try testing.expectError(error.InvalidSnapshot, target.replaceFromSnapshot(&snapshot));
    try testing.expectEqual(@as(usize, 0), target.sent[2].packets.items.len);
    try testing.expectEqual(@as(u64, initial_window_packets * 1252), target.congestionWindow());
    snapshot.cc.congestion_window = original_window;

    snapshot.rtt.has_sample = false;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.rtt.has_sample = true;

    const original_bytes = snapshot.cc.bytes_in_flight;
    snapshot.cc.bytes_in_flight = std.math.maxInt(u64);
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.cc.bytes_in_flight = original_bytes;

    const original_ack_delay = snapshot.max_ack_delay_ns;
    snapshot.max_ack_delay_ns = std.math.maxInt(u64);
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.max_ack_delay_ns = original_ack_delay;

    const original_time = snapshot.sent[2].packets[1].time_sent_ns;
    snapshot.sent[2].packets[1].time_sent_ns = std.math.maxInt(u64);
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.sent[2].packets[1].time_sent_ns = original_time;

    const original_pto = snapshot.pto_count;
    snapshot.pto_count = std.math.maxInt(u32);
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.pto_count = original_pto;
    try snapshot.validate();
}

test "Recovery snapshot preserves capped-registry and migrated congestion counters" {
    const allocator = testing.allocator;
    var source = Recovery.init(allocator, .{ .max_datagram = 1252, .max_sent = 1 });
    defer source.deinit();
    for ([_]u64{ 1, 2 }) |pn| {
        try source.onPacketSent(.application, .{
            .packet_number = pn,
            .time_sent_ns = pn * ms,
            .in_flight = true,
            .ack_eliciting = true,
            .sent_bytes = 1200,
        });
    }
    try testing.expectEqual(@as(usize, 1), source.sent[2].packets.items.len);
    try testing.expectEqual(@as(u64, 2400), source.bytesInFlight());
    var capped = try source.captureSnapshot(allocator);
    defer capped.deinit(allocator);
    try testing.expectEqual(@as(u64, 2400), capped.cc.bytes_in_flight);

    source.onPathMigration();
    try testing.expectEqual(@as(u64, 0), source.bytesInFlight());
    var migrated = try source.captureSnapshot(allocator);
    defer migrated.deinit(allocator);
    var restored = try Recovery.restoreSnapshot(allocator, &migrated);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 1), restored.sent[2].packets.items.len);
    try testing.expectEqual(@as(u64, 0), restored.bytesInFlight());
    try testing.expectEqual(source.congestionWindow(), restored.congestionWindow());
}

test "Recovery snapshot preserves padded non-ack-eliciting in-flight packet" {
    const allocator = testing.allocator;
    var source = Recovery.init(allocator, .{ .max_datagram = 1252 });
    defer source.deinit();
    try source.onPacketSent(.initial, .{
        .packet_number = 0,
        .time_sent_ns = 10 * ms,
        .in_flight = true,
        .ack_eliciting = false,
        .sent_bytes = 1200,
    });
    try testing.expectEqual(@as(u64, 1200), source.bytesInFlight());
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);
    var restored = try Recovery.restoreSnapshot(allocator, &snapshot);
    defer restored.deinit();
    try testing.expectEqual(@as(u64, 1200), restored.bytesInFlight());
    try testing.expect(!restored.sent[0].packets.items[0].ack_eliciting);
    try testing.expect(restored.sent[0].packets.items[0].in_flight);
    _ = try source.onAckReceived(.initial, &.{0}, 0, 0, 20 * ms);
    _ = try restored.onAckReceived(.initial, &.{0}, 0, 0, 20 * ms);
    try testing.expectEqual(@as(u64, 0), source.bytesInFlight());
    try testing.expectEqual(source.bytesInFlight(), restored.bytesInFlight());
}

test "Recovery snapshot capture and atomic replacement survive every allocation failure" {
    const allocator = testing.allocator;
    var source = try snapshotFixture(allocator);
    defer source.deinit();
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);

    const CaptureSweep = struct {
        fn run(failing: Allocator, original: *const Recovery) !void {
            var captured = original.captureSnapshot(failing) catch |err| {
                try testing.expectEqual(@as(usize, 2), original.sent[2].packets.items.len);
                return err;
            };
            captured.deinit(failing);
        }
    };
    try testing.checkAllAllocationFailures(allocator, CaptureSweep.run, .{&source});

    const RestoreSweep = struct {
        fn run(failing: Allocator, saved: *const Snapshot) !void {
            var target = Recovery.init(failing, .{ .max_datagram = 1252 });
            defer target.deinit();
            target.replaceFromSnapshot(saved) catch |err| {
                try testing.expectEqual(@as(usize, 0), target.sent[2].packets.items.len);
                try testing.expectEqual(@as(u64, initial_window_packets * 1252), target.congestionWindow());
                return err;
            };
            try testing.expectEqual(@as(usize, 2), target.sent[2].packets.items.len);
            try testing.expectEqual(saved.cc.congestion_window, target.congestionWindow());
        }
    };
    try testing.checkAllAllocationFailures(allocator, RestoreSweep.run, .{&snapshot});
}
