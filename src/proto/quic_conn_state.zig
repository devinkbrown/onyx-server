// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC connection frame engine (RFC 9000) — layer 3 of the from-scratch
//! QUIC/WebTransport stack, sitting on top of packet protection
//! (`quic_protect.zig`) and feeding the TLS handshake (`quic_tls.zig`) and the
//! HTTP/3 / connection-driver layers above.
//!
//! This module owns the *per-connection state* that the lower codecs
//! deliberately do not: packet-number spaces, ACK bookkeeping, ordered CRYPTO
//! and STREAM reassembly, and connection/stream flow-control accounting. It
//! consumes already-decoded `quic_frame.Frame` values and reuses
//! `quic_frame`'s wire codecs (it never re-encodes a frame by hand); the
//! transforms here are pure state mutation plus a small amount of allocation
//! for the reassembly buffers and ACK-range scratch.
//!
//! Contents (each maps to an RFC 9000 section):
//!
//!   * `PacketNumberSpace` / `SpaceSet` — RFC 9000 §12.3. One space per
//!     encryption level; tracks the next outbound packet number, the set of
//!     received packet numbers (as a sorted range list, for ACK generation),
//!     `largest_acked` from inbound ACKs, and whether an ACK is owed.
//!   * `AckManager` (the receiver/sender halves of a `PacketNumberSpace`) —
//!     RFC 9000 §13, §19.3. Records received PNs, coalesces them into the
//!     largest-first ACK-range encoding, and processes inbound ACK frames to
//!     return the newly-acknowledged outbound packet numbers.
//!   * `CryptoStream` — RFC 9000 §19.6. Offset-tagged, ordered byte assembler
//!     for the handshake stream (tolerates reorder/overlap/dup, caps the gap
//!     buffer), plus an outbound CRYPTO send buffer that fragments handshake
//!     bytes into frames within a max packet size.
//!   * `StreamRecv` + `StreamId` + `FlowController` — RFC 9000 §2, §3, §4,
//!     §19.8. Per-stream ordered reassembly from STREAM frames (offset, fin),
//!     receive-side flow control against advertised `MAX_STREAM_DATA` /
//!     `MAX_DATA` limits, and stream-id classification helpers.
//!   * `Engine` — the connection-level coordinator and the `intake` function
//!     (RFC 9000 §12, §13): given the decoded frames of a received packet at a
//!     level, it updates every sub-component and returns an `IntakeResult`
//!     describing what the caller must act on.
//!
//! Allocation discipline: every owning type takes the allocator at `init` and
//! frees everything in `deinit`. Buffers are capped (`max_*` config) so a
//! malicious peer cannot drive us to OOM or out-of-bounds. The whole module is
//! unit-testable without a socket; the tests at the bottom exercise the RFC
//! behaviours directly.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const quic_frame = @import("quic_frame.zig");
const quic_protect = @import("quic_protect.zig");

pub const Frame = quic_frame.Frame;
pub const AckFrame = quic_frame.AckFrame;
pub const AckRange = quic_frame.AckRange;
pub const CryptoFrame = quic_frame.CryptoFrame;
pub const StreamFrame = quic_frame.StreamFrame;
pub const ConnectionCloseFrame = quic_frame.ConnectionCloseFrame;

/// Re-export so callers index spaces by encryption level with one import.
pub const EncryptionLevel = quic_protect.EncryptionLevel;

/// Largest legal QUIC varint value (2^62 - 1). Packet numbers, offsets, and
/// stream ids are all bounded by this on the wire (RFC 9000 §16).
pub const max_varint: u64 = quic_frame.max_varint;

pub const ConnError = error{
    /// An ACK frame's ranges underflowed below packet number 0, or otherwise
    /// described a non-existent packet (RFC 9000 §19.3.1) — a connection error
    /// of type FRAME_ENCODING_ERROR for the caller to surface.
    MalformedAck,
    /// A CRYPTO or STREAM offset+len exceeded 2^62-1 (RFC 9000 §19.6/§19.8) —
    /// FRAME_ENCODING_ERROR.
    OffsetTooLarge,
    /// Received CRYPTO/STREAM data would exceed the local reassembly buffer cap.
    /// For CRYPTO this maps to CRYPTO_BUFFER_EXCEEDED (RFC 9000 §7.5).
    BufferExceeded,
    /// Stream or connection receive data exceeded the advertised flow-control
    /// limit (RFC 9000 §4.1) — FLOW_CONTROL_ERROR.
    FlowControl,
    /// A STREAM frame mutated a stream's final size after it was established, or
    /// delivered data past a known fin (RFC 9000 §4.5) — FINAL_SIZE_ERROR.
    FinalSizeError,
};

pub const Error = ConnError || Allocator.Error;

// ===========================================================================
// Stream id classification (RFC 9000 §2.1)
// ===========================================================================

/// Which endpoint opened a stream (low bit 0x1 of the stream id).
pub const Initiator = enum { client, server };

/// Stream directionality (bit 0x2 of the stream id).
pub const Directionality = enum { bidirectional, unidirectional };

/// Decomposed view of a QUIC stream id. The low two bits encode the initiator
/// and directionality; the remaining 60 bits are the per-(initiator,
/// directionality) sequence number (RFC 9000 §2.1, Table 1).
pub const StreamId = struct {
    raw: u64,

    pub fn init(raw: u64) StreamId {
        return .{ .raw = raw };
    }

    /// Bit 0x1: 0 = client-initiated, 1 = server-initiated.
    pub fn initiator(self: StreamId) Initiator {
        return if (self.raw & 0x1 == 0) .client else .server;
    }

    /// Bit 0x2: 0 = bidirectional, 1 = unidirectional.
    pub fn directionality(self: StreamId) Directionality {
        return if (self.raw & 0x2 == 0) .bidirectional else .unidirectional;
    }

    pub fn isClientInitiated(self: StreamId) bool {
        return self.initiator() == .client;
    }

    pub fn isServerInitiated(self: StreamId) bool {
        return self.initiator() == .server;
    }

    pub fn isBidirectional(self: StreamId) bool {
        return self.directionality() == .bidirectional;
    }

    pub fn isUnidirectional(self: StreamId) bool {
        return self.directionality() == .unidirectional;
    }

    /// The 60-bit sequence number within its (initiator, directionality) class.
    pub fn ordinal(self: StreamId) u64 {
        return self.raw >> 2;
    }

    /// Is this stream id one the local endpoint (server or client) is permitted
    /// to *receive* data on? An endpoint may only receive on streams the peer
    /// opened, plus the receive half of its own bidirectional streams. This is
    /// the weak check used to reject obviously-illegal STREAM frames; full
    /// role-aware validation lives in the stream-management layer above.
    pub fn peerInitiated(self: StreamId, local: Initiator) bool {
        return self.initiator() != local;
    }
};

// ===========================================================================
// Sorted packet-number / offset range set (shared building block)
// ===========================================================================

/// A half-open... no — an *inclusive* [start, end] range of integers. Used both
/// for received-packet-number tracking (ACK generation) and, conceptually, for
/// the gap bookkeeping in the reassemblers. Inclusive bounds match the QUIC ACK
/// range encoding (RFC 9000 §19.3.1), which counts packets, not byte offsets.
pub const Range = struct {
    start: u64,
    end: u64,

    fn contains(self: Range, v: u64) bool {
        return v >= self.start and v <= self.end;
    }
};

/// A set of received packet numbers stored as a list of disjoint inclusive
/// ranges kept sorted ascending by `start` and always maximally coalesced
/// (no two ranges touch or overlap). Insertion is O(n) in the number of
/// ranges, which is bounded by `max_ranges`; a well-behaved peer produces very
/// few ranges, and the cap stops a peer from forcing unbounded growth by
/// sending a pathological hole pattern.
pub const RangeSet = struct {
    ranges: std.ArrayList(Range) = .empty,
    max_ranges: usize,

    pub fn init(max_ranges: usize) RangeSet {
        assert(max_ranges > 0);
        return .{ .ranges = .empty, .max_ranges = max_ranges };
    }

    pub fn deinit(self: *RangeSet, allocator: Allocator) void {
        self.ranges.deinit(allocator);
        self.* = undefined;
    }

    pub fn isEmpty(self: *const RangeSet) bool {
        return self.ranges.items.len == 0;
    }

    pub fn count(self: *const RangeSet) usize {
        return self.ranges.items.len;
    }

    pub fn contains(self: *const RangeSet, v: u64) bool {
        // Ranges are sorted; a small linear scan is fine for the bounded count.
        for (self.ranges.items) |r| {
            if (v < r.start) return false;
            if (v <= r.end) return true;
        }
        return false;
    }

    /// Largest value present, or null if empty.
    pub fn max(self: *const RangeSet) ?u64 {
        if (self.ranges.items.len == 0) return null;
        return self.ranges.items[self.ranges.items.len - 1].end;
    }

    /// Insert a single value, coalescing with any adjacent/overlapping ranges.
    /// Duplicates are a no-op. Returns `error.BufferExceeded` only if inserting
    /// a brand-new isolated range would exceed `max_ranges` (a fresh value that
    /// neither extends nor merges existing ranges).
    pub fn insert(self: *RangeSet, allocator: Allocator, v: u64) Error!void {
        // Find the first range whose start is >= v (insertion point).
        var idx: usize = 0;
        while (idx < self.ranges.items.len and self.ranges.items[idx].start <= v) : (idx += 1) {
            const r = self.ranges.items[idx];
            if (v <= r.end) return; // already present
        }
        // `idx` is now the index of the first range with start > v (or end).
        // Check merge with the predecessor (range at idx-1) and successor (idx).
        const has_prev = idx > 0;
        const has_next = idx < self.ranges.items.len;
        const touches_prev = has_prev and self.ranges.items[idx - 1].end + 1 == v;
        const touches_next = has_next and v + 1 == self.ranges.items[idx].start;

        if (touches_prev and touches_next) {
            // Bridge two ranges into one; drop the successor.
            self.ranges.items[idx - 1].end = self.ranges.items[idx].end;
            _ = self.ranges.orderedRemove(idx);
            return;
        }
        if (touches_prev) {
            self.ranges.items[idx - 1].end = v;
            return;
        }
        if (touches_next) {
            self.ranges.items[idx].start = v;
            return;
        }
        // Brand-new isolated range.
        if (self.ranges.items.len >= self.max_ranges) return error.BufferExceeded;
        try self.ranges.insert(allocator, idx, .{ .start = v, .end = v });
    }
};

// ===========================================================================
// ACK generation + processing (RFC 9000 §13, §19.3)
// ===========================================================================

/// The encoded form of an ACK frame plus the allocation backing its ranges.
/// Returned by `PacketNumberSpace.buildAck`. The `frame` borrows `ranges`; call
/// `deinit` to free. Re-encode it onto the wire with
/// `quic_frame.encodeFrame(.{ .ACK = built.frame })`.
pub const BuiltAck = struct {
    frame: AckFrame,
    ranges: []AckRange,

    pub fn deinit(self: *BuiltAck, allocator: Allocator) void {
        allocator.free(self.ranges);
        self.* = undefined;
    }
};

/// Default ceiling on the number of distinct received-PN ranges we will track
/// per space. 256 holes is far beyond any benign pattern; past it we collapse
/// (drop the oldest/lowest range) rather than erroring, because dropping an old
/// ACK range only costs a spurious retransmit, never correctness.
pub const default_max_ack_ranges: usize = 256;

/// One QUIC packet-number space (RFC 9000 §12.3). There are three of them per
/// connection (Initial / Handshake / Application), each fully independent: a
/// packet number sent in one space says nothing about another.
pub const PacketNumberSpace = struct {
    level: EncryptionLevel,

    /// Next packet number to assign to an outgoing packet in this space.
    next_outbound: u64 = 0,

    /// Received packet numbers, for ACK generation. Coalesced range set.
    received: RangeSet,

    /// Largest packet number acknowledged by the peer (from inbound ACKs).
    /// Monotonically non-decreasing (RFC 9000 §13.2.3 — a peer never un-acks).
    largest_acked: ?u64 = null,

    /// True once we have received an ack-eliciting packet that has not yet been
    /// acknowledged by an ACK we sent. The driver checks this to decide whether
    /// it must emit an ACK frame (RFC 9000 §13.2.1).
    ack_eliciting_pending: bool = false,

    /// Largest packet number ever received, cached for the ACK delay calc. It
    /// can exceed `received.max()` when the range cap evicts a higher range
    /// while admitting a much older out-of-order packet.
    largest_received: ?u64 = null,

    pub fn init(level: EncryptionLevel, max_ack_ranges: usize) PacketNumberSpace {
        return .{
            .level = level,
            .received = RangeSet.init(max_ack_ranges),
        };
    }

    pub fn deinit(self: *PacketNumberSpace, allocator: Allocator) void {
        self.received.deinit(allocator);
        self.* = undefined;
    }

    /// Allocate the next outbound packet number in this space.
    pub fn nextPacketNumber(self: *PacketNumberSpace) u64 {
        const pn = self.next_outbound;
        self.next_outbound += 1;
        return pn;
    }

    /// Record a received packet number for later acknowledgement. `ack_eliciting`
    /// marks whether the packet carried any ack-eliciting frame (anything other
    /// than ACK / PADDING / CONNECTION_CLOSE — RFC 9000 §13.2.1); if so we set
    /// the pending flag so the driver knows it owes an ACK.
    ///
    /// If recording the PN would overflow the range cap, we evict the lowest
    /// (oldest) range to make room. Dropping an old ACK range is always safe:
    /// the worst case is the peer retransmits a packet we already had.
    pub fn recordReceived(
        self: *PacketNumberSpace,
        allocator: Allocator,
        pn: u64,
        ack_eliciting: bool,
    ) Error!void {
        self.received.insert(allocator, pn) catch |err| switch (err) {
            error.BufferExceeded => {
                // Evict the lowest range and retry once.
                if (self.received.ranges.items.len > 0) {
                    _ = self.received.ranges.orderedRemove(0);
                }
                try self.received.insert(allocator, pn);
            },
            else => return err,
        };
        if (self.largest_received == null or pn > self.largest_received.?) {
            self.largest_received = pn;
        }
        if (ack_eliciting) self.ack_eliciting_pending = true;
    }

    /// Whether the driver owes the peer an ACK for this space.
    pub fn ackPending(self: *const PacketNumberSpace) bool {
        return self.ack_eliciting_pending;
    }

    /// Build an `AckFrame` acknowledging every packet number recorded so far,
    /// in the QUIC largest-first range encoding (RFC 9000 §19.3.1):
    ///
    ///   * `largest`     = highest received PN.
    ///   * `first_range` = (number of contiguous PNs below `largest` in the
    ///     top range). For received {0,1,2,5,6,9}, largest=9, top range is the
    ///     singleton [9,9] so first_range=0.
    ///   * each subsequent range: `gap` = (PNs skipped between this range and
    ///     the previous one, minus the mandatory 1) and `len` = (range length
    ///     minus 1). The decoder in `quic_frame` mirrors this exactly.
    ///
    /// `ack_delay` is the value to put in the frame's delay field (already in
    /// the peer's ack-delay-exponent units; this layer does not apply the
    /// exponent). Returns null if nothing has been received yet.
    ///
    /// Building an ACK does *not* by itself clear the pending flag — the driver
    /// clears it via `onAckSent` once the packet carrying this ACK is actually
    /// transmitted, so a build that is later dropped does not silently suppress
    /// a future ACK.
    pub fn buildAck(
        self: *const PacketNumberSpace,
        allocator: Allocator,
        ack_delay: u64,
    ) Error!?BuiltAck {
        const items = self.received.ranges.items;
        if (items.len == 0) return null;

        // Walk ranges from highest to lowest. The top range yields `largest` and
        // `first_range`; the rest become (gap, len) pairs.
        const top = items[items.len - 1];
        const largest = top.end;
        const first_range = top.end - top.start;

        const range_count = items.len - 1;
        const ranges = try allocator.alloc(AckRange, range_count);
        errdefer allocator.free(ranges);

        // prev_smallest = the lowest PN of the previously-emitted (higher) range.
        var prev_smallest = top.start;
        var out_idx: usize = 0;
        var i: usize = items.len - 1;
        while (i > 0) {
            i -= 1;
            const r = items[i];
            // Gap counts the unacked PNs strictly between this range's end and
            // the previous range's start, encoded as (count - 1) per §19.3.1:
            //   gap = prev_smallest - r.end - 2
            // and len = (r.end - r.start) (range length minus 1).
            const gap = prev_smallest - r.end - 2;
            const len = r.end - r.start;
            ranges[out_idx] = .{ .gap = gap, .len = len };
            out_idx += 1;
            prev_smallest = r.start;
        }
        assert(out_idx == range_count);

        return .{
            .frame = .{
                .largest = largest,
                .delay = ack_delay,
                .first_range = first_range,
                .ranges = ranges,
            },
            .ranges = ranges,
        };
    }

    /// Clear the ack-eliciting-pending flag. Call once the ACK has been put on
    /// the wire (RFC 9000 §13.2.1).
    pub fn onAckSent(self: *PacketNumberSpace) void {
        self.ack_eliciting_pending = false;
    }

    /// Process an inbound `AckFrame` against the packets we have sent in this
    /// space. Advances `largest_acked` (monotonically) and appends every
    /// *newly* acknowledged outbound packet number to `newly_acked`
    /// (caller-owned, e.g. an ArrayList) for the loss/congestion layer.
    ///
    /// `acked_set` is this space's record of which of our outbound PNs have been
    /// acked already, so a duplicate ACK reports nothing new (RFC 9000 §13.2.3).
    ///
    /// Validates the range arithmetic: any range that underflows below 0 or
    /// names a packet we never sent (>= `next_outbound`) is a MalformedAck. The
    /// reassembly of the ranges follows §19.3.1 in reverse.
    pub fn processAck(
        self: *PacketNumberSpace,
        ack: AckFrame,
        acked_set: *RangeSet,
        acked_allocator: Allocator,
        newly_acked: *std.ArrayList(u64),
        newly_allocator: Allocator,
    ) Error!void {
        if (ack.largest >= self.next_outbound) return error.MalformedAck;

        // Advance largest_acked monotonically.
        if (self.largest_acked == null or ack.largest > self.largest_acked.?) {
            self.largest_acked = ack.largest;
        }

        // Top range: [largest - first_range, largest].
        if (ack.first_range > ack.largest) return error.MalformedAck;
        var range_hi = ack.largest;
        var range_lo = ack.largest - ack.first_range;
        try self.ackRange(range_lo, range_hi, acked_set, acked_allocator, newly_acked, newly_allocator);

        // Subsequent ranges walk downward. Per §19.3.1:
        //   next_largest = range_lo - gap - 2
        //   next_lo      = next_largest - len
        for (ack.ranges) |r| {
            // gap+2 must not underflow past the smallest acked PN (which is
            // range_lo). If it does, the peer described packet -1 — malformed.
            const step = r.gap + 2;
            if (step > range_lo) return error.MalformedAck;
            range_hi = range_lo - step;
            if (r.len > range_hi) return error.MalformedAck;
            range_lo = range_hi - r.len;
            try self.ackRange(range_lo, range_hi, acked_set, acked_allocator, newly_acked, newly_allocator);
        }
    }

    /// Mark inclusive [lo, hi] of our outbound PNs as acknowledged, recording
    /// any not-yet-seen PN in `newly_acked`. Rejects a range naming a packet we
    /// never sent.
    fn ackRange(
        self: *PacketNumberSpace,
        lo: u64,
        hi: u64,
        acked_set: *RangeSet,
        acked_allocator: Allocator,
        newly_acked: *std.ArrayList(u64),
        newly_allocator: Allocator,
    ) Error!void {
        if (hi >= self.next_outbound) return error.MalformedAck;
        var pn = lo;
        while (pn <= hi) : (pn += 1) {
            if (!acked_set.contains(pn)) {
                try acked_set.insert(acked_allocator, pn);
                try newly_acked.append(newly_allocator, pn);
            }
            if (pn == std.math.maxInt(u64)) break; // avoid wrap (unreachable in practice)
        }
    }
};

/// The three packet-number spaces of a connection, indexed by encryption level.
/// The Application space holds both 0-RTT and 1-RTT packets (they share one
/// space — RFC 9000 §12.3).
pub const SpaceSet = struct {
    initial: PacketNumberSpace,
    handshake: PacketNumberSpace,
    application: PacketNumberSpace,

    pub fn init(max_ack_ranges: usize) SpaceSet {
        return .{
            .initial = PacketNumberSpace.init(.initial, max_ack_ranges),
            .handshake = PacketNumberSpace.init(.handshake, max_ack_ranges),
            .application = PacketNumberSpace.init(.application, max_ack_ranges),
        };
    }

    pub fn deinit(self: *SpaceSet, allocator: Allocator) void {
        self.initial.deinit(allocator);
        self.handshake.deinit(allocator);
        self.application.deinit(allocator);
        self.* = undefined;
    }

    pub fn get(self: *SpaceSet, level: EncryptionLevel) *PacketNumberSpace {
        return switch (level) {
            .initial => &self.initial,
            .handshake => &self.handshake,
            .application => &self.application,
        };
    }
};

// ===========================================================================
// CRYPTO stream reassembly + send buffer (RFC 9000 §19.6)
// ===========================================================================

/// Default cap on buffered (received-but-not-yet-delivered) CRYPTO bytes.
/// RFC 9000 §7.5 lets an endpoint bound this and raise CRYPTO_BUFFER_EXCEEDED;
/// 64 KiB comfortably holds a full handshake flight including a cert chain.
pub const default_crypto_buffer_cap: usize = 64 * 1024;

/// Ordered byte assembler for one direction of the CRYPTO stream (RFC 9000
/// §19.6). CRYPTO frames carry an absolute offset; they may arrive out of
/// order, overlap, or duplicate. This assembler stores any out-of-order bytes
/// in a single contiguous staging buffer indexed by absolute offset, and yields
/// the in-order prefix as it becomes contiguous from `read_offset`.
///
/// The staging buffer holds bytes in the window [read_offset, read_offset +
/// staged.len). A per-byte `filled` bitmap-equivalent (a bool array) records
/// which staged offsets have actually been written, so overlapping/partial
/// frames coalesce correctly and we never emit a gap.
///
/// Cap: the highest offset any frame may reference is `read_offset + cap`.
/// Beyond that we return `error.BufferExceeded` (CRYPTO_BUFFER_EXCEEDED).
pub const CryptoStream = struct {
    /// Absolute stream offset of the next byte the consumer will read. Every
    /// byte below this has already been delivered.
    read_offset: u64 = 0,

    /// Staged bytes for offsets [read_offset, read_offset + staged.items.len).
    staged: std.ArrayList(u8) = .empty,
    /// `filled[i]` is true iff staged offset read_offset+i has been written.
    filled: std.ArrayList(bool) = .empty,

    /// Maximum number of buffered (staged) bytes ahead of `read_offset`.
    cap: usize,

    pub fn init(cap: usize) CryptoStream {
        assert(cap > 0);
        return .{ .cap = cap };
    }

    pub fn deinit(self: *CryptoStream, allocator: Allocator) void {
        self.staged.deinit(allocator);
        self.filled.deinit(allocator);
        self.* = undefined;
    }

    /// Total contiguous bytes available to read from `read_offset` (the length
    /// of the in-order prefix that is fully filled).
    pub fn readable(self: *const CryptoStream) usize {
        var n: usize = 0;
        while (n < self.filled.items.len and self.filled.items[n]) : (n += 1) {}
        return n;
    }

    /// Accept a CRYPTO frame's (offset, data). Bytes wholly below `read_offset`
    /// (already delivered) are ignored; overlap with already-staged bytes is
    /// tolerated (idempotent write). Returns `error.OffsetTooLarge` if
    /// offset+len overflows the varint space, `error.BufferExceeded` if the
    /// frame references an offset beyond the cap.
    pub fn receive(self: *CryptoStream, allocator: Allocator, offset: u64, data: []const u8) Error!void {
        const end = std.math.add(u64, offset, data.len) catch return error.OffsetTooLarge;
        if (end > max_varint) return error.OffsetTooLarge;

        // Drop the portion that is fully before read_offset (already consumed).
        var off = offset;
        var src = data;
        if (off < self.read_offset) {
            const skip = self.read_offset - off;
            if (skip >= src.len) return; // entirely old
            src = src[@intCast(skip)..];
            off = self.read_offset;
        }
        if (src.len == 0) return;

        // Position within the staging window.
        const rel = off - self.read_offset; // >= 0 by construction
        const needed_len = rel + src.len; // bytes from read_offset to frame end
        if (needed_len > self.cap) return error.BufferExceeded;
        const rel_idx: usize = @intCast(rel);
        const new_len: usize = @intCast(needed_len);

        // Grow the staging buffers to cover [read_offset, end).
        if (new_len > self.staged.items.len) {
            const old_len = self.staged.items.len;
            try self.staged.resize(allocator, new_len);
            try self.filled.resize(allocator, new_len);
            // Newly-grown filled slots default to false.
            var i = old_len;
            while (i < new_len) : (i += 1) self.filled.items[i] = false;
        }

        // Write the bytes, marking them filled (idempotent on overlap).
        for (src, 0..) |b, i| {
            self.staged.items[rel_idx + i] = b;
            self.filled.items[rel_idx + i] = true;
        }
    }

    /// Peek the contiguous in-order bytes currently available (a borrow into the
    /// internal buffer; valid only until the next `receive`/`consume`).
    pub fn peek(self: *const CryptoStream) []const u8 {
        return self.staged.items[0..self.readable()];
    }

    /// Consume up to `n` contiguous in-order bytes, advancing `read_offset` and
    /// compacting the staging buffer. Returns the number actually consumed
    /// (`min(n, readable())`).
    pub fn consume(self: *CryptoStream, n: usize) usize {
        const avail = self.readable();
        const take = @min(n, avail);
        if (take == 0) return 0;
        // Shift the remaining staged bytes down.
        const remaining = self.staged.items.len - take;
        std.mem.copyForwards(u8, self.staged.items[0..remaining], self.staged.items[take..]);
        std.mem.copyForwards(bool, self.filled.items[0..remaining], self.filled.items[take..]);
        self.staged.shrinkRetainingCapacity(remaining);
        self.filled.shrinkRetainingCapacity(remaining);
        self.read_offset += take;
        return take;
    }
};

/// Outbound CRYPTO send buffer (RFC 9000 §19.6, send side). Accumulates
/// handshake bytes produced by the TLS layer and fragments them into CRYPTO
/// frames that fit within a caller-supplied max frame-payload size. Tracks the
/// next un-emitted offset so successive `nextFrame` calls advance through the
/// buffer.
pub const CryptoSendBuffer = struct {
    /// All handshake bytes queued so far. `base_offset` is the absolute stream
    /// offset of buf[0].
    buf: std.ArrayList(u8) = .empty,
    base_offset: u64 = 0,
    /// Next absolute offset to emit (>= base_offset, <= base_offset + buf.len).
    send_offset: u64 = 0,

    pub fn init() CryptoSendBuffer {
        return .{};
    }

    pub fn deinit(self: *CryptoSendBuffer, allocator: Allocator) void {
        self.buf.deinit(allocator);
        self.* = undefined;
    }

    /// Queue handshake bytes for transmission. Returns `error.OffsetTooLarge`
    /// if the resulting stream length would exceed the varint space.
    pub fn write(self: *CryptoSendBuffer, allocator: Allocator, data: []const u8) Error!void {
        const total = std.math.add(u64, self.base_offset, self.buf.items.len + data.len) catch
            return error.OffsetTooLarge;
        if (total > max_varint) return error.OffsetTooLarge;
        try self.buf.appendSlice(allocator, data);
    }

    /// Bytes queued but not yet emitted into a frame.
    pub fn pending(self: *const CryptoSendBuffer) u64 {
        const end = self.base_offset + self.buf.items.len;
        return end - self.send_offset;
    }

    /// Produce the next CRYPTO frame of at most `max_payload` bytes, or null if
    /// nothing is pending. The returned frame *borrows* into this buffer (its
    /// `data` slice is valid until the next mutating call); the caller hands it
    /// to `quic_frame.encodeFrame` immediately. `send_offset` advances by the
    /// emitted length so the next call continues where this left off.
    pub fn nextFrame(self: *CryptoSendBuffer, max_payload: usize) ?CryptoFrame {
        if (max_payload == 0) return null;
        const avail = self.pending();
        if (avail == 0) return null;
        const take: usize = @intCast(@min(@as(u64, max_payload), avail));
        const rel_start: usize = @intCast(self.send_offset - self.base_offset);
        const frame_offset = self.send_offset;
        const slice = self.buf.items[rel_start .. rel_start + take];
        self.send_offset += take;
        return .{ .offset = frame_offset, .len = take, .data = slice };
    }
};

// ===========================================================================
// STREAM reassembly + flow control (RFC 9000 §2, §4, §19.8)
// ===========================================================================

/// Receive-side flow controller for a single window: tracks how many bytes have
/// been *received* (the highest offset seen + 1, i.e. the current data length)
/// against an advertised maximum. Used both per-stream (MAX_STREAM_DATA) and
/// connection-wide (MAX_DATA), RFC 9000 §4.1.
pub const FlowController = struct {
    /// Highest received absolute offset + 1 (total bytes the peer has committed
    /// to send on this window so far). Monotonically non-decreasing.
    received: u64 = 0,
    /// Maximum offset the peer is permitted to send (the advertised limit).
    limit: u64,

    pub fn init(limit: u64) FlowController {
        return .{ .limit = limit };
    }

    /// Record that the peer has now committed data up to absolute offset `end`
    /// (exclusive). Returns `error.FlowControl` if `end` exceeds the advertised
    /// limit. Only advances `received` (never lowers it), so re-delivered or
    /// out-of-order frames within the window are free.
    pub fn observe(self: *FlowController, end: u64) Error!void {
        if (end > self.limit) return error.FlowControl;
        if (end > self.received) self.received = end;
    }

    /// Raise the advertised limit (when the local endpoint sends MAX_DATA /
    /// MAX_STREAM_DATA). Never lowers it (RFC 9000 §4.1).
    pub fn setLimit(self: *FlowController, new_limit: u64) void {
        if (new_limit > self.limit) self.limit = new_limit;
    }

    /// Remaining window the peer may still use.
    pub fn available(self: *const FlowController) u64 {
        return self.limit - self.received;
    }
};

/// Default per-stream reassembly buffer cap. Independent of the stream
/// flow-control limit; this bounds the *out-of-order* staging memory so a peer
/// cannot make us buffer a huge hole even within its flow-control window.
pub const default_stream_buffer_cap: usize = 256 * 1024;

/// Per-stream ordered receive reassembler (RFC 9000 §2.2, §19.8). Like
/// `CryptoStream` but stream-id aware and fin-tracking, and it owns its own
/// per-stream `FlowController` (MAX_STREAM_DATA). The connection-wide MAX_DATA
/// controller lives on the `Engine` and is checked there.
pub const StreamRecv = struct {
    id: StreamId,
    read_offset: u64 = 0,
    staged: std.ArrayList(u8) = .empty,
    filled: std.ArrayList(bool) = .empty,
    cap: usize,

    /// Per-stream receive flow control (MAX_STREAM_DATA).
    flow: FlowController,

    /// Final size of the stream once a FIN has been observed, else null. After
    /// this is set, any frame implying a larger size is a FINAL_SIZE_ERROR.
    final_size: ?u64 = null,
    /// True once the consumer has read up to `final_size` (clean EOF delivered).
    fin_consumed: bool = false,

    pub fn init(id: StreamId, stream_data_limit: u64, cap: usize) StreamRecv {
        assert(cap > 0);
        return .{
            .id = id,
            .cap = cap,
            .flow = FlowController.init(stream_data_limit),
        };
    }

    pub fn deinit(self: *StreamRecv, allocator: Allocator) void {
        self.staged.deinit(allocator);
        self.filled.deinit(allocator);
        self.* = undefined;
    }

    pub fn readable(self: *const StreamRecv) usize {
        var n: usize = 0;
        while (n < self.filled.items.len and self.filled.items[n]) : (n += 1) {}
        return n;
    }

    /// True once every byte through the final size has been read by the
    /// consumer — the point at which the application observes a clean fin.
    pub fn finReached(self: *const StreamRecv) bool {
        return self.fin_consumed;
    }

    /// Accept a STREAM frame's (offset, fin, data). Enforces per-stream flow
    /// control and final-size invariants. Returns:
    ///   * `error.OffsetTooLarge`  — offset+len overflows varint space.
    ///   * `error.FlowControl`     — end offset exceeds MAX_STREAM_DATA.
    ///   * `error.FinalSizeError`  — fin/offset contradicts an established final
    ///                               size (RFC 9000 §4.5).
    ///   * `error.BufferExceeded`  — staging would exceed the local buffer cap.
    pub fn receive(
        self: *StreamRecv,
        allocator: Allocator,
        offset: u64,
        fin: bool,
        data: []const u8,
    ) Error!void {
        const end = std.math.add(u64, offset, data.len) catch return error.OffsetTooLarge;
        if (end > max_varint) return error.OffsetTooLarge;

        // Final-size checks (RFC 9000 §4.5).
        if (fin and end < self.flow.received) return error.FinalSizeError;
        if (self.final_size) |fsz| {
            // No byte may be delivered at or beyond an established final size,
            // and a new fin must agree on the size.
            if (end > fsz) return error.FinalSizeError;
            if (fin and end != fsz) return error.FinalSizeError;
        }
        if (fin) {
            // Establish (or re-confirm) the final size = end of this frame.
            if (self.final_size) |fsz| {
                if (fsz != end) return error.FinalSizeError;
            } else {
                self.final_size = end;
            }
        }

        // Flow control: the peer has now committed data up to `end`.
        try self.flow.observe(end);

        // Stage the bytes (same logic as CryptoStream).
        var off = offset;
        var src = data;
        if (off < self.read_offset) {
            const skip = self.read_offset - off;
            if (skip >= src.len) {
                // Wholly-old data; still may carry the fin which we handled above.
                return;
            }
            src = src[@intCast(skip)..];
            off = self.read_offset;
        }
        if (src.len == 0) return;

        const rel = off - self.read_offset;
        const needed_len = rel + src.len;
        if (needed_len > self.cap) return error.BufferExceeded;
        const rel_idx: usize = @intCast(rel);
        const new_len: usize = @intCast(needed_len);

        if (new_len > self.staged.items.len) {
            const old_len = self.staged.items.len;
            try self.staged.resize(allocator, new_len);
            try self.filled.resize(allocator, new_len);
            var i = old_len;
            while (i < new_len) : (i += 1) self.filled.items[i] = false;
        }
        for (src, 0..) |b, i| {
            self.staged.items[rel_idx + i] = b;
            self.filled.items[rel_idx + i] = true;
        }
    }

    pub fn peek(self: *const StreamRecv) []const u8 {
        return self.staged.items[0..self.readable()];
    }

    /// Consume up to `n` contiguous in-order bytes. Sets `fin_consumed` once the
    /// reader has drained through the final size.
    pub fn consume(self: *StreamRecv, n: usize) usize {
        const avail = self.readable();
        const take = @min(n, avail);
        if (take > 0) {
            const remaining = self.staged.items.len - take;
            std.mem.copyForwards(u8, self.staged.items[0..remaining], self.staged.items[take..]);
            std.mem.copyForwards(bool, self.filled.items[0..remaining], self.filled.items[take..]);
            self.staged.shrinkRetainingCapacity(remaining);
            self.filled.shrinkRetainingCapacity(remaining);
            self.read_offset += take;
        }
        if (self.final_size) |fsz| {
            if (self.read_offset >= fsz) self.fin_consumed = true;
        }
        return take;
    }
};

// ===========================================================================
// Connection engine + frame intake (RFC 9000 §12, §13)
// ===========================================================================

/// Tunable caps for the whole engine. All have safe defaults; a deployment can
/// tighten them. Every cap exists to bound peer-controlled memory.
pub const Config = struct {
    max_ack_ranges: usize = default_max_ack_ranges,
    crypto_buffer_cap: usize = default_crypto_buffer_cap,
    stream_buffer_cap: usize = default_stream_buffer_cap,
    /// Connection-wide receive flow-control limit (MAX_DATA).
    initial_max_data: u64 = 1 << 24, // 16 MiB
    /// Default per-stream receive limit (MAX_STREAM_DATA) for new streams.
    initial_max_stream_data: u64 = 1 << 20, // 1 MiB
    /// Maximum number of distinct receive streams to track concurrently.
    max_streams: usize = 4096,
};

/// What the caller must act on after `intake` processes one packet's frames.
/// Pure data — the engine has already updated its own state; this is the
/// to-do list it hands back.
pub const IntakeResult = struct {
    /// The packet contained at least one ack-eliciting frame, so an ACK is owed
    /// in this space (mirror of `space.ackPending()` after intake).
    ack_eliciting: bool = false,
    /// New handshake bytes became contiguously readable on the CRYPTO stream.
    crypto_readable: usize = 0,
    /// A CONNECTION_CLOSE was received; the connection is closing. The error
    /// code is captured for the caller (the reason slice is *not* retained —
    /// it borrows the decoded frame which the caller still owns).
    connection_close: ?u64 = null,
    /// Number of PING frames seen (purely informational; PING is ack-eliciting
    /// and already reflected in `ack_eliciting`).
    ping_count: usize = 0,
    /// Number of newly-acknowledged outbound packets appended to the caller's
    /// `newly_acked` list by inbound ACK processing.
    newly_acked_count: usize = 0,
};

/// The per-connection frame engine. Owns the three packet-number spaces, the
/// per-space sent-PN sets (for ACK processing), one CRYPTO reassembler per
/// space, the receive-stream table, and the connection-wide flow controller.
///
/// The send-side CRYPTO buffers and outbound packet assembly are the next
/// layer's concern beyond `CryptoSendBuffer` (provided here as a building
/// block); this engine focuses on *receive* processing and ACK state, which is
/// what the intake path needs.
pub const Engine = struct {
    allocator: Allocator,
    config: Config,
    /// Which endpoint we are — used to classify peer- vs self-initiated streams.
    local: Initiator,

    spaces: SpaceSet,
    /// Per-space record of which of *our* outbound PNs the peer has acked, so a
    /// duplicate ACK reports nothing new (RFC 9000 §13.2.3).
    acked_initial: RangeSet,
    acked_handshake: RangeSet,
    acked_application: RangeSet,

    /// One ordered CRYPTO reassembler per space (the handshake uses distinct
    /// CRYPTO streams per encryption level — RFC 9001 §4.1.3).
    crypto_initial: CryptoStream,
    crypto_handshake: CryptoStream,
    crypto_application: CryptoStream,

    /// Receive-stream table keyed by raw stream id.
    streams: std.AutoHashMap(u64, *StreamRecv),

    /// Connection-wide receive flow control (MAX_DATA, RFC 9000 §4.1).
    conn_flow: FlowController,
    /// Sum of every stream's `received` offset, which is what MAX_DATA bounds
    /// (RFC 9000 §4.1: connection data = Σ final/received offsets per stream).
    conn_received_total: u64 = 0,

    pub fn init(allocator: Allocator, local: Initiator, config: Config) Engine {
        return .{
            .allocator = allocator,
            .config = config,
            .local = local,
            .spaces = SpaceSet.init(config.max_ack_ranges),
            .acked_initial = RangeSet.init(config.max_ack_ranges),
            .acked_handshake = RangeSet.init(config.max_ack_ranges),
            .acked_application = RangeSet.init(config.max_ack_ranges),
            .crypto_initial = CryptoStream.init(config.crypto_buffer_cap),
            .crypto_handshake = CryptoStream.init(config.crypto_buffer_cap),
            .crypto_application = CryptoStream.init(config.crypto_buffer_cap),
            .streams = std.AutoHashMap(u64, *StreamRecv).init(allocator),
            .conn_flow = FlowController.init(config.initial_max_data),
        };
    }

    pub fn deinit(self: *Engine) void {
        self.spaces.deinit(self.allocator);
        self.acked_initial.deinit(self.allocator);
        self.acked_handshake.deinit(self.allocator);
        self.acked_application.deinit(self.allocator);
        self.crypto_initial.deinit(self.allocator);
        self.crypto_handshake.deinit(self.allocator);
        self.crypto_application.deinit(self.allocator);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit();
        self.* = undefined;
    }

    pub fn space(self: *Engine, level: EncryptionLevel) *PacketNumberSpace {
        return self.spaces.get(level);
    }

    pub fn cryptoStream(self: *Engine, level: EncryptionLevel) *CryptoStream {
        return switch (level) {
            .initial => &self.crypto_initial,
            .handshake => &self.crypto_handshake,
            .application => &self.crypto_application,
        };
    }

    fn ackedSet(self: *Engine, level: EncryptionLevel) *RangeSet {
        return switch (level) {
            .initial => &self.acked_initial,
            .handshake => &self.acked_handshake,
            .application => &self.acked_application,
        };
    }

    /// Look up (or lazily create) the receive state for a stream id. Returns
    /// `error.OutOfMemory` or a fresh `StreamRecv` configured with the default
    /// per-stream limit. Returns null-via-error only on allocation failure or
    /// when the stream table is full (`error.BufferExceeded`).
    fn getOrCreateStream(self: *Engine, raw_id: u64) Error!*StreamRecv {
        if (self.streams.get(raw_id)) |s| return s;
        if (self.streams.count() >= self.config.max_streams) return error.BufferExceeded;
        const s = try self.allocator.create(StreamRecv);
        errdefer self.allocator.destroy(s);
        s.* = StreamRecv.init(
            StreamId.init(raw_id),
            self.config.initial_max_stream_data,
            self.config.stream_buffer_cap,
        );
        try self.streams.put(raw_id, s);
        return s;
    }

    /// Get an existing receive stream, or null if none has been created.
    pub fn getStream(self: *Engine, raw_id: u64) ?*StreamRecv {
        return self.streams.get(raw_id);
    }

    /// Process the decoded frames of one received packet at `level` with packet
    /// number `pn`. Updates the packet-number space, feeds CRYPTO/STREAM
    /// reassemblers, processes ACKs (appending newly-acked outbound PNs to
    /// `newly_acked`), and notes PING/PADDING/CONNECTION_CLOSE. Returns an
    /// `IntakeResult` of what the caller must act on.
    ///
    /// On any frame error (flow control, malformed ACK, final size, buffer cap)
    /// the engine returns the error; the partial state changes already applied
    /// are safe to keep because a connection error tears the connection down.
    pub fn intake(
        self: *Engine,
        level: EncryptionLevel,
        pn: u64,
        frames: []const Frame,
        newly_acked: *std.ArrayList(u64),
    ) Error!IntakeResult {
        var result = IntakeResult{};
        const sp = self.space(level);
        const cs = self.cryptoStream(level);
        const crypto_readable_before = cs.readable();

        var ack_eliciting = false;
        for (frames) |frame| {
            switch (frame) {
                .PADDING => {}, // not ack-eliciting (RFC 9000 §19.1)
                .PING => {
                    ack_eliciting = true;
                    result.ping_count += 1;
                },
                .ACK => |ack| {
                    // ACK is not ack-eliciting (RFC 9000 §13.2.1).
                    const before = newly_acked.items.len;
                    try sp.processAck(
                        ack,
                        self.ackedSet(level),
                        self.allocator,
                        newly_acked,
                        self.allocator,
                    );
                    result.newly_acked_count += newly_acked.items.len - before;
                },
                .CRYPTO => |c| {
                    ack_eliciting = true;
                    try cs.receive(self.allocator, c.offset, c.data);
                },
                .STREAM => |s| {
                    ack_eliciting = true;
                    try self.intakeStream(s);
                },
                .DATAGRAM => {
                    // DATAGRAM is ack-eliciting (RFC 9221 §5); delivery of the
                    // payload to the application is the driver's job. We only
                    // account the ACK obligation here.
                    ack_eliciting = true;
                },
                .CONNECTION_CLOSE => |close| {
                    // Not ack-eliciting (RFC 9000 §13.2.1). Signals teardown.
                    result.connection_close = close.error_code;
                },
                .PATH_CHALLENGE, .PATH_RESPONSE => {
                    // Both are ack-eliciting (RFC 9000 §13.2.1). Path validation
                    // itself (challenge/response matching + migration) lives in
                    // the connection driver, which re-walks the decoded frames;
                    // the engine only owes the ACK obligation here.
                    ack_eliciting = true;
                },
                .HANDSHAKE_DONE => {
                    // RFC 9000 §19.20: ack-eliciting. The client uses it to
                    // confirm the handshake; the server never receives one. We owe
                    // the ACK; the driver acts on it if it cares.
                    ack_eliciting = true;
                },
                .MAX_DATA, .MAX_STREAM_DATA => {
                    // RFC 9000 §13.2.1: ack-eliciting. The send-side flow-control
                    // limits these raise are applied by the connection driver,
                    // which re-walks the decoded frames; the engine only owes the
                    // ACK here.
                    ack_eliciting = true;
                },
                .OTHER => |o| {
                    // A parse-and-skip transport frame (MAX_DATA, MAX_STREAMS,
                    // NEW_CONNECTION_ID, RESET_STREAM, …). We honor our peers'
                    // limits implicitly via our own generous windows and keep a
                    // single connection id, so there is nothing to act on — but we
                    // MUST still owe an ACK for an ack-eliciting frame (RFC 9000
                    // §13.2.1) so the peer's loss recovery makes progress.
                    if (o.ack_eliciting) ack_eliciting = true;
                },
            }
        }

        // Record the PN for ACK generation (after frame processing so a malformed
        // frame does not leave us owing an ACK for a packet we rejected).
        try sp.recordReceived(self.allocator, pn, ack_eliciting);

        result.ack_eliciting = sp.ackPending();
        const crypto_readable_after = cs.readable();
        result.crypto_readable = crypto_readable_after - crypto_readable_before;
        return result;
    }

    /// Feed one STREAM frame through per-stream reassembly + connection-wide
    /// flow control. The connection MAX_DATA is enforced against the *increase*
    /// in this stream's committed length.
    fn intakeStream(self: *Engine, s: StreamFrame) Error!void {
        const sid = StreamId.init(s.stream_id);
        // Weak role check: reject data on a stream we (the local endpoint) are
        // the sole sender of. The send-only half of a unidirectional stream the
        // *local* endpoint opened can never carry inbound data.
        if (sid.isUnidirectional() and !sid.peerInitiated(self.local)) {
            return error.FinalSizeError; // STREAM_STATE_ERROR analogue
        }

        const stream = try self.getOrCreateStream(s.stream_id);
        const before = stream.flow.received;

        // Connection-level flow control: the new end must fit under MAX_DATA in
        // aggregate. We compute the prospective connection total first so we
        // reject before mutating the stream.
        const new_end = std.math.add(u64, s.offset, s.data.len) catch return error.OffsetTooLarge;
        if (new_end > before) {
            const delta = new_end - before;
            const prospective = std.math.add(u64, self.conn_received_total, delta) catch
                return error.OffsetTooLarge;
            if (prospective > self.conn_flow.limit) return error.FlowControl;
        }

        try stream.receive(self.allocator, s.offset, s.fin, s.data);

        // Commit the connection-level accounting for the actual increase.
        const after = stream.flow.received;
        if (after > before) {
            self.conn_received_total += after - before;
            try self.conn_flow.observe(self.conn_received_total);
        }
    }

    /// Raise the connection-wide MAX_DATA (local endpoint sending MAX_DATA).
    pub fn setMaxData(self: *Engine, new_limit: u64) void {
        self.conn_flow.setLimit(new_limit);
    }

    /// Capture logical engine state at a quiescent packet boundary. The owned
    /// DTO never reads unfilled staging bytes; holes are encoded as zeroes.
    pub fn captureSnapshot(self: *const Engine, allocator: Allocator) SnapshotError!EngineSnapshot {
        var spaces: [3]?SpaceSnapshot = .{ null, null, null };
        errdefer for (&spaces) |*item| if (item.*) |*value| value.deinit(allocator);
        const source_spaces = [_]*const PacketNumberSpace{ &self.spaces.initial, &self.spaces.handshake, &self.spaces.application };
        const source_acked = [_]*const RangeSet{ &self.acked_initial, &self.acked_handshake, &self.acked_application };
        for (source_spaces, source_acked, 0..) |space_ptr, acked_ptr, i| {
            if (space_ptr.level != snapshotLevel(i)) return error.InvalidSnapshot;
            spaces[i] = try captureSpaceSnapshot(allocator, space_ptr, acked_ptr);
        }

        var crypto: [3]?ByteWindowSnapshot = .{ null, null, null };
        errdefer for (&crypto) |*item| if (item.*) |*value| value.deinit(allocator);
        const source_crypto = [_]*const CryptoStream{ &self.crypto_initial, &self.crypto_handshake, &self.crypto_application };
        var staged_total: usize = 0;
        for (source_crypto, 0..) |stream, i| {
            staged_total = try addSnapshotStaged(staged_total, stream.staged.items.len);
            crypto[i] = try captureByteWindow(allocator, stream.read_offset, stream.cap, stream.staged.items, stream.filled.items, snapshot_max_crypto_cap);
        }

        if (self.streams.count() > snapshot_max_streams) return error.SnapshotTooLarge;
        const ids = try allocator.alloc(u64, self.streams.count());
        defer allocator.free(ids);
        var iter = self.streams.iterator();
        var id_count: usize = 0;
        while (iter.next()) |entry| {
            ids[id_count] = entry.key_ptr.*;
            id_count += 1;
        }
        std.mem.sort(u64, ids, {}, std.sort.asc(u64));

        const streams = try allocator.alloc(StreamSnapshot, ids.len);
        var captured_streams: usize = 0;
        errdefer {
            for (streams[0..captured_streams]) |*stream| stream.deinit(allocator);
            allocator.free(streams);
        }
        for (ids, 0..) |id, i| {
            const source = self.streams.get(id) orelse return error.InvalidSnapshot;
            if (source.id.raw != id) return error.InvalidSnapshot;
            staged_total = try addSnapshotStaged(staged_total, source.staged.items.len);
            streams[i] = .{
                .id = id,
                .window = try captureByteWindow(allocator, source.read_offset, source.cap, source.staged.items, source.filled.items, snapshot_max_stream_cap),
                .flow = source.flow,
                .final_size = source.final_size,
                .fin_consumed = source.fin_consumed,
            };
            captured_streams += 1;
        }

        const snapshot: EngineSnapshot = .{
            .config = self.config,
            .local = self.local,
            .spaces = .{ spaces[0].?, spaces[1].?, spaces[2].? },
            .crypto = .{ crypto[0].?, crypto[1].?, crypto[2].? },
            .streams = streams,
            .conn_flow = self.conn_flow,
            .conn_received_total = self.conn_received_total,
        };
        try snapshot.validate();
        return snapshot;
    }

    /// Build an independent engine before publication. Validation and any
    /// allocation failure leave the caller's engine untouched.
    pub fn restoreSnapshot(allocator: Allocator, snapshot: *const EngineSnapshot) SnapshotError!Engine {
        try snapshot.validate();
        var restored = Engine.init(allocator, snapshot.local, snapshot.config);
        errdefer restored.deinit();
        for (snapshot.spaces, 0..) |part, i| {
            const space_ptr = restored.space(snapshotLevel(i));
            space_ptr.next_outbound = part.next_outbound;
            space_ptr.largest_acked = part.largest_acked;
            space_ptr.ack_eliciting_pending = part.ack_eliciting_pending;
            space_ptr.largest_received = part.largest_received;
            space_ptr.received.max_ranges = part.received.max_ranges;
            try space_ptr.received.ranges.appendSlice(allocator, part.received.ranges);
            const acked = restored.ackedSet(snapshotLevel(i));
            acked.max_ranges = part.acked.max_ranges;
            try acked.ranges.appendSlice(allocator, part.acked.ranges);
        }
        for (snapshot.crypto, 0..) |part, i| {
            const stream = restored.cryptoStream(snapshotLevel(i));
            stream.read_offset = part.read_offset;
            stream.cap = part.cap;
            try stream.staged.appendSlice(allocator, part.staged);
            try stream.filled.appendSlice(allocator, part.filled);
        }
        for (snapshot.streams) |part| {
            {
                const stream = try allocator.create(StreamRecv);
                stream.* = StreamRecv.init(StreamId.init(part.id), part.flow.limit, part.window.cap);
                errdefer {
                    stream.deinit(allocator);
                    allocator.destroy(stream);
                }
                stream.read_offset = part.window.read_offset;
                stream.flow = part.flow;
                stream.final_size = part.final_size;
                stream.fin_consumed = part.fin_consumed;
                try stream.staged.appendSlice(allocator, part.window.staged);
                try stream.filled.appendSlice(allocator, part.window.filled);
                try restored.streams.put(part.id, stream);
            }
        }
        restored.conn_flow = snapshot.conn_flow;
        restored.conn_received_total = snapshot.conn_received_total;
        return restored;
    }

    /// Replace only after external stream pointers and packet views are
    /// quiesced; they become invalid when the old engine is deinitialized.
    pub fn replaceFromSnapshot(self: *Engine, snapshot: *const EngineSnapshot) SnapshotError!void {
        const replacement = try restoreSnapshot(self.allocator, snapshot);
        var prior = self.*;
        self.* = replacement;
        prior.deinit();
    }
};

/// Snapshot bounds are independent of caller-provided Config values. An
/// oversized live engine fails capture; restore never allocates past these caps.
pub const snapshot_max_ack_ranges: usize = default_max_ack_ranges;
pub const snapshot_max_crypto_cap: usize = default_crypto_buffer_cap;
pub const snapshot_max_stream_cap: usize = default_stream_buffer_cap;
pub const snapshot_max_streams: usize = 4096;
pub const snapshot_max_staged_bytes: usize = 64 * 1024 * 1024;
pub const SnapshotError = error{ InvalidSnapshot, SnapshotTooLarge } || Allocator.Error;

pub const RangeSetSnapshot = struct {
    max_ranges: usize,
    ranges: []Range,

    pub fn deinit(self: *RangeSetSnapshot, allocator: Allocator) void {
        allocator.free(self.ranges);
        self.* = undefined;
    }

    fn max(self: *const RangeSetSnapshot) ?u64 {
        return if (self.ranges.len == 0) null else self.ranges[self.ranges.len - 1].end;
    }

    fn validate(self: *const RangeSetSnapshot) SnapshotError!void {
        if (self.max_ranges == 0 or self.max_ranges > snapshot_max_ack_ranges or
            self.ranges.len > self.max_ranges) return error.InvalidSnapshot;
        var prior_end: ?u64 = null;
        for (self.ranges) |range| {
            if (range.start > range.end or range.end > max_varint) return error.InvalidSnapshot;
            if (prior_end) |end| {
                if (end + 1 >= range.start) return error.InvalidSnapshot;
            }
            prior_end = range.end;
        }
    }
};

pub const SpaceSnapshot = struct {
    next_outbound: u64,
    received: RangeSetSnapshot,
    largest_acked: ?u64,
    ack_eliciting_pending: bool,
    largest_received: ?u64,
    acked: RangeSetSnapshot,

    pub fn deinit(self: *SpaceSnapshot, allocator: Allocator) void {
        self.received.deinit(allocator);
        self.acked.deinit(allocator);
        self.* = undefined;
    }

    fn validate(self: *const SpaceSnapshot) SnapshotError!void {
        try self.received.validate();
        try self.acked.validate();
        if (self.next_outbound > max_varint or
            self.largest_acked != self.acked.max() or
            (self.ack_eliciting_pending and self.largest_received == null))
            return error.InvalidSnapshot;
        if (self.received.max()) |retained_max| {
            if (self.largest_received == null or self.largest_received.? < retained_max or
                self.largest_received.? > max_varint) return error.InvalidSnapshot;
        } else if (self.largest_received != null) return error.InvalidSnapshot;
        if (self.largest_acked) |pn| {
            if (pn >= self.next_outbound) return error.InvalidSnapshot;
        }
    }
};

/// Staging holes are encoded as zero bytes. The bool slice is the source of
/// truth; no uninitialized bytes from ArrayList capacity reach the DTO.
pub const ByteWindowSnapshot = struct {
    read_offset: u64,
    cap: usize,
    staged: []u8,
    filled: []bool,

    pub fn deinit(self: *ByteWindowSnapshot, allocator: Allocator) void {
        allocator.free(self.staged);
        allocator.free(self.filled);
        self.* = undefined;
    }

    fn validate(self: *const ByteWindowSnapshot, max_cap: usize) SnapshotError!void {
        if (self.cap == 0 or self.cap > max_cap or self.staged.len != self.filled.len or
            self.staged.len > self.cap or self.read_offset > max_varint)
            return error.InvalidSnapshot;
        const end = std.math.add(u64, self.read_offset, self.staged.len) catch return error.InvalidSnapshot;
        if (end > max_varint) return error.InvalidSnapshot;
        for (self.staged, self.filled) |byte, filled| {
            if (!filled and byte != 0) return error.InvalidSnapshot;
        }
    }
};

pub const StreamSnapshot = struct {
    id: u64,
    window: ByteWindowSnapshot,
    flow: FlowController,
    final_size: ?u64,
    fin_consumed: bool,

    pub fn deinit(self: *StreamSnapshot, allocator: Allocator) void {
        self.window.deinit(allocator);
        self.* = undefined;
    }
};

/// Complete owned state of Engine. Stream entries are sorted by raw stream ID,
/// so a later field-wise wire codec has one canonical traversal order.
pub const EngineSnapshot = struct {
    config: Config,
    local: Initiator,
    spaces: [3]SpaceSnapshot,
    crypto: [3]ByteWindowSnapshot,
    streams: []StreamSnapshot,
    conn_flow: FlowController,
    conn_received_total: u64,

    pub fn deinit(self: *EngineSnapshot, allocator: Allocator) void {
        for (&self.spaces) |*part| part.deinit(allocator);
        for (&self.crypto) |*part| part.deinit(allocator);
        for (self.streams) |*stream| stream.deinit(allocator);
        allocator.free(self.streams);
        self.* = undefined;
    }

    pub fn validate(self: *const EngineSnapshot) SnapshotError!void {
        if (self.config.max_ack_ranges == 0 or self.config.max_ack_ranges > snapshot_max_ack_ranges or
            self.config.crypto_buffer_cap == 0 or self.config.crypto_buffer_cap > snapshot_max_crypto_cap or
            self.config.stream_buffer_cap == 0 or self.config.stream_buffer_cap > snapshot_max_stream_cap or
            self.config.max_streams > snapshot_max_streams or
            self.config.initial_max_data > max_varint or
            self.config.initial_max_stream_data > max_varint or
            self.streams.len > self.config.max_streams)
            return error.SnapshotTooLarge;
        if (self.conn_flow.limit < self.config.initial_max_data or
            self.conn_flow.limit > max_varint or
            self.conn_flow.received != self.conn_received_total or
            self.conn_received_total > self.conn_flow.limit)
            return error.InvalidSnapshot;

        var staged_total: usize = 0;
        for (&self.spaces) |*part| {
            try part.validate();
            if (part.received.max_ranges != self.config.max_ack_ranges or
                part.acked.max_ranges != self.config.max_ack_ranges) return error.InvalidSnapshot;
        }
        for (&self.crypto) |*part| {
            try part.validate(snapshot_max_crypto_cap);
            if (part.cap != self.config.crypto_buffer_cap) return error.InvalidSnapshot;
            staged_total = try addSnapshotStaged(staged_total, part.staged.len);
        }

        var previous_id: ?u64 = null;
        var received_sum: u64 = 0;
        for (self.streams) |*stream| {
            if (stream.id > max_varint) return error.InvalidSnapshot;
            if (previous_id) |id| {
                if (stream.id <= id) return error.InvalidSnapshot;
            }
            previous_id = stream.id;
            const sid = StreamId.init(stream.id);
            if (sid.isUnidirectional() and !sid.peerInitiated(self.local)) return error.InvalidSnapshot;
            try stream.window.validate(snapshot_max_stream_cap);
            if (stream.window.cap != self.config.stream_buffer_cap) return error.InvalidSnapshot;
            staged_total = try addSnapshotStaged(staged_total, stream.window.staged.len);
            if (stream.flow.limit < self.config.initial_max_stream_data or
                stream.flow.limit > max_varint or stream.flow.received > stream.flow.limit or
                stream.window.read_offset > stream.flow.received or
                stream.window.staged.len > stream.flow.received - stream.window.read_offset)
                return error.InvalidSnapshot;
            if (stream.final_size) |size| {
                if (size != stream.flow.received or size < stream.window.read_offset)
                    return error.InvalidSnapshot;
            }
            if (stream.fin_consumed and (stream.final_size == null or
                stream.window.read_offset != stream.final_size.?)) return error.InvalidSnapshot;
            received_sum = std.math.add(u64, received_sum, stream.flow.received) catch return error.InvalidSnapshot;
        }
        if (received_sum != self.conn_received_total) return error.InvalidSnapshot;
    }
};

fn snapshotLevel(i: usize) EncryptionLevel {
    return switch (i) {
        0 => .initial,
        1 => .handshake,
        2 => .application,
        else => unreachable,
    };
}

fn addSnapshotStaged(current: usize, added: usize) SnapshotError!usize {
    const total = std.math.add(usize, current, added) catch return error.SnapshotTooLarge;
    if (total > snapshot_max_staged_bytes) return error.SnapshotTooLarge;
    return total;
}

fn captureRangeSet(allocator: Allocator, source: *const RangeSet) SnapshotError!RangeSetSnapshot {
    if (source.ranges.items.len > snapshot_max_ack_ranges) return error.SnapshotTooLarge;
    return .{ .max_ranges = source.max_ranges, .ranges = try allocator.dupe(Range, source.ranges.items) };
}

fn captureSpaceSnapshot(allocator: Allocator, source: *const PacketNumberSpace, acked: *const RangeSet) SnapshotError!SpaceSnapshot {
    var received = try captureRangeSet(allocator, &source.received);
    errdefer received.deinit(allocator);
    const acked_snapshot = try captureRangeSet(allocator, acked);
    return .{
        .next_outbound = source.next_outbound,
        .received = received,
        .largest_acked = source.largest_acked,
        .ack_eliciting_pending = source.ack_eliciting_pending,
        .largest_received = source.largest_received,
        .acked = acked_snapshot,
    };
}

fn captureByteWindow(
    allocator: Allocator,
    read_offset: u64,
    cap: usize,
    staged: []const u8,
    filled: []const bool,
    max_cap: usize,
) SnapshotError!ByteWindowSnapshot {
    if (staged.len != filled.len) return error.InvalidSnapshot;
    if (staged.len > max_cap) return error.SnapshotTooLarge;
    const bytes = try allocator.alloc(u8, staged.len);
    errdefer allocator.free(bytes);
    const flags = try allocator.dupe(bool, filled);
    for (filled, 0..) |is_filled, i| {
        bytes[i] = if (is_filled) staged[i] else 0;
    }
    return .{ .read_offset = read_offset, .cap = cap, .staged = bytes, .filled = flags };
}

// ===========================================================================
// Tests (RFC 9000 §12.3 / §13 / §19.3 / §19.6 / §19.8)
// ===========================================================================

const testing = std.testing;

test "quic stream id classification — initiator and directionality bits" {
    // RFC 9000 §2.1 Table 1:
    //   0x0 client bidi, 0x1 server bidi, 0x2 client uni, 0x3 server uni.
    const c_bidi = StreamId.init(0x0);
    try testing.expect(c_bidi.isClientInitiated());
    try testing.expect(c_bidi.isBidirectional());
    try testing.expectEqual(@as(u64, 0), c_bidi.ordinal());

    const s_bidi = StreamId.init(0x1);
    try testing.expect(s_bidi.isServerInitiated());
    try testing.expect(s_bidi.isBidirectional());

    const c_uni = StreamId.init(0x2);
    try testing.expect(c_uni.isClientInitiated());
    try testing.expect(c_uni.isUnidirectional());

    const s_uni = StreamId.init(0x3);
    try testing.expect(s_uni.isServerInitiated());
    try testing.expect(s_uni.isUnidirectional());

    // Ordinal is the id >> 2.
    try testing.expectEqual(@as(u64, 5), StreamId.init(0x14).ordinal()); // 20 >> 2
    // peerInitiated: from the server's view, client streams are peer-initiated.
    try testing.expect(c_bidi.peerInitiated(.server));
    try testing.expect(!s_bidi.peerInitiated(.server));
}

test "quic packet-number spaces are independent and largest_acked monotonic" {
    const allocator = testing.allocator;
    var spaces = SpaceSet.init(default_max_ack_ranges);
    defer spaces.deinit(allocator);

    // next_outbound advances independently per space.
    try testing.expectEqual(@as(u64, 0), spaces.initial.nextPacketNumber());
    try testing.expectEqual(@as(u64, 1), spaces.initial.nextPacketNumber());
    try testing.expectEqual(@as(u64, 0), spaces.handshake.nextPacketNumber());
    try testing.expectEqual(@as(u64, 0), spaces.application.nextPacketNumber());
    try testing.expectEqual(@as(u64, 1), spaces.handshake.nextPacketNumber());
    try testing.expectEqual(@as(u64, 2), spaces.initial.nextPacketNumber());

    // largest_acked is monotonic: a stale ACK never lowers it.
    var acked = RangeSet.init(default_max_ack_ranges);
    defer acked.deinit(allocator);
    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);

    _ = spaces.handshake.nextPacketNumber(); // ensure next_outbound >= 6 (we have 0,1,then 6 more)
    while (spaces.handshake.next_outbound < 10) _ = spaces.handshake.nextPacketNumber();

    try spaces.handshake.processAck(.{ .largest = 5, .first_range = 0 }, &acked, allocator, &newly, allocator);
    try testing.expectEqual(@as(?u64, 5), spaces.handshake.largest_acked);
    // A lower largest does not regress largest_acked.
    try spaces.handshake.processAck(.{ .largest = 3, .first_range = 0 }, &acked, allocator, &newly, allocator);
    try testing.expectEqual(@as(?u64, 5), spaces.handshake.largest_acked);
}

test "ack generation — received {0,1,2,5,6,9} yields largest=9 ranges [9],[5..6],[0..2]" {
    const allocator = testing.allocator;
    var sp = PacketNumberSpace.init(.application, default_max_ack_ranges);
    defer sp.deinit(allocator);

    // Receive out of order to also exercise coalescing.
    for ([_]u64{ 2, 0, 9, 6, 1, 5 }) |pn| {
        try sp.recordReceived(allocator, pn, true);
    }
    try testing.expect(sp.ackPending());

    var built = (try sp.buildAck(allocator, 0)).?;
    defer built.deinit(allocator);

    // largest = 9, top range is the singleton [9,9] → first_range = 0.
    try testing.expectEqual(@as(u64, 9), built.frame.largest);
    try testing.expectEqual(@as(u64, 0), built.frame.first_range);
    // Two more ranges: [5..6] then [0..2].
    //   gap from 9 down to 6: prev_smallest=9, r.end=6 → gap = 9-6-2 = 1; len = 6-5 = 1.
    //   gap from 5 down to 2: prev_smallest=5, r.end=2 → gap = 5-2-2 = 1; len = 2-0 = 2.
    try testing.expectEqual(@as(usize, 2), built.frame.ranges.len);
    try testing.expectEqual(AckRange{ .gap = 1, .len = 1 }, built.frame.ranges[0]);
    try testing.expectEqual(AckRange{ .gap = 1, .len = 2 }, built.frame.ranges[1]);

    // Round-trip the built ACK through the quic_frame codec.
    const encoded = try quic_frame.encodeFrames(allocator, &.{.{ .ACK = built.frame }});
    defer allocator.free(encoded);
    const decoded = try quic_frame.decodeFrameExact(allocator, encoded);
    defer quic_frame.freeFrame(allocator, decoded);
    try testing.expectEqual(@as(u64, 9), decoded.ACK.largest);
    try testing.expectEqual(@as(u64, 0), decoded.ACK.first_range);
    try testing.expectEqual(@as(usize, 2), decoded.ACK.ranges.len);
    try testing.expectEqual(AckRange{ .gap = 1, .len = 1 }, decoded.ACK.ranges[0]);
    try testing.expectEqual(AckRange{ .gap = 1, .len = 2 }, decoded.ACK.ranges[1]);
}

test "ack generation — single contiguous run collapses to one range" {
    const allocator = testing.allocator;
    var sp = PacketNumberSpace.init(.initial, default_max_ack_ranges);
    defer sp.deinit(allocator);
    for ([_]u64{ 0, 1, 2, 3, 4 }) |pn| try sp.recordReceived(allocator, pn, true);

    var built = (try sp.buildAck(allocator, 7)).?;
    defer built.deinit(allocator);
    try testing.expectEqual(@as(u64, 4), built.frame.largest);
    try testing.expectEqual(@as(u64, 4), built.frame.first_range); // [0..4]
    try testing.expectEqual(@as(u64, 7), built.frame.delay);
    try testing.expectEqual(@as(usize, 0), built.frame.ranges.len);
}

test "ack processing — newly acked is reported once, duplicates yield none" {
    const allocator = testing.allocator;
    var sp = PacketNumberSpace.init(.application, default_max_ack_ranges);
    defer sp.deinit(allocator);
    // We sent outbound packets 0..10.
    while (sp.next_outbound <= 10) _ = sp.nextPacketNumber();
    try testing.expectEqual(@as(u64, 11), sp.next_outbound);

    var acked = RangeSet.init(default_max_ack_ranges);
    defer acked.deinit(allocator);
    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);

    // Inbound ACK acking [3..7]: largest=7, first_range=4 → [3,7].
    try sp.processAck(.{ .largest = 7, .first_range = 4 }, &acked, allocator, &newly, allocator);
    try testing.expectEqualSlices(u64, &.{ 3, 4, 5, 6, 7 }, newly.items);

    // A second identical ACK yields nothing new.
    newly.clearRetainingCapacity();
    try sp.processAck(.{ .largest = 7, .first_range = 4 }, &acked, allocator, &newly, allocator);
    try testing.expectEqual(@as(usize, 0), newly.items.len);
}

test "ack processing — multi-range ack and malformed-range rejection" {
    const allocator = testing.allocator;
    var sp = PacketNumberSpace.init(.application, default_max_ack_ranges);
    defer sp.deinit(allocator);
    while (sp.next_outbound <= 12) _ = sp.nextPacketNumber();

    var acked = RangeSet.init(default_max_ack_ranges);
    defer acked.deinit(allocator);
    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);

    // Re-acknowledge the {0,1,2,5,6,9} pattern we generated above:
    //   largest=9 first_range=0  ranges=[{gap=1,len=1},{gap=1,len=2}]
    // → acks 9, 5,6, 0,1,2.
    try sp.processAck(.{
        .largest = 9,
        .first_range = 0,
        .ranges = &.{ .{ .gap = 1, .len = 1 }, .{ .gap = 1, .len = 2 } },
    }, &acked, allocator, &newly, allocator);
    std.mem.sort(u64, newly.items, {}, std.sort.asc(u64));
    try testing.expectEqualSlices(u64, &.{ 0, 1, 2, 5, 6, 9 }, newly.items);

    // Malformed: largest beyond what we ever sent.
    try testing.expectError(error.MalformedAck, sp.processAck(
        .{ .largest = 99, .first_range = 0 },
        &acked,
        allocator,
        &newly,
        allocator,
    ));
    // Malformed: a gap that underflows below packet 0.
    try testing.expectError(error.MalformedAck, sp.processAck(
        .{ .largest = 1, .first_range = 0, .ranges = &.{.{ .gap = 5, .len = 0 }} },
        &acked,
        allocator,
        &newly,
        allocator,
    ));
}

test "crypto reassembly — gap fills before bytes emerge; overlap and dup tolerated" {
    const allocator = testing.allocator;
    var cs = CryptoStream.init(default_crypto_buffer_cap);
    defer cs.deinit(allocator);

    // Frame at offset 5 first: nothing contiguous yet from offset 0.
    try cs.receive(allocator, 5, "world");
    try testing.expectEqual(@as(usize, 0), cs.readable());

    // Frame at offset 0 fills the gap: now [0..10) is contiguous.
    try cs.receive(allocator, 0, "hello");
    try testing.expectEqual(@as(usize, 10), cs.readable());
    try testing.expectEqualSlices(u8, "helloworld", cs.peek());

    // Duplicate + overlapping frame is idempotent.
    try cs.receive(allocator, 3, "lowor");
    try testing.expectEqual(@as(usize, 10), cs.readable());
    try testing.expectEqualSlices(u8, "helloworld", cs.peek());

    // Consume part, then more arrives appended in order.
    try testing.expectEqual(@as(usize, 6), cs.consume(6)); // drop "hellow"
    try testing.expectEqual(@as(u64, 6), cs.read_offset);
    try testing.expectEqualSlices(u8, "orld", cs.peek());
    try cs.receive(allocator, 10, "!!");
    try testing.expectEqualSlices(u8, "orld!!", cs.peek());

    // Data wholly below read_offset is ignored.
    try cs.receive(allocator, 0, "hello");
    try testing.expectEqual(@as(u64, 6), cs.read_offset);
    try testing.expectEqualSlices(u8, "orld!!", cs.peek());
}

test "crypto reassembly — exceeding the buffer cap errors" {
    const allocator = testing.allocator;
    var cs = CryptoStream.init(16); // tiny cap
    defer cs.deinit(allocator);

    // A frame ending within the cap is fine.
    try cs.receive(allocator, 0, "0123456789abcdef"); // exactly 16
    try testing.expectEqual(@as(usize, 16), cs.readable());

    // Once consumed, the window slides; offsets relative to read_offset matter.
    try testing.expectEqual(@as(usize, 16), cs.consume(16));
    // A frame whose end is more than cap past read_offset is rejected.
    try testing.expectError(error.BufferExceeded, cs.receive(allocator, 100, "x")); // rel 84 > 16
    // OffsetTooLarge for varint overflow.
    try testing.expectError(error.OffsetTooLarge, cs.receive(allocator, max_varint, "x"));
}

test "crypto send buffer — fragments handshake bytes within a max payload" {
    const allocator = testing.allocator;
    var sb = CryptoSendBuffer.init();
    defer sb.deinit(allocator);

    try sb.write(allocator, "ABCDEFGHIJ"); // 10 bytes
    try testing.expectEqual(@as(u64, 10), sb.pending());

    const f0 = sb.nextFrame(4).?;
    try testing.expectEqual(@as(u64, 0), f0.offset);
    try testing.expectEqualSlices(u8, "ABCD", f0.data);
    const f1 = sb.nextFrame(4).?;
    try testing.expectEqual(@as(u64, 4), f1.offset);
    try testing.expectEqualSlices(u8, "EFGH", f1.data);
    const f2 = sb.nextFrame(4).?;
    try testing.expectEqual(@as(u64, 8), f2.offset);
    try testing.expectEqualSlices(u8, "IJ", f2.data);
    try testing.expect(sb.nextFrame(4) == null);

    // A late write continues the offset sequence.
    try sb.write(allocator, "KL");
    const f3 = sb.nextFrame(8).?;
    try testing.expectEqual(@as(u64, 10), f3.offset);
    try testing.expectEqualSlices(u8, "KL", f3.data);

    // The produced frame round-trips through quic_frame.
    const encoded = try quic_frame.encodeFrames(allocator, &.{.{ .CRYPTO = f3 }});
    defer allocator.free(encoded);
    const decoded = try quic_frame.decodeFrameExact(allocator, encoded);
    defer quic_frame.freeFrame(allocator, decoded);
    try testing.expectEqual(@as(u64, 10), decoded.CRYPTO.offset);
    try testing.expectEqualSlices(u8, "KL", decoded.CRYPTO.data);
}

test "stream reassembly — out of order plus fin; read stops at the gap" {
    const allocator = testing.allocator;
    var sr = StreamRecv.init(StreamId.init(0x0), 1024, default_stream_buffer_cap);
    defer sr.deinit(allocator);

    // Out-of-order: deliver [4..9) "wxyz?" with fin first... actually deliver the
    // tail with fin, then the head. Reading must stop at the gap until filled.
    try sr.receive(allocator, 5, true, "world"); // offsets 5..10, fin → final size 10
    try testing.expectEqual(@as(usize, 0), sr.readable()); // gap [0..5)
    try testing.expect(!sr.finReached());

    try sr.receive(allocator, 0, false, "hello"); // fills [0..5)
    try testing.expectEqual(@as(usize, 10), sr.readable());
    try testing.expectEqualSlices(u8, "helloworld", sr.peek());

    // Consuming all bytes reaches the fin (final size 10).
    try testing.expectEqual(@as(usize, 10), sr.consume(10));
    try testing.expect(sr.finReached());
}

test "stream reassembly — final size violations are rejected" {
    const allocator = testing.allocator;
    var sr = StreamRecv.init(StreamId.init(0x4), 1024, default_stream_buffer_cap);
    defer sr.deinit(allocator);

    try sr.receive(allocator, 0, true, "abcd"); // final size = 4
    // Data past the established final size → FinalSizeError.
    try testing.expectError(error.FinalSizeError, sr.receive(allocator, 4, false, "e"));
    // A second fin at a different size → FinalSizeError.
    try testing.expectError(error.FinalSizeError, sr.receive(allocator, 0, true, "abcde"));
    // Re-confirming the same final size is allowed (idempotent retransmit).
    try sr.receive(allocator, 0, true, "abcd");
}

test "stream flow control — data beyond MAX_STREAM_DATA is a flow-control error" {
    const allocator = testing.allocator;
    var sr = StreamRecv.init(StreamId.init(0x0), 8, default_stream_buffer_cap); // limit 8
    defer sr.deinit(allocator);

    try sr.receive(allocator, 0, false, "01234567"); // ends at 8, exactly the limit
    try testing.expectEqual(@as(u64, 8), sr.flow.received);
    // One more byte past the limit → FlowControl.
    try testing.expectError(error.FlowControl, sr.receive(allocator, 8, false, "8"));
    // Raising the limit then admits it.
    sr.flow.setLimit(16);
    try sr.receive(allocator, 8, false, "8");
    try testing.expectEqual(@as(u64, 9), sr.flow.received);
}

test "engine intake — crypto + ping + ack in one packet, ack obligation tracked" {
    const allocator = testing.allocator;
    var eng = Engine.init(allocator, .server, .{});
    defer eng.deinit();

    // Pretend we sent outbound application packets 0..3 so an inbound ACK is valid.
    while (eng.space(.application).next_outbound <= 3) _ = eng.space(.application).nextPacketNumber();

    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);

    const frames = [_]Frame{
        .{ .PADDING = {} },
        .{ .PING = {} },
        .{ .CRYPTO = .{ .offset = 0, .len = 5, .data = "hello" } },
        .{ .ACK = .{ .largest = 2, .first_range = 1 } }, // acks 1,2
    };
    const r = try eng.intake(.application, 0, &frames, &newly);

    try testing.expect(r.ack_eliciting); // PING + CRYPTO are ack-eliciting
    try testing.expectEqual(@as(usize, 1), r.ping_count);
    try testing.expectEqual(@as(usize, 5), r.crypto_readable);
    try testing.expectEqual(@as(?u64, null), r.connection_close);
    try testing.expectEqual(@as(usize, 2), r.newly_acked_count);
    try testing.expectEqualSlices(u8, "hello", eng.cryptoStream(.application).peek());
    try testing.expect(eng.space(.application).ackPending());

    // PADDING/ACK-only packet does not set ack-pending.
    var sp_hs = eng.space(.handshake);
    const only_ack = [_]Frame{.{ .PADDING = {} }};
    const r2 = try eng.intake(.handshake, 0, &only_ack, &newly);
    try testing.expect(!r2.ack_eliciting);
    try testing.expect(!sp_hs.ackPending());
}

test "engine intake — stream frame feeds per-stream reassembly and conn flow control" {
    const allocator = testing.allocator;
    var eng = Engine.init(allocator, .server, .{ .initial_max_data = 16, .initial_max_stream_data = 16 });
    defer eng.deinit();

    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);

    // Client-initiated bidi stream 0, out of order.
    const f_tail = [_]Frame{.{ .STREAM = .{ .stream_id = 0, .offset = 5, .fin = true, .len = 5, .data = "world" } }};
    _ = try eng.intake(.application, 0, &f_tail, &newly);
    const s0 = eng.getStream(0).?;
    try testing.expectEqual(@as(usize, 0), s0.readable()); // gap

    const f_head = [_]Frame{.{ .STREAM = .{ .stream_id = 0, .offset = 0, .fin = false, .len = 5, .data = "hello" } }};
    _ = try eng.intake(.application, 1, &f_head, &newly);
    try testing.expectEqual(@as(usize, 10), s0.readable());
    try testing.expectEqualSlices(u8, "helloworld", s0.peek());
    try testing.expectEqual(@as(u64, 10), eng.conn_received_total);

    // A second stream pushing total past MAX_DATA(16) → connection FlowControl.
    const f_big = [_]Frame{.{ .STREAM = .{ .stream_id = 4, .offset = 0, .fin = false, .len = 10, .data = "0123456789" } }};
    try testing.expectError(error.FlowControl, eng.intake(.application, 2, &f_big, &newly));
}

test "engine intake — connection close is surfaced and not ack-eliciting" {
    const allocator = testing.allocator;
    var eng = Engine.init(allocator, .client, .{});
    defer eng.deinit();
    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);

    const frames = [_]Frame{.{ .CONNECTION_CLOSE = .{ .error_code = 0x0a, .reason_len = 3, .reason = "bye" } }};
    const r = try eng.intake(.application, 0, &frames, &newly);
    try testing.expectEqual(@as(?u64, 0x0a), r.connection_close);
    try testing.expect(!r.ack_eliciting); // CONNECTION_CLOSE alone is not ack-eliciting
}

test "range set coalesces and tolerates duplicates" {
    const allocator = testing.allocator;
    var rs = RangeSet.init(default_max_ack_ranges);
    defer rs.deinit(allocator);

    try rs.insert(allocator, 5);
    try rs.insert(allocator, 7);
    try rs.insert(allocator, 6); // bridges 5..7
    try testing.expectEqual(@as(usize, 1), rs.count());
    try testing.expect(rs.contains(5) and rs.contains(6) and rs.contains(7));
    try testing.expect(!rs.contains(4) and !rs.contains(8));
    try rs.insert(allocator, 6); // dup, no-op
    try testing.expectEqual(@as(usize, 1), rs.count());
    try rs.insert(allocator, 1);
    try rs.insert(allocator, 3);
    try testing.expectEqual(@as(usize, 3), rs.count()); // {1},{3},{5..7}
    try testing.expectEqual(@as(?u64, 7), rs.max());
    try rs.insert(allocator, 2); // bridges 1..3
    try testing.expectEqual(@as(usize, 2), rs.count()); // {1..3},{5..7}
}

fn engineSnapshotFixture(allocator: Allocator) !Engine {
    var engine = Engine.init(allocator, .server, .{
        .max_ack_ranges = 8,
        .crypto_buffer_cap = 64,
        .stream_buffer_cap = 64,
        .initial_max_data = 100,
        .initial_max_stream_data = 64,
        .max_streams = 4,
    });
    errdefer engine.deinit();
    _ = engine.space(.initial).nextPacketNumber();
    for (0..4) |_| _ = engine.space(.application).nextPacketNumber();

    var newly: std.ArrayList(u64) = .empty;
    defer newly.deinit(allocator);
    _ = try engine.intake(.initial, 5, &.{.{ .CRYPTO = .{ .offset = 4, .len = 2, .data = "ef" } }}, &newly);
    _ = try engine.intake(.initial, 2, &.{.{ .PING = {} }}, &newly);
    _ = try engine.intake(.application, 7, &.{.{ .STREAM = .{ .stream_id = 4, .offset = 5, .fin = true, .len = 5, .data = "world" } }}, &newly);
    _ = try engine.intake(.application, 1, &.{.{ .STREAM = .{ .stream_id = 0, .offset = 0, .fin = false, .len = 2, .data = "hi" } }}, &newly);
    _ = try engine.intake(.application, 3, &.{.{ .ACK = .{ .largest = 2, .first_range = 1 } }}, &newly);
    _ = engine.getStream(0).?.consume(1);
    engine.getStream(0).?.flow.setLimit(80);
    engine.setMaxData(120);
    return engine;
}

test "Engine snapshot roundtrips ACK, CRYPTO gaps, sorted streams and flow state" {
    const allocator = testing.allocator;
    var source = try engineSnapshotFixture(allocator);
    defer source.deinit();
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);
    try snapshot.validate();
    try testing.expectEqualSlices(u64, &.{ 0, 4 }, &.{ snapshot.streams[0].id, snapshot.streams[1].id });
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 'e', 'f' }, snapshot.crypto[0].staged);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 'w', 'o', 'r', 'l', 'd' }, snapshot.streams[1].window.staged);

    var restored = try Engine.restoreSnapshot(allocator, &snapshot);
    defer restored.deinit();
    var recaptured = try restored.captureSnapshot(allocator);
    defer recaptured.deinit(allocator);
    try testing.expectEqualDeep(snapshot, recaptured);

    var source_ack = (try source.space(.initial).buildAck(allocator, 7)).?;
    defer source_ack.deinit(allocator);
    var restored_ack = (try restored.space(.initial).buildAck(allocator, 7)).?;
    defer restored_ack.deinit(allocator);
    try testing.expectEqualDeep(source_ack.frame, restored_ack.frame);

    try source.cryptoStream(.initial).receive(allocator, 0, "abcd");
    try restored.cryptoStream(.initial).receive(allocator, 0, "abcd");
    try testing.expectEqualSlices(u8, source.cryptoStream(.initial).peek(), restored.cryptoStream(.initial).peek());
    var source_newly: std.ArrayList(u64) = .empty;
    defer source_newly.deinit(allocator);
    var restored_newly: std.ArrayList(u64) = .empty;
    defer restored_newly.deinit(allocator);
    const head = &[_]Frame{.{ .STREAM = .{ .stream_id = 4, .offset = 0, .fin = false, .len = 5, .data = "hello" } }};
    _ = try source.intake(.application, 8, head, &source_newly);
    _ = try restored.intake(.application, 8, head, &restored_newly);
    try testing.expectEqualSlices(u8, source.getStream(4).?.peek(), restored.getStream(4).?.peek());
    try testing.expectEqual(source.conn_received_total, restored.conn_received_total);
}

test "Engine snapshot rejects malformed joins and noncanonical staging" {
    const allocator = testing.allocator;
    var source = try engineSnapshotFixture(allocator);
    defer source.deinit();
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);

    snapshot.streams[1].id = snapshot.streams[0].id;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.streams[1].id = 4;

    snapshot.crypto[0].staged[0] = 1;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.crypto[0].staged[0] = 0;

    snapshot.conn_received_total += 1;
    var target = Engine.init(allocator, .client, .{});
    defer target.deinit();
    try testing.expectError(error.InvalidSnapshot, target.replaceFromSnapshot(&snapshot));
    try testing.expectEqual(@as(usize, 0), target.streams.count());
    try testing.expectEqual(Initiator.client, target.local);
    snapshot.conn_received_total -= 1;

    const original_start = snapshot.spaces[0].received.ranges[1].start;
    snapshot.spaces[0].received.ranges[1].start = snapshot.spaces[0].received.ranges[0].end + 1;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.spaces[0].received.ranges[1].start = original_start;

    snapshot.streams[1].final_size = 9;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.streams[1].final_size = 10;

    snapshot.crypto[0].cap += 1;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.crypto[0].cap -= 1;
    snapshot.streams[1].window.cap += 1;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.streams[1].window.cap -= 1;
    snapshot.spaces[0].received.max_ranges += 1;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.spaces[0].received.max_ranges -= 1;
    try snapshot.validate();
}

test "Engine snapshot preserves high received PN cache after capped range eviction" {
    const allocator = testing.allocator;
    var source = Engine.init(allocator, .server, .{ .max_ack_ranges = 1 });
    defer source.deinit();
    try source.space(.application).recordReceived(allocator, 10, true);
    try source.space(.application).recordReceived(allocator, 0, true);
    try testing.expectEqual(@as(?u64, 10), source.space(.application).largest_received);
    try testing.expectEqual(@as(?u64, 0), source.space(.application).received.max());
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);
    var restored = try Engine.restoreSnapshot(allocator, &snapshot);
    defer restored.deinit();
    try testing.expectEqual(@as(?u64, 10), restored.space(.application).largest_received);
    try testing.expectEqual(@as(?u64, 0), restored.space(.application).received.max());
}

test "Engine snapshot final-size invariant rejects FIN below received data" {
    const allocator = testing.allocator;
    var stream = StreamRecv.init(StreamId.init(0), 64, 64);
    defer stream.deinit(allocator);
    try stream.receive(allocator, 0, false, "abcdefghij");
    try testing.expectError(error.FinalSizeError, stream.receive(allocator, 5, true, ""));
    try testing.expectEqual(@as(?u64, null), stream.final_size);
    try testing.expectEqual(@as(u64, 10), stream.flow.received);
}

test "Engine snapshot capture and replacement are allocation-failure atomic" {
    const allocator = testing.allocator;
    var source = try engineSnapshotFixture(allocator);
    defer source.deinit();
    var snapshot = try source.captureSnapshot(allocator);
    defer snapshot.deinit(allocator);

    const CaptureSweep = struct {
        fn run(failing: Allocator, original: *const Engine) !void {
            var captured = original.captureSnapshot(failing) catch |err| {
                try testing.expectEqual(@as(usize, 2), original.streams.count());
                return err;
            };
            captured.deinit(failing);
        }
    };
    try testing.checkAllAllocationFailures(allocator, CaptureSweep.run, .{&source});

    const RestoreSweep = struct {
        fn run(failing: Allocator, saved: *const EngineSnapshot) !void {
            var target = Engine.init(failing, .client, .{});
            defer target.deinit();
            target.replaceFromSnapshot(saved) catch |err| {
                try testing.expectEqual(@as(usize, 0), target.streams.count());
                try testing.expectEqual(Initiator.client, target.local);
                return err;
            };
            try testing.expectEqual(@as(usize, 2), target.streams.count());
            try testing.expectEqual(Initiator.server, target.local);
        }
    };
    try testing.checkAllAllocationFailures(allocator, RestoreSweep.run, .{&snapshot});
}

test "Engine snapshot rejects oversized live configuration" {
    const allocator = testing.allocator;
    var source = Engine.init(allocator, .server, .{ .stream_buffer_cap = snapshot_max_stream_cap + 1 });
    defer source.deinit();
    try testing.expectError(error.SnapshotTooLarge, source.captureSnapshot(allocator));
}
