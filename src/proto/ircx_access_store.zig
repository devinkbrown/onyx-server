// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX per-channel ACCESS parsing, storage, matching, and reply builders.
//!
//! This complements `ircx_saccess.zig`: SACCESS handles server-level entries,
//! while this module owns channel-scoped ACCESS entries with setter metadata.
const std = @import("std");
const listx = @import("listx.zig");
const limits_config = @import("limits_config.zig");

pub const RPL_ACCESSADD: u16 = 801;
pub const RPL_ACCESSDELETE: u16 = 802;
pub const RPL_ACCESSSTART: u16 = 803;
pub const RPL_ACCESSENTRY: u16 = 804;
pub const RPL_ACCESSEND: u16 = 805;

pub const DEFAULT_MAX_ENTRIES: usize = 256;
/// Retained delete markers. A tombstone must outlive the mesh re-broadcast
/// window of the ADD it retracts, or a relayed ADD resurrects a revoked grant
/// (see `applyRemote`). Bounded so a delete storm cannot grow memory without
/// limit; when full, the oldest (lowest HLC) marker is evicted first.
pub const DEFAULT_MAX_TOMBSTONES: usize = 256;
/// How long a delete marker is kept, in wall-clock seconds. Generous relative to
/// any realistic mesh convergence or anti-entropy repair cycle.
pub const DEFAULT_TOMBSTONE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// Default rows one `ACCESS ... LIST` page carries when the caller does not
/// impose its own smaller window.
pub const DEFAULT_PAGE_ROWS: usize = 64;
pub const DEFAULT_MAX_CHANNEL_BYTES: usize = 128;
pub const DEFAULT_MAX_MASK_BYTES: usize = 128;
pub const DEFAULT_MAX_SET_BY_BYTES: usize = 64;
pub const DEFAULT_MAX_REASON_BYTES: usize = 256;
pub const DEFAULT_MAX_LINE_BYTES: usize = 512;
pub const DEFAULT_MAX_SERVER_BYTES: usize = 255;
pub const DEFAULT_MAX_REQUESTER_BYTES: usize = 64;
pub const DEFAULT_MAX_DURATION_DIGITS: usize = 20;

pub const AccessError = error{
    MissingChannel,
    InvalidChannel,
    MissingSubcommand,
    InvalidSubcommand,
    MissingLevel,
    InvalidLevel,
    MissingMask,
    InvalidMask,
    MaskTooLong,
    InvalidSetBy,
    InvalidDuration,
    DurationTooLong,
    InvalidReason,
    ReasonTooLong,
    TooManyParameters,
    TooManyEntries,
    InvalidServerName,
    InvalidRequester,
    LineTooLong,
    OutputTooSmall,
};

pub const StoreError = AccessError || std.mem.Allocator.Error;

pub const Params = struct {
    max_entries: usize = DEFAULT_MAX_ENTRIES,
    max_channel_bytes: usize = DEFAULT_MAX_CHANNEL_BYTES,
    max_mask_bytes: usize = DEFAULT_MAX_MASK_BYTES,
    max_set_by_bytes: usize = DEFAULT_MAX_SET_BY_BYTES,
    max_reason_bytes: usize = DEFAULT_MAX_REASON_BYTES,
    max_line_bytes: usize = DEFAULT_MAX_LINE_BYTES,
    max_server_bytes: usize = DEFAULT_MAX_SERVER_BYTES,
    max_requester_bytes: usize = DEFAULT_MAX_REQUESTER_BYTES,
    max_duration_digits: usize = DEFAULT_MAX_DURATION_DIGITS,

    /// Derive `Params` from the central policy limits (config-driven).
    /// `max_set_by_bytes` and `max_line_bytes` keep their defaults.
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_entries = limits.ircx_access_max_entries,
            .max_channel_bytes = limits.target_len_128,
            .max_mask_bytes = limits.ircx_access_mask_len,
            .max_reason_bytes = limits.ircx_access_reason_len,
            .max_server_bytes = limits.server_name_len,
            .max_requester_bytes = limits.nick_len,
            .max_duration_digits = limits.ircx_duration_digits,
        };
    }
};

pub const Level = enum {
    voice,
    host,
    owner,
    founder,
    grant,
    deny,

    pub fn token(self: Level) []const u8 {
        return switch (self) {
            .founder => "FOUNDER",
            .owner => "OWNER",
            .host => "HOST",
            .voice => "VOICE",
            .deny => "DENY",
            .grant => "GRANT",
        };
    }

    pub fn parse(raw: []const u8) ?Level {
        if (std.ascii.eqlIgnoreCase(raw, "FOUNDER")) return .founder;
        if (std.ascii.eqlIgnoreCase(raw, "OWNER")) return .owner;
        if (std.ascii.eqlIgnoreCase(raw, "HOST")) return .host;
        if (std.ascii.eqlIgnoreCase(raw, "VOICE")) return .voice;
        if (std.ascii.eqlIgnoreCase(raw, "DENY")) return .deny;
        if (std.ascii.eqlIgnoreCase(raw, "GRANT")) return .grant;
        return null;
    }

    pub fn precedence(self: Level) u8 {
        return switch (self) {
            .deny => 70,
            .founder => 60,
            .owner => 50,
            .host, .grant => 40,
            .voice => 30,
        };
    }
};

pub const AddRequest = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
    timeout: ?u64 = null,
    reason: ?[]const u8 = null,
};

pub const DeleteRequest = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
};

pub const Selector = struct {
    channel: []const u8,
    level: ?Level = null,
    mask: ?[]const u8 = null,
    /// Rows to skip before the first returned row, for `listPage`. Parsed from an
    /// optional trailing numeric token on `ACCESS <chan> LIST`; 0 (the default)
    /// is the first page and keeps the pre-pagination wire behavior.
    offset: usize = 0,

    fn matches(self: Selector, entry: Entry) bool {
        if (!std.ascii.eqlIgnoreCase(self.channel, entry.channel)) return false;
        if (self.level) |level| {
            if (level != entry.level) return false;
        }
        if (self.mask) |mask| {
            if (!std.ascii.eqlIgnoreCase(mask, entry.mask)) return false;
        }
        return true;
    }
};

/// `ACCESS <destination> COPY <source> [REPLACE]` — seed one channel's ACL from
/// another (a template channel, or inheritance from a parent). Distinct from a
/// per-entry ADD so the daemon can gate it on the destination's FOUNDER tier
/// rather than the per-level rank a single ADD needs.
pub const CopyRequest = struct {
    destination: []const u8,
    source: []const u8,
    mode: AccessStore.CopyMode = .merge,
};

pub const Request = union(enum) {
    add: AddRequest,
    delete: DeleteRequest,
    list: Selector,
    clear: Selector,
    copy: CopyRequest,
};

pub const EntryView = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
    set_by: []const u8,
    duration: ?u64 = null,
    /// Hybrid logical clock of the write that produced this entry, and the node
    /// that authored it. Together they are the total order `applyRemote` resolves
    /// against; both are 0 on a store that has never stamped (a pure-local
    /// deployment or a test), which sorts below every real write.
    hlc: u64 = 0,
    origin_node: u64 = 0,
};

pub const ReplyContext = struct {
    server_name: []const u8,
    requester: []const u8,
};

/// One replicated ACCESS fact as it arrives from a mesh peer (see
/// `ircx_access_event.zig`). Slices borrow the frame bytes; `applyRemote` copies
/// anything it retains before returning.
pub const RemoteFact = struct {
    /// False is a TOMBSTONE: the entry is absent as of `hlc`.
    present: bool,
    channel: []const u8,
    level: Level,
    mask: []const u8,
    set_by: []const u8 = "",
    duration: ?u64 = null,
    hlc: u64,
    origin_node: u64,
};

/// What `applyRemote` did with a fact. Every outcome is a success — a `.stale`
/// fact is correct convergence behavior, not an error.
pub const ApplyOutcome = enum {
    /// The fact was newer and is now the stored state (added or updated).
    applied,
    /// A tombstone was newer than the local entry: the entry is gone and the
    /// marker is retained so a re-broadcast ADD cannot resurrect it.
    deleted,
    /// Local state already ranks at or above the fact's `(hlc, origin_node)`;
    /// nothing changed. This is the loop-breaker for re-broadcast facts.
    stale,
};

/// Total order over writes: HLC first, then the authoring node id as a
/// deterministic tie-break so two nodes that stamp the same HLC converge on the
/// same winner instead of oscillating.
fn ranksAbove(hlc_a: u64, node_a: u64, hlc_b: u64, node_b: u64) bool {
    if (hlc_a != hlc_b) return hlc_a > hlc_b;
    return node_a > node_b;
}

const Entry = struct {
    channel: []u8,
    level: Level,
    mask: []u8,
    set_by: []u8,
    /// Original requested timeout in seconds, echoed verbatim in ACCESS replies
    /// (kept for wire-display stability). A value of 0 or null means permanent.
    duration: ?u64,
    /// Absolute expiry as wall-clock unix seconds; null when the entry never
    /// expires. Derived from `duration` and the store clock at add time.
    expires_at: ?u64,
    /// Write order stamp; see `EntryView.hlc`.
    hlc: u64 = 0,
    origin_node: u64 = 0,

    fn view(self: *const Entry) EntryView {
        return .{
            .channel = self.channel,
            .level = self.level,
            .mask = self.mask,
            .set_by = self.set_by,
            .duration = self.duration,
            .hlc = self.hlc,
            .origin_node = self.origin_node,
        };
    }
};

/// A retained delete marker. Only the identity triple plus the retracting write
/// stamp is kept — never the setter or reason, which the delete already dropped.
const Tombstone = struct {
    channel: []u8,
    level: Level,
    mask: []u8,
    hlc: u64,
    origin_node: u64,
    /// Store-clock second the marker was recorded, for TTL reclaim.
    recorded_at: u64,
};

/// Absolute expiry for `duration` relative to `now` (wall-clock seconds). A
/// null or zero duration is permanent (no expiry). Saturating add avoids wrap.
fn computeExpiry(now: u64, duration: ?u64) ?u64 {
    const d = duration orelse return null;
    if (d == 0) return null;
    return now +| d;
}

pub const AccessStore = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    /// Retained delete markers, ordered by insertion. See `Tombstone`.
    tombstones: std.ArrayList(Tombstone) = .empty,
    max_entries: usize = DEFAULT_MAX_ENTRIES,
    max_tombstones: usize = DEFAULT_MAX_TOMBSTONES,
    tombstone_ttl_seconds: u64 = DEFAULT_TOMBSTONE_TTL_SECONDS,
    /// Current wall-clock unix seconds, refreshed by the daemon before store
    /// reads/writes (see `handleAccess`/`onTimerTick`). Defaults to 0 so
    /// clock-agnostic callers/tests see timed entries as always-live.
    now_seconds: u64 = 0,
    /// This node's mesh short id, stamped onto local writes so a peer can
    /// tie-break two writes that share an HLC. 0 on a store with no node
    /// identity (single-node or test), which ranks below every identified node.
    local_node: u64 = 0,
    /// Monotonic hybrid logical clock. Advanced past both wall-clock time and
    /// every stamp the store has observed, so a local write always ranks above
    /// the remote facts it has already seen — the property that makes a local
    /// DELETE beat an in-flight re-broadcast of the ADD it retracts.
    hlc: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) AccessStore {
        return .{ .allocator = allocator };
    }

    pub fn initWith(allocator: std.mem.Allocator, max_entries: usize) AccessStore {
        return .{ .allocator = allocator, .max_entries = max_entries };
    }

    /// Stamp the next local write. Monotonic even when the store clock stalls or
    /// steps backwards: the counter never returns a value it has already issued.
    fn nextHlc(self: *AccessStore) u64 {
        const wall = self.now_seconds *| 1000;
        self.hlc = @max(self.hlc + 1, wall);
        return self.hlc;
    }

    /// Fold an observed remote stamp into the local clock so a subsequent local
    /// write outranks it. Called for every fact `applyRemote` inspects, including
    /// stale ones — a stale fact still proves the peer's clock reached that value.
    fn observeHlc(self: *AccessStore, hlc_value: u64) void {
        self.hlc = @max(self.hlc, hlc_value);
    }

    /// True when `entry` carries an expiry that the store clock has passed.
    fn isExpired(self: *const AccessStore, entry: Entry) bool {
        const at = entry.expires_at orelse return false;
        return self.now_seconds >= at;
    }

    /// Drop every entry whose timeout has elapsed against the store clock,
    /// returning how many were removed. Called by the daemon on its timer tick;
    /// reads (`matchHostmask`/`list`) already skip expired entries, so this is a
    /// bounded-memory reclaim, not a correctness dependency.
    pub fn pruneExpired(self: *AccessStore) usize {
        var removed_count: usize = 0;
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (self.isExpired(self.entries.items[idx])) {
                const removed = self.entries.orderedRemove(idx);
                freeEntry(self.allocator, removed);
                removed_count += 1;
            } else {
                idx += 1;
            }
        }
        removed_count += self.pruneTombstones();
        return removed_count;
    }

    /// Drop delete markers older than the tombstone TTL. Safe because the TTL is
    /// far longer than any mesh convergence window: past it, no peer is still
    /// re-broadcasting the retracted ADD. A store with no clock (`now_seconds`
    /// 0) retains every marker rather than guessing.
    fn pruneTombstones(self: *AccessStore) usize {
        if (self.now_seconds == 0) return 0;
        var removed_count: usize = 0;
        var idx: usize = 0;
        while (idx < self.tombstones.items.len) {
            const marker = self.tombstones.items[idx];
            if (self.now_seconds -| marker.recorded_at >= self.tombstone_ttl_seconds) {
                const removed = self.tombstones.orderedRemove(idx);
                freeTombstone(self.allocator, removed);
                removed_count += 1;
            } else {
                idx += 1;
            }
        }
        return removed_count;
    }

    pub fn deinit(self: *AccessStore) void {
        for (self.entries.items) |entry| freeEntry(self.allocator, entry);
        self.entries.deinit(self.allocator);
        for (self.tombstones.items) |marker| freeTombstone(self.allocator, marker);
        self.tombstones.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn add(
        self: *AccessStore,
        channel: []const u8,
        level: Level,
        mask: []const u8,
        set_by: []const u8,
        duration: ?u64,
    ) StoreError!void {
        try validateChannelWith(.{}, channel);
        try validateMaskWith(.{}, mask);
        try validateSetByWith(.{}, set_by);

        const stamp = self.nextHlc();
        try self.upsert(channel, level, mask, set_by, duration, stamp, self.local_node);
        // A local ADD is an explicit re-grant: retire any marker that would make
        // the store treat this very entry as already-deleted.
        self.dropTombstone(channel, level, mask);
    }

    /// Add or replace an entry at a caller-chosen write stamp. Shared by the
    /// local `add` path and `applyRemote`; the caller owns rank resolution.
    fn upsert(
        self: *AccessStore,
        channel: []const u8,
        level: Level,
        mask: []const u8,
        set_by: []const u8,
        duration: ?u64,
        hlc_value: u64,
        origin_node: u64,
    ) StoreError!void {
        if (self.findIndex(channel, level, mask)) |idx| {
            const set_by_copy = try self.allocator.dupe(u8, set_by);
            self.allocator.free(self.entries.items[idx].set_by);
            self.entries.items[idx].set_by = set_by_copy;
            self.entries.items[idx].duration = duration;
            self.entries.items[idx].expires_at = computeExpiry(self.now_seconds, duration);
            self.entries.items[idx].hlc = hlc_value;
            self.entries.items[idx].origin_node = origin_node;
            return;
        }

        if (self.entries.items.len >= self.max_entries) return error.TooManyEntries;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const mask_copy = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(mask_copy);
        const set_by_copy = try self.allocator.dupe(u8, set_by);
        errdefer self.allocator.free(set_by_copy);

        try self.entries.append(self.allocator, .{
            .channel = channel_copy,
            .level = level,
            .mask = mask_copy,
            .set_by = set_by_copy,
            .duration = duration,
            .expires_at = computeExpiry(self.now_seconds, duration),
            .hlc = hlc_value,
            .origin_node = origin_node,
        });
    }

    pub fn remove(self: *AccessStore, channel: []const u8, level: Level, mask: []const u8) AccessError!bool {
        try validateChannelWith(.{}, channel);
        try validateMaskWith(.{}, mask);

        const stamp = self.nextHlc();
        const idx = self.findIndex(channel, level, mask) orelse {
            // Tombstone even a miss: the ADD this retracts may still be in
            // flight from a peer, and only a marker can outrank its arrival.
            self.recordTombstone(channel, level, mask, stamp, self.local_node) catch {};
            return false;
        };
        const removed = self.entries.orderedRemove(idx);
        self.recordTombstone(removed.channel, removed.level, removed.mask, stamp, self.local_node) catch {};
        freeEntry(self.allocator, removed);
        return true;
    }

    pub fn clear(self: *AccessStore, selector: Selector) AccessError!usize {
        try validateSelectorWith(.{}, selector);

        const stamp = self.nextHlc();
        var removed_count: usize = 0;
        var idx: usize = 0;
        while (idx < self.entries.items.len) {
            if (selector.matches(self.entries.items[idx])) {
                const removed = self.entries.orderedRemove(idx);
                self.recordTombstone(removed.channel, removed.level, removed.mask, stamp, self.local_node) catch {};
                freeEntry(self.allocator, removed);
                removed_count += 1;
            } else {
                idx += 1;
            }
        }
        return removed_count;
    }

    /// Converge one replicated fact from a mesh peer. Last-writer-wins over
    /// `(hlc, origin_node)`, with delete markers so a re-broadcast ADD cannot
    /// resurrect a revoked grant. Returns what it did; a `.stale` fact is normal
    /// (that is how a re-broadcast loop terminates), never an error.
    ///
    /// Field bounds are enforced here too, not just at the codec: a peer is
    /// untrusted input, and this is the last gate before the fact reaches memory.
    pub fn applyRemote(self: *AccessStore, fact: RemoteFact) StoreError!ApplyOutcome {
        try validateChannelWith(.{}, fact.channel);
        try validateMaskWith(.{}, fact.mask);
        if (fact.present) try validateSetByWith(.{}, fact.set_by);

        self.observeHlc(fact.hlc);

        if (self.findTombstone(fact.channel, fact.level, fact.mask)) |marker| {
            // A tombstone at or above the fact's rank wins: the entry stays gone.
            if (!ranksAbove(fact.hlc, fact.origin_node, marker.hlc, marker.origin_node)) return .stale;
        }

        if (self.findIndex(fact.channel, fact.level, fact.mask)) |idx| {
            const current = self.entries.items[idx];
            if (!ranksAbove(fact.hlc, fact.origin_node, current.hlc, current.origin_node)) return .stale;
            if (!fact.present) {
                const removed = self.entries.orderedRemove(idx);
                try self.recordTombstone(removed.channel, removed.level, removed.mask, fact.hlc, fact.origin_node);
                freeEntry(self.allocator, removed);
                return .deleted;
            }
        } else if (!fact.present) {
            try self.recordTombstone(fact.channel, fact.level, fact.mask, fact.hlc, fact.origin_node);
            return .deleted;
        }

        try self.upsert(
            fact.channel,
            fact.level,
            fact.mask,
            fact.set_by,
            fact.duration,
            fact.hlc,
            fact.origin_node,
        );
        self.dropTombstone(fact.channel, fact.level, fact.mask);
        return .applied;
    }

    /// Snapshot the write stamp the store would replicate for one entry, so the
    /// daemon can frame an `ircx_access_event` after a local mutation.
    pub fn lastStamp(self: *const AccessStore) struct { hlc: u64, origin_node: u64 } {
        return .{ .hlc = self.hlc, .origin_node = self.local_node };
    }

    fn findTombstone(self: *const AccessStore, channel: []const u8, level: Level, mask: []const u8) ?Tombstone {
        for (self.tombstones.items) |marker| {
            if (marker.level == level and
                std.ascii.eqlIgnoreCase(marker.channel, channel) and
                std.ascii.eqlIgnoreCase(marker.mask, mask))
            {
                return marker;
            }
        }
        return null;
    }

    fn recordTombstone(
        self: *AccessStore,
        channel: []const u8,
        level: Level,
        mask: []const u8,
        hlc_value: u64,
        origin_node: u64,
    ) StoreError!void {
        for (self.tombstones.items) |*marker| {
            if (marker.level == level and
                std.ascii.eqlIgnoreCase(marker.channel, channel) and
                std.ascii.eqlIgnoreCase(marker.mask, mask))
            {
                if (ranksAbove(hlc_value, origin_node, marker.hlc, marker.origin_node)) {
                    marker.hlc = hlc_value;
                    marker.origin_node = origin_node;
                    marker.recorded_at = self.now_seconds;
                }
                return;
            }
        }

        if (self.tombstones.items.len >= self.max_tombstones) self.evictOldestTombstone();
        if (self.tombstones.items.len >= self.max_tombstones) return error.TooManyEntries;

        const channel_copy = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(channel_copy);
        const mask_copy = try self.allocator.dupe(u8, mask);
        errdefer self.allocator.free(mask_copy);

        try self.tombstones.append(self.allocator, .{
            .channel = channel_copy,
            .level = level,
            .mask = mask_copy,
            .hlc = hlc_value,
            .origin_node = origin_node,
            .recorded_at = self.now_seconds,
        });
    }

    /// Evict the lowest-ranked marker when the tombstone budget is full. The
    /// oldest write is the one whose ADD is least likely to still be in flight.
    fn evictOldestTombstone(self: *AccessStore) void {
        if (self.tombstones.items.len == 0) return;
        var victim: usize = 0;
        for (self.tombstones.items, 0..) |marker, idx| {
            const lowest = self.tombstones.items[victim];
            if (ranksAbove(lowest.hlc, lowest.origin_node, marker.hlc, marker.origin_node)) victim = idx;
        }
        const removed = self.tombstones.orderedRemove(victim);
        freeTombstone(self.allocator, removed);
    }

    fn dropTombstone(self: *AccessStore, channel: []const u8, level: Level, mask: []const u8) void {
        for (self.tombstones.items, 0..) |marker, idx| {
            if (marker.level == level and
                std.ascii.eqlIgnoreCase(marker.channel, channel) and
                std.ascii.eqlIgnoreCase(marker.mask, mask))
            {
                const removed = self.tombstones.orderedRemove(idx);
                freeTombstone(self.allocator, removed);
                return;
            }
        }
    }

    pub fn tombstoneCount(self: *const AccessStore) usize {
        return self.tombstones.items.len;
    }

    pub fn list(self: *const AccessStore, channel: []const u8, out: []EntryView) AccessError![]const EntryView {
        return self.listMatching(.{ .channel = channel }, out);
    }

    pub fn listMatching(self: *const AccessStore, selector: Selector, out: []EntryView) AccessError![]const EntryView {
        try validateSelectorWith(.{}, selector);

        var count: usize = 0;
        for (self.entries.items) |*entry| {
            if (self.isExpired(entry.*)) continue;
            if (!selector.matches(entry.*)) continue;
            if (count >= out.len) return error.OutputTooSmall;
            out[count] = entry.view();
            count += 1;
        }
        return out[0..count];
    }

    /// One page of `listPage` results.
    pub const Page = struct {
        /// Rows filled into the caller's buffer, in stable store order.
        rows: []const EntryView,
        /// Offset to pass for the next page, or null when this page is the last.
        /// Never equal to the requested offset, so a paging caller cannot loop.
        next_offset: ?usize,
        /// Total matching entries, so a client can render "1-64 of 210" without
        /// walking every page.
        total: usize,
    };

    /// Page through matching entries instead of demanding a buffer sized for the
    /// whole ACL. Unlike `listMatching`, a buffer smaller than the match set is
    /// NOT an error: this fills what fits and reports where to resume.
    ///
    /// `listMatching` returns `error.OutputTooSmall` when the ACL outgrows the
    /// caller's array, and the historical daemon call site turned that error into
    /// an EMPTY reply — a full ACL rendering as no entries at all. Paging removes
    /// that cliff. Ordering is store insertion order, kept stable by the ordered
    /// (never swap) removals above, so a page boundary cannot skip or duplicate
    /// an entry across calls in the absence of a concurrent mutation.
    pub fn listPage(
        self: *const AccessStore,
        selector: Selector,
        offset: usize,
        out: []EntryView,
    ) AccessError!Page {
        try validateSelectorWith(.{}, selector);

        var matched: usize = 0;
        var filled: usize = 0;
        var next_offset: ?usize = null;
        for (self.entries.items) |*entry| {
            if (self.isExpired(entry.*)) continue;
            if (!selector.matches(entry.*)) continue;
            const position = matched;
            matched += 1;
            if (position < offset) continue;
            if (filled < out.len) {
                out[filled] = entry.view();
                filled += 1;
            } else if (next_offset == null) {
                next_offset = offset + filled;
            }
        }

        return .{ .rows = out[0..filled], .next_offset = next_offset, .total = matched };
    }

    /// How a template copy treats entries already present on the destination.
    pub const CopyMode = enum {
        /// Keep existing destination entries; add only levels/masks not there.
        merge,
        /// Clear the destination's ACL first, then copy. The clear tombstones
        /// what it drops, so the removals replicate like any other delete.
        replace,
    };

    pub const CopyResult = struct {
        copied: usize,
        /// Entries dropped by a `.replace` clear before copying.
        removed: usize,
    };

    /// Copy `source`'s live ACL onto `destination` — the primitive behind
    /// template channels and per-channel ACL inheritance.
    ///
    /// Copied entries are stamped with fresh local write stamps, so they
    /// replicate as this node's own facts rather than forging the source
    /// author's origin. Timed entries carry their remaining lifetime, not the
    /// original duration, so a copy cannot silently extend a grant. Refuses
    /// (`error.TooManyEntries`) before writing anything if the destination would
    /// exceed `max_entries`, so a partial ACL is never left behind.
    pub fn copyFrom(
        self: *AccessStore,
        destination: []const u8,
        source: []const u8,
        mode: CopyMode,
    ) StoreError!CopyResult {
        try validateChannelWith(.{}, destination);
        try validateChannelWith(.{}, source);
        if (std.ascii.eqlIgnoreCase(destination, source)) return error.InvalidChannel;

        const removed = switch (mode) {
            .replace => try self.clear(.{ .channel = destination }),
            .merge => 0,
        };

        // Count the copy up front: the destination must fit the whole template or
        // the operator gets a refusal, not a truncated ACL.
        var incoming: usize = 0;
        for (self.entries.items) |*entry| {
            if (self.isExpired(entry.*)) continue;
            if (!std.ascii.eqlIgnoreCase(entry.channel, source)) continue;
            if (self.findIndex(destination, entry.level, entry.mask) != null) continue;
            incoming += 1;
        }
        if (self.entries.items.len + incoming > self.max_entries) return error.TooManyEntries;

        // `upsert` may grow `entries`, invalidating every pointer into it, so the
        // source rows are snapshotted into owned copies before any write.
        var staged: std.ArrayList(Entry) = .empty;
        defer {
            for (staged.items) |row| freeEntry(self.allocator, row);
            staged.deinit(self.allocator);
        }
        for (self.entries.items) |*entry| {
            if (self.isExpired(entry.*)) continue;
            if (!std.ascii.eqlIgnoreCase(entry.channel, source)) continue;
            const mask_copy = try self.allocator.dupe(u8, entry.mask);
            errdefer self.allocator.free(mask_copy);
            const set_by_copy = try self.allocator.dupe(u8, entry.set_by);
            errdefer self.allocator.free(set_by_copy);
            const channel_copy = try self.allocator.dupe(u8, destination);
            errdefer self.allocator.free(channel_copy);
            try staged.append(self.allocator, .{
                .channel = channel_copy,
                .level = entry.level,
                .mask = mask_copy,
                .set_by = set_by_copy,
                .duration = self.remainingDuration(entry.*),
                .expires_at = entry.expires_at,
            });
        }

        var copied: usize = 0;
        for (staged.items) |row| {
            const stamp = self.nextHlc();
            try self.upsert(destination, row.level, row.mask, row.set_by, row.duration, stamp, self.local_node);
            self.dropTombstone(destination, row.level, row.mask);
            copied += 1;
        }

        return .{ .copied = copied, .removed = removed };
    }

    /// Remaining lifetime of a timed entry against the store clock. A permanent
    /// entry stays permanent; an entry whose clock is unknown keeps its original
    /// duration rather than being silently made permanent.
    fn remainingDuration(self: *const AccessStore, entry: Entry) ?u64 {
        const expires_at = entry.expires_at orelse return null;
        if (self.now_seconds == 0) return entry.duration;
        if (expires_at <= self.now_seconds) return 1;
        return expires_at - self.now_seconds;
    }

    pub fn matchHostmask(self: *const AccessStore, channel: []const u8, hostmask: []const u8) AccessError!?EntryView {
        try validateChannelWith(.{}, channel);
        try validateHostmaskWith(.{}, hostmask);

        var best: ?*const Entry = null;
        for (self.entries.items) |*entry| {
            if (self.isExpired(entry.*)) continue;
            if (!std.ascii.eqlIgnoreCase(entry.channel, channel)) continue;
            if (!listx.globMatch(entry.mask, hostmask)) continue;
            if (best == null or entry.level.precedence() > best.?.level.precedence()) {
                best = entry;
            }
        }

        if (best) |entry| return entry.view();
        return null;
    }

    fn findIndex(self: *const AccessStore, channel: []const u8, level: Level, mask: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (entry.level == level and
                std.ascii.eqlIgnoreCase(entry.channel, channel) and
                std.ascii.eqlIgnoreCase(entry.mask, mask))
            {
                return idx;
            }
        }
        return null;
    }
};

const Subcommand = enum {
    add,
    delete,
    list,
    clear,
    copy,

    fn parse(raw: []const u8) ?Subcommand {
        if (std.ascii.eqlIgnoreCase(raw, "ADD")) return .add;
        if (std.ascii.eqlIgnoreCase(raw, "DEL") or std.ascii.eqlIgnoreCase(raw, "DELETE")) return .delete;
        if (std.ascii.eqlIgnoreCase(raw, "LIST")) return .list;
        if (std.ascii.eqlIgnoreCase(raw, "CLEAR")) return .clear;
        if (std.ascii.eqlIgnoreCase(raw, "COPY") or std.ascii.eqlIgnoreCase(raw, "INHERIT")) return .copy;
        return null;
    }
};

pub fn parse(params: []const []const u8) AccessError!Request {
    return parseWith(.{}, params);
}

pub fn parseWith(comptime limits: Params, params: []const []const u8) AccessError!Request {
    if (params.len == 0) return error.MissingChannel;
    const channel = params[0];
    try validateChannelWith(limits, channel);

    if (params.len == 1) return error.MissingSubcommand;
    const subcommand = Subcommand.parse(params[1]) orelse return error.InvalidSubcommand;
    const tail = params[2..];

    return switch (subcommand) {
        .add => .{ .add = try parseAddWith(limits, channel, tail) },
        .delete => .{ .delete = try parseDeleteWith(limits, channel, tail) },
        .list => .{ .list = try parseListSelectorWith(limits, channel, tail) },
        .clear => .{ .clear = try parseSelectorWith(limits, channel, tail) },
        .copy => .{ .copy = try parseCopyWith(limits, channel, tail) },
    };
}

pub fn buildAccessStart(out: []u8, ctx: ReplyContext, channel: []const u8) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateChannelWith(.{}, channel);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSSTART, ctx.server_name, ctx.requester);
    try b.spaceParam(channel);
    try b.spaceTrailing("ACCESS list begins");
    try b.crlf();
    return b.slice();
}

pub fn buildAccessEntry(out: []u8, ctx: ReplyContext, entry: EntryView) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateEntryViewWith(.{}, entry);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSENTRY, ctx.server_name, ctx.requester);
    try appendEntryFields(&b, entry);
    try b.crlf();
    return b.slice();
}

pub fn buildAccessEnd(out: []u8, ctx: ReplyContext, channel: []const u8) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateChannelWith(.{}, channel);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSEND, ctx.server_name, ctx.requester);
    try b.spaceParam(channel);
    try b.spaceTrailing("End of ACCESS list");
    try b.crlf();
    return b.slice();
}

pub fn buildAccessAdd(out: []u8, ctx: ReplyContext, entry: EntryView) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateEntryViewWith(.{}, entry);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSADD, ctx.server_name, ctx.requester);
    try b.spaceParam(entry.channel);
    try b.spaceParam(entry.level.token());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("ACCESS entry added");
    try b.crlf();
    return b.slice();
}

pub fn buildAccessDelete(out: []u8, ctx: ReplyContext, entry: DeleteRequest) AccessError![]const u8 {
    try validateContextWith(.{}, ctx);
    try validateChannelWith(.{}, entry.channel);
    try validateMaskWith(.{}, entry.mask);

    var b = LineBuilder.init(out, DEFAULT_MAX_LINE_BYTES);
    try b.numericPrefix(RPL_ACCESSDELETE, ctx.server_name, ctx.requester);
    try b.spaceParam(entry.channel);
    try b.spaceParam(entry.level.token());
    try b.spaceParam(entry.mask);
    try b.spaceTrailing("ACCESS entry deleted");
    try b.crlf();
    return b.slice();
}

fn parseAddWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!AddRequest {
    if (params.len == 0) return error.MissingLevel;
    if (params.len == 1) return error.MissingMask;
    if (params.len > 4) return error.TooManyParameters;

    const level = Level.parse(params[0]) orelse return error.InvalidLevel;
    const mask = params[1];
    try validateMaskWith(limits, mask);

    var request = AddRequest{ .channel = channel, .level = level, .mask = mask };
    if (params.len >= 3) {
        if (params[2].len > 0 and params[2][0] == ':') {
            if (params.len > 3) return error.TooManyParameters;
            request.reason = try parseReasonWith(limits, params[2]);
        } else {
            request.timeout = try parseDurationWith(limits, params[2]);
        }
    }
    if (params.len == 4) request.reason = try parseReasonWith(limits, params[3]);
    return request;
}

fn parseDeleteWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!DeleteRequest {
    if (params.len == 0) return error.MissingLevel;
    if (params.len == 1) return error.MissingMask;
    if (params.len > 2) return error.TooManyParameters;

    const level = Level.parse(params[0]) orelse return error.InvalidLevel;
    const mask = params[1];
    try validateMaskWith(limits, mask);
    return .{ .channel = channel, .level = level, .mask = mask };
}

fn parseSelectorWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!Selector {
    if (params.len > 2) return error.TooManyParameters;

    var selector = Selector{ .channel = channel };
    if (params.len >= 1) {
        selector.level = Level.parse(params[0]) orelse return error.InvalidLevel;
    }
    if (params.len == 2) {
        try validateMaskWith(limits, params[1]);
        selector.mask = params[1];
    }
    return selector;
}

/// `ACCESS <chan> LIST [level] [mask] [offset]` — `parseSelectorWith` plus the
/// optional trailing page offset. The offset is only recognized as the LAST
/// token and only when it is all digits, so a numeric-looking MASK (a bare
/// `*!*@1234` is not all digits) is never mistaken for a page cursor. No `Level`
/// token is numeric (FOUNDER/OWNER/HOST/VOICE/DENY/GRANT), so a lone all-digits
/// token is unambiguously a cursor — `ACCESS #c LIST 64` pages an unfiltered
/// list, which is the form a paging client actually needs.
fn parseListSelectorWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!Selector {
    if (params.len == 0) return .{ .channel = channel };
    if (params.len > 3) return error.TooManyParameters;

    const last = params[params.len - 1];
    if (isAllDigits(last)) {
        var selector = try parseSelectorWith(limits, channel, params[0 .. params.len - 1]);
        selector.offset = try parseOffsetWith(limits, last);
        return selector;
    }
    if (params.len > 2) return error.TooManyParameters;
    return parseSelectorWith(limits, channel, params);
}

fn isAllDigits(raw: []const u8) bool {
    if (raw.len == 0) return false;
    for (raw) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

/// Bounded page offset. Digit-count capped like every other numeric parameter so
/// a hostile client cannot feed an unbounded token, and range-capped to the
/// store's entry ceiling: an offset past the largest possible ACL is a client
/// error, not a silently empty page.
fn parseOffsetWith(comptime limits: Params, raw: []const u8) AccessError!usize {
    if (raw.len == 0 or raw.len > limits.max_duration_digits) return error.InvalidDuration;
    var value: usize = 0;
    for (raw) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDuration;
        const digit: usize = byte - '0';
        if (value > (limits.max_entries - digit) / 10) return error.TooManyParameters;
        value = value * 10 + digit;
    }
    if (value > limits.max_entries) return error.TooManyParameters;
    return value;
}

/// `ACCESS <destination> COPY <source> [MERGE|REPLACE]`.
fn parseCopyWith(comptime limits: Params, channel: []const u8, params: []const []const u8) AccessError!CopyRequest {
    if (params.len == 0) return error.MissingChannel;
    if (params.len > 2) return error.TooManyParameters;

    const source = params[0];
    try validateChannelWith(limits, source);
    if (std.ascii.eqlIgnoreCase(source, channel)) return error.InvalidChannel;

    var request = CopyRequest{ .destination = channel, .source = source };
    if (params.len == 2) {
        if (std.ascii.eqlIgnoreCase(params[1], "REPLACE")) {
            request.mode = .replace;
        } else if (std.ascii.eqlIgnoreCase(params[1], "MERGE")) {
            request.mode = .merge;
        } else {
            return error.InvalidSubcommand;
        }
    }
    return request;
}

fn parseDurationWith(comptime limits: Params, raw: []const u8) AccessError!u64 {
    if (raw.len == 0) return error.InvalidDuration;
    if (raw.len > limits.max_duration_digits) return error.DurationTooLong;

    var value: u64 = 0;
    for (raw) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidDuration;
        const digit: u64 = byte - '0';
        if (value > (std.math.maxInt(u64) - digit) / 10) return error.InvalidDuration;
        value = value * 10 + digit;
    }
    return value;
}

fn parseReasonWith(comptime limits: Params, raw: []const u8) AccessError![]const u8 {
    const reason = if (raw.len > 0 and raw[0] == ':') raw[1..] else raw;
    try validateReasonWith(limits, reason);
    return reason;
}

fn validateSelectorWith(comptime limits: Params, selector: Selector) AccessError!void {
    try validateChannelWith(limits, selector.channel);
    if (selector.mask) |mask| try validateMaskWith(limits, mask);
}

fn validateEntryViewWith(comptime limits: Params, entry: EntryView) AccessError!void {
    try validateChannelWith(limits, entry.channel);
    try validateMaskWith(limits, entry.mask);
    try validateSetByWith(limits, entry.set_by);
}

fn validateContextWith(comptime limits: Params, ctx: ReplyContext) AccessError!void {
    try validateParamBounded(ctx.server_name, limits.max_server_bytes, error.InvalidServerName);
    try validateParamBounded(ctx.requester, limits.max_requester_bytes, error.InvalidRequester);
}

fn validateChannelWith(comptime limits: Params, channel: []const u8) AccessError!void {
    if (channel.len == 0 or channel.len > limits.max_channel_bytes) return error.InvalidChannel;
    try validateSafeText(channel, error.InvalidChannel);
    if (!validChannelNamePrefix(channel)) return error.InvalidChannel;
    for (channel) |byte| {
        if (byte == ' ' or byte == ',' or byte == 7) return error.InvalidChannel;
    }
}

fn validChannelNamePrefix(channel: []const u8) bool {
    return switch (channel[0]) {
        '#', '&' => true,
        '%' => channel.len >= 2 and (channel[1] == '#' or channel[1] == '&'),
        else => false,
    };
}

fn validateMaskWith(comptime limits: Params, mask: []const u8) AccessError!void {
    if (mask.len == 0) return error.InvalidMask;
    if (mask.len > limits.max_mask_bytes) return error.MaskTooLong;
    if (mask[0] == ':') return error.InvalidMask;
    try validateSafeText(mask, error.InvalidMask);

    var bang: ?usize = null;
    var at: ?usize = null;
    for (mask, 0..) |byte, idx| {
        switch (byte) {
            ' ', '\t', ',' => return error.InvalidMask,
            '!' => {
                if (bang == null) bang = idx;
            },
            '@' => {
                if (at == null) at = idx;
            },
            else => {},
        }
    }

    const bang_idx = bang orelse return error.InvalidMask;
    const at_idx = at orelse return error.InvalidMask;
    if (bang_idx == 0 or at_idx <= bang_idx + 1 or at_idx == mask.len - 1) return error.InvalidMask;
}

fn validateHostmaskWith(comptime limits: Params, hostmask: []const u8) AccessError!void {
    try validateMaskWith(limits, hostmask);
    if (std.mem.indexOfScalar(u8, hostmask, '*') != null) return error.InvalidMask;
    if (std.mem.indexOfScalar(u8, hostmask, '?') != null) return error.InvalidMask;
}

fn validateSetByWith(comptime limits: Params, set_by: []const u8) AccessError!void {
    try validateParamBounded(set_by, limits.max_set_by_bytes, error.InvalidSetBy);
}

fn validateReasonWith(comptime limits: Params, reason: []const u8) AccessError!void {
    if (reason.len > limits.max_reason_bytes) return error.ReasonTooLong;
    for (reason) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidReason,
            else => {},
        }
    }
}

fn validateParamBounded(param: []const u8, max_len: usize, err: AccessError) AccessError!void {
    if (param.len == 0 or param.len > max_len) return err;
    if (param[0] == ':') return err;
    for (param) |byte| {
        if (byte <= ' ' or byte == 0x7f) return err;
    }
}

fn validateSafeText(bytes: []const u8, err: AccessError) AccessError!void {
    for (bytes) |byte| {
        switch (byte) {
            0, '\r', '\n' => return err,
            1...8, 11, 12, 14...31, 127 => return err,
            else => {},
        }
    }
}

fn appendEntryFields(b: *LineBuilder, entry: EntryView) AccessError!void {
    try b.spaceParam(entry.channel);
    try b.spaceParam(entry.level.token());
    try b.spaceParam(entry.mask);
    try b.spaceParam(entry.set_by);
    try b.spaceUnsigned(entry.duration orelse 0);
}

fn freeEntry(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.channel);
    allocator.free(entry.mask);
    allocator.free(entry.set_by);
}

fn freeTombstone(allocator: std.mem.Allocator, marker: Tombstone) void {
    allocator.free(marker.channel);
    allocator.free(marker.mask);
}

fn formatCodeValue(value: u16, buf: []u8) []const u8 {
    if (buf.len < 3) return buf[0..0];
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

const LineBuilder = struct {
    out: []u8,
    max_line_bytes: usize,
    len: usize = 0,

    fn init(out: []u8, max_line_bytes: usize) LineBuilder {
        return .{ .out = out, .max_line_bytes = max_line_bytes };
    }

    fn slice(self: *const LineBuilder) []const u8 {
        return self.out[0..self.len];
    }

    fn numericPrefix(self: *LineBuilder, code_value: u16, server_name: []const u8, requester: []const u8) AccessError!void {
        try self.appendByte(':');
        try self.appendBytes(server_name);
        try self.appendByte(' ');
        var code_buf: [3]u8 = undefined;
        try self.appendBytes(formatCodeValue(code_value, &code_buf));
        try self.appendByte(' ');
        try self.appendBytes(requester);
    }

    fn spaceParam(self: *LineBuilder, param: []const u8) AccessError!void {
        try self.appendByte(' ');
        try self.appendBytes(param);
    }

    fn spaceTrailing(self: *LineBuilder, param: []const u8) AccessError!void {
        try self.appendBytes(" :");
        try self.appendBytes(param);
    }

    fn spaceUnsigned(self: *LineBuilder, value: u64) AccessError!void {
        try self.appendByte(' ');
        try self.appendUnsigned(value);
    }

    fn appendUnsigned(self: *LineBuilder, value: u64) AccessError!void {
        var buf: [20]u8 = undefined;
        var cursor: usize = buf.len;
        var current = value;
        while (true) {
            cursor -= 1;
            buf[cursor] = @as(u8, '0') + @as(u8, @intCast(current % 10));
            current /= 10;
            if (current == 0) break;
        }
        try self.appendBytes(buf[cursor..]);
    }

    fn crlf(self: *LineBuilder) AccessError!void {
        try self.appendBytes("\r\n");
    }

    fn appendBytes(self: *LineBuilder, bytes: []const u8) AccessError!void {
        if (self.len + bytes.len > self.out.len) return error.OutputTooSmall;
        if (self.len + bytes.len > self.max_line_bytes) return error.LineTooLong;
        @memcpy(self.out[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *LineBuilder, byte: u8) AccessError!void {
        if (self.len == self.out.len) return error.OutputTooSmall;
        if (self.len + 1 > self.max_line_bytes) return error.LineTooLong;
        self.out[self.len] = byte;
        self.len += 1;
    }
};

test "add match precedence and update without leaks" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add("#zig", .voice, "nick!*@example.test", "alice", 10);
    try store.add("#zig", .host, "*!*@example.test", "alice", 20);
    try store.add("#zig", .owner, "nick!*@example.test", "bob", 30);
    try store.add("#zig", .grant, "nick!*@example.test", "carol", 40);
    try store.add("#zig", .deny, "nick!*@example.test", "dan", 50);

    const best = (try store.matchHostmask("#zig", "Nick!u@example.test")).?;
    try std.testing.expectEqual(Level.deny, best.level);
    try std.testing.expectEqual(@as(?u64, 50), best.duration);

    try store.add("#zig", .deny, "nick!*@example.test", "erin", 60);
    const updated = (try store.matchHostmask("#zig", "nick!u@example.test")).?;
    try std.testing.expectEqual(Level.deny, updated.level);
    try std.testing.expectEqualStrings("erin", updated.set_by);
    try std.testing.expectEqual(@as(?u64, 60), updated.duration);
}

test "parse each ACCESS subcommand" {
    const add_req = try parse(&.{ "#zig", "ADD", "OWNER", "nick!*@host.test", "3600", ":founder" });
    try std.testing.expectEqual(Level.owner, add_req.add.level);
    try std.testing.expectEqualStrings("#zig", add_req.add.channel);
    try std.testing.expectEqualStrings("nick!*@host.test", add_req.add.mask);
    try std.testing.expectEqual(@as(?u64, 3600), add_req.add.timeout);
    try std.testing.expectEqualStrings("founder", add_req.add.reason.?);

    const del_req = try parse(&.{ "#zig", "DEL", "VOICE", "*!*@guest.test" });
    try std.testing.expectEqual(Level.voice, del_req.delete.level);
    try std.testing.expectEqualStrings("*!*@guest.test", del_req.delete.mask);

    const list_req = try parse(&.{ "#zig", "LIST", "HOST", "*!*@staff.test" });
    try std.testing.expectEqual(@as(?Level, .host), list_req.list.level);
    try std.testing.expectEqualStrings("*!*@staff.test", list_req.list.mask.?);

    const clear_req = try parse(&.{ "#zig", "CLEAR", "DENY" });
    try std.testing.expectEqual(@as(?Level, .deny), clear_req.clear.level);
    try std.testing.expectEqual(@as(?[]const u8, null), clear_req.clear.mask);
}

test "list remove clear and reply builders" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add("#zig", .voice, "a!*@host.test", "oper", null);
    try store.add("#zig", .host, "b!*@host.test", "oper", 25);
    try store.add("#ops", .deny, "*!*@bad.test", "oper", null);

    var views: [4]EntryView = undefined;
    const listed = try store.list("#zig", &views);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqual(Level.voice, listed[0].level);
    try std.testing.expectEqual(Level.host, listed[1].level);

    try std.testing.expect(try store.remove("#zig", .voice, "a!*@host.test"));
    try std.testing.expectEqual(@as(usize, 1), (try store.list("#zig", &views)).len);
    try std.testing.expectEqual(@as(usize, 1), try store.clear(.{ .channel = "#ops" }));

    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        ":irc.example.test 803 dan #zig :ACCESS list begins\r\n",
        try buildAccessStart(&buf, ctx, "#zig"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 804 dan #zig HOST b!*@host.test oper 25\r\n",
        try buildAccessEntry(&buf, ctx, listed[1]),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 805 dan #zig :End of ACCESS list\r\n",
        try buildAccessEnd(&buf, ctx, "#zig"),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 801 dan #zig HOST b!*@host.test :ACCESS entry added\r\n",
        try buildAccessAdd(&buf, ctx, listed[1]),
    );
    try std.testing.expectEqualStrings(
        ":irc.example.test 802 dan #zig HOST b!*@host.test :ACCESS entry deleted\r\n",
        try buildAccessDelete(&buf, ctx, .{ .channel = "#zig", .level = .host, .mask = "b!*@host.test" }),
    );
}

test "ACCESS timed entry stops matching once its timeout elapses" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    store.now_seconds = 1000;
    // 50s DENY added at t=1000 expires at t=1050.
    try store.add("#zig", .deny, "bad!*@evil.test", "oper", 50);

    // Still live at t=1049.
    store.now_seconds = 1049;
    try std.testing.expect((try store.matchHostmask("#zig", "bad!u@evil.test")) != null);
    var views: [4]EntryView = undefined;
    try std.testing.expectEqual(@as(usize, 1), (try store.list("#zig", &views)).len);

    // Exactly at expiry (>=) it is gone from every read path.
    store.now_seconds = 1050;
    try std.testing.expectEqual(@as(?EntryView, null), try store.matchHostmask("#zig", "bad!u@evil.test"));
    try std.testing.expectEqual(@as(usize, 0), (try store.list("#zig", &views)).len);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try store.listMatching(.{ .channel = "#zig", .level = .deny }, &views)).len,
    );
}

test "ACCESS permanent entries never expire regardless of the clock" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    store.now_seconds = 500;
    try store.add("#zig", .owner, "boss!*@corp.test", "oper", null); // null == permanent
    try store.add("#zig", .voice, "reg!*@corp.test", "oper", 0); // 0 == permanent

    store.now_seconds = std.math.maxInt(u64);
    var views: [4]EntryView = undefined;
    try std.testing.expectEqual(@as(usize, 2), (try store.list("#zig", &views)).len);
    try std.testing.expect((try store.matchHostmask("#zig", "boss!u@corp.test")) != null);
    try std.testing.expectEqual(@as(usize, 0), store.pruneExpired());
}

test "ACCESS pruneExpired reclaims only lapsed entries" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    store.now_seconds = 100;
    try store.add("#zig", .deny, "a!*@h.test", "oper", 10); // expires 110
    try store.add("#zig", .host, "b!*@h.test", "oper", null); // permanent
    try store.add("#zig", .voice, "c!*@h.test", "oper", 1000); // expires 1100

    store.now_seconds = 200; // only the 10s entry has lapsed
    try std.testing.expectEqual(@as(usize, 1), store.pruneExpired());

    var views: [4]EntryView = undefined;
    const rows = try store.list("#zig", &views);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expect(!try store.remove("#zig", .deny, "a!*@h.test")); // already reclaimed
    try std.testing.expect(try store.remove("#zig", .host, "b!*@h.test"));
}

test "ACCESS re-add refreshes an expired entry's timeout" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    store.now_seconds = 100;
    try store.add("#zig", .deny, "x!*@h.test", "oper", 10); // expires 110

    store.now_seconds = 200; // lapsed but not yet pruned
    try std.testing.expectEqual(@as(?EntryView, null), try store.matchHostmask("#zig", "x!u@h.test"));

    // Re-adding the same mask must revive it with a fresh window (no duplicate).
    try store.add("#zig", .deny, "x!*@h.test", "oper", 50); // expires 250
    var views: [4]EntryView = undefined;
    try std.testing.expectEqual(@as(usize, 1), (try store.list("#zig", &views)).len);
    try std.testing.expect((try store.matchHostmask("#zig", "x!u@h.test")) != null);
}

test "validation and bounded outputs" {
    var tiny = AccessStore.initWith(std.testing.allocator, 1);
    defer tiny.deinit();

    try tiny.add("#zig", .voice, "a!*@host.test", "oper", null);
    try std.testing.expectError(error.TooManyEntries, tiny.add("#zig", .host, "b!*@host.test", "oper", null));
    try std.testing.expectError(error.InvalidMask, parse(&.{ "#zig", "ADD", "VOICE", "not-a-hostmask" }));
    try std.testing.expectError(error.InvalidDuration, parse(&.{ "#zig", "ADD", "VOICE", "a!*@h", "abc" }));

    const ctx = ReplyContext{ .server_name = "irc.example.test", .requester = "dan" };
    var short: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, buildAccessEnd(&short, ctx, "#zig"));
}

test "ACCESS applyRemote converges last-writer-wins on (hlc, origin_node)" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();
    store.local_node = 1;

    const base = RemoteFact{
        .present = true,
        .channel = "#mesh",
        .level = .host,
        .mask = "*!*@a.test",
        .set_by = "alice",
        .hlc = 100,
        .origin_node = 7,
    };
    try std.testing.expectEqual(ApplyOutcome.applied, try store.applyRemote(base));

    // Re-broadcast of the SAME fact is stale, not an error: that is what makes a
    // gossip loop terminate instead of ping-ponging writes forever.
    try std.testing.expectEqual(ApplyOutcome.stale, try store.applyRemote(base));

    // An older writer loses even though it arrives later in wall time.
    var older = base;
    older.hlc = 99;
    older.set_by = "stale-writer";
    try std.testing.expectEqual(ApplyOutcome.stale, try store.applyRemote(older));
    try std.testing.expectEqualStrings("alice", (try store.matchHostmask("#mesh", "x!u@a.test")).?.set_by);

    // Equal HLC is broken by the higher origin_node, so both directions of a
    // concurrent write agree on the same winner.
    var tie_low = base;
    tie_low.origin_node = 6;
    tie_low.set_by = "loser";
    try std.testing.expectEqual(ApplyOutcome.stale, try store.applyRemote(tie_low));

    var tie_high = base;
    tie_high.origin_node = 8;
    tie_high.set_by = "winner";
    try std.testing.expectEqual(ApplyOutcome.applied, try store.applyRemote(tie_high));
    try std.testing.expectEqualStrings("winner", (try store.matchHostmask("#mesh", "x!u@a.test")).?.set_by);
}

test "ACCESS tombstone keeps a revoked grant from being resurrected" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    const grant = RemoteFact{
        .present = true,
        .channel = "#mesh",
        .level = .grant,
        .mask = "*!*@b.test",
        .set_by = "alice",
        .hlc = 200,
        .origin_node = 3,
    };
    try std.testing.expectEqual(ApplyOutcome.applied, try store.applyRemote(grant));

    var revoke = grant;
    revoke.present = false;
    revoke.hlc = 300;
    try std.testing.expectEqual(ApplyOutcome.deleted, try store.applyRemote(revoke));
    try std.testing.expectEqual(@as(?EntryView, null), try store.matchHostmask("#mesh", "x!u@b.test"));

    // The original ADD re-arriving from a slow peer must NOT bring the grant
    // back — this is the privilege-resurrection bug the tombstone exists for.
    try std.testing.expectEqual(ApplyOutcome.stale, try store.applyRemote(grant));
    try std.testing.expectEqual(@as(?EntryView, null), try store.matchHostmask("#mesh", "x!u@b.test"));

    // A genuinely NEWER re-grant still wins, and clears the marker.
    var regrant = grant;
    regrant.hlc = 400;
    regrant.set_by = "bob";
    try std.testing.expectEqual(ApplyOutcome.applied, try store.applyRemote(regrant));
    try std.testing.expectEqualStrings("bob", (try store.matchHostmask("#mesh", "x!u@b.test")).?.set_by);
}

test "ACCESS applyRemote order does not change the converged state" {
    const a = RemoteFact{ .present = true, .channel = "#c", .level = .voice, .mask = "*!*@1.test", .set_by = "a", .hlc = 10, .origin_node = 1 };
    const b = RemoteFact{ .present = true, .channel = "#c", .level = .voice, .mask = "*!*@1.test", .set_by = "b", .hlc = 20, .origin_node = 2 };
    const c = RemoteFact{ .present = false, .channel = "#c", .level = .host, .mask = "*!*@2.test", .hlc = 15, .origin_node = 5 };

    var forward = AccessStore.init(std.testing.allocator);
    defer forward.deinit();
    _ = try forward.applyRemote(a);
    _ = try forward.applyRemote(b);
    _ = try forward.applyRemote(c);

    var reverse = AccessStore.init(std.testing.allocator);
    defer reverse.deinit();
    _ = try reverse.applyRemote(c);
    _ = try reverse.applyRemote(b);
    _ = try reverse.applyRemote(a);

    const lhs = (try forward.matchHostmask("#c", "n!u@1.test")).?;
    const rhs = (try reverse.matchHostmask("#c", "n!u@1.test")).?;
    try std.testing.expectEqualStrings(lhs.set_by, rhs.set_by);
    try std.testing.expectEqualStrings("b", rhs.set_by);
    try std.testing.expectEqual(@as(?EntryView, null), try forward.matchHostmask("#c", "n!u@2.test"));
    try std.testing.expectEqual(@as(?EntryView, null), try reverse.matchHostmask("#c", "n!u@2.test"));
}

test "ACCESS applyRemote enforces field bounds on peer input" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    var channel_buf: [200]u8 = undefined;
    @memset(&channel_buf, 'a');
    channel_buf[0] = '#';
    try std.testing.expectError(error.InvalidChannel, store.applyRemote(.{
        .present = true,
        .channel = &channel_buf,
        .level = .voice,
        .mask = "*!*@h.test",
        .set_by = "a",
        .hlc = 1,
        .origin_node = 1,
    }));

    var mask_buf: [400]u8 = undefined;
    @memset(&mask_buf, 'a');
    try std.testing.expectError(error.MaskTooLong, store.applyRemote(.{
        .present = true,
        .channel = "#ok",
        .level = .voice,
        .mask = &mask_buf,
        .set_by = "a",
        .hlc = 1,
        .origin_node = 1,
    }));
}

test "ACCESS listPage walks every entry exactly once" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var mask_buf: [32]u8 = undefined;
        const mask = try std.fmt.bufPrint(&mask_buf, "n{d}!*@h.test", .{i});
        try store.add("#page", .voice, mask, "oper", null);
    }

    var views: [4]EntryView = undefined;
    var seen: usize = 0;
    var offset: usize = 0;
    var pages: usize = 0;
    while (true) {
        const page = try store.listPage(.{ .channel = "#page" }, offset, &views);
        try std.testing.expectEqual(@as(usize, 10), page.total);
        seen += page.rows.len;
        pages += 1;
        offset = page.next_offset orelse break;
        try std.testing.expect(offset > 0);
        try std.testing.expect(pages < 10); // a cursor that never advances would spin
    }
    try std.testing.expectEqual(@as(usize, 10), seen);
    try std.testing.expectEqual(@as(usize, 3), pages);

    // An offset past the end is an empty LAST page, never a loop.
    const past = try store.listPage(.{ .channel = "#page" }, 99, &views);
    try std.testing.expectEqual(@as(usize, 0), past.rows.len);
    try std.testing.expectEqual(@as(?usize, null), past.next_offset);
}

test "ACCESS copyFrom seeds a template channel in merge and replace modes" {
    var store = AccessStore.init(std.testing.allocator);
    defer store.deinit();

    try store.add("#tmpl", .host, "*!*@staff.test", "alice", null);
    try store.add("#tmpl", .voice, "*!*@member.test", "alice", null);
    try store.add("#live", .deny, "*!*@spam.test", "bob", null);

    const merged = try store.copyFrom("#live", "#tmpl", .merge);
    try std.testing.expectEqual(@as(usize, 2), merged.copied);
    try std.testing.expectEqual(@as(usize, 0), merged.removed);
    // MERGE keeps what the destination already enforced.
    try std.testing.expectEqual(Level.deny, (try store.matchHostmask("#live", "x!u@spam.test")).?.level);
    try std.testing.expectEqual(Level.host, (try store.matchHostmask("#live", "x!u@staff.test")).?.level);

    const replaced = try store.copyFrom("#live", "#tmpl", .replace);
    try std.testing.expectEqual(@as(usize, 2), replaced.copied);
    try std.testing.expectEqual(@as(usize, 3), replaced.removed);
    // REPLACE drops the destination's own entries first.
    try std.testing.expectEqual(@as(?EntryView, null), try store.matchHostmask("#live", "x!u@spam.test"));
    try std.testing.expectEqual(Level.host, (try store.matchHostmask("#live", "x!u@staff.test")).?.level);

    // Copying a channel onto itself would be a self-clearing no-op in REPLACE.
    try std.testing.expectError(error.InvalidChannel, store.copyFrom("#live", "#LIVE", .merge));
}

test "ACCESS parses the LIST page cursor and COPY subcommand" {
    // A bare trailing cursor pages an unfiltered list: no Level token is numeric,
    // so this is unambiguous.
    const bare = (try parse(&.{ "#c", "LIST", "64" })).list;
    try std.testing.expectEqual(@as(usize, 64), bare.offset);
    try std.testing.expectEqual(@as(?Level, null), bare.level);

    const filtered = (try parse(&.{ "#c", "LIST", "VOICE", "128" })).list;
    try std.testing.expectEqual(@as(usize, 128), filtered.offset);
    try std.testing.expectEqual(@as(?Level, .voice), filtered.level);

    // A mask is not a cursor, and the default page starts at zero.
    const masked = (try parse(&.{ "#c", "LIST", "VOICE", "*!*@1234.test" })).list;
    try std.testing.expectEqual(@as(usize, 0), masked.offset);
    try std.testing.expectEqualStrings("*!*@1234.test", masked.mask.?);

    // Hostile cursors are refused rather than clamped.
    try std.testing.expectError(error.TooManyParameters, parse(&.{ "#c", "LIST", "999999999" }));
    try std.testing.expectError(error.InvalidDuration, parse(&.{ "#c", "LIST", "VOICE", "*!*@h", "999999999999999999999999" }));

    const merge = (try parse(&.{ "#dst", "COPY", "#src" })).copy;
    try std.testing.expectEqualStrings("#dst", merge.destination);
    try std.testing.expectEqualStrings("#src", merge.source);
    try std.testing.expectEqual(AccessStore.CopyMode.merge, merge.mode);

    const replace = (try parse(&.{ "#dst", "COPY", "#src", "REPLACE" })).copy;
    try std.testing.expectEqual(AccessStore.CopyMode.replace, replace.mode);
}
