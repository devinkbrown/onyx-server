// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded, node-wide ring of recent Event Spine events, backing `EVENT REPLAY`
//! so an operator who just connected (or just subscribed) can see what they
//! missed. One shared instance per node, written from ANY reactor thread (a
//! connect/kill/ward can be raised on any shard) and from the mesh drain, so
//! every push/collect takes the internal mutex. Strings are copied into fixed
//! in-slot buffers (no external ownership), and the ring serializes to a small
//! snapshot file so history survives a USR2 hot-upgrade and a cold restart.
const std = @import("std");
const event_spine = @import("event_spine.zig");
const rwlock = @import("../substrate/rwlock.zig");

pub const max_origin_len: usize = 64;
/// Wide enough for a signed MEDIA E2EE handshake (~405 bytes) and a max
/// GROUPKEY line. A 400-byte slot drops that live call event before delivery.
pub const max_message_len: usize = 1024;
pub const EventId = [16]u8;

pub const StableEvent = struct {
    event_id: EventId,
    category: u8,
    severity: u8,
    origin_ts_unix_ms: i64,
    origin: []const u8,
    message: []const u8,
};

pub const StableIngestResult = enum {
    inserted,
    exact_duplicate,
    equivocation,
};

pub const StableIngestError = error{
    OriginTooLong,
    MessageTooLong,
};

pub const SerializeError = std.Io.Writer.Error || error{InvalidState};

/// One retained event. Byte layout is stable and little-endian on disk (see
/// `serializeInto`); `category`/`severity` are raw ordinals validated on read.
pub const StoredEvent = struct {
    event_id: EventId = @splat(0),
    has_event_id: bool = false,
    category: u8,
    severity: u8,
    ts_unix_ms: i64,
    origin_buf: [max_origin_len]u8 = undefined,
    origin_len: u16 = 0,
    msg_buf: [max_message_len]u8 = undefined,
    msg_len: u16 = 0,

    pub fn origin(self: *const StoredEvent) []const u8 {
        return self.origin_buf[0..self.origin_len];
    }

    pub fn message(self: *const StoredEvent) []const u8 {
        return self.msg_buf[0..self.msg_len];
    }

    pub fn eventId(self: *const StoredEvent) ?EventId {
        return if (self.has_event_id) self.event_id else null;
    }

    /// The category as an enum, or null if the stored ordinal is out of range
    /// (a forward-compat / corrupt-snapshot guard — callers skip such rows).
    pub fn categoryEnum(self: *const StoredEvent) ?event_spine.EventCategory {
        const n = @typeInfo(event_spine.EventCategory).@"enum".field_names.len;
        if (self.category >= n) return null;
        return @enumFromInt(self.category);
    }

    /// The severity as an enum, clamped to the top defined level.
    pub fn severityEnum(self: *const StoredEvent) event_spine.EventSeverity {
        const max = @as(u8, @typeInfo(event_spine.EventSeverity).@"enum".field_names.len - 1);
        return @enumFromInt(@min(self.severity, max));
    }

    fn set(cat: u8, sev: u8, ts: i64, origin_s: []const u8, message_s: []const u8) StoredEvent {
        var ev = StoredEvent{ .category = cat, .severity = sev, .ts_unix_ms = ts };
        const on = @min(origin_s.len, max_origin_len);
        @memcpy(ev.origin_buf[0..on], origin_s[0..on]);
        ev.origin_len = @intCast(on);
        const mn = @min(message_s.len, max_message_len);
        @memcpy(ev.msg_buf[0..mn], message_s[0..mn]);
        ev.msg_len = @intCast(mn);
        return ev;
    }

    fn setStable(event: StableEvent) StoredEvent {
        var stored = set(
            event.category,
            event.severity,
            event.origin_ts_unix_ms,
            event.origin,
            event.message,
        );
        stored.event_id = event.event_id;
        stored.has_event_id = true;
        return stored;
    }

    fn matchesStable(self: *const StoredEvent, event: StableEvent) bool {
        return self.category == event.category and
            self.severity == event.severity and
            self.ts_unix_ms == event.origin_ts_unix_ms and
            std.mem.eql(u8, self.origin(), event.origin) and
            std.mem.eql(u8, self.message(), event.message);
    }
};

pub const category_count = @typeInfo(event_spine.EventCategory).@"enum".field_names.len;
pub const severity_count = @typeInfo(event_spine.EventSeverity).@"enum".field_names.len;

/// Lock-free per-category / per-severity Event Spine counters backing
/// `EVENT STATS`. Incremented from any reactor + the mesh drain (atomic adds),
/// read for the stats reply. Process-lifetime (not persisted — a running total
/// resets on restart, which is the useful semantics for "since this boot").
pub const EventStats = struct {
    by_category: [category_count]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    by_severity: [severity_count]std.atomic.Value(u64) = @splat(std.atomic.Value(u64).init(0)),
    total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn record(self: *EventStats, cat: u8, sev: u8) void {
        if (cat < category_count) _ = self.by_category[cat].fetchAdd(1, .monotonic);
        if (sev < severity_count) _ = self.by_severity[sev].fetchAdd(1, .monotonic);
        _ = self.total.fetchAdd(1, .monotonic);
    }

    pub fn categoryCount(self: *const EventStats, cat: usize) u64 {
        return self.by_category[cat].load(.monotonic);
    }
    pub fn severityCount(self: *const EventStats, sev: usize) u64 {
        return self.by_severity[sev].load(.monotonic);
    }
    pub fn totalCount(self: *const EventStats) u64 {
        return self.total.load(.monotonic);
    }
};

const snapshot_magic = "OEH1";
const legacy_snapshot_version: u8 = 1;
const snapshot_version: u8 = 2;
const snapshot_flag_has_event_id: u8 = 1 << 0;
const zero_event_id: EventId = @splat(0);

pub fn EventHistory(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        /// Fully parsed, self-contained OEH1 ring image. It deliberately does
        /// not contain a mutex: moving a live `RwLock` would copy atomic lock
        /// state and can strand waiters. Stage this value first, then publish it
        /// with `publishCheckpoint`, which copies only ring fields under the
        /// destination's existing lock.
        pub const CheckpointState = struct {
            items: [capacity]StoredEvent,
            start: usize,
            count: usize,
        };

        items: [capacity]StoredEvent = undefined,
        start: usize = 0,
        count: usize = 0,
        mu: rwlock.RwLock = .{},

        /// Legacy local append (thread-safe). It intentionally has no stable
        /// event id, preserves its historical truncation behavior, and does not
        /// perform replay classification. Oldest is evicted when full.
        pub fn record(
            self: *Self,
            category: u8,
            severity: u8,
            ts_unix_ms: i64,
            origin_s: []const u8,
            message_s: []const u8,
        ) void {
            if (capacity == 0) return;
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            self.appendLocked(StoredEvent.set(category, severity, ts_unix_ms, origin_s, message_s));
        }

        /// Conflict-aware OEVT v2 ingestion keyed by the complete 16-byte event
        /// id. Equality covers category, severity, origin timestamp, origin and
        /// message. Exact duplicates and equivocations are allocation-free and
        /// leave ring contents, length and eviction cursor unchanged.
        pub fn ingestStableEvent(self: *Self, event: StableEvent) StableIngestError!StableIngestResult {
            if (event.origin.len > max_origin_len) return error.OriginTooLong;
            if (event.message.len > max_message_len) return error.MessageTooLong;
            if (capacity == 0) return .inserted;

            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            var found_exact = false;
            var logical: usize = 0;
            while (logical < self.count) : (logical += 1) {
                const stored = &self.items[(self.start + logical) % capacity];
                if (!stored.has_event_id or !std.mem.eql(u8, &stored.event_id, &event.event_id)) continue;
                if (!stored.matchesStable(event)) return .equivocation;
                found_exact = true;
            }
            if (found_exact) return .exact_duplicate;
            self.appendLocked(StoredEvent.setStable(event));
            return .inserted;
        }

        fn appendLocked(self: *Self, event: StoredEvent) void {
            const slot = if (self.count < capacity) blk: {
                const i = (self.start + self.count) % capacity;
                self.count += 1;
                break :blk i;
            } else blk: {
                const i = self.start;
                self.start = (self.start + 1) % capacity;
                break :blk i;
            };
            self.items[slot] = event;
        }

        /// Copy up to `out.len` recent events into `out`, NEWEST FIRST, keeping
        /// only those matching `filter_category` (null = any) with severity ≥
        /// `min_severity` (raw ordinal). Returns the number written. Done under
        /// the lock into caller storage so rendering/delivery happens lock-free.
        pub fn collect(
            self: *Self,
            filter_category: ?u8,
            min_severity: u8,
            out: []StoredEvent,
        ) usize {
            if (out.len == 0) return 0;
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            var written: usize = 0;
            var scanned: usize = 0;
            // Walk newest→oldest: index count-1 down to 0 in ring order.
            while (scanned < self.count and written < out.len) : (scanned += 1) {
                const logical = self.count - 1 - scanned;
                const ev = self.items[(self.start + logical) % capacity];
                if (filter_category) |fc| {
                    if (ev.category != fc) continue;
                }
                if (ev.severity < min_severity) continue;
                out[written] = ev;
                written += 1;
            }
            return written;
        }

        pub fn len(self: *Self) usize {
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            return self.count;
        }

        /// Serialize the current OEH1/v2 ring OLDEST-FIRST. Every row carries a
        /// canonical id-presence flag and the complete 16-byte id. This takes
        /// the lock so concurrent ingestion cannot tear a row, and refuses to
        /// emit any impossible live image containing a repeated stable id.
        pub fn serializeInto(self: *Self, w: *std.Io.Writer) SerializeError!void {
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            if (!self.validateCurrentImageLocked()) return error.InvalidState;
            try w.writeAll(snapshot_magic);
            try w.writeByte(snapshot_version);
            try putU32(w, @intCast(self.count));
            var i: usize = 0;
            while (i < self.count) : (i += 1) {
                const ev = self.items[(self.start + i) % capacity];
                try w.writeByte(if (ev.has_event_id) snapshot_flag_has_event_id else 0);
                try w.writeAll(&ev.event_id);
                try w.writeByte(ev.category);
                try w.writeByte(ev.severity);
                try putI64(w, ev.ts_unix_ms);
                try putBytes(w, ev.origin());
                try putBytes(w, ev.message());
            }
        }

        fn validateCurrentImageLocked(self: *const Self) bool {
            if (self.count > capacity) return false;
            if (self.count == 0) return self.start == 0;
            if (self.start >= capacity) return false;
            var i: usize = 0;
            while (i < self.count) : (i += 1) {
                const event = &self.items[(self.start + i) % capacity];
                if (event.origin_len > max_origin_len or event.msg_len > max_message_len) return false;
                if (!event.has_event_id) {
                    if (!std.mem.eql(u8, &event.event_id, &zero_event_id)) return false;
                    continue;
                }
                var prior: usize = 0;
                while (prior < i) : (prior += 1) {
                    const earlier = &self.items[(self.start + prior) % capacity];
                    if (earlier.has_event_id and std.mem.eql(u8, &earlier.event_id, &event.event_id))
                        return false;
                }
            }
            return true;
        }

        /// Parse a cold-restart snapshot without touching a live ring. Current
        /// v2 images remain exact; legacy v1 images may be truncated to retain
        /// their newest rows for the historical best-effort cold-load policy.
        pub fn restoreCheckpoint(data: []const u8) ?CheckpointState {
            if (data.len < 5) return null;
            return switch (data[4]) {
                legacy_snapshot_version => restoreCheckpointImpl(data, legacy_snapshot_version, true),
                snapshot_version => restoreCheckpointImpl(data, snapshot_version, false),
                else => null,
            };
        }

        /// Explicitly isolated OEH1/v1 cold-load migration path. Stable event
        /// ids did not exist in this schema, so restored rows remain legacy and
        /// do not participate in v2 exact-once classification.
        pub fn restoreLegacyColdCheckpoint(data: []const u8) ?CheckpointState {
            return restoreCheckpointImpl(data, legacy_snapshot_version, true);
        }

        /// Parse only the exact current OEH1/v2 Helix handoff. Legacy v1,
        /// over-capacity images, noncanonical id flags and every repeated stable
        /// id are rejected rather than silently weakening mesh continuity.
        pub fn restoreHelixCheckpoint(data: []const u8) ?CheckpointState {
            return restoreCheckpointImpl(data, snapshot_version, false);
        }

        fn restoreCheckpointImpl(data: []const u8, expected_version: u8, allow_truncate: bool) ?CheckpointState {
            if (data.len < 5 or !std.mem.eql(u8, data[0..4], snapshot_magic)) return null;
            if (data[4] != expected_version) return null;
            var c = Cursor{ .b = data, .i = 5 };
            const n = c.readU32() orelse return null;
            if (!allow_truncate and n > capacity) return null;
            var staged: [capacity]StoredEvent = undefined;
            var staged_start: usize = 0;
            var staged_count: usize = 0;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                var event_id: EventId = @splat(0);
                var has_event_id = false;
                if (expected_version == snapshot_version) {
                    const flags = c.byte() orelse return null;
                    if (flags & ~snapshot_flag_has_event_id != 0) return null;
                    const id = c.fixed(event_id.len) orelse return null;
                    @memcpy(&event_id, id);
                    has_event_id = flags & snapshot_flag_has_event_id != 0;
                    if (!has_event_id and !std.mem.eql(u8, &event_id, &zero_event_id)) return null;
                }
                const cat = c.byte() orelse return null;
                const sev = c.byte() orelse return null;
                const ts = c.readI64() orelse return null;
                const origin_s = c.bytes() orelse return null;
                const message_s = c.bytes() orelse return null;
                // serializeInto never truncates: accepting wider fields here
                // would make restore non-exact and hide a corrupt writer.
                if (origin_s.len > max_origin_len or message_s.len > max_message_len) return null;
                if (capacity == 0) continue;
                var stored = StoredEvent.set(cat, sev, ts, origin_s, message_s);
                if (has_event_id) {
                    var prior: usize = 0;
                    while (prior < staged_count) : (prior += 1) {
                        const earlier = &staged[(staged_start + prior) % capacity];
                        if (earlier.has_event_id and std.mem.eql(u8, &earlier.event_id, &event_id))
                            return null;
                    }
                    stored.event_id = event_id;
                    stored.has_event_id = true;
                }
                if (staged_count >= capacity) {
                    // A snapshot larger than this build's ring: keep the newest
                    // `capacity` by evicting oldest (mirrors record()).
                    staged[staged_start] = stored;
                    staged_start = (staged_start + 1) % capacity;
                } else {
                    staged[staged_count] = stored;
                    staged_count += 1;
                }
            }
            if (c.i != data.len) return null;
            return .{ .items = staged, .start = staged_start, .count = staged_count };
        }

        /// No-fail publication of a previously validated image. The live mutex
        /// never moves and protects the one visible transition from old ring to
        /// new ring. Inactive undefined slots are never read or copied.
        pub fn publishCheckpoint(self: *Self, checkpoint: *const CheckpointState) void {
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            if (checkpoint.count == capacity) {
                self.items = checkpoint.items;
            } else if (checkpoint.count != 0) {
                @memcpy(self.items[0..checkpoint.count], checkpoint.items[0..checkpoint.count]);
            }
            self.start = checkpoint.start;
            self.count = checkpoint.count;
        }

        /// Boot-friendly one-shot wrapper. Parsing happens before locking; a
        /// malformed/truncated snapshot leaves the prior ring untouched.
        pub fn load(self: *Self, data: []const u8) bool {
            const checkpoint = restoreCheckpoint(data) orelse return false;
            self.publishCheckpoint(&checkpoint);
            return true;
        }
    };
}

fn putU32(w: *std.Io.Writer, v: u32) std.Io.Writer.Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    try w.writeAll(&b);
}

fn putI64(w: *std.Io.Writer, v: i64) std.Io.Writer.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(i64, &b, v, .little);
    try w.writeAll(&b);
}

fn putBytes(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const n: u16 = @intCast(@min(s.len, std.math.maxInt(u16)));
    try putU32(w, n);
    try w.writeAll(s[0..n]);
}

const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) ?u8 {
        if (c.i + 1 > c.b.len) return null;
        const v = c.b[c.i];
        c.i += 1;
        return v;
    }
    fn readU32(c: *Cursor) ?u32 {
        if (c.i + 4 > c.b.len) return null;
        const v = std.mem.readInt(u32, c.b[c.i..][0..4], .little);
        c.i += 4;
        return v;
    }
    fn readI64(c: *Cursor) ?i64 {
        if (c.i + 8 > c.b.len) return null;
        const v = std.mem.readInt(i64, c.b[c.i..][0..8], .little);
        c.i += 8;
        return v;
    }
    fn fixed(c: *Cursor, n: usize) ?[]const u8 {
        if (c.i > c.b.len or n > c.b.len - c.i) return null;
        const s = c.b[c.i .. c.i + n];
        c.i += n;
        return s;
    }
    fn bytes(c: *Cursor) ?[]const u8 {
        const n = c.readU32() orelse return null;
        if (c.i > c.b.len or n > c.b.len - c.i) return null;
        const s = c.b[c.i .. c.i + n];
        c.i += n;
        return s;
    }
};

test "EventStats counts per category, per severity, and total" {
    var s = EventStats{};
    s.record(7, 3); // category 7, severity 3
    s.record(7, 1); // category 7, severity 1
    s.record(3, 3); // category 3, severity 3
    try std.testing.expectEqual(@as(u64, 3), s.totalCount());
    try std.testing.expectEqual(@as(u64, 2), s.categoryCount(7));
    try std.testing.expectEqual(@as(u64, 1), s.categoryCount(3));
    try std.testing.expectEqual(@as(u64, 0), s.categoryCount(0));
    try std.testing.expectEqual(@as(u64, 2), s.severityCount(3));
    try std.testing.expectEqual(@as(u64, 1), s.severityCount(1));
    // Out-of-range ordinals still bump the total but no per-slot counter.
    s.record(250, 250);
    try std.testing.expectEqual(@as(u64, 4), s.totalCount());
}

test "legacy record preserves append and eviction behavior without stable ids" {
    var h = EventHistory(3){};
    h.record(0, 2, 100, "a.node", "one");
    h.record(1, 2, 200, "a.node", "two");
    h.record(2, 2, 300, "a.node", "three");
    h.record(3, 2, 400, "a.node", "four"); // evicts "one"

    var out: [8]StoredEvent = undefined;
    const n = h.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("four", out[0].message());
    try std.testing.expectEqualStrings("three", out[1].message());
    try std.testing.expectEqualStrings("two", out[2].message());
    for (out[0..n]) |event| try std.testing.expect(event.eventId() == null);
}

test "collect filters by category and minimum severity" {
    var h = EventHistory(8){};
    h.record(7, 1, 1, "n", "kill-info"); // category 7, severity 1 (info)
    h.record(7, 3, 2, "n", "kill-warn"); // category 7, severity 3 (warn)
    h.record(3, 3, 3, "n", "flood-warn"); // category 3

    var out: [8]StoredEvent = undefined;
    // Category 7 only, severity ≥ warn(3): just the warn kill.
    const n = h.collect(7, 3, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("kill-warn", out[0].message());

    // Category 7, any severity: both kills, newest first.
    const n2 = h.collect(7, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), n2);
    try std.testing.expectEqualStrings("kill-warn", out[0].message());
    try std.testing.expectEqualStrings("kill-info", out[1].message());
}

test "stable event ingestion is exact-once and non-inserts are byte-exact" {
    const History = EventHistory(3);
    var history = History{};
    const id = testEventId(0x11);
    const original = StableEvent{
        .event_id = id,
        .category = 7,
        .severity = 3,
        .origin_ts_unix_ms = 1234,
        .origin = "node.a",
        .message = "client connected",
    };
    try std.testing.expectEqual(StableIngestResult.inserted, try history.ingestStableEvent(original));
    const before_start = history.start;
    const before_count = history.count;
    var before_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer before_writer.deinit();
    try history.serializeInto(&before_writer.writer);

    try std.testing.expectEqual(StableIngestResult.exact_duplicate, try history.ingestStableEvent(original));
    const conflicts = [_]StableEvent{
        .{ .event_id = id, .category = 8, .severity = 3, .origin_ts_unix_ms = 1234, .origin = "node.a", .message = "client connected" },
        .{ .event_id = id, .category = 7, .severity = 4, .origin_ts_unix_ms = 1234, .origin = "node.a", .message = "client connected" },
        .{ .event_id = id, .category = 7, .severity = 3, .origin_ts_unix_ms = 1235, .origin = "node.a", .message = "client connected" },
        .{ .event_id = id, .category = 7, .severity = 3, .origin_ts_unix_ms = 1234, .origin = "node.b", .message = "client connected" },
        .{ .event_id = id, .category = 7, .severity = 3, .origin_ts_unix_ms = 1234, .origin = "node.a", .message = "different" },
    };
    for (conflicts) |conflict| {
        try std.testing.expectEqual(StableIngestResult.equivocation, try history.ingestStableEvent(conflict));
        try std.testing.expectEqual(before_start, history.start);
        try std.testing.expectEqual(before_count, history.count);
        var after_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
        defer after_writer.deinit();
        try history.serializeInto(&after_writer.writer);
        try std.testing.expectEqualSlices(u8, before_writer.written(), after_writer.written());
    }

    const oversized_origin: [max_origin_len + 1]u8 = @splat('o');
    var too_wide = original;
    too_wide.origin = &oversized_origin;
    try std.testing.expectError(error.OriginTooLong, history.ingestStableEvent(too_wide));
    const oversized_message: [max_message_len + 1]u8 = @splat('m');
    too_wide = original;
    too_wide.message = &oversized_message;
    try std.testing.expectError(error.MessageTooLong, history.ingestStableEvent(too_wide));
    try std.testing.expectEqual(before_start, history.start);
    try std.testing.expectEqual(before_count, history.count);
}

test "stable event ingestion preserves the bounded eviction window" {
    const History = EventHistory(2);
    var history = History{};
    const first = StableEvent{ .event_id = testEventId(1), .category = 1, .severity = 1, .origin_ts_unix_ms = 1, .origin = "n", .message = "one" };
    const second = StableEvent{ .event_id = testEventId(2), .category = 1, .severity = 1, .origin_ts_unix_ms = 2, .origin = "n", .message = "two" };
    const third = StableEvent{ .event_id = testEventId(3), .category = 1, .severity = 1, .origin_ts_unix_ms = 3, .origin = "n", .message = "three" };
    try std.testing.expectEqual(StableIngestResult.inserted, try history.ingestStableEvent(first));
    try std.testing.expectEqual(StableIngestResult.inserted, try history.ingestStableEvent(second));
    try std.testing.expectEqual(StableIngestResult.exact_duplicate, try history.ingestStableEvent(first));
    try std.testing.expectEqual(StableIngestResult.inserted, try history.ingestStableEvent(third));
    // The evicted id leaves the exact-once memory window and can be retained anew.
    try std.testing.expectEqual(StableIngestResult.inserted, try history.ingestStableEvent(first));

    var out: [2]StoredEvent = undefined;
    const count = history.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualSlices(u8, &first.event_id, &out[0].eventId().?);
    try std.testing.expectEqualSlices(u8, &third.event_id, &out[1].eventId().?);
}

test "stable event ingestion serializes concurrent duplicates and equivocations" {
    const History = EventHistory(8);
    const Worker = struct {
        fn run(history: *History, event: StableEvent, result: *StableIngestResult) void {
            result.* = history.ingestStableEvent(event) catch unreachable;
        }
    };

    var duplicate_history = History{};
    const duplicate = StableEvent{ .event_id = testEventId(0x18), .category = 1, .severity = 2, .origin_ts_unix_ms = 10, .origin = "mesh", .message = "same" };
    var duplicate_results: [8]StableIngestResult = undefined;
    var duplicate_threads: [8]std.Thread = undefined;
    for (&duplicate_threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &duplicate_history, duplicate, &duplicate_results[index] });
    }
    for (&duplicate_threads) |*thread| thread.join();
    var inserted: usize = 0;
    var exact: usize = 0;
    for (duplicate_results) |result| switch (result) {
        .inserted => inserted += 1,
        .exact_duplicate => exact += 1,
        .equivocation => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), inserted);
    try std.testing.expectEqual(@as(usize, 7), exact);
    try std.testing.expectEqual(@as(usize, 1), duplicate_history.len());

    var conflict_history = History{};
    const first = StableEvent{ .event_id = testEventId(0x19), .category = 3, .severity = 4, .origin_ts_unix_ms = 20, .origin = "mesh.a", .message = "first" };
    const second = StableEvent{ .event_id = first.event_id, .category = 3, .severity = 4, .origin_ts_unix_ms = 20, .origin = "mesh.b", .message = "second" };
    var conflict_results: [8]StableIngestResult = undefined;
    var conflict_threads: [8]std.Thread = undefined;
    for (&conflict_threads, 0..) |*thread, index| {
        const event = if (index % 2 == 0) first else second;
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &conflict_history, event, &conflict_results[index] });
    }
    for (&conflict_threads) |*thread| thread.join();
    inserted = 0;
    exact = 0;
    var equivocations: usize = 0;
    for (conflict_results) |result| switch (result) {
        .inserted => inserted += 1,
        .exact_duplicate => exact += 1,
        .equivocation => equivocations += 1,
    };
    try std.testing.expectEqual(@as(usize, 1), inserted);
    try std.testing.expectEqual(@as(usize, 3), exact);
    try std.testing.expectEqual(@as(usize, 4), equivocations);
    try std.testing.expectEqual(@as(usize, 1), conflict_history.len());
}

test "current checkpoint preserves stable ids and legacy identity absence exactly" {
    const History = EventHistory(4);
    var source = History{};
    const first = StableEvent{ .event_id = testEventId(0x21), .category = 1, .severity = 2, .origin_ts_unix_ms = 10, .origin = "node", .message = "one" };
    const second = StableEvent{ .event_id = testEventId(0x22), .category = 3, .severity = 4, .origin_ts_unix_ms = 30, .origin = "mesh", .message = "three" };
    _ = try source.ingestStableEvent(first);
    source.record(2, 3, 20, "legacy", "two");
    _ = try source.ingestStableEvent(second);

    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try source.serializeInto(&writer.writer);
    try std.testing.expectEqual(snapshot_version, writer.written()[4]);
    const checkpoint = History.restoreHelixCheckpoint(writer.written()) orelse
        return error.TestUnexpectedResult;
    var restored = History{};
    restored.publishCheckpoint(&checkpoint);

    var out: [4]StoredEvent = undefined;
    const count = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualSlices(u8, &second.event_id, &out[0].eventId().?);
    try std.testing.expect(out[1].eventId() == null);
    try std.testing.expectEqualSlices(u8, &first.event_id, &out[2].eventId().?);

    var reencoded = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer reencoded.deinit();
    try restored.serializeInto(&reencoded.writer);
    try std.testing.expectEqualSlices(u8, writer.written(), reencoded.written());
    try std.testing.expect(History.restoreCheckpoint(writer.written()) != null);
    try std.testing.expect(History.restoreLegacyColdCheckpoint(writer.written()) == null);
}

test "zero stable id remains distinct from a legacy row without identity" {
    const History = EventHistory(3);
    var source = History{};
    const stable = StableEvent{
        .event_id = @splat(0),
        .category = 1,
        .severity = 2,
        .origin_ts_unix_ms = 10,
        .origin = "mesh",
        .message = "zero is still an id",
    };
    try std.testing.expectEqual(StableIngestResult.inserted, try source.ingestStableEvent(stable));
    source.record(2, 3, 20, "local", "no stable id");
    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try source.serializeInto(&writer.writer);
    const checkpoint = History.restoreHelixCheckpoint(writer.written()) orelse
        return error.TestUnexpectedResult;
    var restored = History{};
    restored.publishCheckpoint(&checkpoint);

    var out: [3]StoredEvent = undefined;
    const count = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expect(out[0].eventId() == null);
    const restored_id = out[1].eventId() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &stable.event_id, &restored_id);
    const before_start = restored.start;
    const before_count = restored.count;
    try std.testing.expectEqual(StableIngestResult.exact_duplicate, try restored.ingestStableEvent(stable));
    var conflict = stable;
    conflict.message = "conflicting zero id";
    try std.testing.expectEqual(StableIngestResult.equivocation, try restored.ingestStableEvent(conflict));
    try std.testing.expectEqual(before_start, restored.start);
    try std.testing.expectEqual(before_count, restored.count);
}

test "current checkpoint rejects repeated stable ids and noncanonical identity fields" {
    const History = EventHistory(3);
    var source = History{};
    _ = try source.ingestStableEvent(.{ .event_id = testEventId(0x31), .category = 1, .severity = 1, .origin_ts_unix_ms = 1, .origin = "aa", .message = "one" });
    _ = try source.ingestStableEvent(.{ .event_id = testEventId(0x32), .category = 2, .severity = 2, .origin_ts_unix_ms = 2, .origin = "bb", .message = "two" });
    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try source.serializeInto(&writer.writer);
    const wire = writer.written();
    const first_offset: usize = 9;
    const second_offset = nextCurrentEventOffset(wire, first_offset) orelse return error.TestUnexpectedResult;
    const end_offset = nextCurrentEventOffset(wire, second_offset) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(wire.len, end_offset);

    const conflicting = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(conflicting);
    @memcpy(conflicting[second_offset + 1 ..][0..16], conflicting[first_offset + 1 ..][0..16]);
    try std.testing.expect(History.restoreHelixCheckpoint(conflicting) == null);
    try std.testing.expect(History.restoreCheckpoint(conflicting) == null);

    var live = History{};
    _ = try live.ingestStableEvent(.{ .event_id = testEventId(0x40), .category = 9, .severity = 3, .origin_ts_unix_ms = 99, .origin = "live", .message = "sentinel" });
    var live_before = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer live_before.deinit();
    try live.serializeInto(&live_before.writer);
    try std.testing.expect(!live.load(conflicting));
    var live_after = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer live_after.deinit();
    try live.serializeInto(&live_after.writer);
    try std.testing.expectEqualSlices(u8, live_before.written(), live_after.written());

    const duplicate = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(duplicate);
    const first_len = second_offset - first_offset;
    try std.testing.expectEqual(first_len, end_offset - second_offset);
    @memcpy(duplicate[second_offset..end_offset], duplicate[first_offset..second_offset]);
    try std.testing.expect(History.restoreHelixCheckpoint(duplicate) == null);

    var legacy_row = History{};
    legacy_row.record(1, 1, 1, "n", "legacy");
    var legacy_current_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer legacy_current_writer.deinit();
    try legacy_row.serializeInto(&legacy_current_writer.writer);
    const noncanonical_absent = try std.testing.allocator.dupe(u8, legacy_current_writer.written());
    defer std.testing.allocator.free(noncanonical_absent);
    noncanonical_absent[10] = 1; // flag is absent, so all 16 id bytes must be zero.
    try std.testing.expect(History.restoreHelixCheckpoint(noncanonical_absent) == null);
    const bad_flags = try std.testing.allocator.dupe(u8, legacy_current_writer.written());
    defer std.testing.allocator.free(bad_flags);
    bad_flags[9] = 0x80;
    try std.testing.expect(History.restoreHelixCheckpoint(bad_flags) == null);

    // Encoding also fails closed if memory corruption or an unsafe caller has
    // manufactured a repeated id that the public ingestion API cannot create.
    source.items[1].event_id = source.items[0].event_id;
    var impossible_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer impossible_writer.deinit();
    try std.testing.expectError(error.InvalidState, source.serializeInto(&impossible_writer.writer));
    try std.testing.expectEqual(@as(usize, 0), impossible_writer.written().len);
}

test "legacy v1 cold-load migration is explicit and never invents stable ids" {
    const History = EventHistory(3);
    var source = History{};
    source.record(1, 1, 1, "n", "one");
    source.record(2, 2, 2, "n", "two");
    var legacy_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer legacy_writer.deinit();
    try serializeLegacyForTest(&source, &legacy_writer.writer);
    try std.testing.expectEqual(legacy_snapshot_version, legacy_writer.written()[4]);
    try std.testing.expect(History.restoreHelixCheckpoint(legacy_writer.written()) == null);
    const checkpoint = History.restoreLegacyColdCheckpoint(legacy_writer.written()) orelse
        return error.TestUnexpectedResult;
    var restored = History{};
    restored.publishCheckpoint(&checkpoint);
    var out: [3]StoredEvent = undefined;
    const count = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    for (out[0..count]) |event| try std.testing.expect(event.eventId() == null);
    try std.testing.expect(History.restoreCheckpoint(legacy_writer.written()) != null);
}

test "snapshot round-trips oldest-first and survives reload" {
    var h = EventHistory(4){};
    h.record(1, 2, 111, "eshmaki.me", "USER CONNECT n!u@h");
    h.record(7, 3, 222, "ircx.us", "k killed s (flood)");

    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    try h.serializeInto(&aw.writer);

    var restored = EventHistory(4){};
    try std.testing.expect(restored.load(aw.written()));
    var out: [8]StoredEvent = undefined;
    const n = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("k killed s (flood)", out[0].message());
    try std.testing.expectEqual(@as(i64, 222), out[0].ts_unix_ms);
    try std.testing.expectEqual(@as(u8, 7), out[0].category);
    try std.testing.expectEqualStrings("ircx.us", out[0].origin());
    try std.testing.expectEqualStrings("USER CONNECT n!u@h", out[1].message());

    // A bad magic / version is atomic: the prior exact ring stays live.
    try std.testing.expect(!restored.load("XXXX\x01\x00\x00\x00\x00"));
    try std.testing.expect(!restored.load("OEH1\x03\x00\x00\x00\x00"));
    try std.testing.expectEqual(@as(usize, 2), restored.len());
    // Authenticated framing is exact: trailing bytes are rejected too.
    var trailing = try std.testing.allocator.alloc(u8, aw.written().len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..aw.written().len], aw.written());
    trailing[aw.written().len] = 0;
    try std.testing.expect(!restored.load(trailing));
    try std.testing.expectEqual(@as(usize, 2), restored.len());
}

test "checkpoint stages independently and publishes without moving the live mutex" {
    const History = EventHistory(3);
    var source = History{};
    source.record(1, 1, 1, "node", "one");
    source.record(2, 2, 2, "node", "two");
    source.record(3, 3, 3, "node", "three");
    source.record(4, 4, 4, "node", "four");

    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try source.serializeInto(&writer.writer);
    const owned_wire = try std.testing.allocator.dupe(u8, writer.written());
    const checkpoint = History.restoreCheckpoint(owned_wire) orelse return error.TestUnexpectedResult;
    @memset(owned_wire, 0xa5);
    std.testing.allocator.free(owned_wire);

    var live = History{};
    live.record(9, 1, 99, "old", "sentinel");
    const mutex_address = &live.mu;
    live.publishCheckpoint(&checkpoint);
    try std.testing.expectEqual(mutex_address, &live.mu);
    try std.testing.expectEqual(@as(u32, 0), live.mu.state.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), live.mu.writers_waiting.load(.acquire));

    var out: [4]StoredEvent = undefined;
    var count = live.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("four", out[0].message());
    try std.testing.expectEqualStrings("three", out[1].message());
    try std.testing.expectEqualStrings("two", out[2].message());

    // The original lock remains operational and the restored full-ring cursor
    // evicts the correct oldest row on its next live write.
    live.record(5, 1, 5, "node", "five");
    count = live.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("five", out[0].message());
    try std.testing.expectEqualStrings("four", out[1].message());
    try std.testing.expectEqualStrings("three", out[2].message());
}

test "checkpoint serialization is allocation-failure safe and unlocks the ring" {
    const History = EventHistory(3);
    var history = History{};
    history.record(1, 1, 1, "node", "one");
    history.record(2, 2, 2, "node", "two");

    // Writer translates allocator OOM into `error.WriteFailed`, so exercise its
    // allocation sites explicitly instead of using checkAllAllocationFailures
    // (which requires OOM to remain visible in the function's error set).
    var baseline = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var writer = std.Io.Writer.Allocating.init(baseline.allocator());
        defer writer.deinit();
        try history.serializeInto(&writer.writer);
        const checkpoint = History.restoreHelixCheckpoint(writer.written()) orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 2), checkpoint.count);
    }
    try std.testing.expectEqual(baseline.allocated_bytes, baseline.freed_bytes);

    for (0..baseline.alloc_index) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = fail_index,
        });
        var writer = std.Io.Writer.Allocating.init(failing.allocator());
        const result = history.serializeInto(&writer.writer);
        writer.deinit();
        try std.testing.expectError(error.WriteFailed, result);
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        try std.testing.expectEqual(@as(usize, 2), history.len());
    }

    history.record(3, 3, 3, "node", "three");
    var out: [3]StoredEvent = undefined;
    const count = history.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("three", out[0].message());
    try std.testing.expectEqualStrings("two", out[1].message());
    try std.testing.expectEqualStrings("one", out[2].message());
}

test "checkpoint parse failures never partially mutate prior live state" {
    const History = EventHistory(4);
    var source = History{};
    source.record(1, 1, 1, "new", "new-one");
    source.record(2, 2, 2, "new", "new-two");
    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try source.serializeInto(&writer.writer);
    const wire = writer.written();

    var live = History{};
    live.record(7, 3, 70, "old", "old-one");
    live.record(8, 4, 80, "old", "old-two");

    // Every incomplete prefix is rejected after staging only; prefixes that
    // contain the complete first row prove no partial row ever publishes.
    for (0..wire.len) |len| try std.testing.expect(!live.load(wire[0..len]));

    const bad_magic = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try std.testing.expect(!live.load(bad_magic));

    const bad_version = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    try std.testing.expect(!live.load(bad_version));

    const bad_count = try std.testing.allocator.dupe(u8, wire);
    defer std.testing.allocator.free(bad_count);
    std.mem.writeInt(u32, bad_count[5..9], 3, .little);
    try std.testing.expect(!live.load(bad_count));

    const trailing = try std.testing.allocator.alloc(u8, wire.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expect(!live.load(trailing));

    var out: [4]StoredEvent = undefined;
    const count = live.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("old-two", out[0].message());
    try std.testing.expectEqual(@as(i64, 80), out[0].ts_unix_ms);
    try std.testing.expectEqualStrings("old-one", out[1].message());
    try std.testing.expectEqual(@as(i64, 70), out[1].ts_unix_ms);
}

test "checkpoint rejects non-exact oversized event fields without mutation" {
    const History = EventHistory(2);
    var live = History{};
    live.record(1, 1, 1, "old", "sentinel");

    const oversized_origin: [max_origin_len + 1]u8 = @splat('o');
    var origin_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer origin_writer.deinit();
    try origin_writer.writer.writeAll(snapshot_magic);
    try origin_writer.writer.writeByte(legacy_snapshot_version);
    try putU32(&origin_writer.writer, 1);
    try origin_writer.writer.writeByte(1);
    try origin_writer.writer.writeByte(1);
    try putI64(&origin_writer.writer, 1);
    try putU32(&origin_writer.writer, @intCast(oversized_origin.len));
    try origin_writer.writer.writeAll(&oversized_origin);
    try putU32(&origin_writer.writer, 0);
    try std.testing.expect(History.restoreCheckpoint(origin_writer.written()) == null);
    try std.testing.expect(!live.load(origin_writer.written()));

    const oversized_message: [max_message_len + 1]u8 = @splat('m');
    var message_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer message_writer.deinit();
    try message_writer.writer.writeAll(snapshot_magic);
    try message_writer.writer.writeByte(legacy_snapshot_version);
    try putU32(&message_writer.writer, 1);
    try message_writer.writer.writeByte(1);
    try message_writer.writer.writeByte(1);
    try putI64(&message_writer.writer, 1);
    try putU32(&message_writer.writer, 0);
    try putU32(&message_writer.writer, @intCast(oversized_message.len));
    try message_writer.writer.writeAll(&oversized_message);
    try std.testing.expect(History.restoreCheckpoint(message_writer.written()) == null);
    try std.testing.expect(!live.load(message_writer.written()));

    var out: [2]StoredEvent = undefined;
    const count = live.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings("sentinel", out[0].message());
}

test "checkpoint into a smaller ring retains the newest complete rows" {
    var source = EventHistory(4){};
    source.record(1, 1, 1, "n", "one");
    source.record(2, 1, 2, "n", "two");
    source.record(3, 1, 3, "n", "three");
    source.record(4, 1, 4, "n", "four");
    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try serializeLegacyForTest(&source, &writer.writer);

    const SmallHistory = EventHistory(2);
    const checkpoint = SmallHistory.restoreCheckpoint(writer.written()) orelse return error.TestUnexpectedResult;
    var restored = SmallHistory{};
    restored.publishCheckpoint(&checkpoint);
    var out: [2]StoredEvent = undefined;
    const count = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("four", out[0].message());
    try std.testing.expectEqualStrings("three", out[1].message());
}

test "Helix checkpoint refuses truncation but accepts a complete fitting image" {
    var source = EventHistory(4){};
    source.record(1, 1, 1, "n", "one");
    source.record(2, 1, 2, "n", "two");
    source.record(3, 1, 3, "n", "three");
    var writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer writer.deinit();
    try source.serializeInto(&writer.writer);

    const SmallHistory = EventHistory(2);
    try std.testing.expect(SmallHistory.restoreHelixCheckpoint(writer.written()) == null);

    var legacy_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer legacy_writer.deinit();
    try serializeLegacyForTest(&source, &legacy_writer.writer);
    try std.testing.expect(SmallHistory.restoreHelixCheckpoint(legacy_writer.written()) == null);

    var fitting = EventHistory(2){};
    fitting.record(7, 1, 7, "fit", "seven");
    fitting.record(8, 1, 8, "fit", "eight");
    var fitting_writer = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer fitting_writer.deinit();
    try fitting.serializeInto(&fitting_writer.writer);
    const checkpoint = SmallHistory.restoreHelixCheckpoint(fitting_writer.written()) orelse
        return error.TestUnexpectedResult;

    var restored = SmallHistory{};
    restored.publishCheckpoint(&checkpoint);
    var out: [2]StoredEvent = undefined;
    const count = restored.collect(null, 0, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("eight", out[0].message());
    try std.testing.expectEqualStrings("seven", out[1].message());
}

fn testEventId(seed: u8) EventId {
    var id: EventId = undefined;
    for (&id, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return id;
}

fn serializeLegacyForTest(history: anytype, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    try writer.writeAll(snapshot_magic);
    try writer.writeByte(legacy_snapshot_version);
    try putU32(writer, @intCast(history.count));
    var logical: usize = 0;
    while (logical < history.count) : (logical += 1) {
        const event = history.items[(history.start + logical) % history.items.len];
        try writer.writeByte(event.category);
        try writer.writeByte(event.severity);
        try putI64(writer, event.ts_unix_ms);
        try putBytes(writer, event.origin());
        try putBytes(writer, event.message());
    }
}

fn nextCurrentEventOffset(bytes: []const u8, offset: usize) ?usize {
    const fixed_len = 1 + @sizeOf(EventId) + 1 + 1 + 8;
    if (offset > bytes.len or fixed_len + 4 > bytes.len - offset) return null;
    var pos = offset + fixed_len;
    const origin_len: usize = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    if (pos > bytes.len or origin_len > bytes.len - pos) return null;
    pos += origin_len;
    if (pos > bytes.len or 4 > bytes.len - pos) return null;
    const message_len: usize = std.mem.readInt(u32, bytes[pos..][0..4], .little);
    pos += 4;
    if (pos > bytes.len or message_len > bytes.len - pos) return null;
    return pos + message_len;
}
