// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Flood-collapse for the Event Spine: when the SAME low-severity event repeats
//! many times in a short window (a join storm, a spamtrap firing in a loop), the
//! individual copies past a threshold are suppressed and replaced by a single
//! "N× <message> in Ys" summary, so an operator feed is not drowned.
//!
//! SAFETY: events at severity >= warn are NEVER collapsed — a kill / ward /
//! security / error storm must always reach operators in full. Only exact
//! repeats (same category + identical message) collapse, so distinct events
//! (different nick/channel) are unaffected. The threshold is high enough that
//! normal traffic never collapses; only a genuine identical-message flood does.
const std = @import("std");
const rwlock = @import("../substrate/rwlock.zig");
const event_spine = @import("event_spine.zig");

/// Severity ordinal at/above which events are never collapsed (`.warn`).
const collapse_severity_ceiling: u8 = @backingInt(event_spine.EventSeverity.warn);

pub const default_window_ms: i64 = 10_000;
/// Deliver the first `default_threshold` copies in a window; suppress the rest.
pub const default_threshold: u32 = 8;
pub const max_summary_msg: usize = 200;

/// One collapsed-burst summary produced by `flush`, for the caller to publish.
pub const Summary = struct {
    category: u8,
    /// Total events seen in the window (delivered + suppressed).
    total: u32,
    /// How many were suppressed (total - delivered).
    suppressed: u32,
    /// Window span in milliseconds (first→last event).
    span_ms: i64,
    msg_buf: [max_summary_msg]u8 = undefined,
    msg_len: u16 = 0,

    pub fn message(self: *const Summary) []const u8 {
        return self.msg_buf[0..self.msg_len];
    }
};

fn fnv1a(bytes: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (bytes) |b| {
        h ^= b;
        h *%= 0x100000001b3;
    }
    return h;
}

pub fn CollapseTable(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            used: bool = false,
            cat: u8 = 0,
            hash: u64 = 0,
            window_start: i64 = 0,
            last_seen: i64 = 0,
            count: u32 = 0, // total in the current window
            delivered: u32 = 0, // delivered (un-suppressed) in the current window
            msg_buf: [max_summary_msg]u8 = undefined,
            msg_len: u16 = 0,
        };

        entries: [capacity]Entry = @splat(.{}),
        window_ms: i64 = default_window_ms,
        threshold: u32 = default_threshold,
        mu: rwlock.RwLock = .{},

        /// Decide whether to deliver `message` (category `cat`, severity ordinal
        /// `sev`). Returns true to deliver, false to suppress. High-severity
        /// events (>= warn) always deliver. A suppressed event is counted toward
        /// its window's summary (emitted later by `flush`).
        pub fn admit(self: *Self, cat: u8, sev: u8, message: []const u8, now_ms: i64) bool {
            if (sev >= collapse_severity_ceiling) return true;
            if (capacity == 0) return true;
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();

            const h = fnv1a(message);
            const e = self.slotFor(cat, h, now_ms);
            // New or rolled-over window: reset counters + remember the message.
            if (!e.used or e.hash != h or e.cat != cat or (now_ms - e.window_start) > self.window_ms) {
                e.used = true;
                e.cat = cat;
                e.hash = h;
                e.window_start = now_ms;
                e.count = 0;
                e.delivered = 0;
                const n = @min(message.len, max_summary_msg);
                @memcpy(e.msg_buf[0..n], message[0..n]);
                e.msg_len = @intCast(n);
            }
            e.last_seen = now_ms;
            e.count += 1;
            if (e.delivered < self.threshold) {
                e.delivered += 1;
                return true;
            }
            return false; // past threshold this window → suppress
        }

        /// Emit summaries for windows that (a) have elapsed and (b) suppressed at
        /// least one event, into `out`; those slots are then cleared. Returns the
        /// count written. Called off the hot path (e.g. the stats tick).
        pub fn flush(self: *Self, now_ms: i64, out: []Summary) usize {
            if (out.len == 0) return 0;
            self.mu.lockExclusive();
            defer self.mu.unlockExclusive();
            var written: usize = 0;
            for (&self.entries) |*e| {
                if (written >= out.len) break;
                if (!e.used) continue;
                if ((now_ms - e.window_start) <= self.window_ms) continue; // window still open
                const suppressed = e.count - e.delivered;
                if (suppressed == 0) {
                    e.used = false; // nothing to summarize; free the slot
                    continue;
                }
                var s = Summary{
                    .category = e.cat,
                    .total = e.count,
                    .suppressed = suppressed,
                    .span_ms = e.last_seen - e.window_start,
                };
                const n = @min(e.msg_len, max_summary_msg);
                @memcpy(s.msg_buf[0..n], e.msg_buf[0..n]);
                s.msg_len = n;
                out[written] = s;
                written += 1;
                e.used = false; // consumed
            }
            return written;
        }

        /// Find the entry for (cat, hash), or a slot to (re)use: prefer an exact
        /// match, then a free slot, then the least-recently-seen slot (LRU evict).
        fn slotFor(self: *Self, cat: u8, h: u64, now_ms: i64) *Entry {
            var free: ?*Entry = null;
            var lru: *Entry = &self.entries[0];
            for (&self.entries) |*e| {
                if (e.used and e.cat == cat and e.hash == h) return e;
                if (!e.used and free == null) free = e;
                if (e.last_seen < lru.last_seen) lru = e;
            }
            if (free) |f| return f;
            // All slots in use with no match: evict the LRU. If the victim had a
            // pending burst we lose its summary, but the table is sized so this is
            // rare, and dropping a stale summary is preferable to unbounded growth.
            lru.used = false;
            _ = now_ms;
            return lru;
        }
    };
}

test "admit delivers up to the threshold then suppresses identical low-sev events" {
    var t = CollapseTable(8){ .threshold = 3, .window_ms = 1000 };
    const notice: u8 = @backingInt(event_spine.EventSeverity.notice);
    // First 3 delivered, rest suppressed within the window.
    try std.testing.expect(t.admit(7, notice, "MEMBER JOIN #c a", 0));
    try std.testing.expect(t.admit(7, notice, "MEMBER JOIN #c a", 10));
    try std.testing.expect(t.admit(7, notice, "MEMBER JOIN #c a", 20));
    try std.testing.expect(!t.admit(7, notice, "MEMBER JOIN #c a", 30));
    try std.testing.expect(!t.admit(7, notice, "MEMBER JOIN #c a", 40));
}

test "severity >= warn is never collapsed" {
    var t = CollapseTable(8){ .threshold = 1, .window_ms = 10_000 };
    const warn: u8 = @backingInt(event_spine.EventSeverity.warn);
    const crit: u8 = @backingInt(event_spine.EventSeverity.critical);
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expect(t.admit(12, warn, "WARD refused x", @intCast(i)));
        try std.testing.expect(t.admit(7, crit, "kill storm", @intCast(i)));
    }
}

test "distinct messages collapse independently" {
    var t = CollapseTable(8){ .threshold = 1, .window_ms = 10_000 };
    const notice: u8 = @backingInt(event_spine.EventSeverity.notice);
    try std.testing.expect(t.admit(7, notice, "MEMBER JOIN #c alice", 0));
    try std.testing.expect(!t.admit(7, notice, "MEMBER JOIN #c alice", 1)); // 2nd of same → suppress
    // A different message is a different key → delivered.
    try std.testing.expect(t.admit(7, notice, "MEMBER JOIN #c bob", 2));
}

test "flush summarizes an elapsed window with suppressed events, then clears it" {
    var t = CollapseTable(8){ .threshold = 2, .window_ms = 100 };
    const notice: u8 = @backingInt(event_spine.EventSeverity.notice);
    _ = t.admit(7, notice, "MEMBER JOIN #c a", 0);
    _ = t.admit(7, notice, "MEMBER JOIN #c a", 10);
    _ = t.admit(7, notice, "MEMBER JOIN #c a", 20); // suppressed
    _ = t.admit(7, notice, "MEMBER JOIN #c a", 30); // suppressed

    var out: [4]Summary = undefined;
    // Window still open at t=50 → no summary yet.
    try std.testing.expectEqual(@as(usize, 0), t.flush(50, &out));
    // After the window elapses → one summary with the suppressed count.
    const n = t.flush(500, &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u32, 4), out[0].total);
    try std.testing.expectEqual(@as(u32, 2), out[0].suppressed);
    try std.testing.expectEqualStrings("MEMBER JOIN #c a", out[0].message());
    // A second flush finds nothing (slot cleared).
    try std.testing.expectEqual(@as(usize, 0), t.flush(600, &out));
}
