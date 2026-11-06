// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Q06: mesh-wide-consistent ACCESS expiry reminders.
//!
//! `ircx_access_store` stores every timed entry's `expires_at` as a pure
//! function of its signed `(hlc, duration)` pair (`anchoredExpiry`), never of
//! a node's arrival time. Every node therefore holds the IDENTICAL absolute
//! expiry for one fact, whether it was applied live, replayed by
//! anti-entropy, or caught up after a cold restart, so there is one due
//! instant per rule mesh-wide and a reminder planned here agrees with
//! enforcement on every node. Rows restored from a Helix checkpoint hold the
//! same instant only after `AccessStore.reanchorTimedExpiries` runs on adopt:
//! a capsule written by an older binary carries arrival-anchored expiries.
//!
//! This module is pure and allocation-free: `Ledger` is a fixed-capacity
//! array and `formatReminder` writes only into a caller buffer. It decides
//! WHICH rules are due, renders the line, and owns the exactly-once
//! bookkeeping. It deliberately does not decide WHO receives a reminder: the
//! `sweep` deliverer resolves `Due.set_by` to a live local connection and must
//! re-check that connection's ACCESS management authority for
//! `(Due.channel, Due.level)` at send time. `set_by` is only a display name,
//! so a nick reused by someone without authority must not learn the rule's
//! channel, level, or mask; such a delivery is refused and retried later.
//!
//! The ledger is process-local: after a cold restart or a Helix upgrade it
//! starts empty and the first sweep re-reminds rules already inside the lead
//! window once (boot catch-up), never zero times.
const std = @import("std");
const ircx_access_store = @import("ircx_access_store.zig");

const CheckpointEntry = ircx_access_store.CheckpointEntry;
const Level = ircx_access_store.Level;

/// How long before a rule's mesh-wide expiry its issuer is reminded.
pub const default_lead_s: u64 = 3600;
/// Sweep cadence. Much shorter than `default_lead_s` so a rule is reminded
/// close to its lead edge; the ledger keeps repeated sweeps exactly-once.
pub const sweep_interval_ms: i64 = 60_000;
/// Successful deliveries per sweep. The rest stay due and are delivered by
/// the next sweeps, so a burst of expiring rules cannot flood one turn.
pub const max_sends_per_sweep: usize = 64;

/// One ACCESS rule due for a reminder: the fields a reminder line needs plus
/// the exact rank fields the `Ledger` is keyed on. Borrows slices from the
/// store rows passed to `isDue`/`sweep`; the store must not be mutated while
/// a `Due` is in use.
pub const Due = struct {
    channel: []const u8,
    level: Level,
    mask: []const u8,
    set_by: []const u8,
    /// Mesh-wide absolute expiry (unix seconds); only timed rows are due.
    expires_at: u64,
    hlc: u64,
    origin_node: u64,
};

/// Fold one identity field into `hasher`, case-folded so the key matches the
/// store's case-insensitive row identity.
fn foldField(hasher: *std.hash.Wyhash, bytes: []const u8) void {
    for (bytes) |byte| hasher.update(&[1]u8{std.ascii.toLower(byte)});
    hasher.update(&[1]u8{0}); // field separator so "ab","c" != "a","bc"
}

/// Digest of a row's (channel, level, mask) identity. It is only a fast
/// filter: ledger membership also requires the exact `hlc`, `origin_node`,
/// and `expires_at`, and an origin never issues one stamp twice, so a digest
/// collision cannot suppress a different rule's reminder.
fn identityDigest(channel: []const u8, level: Level, mask: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    foldField(&hasher, channel);
    hasher.update(&[1]u8{@as(u8, @backingInt(level))});
    foldField(&hasher, mask);
    return hasher.final();
}

/// Fixed-capacity, allocation-free record of reminders already delivered, so
/// a node reminds each distinct (rule, write, expiry) exactly once rather than
/// on every sweep inside the lead window. A re-grant of the same
/// (channel, level, mask) carries a fresh `hlc`/`expires_at` and is reminded
/// again on its own schedule.
///
/// Capacity equals the store's default entry bound and `retainLive` drops
/// every slot whose row is gone, superseded, or expired, so live slots never
/// exceed live timed rows. If a larger store ever fills it, `reserve` refuses
/// (fail-closed): an unrecordable reminder is deferred, never sent, because a
/// send the ledger cannot remember would repeat on every sweep.
pub const Ledger = struct {
    pub const capacity: usize = ircx_access_store.DEFAULT_MAX_ENTRIES;
    pub const Error = error{LedgerFull};

    const Slot = struct {
        identity: u64,
        hlc: u64,
        origin_node: u64,
        expires_at: u64,

        fn of(due: Due) Slot {
            return .{
                .identity = identityDigest(due.channel, due.level, due.mask),
                .hlc = due.hlc,
                .origin_node = due.origin_node,
                .expires_at = due.expires_at,
            };
        }

        fn eql(a: Slot, b: Slot) bool {
            return a.identity == b.identity and a.hlc == b.hlc and
                a.origin_node == b.origin_node and a.expires_at == b.expires_at;
        }

        /// True when `entry` is the very write this slot recorded.
        fn matchesEntry(slot: Slot, entry: *const CheckpointEntry) bool {
            const expires_at = entry.expires_at orelse return false;
            if (expires_at != slot.expires_at or entry.hlc != slot.hlc or entry.origin_node != slot.origin_node) return false;
            return identityDigest(entry.channel, entry.level, entry.mask) == slot.identity;
        }
    };

    slots: [capacity]Slot = undefined,
    len: usize = 0,

    fn indexOf(self: *const Ledger, key: Slot) ?usize {
        for (self.slots[0..self.len], 0..) |slot, idx| {
            if (slot.eql(key)) return idx;
        }
        return null;
    }

    pub fn contains(self: *const Ledger, due: Due) bool {
        return self.indexOf(Slot.of(due)) != null;
    }

    /// Record `due` as reminded. Idempotent for an already-recorded key.
    /// Refuses with `error.LedgerFull` instead of evicting: evicting a live
    /// slot would make its rule due again and remind it twice.
    pub fn reserve(self: *Ledger, due: Due) Error!void {
        const key = Slot.of(due);
        if (self.indexOf(key) != null) return;
        if (self.len >= capacity) return error.LedgerFull;
        self.slots[self.len] = key;
        self.len += 1;
    }

    /// Undo a `reserve` whose delivery failed, so the next sweep retries it.
    pub fn release(self: *Ledger, due: Due) void {
        const idx = self.indexOf(Slot.of(due)) orelse return;
        self.len -= 1;
        self.slots[idx] = self.slots[self.len];
    }

    /// Drop every slot that can never be due again: its expiry has passed, or
    /// no current row is the exact write it recorded (deleted, re-granted at a
    /// new stamp, or replaced by a peer). Returns how many slots were dropped.
    /// O(slots * entries) integer compares, both bounded by the store bound.
    pub fn retainLive(self: *Ledger, entries: []const CheckpointEntry, now_s: u64) usize {
        var dropped: usize = 0;
        var idx: usize = 0;
        while (idx < self.len) {
            if (self.slots[idx].expires_at > now_s and slotHasEntry(self.slots[idx], entries)) {
                idx += 1;
            } else {
                self.len -= 1;
                self.slots[idx] = self.slots[self.len];
                dropped += 1;
            }
        }
        return dropped;
    }

    fn slotHasEntry(slot: Slot, entries: []const CheckpointEntry) bool {
        for (entries) |*entry| {
            if (slot.matchesEntry(entry)) return true;
        }
        return false;
    }

    pub fn count(self: *const Ledger) usize {
        return self.len;
    }
};

/// The reminder view of `entry` when it is due at `now_s`: timed, inside
/// `[expires_at - lead_s, expires_at)`, and not already in `ledger`. Edges
/// match `ircx_access_store`'s `isExpiredAt`: at `expires_at` the rule is
/// already expired (never due), and the lead edge itself is due.
pub fn isDue(entry: *const CheckpointEntry, now_s: u64, lead_s: u64, ledger: *const Ledger) ?Due {
    const expires_at = entry.expires_at orelse return null;
    if (now_s >= expires_at or now_s < expires_at -| lead_s) return null;
    const due = Due{
        .channel = entry.channel,
        .level = entry.level,
        .mask = entry.mask,
        .set_by = entry.set_by,
        .expires_at = expires_at,
        .hlc = entry.hlc,
        .origin_node = entry.origin_node,
    };
    if (ledger.contains(due)) return null;
    return due;
}

pub const SweepResult = struct {
    /// Rules due at this sweep (not yet reminded), delivered or not.
    due: usize = 0,
    /// Reminders delivered and recorded in the ledger.
    sent: usize = 0,
    /// Due rules left for a later sweep: refused by the deliverer (issuer
    /// offline, unauthorized, field unsafe, queue full), over the per-sweep
    /// cap, or unrecordable because the ledger is full.
    deferred: usize = 0,
};

/// One reminder pass over the whole store (no fixed row cap), in store order.
/// `deliverer` is a pointer whose `deliver(Due) bool` returns true only after
/// the notice is queued to a recipient authorized for the rule's details.
/// A slot is reserved BEFORE delivery and released if delivery fails, so a
/// reminder is never sent unless it is recorded, and a failed or refused
/// delivery is retried on the next sweep. At most `max_sends` deliveries
/// succeed per call; the deliverer must not mutate `entries`.
pub fn sweep(
    entries: []const CheckpointEntry,
    now_s: u64,
    lead_s: u64,
    ledger: *Ledger,
    max_sends: usize,
    deliverer: anytype,
) SweepResult {
    _ = ledger.retainLive(entries, now_s);
    var result: SweepResult = .{};
    for (entries) |*entry| {
        const due = isDue(entry, now_s, lead_s, ledger) orelse continue;
        result.due += 1;
        if (result.sent >= max_sends) {
            result.deferred += 1;
            continue;
        }
        ledger.reserve(due) catch {
            result.deferred += 1;
            continue;
        };
        if (deliverer.deliver(due)) {
            result.sent += 1;
        } else {
            ledger.release(due);
            result.deferred += 1;
        }
    }
    return result;
}

/// Reminder text safety: no control bytes, DEL, or spaces (store validation
/// already forbids spaces in channels and masks, so one here means a row
/// bypassed it), and never longer than the stored column bound. A refused
/// field yields no line rather than a spliced or truncated one.
fn fieldSafe(value: []const u8, max_len: usize) bool {
    if (value.len > max_len) return false;
    for (value) |byte| if (byte <= ' ' or byte == 0x7f) return false;
    return true;
}

pub const FormatError = error{UnsafeField} || std.fmt.BufPrintError;

/// Render the wire-visible reminder line the daemon already sends:
/// `ACCESS EXPIRY channel=<c> level=<lvl> mask=<m> expires_at=<unix_seconds>`.
/// Only the rule's own channel, level, mask, and mesh-wide expiry appear; the
/// issuer, origin node, and write stamp never do.
pub fn formatReminder(buf: []u8, due: Due) FormatError![]const u8 {
    if (!fieldSafe(due.channel, ircx_access_store.DEFAULT_MAX_CHANNEL_BYTES)) return error.UnsafeField;
    if (!fieldSafe(due.mask, ircx_access_store.DEFAULT_MAX_MASK_BYTES)) return error.UnsafeField;
    return std.fmt.bufPrint(buf, "ACCESS EXPIRY channel={s} level={s} mask={s} expires_at={d}", .{
        due.channel,
        @tagName(due.level),
        due.mask,
        due.expires_at,
    });
}

const testing = std.testing;

fn makeEntry(channel: []const u8, level: Level, mask: []const u8, set_by: []const u8, expires_at: ?u64, hlc: u64, origin_node: u64) CheckpointEntry {
    return .{
        .channel = @constCast(channel),
        .level = level,
        .mask = @constCast(mask),
        .set_by = @constCast(set_by),
        .duration = if (expires_at) |_| 1 else null,
        .expires_at = expires_at,
        .hlc = hlc,
        .origin_node = origin_node,
    };
}

/// Test deliverer: records delivered masks; refuses any issuer in `refuse`.
const Recorder = struct {
    delivered: [16][]const u8 = undefined,
    len: usize = 0,
    refuse: []const []const u8 = &.{},
    calls: usize = 0,

    fn deliver(self: *Recorder, due: Due) bool {
        self.calls += 1;
        for (self.refuse) |name| if (std.mem.eql(u8, name, due.set_by)) return false;
        var line: [256]u8 = undefined;
        _ = formatReminder(&line, due) catch return false;
        self.delivered[self.len] = due.mask;
        self.len += 1;
        return true;
    }
};

test "reminder due exactly once per rule within lead window" {
    var ledger = Ledger{};
    const entries = [_]CheckpointEntry{
        makeEntry("#mesh", .host, "*!*@a.test", "alice", 1_000, 10, 1),
        makeEntry("#mesh", .deny, "*!*@perm.test", "alice", null, 11, 1),
        makeEntry("#mesh", .voice, "*!*@later.test", "alice", 4_000, 12, 1),
    };
    var rec = Recorder{};
    const first = sweep(&entries, 950, default_lead_s, &ledger, max_sends_per_sweep, &rec);
    try testing.expectEqual(SweepResult{ .due = 2, .sent = 2, .deferred = 0 }, first);
    try testing.expectEqual(@as(usize, 2), ledger.count());

    // Every later sweep inside the window is silent for the reminded rules.
    for ([_]u64{ 951, 960, 999 }) |now| {
        const again = sweep(&entries, now, default_lead_s, &ledger, max_sends_per_sweep, &rec);
        try testing.expectEqual(SweepResult{}, again);
    }
    try testing.expectEqual(@as(usize, 2), rec.len);
    try testing.expectEqual(@as(usize, 2), rec.calls);

    // Past its expiry the first rule's slot is reclaimed; the second stays.
    _ = sweep(&entries, 1_000, default_lead_s, &ledger, max_sends_per_sweep, &rec);
    try testing.expectEqual(@as(usize, 1), ledger.count());
    try testing.expectEqual(@as(usize, 2), rec.len);
}

test "reminder planner pins lead and expiry edges (expires_at-lead due, expires_at not due)" {
    const ledger = Ledger{};
    const entry = makeEntry("#mesh", .host, "*!*@edge.test", "alice", 1_000, 10, 1);
    try testing.expect(isDue(&entry, 1_000 - 100, 100, &ledger) != null);
    try testing.expect(isDue(&entry, 1_000 - 101, 100, &ledger) == null);
    try testing.expect(isDue(&entry, 999, 100, &ledger) != null);
    try testing.expect(isDue(&entry, 1_000, 100, &ledger) == null);
    try testing.expect(isDue(&entry, std.math.maxInt(u64), 100, &ledger) == null);
    // A lead longer than the whole epoch saturates instead of wrapping.
    try testing.expect(isDue(&entry, 0, std.math.maxInt(u64), &ledger) != null);
    const permanent = makeEntry("#mesh", .host, "*!*@perm.test", "alice", null, 10, 1);
    try testing.expect(isDue(&permanent, 999, 100, &ledger) == null);
}

test "re-granted rule with new hlc/expiry is reminded again" {
    var ledger = Ledger{};
    var rec = Recorder{};
    const first = [_]CheckpointEntry{makeEntry("#mesh", .host, "*!*@a.test", "alice", 1_000, 10, 1)};
    try testing.expectEqual(@as(usize, 1), sweep(&first, 950, 3600, &ledger, 8, &rec).sent);
    try testing.expectEqual(@as(usize, 0), sweep(&first, 960, 3600, &ledger, 8, &rec).sent);

    // Same identity triple re-granted at a fresh stamp and expiry: the old
    // slot is superseded and dropped, the new write is reminded once.
    const regranted = [_]CheckpointEntry{makeEntry("#MESH", .host, "*!*@A.test", "bob", 2_000, 1_500, 1)};
    try testing.expectEqual(@as(usize, 1), sweep(&regranted, 1_950, 3600, &ledger, 8, &rec).sent);
    try testing.expectEqual(@as(usize, 1), ledger.count());
    try testing.expectEqual(@as(usize, 0), sweep(&regranted, 1_960, 3600, &ledger, 8, &rec).sent);
    try testing.expectEqual(@as(usize, 2), rec.len);
}

test "reminder refused for offline or unauthorized issuer is retried, never recorded" {
    var ledger = Ledger{};
    const entries = [_]CheckpointEntry{
        makeEntry("#mesh", .host, "*!*@a.test", "mallory", 1_000, 10, 1),
        makeEntry("#mesh", .host, "*!*@b.test", "alice", 1_000, 11, 1),
    };
    var refusing = Recorder{ .refuse = &.{"mallory"} };
    const first = sweep(&entries, 950, 3600, &ledger, 8, &refusing);
    try testing.expectEqual(SweepResult{ .due = 2, .sent = 1, .deferred = 1 }, first);
    try testing.expectEqual(@as(usize, 1), ledger.count());
    try testing.expectEqualStrings("*!*@b.test", refusing.delivered[0]);

    // Still refused: still due, still unrecorded, nothing re-sent to alice.
    const second = sweep(&entries, 960, 3600, &ledger, 8, &refusing);
    try testing.expectEqual(SweepResult{ .due = 1, .sent = 0, .deferred = 1 }, second);
    try testing.expectEqual(@as(usize, 1), refusing.len);

    // Once an authorized issuer is reachable the deferred rule is delivered.
    var accepting = Recorder{};
    const third = sweep(&entries, 970, 3600, &ledger, 8, &accepting);
    try testing.expectEqual(SweepResult{ .due = 1, .sent = 1, .deferred = 0 }, third);
    try testing.expectEqualStrings("*!*@a.test", accepting.delivered[0]);
    try testing.expectEqual(@as(usize, 2), ledger.count());
}

test "reminder rows with unsafe fields are refused, not rendered" {
    var ledger = Ledger{};
    const entries = [_]CheckpointEntry{makeEntry("#mesh", .host, "*!*@a\r\nPRIVMSG x", "alice", 1_000, 10, 1)};
    var rec = Recorder{};
    const result = sweep(&entries, 950, 3600, &ledger, 8, &rec);
    try testing.expectEqual(SweepResult{ .due = 1, .sent = 0, .deferred = 1 }, result);
    try testing.expectEqual(@as(usize, 0), ledger.count());
}

test "reminder per-sweep cap defers the rest without duplicates" {
    var ledger = Ledger{};
    const entries = [_]CheckpointEntry{
        makeEntry("#mesh", .host, "a!*@h.test", "alice", 1_000, 1, 1),
        makeEntry("#mesh", .host, "b!*@h.test", "alice", 1_000, 2, 1),
        makeEntry("#mesh", .host, "c!*@h.test", "alice", 1_000, 3, 1),
    };
    var rec = Recorder{};
    try testing.expectEqual(SweepResult{ .due = 3, .sent = 2, .deferred = 1 }, sweep(&entries, 950, 3600, &ledger, 2, &rec));
    try testing.expectEqual(SweepResult{ .due = 1, .sent = 1, .deferred = 0 }, sweep(&entries, 951, 3600, &ledger, 2, &rec));
    try testing.expectEqual(SweepResult{}, sweep(&entries, 952, 3600, &ledger, 2, &rec));
    try testing.expectEqual(@as(usize, 3), rec.len);
    try testing.expectEqualStrings("a!*@h.test", rec.delivered[0]);
    try testing.expectEqualStrings("c!*@h.test", rec.delivered[2]);
}

test "reminder ledger full fails closed: deferred, never sent unrecorded" {
    var ledger = Ledger{};
    var filler_entries: [Ledger.capacity]CheckpointEntry = undefined;
    for (&filler_entries, 0..) |*entry, i| {
        entry.* = makeEntry("#fill", .voice, "m", "alice", 5_000, i, 1);
        try ledger.reserve(isDue(entry, 4_000, 3600, &ledger).?);
    }
    try testing.expectEqual(Ledger.capacity, ledger.count());

    const extra = makeEntry("#mesh", .host, "*!*@x.test", "alice", 1_000, 99_999, 1);
    try testing.expectError(error.LedgerFull, ledger.reserve(isDue(&extra, 950, 3600, &ledger).?));
    // Re-reserving an already-recorded key is idempotent even when full.
    try ledger.reserve(isDue(&filler_entries[0], 4_000, 3600, &Ledger{}).?);

    var both: [Ledger.capacity + 1]CheckpointEntry = undefined;
    @memcpy(both[0..Ledger.capacity], &filler_entries);
    both[Ledger.capacity] = extra;
    var rec = Recorder{};
    const blocked = sweep(&both, 950, 3600, &ledger, 8, &rec);
    try testing.expectEqual(SweepResult{ .due = 1, .sent = 0, .deferred = 1 }, blocked);
    try testing.expectEqual(@as(usize, 0), rec.calls);

    // Deleting the filler rows frees their slots; the deferred rule goes out.
    const freed = sweep(both[Ledger.capacity..], 951, 3600, &ledger, 8, &rec);
    try testing.expectEqual(SweepResult{ .due = 1, .sent = 1, .deferred = 0 }, freed);
    try testing.expectEqual(@as(usize, 1), ledger.count());
}

test "reminder ledger retainLive drops expired, deleted, and superseded writes" {
    var ledger = Ledger{};
    const kept = makeEntry("#mesh", .host, "*!*@kept.test", "alice", 2_000, 10, 1);
    const deleted = makeEntry("#mesh", .host, "*!*@gone.test", "alice", 2_000, 11, 1);
    const old = makeEntry("#mesh", .host, "*!*@swap.test", "alice", 2_000, 12, 1);
    const short = makeEntry("#mesh", .host, "*!*@short.test", "alice", 1_000, 13, 1);
    for ([_]*const CheckpointEntry{ &kept, &deleted, &old, &short }) |entry| {
        try ledger.reserve(isDue(entry, 950, 3600, &ledger).?);
    }
    // Same identity replaced by a peer write of the same expiry but another
    // origin: a different fact, so the old slot no longer matches anything.
    const swapped = makeEntry("#mesh", .host, "*!*@swap.test", "bob", 2_000, 12, 2);
    const now_rows = [_]CheckpointEntry{ kept, swapped, short };
    try testing.expectEqual(@as(usize, 2), ledger.retainLive(&now_rows, 999));
    try testing.expect(ledger.contains(isDue(&kept, 999, 3600, &Ledger{}).?));
    try testing.expect(ledger.contains(isDue(&short, 999, 3600, &Ledger{}).?));
    try testing.expect(isDue(&swapped, 999, 3600, &ledger) != null);
    try testing.expectEqual(@as(usize, 1), ledger.retainLive(&now_rows, 1_000));
    try testing.expectEqual(@as(usize, 1), ledger.count());
}

test "reminder boot catch-up with empty ledger reminds rules already inside lead window" {
    // A cold-restarted or Helix-upgraded node's ledger is empty, so its FIRST
    // sweep must surface rules already inside the window, exactly once.
    var ledger = Ledger{};
    const entries = [_]CheckpointEntry{makeEntry("#mesh", .host, "*!*@boot.test", "alice", 1_000, 10, 1)};
    var rec = Recorder{};
    try testing.expectEqual(@as(usize, 1), sweep(&entries, 950, 3600, &ledger, 8, &rec).sent);
    try testing.expectEqual(@as(usize, 0), sweep(&entries, 960, 3600, &ledger, 8, &rec).sent);
}

test "reminder sweep scans beyond 32 rows" {
    var ledger = Ledger{};
    var rows: [40]CheckpointEntry = undefined;
    var mask_bufs: [40][32]u8 = undefined;
    for (&rows, 0..) |*row, i| {
        const mask = try std.fmt.bufPrint(&mask_bufs[i], "n{d}!*@h.test", .{i});
        row.* = makeEntry("#mesh", .voice, mask, "alice", 10_039 - @as(u64, i), i, 1);
    }
    const Counter = struct {
        n: usize = 0,
        last: []const u8 = "",
        fn deliver(self: *@This(), due: Due) bool {
            self.n += 1;
            self.last = due.mask;
            return true;
        }
    };
    var counter = Counter{};
    const result = sweep(&rows, 9_999, 100, &ledger, max_sends_per_sweep, &counter);
    try testing.expectEqual(SweepResult{ .due = 40, .sent = 40, .deferred = 0 }, result);
    try testing.expectEqualStrings("n39!*@h.test", counter.last);
}

test "reminder formatReminder rejects unsafe fields and omits issuer identity" {
    var buf: [512]u8 = undefined;
    const ok = Due{
        .channel = "#mesh",
        .level = .host,
        .mask = "*!*@safe.test",
        .set_by = "alice",
        .expires_at = 1_700_000_600,
        .hlc = 1_699_999_000_123,
        .origin_node = 77,
    };
    const line = try formatReminder(&buf, ok);
    try testing.expectEqualStrings("ACCESS EXPIRY channel=#mesh level=host mask=*!*@safe.test expires_at=1700000600", line);
    try testing.expect(std.mem.indexOf(u8, line, "alice") == null);
    try testing.expect(std.mem.indexOf(u8, line, "1699999000123") == null);

    const hostile = [_][2][]const u8{
        .{ "#mesh", "*!*@has space.test" },
        .{ "#me\x00sh", "*!*@a.test" },
        .{ "#mesh", "*!*@a\r\nb" },
        .{ "#mesh", "*!*@a\tb" },
        .{ "#me\x7fsh", "*!*@a.test" },
    };
    for (hostile) |pair| {
        var bad = ok;
        bad.channel = pair[0];
        bad.mask = pair[1];
        try testing.expectError(error.UnsafeField, formatReminder(&buf, bad));
    }

    var oversize_buf: [ircx_access_store.DEFAULT_MAX_CHANNEL_BYTES + 1]u8 = undefined;
    @memset(&oversize_buf, 'a');
    oversize_buf[0] = '#';
    var oversize = ok;
    oversize.channel = &oversize_buf;
    try testing.expectError(error.UnsafeField, formatReminder(&buf, oversize));

    var tiny: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, formatReminder(&tiny, ok));
}

test "reminder agrees mesh-wide for one fact applied at different times" {
    // Two receivers apply the same timed fact at different local times (one
    // live, one after a cold restart); both find it due at the same instant
    // and render byte-identical reminder text.
    const t: u64 = 1_700_000_000;
    const fact = ircx_access_store.RemoteFact{
        .present = true,
        .channel = "#mesh",
        .level = .deny,
        .mask = "*!*@remind.test",
        .set_by = "alice",
        .duration = 3_000,
        .hlc = t * 1000,
        .origin_node = 4,
    };
    var live = ircx_access_store.AccessStore.init(testing.allocator);
    defer live.deinit();
    live.now_seconds = t + 1;
    try testing.expectEqual(ircx_access_store.ApplyOutcome.applied, try live.applyRemote(fact));
    var restarted = ircx_access_store.AccessStore.init(testing.allocator);
    defer restarted.deinit();
    restarted.now_seconds = t + 2_500;
    try testing.expectEqual(ircx_access_store.ApplyOutcome.applied, try restarted.applyRemote(fact));

    const ledger = Ledger{};
    for ([_]u64{ t + 3_000 - default_lead_s - 1, t + 3_000 - default_lead_s, t + 2_999, t + 3_000 }) |now| {
        const a = isDue(&live.entries.items[0], now, default_lead_s, &ledger);
        const b = isDue(&restarted.entries.items[0], now, default_lead_s, &ledger);
        try testing.expectEqual(a == null, b == null);
    }
    const a = isDue(&live.entries.items[0], t + 2_600, default_lead_s, &ledger).?;
    const b = isDue(&restarted.entries.items[0], t + 2_600, default_lead_s, &ledger).?;
    var buf_a: [256]u8 = undefined;
    var buf_b: [256]u8 = undefined;
    const line_a = try formatReminder(&buf_a, a);
    try testing.expectEqualStrings(line_a, try formatReminder(&buf_b, b));
    try testing.expectEqualStrings("ACCESS EXPIRY channel=#mesh level=deny mask=*!*@remind.test expires_at=1700003000", line_a);
}

test "reminder ledger keys on case-folded identity plus exact write" {
    var ledger = Ledger{};
    const upper = makeEntry("#Mesh", .host, "*!*@A.test", "alice", 1_000, 10, 1);
    try ledger.reserve(isDue(&upper, 950, 3600, &ledger).?);
    const lower = makeEntry("#mesh", .host, "*!*@a.test", "alice", 1_000, 10, 1);
    try testing.expect(isDue(&lower, 950, 3600, &ledger) == null);
    try ledger.reserve(isDue(&lower, 950, 3600, &Ledger{}).?);
    try testing.expectEqual(@as(usize, 1), ledger.count());

    // A different level, origin, stamp, or expiry is a different reminder.
    const variants = [_]CheckpointEntry{
        makeEntry("#mesh", .deny, "*!*@a.test", "alice", 1_000, 10, 1),
        makeEntry("#mesh", .host, "*!*@a.test", "alice", 1_000, 10, 2),
        makeEntry("#mesh", .host, "*!*@a.test", "alice", 1_000, 11, 1),
        makeEntry("#mesh", .host, "*!*@a.test", "alice", 1_001, 10, 1),
    };
    for (&variants) |*variant| try testing.expect(isDue(variant, 950, 3600, &ledger) != null);

    // Releasing an unknown key is a no-op; releasing the known one frees it.
    ledger.release(isDue(&variants[0], 950, 3600, &ledger).?);
    try testing.expectEqual(@as(usize, 1), ledger.count());
    ledger.release(isDue(&lower, 950, 3600, &Ledger{}).?);
    try testing.expectEqual(@as(usize, 0), ledger.count());
}
