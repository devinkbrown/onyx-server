// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reactor-0 correlation of channel joins across Mooring peers.
//!
//! A note records one successful join and the peer that delivered it. Reactor 0
//! evaluates the notes. A channel trips only when a burst exceeds its GCRA and
//! the recent notes came from at least three peers. One peer's growth never
//! trips. The channel table, Count-Min sketch, hottest-channel sketch, and
//! per-channel origin ring all have fixed bounds. A new note overwrites the
//! coldest quiet channel or the oldest origin sample. It does not refuse the join.

const std = @import("std");
const count_min = @import("../substrate/count_min_sketch.zig");
const gcra_mod = @import("../substrate/gcra.zig");
const topk = @import("../substrate/topk.zig");

pub const max_channels: usize = 1024;
pub const sketch_width: usize = 256;
pub const sketch_depth: usize = 4;
pub const hottest_capacity: usize = 256;
pub const origin_ring: usize = 32;
pub const min_distinct_origins: usize = 3;
pub const join_rate_per_sec: u64 = 5;
pub const join_burst: u64 = 4;
pub const correlation_window_ms: u64 = 2_000;
pub const relax_after_ms: u64 = 30_000;
pub const engaged_gap_secs: u64 = 10;

pub const ActionKind = enum { engage, relax };

pub const Action = struct {
    kind: ActionKind,
    channel: []const u8,
};

const OriginSlot = struct {
    hash: u64 = 0,
    at_ms: u64 = 0,
    used: bool = false,
};

const Watch = struct {
    gcra: gcra_mod.Gcra,
    origins: [origin_ring]OriginSlot,
    origin_i: usize = 0,
    last_note_ms: u64 = 0,
    over_rate: bool = false,
    engaged: bool = false,
};

pub const Shield = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMap(Watch),
    joins: count_min.CountMinSketch,
    hottest: topk.SpaceSaving(u64),
    noted: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) !Shield {
        var joins = try count_min.CountMinSketch.init(allocator, sketch_width, sketch_depth);
        errdefer joins.deinit();
        return .{
            .allocator = allocator,
            .channels = std.StringHashMap(Watch).init(allocator),
            .joins = joins,
            .hottest = topk.SpaceSaving(u64).init(allocator, hottest_capacity),
        };
    }

    pub fn deinit(self: *Shield) void {
        var it = self.channels.keyIterator();
        while (it.next()) |key| self.allocator.free(@constCast(key.*));
        self.channels.deinit();
        self.joins.deinit();
        self.hottest.deinit();
        self.* = undefined;
    }

    pub fn channelCount(self: *const Shield) usize {
        return self.channels.count();
    }

    /// True when a correlated burst has engaged at least one channel.
    pub fn engaged(self: *Shield) bool {
        var it = self.channels.iterator();
        while (it.next()) |entry| if (entry.value_ptr.engaged) return true;
        return false;
    }

    pub fn sketchCells(self: *const Shield) usize {
        return self.joins.width * self.joins.depth;
    }

    /// Record one join from `origin` (the local server name, or the Mooring
    /// peer that announced the join). Errors are allocation failures. A full
    /// table evicts a quiet channel or drops the observation. The join itself
    /// is never rejected here.
    pub fn note(self: *Shield, channel: []const u8, origin: []const u8, now_ms: u64) !void {
        if (channel.len < 2 or (channel[0] != '#' and channel[0] != '&')) return;
        if (origin.len == 0) return;
        try self.joins.add(channel, 1);
        try self.hottest.offer(std.hash.Wyhash.hash(0, channel));
        self.noted += 1;
        if (self.channels.getPtr(channel)) |watch| {
            touch(watch, origin, now_ms);
            return;
        }
        if (self.channels.count() >= max_channels and !self.evictQuietest()) return;
        const owned = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(owned);
        var watch = blankWatch();
        touch(&watch, origin, now_ms);
        try self.channels.put(owned, watch);
    }

    /// Borrowed channel names stay valid until the next mutating note.
    pub fn evaluate(self: *Shield, now_ms: u64) ![]Action {
        var list: std.ArrayList(Action) = .empty;
        errdefer list.deinit(self.allocator);
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            const watch = entry.value_ptr;
            if (watch.engaged) {
                if (quietFor(watch.last_note_ms, now_ms)) {
                    watch.engaged = false;
                    watch.over_rate = false;
                    watch.gcra = gcra_mod.Gcra.init(join_rate_per_sec, join_burst);
                    try list.append(self.allocator, .{ .kind = .relax, .channel = entry.key_ptr.* });
                }
                continue;
            }
            const hot = watch.over_rate;
            watch.over_rate = false;
            if (hot and distinctRecent(watch, now_ms) >= min_distinct_origins) {
                watch.engaged = true;
                try list.append(self.allocator, .{ .kind = .engage, .channel = entry.key_ptr.* });
            } else if (quietFor(watch.last_note_ms, now_ms)) {
                watch.gcra = gcra_mod.Gcra.init(join_rate_per_sec, join_burst);
            }
        }
        if (list.items.len == 0) {
            list.deinit(self.allocator);
            return &.{};
        }
        return try list.toOwnedSlice(self.allocator);
    }

    fn evictQuietest(self: *Shield) bool {
        var victim: ?[]const u8 = null;
        var oldest: u64 = std.math.maxInt(u64);
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.engaged) continue;
            if (victim == null or entry.value_ptr.last_note_ms < oldest) {
                oldest = entry.value_ptr.last_note_ms;
                victim = entry.key_ptr.*;
            }
        }
        const name = victim orelse return false;
        const removed = self.channels.fetchRemove(name) orelse return false;
        self.allocator.free(removed.key);
        return true;
    }
};

fn blankWatch() Watch {
    var watch = Watch{
        .gcra = gcra_mod.Gcra.init(join_rate_per_sec, join_burst),
        .origins = undefined,
    };
    var index: usize = 0;
    while (index < origin_ring) : (index += 1) watch.origins[index] = .{};
    return watch;
}

fn touch(watch: *Watch, origin: []const u8, now_ms: u64) void {
    const hash = std.hash.Wyhash.hash(0, origin);
    watch.origins[watch.origin_i] = .{ .hash = hash, .at_ms = now_ms, .used = true };
    watch.origin_i = (watch.origin_i + 1) % origin_ring;
    watch.last_note_ms = now_ms;
    const now_us = std.math.mul(u64, now_ms, 1000) catch std.math.maxInt(u64);
    if (!watch.gcra.allow(now_us, 1)) watch.over_rate = true;
}

fn distinctRecent(watch: *const Watch, now_ms: u64) usize {
    var hashes: [origin_ring]u64 = undefined;
    var n: usize = 0;
    for (watch.origins) |slot| {
        if (!slot.used) continue;
        if (slot.at_ms > now_ms) continue;
        if (now_ms - slot.at_ms > correlation_window_ms) continue;
        var seen = false;
        for (hashes[0..n]) |existing| {
            if (existing == slot.hash) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        hashes[n] = slot.hash;
        n += 1;
    }
    return n;
}

fn quietFor(last_note_ms: u64, now_ms: u64) bool {
    return now_ms >= last_note_ms and now_ms - last_note_ms >= relax_after_ms;
}

fn expectActions(shield: *Shield, now_ms: u64, kind: ?ActionKind, channel: ?[]const u8) !void {
    const actions = try shield.evaluate(now_ms);
    defer if (actions.len != 0) shield.allocator.free(actions);
    if (kind == null) {
        try std.testing.expectEqual(@as(usize, 0), actions.len);
        return;
    }
    try std.testing.expectEqual(@as(usize, 1), actions.len);
    try std.testing.expectEqual(kind.?, actions[0].kind);
    try std.testing.expectEqualStrings(channel.?, actions[0].channel);
}

test "GAP-O6 shield correlates distinct origins and stays bounded" {
    const alloc = std.testing.allocator;
    var shield = try Shield.init(alloc);
    defer shield.deinit();
    try std.testing.expectEqual(sketch_width * sketch_depth, shield.sketchCells());
    try std.testing.expectEqual(hottest_capacity, shield.hottest.capacity());

    const t0: u64 = 1_000_000;
    var n: usize = 0;
    while (n < 8) : (n += 1) try shield.note("#pop", "this-node", t0);
    try expectActions(&shield, t0, null, null);

    try shield.note("#trick", "peer-a", t0);
    try shield.note("#trick", "peer-b", t0);
    try shield.note("#trick", "peer-c", t0);
    try expectActions(&shield, t0, null, null);

    const peers = [_][]const u8{ "peer-a", "peer-b", "peer-c" };
    for (peers) |peer| {
        try shield.note("#raid", peer, t0);
        try shield.note("#raid", peer, t0);
    }
    try expectActions(&shield, t0, .engage, "#raid");
    try expectActions(&shield, t0, null, null);
    try expectActions(&shield, t0 + relax_after_ms, .relax, "#raid");

    var i: usize = 0;
    while (i < max_channels + 80) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "#c{d}", .{i});
        try shield.note(name, "peer-a", t0);
    }
    try std.testing.expectEqual(max_channels, shield.channelCount());

    var origin_i: usize = 0;
    while (origin_i < 80) : (origin_i += 1) {
        var origin_buf: [32]u8 = undefined;
        const origin = try std.fmt.bufPrint(&origin_buf, "peer-{d}", .{origin_i});
        try shield.note("#wide", origin, t0 + 1_000);
    }
    try std.testing.expect(shield.channelCount() <= max_channels);
    try std.testing.expectEqual(sketch_width * sketch_depth, shield.sketchCells());
    const wide = try shield.evaluate(t0 + 1_000);
    defer if (wide.len != 0) shield.allocator.free(wide);
    try std.testing.expectEqual(@as(usize, 1), wide.len);
    try std.testing.expectEqual(ActionKind.engage, wide[0].kind);
    try std.testing.expectEqualStrings("#wide", wide[0].channel);
}
