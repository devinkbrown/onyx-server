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

/// A complete table with maximum length channel names is below this ceiling.
/// The limit is also comfortably within the Helix arena budget.
pub const max_checkpoint_channel_bytes: usize = 65_535;
pub const max_checkpoint_bytes: usize = @min(@import("helix/live.zig").max_arena_bytes, 80 * 1024 * 1024);
pub const checkpoint_magic = [_]u8{ 'R', 'S', 'H', 'D' };
pub const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 3 + 4;
const checkpoint_checksum_len: usize = 32;
const checkpoint_fixed_body_len: usize = 2 + 2 + 8 + 8 + 8 + sketch_depth * 16 + sketch_width * sketch_depth * 8;
const checkpoint_watch_fixed_len: usize = 2 + 1 + 1 + 8 + 8 + 8 + 16 + origin_ring * 17;
const checkpoint_slot_len: usize = 8 + 8 + 8 + 8;
const checkpoint_domain = "onyx-raid-shield-checkpoint-v1";
const sketch_prime: u64 = 0x1fff_ffff_ffff_ffff;

pub const CheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    InvalidDimensions,
    NonCanonicalOrder,
    DuplicateItem,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Checks the entire wire image, including the sketch and ring, without
/// allocating. The two duplicate checks have small fixed upper bounds.
pub fn validateUpgradeCheckpoint(bytes: []const u8) CheckpointError!void {
    if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const expected_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    const saved: [checkpoint_checksum_len]u8 = bytes[bytes.len - checkpoint_checksum_len ..][0..checkpoint_checksum_len].*;
    if (!std.crypto.timing_safe.eql([checkpoint_checksum_len]u8, digest, saved)) return error.ChecksumMismatch;

    var reader = CheckpointReader{ .bytes = bytes[checkpoint_header_len .. bytes.len - checkpoint_checksum_len] };
    const channel_count: usize = try reader.readU16();
    const slot_count: usize = try reader.readU16();
    if (channel_count > max_channels or slot_count > hottest_capacity) return error.CheckpointTooLarge;
    if (body_len < checkpoint_fixed_body_len + channel_count * checkpoint_watch_fixed_len + slot_count * checkpoint_slot_len) return error.Truncated;
    _ = try reader.readU64(); // noted; an allocation failure can make this differ from joins.total
    _ = try reader.readU64(); // exact Count-Min total
    const next_order = try reader.readU64();
    for (0..sketch_depth) |_| {
        const a = try reader.readU64();
        const b = try reader.readU64();
        if (a == 0 or a >= sketch_prime or b >= sketch_prime) return error.InvalidField;
    }
    for (0..sketch_width * sketch_depth) |_| _ = try reader.readU64();

    var seen_items: [hottest_capacity]u64 = undefined;
    var seen_orders: [hottest_capacity]u64 = undefined;
    for (0..slot_count) |index| {
        const item = try reader.readU64();
        const count = try reader.readU64();
        const err_count = try reader.readU64();
        const order = try reader.readU64();
        if (count == 0 or err_count >= count or order >= next_order) return error.InvalidField;
        for (seen_items[0..index], seen_orders[0..index]) |prior_item, prior_order| {
            if (prior_item == item or prior_order == order) return error.DuplicateItem;
        }
        seen_items[index] = item;
        seen_orders[index] = order;
    }

    var previous_name: ?[]const u8 = null;
    for (0..channel_count) |_| {
        const name_len: usize = try reader.readU16();
        if (name_len < 2 or name_len > max_checkpoint_channel_bytes) return error.InvalidField;
        const name = try reader.take(name_len);
        if (name[0] != '#' and name[0] != '&') return error.InvalidField;
        if (previous_name) |previous| {
            if (!std.mem.lessThan(u8, previous, name)) return error.NonCanonicalOrder;
        }
        previous_name = name;
        const origin_i = try reader.readByte();
        const flags = try reader.readByte();
        if (origin_i >= origin_ring or flags & ~@as(u8, 3) != 0) return error.InvalidField;
        _ = try reader.readU64(); // last note timestamp
        if (try reader.readU64() != join_rate_per_sec) return error.InvalidField;
        if (try reader.readU64() != join_burst) return error.InvalidField;
        _ = try reader.readU128(); // GCRA theoretical arrival time
        for (0..origin_ring) |_| {
            const used = try reader.readByte();
            const hash = try reader.readU64();
            const at_ms = try reader.readU64();
            if (used > 1 or (used == 0 and (hash != 0 or at_ms != 0))) return error.InvalidField;
        }
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

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

    /// A successor cannot reconstruct a recent correlation window or an
    /// engaged slowmode timer from the channel modes alone. A quiet, never
    /// engaged watch has refilled its GCRA budget and aged out its origins, so
    /// losing that watch cannot weaken a future mitigation decision.
    pub fn hasActiveContinuity(self: *const Shield, now_ms: u64) bool {
        var it = self.channels.valueIterator();
        while (it.next()) |watch| {
            if (watch.engaged or watch.over_rate) return true;
            if (watch.last_note_ms > now_ms or now_ms - watch.last_note_ms <= correlation_window_ms)
                return true;
        }
        return false;
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

    /// Serialize every mutable observation. Physical Space-Saving slot order
    /// and ring positions matter for subsequent ties and correlation.
    pub fn exportUpgradeCheckpoint(self: *const Shield, allocator: std.mem.Allocator) CheckpointError![]u8 {
        if (self.channels.count() > max_channels or
            self.joins.width != sketch_width or self.joins.depth != sketch_depth or
            self.joins.cells.len != sketch_width * sketch_depth or self.joins.seeds.len != sketch_depth or
            self.hottest.capacity_value != hottest_capacity or self.hottest.slots.items.len > hottest_capacity or
            self.hottest.index.count() != self.hottest.slots.items.len)
            return error.InvalidField;
        for (self.joins.seeds) |seed| {
            if (seed.a == 0 or seed.a >= sketch_prime or seed.b >= sketch_prime) return error.InvalidField;
        }
        for (self.hottest.slots.items, 0..) |slot, index| {
            if (slot.count == 0 or slot.@"error" >= slot.count or slot.order >= self.hottest.next_order or
                self.hottest.index.get(slot.item) != index)
                return error.InvalidField;
            for (self.hottest.slots.items[0..index]) |prior| {
                if (prior.item == slot.item or prior.order == slot.order) return error.DuplicateItem;
            }
        }

        var names: [max_channels][]const u8 = undefined;
        var name_count: usize = 0;
        var total_len: usize = checkpoint_header_len + checkpoint_checksum_len + checkpoint_fixed_body_len;
        try checkpointAddLen(&total_len, self.hottest.slots.items.len * checkpoint_slot_len);
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const watch = entry.value_ptr;
            if (name.len < 2 or name.len > max_checkpoint_channel_bytes or (name[0] != '#' and name[0] != '&') or
                watch.origin_i >= origin_ring or watch.gcra.rate_per_sec != join_rate_per_sec or watch.gcra.burst != join_burst)
                return error.InvalidField;
            for (watch.origins) |origin| {
                if (!origin.used and (origin.hash != 0 or origin.at_ms != 0)) return error.InvalidField;
            }
            names[name_count] = name;
            name_count += 1;
            try checkpointAddLen(&total_len, checkpoint_watch_fixed_len);
            try checkpointAddLen(&total_len, name.len);
        }
        std.mem.sort([]const u8, names[0..name_count], {}, channelLessThan);

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = CheckpointWriter{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeBytes(&.{ 0, 0, 0 });
        writer.writeU32(@intCast(total_len - checkpoint_header_len - checkpoint_checksum_len));
        writer.writeU16(@intCast(name_count));
        writer.writeU16(@intCast(self.hottest.slots.items.len));
        writer.writeU64(self.noted);
        writer.writeU64(self.joins.total);
        writer.writeU64(@intCast(self.hottest.next_order));
        for (self.joins.seeds) |seed| {
            writer.writeU64(seed.a);
            writer.writeU64(seed.b);
        }
        for (self.joins.cells) |cell| writer.writeU64(cell);
        for (self.hottest.slots.items) |slot| {
            writer.writeU64(slot.item);
            writer.writeU64(@intCast(slot.count));
            writer.writeU64(@intCast(slot.@"error"));
            writer.writeU64(@intCast(slot.order));
        }
        for (names[0..name_count]) |name| {
            const watch = self.channels.get(name) orelse unreachable;
            writer.writeU16(@intCast(name.len));
            writer.writeBytes(name);
            writer.writeByte(@intCast(watch.origin_i));
            writer.writeByte(@as(u8, @intFromBool(watch.over_rate)) | (@as(u8, @intFromBool(watch.engaged)) << 1));
            writer.writeU64(watch.last_note_ms);
            writer.writeU64(watch.gcra.rate_per_sec);
            writer.writeU64(watch.gcra.burst);
            writer.writeU128(watch.gcra.tat_scaled);
            for (watch.origins) |origin| {
                writer.writeByte(@intFromBool(origin.used));
                writer.writeU64(origin.hash);
                writer.writeU64(origin.at_ms);
            }
        }
        std.debug.assert(writer.pos + checkpoint_checksum_len == out.len);
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointChecksum(out[0..writer.pos], &digest);
        writer.writeBytes(&digest);
        try validateUpgradeCheckpoint(out);
        return out;
    }

    /// Construct a detached Shield before COMMIT. A failed allocation leaves
    /// the live Shield untouched; the caller can swap this value without fail.
    pub fn restoreUpgradeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) CheckpointError!Shield {
        try validateUpgradeCheckpoint(bytes);
        var reader = CheckpointReader{ .bytes = bytes[checkpoint_header_len .. bytes.len - checkpoint_checksum_len] };
        const channel_count: usize = try reader.readU16();
        const slot_count: usize = try reader.readU16();
        const noted = try reader.readU64();
        const joins_total = try reader.readU64();
        const next_order = try reader.readU64();
        var restored = try Shield.init(allocator);
        errdefer restored.deinit();
        restored.noted = noted;
        restored.joins.total = joins_total;
        restored.hottest.next_order = @intCast(next_order);
        for (restored.joins.seeds) |*seed| {
            seed.a = try reader.readU64();
            seed.b = try reader.readU64();
        }
        for (restored.joins.cells) |*cell| cell.* = try reader.readU64();
        try restored.hottest.slots.ensureTotalCapacityPrecise(allocator, slot_count);
        try restored.hottest.index.ensureTotalCapacity(@intCast(slot_count));
        for (0..slot_count) |index| {
            const item = try reader.readU64();
            const count = try reader.readU64();
            const err_count = try reader.readU64();
            const order = try reader.readU64();
            restored.hottest.slots.appendAssumeCapacity(.{
                .item = item,
                .count = @intCast(count),
                .@"error" = @intCast(err_count),
                .order = @intCast(order),
            });
            restored.hottest.index.putAssumeCapacity(item, index);
        }
        try restored.channels.ensureTotalCapacity(@intCast(channel_count));
        for (0..channel_count) |_| {
            const name_len: usize = try reader.readU16();
            const name = try reader.take(name_len);
            const origin_i = try reader.readByte();
            const flags = try reader.readByte();
            const last_note_ms = try reader.readU64();
            const rate = try reader.readU64();
            const burst = try reader.readU64();
            const tat_scaled = try reader.readU128();
            var watch = blankWatch();
            watch.origin_i = origin_i;
            watch.over_rate = flags & 1 != 0;
            watch.engaged = flags & 2 != 0;
            watch.last_note_ms = last_note_ms;
            watch.gcra = .{ .rate_per_sec = rate, .burst = burst, .tat_scaled = tat_scaled };
            for (&watch.origins) |*origin| {
                origin.used = try reader.readByte() == 1;
                origin.hash = try reader.readU64();
                origin.at_ms = try reader.readU64();
            }
            const owned = try allocator.dupe(u8, name);
            errdefer allocator.free(owned);
            try restored.channels.put(owned, watch);
        }
        std.debug.assert(reader.remaining() == 0);
        return restored;
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

fn channelLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn checkpointAddLen(total: *usize, amount: usize) CheckpointError!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn checkpointChecksum(bytes: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checkpoint_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const CheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *CheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn writeByte(self: *CheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeU16(self: *CheckpointWriter, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .little);
        self.pos += 2;
    }

    fn writeU32(self: *CheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn writeU64(self: *CheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn writeU128(self: *CheckpointWriter, value: u128) void {
        std.mem.writeInt(u128, self.bytes[self.pos..][0..16], value, .little);
        self.pos += 16;
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CheckpointReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn readByte(self: *CheckpointReader) CheckpointError!u8 {
        return (try self.take(1))[0];
    }

    fn readU16(self: *CheckpointReader) CheckpointError!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn readU64(self: *CheckpointReader) CheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn readU128(self: *CheckpointReader) CheckpointError!u128 {
        return std.mem.readInt(u128, (try self.take(16))[0..16], .little);
    }
};

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

test "raid shield checkpoint preserves sketches ring and engagement" {
    const alloc = std.testing.allocator;
    var source = try Shield.init(alloc);
    defer source.deinit();
    const at: u64 = 1_000_000;
    const peers = [_][]const u8{ "peer-a", "peer-b", "peer-c" };
    for (peers) |peer| {
        try source.note("#raid", peer, at);
        try source.note("#raid", peer, at);
    }
    try expectActions(&source, at, .engage, "#raid");
    for (0..40) |index| {
        var origin_buf: [32]u8 = undefined;
        const origin = try std.fmt.bufPrint(&origin_buf, "peer-{d}", .{index});
        try source.note("#ring", origin, at + 1);
    }
    try source.note("#a", "peer-a", at + 2);
    source.noted -= 1; // A failed note can advance Count-Min before the noted counter.

    const wire = try source.exportUpgradeCheckpoint(alloc);
    defer alloc.free(wire);
    try validateUpgradeCheckpoint(wire);
    var restored = try Shield.restoreUpgradeCheckpoint(alloc, wire);
    defer restored.deinit();
    try std.testing.expectEqual(source.noted, restored.noted);
    try std.testing.expectEqual(source.joins.total, restored.joins.total);
    try std.testing.expectEqualSlices(u64, source.joins.cells, restored.joins.cells);
    for (source.joins.seeds, restored.joins.seeds) |a, b| {
        try std.testing.expectEqual(a.a, b.a);
        try std.testing.expectEqual(a.b, b.b);
    }
    try std.testing.expectEqual(source.hottest.next_order, restored.hottest.next_order);
    try std.testing.expectEqual(source.hottest.slots.items.len, restored.hottest.slots.items.len);
    for (source.hottest.slots.items, restored.hottest.slots.items) |a, b| {
        try std.testing.expectEqual(a.item, b.item);
        try std.testing.expectEqual(a.count, b.count);
        try std.testing.expectEqual(a.@"error", b.@"error");
        try std.testing.expectEqual(a.order, b.order);
    }
    const original_ring = source.channels.get("#ring").?;
    const adopted_ring = restored.channels.get("#ring").?;
    try std.testing.expectEqual(original_ring.origin_i, adopted_ring.origin_i);
    for (original_ring.origins, adopted_ring.origins) |a, b| {
        try std.testing.expectEqual(a.hash, b.hash);
        try std.testing.expectEqual(a.at_ms, b.at_ms);
        try std.testing.expectEqual(a.used, b.used);
    }
    try std.testing.expect(restored.channels.get("#raid").?.engaged);
    const reencoded = try restored.exportUpgradeCheckpoint(alloc);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, wire, reencoded);
    try expectActions(&restored, at + 1 + relax_after_ms, .relax, "#raid");
}

test "raid shield checkpoint rejects malformed and noncanonical state" {
    const alloc = std.testing.allocator;
    var source = try Shield.init(alloc);
    defer source.deinit();
    try source.note("#a", "peer-a", 100);
    try source.note("#b", "peer-b", 200);
    const wire = try source.exportUpgradeCheckpoint(alloc);
    defer alloc.free(wire);
    var damaged = try alloc.dupe(u8, wire);
    defer alloc.free(damaged);

    try std.testing.expect(!isUpgradeCheckpoint("no"));
    try std.testing.expectError(error.Truncated, validateUpgradeCheckpoint(wire[0 .. wire.len - 1]));
    damaged[4] = 2;
    try std.testing.expectError(error.UnsupportedVersion, validateUpgradeCheckpoint(damaged));
    @memcpy(damaged, wire);
    damaged[checkpoint_header_len + 4] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, validateUpgradeCheckpoint(damaged));

    const slots_at = checkpoint_header_len + 2 + 2 + 8 + 8 + 8 + sketch_depth * 16 + sketch_width * sketch_depth * 8;
    const first_watch_at = slots_at + 2 * checkpoint_slot_len;
    const second_watch_at = first_watch_at + checkpoint_watch_fixed_len + 2;
    @memcpy(damaged, wire);
    std.mem.writeInt(u64, damaged[slots_at + checkpoint_slot_len ..][0..8], std.mem.readInt(u64, damaged[slots_at..][0..8], .little), .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.DuplicateItem, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[second_watch_at + 3] = 'a';
    testRechecksum(damaged);
    try std.testing.expectError(error.NonCanonicalOrder, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[first_watch_at + 2 + 2 + 1] = 4; // unknown watch flag
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    const first_ring_at = first_watch_at + 2 + 2 + 1 + 1 + 8 + 8 + 8 + 16;
    damaged[first_ring_at + 17] = 2; // the next unused ring slot
    testRechecksum(damaged);
    try std.testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(u16, damaged[checkpoint_header_len..][0..2], @intCast(max_channels + 1), .little);
    testRechecksum(damaged);
    try std.testing.expectError(error.CheckpointTooLarge, validateUpgradeCheckpoint(damaged));
}

test "raid shield checkpoint restore is allocation failure atomic" {
    const alloc = std.testing.allocator;
    var source = try Shield.init(alloc);
    defer source.deinit();
    try source.note("#a", "peer-a", 100);
    try source.note("#b", "peer-b", 200);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, shield: *const Shield) !void {
            const bytes = try shield.exportUpgradeCheckpoint(allocator);
            defer allocator.free(bytes);
            try validateUpgradeCheckpoint(bytes);
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, EncodeSweep.run, .{&source});
    const wire = try source.exportUpgradeCheckpoint(alloc);
    defer alloc.free(wire);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var current = try Shield.init(allocator);
            defer current.deinit();
            try current.note("#keeper", "peer", 10);
            var staged = Shield.restoreUpgradeCheckpoint(allocator, bytes) catch |err| {
                try std.testing.expect(current.channels.contains("#keeper"));
                try std.testing.expectEqual(@as(usize, 1), current.channelCount());
                return err;
            };
            std.mem.swap(Shield, &current, &staged);
            staged.deinit();
            try std.testing.expect(current.channels.contains("#a"));
            try std.testing.expect(!current.channels.contains("#keeper"));
        }
    };
    try std.testing.checkAllAllocationFailures(alloc, RestoreSweep.run, .{wire});
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    @memcpy(bytes[bytes.len - checkpoint_checksum_len ..], &digest);
}
