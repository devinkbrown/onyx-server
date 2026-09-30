// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account read markers in the OroStore `props` family.
//!
//! Keys are prefixed `markread:` so they do not collide with credential props.
//! The generation is published after the records, so a kill keeps the previous
//! image. Restore swaps into the live store only after every row is staged.

const std = @import("std");
const store_mod = @import("store.zig");
const read_marker_store = @import("../proto/read_marker_store.zig");

const OroStore = store_mod.OroStore;
const Store = read_marker_store.DefaultStore;
const Timestamp = read_marker_store.Timestamp;

const meta_key = "markread:meta";

pub const Error = error{
    BadRecord,
    Truncated,
    MissingRecord,
} || store_mod.StoreError || read_marker_store.ReadMarkerStoreError;

const Meta = struct {
    generation: u64 = 0,
    count: u64 = 0,
};

fn readMeta(store: *const OroStore) Error!Meta {
    const raw = store.get(.props, meta_key) orelse return .{};
    if (raw.len != 16) return error.BadRecord;
    return .{
        .generation = std.mem.readInt(u64, raw[0..8], .little),
        .count = std.mem.readInt(u64, raw[8..16], .little),
    };
}

fn writeMeta(store: *OroStore, meta: Meta) !void {
    var raw: [16]u8 = undefined;
    std.mem.writeInt(u64, raw[0..8], meta.generation, .little);
    std.mem.writeInt(u64, raw[8..16], meta.count, .little);
    try store.put(.props, meta_key, &raw);
}

fn recordKey(gen: u64, seq: u64, out: *[64]u8) []const u8 {
    return std.fmt.bufPrint(out, "markread:{x:0>16}:{d}", .{ gen, seq }) catch unreachable;
}

fn putMarker(store: *OroStore, gen: u64, seq: u64, owner: []const u8, target: []const u8, timestamp: Timestamp) !void {
    if (owner.len > 65535 or target.len > 65535) return error.BadRecord;
    var body: [1 + 24 + 2 + 128 + 2 + 128]u8 = undefined;
    var n: usize = 0;
    body[n] = 1;
    n += 1;
    @memcpy(body[n..][0..24], timestamp.slice());
    n += 24;
    const fields = [_][]const u8{ owner, target };
    for (fields) |field| {
        std.mem.writeInt(u16, body[n..][0..2], @intCast(field.len), .little);
        n += 2;
        @memcpy(body[n..][0..field.len], field);
        n += field.len;
    }
    var key_buf: [64]u8 = undefined;
    try store.put(.props, recordKey(gen, seq, &key_buf), body[0..n]);
}

const ReplaceCtx = struct {
    store: *OroStore,
    generation: u64,
    seq: u64 = 0,
};

fn replaceOne(ctx: *ReplaceCtx, owner: []const u8, target: []const u8, timestamp: Timestamp) !void {
    try putMarker(ctx.store, ctx.generation, ctx.seq, owner, target, timestamp);
    ctx.seq += 1;
}

pub fn replaceAll(store: *OroStore, markers: *const Store) !void {
    const meta = try readMeta(store);
    var ctx = ReplaceCtx{ .store = store, .generation = meta.generation + 1 };
    try markers.forEach(&ctx, replaceOne);
    try writeMeta(store, .{ .generation = ctx.generation, .count = ctx.seq });
}

pub fn restoreInto(store: *OroStore, markers: *Store) !void {
    const meta = try readMeta(store);
    var staged = Store.init(markers.allocator);
    errdefer staged.deinit();
    if (meta.count > read_marker_store.default_max_entries) return error.BadRecord;
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [64]u8 = undefined;
        const raw = store.get(.props, recordKey(meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        if (raw.len < 25 or raw[0] != 1) return error.BadRecord;
        const timestamp = Timestamp.parseWire(raw[1..25]) catch return error.BadRecord;
        var n: usize = 25;
        var fields: [2][]const u8 = undefined;
        for (&fields) |*field| {
            if (raw.len < n + 2) return error.Truncated;
            const len = std.mem.readInt(u16, raw[n..][0..2], .little);
            n += 2;
            if (raw.len < n + len) return error.Truncated;
            field.* = raw[n..][0..len];
            n += len;
        }
        if (n != raw.len) return error.BadRecord;
        _ = try staged.set(fields[0], fields[1], timestamp);
    }
    std.mem.swap(Store, markers, &staged);
    staged.deinit();
}

/// New rows retain one bounded position plus its exact signed mesh fact.
/// Legacy generation rows remain readable and local-only until an authenticated
/// command explicitly authors a signed replacement. Callers serialize store access.
pub const item_prefix = "markread:item:";
const clock_key = "markread:clock";
pub const max_fact_bytes = 1536;
const max_item_key = item_prefix.len + read_marker_store.default_max_owner_bytes + 1 + read_marker_store.default_max_target_bytes;
const max_item_body = 3 + 24 + 2 + max_fact_bytes;

pub const Row = struct {
    owner: []const u8,
    target: []const u8,
    timestamp: Timestamp,
    fact_wire: ?[]const u8,
};

pub const RestoreCandidate = struct {
    markers: Store,
    rows: std.ArrayList(Row) = .empty,
    clock: u64 = 0,

    pub fn deinit(self: *RestoreCandidate) void {
        self.rows.deinit(self.markers.allocator);
        self.markers.deinit();
    }
};

pub fn clock(store: *const OroStore) Error!u64 {
    const raw = store.get(.props, clock_key) orelse return 0;
    if (raw.len != 8) return error.BadRecord;
    return std.mem.readInt(u64, raw[0..8], .little);
}

fn itemKey(owner: []const u8, target: []const u8, out: *[max_item_key]u8) Error![]const u8 {
    // Reuse the runtime store's complete input validation before indexing buffers.
    var validation = Store.init(std.heap.page_allocator);
    defer validation.deinit();
    _ = try validation.get(owner, target);
    @memcpy(out[0..item_prefix.len], item_prefix);
    @memcpy(out[item_prefix.len..][0..owner.len], owner);
    const sep = item_prefix.len + owner.len;
    out[sep] = 0;
    for (target, 0..) |byte, i| out[sep + 1 + i] = std.ascii.toLower(byte);
    return out[0 .. sep + 1 + target.len];
}

pub fn preparePut(store: *OroStore, owner: []const u8, target: []const u8, timestamp: Timestamp, fact_wire: ?[]const u8) !store_mod.PreparedBatch {
    return preparePutInternal(store, owner, target, timestamp, fact_wire, null);
}

/// Persist the signing/observation watermark even if later winning positions
/// replace every locally authored fact. It must not be recovered from winners.
pub fn preparePutWithClock(store: *OroStore, owner: []const u8, target: []const u8, timestamp: Timestamp, fact_wire: ?[]const u8, watermark: u64) !store_mod.PreparedBatch {
    return preparePutInternal(store, owner, target, timestamp, fact_wire, watermark);
}

fn preparePutInternal(store: *OroStore, owner: []const u8, target: []const u8, timestamp: Timestamp, fact_wire: ?[]const u8, watermark: ?u64) !store_mod.PreparedBatch {
    var key_buf: [max_item_key]u8 = undefined;
    const key = try itemKey(owner, target, &key_buf);
    const fact = fact_wire orelse "";
    if (fact.len > max_fact_bytes) return error.BadRecord;
    if (fact_wire != null and fact.len == 0) return error.BadRecord;
    _ = Timestamp.parseWire(timestamp.slice()) catch return error.BadRecord;
    var body: [max_item_body]u8 = undefined;
    @memcpy(body[0..3], "MR1");
    @memcpy(body[3..27], timestamp.slice());
    std.mem.writeInt(u16, body[27..29], @intCast(fact.len), .little);
    @memcpy(body[29..][0..fact.len], fact);
    var mutations: [2]store_mod.BatchMutation = undefined;
    mutations[0] = .{ .family = .props, .kind = .put, .key = key, .value = body[0 .. 29 + fact.len] };
    var clock_buf: [8]u8 = undefined;
    var count: usize = 1;
    if (watermark) |next| {
        std.mem.writeInt(u64, &clock_buf, @max(try clock(store), next), .little);
        mutations[1] = .{ .family = .props, .kind = .put, .key = clock_key, .value = &clock_buf };
        count = 2;
    }
    return try store.prepareBatch(mutations[0..count]);
}

/// Every row and runtime allocation is staged, and the caller validates/stages
/// all signed facts before swapping either runtime markers or the mesh frontier.
/// Row slices borrow OroStore, so retain its lock until the candidate is consumed.
pub fn stageRestore(store: *OroStore, allocator: std.mem.Allocator) Error!RestoreCandidate {
    var candidate = RestoreCandidate{ .markers = Store.init(allocator), .clock = try clock(store) };
    errdefer candidate.deinit();
    try restoreInto(store, &candidate.markers);
    var it = store.maps[@intFromEnum(store_mod.Family.props)].map.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        if (!std.mem.startsWith(u8, key, item_prefix)) continue;
        const identity = key[item_prefix.len..];
        const sep = std.mem.indexOfScalar(u8, identity, 0) orelse return error.BadRecord;
        const owner = identity[0..sep];
        const target = identity[sep + 1 ..];
        var canonical_buf: [max_item_key]u8 = undefined;
        const canonical = try itemKey(owner, target, &canonical_buf);
        if (!std.mem.eql(u8, key, canonical)) return error.BadRecord;
        const raw = entry.value_ptr.*;
        if (raw.len < 29 or raw.len > max_item_body or !std.mem.eql(u8, raw[0..3], "MR1")) return error.BadRecord;
        const timestamp = Timestamp.parseWire(raw[3..27]) catch return error.BadRecord;
        const fact_len = std.mem.readInt(u16, raw[27..29], .little);
        if (raw.len != 29 + @as(usize, fact_len)) return error.BadRecord;
        _ = try candidate.markers.set(owner, target, timestamp);
        try candidate.rows.append(allocator, .{
            .owner = owner,
            .target = target,
            .timestamp = timestamp,
            .fact_wire = if (fact_len == 0) null else raw[29..],
        });
    }
    return candidate;
}

test "UPGRADE GAP-P16 read marker survives a dropped store image" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ts = try Timestamp.parseWire("1970-01-01T00:00:01.500Z");
    const newer = try Timestamp.parseWire("1970-01-01T00:00:02.000Z");
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-p16.wal");
    var markers = Store.init(alloc);
    defer markers.deinit();
    _ = try markers.set("carol", "#Room", ts);
    try replaceAll(&store, &markers);
    _ = try markers.set("carol", "#room", newer);
    try replaceAll(&store, &markers);
    store.deinit();

    var store2 = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-p16.wal");
    defer store2.deinit();
    var restored = Store.init(alloc);
    defer restored.deinit();
    const sentinel = try Timestamp.parseWire("1970-01-01T00:00:00.001Z");
    _ = try restored.set("carol", "#room", sentinel);
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    var empty = Store.init(failing.allocator());
    defer empty.deinit();
    try std.testing.expectError(error.OutOfMemory, restoreInto(&store2, &empty));
    try std.testing.expectEqual(@as(usize, 0), empty.count());
    const kept = (try restored.get("carol", "#room")).?;
    try std.testing.expectEqualStrings(sentinel.slice(), kept.slice());
    try restoreInto(&store2, &restored);
    const got = (try restored.get("carol", "#room")).?;
    try std.testing.expectEqualStrings(newer.slice(), got.slice());
    const again = (try restored.get("carol", "#ROOM")).?;
    try std.testing.expectEqualStrings(got.slice(), again.slice());
}

test "MARKREAD durable prepared row and clock preserve abort retry and reopen" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "markers.wal");
    const ts = try Timestamp.parseWire("2026-06-02T08:09:10.123Z");
    {
        var aborted = try preparePutWithClock(&store, "alice", "#ROOM", ts, "signed-fact", 17);
        aborted.deinit();
        try std.testing.expectEqual(@as(u64, 0), try clock(&store));
        var committed = try preparePutWithClock(&store, "alice", "#ROOM", ts, "signed-fact", 17);
        defer committed.deinit();
        try committed.commit();
    }
    store.deinit();
    var reopened = try OroStore.open(alloc, std.testing.io, tmp.dir, "markers.wal");
    defer reopened.deinit();
    var candidate = try stageRestore(&reopened, alloc);
    defer candidate.deinit();
    try std.testing.expectEqual(@as(u64, 17), candidate.clock);
    try std.testing.expectEqual(@as(usize, 1), candidate.rows.items.len);
    try std.testing.expectEqualStrings("signed-fact", candidate.rows.items[0].fact_wire.?);
    try std.testing.expectEqualStrings(ts.slice(), (try candidate.markers.get("alice", "#room")).?.slice());
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, stageRestore(&reopened, failing.allocator()));
}

test "MARKREAD malformed legacy metadata preserves existing runtime markers" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "malformed-markers.wal");
    defer store.deinit();
    var markers = Store.init(std.testing.allocator);
    defer markers.deinit();
    const ts = try Timestamp.parseWire("2026-06-02T08:09:10.123Z");
    _ = try markers.set("alice", "#room", ts);
    try store.put(.props, meta_key, &@as([15]u8, @splat(0)));
    try std.testing.expectError(error.BadRecord, restoreInto(&store, &markers));
    try std.testing.expectEqualStrings(ts.slice(), (try markers.get("alice", "#room")).?.slice());
    try std.testing.expectError(error.BadRecord, stageRestore(&store, std.testing.allocator));
}

test "MARKREAD durable admission allocation sweep preserves row runtime and clock then retries" {
    const alloc = std.testing.allocator;
    const old = try Timestamp.parseWire("2026-06-02T08:09:10.123Z");
    const next = try Timestamp.parseWire("2026-06-02T08:09:11.000Z");
    var failures: usize = 0;
    for (0..64) |offset| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(alloc, .{ .resize_fail_index = 0 });
        var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "marker-oom.wal");
        defer store.deinit();
        var markers = Store.init(failing.allocator());
        defer markers.deinit();
        _ = try markers.set("alice", "#room", old);
        var seed = try preparePutWithClock(&store, "alice", "#room", old, "old-fact", 7);
        try seed.commit();
        seed.deinit();
        const before_seq = store.next_seq;
        const before_offset = store.wal_offset;
        const before_changes = store.changeCount();
        var runtime = try markers.prepareSet("alice", "#room", next);
        defer runtime.deinit();
        failing.fail_index = failing.alloc_index + offset;
        var durable = preparePutWithClock(&store, "alice", "#room", next, "new-fact", 8) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            failures += 1;
            try std.testing.expectEqual(before_seq, store.next_seq);
            try std.testing.expectEqual(before_offset, store.wal_offset);
            try std.testing.expectEqual(before_changes, store.changeCount());
            try std.testing.expectEqual(@as(u64, 7), try clock(&store));
            try std.testing.expectEqualStrings(old.slice(), (try markers.get("alice", "#room")).?.slice());
            failing.fail_index = std.math.maxInt(usize);
            var cold_before = try stageRestore(&store, alloc);
            defer cold_before.deinit();
            try std.testing.expectEqualStrings("old-fact", cold_before.rows.items[0].fact_wire.?);
            var retry = try preparePutWithClock(&store, "alice", "#room", next, "new-fact", 8);
            defer retry.deinit();
            try retry.commit();
            _ = runtime.commit();
            var reopened = try OroStore.open(alloc, std.testing.io, tmp.dir, "marker-oom.wal");
            defer reopened.deinit();
            var cold = try stageRestore(&reopened, alloc);
            defer cold.deinit();
            try std.testing.expectEqual(@as(u64, 8), cold.clock);
            try std.testing.expectEqualStrings("new-fact", cold.rows.items[0].fact_wire.?);
            try std.testing.expectEqualStrings(next.slice(), (try cold.markers.get("alice", "#room")).?.slice());
            continue;
        };
        defer durable.deinit();
        failing.fail_index = std.math.maxInt(usize);
        try durable.commit();
        _ = runtime.commit();
        try std.testing.expect(failures >= 4);
        break;
    } else return error.TestUnexpectedResult;
}

test "MARKREAD durable ambiguous I/O retains live marker and clock until reopen" {
    const alloc = std.testing.allocator;
    const old = try Timestamp.parseWire("2026-06-02T08:09:10.123Z");
    const next = try Timestamp.parseWire("2026-06-02T08:09:11.000Z");
    const faults = [_]store_mod.PreparedIoFault{ .{ .write = .short }, .{ .write = .failed }, .{ .sync = true } };
    for (faults) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "marker-io.wal");
        defer store.deinit();
        var markers = Store.init(alloc);
        defer markers.deinit();
        _ = try markers.set("alice", "#room", old);
        var seed = try preparePutWithClock(&store, "alice", "#room", old, "old-fact", 7);
        try seed.commit();
        seed.deinit();
        var runtime = try markers.prepareSet("alice", "#room", next);
        defer runtime.deinit();
        var durable = try preparePutWithClock(&store, "alice", "#room", next, "new-fact", 8);
        defer durable.deinit();
        store.setPreparedIoFault(fault);
        try std.testing.expectError(error.IoAmbiguous, durable.commit());
        runtime.abort();
        try std.testing.expect(store.preparedWritesPoisoned());
        try std.testing.expectEqual(@as(u64, 7), try clock(&store));
        try std.testing.expectEqualStrings(old.slice(), (try markers.get("alice", "#room")).?.slice());
        try std.testing.expectError(error.StorePoisoned, preparePutWithClock(&store, "alice", "#room", next, "new-fact", 8));
        var reopened = try OroStore.open(alloc, std.testing.io, tmp.dir, "marker-io.wal");
        defer reopened.deinit();
        var cold = try stageRestore(&reopened, alloc);
        defer cold.deinit();
        const expected = if (fault.sync) next else old;
        try std.testing.expectEqualStrings(expected.slice(), (try cold.markers.get("alice", "#room")).?.slice());
        try std.testing.expectEqual(@as(u64, if (fault.sync) 8 else 7), cold.clock);
    }
}

test "MARKREAD repeated per-key commits keep retained durable rows bounded through compaction" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "marker-bound.wal");
    defer store.deinit();
    const ts = try Timestamp.parseWire("2026-06-02T08:09:10.123Z");
    for (1..65) |stamp| {
        var candidate = try preparePutWithClock(&store, "alice", "#room", ts, "retained-fact", @intCast(stamp));
        defer candidate.deinit();
        try candidate.commit();
        try std.testing.expectEqual(@as(u32, 2), store.maps[@intFromEnum(store_mod.Family.props)].map.count());
    }
    try store.snapshotAndTruncate();
    var reopened = try OroStore.open(alloc, std.testing.io, tmp.dir, "marker-bound.wal");
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u32, 2), reopened.maps[@intFromEnum(store_mod.Family.props)].map.count());
    var restored = try stageRestore(&reopened, alloc);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u64, 64), restored.clock);
    try std.testing.expectEqual(@as(usize, 1), restored.rows.items.len);
    try std.testing.expectEqualStrings("retained-fact", restored.rows.items[0].fact_wire.?);
}
