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

fn readMeta(store: *const OroStore) Meta {
    const raw = store.get(.props, meta_key) orelse return .{};
    if (raw.len != 16) return .{};
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
    const meta = readMeta(store);
    var ctx = ReplaceCtx{ .store = store, .generation = meta.generation + 1 };
    try markers.forEach(&ctx, replaceOne);
    try writeMeta(store, .{ .generation = ctx.generation, .count = ctx.seq });
}

pub fn restoreInto(store: *OroStore, markers: *Store) !void {
    const meta = readMeta(store);
    var staged = Store.init(markers.allocator);
    errdefer staged.deinit();
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
