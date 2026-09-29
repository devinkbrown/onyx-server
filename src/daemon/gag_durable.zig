// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCX `MODE +z` gag IPs in the OroStore `bans` family.
//!
//! Keys are prefixed `gag:` so they sit beside `ward:` and `saccess:` without
//! sharing either namespace. The generation is published after the records.

const std = @import("std");
const store_mod = @import("store.zig");
const gag_set = @import("gag_set.zig");

const OroStore = store_mod.OroStore;

const meta_key = "gag:meta";

pub const Error = error{
    BadRecord,
    Truncated,
    MissingRecord,
} || store_mod.StoreError || gag_set.GagError;

const Meta = struct {
    generation: u64 = 0,
    count: u64 = 0,
};

fn readMeta(store: *const OroStore) Meta {
    const raw = store.get(.bans, meta_key) orelse return .{};
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
    try store.put(.bans, meta_key, &raw);
}

fn recordKey(gen: u64, seq: u64, out: *[48]u8) []const u8 {
    return std.fmt.bufPrint(out, "gag:{x:0>16}:{d}", .{ gen, seq }) catch unreachable;
}

fn putIp(store: *OroStore, gen: u64, seq: u64, ip: []const u8) !void {
    if (ip.len == 0 or ip.len > 64) return error.BadRecord;
    var body: [65]u8 = undefined;
    body[0] = 1;
    @memcpy(body[1..][0..ip.len], ip);
    var key_buf: [48]u8 = undefined;
    try store.put(.bans, recordKey(gen, seq, &key_buf), body[0 .. 1 + ip.len]);
}

pub fn replaceAll(store: *OroStore, gags: *const gag_set.GagSet) !void {
    const meta = readMeta(store);
    const generation = meta.generation + 1;
    for (gags.ips.items, 0..) |ip, seq| {
        try putIp(store, generation, @intCast(seq), ip);
    }
    try writeMeta(store, .{ .generation = generation, .count = gags.ips.items.len });
}

pub fn restoreInto(store: *OroStore, gags: *gag_set.GagSet) !void {
    const meta = readMeta(store);
    var staged = gag_set.GagSet.init(gags.allocator, gags.params);
    errdefer staged.deinit();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [48]u8 = undefined;
        const raw = store.get(.bans, recordKey(meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        if (raw.len < 2 or raw[0] != 1) return error.BadRecord;
        try staged.add(raw[1..]);
    }
    std.mem.swap(gag_set.GagSet, gags, &staged);
    staged.deinit();
}

test "UPGRADE GAP-D3 gag ip survives a dropped store image" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d3-gag.wal");
    var gags = gag_set.GagSet.init(alloc, .{});
    defer gags.deinit();
    try gags.add("192.0.2.10");
    try gags.add("192.0.2.11");
    try replaceAll(&store, &gags);
    try std.testing.expect(gags.remove("192.0.2.10"));
    try replaceAll(&store, &gags);
    store.deinit();

    var store2 = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d3-gag.wal");
    defer store2.deinit();
    var restored = gag_set.GagSet.init(alloc, .{});
    defer restored.deinit();
    try restored.add("198.51.100.9");
    try restoreInto(&store2, &restored);
    try std.testing.expect(!restored.contains("198.51.100.9"));
    try std.testing.expect(!restored.contains("192.0.2.10"));
    try std.testing.expect(restored.contains("192.0.2.11"));
    try std.testing.expect(restored.contains("192.0.2.11"));
}
