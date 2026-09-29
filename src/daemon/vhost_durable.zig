// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Granted vhost personas and offer templates in the OroStore `vhosts` family.
//!
//! The generation is published after the records. Restore swaps into the live
//! registry only after every persona and offer has been staged.

const std = @import("std");
const store_mod = @import("store.zig");
const guise = @import("guise.zig");

const OroStore = store_mod.OroStore;
const Source = guise.Source;

const meta_key = "meta";

pub const Error = error{
    BadRecord,
    Truncated,
    MissingRecord,
} || store_mod.StoreError || guise.GuiseError;

const Meta = struct {
    generation: u64 = 0,
    count: u64 = 0,
};

fn readMeta(store: *const OroStore) Meta {
    const raw = store.get(.vhosts, meta_key) orelse return .{};
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
    try store.put(.vhosts, meta_key, &raw);
}

fn recordKey(gen: u64, seq: u64, out: *[48]u8) []const u8 {
    return std.fmt.bufPrint(out, "m{x:0>16}:{d}", .{ gen, seq }) catch unreachable;
}

fn sourceToken(source: Source) []const u8 {
    return source.token();
}

fn sourceFrom(token: []const u8) ?Source {
    if (std.mem.eql(u8, token, "granted")) return .granted;
    if (std.mem.eql(u8, token, "claimed")) return .claimed;
    if (std.mem.eql(u8, token, "verified")) return .verified;
    if (std.mem.eql(u8, token, "auto")) return .auto;
    return null;
}

fn putFields(store: *OroStore, gen: u64, seq: u64, kind: u8, ms: i64, fields: []const []const u8) !void {
    var body: [1 + 8 + 4 * (2 + 128)]u8 = undefined;
    var n: usize = 0;
    body[n] = kind;
    n += 1;
    std.mem.writeInt(i64, body[n..][0..8], ms, .little);
    n += 8;
    for (fields) |field| {
        if (field.len > 65535) return error.BadRecord;
        std.mem.writeInt(u16, body[n..][0..2], @intCast(field.len), .little);
        n += 2;
        @memcpy(body[n..][0..field.len], field);
        n += field.len;
    }
    var key_buf: [48]u8 = undefined;
    try store.put(.vhosts, recordKey(gen, seq, &key_buf), body[0..n]);
}

pub fn replaceAll(store: *OroStore, registry: *const guise.Registry) !void {
    const meta = readMeta(store);
    const generation = meta.generation + 1;
    var seq: u64 = 0;
    var it = registry.accounts.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |persona| {
            try putFields(store, generation, seq, 'p', persona.granted_ms, &.{
                entry.key_ptr.*,
                persona.name,
                persona.host,
                sourceToken(persona.source),
            });
            seq += 1;
        }
    }
    for (registry.offers.items) |offer| {
        try putFields(store, generation, seq, 'o', 0, &.{ offer.template, offer.label });
        seq += 1;
    }
    try writeMeta(store, .{ .generation = generation, .count = seq });
}

fn readFields(raw: []const u8, n: *usize, count: usize, out: [][]const u8) !void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (raw.len < n.* + 2) return error.Truncated;
        const len = std.mem.readInt(u16, raw[n.*..][0..2], .little);
        n.* += 2;
        if (raw.len < n.* + len) return error.Truncated;
        out[i] = raw[n.*..][0..len];
        n.* += len;
    }
}

pub fn restoreInto(store: *OroStore, registry: *guise.Registry) !void {
    const meta = readMeta(store);
    var staged = guise.Registry.init(registry.allocator, registry.params);
    errdefer staged.deinit();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [48]u8 = undefined;
        const raw = store.get(.vhosts, recordKey(meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        if (raw.len < 9) return error.BadRecord;
        const kind = raw[0];
        const ms = std.mem.readInt(i64, raw[1..9], .little);
        var n: usize = 9;
        if (kind == 'p') {
            var fields: [4][]const u8 = undefined;
            try readFields(raw, &n, 4, &fields);
            if (n != raw.len) return error.BadRecord;
            const source = sourceFrom(fields[3]) orelse return error.BadRecord;
            try staged.grant(fields[0], fields[1], fields[2], source, ms);
        } else if (kind == 'o') {
            var fields: [2][]const u8 = undefined;
            try readFields(raw, &n, 2, &fields);
            if (n != raw.len) return error.BadRecord;
            try staged.addOffer(fields[0], fields[1]);
        } else return error.BadRecord;
    }
    std.mem.swap(guise.Registry, registry, &staged);
    staged.deinit();
}

test "UPGRADE GAP-D3 granted vhost survives a dropped store image" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d3-vhost.wal");
    var registry = guise.Registry.init(alloc, .{});
    defer registry.deinit();
    try registry.grant("Carol", "staff", "carol.staff.example", .granted, 40);
    try registry.addOffer("*.users.example", "community");
    try replaceAll(&store, &registry);
    store.deinit();

    var store2 = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d3-vhost.wal");
    defer store2.deinit();
    var restored = guise.Registry.init(alloc, .{});
    defer restored.deinit();
    try restored.grant("carol", "sentinel", "gone.example", .auto, 1);
    try restoreInto(&store2, &restored);
    const personas = restored.personas("carol");
    try std.testing.expectEqual(@as(usize, 1), personas.len);
    try std.testing.expectEqualStrings("staff", personas[0].name);
    try std.testing.expectEqualStrings("carol.staff.example", personas[0].host);
    try std.testing.expectEqual(Source.granted, personas[0].source);
    try std.testing.expectEqual(@as(i64, 40), personas[0].granted_ms);
    try std.testing.expect(restored.find("carol", "sentinel") == null);
    const offers = restored.offerList();
    try std.testing.expectEqual(@as(usize, 1), offers.len);
    try std.testing.expectEqualStrings("*.users.example", offers[0].template);
    try std.testing.expectEqualStrings("community", offers[0].label);
}
