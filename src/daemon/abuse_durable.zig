// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shun, spamtrap, Koshi, reputation, and per-account abuse rows in the
//! OroStore `bans` family. Each prefix has its own generation, published
//! after the records, so one snapshot cannot clobber another namespace
//! (`gag:`, `ward:`, `saccess:` stay untouched).

const std = @import("std");
const store_mod = @import("store.zig");
const shun_mod = @import("shun.zig");
const content_filter_mod = @import("content_filter.zig");
const ip_reputation_mod = @import("ip_reputation.zig");
const account_abuse_mod = @import("account_abuse.zig");

const OroStore = store_mod.OroStore;

pub const Error = error{
    BadRecord,
    Truncated,
    MissingRecord,
} || store_mod.StoreError || shun_mod.ShunError || content_filter_mod.Error || ip_reputation_mod.Error || account_abuse_mod.AccountAbuse.Error;

const Meta = struct {
    generation: u64 = 0,
    count: u64 = 0,
};

const shun_meta = "shun:meta";
const spam_meta = "spam:meta";
const koshi_meta = "koshi:meta";
const rep_meta = "rep:meta";
const acct_meta = "acct:meta";

fn readMeta(store: *const OroStore, key: []const u8) Meta {
    const raw = store.get(.bans, key) orelse return .{};
    if (raw.len != 16) return .{};
    return .{
        .generation = std.mem.readInt(u64, raw[0..8], .little),
        .count = std.mem.readInt(u64, raw[8..16], .little),
    };
}

fn writeMeta(store: *OroStore, key: []const u8, meta: Meta) !void {
    var raw: [16]u8 = undefined;
    std.mem.writeInt(u64, raw[0..8], meta.generation, .little);
    std.mem.writeInt(u64, raw[8..16], meta.count, .little);
    try store.put(.bans, key, &raw);
}

fn recordKey(prefix: []const u8, gen: u64, seq: u64, out: *[64]u8) []const u8 {
    return std.fmt.bufPrint(out, "{s}:{x:0>16}:{d}", .{ prefix, gen, seq }) catch unreachable;
}

const Cursor = struct {
    raw: []const u8,
    i: usize = 0,

    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (self.i + n > self.raw.len) return error.Truncated;
        const slice = self.raw[self.i..][0..n];
        self.i += n;
        return slice;
    }

    fn u8b(self: *Cursor) Error!u8 {
        const s = try self.take(1);
        return s[0];
    }

    fn readU16(self: *Cursor) Error!u16 {
        const s = try self.take(2);
        return std.mem.readInt(u16, s[0..2], .little);
    }

    fn readU64(self: *Cursor) Error!u64 {
        const s = try self.take(8);
        return std.mem.readInt(u64, s[0..8], .little);
    }

    fn readI64(self: *Cursor) Error!i64 {
        return @bitCast(try self.readU64());
    }

    fn str(self: *Cursor) Error![]const u8 {
        const n = try self.readU16();
        return self.take(n);
    }
};

fn appendStr(body: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    if (text.len > 65535) return error.BadRecord;
    var len: [2]u8 = undefined;
    std.mem.writeInt(u16, &len, @intCast(text.len), .little);
    try body.appendSlice(allocator, &len);
    try body.appendSlice(allocator, text);
}

pub fn replaceShuns(store: *OroStore, list: *const shun_mod.ShunList) !void {
    const generation = readMeta(store, shun_meta).generation + 1;
    for (list.shuns.items, 0..) |row, seq| {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(store.allocator);
        try body.append(store.allocator, 1);
        try appendStr(&body, store.allocator, row.mask);
        try appendStr(&body, store.allocator, row.reason);
        try appendStr(&body, store.allocator, row.set_by);
        var times: [16]u8 = undefined;
        std.mem.writeInt(u64, times[0..8], @bitCast(row.created_ms), .little);
        std.mem.writeInt(u64, times[8..16], @bitCast(row.expires_ms), .little);
        try body.appendSlice(store.allocator, &times);
        var key_buf: [64]u8 = undefined;
        try store.put(.bans, recordKey("shun", generation, @intCast(seq), &key_buf), body.items);
    }
    try writeMeta(store, shun_meta, .{ .generation = generation, .count = list.shuns.items.len });
}

pub fn restoreShuns(store: *OroStore, list: *shun_mod.ShunList) !void {
    const meta = readMeta(store, shun_meta);
    if (meta.generation == 0) return;
    var staged = shun_mod.ShunList.init(list.allocator, list.params);
    errdefer staged.deinit();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [64]u8 = undefined;
        const raw = store.get(.bans, recordKey("shun", meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        var cur = Cursor{ .raw = raw };
        if (try cur.u8b() != 1) return error.BadRecord;
        const mask = try cur.str();
        const reason = try cur.str();
        const set_by = try cur.str();
        const created_ms = try cur.readI64();
        const expires_ms = try cur.readI64();
        try staged.add(.{
            .mask = mask,
            .reason = reason,
            .set_by = set_by,
            .created_ms = created_ms,
            .expires_ms = expires_ms,
        });
    }
    std.mem.swap(shun_mod.ShunList, list, &staged);
    staged.deinit();
}

pub fn replaceSpam(store: *OroStore, nicks: []const []const u8, channels: []const []const u8) !void {
    const generation = readMeta(store, spam_meta).generation + 1;
    var seq: u64 = 0;
    for (nicks) |nick| {
        try putSpam(store, generation, seq, 1, nick);
        seq += 1;
    }
    for (channels) |channel| {
        try putSpam(store, generation, seq, 2, channel);
        seq += 1;
    }
    try writeMeta(store, spam_meta, .{ .generation = generation, .count = seq });
}

fn putSpam(store: *OroStore, gen: u64, seq: u64, kind: u8, name: []const u8) !void {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    defer body.deinit(store.allocator);
    try body.append(store.allocator, 1);
    try body.append(store.allocator, kind);
    try appendStr(&body, store.allocator, name);
    var key_buf: [64]u8 = undefined;
    try store.put(.bans, recordKey("spam", gen, seq, &key_buf), body.items);
}

pub fn restoreSpam(store: *OroStore, traps: anytype) !void {
    const meta = readMeta(store, spam_meta);
    if (meta.generation == 0) return;
    var staged = @TypeOf(traps.*).init(traps.allocator);
    errdefer staged.deinit();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [64]u8 = undefined;
        const raw = store.get(.bans, recordKey("spam", meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        var cur = Cursor{ .raw = raw };
        if (try cur.u8b() != 1) return error.BadRecord;
        const kind = try cur.u8b();
        const name = try cur.str();
        switch (kind) {
            1 => try staged.addTrapNick(name),
            2 => try staged.addTrapChannel(name),
            else => return error.BadRecord,
        }
    }
    std.mem.swap(@TypeOf(traps.*), traps, &staged);
    staged.deinit();
}

pub fn replaceKoshi(store: *OroStore, filter: *const content_filter_mod.ContentFilter) !void {
    const generation = readMeta(store, koshi_meta).generation + 1;
    for (filter.list(), 0..) |pattern, seq| {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(store.allocator);
        try body.append(store.allocator, 1);
        try appendStr(&body, store.allocator, pattern);
        var key_buf: [64]u8 = undefined;
        try store.put(.bans, recordKey("koshi", generation, @intCast(seq), &key_buf), body.items);
    }
    try writeMeta(store, koshi_meta, .{ .generation = generation, .count = filter.list().len });
}

pub fn restoreKoshi(store: *OroStore, filter: *content_filter_mod.ContentFilter) !void {
    const meta = readMeta(store, koshi_meta);
    if (meta.generation == 0) return;
    while (filter.list().len > 0) {
        const last = filter.list()[filter.list().len - 1];
        if (!try filter.remove(last)) return error.BadRecord;
    }
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [64]u8 = undefined;
        const raw = store.get(.bans, recordKey("koshi", meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        var cur = Cursor{ .raw = raw };
        if (try cur.u8b() != 1) return error.BadRecord;
        const pattern = try cur.str();
        if (!try filter.add(pattern)) return error.BadRecord;
    }
}

pub fn replaceReputation(store: *OroStore, rows: []const ip_reputation_mod.StoredRow) !void {
    const generation = readMeta(store, rep_meta).generation + 1;
    for (rows, 0..) |row, seq| {
        var body: [1 + 1 + 16 + 8 + 8]u8 = undefined;
        body[0] = 1;
        body[1] = row.tag;
        @memcpy(body[2..18], &row.bytes);
        std.mem.writeInt(u64, body[18..26], @bitCast(row.score), .little);
        std.mem.writeInt(u64, body[26..34], row.updated_ms, .little);
        var key_buf: [64]u8 = undefined;
        try store.put(.bans, recordKey("rep", generation, @intCast(seq), &key_buf), &body);
    }
    try writeMeta(store, rep_meta, .{ .generation = generation, .count = rows.len });
}

pub fn restoreReputation(store: *OroStore, rep: *ip_reputation_mod.IpReputation) !void {
    const meta = readMeta(store, rep_meta);
    if (meta.generation == 0) return;
    rep.clearAll();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [64]u8 = undefined;
        const raw = store.get(.bans, recordKey("rep", meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        if (raw.len != 34 or raw[0] != 1) return error.BadRecord;
        var bytes: [16]u8 = undefined;
        @memcpy(&bytes, raw[2..18]);
        const score: f64 = @bitCast(std.mem.readInt(u64, raw[18..26], .little));
        const updated_ms = std.mem.readInt(u64, raw[26..34], .little);
        try rep.importRow(.{
            .tag = raw[1],
            .bytes = bytes,
            .score = score,
            .updated_ms = updated_ms,
        });
    }
}

pub fn replaceAccounts(store: *OroStore, scores: *const account_abuse_mod.AccountAbuse) !void {
    const generation = readMeta(store, acct_meta).generation + 1;
    var seq: u64 = 0;
    var it = scores.scores.iterator();
    while (it.next()) |kv| {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(store.allocator);
        try body.append(store.allocator, 1);
        try appendStr(&body, store.allocator, kv.key_ptr.*);
        var raw_score: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw_score, kv.value_ptr.*, .little);
        try body.appendSlice(store.allocator, &raw_score);
        var key_buf: [64]u8 = undefined;
        try store.put(.bans, recordKey("acct", generation, seq, &key_buf), body.items);
        seq += 1;
    }
    try writeMeta(store, acct_meta, .{ .generation = generation, .count = seq });
}

pub fn restoreAccounts(store: *OroStore, scores: *account_abuse_mod.AccountAbuse) !void {
    const meta = readMeta(store, acct_meta);
    if (meta.generation == 0) return;
    var staged = account_abuse_mod.AccountAbuse.init(scores.allocator);
    errdefer staged.deinit();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [64]u8 = undefined;
        const raw = store.get(.bans, recordKey("acct", meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        var cur = Cursor{ .raw = raw };
        if (try cur.u8b() != 1) return error.BadRecord;
        const account = try cur.str();
        const value_raw = try cur.take(4);
        const value = std.mem.readInt(u32, value_raw[0..4], .little);
        try staged.importScore(account, value);
    }
    std.mem.swap(account_abuse_mod.AccountAbuse, scores, &staged);
    staged.deinit();
}
