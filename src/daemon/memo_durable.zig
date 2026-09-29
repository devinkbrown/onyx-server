// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline memos in the OroStore `memos` family.
//!
//! The generation is published after the records, so a kill keeps the previous
//! mailbox image. Restore swaps into the live MemoBox only after every row is
//! staged.

const std = @import("std");
const store_mod = @import("store.zig");
const memo_mod = @import("memo.zig");

const OroStore = store_mod.OroStore;

const meta_key = "meta";

pub const Error = error{
    BadRecord,
    Truncated,
    MissingRecord,
} || OroStore.StoreError || std.mem.Allocator.Error || memo_mod.Error;

const Meta = struct {
    generation: u64 = 0,
    count: u64 = 0,
};

fn readMeta(store: *const OroStore) Meta {
    const raw = store.get(.memos, meta_key) orelse return .{};
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
    try store.put(.memos, meta_key, &raw);
}

fn messageKey(gen: u64, seq: u64, out: *[17]u8) []const u8 {
    out[0] = 'm';
    std.mem.writeInt(u64, out[1..9], gen, .little);
    std.mem.writeInt(u64, out[9..17], seq, .little);
    return out;
}

const Row = struct {
    account: []const u8,
    from: []const u8,
    text: []const u8,
    sent_ms: i64,
};

fn putRow(store: *OroStore, gen: u64, seq: u64, row: Row) !void {
    var body: [16 + 512 + 64 + 1024]u8 = undefined;
    var n: usize = 0;
    body[n] = 1;
    n += 1;
    std.mem.writeInt(i64, body[n..][0..8], row.sent_ms, .little);
    n += 8;
    const fields = [_][]const u8{ row.account, row.from, row.text };
    for (fields) |field| {
        if (field.len > 65535) return error.BadRecord;
        std.mem.writeInt(u16, body[n..][0..2], @intCast(field.len), .little);
        n += 2;
        @memcpy(body[n..][0..field.len], field);
        n += field.len;
    }
    var key_buf: [17]u8 = undefined;
    try store.put(.memos, messageKey(gen, seq, &key_buf), body[0..n]);
}

pub fn append(store: *OroStore, account: []const u8, from: []const u8, text: []const u8, sent_ms: i64) !void {
    const meta = readMeta(store);
    try putRow(store, meta.generation, meta.count, .{
        .account = account,
        .from = from,
        .text = text,
        .sent_ms = sent_ms,
    });
    try writeMeta(store, .{ .generation = meta.generation, .count = meta.count + 1 });
}

const ReplaceCtx = struct {
    store: *OroStore,
    generation: u64,
    seq: u64 = 0,
};

fn replaceOne(ctx: *ReplaceCtx, account: []const u8, message: *const memo_mod.Message) !void {
    try putRow(ctx.store, ctx.generation, ctx.seq, .{
        .account = account,
        .from = message.from,
        .text = message.text,
        .sent_ms = message.sent_ms,
    });
    ctx.seq += 1;
}

pub fn replaceAll(store: *OroStore, box: *const memo_mod.MemoBox) !void {
    const meta = readMeta(store);
    var ctx = ReplaceCtx{ .store = store, .generation = meta.generation + 1 };
    try box.forEach(&ctx, replaceOne);
    try writeMeta(store, .{ .generation = ctx.generation, .count = ctx.seq });
}

pub fn restoreInto(store: *OroStore, box: *memo_mod.MemoBox) !void {
    const meta = readMeta(store);
    var staged = memo_mod.MemoBox.initWithConfig(box.allocator, box.cfg);
    errdefer staged.deinit();
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [17]u8 = undefined;
        const raw = store.get(.memos, messageKey(meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        if (raw.len < 9 or raw[0] != 1) return error.BadRecord;
        const sent_ms = std.mem.readInt(i64, raw[1..9], .little);
        var n: usize = 9;
        var fields: [3][]const u8 = undefined;
        for (&fields) |*field| {
            if (raw.len < n + 2) return error.Truncated;
            const len = std.mem.readInt(u16, raw[n..][0..2], .little);
            n += 2;
            if (raw.len < n + len) return error.Truncated;
            field.* = raw[n..][0..len];
            n += len;
        }
        if (n != raw.len) return error.BadRecord;
        _ = try staged.send(fields[0], fields[1], fields[2], sent_ms);
    }
    std.mem.swap(memo_mod.MemoBox, box, &staged);
    staged.deinit();
}

test "GAP-D2 memo survives a dropped store image and keeps the mailbox bound" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d2.wal");
    var box = memo_mod.MemoBox.initWithConfig(alloc, .{ .max_per_account = 1 });
    defer box.deinit();
    try std.testing.expectEqual(@as(usize, 1), try box.send("alice", "bob", "while you were gone", 50));
    try append(&store, "alice", "bob", "while you were gone", 50);
    try std.testing.expectError(error.MailboxFull, box.send("alice", "carol", "third", 60));
    store.deinit();

    var store2 = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d2.wal");
    defer store2.deinit();
    var restored = memo_mod.MemoBox.initWithConfig(alloc, .{ .max_per_account = 1 });
    defer restored.deinit();
    _ = try restored.send("alice", "keep", "sentinel", 1);
    try restoreInto(&store2, &restored);
    const pending = restored.pending("alice");
    try std.testing.expectEqual(@as(usize, 1), pending.len);
    try std.testing.expectEqualStrings("bob", pending[0].from);
    try std.testing.expectEqualStrings("while you were gone", pending[0].text);
    try std.testing.expectEqual(@as(i64, 50), pending[0].sent_ms);
    try std.testing.expectError(error.MailboxFull, restored.send("alice", "carol", "nope", 70));
}
