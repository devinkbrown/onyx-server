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
} || store_mod.StoreError || std.mem.Allocator.Error || memo_mod.Error;

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

/// Check the durable field width before admitting a memo into RAM.
pub fn validateRow(account: []const u8, from: []const u8, text: []const u8) error{BadRecord}!void {
    for ([_][]const u8{ account, from, text }) |field| {
        if (field.len > std.math.maxInt(u16)) return error.BadRecord;
    }
}

fn encodedRowLen(store: *const OroStore, fields: [3][]const u8) error{ BadRecord, RecordTooLarge }!usize {
    try validateRow(fields[0], fields[1], fields[2]);
    var body_len: usize = 9 + fields.len * 2;
    for (fields) |field| body_len += field.len;
    // OroStore's put payload has a 10-byte header; memo row keys are 17 bytes.
    const store_overhead: usize = 10 + 17;
    if (store.cfg.max_record_bytes < store_overhead or
        body_len > store.cfg.max_record_bytes - store_overhead) return error.RecordTooLarge;
    return body_len;
}

/// Include the store's configured put-payload limit in admission checks.
pub fn validateRowForStore(store: *const OroStore, account: []const u8, from: []const u8, text: []const u8) error{ BadRecord, RecordTooLarge }!void {
    _ = try encodedRowLen(store, .{ account, from, text });
}

fn putRow(store: *OroStore, gen: u64, seq: u64, row: Row) !void {
    const fields = [_][]const u8{ row.account, row.from, row.text };
    const body_len = try encodedRowLen(store, fields);
    const body = try store.allocator.alloc(u8, body_len);
    defer {
        std.crypto.secureZero(u8, body);
        store.allocator.free(body);
    }
    var n: usize = 0;
    body[n] = 1;
    n += 1;
    std.mem.writeInt(i64, body[n..][0..8], row.sent_ms, .little);
    n += 8;
    for (fields) |field| {
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

test "memo durable accepts configured fields beyond the old row buffer and u16 text boundary" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const account = try alloc.alloc(u8, 700);
    defer alloc.free(account);
    @memset(account, 'a');
    const from = try alloc.alloc(u8, 1500);
    defer alloc.free(from);
    @memset(from, 'f');
    const text = try alloc.alloc(u8, std.math.maxInt(u16));
    defer alloc.free(text);
    @memset(text, 't');
    const cfg: memo_mod.Config = .{ .max_from_bytes = from.len, .max_text_bytes = text.len };
    try validateRow(account, from, text);

    {
        var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "large-memo.wal");
        defer store.deinit();
        try validateRowForStore(&store, account, from, text);
        try append(&store, account, from, text, -42);
    }

    var reopened = try OroStore.open(alloc, std.testing.io, tmp.dir, "large-memo.wal");
    defer reopened.deinit();
    var restored = memo_mod.MemoBox.initWithConfig(alloc, cfg);
    defer restored.deinit();
    try restoreInto(&reopened, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.count(account));
    try std.testing.expectEqualSlices(u8, from, restored.pending(account)[0].from);
    try std.testing.expectEqualSlices(u8, text, restored.pending(account)[0].text);
    try std.testing.expectEqual(@as(i64, -42), restored.pending(account)[0].sent_ms);

    var replacement = memo_mod.MemoBox.initWithConfig(alloc, cfg);
    defer replacement.deinit();
    _ = try replacement.send(account, from, text, 99);
    try replaceAll(&reopened, &replacement);
    try restoreInto(&reopened, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.count(account));
    try std.testing.expectEqualSlices(u8, from, restored.pending(account)[0].from);
    try std.testing.expectEqualSlices(u8, text, restored.pending(account)[0].text);
    try std.testing.expectEqual(@as(i64, 99), restored.pending(account)[0].sent_ms);
}

test "memo durable refuses unencodable fields and store limits without publishing them" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "bounded-memo.wal");
    defer store.deinit();
    try append(&store, "alice", "bob", "old", 1);

    const oversized = try alloc.alloc(u8, std.math.maxInt(u16) + 1);
    defer alloc.free(oversized);
    @memset(oversized, 'x');
    try std.testing.expectError(error.BadRecord, validateRow(oversized, "bob", "new"));
    try std.testing.expectError(error.BadRecord, validateRow("alice", oversized, "new"));
    try std.testing.expectError(error.BadRecord, validateRow("alice", "bob", oversized));
    try std.testing.expectError(error.BadRecord, append(&store, oversized, "bob", "new", 2));
    try std.testing.expectError(error.BadRecord, append(&store, "alice", oversized, "new", 2));
    try std.testing.expectError(error.BadRecord, append(&store, "alice", "bob", oversized, 2));

    var replacement = memo_mod.MemoBox.initWithConfig(alloc, .{});
    defer replacement.deinit();
    _ = try replacement.send(oversized, "bob", "new", 2);
    try std.testing.expectError(error.BadRecord, replaceAll(&store, &replacement));
    try std.testing.expectEqual(@as(u64, 0), readMeta(&store).generation);
    try std.testing.expectEqual(@as(u64, 1), readMeta(&store).count);

    var restored = memo_mod.MemoBox.init(alloc);
    defer restored.deinit();
    try restoreInto(&store, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.count("alice"));
    try std.testing.expectEqualStrings("old", restored.pending("alice")[0].text);
    try std.testing.expectEqual(@as(usize, 0), restored.count(oversized));

    var limited = try OroStore.openWithConfig(alloc, std.testing.io, tmp.dir, "limited-memo.wal", .{ .max_record_bytes = 64 });
    defer limited.deinit();
    try std.testing.expectError(error.RecordTooLarge, validateRowForStore(&limited, "alice", "bob", "a message exceeding the configured record limit"));
    try std.testing.expectError(error.RecordTooLarge, append(&limited, "alice", "bob", "a message exceeding the configured record limit", 3));
    try std.testing.expectEqual(@as(u64, 0), readMeta(&limited).count);
    try append(&limited, "alice", "bob", "ok", 4);
    try std.testing.expectEqual(@as(u64, 1), readMeta(&limited).count);
}

test "memo durable restore leaves the live mailbox unchanged after a later truncated row" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "truncated-memo.wal");
    defer store.deinit();
    try append(&store, "alice", "bob", "stored", 1);
    var key_buf: [17]u8 = undefined;
    var truncated: [9]u8 = @splat(0);
    truncated[0] = 1;
    try store.put(.memos, messageKey(0, 1, &key_buf), &truncated);
    try writeMeta(&store, .{ .generation = 0, .count = 2 });

    var live = memo_mod.MemoBox.init(alloc);
    defer live.deinit();
    _ = try live.send("alice", "keep", "sentinel", 7);
    try std.testing.expectError(error.Truncated, restoreInto(&store, &live));
    try std.testing.expectEqual(@as(usize, 1), live.count("alice"));
    try std.testing.expectEqualStrings("keep", live.pending("alice")[0].from);
    try std.testing.expectEqualStrings("sentinel", live.pending("alice")[0].text);
    try std.testing.expectEqual(@as(i64, 7), live.pending("alice")[0].sent_ms);
}
