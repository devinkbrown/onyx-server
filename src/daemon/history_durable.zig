// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cold CHATHISTORY in the OroStore `history` family.
//!
//! A generation counter published after the message records makes a kill
//! between those writes keep the previous complete image. Restore builds a
//! side Lotus and SearchIndex and swaps them in only after both succeed.

const std = @import("std");
const store_mod = @import("store.zig");
const search_index_mod = @import("search_index.zig");
const e2ee_policy = @import("../proto/e2ee_policy.zig");

const OroStore = store_mod.OroStore;

const meta_key = "meta";
const max_target: usize = 512;
const max_msgid: usize = 256;
const max_sender: usize = 512;
const max_text: usize = 8192;
const max_command: usize = 32;
const max_tags: usize = 8192;
const max_record_bytes = 32 + max_target + max_msgid + max_sender + max_text + max_command + max_tags;

pub const Error = error{
    BadRecord,
    Truncated,
    RecordTooLarge,
    MissingRecord,
} || OroStore.StoreError || std.mem.Allocator.Error;

pub const Record = struct {
    target: []const u8,
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    command: []const u8 = "PRIVMSG",
    client_tags: []const u8 = "",
    tombstone: bool = false,
};

const Meta = struct {
    generation: u64,
    count: u64,
};

fn readMeta(store: *const OroStore) Meta {
    const raw = store.get(.history, meta_key) orelse return .{ .generation = 0, .count = 0 };
    if (raw.len != 16) return .{ .generation = 0, .count = 0 };
    return .{
        .generation = std.mem.readInt(u64, raw[0..8], .little),
        .count = std.mem.readInt(u64, raw[8..16], .little),
    };
}

fn writeMeta(store: *OroStore, meta: Meta) !void {
    var raw: [16]u8 = undefined;
    std.mem.writeInt(u64, raw[0..8], meta.generation, .little);
    std.mem.writeInt(u64, raw[8..16], meta.count, .little);
    try store.put(.history, meta_key, &raw);
}

fn messageKey(gen: u64, seq: u64, out: *[17]u8) []const u8 {
    out[0] = 'm';
    std.mem.writeInt(u64, out[1..9], gen, .little);
    std.mem.writeInt(u64, out[9..17], seq, .little);
    return out;
}

fn encodeRecord(rec: Record, body: *[max_record_bytes]u8) ![]const u8 {
    if (rec.target.len > max_target or rec.msgid.len > max_msgid or rec.sender.len > max_sender or
        rec.text.len > max_text or rec.command.len > max_command or rec.client_tags.len > max_tags)
        return error.RecordTooLarge;
    var n: usize = 0;
    body[n] = 1;
    n += 1;
    body[n] = if (rec.tombstone) 1 else 0;
    n += 1;
    std.mem.writeInt(u64, body[n..][0..8], rec.timestamp, .little);
    n += 8;
    const fields = [_][]const u8{ rec.target, rec.msgid, rec.sender, rec.command, rec.client_tags };
    for (fields) |field| {
        std.mem.writeInt(u16, body[n..][0..2], @intCast(field.len), .little);
        n += 2;
        @memcpy(body[n..][0..field.len], field);
        n += field.len;
    }
    std.mem.writeInt(u32, body[n..][0..4], @intCast(rec.text.len), .little);
    n += 4;
    @memcpy(body[n..][0..rec.text.len], rec.text);
    n += rec.text.len;
    return body[0..n];
}

fn putRecord(store: *OroStore, gen: u64, seq: u64, rec: Record) !void {
    var body: [max_record_bytes]u8 = undefined;
    const encoded = try encodeRecord(rec, &body);
    var key_buf: [17]u8 = undefined;
    try store.put(.history, messageKey(gen, seq, &key_buf), encoded);
}

const Owned = struct {
    target: []u8,
    msgid: []u8,
    sender: []u8,
    text: []u8,
    command: []u8,
    tags: []u8,
    timestamp: u64,
    tombstone: bool,

    fn deinit(self: *Owned, allocator: std.mem.Allocator) void {
        allocator.free(self.target);
        allocator.free(self.msgid);
        allocator.free(self.sender);
        allocator.free(self.text);
        allocator.free(self.command);
        allocator.free(self.tags);
    }
};

fn decodeOwned(allocator: std.mem.Allocator, raw: []const u8) !Owned {
    if (raw.len < 10 or raw[0] != 1) return error.BadRecord;
    var n: usize = 2;
    const tombstone = raw[1] != 0;
    if (raw.len < n + 8) return error.Truncated;
    const timestamp = std.mem.readInt(u64, raw[n..][0..8], .little);
    n += 8;
    var fields: [5][]u8 = undefined;
    var nfields: usize = 0;
    errdefer {
        for (fields[0..nfields]) |field| allocator.free(field);
    }
    for (&fields) |*field| {
        if (raw.len < n + 2) return error.Truncated;
        const len = std.mem.readInt(u16, raw[n..][0..2], .little);
        n += 2;
        if (raw.len < n + len) return error.Truncated;
        field.* = try allocator.dupe(u8, raw[n..][0..len]);
        n += len;
        nfields += 1;
    }
    if (raw.len < n + 4) return error.Truncated;
    const text_len = std.mem.readInt(u32, raw[n..][0..4], .little);
    n += 4;
    if (text_len > max_text or raw.len < n + text_len) return error.Truncated;
    const text = try allocator.dupe(u8, raw[n..][0..text_len]);
    n += text_len;
    errdefer allocator.free(text);
    if (n != raw.len) return error.BadRecord;
    return .{
        .target = fields[0],
        .msgid = fields[1],
        .sender = fields[2],
        .command = fields[3],
        .tags = fields[4],
        .text = text,
        .timestamp = timestamp,
        .tombstone = tombstone,
    };
}

fn freeOwned(allocator: std.mem.Allocator, rows: []Owned) void {
    for (rows) |*row| row.deinit(allocator);
    allocator.free(rows);
}

fn loadOwned(store: *OroStore, allocator: std.mem.Allocator) ![]Owned {
    const meta = readMeta(store);
    const rows = try allocator.alloc(Owned, meta.count);
    errdefer allocator.free(rows);
    var filled: usize = 0;
    errdefer {
        for (rows[0..filled]) |*row| row.deinit(allocator);
    }
    var seq: u64 = 0;
    while (seq < meta.count) : (seq += 1) {
        var key_buf: [17]u8 = undefined;
        const raw = store.get(.history, messageKey(meta.generation, seq, &key_buf)) orelse return error.MissingRecord;
        rows[filled] = try decodeOwned(allocator, raw);
        filled += 1;
    }
    return rows;
}

/// Append one retained message. The count is published only after the record
/// is durable, so a kill keeps the previous prefix.
pub fn append(store: *OroStore, rec: Record) !void {
    const meta = readMeta(store);
    try putRecord(store, meta.generation, meta.count, rec);
    try writeMeta(store, .{ .generation = meta.generation, .count = meta.count + 1 });
}

/// Replace the durable image with the messages still inside `lotus`. The new
/// generation is published last. An already-identical canonical image is a
/// read-only, allocation-free no-op. Different ordering conservatively rewrites
/// the image, preserving compaction and repair after failed ordinary appends.
pub fn replaceAll(comptime LotusT: type, store: *OroStore, lotus: *const LotusT) !void {
    const meta = readMeta(store);
    if (try imageMatches(LotusT, store, lotus, meta)) return;
    const generation = meta.generation + 1;
    var seq: u64 = 0;
    var it = lotus.deterministicIterator();
    while (it.next()) |entry| {
        const tags = entry.message.client_tags orelse "";
        try putRecord(store, generation, seq, .{
            .target = entry.target,
            .msgid = entry.message.msgid,
            .sender = entry.message.sender,
            .text = entry.message.text,
            .timestamp = entry.message.timestamp,
            .command = entry.message.command,
            .client_tags = tags,
            .tombstone = entry.message.tombstone,
        });
        seq += 1;
    }
    try writeMeta(store, .{ .generation = generation, .count = seq });
}

fn imageMatches(comptime LotusT: type, store: *OroStore, lotus: *const LotusT, meta: Meta) !bool {
    if (store.get(.history, meta_key)) |raw| {
        if (raw.len != 16) return false;
    }
    if (meta.count != lotus.totalStoredCount()) return false;
    var it = lotus.deterministicIterator();
    var seq: u64 = 0;
    var body: [max_record_bytes]u8 = undefined;
    while (it.next()) |entry| {
        var key_buf: [17]u8 = undefined;
        const raw = store.get(.history, messageKey(meta.generation, seq, &key_buf)) orelse return false;
        const encoded = try encodeRecord(.{
            .target = entry.target,
            .msgid = entry.message.msgid,
            .sender = entry.message.sender,
            .text = entry.message.text,
            .timestamp = entry.message.timestamp,
            .command = entry.message.command,
            .client_tags = entry.message.client_tags orelse "",
            .tombstone = entry.message.tombstone,
        }, &body);
        if (!std.mem.eql(u8, raw, encoded)) return false;
        seq += 1;
    }
    return seq == meta.count;
}

/// Stage a restored ring and search projection, then swap both in. A failure
/// leaves `lotus` and `search` untouched.
pub fn restoreInto(comptime LotusT: type, store: *OroStore, lotus: *LotusT, search: *search_index_mod.SearchIndex) !void {
    const allocator = lotus.allocator;
    const rows = try loadOwned(store, allocator);
    defer freeOwned(allocator, rows);

    var staged = LotusT.init(allocator);
    errdefer staged.deinit();
    for (rows) |row| {
        _ = try staged.ingestExactOnce(row.target, .{
            .msgid = row.msgid,
            .sender = row.sender,
            .text = row.text,
            .timestamp = row.timestamp,
            .command = row.command,
            .client_tags = if (row.tags.len == 0) null else row.tags,
            .tombstone = row.tombstone,
        });
    }

    var staged_search = search_index_mod.SearchIndex.initWithConfig(allocator, search.cfg);
    errdefer staged_search.deinit();
    var it = staged.deterministicIterator();
    while (it.next()) |entry| {
        if (entry.message.tombstone) continue;
        if (e2ee_policy.encryptedTagPresent(entry.message.client_tags)) continue;
        if (std.mem.startsWith(u8, entry.message.text, e2ee_policy.room_envelope_prefix)) continue;
        try staged_search.index(entry.message.msgid, entry.message.text);
    }

    std.mem.swap(LotusT, lotus, &staged);
    std.mem.swap(search_index_mod.SearchIndex, search, &staged_search);
    staged.deinit();
    staged_search.deinit();
}

const test_lotus = @import("../proto/lotus.zig");

test "GAP-D1 identical history snapshot is allocation-free and divergent history repairs the durable image" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(alloc, .{});
    var store = try OroStore.open(failing.allocator(), std.testing.io, tmp.dir, "history-noop.wal");
    defer store.deinit();
    const LotusT = test_lotus.Lotus(.{ .max_targets = 4, .max_per_target = 8, .max_text = 128 });
    var lotus = LotusT.init(alloc);
    defer lotus.deinit();
    // Even an empty image must not emit a metadata/changefeed write.
    const empty_changes = store.changeCount();
    try replaceAll(LotusT, &store, &lotus);
    try std.testing.expectEqual(empty_changes, store.changeCount());
    _ = try lotus.append("#room", .{
        .msgid = "m1",
        .sender = "alice",
        .text = "before",
        .timestamp = 1,
        .client_tags = "+draft/reply=parent",
    });
    try replaceAll(LotusT, &store, &lotus);
    const before_meta = readMeta(&store);
    const before_changes = store.changeCount();
    const before_allocs = failing.alloc_index;
    failing.fail_index = before_allocs;
    try replaceAll(LotusT, &store, &lotus);
    try std.testing.expectEqual(before_allocs, failing.alloc_index);
    try std.testing.expectEqual(before_changes, store.changeCount());
    try std.testing.expectEqual(before_meta, readMeta(&store));

    // Preserve reconciliation: a divergent edit must attempt a real write,
    // and retry after allocation pressure must retain the edited text.
    try lotus.edit("#room", "m1", "after");
    try std.testing.expectError(error.OutOfMemory, replaceAll(LotusT, &store, &lotus));
    try std.testing.expectEqual(before_meta, readMeta(&store));
    failing.fail_index = std.math.maxInt(usize);
    try replaceAll(LotusT, &store, &lotus);
    var restored = LotusT.init(alloc);
    defer restored.deinit();
    var search = search_index_mod.SearchIndex.init(alloc);
    defer search.deinit();
    try restoreInto(LotusT, &store, &restored, &search);
    var out: [1]test_lotus.Message = undefined;
    const messages = try restored.latest("#room", 1, &out);
    try std.testing.expectEqual(@as(usize, 1), messages.len);
    try std.testing.expectEqualStrings("after", messages[0].text);
    try std.testing.expectEqualStrings("+draft/reply=parent", messages[0].client_tags.?);
}

test "UPGRADE GAP-D1 history restore is allocation-failure atomic" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try OroStore.open(alloc, std.testing.io, tmp.dir, "gap-d1-atomic.wal");
    defer store.deinit();
    try append(&store, .{
        .target = "#room",
        .msgid = "m-keep",
        .sender = "alice",
        .text = "sentinel",
        .timestamp = 1,
    });
    try append(&store, .{
        .target = "#room",
        .msgid = "m-cipher",
        .sender = "alice",
        .text = "ONYXROOM1 secretphrase",
        .timestamp = 2,
        .client_tags = "+onyx/e2ee=mls",
    });

    const LotusT = test_lotus.Lotus(.{ .max_targets = 4, .max_per_target = 8, .max_text = 128 });
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    var lotus = LotusT.init(failing.allocator());
    defer lotus.deinit();
    var search = search_index_mod.SearchIndex.init(failing.allocator());
    defer search.deinit();
    try std.testing.expectError(error.OutOfMemory, restoreInto(LotusT, &store, &lotus, &search));
    try std.testing.expectEqual(@as(usize, 0), lotus.totalStoredCount());

    var live = LotusT.init(alloc);
    defer live.deinit();
    _ = try live.append("#room", .{ .msgid = "already", .sender = "bob", .text = "stay", .timestamp = 9 });
    var live_search = search_index_mod.SearchIndex.init(alloc);
    defer live_search.deinit();
    try live_search.index("already", "stay");
    try restoreInto(LotusT, &store, &live, &live_search);
    var out: [4]test_lotus.Message = undefined;
    const got = try live.latest("#room", 4, &out);
    try std.testing.expectEqual(@as(usize, 2), got.len);
    try std.testing.expectEqualStrings("m-cipher", got[0].msgid);
    try std.testing.expectEqualStrings("m-keep", got[1].msgid);
    try std.testing.expect(live_search.find("sentinel").len == 1);
    try std.testing.expect(live_search.find("secretphrase").len == 0);
    try std.testing.expect(live_search.find("stay").len == 0);
}
