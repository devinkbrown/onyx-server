// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reply threads carried across a Helix UPGRADE and rebuilt from cold history.
//!
//! A thread is the root msgid plus a bounded list of reply msgids. The id is
//! the Blake3 of that root under a fixed domain, so a successor does not mint
//! a new id. The image rides the existing `.mesh_checkpoint` family (magic
//! "THRD", `min_supported = 2`). There is no new capsule kind. A predecessor
//! arena that lacks the piece still adopts; a present but malformed or
//! duplicate image rejects the whole handoff.
//!
//! The table is one heap allocation. `LinuxServer` is returned by value from
//! `init`, and an inline table of this size would land on the caller's stack.

const std = @import("std");
const draft_reply_relay = @import("../../proto/draft_reply_relay.zig");

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    TrailingBytes,
    TooMany,
    InvalidThread,
};

pub const magic = [_]u8{ 'T', 'H', 'R', 'D' };
pub const version: u8 = 1;

/// Product bounds for the live table. These are not a peer-capacity lock.
pub const max_threads: usize = 256;
pub const max_replies: usize = 128;
pub const max_msgid: usize = draft_reply_relay.MAX_MSGID_LEN;
pub const id_len: usize = 32;

const domain = "onyx-thread-id-v1\x00";

pub fn idFromRoot(root: []const u8, out: *[id_len]u8) []const u8 {
    var material: [domain.len + max_msgid]u8 = undefined;
    @memcpy(material[0..domain.len], domain);
    @memcpy(material[domain.len..][0..root.len], root);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    std.crypto.hash.Blake3.hash(material[0 .. domain.len + root.len], &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..16], .lower);
    @memcpy(out, &hex);
    return out;
}

const ReplySlot = struct {
    len: u8 = 0,
    bytes: [max_msgid]u8 = undefined,

    fn slice(self: *const ReplySlot) []const u8 {
        return self.bytes[0..self.len];
    }
};

const ThreadSlot = struct {
    used: bool = false,
    root_len: u8 = 0,
    reply_count: u8 = 0,
    id: [id_len]u8 = undefined,
    root: [max_msgid]u8 = undefined,
    replies: [max_replies]ReplySlot = @splat(.{}),

    fn rootSlice(self: *const ThreadSlot) []const u8 {
        return self.root[0..self.root_len];
    }

    fn idSlice(self: *const ThreadSlot) []const u8 {
        return &self.id;
    }

    fn replySlice(self: *const ThreadSlot, index: usize) []const u8 {
        return self.replies[index].slice();
    }

    fn hasReply(self: *const ThreadSlot, reply: []const u8) bool {
        var i: usize = 0;
        while (i < self.reply_count) : (i += 1) {
            if (std.mem.eql(u8, self.replySlice(i), reply)) return true;
        }
        return false;
    }

    fn appendReply(self: *ThreadSlot, reply: []const u8) void {
        if (self.reply_count == max_replies) {
            var i: usize = 1;
            while (i < self.reply_count) : (i += 1) {
                self.replies[i - 1] = self.replies[i];
            }
            self.reply_count -= 1;
        }
        const dest = &self.replies[self.reply_count];
        @memcpy(dest.bytes[0..reply.len], reply);
        dest.len = @intCast(reply.len);
        self.reply_count += 1;
    }
};

const Storage = struct {
    threads: [max_threads]ThreadSlot = @splat(.{}),
};

pub const ThreadView = struct {
    id: []const u8,
    root: []const u8,
    reply_count: usize,
    replies: []const u8,

    pub fn replyAt(self: ThreadView, index: usize) ?[]const u8 {
        if (index >= self.reply_count) return null;
        var reader = Reader{ .buf = self.replies };
        var i: usize = 0;
        while (i <= index) : (i += 1) {
            const slice = reader.shortSlice() orelse return null;
            if (i == index) return slice;
        }
        return null;
    }
};

pub const Snapshot = struct {
    count: u32,
    records: []const u8,

    pub fn iterator(self: *const Snapshot) ThreadIterator {
        return .{ .reader = .{ .buf = self.records }, .remaining = self.count };
    }
};

pub const ThreadIterator = struct {
    reader: Reader,
    remaining: u32,

    pub fn next(self: *ThreadIterator) ?ThreadView {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        const id = self.reader.shortSlice() orelse return null;
        const root = self.reader.shortSlice() orelse return null;
        const reply_count = self.reader.int(u16) orelse return null;
        const start = self.reader.pos;
        var i: usize = 0;
        while (i < reply_count) : (i += 1) {
            _ = self.reader.shortSlice() orelse return null;
        }
        return .{
            .id = id,
            .root = root,
            .reply_count = reply_count,
            .replies = self.reader.buf[start..self.reader.pos],
        };
    }
};

/// Heap table. Slot bytes are owned here, so a restore at the adoption commit
/// edge copies into existing storage and does not allocate.
pub const Table = struct {
    allocator: std.mem.Allocator = undefined,
    storage: ?*Storage = null,

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!Table {
        const storage = try allocator.create(Storage);
        storage.* = .{};
        return .{ .allocator = allocator, .storage = storage };
    }

    pub fn deinit(self: *Table) void {
        const storage = self.storage orelse return;
        self.storage = null;
        self.allocator.destroy(storage);
    }

    pub fn clear(self: *Table) void {
        const storage = self.storage orelse return;
        for (&storage.threads) |*slot| slot.* = .{};
    }

    pub fn count(self: *const Table) usize {
        const storage = self.storage orelse return 0;
        var n: usize = 0;
        for (storage.threads) |slot| {
            if (slot.used) n += 1;
        }
        return n;
    }

    pub fn findByRoot(self: *const Table, root: []const u8) ?usize {
        const storage = self.storage orelse return null;
        for (storage.threads, 0..) |slot, index| {
            if (!slot.used) continue;
            if (std.mem.eql(u8, slot.rootSlice(), root)) return index;
        }
        return null;
    }

    pub fn idAt(self: *const Table, index: usize) []const u8 {
        const storage = self.storage orelse return "";
        if (index >= storage.threads.len or !storage.threads[index].used) return "";
        return storage.threads[index].idSlice();
    }

    pub fn rootAt(self: *const Table, index: usize) []const u8 {
        const storage = self.storage orelse return "";
        if (index >= storage.threads.len or !storage.threads[index].used) return "";
        return storage.threads[index].rootSlice();
    }

    pub fn replyCountAt(self: *const Table, index: usize) usize {
        const storage = self.storage orelse return 0;
        if (index >= storage.threads.len or !storage.threads[index].used) return 0;
        return storage.threads[index].reply_count;
    }

    pub fn replyAt(self: *const Table, index: usize, n: usize) []const u8 {
        const storage = self.storage orelse return "";
        if (index >= storage.threads.len or !storage.threads[index].used) return "";
        const slot = &storage.threads[index];
        if (n >= slot.reply_count) return "";
        return slot.replySlice(n);
    }

    pub fn containsReply(self: *const Table, index: usize, reply: []const u8) bool {
        const storage = self.storage orelse return false;
        if (index >= storage.threads.len or !storage.threads[index].used) return false;
        return storage.threads[index].hasReply(reply);
    }

    /// Record `reply` as a member of the thread that owns `parent`. The first
    /// reply to an unknown parent creates the thread and keeps that parent as
    /// the root. A repeated reply is a no-op. The visible list drops the oldest
    /// msgid once it reaches `max_replies`.
    pub fn noteReply(self: *Table, parent: []const u8, reply: []const u8) Error!void {
        const storage = self.storage orelse return error.InvalidThread;
        if (!draft_reply_relay.isValidMsgid(parent) or !draft_reply_relay.isValidMsgid(reply))
            return error.InvalidThread;
        if (std.mem.eql(u8, parent, reply)) return error.InvalidThread;
        if (self.memberSlot(parent)) |slot| {
            if (std.mem.eql(u8, slot.rootSlice(), reply) or slot.hasReply(reply)) return;
            slot.appendReply(reply);
            return;
        }
        const slot = self.freeSlot(storage) orelse return error.TooMany;
        var id_buf: [id_len]u8 = undefined;
        const id = idFromRoot(parent, &id_buf);
        @memcpy(slot.id[0..id_len], id);
        @memcpy(slot.root[0..parent.len], parent);
        slot.root_len = @intCast(parent.len);
        slot.reply_count = 0;
        slot.used = true;
        slot.appendReply(reply);
    }

    /// Replace the live table with a validated image. Returns how many threads
    /// could not be copied. A decoded snapshot that passed `decodeCurrent`
    /// copies in full.
    pub fn replace(self: *Table, snap: Snapshot) usize {
        self.clear();
        var dropped: usize = 0;
        var it = snap.iterator();
        while (it.next()) |view| {
            self.insertExact(view) catch {
                dropped += 1;
                continue;
            };
        }
        return dropped;
    }

    fn memberSlot(self: *Table, msgid: []const u8) ?*ThreadSlot {
        const storage = self.storage orelse return null;
        for (&storage.threads) |*slot| {
            if (!slot.used) continue;
            if (std.mem.eql(u8, slot.rootSlice(), msgid) or slot.hasReply(msgid)) return slot;
        }
        return null;
    }

    fn freeSlot(self: *Table, storage: *Storage) ?*ThreadSlot {
        _ = self;
        for (&storage.threads) |*slot| {
            if (!slot.used) return slot;
        }
        return null;
    }

    fn insertExact(self: *Table, view: ThreadView) Error!void {
        const storage = self.storage orelse return error.InvalidThread;
        if (view.id.len != id_len or view.root.len == 0 or view.root.len > max_msgid)
            return error.InvalidThread;
        if (view.reply_count > max_replies) return error.TooMany;
        const slot = self.freeSlot(storage) orelse return error.TooMany;
        @memcpy(slot.id[0..id_len], view.id);
        @memcpy(slot.root[0..view.root.len], view.root);
        slot.root_len = @intCast(view.root.len);
        slot.reply_count = 0;
        var n: usize = 0;
        while (n < view.reply_count) : (n += 1) {
            const reply = view.replyAt(n) orelse return error.InvalidThread;
            if (reply.len == 0 or reply.len > max_msgid) return error.InvalidThread;
            @memcpy(slot.replies[n].bytes[0..reply.len], reply);
            slot.replies[n].len = @intCast(reply.len);
            slot.reply_count += 1;
        }
        slot.used = true;
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn encodeFrom(allocator: std.mem.Allocator, table: *const Table) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &magic);
    try out.append(allocator, version);
    const count_off = out.items.len;
    try appendInt(&out, allocator, u32, 0);

    var thread_count: u32 = 0;
    if (table.storage) |storage| {
        for (storage.threads) |slot| {
            if (!slot.used) continue;
            if (thread_count == max_threads) return error.TooMany;
            if (slot.rootSlice().len == 0 or slot.reply_count == 0) return error.InvalidThread;
            try appendShortSlice(&out, allocator, slot.idSlice());
            try appendShortSlice(&out, allocator, slot.rootSlice());
            try appendInt(&out, allocator, u16, @as(u16, slot.reply_count));
            var i: usize = 0;
            while (i < slot.reply_count) : (i += 1) {
                try appendShortSlice(&out, allocator, slot.replySlice(i));
            }
            thread_count += 1;
        }
    }
    std.mem.writeInt(u32, out.items[count_off..][0..4], thread_count, .little);
    _ = try decodeCurrent(out.items);
    return out.toOwnedSlice(allocator);
}

pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    if (bytes.len < magic.len + 1 + @sizeOf(u32)) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    const count = std.mem.readInt(u32, bytes[magic.len + 1 ..][0..4], .little);
    if (count > max_threads) return error.TooMany;
    const records = bytes[magic.len + 1 + @sizeOf(u32) ..];
    var reader = Reader{ .buf = records };
    var seen_roots: [max_threads][]const u8 = undefined;
    var seen_ids: [max_threads][]const u8 = undefined;
    var seen: usize = 0;
    while (seen < count) : (seen += 1) {
        const id = reader.shortSlice() orelse return error.Truncated;
        const root = reader.shortSlice() orelse return error.Truncated;
        if (id.len != id_len or root.len == 0 or root.len > max_msgid) return error.InvalidThread;
        if (!draft_reply_relay.isValidMsgid(root)) return error.InvalidThread;
        var expect_id: [id_len]u8 = undefined;
        if (!std.mem.eql(u8, id, idFromRoot(root, &expect_id))) return error.InvalidThread;
        const reply_count = reader.int(u16) orelse return error.Truncated;
        if (reply_count == 0 or reply_count > max_replies) return error.InvalidThread;
        var replies: [max_replies][]const u8 = undefined;
        var r: usize = 0;
        while (r < reply_count) : (r += 1) {
            const reply = reader.shortSlice() orelse return error.Truncated;
            if (!draft_reply_relay.isValidMsgid(reply)) return error.InvalidThread;
            if (std.mem.eql(u8, reply, root)) return error.InvalidThread;
            for (replies[0..r]) |prior| {
                if (std.mem.eql(u8, prior, reply)) return error.InvalidThread;
            }
            replies[r] = reply;
        }
        for (seen_roots[0..seen], seen_ids[0..seen]) |prior_root, prior_id| {
            if (std.mem.eql(u8, prior_root, root) or std.mem.eql(u8, prior_id, id))
                return error.InvalidThread;
        }
        seen_roots[seen] = root;
        seen_ids[seen] = id;
    }
    if (reader.pos != records.len) return error.TrailingBytes;
    return .{ .count = count, .records = records };
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    _ = try decodeCurrent(bytes);
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendShortSlice(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) (Error || std.mem.Allocator.Error)!void {
    if (bytes.len == 0 or bytes.len > 255) return error.InvalidThread;
    try out.append(allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn int(self: *Reader, comptime T: type) ?T {
        if (self.buf.len - self.pos < @sizeOf(T)) return null;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }

    fn shortSlice(self: *Reader) ?[]const u8 {
        if (self.pos >= self.buf.len) return null;
        const n: usize = self.buf[self.pos];
        if (self.buf.len - self.pos - 1 < n) return null;
        defer self.pos += 1 + n;
        return self.buf[self.pos + 1 ..][0..n];
    }
};

test "GAP-P1 thread snapshot round trip keeps a stable id and drops the oldest reply" {
    const allocator = std.testing.allocator;
    var table = try Table.init(allocator);
    defer table.deinit();
    try table.noteReply("root-msg", "reply-a");
    try table.noteReply("reply-a", "reply-b");
    const slot = table.findByRoot("root-msg") orelse return error.TestUnexpectedResult;
    var id_buf: [id_len]u8 = undefined;
    const expect_id = idFromRoot("root-msg", &id_buf);
    try std.testing.expectEqualStrings(expect_id, table.idAt(slot));
    try std.testing.expect(!std.mem.eql(u8, expect_id, "root-msg"));
    try std.testing.expectEqual(@as(usize, 1), table.count());
    try std.testing.expectEqual(@as(usize, 2), table.replyCountAt(slot));

    var i: usize = 0;
    while (i < max_replies) : (i += 1) {
        var buf: [16]u8 = undefined;
        const reply = std.fmt.bufPrint(&buf, "r{d}", .{i}) catch unreachable;
        try table.noteReply("root-msg", reply);
    }
    try std.testing.expectEqual(max_replies, table.replyCountAt(slot));
    try std.testing.expect(!table.containsReply(slot, "reply-a"));
    try std.testing.expect(!table.containsReply(slot, "reply-b"));
    var last_buf: [16]u8 = undefined;
    const last = std.fmt.bufPrint(&last_buf, "r{d}", .{max_replies - 1}) catch unreachable;
    try std.testing.expect(table.containsReply(slot, last));

    const wire = try encodeFrom(allocator, &table);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    const snap = try decodeCurrent(wire);
    var restored = try Table.init(allocator);
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), restored.replace(snap));
    const slot2 = restored.findByRoot("root-msg") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(expect_id, restored.idAt(slot2));
    try std.testing.expectEqual(max_replies, restored.replyCountAt(slot2));
    try std.testing.expect(restored.containsReply(slot2, last));

    var bad = try allocator.dupe(u8, wire);
    defer allocator.free(bad);
    bad[magic.len] = 0xff;
    try std.testing.expectError(error.UnsupportedVersion, decodeCurrent(bad));
}
