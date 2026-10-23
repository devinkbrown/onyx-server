// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 CHATHISTORY Lotus append log.
//!
//! Lotus stores per-target history as bounded append rings. Message content is
//! addressed by BLAKE3 and shared across entries with the same body, while each
//! log entry keeps IRC-facing metadata: `msgid`, sender, and an HLC-ish
//! timestamp. Redaction appends no destructive rewrite; the entry remains as a
//! tombstone and query results hide its content.
const std = @import("std");
const builtin = @import("builtin");

const Blake3 = std.crypto.hash.Blake3;

/// BLAKE3 content address for one message body.
pub const ContentHash = [Blake3.digest_length]u8;

/// Target class for per-channel and per-user history.
pub const TargetKind = enum(u8) {
    channel,
    user,
};

/// Caller-owned target view.
pub const Target = struct {
    kind: TargetKind,
    name: []const u8,
};

/// Hybrid logical timestamp used for history ordering.
pub const Hlc = packed struct {
    wall_ms: u48 = 0,
    logical: u16 = 0,

    pub const Error = error{
        WallTimeOutOfRange,
    };

    /// Build a timestamp after validating the u48 wall-time bound.
    pub fn init(wall_ms: u64, logical: u16) Error!Hlc {
        if (wall_ms > std.math.maxInt(u48)) return error.WallTimeOutOfRange;
        return .{ .wall_ms = @intCast(wall_ms), .logical = logical };
    }

    /// Total order by wall time, then logical counter.
    pub fn compare(a: Hlc, b: Hlc) std.math.Order {
        if (a.wall_ms < b.wall_ms) return .lt;
        if (a.wall_ms > b.wall_ms) return .gt;
        if (a.logical < b.logical) return .lt;
        if (a.logical > b.logical) return .gt;
        return .eq;
    }
};

/// CHATHISTORY query operation.
pub const QueryOp = union(enum) {
    latest,
    before: Hlc,
    after: Hlc,
    around: Hlc,
    between: HlcRange,
};

pub const HlcRange = struct {
    start: Hlc,
    end: Hlc,
};

/// One query result. Slices remain valid until the store is mutated.
pub const MessageRef = struct {
    hash: ContentHash,
    msgid: []const u8,
    sender: []const u8,
    timestamp: Hlc,
    /// Borrowed message bytes. Any append or redact invalidates previously returned slices.
    content: ?[]const u8,
    tombstone: bool,
};

/// Result returned after appending one message entry.
pub const AppendResult = struct {
    hash: ContentHash,
    shared_content: bool,
    evicted: bool,
    target_len: usize,
};

/// Store errors are explicit so attacker-controlled bytes never reach panics.
pub const HistoryError = std.mem.Allocator.Error || Hlc.Error || error{
    InvalidTarget,
    InvalidSender,
    InvalidMsgid,
    InvalidContent,
    InvalidRange,
    TargetLimitExceeded,
    OutputTooSmall,
    NotFound,
    RefOverflow,
    CorruptStore,
};

/// A bounded, content-addressed, per-target CHATHISTORY store.
///
/// `max_targets` bounds distinct channel/user logs. `max_entries_per_target`
/// bounds each target ring. Byte limits bound retained metadata and content.
pub fn HistoryStore(
    comptime max_targets: usize,
    comptime max_entries_per_target: usize,
    comptime max_target_bytes: usize,
    comptime max_sender_bytes: usize,
    comptime max_msgid_bytes: usize,
    comptime max_content_bytes: usize,
) type {
    comptime {
        if (max_targets == 0) @compileError("HistoryStore needs at least one target");
        if (max_entries_per_target == 0) @compileError("HistoryStore needs at least one entry per target");
        if (max_target_bytes == 0) @compileError("target names need storage");
        if (max_sender_bytes == 0) @compileError("senders need storage");
        if (max_msgid_bytes == 0) @compileError("msgids need storage");
        if (max_content_bytes == 0) @compileError("message content needs storage");
    }

    const TargetName = FixedBytes(max_target_bytes);
    const SenderName = FixedBytes(max_sender_bytes);
    const Msgid = FixedBytes(max_msgid_bytes);

    const TargetKey = struct {
        const Self = @This();

        kind: TargetKind = .channel,
        name: TargetName = TargetName.empty(),

        fn init(target: Target) HistoryError!Self {
            if (!validAtom(target.name, max_target_bytes)) return error.InvalidTarget;
            return .{ .kind = target.kind, .name = try TargetName.init(target.name) };
        }
    };

    const MessageEntry = struct {
        hash: ContentHash = @splat(0),
        msgid: Msgid = Msgid.empty(),
        sender: SenderName = SenderName.empty(),
        timestamp: Hlc = .{},
        tombstone: bool = false,
    };

    const TargetLog = struct {
        const Self = @This();

        entries: [max_entries_per_target]MessageEntry =
            @as([max_entries_per_target]MessageEntry, @splat(.{})),
        start: usize = 0,
        len: usize = 0,

        fn slot(self: *const Self, logical_index: usize) usize {
            return (self.start + logical_index) % max_entries_per_target;
        }

        fn entry(self: *const Self, logical_index: usize) *const MessageEntry {
            return &self.entries[self.slot(logical_index)];
        }

        fn entryMut(self: *Self, logical_index: usize) *MessageEntry {
            return &self.entries[self.slot(logical_index)];
        }
    };

    const StoredContent = struct {
        bytes: []u8,
        refs: usize,
    };

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        targets: std.AutoHashMap(TargetKey, TargetLog),
        contents: std.AutoHashMap(ContentHash, StoredContent),

        /// Empty store using `allocator` for target maps and retained content.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .targets = std.AutoHashMap(TargetKey, TargetLog).init(allocator),
                .contents = std.AutoHashMap(ContentHash, StoredContent).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var content_it = self.contents.iterator();
            while (content_it.next()) |entry| {
                self.allocator.free(entry.value_ptr.bytes);
            }
            self.contents.deinit();
            self.targets.deinit();
        }

        /// Append a message to its target ring.
        ///
        /// Content bytes are copied once per unique BLAKE3 hash. Query paths
        /// later borrow these retained bytes and allocate nothing.
        pub fn append(
            self: *Self,
            target: Target,
            msgid: []const u8,
            sender: []const u8,
            timestamp: Hlc,
            content: []const u8,
        ) HistoryError!AppendResult {
            const key = try TargetKey.init(target);
            if (!validAtom(sender, max_sender_bytes)) return error.InvalidSender;
            if (!validAtom(msgid, max_msgid_bytes)) return error.InvalidMsgid;
            if (!validContent(content, max_content_bytes)) return error.InvalidContent;

            const hash = hashContent(content);
            var log = try self.targetLog(key);
            const shared_content = try self.retainContent(hash, content);
            const evicted = self.evictIfFull(log);

            const write_index = if (log.len < max_entries_per_target) blk: {
                const index = log.slot(log.len);
                log.len += 1;
                break :blk index;
            } else blk: {
                const index = log.start;
                log.start = (log.start + 1) % max_entries_per_target;
                break :blk index;
            };

            log.entries[write_index] = .{
                .hash = hash,
                .msgid = try Msgid.init(msgid),
                .sender = try SenderName.init(sender),
                .timestamp = timestamp,
                .tombstone = false,
            };

            self.debugAssertContentRefs();

            return .{
                .hash = hash,
                .shared_content = shared_content,
                .evicted = evicted,
                .target_len = log.len,
            };
        }

        /// Mark all matching target entries as tombstones by content address.
        pub fn redactByHash(self: *Self, target: Target, hash: ContentHash) HistoryError!usize {
            const key = try TargetKey.init(target);
            const log = self.targets.getPtr(key) orelse return error.NotFound;
            var redacted: usize = 0;

            var i: usize = 0;
            while (i < log.len) : (i += 1) {
                const item = log.entryMut(i);
                if (!item.tombstone and std.mem.eql(u8, &item.hash, &hash)) {
                    item.tombstone = true;
                    self.releaseContent(item.hash);
                    redacted += 1;
                }
            }

            if (redacted == 0) return error.NotFound;
            self.debugAssertContentRefs();
            return redacted;
        }

        /// Mark all matching target entries as tombstones by IRC msgid.
        pub fn redactByMsgid(self: *Self, target: Target, msgid: []const u8) HistoryError!usize {
            const key = try TargetKey.init(target);
            if (!validAtom(msgid, max_msgid_bytes)) return error.InvalidMsgid;
            const log = self.targets.getPtr(key) orelse return error.NotFound;
            var redacted: usize = 0;

            var i: usize = 0;
            while (i < log.len) : (i += 1) {
                const item = log.entryMut(i);
                if (!item.tombstone and std.mem.eql(u8, item.msgid.slice(), msgid)) {
                    item.tombstone = true;
                    self.releaseContent(item.hash);
                    redacted += 1;
                }
            }

            if (redacted == 0) return error.NotFound;
            self.debugAssertContentRefs();
            return redacted;
        }

        /// Run one CHATHISTORY query into caller-provided output storage.
        ///
        /// Results are chronological in the target log's retained window.
        pub fn query(
            self: *const Self,
            target: Target,
            op: QueryOp,
            limit: usize,
            out: []MessageRef,
        ) HistoryError![]const MessageRef {
            if (limit > out.len) return error.OutputTooSmall;
            if (limit == 0) return out[0..0];

            const key = try TargetKey.init(target);
            const log = self.targets.getPtr(key) orelse return out[0..0];

            return switch (op) {
                .latest => self.queryMatching(log, null, limit, out),
                .before => |anchor| self.queryMatching(log, .{ .before = anchor }, limit, out),
                .after => |anchor| self.queryMatching(log, .{ .after = anchor }, limit, out),
                .between => |range| blk: {
                    if (Hlc.compare(range.start, range.end) == .gt) return error.InvalidRange;
                    break :blk self.queryMatching(log, .{ .between = range }, limit, out);
                },
                .around => |anchor| self.queryAround(log, anchor, limit, out),
            };
        }

        /// Number of retained entries for one target.
        pub fn targetLen(self: *const Self, target: Target) HistoryError!usize {
            const key = try TargetKey.init(target);
            const log = self.targets.getPtr(key) orelse return 0;
            return log.len;
        }

        /// Number of unique content chunks currently referenced by live entries.
        pub fn uniqueContentCount(self: *const Self) usize {
            return self.contents.count();
        }

        fn targetLog(self: *Self, key: TargetKey) HistoryError!*TargetLog {
            if (self.targets.getPtr(key)) |log| return log;
            if (self.targets.count() >= max_targets) return error.TargetLimitExceeded;
            try self.targets.put(key, .{});
            return self.targets.getPtr(key) orelse error.CorruptStore;
        }

        fn evictIfFull(self: *Self, log: *TargetLog) bool {
            if (log.len < max_entries_per_target) return false;
            const old = log.entries[log.start];
            if (!old.tombstone) self.releaseContent(old.hash);
            return true;
        }

        fn retainContent(self: *Self, hash: ContentHash, content: []const u8) HistoryError!bool {
            if (self.contents.getPtr(hash)) |stored| {
                if (stored.refs == std.math.maxInt(usize)) return error.RefOverflow;
                stored.refs += 1;
                return true;
            }

            const bytes = try self.allocator.dupe(u8, content);
            errdefer self.allocator.free(bytes);
            try self.contents.put(hash, .{ .bytes = bytes, .refs = 1 });
            return false;
        }

        fn releaseContent(self: *Self, hash: ContentHash) void {
            const entry = self.contents.getEntry(hash) orelse return;
            if (entry.value_ptr.refs > 1) {
                entry.value_ptr.refs -= 1;
                return;
            }

            const bytes = entry.value_ptr.bytes;
            _ = self.contents.remove(hash);
            self.allocator.free(bytes);
        }

        const Match = union(enum) {
            before: Hlc,
            after: Hlc,
            between: HlcRange,
        };

        fn queryMatching(
            self: *const Self,
            log: *const TargetLog,
            match: ?Match,
            limit: usize,
            out: []MessageRef,
        ) HistoryError![]const MessageRef {
            const total = countMatching(log, match);
            const take = @min(total, limit);
            const skip = total - take;
            var skipped: usize = 0;
            var written: usize = 0;

            var i: usize = 0;
            while (i < log.len) : (i += 1) {
                const item = log.entry(i);
                if (!matches(item.timestamp, match)) continue;
                if (skipped < skip) {
                    skipped += 1;
                    continue;
                }

                out[written] = try self.toRef(item);
                written += 1;
                if (written == take) break;
            }

            return out[0..written];
        }

        fn queryAround(
            self: *const Self,
            log: *const TargetLog,
            anchor: Hlc,
            limit: usize,
            out: []MessageRef,
        ) HistoryError![]const MessageRef {
            if (log.len == 0) return out[0..0];
            const take = @min(log.len, limit);
            if (take == 0) return out[0..0];
            const pivot = findPivot(log, anchor);
            const desired_left = @min(pivot, (take - 1) / 2);
            var start = pivot - desired_left;
            var available = log.len - start;

            if (available < take) {
                const short = take - available;
                start -= @min(start, short);
                available = log.len - start;
            }

            const actual_take = @min(take, available);
            var written: usize = 0;
            while (written < actual_take) : (written += 1) {
                out[written] = try self.toRef(log.entry(start + written));
            }
            return out[0..written];
        }

        fn toRef(self: *const Self, item: *const MessageEntry) HistoryError!MessageRef {
            const content: ?[]const u8 = if (item.tombstone) null else blk: {
                const stored = self.contents.getPtr(item.hash) orelse return error.CorruptStore;
                break :blk stored.bytes;
            };

            return .{
                .hash = item.hash,
                .msgid = item.msgid.slice(),
                .sender = item.sender.slice(),
                .timestamp = item.timestamp,
                .content = content,
                .tombstone = item.tombstone,
            };
        }

        fn countMatching(log: *const TargetLog, match: ?Match) usize {
            var count: usize = 0;
            var i: usize = 0;
            while (i < log.len) : (i += 1) {
                if (matches(log.entry(i).timestamp, match)) count += 1;
            }
            return count;
        }

        fn matches(timestamp: Hlc, match: ?Match) bool {
            const rule = match orelse return true;
            return switch (rule) {
                .before => |anchor| Hlc.compare(timestamp, anchor) == .lt,
                .after => |anchor| Hlc.compare(timestamp, anchor) == .gt,
                .between => |range| Hlc.compare(timestamp, range.start) != .lt and
                    Hlc.compare(timestamp, range.end) != .gt,
            };
        }

        fn findPivot(log: *const TargetLog, anchor: Hlc) usize {
            var i: usize = 0;
            while (i < log.len) : (i += 1) {
                if (Hlc.compare(log.entry(i).timestamp, anchor) != .lt) return i;
            }
            return log.len - 1;
        }

        fn debugAssertContentRefs(self: *const Self) void {
            const debug_mode: std.builtin.OptimizeMode = if (comptime builtin.zig_version.pre != null) .Debug else .debug;
            if (builtin.mode != debug_mode) return;

            var content_it = self.contents.iterator();
            while (content_it.next()) |content_entry| {
                const live_refs = self.countLiveContentRefs(content_entry.key_ptr.*);
                std.debug.assert(live_refs > 0);
                std.debug.assert(live_refs == content_entry.value_ptr.refs);
            }

            var target_it = self.targets.iterator();
            while (target_it.next()) |target_entry| {
                const log = target_entry.value_ptr;
                var i: usize = 0;
                while (i < log.len) : (i += 1) {
                    const item = log.entry(i);
                    if (!item.tombstone) {
                        std.debug.assert(self.contents.contains(item.hash));
                    }
                }
            }
        }

        fn countLiveContentRefs(self: *const Self, hash: ContentHash) usize {
            var refs: usize = 0;
            var target_it = self.targets.iterator();
            while (target_it.next()) |target_entry| {
                const log = target_entry.value_ptr;
                var i: usize = 0;
                while (i < log.len) : (i += 1) {
                    const item = log.entry(i);
                    if (!item.tombstone and std.mem.eql(u8, &item.hash, &hash)) {
                        refs += 1;
                    }
                }
            }
            return refs;
        }
    };
}

fn FixedBytes(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        bytes: [capacity]u8 = @splat(0),
        len: usize = 0,

        fn empty() Self {
            return .{};
        }

        fn init(value: []const u8) HistoryError!Self {
            if (value.len > capacity) return error.OutputTooSmall;
            var out = Self{ .len = value.len };
            @memcpy(out.bytes[0..value.len], value);
            return out;
        }

        fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

fn hashContent(content: []const u8) ContentHash {
    var out: ContentHash = undefined;
    Blake3.hash(content, &out, .{});
    return out;
}

fn validAtom(value: []const u8, max_len: usize) bool {
    if (value.len == 0 or value.len > max_len) return false;
    for (value) |ch| {
        if (ch <= 0x20 or ch == 0x7f or ch == ',' or ch == 0) return false;
    }
    return true;
}

fn validContent(value: []const u8, max_len: usize) bool {
    if (value.len == 0 or value.len > max_len) return false;
    for (value) |ch| {
        switch (ch) {
            0, '\r', '\n' => return false,
            else => {},
        }
    }
    return true;
}

const TestStore = HistoryStore(4, 4, 32, 32, 32, 512);

fn appendTest(
    store: *TestStore,
    msgid: []const u8,
    sender: []const u8,
    ms: u64,
    content: []const u8,
) !AppendResult {
    return store.append(.{ .kind = .channel, .name = "#zig" }, msgid, sender, try Hlc.init(ms, 0), content);
}

fn testContentRefs(store: *const TestStore, hash: ContentHash) usize {
    const stored = store.contents.get(hash) orelse return 0;
    return stored.refs;
}

test "append and query latest before and around" {
    var store = TestStore.init(std.testing.allocator);
    defer store.deinit();

    _ = try appendTest(&store, "m1", "alice", 1000, "one");
    _ = try appendTest(&store, "m2", "bob", 2000, "two");
    _ = try appendTest(&store, "m3", "alice", 3000, "three");
    _ = try appendTest(&store, "m4", "bob", 4000, "four");

    var out: [4]MessageRef = undefined;
    const latest = try store.query(.{ .kind = .channel, .name = "#zig" }, .latest, 2, &out);
    try std.testing.expectEqual(@as(usize, 2), latest.len);
    try std.testing.expectEqualStrings("m3", latest[0].msgid);
    try std.testing.expectEqualStrings("three", latest[0].content.?);
    try std.testing.expectEqualStrings("m4", latest[1].msgid);

    const before = try store.query(.{ .kind = .channel, .name = "#zig" }, .{ .before = try Hlc.init(3000, 0) }, 2, &out);
    try std.testing.expectEqual(@as(usize, 2), before.len);
    try std.testing.expectEqualStrings("m1", before[0].msgid);
    try std.testing.expectEqualStrings("m2", before[1].msgid);

    const around = try store.query(.{ .kind = .channel, .name = "#zig" }, .{ .around = try Hlc.init(3000, 0) }, 3, &out);
    try std.testing.expectEqual(@as(usize, 3), around.len);
    try std.testing.expectEqualStrings("m2", around[0].msgid);
    try std.testing.expectEqualStrings("m3", around[1].msgid);
    try std.testing.expectEqualStrings("m4", around[2].msgid);

    const around_end = try store.query(.{ .kind = .channel, .name = "#zig" }, .{ .around = try Hlc.init(4000, 0) }, 3, &out);
    try std.testing.expectEqual(@as(usize, 3), around_end.len);
    try std.testing.expectEqualStrings("m2", around_end[0].msgid);
    try std.testing.expectEqualStrings("m3", around_end[1].msgid);
    try std.testing.expectEqualStrings("m4", around_end[2].msgid);
}

test "dedupe by content hash shares retained content" {
    var store = TestStore.init(std.testing.allocator);
    defer store.deinit();

    const first = try appendTest(&store, "m1", "alice", 1000, "same body");
    const second = try appendTest(&store, "m2", "bob", 2000, "same body");

    try std.testing.expect(std.mem.eql(u8, &first.hash, &second.hash));
    try std.testing.expect(!first.shared_content);
    try std.testing.expect(second.shared_content);
    try std.testing.expectEqual(@as(usize, 1), store.uniqueContentCount());

    var out: [4]MessageRef = undefined;
    const latest = try store.query(.{ .kind = .channel, .name = "#zig" }, .latest, 4, &out);
    try std.testing.expectEqual(@as(usize, 2), latest.len);
    try std.testing.expectEqualStrings("same body", latest[0].content.?);
    try std.testing.expectEqualStrings("same body", latest[1].content.?);
}

test "dedupe survives redaction then eviction of identical content" {
    var store = TestStore.init(std.testing.allocator);
    defer store.deinit();

    const first = try appendTest(&store, "m1", "alice", 1000, "same body");
    const second = try appendTest(&store, "m2", "bob", 2000, "same body");

    try std.testing.expect(std.mem.eql(u8, &first.hash, &second.hash));
    try std.testing.expectEqual(@as(usize, 1), store.uniqueContentCount());
    try std.testing.expectEqual(@as(usize, 2), testContentRefs(&store, first.hash));
    try std.testing.expectEqual(@as(usize, 1), try store.redactByMsgid(.{ .kind = .channel, .name = "#zig" }, "m1"));
    try std.testing.expectEqual(@as(usize, 1), store.uniqueContentCount());
    try std.testing.expectEqual(@as(usize, 1), testContentRefs(&store, first.hash));

    _ = try appendTest(&store, "m3", "alice", 3000, "three");
    try std.testing.expectEqual(@as(usize, 1), try store.redactByMsgid(.{ .kind = .channel, .name = "#zig" }, "m3"));
    _ = try appendTest(&store, "m4", "alice", 4000, "four");
    try std.testing.expectEqual(@as(usize, 1), try store.redactByMsgid(.{ .kind = .channel, .name = "#zig" }, "m4"));
    try std.testing.expectEqual(@as(usize, 1), store.uniqueContentCount());

    _ = try appendTest(&store, "m5", "alice", 5000, "five");
    try std.testing.expectEqual(@as(usize, 1), try store.redactByMsgid(.{ .kind = .channel, .name = "#zig" }, "m5"));
    try std.testing.expectEqual(@as(usize, 1), store.uniqueContentCount());

    const sixth = try appendTest(&store, "m6", "alice", 6000, "six");
    try std.testing.expect(sixth.evicted);
    try std.testing.expectEqual(@as(usize, 1), try store.redactByMsgid(.{ .kind = .channel, .name = "#zig" }, "m6"));
    try std.testing.expectEqual(@as(usize, 0), store.uniqueContentCount());
}

test "redact by shared content hash tombstones all live entries" {
    var store = TestStore.init(std.testing.allocator);
    defer store.deinit();

    const first = try appendTest(&store, "m1", "alice", 1000, "same body");
    const second = try appendTest(&store, "m2", "bob", 2000, "same body");

    try std.testing.expect(std.mem.eql(u8, &first.hash, &second.hash));
    try std.testing.expectEqual(@as(usize, 1), store.uniqueContentCount());
    try std.testing.expectEqual(@as(usize, 2), testContentRefs(&store, first.hash));
    try std.testing.expectEqual(@as(usize, 2), try store.redactByHash(.{ .kind = .channel, .name = "#zig" }, first.hash));
    try std.testing.expectEqual(@as(usize, 0), store.uniqueContentCount());

    var out: [4]MessageRef = undefined;
    const latest = try store.query(.{ .kind = .channel, .name = "#zig" }, .latest, 4, &out);
    try std.testing.expectEqual(@as(usize, 2), latest.len);
    try std.testing.expect(latest[0].tombstone);
    try std.testing.expect(latest[0].content == null);
    try std.testing.expect(latest[1].tombstone);
    try std.testing.expect(latest[1].content == null);
}

test "redaction hides content but keeps tombstone" {
    var store = TestStore.init(std.testing.allocator);
    defer store.deinit();

    _ = try appendTest(&store, "m1", "alice", 1000, "keep");
    _ = try appendTest(&store, "m2", "bob", 2000, "hide me");

    try std.testing.expectEqual(@as(usize, 1), try store.redactByMsgid(.{ .kind = .channel, .name = "#zig" }, "m2"));

    var out: [4]MessageRef = undefined;
    const latest = try store.query(.{ .kind = .channel, .name = "#zig" }, .latest, 4, &out);
    try std.testing.expectEqual(@as(usize, 2), latest.len);
    try std.testing.expect(!latest[0].tombstone);
    try std.testing.expect(latest[0].content != null);
    try std.testing.expect(latest[1].tombstone);
    try std.testing.expect(latest[1].content == null);
    try std.testing.expectEqualStrings("m2", latest[1].msgid);
}

test "limit is respected across after between and ring retention" {
    var store = TestStore.init(std.testing.allocator);
    defer store.deinit();

    _ = try appendTest(&store, "m1", "alice", 1000, "one");
    _ = try appendTest(&store, "m2", "alice", 2000, "two");
    _ = try appendTest(&store, "m3", "alice", 3000, "three");
    _ = try appendTest(&store, "m4", "alice", 4000, "four");
    const fifth = try appendTest(&store, "m5", "alice", 5000, "five");

    try std.testing.expect(fifth.evicted);
    try std.testing.expectEqual(@as(usize, 4), try store.targetLen(.{ .kind = .channel, .name = "#zig" }));

    var out: [2]MessageRef = undefined;
    const after = try store.query(.{ .kind = .channel, .name = "#zig" }, .{ .after = try Hlc.init(1000, 0) }, 2, &out);
    try std.testing.expectEqual(@as(usize, 2), after.len);
    try std.testing.expectEqualStrings("m4", after[0].msgid);
    try std.testing.expectEqualStrings("m5", after[1].msgid);

    const between = try store.query(.{
        .kind = .channel,
        .name = "#zig",
    }, .{ .between = .{
        .start = try Hlc.init(2000, 0),
        .end = try Hlc.init(5000, 0),
    } }, 1, &out);
    try std.testing.expectEqual(@as(usize, 1), between.len);
    try std.testing.expectEqualStrings("m5", between[0].msgid);

    try std.testing.expectError(
        error.OutputTooSmall,
        store.query(.{ .kind = .channel, .name = "#zig" }, .latest, 3, &out),
    );
}
