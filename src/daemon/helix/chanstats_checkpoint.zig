// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact, bounded Windows Helix custody for live channel statistics.
//! The source holds the World/reactor mutation boundary through COMMIT/ABORT.
//! A decoded image owns every map key and aggregate independently of the wire.
const std = @import("std");
const chanstats = @import("../chanstats.zig");

const magic = "HXCS";
const version: u16 = 1;
const header_len: usize = 96;
pub const max_snapshot_bytes: usize = 256 << 20;
const max_text_bytes: usize = std.math.maxInt(u16);
const max_topic_bytes: usize = 400;

comptime {
    if (chanstats.helix_max_channels > std.math.maxInt(u16) or
        chanstats.helix_max_users_per_channel > std.math.maxInt(u16) or
        chanstats.helix_max_words_per_channel > std.math.maxInt(u16) or
        chanstats.helix_max_days_kept > std.math.maxInt(u8) or
        chanstats.helix_max_topics_kept > std.math.maxInt(u8) or
        max_snapshot_bytes > std.math.maxInt(u32))
        @compileError("Windows channel-statistics checkpoint exceeds wire bounds");
}

pub const Error = std.mem.Allocator.Error || error{ InvalidSnapshot, ConfigMismatch, TooLarge };

pub const Config = struct {
    chanstats_dir: []const u8,
    stats_interval_ms: i64,
    ignored_nicks: []const []const u8,
};

pub const Owned = struct {
    stats: chanstats.ChanStats,
    last_write_ms: i64,
    prune_ready_ms: i64,

    pub fn deinit(self: *Owned) void {
        self.stats.deinit();
        self.* = undefined;
    }
};

fn hashLen(hash: *std.crypto.hash.sha2.Sha256, len: usize) void {
    var field: [8]u8 = undefined;
    std.mem.writeInt(u64, &field, @intCast(len), .big);
    hash.update(&field);
}

fn configDigest(config: Config) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("onyx-helix-chanstats-config-v1\x00");
    hashLen(&hash, config.chanstats_dir.len);
    hash.update(config.chanstats_dir);
    var interval: [8]u8 = undefined;
    std.mem.writeInt(u64, &interval, @bitCast(config.stats_interval_ms), .big);
    hash.update(&interval);
    hashLen(&hash, config.ignored_nicks.len);
    for (config.ignored_nicks) |nick| {
        hashLen(&hash, nick.len);
        hash.update(nick);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

const Sink = struct {
    bytes: ?[]u8 = null,
    pos: usize = 0,

    fn write(self: *Sink, value: []const u8) Error!void {
        const end = std.math.add(usize, self.pos, value.len) catch return error.TooLarge;
        if (end > max_snapshot_bytes) return error.TooLarge;
        if (self.bytes) |bytes| {
            std.debug.assert(end <= bytes.len);
            @memcpy(bytes[self.pos..end], value);
        }
        self.pos = end;
    }

    fn int(self: *Sink, comptime T: type, value: T) Error!void {
        var field: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &field, value, .big);
        try self.write(&field);
    }

    fn text(self: *Sink, value: []const u8, max_len: usize) Error!void {
        if (value.len > max_len or value.len > max_text_bytes) return error.TooLarge;
        try self.int(u16, @intCast(value.len));
        try self.write(value);
    }
};

fn lessText(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn sortedKeys(allocator: std.mem.Allocator, map: anytype) Error![][]const u8 {
    const keys = try allocator.alloc([]const u8, map.count());
    errdefer allocator.free(keys);
    var it = map.keyIterator();
    var i: usize = 0;
    while (it.next()) |key| : (i += 1) keys[i] = key.*;
    std.debug.assert(i == keys.len);
    std.mem.sort([]const u8, keys, {}, lessText);
    return keys;
}

fn lowercase(value: []const u8) bool {
    for (value) |c| if (std.ascii.toLower(c) != c) return false;
    return true;
}

fn writeUser(sink: *Sink, nick: []const u8, user: *const chanstats.UserAgg) Error!void {
    if (nick.len == 0 or !std.mem.eql(u8, nick, user.nick)) return error.InvalidSnapshot;
    try sink.text(nick, max_text_bytes);
    inline for (.{ user.messages, user.words, user.questions, user.exclamations, user.urls, user.actions }) |v|
        try sink.int(u64, v);
    try sink.int(i64, user.last_active);
    try sink.int(u32, user.monologue);
}

fn writeChannel(allocator: std.mem.Allocator, sink: *Sink, key: []const u8, agg: *const chanstats.ChannelAgg) Error!void {
    if (key.len == 0 or !std.mem.eql(u8, key, agg.name)) return error.InvalidSnapshot;
    if (agg.days.items.len > chanstats.helix_max_days_kept or
        agg.users.count() > chanstats.helix_max_users_per_channel or
        agg.word_freq.count() > chanstats.helix_max_words_per_channel or
        agg.topics.items.len > chanstats.helix_max_topics_kept)
        return error.InvalidSnapshot;
    try sink.text(key, max_text_bytes);
    try sink.int(i64, agg.first_seen);
    try sink.int(i64, agg.last_active);
    inline for (.{ agg.messages, agg.words, agg.joins, agg.parts, agg.quits, agg.kicks, agg.topic_changes, agg.actions, agg.peak_members }) |v|
        try sink.int(u64, v);
    for (agg.hours) |v| try sink.int(u64, v);
    for (agg.heatmap) |row| {
        for (row) |v| try sink.int(u64, v);
    }
    try sink.text(agg.last_speaker, max_text_bytes);
    try sink.int(u32, agg.monologue_run);
    try sink.int(u8, @intCast(agg.days.items.len));
    for (agg.days.items) |day| {
        try sink.int(i64, day.day);
        try sink.int(u64, day.messages);
    }
    try sink.int(u16, @intCast(agg.users.count()));
    var users = agg.users;
    const user_keys = try sortedKeys(allocator, &users);
    defer allocator.free(user_keys);
    for (user_keys) |nick| try writeUser(sink, nick, agg.users.get(nick).?);
    try sink.int(u16, @intCast(agg.word_freq.count()));
    var words = agg.word_freq;
    const word_keys = try sortedKeys(allocator, &words);
    defer allocator.free(word_keys);
    for (word_keys) |word| {
        if (word.len < 4 or word.len > chanstats.helix_max_word_len or !lowercase(word))
            return error.InvalidSnapshot;
        try sink.text(word, chanstats.helix_max_word_len);
        try sink.int(u64, agg.word_freq.get(word).?);
    }
    try sink.int(u8, @intCast(agg.topics.items.len));
    for (agg.topics.items) |topic| {
        try sink.int(i64, topic.ts);
        try sink.text(topic.setter, max_text_bytes);
        try sink.text(topic.topic, max_topic_bytes);
    }
}

fn writeBody(allocator: std.mem.Allocator, sink: *Sink, source: *const chanstats.ChanStats) Error!void {
    if (source.channels.count() > chanstats.helix_max_channels or
        source.ignored_nicks.count() > std.math.maxInt(u32)) return error.TooLarge;
    var ignored = source.ignored_nicks;
    const ignored_keys = try sortedKeys(allocator, &ignored);
    defer allocator.free(ignored_keys);
    for (ignored_keys) |nick| {
        if (nick.len == 0 or !lowercase(nick)) return error.InvalidSnapshot;
        try sink.text(nick, max_text_bytes);
    }
    var channels = source.channels;
    const channel_keys = try sortedKeys(allocator, &channels);
    defer allocator.free(channel_keys);
    for (channel_keys) |name| try writeChannel(allocator, sink, name, source.channels.get(name).?);
}

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize,

    fn read(self: *Cursor, len: usize) error{InvalidSnapshot}![]const u8 {
        if (self.pos > self.bytes.len or len > self.bytes.len - self.pos) return error.InvalidSnapshot;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn int(self: *Cursor, comptime T: type) error{InvalidSnapshot}!T {
        const field = try self.read(@sizeOf(T));
        return std.mem.readInt(T, field[0..@sizeOf(T)], .big);
    }

    fn text(self: *Cursor, max_len: usize, required: bool) error{InvalidSnapshot}![]const u8 {
        const len: usize = try self.int(u16);
        if (len > max_len or (required and len == 0)) return error.InvalidSnapshot;
        return self.read(len);
    }
};

fn strictlyAfter(previous: ?[]const u8, current: []const u8) bool {
    return if (previous) |old| std.mem.lessThan(u8, old, current) else true;
}

/// Full framing and canonical-order check without allocation. This is also
/// safe to use in the whole-handoff relation pass before candidate mutation.
pub fn validateCheckpoint(bytes: []const u8) error{InvalidSnapshot}!void {
    if (bytes.len < header_len or bytes.len > max_snapshot_bytes or !isCheckpoint(bytes))
        return error.InvalidSnapshot;
    var c = Cursor{ .bytes = bytes, .pos = 4 };
    if (try c.int(u16) != version or try c.int(u16) != 0) return error.InvalidSnapshot;
    const channel_count: usize = try c.int(u32);
    const ignored_count: usize = try c.int(u32);
    if (channel_count > chanstats.helix_max_channels or
        try c.int(u16) != chanstats.helix_max_channels or
        try c.int(u16) != chanstats.helix_max_users_per_channel or
        try c.int(u16) != chanstats.helix_max_words_per_channel or
        try c.int(u16) != chanstats.helix_max_days_kept or
        try c.int(u16) != chanstats.helix_max_topics_kept or
        try c.int(u16) != chanstats.helix_max_word_len or
        try c.int(u16) != max_topic_bytes or
        try c.int(u16) != 0)
        return error.InvalidSnapshot;
    const wire_len: usize = try c.int(u32);
    if (wire_len != bytes.len) return error.InvalidSnapshot;
    _ = try c.int(i64); // last write, which may be zero before the first flush
    _ = try c.int(i64); // prune readiness; preserve even if in the past
    _ = try c.int(u64); // min_messages
    _ = try c.read(32); // config digest, checked against candidate in decodeOwned
    if (!std.mem.allEqual(u8, try c.read(4), 0) or c.pos != header_len) return error.InvalidSnapshot;
    var previous_ignored: ?[]const u8 = null;
    for (0..ignored_count) |_| {
        const nick = try c.text(max_text_bytes, true);
        if (!lowercase(nick) or !strictlyAfter(previous_ignored, nick)) return error.InvalidSnapshot;
        previous_ignored = nick;
    }
    var previous_channel: ?[]const u8 = null;
    for (0..channel_count) |_| {
        const name = try c.text(max_text_bytes, true);
        if (!strictlyAfter(previous_channel, name)) return error.InvalidSnapshot;
        previous_channel = name;
        _ = try c.int(i64);
        _ = try c.int(i64);
        for (0..9 + 24 + 7 * 24) |_| _ = try c.int(u64);
        _ = try c.text(max_text_bytes, false); // last_speaker
        _ = try c.int(u32); // monologue_run
        const day_count: usize = try c.int(u8);
        if (day_count > chanstats.helix_max_days_kept) return error.InvalidSnapshot;
        for (0..day_count) |_| {
            _ = try c.int(i64);
            _ = try c.int(u64);
        }
        const user_count: usize = try c.int(u16);
        if (user_count > chanstats.helix_max_users_per_channel) return error.InvalidSnapshot;
        var previous_user: ?[]const u8 = null;
        for (0..user_count) |_| {
            const nick = try c.text(max_text_bytes, true);
            if (!strictlyAfter(previous_user, nick)) return error.InvalidSnapshot;
            previous_user = nick;
            for (0..6) |_| _ = try c.int(u64);
            _ = try c.int(i64);
            _ = try c.int(u32);
        }
        const word_count: usize = try c.int(u16);
        if (word_count > chanstats.helix_max_words_per_channel) return error.InvalidSnapshot;
        var previous_word: ?[]const u8 = null;
        for (0..word_count) |_| {
            const word = try c.text(chanstats.helix_max_word_len, true);
            if (word.len < 4 or !lowercase(word) or !strictlyAfter(previous_word, word))
                return error.InvalidSnapshot;
            previous_word = word;
            _ = try c.int(u64);
        }
        const topic_count: usize = try c.int(u8);
        if (topic_count > chanstats.helix_max_topics_kept) return error.InvalidSnapshot;
        for (0..topic_count) |_| {
            _ = try c.int(i64);
            _ = try c.text(max_text_bytes, false);
            _ = try c.text(max_topic_bytes, false);
        }
    }
    if (c.pos != bytes.len) return error.InvalidSnapshot;
}

/// Encode all live counters, maps, lists, and scheduling state under the
/// source's existing World/reactor mutation fence. Oversize images fail closed.
pub fn encodeSnapshot(
    allocator: std.mem.Allocator,
    source: *const chanstats.ChanStats,
    last_write_ms: i64,
    prune_ready_ms: i64,
    config: Config,
) Error![]u8 {
    var measure = Sink{ .pos = header_len };
    try writeBody(allocator, &measure, source);
    const bytes = try allocator.alloc(u8, measure.pos);
    errdefer allocator.free(bytes);
    var sink = Sink{ .bytes = bytes };
    try sink.write(magic);
    try sink.int(u16, version);
    try sink.int(u16, 0);
    try sink.int(u32, @intCast(source.channels.count()));
    try sink.int(u32, @intCast(source.ignored_nicks.count()));
    try sink.int(u16, @intCast(chanstats.helix_max_channels));
    try sink.int(u16, @intCast(chanstats.helix_max_users_per_channel));
    try sink.int(u16, @intCast(chanstats.helix_max_words_per_channel));
    try sink.int(u16, @intCast(chanstats.helix_max_days_kept));
    try sink.int(u16, @intCast(chanstats.helix_max_topics_kept));
    try sink.int(u16, @intCast(chanstats.helix_max_word_len));
    try sink.int(u16, @intCast(max_topic_bytes));
    try sink.int(u16, 0);
    try sink.int(u32, @intCast(measure.pos));
    try sink.int(i64, last_write_ms);
    try sink.int(i64, prune_ready_ms);
    try sink.int(u64, source.min_messages);
    const digest = configDigest(config);
    try sink.write(&digest);
    try sink.int(u32, 0);
    std.debug.assert(sink.pos == header_len);
    try writeBody(allocator, &sink, source);
    std.debug.assert(sink.pos == bytes.len);
    return bytes;
}

fn putIgnored(stats: *chanstats.ChanStats, nick: []const u8) std.mem.Allocator.Error!void {
    const key = try stats.allocator.dupe(u8, nick);
    stats.ignored_nicks.put(stats.allocator, key, {}) catch |err| {
        stats.allocator.free(key);
        return err;
    };
}

fn putChannel(stats: *chanstats.ChanStats, name: []const u8) std.mem.Allocator.Error!*chanstats.ChannelAgg {
    const key = try stats.allocator.dupe(u8, name);
    const agg = stats.allocator.create(chanstats.ChannelAgg) catch |err| {
        stats.allocator.free(key);
        return err;
    };
    const owned_name = stats.allocator.dupe(u8, name) catch |err| {
        stats.allocator.destroy(agg);
        stats.allocator.free(key);
        return err;
    };
    agg.* = .{ .name = owned_name };
    stats.channels.put(stats.allocator, key, agg) catch |err| {
        stats.allocator.free(owned_name);
        stats.allocator.destroy(agg);
        stats.allocator.free(key);
        return err;
    };
    return agg;
}

fn putUser(stats: *chanstats.ChanStats, agg: *chanstats.ChannelAgg, nick: []const u8, user: chanstats.UserAgg) std.mem.Allocator.Error!void {
    const owned = try stats.allocator.create(chanstats.UserAgg);
    owned.* = user;
    owned.nick = stats.allocator.dupe(u8, nick) catch |err| {
        stats.allocator.destroy(owned);
        return err;
    };
    agg.users.put(stats.allocator, owned.nick, owned) catch |err| {
        stats.allocator.free(owned.nick);
        stats.allocator.destroy(owned);
        return err;
    };
}

fn putWord(stats: *chanstats.ChanStats, agg: *chanstats.ChannelAgg, word: []const u8, count: u64) std.mem.Allocator.Error!void {
    const key = try stats.allocator.dupe(u8, word);
    agg.word_freq.put(stats.allocator, key, count) catch |err| {
        stats.allocator.free(key);
        return err;
    };
}

/// Validate framing and config before the first allocation. On failure every
/// partially decoded owner is destroyed; the candidate's live store is intact.
pub fn decodeOwned(allocator: std.mem.Allocator, bytes: []const u8, config: Config) Error!Owned {
    try validateCheckpoint(bytes);
    const digest = configDigest(config);
    if (!std.crypto.timing_safe.eql([32]u8, digest, bytes[60..92].*)) return error.ConfigMismatch;
    var result = Owned{
        .stats = chanstats.ChanStats.init(allocator),
        .last_write_ms = @bitCast(std.mem.readInt(u64, bytes[36..44], .big)),
        .prune_ready_ms = @bitCast(std.mem.readInt(u64, bytes[44..52], .big)),
    };
    errdefer result.deinit();
    result.stats.min_messages = std.mem.readInt(u64, bytes[52..60], .big);
    var c = Cursor{ .bytes = bytes, .pos = header_len };
    const ignored_count: usize = std.mem.readInt(u32, bytes[12..16], .big);
    const channel_count: usize = std.mem.readInt(u32, bytes[8..12], .big);
    for (0..ignored_count) |_| try putIgnored(&result.stats, try c.text(max_text_bytes, true));
    for (0..channel_count) |_| {
        const agg = try putChannel(&result.stats, try c.text(max_text_bytes, true));
        agg.first_seen = try c.int(i64);
        agg.last_active = try c.int(i64);
        agg.messages = try c.int(u64);
        agg.words = try c.int(u64);
        agg.joins = try c.int(u64);
        agg.parts = try c.int(u64);
        agg.quits = try c.int(u64);
        agg.kicks = try c.int(u64);
        agg.topic_changes = try c.int(u64);
        agg.actions = try c.int(u64);
        agg.peak_members = try c.int(u64);
        for (&agg.hours) |*v| v.* = try c.int(u64);
        for (&agg.heatmap) |*row| {
            for (row) |*v| v.* = try c.int(u64);
        }
        const speaker = try c.text(max_text_bytes, false);
        if (speaker.len != 0) agg.last_speaker = try allocator.dupe(u8, speaker);
        agg.monologue_run = try c.int(u32);
        const day_count: usize = try c.int(u8);
        for (0..day_count) |_| try agg.days.append(allocator, .{
            .day = try c.int(i64),
            .messages = try c.int(u64),
        });
        const user_count: usize = try c.int(u16);
        for (0..user_count) |_| {
            const nick = try c.text(max_text_bytes, true);
            const user = chanstats.UserAgg{
                .nick = undefined,
                .messages = try c.int(u64),
                .words = try c.int(u64),
                .questions = try c.int(u64),
                .exclamations = try c.int(u64),
                .urls = try c.int(u64),
                .actions = try c.int(u64),
                .last_active = try c.int(i64),
                .monologue = try c.int(u32),
            };
            try putUser(&result.stats, agg, nick, user);
        }
        const word_count: usize = try c.int(u16);
        for (0..word_count) |_| {
            const word = try c.text(chanstats.helix_max_word_len, true);
            try putWord(&result.stats, agg, word, try c.int(u64));
        }
        const topic_count: usize = try c.int(u8);
        for (0..topic_count) |_| {
            const ts = try c.int(i64);
            const setter = try c.text(max_text_bytes, false);
            const topic = try c.text(max_topic_bytes, false);
            const owned_setter = try allocator.dupe(u8, setter);
            const owned_topic = allocator.dupe(u8, topic) catch |err| {
                allocator.free(owned_setter);
                return err;
            };
            agg.topics.append(allocator, .{ .ts = ts, .setter = owned_setter, .topic = owned_topic }) catch |err| {
                allocator.free(owned_setter);
                allocator.free(owned_topic);
                return err;
            };
        }
    }
    std.debug.assert(c.pos == bytes.len);
    return result;
}

const test_config = Config{
    .chanstats_dir = "C:/onyx/stats",
    .stats_interval_ms = 30_000,
    .ignored_nicks = &.{ "Bot", "Service" },
};

test "Windows Helix channel statistics checkpoint owns every live field" {
    const allocator = std.testing.allocator;
    var source = chanstats.ChanStats.init(allocator);
    defer source.deinit();
    source.setIgnoredNicks(test_config.ignored_nicks);
    source.min_messages = 7;
    source.recordEvent("#alpha", .join, 1_000);
    source.recordMessage("#zeta", "bob", "hello? world!", 86_400_000);
    source.recordMessage("#zeta", "bob", "hello? world!", 172_800_000);
    source.recordMessage("#zeta", "alice", "another http://example.test", 172_800_001);
    source.recordTopic("#zeta", "alice", "new topic", 172_800_002);
    const zeta = source.channels.get("#zeta").?;
    zeta.peak_members = 23;
    zeta.last_speaker[0] = 'a'; // keep an independently owned speaker string
    const wire = try encodeSnapshot(allocator, &source, 333, 444, test_config);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    try validateCheckpoint(wire);
    const baseline = try allocator.dupe(u8, wire);
    defer allocator.free(baseline);
    var owned = try decodeOwned(allocator, wire, test_config);
    defer owned.deinit();
    try std.testing.expectEqual(@as(i64, 333), owned.last_write_ms);
    try std.testing.expectEqual(@as(i64, 444), owned.prune_ready_ms);
    try std.testing.expectEqual(@as(u64, 7), owned.stats.min_messages);
    try std.testing.expect(owned.stats.isIgnored("BOT"));
    const restored = owned.stats.channels.get("#zeta").?;
    try std.testing.expectEqual(@as(u64, 23), restored.peak_members);
    try std.testing.expectEqual(@as(u32, 1), restored.monologue_run);
    try std.testing.expectEqualStrings("alice", restored.last_speaker);
    try std.testing.expectEqual(@as(usize, 2), restored.days.items.len);
    try std.testing.expectEqual(@as(usize, 1), restored.topics.items.len);
    try std.testing.expectEqual(@as(usize, 2), restored.users.count());
    try std.testing.expect(restored.word_freq.count() >= 2);
    @memset(wire, 0);
    const again = try encodeSnapshot(allocator, &owned.stats, owned.last_write_ms, owned.prune_ready_ms, test_config);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, baseline, again);
}

test "Windows Helix channel statistics checkpoint sorts map insertion order" {
    const allocator = std.testing.allocator;
    var first = chanstats.ChanStats.init(allocator);
    defer first.deinit();
    var second = chanstats.ChanStats.init(allocator);
    defer second.deinit();
    first.setIgnoredNicks(&.{ "Bot", "Service" });
    second.setIgnoredNicks(&.{ "Service", "Bot" });
    first.recordEvent("#zeta", .join, 1000);
    first.recordEvent("#alpha", .part, 1000);
    second.recordEvent("#alpha", .part, 1000);
    second.recordEvent("#zeta", .join, 1000);
    const a = try encodeSnapshot(allocator, &first, 0, 123, test_config);
    defer allocator.free(a);
    const b = try encodeSnapshot(allocator, &second, 0, 123, test_config);
    defer allocator.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}

test "Windows Helix channel statistics checkpoint rejects malformed rows before allocation" {
    const allocator = std.testing.allocator;
    var source = chanstats.ChanStats.init(allocator);
    defer source.deinit();
    source.setIgnoredNicks(&.{ "alpha", "bravo" });
    const wire = try encodeSnapshot(allocator, &source, 0, 0, test_config);
    defer allocator.free(wire);
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(wire[0 .. wire.len - 1]));
    var bad = try allocator.dupe(u8, wire);
    defer allocator.free(bad);
    bad[16] ^= 1; // recorder's max_channels policy
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    bad[16] ^= 1;
    const second = header_len + 2 + "alpha".len + 2;
    @memcpy(bad[second..][0..5], "alpha");
    try std.testing.expectError(error.InvalidSnapshot, validateCheckpoint(bad));
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSnapshot, decodeOwned(failing.allocator(), bad, test_config));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectError(error.ConfigMismatch, decodeOwned(failing.allocator(), wire, .{
        .chanstats_dir = test_config.chanstats_dir,
        .stats_interval_ms = 100,
        .ignored_nicks = test_config.ignored_nicks,
    }));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
}

fn decodeAllocationCampaign(allocator: std.mem.Allocator, wire: []const u8) !void {
    var owned = try decodeOwned(allocator, wire, test_config);
    defer owned.deinit();
    try std.testing.expectEqual(@as(usize, 1), owned.stats.channels.count());
    try std.testing.expectEqual(@as(i64, 1234), owned.prune_ready_ms);
}

test "Windows Helix channel statistics checkpoint decode sweeps allocation failures" {
    const allocator = std.testing.allocator;
    var source = chanstats.ChanStats.init(allocator);
    defer source.deinit();
    source.recordMessage("#a", "bob", "hello world", 86_400_000);
    source.recordTopic("#a", "bob", "topic", 86_400_001);
    const wire = try encodeSnapshot(allocator, &source, 42, 1234, test_config);
    defer allocator.free(wire);
    try std.testing.checkAllAllocationFailures(allocator, decodeAllocationCampaign, .{wire});
}

test "Windows Helix channel statistics checkpoint refuses oversized live text" {
    const allocator = std.testing.allocator;
    var source = chanstats.ChanStats.init(allocator);
    defer source.deinit();
    const oversized = try allocator.alloc(u8, max_text_bytes + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'x');
    source.recordEvent(oversized, .join, 1);
    try std.testing.expectError(error.TooLarge, encodeSnapshot(allocator, &source, 0, 0, test_config));
}
