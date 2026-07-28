//! chanstats.zig — per-channel statistics engine (native + in-process).
//! Aggregates live channel activity into
//! per-channel counters and emits self-describing JSON (an index plus one file
//! per channel) into a directory that nginx serves; a SolidJS dashboard renders
//! it. Pure data + JSON; no sockets, no SQLite — the daemon feeds it via
//! `recordMessage`/`recordEvent`/`recordTopic` and flushes with `writeJson` on
//! a throttled cadence.
//!
//! Bounded by construction: per-channel user and word tables are capped (when
//! full, only already-tracked keys update), so a hostile flood cannot pin
//! unbounded memory. Timestamps are WALL-CLOCK unix-ms (the caller passes
//! `platform.realtimeMillis()`); hour-of-day and the weekday heatmap derive
//! from them in UTC.

const std = @import("std");

/// Case-insensitive substring search, mirroring the pre-0.17 `std.ascii.indexOfIgnoreCase`
/// (removed from std). Returns the index of the first case-insensitive match, or null;
/// an empty needle matches at 0.
fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;
    const end = haystack.len - needle.len;
    var i: usize = 0;
    while (i <= end) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

/// Caps — generous for real channels, hard ceilings against abuse.
const max_channels: usize = 8192;
const max_users_per_channel: usize = 4096;
const max_words_per_channel: usize = 8192;
const max_days_kept: usize = 60;
const max_topics_kept: usize = 40;
const top_users_emitted: usize = 30;
const top_words_emitted: usize = 40;
const spark_days: usize = 14; // recent-daily sparkline length in index.json
const min_word_len: usize = 4;
const max_word_len: usize = 32;

pub const EventKind = enum { join, part, quit, kick };

pub const UserAgg = struct {
    nick: []u8,
    messages: u64 = 0,
    words: u64 = 0,
    questions: u64 = 0,
    exclamations: u64 = 0,
    urls: u64 = 0,
    /// CTCP ACTION (/me) lines by this nick (subset of messages).
    actions: u64 = 0,
    monologue: u32 = 0,
    last_active: i64 = 0,
};

const TopicEntry = struct {
    ts: i64,
    setter: []u8,
    topic: []u8,
};

pub const DayBucket = struct {
    /// Unix day index (sec / 86400).
    day: i64,
    messages: u64 = 0,
};

pub const ChannelAgg = struct {
    name: []u8,
    first_seen: i64 = 0,
    last_active: i64 = 0,
    messages: u64 = 0,
    words: u64 = 0,
    joins: u64 = 0,
    parts: u64 = 0,
    quits: u64 = 0,
    kicks: u64 = 0,
    topic_changes: u64 = 0,
    /// CTCP ACTION (/me) lines in this channel (subset of messages).
    actions: u64 = 0,
    /// High-water mark of simultaneous members (local + mesh), ophion peak_members.
    peak_members: u64 = 0,
    hours: [24]u64 = @splat(0),
    heatmap: [7][24]u64 = @splat(@as([24]u64, @splat(0))),
    days: std.ArrayListUnmanaged(DayBucket) = .empty,
    users: std.StringHashMapUnmanaged(*UserAgg) = .empty,
    word_freq: std.StringHashMapUnmanaged(u64) = .empty,
    topics: std.ArrayListUnmanaged(TopicEntry) = .empty,
    /// Monologue tracking: who spoke last + the current consecutive run.
    last_speaker: []u8 = &.{},
    monologue_run: u32 = 0,

    fn deinit(self: *ChannelAgg, a: std.mem.Allocator) void {
        a.free(self.name);
        self.days.deinit(a);
        var uit = self.users.iterator();
        while (uit.next()) |e| {
            a.free(e.value_ptr.*.nick);
            a.destroy(e.value_ptr.*);
        }
        self.users.deinit(a);
        var wit = self.word_freq.iterator();
        while (wit.next()) |e| a.free(e.key_ptr.*);
        self.word_freq.deinit(a);
        for (self.topics.items) |t| {
            a.free(t.setter);
            a.free(t.topic);
        }
        self.topics.deinit(a);
        if (self.last_speaker.len != 0) a.free(self.last_speaker);
    }
};

pub const ChanStats = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMapUnmanaged(*ChannelAgg) = .empty,
    /// Lowercased nicks excluded from all recording (bots, services, …).
    /// Ported from ophion m_chanstats ignored_nicks.
    ignored_nicks: std.StringHashMapUnmanaged(void) = .empty,
    /// A channel must reach this many messages before it is emitted (keeps the
    /// index free of fly-by one-liner channels). 0 = emit everything.
    min_messages: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) ChanStats {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChanStats) void {
        var it = self.channels.iterator();
        while (it.next()) |e| {
            e.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(e.value_ptr.*);
            self.allocator.free(e.key_ptr.*);
        }
        self.channels.deinit(self.allocator);
        var iit = self.ignored_nicks.keyIterator();
        while (iit.next()) |k| self.allocator.free(k.*);
        self.ignored_nicks.deinit(self.allocator);
    }

    /// Replace the ignore list with lowercased copies of `nicks`.
    pub fn setIgnoredNicks(self: *ChanStats, nicks: []const []const u8) void {
        var iit = self.ignored_nicks.keyIterator();
        while (iit.next()) |k| self.allocator.free(k.*);
        self.ignored_nicks.clearRetainingCapacity();
        for (nicks) |raw| {
            if (raw.len == 0) continue;
            const key = self.allocator.alloc(u8, raw.len) catch continue;
            for (raw, 0..) |c, i| key[i] = std.ascii.toLower(c);
            const gop = self.ignored_nicks.getOrPut(self.allocator, key) catch {
                self.allocator.free(key);
                continue;
            };
            if (gop.found_existing) {
                self.allocator.free(key);
            } else {
                gop.key_ptr.* = key;
                gop.value_ptr.* = {};
            }
        }
    }

    pub fn isIgnored(self: *const ChanStats, nick: []const u8) bool {
        if (nick.len == 0 or self.ignored_nicks.count() == 0) return false;
        var buf: [64]u8 = undefined;
        if (nick.len > buf.len) return false;
        for (nick, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        return self.ignored_nicks.contains(buf[0..nick.len]);
    }

    /// Parse CTCP ACTION body if `text` is `\x01ACTION …\x01`; else null.
    pub fn ctcpActionBody(text: []const u8) ?[]const u8 {
        if (text.len < 9) return null;
        if (text[0] != 0x01 or text[text.len - 1] != 0x01) return null;
        const inner = text[1 .. text.len - 1];
        if (inner.len < 7) return null;
        if (!std.ascii.eqlIgnoreCase(inner[0..6], "ACTION")) return null;
        if (inner.len == 6) return "";
        if (inner[6] != ' ') return null;
        return inner[7..];
    }

    /// Total recorded messages for a channel (0 if never recorded). Read-only
    /// accessor used by tests and diagnostics; never creates a channel.
    pub fn channelMessageCount(self: *const ChanStats, name: []const u8) u64 {
        const e = self.channels.getEntry(name) orelse return 0;
        return e.value_ptr.*.messages;
    }

    pub const PublicSummary = struct {
        channels: u64 = 0,
        messages: u64 = 0,
        active_channels_24h: u64 = 0,
        last_active_ms: ?i64 = null,
        heatline_days: [spark_days]i64 = @splat(0),
        heatline: [spark_days]u64 = @splat(0),
        heatline_len: usize = 0,
    };

    /// Compact discovery/status summary. Counts only channels that meet the
    /// public index threshold, mirroring `writeJson` instead of leaking one-off
    /// transient probes into directory rankings.
    pub fn publicSummary(self: *const ChanStats, now_ms: i64) PublicSummary {
        const day_ms: i64 = 24 * 60 * 60 * 1000;
        var out: PublicSummary = .{};
        var it = self.channels.iterator();
        while (it.next()) |entry| {
            const agg = entry.value_ptr.*;
            if (agg.messages < self.min_messages) continue;
            out.channels += 1;
            out.messages +|= agg.messages;
            if (now_ms >= agg.last_active and now_ms - agg.last_active <= day_ms) out.active_channels_24h += 1;
            if (out.last_active_ms == null or agg.last_active > out.last_active_ms.?) out.last_active_ms = agg.last_active;
            for (agg.days.items) |d| mergePublicHeatlineDay(&out, d.day, d.messages);
        }
        return out;
    }

    fn mergePublicHeatlineDay(out: *PublicSummary, day: i64, messages: u64) void {
        var lo: usize = 0;
        while (lo < out.heatline_len and out.heatline_days[lo] < day) lo += 1;
        if (lo < out.heatline_len and out.heatline_days[lo] == day) {
            out.heatline[lo] +|= messages;
            return;
        }
        if (out.heatline_len == spark_days) {
            if (day <= out.heatline_days[0]) return;
            var i: usize = 0;
            while (i + 1 < out.heatline_len) : (i += 1) {
                out.heatline_days[i] = out.heatline_days[i + 1];
                out.heatline[i] = out.heatline[i + 1];
            }
            out.heatline_len -= 1;
            if (lo > 0) lo -= 1;
        }
        var j = out.heatline_len;
        while (j > lo) : (j -= 1) {
            out.heatline_days[j] = out.heatline_days[j - 1];
            out.heatline[j] = out.heatline[j - 1];
        }
        out.heatline_days[lo] = day;
        out.heatline[lo] = messages;
        out.heatline_len += 1;
    }

    fn channel(self: *ChanStats, name: []const u8, now_ms: i64) ?*ChannelAgg {
        if (self.channels.getEntry(name)) |e| return e.value_ptr.*;
        // Cap the number of DISTINCT channels tracked. Per-channel sub-tables are
        // already bounded (see `userOf`/`max_users_per_channel`); this bounds the
        // channel COUNT so a burst of unique channel names within one flush
        // interval cannot spike memory faster than `pruneDeadChannels` reclaims
        // it. Fail closed: an over-cap channel is simply not tracked (analytics
        // degrade, nothing crashes) until the pruner frees room.
        if (self.channels.count() >= max_channels) return null;
        const key = self.allocator.dupe(u8, name) catch return null;
        errdefer self.allocator.free(key);
        const agg = self.allocator.create(ChannelAgg) catch {
            self.allocator.free(key);
            return null;
        };
        agg.* = .{ .name = self.allocator.dupe(u8, name) catch {
            self.allocator.destroy(agg);
            self.allocator.free(key);
            return null;
        }, .first_seen = now_ms, .last_active = now_ms };
        self.channels.put(self.allocator, key, agg) catch {
            agg.deinit(self.allocator);
            self.allocator.destroy(agg);
            self.allocator.free(key);
            return null;
        };
        return agg;
    }

    fn userOf(self: *ChanStats, agg: *ChannelAgg, nick: []const u8) ?*UserAgg {
        if (agg.users.getEntry(nick)) |e| return e.value_ptr.*;
        if (agg.users.count() >= max_users_per_channel) return null;
        const u = self.allocator.create(UserAgg) catch return null;
        u.* = .{ .nick = self.allocator.dupe(u8, nick) catch {
            self.allocator.destroy(u);
            return null;
        } };
        agg.users.put(self.allocator, u.nick, u) catch {
            self.allocator.free(u.nick);
            self.allocator.destroy(u);
            return null;
        };
        return u;
    }

    /// Record one channel message. `now_ms` is wall-clock unix-ms.
    /// CTCP ACTION (`\x01ACTION …\x01`) counts as a message and increments actions.
    pub fn recordMessage(self: *ChanStats, chan: []const u8, nick: []const u8, text: []const u8, now_ms: i64) void {
        if (chan.len == 0 or nick.len == 0) return;
        if (self.isIgnored(nick)) return;
        const agg = self.channel(chan, now_ms) orelse return;
        agg.last_active = now_ms;
        agg.messages += 1;
        const action_body = ctcpActionBody(text);
        const is_action = action_body != null;
        if (is_action) agg.actions += 1;
        const body = action_body orelse text;

        const sec = @divFloor(now_ms, 1000);
        const day = @divFloor(sec, 86400);
        const hour: usize = @intCast(@mod(@divFloor(sec, 3600), 24));
        // Unix epoch (1970-01-01) was a Thursday → weekday with Sunday=0.
        const weekday: usize = @intCast(@mod(day + 4, 7));
        agg.hours[hour] += 1;
        agg.heatmap[weekday][hour] += 1;
        bumpDay(self.allocator, agg, day);

        // Word + behavioural metrics (ACTION uses the unwrapped body).
        var words: u64 = 0;
        var it = std.mem.tokenizeAny(u8, body, " \t\r\n");
        while (it.next()) |tok| {
            words += 1;
            if (indexOfIgnoreCase(tok, "http://") != null or
                indexOfIgnoreCase(tok, "https://") != null)
            {
                // counted per-user below
            }
            self.bumpWord(agg, tok);
        }
        agg.words += words;

        const u = self.userOf(agg, nick);
        if (u) |usr| {
            usr.messages += 1;
            usr.words += words;
            usr.last_active = now_ms;
            if (is_action) usr.actions += 1;
            if (body.len != 0 and body[body.len - 1] == '?') usr.questions += 1;
            for (body) |c| {
                if (c == '!') usr.exclamations += 1;
            }
            if (indexOfIgnoreCase(body, "http://") != null or
                indexOfIgnoreCase(body, "https://") != null) usr.urls += 1;
        }

        // Monologue: consecutive lines by the same nick.
        if (std.mem.eql(u8, agg.last_speaker, nick)) {
            agg.monologue_run += 1;
        } else {
            agg.monologue_run = 1;
            if (agg.last_speaker.len != 0) self.allocator.free(agg.last_speaker);
            agg.last_speaker = self.allocator.dupe(u8, nick) catch &.{};
        }
        if (u) |usr| {
            if (agg.monologue_run > usr.monologue) usr.monologue = agg.monologue_run;
        }
    }

    /// Raise the channel's peak concurrent member high-water mark.
    pub fn notePresent(self: *ChanStats, chan: []const u8, present: usize) void {
        const entry = self.channels.getEntry(chan) orelse return;
        const agg = entry.value_ptr.*;
        if (present > agg.peak_members) agg.peak_members = present;
    }

    pub fn recordEvent(self: *ChanStats, chan: []const u8, kind: EventKind, now_ms: i64) void {
        if (chan.len == 0) return;
        const agg = self.channel(chan, now_ms) orelse return;
        switch (kind) {
            .join => agg.joins += 1,
            .part => agg.parts += 1,
            .quit => agg.quits += 1,
            .kick => agg.kicks += 1,
        }
    }

    pub fn recordTopic(self: *ChanStats, chan: []const u8, setter: []const u8, topic: []const u8, now_ms: i64) void {
        if (chan.len == 0) return;
        const agg = self.channel(chan, now_ms) orelse return;
        agg.last_active = now_ms;
        agg.topic_changes += 1;
        self.appendTopic(agg, setter, topic, now_ms);
    }

    /// Bring an already-tracked channel's current topic into line with the
    /// authoritative World state. This is deliberately not an event: it must
    /// not manufacture a topic-change count or move last_activity merely
    /// because a periodic stats flush repaired an older snapshot.
    pub fn syncTopic(self: *ChanStats, chan: []const u8, setter: []const u8, topic: []const u8, now_ms: i64) void {
        const entry = self.channels.getEntry(chan) orelse return;
        const agg = entry.value_ptr.*;
        if (agg.topics.items.len != 0) {
            const current = agg.topics.items[agg.topics.items.len - 1];
            if (std.mem.eql(u8, current.setter, setter) and std.mem.eql(u8, current.topic, topic)) return;
        }
        self.appendTopic(agg, setter, topic, now_ms);
    }

    fn appendTopic(self: *ChanStats, agg: *ChannelAgg, setter: []const u8, topic: []const u8, now_ms: i64) void {
        const s = self.allocator.dupe(u8, setter) catch return;
        const t = self.allocator.dupe(u8, clampLen(topic, 400)) catch {
            self.allocator.free(s);
            return;
        };
        agg.topics.append(self.allocator, .{ .ts = now_ms, .setter = s, .topic = t }) catch {
            self.allocator.free(s);
            self.allocator.free(t);
            return;
        };
        // Trim oldest beyond the cap.
        while (agg.topics.items.len > max_topics_kept) {
            const old = agg.topics.orderedRemove(0);
            self.allocator.free(old.setter);
            self.allocator.free(old.topic);
        }
    }

    fn bumpWord(self: *ChanStats, agg: *ChannelAgg, raw: []const u8) void {
        var buf: [max_word_len]u8 = undefined;
        const w = normalizeWord(raw, &buf) orelse return;
        if (agg.word_freq.getEntry(w)) |e| {
            e.value_ptr.* += 1;
            return;
        }
        if (agg.word_freq.count() >= max_words_per_channel) return; // table full: ignore new words
        const key = self.allocator.dupe(u8, w) catch return;
        agg.word_freq.put(self.allocator, key, 1) catch self.allocator.free(key);
    }

    fn bumpDay(a: std.mem.Allocator, agg: *ChannelAgg, day: i64) void {
        if (agg.days.items.len != 0) {
            const last = &agg.days.items[agg.days.items.len - 1];
            if (last.day == day) {
                last.messages += 1;
                return;
            }
        }
        agg.days.append(a, .{ .day = day, .messages = 1 }) catch return;
        if (agg.days.items.len > max_days_kept) _ = agg.days.orderedRemove(0);
    }

    // ── JSON emission ────────────────────────────────────────────────────────

    /// Live network context injected by the server at flush time (the flush
    /// runs under world.lockWrite, so presence reads are consistent). All
    /// fields default to "absent" so tests and headless callers can pass `.{}`.
    pub const NetInfo = struct {
        /// Mesh-wide users online (server meshUserCount) — 0 when unknown.
        users_online: u64 = 0,
        presence_ctx: ?*anyopaque = null,
        /// Current member count (local + mesh roster) for a channel name.
        presence_fn: ?*const fn (ctx: *anyopaque, channel: []const u8) usize = null,
        /// Whether a channel STILL EXISTS: currently populated (present > 0) or
        /// durably registered. When absent, every channel is treated as existing
        /// (tests / callers with no world context). A channel that no longer
        /// exists is pruned from the index, its `<slug>.json` deleted, and its
        /// aggregate freed — so transient/probe channels don't linger forever.
        exists_fn: ?*const fn (ctx: *anyopaque, channel: []const u8) bool = null,

        fn presentOf(self: NetInfo, chan_name: []const u8) usize {
            const f = self.presence_fn orelse return 0;
            const ctx = self.presence_ctx orelse return 0;
            return f(ctx, chan_name);
        }

        fn existsOf(self: NetInfo, chan_name: []const u8) bool {
            const f = self.exists_fn orelse return true;
            const ctx = self.presence_ctx orelse return true;
            return f(ctx, chan_name);
        }
    };

    /// Write `index.json` + one `<slug>.json` per channel into `dir_path` (which
    /// must already exist — the deploy creates it). Best-effort: any render/I/O
    /// error on one file is swallowed so a single bad channel never aborts the
    /// flush. `io` is the daemon's crypto IO (the Zig 0.16 file API).
    pub fn writeJson(self: *ChanStats, io: std.Io, dir_path: []const u8, network: []const u8, node: []const u8, now_ms: i64, net: NetInfo) void {
        // Prune channels that no longer exist (unregistered AND empty) BEFORE
        // rendering, so the index, per-channel files and network_days all reflect
        // only live channels. Transient/probe channels vanish once the last
        // member leaves; a registered channel survives even while momentarily
        // empty. Best-effort: pruning never blocks the flush.
        self.pruneDeadChannels(io, dir_path, net);

        var iaw = std.Io.Writer.Allocating.init(self.allocator);
        defer iaw.deinit();
        const iw = &iaw.writer;
        iw.print("{{\"generated_at\":{d},\"network\":", .{@divFloor(now_ms, 1000)}) catch return;
        writeJsonString(iw, network) catch return;
        iw.writeAll(",\"node\":") catch return;
        writeJsonString(iw, node) catch return;
        iw.print(",\"users_online\":{d}", .{net.users_online}) catch return;
        self.writeNetworkDays(iw) catch return;
        iw.writeAll(",\"channels\":[") catch return;

        var first = true;
        var it = self.channels.iterator();
        while (it.next()) |e| {
            const agg = e.value_ptr.*;
            if (agg.messages < self.min_messages) continue;
            const present = net.presentOf(agg.name);
            if (present > agg.peak_members) agg.peak_members = present;
            self.writeChannelFile(io, dir_path, agg, now_ms, present);

            if (!first) iw.writeByte(',') catch return;
            first = false;
            iw.writeAll("{\"channel\":") catch return;
            writeJsonString(iw, agg.name) catch return;
            iw.print(",\"messages\":{d},\"active_users\":{d},\"present\":{d},\"peak_members\":{d},\"last_active\":{d},\"topic\":", .{
                agg.messages, agg.users.count(), present, agg.peak_members, @divFloor(agg.last_active, 1000),
            }) catch return;
            writeJsonString(iw, currentTopic(agg)) catch return;
            // Compact recent-activity sparkline: the last up-to-14 daily message
            // counts (oldest→newest). Lets the index render per-card trends with
            // no extra fetches. days.items is chronological (see bumpDay).
            iw.writeAll(",\"spark\":[") catch return;
            {
                const days = agg.days.items;
                const start = if (days.len > spark_days) days.len - spark_days else 0;
                var di = start;
                while (di < days.len) : (di += 1) {
                    if (di != start) iw.writeByte(',') catch return;
                    iw.print("{d}", .{days[di].messages}) catch return;
                }
            }
            iw.writeAll("]}") catch return;
        }
        iw.writeAll("]}") catch return;
        writeFileAtomicIo(io, dir_path, "index.json", iaw.written());

        // Persist the full-fidelity binary snapshot alongside the served JSON so
        // per-channel stats survive a restart or USR2 hot-upgrade.
        saveSnapshot(self, io, dir_path);
    }

    /// Network-wide recent activity: per-day message totals summed across every
    /// tracked channel (last `spark_days` days), emitted as
    /// `,"network_days":[{"date":"YYYY-MM-DD","messages":N},…]` oldest→newest.
    fn writeNetworkDays(self: *ChanStats, w: *std.Io.Writer) !void {
        const cap = 64;
        var days: [cap]i64 = undefined;
        var totals: [cap]u64 = undefined;
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.*.days.items) |d| {
                // insertion into a day-sorted bounded set
                var lo: usize = 0;
                while (lo < n and days[lo] < d.day) lo += 1;
                if (lo < n and days[lo] == d.day) {
                    totals[lo] += d.messages;
                    continue;
                }
                if (n == cap) {
                    // full: drop the OLDEST if this day is newer, else skip
                    if (d.day <= days[0]) continue;
                    var i: usize = 0;
                    while (i + 1 < n) : (i += 1) {
                        days[i] = days[i + 1];
                        totals[i] = totals[i + 1];
                    }
                    n -= 1;
                    if (lo > 0) lo -= 1;
                }
                var j: usize = n;
                while (j > lo) : (j -= 1) {
                    days[j] = days[j - 1];
                    totals[j] = totals[j - 1];
                }
                days[lo] = d.day;
                totals[lo] = d.messages;
                n += 1;
            }
        }
        try w.writeAll(",\"network_days\":[");
        const start = if (n > spark_days) n - spark_days else 0;
        var i = start;
        while (i < n) : (i += 1) {
            if (i != start) try w.writeByte(',');
            var buf: [16]u8 = undefined;
            try w.print("{{\"date\":\"{s}\",\"messages\":{d}}}", .{ fmtDay(days[i], &buf), totals[i] });
        }
        try w.writeAll("]");
    }

    /// Remove channels that no longer exist: delete each dead channel's served
    /// `<slug>.json`, free its aggregate, and drop it from the map. `exists_fn`
    /// absent (no world context) → nothing is pruned. Two-phase (collect keys,
    /// then remove) so the map isn't mutated mid-iteration.
    fn pruneDeadChannels(self: *ChanStats, io: std.Io, dir_path: []const u8, net: NetInfo) void {
        if (net.exists_fn == null) return;
        // Collect dead channel keys. Bounded scratch keeps this alloc-free on the
        // flush path; if more than `max_prune` die in one interval the rest are
        // reaped on the next flush.
        const max_prune = 64;
        var dead: [max_prune][]const u8 = undefined;
        var n: usize = 0;
        var it = self.channels.iterator();
        while (it.next()) |e| {
            if (n >= max_prune) break;
            if (net.existsOf(e.value_ptr.*.name)) continue;
            dead[n] = e.key_ptr.*;
            n += 1;
        }
        for (dead[0..n]) |key| {
            const entry = self.channels.getEntry(key) orelse continue;
            const agg = entry.value_ptr.*;
            // Delete the served per-channel file (best-effort).
            var buf: [128]u8 = undefined;
            if (slugify(agg.name, &buf)) |slug| {
                var name_buf: [160]u8 = undefined;
                if (std.fmt.bufPrint(&name_buf, "{s}.json", .{slug})) |fname| {
                    var path_buf: [1024]u8 = undefined;
                    if (std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir_path, fname })) |path| {
                        std.Io.Dir.cwd().deleteFile(io, path) catch {};
                    } else |_| {}
                } else |_| {}
            }
            const owned_key = entry.key_ptr.*;
            agg.deinit(self.allocator);
            self.allocator.destroy(agg);
            _ = self.channels.remove(key);
            self.allocator.free(owned_key);
        }
    }

    fn writeChannelFile(self: *ChanStats, io: std.Io, dir_path: []const u8, agg: *ChannelAgg, now_ms: i64, present: usize) void {
        var buf: [128]u8 = undefined;
        const slug = slugify(agg.name, &buf) orelse return;
        var name_buf: [160]u8 = undefined;
        const fname = std.fmt.bufPrint(&name_buf, "{s}.json", .{slug}) catch return;

        var aw = std.Io.Writer.Allocating.init(self.allocator);
        defer aw.deinit();
        self.renderChannel(&aw.writer, agg, now_ms, present);
        writeFileAtomicIo(io, dir_path, fname, aw.written());
    }

    /// Render one channel's full statistics JSON into `w`. Separated from the file
    /// write so it can be unit-tested (parse the output back) and reused as the
    /// persistence snapshot.
    fn renderChannel(self: *ChanStats, w: *std.Io.Writer, agg: *ChannelAgg, now_ms: i64, present: usize) void {
        w.writeAll("{\"channel\":") catch return;
        writeJsonString(w, agg.name) catch return;
        w.print(",\"generated_at\":{d},\"first_seen\":{d},\"last_active\":{d},\"present\":{d},", .{
            @divFloor(now_ms, 1000), @divFloor(agg.first_seen, 1000), @divFloor(agg.last_active, 1000), present,
        }) catch return;
        w.writeAll("\"last_speaker\":") catch return;
        writeJsonString(w, agg.last_speaker) catch return;
        w.writeByte(',') catch return;
        w.print("\"totals\":{{\"messages\":{d},\"words\":{d},\"active_users\":{d},\"joins\":{d},\"parts\":{d},\"quits\":{d},\"kicks\":{d},\"topic_changes\":{d},\"actions\":{d},\"peak_members\":{d}}},", .{
            agg.messages, agg.words, agg.users.count(), agg.joins, agg.parts, agg.quits, agg.kicks, agg.topic_changes, agg.actions, agg.peak_members,
        }) catch return;

        // hours[24]
        w.writeAll("\"hours\":[") catch return;
        for (agg.hours, 0..) |h, i| {
            if (i != 0) w.writeByte(',') catch return;
            w.print("{d}", .{h}) catch return;
        }
        w.writeAll("],") catch return;

        // days
        w.writeAll("\"days\":[") catch return;
        for (agg.days.items, 0..) |d, i| {
            if (i != 0) w.writeByte(',') catch return;
            var db: [16]u8 = undefined;
            const ds = fmtDay(d.day, &db);
            w.print("{{\"date\":\"{s}\",\"messages\":{d}}}", .{ ds, d.messages }) catch return;
        }
        w.writeAll("],") catch return;

        // heatmap[7][24]
        w.writeAll("\"heatmap\":[") catch return;
        for (agg.heatmap, 0..) |row, r| {
            if (r != 0) w.writeByte(',') catch return;
            w.writeByte('[') catch return;
            for (row, 0..) |c, ci| {
                if (ci != 0) w.writeByte(',') catch return;
                w.print("{d}", .{c}) catch return;
            }
            w.writeByte(']') catch return;
        }
        w.writeAll("],") catch return;

        // top_users
        self.writeTopUsers(w, agg) catch return;
        // top_words
        self.writeTopWords(w, agg) catch return;

        // topics (newest first)
        w.writeAll("\"topics\":[") catch return;
        {
            var i = agg.topics.items.len;
            var emitted: usize = 0;
            while (i > 0) : (i -= 1) {
                const t = agg.topics.items[i - 1];
                if (emitted != 0) w.writeByte(',') catch return;
                emitted += 1;
                w.print("{{\"ts\":{d},\"setter\":", .{@divFloor(t.ts, 1000)}) catch return;
                writeJsonString(w, t.setter) catch return;
                w.writeAll(",\"topic\":") catch return;
                writeJsonString(w, t.topic) catch return;
                w.writeByte('}') catch return;
            }
        }
        w.writeAll("],") catch return;

        // records (ophion-aligned: busiest day, peak hour, peak concurrent members)
        const bd = busiestDay(agg);
        w.print("\"records\":{{\"busiest_day\":{{\"date\":\"{s}\",\"messages\":{d}}},\"peak_hour\":{d},\"peak_members\":{d}}}", .{
            bd.date, bd.messages, peakHour(agg), agg.peak_members,
        }) catch return;
        w.writeByte('}') catch return;
    }

    fn writeTopUsers(self: *ChanStats, w: anytype, agg: *ChannelAgg) !void {
        // Collect into a scratch slice, partial-sort by messages desc.
        const n = agg.users.count();
        if (n == 0) {
            try w.writeAll("\"top_users\":[],");
            return;
        }
        const list = self.allocator.alloc(*UserAgg, n) catch {
            try w.writeAll("\"top_users\":[],");
            return;
        };
        defer self.allocator.free(list);
        var idx: usize = 0;
        var it = agg.users.valueIterator();
        while (it.next()) |v| : (idx += 1) list[idx] = v.*;
        const k = @min(top_users_emitted, n);
        selectTop(*UserAgg, list, k, struct {
            fn gt(a: *UserAgg, b: *UserAgg) bool {
                return a.messages > b.messages;
            }
        }.gt);
        try w.writeAll("\"top_users\":[");
        for (list[0..k], 0..) |u, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll("{\"nick\":");
            try writeJsonString(w, u.nick);
            try w.print(",\"messages\":{d},\"words\":{d},\"last_active\":{d},\"questions\":{d},\"exclamations\":{d},\"urls\":{d},\"monologue\":{d},\"actions\":{d}}}", .{
                u.messages, u.words, @divFloor(u.last_active, 1000), u.questions, u.exclamations, u.urls, u.monologue, u.actions,
            });
        }
        try w.writeAll("],");
    }

    fn writeTopWords(self: *ChanStats, w: anytype, agg: *ChannelAgg) !void {
        const n = agg.word_freq.count();
        if (n == 0) {
            try w.writeAll("\"top_words\":[],");
            return;
        }
        const WordCount = struct { word: []const u8, count: u64 };
        const list = self.allocator.alloc(WordCount, n) catch {
            try w.writeAll("\"top_words\":[],");
            return;
        };
        defer self.allocator.free(list);
        var idx: usize = 0;
        var it = agg.word_freq.iterator();
        while (it.next()) |e| : (idx += 1) list[idx] = .{ .word = e.key_ptr.*, .count = e.value_ptr.* };
        const k = @min(top_words_emitted, n);
        selectTop(WordCount, list, k, struct {
            fn gt(a: WordCount, b: WordCount) bool {
                return a.count > b.count;
            }
        }.gt);
        try w.writeAll("\"top_words\":[");
        for (list[0..k], 0..) |wc, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll("{\"word\":");
            try writeJsonString(w, wc.word);
            try w.print(",\"count\":{d}}}", .{wc.count});
        }
        try w.writeAll("],");
    }
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn currentTopic(agg: *ChannelAgg) []const u8 {
    if (agg.topics.items.len == 0) return "";
    return agg.topics.items[agg.topics.items.len - 1].topic;
}

fn clampLen(s: []const u8, max: usize) []const u8 {
    return if (s.len > max) s[0..max] else s;
}

/// Lowercase + strip surrounding punctuation; reject too-short/too-long and
/// pure-numeric/URL-ish tokens so the word cloud stays meaningful.
fn normalizeWord(raw: []const u8, buf: []u8) ?[]const u8 {
    var start: usize = 0;
    var end: usize = raw.len;
    while (start < end and !std.ascii.isAlphanumeric(raw[start])) start += 1;
    while (end > start and !std.ascii.isAlphanumeric(raw[end - 1])) end -= 1;
    const w = raw[start..end];
    if (w.len < min_word_len or w.len > max_word_len) return null;
    if (indexOfIgnoreCase(w, "http") == 0) return null;
    var all_digit = true;
    for (w) |c| {
        if (!std.ascii.isDigit(c)) {
            all_digit = false;
            break;
        }
    }
    if (all_digit) return null;
    for (w, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..w.len];
}

/// Filename slug: lowercase, strip leading channel prefix, keep [a-z0-9._-],
/// other bytes → '_'. Never produces '.', '..', or a path separator.
fn slugify(name: []const u8, buf: []u8) ?[]const u8 {
    var src = name;
    if (src.len != 0 and (src[0] == '#' or src[0] == '&' or src[0] == '+' or src[0] == '!')) src = src[1..];
    if (src.len == 0) return null;
    var n: usize = 0;
    for (src) |c| {
        if (n >= buf.len) break;
        const lc = std.ascii.toLower(c);
        buf[n] = if ((lc >= 'a' and lc <= 'z') or (lc >= '0' and lc <= '9') or lc == '.' or lc == '-' or lc == '_') lc else '_';
        n += 1;
    }
    if (n == 0) return null;
    // Avoid a leading dot (hidden file / traversal-ish).
    if (buf[0] == '.') buf[0] = '_';
    return buf[0..n];
}

fn fmtDay(day: i64, buf: []u8) []const u8 {
    const secs = day * 86400;
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(0, secs)) };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1 }) catch "1970-01-01";
}

const DayMsgs = struct { date: []const u8, messages: u64 };

fn busiestDay(agg: *ChannelAgg) struct { date: [10]u8, messages: u64 } {
    var best_day: i64 = 0;
    var best: u64 = 0;
    for (agg.days.items) |d| {
        if (d.messages > best) {
            best = d.messages;
            best_day = d.day;
        }
    }
    var out: [10]u8 = @splat(0);
    var tmp: [16]u8 = undefined;
    const s = fmtDay(best_day, &tmp);
    @memcpy(out[0..@min(s.len, 10)], s[0..@min(s.len, 10)]);
    return .{ .date = out, .messages = best };
}

fn peakHour(agg: *ChannelAgg) usize {
    var best: u64 = 0;
    var hour: usize = 0;
    for (agg.hours, 0..) |h, i| {
        if (h > best) {
            best = h;
            hour = i;
        }
    }
    return hour;
}

/// Partial selection sort: arranges the top-`k` (by `gt`) into list[0..k].
fn selectTop(comptime T: type, list: []T, k: usize, comptime gt: fn (T, T) bool) void {
    const kk = @min(k, list.len);
    var i: usize = 0;
    while (i < kk) : (i += 1) {
        var best = i;
        var j = i + 1;
        while (j < list.len) : (j += 1) {
            if (gt(list[j], list[best])) best = j;
        }
        if (best != i) {
            const t = list[i];
            list[i] = list[best];
            list[best] = t;
        }
    }
}

fn writeJsonString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...31 => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

/// Write `bytes` to `dir/name` via a temp file + rename so nginx never serves a
/// half-written file. Uses the Zig 0.16 `std.Io` file API (mirrors the daemon's
/// own `writeStatsFileAtomic`). Best-effort: errors are swallowed.
/// Atomically replace `dir`/`name` with `bytes`: write a sibling dotfile
/// (`.{name}.tmp`) then `rename` it over the target, so a crash or power loss
/// mid-write leaves the previous file intact rather than a truncated one. Shared
/// with other snapshot writers (e.g. the Event Spine history) that need the same
/// tmp+rename guarantee. Best-effort — any failure is swallowed (persistence is
/// non-authoritative), but a partial write can never clobber a good file.
pub fn writeFileAtomicIo(io: std.Io, dir: []const u8, name: []const u8, bytes: []const u8) void {
    var path_buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name }) catch return;
    var tmp_buf: [1024]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}/.{s}.tmp", .{ dir, name }) catch return;
    const cwd = std.Io.Dir.cwd();
    cwd.writeFile(io, .{ .sub_path = tmp, .data = bytes }) catch return;
    cwd.rename(tmp, cwd, path, io) catch {
        cwd.deleteFile(io, tmp) catch {};
    };
}

// ── persistence (binary snapshot, full fidelity) ─────────────────────────────
//
// The emitted JSON is top-N capped (lossy), so it can't be the persistence
// source. Instead a compact versioned binary snapshot of the WHOLE aggregate is
// written alongside the JSON on every flush and loaded once at boot, so stats
// survive a restart or USR2 hot-upgrade. Dotfile name → distinguishable from the
// served data; harmless if nginx serves it (same public aggregate, binary form).

const snapshot_name = ".chanstats.snapshot";
// Bumped OCS1 → OCS2 to add an explicit format-version byte after the magic.
// Old OCS1 files fail the magic check and load as empty (analytics-only, so a
// one-time reset is harmless). Future in-place layout changes bump
// `snapshot_version`, not the magic — a reader can then distinguish "wrong
// file" (bad magic) from "newer format" (good magic, higher version).
const snapshot_magic = "OCS2";
/// v1: original OCS2 layout. v2: adds channel/user `actions` + channel `peak_members`
/// (ophion m_chanstats parity fields). Readers accept both; writers emit v2.
const snapshot_version: u8 = 2;
const snapshot_version_v1: u8 = 1;

fn putInt(w: *std.Io.Writer, comptime T: type, v: T) std.Io.Writer.Error!void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    try w.writeAll(&b);
}

fn putBytes(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const n: u16 = @intCast(@min(s.len, std.math.maxInt(u16)));
    try putInt(w, u16, n);
    try w.writeAll(s[0..n]);
}

const Cursor = struct {
    b: []const u8,
    i: usize = 0,
    fn int(c: *Cursor, comptime T: type) ?T {
        const n = @sizeOf(T);
        if (c.i + n > c.b.len) return null;
        const v = std.mem.readInt(T, c.b[c.i..][0..n], .little);
        c.i += n;
        return v;
    }
    fn bytes(c: *Cursor) ?[]const u8 {
        const len = c.int(u16) orelse return null;
        if (c.i + len > c.b.len) return null;
        const s = c.b[c.i .. c.i + len];
        c.i += len;
        return s;
    }
};

/// Persist the whole aggregate to `<dir>/.chanstats.snapshot`. Best-effort.
pub fn saveSnapshot(self: *ChanStats, io: std.Io, dir_path: []const u8) void {
    var aw = std.Io.Writer.Allocating.init(self.allocator);
    defer aw.deinit();
    serialize(self, &aw.writer) catch return;
    writeFileAtomicIo(io, dir_path, snapshot_name, aw.written());
}

/// Serialize the whole aggregate (magic + channel count + channels) into `w`.
/// Split from the file write so the round-trip can be unit-tested in memory.
fn serialize(self: *ChanStats, w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll(snapshot_magic);
    try putInt(w, u8, snapshot_version);
    try putInt(w, u32, @intCast(self.channels.count()));
    var it = self.channels.iterator();
    while (it.next()) |e| try snapChannel(w, e.value_ptr.*);
}

fn snapChannel(w: *std.Io.Writer, agg: *ChannelAgg) std.Io.Writer.Error!void {
    try putBytes(w, agg.name);
    try putInt(w, i64, agg.first_seen);
    try putInt(w, i64, agg.last_active);
    inline for (.{ agg.messages, agg.words, agg.joins, agg.parts, agg.quits, agg.kicks, agg.topic_changes, agg.actions, agg.peak_members }) |v| try putInt(w, u64, v);
    for (agg.hours) |h| try putInt(w, u64, h);
    for (agg.heatmap) |row| for (row) |cell| try putInt(w, u64, cell);
    try putInt(w, u32, @intCast(agg.days.items.len));
    for (agg.days.items) |d| {
        try putInt(w, i64, d.day);
        try putInt(w, u64, d.messages);
    }
    try putInt(w, u32, @intCast(agg.users.count()));
    var uit = agg.users.valueIterator();
    while (uit.next()) |v| {
        const u = v.*;
        try putBytes(w, u.nick);
        inline for (.{ u.messages, u.words, u.questions, u.exclamations, u.urls }) |x| try putInt(w, u64, x);
        try putInt(w, i64, u.last_active);
        try putInt(w, u32, u.monologue);
        try putInt(w, u64, u.actions);
    }
    try putInt(w, u32, @intCast(agg.word_freq.count()));
    var wit = agg.word_freq.iterator();
    while (wit.next()) |e| {
        try putBytes(w, e.key_ptr.*);
        try putInt(w, u64, e.value_ptr.*);
    }
    try putInt(w, u32, @intCast(agg.topics.items.len));
    for (agg.topics.items) |t| {
        try putInt(w, i64, t.ts);
        try putBytes(w, t.setter);
        try putBytes(w, t.topic);
    }
}

/// Reload a snapshot written by `saveSnapshot` (called once at boot). Best-effort:
/// a missing/short/corrupt file leaves the aggregate empty. Partial parse stops
/// cleanly (already-loaded channels are kept).
pub fn loadSnapshot(self: *ChanStats, io: std.Io, dir_path: []const u8) void {
    var path_buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir_path, snapshot_name }) catch return;
    const data = std.Io.Dir.cwd().readFileAlloc(io, path, self.allocator, .limited(256 << 20)) catch return;
    defer self.allocator.free(data);
    _ = deserialize(self, data);
}

/// Restore channels from an in-memory snapshot blob. Returns false on a
/// missing/short/corrupt blob; a partial parse keeps already-restored channels.
fn deserialize(self: *ChanStats, data: []const u8) bool {
    if (data.len < 4 or !std.mem.eql(u8, data[0..4], snapshot_magic)) return false;
    var c = Cursor{ .b = data, .i = 4 };
    const version = c.int(u8) orelse return false;
    if (version != snapshot_version and version != snapshot_version_v1) return false;
    const ccount = c.int(u32) orelse return false;
    var i: u32 = 0;
    while (i < ccount) : (i += 1) {
        if (!loadChannel(self, &c, version)) return false;
    }
    return true;
}

fn loadChannel(self: *ChanStats, c: *Cursor, version: u8) bool {
    const name = c.bytes() orelse return false;
    // A snapshot with the same channel twice would double-append its days/
    // topics/word_freq onto the existing agg (scalars would just overwrite).
    // Reject the duplicate outright.
    if (self.channels.contains(name)) return false;
    const agg = self.channel(name, 0) orelse return false;
    agg.first_seen = c.int(i64) orelse return false;
    agg.last_active = c.int(i64) orelse return false;
    agg.messages = c.int(u64) orelse return false;
    agg.words = c.int(u64) orelse return false;
    agg.joins = c.int(u64) orelse return false;
    agg.parts = c.int(u64) orelse return false;
    agg.quits = c.int(u64) orelse return false;
    agg.kicks = c.int(u64) orelse return false;
    agg.topic_changes = c.int(u64) orelse return false;
    if (version >= snapshot_version) {
        agg.actions = c.int(u64) orelse return false;
        agg.peak_members = c.int(u64) orelse return false;
    }
    for (&agg.hours) |*h| h.* = c.int(u64) orelse return false;
    for (&agg.heatmap) |*row| for (row) |*cell| {
        cell.* = c.int(u64) orelse return false;
    };
    // Counts come straight off disk: read every element (to keep the cursor
    // aligned) but only KEEP up to the same cap the live recorders enforce, so
    // a corrupt-but-parseable snapshot can't load a channel past its limits.
    const days_len = c.int(u32) orelse return false;
    var d: u32 = 0;
    while (d < days_len) : (d += 1) {
        const day = c.int(i64) orelse return false;
        const msgs = c.int(u64) orelse return false;
        if (agg.days.items.len >= max_days_kept) continue;
        agg.days.append(self.allocator, .{ .day = day, .messages = msgs }) catch return false;
    }
    const users_len = c.int(u32) orelse return false;
    var u: u32 = 0;
    while (u < users_len) : (u += 1) {
        const nick = c.bytes() orelse return false;
        const messages = c.int(u64) orelse return false;
        const words = c.int(u64) orelse return false;
        const questions = c.int(u64) orelse return false;
        const exclamations = c.int(u64) orelse return false;
        const urls = c.int(u64) orelse return false;
        const last_active = c.int(i64) orelse return false;
        const monologue = c.int(u32) orelse return false;
        const actions: u64 = if (version >= snapshot_version) (c.int(u64) orelse return false) else 0;
        if (self.userOf(agg, nick)) |usr| {
            usr.messages = messages;
            usr.words = words;
            usr.questions = questions;
            usr.exclamations = exclamations;
            usr.urls = urls;
            usr.last_active = last_active;
            usr.monologue = monologue;
            usr.actions = actions;
        }
    }
    const words_len = c.int(u32) orelse return false;
    var wi: u32 = 0;
    while (wi < words_len) : (wi += 1) {
        const word = c.bytes() orelse return false;
        const cnt = c.int(u64) orelse return false;
        if (agg.word_freq.count() >= max_words_per_channel) continue;
        // getOrPut, not put: a repeated word key in a hostile snapshot would
        // otherwise orphan each duplicate dupe (put doesn't free the passed
        // key on found_existing).
        const gop = agg.word_freq.getOrPut(self.allocator, word) catch return false;
        if (gop.found_existing) {
            gop.value_ptr.* = cnt;
        } else {
            const key = self.allocator.dupe(u8, word) catch {
                _ = agg.word_freq.remove(word);
                return false;
            };
            gop.key_ptr.* = key;
            gop.value_ptr.* = cnt;
        }
    }
    const topics_len = c.int(u32) orelse return false;
    var ti: u32 = 0;
    while (ti < topics_len) : (ti += 1) {
        const ts = c.int(i64) orelse return false;
        const setter = c.bytes() orelse return false;
        const topic = c.bytes() orelse return false;
        if (agg.topics.items.len >= max_topics_kept) continue;
        const s = self.allocator.dupe(u8, setter) catch return false;
        const t = self.allocator.dupe(u8, topic) catch {
            self.allocator.free(s);
            return false;
        };
        agg.topics.append(self.allocator, .{ .ts = ts, .setter = s, .topic = t }) catch {
            self.allocator.free(s);
            self.allocator.free(t);
        };
    }
    return true;
}

// ── tests ────────────────────────────────────────────────────────────────────

test "records messages, words, hour buckets, and per-user behaviour metrics" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000; // fixed wall-clock ms
    s.recordMessage("#root", "kain", "hello world this is a test?", ts);
    s.recordMessage("#root", "kain", "AGAIN!!", ts);
    s.recordMessage("#root", "trev", "look http://example.com cool", ts);

    const agg = s.channels.get("#root").?;
    try std.testing.expectEqual(@as(u64, 3), agg.messages);
    try std.testing.expectEqual(@as(u64, 10), agg.words); // 6 + 1 + 3 tokens
    var total_hours: u64 = 0;
    for (agg.hours) |h| total_hours += h;
    try std.testing.expectEqual(@as(u64, 3), total_hours);

    const k = agg.users.get("kain").?;
    try std.testing.expectEqual(@as(u64, 2), k.messages);
    try std.testing.expectEqual(@as(u64, 1), k.questions); // first line ends with '?'
    try std.testing.expectEqual(@as(u64, 2), k.exclamations); // "AGAIN!!"
    try std.testing.expectEqual(@as(u32, 2), k.monologue); // two consecutive lines
    const t = agg.users.get("trev").?;
    try std.testing.expectEqual(@as(u64, 1), t.urls);
    // The URL token is excluded from the word cloud but real words are kept.
    try std.testing.expect(agg.word_freq.get("hello") != null);
    try std.testing.expect(agg.word_freq.get("http://example.com") == null);
}

test "ophion parity: CTCP ACTION, ignore list, peak members" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    s.setIgnoredNicks(&.{ "Announce", "GitHub" });
    try std.testing.expect(s.isIgnored("announce"));
    try std.testing.expect(!s.isIgnored("kain"));

    const ts: i64 = 1_700_000_100_000;
    s.recordMessage("#ops", "Announce", "bot noise", ts);
    s.recordMessage("#ops", "kain", "\x01ACTION waves\x01", ts);
    s.recordMessage("#ops", "kain", "hello", ts + 1);
    try std.testing.expectEqual(@as(u64, 2), s.channelMessageCount("#ops")); // ignored bot not counted
    const agg = s.channels.get("#ops").?;
    try std.testing.expectEqual(@as(u64, 2), agg.messages);
    try std.testing.expectEqual(@as(u64, 1), agg.actions);
    try std.testing.expectEqual(@as(u64, 1), agg.users.get("kain").?.actions);
    try std.testing.expect(ChanStats.ctcpActionBody("\x01ACTION waves\x01") != null);
    try std.testing.expectEqualStrings("waves", ChanStats.ctcpActionBody("\x01ACTION waves\x01").?);

    s.notePresent("#ops", 12);
    s.notePresent("#ops", 7);
    try std.testing.expectEqual(@as(u64, 12), agg.peak_members);

    // Snapshot round-trip preserves v2 fields.
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    try serialize(&s, &aw.writer);
    var s2 = ChanStats.init(std.testing.allocator);
    defer s2.deinit();
    try std.testing.expect(deserialize(&s2, aw.written()));
    const a2 = s2.channels.get("#ops").?;
    try std.testing.expectEqual(@as(u64, 1), a2.actions);
    try std.testing.expectEqual(@as(u64, 12), a2.peak_members);
    try std.testing.expectEqual(@as(u64, 1), a2.users.get("kain").?.actions);
}

test "records membership events and topic history" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;
    s.recordEvent("#root", .join, ts);
    s.recordEvent("#root", .join, ts);
    s.recordEvent("#root", .part, ts);
    s.recordEvent("#root", .kick, ts);
    s.recordTopic("#root", "kain", "the new topic", ts);

    const agg = s.channels.get("#root").?;
    try std.testing.expectEqual(@as(u64, 2), agg.joins);
    try std.testing.expectEqual(@as(u64, 1), agg.parts);
    try std.testing.expectEqual(@as(u64, 1), agg.kicks);
    try std.testing.expectEqual(@as(u64, 1), agg.topic_changes);
    try std.testing.expectEqual(@as(usize, 1), agg.topics.items.len);
    try std.testing.expectEqualStrings("the new topic", agg.topics.items[0].topic);
}

test "syncTopic repairs a tracked current topic without inventing an event" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;
    s.recordMessage("#root", "kain", "existing activity", ts);
    s.recordTopic("#root", "kain", "#root :stale wire payload", ts);
    s.syncTopic("#root", "kain", "current topic", ts + 1);

    const agg = s.channels.get("#root").?;
    try std.testing.expectEqual(@as(u64, 1), agg.topic_changes);
    try std.testing.expectEqual(@as(usize, 2), agg.topics.items.len);
    try std.testing.expectEqualStrings("current topic", agg.topics.items[1].topic);
    try std.testing.expectEqual(ts, agg.last_active);

    s.syncTopic("#untracked", "kain", "must not create a channel", ts + 2);
    try std.testing.expect(s.channels.get("#untracked") == null);
}

test "writeJson prunes channels that no longer exist (unregistered + empty)" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;
    // Three channels with activity: one live (has members), one registered but
    // empty, one transient probe (empty + unregistered).
    s.recordMessage("#live", "a", "hello", ts);
    s.recordMessage("#registered", "b", "hi", ts);
    s.recordMessage("#probe-123", "c", "test", ts);
    try std.testing.expectEqual(@as(usize, 3), s.channels.count());

    const Ctx = struct {
        fn exists(_: *anyopaque, channel: []const u8) bool {
            // #live has a member; #registered is registered; #probe-* is gone.
            return std.mem.eql(u8, channel, "#live") or std.mem.eql(u8, channel, "#registered");
        }
    };
    var dummy: u8 = 0;
    // A dir that doesn't matter — file writes/deletes are best-effort and the
    // channel we prune has no file yet, so deleteFile just no-ops.
    s.writeJson(std.testing.io, "/tmp", "IRCXNet", "test.node", ts, .{
        .presence_ctx = @ptrCast(&dummy),
        .exists_fn = Ctx.exists,
    });

    // The probe channel is gone; the live + registered ones remain.
    try std.testing.expectEqual(@as(usize, 2), s.channels.count());
    try std.testing.expect(s.channels.get("#live") != null);
    try std.testing.expect(s.channels.get("#registered") != null);
    try std.testing.expect(s.channels.get("#probe-123") == null);
}

test "distinct-channel count is capped against a unique-name burst" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;

    // Flood more unique channel names than the ceiling within one interval.
    var buf: [32]u8 = undefined;
    var i: usize = 0;
    while (i < max_channels + 64) : (i += 1) {
        const name = std.fmt.bufPrint(&buf, "#c{d}", .{i}) catch unreachable;
        s.recordMessage(name, "nick", "hello there", ts);
    }

    // The tracked-channel count never exceeds the hard ceiling, regardless of
    // how many unique names arrived.
    try std.testing.expectEqual(max_channels, s.channels.count());
    // A name that arrived after the cap was reached is simply not tracked
    // (fail closed, no crash).
    const overflow = std.fmt.bufPrint(&buf, "#c{d}", .{max_channels + 63}) catch unreachable;
    try std.testing.expect(s.channels.getEntry(overflow) == null);
}

test "writeJson without an exists_fn prunes nothing (backward compatible)" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    s.recordMessage("#a", "x", "hi", 1_700_000_000_000);
    s.recordMessage("#b", "y", "hi", 1_700_000_000_000);
    s.writeJson(std.testing.io, "/tmp", "IRCXNet", "n", 1_700_000_000_000, .{});
    try std.testing.expectEqual(@as(usize, 2), s.channels.count());
}

test "publicSummary mirrors public index threshold and recent activity" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const now: i64 = 1_700_000_000_000;
    const old = now - (25 * 60 * 60 * 1000);

    s.recordMessage("#live", "alice", "one", now);
    s.recordMessage("#old", "bob", "older", old);
    s.min_messages = 2;
    const hidden = s.publicSummary(now);
    try std.testing.expectEqual(@as(u64, 0), hidden.channels);
    try std.testing.expectEqual(@as(u64, 0), hidden.messages);
    try std.testing.expectEqual(@as(?i64, null), hidden.last_active_ms);
    try std.testing.expectEqual(@as(usize, 0), hidden.heatline_len);

    s.recordMessage("#live", "alice", "two", now);
    s.recordMessage("#old", "bob", "older again", old);
    const summary = s.publicSummary(now);
    try std.testing.expectEqual(@as(u64, 2), summary.channels);
    try std.testing.expectEqual(@as(u64, 4), summary.messages);
    try std.testing.expectEqual(@as(u64, 1), summary.active_channels_24h);
    try std.testing.expectEqual(@as(?i64, now), summary.last_active_ms);
    try std.testing.expectEqual(@as(usize, 2), summary.heatline_len);
    try std.testing.expectEqual(@as(u64, 2), summary.heatline[0]);
    try std.testing.expectEqual(@as(u64, 2), summary.heatline[1]);
}

test "slugify strips the channel prefix and neutralises unsafe / traversal bytes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("root", slugify("#root", &buf).?);
    try std.testing.expectEqualStrings("foo_bar", slugify("#foo/bar", &buf).?);
    // Path separators become '_' and the leading dot is neutralised, so a
    // traversal attempt can never escape the data dir or hit a hidden file.
    try std.testing.expectEqualStrings("_._etc_passwd", slugify("#../etc/passwd", &buf).?);
    try std.testing.expectEqualStrings("_hidden", slugify("&.hidden", &buf).?); // leading dot guarded
    try std.testing.expect(slugify("#", &buf) == null);
}

test "writeJsonString escapes control + quote characters" {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    try writeJsonString(&aw.writer, "a\"b\n\t<\\>");
    try std.testing.expectEqualStrings("\"a\\\"b\\n\\t<\\\\>\"", aw.written());
}

test "renderChannel emits valid JSON matching the dashboard contract" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;
    s.recordMessage("#root", "kain", "onyx mesh build channel", ts);
    s.recordMessage("#root", "trev", "voice and video work", ts);
    s.recordEvent("#root", .join, ts);
    s.recordTopic("#root", "kain", "build channel", ts);

    const agg = s.channels.get("#root").?;
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    s.renderChannel(&aw.writer, agg, ts, 0);

    // Must parse as JSON and carry the shape the SolidJS app expects.
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("#root", root.get("channel").?.string);
    const totals = root.get("totals").?.object;
    try std.testing.expectEqual(@as(i64, 2), totals.get("messages").?.integer);
    try std.testing.expectEqual(@as(i64, 1), totals.get("joins").?.integer);
    try std.testing.expectEqual(@as(usize, 24), root.get("hours").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 7), root.get("heatmap").?.array.items.len);
    try std.testing.expectEqual(@as(usize, 24), root.get("heatmap").?.array.items[0].array.items.len);
    try std.testing.expectEqual(@as(usize, 2), root.get("top_users").?.array.items.len);
    try std.testing.expect(root.get("top_words").?.array.items.len > 0);
    try std.testing.expect(root.get("records").?.object.get("peak_hour") != null);
    try std.testing.expectEqual(@as(usize, 1), root.get("topics").?.array.items.len);
}

test "snapshot serialize/deserialize round-trips the full aggregate" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;
    s.recordMessage("#root", "kain", "onyx mesh build channel?", ts);
    s.recordMessage("#root", "kain", "shipping it!!", ts);
    s.recordMessage("#root", "trev", "voice and video http://example.com", ts);
    s.recordEvent("#root", .join, ts);
    s.recordEvent("#root", .part, ts);
    s.recordTopic("#root", "kain", "build channel", ts);
    s.recordMessage("#ops", "trev", "second channel here", ts);

    // Serialize in memory, then load into a fresh instance.
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    try serialize(&s, &aw.writer);

    var restored = ChanStats.init(std.testing.allocator);
    defer restored.deinit();
    try std.testing.expect(deserialize(&restored, aw.written()));

    try std.testing.expectEqual(s.channels.count(), restored.channels.count());
    const a = restored.channels.get("#root").?;
    const b = s.channels.get("#root").?;
    try std.testing.expectEqual(b.messages, a.messages);
    try std.testing.expectEqual(b.words, a.words);
    try std.testing.expectEqual(b.joins, a.joins);
    try std.testing.expectEqual(b.parts, a.parts);
    try std.testing.expectEqual(b.topic_changes, a.topic_changes);
    try std.testing.expectEqual(b.first_seen, a.first_seen);
    try std.testing.expectEqual(b.last_active, a.last_active);
    try std.testing.expectEqual(b.users.count(), a.users.count());

    const k = a.users.get("kain").?;
    try std.testing.expectEqual(@as(u64, 2), k.messages);
    try std.testing.expectEqual(@as(u64, 1), k.questions);
    try std.testing.expectEqual(@as(u64, 2), k.exclamations);
    const tr = a.users.get("trev").?;
    try std.testing.expectEqual(@as(u64, 1), tr.urls);

    try std.testing.expect(a.word_freq.get("onyx") != null);
    try std.testing.expectEqual(@as(usize, 1), a.topics.items.len);
    try std.testing.expectEqualStrings("build channel", a.topics.items[0].topic);
    try std.testing.expectEqualStrings("kain", a.topics.items[0].setter);
    try std.testing.expect(restored.channels.get("#ops") != null);

    // A truncated/garbage blob must be rejected without corrupting state.
    var empty = ChanStats.init(std.testing.allocator);
    defer empty.deinit();
    try std.testing.expect(!deserialize(&empty, snapshot_magic)); // magic only, no version/count
    try std.testing.expect(!deserialize(&empty, "XXXXXXXX")); // wrong magic
    try std.testing.expect(!deserialize(&empty, "OCS1\x01\x00\x00\x00\x00")); // superseded magic
    // Good magic but an unknown version byte → cleanly rejected (start empty).
    try std.testing.expect(!deserialize(&empty, "OCS2\x03\x00\x00\x00\x00"));
    // Good magic + correct version + zero channels → valid empty snapshot.
    try std.testing.expect(deserialize(&empty, "OCS2\x01\x00\x00\x00\x00"));
    try std.testing.expectEqual(@as(usize, 0), empty.channels.count());
}
