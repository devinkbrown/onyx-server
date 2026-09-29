// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SEARCH command family. The messaging module thunk calls this through
//! `LinuxServer.handleSearch`. The live server stays the caller; this file
//! owns the draft/search parse, cap, and replay.

const std = @import("std");
const lotus = @import("../proto/lotus.zig");
const world_model = @import("world.zig");
const mesh_search = @import("mesh_search.zig");

/// draft/search anti-abuse: the minimum gap (monotonic ms) between two SEARCH
/// commands from one client. A 5s/client floor.
pub const rate_limit_ms: i64 = 5_000;
/// draft/search result cap: at most this many messages per query, newest
/// first. A fixed per-query result ceiling.
pub const max_results: usize = 50;
/// draft/search query bound: at most this many distinct words are intersected
/// (AND). Excess words are ignored, keeping the per-query cost bounded.
pub const max_query_words: usize = 8;

/// Look up a single history message in `store_target` by its exact msgid,
/// newest-first. Returns null when no live (non-tombstoned) entry matches.
fn historyMessageExact(self: anytype, store_target: []const u8, msgid: []const u8) ?lotus.Message {
    var buf: [256]lotus.Message = undefined;
    const found = self.history.latest(store_target, buf.len, &buf) catch return null;
    for (found) |message| {
        if (std.mem.eql(u8, message.msgid, msgid)) return message;
    }
    return null;
}

/// AND semantics: whether `msgid` is in the index hit list for every word in
/// `rest`. Empty `rest` (single-word query) is vacuously true.
fn msgidMatchesAll(self: anytype, msgid: []const u8, rest: []const []const u8) bool {
    for (rest) |word| {
        const hits = self.search_index.find(word);
        var present = false;
        for (hits) |hit| {
            if (std.mem.eql(u8, hit, msgid)) {
                present = true;
                break;
            }
        }
        if (!present) return false;
    }
    return true;
}

/// `SEARCH <target> [<query...>]` — IRCv3 draft/search full-text message
/// search over the CHATHISTORY store. `world_id` is the caller's world-model
/// id, already projected by the server wrapper.
pub fn handle(self: anytype, world_id: anytype, conn: anytype, line: []const u8) !void {
    const Server = @TypeOf(self.*);
    if (!conn.session.hasCap(.search)) {
        try self.failReply(conn, "SEARCH", "NEED_REGISTRATION", "You must negotiate the draft/search capability");
        return;
    }

    // Parse: drop the leading `SEARCH` verb, take the first whitespace token as
    // the target, and treat the remainder (a `:`-trailing is unwrapped) as the
    // raw query text. Tokenization mirrors the index's word splitter.
    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
    var rest = std.mem.trimStart(u8, trimmed, " ");
    if (std.ascii.startsWithIgnoreCase(rest, "SEARCH")) rest = rest["SEARCH".len..];
    rest = std.mem.trimStart(u8, rest, " ");

    const target_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    const target = rest[0..target_end];
    var query = std.mem.trimStart(u8, rest[target_end..], " ");
    if (query.len != 0 and query[0] == ':') query = query[1..];

    if (target.len == 0 or query.len == 0) {
        try self.failReply(conn, "SEARCH", "INVALID_PARAMS", "Usage: SEARCH <target> :<query>");
        return;
    }

    // Rate limit (anti-abuse): reject a too-fast second SEARCH.
    const now = self.nowMs();
    if (conn.last_search_ms != 0 and now - conn.last_search_ms < rate_limit_ms) {
        try self.failReply(conn, "SEARCH", "RATE_LIMITED", "Please wait before searching again");
        return;
    }

    // Visibility: a channel target requires membership (no leaking non-member
    // channel history); a non-channel target resolves to the requester's DM
    // history with that peer via the shared history key.
    if (world_model.isChannelName(target)) {
        if (!self.world.isMember(target, world_id)) {
            try self.failReply(conn, "SEARCH", "INVALID_TARGET", "You must be a member of the channel");
            return;
        }
    }
    conn.last_search_ms = now;

    var key_buf: [320]u8 = undefined;
    const store_target = self.historyKeyForTarget(conn, target, &key_buf);

    // Tokenize the query (bounded) and AND-intersect the index hit sets. The
    // first word seeds the candidate msgid list; each later word filters it.
    var words: [max_query_words][]const u8 = undefined;
    var word_count: usize = 0;
    {
        var it = std.mem.tokenizeAny(u8, query, " \t");
        while (it.next()) |w| {
            if (word_count >= max_query_words) break;
            words[word_count] = w;
            word_count += 1;
        }
    }
    if (word_count == 0) {
        try self.failReply(conn, "SEARCH", "INVALID_PARAMS", "Query must contain at least one word");
        return;
    }

    // Candidate msgids = hits for the first word, scoped to this target and
    // requiring every other query word to also hit that msgid (AND). Bounded
    // by `max_results`, newest-first (the history ring is oldest-first,
    // so we walk it in reverse).
    var found_buf: [max_results]lotus.Message = undefined;
    var found_len: usize = 0;
    const seed_hits = self.search_index.find(words[0]);
    // Iterate seed hits newest-first: the index appends in record order, so
    // later indices are newer messages.
    var hit_i: usize = seed_hits.len;
    while (hit_i > 0 and found_len < max_results) {
        hit_i -= 1;
        const msgid = seed_hits[hit_i];
        if (!msgidMatchesAll(self, msgid, words[1..word_count])) continue;
        const message = historyMessageExact(self, store_target, msgid) orelse continue;
        if (!Server.historyMessageVisibleTo(&conn.session, message)) continue;
        if (mesh_search.isCiphertext(message.text, message.client_tags)) continue;
        found_buf[found_len] = message;
        found_len += 1;
    }

    var remote_buf: [max_results]mesh_search.Borrowed = undefined;
    const remote_n = gatherRemote(self, world_id, target, words[0..word_count], &remote_buf);
    var merged: [max_results]lotus.Message = undefined;
    const merged_len = if (remote_n == 0)
        found_len
    else
        mesh_search.mergeNewest(found_buf[0..found_len], remote_buf[0..remote_n], max_results, &merged);
    const newest = if (remote_n == 0) found_buf[0..found_len] else merged[0..merged_len];

    // A live link answers later. Hold an empty local merge until that reply
    // instead of telling the client there were no hits.
    if (self.dispatchMeshSearchQuery(conn, target, words[0..word_count], newest) and newest.len == 0) return;

    // Reverse into chronological (oldest-first) order for replay, matching
    // CHATHISTORY's BATCH ordering. No remote hits leaves the local order alone.
    var ordered: [max_results]lotus.Message = undefined;
    var k: usize = 0;
    while (k < newest.len) : (k += 1) {
        ordered[k] = newest[newest.len - 1 - k];
    }

    const replay = self.renderHistoryReplayOwned(conn, "search", target, ordered[0..newest.len], null) catch {
        try self.failReply(conn, "SEARCH", "RESULTS_TOO_LARGE", "Too many results; narrow the query");
        return;
    };
    defer self.allocator.free(replay);
    Server.appendHistoryReplay(conn, replay) catch {
        self.poisonOwnedDelivery(conn);
        return;
    };
}

/// Hits this node can offer another node for `target`. Ciphertext stays in
/// the result so the asking node can drop it itself; a peer that already
/// filtered is fine, and a peer that did not cannot force the body through.
pub fn serve(self: anytype, target: []const u8, words: []const []const u8, out: []mesh_search.Borrowed) usize {
    if (words.len == 0 or target.len == 0 or !world_model.isChannelName(target)) return 0;
    var n: usize = 0;
    const seed_hits = self.search_index.find(words[0]);
    var hit_i: usize = seed_hits.len;
    while (hit_i > 0 and n < out.len) {
        hit_i -= 1;
        const msgid = seed_hits[hit_i];
        if (!msgidMatchesAll(self, msgid, words[1..])) continue;
        const message = historyMessageExact(self, target, msgid) orelse continue;
        if (message.tombstone) continue;
        out[n] = .{ .target = target, .message = message };
        n += 1;
    }
    return n;
}

fn gatherRemote(
    self: anytype,
    world_id: anytype,
    query_target: []const u8,
    words: []const []const u8,
    out: []mesh_search.Borrowed,
) usize {
    if (!world_model.isChannelName(query_target)) return 0;
    var n: usize = 0;
    for (self.mesh_search_peers.items) |peer| {
        if (peer == self) continue;
        var got_buf: [max_results]mesh_search.Borrowed = undefined;
        const got = serve(peer, query_target, words, &got_buf);
        for (got_buf[0..got]) |hit| {
            if (n >= out.len) return n;
            const can_see = world_model.isChannelName(hit.target) and self.world.isMember(hit.target, world_id);
            if (!mesh_search.keep(can_see, hit.message.text, hit.message.client_tags)) continue;
            out[n] = hit;
            n += 1;
        }
    }
    return n;
}
