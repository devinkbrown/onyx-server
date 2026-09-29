// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mesh search hits. A node asks another node for history matches and keeps
//! each returned hit on its own: the caller must be able to see that hit's
//! target, and a ciphertext body is never a result. The merged list has a
//! hard cap. Transcript search stays off until call transcripts are durable.

const std = @import("std");
const lotus = @import("../proto/lotus.zig");
const e2ee_policy = @import("../proto/e2ee_policy.zig");

pub const Borrowed = struct {
    target: []const u8,
    message: lotus.Message,
};

pub fn isCiphertext(text: []const u8, tags: ?[]const u8) bool {
    if (e2ee_policy.encryptedTagPresent(tags)) return true;
    return std.mem.startsWith(u8, text, e2ee_policy.room_envelope_prefix);
}

/// One hit. `can_see_target` is that hit's own target, not the rest of the
/// response. Ciphertext and empty bodies are dropped.
pub fn keep(can_see_target: bool, text: []const u8, tags: ?[]const u8) bool {
    if (!can_see_target) return false;
    if (text.len == 0) return false;
    return !isCiphertext(text, tags);
}

fn contains(messages: []const lotus.Message, msgid: []const u8) bool {
    for (messages) |message| {
        if (std.mem.eql(u8, message.msgid, msgid)) return true;
    }
    return false;
}

fn newer(a: lotus.Message, b: lotus.Message) bool {
    return a.timestamp > b.timestamp;
}

/// Newest-first merge. The same msgid is kept once. `cap` is the hard result
/// ceiling for the whole search, local and remote together.
pub fn mergeNewest(
    local: []const lotus.Message,
    remote: []const Borrowed,
    cap: usize,
    out: []lotus.Message,
) usize {
    var scratch: [128]lotus.Message = undefined;
    var n: usize = 0;
    for (local) |message| {
        if (n >= scratch.len) break;
        if (contains(scratch[0..n], message.msgid)) continue;
        scratch[n] = message;
        n += 1;
    }
    for (remote) |hit| {
        if (n >= scratch.len) break;
        if (contains(scratch[0..n], hit.message.msgid)) continue;
        scratch[n] = hit.message;
        n += 1;
    }
    var i: usize = 1;
    while (i < n) : (i += 1) {
        const item = scratch[i];
        var j = i;
        while (j > 0 and newer(item, scratch[j - 1])) : (j -= 1) {
            scratch[j] = scratch[j - 1];
        }
        scratch[j] = item;
    }
    const take = @min(cap, @min(n, out.len));
    var k: usize = 0;
    while (k < take) : (k += 1) out[k] = scratch[k];
    return take;
}

/// Wire bounds for SEARCH_QUERY / SEARCH_REPLY. These match the SEARCH command
/// ceilings (8 words, 50 hits) without a peer-count lock.
pub const max_query_words: usize = 8;
pub const max_target_len: usize = 256;
pub const max_word_len: usize = 64;
pub const max_msgid_len: usize = 128;
pub const max_sender_len: usize = 320;
pub const max_text_len: usize = 4096;
pub const max_tags_len: usize = 512;

pub const QueryView = struct {
    id: u32,
    target: []const u8,
    words: [max_query_words][]const u8 = undefined,
    word_count: usize = 0,
};

pub const HitView = struct {
    msgid: []const u8,
    sender: []const u8,
    text: []const u8,
    timestamp: u64,
    tags: ?[]const u8,
};

fn readU16(bytes: []const u8, i: *usize) ?u16 {
    if (i.* > bytes.len or bytes.len - i.* < 2) return null;
    const v = std.mem.readInt(u16, bytes[i.*..][0..2], .little);
    i.* += 2;
    return v;
}

fn readU32(bytes: []const u8, i: *usize) ?u32 {
    if (i.* > bytes.len or bytes.len - i.* < 4) return null;
    const v = std.mem.readInt(u32, bytes[i.*..][0..4], .little);
    i.* += 4;
    return v;
}

fn readU64(bytes: []const u8, i: *usize) ?u64 {
    if (i.* > bytes.len or bytes.len - i.* < 8) return null;
    const v = std.mem.readInt(u64, bytes[i.*..][0..8], .little);
    i.* += 8;
    return v;
}

fn readSlice(bytes: []const u8, i: *usize, n: usize) ?[]const u8 {
    if (i.* > bytes.len or n > bytes.len - i.*) return null;
    const s = bytes[i.*..][0..n];
    i.* += n;
    return s;
}

fn writeU16(buf: []u8, i: *usize, v: u16) void {
    std.mem.writeInt(u16, buf[i.*..][0..2], v, .little);
    i.* += 2;
}

fn writePrefixed(buf: []u8, i: *usize, bytes: []const u8) void {
    writeU16(buf, i, @intCast(bytes.len));
    @memcpy(buf[i.*..][0..bytes.len], bytes);
    i.* += bytes.len;
}

fn hitFits(hit: Borrowed) bool {
    const message = hit.message;
    if (message.msgid.len > max_msgid_len or message.sender.len > max_sender_len) return false;
    if (message.text.len > max_text_len) return false;
    if (message.client_tags) |tags| {
        if (tags.len > max_tags_len) return false;
    }
    return true;
}

fn hitWireLen(hit: Borrowed) usize {
    var n: usize = 2 + hit.message.msgid.len + 2 + hit.message.sender.len + 2 + hit.message.text.len + 8 + 1;
    if (hit.message.client_tags) |tags| n += 2 + tags.len;
    return n;
}

/// `SEARCH_QUERY` body: request id, target, and the AND-words. Slices in the
/// returned view alias `payload`.
pub fn decodeQuery(payload: []const u8) ?QueryView {
    var i: usize = 0;
    const id = readU32(payload, &i) orelse return null;
    const target_len = readU16(payload, &i) orelse return null;
    if (target_len == 0 or target_len > max_target_len) return null;
    const target = readSlice(payload, &i, target_len) orelse return null;
    if (i >= payload.len) return null;
    const word_count = payload[i];
    i += 1;
    if (word_count == 0 or word_count > max_query_words) return null;
    var view = QueryView{ .id = id, .target = target, .word_count = word_count };
    var w: usize = 0;
    while (w < word_count) : (w += 1) {
        const word_len = readU16(payload, &i) orelse return null;
        if (word_len == 0 or word_len > max_word_len) return null;
        view.words[w] = readSlice(payload, &i, word_len) orelse return null;
    }
    if (i != payload.len) return null;
    return view;
}

pub fn encodeQuery(id: u32, target: []const u8, words: []const []const u8, out: []u8) ?[]const u8 {
    if (target.len == 0 or target.len > max_target_len) return null;
    if (words.len == 0 or words.len > max_query_words) return null;
    var size: usize = 4 + 2 + target.len + 1;
    for (words) |word| {
        if (word.len == 0 or word.len > max_word_len) return null;
        size += 2 + word.len;
    }
    if (size > out.len) return null;
    var i: usize = 0;
    std.mem.writeInt(u32, out[i..][0..4], id, .little);
    i += 4;
    writePrefixed(out, &i, target);
    out[i] = @intCast(words.len);
    i += 1;
    for (words) |word| writePrefixed(out, &i, word);
    return out[0..i];
}

/// `SEARCH_REPLY` body. Hit text is copied so the caller can free `hits`.
/// `max_hits` is the SEARCH hard cap. Oversize fields are skipped, not truncated.
pub fn encodeReply(allocator: std.mem.Allocator, id: u32, hits: []const Borrowed, max_hits: usize) ![]u8 {
    var size: usize = 4 + 2;
    var kept: usize = 0;
    for (hits) |hit| {
        if (kept >= max_hits) break;
        if (!hitFits(hit)) continue;
        size = std.math.add(usize, size, hitWireLen(hit)) catch return error.Overflow;
        kept += 1;
    }
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    var i: usize = 0;
    std.mem.writeInt(u32, buf[i..][0..4], id, .little);
    i += 4;
    writeU16(buf, &i, @intCast(kept));
    var n: usize = 0;
    for (hits) |hit| {
        if (n >= kept) break;
        if (!hitFits(hit)) continue;
        writePrefixed(buf, &i, hit.message.msgid);
        writePrefixed(buf, &i, hit.message.sender);
        writePrefixed(buf, &i, hit.message.text);
        std.mem.writeInt(u64, buf[i..][0..8], hit.message.timestamp, .little);
        i += 8;
        if (hit.message.client_tags) |tags| {
            buf[i] = 1;
            i += 1;
            writePrefixed(buf, &i, tags);
        } else {
            buf[i] = 0;
            i += 1;
        }
        n += 1;
    }
    std.debug.assert(i == buf.len);
    return buf;
}

pub const ReplyView = struct {
    id: u32,
    count: usize,
};

/// Decode a reply into `out`. A short or oversize body is rejected whole so a
/// peer cannot append a second target. `count` is the number of filled slots.
pub fn decodeReply(payload: []const u8, out: []HitView) ?ReplyView {
    var i: usize = 0;
    const id = readU32(payload, &i) orelse return null;
    const count = readU16(payload, &i) orelse return null;
    if (count > out.len) return null;
    var n: usize = 0;
    while (n < count) : (n += 1) {
        const msgid_len = readU16(payload, &i) orelse return null;
        if (msgid_len == 0 or msgid_len > max_msgid_len) return null;
        const msgid = readSlice(payload, &i, msgid_len) orelse return null;
        const sender_len = readU16(payload, &i) orelse return null;
        if (sender_len == 0 or sender_len > max_sender_len) return null;
        const sender = readSlice(payload, &i, sender_len) orelse return null;
        const text_len = readU16(payload, &i) orelse return null;
        if (text_len == 0 or text_len > max_text_len) return null;
        const text = readSlice(payload, &i, text_len) orelse return null;
        const timestamp = readU64(payload, &i) orelse return null;
        if (i >= payload.len) return null;
        const tag_flag = payload[i];
        i += 1;
        const tags: ?[]const u8 = switch (tag_flag) {
            0 => null,
            1 => blk: {
                const tags_len = readU16(payload, &i) orelse return null;
                if (tags_len > max_tags_len) return null;
                break :blk readSlice(payload, &i, tags_len) orelse return null;
            },
            else => return null,
        };
        out[n] = .{
            .msgid = msgid,
            .sender = sender,
            .text = text,
            .timestamp = timestamp,
            .tags = tags,
        };
    }
    if (i != payload.len) return null;
    return .{ .id = id, .count = @as(usize, count) };
}

fn sample(id: []const u8, text: []const u8, ts: u64) lotus.Message {
    return .{
        .msgid = id,
        .sender = "alice!alice@test",
        .text = text,
        .timestamp = ts,
        .tombstone = false,
    };
}

test "GAP-P5 merge keeps each authorized hit once under the cap" {
    try std.testing.expect(!keep(false, "visible", null));
    try std.testing.expect(!keep(true, "ONYXROOM1 secret", null));
    try std.testing.expect(!keep(true, "plain", "+onyx/e2ee=mls"));
    try std.testing.expect(keep(true, "plain", null));

    const local = [_]lotus.Message{
        sample("same", "local", 10),
        sample("old", "old", 1),
    };
    const remote = [_]Borrowed{
        .{ .target = "#room", .message = sample("same", "remote-copy", 10) },
        .{ .target = "#room", .message = sample("new", "remote", 50) },
    };
    var out: [8]lotus.Message = undefined;
    const n = mergeNewest(&local, &remote, 2, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqualStrings("new", out[0].msgid);
    try std.testing.expectEqualStrings("same", out[1].msgid);

    var many: [60]lotus.Message = undefined;
    var i: usize = 0;
    while (i < many.len) : (i += 1) {
        many[i] = sample("id", "body", i);
    }
    // Distinct msgids, or the dedup collapses them.
    var ids: [60][8]u8 = undefined;
    i = 0;
    while (i < many.len) : (i += 1) {
        ids[i][0] = 'm';
        ids[i][1] = '0' + @as(u8, @intCast(i / 10));
        ids[i][2] = '0' + @as(u8, @intCast(i % 10));
        ids[i][3] = 0;
        many[i].msgid = ids[i][0..3];
        many[i].timestamp = i;
    }
    var capped: [50]lotus.Message = undefined;
    const kept = mergeNewest(&many, &.{}, 50, &capped);
    try std.testing.expectEqual(@as(usize, 50), kept);
    try std.testing.expectEqual(@as(u64, 59), capped[0].timestamp);
    try std.testing.expectEqual(@as(u64, 10), capped[49].timestamp);
}

test "GAP-P5 mesh search query round trip rejects a short reply" {
    var qbuf: [256]u8 = undefined;
    const words = [_][]const u8{ "meshonlyphrase", "second" };
    const wire = encodeQuery(7, "#room", &words, &qbuf) orelse return error.TestUnexpectedResult;
    const query = decodeQuery(wire) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 7), query.id);
    try std.testing.expectEqualStrings("#room", query.target);
    try std.testing.expectEqual(@as(usize, 2), query.word_count);
    try std.testing.expectEqualStrings("second", query.words[1]);
    try std.testing.expect(decodeQuery(wire[0 .. wire.len - 1]) == null);

    const hits = [_]Borrowed{
        .{ .target = "#room", .message = sample("m1", "plain hit", 9) },
        .{ .target = "#room", .message = sample("m2", "ONYXROOM1 secret", 8) },
    };
    const reply = try encodeReply(std.testing.allocator, 7, &hits, 50);
    defer std.testing.allocator.free(reply);
    var got: [50]HitView = undefined;
    const view = decodeReply(reply, &got) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 7), view.id);
    try std.testing.expectEqual(@as(usize, 2), view.count);
    try std.testing.expectEqualStrings("plain hit", got[0].text);
    try std.testing.expectEqualStrings("ONYXROOM1 secret", got[1].text);
    try std.testing.expect(decodeReply(reply[0 .. reply.len - 1], &got) == null);
    try std.testing.expect(encodeQuery(1, "#room", &words, qbuf[0..4]) == null);
}
