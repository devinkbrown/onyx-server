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
