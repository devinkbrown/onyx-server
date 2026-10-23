// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared history assertions and checkpoint corruption fixture helpers.

const std = @import("std");
const types = @import("types.zig");
const checkpoint = @import("checkpoint_wire.zig");

pub fn rewriteCheckpointChecksum(bytes: []u8) void {
    if (bytes.len < checkpoint.checkpoint_checksum_len) return;
    const prefix_len = bytes.len - checkpoint.checkpoint_checksum_len;
    checkpoint.checkpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checkpoint.checkpoint_checksum_len]);
}

pub fn firstCheckpointEntryOffset(bytes: []const u8) usize {
    const target_len: usize = checkpoint.readU32(bytes[checkpoint.checkpoint_header_len..][0..4]);
    return checkpoint.checkpoint_header_len + checkpoint.checkpoint_target_prefix_len + target_len;
}

pub fn nextCheckpointTargetOffset(bytes: []const u8, target_offset: usize) usize {
    const target_len: usize = checkpoint.readU32(bytes[target_offset..][0..4]);
    const entry_count: usize = checkpoint.readU32(bytes[target_offset + 4 ..][0..4]);
    var pos = target_offset + checkpoint.checkpoint_target_prefix_len + target_len;
    for (0..entry_count) |_| {
        const lengths_offset = pos + 1 + 8 + @sizeOf(types.ContentHash);
        var payload_len: usize = 0;
        for (0..5) |index| {
            payload_len += checkpoint.readU32(bytes[lengths_offset + index * 4 ..][0..4]);
        }
        pos += checkpoint.checkpoint_entry_prefix_len + payload_len;
    }
    return pos;
}

pub fn appendForTest(store: anytype, target: []const u8, msgid: []const u8, timestamp: u64, text: []const u8) !void {
    _ = try store.append(target, .{
        .msgid = msgid,
        .sender = "alice",
        .text = text,
        .timestamp = timestamp,
    });
}

pub fn expectMsg(msg: types.Message, msgid: []const u8, timestamp: u64, text: []const u8) !void {
    try std.testing.expectEqualStrings(msgid, msg.msgid);
    try std.testing.expectEqual(timestamp, msg.timestamp);
    try std.testing.expectEqualStrings(text, msg.text);
    try std.testing.expect(!msg.tombstone);
}

pub fn expectIds(messages: []const types.Message, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, messages.len);
    for (expected, 0..) |msgid, index| {
        try std.testing.expectEqualStrings(msgid, messages[index].msgid);
    }
}
