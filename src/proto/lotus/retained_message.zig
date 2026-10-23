// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned retained-message lifecycle and canonical history-root hashing.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const types = @import("types.zig");

pub const StoredMessage = struct {
    hash: types.ContentHash,
    msgid: []u8,
    sender: []u8,
    text: []u8,
    timestamp: u64,
    tombstone: bool,
    command: []u8,
    client_tags: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator, msg: types.InputMessage) std.mem.Allocator.Error!StoredMessage {
        var stored = StoredMessage{
            .hash = hashText(msg.text),
            .msgid = &.{},
            .sender = &.{},
            .text = &.{},
            .timestamp = msg.timestamp,
            .tombstone = false,
            .command = &.{},
            .client_tags = null,
        };
        errdefer stored.deinit(allocator);

        stored.msgid = try allocator.dupe(u8, msg.msgid);
        stored.sender = try allocator.dupe(u8, msg.sender);
        stored.text = try allocator.dupe(u8, msg.text);
        stored.command = try allocator.dupe(u8, msg.command);
        if (msg.client_tags) |tags| stored.client_tags = try allocator.dupe(u8, tags);
        return stored;
    }

    pub fn deinit(self: *StoredMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.msgid);
        allocator.free(self.sender);
        allocator.free(self.text);
        allocator.free(self.command);
        if (self.client_tags) |tags| allocator.free(tags);
        self.* = .{
            .hash = @splat(0),
            .msgid = &.{},
            .sender = &.{},
            .text = &.{},
            .timestamp = 0,
            .tombstone = false,
            .command = &.{},
            .client_tags = null,
        };
    }

    pub fn view(self: *const StoredMessage) types.Message {
        return .{
            .hash = self.hash,
            .msgid = self.msgid,
            .sender = self.sender,
            .text = self.text,
            .timestamp = self.timestamp,
            .tombstone = self.tombstone,
            .command = self.command,
            .client_tags = self.client_tags,
        };
    }
};

pub fn hashText(text: []const u8) types.ContentHash {
    var out: types.ContentHash = undefined;
    Blake3.hash(text, &out, .{});
    return out;
}

pub fn updateLen(hasher: *Blake3, len: usize) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, @intCast(len), .little);
    hasher.update(&buf);
}

fn updateU64(hasher: *Blake3, value: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    hasher.update(&buf);
}

pub fn updateBytes(hasher: *Blake3, bytes: []const u8) void {
    updateLen(hasher, bytes.len);
    hasher.update(bytes);
}

pub fn updateStoredMessage(hasher: *Blake3, entry: *const StoredMessage) void {
    hasher.update("entry");
    updateBytes(hasher, entry.msgid);
    updateBytes(hasher, entry.sender);
    updateBytes(hasher, entry.command);
    updateBytes(hasher, entry.client_tags orelse "");
    updateU64(hasher, entry.timestamp);
    hasher.update(if (entry.tombstone) "t" else "l");
    hasher.update(&entry.hash);
}
