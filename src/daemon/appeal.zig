// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One structured ban appeal per host per window. The table is heap storage so
//! `LinuxServer.init` does not put it on the caller's stack. Filing an appeal
//! does not send channel traffic.

const std = @import("std");

pub const window_ms: i64 = 3_600_000;
pub const max_appeals: usize = 256;
pub const max_nick: usize = 32;
pub const max_host: usize = 64;
pub const max_text: usize = 400;

pub const Error = error{
    Empty,
    TooLong,
    Window,
    Limit,
    Missing,
    Invalid,
};

const Slot = struct {
    used: bool = false,
    answered: bool = false,
    id: u64 = 0,
    filed_ms: i64 = 0,
    nick_len: u8 = 0,
    host_len: u8 = 0,
    text_len: u16 = 0,
    answer_len: u16 = 0,
    nick: [max_nick]u8 = @splat(0),
    host: [max_host]u8 = @splat(0),
    text: [max_text]u8 = @splat(0),
    answer: [max_text]u8 = @splat(0),

    fn nickSlice(self: *const Slot) []const u8 {
        return self.nick[0..self.nick_len];
    }
    fn hostSlice(self: *const Slot) []const u8 {
        return self.host[0..self.host_len];
    }
    fn textSlice(self: *const Slot) []const u8 {
        return self.text[0..self.text_len];
    }
    fn answerSlice(self: *const Slot) []const u8 {
        return self.answer[0..self.answer_len];
    }
};

const Storage = struct {
    next_id: u64 = 1,
    slots: [max_appeals]Slot = @splat(.{}),
};

pub const View = struct {
    id: u64,
    answered: bool,
    nick: []const u8,
    host: []const u8,
    text: []const u8,
    answer: []const u8,
};

pub const Table = struct {
    allocator: std.mem.Allocator = undefined,
    storage: ?*Storage = null,

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!Table {
        const storage = try allocator.create(Storage);
        storage.* = .{};
        return .{ .allocator = allocator, .storage = storage };
    }

    pub fn deinit(self: *Table) void {
        if (self.storage) |storage| self.allocator.destroy(storage);
        self.storage = null;
    }

    pub fn file(self: *Table, nick: []const u8, host: []const u8, text: []const u8, now_ms: i64) Error!u64 {
        const storage = self.storage orelse return error.Invalid;
        if (text.len == 0 or nick.len == 0 or host.len == 0) return error.Empty;
        if (text.len > max_text or nick.len > max_nick or host.len > max_host) return error.TooLong;
        if (hasControl(text) or hasControl(nick) or hasControl(host)) return error.Invalid;
        if (self.recent(host, now_ms)) return error.Window;
        const slot = self.freeSlot() orelse return error.Limit;
        const id = storage.next_id;
        if (id == 0) return error.Limit;
        storage.next_id += 1;
        slot.* = .{
            .used = true,
            .id = id,
            .filed_ms = now_ms,
            .nick_len = @intCast(nick.len),
            .host_len = @intCast(host.len),
            .text_len = @intCast(text.len),
        };
        @memcpy(slot.nick[0..nick.len], nick);
        @memcpy(slot.host[0..host.len], host);
        @memcpy(slot.text[0..text.len], text);
        return id;
    }

    pub fn answer(self: *Table, id: u64, text: []const u8) Error!void {
        if (text.len == 0) return error.Empty;
        if (text.len > max_text or hasControl(text)) return error.Invalid;
        const slot = self.find(id) orelse return error.Missing;
        @memcpy(slot.answer[0..text.len], text);
        slot.answer_len = @intCast(text.len);
        slot.answered = true;
    }

    pub fn list(self: *const Table, out: []View) usize {
        const storage = self.storage orelse return 0;
        var n: usize = 0;
        for (&storage.slots) |*slot| {
            if (!slot.used or n >= out.len) continue;
            out[n] = .{
                .id = slot.id,
                .answered = slot.answered,
                .nick = slot.nickSlice(),
                .host = slot.hostSlice(),
                .text = slot.textSlice(),
                .answer = slot.answerSlice(),
            };
            n += 1;
        }
        return n;
    }

    pub fn count(self: *const Table) usize {
        const storage = self.storage orelse return 0;
        var n: usize = 0;
        for (storage.slots) |slot| {
            if (slot.used) n += 1;
        }
        return n;
    }

    fn recent(self: *const Table, host: []const u8, now_ms: i64) bool {
        const storage = self.storage orelse return false;
        for (storage.slots) |slot| {
            if (!slot.used) continue;
            if (!std.mem.eql(u8, slot.hostSlice(), host)) continue;
            if (now_ms >= slot.filed_ms and now_ms - slot.filed_ms < window_ms) return true;
        }
        return false;
    }

    fn freeSlot(self: *Table) ?*Slot {
        const storage = self.storage orelse return null;
        for (&storage.slots) |*slot| {
            if (!slot.used) return slot;
        }
        return null;
    }

    fn find(self: *Table, id: u64) ?*Slot {
        const storage = self.storage orelse return null;
        for (&storage.slots) |*slot| {
            if (slot.used and slot.id == id) return slot;
        }
        return null;
    }
};

fn hasControl(text: []const u8) bool {
    for (text) |byte| {
        if (byte < 0x20 or byte == 0x7f) return true;
    }
    return false;
}

test "GAP-P7 one appeal per host per window" {
    var table = try Table.init(std.testing.allocator);
    defer table.deinit();
    const id = try table.file("alice", "banned.example", "please review", 1_000);
    try std.testing.expectError(error.Window, table.file("alice2", "banned.example", "again", 1_000 + 10));
    const other = try table.file("bob", "other.example", "different host", 1_000);
    try std.testing.expect(other != id);
    try table.answer(id, "reviewed");
    var views: [4]View = undefined;
    const n = table.list(&views);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expect(views[0].answered);
    try std.testing.expectEqualStrings("reviewed", views[0].answer);
}
