// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! First messages held for an oper to release or drop.
//! The slot count is a review queue bound, not a peer ceiling.

const std = @import("std");

pub const max_body: usize = 400;
pub const max_per_member: u16 = 8;
pub const max_slots: usize = 256;
pub const max_members: usize = 1024;

const Slot = struct {
    used: bool = false,
    channel: [64]u8 = @splat(0),
    channel_len: usize = 0,
    nick: [32]u8 = @splat(0),
    nick_len: usize = 0,
    body: [max_body]u8 = @splat(0),
    body_len: usize = 0,
};

const Counter = struct {
    used: bool = false,
    channel: [64]u8 = @splat(0),
    channel_len: usize = 0,
    nick: [32]u8 = @splat(0),
    nick_len: usize = 0,
    seen: u16 = 0,
};

pub const Table = struct {
    allocator: std.mem.Allocator = undefined,
    slots: []Slot = &.{},
    members: []Counter = &.{},

    pub fn init(allocator: std.mem.Allocator) !Table {
        const slots = try allocator.alloc(Slot, max_slots);
        errdefer allocator.free(slots);
        const members = try allocator.alloc(Counter, max_members);
        @memset(slots, .{});
        @memset(members, .{});
        return .{ .allocator = allocator, .slots = slots, .members = members };
    }

    pub fn deinit(self: *Table) void {
        if (self.slots.len != 0) self.allocator.free(self.slots);
        if (self.members.len != 0) self.allocator.free(self.members);
        self.* = .{};
    }

    pub fn seen(self: *const Table, channel: []const u8, nick: []const u8) u16 {
        const row = self.findMember(channel, nick) orelse return 0;
        return row.seen;
    }

    pub fn hold(self: *Table, channel: []const u8, nick: []const u8, body: []const u8, limit: u16) !void {
        if (limit == 0 or channel.len == 0 or channel.len > 64 or nick.len == 0 or nick.len > 32 or body.len == 0) return error.Rejected;
        if (self.seen(channel, nick) >= limit) return error.Past;
        const slot = self.freeSlot() orelse return error.Full;
        try self.bump(channel, nick);
        const n = @min(body.len, max_body);
        @memcpy(slot.channel[0..channel.len], channel);
        slot.channel_len = channel.len;
        @memcpy(slot.nick[0..nick.len], nick);
        slot.nick_len = nick.len;
        @memcpy(slot.body[0..n], body[0..n]);
        slot.body_len = n;
        slot.used = true;
    }

    pub fn copyOut(self: *Table, channel: []const u8, nick: []const u8, out: [][max_body]u8, lens: []usize) usize {
        var n: usize = 0;
        for (self.slots) |*slot| {
            if (!slot.used or !same(slot.channel[0..slot.channel_len], channel) or !same(slot.nick[0..slot.nick_len], nick)) continue;
            if (n >= out.len or n >= lens.len) break;
            @memcpy(out[n][0..slot.body_len], slot.body[0..slot.body_len]);
            lens[n] = slot.body_len;
            slot.used = false;
            n += 1;
        }
        return n;
    }

    pub fn drop(self: *Table, channel: []const u8, nick: []const u8) usize {
        var n: usize = 0;
        for (self.slots) |*slot| {
            if (!slot.used or !same(slot.channel[0..slot.channel_len], channel) or !same(slot.nick[0..slot.nick_len], nick)) continue;
            slot.used = false;
            n += 1;
        }
        return n;
    }

    fn freeSlot(self: *Table) ?*Slot {
        for (self.slots) |*slot| if (!slot.used) return slot;
        return null;
    }

    fn findMember(self: *const Table, channel: []const u8, nick: []const u8) ?*const Counter {
        for (self.members) |*row| {
            if (row.used and same(row.channel[0..row.channel_len], channel) and same(row.nick[0..row.nick_len], nick)) return row;
        }
        return null;
    }

    fn bump(self: *Table, channel: []const u8, nick: []const u8) !void {
        for (self.members) |*row| {
            if (row.used and same(row.channel[0..row.channel_len], channel) and same(row.nick[0..row.nick_len], nick)) {
                row.seen += 1;
                return;
            }
        }
        for (self.members) |*row| {
            if (row.used) continue;
            @memcpy(row.channel[0..channel.len], channel);
            row.channel_len = channel.len;
            @memcpy(row.nick[0..nick.len], nick);
            row.nick_len = nick.len;
            row.seen = 1;
            row.used = true;
            return;
        }
        return error.Full;
    }
};

fn same(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

test "GAP-P9 one held body is copied out or dropped" {
    var table = try Table.init(std.testing.allocator);
    defer table.deinit();
    try table.hold("#room", "alice", "hello held", 1);
    try std.testing.expectEqual(@as(u16, 1), table.seen("#room", "alice"));
    try std.testing.expectError(error.Past, table.hold("#room", "alice", "again", 1));
    var bodies: [4][max_body]u8 = undefined;
    var lens: [4]usize = undefined;
    try std.testing.expectEqual(@as(usize, 1), table.copyOut("#room", "alice", &bodies, &lens));
    try std.testing.expectEqualStrings("hello held", bodies[0][0..lens[0]]);
    try table.hold("#room", "eve", "secret drop", 1);
    try std.testing.expectEqual(@as(usize, 1), table.drop("#room", "eve"));
    try std.testing.expectEqual(@as(usize, 0), table.copyOut("#room", "eve", &bodies, &lens));
}
