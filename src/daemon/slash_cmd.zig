// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bot command names, help lines, and bounded argument counts.
//! The table size is a registry bound, not a peer ceiling.

const std = @import("std");

pub const max_cmds: usize = 128;
pub const max_name: usize = 16;
pub const max_help: usize = 80;
pub const max_args: u8 = 8;
pub const max_account: usize = 64;

const Slot = struct {
    used: bool = false,
    account: [max_account]u8 = @splat(0),
    account_len: usize = 0,
    name: [max_name]u8 = @splat(0),
    name_len: usize = 0,
    help: [max_help]u8 = @splat(0),
    help_len: usize = 0,
    argc: u8 = 0,
};

pub const View = struct {
    name: []const u8,
    help: []const u8,
    argc: u8,
};

pub const Table = struct {
    allocator: std.mem.Allocator = undefined,
    slots: []Slot = &.{},

    pub fn init(allocator: std.mem.Allocator) !Table {
        const slots = try allocator.alloc(Slot, max_cmds);
        @memset(slots, .{});
        return .{ .allocator = allocator, .slots = slots };
    }

    pub fn deinit(self: *Table) void {
        if (self.slots.len != 0) self.allocator.free(self.slots);
        self.* = .{};
    }

    pub fn add(self: *Table, account: []const u8, name: []const u8, help: []const u8, argc: u8) !void {
        if (account.len == 0 or account.len > max_account) return error.Rejected;
        if (!validName(name) or help.len == 0 or help.len > max_help or argc > max_args) return error.Rejected;
        if (self.findSlot(account, name)) |slot| {
            write(slot, account, name, help, argc);
            return;
        }
        const slot = self.freeSlot() orelse return error.Full;
        write(slot, account, name, help, argc);
        slot.used = true;
    }

    pub fn find(self: *Table, account: []const u8, name: []const u8) ?View {
        const slot = self.findSlot(account, name) orelse return null;
        return .{
            .name = slot.name[0..slot.name_len],
            .help = slot.help[0..slot.help_len],
            .argc = slot.argc,
        };
    }

    pub fn list(self: *Table, account: []const u8, out: []View) usize {
        var n: usize = 0;
        for (self.slots) |*slot| {
            if (!slot.used or !std.ascii.eqlIgnoreCase(slot.account[0..slot.account_len], account)) continue;
            if (n >= out.len) break;
            out[n] = .{
                .name = slot.name[0..slot.name_len],
                .help = slot.help[0..slot.help_len],
                .argc = slot.argc,
            };
            n += 1;
        }
        return n;
    }

    fn findSlot(self: *Table, account: []const u8, name: []const u8) ?*Slot {
        for (self.slots) |*slot| {
            if (!slot.used) continue;
            if (!std.ascii.eqlIgnoreCase(slot.account[0..slot.account_len], account)) continue;
            if (!std.ascii.eqlIgnoreCase(slot.name[0..slot.name_len], name)) continue;
            return slot;
        }
        return null;
    }

    fn freeSlot(self: *Table) ?*Slot {
        for (self.slots) |*slot| if (!slot.used) return slot;
        return null;
    }
};

fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name) return false;
    for (name) |b| {
        const ok = std.ascii.isAlphanumeric(b) or b == '_';
        if (!ok) return false;
    }
    return true;
}

fn write(slot: *Slot, account: []const u8, name: []const u8, help: []const u8, argc: u8) void {
    @memcpy(slot.account[0..account.len], account);
    slot.account_len = account.len;
    @memcpy(slot.name[0..name.len], name);
    slot.name_len = name.len;
    @memcpy(slot.help[0..help.len], help);
    slot.help_len = help.len;
    slot.argc = argc;
}

test "GAP-P10 a command keeps its help line and argument count" {
    var table = try Table.init(std.testing.allocator);
    defer table.deinit();
    try table.add("helper", "ping", "say hello", 2);
    const found = table.find("helper", "ping").?;
    try std.testing.expectEqualStrings("say hello", found.help);
    try std.testing.expectEqual(@as(u8, 2), found.argc);
    try std.testing.expectError(error.Rejected, table.add("helper", "bad name", "x", 0));
    try std.testing.expect(table.find("other", "ping") == null);
}
