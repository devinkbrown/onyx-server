// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Registered-channel founder succession policy.
//!
//! This module is deliberately std-only. It models the data a daemon services
//! layer can pass in, parses a real server command surface (`SUCCESSOR ...`),
//! stores configured successor accounts, and returns pure decisions. It does
//! not import daemon/protocol modules and does not model services as clients.

const std = @import("std");

pub const max_channel_len: usize = 128;
pub const max_account_len: usize = 64;
pub const max_successors: usize = 4096;

pub const SuccessionError = error{
    EmptyName,
    ChannelTooLong,
    AccountTooLong,
    InvalidChannel,
    InvalidAccount,
    TooManySuccessors,
} || std.mem.Allocator.Error;

pub const ParseError = error{
    EmptyLine,
    UnknownCommand,
    MissingChannel,
    MissingAction,
    MissingAccount,
    TooManyArguments,
    InvalidChannel,
    InvalidAccount,
    UnknownAction,
};

/// Channel access levels mirror the existing services lattice, without
/// importing it: founder > admin > op > voice.
pub const AccessLevel = enum(u16) {
    voice = 10,
    op = 25,
    admin = 50,
    founder = 100,

    pub fn rank(self: AccessLevel) u16 {
        return @backingInt(self);
    }

    pub fn lessThan(self: AccessLevel, other: AccessLevel) bool {
        return self.rank() < other.rank();
    }

    pub fn parse(raw: []const u8) ?AccessLevel {
        if (std.ascii.eqlIgnoreCase(raw, "VOICE")) return .voice;
        if (std.ascii.eqlIgnoreCase(raw, "OP")) return .op;
        if (std.ascii.eqlIgnoreCase(raw, "ADMIN")) return .admin;
        if (std.ascii.eqlIgnoreCase(raw, "FOUNDER")) return .founder;
        return null;
    }
};

pub const FounderExitReason = enum {
    dropped,
    expired,
};

pub const TransferSource = enum {
    configured_successor,
    highest_access,
};

pub const AccountAccess = struct {
    account: []const u8,
    level: AccessLevel,
    /// False when the account or access entry has already been removed from the
    /// registered-channel state being evaluated.
    remaining: bool = true,
};

pub const SuccessionInput = struct {
    channel: []const u8,
    founder: []const u8,
    reason: FounderExitReason,
    /// Configured successor account, if any. This is intentionally independent
    /// of the access list: an explicitly configured successor does not need to
    /// outrank anyone in the channel access table.
    configured_successor: ?[]const u8 = null,
    configured_successor_remaining: bool = true,
    access: []const AccountAccess = &.{},
};

pub const TransferDecision = struct {
    channel: []const u8,
    old_founder: []const u8,
    new_founder: []const u8,
    source: TransferSource,
    reason: FounderExitReason,
};

pub const DeleteDecision = struct {
    channel: []const u8,
    old_founder: []const u8,
    reason: FounderExitReason,
};

pub const SuccessionDecision = union(enum) {
    transfer: TransferDecision,
    mark_for_deletion: DeleteDecision,
};

/// Decide registered-channel ownership after the current founder disappears.
/// The configured successor wins when it still names a remaining, non-founder
/// account. Otherwise the highest access entry wins; ties keep input order so
/// callers can impose their own stable ordering. With no eligible account, the
/// channel is marked for deletion.
pub fn decideFounderSuccession(input: SuccessionInput) SuccessionDecision {
    if (input.configured_successor) |successor| {
        if (input.configured_successor_remaining and !sameAccount(successor, input.founder)) {
            return .{ .transfer = .{
                .channel = input.channel,
                .old_founder = input.founder,
                .new_founder = successor,
                .source = .configured_successor,
                .reason = input.reason,
            } };
        }
    }

    var best: ?AccountAccess = null;
    for (input.access) |entry| {
        if (!entry.remaining) continue;
        if (sameAccount(entry.account, input.founder)) continue;

        if (best == null or best.?.level.lessThan(entry.level)) {
            best = entry;
        }
    }

    if (best) |entry| {
        return .{ .transfer = .{
            .channel = input.channel,
            .old_founder = input.founder,
            .new_founder = entry.account,
            .source = .highest_access,
            .reason = input.reason,
        } };
    }

    return .{ .mark_for_deletion = .{
        .channel = input.channel,
        .old_founder = input.founder,
        .reason = input.reason,
    } };
}

pub const SuccessorCommand = union(enum) {
    set: struct { channel: []const u8, account: []const u8 },
    clear: struct { channel: []const u8 },
    show: struct { channel: []const u8 },
};

/// Parse a real server command:
///   SUCCESSOR <channel> SET <account>
///   SUCCESSOR <channel> CLEAR
///   SUCCESSOR <channel> SHOW
pub fn parseCommand(line: []const u8) ParseError!SuccessorCommand {
    var it = std.mem.tokenizeAny(u8, line, " \t\r\n");
    const cmd = it.next() orelse return error.EmptyLine;
    if (!std.ascii.eqlIgnoreCase(cmd, "SUCCESSOR")) return error.UnknownCommand;

    const channel = it.next() orelse return error.MissingChannel;
    validateChannelForParse(channel) catch return error.InvalidChannel;

    const action = it.next() orelse return error.MissingAction;
    if (std.ascii.eqlIgnoreCase(action, "SET")) {
        const account = it.next() orelse return error.MissingAccount;
        validateAccountForParse(account) catch return error.InvalidAccount;
        if (it.next() != null) return error.TooManyArguments;
        return .{ .set = .{ .channel = channel, .account = account } };
    }
    if (std.ascii.eqlIgnoreCase(action, "CLEAR")) {
        if (it.next() != null) return error.TooManyArguments;
        return .{ .clear = .{ .channel = channel } };
    }
    if (std.ascii.eqlIgnoreCase(action, "SHOW")) {
        if (it.next() != null) return error.TooManyArguments;
        return .{ .show = .{ .channel = channel } };
    }
    return error.UnknownAction;
}

/// Heap-backed store for per-channel configured successor accounts.
pub const SuccessorStore = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMapUnmanaged([]u8) = .empty,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn set(self: *Self, channel: []const u8, account: []const u8) SuccessionError!void {
        try validateChannel(channel);
        try validateAccount(account);
        if (self.entries.count() >= max_successors and self.entries.get(channel) == null) return error.TooManySuccessors;

        const key = try self.allocator.dupe(u8, channel);
        errdefer self.allocator.free(key);
        const value = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(value);

        const gop = try self.entries.getOrPut(self.allocator, key);
        if (gop.found_existing) {
            self.allocator.free(key);
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = value;
            return;
        }

        gop.value_ptr.* = value;
    }

    pub fn get(self: *const Self, channel: []const u8) ?[]const u8 {
        return self.entries.get(channel);
    }

    pub fn clear(self: *Self, channel: []const u8) bool {
        if (self.entries.fetchRemove(channel)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
            return true;
        }
        return false;
    }

    pub fn count(self: *const Self) usize {
        return self.entries.count();
    }
};

pub fn validateChannel(channel: []const u8) SuccessionError!void {
    if (channel.len == 0) return error.EmptyName;
    if (channel.len > max_channel_len) return error.ChannelTooLong;
    if (channel[0] != '#' or channel.len == 1) return error.InvalidChannel;
    for (channel) |c| {
        if (c == 0 or c == '\r' or c == '\n' or c == ' ' or c == '\t') return error.InvalidChannel;
    }
}

pub fn validateAccount(account: []const u8) SuccessionError!void {
    if (account.len == 0) return error.EmptyName;
    if (account.len > max_account_len) return error.AccountTooLong;
    if (account[0] == '#') return error.InvalidAccount;
    for (account) |c| {
        if (c == 0 or c == '\r' or c == '\n' or c == ' ' or c == '\t' or c == ':') return error.InvalidAccount;
    }
}

fn validateChannelForParse(channel: []const u8) ParseError!void {
    validateChannel(channel) catch return error.InvalidChannel;
}

fn validateAccountForParse(account: []const u8) ParseError!void {
    validateAccount(account) catch return error.InvalidAccount;
}

fn sameAccount(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

test "decide: configured successor wins over higher access account" {
    const access = [_]AccountAccess{
        .{ .account = "carol", .level = .admin },
        .{ .account = "bob", .level = .voice },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#zig",
        .founder = "alice",
        .reason = .dropped,
        .configured_successor = "bob",
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .transfer);
    try std.testing.expectEqualStrings("bob", decision.transfer.new_founder);
    try std.testing.expectEqual(.configured_successor, decision.transfer.source);
}

test "decide: configured successor is skipped when it is the departing founder" {
    const access = [_]AccountAccess{
        .{ .account = "Alice", .level = .founder },
        .{ .account = "carol", .level = .op },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#ops",
        .founder = "alice",
        .reason = .expired,
        .configured_successor = "ALICE",
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .transfer);
    try std.testing.expectEqualStrings("carol", decision.transfer.new_founder);
    try std.testing.expectEqual(.highest_access, decision.transfer.source);
}

test "decide: unavailable configured successor falls back to highest access" {
    const access = [_]AccountAccess{
        .{ .account = "voice", .level = .voice },
        .{ .account = "admin", .level = .admin },
        .{ .account = "op", .level = .op },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#team",
        .founder = "founder",
        .reason = .dropped,
        .configured_successor = "next",
        .configured_successor_remaining = false,
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .transfer);
    try std.testing.expectEqualStrings("admin", decision.transfer.new_founder);
    try std.testing.expectEqual(.highest_access, decision.transfer.source);
}

test "decide: highest access skips removed accounts and old founder" {
    const access = [_]AccountAccess{
        .{ .account = "alice", .level = .founder },
        .{ .account = "root2", .level = .founder, .remaining = false },
        .{ .account = "oper", .level = .op },
        .{ .account = "admin", .level = .admin },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#staff",
        .founder = "ALICE",
        .reason = .expired,
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .transfer);
    try std.testing.expectEqualStrings("admin", decision.transfer.new_founder);
}

test "decide: ties keep input order" {
    const access = [_]AccountAccess{
        .{ .account = "first", .level = .op },
        .{ .account = "second", .level = .op },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#tie",
        .founder = "gone",
        .reason = .dropped,
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .transfer);
    try std.testing.expectEqualStrings("first", decision.transfer.new_founder);
}

test "decide: no eligible accounts marks channel for deletion" {
    const access = [_]AccountAccess{
        .{ .account = "founder", .level = .founder },
        .{ .account = "old", .level = .admin, .remaining = false },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#empty",
        .founder = "founder",
        .reason = .expired,
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .mark_for_deletion);
    try std.testing.expectEqualStrings("#empty", decision.mark_for_deletion.channel);
}

test "parse: set command returns borrowed channel and account" {
    const parsed = try parseCommand("SUCCESSOR #zig SET bob");
    try std.testing.expect(std.meta.activeTag(parsed) == .set);
    try std.testing.expectEqualStrings("#zig", parsed.set.channel);
    try std.testing.expectEqualStrings("bob", parsed.set.account);
}

test "parse: commands are case-insensitive and tolerate surrounding whitespace" {
    const parsed = try parseCommand(" \t successor #ops clear \r\n");
    try std.testing.expect(std.meta.activeTag(parsed) == .clear);
    try std.testing.expectEqualStrings("#ops", parsed.clear.channel);
}

test "parse: show command" {
    const parsed = try parseCommand("SUCCESSOR #ops SHOW");
    try std.testing.expect(std.meta.activeTag(parsed) == .show);
    try std.testing.expectEqualStrings("#ops", parsed.show.channel);
}

test "parse: rejects unknown action and excess arguments" {
    try std.testing.expectError(error.UnknownAction, parseCommand("SUCCESSOR #x LIST"));
    try std.testing.expectError(error.TooManyArguments, parseCommand("SUCCESSOR #x CLEAR extra"));
    try std.testing.expectError(error.TooManyArguments, parseCommand("SUCCESSOR #x SET bob extra"));
}

test "parse: rejects invalid channel and account" {
    try std.testing.expectError(error.InvalidChannel, parseCommand("SUCCESSOR chan SET bob"));
    try std.testing.expectError(error.InvalidChannel, parseCommand("SUCCESSOR # SET bob"));
    try std.testing.expectError(error.InvalidAccount, parseCommand("SUCCESSOR #x SET #not-account"));
    try std.testing.expectError(error.InvalidAccount, parseCommand("SUCCESSOR #x SET bad:account"));
}

test "access level parse and ordering" {
    try std.testing.expectEqual(AccessLevel.voice, AccessLevel.parse("voice").?);
    try std.testing.expectEqual(AccessLevel.op, AccessLevel.parse("OP").?);
    try std.testing.expectEqual(AccessLevel.admin, AccessLevel.parse("Admin").?);
    try std.testing.expectEqual(AccessLevel.founder, AccessLevel.parse("founder").?);
    try std.testing.expect(AccessLevel.admin.lessThan(.founder));
    try std.testing.expect(!AccessLevel.admin.lessThan(.op));
    try std.testing.expect(AccessLevel.parse("halfop") == null);
}

test "store: set get replace and clear successor" {
    var store = SuccessorStore.init(std.testing.allocator);
    defer store.deinit();

    try store.set("#zig", "alice");
    try std.testing.expectEqual(@as(usize, 1), store.count());
    try std.testing.expectEqualStrings("alice", store.get("#zig").?);

    try store.set("#zig", "bob");
    try std.testing.expectEqual(@as(usize, 1), store.count());
    try std.testing.expectEqualStrings("bob", store.get("#zig").?);

    try std.testing.expect(store.clear("#zig"));
    try std.testing.expect(!store.clear("#zig"));
    try std.testing.expect(store.get("#zig") == null);
}

test "store: validates names before allocating entries" {
    var store = SuccessorStore.init(std.testing.allocator);
    defer store.deinit();

    try std.testing.expectError(error.InvalidChannel, store.set("plain", "alice"));
    try std.testing.expectError(error.InvalidAccount, store.set("#x", "#alice"));
    try std.testing.expectError(error.EmptyName, store.set("#x", ""));
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "store value feeds pure succession decision" {
    var store = SuccessorStore.init(std.testing.allocator);
    defer store.deinit();

    try store.set("#handoff", "next");
    const access = [_]AccountAccess{
        .{ .account = "admin", .level = .admin },
    };

    const decision = decideFounderSuccession(.{
        .channel = "#handoff",
        .founder = "old",
        .reason = .dropped,
        .configured_successor = store.get("#handoff"),
        .access = &access,
    });

    try std.testing.expect(std.meta.activeTag(decision) == .transfer);
    try std.testing.expectEqualStrings("next", decision.transfer.new_founder);
}
