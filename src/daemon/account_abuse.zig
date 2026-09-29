// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account abuse score.
//!
//! This is a different axis from the per-connection flood guard. The guard's
//! token buckets die with the socket. This score is keyed by the authenticated
//! account, survives reconnect, and never writes those buckets.

const std = @import("std");

pub const max_account_len: usize = 128;
/// Allocator-backed ceiling. Not a peer cap: an account table past 64 is normal.
pub const max_accounts: usize = 8192;

pub const AccountAbuse = struct {
    allocator: std.mem.Allocator,
    scores: std.StringHashMapUnmanaged(u32) = .empty,

    pub fn init(allocator: std.mem.Allocator) AccountAbuse {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AccountAbuse) void {
        var it = self.scores.iterator();
        while (it.next()) |kv| self.allocator.free(kv.key_ptr.*);
        self.scores.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const AccountAbuse) usize {
        return self.scores.count();
    }

    /// Current score, or 0 when the account has never been noted.
    pub fn score(self: *const AccountAbuse, account: []const u8) u32 {
        return self.scores.get(account) orelse 0;
    }

    /// Add one point. Empty or over-long names are ignored. A full table
    /// refuses a new account and still increments one that is already present.
    pub fn note(self: *AccountAbuse, account: []const u8) !u32 {
        if (account.len == 0 or account.len > max_account_len) return 0;
        if (self.scores.getPtr(account)) |slot| {
            slot.* +|= 1;
            return slot.*;
        }
        if (self.scores.count() >= max_accounts) return 0;
        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        try self.scores.put(self.allocator, key, 1);
        return 1;
    }

    /// Install a restored score, replacing any previous value for `account`.
    pub fn importScore(self: *AccountAbuse, account: []const u8, value: u32) !void {
        if (account.len == 0 or account.len > max_account_len) return error.BadRecord;
        if (self.scores.getPtr(account)) |slot| {
            slot.* = value;
            return;
        }
        if (self.scores.count() >= max_accounts) return error.TooManyAccounts;
        const key = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(key);
        try self.scores.put(self.allocator, key, value);
    }

    pub const Error = error{
        BadRecord,
        TooManyAccounts,
    } || std.mem.Allocator.Error;
};

test "GAP-D4 account score is independent of a fresh connection bucket" {
    var scores = AccountAbuse.init(std.testing.allocator);
    defer scores.deinit();
    try std.testing.expectEqual(@as(u32, 0), scores.score("d4acct"));
    try std.testing.expectEqual(@as(u32, 1), try scores.note("d4acct"));
    try std.testing.expectEqual(@as(u32, 2), try scores.note("d4acct"));
    try std.testing.expectEqual(@as(u32, 0), try scores.note(""));
    try std.testing.expectEqual(@as(u32, 2), scores.score("d4acct"));
}
