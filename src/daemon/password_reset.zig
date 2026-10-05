// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account password-reset token state.
//!
//! This module stores reset tokens only. Random byte generation, token
//! delivery, and the actual password change stay with the caller.

const std = @import("std");

/// A pending password-reset record owned by `ResetStore`.
pub const Pending = struct {
    /// Original account name as supplied by the caller.
    account: []const u8,
    /// Reset token bytes as supplied by the caller.
    token: []const u8,
    /// Millisecond timestamp when this token was issued.
    issued_ms: u64,
    /// Failed confirmation attempts for this pending token.
    attempts: u8,

    fn deinit(self: *Pending, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        std.crypto.secureZero(u8, @constCast(self.token));
        allocator.free(self.token);
        self.* = undefined;
    }
};

/// Runtime bounds and policy for password-reset token storage.
pub const Params = struct {
    token_bytes: usize = 16,
    ttl_ms: u64 = 15 * 60 * 1000,
    max_attempts: u8 = 5,
};

/// Errors returned while issuing reset tokens.
pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    InvalidTokenBytes,
};

/// Outcome of a password-reset confirmation attempt.
pub const Result = enum {
    ok,
    no_request,
    expired,
    bad_token,
    too_many_attempts,
};

/// Owned pending reset records keyed by normalized account name.
pub const ResetStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.StringHashMap(Pending),

    /// Creates an empty reset store using caller-provided bounds.
    pub fn init(allocator: std.mem.Allocator, params: Params) ResetStore {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = std.StringHashMap(Pending).init(allocator),
        };
    }

    /// Frees all pending records and invalidates the store.
    pub fn deinit(self: *ResetStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Issues or replaces a pending reset token for an account.
    pub fn issue(self: *ResetStore, account: []const u8, token: []const u8, now: u64) Error!void {
        try self.validateAccount(account);
        if (token.len != self.params.token_bytes or token.len == 0) return error.InvalidTokenBytes;

        if (self.findEntry(account)) |entry| {
            const next = try self.makePending(account, token, now);
            entry.value_ptr.deinit(self.allocator);
            entry.value_ptr.* = next;
            return;
        }

        const owned_key = try self.normalizedAccount(account);
        errdefer self.allocator.free(owned_key);
        var next = try self.makePending(account, token, now);
        errdefer next.deinit(self.allocator);

        try self.entries.putNoClobber(owned_key, next);
    }

    /// Confirms a pending token and consumes the entry on success.
    pub fn confirm(self: *ResetStore, account: []const u8, token: []const u8, now: u64) Result {
        const entry = self.findEntry(account) orelse return .no_request;
        if (self.isExpired(entry.value_ptr.*, now)) {
            self.dropEntry(entry);
            return .expired;
        }

        if (tokenMatches(entry.value_ptr.token, token)) {
            self.dropEntry(entry);
            return .ok;
        }

        // Fence-post: `max_attempts` wrong tries return `bad_token`; the
        // (max_attempts + 1)-th trips lockout and drops the record. (One extra
        // attempt beyond `max_attempts` before lockout — chosen for this store.)
        if (entry.value_ptr.attempts < std.math.maxInt(u8)) entry.value_ptr.attempts += 1;
        if (entry.value_ptr.attempts > self.params.max_attempts) {
            self.dropEntry(entry);
            return .too_many_attempts;
        }
        return .bad_token;
    }

    /// Returns true when the account has a pending reset record.
    pub fn isPending(self: *const ResetStore, account: []const u8) bool {
        return self.findEntry(account) != null;
    }

    /// Returns a borrowed snapshot of the pending record for an account. Its
    /// `account`/`token` slices point into store-owned memory and are valid ONLY
    /// until the next mutating call for this account (`confirm`/`cancel`/`issue`/
    /// `sweepExpired`), which may free them. Copy out anything that must outlive
    /// the next store call.
    pub fn pending(self: *const ResetStore, account: []const u8) ?Pending {
        const entry = self.findEntry(account) orelse return null;
        return entry.value_ptr.*;
    }

    /// Cancels a pending reset record if one exists.
    pub fn cancel(self: *ResetStore, account: []const u8) bool {
        const entry = self.findEntry(account) orelse return false;
        self.dropEntry(entry);
        return true;
    }

    /// Removes expired pending records and returns the number removed.
    pub fn sweepExpired(self: *ResetStore, now: u64) usize {
        var removed: usize = 0;
        while (self.findExpiredEntry(now)) |entry| {
            self.dropEntry(entry);
            removed += 1;
        }
        return removed;
    }

    fn makePending(self: *ResetStore, account: []const u8, token: []const u8, now: u64) Error!Pending {
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);

        return .{
            .account = owned_account,
            .token = owned_token,
            .issued_ms = now,
            .attempts = 0,
        };
    }

    fn normalizedAccount(self: *ResetStore, account: []const u8) Error![]u8 {
        const owned_key = try self.allocator.alloc(u8, account.len);
        for (account, 0..) |byte, index| {
            owned_key[index] = std.ascii.toLower(byte);
        }
        return owned_key;
    }

    fn validateAccount(self: *const ResetStore, account: []const u8) Error!void {
        _ = self;
        if (account.len == 0) return error.InvalidAccount;
        for (account) |byte| {
            if (!validAccountByte(byte)) return error.InvalidAccount;
        }
    }

    fn findEntry(self: *const ResetStore, account: []const u8) ?std.StringHashMap(Pending).Entry {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn findExpiredEntry(self: *const ResetStore, now: u64) ?std.StringHashMap(Pending).Entry {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (self.isExpired(entry.value_ptr.*, now)) return entry;
        }
        return null;
    }

    fn dropEntry(self: *ResetStore, entry: std.StringHashMap(Pending).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.entries.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn isExpired(self: *const ResetStore, item: Pending, now: u64) bool {
        if (now < item.issued_ms) return false;
        return now - item.issued_ms > self.params.ttl_ms;
    }
};

fn tokenMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    return std.crypto.timing_safe.compare(u8, expected, actual, .big) == .eq;
}

fn validAccountByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '@' => true,
        else => false,
    };
}

const testing = std.testing;

test "issue then confirm succeeds and removes pending entry" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 4 });
    defer store.deinit();
    const token = [_]u8{ 0xde, 0xad, 0xbe, 0xef };

    // Act.
    try store.issue("Alice", &token, 1000);
    const result = store.confirm("alice", &token, 1001);

    // Assert.
    try testing.expectEqual(Result.ok, result);
    try testing.expect(!store.isPending("ALICE"));
    try testing.expectEqual(@as(?Pending, null), store.pending("alice"));
}

test "confirm without prior issue reports no request" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 2 });
    defer store.deinit();
    const token = [_]u8{ 0x01, 0x02 };

    // Act.
    const result = store.confirm("bob", &token, 2000);

    // Assert.
    try testing.expectEqual(Result.no_request, result);
}

test "expired token is reported and the entry is dropped" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 1, .ttl_ms = 10 });
    defer store.deinit();
    const token = [_]u8{0x7f};
    try store.issue("dave", &token, 4000);

    // Act.
    const result = store.confirm("dave", &token, 4011);

    // Assert.
    try testing.expectEqual(Result.expired, result);
    try testing.expect(!store.isPending("DAVE"));
}

test "wrong token bumps attempts then locks out after the max" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 1, .max_attempts = 2 });
    defer store.deinit();
    const token = [_]u8{0xaa};
    try store.issue("carol", &token, 3000);

    // Act.
    const first = store.confirm("carol", &[_]u8{0x00}, 3001);
    const item = store.pending("carol").?;
    const second = store.confirm("carol", &[_]u8{0x01}, 3002);
    const third = store.confirm("carol", &[_]u8{0x02}, 3003);

    // Assert.
    try testing.expectEqual(Result.bad_token, first);
    try testing.expectEqual(@as(u8, 1), item.attempts);
    try testing.expectEqual(Result.bad_token, second);
    try testing.expectEqual(Result.too_many_attempts, third);
    try testing.expect(!store.isPending("CAROL"));
}

test "cancel removes a pending entry and all owned memory" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 1 });
    defer store.deinit();
    const token = [_]u8{0x33};
    try store.issue("frank", &token, 8000);

    // Act.
    const removed = store.cancel("FRANK");
    const missing = store.confirm("frank", &token, 8001);

    // Assert.
    try testing.expect(removed);
    try testing.expectEqual(Result.no_request, missing);
    try testing.expect(!store.cancel("frank"));
}

test "sweep expired drops only expired entries and returns the count" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 1, .ttl_ms = 50 });
    defer store.deinit();
    const old_token = [_]u8{0x01};
    const fresh_token = [_]u8{0x02};
    try store.issue("old", &old_token, 7000);
    try store.issue("fresh", &fresh_token, 7040);

    // Act.
    const removed = store.sweepExpired(7060);

    // Assert.
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expect(!store.isPending("old"));
    try testing.expect(store.isPending("fresh"));
    try testing.expectEqual(Result.ok, store.confirm("fresh", &fresh_token, 7049));
}

test "re-issue replaces the prior token so the old token no longer confirms" {
    // Arrange.
    var store = ResetStore.init(testing.allocator, .{ .token_bytes = 2 });
    defer store.deinit();
    const first_token = [_]u8{ 0x10, 0x11 };
    const second_token = [_]u8{ 0x20, 0x21 };

    // Act.
    try store.issue("erin", &first_token, 5000);
    try store.issue("ERIN", &second_token, 6000);
    const item = store.pending("erin").?;

    // Assert.
    try testing.expectEqualStrings("ERIN", item.account);
    try testing.expectEqual(@as(u64, 6000), item.issued_ms);
    try testing.expectEqual(Result.bad_token, store.confirm("erin", &first_token, 6001));
    try testing.expectEqual(Result.ok, store.confirm("erin", &second_token, 6002));
}
