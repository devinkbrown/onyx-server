// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account contact verification state.
//!
//! This module stores verification tokens only. Message delivery and random
//! byte generation stay with the caller.

const std = @import("std");

/// Verification status for an account registration.
pub const Status = enum {
    pending,
    verified,
};

/// A pending account verification record owned by `VerifyStore`.
pub const Pending = struct {
    /// Original account name as supplied by the caller.
    account: []const u8,
    /// Contact address or identifier as supplied by the caller.
    contact: []const u8,
    /// Encoded verification token derived from caller-supplied random bytes.
    token: []const u8,
    /// Millisecond timestamp when this token was issued.
    issued_ms: u64,
    /// Failed confirmation attempts for this pending token.
    attempts: u8,

    fn deinit(self: *Pending, allocator: std.mem.Allocator) void {
        allocator.free(self.account);
        allocator.free(self.contact);
        allocator.free(self.token);
        self.* = undefined;
    }
};

/// Runtime bounds and policy for account verification storage.
pub const Params = struct {
    max_pending: usize = 65536,
    token_bytes: usize = 32,
    ttl_ms: u64 = 15 * 60 * 1000,
    max_attempts: u8 = 5,
    max_account_bytes: usize = 128,
    max_contact_bytes: usize = 320,
};

/// Errors returned while issuing verification tokens.
pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidContact,
    ContactTooLong,
    InvalidTokenBytes,
    TooManyPending,
};

/// Outcome of an account verification confirmation attempt.
pub const Result = enum {
    verified,
    expired,
    no_pending,
    bad_token,
    locked,
};

/// Owned pending-verification records keyed by normalized account name.
pub const VerifyStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.StringHashMap(Pending),

    /// Creates an empty verification store using caller-provided bounds.
    pub fn init(allocator: std.mem.Allocator, params: Params) VerifyStore {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = std.StringHashMap(Pending).init(allocator),
        };
    }

    /// Frees all pending records and invalidates the store.
    pub fn deinit(self: *VerifyStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Issues or replaces a pending token and returns the stored token slice.
    pub fn issue(
        self: *VerifyStore,
        account: []const u8,
        contact: []const u8,
        random_bytes: []const u8,
        now: u64,
    ) Error![]const u8 {
        try self.validateAccount(account);
        try self.validateContact(contact);
        if (random_bytes.len != self.params.token_bytes or random_bytes.len == 0) return error.InvalidTokenBytes;
        if (random_bytes.len > std.math.maxInt(usize) / 2) return error.InvalidTokenBytes;

        if (self.findEntry(account)) |entry| {
            const next = try self.makePending(account, contact, random_bytes, now);
            entry.value_ptr.deinit(self.allocator);
            entry.value_ptr.* = next;
            return entry.value_ptr.token;
        }

        if (self.entries.count() >= self.params.max_pending) return error.TooManyPending;

        const owned_key = try self.normalizedAccount(account);
        errdefer self.allocator.free(owned_key);
        var next = try self.makePending(account, contact, random_bytes, now);
        errdefer next.deinit(self.allocator);

        try self.entries.putNoClobber(owned_key, next);
        return self.entries.getPtr(owned_key).?.token;
    }

    /// Confirms a pending token and consumes the entry on success.
    pub fn confirm(self: *VerifyStore, account: []const u8, token: []const u8, now: u64) Result {
        const entry = self.findEntry(account) orelse return .no_pending;
        if (self.isExpired(entry.value_ptr.*, now)) return .expired;
        if (entry.value_ptr.attempts >= self.params.max_attempts) return .locked;

        if (tokenMatches(entry.value_ptr.token, token)) {
            self.dropEntry(entry);
            return .verified;
        }

        if (entry.value_ptr.attempts < std.math.maxInt(u8)) entry.value_ptr.attempts += 1;
        if (entry.value_ptr.attempts >= self.params.max_attempts) return .locked;
        return .bad_token;
    }

    /// Returns true when the account has a pending verification record.
    pub fn isPending(self: *const VerifyStore, account: []const u8) bool {
        return self.findEntry(account) != null;
    }

    /// Returns a borrowed snapshot of the pending record for an account.
    pub fn pending(self: *const VerifyStore, account: []const u8) ?Pending {
        const entry = self.findEntry(account) orelse return null;
        return entry.value_ptr.*;
    }

    /// Cancels a pending verification record if one exists.
    pub fn cancel(self: *VerifyStore, account: []const u8) bool {
        const entry = self.findEntry(account) orelse return false;
        self.dropEntry(entry);
        return true;
    }

    /// Removes expired pending records and returns the number removed.
    pub fn sweepExpired(self: *VerifyStore, now: u64) usize {
        var removed: usize = 0;
        while (self.findExpiredEntry(now)) |entry| {
            self.dropEntry(entry);
            removed += 1;
        }
        return removed;
    }

    fn makePending(
        self: *VerifyStore,
        account: []const u8,
        contact: []const u8,
        random_bytes: []const u8,
        now: u64,
    ) Error!Pending {
        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        const owned_contact = try self.allocator.dupe(u8, contact);
        errdefer self.allocator.free(owned_contact);
        const owned_token = try self.allocator.alloc(u8, random_bytes.len * 2);
        errdefer self.allocator.free(owned_token);

        encodeHex(random_bytes, owned_token);
        return .{
            .account = owned_account,
            .contact = owned_contact,
            .token = owned_token,
            .issued_ms = now,
            .attempts = 0,
        };
    }

    fn normalizedAccount(self: *VerifyStore, account: []const u8) Error![]u8 {
        const owned_key = try self.allocator.alloc(u8, account.len);
        for (account, 0..) |byte, index| {
            owned_key[index] = std.ascii.toLower(byte);
        }
        return owned_key;
    }

    fn validateAccount(self: *const VerifyStore, account: []const u8) Error!void {
        if (account.len == 0) return error.InvalidAccount;
        if (account.len > self.params.max_account_bytes) return error.AccountTooLong;
        for (account) |byte| {
            if (!validTokenSubjectByte(byte)) return error.InvalidAccount;
        }
    }

    fn validateContact(self: *const VerifyStore, contact: []const u8) Error!void {
        if (contact.len == 0) return error.InvalidContact;
        if (contact.len > self.params.max_contact_bytes) return error.ContactTooLong;
        for (contact) |byte| {
            if (!validContactByte(byte)) return error.InvalidContact;
        }
    }

    fn findEntry(self: *const VerifyStore, account: []const u8) ?std.StringHashMap(Pending).Entry {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }

    fn findExpiredEntry(self: *const VerifyStore, now: u64) ?std.StringHashMap(Pending).Entry {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (self.isExpired(entry.value_ptr.*, now)) return entry;
        }
        return null;
    }

    fn dropEntry(self: *VerifyStore, entry: std.StringHashMap(Pending).Entry) void {
        const owned_key = entry.key_ptr.*;
        entry.value_ptr.deinit(self.allocator);
        self.entries.removeByPtr(entry.key_ptr);
        self.allocator.free(owned_key);
    }

    fn isExpired(self: *const VerifyStore, item: Pending, now: u64) bool {
        if (now < item.issued_ms) return false;
        return now - item.issued_ms >= self.params.ttl_ms;
    }
};

pub fn formatToken(random_bytes: []const u8, out: []u8) error{BufferTooSmall}![]u8 {
    if (random_bytes.len > out.len / 2) return error.BufferTooSmall;
    encodeHex(random_bytes, out[0 .. random_bytes.len * 2]);
    return out[0 .. random_bytes.len * 2];
}

fn encodeHex(bytes: []const u8, out: []u8) void {
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
}

fn tokenMatches(expected: []const u8, actual: []const u8) bool {
    if (expected.len != actual.len) return false;
    return std.crypto.timing_safe.compare(u8, expected, actual, .big) == .eq;
}

fn validTokenSubjectByte(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '@' => true,
        else => false,
    };
}

fn validContactByte(byte: u8) bool {
    return switch (byte) {
        0x21...0x7e => true,
        else => false,
    };
}

const testing = std.testing;

test "issue then confirm verifies and removes pending entry" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 4 });
    defer store.deinit();
    const random = [_]u8{ 0xde, 0xad, 0xbe, 0xef };

    // Act. Copy the token before confirm: a successful confirm removes the
    // pending entry that owns the returned slice (the live server uses the token
    // immediately, before any confirm).
    const issued = try store.issue("Alice", "alice@example.test", &random, 1000);
    var token_buf: [64]u8 = undefined;
    const token = token_buf[0..issued.len];
    @memcpy(token, issued);
    const result = store.confirm("alice", token, 1001);

    // Assert.
    try testing.expectEqualStrings("deadbeef", token);
    try testing.expectEqual(Result.verified, result);
    try testing.expect(!store.isPending("ALICE"));
    try testing.expectEqual(@as(?Pending, null), store.pending("alice"));
}

test "wrong token returns bad token and increments attempts" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 2, .max_attempts = 3 });
    defer store.deinit();
    const random = [_]u8{ 0x01, 0x23 };
    _ = try store.issue("bob", "bob@example.test", &random, 2000);

    // Act.
    const result = store.confirm("BOB", "wrong", 2001);
    const item = store.pending("bob").?;

    // Assert.
    try testing.expectEqual(Result.bad_token, result);
    try testing.expectEqual(@as(u8, 1), item.attempts);
    try testing.expect(store.isPending("BoB"));
}

test "wrong token locks after max attempts" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 1, .max_attempts = 2 });
    defer store.deinit();
    const random = [_]u8{0xaa};
    _ = try store.issue("carol", "carol@example.test", &random, 3000);

    // Act.
    const first = store.confirm("carol", "00", 3001);
    const second = store.confirm("carol", "01", 3002);
    const third = store.confirm("carol", "aa", 3003);

    // Assert.
    try testing.expectEqual(Result.bad_token, first);
    try testing.expectEqual(Result.locked, second);
    try testing.expectEqual(Result.locked, third);
    try testing.expect(store.isPending("CAROL"));
    try testing.expectEqual(@as(u8, 2), store.pending("carol").?.attempts);
}

test "expired token is reported without consuming pending entry" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 1, .ttl_ms = 10 });
    defer store.deinit();
    const random = [_]u8{0x7f};
    const token = try store.issue("dave", "dave@example.test", &random, 4000);

    // Act.
    const result = store.confirm("dave", token, 4010);

    // Assert.
    try testing.expectEqual(Result.expired, result);
    try testing.expect(store.isPending("DAVE"));
}

test "issuing again replaces the prior pending token and metadata" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 2 });
    defer store.deinit();
    const first_random = [_]u8{ 0x10, 0x11 };
    const second_random = [_]u8{ 0x20, 0x21 };

    // Act.
    const first = try store.issue("erin", "old@example.test", &first_random, 5000);
    try testing.expectEqualStrings("1011", first);
    const second = try store.issue("ERIN", "new@example.test", &second_random, 6000);
    const item = store.pending("erin").?;

    // Assert.
    try testing.expectEqualStrings("2021", second);
    try testing.expectEqualStrings("ERIN", item.account);
    try testing.expectEqualStrings("new@example.test", item.contact);
    try testing.expectEqual(@as(u64, 6000), item.issued_ms);
    try testing.expectEqual(Result.bad_token, store.confirm("erin", "1011", 6001));
    try testing.expectEqual(Result.verified, store.confirm("erin", "2021", 6002));
}

test "sweep expired frees only expired pending entries" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 1, .ttl_ms = 50 });
    defer store.deinit();
    const old_random = [_]u8{0x01};
    const fresh_random = [_]u8{0x02};
    _ = try store.issue("old", "old@example.test", &old_random, 7000);
    _ = try store.issue("fresh", "fresh@example.test", &fresh_random, 7040);

    // Act.
    const removed = store.sweepExpired(7050);

    // Assert.
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expect(!store.isPending("old"));
    try testing.expect(store.isPending("fresh"));
    try testing.expectEqual(Result.verified, store.confirm("fresh", "02", 7049));
}

test "cancel removes pending entry and all owned memory" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{ .token_bytes = 1 });
    defer store.deinit();
    const random = [_]u8{0x33};
    _ = try store.issue("frank", "frank@example.test", &random, 8000);

    // Act.
    const removed = store.cancel("FRANK");
    const missing = store.confirm("frank", "33", 8001);

    // Assert.
    try testing.expect(removed);
    try testing.expectEqual(Result.no_pending, missing);
    try testing.expect(!store.cancel("frank"));
}

test "bounds reject invalid issue inputs without leaks" {
    // Arrange.
    var store = VerifyStore.init(testing.allocator, .{
        .max_pending = 1,
        .token_bytes = 2,
        .max_account_bytes = 4,
        .max_contact_bytes = 8,
    });
    defer store.deinit();
    const random = [_]u8{ 0xab, 0xcd };
    const short_random = [_]u8{0xab};

    // Act and assert.
    try testing.expectError(error.InvalidAccount, store.issue("", "a@b.test", &random, 9000));
    try testing.expectError(error.AccountTooLong, store.issue("abcde", "a@b.test", &random, 9000));
    try testing.expectError(error.ContactTooLong, store.issue("abc", "long@example.test", &random, 9000));
    try testing.expectError(error.InvalidTokenBytes, store.issue("abc", "a@b.test", &short_random, 9000));
    _ = try store.issue("abc", "a@b.test", &random, 9000);
    try testing.expectError(error.TooManyPending, store.issue("def", "d@e.test", &random, 9000));
}
