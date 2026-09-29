// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline memo — Onyx Server-native offline messaging keyed by account.
//!
//! The bouncer rewind replays *channel* history a session missed; The offline memo service covers
//! the other gap: a direct message left for an account that has no attached
//! session. Messages are stored per recipient account and delivered when that
//! account next logs in (REGISTER / IDENTIFY / SASL). In-memory + bounded; a
//! WAL/snapshot backing can be layered later (mirroring the account store).
const std = @import("std");
const toml = @import("../proto/toml.zig");

pub const default_max_text_bytes: usize = 400;
pub const default_max_from_bytes: usize = 64;
pub const default_max_per_account: usize = 64;
pub const default_max_accounts: usize = 65536;

/// Runtime-tunable offline-mailbox limits. Defaults preserve the historical
/// hardcoded behaviour; the orchestrator overlays the `[bouncer]` TOML section
/// via `Config.applyToml` before constructing a `MemoBox`.
pub const Config = struct {
    /// Max offline DM body length (bytes).
    max_text_bytes: usize = default_max_text_bytes,
    /// Max sender-name length on an offline DM (bytes).
    max_from_bytes: usize = default_max_from_bytes,
    /// Offline mailbox depth cap per account (entries).
    max_per_account: usize = default_max_per_account,
    /// Max distinct offline mailboxes.
    max_accounts: usize = default_max_accounts,

    /// Overlay `[bouncer]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("bouncer.memo_text_max_len")) |v| {
            if (v >= 1) cfg.max_text_bytes = @intCast(v);
        }
        if (doc.getUint("bouncer.memo_from_max_len")) |v| {
            if (v >= 1) cfg.max_from_bytes = @intCast(v);
        }
        if (doc.getUint("bouncer.memo_mailbox_depth")) |v| {
            if (v >= 1) cfg.max_per_account = @intCast(v);
        }
        if (doc.getUint("bouncer.memo_max_accounts")) |v| {
            if (v >= 1) cfg.max_accounts = @intCast(v);
        }
    }
};

pub const Error = std.mem.Allocator.Error || error{ TooManyAccounts, MailboxFull, MessageInvalid };

pub const Message = struct {
    from: []u8,
    text: []u8,
    sent_ms: i64,

    fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        allocator.free(self.from);
        allocator.free(self.text);
    }
};

const Mailbox = struct {
    items: std.ArrayListUnmanaged(Message) = .empty,

    fn deinit(self: *Mailbox, allocator: std.mem.Allocator) void {
        for (self.items.items) |*m| m.deinit(allocator);
        self.items.deinit(allocator);
    }
};

pub const MemoBox = struct {
    allocator: std.mem.Allocator,
    boxes: std.StringHashMap(Mailbox),
    cfg: Config = .{},

    pub fn init(allocator: std.mem.Allocator) MemoBox {
        return initWithConfig(allocator, .{});
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) MemoBox {
        return .{ .allocator = allocator, .boxes = std.StringHashMap(Mailbox).init(allocator), .cfg = cfg };
    }

    pub fn deinit(self: *MemoBox) void {
        var it = self.boxes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.boxes.deinit();
        self.* = undefined;
    }

    /// Store a message for `to_account` from `from`. Returns the new mailbox
    /// depth. Errors on empty/oversize fields, a full mailbox, or too many
    /// accounts. `from`/`text` are copied.
    pub fn send(self: *MemoBox, to_account: []const u8, from: []const u8, text: []const u8, now_ms: i64) Error!usize {
        if (to_account.len == 0 or from.len == 0 or from.len > self.cfg.max_from_bytes) return error.MessageInvalid;
        if (text.len == 0 or text.len > self.cfg.max_text_bytes) return error.MessageInvalid;
        const box = try self.ensure(to_account);
        if (box.items.items.len >= self.cfg.max_per_account) return error.MailboxFull;

        const from_owned = try self.allocator.dupe(u8, from);
        errdefer self.allocator.free(from_owned);
        const text_owned = try self.allocator.dupe(u8, text);
        errdefer self.allocator.free(text_owned);
        try box.items.append(self.allocator, .{ .from = from_owned, .text = text_owned, .sent_ms = now_ms });
        return box.items.items.len;
    }

    /// Borrowed pending messages for `account` (empty if none). Valid until the
    /// next mutation of this account's mailbox.
    pub fn pending(self: *const MemoBox, account: []const u8) []const Message {
        const box = self.boxes.getPtr(account) orelse return &.{};
        return box.items.items;
    }

    pub fn count(self: *const MemoBox, account: []const u8) usize {
        return self.pending(account).len;
    }

    /// Visit every stored memo. `callback` may not mutate the box.
    pub fn forEach(self: *const MemoBox, context: anytype, comptime callback: anytype) !void {
        var accounts = self.boxes.iterator();
        while (accounts.next()) |entry| {
            for (entry.value_ptr.items.items) |*message| {
                try callback(context, entry.key_ptr.*, message);
            }
        }
    }

    /// Drop all of `account`'s messages (e.g. after delivery). Returns how many
    /// were removed and prunes the (now-empty) mailbox.
    pub fn clear(self: *MemoBox, account: []const u8) usize {
        const entry = self.boxes.getEntry(account) orelse return 0;
        const n = entry.value_ptr.items.items.len;
        entry.value_ptr.deinit(self.allocator);
        const key = entry.key_ptr.*;
        self.boxes.removeByPtr(entry.key_ptr);
        self.allocator.free(key);
        return n;
    }

    fn ensure(self: *MemoBox, account: []const u8) Error!*Mailbox {
        if (self.boxes.getPtr(account)) |box| return box;
        if (self.boxes.count() >= self.cfg.max_accounts) return error.TooManyAccounts;
        const owned = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned);
        try self.boxes.putNoClobber(owned, .{});
        return self.boxes.getPtr(account).?;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "send then pending then clear" {
    var t = MemoBox.init(testing.allocator);
    defer t.deinit();
    try testing.expectEqual(@as(usize, 0), t.count("alice"));
    try testing.expectEqual(@as(usize, 1), try t.send("alice", "bob", "hi alice", 100));
    try testing.expectEqual(@as(usize, 2), try t.send("alice", "carol", "ping", 200));
    const msgs = t.pending("alice");
    try testing.expectEqual(@as(usize, 2), msgs.len);
    try testing.expectEqualStrings("bob", msgs[0].from);
    try testing.expectEqualStrings("ping", msgs[1].text);
    try testing.expectEqual(@as(usize, 2), t.clear("alice"));
    try testing.expectEqual(@as(usize, 0), t.count("alice")); // pruned
}

test "rejects invalid fields and enforces mailbox cap" {
    var t = MemoBox.init(testing.allocator);
    defer t.deinit();
    try testing.expectError(error.MessageInvalid, t.send("alice", "bob", "", 0));
    try testing.expectError(error.MessageInvalid, t.send("alice", "", "hi", 0));
    var i: usize = 0;
    while (i < default_max_per_account) : (i += 1) _ = try t.send("bob", "x", "m", 0);
    try testing.expectError(error.MailboxFull, t.send("bob", "x", "m", 0));
}

test "mailboxes are independent per account" {
    var t = MemoBox.init(testing.allocator);
    defer t.deinit();
    _ = try t.send("alice", "bob", "for alice", 0);
    _ = try t.send("carol", "bob", "for carol", 0);
    try testing.expectEqual(@as(usize, 1), t.count("alice"));
    try testing.expectEqual(@as(usize, 1), t.count("carol"));
    _ = t.clear("alice");
    try testing.expectEqual(@as(usize, 0), t.count("alice"));
    try testing.expectEqual(@as(usize, 1), t.count("carol"));
}

test "Config defaults preserve historical limits" {
    const cfg = Config{};
    try testing.expectEqual(default_max_text_bytes, cfg.max_text_bytes);
    try testing.expectEqual(default_max_from_bytes, cfg.max_from_bytes);
    try testing.expectEqual(default_max_per_account, cfg.max_per_account);
    try testing.expectEqual(default_max_accounts, cfg.max_accounts);
}

test "Config.applyToml overlays [bouncer] memo keys" {
    var doc = try toml.parse(
        testing.allocator,
        "[bouncer]\nmemo_text_max_len = 800\nmemo_from_max_len = 32\nmemo_mailbox_depth = 8\nmemo_max_accounts = 1024\n",
    );
    defer doc.deinit(testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try testing.expectEqual(@as(usize, 800), cfg.max_text_bytes);
    try testing.expectEqual(@as(usize, 32), cfg.max_from_bytes);
    try testing.expectEqual(@as(usize, 8), cfg.max_per_account);
    try testing.expectEqual(@as(usize, 1024), cfg.max_accounts);
}

test "initWithConfig enforces a smaller mailbox depth" {
    var t = MemoBox.initWithConfig(testing.allocator, .{ .max_per_account = 2 });
    defer t.deinit();
    _ = try t.send("alice", "bob", "one", 0);
    _ = try t.send("alice", "bob", "two", 0);
    try testing.expectError(error.MailboxFull, t.send("alice", "bob", "three", 0));
}
