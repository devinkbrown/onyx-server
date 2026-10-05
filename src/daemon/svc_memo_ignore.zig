// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure memo-ignore policy for services-backed memos.
//!
//! This module intentionally imports only `std`. It models the data and parser
//! for a real server command (`MEMOIGNORE`) without routing through service
//! pseudo-clients such as NickServ, ChanServ, or MemoServ.

const std = @import("std");

comptime {
    if (@bitSizeOf(usize) != 64) @compileError("svc_memo_ignore requires a 64-bit target");
}

pub const DEFAULT_MAX_ACCOUNTS: usize = 65536;
pub const DEFAULT_MAX_ENTRIES_PER_ACCOUNT: usize = 128;
pub const DEFAULT_MAX_ACCOUNT_BYTES: usize = 64;
pub const DEFAULT_MAX_SENDER_BYTES: usize = 128;
pub const DEFAULT_MAX_OPERATIONS: usize = 16;

pub const Params = struct {
    max_accounts: usize = DEFAULT_MAX_ACCOUNTS,
    max_entries_per_account: usize = DEFAULT_MAX_ENTRIES_PER_ACCOUNT,
    max_account_bytes: usize = DEFAULT_MAX_ACCOUNT_BYTES,
    max_sender_bytes: usize = DEFAULT_MAX_SENDER_BYTES,
    max_operations: usize = DEFAULT_MAX_OPERATIONS,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidCommand,
    InvalidAction,
    InvalidAccount,
    AccountTooLong,
    InvalidSender,
    SenderTooLong,
    TooManyAccounts,
    TooManyEntries,
    TooManyOperations,
    OutputTooSmall,
};

pub const Action = enum {
    add,
    remove,
    list,
};

pub const SenderKind = enum {
    account,
    mask,
};

pub const Operation = struct {
    action: Action,
    sender: []const u8 = "",
};

pub const Entry = struct {
    sender: []const u8,
    kind: SenderKind,
};

pub fn RequestType(comptime max_operations: usize) type {
    if (max_operations == 0) @compileError("MEMOIGNORE request needs at least one operation slot");

    return struct {
        const Self = @This();

        operations: [max_operations]Operation = undefined,
        count: usize = 0,

        pub fn slice(self: *const Self) []const Operation {
            return self.operations[0..self.count];
        }

        fn append(self: *Self, op: Operation) Error!void {
            if (self.count >= self.operations.len) return error.TooManyOperations;
            self.operations[self.count] = op;
            self.count += 1;
        }
    };
}

pub const Request = RequestType(DEFAULT_MAX_OPERATIONS);

pub fn MemoIgnoreListWith(comptime params: Params) type {
    comptime {
        if (params.max_accounts == 0) @compileError("MemoIgnoreList needs account storage");
        if (params.max_entries_per_account == 0) @compileError("MemoIgnoreList needs entry storage");
        if (params.max_account_bytes == 0) @compileError("MemoIgnoreList needs account names");
        if (params.max_sender_bytes == 0) @compileError("MemoIgnoreList needs sender patterns");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        accounts: std.StringHashMap(SenderSet),

        const SenderSet = struct {
            items: std.ArrayListUnmanaged(StoredSender) = .empty,

            fn deinit(self: *SenderSet, allocator: std.mem.Allocator) void {
                for (self.items.items) |*item| item.deinit(allocator);
                self.items.deinit(allocator);
            }

            fn indexOf(self: *const SenderSet, sender: []const u8) ?usize {
                for (self.items.items, 0..) |item, index| {
                    if (asciiEql(item.sender, sender)) return index;
                }
                return null;
            }
        };

        const StoredSender = struct {
            sender: []u8,
            kind: SenderKind,

            fn view(self: *const StoredSender) Entry {
                return .{ .sender = self.sender, .kind = self.kind };
            }

            fn deinit(self: *StoredSender, allocator: std.mem.Allocator) void {
                allocator.free(self.sender);
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .accounts = std.StringHashMap(SenderSet).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.accounts.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.accounts.deinit();
            self.* = undefined;
        }

        /// Add a sender account or glob mask to `recipient`'s memo-ignore list.
        /// Returns false for duplicate entries.
        pub fn add(self: *Self, recipient: []const u8, sender: []const u8) Error!bool {
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const recipient_key = try accountKeyWith(params, recipient, &recipient_buf);
            try validateSenderWith(params, sender);

            const set = try self.ensureRecipient(recipient_key);
            if (set.indexOf(sender) != null) return false;
            if (set.items.items.len >= params.max_entries_per_account) return error.TooManyEntries;

            const owned_sender = try self.allocator.dupe(u8, sender);
            errdefer self.allocator.free(owned_sender);
            try set.items.append(self.allocator, .{
                .sender = owned_sender,
                .kind = classifySender(sender),
            });
            return true;
        }

        /// Remove a sender account or glob mask from `recipient`'s list.
        /// Returns false when the entry is absent.
        pub fn remove(self: *Self, recipient: []const u8, sender: []const u8) Error!bool {
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const recipient_key = try accountKeyWith(params, recipient, &recipient_buf);
            try validateSenderWith(params, sender);

            const entry = self.accounts.getEntry(recipient_key) orelse return false;
            const index = entry.value_ptr.indexOf(sender) orelse return false;
            var removed = entry.value_ptr.items.orderedRemove(index);
            removed.deinit(self.allocator);

            if (entry.value_ptr.items.items.len == 0) self.dropRecipient(entry);
            return true;
        }

        /// Copy `recipient`'s entries into caller storage.
        ///
        /// Returned sender slices are borrowed and stay valid until the next
        /// mutation affecting that recipient or until `deinit`.
        pub fn list(self: *const Self, recipient: []const u8, out: []Entry) Error![]const Entry {
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const recipient_key = try accountKeyWith(params, recipient, &recipient_buf);
            const set = self.accounts.getPtr(recipient_key) orelse return out[0..0];
            if (out.len < set.items.items.len) return error.OutputTooSmall;

            for (set.items.items, 0..) |*item, index| out[index] = item.view();
            return out[0..set.items.items.len];
        }

        /// Return true when a memo from `sender` to `recipient` should be stored.
        ///
        /// Matching is ASCII case-insensitive. Literal account entries match
        /// exactly; mask entries support `*` and `?` globs.
        pub fn shouldAccept(self: *const Self, recipient: []const u8, sender: []const u8) Error!bool {
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const recipient_key = try accountKeyWith(params, recipient, &recipient_buf);
            try validateSenderWith(params, sender);

            const set = self.accounts.getPtr(recipient_key) orelse return true;
            for (set.items.items) |item| {
                const blocked = switch (item.kind) {
                    .account => asciiEql(item.sender, sender),
                    .mask => globMatch(item.sender, sender),
                };
                if (blocked) return false;
            }
            return true;
        }

        pub fn count(self: *const Self, recipient: []const u8) Error!usize {
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const recipient_key = try accountKeyWith(params, recipient, &recipient_buf);
            const set = self.accounts.getPtr(recipient_key) orelse return 0;
            return set.items.items.len;
        }

        /// Helix may need to restore a recipient row whose first add failed
        /// after creating the row. It has no entries, but is still live state.
        pub fn checkpointEnsureRecipient(self: *Self, recipient: []const u8) Error!void {
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const recipient_key = try accountKeyWith(params, recipient, &recipient_buf);
            _ = try self.ensureRecipient(recipient_key);
        }

        fn ensureRecipient(self: *Self, recipient_key: []const u8) Error!*SenderSet {
            if (self.accounts.getPtr(recipient_key)) |set| return set;
            if (self.accounts.count() >= params.max_accounts) return error.TooManyAccounts;

            const owned_recipient = try self.allocator.dupe(u8, recipient_key);
            errdefer self.allocator.free(owned_recipient);
            try self.accounts.putNoClobber(owned_recipient, .{});
            return self.accounts.getPtr(owned_recipient).?;
        }

        fn dropRecipient(self: *Self, entry: std.StringHashMap(SenderSet).Entry) void {
            const owned_recipient = entry.key_ptr.*;
            entry.value_ptr.deinit(self.allocator);
            self.accounts.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_recipient);
        }
    };
}

pub const MemoIgnoreList = MemoIgnoreListWith(.{});

pub fn parse(params: []const []const u8) Error!Request {
    return parseWith(.{}, params);
}

pub fn parseWith(comptime params_config: Params, params: []const []const u8) Error!RequestType(params_config.max_operations) {
    var request = RequestType(params_config.max_operations){};
    if (params.len == 0) {
        try request.append(.{ .action = .list });
        return request;
    }

    const action = try parseAction(params[0]);
    switch (action) {
        .list => {
            if (params.len != 1) return error.InvalidSender;
            try request.append(.{ .action = .list });
        },
        .add, .remove => {
            if (params.len < 2) return error.InvalidSender;
            for (params[1..]) |sender| {
                try validateSenderWith(params_config, sender);
                try request.append(.{ .action = action, .sender = sender });
            }
        },
    }
    return request;
}

pub fn parseLine(line: []const u8) Error!Request {
    return parseLineWith(.{}, line);
}

pub fn parseLineWith(comptime params_config: Params, line: []const u8) Error!RequestType(params_config.max_operations) {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    const command = "MEMOIGNORE";
    if (trimmed.len < command.len) return error.InvalidCommand;
    if (!asciiEql(trimmed[0..command.len], command)) return error.InvalidCommand;
    if (trimmed.len == command.len) return parseWith(params_config, &.{});
    if (trimmed[command.len] != ' ' and trimmed[command.len] != '\t') return error.InvalidCommand;

    var tokens: [params_config.max_operations + 1][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, trimmed[command.len..], " \t");
    while (it.next()) |token| {
        if (count >= tokens.len) return error.TooManyOperations;
        tokens[count] = token;
        count += 1;
    }
    return parseWith(params_config, tokens[0..count]);
}

pub fn parseAction(token: []const u8) Error!Action {
    if (asciiEql(token, "ADD")) return .add;
    if (asciiEql(token, "+")) return .add;
    if (asciiEql(token, "DEL")) return .remove;
    if (asciiEql(token, "DELETE")) return .remove;
    if (asciiEql(token, "REMOVE")) return .remove;
    if (asciiEql(token, "-")) return .remove;
    if (asciiEql(token, "LIST")) return .list;
    return error.InvalidAction;
}

pub fn classifySender(sender: []const u8) SenderKind {
    for (sender) |byte| {
        switch (byte) {
            '*', '?', '!', '@' => return .mask,
            else => {},
        }
    }
    return .account;
}

pub fn validateAccount(account: []const u8) Error!void {
    try validateAccountWith(.{}, account);
}

pub fn validateAccountWith(comptime params: Params, account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    try validateToken(account, error.InvalidAccount);
}

pub fn validateSender(sender: []const u8) Error!void {
    try validateSenderWith(.{}, sender);
}

pub fn validateSenderWith(comptime params: Params, sender: []const u8) Error!void {
    if (sender.len == 0) return error.InvalidSender;
    if (sender.len > params.max_sender_bytes) return error.SenderTooLong;
    try validateToken(sender, error.InvalidSender);
}

pub fn globMatch(pattern: []const u8, value: []const u8) bool {
    var pattern_index: usize = 0;
    var value_index: usize = 0;
    var star_index: ?usize = null;
    var retry_value_index: usize = 0;

    while (value_index < value.len) {
        if (pattern_index < pattern.len and (pattern[pattern_index] == '?' or asciiLower(pattern[pattern_index]) == asciiLower(value[value_index]))) {
            pattern_index += 1;
            value_index += 1;
        } else if (pattern_index < pattern.len and pattern[pattern_index] == '*') {
            star_index = pattern_index;
            pattern_index += 1;
            retry_value_index = value_index;
        } else if (star_index) |star| {
            pattern_index = star + 1;
            retry_value_index += 1;
            value_index = retry_value_index;
        } else {
            return false;
        }
    }

    while (pattern_index < pattern.len and pattern[pattern_index] == '*') pattern_index += 1;
    return pattern_index == pattern.len;
}

fn accountKeyWith(comptime params: Params, account: []const u8, out: *[params.max_account_bytes]u8) Error![]const u8 {
    try validateAccountWith(params, account);
    for (account, 0..) |byte, index| out[index] = asciiLower(byte);
    return out[0..account.len];
}

fn validateToken(token: []const u8, comptime err: Error) Error!void {
    for (token) |byte| {
        switch (byte) {
            0, ',', ' ', '\t', '\r', '\n' => return err,
            else => {},
        }
        if (byte < 0x21 or byte == 0x7f) return err;
    }
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (asciiLower(left) != asciiLower(right)) return false;
    }
    return true;
}

fn asciiLower(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte + ('a' - 'A') else byte;
}

const testing = std.testing;

test "standalone module imports only std by construction" {
    try testing.expect(@bitSizeOf(usize) == 64);
}

test "add list duplicate and remove entries" {
    var ignores = MemoIgnoreList.init(testing.allocator);
    defer ignores.deinit();

    try testing.expect(try ignores.add("alice", "bob"));
    try testing.expect(!try ignores.add("ALICE", "BOB"));
    try testing.expect(try ignores.add("alice", "*!bad@example.test"));

    var out: [2]Entry = undefined;
    const listed = try ignores.list("aLiCe", &out);
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("bob", listed[0].sender);
    try testing.expectEqual(SenderKind.account, listed[0].kind);
    try testing.expectEqualStrings("*!bad@example.test", listed[1].sender);
    try testing.expectEqual(SenderKind.mask, listed[1].kind);

    try testing.expect(try ignores.remove("ALICE", "bob"));
    try testing.expect(!try ignores.remove("alice", "bob"));
    try testing.expectEqual(@as(usize, 1), try ignores.count("alice"));
}

test "empty recipient is pruned after last removal" {
    var ignores = MemoIgnoreList.init(testing.allocator);
    defer ignores.deinit();

    try testing.expect(try ignores.add("alice", "bob"));
    try testing.expect(try ignores.remove("ALICE", "BOB"));

    var out: [1]Entry = undefined;
    try testing.expectEqual(@as(usize, 0), (try ignores.list("alice", &out)).len);
    try testing.expect(try ignores.shouldAccept("alice", "bob"));
}

test "shouldAccept rejects exact account case-insensitively" {
    var ignores = MemoIgnoreList.init(testing.allocator);
    defer ignores.deinit();

    try testing.expect(try ignores.add("Alice", "BadSender"));
    try testing.expect(!try ignores.shouldAccept("alice", "badsender"));
    try testing.expect(try ignores.shouldAccept("alice", "friendly"));
    try testing.expect(try ignores.shouldAccept("other", "badsender"));
}

test "shouldAccept rejects glob masks case-insensitively" {
    var ignores = MemoIgnoreList.init(testing.allocator);
    defer ignores.deinit();

    try testing.expect(try ignores.add("alice", "bad*!*@*.Example.Test"));
    try testing.expect(!try ignores.shouldAccept("ALICE", "BadNick!u@chat.example.test"));
    try testing.expect(!try ignores.shouldAccept("alice", "bad!@x.example.test"));
    try testing.expect(try ignores.shouldAccept("alice", "good!u@chat.example.test"));
}

test "globMatch supports star question and trailing star" {
    try testing.expect(globMatch("a?c", "abc"));
    try testing.expect(globMatch("a*", "abcdef"));
    try testing.expect(globMatch("*@example.*", "user@example.test"));
    try testing.expect(globMatch("**BAD**", "verybadname"));
    try testing.expect(!globMatch("a?c", "ac"));
    try testing.expect(!globMatch("*@example.test", "user@example.net"));
}

test "parse server command line without service pseudo-client names" {
    const add_req = try parseLine("MEMOIGNORE ADD bob *!*@example.test");
    try testing.expectEqual(@as(usize, 2), add_req.count);
    try testing.expectEqual(Action.add, add_req.operations[0].action);
    try testing.expectEqualStrings("bob", add_req.operations[0].sender);
    try testing.expectEqualStrings("*!*@example.test", add_req.operations[1].sender);

    const remove_req = try parseLine("memoignore remove bob");
    try testing.expectEqual(@as(usize, 1), remove_req.count);
    try testing.expectEqual(Action.remove, remove_req.operations[0].action);

    const list_req = try parseLine("MEMOIGNORE LIST");
    try testing.expectEqual(@as(usize, 1), list_req.count);
    try testing.expectEqual(Action.list, list_req.operations[0].action);
}

test "parse bare command as list and reject pseudo-client commands" {
    const list_req = try parseLine("MEMOIGNORE");
    try testing.expectEqual(@as(usize, 1), list_req.count);
    try testing.expectEqual(Action.list, list_req.operations[0].action);

    try testing.expectError(error.InvalidCommand, parseLine("MEMOSERV IGNORE ADD bob"));
    try testing.expectError(error.InvalidCommand, parseLine("NickServ MEMOIGNORE ADD bob"));
    try testing.expectError(error.InvalidAction, parse(&.{"BLOCK"}));
}

test "parse bounds and validation errors are stable" {
    try testing.expectError(error.InvalidSender, parse(&.{ "ADD", "" }));
    try testing.expectError(error.InvalidSender, parse(&.{ "ADD", "bad sender" }));
    try testing.expectError(error.InvalidSender, parse(&.{ "LIST", "extra" }));
    try testing.expectError(error.TooManyOperations, parseWith(.{ .max_operations = 1 }, &.{ "ADD", "a", "b" }));
    try testing.expectError(error.TooManyOperations, parseLineWith(.{ .max_operations = 1 }, "MEMOIGNORE ADD a b"));
}

test "store enforces account entry and output bounds" {
    const Tiny = MemoIgnoreListWith(.{
        .max_accounts = 1,
        .max_entries_per_account = 1,
        .max_account_bytes = 5,
        .max_sender_bytes = 5,
    });
    var ignores = Tiny.init(testing.allocator);
    defer ignores.deinit();

    try testing.expect(try ignores.add("alice", "bob"));
    try testing.expectError(error.TooManyEntries, ignores.add("alice", "carol"));
    try testing.expectError(error.TooManyAccounts, ignores.add("other", "bob"));
    try testing.expectError(error.AccountTooLong, ignores.add("toolong", "bob"));
    try testing.expectError(error.SenderTooLong, ignores.add("alice", "longer"));

    var short: [0]Entry = undefined;
    try testing.expectError(error.OutputTooSmall, ignores.list("alice", &short));
}

test "validation rejects empty and control-delimited tokens" {
    try testing.expectError(error.InvalidAccount, validateAccount(""));
    try testing.expectError(error.InvalidAccount, validateAccount("bad account"));
    try testing.expectError(error.InvalidSender, validateSender(""));
    try testing.expectError(error.InvalidSender, validateSender("bad,sender"));
    try testing.expectError(error.InvalidSender, validateSender("bad\nsender"));
}

test "churn releases all owned memory" {
    var ignores = MemoIgnoreList.init(testing.allocator);
    try testing.expect(try ignores.add("alice", "bob"));
    try testing.expect(try ignores.add("alice", "carol"));
    try testing.expect(try ignores.add("dave", "*!*@example.test"));
    try testing.expect(try ignores.remove("alice", "bob"));
    try testing.expect(try ignores.remove("alice", "carol"));
    ignores.deinit();
}
