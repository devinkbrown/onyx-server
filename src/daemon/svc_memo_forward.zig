// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure memo forwarding and read-receipt state for real services commands.
//!
//! This module deliberately imports only `std`: it owns no daemon integration
//! and creates no pseudo-client identity. Callers translate parsed commands and
//! numeric hints into Onyx Server's real server command/numeric path.

const std = @import("std");

pub const Params = struct {
    max_accounts: usize = 65536,
    max_account_bytes: usize = 64,
    max_memo_id_bytes: usize = 128,
    max_forward_hops: usize = 16,
    max_receipts_per_sender: usize = 4096,
};

pub const NumericHint = enum(u16) {
    ERR_NOSUCHNICK = 401,
    ERR_NEEDMOREPARAMS = 461,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_BADVALUE = 972,
    RPL_MEMOFORWARD = 988,
    RPL_MEMORECEIPT = 989,

    pub fn value(self: NumericHint) u16 {
        return @intFromEnum(self);
    }
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidAccount,
    AccountTooLong,
    InvalidMemoId,
    MemoIdTooLong,
    TooManyAccounts,
    TooManyReceipts,
    ForwardCycle,
    ForwardHopLimit,
};

pub const ParseError = error{
    EmptyCommand,
    UnknownCommand,
    MissingParameter,
    UnexpectedParameter,
    InvalidTimestamp,
    TimestampOverflow,
};

pub const ParsedCommand = union(enum) {
    forward_get,
    forward_clear,
    forward_set: []const u8,
    mark_read: MarkReadArgs,
    receipt_get: []const u8,
};

pub const MarkReadArgs = struct {
    memo_id: []const u8,
    sender_account: []const u8,
    read_at_ms: i64,
};

pub const ForwardDecision = struct {
    /// Borrows the caller's account with its original spelling.
    original_account: []const u8,
    /// With zero hops, borrows original_account unchanged. Otherwise borrows
    /// the normalized store target until its forwarding entry is changed or
    /// removed, or the store is deinitialized. Resolving never allocates.
    delivery_account: []const u8,
    forwarded: bool,
    hops: usize,
};

pub const ReadReceipt = struct {
    memo_id: []const u8,
    recipient_account: []const u8,
    read_at_ms: i64,
};

const ForwardState = struct {
    target: []u8,
};

const ReceiptState = struct {
    memo_id: []u8,
    recipient_account: []u8,
    read_at_ms: i64,

    fn deinit(self: *ReceiptState, allocator: std.mem.Allocator) void {
        allocator.free(self.memo_id);
        allocator.free(self.recipient_account);
    }

    fn view(self: *const ReceiptState) ReadReceipt {
        return .{
            .memo_id = self.memo_id,
            .recipient_account = self.recipient_account,
            .read_at_ms = self.read_at_ms,
        };
    }
};

const SenderReceipts = struct {
    receipts: std.StringHashMap(ReceiptState),

    fn init(allocator: std.mem.Allocator) SenderReceipts {
        return .{ .receipts = std.StringHashMap(ReceiptState).init(allocator) };
    }

    fn deinit(self: *SenderReceipts, allocator: std.mem.Allocator) void {
        var it = self.receipts.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        self.receipts.deinit();
    }
};

pub const MemoForwardStore = MemoForwardStoreWith(.{});

pub fn MemoForwardStoreWith(comptime params: Params) type {
    comptime {
        if (params.max_accounts == 0) @compileError("MemoForwardStore needs account capacity");
        if (params.max_account_bytes == 0) @compileError("MemoForwardStore needs account bytes");
        if (params.max_forward_hops == 0) @compileError("MemoForwardStore needs forward hop capacity");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        forwards: std.StringHashMap(ForwardState),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .forwards = std.StringHashMap(ForwardState).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.forwards.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.target);
            }
            self.forwards.deinit();
            self.* = undefined;
        }

        pub fn setForward(self: *Self, account: []const u8, target_account: []const u8) Error!void {
            try validateAccountWith(params, account);
            try validateAccountWith(params, target_account);

            var account_buf: [params.max_account_bytes]u8 = undefined;
            var target_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = lowerAccountWith(params, account, &account_buf);
            const target_key = lowerAccountWith(params, target_account, &target_buf);
            if (std.mem.eql(u8, account_key, target_key)) return error.ForwardCycle;

            if (self.forwards.getEntry(account_key)) |entry| {
                const owned_target = try self.allocator.dupe(u8, target_key);
                self.allocator.free(entry.value_ptr.target);
                entry.value_ptr.target = owned_target;
                return;
            }

            if (self.forwards.count() >= params.max_accounts) return error.TooManyAccounts;
            const owned_account = try self.allocator.dupe(u8, account_key);
            errdefer self.allocator.free(owned_account);
            const owned_target = try self.allocator.dupe(u8, target_key);
            errdefer self.allocator.free(owned_target);
            try self.forwards.putNoClobber(owned_account, .{ .target = owned_target });
        }

        pub fn clearForward(self: *Self, account: []const u8) Error!bool {
            try validateAccountWith(params, account);
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = lowerAccountWith(params, account, &account_buf);
            const entry = self.forwards.getEntry(account_key) orelse return false;
            self.allocator.free(entry.value_ptr.target);
            const owned_account = entry.key_ptr.*;
            self.forwards.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_account);
            return true;
        }

        pub fn forwardTarget(self: *const Self, account: []const u8) Error!?[]const u8 {
            try validateAccountWith(params, account);
            var account_buf: [params.max_account_bytes]u8 = undefined;
            const account_key = lowerAccountWith(params, account, &account_buf);
            const state = self.forwards.getPtr(account_key) orelse return null;
            return state.target;
        }

        pub fn resolveDelivery(self: *const Self, account: []const u8) Error!ForwardDecision {
            try validateAccountWith(params, account);
            var original_buf: [params.max_account_bytes]u8 = undefined;
            const original = lowerAccountWith(params, account, &original_buf);
            var current = original;
            var seen: [params.max_forward_hops + 1][]const u8 = undefined;
            seen[0] = current;

            var hops: usize = 0;
            while (self.forwards.getPtr(current)) |state| {
                if (hops >= params.max_forward_hops) return error.ForwardHopLimit;
                for (seen[0 .. hops + 1]) |prior| {
                    if (std.mem.eql(u8, prior, state.target)) return error.ForwardCycle;
                }
                hops += 1;
                seen[hops] = state.target;
                current = state.target;
            }

            return .{
                .original_account = account,
                .delivery_account = if (hops == 0) account else current,
                .forwarded = hops != 0,
                .hops = hops,
            };
        }

        pub fn count(self: *const Self) usize {
            return self.forwards.count();
        }
    };
}

pub const MemoReadReceiptStore = MemoReadReceiptStoreWith(.{});

pub fn MemoReadReceiptStoreWith(comptime params: Params) type {
    comptime {
        if (params.max_accounts == 0) @compileError("MemoReadReceiptStore needs account capacity");
        if (params.max_account_bytes == 0) @compileError("MemoReadReceiptStore needs account bytes");
        if (params.max_memo_id_bytes == 0) @compileError("MemoReadReceiptStore needs memo id bytes");
        if (params.max_receipts_per_sender == 0) @compileError("MemoReadReceiptStore needs receipt capacity");
    }

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        senders: std.StringHashMap(SenderReceipts),

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .senders = std.StringHashMap(SenderReceipts).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var it = self.senders.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.senders.deinit();
            self.* = undefined;
        }

        pub fn markRead(
            self: *Self,
            sender_account: []const u8,
            recipient_account: []const u8,
            memo_id: []const u8,
            read_at_ms: i64,
        ) Error!void {
            try validateAccountWith(params, sender_account);
            try validateAccountWith(params, recipient_account);
            try validateMemoIdWith(params, memo_id);

            var sender_buf: [params.max_account_bytes]u8 = undefined;
            var recipient_buf: [params.max_account_bytes]u8 = undefined;
            const sender_key = lowerAccountWith(params, sender_account, &sender_buf);
            const recipient_key = lowerAccountWith(params, recipient_account, &recipient_buf);
            const sender = try self.ensureSender(sender_key);

            if (sender.receipts.getPtr(memo_id)) |state| {
                state.read_at_ms = read_at_ms;
                if (!std.mem.eql(u8, state.recipient_account, recipient_key)) {
                    const owned_recipient = try self.allocator.dupe(u8, recipient_key);
                    self.allocator.free(state.recipient_account);
                    state.recipient_account = owned_recipient;
                }
                return;
            }

            if (sender.receipts.count() >= params.max_receipts_per_sender) return error.TooManyReceipts;
            const owned_memo_id = try self.allocator.dupe(u8, memo_id);
            errdefer self.allocator.free(owned_memo_id);
            const owned_recipient = try self.allocator.dupe(u8, recipient_key);
            errdefer self.allocator.free(owned_recipient);
            try sender.receipts.putNoClobber(owned_memo_id, .{
                .memo_id = owned_memo_id,
                .recipient_account = owned_recipient,
                .read_at_ms = read_at_ms,
            });
        }

        pub fn receipt(self: *const Self, sender_account: []const u8, memo_id: []const u8) Error!?ReadReceipt {
            try validateAccountWith(params, sender_account);
            try validateMemoIdWith(params, memo_id);

            var sender_buf: [params.max_account_bytes]u8 = undefined;
            const sender_key = lowerAccountWith(params, sender_account, &sender_buf);
            const sender = self.senders.getPtr(sender_key) orelse return null;
            const state = sender.receipts.getPtr(memo_id) orelse return null;
            return state.view();
        }

        pub fn clearReceipt(self: *Self, sender_account: []const u8, memo_id: []const u8) Error!bool {
            try validateAccountWith(params, sender_account);
            try validateMemoIdWith(params, memo_id);

            var sender_buf: [params.max_account_bytes]u8 = undefined;
            const sender_key = lowerAccountWith(params, sender_account, &sender_buf);
            const sender_entry = self.senders.getEntry(sender_key) orelse return false;
            const receipt_entry = sender_entry.value_ptr.receipts.getEntry(memo_id) orelse return false;
            receipt_entry.value_ptr.deinit(self.allocator);
            sender_entry.value_ptr.receipts.removeByPtr(receipt_entry.key_ptr);

            if (sender_entry.value_ptr.receipts.count() == 0) {
                sender_entry.value_ptr.deinit(self.allocator);
                const owned_sender = sender_entry.key_ptr.*;
                self.senders.removeByPtr(sender_entry.key_ptr);
                self.allocator.free(owned_sender);
            }
            return true;
        }

        pub fn countForSender(self: *const Self, sender_account: []const u8) Error!usize {
            try validateAccountWith(params, sender_account);
            var sender_buf: [params.max_account_bytes]u8 = undefined;
            const sender_key = lowerAccountWith(params, sender_account, &sender_buf);
            const sender = self.senders.getPtr(sender_key) orelse return 0;
            return sender.receipts.count();
        }

        fn ensureSender(self: *Self, sender_key: []const u8) Error!*SenderReceipts {
            if (self.senders.getPtr(sender_key)) |sender| return sender;
            if (self.senders.count() >= params.max_accounts) return error.TooManyAccounts;
            const owned_sender = try self.allocator.dupe(u8, sender_key);
            errdefer self.allocator.free(owned_sender);
            try self.senders.putNoClobber(owned_sender, SenderReceipts.init(self.allocator));
            return self.senders.getPtr(owned_sender).?;
        }
    };
}

pub fn parseServicePayload(input: []const u8) ParseError!ParsedCommand {
    var it = std.mem.tokenizeAny(u8, input, " \t\r\n");
    const command = it.next() orelse return error.EmptyCommand;

    if (asciiEql(command, "FORWARD")) {
        const op = it.next() orelse return error.MissingParameter;
        if (asciiEql(op, "GET")) {
            if (it.next() != null) return error.UnexpectedParameter;
            return .forward_get;
        }
        if (asciiEql(op, "OFF") or asciiEql(op, "CLEAR")) {
            if (it.next() != null) return error.UnexpectedParameter;
            return .forward_clear;
        }
        if (asciiEql(op, "SET")) {
            const target = it.next() orelse return error.MissingParameter;
            if (it.next() != null) return error.UnexpectedParameter;
            return .{ .forward_set = target };
        }
        return error.UnknownCommand;
    }

    if (asciiEql(command, "READ")) {
        const memo_id = it.next() orelse return error.MissingParameter;
        const sender = it.next() orelse return error.MissingParameter;
        const ts_text = it.next() orelse return error.MissingParameter;
        if (it.next() != null) return error.UnexpectedParameter;
        return .{ .mark_read = .{
            .memo_id = memo_id,
            .sender_account = sender,
            .read_at_ms = try parseTimestamp(ts_text),
        } };
    }

    if (asciiEql(command, "RECEIPT")) {
        const memo_id = it.next() orelse return error.MissingParameter;
        if (it.next() != null) return error.UnexpectedParameter;
        return .{ .receipt_get = memo_id };
    }

    return error.UnknownCommand;
}

pub fn validateAccount(account: []const u8) Error!void {
    return validateAccountWith(.{}, account);
}

pub fn validateMemoId(memo_id: []const u8) Error!void {
    return validateMemoIdWith(.{}, memo_id);
}

pub fn numericForError(err: anyerror) ?NumericHint {
    return switch (err) {
        error.EmptyCommand,
        error.UnknownCommand,
        => .ERR_UNKNOWNCOMMAND,
        error.MissingParameter,
        error.UnexpectedParameter,
        => .ERR_NEEDMOREPARAMS,
        error.InvalidAccount,
        error.AccountTooLong,
        error.InvalidMemoId,
        error.MemoIdTooLong,
        error.InvalidTimestamp,
        error.TimestampOverflow,
        error.ForwardCycle,
        error.ForwardHopLimit,
        => .ERR_BADVALUE,
        else => null,
    };
}

fn validateAccountWith(comptime params: Params, account: []const u8) Error!void {
    if (account.len == 0) return error.InvalidAccount;
    if (account.len > params.max_account_bytes) return error.AccountTooLong;
    for (account) |byte| {
        if (!isAccountByte(byte)) return error.InvalidAccount;
    }
}

fn validateMemoIdWith(comptime params: Params, memo_id: []const u8) Error!void {
    if (memo_id.len == 0) return error.InvalidMemoId;
    if (memo_id.len > params.max_memo_id_bytes) return error.MemoIdTooLong;
    for (memo_id) |byte| {
        if (!isMemoIdByte(byte)) return error.InvalidMemoId;
    }
}

fn lowerAccountWith(comptime params: Params, account: []const u8, buf: *[params.max_account_bytes]u8) []const u8 {
    for (account, 0..) |byte, idx| buf[idx] = std.ascii.toLower(byte);
    return buf[0..account.len];
}

fn parseTimestamp(text: []const u8) ParseError!i64 {
    if (text.len == 0) return error.InvalidTimestamp;
    if (text[0] == '-') return error.InvalidTimestamp;
    return std.fmt.parseInt(i64, text, 10) catch |err| switch (err) {
        error.InvalidCharacter => error.InvalidTimestamp,
        error.Overflow => error.TimestampOverflow,
    };
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn isAccountByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.';
}

fn isMemoIdByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.' or byte == ':';
}

const testing = std.testing;

test "forward target is optional and case normalized" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectEqual(@as(?[]const u8, null), try store.forwardTarget("Alice"));
    try store.setForward("Alice", "Bob.Backup");
    const target = (try store.forwardTarget("alice")).?;
    try testing.expectEqualStrings("bob.backup", target);
    try testing.expectEqual(@as(usize, 1), store.count());
}

test "setting an existing forward target replaces owned target without growing store" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    try store.setForward("alice", "bob");
    try store.setForward("ALICE", "carol");
    try testing.expectEqual(@as(usize, 1), store.count());
    try testing.expectEqualStrings("carol", (try store.forwardTarget("alice")).?);
}

test "clear forward removes only the requested account" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    try store.setForward("alice", "bob");
    try store.setForward("carol", "dave");
    try testing.expect(try store.clearForward("ALICE"));
    try testing.expect(!try store.clearForward("alice"));
    try testing.expectEqual(@as(?[]const u8, null), try store.forwardTarget("alice"));
    try testing.expectEqualStrings("dave", (try store.forwardTarget("carol")).?);
}

test "resolve delivery follows forward chain" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    try store.setForward("alice", "bob");
    try store.setForward("bob", "carol");
    const decision = try store.resolveDelivery("ALICE");
    try testing.expect(decision.forwarded);
    try testing.expectEqual(@as(usize, 2), decision.hops);
    try testing.expectEqualStrings("ALICE", decision.original_account);
    try testing.expectEqualStrings("carol", decision.delivery_account);
}

test "resolve delivery reports unforwarded account" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    const decision = try store.resolveDelivery("Alice");
    try testing.expect(!decision.forwarded);
    try testing.expectEqual(@as(usize, 0), decision.hops);
    try testing.expectEqualStrings("Alice", decision.original_account);
    try testing.expectEqualStrings("Alice", decision.delivery_account);
    try testing.expectEqual(decision.original_account.ptr, decision.delivery_account.ptr);
}

test "resolve delivery borrows caller storage across repeated resolutions" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    var account = [_]u8{ 'A', 'l', 'i', 'c', 'e' };
    const first = try store.resolveDelivery(&account);
    try testing.expectEqual(account[0..].ptr, first.delivery_account.ptr);
    const second = try store.resolveDelivery("A_DIFFERENT_ACCOUNT");
    try testing.expectEqualStrings("A_DIFFERENT_ACCOUNT", second.delivery_account);
    try testing.expectEqualStrings("Alice", first.delivery_account);
    account[0] = 'a';
    try testing.expectEqualStrings("alice", first.delivery_account);
}

test "resolve delivery allocates neither direct nor forwarded decisions" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var store = MemoForwardStore.init(failing.allocator());
    defer store.deinit();

    try store.setForward("Alice", "Bob");
    try store.setForward("Bob", "Carol");
    const allocations = failing.alloc_index;
    failing.fail_index = allocations;
    const direct = try store.resolveDelivery("Direct");
    const forwarded = try store.resolveDelivery("ALICE");
    try testing.expectEqualStrings("Direct", direct.delivery_account);
    try testing.expectEqualStrings("carol", forwarded.delivery_account);
    try testing.expectEqual(@as(usize, 2), forwarded.hops);
    try testing.expectEqual(allocations, failing.alloc_index);
    try testing.expect(!failing.has_induced_failure);
}

test "forward cycles and self-forward are rejected" {
    var store = MemoForwardStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectError(error.ForwardCycle, store.setForward("alice", "ALICE"));
    try store.setForward("alice", "bob");
    try store.setForward("bob", "carol");
    try store.setForward("carol", "alice");
    try testing.expectError(error.ForwardCycle, store.resolveDelivery("alice"));
}

test "forward hop limit is enforced before unbounded traversal" {
    const SmallStore = MemoForwardStoreWith(.{ .max_accounts = 8, .max_forward_hops = 2 });
    var store = SmallStore.init(testing.allocator);
    defer store.deinit();

    try store.setForward("a", "b");
    try store.setForward("b", "c");
    try store.setForward("c", "d");
    try testing.expectError(error.ForwardHopLimit, store.resolveDelivery("a"));
}

test "forward validation rejects invalid names and capacity overflow" {
    const SmallStore = MemoForwardStoreWith(.{ .max_accounts = 1, .max_account_bytes = 4 });
    var store = SmallStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectError(error.InvalidAccount, store.setForward("", "b"));
    try testing.expectError(error.InvalidAccount, store.setForward("a!", "b"));
    try testing.expectError(error.AccountTooLong, store.setForward("alice", "b"));
    try store.setForward("a", "b");
    try testing.expectError(error.TooManyAccounts, store.setForward("c", "d"));
}

test "mark read creates receipt visible to sender query" {
    var receipts = MemoReadReceiptStore.init(testing.allocator);
    defer receipts.deinit();

    try receipts.markRead("Alice", "Bob", "memo:1", 12345);
    const got = (try receipts.receipt("alice", "memo:1")).?;
    try testing.expectEqualStrings("memo:1", got.memo_id);
    try testing.expectEqualStrings("bob", got.recipient_account);
    try testing.expectEqual(@as(i64, 12345), got.read_at_ms);
    try testing.expectEqual(@as(usize, 1), try receipts.countForSender("ALICE"));
}

test "mark read updates timestamp and recipient for an existing memo id" {
    var receipts = MemoReadReceiptStore.init(testing.allocator);
    defer receipts.deinit();

    try receipts.markRead("alice", "bob", "m1", 10);
    try receipts.markRead("ALICE", "carol", "m1", 20);
    const got = (try receipts.receipt("alice", "m1")).?;
    try testing.expectEqualStrings("carol", got.recipient_account);
    try testing.expectEqual(@as(i64, 20), got.read_at_ms);
    try testing.expectEqual(@as(usize, 1), try receipts.countForSender("alice"));
}

test "read receipts are isolated by sender account" {
    var receipts = MemoReadReceiptStore.init(testing.allocator);
    defer receipts.deinit();

    try receipts.markRead("alice", "bob", "m1", 10);
    try receipts.markRead("carol", "dave", "m1", 30);
    try testing.expectEqualStrings("bob", (try receipts.receipt("alice", "m1")).?.recipient_account);
    try testing.expectEqualStrings("dave", (try receipts.receipt("carol", "m1")).?.recipient_account);
    try testing.expectEqual(@as(?ReadReceipt, null), try receipts.receipt("eve", "m1"));
}

test "clear receipt prunes empty sender bucket" {
    var receipts = MemoReadReceiptStore.init(testing.allocator);
    defer receipts.deinit();

    try receipts.markRead("alice", "bob", "m1", 10);
    try testing.expect(try receipts.clearReceipt("alice", "m1"));
    try testing.expect(!try receipts.clearReceipt("alice", "m1"));
    try testing.expectEqual(@as(usize, 0), try receipts.countForSender("alice"));
}

test "receipt validation rejects invalid account and memo ids" {
    var receipts = MemoReadReceiptStore.init(testing.allocator);
    defer receipts.deinit();

    try testing.expectError(error.InvalidAccount, receipts.markRead("", "bob", "m1", 0));
    try testing.expectError(error.InvalidAccount, receipts.markRead("alice", "bo b", "m1", 0));
    try testing.expectError(error.InvalidMemoId, receipts.markRead("alice", "bob", "", 0));
    try testing.expectError(error.InvalidMemoId, receipts.markRead("alice", "bob", "bad/memo", 0));
}

test "receipt capacity is enforced per sender" {
    const SmallReceipts = MemoReadReceiptStoreWith(.{ .max_receipts_per_sender = 2 });
    var receipts = SmallReceipts.init(testing.allocator);
    defer receipts.deinit();

    try receipts.markRead("alice", "bob", "m1", 1);
    try receipts.markRead("alice", "bob", "m2", 2);
    try testing.expectError(error.TooManyReceipts, receipts.markRead("alice", "bob", "m3", 3));
    try receipts.markRead("carol", "bob", "m3", 3);
}

test "parse forward commands" {
    try testing.expectEqual(.forward_get, try parseServicePayload("FORWARD GET"));
    try testing.expectEqual(.forward_clear, try parseServicePayload("forward off"));

    const set = try parseServicePayload("FORWARD SET Bob");
    switch (set) {
        .forward_set => |target| try testing.expectEqualStrings("Bob", target),
        else => return error.TestUnexpectedResult,
    }
}

test "parse read and receipt commands" {
    const read = try parseServicePayload("READ memo:1 Alice 987654");
    switch (read) {
        .mark_read => |args| {
            try testing.expectEqualStrings("memo:1", args.memo_id);
            try testing.expectEqualStrings("Alice", args.sender_account);
            try testing.expectEqual(@as(i64, 987654), args.read_at_ms);
        },
        else => return error.TestUnexpectedResult,
    }

    const receipt = try parseServicePayload("RECEIPT memo:1");
    switch (receipt) {
        .receipt_get => |memo_id| try testing.expectEqualStrings("memo:1", memo_id),
        else => return error.TestUnexpectedResult,
    }
}

test "parser rejects missing extra and malformed parameters" {
    try testing.expectError(error.EmptyCommand, parseServicePayload(" \t\r\n"));
    try testing.expectError(error.UnknownCommand, parseServicePayload("MEMOSERV HELP"));
    try testing.expectError(error.MissingParameter, parseServicePayload("FORWARD"));
    try testing.expectError(error.MissingParameter, parseServicePayload("FORWARD SET"));
    try testing.expectError(error.UnexpectedParameter, parseServicePayload("FORWARD GET extra"));
    try testing.expectError(error.InvalidTimestamp, parseServicePayload("READ m1 alice -1"));
    try testing.expectError(error.InvalidTimestamp, parseServicePayload("READ m1 alice yesterday"));
    try testing.expectError(error.TimestampOverflow, parseServicePayload("READ m1 alice 999999999999999999999999999999"));
}

test "numeric hints are data only for real server replies" {
    try testing.expectEqual(@as(u16, 988), NumericHint.RPL_MEMOFORWARD.value());
    try testing.expectEqual(@as(?NumericHint, .ERR_BADVALUE), numericForError(error.ForwardCycle));
    try testing.expectEqual(@as(?NumericHint, .ERR_NEEDMOREPARAMS), numericForError(error.MissingParameter));
    try testing.expectEqual(@as(?NumericHint, null), numericForError(error.OutOfMemory));
}
