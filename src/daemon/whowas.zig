// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WHOWAS history ring.
//!
//! The daemon records departing nick identities in a bounded ring so WHOWAS can
//! answer recent lookups without unbounded memory growth. Storage is allocated
//! once at init; add and query paths only copy into fixed-size slots and write
//! into caller-provided result buffers.
const std = @import("std");

/// Compile-time storage limits for a WHOWAS ring.
pub const Params = struct {
    capacity: usize,
    max_nick_len: usize = 32,
    max_user_len: usize = 32,
    max_host_len: usize = 255,
    max_realname_len: usize = 255,
    max_account_len: usize = 64,
    max_server_len: usize = 255,
};

/// Validation and storage errors for WHOWAS records.
pub const WhowasError = error{
    EmptyNick,
    NickTooLong,
    UserTooLong,
    HostTooLong,
    RealnameTooLong,
    AccountTooLong,
    ServerTooLong,
    InvalidNick,
    InvalidUser,
    InvalidHost,
    InvalidRealname,
    InvalidAccount,
    InvalidServer,
    NegativeSignoffTime,
};

/// Public view of a historical nick record.
///
/// Values returned from `query` borrow from the history ring and remain valid
/// until the corresponding slot is evicted or overwritten.
pub const Record = struct {
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    realname: []const u8,
    account: []const u8,
    signoff_time: i64,
    /// Origin server for mesh-replicated records; empty means the local node.
    server: []const u8 = "",
};

/// Bounded WHOWAS ring with fixed per-field storage.
pub fn Whowas(comptime params: Params) type {
    comptime validateParams(params);

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        slots: []Slot,
        next: usize = 0,
        count: usize = 0,

        /// Allocate ring storage. Add/query paths do not allocate afterward.
        pub fn init(allocator: std.mem.Allocator) !Self {
            return .{
                .allocator = allocator,
                .slots = try allocator.alloc(Slot, params.capacity),
                .next = 0,
                .count = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.slots);
            self.* = undefined;
        }

        /// Record a nick identity when a client quits.
        pub fn addOnQuit(self: *Self, record: Record) WhowasError!void {
            try self.add(record);
        }

        /// Record the old nick identity when a client changes nick.
        pub fn addOnNickChange(self: *Self, record: Record) WhowasError!void {
            try self.add(record);
        }

        /// Record a past nick identity, evicting the oldest slot at capacity.
        pub fn add(self: *Self, record: Record) WhowasError!void {
            try validateRecord(params, record);

            var slot = &self.slots[self.next];
            slot.write(record);

            self.next += 1;
            if (self.next == self.slots.len) self.next = 0;
            if (self.count < self.slots.len) self.count += 1;
        }

        /// Query records for `nick`, most-recent-first.
        ///
        /// At most `max_results` records are written, capped by `out.len`.
        /// Returned records borrow from the ring.
        pub fn query(
            self: *const Self,
            nick: []const u8,
            max_results: usize,
            out: []Record,
        ) WhowasError![]Record {
            try validateNick(params, nick);
            const limit = @min(max_results, out.len);
            if (limit == 0 or self.count == 0) return out[0..0];

            const wanted_hash = foldedHash(nick);
            var written: usize = 0;
            var scanned: usize = 0;
            var index = if (self.next == 0) self.slots.len - 1 else self.next - 1;

            while (scanned < self.count and written < limit) : (scanned += 1) {
                const slot = &self.slots[index];
                if (slot.nick_hash == wanted_hash and nickEqualsFolded(slot.nickFolded(), nick)) {
                    out[written] = slot.record();
                    written += 1;
                }
                index = if (index == 0) self.slots.len - 1 else index - 1;
            }

            return out[0..written];
        }

        pub fn len(self: *const Self) usize {
            return self.count;
        }

        pub fn capacity(self: *const Self) usize {
            return self.slots.len;
        }

        const Slot = struct {
            nick: [params.max_nick_len]u8 = undefined,
            nick_folded: [params.max_nick_len]u8 = undefined,
            user: [params.max_user_len]u8 = undefined,
            host: [params.max_host_len]u8 = undefined,
            realname: [params.max_realname_len]u8 = undefined,
            account: [params.max_account_len]u8 = undefined,
            server: [params.max_server_len]u8 = undefined,
            nick_len: usize = 0,
            user_len: usize = 0,
            host_len: usize = 0,
            realname_len: usize = 0,
            account_len: usize = 0,
            server_len: usize = 0,
            signoff_time: i64 = 0,
            nick_hash: u64 = 0,

            fn write(self: *Slot, source: Record) void {
                self.nick_len = source.nick.len;
                self.user_len = source.user.len;
                self.host_len = source.host.len;
                self.realname_len = source.realname.len;
                self.account_len = source.account.len;
                self.server_len = source.server.len;
                self.signoff_time = source.signoff_time;
                self.nick_hash = foldedHash(source.nick);

                copyBytes(self.nick[0..self.nick_len], source.nick);
                copyBytes(self.user[0..self.user_len], source.user);
                copyBytes(self.host[0..self.host_len], source.host);
                copyBytes(self.realname[0..self.realname_len], source.realname);
                copyBytes(self.account[0..self.account_len], source.account);
                copyBytes(self.server[0..self.server_len], source.server);
                for (source.nick, 0..) |ch, index| {
                    self.nick_folded[index] = foldNickByte(ch);
                }
            }

            fn record(self: *const Slot) Record {
                return .{
                    .nick = self.nick[0..self.nick_len],
                    .user = self.user[0..self.user_len],
                    .host = self.host[0..self.host_len],
                    .realname = self.realname[0..self.realname_len],
                    .account = self.account[0..self.account_len],
                    .signoff_time = self.signoff_time,
                    .server = self.server[0..self.server_len],
                };
            }

            fn nickFolded(self: *const Slot) []const u8 {
                return self.nick_folded[0..self.nick_len];
            }
        };
    };
}

fn validateParams(comptime params: Params) void {
    if (params.capacity == 0) @compileError("whowas capacity must be non-zero");
    if (params.max_nick_len == 0) @compileError("whowas max nick length must be non-zero");
    if (params.max_user_len == 0) @compileError("whowas max user length must be non-zero");
    if (params.max_host_len == 0) @compileError("whowas max host length must be non-zero");
}

fn validateRecord(comptime params: Params, record: Record) WhowasError!void {
    try validateNick(params, record.nick);
    if (record.user.len > params.max_user_len) return WhowasError.UserTooLong;
    if (record.host.len > params.max_host_len) return WhowasError.HostTooLong;
    if (record.realname.len > params.max_realname_len) return WhowasError.RealnameTooLong;
    if (record.account.len > params.max_account_len) return WhowasError.AccountTooLong;
    if (record.server.len > params.max_server_len) return WhowasError.ServerTooLong;
    if (!validSimpleField(record.user, false)) return WhowasError.InvalidUser;
    if (!validSimpleField(record.host, false)) return WhowasError.InvalidHost;
    if (!validSimpleField(record.realname, true)) return WhowasError.InvalidRealname;
    if (!validSimpleField(record.account, false)) return WhowasError.InvalidAccount;
    if (!validSimpleField(record.server, false)) return WhowasError.InvalidServer;
    if (record.signoff_time < 0) return WhowasError.NegativeSignoffTime;
}

fn validateNick(comptime params: Params, nick: []const u8) WhowasError!void {
    if (nick.len == 0) return WhowasError.EmptyNick;
    if (nick.len > params.max_nick_len) return WhowasError.NickTooLong;
    for (nick) |ch| {
        if (!validNickByte(ch)) return WhowasError.InvalidNick;
    }
}

fn validNickByte(ch: u8) bool {
    return switch (ch) {
        'A'...'Z', 'a'...'z', '0'...'9', '[', ']', '\\', '`', '_', '^', '{', '|', '}', '-' => true,
        else => false,
    };
}

fn validSimpleField(value: []const u8, allow_space: bool) bool {
    for (value) |ch| {
        if (ch == 0 or ch == '\r' or ch == '\n') return false;
        if (!allow_space and ch == ' ') return false;
        if (ch < 0x20 or ch == 0x7f) return false;
    }
    return true;
}

fn nickEqualsFolded(folded: []const u8, raw: []const u8) bool {
    if (folded.len != raw.len) return false;
    for (raw, 0..) |ch, index| {
        if (folded[index] != foldNickByte(ch)) return false;
    }
    return true;
}

fn foldedHash(nick: []const u8) u64 {
    var hash: u64 = 14695981039346656037;
    for (nick) |ch| {
        hash ^= foldNickByte(ch);
        hash *%= 1099511628211;
    }
    return hash;
}

fn foldNickByte(ch: u8) u8 {
    return switch (ch) {
        'A'...'Z' => ch + ('a' - 'A'),
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        else => ch,
    };
}

fn copyBytes(dst: []u8, src: []const u8) void {
    if (src.len == 0) return;
    @memcpy(dst, src);
}

const TestHistory = Whowas(.{
    .capacity = 3,
    .max_nick_len = 16,
    .max_user_len = 16,
    .max_host_len = 32,
    .max_realname_len = 64,
    .max_account_len = 16,
});

fn testRecord(
    nick: []const u8,
    user: []const u8,
    host: []const u8,
    realname: []const u8,
    account: []const u8,
    signoff_time: i64,
) Record {
    return .{
        .nick = nick,
        .user = user,
        .host = host,
        .realname = realname,
        .account = account,
        .signoff_time = signoff_time,
    };
}

test "record and query returns recent first" {
    var history = try TestHistory.init(std.testing.allocator);
    defer history.deinit();

    try history.addOnQuit(testRecord("alice", "u1", "host1", "Alice One", "acct1", 100));
    try history.addOnQuit(testRecord("bob", "u2", "host2", "Bob Two", "", 200));
    try history.addOnQuit(testRecord("alice", "u3", "host3", "Alice Three", "acct3", 300));

    var out: [4]Record = undefined;
    const results = try history.query("alice", 4, &out);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("u3", results[0].user);
    try std.testing.expectEqual(@as(i64, 300), results[0].signoff_time);
    try std.testing.expectEqualStrings("u1", results[1].user);
    try std.testing.expectEqual(@as(i64, 100), results[1].signoff_time);
}

test "origin server round-trips for mesh-replicated records" {
    var history = try TestHistory.init(std.testing.allocator);
    defer history.deinit();

    var remote = testRecord("carol", "u9", "host9", "Remote mesh user", "acct9", 400);
    remote.server = "peer.example.test";
    try history.addOnQuit(remote);
    try history.addOnQuit(testRecord("carol", "u8", "host8", "Carol Local", "", 500));

    var out: [2]Record = undefined;
    const results = try history.query("carol", 2, &out);
    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("", results[0].server);
    try std.testing.expectEqualStrings("peer.example.test", results[1].server);
}

test "multiple entries per nick obey query max" {
    var history = try TestHistory.init(std.testing.allocator);
    defer history.deinit();

    try history.addOnQuit(testRecord("sam", "u1", "h1", "Sam One", "", 10));
    try history.addOnNickChange(testRecord("sam", "u2", "h2", "Sam Two", "a2", 20));
    try history.addOnQuit(testRecord("sam", "u3", "h3", "Sam Three", "a3", 30));

    var out: [3]Record = undefined;
    const results = try history.query("sam", 2, &out);

    try std.testing.expectEqual(@as(usize, 2), results.len);
    try std.testing.expectEqualStrings("u3", results[0].user);
    try std.testing.expectEqualStrings("u2", results[1].user);
}

test "eviction at cap removes oldest" {
    var history = try TestHistory.init(std.testing.allocator);
    defer history.deinit();

    try history.addOnQuit(testRecord("old", "u1", "h1", "Old", "", 1));
    try history.addOnQuit(testRecord("mid", "u2", "h2", "Mid", "", 2));
    try history.addOnQuit(testRecord("new", "u3", "h3", "New", "", 3));
    try history.addOnQuit(testRecord("last", "u4", "h4", "Last", "", 4));

    var out: [3]Record = undefined;
    try std.testing.expectEqual(@as(usize, 3), history.len());
    try std.testing.expectEqual(@as(usize, 0), (try history.query("old", 3, &out)).len);
    try std.testing.expectEqual(@as(usize, 1), (try history.query("last", 3, &out)).len);
}

test "case-insensitive nick lookup uses IRC case folding" {
    var history = try TestHistory.init(std.testing.allocator);
    defer history.deinit();

    try history.addOnQuit(testRecord("Nick[One]", "u", "h", "Real", "acct", 55));

    var out: [2]Record = undefined;
    const results = try history.query("nick{one}", 2, &out);

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqualStrings("Nick[One]", results[0].nick);
    try std.testing.expectEqualStrings("acct", results[0].account);
}
