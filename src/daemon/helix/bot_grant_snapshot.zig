// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scoped bot grants carried across a Helix UPGRADE.
//!
//! A bot account may hold a speak, webhook, or history grant for one channel.
//! The grant expires, can be listed, and can be revoked. It is not an operator
//! privilege bit: the record has no privilege mask and restoring it never sets
//! `is_oper`.
//!
//! The image rides the existing `.mesh_checkpoint` family (magic "BGNT",
//! `min_supported = 2`). There is no new capsule kind. A predecessor arena
//! that lacks the piece still adopts; a present but malformed or duplicate
//! image rejects the whole handoff. Expired grants are omitted at seal time.
//! The account stays a bot, so a successor still refuses the action after the
//! grant has lapsed.

const std = @import("std");

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    TrailingBytes,
    TooMany,
    InvalidGrant,
};

pub const magic = [_]u8{ 'B', 'G', 'N', 'T' };
pub const version: u8 = 1;

pub const max_bots: u32 = 256;
pub const max_grants: u32 = 256;
pub const max_account: usize = 64;
pub const max_scope: usize = 64;

pub const Kind = enum(u8) {
    speak = 1,
    webhook = 2,
    history = 3,

    pub fn parse(text: []const u8) ?Kind {
        if (std.ascii.eqlIgnoreCase(text, "speak")) return .speak;
        if (std.ascii.eqlIgnoreCase(text, "webhook")) return .webhook;
        if (std.ascii.eqlIgnoreCase(text, "history")) return .history;
        return null;
    }
};

fn kindFromRaw(raw: u8) ?Kind {
    return switch (raw) {
        @intFromEnum(Kind.speak) => .speak,
        @intFromEnum(Kind.webhook) => .webhook,
        @intFromEnum(Kind.history) => .history,
        else => null,
    };
}

const BotSlot = struct {
    used: bool = false,
    len: u8 = 0,
    bytes: [max_account]u8 = undefined,

    fn slice(self: *const BotSlot) []const u8 {
        return self.bytes[0..self.len];
    }
};

const GrantSlot = struct {
    used: bool = false,
    kind: Kind = .speak,
    account_len: u8 = 0,
    scope_len: u8 = 0,
    account: [max_account]u8 = undefined,
    scope: [max_scope]u8 = undefined,
    expiry_ms: u64 = 0,

    fn accountSlice(self: *const GrantSlot) []const u8 {
        return self.account[0..self.account_len];
    }

    fn scopeSlice(self: *const GrantSlot) []const u8 {
        return self.scope[0..self.scope_len];
    }
};

pub const GrantView = struct {
    account: []const u8,
    kind: Kind,
    scope: []const u8,
    expiry_ms: u64,
};

/// Fixed table. Account bytes live in the slot, so a restore at the adoption
/// commit edge does not allocate.
pub const Table = struct {
    bots: [max_bots]BotSlot = @splat(.{}),
    grants: [max_grants]GrantSlot = @splat(.{}),

    pub fn isBot(self: *const Table, account: []const u8) bool {
        for (self.bots) |slot| {
            if (!slot.used) continue;
            if (std.ascii.eqlIgnoreCase(slot.slice(), account)) return true;
        }
        return false;
    }

    pub fn botCount(self: *const Table) usize {
        var n: usize = 0;
        for (self.bots) |slot| {
            if (slot.used) n += 1;
        }
        return n;
    }

    pub fn grantCount(self: *const Table) usize {
        var n: usize = 0;
        for (self.grants) |slot| {
            if (slot.used) n += 1;
        }
        return n;
    }

    /// Live (unexpired) grants, borrowing the slot bytes. `out` is filled in
    /// slot order. Returns how many were written.
    pub fn copyLive(self: *const Table, now_ms: u64, out: []GrantView) usize {
        var n: usize = 0;
        for (&self.grants) |*slot| {
            if (n == out.len) break;
            if (!slot.used or slot.expiry_ms <= now_ms) continue;
            out[n] = .{
                .account = slot.accountSlice(),
                .kind = slot.kind,
                .scope = slot.scopeSlice(),
                .expiry_ms = slot.expiry_ms,
            };
            n += 1;
        }
        return n;
    }

    pub fn insertBot(self: *Table, account: []const u8) Error!void {
        if (account.len == 0 or account.len > max_account) return error.InvalidGrant;
        for (self.bots) |slot| {
            if (!slot.used) continue;
            if (std.ascii.eqlIgnoreCase(slot.slice(), account)) return;
        }
        for (&self.bots) |*slot| {
            if (slot.used) continue;
            @memcpy(slot.bytes[0..account.len], account);
            slot.len = @intCast(account.len);
            slot.used = true;
            return;
        }
        return error.TooMany;
    }

    /// Insert or refresh one grant and remember the account as a bot.
    /// `expiry_ms` is absolute wall-clock milliseconds.
    pub fn upsert(
        self: *Table,
        account: []const u8,
        kind: Kind,
        scope: []const u8,
        expiry_ms: u64,
        now_ms: u64,
    ) Error!void {
        if (account.len == 0 or account.len > max_account) return error.InvalidGrant;
        if (scope.len == 0 or scope.len > max_scope) return error.InvalidGrant;
        if (expiry_ms <= now_ms) return error.InvalidGrant;
        self.reclaimExpired(now_ms);
        try self.insertBot(account);
        for (&self.grants) |*slot| {
            if (!slot.used or slot.kind != kind) continue;
            if (!std.ascii.eqlIgnoreCase(slot.accountSlice(), account)) continue;
            if (!std.ascii.eqlIgnoreCase(slot.scopeSlice(), scope)) continue;
            slot.expiry_ms = expiry_ms;
            return;
        }
        for (&self.grants) |*slot| {
            if (slot.used) continue;
            @memcpy(slot.account[0..account.len], account);
            @memcpy(slot.scope[0..scope.len], scope);
            slot.account_len = @intCast(account.len);
            slot.scope_len = @intCast(scope.len);
            slot.kind = kind;
            slot.expiry_ms = expiry_ms;
            slot.used = true;
            return;
        }
        return error.TooMany;
    }

    pub fn remove(self: *Table, account: []const u8, kind: Kind, scope: []const u8) bool {
        for (&self.grants) |*slot| {
            if (!slot.used or slot.kind != kind) continue;
            if (!std.ascii.eqlIgnoreCase(slot.accountSlice(), account)) continue;
            if (!std.ascii.eqlIgnoreCase(slot.scopeSlice(), scope)) continue;
            slot.used = false;
            return true;
        }
        return false;
    }

    pub fn allows(self: *const Table, account: []const u8, kind: Kind, scope: []const u8, now_ms: u64) bool {
        for (self.grants) |slot| {
            if (!slot.used or slot.kind != kind) continue;
            if (slot.expiry_ms <= now_ms) continue;
            if (!std.ascii.eqlIgnoreCase(slot.accountSlice(), account)) continue;
            if (!std.ascii.eqlIgnoreCase(slot.scopeSlice(), scope)) continue;
            return true;
        }
        return false;
    }

    /// Move one matching grant into the past. The account stays a bot.
    pub fn expire(self: *Table, account: []const u8, kind: Kind, scope: []const u8) bool {
        for (&self.grants) |*slot| {
            if (!slot.used or slot.kind != kind) continue;
            if (!std.ascii.eqlIgnoreCase(slot.accountSlice(), account)) continue;
            if (!std.ascii.eqlIgnoreCase(slot.scopeSlice(), scope)) continue;
            slot.expiry_ms = 1;
            return true;
        }
        return false;
    }

    fn reclaimExpired(self: *Table, now_ms: u64) void {
        for (&self.grants) |*slot| {
            if (slot.used and slot.expiry_ms <= now_ms) slot.used = false;
        }
    }
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub const Snapshot = struct {
    bot_count: u32,
    grant_count: u32,
    bot_records: []const u8,
    grant_records: []const u8,

    pub fn botIterator(self: *const Snapshot) BotIterator {
        return .{ .r = .{ .buf = self.bot_records }, .remaining = self.bot_count };
    }

    pub fn grantIterator(self: *const Snapshot) GrantIterator {
        return .{ .r = .{ .buf = self.grant_records }, .remaining = self.grant_count };
    }
};

pub const BotIterator = struct {
    r: Reader,
    remaining: u32,

    pub fn next(self: *BotIterator) ?[]const u8 {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        return self.r.shortSlice();
    }
};

pub const GrantIterator = struct {
    r: Reader,
    remaining: u32,

    pub fn next(self: *GrantIterator) ?GrantView {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        const account = self.r.shortSlice() orelse return null;
        const kind_raw = self.r.int(u8) orelse return null;
        const kind = kindFromRaw(kind_raw) orelse return null;
        const scope = self.r.shortSlice() orelse return null;
        const expiry_ms = self.r.int(u64) orelse return null;
        return .{
            .account = account,
            .kind = kind,
            .scope = scope,
            .expiry_ms = expiry_ms,
        };
    }
};

pub fn encodeFrom(allocator: std.mem.Allocator, table: *const Table, now_ms: u64) (Error || std.mem.Allocator.Error)![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, &magic);
    try out.append(allocator, version);
    const bot_count_off = out.items.len;
    try appendInt(&out, allocator, u32, 0);

    var bot_count: u32 = 0;
    for (table.bots) |slot| {
        if (!slot.used) continue;
        if (bot_count == max_bots) return error.TooMany;
        if (slot.slice().len == 0) return error.InvalidGrant;
        try appendShortSlice(&out, allocator, slot.slice(), max_account);
        bot_count += 1;
    }
    std.mem.writeInt(u32, out.items[bot_count_off..][0..4], bot_count, .little);

    const grant_count_off = out.items.len;
    try appendInt(&out, allocator, u32, 0);
    var grant_count: u32 = 0;
    for (table.grants) |slot| {
        if (!slot.used or slot.expiry_ms <= now_ms) continue;
        if (grant_count == max_grants) return error.TooMany;
        if (!table.isBot(slot.accountSlice())) return error.InvalidGrant;
        try appendShortSlice(&out, allocator, slot.accountSlice(), max_account);
        try out.append(allocator, @intFromEnum(slot.kind));
        try appendShortSlice(&out, allocator, slot.scopeSlice(), max_scope);
        try appendInt(&out, allocator, u64, slot.expiry_ms);
        grant_count += 1;
    }
    std.mem.writeInt(u32, out.items[grant_count_off..][0..4], grant_count, .little);

    _ = try decodeCurrent(out.items);
    return out.toOwnedSlice(allocator);
}

pub fn decodeCurrent(bytes: []const u8) Error!Snapshot {
    if (bytes.len < magic.len + 1) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    if (bytes.len < magic.len + 1 + @sizeOf(u32)) return error.Truncated;

    const bot_count = std.mem.readInt(u32, bytes[magic.len + 1 ..][0..4], .little);
    if (bot_count > max_bots) return error.TooMany;
    const rest = bytes[magic.len + 1 + @sizeOf(u32) ..];
    var r = Reader{ .buf = rest };

    var bot_starts: [max_bots]usize = undefined;
    var bot_lens: [max_bots]u8 = undefined;
    var seen_bots: u32 = 0;
    while (seen_bots < bot_count) : (seen_bots += 1) {
        const start = r.pos + 1;
        const account = r.shortSlice() orelse return error.Truncated;
        if (account.len == 0 or account.len > max_account) return error.InvalidGrant;
        for (bot_starts[0..seen_bots], bot_lens[0..seen_bots]) |prior, prior_len| {
            if (std.ascii.eqlIgnoreCase(rest[prior..][0..prior_len], account)) return error.InvalidGrant;
        }
        bot_starts[seen_bots] = start;
        bot_lens[seen_bots] = @intCast(account.len);
    }
    const bots_end = r.pos;
    const grant_count = r.int(u32) orelse return error.Truncated;
    if (grant_count > max_grants) return error.TooMany;
    const grants_off = r.pos;

    var g_accounts: [max_grants]usize = undefined;
    var g_account_lens: [max_grants]u8 = undefined;
    var g_kinds: [max_grants]Kind = undefined;
    var g_scopes: [max_grants]usize = undefined;
    var g_scope_lens: [max_grants]u8 = undefined;
    var seen_grants: u32 = 0;
    while (seen_grants < grant_count) : (seen_grants += 1) {
        const account_start = r.pos + 1;
        const account = r.shortSlice() orelse return error.Truncated;
        if (account.len == 0 or account.len > max_account) return error.InvalidGrant;
        const kind_raw = r.int(u8) orelse return error.Truncated;
        const kind = kindFromRaw(kind_raw) orelse return error.InvalidGrant;
        const scope_start = r.pos + 1;
        const scope = r.shortSlice() orelse return error.Truncated;
        if (scope.len == 0 or scope.len > max_scope) return error.InvalidGrant;
        const expiry_ms = r.int(u64) orelse return error.Truncated;
        if (expiry_ms == 0) return error.InvalidGrant;
        var known_bot = false;
        for (bot_starts[0..bot_count], bot_lens[0..bot_count]) |prior, prior_len| {
            if (std.ascii.eqlIgnoreCase(rest[prior..][0..prior_len], account)) known_bot = true;
        }
        if (!known_bot) return error.InvalidGrant;
        for (g_accounts[0..seen_grants], g_account_lens[0..seen_grants], g_kinds[0..seen_grants], g_scopes[0..seen_grants], g_scope_lens[0..seen_grants]) |pa, pl, pk, ps, psl| {
            if (pk == kind and
                std.ascii.eqlIgnoreCase(rest[pa..][0..pl], account) and
                std.ascii.eqlIgnoreCase(rest[ps..][0..psl], scope))
                return error.InvalidGrant;
        }
        g_accounts[seen_grants] = account_start;
        g_account_lens[seen_grants] = @intCast(account.len);
        g_kinds[seen_grants] = kind;
        g_scopes[seen_grants] = scope_start;
        g_scope_lens[seen_grants] = @intCast(scope.len);
    }
    if (r.pos != rest.len) return error.TrailingBytes;
    return .{
        .bot_count = bot_count,
        .grant_count = grant_count,
        .bot_records = rest[0..bots_end],
        .grant_records = rest[grants_off..],
    };
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    _ = try decodeCurrent(bytes);
}

fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) std.mem.Allocator.Error!void {
    var le: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &le, value, .little);
    try out.appendSlice(allocator, &le);
}

fn appendShortSlice(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_len: usize,
) (Error || std.mem.Allocator.Error)!void {
    if (bytes.len == 0 or bytes.len > max_len or bytes.len > 255) return error.InvalidGrant;
    try out.append(allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn int(self: *Reader, comptime T: type) ?T {
        if (self.buf.len - self.pos < @sizeOf(T)) return null;
        defer self.pos += @sizeOf(T);
        return std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .little);
    }

    fn shortSlice(self: *Reader) ?[]const u8 {
        if (self.pos == self.buf.len) return null;
        const n: usize = self.buf[self.pos];
        if (self.buf.len - self.pos - 1 < n) return null;
        defer self.pos += 1 + n;
        return self.buf[self.pos + 1 ..][0..n];
    }
};

test "bot grant snapshot round trip skips expired and keeps the account" {
    const allocator = std.testing.allocator;
    var table = Table{};
    try table.upsert("newsbot", .speak, "#room", 5_000, 1_000);
    try table.upsert("newsbot", .webhook, "#room", 1_500, 1_000);
    try std.testing.expect(table.expire("newsbot", .webhook, "#room"));
    const wire = try encodeFrom(allocator, &table, 2_000);
    defer allocator.free(wire);
    try std.testing.expect(isCheckpoint(wire));
    const snap = try decodeCurrent(wire);
    try std.testing.expectEqual(@as(u32, 1), snap.bot_count);
    try std.testing.expectEqual(@as(u32, 1), snap.grant_count);
    var bots = snap.botIterator();
    try std.testing.expectEqualStrings("newsbot", bots.next().?);
    try std.testing.expect(bots.next() == null);
    var grants = snap.grantIterator();
    const g = grants.next().?;
    try std.testing.expectEqual(Kind.speak, g.kind);
    try std.testing.expectEqualStrings("#room", g.scope);
    try std.testing.expect(grants.next() == null);
}
