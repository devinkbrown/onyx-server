// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public, non-secret selector for one physical resumable session row.
//!
//! A SID is deliberately derived only from the bearer token and the row's
//! non-null stable AttachmentId. Runtime client ids are recyclable and must
//! never influence a resumable identity. Legacy/null-AID rows have no SID and
//! can only be selected through the exact, per-connection LIST image.

const std = @import("std");
const sessions = @import("sessions.zig");

pub const sid_byte_len: usize = 16;
pub const sid_hex_len: usize = sid_byte_len * 2;
pub const Sid = [sid_byte_len]u8;
const sid_domain = "onyx-session-row-id-v1\x00";

pub const DeriveError = error{ NullSessionToken, NullAttachmentId, ZeroAttachmentId, InvalidDerivedSid };
pub const ParseError = error{InvalidDropTarget};
pub const DropTarget = union(enum) { ordinal: usize, sid: Sid };

/// An exact physical row image. This intentionally retains token bytes only in
/// the caller's ephemeral LIST cache, which is securely erased on invalidation.
pub const ListOrdinal = struct {
    token: sessions.Token,
    client: sessions.ClientId,
    signon_ms: i64,
    attachment_id: ?sessions.AttachmentId,
    valid: bool = true,
};

pub const RowSelector = ListOrdinal;
pub const SidMatch = union(enum) { none, unique: RowSelector, ambiguous };

/// Dynamically-sized complete image of exactly what a connection listed. Never
/// truncate this image: configured per-account limits may be larger than the
/// historical fixed SessionStore snapshot capacity.
pub const ListCache = struct {
    epoch: u64 = 0,
    allocator: ?std.mem.Allocator = null,
    account: std.ArrayListUnmanaged(u8) = .empty,
    rows: std.ArrayListUnmanaged(ListOrdinal) = .empty,

    pub fn reset(self: *ListCache) void {
        if (self.allocator) |allocator| {
            std.crypto.secureZero(u8, self.account.items);
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.rows.items));
            self.account.deinit(allocator);
            self.rows.deinit(allocator);
        }
        self.* = .{};
    }

    /// Allocate a complete replacement before touching the old cache: OOM leaves
    /// the old cache valid and cannot mutate selection state.
    pub fn replace(self: *ListCache, allocator: std.mem.Allocator, epoch: u64, account_name: []const u8, sessions_in: []const sessions.Session) std.mem.Allocator.Error!void {
        var next = ListCache{ .epoch = epoch, .allocator = allocator };
        errdefer next.reset();
        try next.account.appendSlice(allocator, account_name);
        try next.rows.ensureTotalCapacity(allocator, sessions_in.len);
        for (sessions_in) |row| next.rows.appendAssumeCapacity(.{
            .token = row.token,
            .client = row.client,
            .signon_ms = row.signon_ms,
            .attachment_id = row.attachment_id,
        });
        self.reset();
        self.* = next;
    }

    /// Reserve every byte before a LIST line is emitted. Callers append only
    /// after the corresponding notice succeeds, then atomically publish this
    /// staging object after the terminating line succeeds.
    pub fn prepare(self: *ListCache, allocator: std.mem.Allocator, epoch: u64, account_name: []const u8, capacity: usize) std.mem.Allocator.Error!void {
        var next = ListCache{ .epoch = epoch, .allocator = allocator };
        errdefer next.reset();
        try next.account.appendSlice(allocator, account_name);
        try next.rows.ensureTotalCapacity(allocator, capacity);
        self.reset();
        self.* = next;
    }

    pub fn lookup(self: *const ListCache, epoch: u64, account_name: []const u8, idx: usize) error{StaleList}!ListOrdinal {
        if (self.epoch == 0 or self.epoch != epoch or idx == 0 or idx > self.rows.items.len) return error.StaleList;
        if (!std.ascii.eqlIgnoreCase(self.account.items, account_name)) return error.StaleList;
        const row = self.rows.items[idx - 1];
        if (!row.valid) return error.StaleList;
        return row;
    }

    /// Securely retire one emitted ordinal without compacting the snapshot.
    /// Subsequent ordinals deliberately retain their original number; a revoked
    /// bearer token/AID must not remain in an otherwise live client cache.
    pub fn invalidate(self: *ListCache, idx: usize) void {
        if (idx == 0 or idx > self.rows.items.len) return;
        const row = &self.rows.items[idx - 1];
        std.crypto.secureZero(u8, std.mem.asBytes(row));
        row.valid = false;
    }

    /// SID selectors have no ordinal in the command, so retire every cached
    /// physical image equal to the successfully removed row. Duplicate images
    /// are harmlessly invalidated together; no lookup may expose their secret
    /// selector bytes after the authoritative CAS succeeds.
    pub fn invalidateExact(self: *ListCache, expected: ListOrdinal) void {
        for (self.rows.items, 0..) |row, index| {
            if (!row.valid or row.client != expected.client or row.signon_ms != expected.signon_ms) continue;
            if (!std.crypto.timing_safe.eql(sessions.Token, row.token, expected.token)) continue;
            const attachment_matches = if (expected.attachment_id) |aid|
                row.attachment_id != null and aid.eql(row.attachment_id.?)
            else
                row.attachment_id == null;
            if (attachment_matches) self.invalidate(index + 1);
        }
    }
};

pub fn isZeroSid(sid: Sid) bool {
    return std.mem.allEqual(u8, &sid, 0);
}
pub fn eql(a: Sid, b: Sid) bool {
    return std.crypto.timing_safe.eql(Sid, a, b);
}
pub fn formatSid(sid: Sid) [sid_hex_len]u8 {
    return std.fmt.bytesToHex(sid, .lower);
}

pub fn deriveSid(token: sessions.Token, attachment_id: ?sessions.AttachmentId) DeriveError!Sid {
    if (std.mem.allEqual(u8, &token, 0)) return error.NullSessionToken;
    const aid = attachment_id orelse return error.NullAttachmentId;
    if (aid.isZero()) return error.ZeroAttachmentId;
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(sid_domain);
    hasher.update(&token);
    hasher.update(&aid.raw);
    var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    hasher.final(&digest);
    const sid: Sid = digest[0..sid_byte_len].*;
    if (isZeroSid(sid)) return error.InvalidDerivedSid;
    return sid;
}

pub fn sidOf(row: sessions.Session) ?Sid {
    return deriveSid(row.token, row.attachment_id) catch null;
}

pub fn exactEql(a: ListOrdinal, row: sessions.Session) bool {
    return a.valid and a.client == row.client and a.signon_ms == row.signon_ms and
        std.crypto.timing_safe.eql(sessions.Token, a.token, row.token) and
        if (a.attachment_id) |attachment|
            row.attachment_id != null and attachment.eql(row.attachment_id.?)
        else
            row.attachment_id == null;
}

pub fn resolveCachedRow(rows: []const sessions.Session, cached: ListOrdinal) error{StaleList}!sessions.Session {
    var found: ?sessions.Session = null;
    for (rows) |row| {
        if (!exactEql(cached, row)) continue;
        if (found != null) return error.StaleList;
        found = row;
    }
    return found orelse error.StaleList;
}

pub fn matchSid(rows: []const sessions.Session, needle: Sid) SidMatch {
    var found: ?sessions.Session = null;
    for (rows) |row| {
        const sid = sidOf(row) orelse continue;
        if (!eql(sid, needle)) continue;
        if (found != null) return .ambiguous;
        found = row;
    }
    const row = found orelse return .none;
    return .{ .unique = .{ .token = row.token, .client = row.client, .signon_ms = row.signon_ms, .attachment_id = row.attachment_id } };
}

pub fn parseSid(text: []const u8) ?Sid {
    const hex = if (text.len >= 4 and std.ascii.eqlIgnoreCase(text[0..4], "sid=")) text[4..] else text;
    if (hex.len != sid_hex_len) return null;
    var sid: Sid = undefined;
    _ = std.fmt.hexToBytes(&sid, hex) catch return null;
    return if (isZeroSid(sid)) null else sid;
}

pub fn parseDropTarget(raw: []const u8) ParseError!DropTarget {
    if (raw.len == 0) return error.InvalidDropTarget;
    if (raw[0] == '#') return .{ .ordinal = parseOrdinal(raw[1..]) catch return error.InvalidDropTarget };
    if (parseSid(raw)) |sid| return .{ .sid = sid };
    return .{ .ordinal = parseOrdinal(raw) catch return error.InvalidDropTarget };
}
fn parseOrdinal(text: []const u8) !usize {
    const n = std.fmt.parseInt(usize, text, 10) catch return error.InvalidDropTarget;
    return if (n == 0) error.InvalidDropTarget else n;
}

test "sid is 128-bit physical stable attachment identity" {
    const token: sessions.Token = @splat(0x11);
    const a = try sessions.AttachmentId.fromBytes(@splat(0x22));
    const b = try sessions.AttachmentId.fromBytes(@splat(0x23));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Sid));
    try std.testing.expect(eql(try deriveSid(token, a), try deriveSid(token, a)));
    try std.testing.expect(!eql(try deriveSid(token, a), try deriveSid(token, b)));
    try std.testing.expectError(error.NullAttachmentId, deriveSid(token, null));
}

test "complete cache preserves more than 64 rows and exact physical identity" {
    var cache = ListCache{};
    defer cache.reset();
    var rows: [65]sessions.Session = undefined;
    const aid = try sessions.AttachmentId.fromBytes(@splat(0x44));
    for (&rows, 0..) |*row, i| row.* = .{ .token = @splat(@intCast(i + 1)), .client = i + 1, .signon_ms = @intCast(i), .attachment_id = aid };
    try cache.replace(std.testing.allocator, 1, "alice", &rows);
    try std.testing.expectEqual(@as(usize, 65), cache.rows.items.len);
    try std.testing.expectEqual(@as(sessions.ClientId, 65), (try cache.lookup(1, "ALICE", 65)).client);
    try std.testing.expectError(error.StaleList, resolveCachedRow(rows[0..64], try cache.lookup(1, "alice", 65)));
}

test "invalidating a cached ordinal zeroes its selector without reindexing later rows" {
    var cache = ListCache{};
    defer cache.reset();
    const first_aid = try sessions.AttachmentId.fromBytes(@splat(0x45));
    const second_aid = try sessions.AttachmentId.fromBytes(@splat(0x46));
    const rows = [_]sessions.Session{
        .{ .token = @splat(0x51), .client = 1, .signon_ms = 1, .attachment_id = first_aid },
        .{ .token = @splat(0x52), .client = 2, .signon_ms = 2, .attachment_id = second_aid },
    };
    try cache.replace(std.testing.allocator, 1, "alice", &rows);
    cache.invalidate(1);
    try std.testing.expectError(error.StaleList, cache.lookup(1, "alice", 1));
    try std.testing.expectEqual(@as(sessions.ClientId, 2), (try cache.lookup(1, "alice", 2)).client);
    const erased = cache.rows.items[0];
    try std.testing.expect(!erased.valid);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&erased), 0));
    try std.testing.expect(std.mem.allEqual(u8, &erased.token, 0));
    try std.testing.expect(erased.attachment_id == null);
}

test "shared-token siblings are distinct by attachment and SID collisions fail closed" {
    const token: sessions.Token = @splat(0x71);
    const first_aid = try sessions.AttachmentId.fromBytes(@splat(0x72));
    const second_aid = try sessions.AttachmentId.fromBytes(@splat(0x73));
    const first = sessions.Session{ .token = token, .client = 10, .signon_ms = 1, .attachment_id = first_aid };
    const second = sessions.Session{ .token = token, .client = 11, .signon_ms = 2, .attachment_id = second_aid };
    const first_sid = sidOf(first).?;
    try std.testing.expect(!eql(first_sid, sidOf(second).?));
    switch (matchSid(&.{ first, second }, first_sid)) {
        .unique => |row| try std.testing.expectEqual(@as(sessions.ClientId, 10), row.client),
        else => return error.TestUnexpectedResult,
    }
    // Two rows with the same stable identity are corrupt/currently ambiguous;
    // fail closed instead of selecting either claimant.
    const collision = sessions.Session{ .token = token, .client = 12, .signon_ms = 3, .attachment_id = first_aid };
    try std.testing.expect(matchSid(&.{ first, collision }, first_sid) == .ambiguous);
}
