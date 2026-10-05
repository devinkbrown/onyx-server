// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-channel AKICK list (pure logic + tests).
//!
//! An AKICK ("auto-kick") is a per-channel ban list consulted on join: when a
//! client whose `nick!user@host` or logged-in account matches an active entry
//! attempts to join, the join path is expected to reject/kick them with the
//! entry's reason. This module owns the storage and matching logic only; wiring
//! into the join path, persistence, and the `CHANNEL ... AKICK` command surface
//! lives elsewhere.
//!
//! Mask grammar:
//!   - Hostmask glob: `nick!user@host` with `*` (any run) and `?` (one char),
//!     matched case-insensitively (ASCII) against the joining client's full
//!     `nick!user@host`.
//!   - Account mask: `account:<glob>` matched case-insensitively against the
//!     client's logged-in account name. An account mask never matches an
//!     unauthenticated client.
//!
//! Memory: every entry owns heap copies of its mask, reason, and setter; the
//! store frees them on removal and on `deinit`. No leaks under the test runner.
//!
//! This is deliberately distinct from `services.zig`'s persistent KV AKICK
//! record (which has no expiry and no join-time matcher) and from the
//! network-wide `warden` ban system. AKICK is per-channel and time-aware.

const std = @import("std");

/// Distinguishes the two mask kinds so matching can short-circuit cheaply and
/// so callers can render entries faithfully.
pub const MaskKind = enum {
    /// `nick!user@host` glob matched against the joining client's hostmask.
    hostmask,
    /// `account:<glob>` matched against the client's logged-in account name.
    account,
};

/// Prefix that marks an account mask. Anything else is treated as a hostmask.
pub const account_prefix = "account:";

/// A single AKICK entry. Strings are owned by the store and remain valid until
/// the entry is removed or the store is deinitialized.
pub const Entry = struct {
    /// Full mask as supplied (including any `account:` prefix). Lowercased copy.
    mask: []const u8,
    /// The portion used for matching: the glob after `account:` for account
    /// masks, or the whole mask for hostmasks. Slices into `mask`.
    pattern: []const u8,
    kind: MaskKind,
    /// Human-readable reason shown to the kicked user. May be empty.
    reason: []const u8,
    /// Who set the entry (account name or oper handle). May be empty.
    setter: []const u8,
    /// Wall-clock milliseconds when the entry was added.
    added_at_ms: i64,
    /// Wall-clock milliseconds when the entry expires; `null` = permanent.
    expires_at_ms: ?i64,

    /// True when `now_ms` is at or past the expiry instant.
    pub fn isExpired(self: Entry, now_ms: i64) bool {
        const exp = self.expires_at_ms orelse return false;
        return now_ms >= exp;
    }
};

pub const Error = error{
    /// The channel already holds the maximum number of entries.
    ListFull,
    /// An entry with this (normalized) mask already exists for the channel.
    Duplicate,
    /// The supplied mask was empty or otherwise unusable.
    InvalidMask,
    OutOfMemory,
};

/// Result of a removal request.
pub const RemoveResult = enum { removed, not_found };

/// Default cap on entries per channel. Callers may override via `initCapacity`.
pub const default_max_per_channel: usize = 64;

/// One channel's AKICK list. Channels are keyed by their lowercased name in the
/// owning `AkickStore`; this struct holds only the entries.
const ChannelList = struct {
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    fn deinit(self: *ChannelList, alloc: std.mem.Allocator) void {
        for (self.entries.items) |entry| freeEntry(alloc, entry);
        self.entries.deinit(alloc);
    }
};

/// In-memory AKICK store keyed by channel name. Owns all entry strings.
pub const AkickStore = struct {
    alloc: std.mem.Allocator,
    channels: std.StringHashMapUnmanaged(ChannelList) = .{},
    max_per_channel: usize = default_max_per_channel,

    pub fn init(alloc: std.mem.Allocator) AkickStore {
        return .{ .alloc = alloc };
    }

    pub fn initCapacity(alloc: std.mem.Allocator, max_per_channel: usize) AkickStore {
        return .{ .alloc = alloc, .max_per_channel = max_per_channel };
    }

    /// Restore an empty channel row as well as nonempty lists. An ordinary ADD
    /// may leave this row behind after a later allocation failure, and purge
    /// keeps the channel row after removing its last entry.
    pub fn checkpointEnsureChannel(self: *AkickStore, channel: []const u8) Error!void {
        _ = try self.ensureChannel(channel);
    }

    pub fn deinit(self: *AkickStore) void {
        var it = self.channels.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.deinit(self.alloc);
            self.alloc.free(kv.key_ptr.*);
        }
        self.channels.deinit(self.alloc);
    }

    /// Add an AKICK to `channel`. `mask`, `reason`, and `setter` are copied; the
    /// caller retains ownership of its inputs. Returns the stored entry's
    /// matchable pattern view is available via `list`. Masks are normalized to
    /// lowercase before storage and duplicate detection.
    pub fn add(
        self: *AkickStore,
        channel: []const u8,
        mask: []const u8,
        reason: []const u8,
        setter: []const u8,
        added_at_ms: i64,
        expires_at_ms: ?i64,
    ) Error!void {
        const trimmed = std.mem.trim(u8, mask, " ");
        if (trimmed.len == 0) return Error.InvalidMask;

        const cl = try self.ensureChannel(channel);

        if (cl.entries.items.len >= self.max_per_channel) return Error.ListFull;

        // Build the normalized (lowercased) mask copy first so we can compare.
        const mask_copy = try self.alloc.alloc(u8, trimmed.len);
        errdefer self.alloc.free(mask_copy);
        lowerInto(mask_copy, trimmed);

        for (cl.entries.items) |existing| {
            if (std.mem.eql(u8, existing.mask, mask_copy)) return Error.Duplicate;
        }

        const kind_pattern = classify(mask_copy);
        if (kind_pattern.pattern.len == 0) {
            // e.g. a bare "account:" with no glob -> unusable.
            return Error.InvalidMask;
        }

        const reason_copy = try self.alloc.dupe(u8, reason);
        errdefer self.alloc.free(reason_copy);
        const setter_copy = try self.alloc.dupe(u8, setter);
        errdefer self.alloc.free(setter_copy);

        try cl.entries.append(self.alloc, .{
            .mask = mask_copy,
            .pattern = kind_pattern.pattern,
            .kind = kind_pattern.kind,
            .reason = reason_copy,
            .setter = setter_copy,
            .added_at_ms = added_at_ms,
            .expires_at_ms = expires_at_ms,
        });
    }

    /// Remove the entry whose normalized mask equals `mask`. Frees its strings.
    pub fn remove(self: *AkickStore, channel: []const u8, mask: []const u8) RemoveResult {
        var mask_buf: [256]u8 = undefined;
        const norm_mask = normalizeForLookup(&mask_buf, mask) orelse return .not_found;

        var key_buf: [256]u8 = undefined;
        const key = channelKeyTmp(&key_buf, channel) catch return .not_found;
        const cl = self.channels.getPtr(key) orelse return .not_found;
        for (cl.entries.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.mask, norm_mask)) {
                freeEntry(self.alloc, entry);
                _ = cl.entries.orderedRemove(idx);
                return .removed;
            }
        }
        return .not_found;
    }

    /// Borrow the entry slice for `channel`. Valid until the next mutation of
    /// this channel's list. Returns an empty slice for unknown channels.
    pub fn list(self: *AkickStore, channel: []const u8) []const Entry {
        var key_buf: [256]u8 = undefined;
        const key = channelKeyTmp(&key_buf, channel) catch return &.{};
        const cl = self.channels.getPtr(key) orelse return &.{};
        return cl.entries.items;
    }

    /// Number of entries currently held for `channel`.
    pub fn count(self: *AkickStore, channel: []const u8) usize {
        return self.list(channel).len;
    }

    /// Drop expired entries from `channel`, freeing their strings. Returns the
    /// number purged. Safe to call opportunistically (e.g. before listing).
    pub fn purgeExpired(self: *AkickStore, channel: []const u8, now_ms: i64) usize {
        var key_buf: [256]u8 = undefined;
        const key = channelKeyTmp(&key_buf, channel) catch return 0;
        const cl = self.channels.getPtr(key) orelse return 0;
        var purged: usize = 0;
        var idx: usize = 0;
        while (idx < cl.entries.items.len) {
            const entry = cl.entries.items[idx];
            if (entry.isExpired(now_ms)) {
                freeEntry(self.alloc, entry);
                _ = cl.entries.orderedRemove(idx);
                purged += 1;
            } else {
                idx += 1;
            }
        }
        return purged;
    }

    /// Join-path matcher: return the first active (non-expired) AKICK whose mask
    /// matches the joining client, or `null` if none applies. `hostmask` is the
    /// client's full `nick!user@host`; `account` is its logged-in account name
    /// or `null`/empty when unauthenticated. Expired entries are skipped but not
    /// removed (call `purgeExpired` to reclaim). The returned pointer borrows
    /// store memory and is valid until the channel's list mutates.
    pub fn matchOnJoin(
        self: *AkickStore,
        channel: []const u8,
        hostmask: []const u8,
        account: ?[]const u8,
        now_ms: i64,
    ) ?*const Entry {
        var key_buf: [256]u8 = undefined;
        const key = channelKeyTmp(&key_buf, channel) catch return null;
        const cl = self.channels.getPtr(key) orelse return null;

        for (cl.entries.items) |*entry| {
            if (entry.isExpired(now_ms)) continue;
            if (entryMatches(entry.*, hostmask, account)) return entry;
        }
        return null;
    }

    fn ensureChannel(self: *AkickStore, channel: []const u8) Error!*ChannelList {
        var key_buf: [256]u8 = undefined;
        const norm_key = channelKeyTmp(&key_buf, channel) catch return Error.InvalidMask;
        if (norm_key.len == 0) return Error.InvalidMask;

        const gop = try self.channels.getOrPut(self.alloc, norm_key);
        if (!gop.found_existing) {
            const owned = self.alloc.dupe(u8, norm_key) catch |e| {
                _ = self.channels.remove(norm_key);
                return e;
            };
            gop.key_ptr.* = owned;
            gop.value_ptr.* = .{};
        }
        return gop.value_ptr;
    }
};

// --- free functions / helpers ------------------------------------------------

fn freeEntry(alloc: std.mem.Allocator, entry: Entry) void {
    alloc.free(entry.mask);
    alloc.free(entry.reason);
    alloc.free(entry.setter);
}

const KindPattern = struct { kind: MaskKind, pattern: []const u8 };

/// Decide whether a (already-lowercased) mask is an account or hostmask mask
/// and slice out the matchable pattern.
fn classify(mask: []const u8) KindPattern {
    if (std.ascii.startsWithIgnoreCase(mask, account_prefix)) {
        return .{ .kind = .account, .pattern = mask[account_prefix.len..] };
    }
    return .{ .kind = .hostmask, .pattern = mask };
}

fn entryMatches(entry: Entry, hostmask: []const u8, account: ?[]const u8) bool {
    return switch (entry.kind) {
        .hostmask => globMatch(entry.pattern, hostmask),
        .account => blk: {
            const acct = account orelse break :blk false;
            if (acct.len == 0) break :blk false;
            break :blk globMatch(entry.pattern, acct);
        },
    };
}

/// Lowercase `src` into `dst` (same length). ASCII-only fold.
fn lowerInto(dst: []u8, src: []const u8) void {
    std.debug.assert(dst.len == src.len);
    for (src, 0..) |c, i| dst[i] = std.ascii.toLower(c);
}

/// Lowercase a channel name into `buf` for use as a hashmap key. Channel names
/// fit comfortably; returns error if oversized.
fn channelKeyTmp(buf: []u8, channel: []const u8) error{Oversize}![]const u8 {
    const trimmed = std.mem.trim(u8, channel, " ");
    if (trimmed.len > buf.len) return error.Oversize;
    lowerInto(buf[0..trimmed.len], trimmed);
    return buf[0..trimmed.len];
}

/// Normalize a mask for lookup (trim + lowercase) into `buf`. Returns null on
/// empty/oversized input.
fn normalizeForLookup(buf: []u8, mask: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, mask, " ");
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;
    lowerInto(buf[0..trimmed.len], trimmed);
    return buf[0..trimmed.len];
}

/// Case-insensitive glob match: `*` matches any run (including empty), `?`
/// matches exactly one character. Iterative with backtracking — no recursion,
/// no allocation. Mirrors the daemon's established glob semantics.
pub fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var retry: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star = p;
            p += 1;
            retry = t;
            continue;
        }
        if (p < pattern.len and
            (pattern[p] == '?' or eqIgnoreCase(pattern[p], text[t])))
        {
            p += 1;
            t += 1;
            continue;
        }
        if (star) |s| {
            p = s + 1;
            retry += 1;
            t = retry;
            continue;
        }
        return false;
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn eqIgnoreCase(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test "globMatch: basic wildcards and case-insensitivity" {
    try testing.expect(globMatch("*!*@*", "nick!user@host"));
    try testing.expect(globMatch("nick!*@*", "Nick!user@example.com"));
    try testing.expect(globMatch("*@example.com", "a!b@EXAMPLE.com"));
    try testing.expect(globMatch("n?ck!*@*", "nIck!u@h"));
    try testing.expect(!globMatch("admin!*@*", "user!x@y"));
    try testing.expect(!globMatch("n?ck", "nck")); // ? requires one char
    try testing.expect(globMatch("*", ""));
    try testing.expect(globMatch("", ""));
    try testing.expect(!globMatch("", "x"));
}

test "add/list: hostmask entry stored and matchable" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "Bad!*@spam.net", "go away", "founder", 1000, null);
    const entries = store.list("#chan");
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqual(MaskKind.hostmask, entries[0].kind);
    try testing.expectEqualStrings("bad!*@spam.net", entries[0].mask); // lowercased
    try testing.expectEqualStrings("go away", entries[0].reason);
    try testing.expectEqualStrings("founder", entries[0].setter);

    const hit = store.matchOnJoin("#chan", "bad!evil@spam.net", null, 2000);
    try testing.expect(hit != null);
    try testing.expectEqualStrings("go away", hit.?.reason);

    try testing.expect(store.matchOnJoin("#chan", "good!ok@example.com", null, 2000) == null);
}

test "matchOnJoin: hostmask mirror matches mixed-case joining prefix" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#c", "Bad!*@*", "no bad", "admin", 1000, null);

    const hit_tilde = store.matchOnJoin("#c", "Bad!~bad@host", null, 2000);
    try testing.expect(hit_tilde != null);
    try testing.expectEqualStrings("no bad", hit_tilde.?.reason);

    const hit_plain = store.matchOnJoin("#c", "Bad!bad@host", null, 2000);
    try testing.expect(hit_plain != null);
    try testing.expectEqualStrings("no bad", hit_plain.?.reason);
}

test "channel name is matched case-insensitively" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();
    try store.add("#Chan", "x!*@*", "", "op", 1, null);
    try testing.expectEqual(@as(usize, 1), store.count("#chan"));
    try testing.expect(store.matchOnJoin("#CHAN", "x!a@b", null, 2) != null);
}

test "account mask: matches logged-in account, not unauthenticated" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "account:Troll*", "begone", "founder", 1000, null);
    const entries = store.list("#chan");
    try testing.expectEqual(MaskKind.account, entries[0].kind);
    try testing.expectEqualStrings("troll*", entries[0].pattern);

    // Matches a logged-in account (case-insensitive).
    try testing.expect(store.matchOnJoin("#chan", "n!u@h", "TrollKing", 2000) != null);
    // Different account: no match.
    try testing.expect(store.matchOnJoin("#chan", "n!u@h", "Friendly", 2000) == null);
    // Unauthenticated client: account mask never matches.
    try testing.expect(store.matchOnJoin("#chan", "n!u@h", null, 2000) == null);
    try testing.expect(store.matchOnJoin("#chan", "n!u@h", "", 2000) == null);
}

test "matchOnJoin: expired entries are skipped" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "evil!*@*", "temp ban", "op", 1000, 5000);
    // Before expiry -> match.
    try testing.expect(store.matchOnJoin("#chan", "evil!x@y", null, 4999) != null);
    // At/after expiry -> skipped.
    try testing.expect(store.matchOnJoin("#chan", "evil!x@y", null, 5000) == null);
    try testing.expect(store.matchOnJoin("#chan", "evil!x@y", null, 9999) == null);

    // Still present (skipped, not removed) until purge.
    try testing.expectEqual(@as(usize, 1), store.count("#chan"));
}

test "matchOnJoin: prefers first active when expired precedes valid" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "a!*@*", "expired one", "op", 0, 100);
    try store.add("#chan", "*!*@bad.host", "active one", "op", 0, null);

    // Joiner matches both masks; expired first entry is skipped, active wins.
    const hit = store.matchOnJoin("#chan", "a!u@bad.host", null, 500);
    try testing.expect(hit != null);
    try testing.expectEqualStrings("active one", hit.?.reason);
}

test "purgeExpired: reclaims only expired entries" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "a!*@*", "", "op", 0, 100);
    try store.add("#chan", "b!*@*", "", "op", 0, null);
    try store.add("#chan", "c!*@*", "", "op", 0, 50);

    const purged = store.purgeExpired("#chan", 200);
    try testing.expectEqual(@as(usize, 2), purged);
    const remaining = store.list("#chan");
    try testing.expectEqual(@as(usize, 1), remaining.len);
    try testing.expectEqualStrings("b!*@*", remaining[0].mask);
}

test "remove: existing and missing entries" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "Foo!*@*", "", "op", 0, null);
    // Remove with differently-cased mask (normalized internally).
    try testing.expectEqual(RemoveResult.removed, store.remove("#chan", "foo!*@*"));
    try testing.expectEqual(@as(usize, 0), store.count("#chan"));

    try testing.expectEqual(RemoveResult.not_found, store.remove("#chan", "foo!*@*"));
    try testing.expectEqual(RemoveResult.not_found, store.remove("#nope", "x!*@*"));
}

test "add: duplicate masks rejected (case-insensitive)" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#chan", "dup!*@*", "first", "op", 0, null);
    try testing.expectError(Error.Duplicate, store.add("#chan", "DUP!*@*", "second", "op", 0, null));
    try testing.expectEqual(@as(usize, 1), store.count("#chan"));
}

test "add: invalid masks rejected" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectError(Error.InvalidMask, store.add("#chan", "", "", "op", 0, null));
    try testing.expectError(Error.InvalidMask, store.add("#chan", "   ", "", "op", 0, null));
    // Bare account prefix with no glob is unusable.
    try testing.expectError(Error.InvalidMask, store.add("#chan", "account:", "", "op", 0, null));
}

test "bounds: ListFull at capacity" {
    var store = AkickStore.initCapacity(testing.allocator, 2);
    defer store.deinit();

    try store.add("#chan", "a!*@*", "", "op", 0, null);
    try store.add("#chan", "b!*@*", "", "op", 0, null);
    try testing.expectError(Error.ListFull, store.add("#chan", "c!*@*", "", "op", 0, null));
    try testing.expectEqual(@as(usize, 2), store.count("#chan"));

    // Removing frees a slot.
    try testing.expectEqual(RemoveResult.removed, store.remove("#chan", "a!*@*"));
    try store.add("#chan", "c!*@*", "", "op", 0, null);
    try testing.expectEqual(@as(usize, 2), store.count("#chan"));
}

test "isolation: entries are per-channel" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();

    try store.add("#one", "x!*@*", "one", "op", 0, null);
    try store.add("#two", "x!*@*", "two", "op", 0, null);

    try testing.expectEqualStrings("one", store.matchOnJoin("#one", "x!a@b", null, 1).?.reason);
    try testing.expectEqualStrings("two", store.matchOnJoin("#two", "x!a@b", null, 1).?.reason);
    try testing.expect(store.matchOnJoin("#three", "x!a@b", null, 1) == null);
}

test "unknown channel: list/count/match are empty/null, no alloc" {
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();
    try testing.expectEqual(@as(usize, 0), store.count("#ghost"));
    try testing.expectEqual(@as(usize, 0), store.list("#ghost").len);
    try testing.expect(store.matchOnJoin("#ghost", "n!u@h", null, 1) == null);
}

test "Entry.isExpired boundary" {
    const e_perm = Entry{
        .mask = "x",
        .pattern = "x",
        .kind = .hostmask,
        .reason = "",
        .setter = "",
        .added_at_ms = 0,
        .expires_at_ms = null,
    };
    try testing.expect(!e_perm.isExpired(std.math.maxInt(i64)));

    const e_temp = Entry{
        .mask = "x",
        .pattern = "x",
        .kind = .hostmask,
        .reason = "",
        .setter = "",
        .added_at_ms = 0,
        .expires_at_ms = 100,
    };
    try testing.expect(!e_temp.isExpired(99));
    try testing.expect(e_temp.isExpired(100));
    try testing.expect(e_temp.isExpired(101));
}
