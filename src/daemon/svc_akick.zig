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
const cloak_match = @import("../proto/cloak_match.zig");

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

/// Validate and trim the mask identity shared by durable and live ADD paths.
/// Callers retain ownership; accepted masks are compared with ASCII folding.
pub fn validateAddMask(mask: []const u8) error{InvalidMask}![]const u8 {
    const trimmed = std.mem.trim(u8, mask, " ");
    if (trimmed.len == 0 or classify(trimmed).pattern.len == 0) return error.InvalidMask;
    return trimmed;
}

/// Evaluate a candidate before durable/live publication. Uses exactly the
/// installed entry matcher, without expiry, authority checks or allocation.
pub fn candidateMatchesWithCloak(mask: []const u8, hostmask: []const u8, account: ?[]const u8, ctx: ?cloak_match.Context) Error!bool {
    return classifiedMatches(classify(try validateAddMask(mask)), hostmask, account, ctx);
}

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

    /// Restore empty channel rows from older checkpoints as well as nonempty
    /// lists. Purge also keeps the channel row after removing its last entry.
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

    /// Owns an unpublished entry and the capacity needed to publish it. Keep
    /// the store alive and do not mutate it while this single-use value exists.
    /// Abort after a failed durable write; commit only after durable success.
    pub const PreparedAdd = struct {
        store: *AkickStore,
        channel: []const u8,
        entry: ?Entry,
        new_channel: bool,
        new_entries: std.ArrayListUnmanaged(Entry) = .empty,

        /// Publish without allocation or any remaining admission checks.
        pub fn commit(self: *PreparedAdd) void {
            const entry = self.entry orelse unreachable;
            if (self.new_channel) {
                self.new_entries.appendAssumeCapacity(entry);
                self.store.channels.putAssumeCapacityNoClobber(self.channel, .{ .entries = self.new_entries });
                self.new_entries = .empty;
            } else {
                const cl = self.store.channels.getPtr(self.channel).?;
                cl.entries.appendAssumeCapacity(entry);
                self.store.alloc.free(self.channel);
            }
            self.entry = null;
        }

        /// Idempotent for this owning value; do not copy prepared ownership.
        pub fn abort(self: *PreparedAdd) void {
            const entry = self.entry orelse return;
            freeEntry(self.store.alloc, entry);
            self.store.alloc.free(self.channel);
            self.new_entries.deinit(self.store.alloc);
            self.entry = null;
        }
    };

    /// Prepare every fallible live admission step without publishing a row or
    /// entry. On failure, existing entries and channel membership are unchanged.
    /// Successful preparation may reserve unused backing capacity.
    pub fn prepareAdd(
        self: *AkickStore,
        channel: []const u8,
        mask: []const u8,
        reason: []const u8,
        setter: []const u8,
        added_at_ms: i64,
        expires_at_ms: ?i64,
    ) Error!PreparedAdd {
        var key_buf: [256]u8 = undefined;
        const key = channelKeyTmp(&key_buf, channel) catch return Error.InvalidMask;
        if (key.len == 0) return Error.InvalidMask;
        const trimmed = try validateAddMask(mask);

        const cl = self.channels.getPtr(key);
        if (cl) |existing_channel| {
            // Reject a duplicate even when the list is full: no implicit
            // replacement of reason, setter, timestamp, expiry or ordering.
            for (existing_channel.entries.items) |existing| {
                if (std.ascii.eqlIgnoreCase(existing.mask, trimmed)) return Error.Duplicate;
            }
            if (existing_channel.entries.items.len >= self.max_per_channel) return Error.ListFull;
        } else if (self.max_per_channel == 0) return Error.ListFull;

        const owned_key = try self.alloc.dupe(u8, key);
        errdefer self.alloc.free(owned_key);
        const mask_copy = try self.alloc.alloc(u8, trimmed.len);
        errdefer self.alloc.free(mask_copy);
        lowerInto(mask_copy, trimmed);
        const kind_pattern = classify(mask_copy);
        const reason_copy = try self.alloc.dupe(u8, reason);
        errdefer self.alloc.free(reason_copy);
        const setter_copy = try self.alloc.dupe(u8, setter);
        errdefer self.alloc.free(setter_copy);

        var new_entries: std.ArrayListUnmanaged(Entry) = .empty;
        errdefer new_entries.deinit(self.alloc);
        if (cl) |existing_channel| {
            try existing_channel.entries.ensureUnusedCapacity(self.alloc, 1);
        } else {
            try new_entries.ensureUnusedCapacity(self.alloc, 1);
            // Last fallible step: no empty channel row survives an OOM.
            try self.channels.ensureUnusedCapacity(self.alloc, 1);
        }
        return .{
            .store = self,
            .channel = owned_key,
            .entry = .{
                .mask = mask_copy,
                .pattern = kind_pattern.pattern,
                .kind = kind_pattern.kind,
                .reason = reason_copy,
                .setter = setter_copy,
                .added_at_ms = added_at_ms,
                .expires_at_ms = expires_at_ms,
            },
            .new_channel = cl == null,
            .new_entries = new_entries,
        };
    }

    /// Copy and publish an entry immediately. Durable callers must instead use
    /// prepareAdd, commit their durable write, then commit the prepared entry.
    pub fn add(
        self: *AkickStore,
        channel: []const u8,
        mask: []const u8,
        reason: []const u8,
        setter: []const u8,
        added_at_ms: i64,
        expires_at_ms: ?i64,
    ) Error!void {
        var prepared = try self.prepareAdd(channel, mask, reason, setter, added_at_ms, expires_at_ms);
        defer prepared.abort();
        prepared.commit();
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
        return self.matchOnJoinWithCloak(channel, hostmask, account, now_ms, null);
    }

    pub fn matchOnJoinWithCloak(self: *AkickStore, channel: []const u8, hostmask: []const u8, account: ?[]const u8, now_ms: i64, ctx: ?cloak_match.Context) ?*const Entry {
        var key_buf: [256]u8 = undefined;
        const key = channelKeyTmp(&key_buf, channel) catch return null;
        const cl = self.channels.getPtr(key) orelse return null;

        for (cl.entries.items) |*entry| {
            if (entry.isExpired(now_ms)) continue;
            if (classifiedMatches(.{ .kind = entry.kind, .pattern = entry.pattern }, hostmask, account, ctx)) return entry;
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

fn classifiedMatches(mask: KindPattern, hostmask: []const u8, account: ?[]const u8, ctx: ?cloak_match.Context) bool {
    return switch (mask.kind) {
        .hostmask => cloak_match.match(mask.pattern, hostmask, ctx),
        .account => blk: {
            const acct = account orelse break :blk false;
            if (acct.len == 0) break :blk false;
            break :blk globMatch(mask.pattern, acct);
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

test "cloak AKICK continuity respects original hostmask and expiry" {
    const c = @import("../proto/cloak.zig");
    const key = c.SecretKey.init(@splat(7));
    var old: [253]u8 = undefined;
    const before = try c.cloakOpaqueEpochV4(&old, &key, "203.0.113.9", 1, 86400, .{});
    var mask_buf: [512]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_buf, "Nick!*@{s}", .{before});
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();
    try store.add("#cloak", mask, "reason", "oper", 1000, 2000);
    const ctx: cloak_match.Context = .{ .key = key, .suffix = "onyx", .address = "203.0.113.9" };
    try testing.expect(store.matchOnJoinWithCloak("#cloak", "Nick!u@current.onyx", null, 1001, ctx) != null);
    try testing.expect(store.matchOnJoinWithCloak("#cloak", "Other!u@current.onyx", null, 1001, ctx) == null);
    try testing.expect(store.matchOnJoinWithCloak("#cloak", "Nick!u@current.onyx", null, 2000, ctx) == null);
}

test "prepared add: abort preserves rows and commit owns metadata without allocation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{});
    var store = AkickStore.init(failing.allocator());
    defer store.deinit();

    var aborted = try store.prepareAdd("#New", "Bad!*@*", "reason", "issuer", 12, 99);
    try testing.expectEqual(@as(usize, 0), store.channels.count());
    aborted.abort();
    aborted.abort();
    try testing.expectEqual(@as(usize, 0), store.channels.count());

    var prepared = try store.prepareAdd("#New", "Account:BaD", "reason", "issuer", 12, 99);
    defer prepared.abort();
    const allocations = failing.alloc_index;
    failing.fail_index = allocations;
    prepared.commit();
    try testing.expect(!failing.has_induced_failure);
    try testing.expectEqual(allocations, failing.alloc_index);
    const entries = store.list("#NEW");
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("account:bad", entries[0].mask);
    try testing.expectEqualStrings("bad", entries[0].pattern);
    try testing.expectEqualStrings("reason", entries[0].reason);
    try testing.expectEqualStrings("issuer", entries[0].setter);
    try testing.expectEqual(@as(i64, 12), entries[0].added_at_ms);
    try testing.expectEqual(@as(?i64, 99), entries[0].expires_at_ms);

    failing.fail_index = std.math.maxInt(usize);
    var existing = try store.prepareAdd("#new", "second!*@*", "next", "other", 14, null);
    defer existing.abort();
    const next_allocations = failing.alloc_index;
    failing.fail_index = next_allocations;
    existing.commit();
    try testing.expect(!failing.has_induced_failure);
    try testing.expectEqual(next_allocations, failing.alloc_index);
    try testing.expectEqual(@as(usize, 2), store.count("#new"));
    try testing.expectEqualStrings("account:bad", store.list("#new")[0].mask);
    try testing.expectEqualStrings("second!*@*", store.list("#new")[1].mask);
}

test "prepared add: duplicate and capacity rejection preserve existing rule" {
    var store = AkickStore.initCapacity(testing.allocator, 1);
    defer store.deinit();
    try store.add("#chan", "Bad!*@*", "original", "issuer", 17, 99);
    try testing.expectError(Error.Duplicate, store.prepareAdd("#CHAN", " BAD!*@* ", "replacement", "other", 22, null));
    try testing.expectError(Error.ListFull, store.prepareAdd("#chan", "another!*@*", "overflow", "other", 23, null));
    const entry = store.list("#chan")[0];
    try testing.expectEqual(@as(usize, 1), store.count("#chan"));
    try testing.expectEqualStrings("original", entry.reason);
    try testing.expectEqualStrings("issuer", entry.setter);
    try testing.expectEqual(@as(i64, 17), entry.added_at_ms);
    try testing.expectEqual(@as(?i64, 99), entry.expires_at_ms);
}

test "prepared add: allocation failure never publishes an empty channel" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = AkickStore.init(allocator);
            defer store.deinit();
            var prepared = store.prepareAdd("#chan", "bad!*@*", "reason", "issuer", 12, null) catch |err| {
                try testing.expectEqual(@as(usize, 0), store.channels.count());
                try testing.expectEqual(@as(usize, 0), store.count("#chan"));
                store.alloc = testing.allocator;
                try store.add("#chan", "bad!*@*", "retry", "issuer", 12, null);
                try testing.expectEqualStrings("retry", store.list("#chan")[0].reason);
                return err;
            };
            defer prepared.abort();
            try testing.expectEqual(@as(usize, 0), store.channels.count());
            prepared.commit();
            try testing.expectEqual(@as(usize, 1), store.count("#chan"));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}

test "prepared add: allocation failure and abort preserve existing entry order" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = AkickStore.init(testing.allocator);
            defer store.deinit();
            try store.add("#chan", "first!*@*", "original", "issuer", 17, 99);
            // Force the existing-list reservation to grow, so this sweep
            // includes its final fallible step as well as owned string copies.
            const cl = store.channels.getPtr("#chan").?;
            const tight = try testing.allocator.dupe(Entry, cl.entries.items);
            cl.entries.deinit(testing.allocator);
            cl.entries = std.ArrayList(Entry).fromOwnedSlice(tight);
            const original_mask = store.list("#chan")[0].mask.ptr;
            store.alloc = allocator;
            var prepared = store.prepareAdd("#CHAN", "second!*@*", "next", "other", 22, null) catch |err| {
                try testing.expectEqual(@as(usize, 1), store.channels.count());
                try testing.expectEqual(@as(usize, 1), store.count("#chan"));
                const original = store.list("#chan")[0];
                try testing.expectEqual(original_mask, original.mask.ptr);
                try testing.expectEqualStrings("original", original.reason);
                try testing.expectEqualStrings("issuer", original.setter);
                try testing.expectEqual(@as(i64, 17), original.added_at_ms);
                try testing.expectEqual(@as(?i64, 99), original.expires_at_ms);
                store.alloc = testing.allocator;
                try store.add("#chan", "second!*@*", "retry", "other", 22, null);
                try testing.expectEqualStrings("first!*@*", store.list("#chan")[0].mask);
                try testing.expectEqualStrings("second!*@*", store.list("#chan")[1].mask);
                return err;
            };
            prepared.abort();
            try testing.expectEqual(@as(usize, 1), store.count("#chan"));
            try testing.expectEqual(original_mask, store.list("#chan")[0].mask.ptr);
            try testing.expectEqualStrings("original", store.list("#chan")[0].reason);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{});
}

test "candidate AKICK matching shares installed trim account and hostmask semantics" {
    const Case = struct {
        mask: []const u8,
        hostmask: []const u8,
        account: ?[]const u8,
        expected: bool,
    };
    const cases = [_]Case{
        .{ .mask = "  BaD!*@Example.?om ", .hostmask = "BAD!u@EXAMPLE.com", .account = null, .expected = true },
        .{ .mask = "BaD!*@Example.?om", .hostmask = "Other!u@example.com", .account = "bad", .expected = false },
        .{ .mask = " Account:AL?CE ", .hostmask = "other!u@elsewhere", .account = "aLiCe", .expected = true },
        .{ .mask = "Account:*", .hostmask = "alice!u@host", .account = null, .expected = false },
        .{ .mask = "Account:*", .hostmask = "alice!u@host", .account = "", .expected = false },
        .{ .mask = "Account:AL?CE", .hostmask = "Alice!u@host", .account = "mallory", .expected = false },
    };
    for (cases) |case| {
        const candidate = try candidateMatchesWithCloak(case.mask, case.hostmask, case.account, null);
        try testing.expectEqual(case.expected, candidate);
        var store = AkickStore.init(testing.allocator);
        defer store.deinit();
        try store.add("#chan", case.mask, "reason", "issuer", 12, null);
        try testing.expectEqual(candidate, store.matchOnJoinWithCloak("#chan", case.hostmask, case.account, 13, null) != null);
    }
    try testing.expectError(error.InvalidMask, candidateMatchesWithCloak("   ", "nick!u@host", null, null));
    try testing.expectError(error.InvalidMask, candidateMatchesWithCloak(" Account: ", "nick!u@host", "alice", null));
}

test "candidate AKICK matching preserves cloak continuity and prefix restrictions before add" {
    const c = @import("../proto/cloak.zig");
    const old_key = c.SecretKey.init(@splat(7));
    const current_key = c.SecretKey.init(@splat(8));
    var old: [253]u8 = undefined;
    const before = try c.cloakOpaqueEpochV4(&old, &old_key, "203.0.113.9", 1, 86400, .{});
    var mask_buf: [512]u8 = undefined;
    const mask = try std.fmt.bufPrint(&mask_buf, " Nick!u?er@{s} ", .{before});
    const ctx: cloak_match.Context = .{ .key = current_key, .previous_key = old_key, .suffix = "onyx", .address = "203.0.113.9" };
    try testing.expect(try candidateMatchesWithCloak(mask, "NICK!user@current.onyx", null, ctx));
    try testing.expect(!try candidateMatchesWithCloak(mask, "Other!user@current.onyx", null, ctx));
    try testing.expect(!try candidateMatchesWithCloak(mask, "Nick!root@current.onyx", null, ctx));
    try testing.expect(!try candidateMatchesWithCloak(mask, "Nick!user@current.onyx", null, null));
    var wrong_address = ctx;
    wrong_address.address = "203.0.113.10";
    try testing.expect(!try candidateMatchesWithCloak(mask, "Nick!user@current.onyx", null, wrong_address));
    var store = AkickStore.init(testing.allocator);
    defer store.deinit();
    try store.add("#cloak", mask, "reason", "issuer", 12, null);
    try testing.expect(store.matchOnJoinWithCloak("#cloak", "NICK!user@current.onyx", null, 13, ctx) != null);
    try testing.expect(store.matchOnJoinWithCloak("#cloak", "Other!user@current.onyx", null, 13, ctx) == null);
}
