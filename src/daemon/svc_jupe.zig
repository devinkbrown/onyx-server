// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! JUPE — server-name jupe store.
//!
//! The classic IRC JUPE: an operator forbids a SERVER name (glob) from linking
//! into the network. A juped name is refused when a mesh peer presenting it
//! reaches the established transition, so a rogue or decommissioned server can
//! never join — the local enforcement counterpart to `svc_resv` (channels) and
//! `ircx_saccess` (nicks), which forbid those namespaces respectively.
//!
//! Each entry carries a reason, the setter's name, and an optional absolute
//! expiry. The store owns every string it holds and frees them on removal,
//! sweep, and deinit. Matching is a pure case-insensitive glob, mirroring IRC
//! server-name folding.
//!
//! This module is a pure policy store + command parser: it has no knowledge of
//! clients, links, sockets, or numerics. The mesh-link path queries `isJuped`
//! with the peer's `remoteName()` and drops the link on a match.

const std = @import("std");

/// Numerics a dispatcher may use when surfacing JUPE results/errors.
pub const Numeric = enum(u16) {
    /// Reject JUPE from a non-oper session.
    ERR_NOPRIVILEGES = 481,
    /// Reject a malformed JUPE command.
    ERR_NEEDMOREPARAMS = 461,
};

/// A single server-name jupe. String fields are owned by the `JupeStore` that
/// returns them; borrow them only for the lifetime of the store.
pub const Entry = struct {
    /// Case-insensitive glob: `*` matches any run, `?` matches one byte.
    pattern: []const u8,
    reason: []const u8,
    setter: []const u8,
    created_ms: i64,
    /// Absolute expiry in epoch milliseconds; 0 means permanent.
    expires_ms: i64 = 0,

    /// Whether this entry has expired at `now_ms`. Permanent entries (expiry 0)
    /// never expire.
    pub fn isExpired(self: Entry, now_ms: i64) bool {
        return self.expires_ms != 0 and self.expires_ms <= now_ms;
    }
};

/// Storage and validation limits for a `JupeStore`.
pub const Params = struct {
    max_entries: usize = 1024,
    max_pattern: usize = 256,
    max_reason: usize = 512,
    max_setter: usize = 64,
};

/// Errors returned while validating or storing entries.
pub const JupeError = error{
    EmptyPattern,
    PatternTooLong,
    InvalidPattern,
    ReasonTooLong,
    SetterTooLong,
    TooManyEntries,
};

/// Errors returned while parsing a JUPE/UNJUPE command line.
pub const ParseError = error{
    UnknownCommand,
    MissingParameter,
    InvalidDuration,
    DurationOverflow,
} || JupeError;

/// Parsed real server command intent. Slices borrow from parser input.
pub const Command = union(enum) {
    add: AddRequest,
    remove: []const u8,
    list,
    sweep,
};

/// Parsed `JUPE <pattern> <duration-ms> :<reason>` request.
pub const AddRequest = struct {
    pattern: []const u8,
    reason: []const u8,
    duration_ms: i64,
    expires_ms: i64,
};

/// Owning registry for server-name jupes.
pub const JupeStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    /// Initialize an empty store with the supplied allocator and limits.
    pub fn init(allocator: std.mem.Allocator, params: Params) JupeStore {
        return .{ .allocator = allocator, .params = params };
    }

    /// Free all owned strings and backing storage.
    pub fn deinit(self: *JupeStore) void {
        for (self.entries.items) |*entry| freeEntry(self.allocator, entry);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Add a jupe, duplicating its strings. An existing entry with the same exact
    /// pattern is replaced in place (its prior strings freed). `expires_ms` of 0
    /// means permanent.
    pub fn add(
        self: *JupeStore,
        pattern: []const u8,
        reason: []const u8,
        setter: []const u8,
        created_ms: i64,
        expires_ms: i64,
    ) (JupeError || std.mem.Allocator.Error)!void {
        try self.validate(pattern, reason, setter);

        var owned = try self.clone(pattern, reason, setter, created_ms, expires_ms);
        errdefer freeEntry(self.allocator, &owned);

        if (self.indexOf(pattern)) |idx| {
            freeEntry(self.allocator, &self.entries.items[idx]);
            self.entries.items[idx] = owned;
            return;
        }

        if (self.entries.items.len >= self.params.max_entries) return error.TooManyEntries;
        try self.entries.append(self.allocator, owned);
    }

    /// Apply a parsed ADD request with a dispatcher-supplied setter + creation time.
    pub fn addParsed(
        self: *JupeStore,
        request: AddRequest,
        setter: []const u8,
        created_ms: i64,
    ) (JupeError || std.mem.Allocator.Error)!void {
        try self.add(request.pattern, request.reason, setter, created_ms, request.expires_ms);
    }

    /// Remove a jupe by exact pattern. Returns true when an entry was present.
    pub fn remove(self: *JupeStore, pattern: []const u8) bool {
        const idx = self.indexOf(pattern) orelse return false;
        var removed = self.entries.orderedRemove(idx);
        freeEntry(self.allocator, &removed);
        return true;
    }

    /// Copy every entry into `out` and return the filled prefix. Returned entries
    /// borrow owned strings from the store. Expired entries are included; call
    /// `sweep` first to exclude them.
    pub fn list(self: *const JupeStore, out: []Entry) []Entry {
        var n: usize = 0;
        for (self.entries.items) |entry| {
            if (n >= out.len) break;
            out[n] = entry;
            n += 1;
        }
        return out[0..n];
    }

    /// Return the first active entry whose pattern matches `server_name`, or null.
    /// Expired entries are skipped but not removed; matching is a pure
    /// case-insensitive glob.
    pub fn isJuped(self: *const JupeStore, server_name: []const u8, now_ms: i64) ?Entry {
        for (self.entries.items) |entry| {
            if (entry.isExpired(now_ms)) continue;
            if (globMatch(entry.pattern, server_name)) return entry;
        }
        return null;
    }

    /// Remove every entry whose expiry is at or before `now_ms`, freeing its
    /// strings. Returns the number of entries removed.
    pub fn sweep(self: *JupeStore, now_ms: i64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].isExpired(now_ms)) {
                var gone = self.entries.orderedRemove(i);
                freeEntry(self.allocator, &gone);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }

    /// Total number of stored entries.
    pub fn count(self: *const JupeStore) usize {
        return self.entries.items.len;
    }

    fn validate(
        self: *const JupeStore,
        pattern: []const u8,
        reason: []const u8,
        setter: []const u8,
    ) JupeError!void {
        try validateStoredEntry(self.params, .{
            .pattern = pattern,
            .reason = reason,
            .setter = setter,
            .created_ms = 0,
        });
    }

    fn clone(
        self: *JupeStore,
        pattern: []const u8,
        reason: []const u8,
        setter: []const u8,
        created_ms: i64,
        expires_ms: i64,
    ) std.mem.Allocator.Error!Entry {
        const owned_pattern = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned_pattern);
        const owned_reason = try self.allocator.dupe(u8, reason);
        errdefer self.allocator.free(owned_reason);
        const owned_setter = try self.allocator.dupe(u8, setter);
        return .{
            .pattern = owned_pattern,
            .reason = owned_reason,
            .setter = owned_setter,
            .created_ms = created_ms,
            .expires_ms = expires_ms,
        };
    }

    fn indexOf(self: *const JupeStore, pattern: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, idx| {
            if (std.mem.eql(u8, entry.pattern, pattern)) return idx;
        }
        return null;
    }
};

/// Validate a stored row against the exact limits of its owning registry.
/// Helix calls this without allocation while checking a custody image.
pub fn validateStoredEntry(params: Params, entry: Entry) JupeError!void {
    try validatePatternWithLimit(entry.pattern, params.max_pattern);
    if (entry.reason.len > params.max_reason) return error.ReasonTooLong;
    if (entry.setter.len > params.max_setter) return error.SetterTooLong;
}

fn freeEntry(allocator: std.mem.Allocator, entry: *Entry) void {
    allocator.free(entry.pattern);
    allocator.free(entry.reason);
    allocator.free(entry.setter);
    entry.* = undefined;
}

/// Parse a `JUPE`/`UNJUPE` real server command.
///
/// Supported forms:
/// * `JUPE <pattern> <duration-ms> :<reason>` (also `JUPE ADD …`)
/// * `JUPE DEL <pattern>` / `JUPE REMOVE <pattern>`
/// * `JUPE LIST`
/// * `JUPE SWEEP`
/// * `UNJUPE <pattern>`
pub fn parseServerCommand(verb: []const u8, params: []const []const u8, now_ms: i64) ParseError!Command {
    if (eqlFoldSlice(verb, "JUPE")) return parseJupeParams(params, now_ms);
    if (eqlFoldSlice(verb, "UNJUPE")) {
        if (params.len < 1) return error.MissingParameter;
        try validatePattern(params[0]);
        return .{ .remove = params[0] };
    }
    return error.UnknownCommand;
}

fn parseJupeParams(params: []const []const u8, now_ms: i64) ParseError!Command {
    if (params.len < 1) return error.MissingParameter;

    if (eqlFoldSlice(params[0], "LIST")) return .list;
    if (eqlFoldSlice(params[0], "SWEEP")) return .sweep;

    if (eqlFoldSlice(params[0], "DEL") or eqlFoldSlice(params[0], "REMOVE")) {
        if (params.len < 2) return error.MissingParameter;
        try validatePattern(params[1]);
        return .{ .remove = params[1] };
    }

    const add_offset: usize = if (eqlFoldSlice(params[0], "ADD")) 1 else 0;
    if (params.len < add_offset + 3) return error.MissingParameter;

    const pattern = params[add_offset];
    const duration_ms = try parseDurationMs(params[add_offset + 1]);
    const expires_ms = try expiryFromDuration(now_ms, duration_ms);
    const reason = params[add_offset + 2];

    try validatePattern(pattern);
    return .{ .add = .{
        .pattern = pattern,
        .reason = reason,
        .duration_ms = duration_ms,
        .expires_ms = expires_ms,
    } };
}

/// Validate a server-name JUPE glob with default limits.
pub fn validatePattern(pattern: []const u8) JupeError!void {
    return validatePatternWithLimit(pattern, (Params{}).max_pattern);
}

fn validatePatternWithLimit(pattern: []const u8, max_pattern: usize) JupeError!void {
    if (pattern.len == 0) return error.EmptyPattern;
    if (pattern.len > max_pattern) return error.PatternTooLong;
    // A server-name glob: letters, digits, dot, hyphen, underscore, and the glob
    // metacharacters `*`/`?`. Anything else (space, ':', ',', control) is rejected
    // so a pattern can never be confused with a multi-token command argument.
    for (pattern) |byte| {
        const ok = std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-' or
            byte == '_' or byte == '*' or byte == '?';
        if (!ok) return error.InvalidPattern;
    }
}

fn parseDurationMs(raw: []const u8) ParseError!i64 {
    if (raw.len == 0) return error.InvalidDuration;
    const value = std.fmt.parseInt(i64, raw, 10) catch return error.InvalidDuration;
    if (value < 0) return error.InvalidDuration;
    return value;
}

fn expiryFromDuration(now_ms: i64, duration_ms: i64) ParseError!i64 {
    if (duration_ms == 0) return 0;
    return std.math.add(i64, now_ms, duration_ms) catch error.DurationOverflow;
}

/// Case-insensitive glob: `*` matches any run (including empty), `?` matches a
/// single byte. Backtracking is iterative, so adversarial patterns cannot blow
/// the stack.
fn globMatch(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null;
    var mark: usize = 0;

    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or eqlFold(pattern[p], text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p;
            mark = t;
            p += 1;
        } else if (star) |s| {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

fn eqlFold(a: u8, b: u8) bool {
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

fn eqlFoldSlice(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!eqlFold(left, right)) return false;
    }
    return true;
}

const testing = std.testing;

test "add stores owned copies and isJuped glob-matches case-insensitively" {
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();

    // Mutate the caller buffer after add to prove the store owns its copy.
    var pat = [_]u8{ 'e', 'v', 'i', 'l', '.', '*' };
    try store.add(&pat, "rogue server", "oper", 100, 0);
    pat[0] = 'X';

    try testing.expectEqual(@as(usize, 1), store.count());
    const hit = store.isJuped("EVIL.example.com", 200).?;
    try testing.expectEqualStrings("evil.*", hit.pattern);
    try testing.expectEqualStrings("rogue server", hit.reason);
    try testing.expectEqualStrings("oper", hit.setter);
    // A non-matching server name is allowed.
    try testing.expect(store.isJuped("good.example.com", 200) == null);
}

test "add with same pattern replaces in place without leaking" {
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add("hub.*", "first", "alice", 100, 0);
    try store.add("hub.*", "second", "bob", 200, 0);
    try testing.expectEqual(@as(usize, 1), store.count());
    const hit = store.isJuped("hub.eu.net", 300).?;
    try testing.expectEqualStrings("second", hit.reason);
    try testing.expectEqualStrings("bob", hit.setter);
}

test "remove and expiry sweep" {
    var store = JupeStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.add("temp.*", "r", "o", 0, 1000); // expires at t=1000
    try store.add("perm.*", "r", "o", 0, 0); // permanent

    try testing.expect(store.isJuped("temp.x", 500) != null);
    try testing.expect(store.isJuped("temp.x", 1000) == null); // expired, skipped
    try testing.expectEqual(@as(usize, 1), store.sweep(1000));
    try testing.expect(store.isJuped("perm.y", 9999) != null);
    try testing.expect(store.remove("perm.*"));
    try testing.expect(!store.remove("perm.*"));
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "validation rejects bad patterns and enforces capacity" {
    var store = JupeStore.init(testing.allocator, .{ .max_entries = 1, .max_pattern = 8 });
    defer store.deinit();
    try testing.expectError(error.EmptyPattern, store.add("", "r", "o", 0, 0));
    try testing.expectError(error.PatternTooLong, store.add("waytoolong.example", "r", "o", 0, 0));
    try testing.expectError(error.InvalidPattern, store.add("bad name", "r", "o", 0, 0)); // space
    try store.add("ok.*", "r", "o", 0, 0);
    try testing.expectError(error.TooManyEntries, store.add("x.*", "r", "o", 0, 0));
}

test "parseServerCommand handles JUPE/UNJUPE forms" {
    // JUPE add (implicit and explicit ADD).
    const add = try parseServerCommand("JUPE", &.{ "evil.net", "60000", "rogue" }, 1000);
    try testing.expectEqualStrings("evil.net", add.add.pattern);
    try testing.expectEqual(@as(i64, 61000), add.add.expires_ms);
    const add2 = try parseServerCommand("JUPE", &.{ "ADD", "evil.net", "0", "perm" }, 1000);
    try testing.expectEqual(@as(i64, 0), add2.add.expires_ms); // 0 duration = permanent

    // DEL / UNJUPE both remove.
    try testing.expectEqualStrings("evil.net", (try parseServerCommand("JUPE", &.{ "DEL", "evil.net" }, 0)).remove);
    try testing.expectEqualStrings("evil.net", (try parseServerCommand("UNJUPE", &.{"evil.net"}, 0)).remove);

    // LIST / SWEEP.
    try testing.expect((try parseServerCommand("JUPE", &.{"LIST"}, 0)) == .list);
    try testing.expect((try parseServerCommand("JUPE", &.{"SWEEP"}, 0)) == .sweep);

    // Errors.
    try testing.expectError(error.MissingParameter, parseServerCommand("JUPE", &.{}, 0));
    try testing.expectError(error.UnknownCommand, parseServerCommand("WHAT", &.{"x"}, 0));
    try testing.expectError(error.InvalidDuration, parseServerCommand("JUPE", &.{ "evil.net", "soon", "r" }, 0));
    try testing.expectError(error.InvalidPattern, parseServerCommand("JUPE", &.{ "evil net", "0", "r" }, 0));
}
