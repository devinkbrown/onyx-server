// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onyx Server content filter (Koshi) — operator-curated message screening.
//!
//! An Onyx Server-native moderation primitive (not a clone of any other daemon's
//! "spamfilter"): a small set of oper-curated patterns is matched against
//! outgoing PRIVMSG / NOTICE bodies and a hit blocks the message. Patterns are
//! owned here and the Aho-Corasick automaton is rebuilt on every mutation — the
//! set is operator-curated and small, so rebuild cost is irrelevant and keeps
//! matching O(text) regardless of pattern count. Matching is case-insensitive.
const std = @import("std");
const aho = @import("../substrate/aho_corasick.zig");
const toml = @import("../proto/toml.zig");

pub const Error = std.mem.Allocator.Error;

pub const default_max_patterns: usize = 256;
pub const default_max_pattern_len: usize = 256;

/// Runtime-tunable Koshi filter limits. Defaults preserve the historical
/// hardcoded behaviour; the orchestrator overlays the `[filter]` TOML section
/// via `Config.applyToml` before constructing a `ContentFilter`.
pub const Config = struct {
    /// Max oper-curated filter patterns (Aho-Corasick set size).
    max_patterns: usize = default_max_patterns,
    /// Max length of a single filter pattern (bytes).
    max_pattern_len: usize = default_max_pattern_len,

    /// Overlay `[filter]` keys from a parsed TOML document onto `cfg`. Missing
    /// keys leave the current value untouched. Pure: no I/O, never fails.
    pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
        if (doc.getUint("filter.koshi_max_patterns")) |v| {
            if (v >= 1) cfg.max_patterns = @intCast(v);
        }
        if (doc.getUint("filter.koshi_pattern_max_len")) |v| {
            if (v >= 1) cfg.max_pattern_len = @intCast(v);
        }
    }
};

pub const ContentFilter = struct {
    allocator: std.mem.Allocator,
    patterns: std.ArrayListUnmanaged([]u8) = .empty,
    automaton: ?aho.AhoCorasick = null,
    cfg: Config = .{},

    pub fn init(allocator: std.mem.Allocator) ContentFilter {
        return .{ .allocator = allocator };
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, cfg: Config) ContentFilter {
        return .{ .allocator = allocator, .cfg = cfg };
    }

    pub fn deinit(self: *ContentFilter) void {
        for (self.patterns.items) |p| self.allocator.free(p);
        self.patterns.deinit(self.allocator);
        if (self.automaton) |*a| a.deinit();
        self.* = undefined;
    }

    /// Add a pattern (deduplicated, case-insensitive). Returns false if the
    /// pattern is empty, too long, the table is full, or it already exists.
    pub fn add(self: *ContentFilter, pattern: []const u8) Error!bool {
        if (pattern.len == 0 or pattern.len > self.cfg.max_pattern_len) return false;
        if (self.patterns.items.len >= self.cfg.max_patterns) return false;
        if (self.indexOf(pattern) != null) return false;
        const owned = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(owned);
        try self.patterns.append(self.allocator, owned);
        errdefer _ = self.patterns.orderedRemove(self.patterns.items.len - 1);
        try self.rebuild();
        return true;
    }

    /// Remove a pattern (case-insensitive). Returns true if it was present.
    pub fn remove(self: *ContentFilter, pattern: []const u8) Error!bool {
        const idx = self.indexOf(pattern) orelse return false;
        self.allocator.free(self.patterns.items[idx]);
        _ = self.patterns.orderedRemove(idx);
        try self.rebuild();
        return true;
    }

    /// Borrowed view of the current patterns (valid until the next mutation).
    pub fn list(self: *const ContentFilter) []const []u8 {
        return self.patterns.items;
    }

    /// Owned copy of the pattern list. The caller frees each string and the slice.
    pub fn clonedPatterns(self: *const ContentFilter) Error![][]u8 {
        const out = try self.allocator.alloc([]u8, self.patterns.items.len);
        var n: usize = 0;
        errdefer {
            for (out[0..n]) |p| self.allocator.free(p);
            self.allocator.free(out);
        }
        for (self.patterns.items) |p| {
            out[n] = try self.allocator.dupe(u8, p);
            n += 1;
        }
        return out;
    }

    /// Replace the pattern set. The previous set stays in place if allocation fails.
    pub fn restorePatterns(self: *ContentFilter, patterns: []const []const u8) Error!void {
        var next: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (next.items) |p| self.allocator.free(p);
            next.deinit(self.allocator);
        }
        for (patterns) |p| {
            const owned = try self.allocator.dupe(u8, p);
            errdefer self.allocator.free(owned);
            try next.append(self.allocator, owned);
        }
        var built: ?aho.AhoCorasick = null;
        errdefer if (built) |*a| a.deinit();
        if (next.items.len != 0) {
            built = try aho.AhoCorasick.build(self.allocator, next.items, .{ .case_insensitive = true });
        }
        if (self.automaton) |*a| a.deinit();
        self.automaton = built;
        built = null;
        for (self.patterns.items) |p| self.allocator.free(p);
        self.patterns.deinit(self.allocator);
        self.patterns = next;
    }

    /// Whether `text` contains any filtered pattern.
    pub fn matches(self: *const ContentFilter, text: []const u8) bool {
        const a = self.automaton orelse return false;
        return a.containsAny(text);
    }

    fn indexOf(self: *const ContentFilter, pattern: []const u8) ?usize {
        for (self.patterns.items, 0..) |p, i| {
            if (std.ascii.eqlIgnoreCase(p, pattern)) return i;
        }
        return null;
    }

    fn rebuild(self: *ContentFilter) Error!void {
        if (self.automaton) |*a| a.deinit();
        self.automaton = null;
        if (self.patterns.items.len == 0) return;
        self.automaton = try aho.AhoCorasick.build(self.allocator, self.patterns.items, .{ .case_insensitive = true });
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "add/match/remove round-trip (case-insensitive)" {
    var f = ContentFilter.init(testing.allocator);
    defer f.deinit();
    try testing.expect(!f.matches("anything")); // empty filter never matches
    try testing.expect(try f.add("spamword"));
    try testing.expect(f.matches("this is SPAMWORD here"));
    try testing.expect(!f.matches("clean message"));
    try testing.expect(try f.remove("SPAMWORD"));
    try testing.expect(!f.matches("this is spamword here"));
}

test "dedup and empty/oversize rejected" {
    var f = ContentFilter.init(testing.allocator);
    defer f.deinit();
    try testing.expect(try f.add("foo"));
    try testing.expect(!try f.add("FOO")); // duplicate (case-insensitive)
    try testing.expect(!try f.add("")); // empty rejected
    try testing.expectEqual(@as(usize, 1), f.list().len);
}

test "multiple patterns match independently" {
    var f = ContentFilter.init(testing.allocator);
    defer f.deinit();
    _ = try f.add("buy now");
    _ = try f.add("free money");
    try testing.expect(f.matches("get FREE MONEY today"));
    try testing.expect(f.matches("please buy now!"));
    try testing.expect(!f.matches("a normal sentence"));
    try testing.expect(try f.remove("buy now"));
    try testing.expect(!f.matches("please buy now!"));
    try testing.expect(f.matches("free money still here"));
}

test "Config defaults preserve historical limits" {
    const cfg = Config{};
    try testing.expectEqual(default_max_patterns, cfg.max_patterns);
    try testing.expectEqual(default_max_pattern_len, cfg.max_pattern_len);
}

test "Config.applyToml overlays [filter] koshi keys" {
    var doc = try toml.parse(
        testing.allocator,
        "[filter]\nkoshi_max_patterns = 16\nkoshi_pattern_max_len = 32\n",
    );
    defer doc.deinit(testing.allocator);

    var cfg = Config{};
    cfg.applyToml(&doc);
    try testing.expectEqual(@as(usize, 16), cfg.max_patterns);
    try testing.expectEqual(@as(usize, 32), cfg.max_pattern_len);
}

test "initWithConfig enforces a smaller pattern cap" {
    var f = ContentFilter.initWithConfig(testing.allocator, .{ .max_patterns = 1 });
    defer f.deinit();
    try testing.expect(try f.add("first"));
    try testing.expect(!try f.add("second")); // table full
    try testing.expectEqual(@as(usize, 1), f.list().len);
}
