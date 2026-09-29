// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Decaying IP reputation / penalty table.
//!
//! A pure, allocator-backed map from client IP address to a floating-point
//! reputation score. Positive scores represent accumulated *penalty* (bad
//! behaviour); negative scores represent accumulated *reward* (good standing).
//! Scores decay exponentially toward zero over time so that both penalties and
//! rewards are forgiven if the address goes quiet.
//!
//! ## Purity
//!
//! This module performs no I/O and never reads a clock. Every call that cares
//! about the passage of time takes an explicit `now_ms` parameter (a caller
//! supplied monotonic-ish millisecond timestamp). The only side effect is
//! memory allocation through the injected allocator. This makes the decay math
//! fully deterministic and trivially testable.
//!
//! ## Decay formula
//!
//! Each entry stores a score `s0` captured at timestamp `t0`. The decayed
//! score at a later timestamp `t` is:
//!
//!     s(t) = s0 * 2^(-(t - t0) / H)
//!
//! where `H` is the configured `half_life_ms`. After exactly one half-life the
//! magnitude of the score halves; after two half-lives it quarters; and so on.
//! Equivalently `s(t) = s0 * exp(-(t - t0) * ln2 / H)`, which is what we
//! compute. The decay is symmetric for positive (penalty) and negative
//! (reward) scores. When `t <= t0` (clock not advanced or moved backward) no
//! decay is applied.
//!
//! ## Refusal
//!
//! `shouldRefuse` reports whether the *decayed penalty* (positive score only)
//! is greater than or equal to the configured `refuse_threshold`. A reward
//! driven (negative) score never refuses.

const std = @import("std");

const dns = @import("../proto/dns.zig");

/// Client address type. Re-exported for caller convenience.
pub const Address = dns.Address;

/// Tunable parameters for an `IpReputation` table.
pub const Config = struct {
    /// Half-life of score decay, in milliseconds. Must be > 0.
    half_life_ms: u64 = 60_000,
    /// Decayed penalty (positive score) at or above which `shouldRefuse`
    /// returns true.
    refuse_threshold: f64 = 100.0,
    /// Entries whose decayed magnitude is at or below this value are considered
    /// negligible and are eligible for eviction by `sweep`.
    negligible: f64 = 0.5,
};

pub const Error = error{
    /// half_life_ms was zero, which would make the decay rate undefined.
    InvalidHalfLife,
    /// A stored row was not an IPv4 or IPv6 key.
    BadRow,
} || std.mem.Allocator.Error;

/// One reputation row as stored, before decay. `tag` is 4 or 6.
pub const StoredRow = struct {
    tag: u8,
    bytes: [16]u8,
    score: f64,
    updated_ms: u64,
};

/// A fixed-width hashable key derived from an `Address`. Tag byte distinguishes
/// the IPv4 / IPv6 families so that, e.g., an IPv4-mapped pattern cannot alias.
const Key = struct {
    tag: u8,
    bytes: [16]u8,

    fn fromAddress(addr: Address) Key {
        var out = Key{ .tag = 0, .bytes = @as([16]u8, @splat(0)) };
        switch (addr) {
            .ipv4 => |b| {
                out.tag = 4;
                @memcpy(out.bytes[0..4], &b);
            },
            .ipv6 => |b| {
                out.tag = 6;
                @memcpy(out.bytes[0..16], &b);
            },
        }
        return out;
    }
};

const Entry = struct {
    /// Score captured at `updated_ms`.
    score: f64,
    /// Timestamp the score was last (re)computed.
    updated_ms: u64,
};

pub const IpReputation = struct {
    allocator: std.mem.Allocator,
    config: Config,
    entries: std.AutoHashMapUnmanaged(Key, Entry),

    pub fn init(allocator: std.mem.Allocator, config: Config) Error!IpReputation {
        if (config.half_life_ms == 0) return error.InvalidHalfLife;
        return .{
            .allocator = allocator,
            .config = config,
            .entries = .empty,
        };
    }

    pub fn deinit(self: *IpReputation) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Number of live entries currently tracked.
    pub fn count(self: *const IpReputation) usize {
        return self.entries.count();
    }

    /// Add `points` of penalty to `addr`'s decayed score. `points` should be
    /// non-negative; callers expressing forgiveness should use `reward`.
    pub fn penalize(self: *IpReputation, addr: Address, points: f64, now_ms: u64) Error!f64 {
        return self.adjust(addr, points, now_ms);
    }

    /// Subtract `points` of penalty from `addr`'s decayed score (i.e. improve
    /// standing). `points` should be non-negative.
    pub fn reward(self: *IpReputation, addr: Address, points: f64, now_ms: u64) Error!f64 {
        return self.adjust(addr, -points, now_ms);
    }

    /// Forget all accumulated penalty for `addr` (oper UNREJECT). Returns true
    /// if an entry was present and removed.
    pub fn clear(self: *IpReputation, addr: Address) bool {
        return self.entries.remove(Key.fromAddress(addr));
    }

    /// Drop every row. Used when a durable generation replaces the table.
    pub fn clearAll(self: *IpReputation) void {
        self.entries.deinit(self.allocator);
        self.entries = .empty;
    }

    /// Copy live rows. The caller frees the slice; it is not a view.
    pub fn dupeRows(self: *const IpReputation, allocator: std.mem.Allocator) Error![]StoredRow {
        const rows = try allocator.alloc(StoredRow, self.entries.count());
        var n: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            rows[n] = .{
                .tag = kv.key_ptr.tag,
                .bytes = kv.key_ptr.bytes,
                .score = kv.value_ptr.score,
                .updated_ms = kv.value_ptr.updated_ms,
            };
            n += 1;
        }
        return rows;
    }

    /// Insert or replace one stored row without applying decay.
    pub fn importRow(self: *IpReputation, row: StoredRow) Error!void {
        if (row.tag != 4 and row.tag != 6) return error.BadRow;
        try self.entries.put(self.allocator, .{ .tag = row.tag, .bytes = row.bytes }, .{
            .score = row.score,
            .updated_ms = row.updated_ms,
        });
    }

    /// Current time-decayed score for `addr`. Unknown addresses score 0.
    /// Read-only: does not allocate or mutate the table.
    pub fn score(self: *const IpReputation, addr: Address, now_ms: u64) f64 {
        const key = Key.fromAddress(addr);
        const entry = self.entries.get(key) orelse return 0;
        return decayed(entry, now_ms, self.config.half_life_ms);
    }

    /// True when the decayed penalty (positive score) is at or above the
    /// configured refuse threshold.
    pub fn shouldRefuse(self: *const IpReputation, addr: Address, now_ms: u64) bool {
        return self.score(addr, now_ms) >= self.config.refuse_threshold;
    }

    /// Evict entries whose decayed magnitude is at or below `config.negligible`.
    /// Returns the number of entries removed.
    pub fn sweep(self: *IpReputation, now_ms: u64) usize {
        var removed: usize = 0;
        var doomed = std.ArrayListUnmanaged(Key).empty;
        defer doomed.deinit(self.allocator);

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const mag = @abs(decayed(kv.value_ptr.*, now_ms, self.config.half_life_ms));
            if (mag <= self.config.negligible) {
                doomed.append(self.allocator, kv.key_ptr.*) catch break;
            }
        }

        for (doomed.items) |k| {
            if (self.entries.remove(k)) removed += 1;
        }
        return removed;
    }

    fn adjust(self: *IpReputation, addr: Address, delta: f64, now_ms: u64) Error!f64 {
        const key = Key.fromAddress(addr);
        const gop = try self.entries.getOrPut(self.allocator, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .score = 0, .updated_ms = now_ms };
        }
        const current = decayed(gop.value_ptr.*, now_ms, self.config.half_life_ms);
        const next = current + delta;
        gop.value_ptr.* = .{ .score = next, .updated_ms = now_ms };
        return next;
    }
};

/// Decay `entry`'s stored score forward to `now_ms` using the half-life model.
fn decayed(entry: Entry, now_ms: u64, half_life_ms: u64) f64 {
    if (now_ms <= entry.updated_ms) return entry.score;
    const dt: f64 = @floatFromInt(now_ms - entry.updated_ms);
    const hl: f64 = @floatFromInt(half_life_ms);
    // 2^(-dt/H) == exp(-dt/H * ln2)
    const factor = @exp(-(dt / hl) * std.math.ln2);
    return entry.score * factor;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn v4(a: u8, b: u8, c: u8, d: u8) Address {
    return .{ .ipv4 = .{ a, b, c, d } };
}

test "penalize raises the decayed score by the points applied" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{ .half_life_ms = 1000 });
    defer rep.deinit();
    const addr = v4(10, 0, 0, 1);

    // Act
    const after = try rep.penalize(addr, 40, 0);

    // Assert
    try testing.expectApproxEqAbs(@as(f64, 40), after, 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 40), rep.score(addr, 0), 1e-9);
}

test "score decays to roughly half after one half-life" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{ .half_life_ms = 1000 });
    defer rep.deinit();
    const addr = v4(192, 168, 1, 1);
    _ = try rep.penalize(addr, 80, 0);

    // Act
    const half = rep.score(addr, 1000);
    const quarter = rep.score(addr, 2000);

    // Assert
    try testing.expectApproxEqAbs(@as(f64, 40), half, 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 20), quarter, 1e-6);
}

test "reward offsets a prior penalty" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{ .half_life_ms = 1000 });
    defer rep.deinit();
    const addr = v4(172, 16, 0, 9);
    _ = try rep.penalize(addr, 50, 0);

    // Act: reward at the same instant so no decay occurs
    const after = try rep.reward(addr, 30, 0);

    // Assert
    try testing.expectApproxEqAbs(@as(f64, 20), after, 1e-9);
}

test "shouldRefuse trips above threshold and clears after decay" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{
        .half_life_ms = 1000,
        .refuse_threshold = 100,
    });
    defer rep.deinit();
    const addr = v4(203, 0, 113, 7);
    _ = try rep.penalize(addr, 200, 0);

    // Act + Assert: above threshold immediately
    try testing.expect(rep.shouldRefuse(addr, 0));

    // After two half-lives: 200 -> 50, below the threshold of 100.
    try testing.expect(!rep.shouldRefuse(addr, 2000));
}

test "shouldRefuse never trips on a reward-driven negative score" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{ .refuse_threshold = 1 });
    defer rep.deinit();
    const addr = v4(8, 8, 8, 8);

    // Act
    _ = try rep.reward(addr, 1000, 0);

    // Assert
    try testing.expect(!rep.shouldRefuse(addr, 0));
}

test "sweep evicts entries whose decayed magnitude is negligible" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{
        .half_life_ms = 1000,
        .negligible = 0.5,
    });
    defer rep.deinit();
    const fading = v4(1, 1, 1, 1);
    const persistent = v4(2, 2, 2, 2);
    _ = try rep.penalize(fading, 4, 0);
    _ = try rep.penalize(persistent, 10_000, 0);
    try testing.expectEqual(@as(usize, 2), rep.count());

    // Act: after many half-lives the small entry decays below 0.5.
    // 4 * 2^(-4) = 0.25 <= 0.5, while 10000 * 2^(-4) = 625 stays.
    const removed = rep.sweep(4000);

    // Assert
    try testing.expectEqual(@as(usize, 1), removed);
    try testing.expectEqual(@as(usize, 1), rep.count());
    try testing.expect(rep.score(fading, 4000) == 0);
    try testing.expect(rep.score(persistent, 4000) > 1);
}

test "unknown address scores zero and does not refuse" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{});
    defer rep.deinit();
    const unknown = v4(127, 0, 0, 1);

    // Act + Assert
    try testing.expectEqual(@as(f64, 0), rep.score(unknown, 12345));
    try testing.expect(!rep.shouldRefuse(unknown, 12345));
}

test "ipv4 and ipv6 keys do not alias" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{ .half_life_ms = 1000 });
    defer rep.deinit();
    const four = v4(0, 0, 0, 0);
    const six = Address{ .ipv6 = @as([16]u8, @splat(0)) };

    // Act
    _ = try rep.penalize(four, 10, 0);
    _ = try rep.penalize(six, 99, 0);

    // Assert
    try testing.expectApproxEqAbs(@as(f64, 10), rep.score(four, 0), 1e-9);
    try testing.expectApproxEqAbs(@as(f64, 99), rep.score(six, 0), 1e-9);
    try testing.expectEqual(@as(usize, 2), rep.count());
}

test "init rejects a zero half-life" {
    // Act + Assert
    try testing.expectError(error.InvalidHalfLife, IpReputation.init(testing.allocator, .{ .half_life_ms = 0 }));
}

test "backward clock does not increase decay" {
    // Arrange
    var rep = try IpReputation.init(testing.allocator, .{ .half_life_ms = 1000 });
    defer rep.deinit();
    const addr = v4(5, 5, 5, 5);
    _ = try rep.penalize(addr, 30, 5000);

    // Act: query with a now_ms earlier than the entry's timestamp
    const s = rep.score(addr, 1000);

    // Assert: no decay applied (and no growth)
    try testing.expectApproxEqAbs(@as(f64, 30), s, 1e-9);
}
