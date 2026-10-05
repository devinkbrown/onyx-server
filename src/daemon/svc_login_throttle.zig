// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Failed-login throttle for the IDENTIFY service command.
//!
//! This is the service-layer brute-force guard. It is deliberately distinct
//! from `login_throttle.zig` (which uses a discrete failure counter with
//! exponential lockout backoff and a single keyspace). This module instead
//! models a *continuously decaying* failure score per key, with a flat lockout
//! cooldown once a threshold score is crossed, and it keeps two independent
//! namespaces so that an attacker abusing one account cannot lock out an IP's
//! other accounts and vice versa.
//!
//! The semantics requested by the service layer:
//!   - `recordFailure(scope, key, now_ms)` bumps the decaying score; if the
//!     score crosses the threshold a flat cooldown lockout is armed.
//!   - `recordSuccess(scope, key)` fully clears the key (score + lockout).
//!   - `isLocked(scope, key, now_ms) -> ?retry_after_ms` reports how long the
//!     caller must wait, or null when not locked.
//!
//! All time is injected by the caller as monotonic milliseconds, so behaviour
//! is fully deterministic and testable without a real clock.

const std = @import("std");

pub const max_checkpoint_bytes: usize = @import("helix/live.zig").max_arena_bytes;
pub const max_checkpoint_entries_per_scope: usize = 1_048_576;
pub const max_checkpoint_key_bytes: usize = 65_535;
pub const checkpoint_magic = [_]u8{ 'S', 'L', 'T', 'H' };
pub const checkpoint_version: u8 = 1;
const checkpoint_header_len: usize = 4 + 1 + 3 + 4 + 6 * 8 + 2 * 4;
const checkpoint_checksum_len: usize = 32;
const checkpoint_row_min_len: usize = 4 + 8 + 8 + 8;
const checkpoint_domain = "onyx-service-login-throttle-checkpoint-v1";

pub const CheckpointError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    ConfigMismatch,
    NonCanonicalOrder,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

pub fn isUpgradeCheckpoint(bytes: []const u8) bool {
    return bytes.len >= checkpoint_magic.len and std.mem.eql(u8, bytes[0..checkpoint_magic.len], &checkpoint_magic);
}

/// Validate a complete checkpoint without allocation or changing any live
/// throttle. The final restore also compares the successor's exact policy.
pub fn validateUpgradeCheckpoint(bytes: []const u8) CheckpointError!void {
    if (bytes.len < checkpoint_header_len + checkpoint_checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!isUpgradeCheckpoint(bytes)) return error.BadMagic;
    if (bytes[4] != checkpoint_version) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    const expected_len = std.math.add(usize, checkpoint_header_len + checkpoint_checksum_len, body_len) catch return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    const saved_digest: [checkpoint_checksum_len]u8 = bytes[bytes.len - checkpoint_checksum_len ..][0..checkpoint_checksum_len].*;
    if (!std.crypto.timing_safe.eql([checkpoint_checksum_len]u8, digest, saved_digest)) return error.ChecksumMismatch;

    var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
    const params = try reader.readParams();
    if (!validCheckpointParams(params)) return error.InvalidField;
    const account_count: usize = try reader.readU32();
    const ip_count: usize = try reader.readU32();
    if (account_count > max_checkpoint_entries_per_scope or ip_count > max_checkpoint_entries_per_scope or
        (params.max_tracked_per_scope != 0 and (account_count > params.max_tracked_per_scope or ip_count > params.max_tracked_per_scope)))
        return error.CheckpointTooLarge;
    if (account_count + ip_count > body_len / checkpoint_row_min_len) return error.Truncated;

    inline for (.{ account_count, ip_count }) |count| {
        var previous_key: ?[]const u8 = null;
        for (0..count) |_| {
            const key_len: usize = try reader.readU32();
            if (key_len > max_checkpoint_key_bytes) return error.CheckpointTooLarge;
            const key = try reader.take(key_len);
            if (!isCanonicalKey(key)) return error.InvalidField;
            if (previous_key) |previous| {
                if (std.mem.order(u8, previous, key) != .lt) return error.NonCanonicalOrder;
            }
            previous_key = key;
            const score: f64 = @bitCast(try reader.readU64());
            if (!std.math.isFinite(score)) return error.InvalidField;
            _ = try reader.readI64(); // exact decay anchor
            _ = try reader.readI64(); // exact lockout deadline
        }
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
}

/// Which namespace a key belongs to. The two namespaces share no state: the
/// same string in `.account` and `.ip` is two different records.
pub const Scope = enum(u1) {
    account,
    ip,
};

/// Tunable policy for the throttle.
pub const Params = struct {
    /// Each failure adds this much to the key's decaying score.
    failure_weight: f64 = 1.0,
    /// Once a key's score reaches this value (after applying the new failure),
    /// a lockout cooldown is armed. Must be > 0.
    lock_threshold: f64 = 5.0,
    /// Flat cooldown window armed when the threshold is crossed, in ms.
    cooldown_ms: i64 = 60_000,
    /// Half-life of the decaying score in ms: a key's score halves every
    /// `score_half_life_ms` of inactivity. Must be > 0.
    score_half_life_ms: i64 = 300_000,
    /// A record is eligible for sweeping once it is unlocked and its decayed
    /// score has fallen at or below this floor. Must be >= 0.
    sweep_score_floor: f64 = 0.01,
    /// Maximum number of distinct keys held *per scope*. When full, brand-new
    /// keys are refused admission so an attacker cannot evict real records by
    /// flooding fresh keys. 0 disables the cap.
    max_tracked_per_scope: usize = 65_536,
};

/// Per-key decaying-score brute-force throttle across two namespaces.
pub const Throttle = struct {
    allocator: std.mem.Allocator,
    params: Params,
    /// One table per scope, indexed by `@intFromEnum(Scope)`.
    tables: [2]Table,

    const Table = std.StringHashMapUnmanaged(Entry);

    /// Mutable record for a single tracked key within one scope.
    const Entry = struct {
        /// Decaying failure score as of `score_ts_ms`.
        score: f64,
        /// Timestamp the `score` value is anchored to; decay is applied lazily
        /// relative to this on every read/write.
        score_ts_ms: i64,
        /// Absolute time the armed lockout ends. `minInt` means "never locked".
        locked_until_ms: i64,
    };

    /// Create an empty throttle. Validates policy invariants in debug builds.
    pub fn init(allocator: std.mem.Allocator, params: Params) Throttle {
        std.debug.assert(params.lock_threshold > 0);
        std.debug.assert(params.score_half_life_ms > 0);
        std.debug.assert(params.sweep_score_floor >= 0);
        return .{
            .allocator = allocator,
            .params = params,
            .tables = .{ .empty, .empty },
        };
    }

    /// Free every owned key and release all internal storage.
    pub fn deinit(self: *Throttle) void {
        self.clear();
        for (&self.tables) |*t| t.deinit(self.allocator);
        self.* = undefined;
    }

    /// Remove and free all keys in both scopes, retaining table capacity.
    pub fn clear(self: *Throttle) void {
        for (&self.tables) |*t| {
            var it = t.iterator();
            while (it.next()) |e| self.allocator.free(e.key_ptr.*);
            t.clearRetainingCapacity();
        }
    }

    /// Number of keys currently tracked in `scope`.
    pub fn count(self: *const Throttle, scope: Scope) usize {
        return self.tables[@intFromEnum(scope)].count();
    }

    /// Total keys tracked across both scopes.
    pub fn countAll(self: *const Throttle) usize {
        return self.count(.account) + self.count(.ip);
    }

    /// Seal exact scores, decay anchors, and lockout deadlines in both scopes.
    /// Expired and low-score rows remain present until the ordinary sweep runs;
    /// omitting them would change future capacity and decay decisions.
    pub fn exportUpgradeCheckpoint(self: *const Throttle, allocator: std.mem.Allocator) CheckpointError![]u8 {
        if (!validCheckpointParams(self.params)) return error.InvalidField;
        const account_count = self.tables[@intFromEnum(Scope.account)].count();
        const ip_count = self.tables[@intFromEnum(Scope.ip)].count();
        if (account_count > max_checkpoint_entries_per_scope or ip_count > max_checkpoint_entries_per_scope or
            (self.params.max_tracked_per_scope != 0 and
                (account_count > self.params.max_tracked_per_scope or ip_count > self.params.max_tracked_per_scope)))
            return error.CheckpointTooLarge;

        const account_keys = try allocator.alloc([]const u8, account_count);
        defer allocator.free(account_keys);
        const ip_keys = try allocator.alloc([]const u8, ip_count);
        defer allocator.free(ip_keys);
        const keys_by_scope = [_][][]const u8{ account_keys, ip_keys };
        var total_len: usize = checkpoint_header_len + checkpoint_checksum_len;
        for (keys_by_scope, 0..) |keys, scope_index| {
            var it = self.tables[scope_index].iterator();
            var i: usize = 0;
            while (it.next()) |row| : (i += 1) {
                if (i >= keys.len) return error.InvalidField;
                keys[i] = row.key_ptr.*;
            }
            if (i != keys.len) return error.InvalidField;
            std.mem.sort([]const u8, keys, {}, keyLess);
            for (keys) |key| {
                const row = self.tables[scope_index].get(key) orelse return error.InvalidField;
                if (key.len > max_checkpoint_key_bytes) return error.CheckpointTooLarge;
                if (!isCanonicalKey(key)) return error.InvalidField;
                if (!std.math.isFinite(row.score)) return error.InvalidField;
                try checkpointAddLen(&total_len, checkpoint_row_min_len);
                try checkpointAddLen(&total_len, key.len);
            }
        }

        const out = try allocator.alloc(u8, total_len);
        errdefer allocator.free(out);
        var writer = CheckpointWriter{ .bytes = out };
        writer.writeBytes(&checkpoint_magic);
        writer.writeByte(checkpoint_version);
        writer.writeBytes(&.{ 0, 0, 0 });
        writer.writeU32(@intCast(total_len - checkpoint_header_len - checkpoint_checksum_len));
        writer.writeParams(self.params);
        writer.writeU32(@intCast(account_count));
        writer.writeU32(@intCast(ip_count));
        for (keys_by_scope, 0..) |keys, scope_index| {
            for (keys) |key| {
                const row = self.tables[scope_index].get(key).?;
                writer.writeU32(@intCast(key.len));
                writer.writeBytes(key);
                writer.writeU64(@bitCast(row.score));
                writer.writeI64(row.score_ts_ms);
                writer.writeI64(row.locked_until_ms);
            }
        }
        std.debug.assert(writer.pos + checkpoint_checksum_len == out.len);
        var digest: [checkpoint_checksum_len]u8 = undefined;
        checkpointChecksum(out[0..writer.pos], &digest);
        writer.writeBytes(&digest);
        return out;
    }

    /// Build a complete replacement before COMMIT. Policy is matched bit for
    /// bit, including signed zero in floating-point tuning values.
    pub fn restoreUpgradeCheckpoint(
        allocator: std.mem.Allocator,
        expected_params: Params,
        bytes: []const u8,
    ) CheckpointError!Throttle {
        if (!validCheckpointParams(expected_params)) return error.InvalidField;
        try validateUpgradeCheckpoint(bytes);
        var reader = CheckpointReader{ .bytes = bytes[12 .. bytes.len - checkpoint_checksum_len] };
        const saved_params = try reader.readParams();
        if (!checkpointParamsEqual(expected_params, saved_params)) return error.ConfigMismatch;
        const counts = [_]usize{ try reader.readU32(), try reader.readU32() };
        var restored = Throttle.init(allocator, expected_params);
        errdefer restored.deinit();
        for (counts, 0..) |row_count, scope_index| {
            for (0..row_count) |_| {
                const key_len: usize = try reader.readU32();
                const key = try reader.take(key_len);
                const saved_score: f64 = @bitCast(try reader.readU64());
                const score_ts_ms = try reader.readI64();
                const locked_until_ms = try reader.readI64();
                const owned_key = try allocator.dupe(u8, key);
                errdefer allocator.free(owned_key);
                try restored.tables[scope_index].putNoClobber(allocator, owned_key, .{
                    .score = saved_score,
                    .score_ts_ms = score_ts_ms,
                    .locked_until_ms = locked_until_ms,
                });
            }
        }
        std.debug.assert(reader.remaining() == 0);
        return restored;
    }

    pub fn replaceFromUpgradeCheckpoint(self: *Throttle, bytes: []const u8) CheckpointError!void {
        var replacement = try restoreUpgradeCheckpoint(self.allocator, self.params, bytes);
        const old = self.*;
        self.* = replacement;
        replacement = old;
        replacement.deinit();
    }

    /// Report how long `key` in `scope` must wait before another attempt, or
    /// null if it is not currently locked. Pure read: never creates entries,
    /// never mutates score state. A key whose lockout has elapsed reports null.
    pub fn isLocked(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?i64 {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse return self.isLockedHeap(scope, key, now_ms);
        return self.lockedFor(scope, norm, now_ms);
    }

    fn isLockedHeap(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?i64 {
        const norm = self.allocator.dupe(u8, key) catch return null;
        defer self.allocator.free(norm);
        toLower(norm);
        return self.lockedFor(scope, norm, now_ms);
    }

    fn lockedFor(self: *Throttle, scope: Scope, norm: []const u8, now_ms: i64) ?i64 {
        const t = &self.tables[@intFromEnum(scope)];
        const entry = t.get(norm) orelse return null;
        if (now_ms < entry.locked_until_ms) {
            // Saturating subtract; both operands are i64 and lhs > rhs here.
            return entry.locked_until_ms - now_ms;
        }
        return null;
    }

    /// Current decayed score for `key` in `scope` as of `now_ms`, or 0 if
    /// untracked. Pure read (does not persist the decayed value).
    pub fn score(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) f64 {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse return self.scoreHeap(scope, key, now_ms);
        const t = &self.tables[@intFromEnum(scope)];
        const entry = t.getPtr(norm) orelse return 0;
        return self.decayedScore(entry, now_ms);
    }

    fn scoreHeap(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) f64 {
        const norm = self.allocator.dupe(u8, key) catch return 0;
        defer self.allocator.free(norm);
        toLower(norm);
        const t = &self.tables[@intFromEnum(scope)];
        const entry = t.getPtr(norm) orelse return 0;
        return self.decayedScore(entry, now_ms);
    }

    /// Record one authentication failure for `key` in `scope` at `now_ms`.
    ///
    /// The decaying score is advanced to `now_ms`, `failure_weight` is added,
    /// and if the result reaches `lock_threshold` a flat `cooldown_ms` lockout
    /// is armed (extending, never shortening, any existing lockout). Returns
    /// the resulting retry-after in ms if now locked, else null.
    ///
    /// Returns null without recording when the scope's table is full and `key`
    /// is not already present.
    pub fn recordFailure(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?i64 {
        const entry = self.getOrCreate(scope, key, now_ms) orelse return null;

        // Advance decay to now, then add this failure's weight.
        entry.score = self.decayedScore(entry, now_ms) + self.params.failure_weight;
        entry.score_ts_ms = now_ms;

        if (entry.score >= self.params.lock_threshold) {
            const candidate = saturatingAdd(now_ms, self.params.cooldown_ms);
            // Extend an existing lockout but never pull it earlier.
            if (candidate > entry.locked_until_ms) entry.locked_until_ms = candidate;
        }

        if (now_ms < entry.locked_until_ms) return entry.locked_until_ms - now_ms;
        return null;
    }

    /// Record a successful authentication: fully clear `key` in `scope`,
    /// freeing its owned storage. No-op when untracked.
    pub fn recordSuccess(self: *Throttle, scope: Scope, key: []const u8) void {
        var buf: [256]u8 = undefined;
        const norm = normalizeInto(&buf, key) orelse {
            self.recordSuccessHeap(scope, key);
            return;
        };
        self.removeNorm(scope, norm);
    }

    fn recordSuccessHeap(self: *Throttle, scope: Scope, key: []const u8) void {
        const norm = self.allocator.dupe(u8, key) catch return;
        defer self.allocator.free(norm);
        toLower(norm);
        self.removeNorm(scope, norm);
    }

    fn removeNorm(self: *Throttle, scope: Scope, norm: []const u8) void {
        const t = &self.tables[@intFromEnum(scope)];
        if (t.fetchRemove(norm)) |removed| self.allocator.free(removed.key);
    }

    /// Drop records in both scopes that are unlocked and whose decayed score
    /// has fallen to/below `sweep_score_floor` as of `now_ms`. Returns the
    /// number of records evicted.
    pub fn sweep(self: *Throttle, now_ms: i64) usize {
        var evicted: usize = 0;
        for (&self.tables) |*t| {
            var it = t.iterator();
            while (it.next()) |entry| {
                const e = entry.value_ptr.*;
                const locked = now_ms < e.locked_until_ms;
                const decayed = self.decayedScore(&e, now_ms);
                if (!locked and decayed <= self.params.sweep_score_floor) {
                    self.allocator.free(entry.key_ptr.*);
                    t.removeByPtr(entry.key_ptr);
                    // Removal invalidates the iterator; restart the scan.
                    it = t.iterator();
                    evicted += 1;
                }
            }
        }
        return evicted;
    }

    /// Decay an entry's stored score forward to `now_ms` using the configured
    /// half-life. Time going backwards (now < anchor) is treated as no decay.
    fn decayedScore(self: *Throttle, entry: *const Entry, now_ms: i64) f64 {
        const elapsed = now_ms - entry.score_ts_ms;
        if (elapsed <= 0) return entry.score;
        const half_life: f64 = @floatFromInt(self.params.score_half_life_ms);
        const ratio = @as(f64, @floatFromInt(elapsed)) / half_life;
        // score * 2^(-elapsed/half_life)
        return entry.score * std.math.pow(f64, 0.5, ratio);
    }

    /// Look up `key` in `scope`, creating a fresh record if absent and the
    /// scope still has admission headroom. Returns null when full and new.
    fn getOrCreate(self: *Throttle, scope: Scope, key: []const u8, now_ms: i64) ?*Entry {
        var buf: [256]u8 = undefined;
        if (normalizeInto(&buf, key)) |norm| {
            return self.getOrCreateNorm(scope, norm, now_ms);
        }
        const heap_norm = self.allocator.dupe(u8, key) catch return null;
        defer self.allocator.free(heap_norm);
        toLower(heap_norm);
        return self.getOrCreateNorm(scope, heap_norm, now_ms);
    }

    fn getOrCreateNorm(self: *Throttle, scope: Scope, norm: []const u8, now_ms: i64) ?*Entry {
        const t = &self.tables[@intFromEnum(scope)];
        if (t.getPtr(norm)) |entry| return entry;

        const cap = self.params.max_tracked_per_scope;
        if (cap != 0 and t.count() >= cap) return null;

        const owned_key = self.allocator.dupe(u8, norm) catch return null;
        errdefer self.allocator.free(owned_key);

        t.putNoClobber(self.allocator, owned_key, .{
            .score = 0,
            .score_ts_ms = now_ms,
            .locked_until_ms = std.math.minInt(i64),
        }) catch {
            self.allocator.free(owned_key);
            return null;
        };
        return t.getPtr(owned_key).?;
    }
};

/// Lowercase every ASCII byte of `s` in place.
fn toLower(s: []u8) void {
    for (s) |*c| c.* = std.ascii.toLower(c.*);
}

/// Copy `key` into `buf` lowercased, returning the slice, or null if too long.
fn normalizeInto(buf: []u8, key: []const u8) ?[]const u8 {
    if (key.len > buf.len) return null;
    for (key, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..key.len];
}

/// Add `a + b` with i64 saturation instead of overflow.
fn saturatingAdd(a: i64, b: i64) i64 {
    return std.math.add(i64, a, b) catch if (b > 0) std.math.maxInt(i64) else std.math.minInt(i64);
}

fn validCheckpointParams(params: Params) bool {
    return std.math.isFinite(params.failure_weight) and
        std.math.isFinite(params.lock_threshold) and params.lock_threshold > 0 and
        params.score_half_life_ms > 0 and
        std.math.isFinite(params.sweep_score_floor) and params.sweep_score_floor >= 0;
}

fn checkpointParamsEqual(a: Params, b: Params) bool {
    return @as(u64, @bitCast(a.failure_weight)) == @as(u64, @bitCast(b.failure_weight)) and
        @as(u64, @bitCast(a.lock_threshold)) == @as(u64, @bitCast(b.lock_threshold)) and
        a.cooldown_ms == b.cooldown_ms and
        a.score_half_life_ms == b.score_half_life_ms and
        @as(u64, @bitCast(a.sweep_score_floor)) == @as(u64, @bitCast(b.sweep_score_floor)) and
        a.max_tracked_per_scope == b.max_tracked_per_scope;
}

fn isCanonicalKey(key: []const u8) bool {
    for (key) |c| if (c != std.ascii.toLower(c)) return false;
    return true;
}

fn keyLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn checkpointAddLen(total: *usize, amount: usize) CheckpointError!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

fn checkpointChecksum(bytes: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checkpoint_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const CheckpointWriter = struct {
    bytes: []u8,
    pos: usize = 0,

    fn writeBytes(self: *CheckpointWriter, value: []const u8) void {
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn writeByte(self: *CheckpointWriter, value: u8) void {
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    fn writeU32(self: *CheckpointWriter, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    fn writeU64(self: *CheckpointWriter, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn writeI64(self: *CheckpointWriter, value: i64) void {
        std.mem.writeInt(i64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    fn writeParams(self: *CheckpointWriter, params: Params) void {
        self.writeU64(@bitCast(params.failure_weight));
        self.writeU64(@bitCast(params.lock_threshold));
        self.writeI64(params.cooldown_ms);
        self.writeI64(params.score_half_life_ms);
        self.writeU64(@bitCast(params.sweep_score_floor));
        self.writeU64(@intCast(params.max_tracked_per_scope));
    }
};

const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const CheckpointReader) usize {
        return self.bytes.len - self.pos;
    }

    fn take(self: *CheckpointReader, len: usize) CheckpointError![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    fn readU32(self: *CheckpointReader) CheckpointError!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn readU64(self: *CheckpointReader) CheckpointError!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    fn readI64(self: *CheckpointReader) CheckpointError!i64 {
        return std.mem.readInt(i64, (try self.take(8))[0..8], .little);
    }

    fn readParams(self: *CheckpointReader) CheckpointError!Params {
        const failure_weight: f64 = @bitCast(try self.readU64());
        const lock_threshold: f64 = @bitCast(try self.readU64());
        const cooldown_ms = try self.readI64();
        const score_half_life_ms = try self.readI64();
        const sweep_score_floor: f64 = @bitCast(try self.readU64());
        const max_tracked_per_scope = try self.readU64();
        if (max_tracked_per_scope > std.math.maxInt(usize)) return error.InvalidField;
        return .{
            .failure_weight = failure_weight,
            .lock_threshold = lock_threshold,
            .cooldown_ms = cooldown_ms,
            .score_half_life_ms = score_half_life_ms,
            .sweep_score_floor = sweep_score_floor,
            .max_tracked_per_scope = @intCast(max_tracked_per_scope),
        };
    }
};

const testing = std.testing;

test "below threshold every failure stays unlocked" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 3, .failure_weight = 1 });
    defer thr.deinit();

    // Act / Assert
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "bob", 0));
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "bob", 0));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "bob", 0));
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "bob", 0), 1e-9);
}

test "crossing threshold arms a cooldown and isLocked returns retry-after" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 3,
        .failure_weight = 1,
        .cooldown_ms = 1000,
    });
    defer thr.deinit();

    // Act: third failure crosses the threshold.
    _ = thr.recordFailure(.account, "eve", 0);
    _ = thr.recordFailure(.account, "eve", 0);
    const locked = thr.recordFailure(.account, "eve", 0);

    // Assert
    try testing.expectEqual(@as(?i64, 1000), locked);
    try testing.expectEqual(@as(?i64, 1000), thr.isLocked(.account, "eve", 0));
    try testing.expectEqual(@as(?i64, 1), thr.isLocked(.account, "eve", 999));
}

test "cooldown expires then unlocks" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = 250,
    });
    defer thr.deinit();

    // Act
    _ = thr.recordFailure(.account, "kana", 1000);

    // Assert
    try testing.expectEqual(@as(?i64, 150), thr.isLocked(.account, "kana", 1100));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "kana", 1250));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "kana", 5000));
}

test "success fully resets a key and frees it" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 2, .cooldown_ms = 1000 });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "user", 0);
    _ = thr.recordFailure(.account, "user", 0);
    try testing.expect(thr.isLocked(.account, "user", 0) != null);

    // Act
    thr.recordSuccess(.account, "user");

    // Assert
    try testing.expectEqual(@as(usize, 0), thr.count(.account));
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.account, "user", 0));
    try testing.expectApproxEqAbs(@as(f64, 0), thr.score(.account, "user", 0), 1e-9);
    // Resetting an unknown key is a harmless no-op.
    thr.recordSuccess(.account, "ghost");
}

test "score decays by half over one half-life" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 100, // high so we never lock
        .failure_weight = 4,
        .score_half_life_ms = 1000,
    });
    defer thr.deinit();

    // Act: score = 4 at t=0.
    _ = thr.recordFailure(.account, "decayer", 0);

    // Assert: halves each half-life.
    try testing.expectApproxEqAbs(@as(f64, 4), thr.score(.account, "decayer", 0), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "decayer", 1000), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 1), thr.score(.account, "decayer", 2000), 1e-6);
    try testing.expectApproxEqAbs(@as(f64, 0.5), thr.score(.account, "decayer", 3000), 1e-6);
}

test "decay lets a key recover below threshold over time" {
    // Arrange: two failures of weight 2 = score 4, threshold 5 (not locked).
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 5,
        .failure_weight = 2,
        .cooldown_ms = 10_000,
        .score_half_life_ms = 1000,
    });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "slow", 0);
    _ = thr.recordFailure(.account, "slow", 0); // score 4, unlocked

    // After a half-life the score is ~2; one more weight-2 failure = ~4 < 5.
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "slow", 1000));

    // But three rapid failures at t=0 would have locked it.
    _ = thr.recordFailure(.account, "fast", 0);
    _ = thr.recordFailure(.account, "fast", 0);
    try testing.expect(thr.recordFailure(.account, "fast", 0) != null);
}

test "account and ip namespaces are independent" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 1, .cooldown_ms = 1000 });
    defer thr.deinit();

    // Act: lock the *account* "1.2.3.4" (same string, different scope).
    _ = thr.recordFailure(.account, "1.2.3.4", 0);

    // Assert: the IP scope with the identical string is untouched.
    try testing.expect(thr.isLocked(.account, "1.2.3.4", 0) != null);
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.ip, "1.2.3.4", 0));
    try testing.expectEqual(@as(usize, 1), thr.count(.account));
    try testing.expectEqual(@as(usize, 0), thr.count(.ip));
}

test "distinct keys within a scope are isolated" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 2, .cooldown_ms = 1000 });
    defer thr.deinit();

    // Act: lock "a" only.
    _ = thr.recordFailure(.ip, "a", 0);
    _ = thr.recordFailure(.ip, "a", 0);

    // Assert
    try testing.expect(thr.isLocked(.ip, "a", 0) != null);
    try testing.expectEqual(@as(?i64, null), thr.isLocked(.ip, "b", 0));
}

test "keys are matched case-insensitively" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 3, .failure_weight = 1 });
    defer thr.deinit();

    // Act
    _ = thr.recordFailure(.account, "Alice", 0);
    _ = thr.recordFailure(.account, "ALICE", 0);
    _ = thr.recordFailure(.account, "alice", 0);

    // Assert: one record, accumulated together.
    try testing.expectEqual(@as(usize, 1), thr.count(.account));
    try testing.expectApproxEqAbs(@as(f64, 3), thr.score(.account, "aLiCe", 0), 1e-9);
}

test "lockout extends but never shortens on repeated failures" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = 1000,
        .score_half_life_ms = 1_000_000, // negligible decay over the test
    });
    defer thr.deinit();

    // Act: lock at t=0 (until 1000), then fail again at t=500 (would-be 1500).
    _ = thr.recordFailure(.account, "x", 0);
    try testing.expectEqual(@as(?i64, 1000), thr.isLocked(.account, "x", 0));
    const extended = thr.recordFailure(.account, "x", 500);

    // Assert: window now ends at 1500, not pulled earlier.
    try testing.expectEqual(@as(?i64, 1000), extended);
    try testing.expectEqual(@as(?i64, 1000), thr.isLocked(.account, "x", 500));
    try testing.expectEqual(@as(?i64, 1), thr.isLocked(.account, "x", 1499));
}

test "sweep drops decayed unlocked records and frees keys" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 100,
        .failure_weight = 1,
        .cooldown_ms = 0,
        .score_half_life_ms = 1000,
        .sweep_score_floor = 0.01,
    });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "stale", 0); // score 1 @ t=0
    _ = thr.recordFailure(.ip, "fresh", 9500); // score 1 @ t=9500

    // Act: at t=10000 "stale" has decayed ~2^-10 < 0.01; "fresh" still ~0.7.
    const evicted = thr.sweep(10_000);

    // Assert
    try testing.expectEqual(@as(usize, 1), evicted);
    try testing.expectEqual(@as(usize, 0), thr.count(.account));
    try testing.expectEqual(@as(usize, 1), thr.count(.ip));
}

test "sweep keeps records still inside their lockout window" {
    // Arrange: locked but old-scored entry must survive the sweep.
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = 100_000,
        .score_half_life_ms = 100,
        .sweep_score_floor = 0.01,
    });
    defer thr.deinit();
    _ = thr.recordFailure(.account, "held", 0);

    // Act: score has fully decayed by t=5000 but lockout runs to t=100000.
    const evicted = thr.sweep(5000);

    // Assert
    try testing.expectEqual(@as(usize, 0), evicted);
    try testing.expect(thr.isLocked(.account, "held", 5000) != null);
}

test "max_tracked_per_scope refuses new keys but serves existing ones" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{
        .max_tracked_per_scope = 1,
        .lock_threshold = 1,
        .cooldown_ms = 1000,
    });
    defer thr.deinit();

    // Act: first account key admitted and locked.
    try testing.expect(thr.recordFailure(.account, "first", 0) != null);

    // Assert: a second distinct account key is refused.
    try testing.expectEqual(@as(?i64, null), thr.recordFailure(.account, "second", 0));
    try testing.expectEqual(@as(usize, 1), thr.count(.account));

    // The per-scope cap does not bleed into the other scope.
    try testing.expect(thr.recordFailure(.ip, "first", 0) != null);
    try testing.expectEqual(@as(usize, 1), thr.count(.ip));

    // The existing account key still accrues failures.
    _ = thr.recordFailure(.account, "first", 0);
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, "first", 0), 1e-6);
}

test "retry-after never overflows with a saturated cooldown" {
    // Arrange: an absurd cooldown near i64 max must saturate, not overflow.
    var thr = Throttle.init(testing.allocator, .{
        .lock_threshold = 1,
        .failure_weight = 1,
        .cooldown_ms = std.math.maxInt(i64),
    });
    defer thr.deinit();

    // Act
    _ = thr.recordFailure(.ip, "huge", 1_000_000);

    // Assert: still locked far in the future, no panic.
    try testing.expect(thr.isLocked(.ip, "huge", 2_000_000) != null);
}

test "long keys exceeding the inline buffer take the heap path" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{ .lock_threshold = 2, .cooldown_ms = 1000 });
    defer thr.deinit();
    const long_key = &@as([300]u8, @splat('X'));

    // Act
    _ = thr.recordFailure(.account, long_key, 0);
    _ = thr.recordFailure(.account, long_key, 0);

    // Assert: stored lowercased, locked, then cleanly cleared.
    try testing.expectApproxEqAbs(@as(f64, 2), thr.score(.account, &@as([300]u8, @splat('x')), 0), 1e-9);
    try testing.expect(thr.isLocked(.account, long_key, 0) != null);
    thr.recordSuccess(.account, long_key);
    try testing.expectEqual(@as(usize, 0), thr.count(.account));
}

test "deinit frees all keys across both scopes with no leaks" {
    // Arrange
    var thr = Throttle.init(testing.allocator, .{});

    // Act
    _ = thr.recordFailure(.account, "one", 0);
    _ = thr.recordFailure(.account, "two", 0);
    _ = thr.recordFailure(.ip, "three", 0);

    // Assert: teardown under the testing allocator catches any leak.
    try testing.expectEqual(@as(usize, 3), thr.countAll());
    thr.deinit();
}

test "service login checkpoint preserves lockout and decay clocks in both scopes" {
    const params = Params{
        .failure_weight = 2,
        .lock_threshold = 3,
        .cooldown_ms = 700,
        .score_half_life_ms = 1000,
        .sweep_score_floor = 0.1,
        .max_tracked_per_scope = 8,
    };
    var source = Throttle.init(testing.allocator, params);
    defer source.deinit();
    _ = source.recordFailure(.account, "Bob", 100);
    _ = source.recordFailure(.account, "bOb", 200);
    _ = source.recordFailure(.ip, "BOB", 150);
    _ = source.recordFailure(.account, "", -10);
    const long_key = &@as([300]u8, @splat('X'));
    _ = source.recordFailure(.ip, long_key, 300);

    const wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    try validateUpgradeCheckpoint(wire);
    var restored = try Throttle.restoreUpgradeCheckpoint(testing.allocator, params, wire);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.count(.account));
    try testing.expectEqual(@as(usize, 2), restored.count(.ip));
    try testing.expectEqualDeep(source.tables[0].get("bob").?, restored.tables[0].get("bob").?);
    try testing.expectEqualDeep(source.tables[1].get("bob").?, restored.tables[1].get("bob").?);
    try testing.expectEqual(source.isLocked(.account, "bob", 400), restored.isLocked(.account, "bob", 400));
    try testing.expectApproxEqAbs(source.score(.account, "bob", 900), restored.score(.account, "bob", 900), 1e-12);
    const reencoded = try restored.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(reencoded);
    try testing.expectEqualSlices(u8, wire, reencoded);

    var reverse = Throttle.init(testing.allocator, params);
    defer reverse.deinit();
    _ = reverse.recordFailure(.ip, long_key, 300);
    _ = reverse.recordFailure(.account, "", -10);
    _ = reverse.recordFailure(.ip, "BOB", 150);
    _ = reverse.recordFailure(.account, "Bob", 100);
    _ = reverse.recordFailure(.account, "bOb", 200);
    const reverse_wire = try reverse.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(reverse_wire);
    try testing.expectEqualSlices(u8, wire, reverse_wire);
}

test "service login checkpoint rejects malformed rows and policy mismatch" {
    const params = Params{ .max_tracked_per_scope = 2 };
    var source = Throttle.init(testing.allocator, params);
    defer source.deinit();
    _ = source.recordFailure(.account, "aa", 1);
    _ = source.recordFailure(.account, "bb", 2);
    const wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    for (0..wire.len) |n| {
        try testing.expectError(error.Truncated, Throttle.restoreUpgradeCheckpoint(testing.allocator, params, wire[0..n]));
    }
    try testing.expectError(error.ConfigMismatch, Throttle.restoreUpgradeCheckpoint(
        testing.allocator,
        .{ .max_tracked_per_scope = 3 },
        wire,
    ));

    var damaged = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(damaged);
    damaged[4] = 2;
    try testing.expectError(error.UnsupportedVersion, validateUpgradeCheckpoint(damaged));
    damaged[4] = checkpoint_version;
    damaged[checkpoint_header_len + 4] ^= 1;
    try testing.expectError(error.ChecksumMismatch, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    // Two sorted two-byte account keys: make the second a duplicate.
    const second_key_offset = checkpoint_header_len + (checkpoint_row_min_len + 2) + 4;
    @memcpy(damaged[second_key_offset..][0..2], "aa");
    testRechecksum(damaged);
    try testing.expectError(error.NonCanonicalOrder, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    damaged[checkpoint_header_len + 4] = 'A';
    testRechecksum(damaged);
    try testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    @memcpy(damaged, wire);
    std.mem.writeInt(u64, damaged[checkpoint_header_len + 4 + 2 ..][0..8], 0x7ff8_0000_0000_0001, .little);
    testRechecksum(damaged);
    try testing.expectError(error.InvalidField, validateUpgradeCheckpoint(damaged));

    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, validateUpgradeCheckpoint(trailing));
}

test "service login checkpoint replacement is atomic across allocation failures" {
    const params = Params{ .lock_threshold = 1, .max_tracked_per_scope = 4 };
    var source = Throttle.init(testing.allocator, params);
    defer source.deinit();
    _ = source.recordFailure(.account, "alice", 10);
    _ = source.recordFailure(.ip, "192.0.2.1", 11);
    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, thr: *const Throttle) !void {
            const bytes = try thr.exportUpgradeCheckpoint(allocator);
            defer allocator.free(bytes);
            try testing.expectEqual(@as(usize, 2), thr.countAll());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{&source});
    const wire = try source.exportUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    const RestoreSweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: Params, bytes: []const u8) !void {
            var target = Throttle.init(allocator, cfg);
            defer target.deinit();
            _ = target.recordFailure(.account, "keeper", 1);
            if (target.countAll() == 0) return error.OutOfMemory;
            target.replaceFromUpgradeCheckpoint(bytes) catch |err| {
                try testing.expectEqual(@as(usize, 1), target.countAll());
                try testing.expect(target.isLocked(.account, "keeper", 1) != null);
                return err;
            };
            try testing.expectEqual(@as(usize, 2), target.countAll());
            try testing.expectEqual(@as(?i64, null), target.isLocked(.account, "keeper", 1));
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, RestoreSweep.run, .{ params, wire });
}

fn testRechecksum(bytes: []u8) void {
    var digest: [checkpoint_checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0 .. bytes.len - checkpoint_checksum_len], &digest);
    @memcpy(bytes[bytes.len - checkpoint_checksum_len ..], &digest);
}
