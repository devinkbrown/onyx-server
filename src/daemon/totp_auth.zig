// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account TOTP second-factor state.
//!
//! This module stores enrollment records only. It owns the decoded shared
//! secret and proves possession via `crypto/totp`. Code generation, the system
//! clock, and random secret generation stay with the caller.

const std = @import("std");
const crypto_totp = @import("../crypto/totp.zig");
const rwlock = @import("../substrate/rwlock.zig");

/// Seconds in a single RFC 6238 time step; used to derive the replay counter.
const step_seconds: i64 = 30;

/// Lifecycle phase of a stored TOTP enrollment.
const Phase = enum {
    pending,
    active,
};

/// An enrollment record owned by `TotpStore`.
const Enrollment = struct {
    /// Lifecycle phase: pending awaits confirmation, active is login-ready.
    phase: Phase,
    /// Raw decoded shared secret bytes owned by the store (verification).
    secret: []const u8,
    /// Original base32 secret owned by the store (so the daemon can persist a
    /// confirmed enrollment without re-encoding the raw bytes).
    secret_b32: []const u8,
    /// Highest accepted time-step counter, or null before first acceptance.
    last_step: ?i64,

    fn deinit(self: *Enrollment, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, @constCast(self.secret));
        std.crypto.secureZero(u8, @constCast(self.secret_b32));
        allocator.free(self.secret);
        allocator.free(self.secret_b32);
        self.* = undefined;
    }
};

/// Runtime policy for TOTP verification.
pub const Params = struct {
    /// Skew window (in steps) tolerated on either side of the current time.
    window: u8 = 1,
    /// Expected code length in decimal digits.
    digits: u8 = 6,
    /// HMAC hash backing the TOTP construction.
    algo: crypto_totp.Algorithm = .sha1,
};

/// Errors returned while enrolling an account secret.
pub const Error = std.mem.Allocator.Error || error{
    InvalidSecret,
};

/// Outcome of a confirmation or login verification attempt.
pub const VerifyOutcome = enum {
    ok,
    bad_code,
    not_enrolled,
};

/// Owned TOTP enrollment records keyed by normalized account name.
pub const TotpStore = struct {
    allocator: std.mem.Allocator,
    params: Params,
    entries: std.StringHashMap(Enrollment),
    /// Internal lock making the store self-synchronizing: it is shared across
    /// reactor shards (login verify, enroll, disable all touch it). Uncontended
    /// today since the reactor count is clamped to 1, but a real prerequisite for
    /// lifting that clamp. Every public method takes it; private helpers
    /// (`insert`/`findEntry`/`matchStep`) run under the caller's hold.
    lock: rwlock.RwLock = .{},

    /// Pins one enrollment across a fallible durable policy change. Lock order:
    /// TotpStore -> caller's Services -> prepared store batch. The caller must
    /// release this guard before calling any other public TotpStore method.
    /// Abort is just deinit: phase, secret and replay counter remain identical.
    pub const PolicyChange = struct {
        store: *TotpStore,
        entry: ?std.StringHashMap(Enrollment).Entry,
        outcome: VerifyOutcome,

        pub fn secretB32(self: *const PolicyChange) []const u8 {
            std.debug.assert(self.outcome == .ok);
            return self.entry.?.value_ptr.secret_b32;
        }

        /// No allocation or verification after durable policy publication.
        pub fn commitConfirmation(self: *PolicyChange) void {
            std.debug.assert(self.outcome == .ok);
            std.debug.assert(self.entry.?.value_ptr.phase == .pending);
            self.entry.?.value_ptr.phase = .active;
        }

        /// No-fail removal after the durable policy and token authority commit.
        pub fn commitRemoval(self: *PolicyChange) bool {
            const entry = self.entry orelse return false;
            const owned_key = entry.key_ptr.*;
            entry.value_ptr.deinit(self.store.allocator);
            self.store.entries.removeByPtr(entry.key_ptr);
            self.store.allocator.free(owned_key);
            self.entry = null;
            return true;
        }

        pub fn deinit(self: *PolicyChange) void {
            self.store.lock.unlockExclusive();
            self.* = undefined;
        }
    };

    /// Validate without activating the secret or consuming a replay step. Holds
    /// the lock even on a rejected code, so every path must deinit the guard.
    pub fn stageConfirmation(self: *TotpStore, account: []const u8, code: []const u8, now: i64) PolicyChange {
        self.lock.lockExclusive();
        const entry = self.findEntry(account);
        const outcome: VerifyOutcome = if (entry) |e|
            if (e.value_ptr.phase != .pending) .not_enrolled else if (self.matchStep(e.value_ptr.secret, code, now) == null) .bad_code else .ok
        else
            .not_enrolled;
        return .{ .store = self, .entry = entry, .outcome = outcome };
    }

    pub fn stageRemoval(self: *TotpStore, account: []const u8) PolicyChange {
        self.lock.lockExclusive();
        const entry = self.findEntry(account);
        return .{ .store = self, .entry = entry, .outcome = if (entry != null) .ok else .not_enrolled };
    }

    /// Creates an empty TOTP store using caller-provided policy.
    pub fn init(allocator: std.mem.Allocator, params: Params) TotpStore {
        return .{
            .allocator = allocator,
            .params = params,
            .entries = std.StringHashMap(Enrollment).init(allocator),
        };
    }

    /// Frees all enrollment records and invalidates the store.
    pub fn deinit(self: *TotpStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();
        self.* = undefined;
    }

    /// Stores a pending enrollment, decoding and validating the base32 secret.
    /// A subsequent `confirm` with a valid code promotes it to active.
    pub fn enroll(self: *TotpStore, account: []const u8, secret_b32: []const u8) Error!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        return self.insert(account, secret_b32, .pending);
    }

    /// Insert an already-confirmed (active) enrollment directly — used to restore
    /// a persisted secret into the live store at login, bypassing the pending →
    /// confirm handshake. Replaces any existing entry for the account.
    pub fn loadActive(self: *TotpStore, account: []const u8, secret_b32: []const u8) Error!void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        return self.insert(account, secret_b32, .active);
    }

    fn insert(self: *TotpStore, account: []const u8, secret_b32: []const u8, phase: Phase) Error!void {
        const secret = try self.decodeSecret(secret_b32);
        errdefer {
            std.crypto.secureZero(u8, @constCast(secret));
            self.allocator.free(secret);
        }
        const owned_b32 = try self.allocator.dupe(u8, secret_b32);
        errdefer {
            std.crypto.secureZero(u8, owned_b32);
            self.allocator.free(owned_b32);
        }
        const next: Enrollment = .{ .phase = phase, .secret = secret, .secret_b32 = owned_b32, .last_step = null };

        if (self.findEntry(account)) |entry| {
            entry.value_ptr.deinit(self.allocator);
            entry.value_ptr.* = next;
            return;
        }

        const owned_key = try self.normalizedAccount(account);
        errdefer self.allocator.free(owned_key);
        try self.entries.putNoClobber(owned_key, next);
    }

    /// The base32 secret for the account's enrollment (any phase), or null. The
    /// returned slice is store-owned and valid until the next mutation for this
    /// account — copy it (e.g. persist it) before the next store call. Used to
    /// durably store a freshly confirmed enrollment.
    pub fn secretB32(self: *TotpStore, account: []const u8) ?[]const u8 {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.findEntry(account) orelse return null;
        return entry.value_ptr.secret_b32;
    }

    /// Confirms a pending enrollment and promotes it to active on success.
    pub fn confirm(self: *TotpStore, account: []const u8, code: []const u8, now: i64) Error!VerifyOutcome {
        var change = self.stageConfirmation(account, code, now);
        defer change.deinit();
        if (change.outcome == .ok) change.commitConfirmation();
        return change.outcome;
    }

    /// Verifies a login second factor against the active secret with replay guard.
    pub fn verify(self: *TotpStore, account: []const u8, code: []const u8, now: i64) Error!VerifyOutcome {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.findEntry(account) orelse return .not_enrolled;
        if (entry.value_ptr.phase != .active) return .not_enrolled;

        const step = self.matchStep(entry.value_ptr.secret, code, now) orelse return .bad_code;
        if (entry.value_ptr.last_step) |last| {
            if (step <= last) return .bad_code; // replay of this or an older step
        }
        entry.value_ptr.last_step = step;
        return .ok;
    }

    /// Returns true when the account has an active enrollment.
    pub fn isEnrolled(self: *TotpStore, account: []const u8) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.findEntry(account) orelse return false;
        return entry.value_ptr.phase == .active;
    }

    /// Returns true when the account has a pending (unconfirmed) enrollment.
    pub fn isPending(self: *TotpStore, account: []const u8) bool {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const entry = self.findEntry(account) orelse return false;
        return entry.value_ptr.phase == .pending;
    }

    /// Removes any enrollment for the account and reports whether one existed.
    pub fn disable(self: *TotpStore, account: []const u8) bool {
        var change = self.stageRemoval(account);
        defer change.deinit();
        return change.commitRemoval();
    }

    /// Decodes a base32 secret into store-owned raw bytes, rejecting empties.
    fn decodeSecret(self: *TotpStore, secret_b32: []const u8) Error![]const u8 {
        const secret = crypto_totp.decodeBase32(self.allocator, secret_b32) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidSecret,
        };
        errdefer {
            std.crypto.secureZero(u8, secret);
            self.allocator.free(secret);
        }
        if (secret.len == 0) return error.InvalidSecret;
        return secret;
    }

    /// Returns the time step whose TOTP code equals `code`, scanning the skew
    /// window from the centre outward so the accepted step tracks the user's real
    /// clock — a leading-edge match must not advance the replay counter past
    /// steps the user has yet to reach. Honors `params.digits` and `params.algo`
    /// and compares the code in constant time. Null when nothing in the window
    /// matches (wrong code, wrong length, or an unsupported digit count).
    fn matchStep(self: *const TotpStore, secret: []const u8, code: []const u8, now: i64) ?i64 {
        const digits = self.params.digits;
        if (digits == 0 or digits > 9 or code.len != digits) return null;
        const skew: i64 = @intCast(self.params.window);
        var d: i64 = 0;
        while (d <= skew) : (d += 1) {
            const neg = now - d * step_seconds;
            if (neg >= 0 and self.codeMatches(secret, code, neg)) return @divFloor(neg, step_seconds);
            if (d != 0) {
                const pos = now + d * step_seconds;
                if (pos >= 0 and self.codeMatches(secret, code, pos)) return @divFloor(pos, step_seconds);
            }
        }
        return null;
    }

    /// True when the TOTP code for `time` (using the store's digit count and
    /// hash algorithm) equals `code`, compared in constant time.
    fn codeMatches(self: *const TotpStore, secret: []const u8, code: []const u8, time: i64) bool {
        const value = crypto_totp.totp(secret, time, 30, 0, self.params.digits, self.params.algo) catch return false;
        var buf: [9]u8 = undefined;
        var v = value;
        var i: usize = self.params.digits;
        while (i > 0) {
            i -= 1;
            buf[i] = @intCast('0' + v % 10);
            v /= 10;
        }
        return ctEqual(buf[0..self.params.digits], code);
    }

    /// Allocates a lowercased copy of the account name for use as a key.
    fn normalizedAccount(self: *TotpStore, account: []const u8) Error![]u8 {
        const owned_key = try self.allocator.alloc(u8, account.len);
        for (account, 0..) |byte, index| {
            owned_key[index] = std.ascii.toLower(byte);
        }
        return owned_key;
    }

    /// Looks up an entry by case-insensitive account name.
    fn findEntry(self: *const TotpStore, account: []const u8) ?std.StringHashMap(Enrollment).Entry {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, account)) return entry;
        }
        return null;
    }
};

/// Constant-time byte-slice equality, so a per-position mismatch in a verified
/// TOTP code does not leak through comparison timing.
fn ctEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

const testing = std.testing;

/// Test helper: computes the canonical 6-digit SHA-1 code for `now`.
fn codeFor(buf: *[6]u8, secret: []const u8, now: i64) ![]const u8 {
    return codeForCfg(buf, secret, now, .sha1);
}

/// Test helper: 6-digit code for a chosen hash algorithm.
fn codeForCfg(buf: *[6]u8, secret: []const u8, now: i64, algo: crypto_totp.Algorithm) ![]const u8 {
    const value = try crypto_totp.totp(secret, now, 30, 0, 6, algo);
    var remaining = value;
    var i: usize = 6;
    while (i > 0) {
        i -= 1;
        buf[i] = @intCast('0' + remaining % 10);
        remaining /= 10;
    }
    return buf[0..];
}

test "enroll then confirm activates the enrollment" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    try store.enroll("Alice", secret_b32);
    var buf: [6]u8 = undefined;
    const code = try codeFor(&buf, secret, 59);

    try testing.expectEqual(VerifyOutcome.ok, try store.confirm("alice", code, 59));
    try testing.expect(store.isEnrolled("ALICE"));
    try testing.expect(!store.isPending("alice"));
}

test "TOTP staged confirmation abort preserves exact pending secret and same-code retry" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    try store.enroll("Alice", b32);
    var buf: [6]u8 = undefined;
    const code = try codeFor(&buf, store.findEntry("alice").?.value_ptr.secret, 59);
    const before = store.findEntry("alice").?.value_ptr.*;
    {
        var staged = store.stageConfirmation("ALICE", code, 59);
        defer staged.deinit();
        try testing.expectEqual(VerifyOutcome.ok, staged.outcome);
        try testing.expectEqualStrings(b32, staged.secretB32());
        try testing.expectEqual(Phase.pending, staged.entry.?.value_ptr.phase);
        try testing.expectEqual(before.last_step, staged.entry.?.value_ptr.last_step);
        // A persistence failure drops the guard without committing.
    }
    const after = store.findEntry("alice").?.value_ptr.*;
    try testing.expectEqual(before.phase, after.phase);
    try testing.expectEqual(before.last_step, after.last_step);
    try testing.expectEqual(before.secret.ptr, after.secret.ptr);
    try testing.expectEqual(before.secret_b32.ptr, after.secret_b32.ptr);
    try testing.expectEqualSlices(u8, before.secret, after.secret);
    {
        var retry = store.stageConfirmation("alice", code, 59);
        defer retry.deinit();
        try testing.expectEqual(VerifyOutcome.ok, retry.outcome);
        retry.commitConfirmation();
    }
    try testing.expect(store.isEnrolled("alice"));
}

test "TOTP staged removal abort preserves active replay guard and pending enrollment" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    try store.loadActive("alice", "MZXW6YTBOI======");
    try store.enroll("bob", "MZXW6YTBOI======");
    var buf: [6]u8 = undefined;
    const code = try codeFor(&buf, store.findEntry("alice").?.value_ptr.secret, 59);
    try testing.expectEqual(VerifyOutcome.ok, try store.verify("alice", code, 59));
    for ([_][]const u8{ "alice", "bob" }) |account| {
        const before = store.findEntry(account).?.value_ptr.*;
        {
            var staged = store.stageRemoval(account);
            defer staged.deinit();
            try testing.expectEqual(VerifyOutcome.ok, staged.outcome);
        }
        const after = store.findEntry(account).?.value_ptr.*;
        try testing.expectEqual(before.phase, after.phase);
        try testing.expectEqual(before.last_step, after.last_step);
        try testing.expectEqual(before.secret.ptr, after.secret.ptr);
    }
    try testing.expectEqual(VerifyOutcome.bad_code, try store.verify("alice", code, 59));
    try testing.expect(store.isPending("bob"));
    {
        var retry = store.stageRemoval("alice");
        defer retry.deinit();
        try testing.expect(retry.commitRemoval());
    }
    try testing.expect(!store.isEnrolled("alice"));
}

test "verify accepts the correct active code" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    var buf: [6]u8 = undefined;
    try store.enroll("bob", secret_b32);
    _ = try store.confirm("bob", try codeFor(&buf, secret, 1234567890), 1234567890);

    const code = try codeFor(&buf, secret, 2000000000);
    try testing.expectEqual(VerifyOutcome.ok, try store.verify("bob", code, 2000000000));
}

test "verify rejects a wrong active code" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    var buf: [6]u8 = undefined;
    try store.enroll("carol", secret_b32);
    _ = try store.confirm("carol", try codeFor(&buf, secret, 59), 59);

    try testing.expectEqual(VerifyOutcome.bad_code, try store.verify("carol", "000000", 2000000000));
}

test "verify before confirm reports not enrolled" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    var buf: [6]u8 = undefined;
    try store.enroll("dave", secret_b32);
    const code = try codeFor(&buf, secret, 59);

    try testing.expectEqual(VerifyOutcome.not_enrolled, try store.verify("dave", code, 59));
}

test "verify for unknown account reports not enrolled" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();

    try testing.expectEqual(VerifyOutcome.not_enrolled, try store.verify("ghost", "123456", 59));
}

test "replay of the same step is rejected after first acceptance" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    var buf: [6]u8 = undefined;
    try store.enroll("erin", secret_b32);
    _ = try store.confirm("erin", try codeFor(&buf, secret, 59), 59);

    const code = try codeFor(&buf, secret, 2000000000);
    try testing.expectEqual(VerifyOutcome.ok, try store.verify("erin", code, 2000000000));
    try testing.expectEqual(VerifyOutcome.bad_code, try store.verify("erin", code, 2000000000));
}

test "disable removes the enrollment" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    var buf: [6]u8 = undefined;
    try store.enroll("frank", secret_b32);
    _ = try store.confirm("frank", try codeFor(&buf, secret, 59), 59);

    try testing.expect(store.disable("FRANK"));
    try testing.expect(!store.isEnrolled("frank"));
    try testing.expect(!store.disable("frank"));
}

test "loadActive restores a persisted secret as immediately verifiable" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    // No pending/confirm handshake: a restored secret verifies a login directly.
    try store.loadActive("kev", secret_b32);
    try testing.expect(store.isEnrolled("KEV"));
    try testing.expect(!store.isPending("kev"));
    var buf: [6]u8 = undefined;
    try testing.expectEqual(VerifyOutcome.ok, try store.verify("kev", try codeFor(&buf, secret, 2000000000), 2000000000));
}

test "invalid base32 secret is rejected on enroll" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();

    try testing.expectError(error.InvalidSecret, store.enroll("grace", "MZXW6Y!B"));
    try testing.expect(!store.isPending("grace"));
}

test "params.algo is honored: a SHA-256 store rejects a SHA-1 code and accepts a SHA-256 one" {
    var store = TotpStore.init(testing.allocator, .{ .algo = .sha256 });
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    try store.enroll("heidi", secret_b32);
    var buf: [6]u8 = undefined;
    // A SHA-1 code must NOT confirm a SHA-256-configured enrollment (the dead-knob
    // bug let this slip through because verify always used SHA-1).
    const sha1_code = try codeForCfg(&buf, secret, 59, .sha1);
    try testing.expectEqual(VerifyOutcome.bad_code, try store.confirm("heidi", sha1_code, 59));
    // The matching SHA-256 code confirms.
    const sha256_code = try codeForCfg(&buf, secret, 59, .sha256);
    try testing.expectEqual(VerifyOutcome.ok, try store.confirm("heidi", sha256_code, 59));
}

test "the replay counter tracks the user's clock without locking out the next step" {
    var store = TotpStore.init(testing.allocator, .{});
    defer store.deinit();
    const secret_b32 = "MZXW6YTBOI======";
    const secret = try crypto_totp.decodeBase32(testing.allocator, secret_b32);
    defer testing.allocator.free(secret);

    var buf: [6]u8 = undefined;
    try store.enroll("ivan", secret_b32);
    const t0: i64 = 2000000010; // step 66666667
    _ = try store.confirm("ivan", try codeFor(&buf, secret, t0), t0);

    // Login at t0 with t0's code.
    try testing.expectEqual(VerifyOutcome.ok, try store.verify("ivan", try codeFor(&buf, secret, t0), t0));
    // The very next 30s step's code must still be accepted (no leading-edge
    // high-water-mark lockout of a step the user legitimately reaches next).
    const t1 = t0 + 30;
    try testing.expectEqual(VerifyOutcome.ok, try store.verify("ivan", try codeFor(&buf, secret, t1), t1));
}
