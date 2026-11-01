// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Operator override policy engine.
//!
//! An operator holding the `channel_moderate` privilege may engage a
//! time-boxed override session that lets them bypass selected channel
//! restrictions purely for moderation purposes. Each bypass that is actually
//! exercised is recorded in a fixed-capacity audit ring so the override is
//! accountable after the fact.
//!
//! The module is self-contained: it owns the audit strings it records, frees
//! every allocation in `deinit`, performs no I/O, and takes the current time
//! and the operator's privilege flags as injected parameters so callers retain
//! control over the clock and the trust source. It deliberately knows nothing
//! about the surrounding daemon wiring beyond the privilege flag it gates on.

const std = @import("std");

/// The privilege an operator must hold to engage an override session. The
/// daemon's `oper` module exposes `channel_moderate`; this engine only needs
/// to be told whether the acting operator has it, so the dependency is a plain
/// boolean injected at the call site.
pub const REQUIRED_PRIVILEGE_NAME: []const u8 = "channel_moderate";

/// A channel restriction that an engaged override session is allowed to bypass.
///
/// These mirror the standard channel modes a moderator may legitimately need to
/// step past: invite-only, key, ban, limit, and moderation. The set is closed
/// on purpose — an override must never bypass anything not enumerated here.
pub const Restriction = enum {
    /// `+i` — invite-only join restriction.
    invite_only,
    /// `+k` — channel key required to join.
    key,
    /// `+b` — ban mask preventing join or speech.
    ban,
    /// `+l` — member-count limit.
    limit,
    /// `+m` — moderation; only voiced or higher may speak.
    moderation,

    /// Return the stable channel-mode letter for this restriction.
    pub fn modeLetter(self: Restriction) u8 {
        return switch (self) {
            .invite_only => 'i',
            .key => 'k',
            .ban => 'b',
            .limit => 'l',
            .moderation => 'm',
        };
    }

    /// Return the stable lowercase token naming this restriction.
    pub fn token(self: Restriction) []const u8 {
        return switch (self) {
            .invite_only => "invite_only",
            .key => "key",
            .ban => "ban",
            .limit => "limit",
            .moderation => "moderation",
        };
    }

    /// Parse a restriction token case-insensitively, or `null` if unknown.
    pub fn parse(raw: []const u8) ?Restriction {
        inline for (@typeInfo(Restriction).@"enum".field_values) |field_value| {
            const restriction: Restriction = @fromBackingInt(@intCast(field_value));
            if (std.ascii.eqlIgnoreCase(raw, restriction.token())) return restriction;
        }
        return null;
    }
};

/// Compile-time bounds for the override engine.
pub const Params = struct {
    /// Capacity of the audit ring; the oldest record is evicted past this.
    audit_capacity: usize = 256,
    /// Maximum bytes accepted for an operator identity.
    max_oper_len: usize = 64,
    /// Maximum bytes accepted for a bypass target (channel, mask, etc.).
    max_target_len: usize = 256,
    /// Largest override time-to-live, in milliseconds, that `engage` accepts.
    max_ttl_ms: i64 = 60 * 60 * 1000,
};

/// Errors returned when engaging an override session.
pub const EngageError = error{
    /// The acting operator lacks the required override privilege.
    NotPrivileged,
    /// The supplied identity was empty or exceeded `max_oper_len`.
    InvalidOper,
    /// The requested time-to-live was not strictly positive.
    NonPositiveTtl,
    /// The requested time-to-live exceeded `Params.max_ttl_ms`.
    TtlTooLong,
};

/// Errors returned when recording an exercised bypass.
pub const RecordError = std.mem.Allocator.Error || error{
    /// No override session was active at `now`.
    NotEngaged,
    /// The supplied operator identity was empty or too long.
    InvalidOper,
    /// The supplied bypass target was too long.
    TargetTooLong,
};

/// The override session held by a single operator.
///
/// A session is "active" while `now < active_until_ms`. The struct is a plain
/// value: callers own where it lives (typically beside the operator's client
/// record) and pass it back into the free functions below.
pub const OverrideState = struct {
    /// Wall-clock millisecond at which the override session expires. A session
    /// is inactive whenever the current time is at or past this value.
    active_until_ms: i64 = 0,
    /// Restrictions this session is permitted to bypass while active.
    allowed: std.EnumSet(Restriction) = .{},

    /// A disengaged session: never active, bypasses nothing.
    pub const off: OverrideState = .{};

    /// Return whether the session is active at `now`.
    pub fn isActive(self: OverrideState, now: i64) bool {
        return now < self.active_until_ms;
    }

    /// Milliseconds remaining before expiry at `now`, clamped at zero.
    pub fn remainingMs(self: OverrideState, now: i64) i64 {
        if (!self.isActive(now)) return 0;
        return self.active_until_ms - now;
    }
};

/// A single recorded bypass. The `oper` and `target` slices are owned by the
/// engine that produced the record and remain valid until the engine is
/// deinitialized or the record is evicted from the ring.
pub const AuditRecord = struct {
    /// Monotonic sequence number assigned at record time.
    seq: u64,
    /// Operator identity that exercised the bypass.
    oper: []const u8,
    /// Restriction that was bypassed.
    restriction: Restriction,
    /// Subject of the bypass (channel name, ban mask, joining nick, etc.).
    target: []const u8,
    /// Wall-clock millisecond at which the bypass occurred.
    at_ms: i64,
};

/// Decide whether an active override session may bypass `restriction` at `now`.
///
/// This is the single authoritative gate: it is `true` only when the session is
/// active at `now` and the restriction is in its allowed set. It never mutates
/// state and records nothing — recording is the caller's explicit follow-up via
/// `OverrideEngine.record` once a bypass is actually taken.
pub fn mayBypass(state: OverrideState, restriction: Restriction, now: i64) bool {
    if (!state.isActive(now)) return false;
    return state.allowed.contains(restriction);
}

/// Build the override session for a privileged operator.
///
/// `has_privilege` is the injected trust decision (the operator holds the
/// `channel_moderate` privilege). `now` and `ttl_ms` set the active window.
/// When `allowed` is `null` every restriction is permitted; otherwise only the
/// supplied set may be bypassed. The returned state replaces any prior session.
pub fn engage(
    has_privilege: bool,
    oper: []const u8,
    now: i64,
    ttl_ms: i64,
    allowed: ?std.EnumSet(Restriction),
    params: Params,
) EngageError!OverrideState {
    if (!has_privilege) return error.NotPrivileged;
    if (oper.len == 0 or oper.len > params.max_oper_len) return error.InvalidOper;
    if (ttl_ms <= 0) return error.NonPositiveTtl;
    if (ttl_ms > params.max_ttl_ms) return error.TtlTooLong;

    const until = std.math.add(i64, now, ttl_ms) catch std.math.maxInt(i64);
    return .{
        .active_until_ms = until,
        .allowed = allowed orelse std.EnumSet(Restriction).full,
    };
}

/// Return a disengaged session. Callers assign the result over the operator's
/// state to end an override immediately, regardless of remaining time.
pub fn disengage() OverrideState {
    return OverrideState.off;
}

/// Owned override engine bundling configuration and a fixed-capacity audit ring.
///
/// The engine itself holds no per-operator session; sessions live in
/// `OverrideState` values the caller owns. The engine's sole owned resource is
/// the audit ring, whose records duplicate the operator and target strings.
pub const OverrideEngine = struct {
    allocator: std.mem.Allocator,
    params: Params,
    records: std.ArrayListUnmanaged(AuditRecord) = .empty,
    /// Index of the oldest live record within `records` once the ring is full.
    start: usize = 0,
    next_seq: u64 = 1,

    /// Initialize an engine with an empty audit ring.
    pub fn init(allocator: std.mem.Allocator, params: Params) OverrideEngine {
        return .{ .allocator = allocator, .params = params };
    }

    /// Free every owned audit record and backing storage.
    pub fn deinit(self: *OverrideEngine) void {
        for (self.records.items) |entry| self.freeRecord(entry);
        self.records.deinit(self.allocator);
        self.* = undefined;
    }

    /// Engage an override session for `oper`, delegating policy to `engage`.
    ///
    /// This is a convenience wrapper that threads the engine's configured
    /// `Params`; it records nothing on its own.
    pub fn engageFor(
        self: *const OverrideEngine,
        has_privilege: bool,
        oper: []const u8,
        now: i64,
        ttl_ms: i64,
        allowed: ?std.EnumSet(Restriction),
    ) EngageError!OverrideState {
        return engage(has_privilege, oper, now, ttl_ms, allowed, self.params);
    }

    /// Record that `oper` exercised a bypass of `restriction` against `target`.
    ///
    /// The session `state` must be active and permit `restriction` at `now`,
    /// matching the `mayBypass` gate; otherwise `error.NotEngaged` is returned
    /// and nothing is recorded. On success the new record's sequence number is
    /// returned and the oldest record is evicted if the ring was full.
    pub fn record(
        self: *OverrideEngine,
        state: OverrideState,
        oper: []const u8,
        restriction: Restriction,
        target: []const u8,
        now: i64,
    ) RecordError!u64 {
        if (!mayBypass(state, restriction, now)) return error.NotEngaged;
        if (oper.len == 0 or oper.len > self.params.max_oper_len) return error.InvalidOper;
        if (target.len > self.params.max_target_len) return error.TargetTooLong;

        const owned_oper = try self.allocator.dupe(u8, oper);
        errdefer self.allocator.free(owned_oper);
        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);

        const seq = self.next_seq;
        self.next_seq = std.math.add(u64, self.next_seq, 1) catch std.math.maxInt(u64);

        const new_record = AuditRecord{
            .seq = seq,
            .oper = owned_oper,
            .restriction = restriction,
            .target = owned_target,
            .at_ms = now,
        };

        if (self.records.items.len < self.params.audit_capacity) {
            try self.records.append(self.allocator, new_record);
        } else {
            // Ring is full: overwrite the oldest slot and advance the head.
            self.freeRecord(self.records.items[self.start]);
            self.records.items[self.start] = new_record;
            self.start = (self.start + 1) % self.params.audit_capacity;
        }
        return seq;
    }

    /// Number of live audit records currently retained.
    pub fn auditCount(self: *const OverrideEngine) usize {
        return self.records.items.len;
    }

    /// Copy audit records, oldest first, into `out` and return the filled slice.
    ///
    /// Records borrow the engine's owned strings, so the slice is valid only
    /// until the next mutating call or `deinit`.
    pub fn auditList(self: *const OverrideEngine, out: []AuditRecord) []AuditRecord {
        const total = self.records.items.len;
        const limit = @min(total, out.len);
        var i: usize = 0;
        while (i < limit) : (i += 1) {
            const index = if (total < self.params.audit_capacity)
                i
            else
                (self.start + i) % self.params.audit_capacity;
            out[i] = self.records.items[index];
        }
        return out[0..limit];
    }

    fn freeRecord(self: *const OverrideEngine, record_value: AuditRecord) void {
        self.allocator.free(record_value.oper);
        self.allocator.free(record_value.target);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "restriction tokens and mode letters round trip case-insensitively" {
    // Arrange / Act / Assert.
    inline for (@typeInfo(Restriction).@"enum".field_values) |field_value| {
        const restriction: Restriction = @fromBackingInt(@intCast(field_value));
        try testing.expectEqual(restriction, Restriction.parse(restriction.token()).?);
    }
    try testing.expectEqual(Restriction.ban, Restriction.parse("BAN").?);
    try testing.expectEqual(@as(u8, 'i'), Restriction.invite_only.modeLetter());
    try testing.expect(Restriction.parse("secret") == null);
}

test "engage requires the override privilege" {
    // Arrange / Act / Assert.
    try testing.expectError(
        error.NotPrivileged,
        engage(false, "alice", 1_000, 5_000, null, .{}),
    );

    const state = try engage(true, "alice", 1_000, 5_000, null, .{});
    try testing.expect(state.isActive(1_000));
}

test "engage validates identity and ttl bounds" {
    const params = Params{ .max_oper_len = 8, .max_ttl_ms = 10_000 };
    try testing.expectError(error.InvalidOper, engage(true, "", 0, 1_000, null, params));
    try testing.expectError(error.InvalidOper, engage(true, "toolongname", 0, 1_000, null, params));
    try testing.expectError(error.NonPositiveTtl, engage(true, "op", 0, 0, null, params));
    try testing.expectError(error.NonPositiveTtl, engage(true, "op", 0, -5, null, params));
    try testing.expectError(error.TtlTooLong, engage(true, "op", 0, 20_000, null, params));

    const ok = try engage(true, "op", 0, 10_000, null, params);
    try testing.expectEqual(@as(i64, 10_000), ok.active_until_ms);
}

test "engaged session expires exactly at its boundary" {
    // Arrange.
    const start_ms: i64 = 1_000;
    const ttl_ms: i64 = 5_000;
    const state = try engage(true, "alice", start_ms, ttl_ms, null, .{});

    // Act / Assert: active up to but not including the expiry instant.
    try testing.expect(state.isActive(start_ms));
    try testing.expect(state.isActive(start_ms + ttl_ms - 1));
    try testing.expect(!state.isActive(start_ms + ttl_ms));
    try testing.expect(!state.isActive(start_ms + ttl_ms + 1));
    try testing.expectEqual(@as(i64, 1), state.remainingMs(start_ms + ttl_ms - 1));
    try testing.expectEqual(@as(i64, 0), state.remainingMs(start_ms + ttl_ms));
}

test "mayBypass gates per restriction and by time" {
    // Arrange: a session permitting only ban and key bypasses.
    var allowed = std.EnumSet(Restriction).empty;
    allowed.insert(.ban);
    allowed.insert(.key);
    const state = try engage(true, "alice", 0, 1_000, allowed, .{});

    // Act / Assert: allowed restrictions pass, others do not.
    try testing.expect(mayBypass(state, .ban, 500));
    try testing.expect(mayBypass(state, .key, 500));
    try testing.expect(!mayBypass(state, .invite_only, 500));
    try testing.expect(!mayBypass(state, .limit, 500));
    try testing.expect(!mayBypass(state, .moderation, 500));

    // After expiry even allowed restrictions are denied.
    try testing.expect(!mayBypass(state, .ban, 1_000));
}

test "default allowed set covers every restriction" {
    const state = try engage(true, "alice", 0, 1_000, null, .{});
    inline for (@typeInfo(Restriction).@"enum".field_values) |field_value| {
        const restriction: Restriction = @fromBackingInt(@intCast(field_value));
        try testing.expect(mayBypass(state, restriction, 500));
    }
}

test "disengage ends an active session immediately" {
    var state = try engage(true, "alice", 0, 10_000, null, .{});
    try testing.expect(mayBypass(state, .ban, 1));
    state = disengage();
    try testing.expect(!state.isActive(1));
    try testing.expect(!mayBypass(state, .ban, 1));
}

test "record stores audited bypasses and rejects inactive sessions" {
    // Arrange.
    var engine = OverrideEngine.init(testing.allocator, .{});
    defer engine.deinit();
    const state = try engine.engageFor(true, "alice", 0, 1_000, null);

    // Act.
    const seq1 = try engine.record(state, "alice", .ban, "#mod", 100);
    const seq2 = try engine.record(state, "alice", .invite_only, "bob", 200);

    // Assert: sequence increments and records are retained oldest-first.
    try testing.expectEqual(@as(u64, 1), seq1);
    try testing.expectEqual(@as(u64, 2), seq2);
    try testing.expectEqual(@as(usize, 2), engine.auditCount());

    var out: [4]AuditRecord = undefined;
    const listed = engine.auditList(&out);
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings("alice", listed[0].oper);
    try testing.expectEqual(Restriction.ban, listed[0].restriction);
    try testing.expectEqualStrings("#mod", listed[0].target);
    try testing.expectEqual(@as(i64, 100), listed[0].at_ms);
    try testing.expectEqual(Restriction.invite_only, listed[1].restriction);

    // A bypass not permitted by the session is refused and not recorded.
    var only_key = std.EnumSet(Restriction).empty;
    only_key.insert(.key);
    const narrow = try engine.engageFor(true, "alice", 0, 1_000, only_key);
    try testing.expectError(error.NotEngaged, engine.record(narrow, "alice", .ban, "#mod", 300));

    // An expired session is refused too.
    try testing.expectError(error.NotEngaged, engine.record(state, "alice", .ban, "#mod", 5_000));
    try testing.expectEqual(@as(usize, 2), engine.auditCount());
}

test "record validates oper identity and target length" {
    var engine = OverrideEngine.init(testing.allocator, .{ .max_oper_len = 5, .max_target_len = 4 });
    defer engine.deinit();
    const state = try engine.engageFor(true, "op", 0, 1_000, null);

    try testing.expectError(error.InvalidOper, engine.record(state, "", .ban, "ab", 1));
    try testing.expectError(error.InvalidOper, engine.record(state, "toolong", .ban, "ab", 1));
    try testing.expectError(error.TargetTooLong, engine.record(state, "op", .ban, "toolong", 1));

    _ = try engine.record(state, "op", .ban, "abcd", 1);
    try testing.expectEqual(@as(usize, 1), engine.auditCount());
}

test "audit ring evicts oldest records past capacity without leaking" {
    // Arrange: a tiny ring of capacity 3.
    var engine = OverrideEngine.init(testing.allocator, .{ .audit_capacity = 3 });
    defer engine.deinit();
    const state = try engine.engageFor(true, "alice", 0, 100_000, null);

    // Act: record five bypasses; only the newest three survive.
    var seq: usize = 0;
    while (seq < 5) : (seq += 1) {
        var target_buf: [16]u8 = undefined;
        const target = try std.fmt.bufPrint(&target_buf, "#chan-{d}", .{seq});
        _ = try engine.record(state, "alice", .ban, target, @intCast(seq));
    }

    // Assert: ring holds exactly capacity, oldest-first, with newest seqs.
    try testing.expectEqual(@as(usize, 3), engine.auditCount());
    var out: [8]AuditRecord = undefined;
    const listed = engine.auditList(&out);
    try testing.expectEqual(@as(usize, 3), listed.len);
    try testing.expectEqual(@as(u64, 3), listed[0].seq);
    try testing.expectEqualStrings("#chan-2", listed[0].target);
    try testing.expectEqual(@as(u64, 5), listed[2].seq);
    try testing.expectEqualStrings("#chan-4", listed[2].target);
}

test "auditList honors a caller buffer smaller than the ring" {
    var engine = OverrideEngine.init(testing.allocator, .{});
    defer engine.deinit();
    const state = try engine.engageFor(true, "alice", 0, 100_000, null);
    _ = try engine.record(state, "alice", .ban, "one", 1);
    _ = try engine.record(state, "alice", .ban, "two", 2);

    var out: [1]AuditRecord = undefined;
    const listed = engine.auditList(&out);
    try testing.expectEqual(@as(usize, 1), listed.len);
    try testing.expectEqualStrings("one", listed[0].target);
}

test "churning the audit ring releases all owned memory" {
    // Arrange.
    var engine = OverrideEngine.init(testing.allocator, .{ .audit_capacity = 8 });
    defer engine.deinit();
    const state = try engine.engageFor(true, "alice", 0, 1_000_000, null);

    // Act: record well past capacity so eviction frees prior records.
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var target_buf: [24]u8 = undefined;
        const target = try std.fmt.bufPrint(&target_buf, "#busy-channel-{d}", .{i});
        _ = try engine.record(state, "moderator", .moderation, target, @intCast(i));
    }

    // Assert: ring stays bounded; deinit (deferred) reclaims the rest.
    try testing.expectEqual(@as(usize, 8), engine.auditCount());
}
