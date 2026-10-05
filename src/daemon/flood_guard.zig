// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The single per-connection flood guard.
//!
//! This is the one flood rate-limiter in the daemon. Earlier the codebase carried
//! three overlapping mechanisms — a crude per-class line counter in the server, a
//! comptime token-bucket primitive (`flood.zig`), and a comptime guard composed
//! from it — none of which were operator-tunable at runtime. They are gone; this
//! module replaces all of them.
//!
//! Policy lives in the struct (not in comptime), so limits arrive from the per-
//! connection class (`conn_class.Policy.floodGuardConfig`) and retune live on
//! REHASH. The hot path is deterministic and allocation-free: callers pass
//! monotonic milliseconds; the guard never reads a clock. It keeps token-bucket +
//! leaky-excess math, lets any single dimension be disabled (capacity 0 =
//! unmetered), and adds **command-class weighting** — keep-alives (`PING`/`PONG`)
//! cost nothing, `PRIVMSG`/`NOTICE`/`JOIN` carry weight — plus a distinct-target
//! spread throttle that counters spray-spam without a repeated target.
//!
//! This guard is strictly per-connection (token-bucket state lives on the
//! connection and dies with it). A per-*account* abuse score that survived
//! reconnects would be a separate axis; this module does not model it.
const std = @import("std");

/// Result of a rate-control observation.
pub const Decision = enum { allow, throttle, disconnect };

/// One token-bucket dimension. `capacity == 0` disables the dimension entirely
/// (every consume succeeds), which is how an operator turns a check off.
pub const BucketCfg = struct {
    capacity: u64 = 0,
    refill_tokens: u64 = 0,
    refill_period_ms: u64 = 1000,
};

/// Leaky excess-flood policy. `threshold == 0` disables disconnect escalation:
/// offending lines are still reported as `.throttle`, the client is never cut.
pub const ExcessCfg = struct {
    threshold: u64 = 0,
    decay_points: u64 = 1,
    decay_period_ms: u64 = 1000,
};

/// Number of distinct recent PRIVMSG targets tracked per client for the
/// target-change (spread-spam) check. Fixed so the guard stays a flat value.
pub const target_slots: usize = 16;

/// Complete runtime flood policy. Built once from a connection class's policy and
/// shared by value into every guard via `reconfigure`, so a REHASH retunes live
/// clients.
pub const GuardConfig = struct {
    /// Master switch. When false the guard is inert and callers should skip it.
    enabled: bool = false,
    messages: BucketCfg = .{},
    bytes: BucketCfg = .{},
    commands: BucketCfg = .{},
    target_changes: BucketCfg = .{},
    excess: ExcessCfg = .{},
    /// Excess points added when a metered dimension (message/byte/command) trips.
    throttle_penalty: u64 = 1,
    /// Excess points added specifically when the distinct-target rate trips.
    target_change_penalty: u64 = 1,
    /// Weight charged to the command bucket for messaging commands.
    privmsg_weight: u64 = 1,
    /// Weight charged to the command bucket for JOIN (raid/cycle pressure).
    join_weight: u64 = 2,
    /// Weight charged to the command bucket for every other metered command.
    default_weight: u64 = 1,

    pub const Error = error{InvalidFloodConfig};

    /// Reject nonsensical policy at boot/REHASH rather than mis-metering live.
    pub fn validate(self: GuardConfig) Error!void {
        try validateBucket(self.messages);
        try validateBucket(self.bytes);
        try validateBucket(self.commands);
        try validateBucket(self.target_changes);
        if (self.excess.threshold != 0 and self.excess.decay_points != 0 and self.excess.decay_period_ms == 0) {
            return Error.InvalidFloodConfig;
        }
        if (self.throttle_penalty == 0 or self.target_change_penalty == 0) return Error.InvalidFloodConfig;
        if (self.default_weight == 0) return Error.InvalidFloodConfig;
    }

    fn validateBucket(b: BucketCfg) Error!void {
        if (b.capacity == 0) return; // disabled dimension
        if (b.refill_tokens != 0 and b.refill_period_ms == 0) return Error.InvalidFloodConfig;
    }
};

/// Parsed view of an IRC line: command verb, first parameter, and total byte cost.
pub const ParsedLine = struct {
    command: []const u8,
    first_param: []const u8 = "",
    byte_count: u64,
};

const RuntimeBucket = struct {
    cfg: BucketCfg,
    tokens: u64,
    last_ms: i64,
    carry: u64,

    fn init(cfg: BucketCfg, now_ms: i64) RuntimeBucket {
        return .{ .cfg = cfg, .tokens = cfg.capacity, .last_ms = now_ms, .carry = 0 };
    }

    fn available(self: *const RuntimeBucket) u64 {
        return self.tokens;
    }

    fn refill(self: *RuntimeBucket, now_ms: i64) void {
        if (self.cfg.capacity == 0) return;
        const elapsed_ms = elapsedMillis(self.last_ms, now_ms);
        if (elapsed_ms == 0) return;
        self.last_ms = now_ms;
        if (self.cfg.refill_tokens == 0 or self.cfg.refill_period_ms == 0) return;
        if (self.tokens >= self.cfg.capacity) {
            self.carry = 0;
            return;
        }
        const units = @as(u128, elapsed_ms) * @as(u128, self.cfg.refill_tokens) + @as(u128, self.carry);
        const add = units / @as(u128, self.cfg.refill_period_ms);
        if (add == 0) {
            self.carry = @intCast(units);
            return;
        }
        const room = self.cfg.capacity - self.tokens;
        if (add >= room) {
            self.tokens = self.cfg.capacity;
            self.carry = 0;
            return;
        }
        self.tokens += @intCast(add);
        self.carry = @intCast(units % @as(u128, self.cfg.refill_period_ms));
    }

    fn tryConsume(self: *RuntimeBucket, now_ms: i64, cost: u64) bool {
        if (!self.canConsume(now_ms, cost)) return false;
        self.consume(cost);
        return true;
    }

    /// Refill, then report whether `cost` fits — does not mutate the balance.
    /// Used by the all-or-nothing classifier so a miss on one dimension cannot
    /// drain another (partial-charge was a recovery false-positive).
    fn canConsume(self: *RuntimeBucket, now_ms: i64, cost: u64) bool {
        if (self.cfg.capacity == 0) return true;
        self.refill(now_ms);
        if (cost == 0) return true;
        return cost <= self.tokens;
    }

    /// Subtract `cost` after a successful `canConsume`. No-op on a disabled
    /// dimension or a zero cost. Caller must not invoke when `canConsume` failed.
    fn consume(self: *RuntimeBucket, cost: u64) void {
        if (self.cfg.capacity == 0 or cost == 0) return;
        // Saturating floor: a buggy caller that over-charges must not wrap.
        self.tokens -|= cost;
    }

    /// Adopt new policy live. Token balance is clamped into the new capacity so a
    /// REHASH that lowers a limit cannot leave a client holding stale credit.
    fn reconfigure(self: *RuntimeBucket, cfg: BucketCfg) void {
        // Fractional refill units belong to the old rate denominator. A new
        // period or refill amount cannot interpret them canonically.
        if (self.cfg.refill_tokens != cfg.refill_tokens or self.cfg.refill_period_ms != cfg.refill_period_ms)
            self.carry = 0;
        self.cfg = cfg;
        if (cfg.capacity == 0) {
            self.tokens = 0;
            self.carry = 0;
        } else if (self.tokens > cfg.capacity) {
            self.tokens = cfg.capacity;
        }
    }
};

const RuntimeExcess = struct {
    cfg: ExcessCfg,
    points: u64,
    last_ms: i64,
    carry: u64,

    fn init(cfg: ExcessCfg, now_ms: i64) RuntimeExcess {
        return .{ .cfg = cfg, .points = 0, .last_ms = now_ms, .carry = 0 };
    }

    fn current(self: *const RuntimeExcess) u64 {
        return self.points;
    }

    fn decay(self: *RuntimeExcess, now_ms: i64) void {
        const elapsed_ms = elapsedMillis(self.last_ms, now_ms);
        if (elapsed_ms == 0) return;
        self.last_ms = now_ms;
        if (self.cfg.decay_points == 0 or self.cfg.decay_period_ms == 0 or self.points == 0) {
            self.carry = 0;
            return;
        }
        const units = @as(u128, elapsed_ms) * @as(u128, self.cfg.decay_points) + @as(u128, self.carry);
        const remove = units / @as(u128, self.cfg.decay_period_ms);
        if (remove == 0) {
            self.carry = @intCast(units);
            return;
        }
        if (remove >= self.points) {
            self.points = 0;
            self.carry = 0;
            return;
        }
        self.points -= @intCast(remove);
        self.carry = @intCast(units % @as(u128, self.cfg.decay_period_ms));
    }

    fn add(self: *RuntimeExcess, now_ms: i64, points: u64) Decision {
        self.decay(now_ms);
        self.points = saturatingAdd(self.points, points);
        if (self.cfg.threshold != 0 and self.points >= self.cfg.threshold) return .disconnect;
        return .throttle;
    }

    fn tripped(self: *const RuntimeExcess) bool {
        return self.cfg.threshold != 0 and self.points >= self.cfg.threshold;
    }

    fn reconfigure(self: *RuntimeExcess, cfg: ExcessCfg) void {
        if (self.cfg.decay_points != cfg.decay_points or self.cfg.decay_period_ms != cfg.decay_period_ms)
            self.carry = 0;
        self.cfg = cfg;
    }
};

const TargetKey = struct {
    hash: u64,
    len: usize,

    const empty: TargetKey = .{ .hash = 0, .len = 0 };

    fn init(target: []const u8) TargetKey {
        return .{ .hash = hashFoldedAscii(target), .len = target.len };
    }

    fn eql(self: TargetKey, other: TargetKey) bool {
        return self.hash == other.hash and self.len == other.len;
    }
};

/// Fixed-size, allocation-free image of one live guard. The later Helix codec
/// serializes these typed fields explicitly; raw struct bytes are not a wire
/// format because Zig may insert padding. The policy is carried so import can
/// prove it matches the successor's independently derived connection class.
pub const CarryState = struct {
    policy: GuardConfig,
    message_rate: BucketCarry,
    byte_rate: BucketCarry,
    command_rate: BucketCarry,
    target_change_rate: BucketCarry,
    excess: ExcessCarry,
    targets: [target_slots]TargetCarry,
    target_count: u8,
    next_target_slot: u8,
};

pub const BucketCarry = struct {
    tokens: u64,
    last_ms: i64,
    carry: u64,
};

pub const ExcessCarry = struct {
    points: u64,
    last_ms: i64,
    carry: u64,
};

pub const TargetCarry = struct {
    hash: u64,
    len: u64,

    pub const empty: TargetCarry = .{ .hash = 0, .len = 0 };
};

pub const CarryError = GuardConfig.Error || error{
    InvalidCarryState,
    PolicyMismatch,
    ClockRegression,
};

fn bucketCarry(bucket: RuntimeBucket) BucketCarry {
    return .{ .tokens = bucket.tokens, .last_ms = bucket.last_ms, .carry = bucket.carry };
}

fn excessCarry(excess: RuntimeExcess) ExcessCarry {
    return .{ .points = excess.points, .last_ms = excess.last_ms, .carry = excess.carry };
}

fn validateBucketCarry(state: BucketCarry, cfg: BucketCfg, now_ms: ?i64) CarryError!void {
    if (cfg.capacity == 0) {
        if (state.tokens != 0 or state.carry != 0) return error.InvalidCarryState;
    } else if (state.tokens > cfg.capacity) return error.InvalidCarryState;
    if (cfg.capacity != 0 and cfg.refill_tokens != 0 and cfg.refill_period_ms != 0 and
        state.carry >= cfg.refill_period_ms) return error.InvalidCarryState;
    if (now_ms) |now| if (state.last_ms > now) return error.ClockRegression;
}

fn validateCarry(state: CarryState, expected_policy: GuardConfig, now_ms: ?i64) CarryError!void {
    try expected_policy.validate();
    try state.policy.validate();
    if (!std.meta.eql(state.policy, expected_policy)) return error.PolicyMismatch;
    try validateBucketCarry(state.message_rate, expected_policy.messages, now_ms);
    try validateBucketCarry(state.byte_rate, expected_policy.bytes, now_ms);
    try validateBucketCarry(state.command_rate, expected_policy.commands, now_ms);
    try validateBucketCarry(state.target_change_rate, expected_policy.target_changes, now_ms);
    if (now_ms) |now| if (state.excess.last_ms > now) return error.ClockRegression;
    if (expected_policy.excess.decay_points != 0 and expected_policy.excess.decay_period_ms != 0 and
        state.excess.carry >= expected_policy.excess.decay_period_ms) return error.InvalidCarryState;
    if (state.target_count > target_slots or state.next_target_slot >= target_slots or
        (state.target_count < target_slots and state.next_target_slot != 0))
        return error.InvalidCarryState;
    for (state.targets, 0..) |key, index| {
        if (index >= state.target_count) {
            if (!std.meta.eql(key, TargetCarry.empty)) return error.InvalidCarryState;
            continue;
        }
        if (key.len == 0 or key.len > std.math.maxInt(usize)) return error.InvalidCarryState;
        for (state.targets[0..index]) |prior| {
            if (std.meta.eql(key, prior)) return error.InvalidCarryState;
        }
    }
}

/// Per-connection flood guard. Bounded, allocation-free, deterministic.
pub const FloodGuard = struct {
    config: GuardConfig,
    message_rate: RuntimeBucket,
    byte_rate: RuntimeBucket,
    command_rate: RuntimeBucket,
    target_change_rate: RuntimeBucket,
    excess: RuntimeExcess,
    targets: [target_slots]TargetKey = @splat(TargetKey.empty),
    target_count: usize = 0,
    next_target_slot: usize = 0,

    pub const Snapshot = struct {
        message_tokens: u64,
        byte_tokens: u64,
        command_tokens: u64,
        target_change_tokens: u64,
        excess_points: u64,
        tracked_targets: usize,
    };

    pub fn init(config: GuardConfig, now_ms: i64) FloodGuard {
        return .{
            .config = config,
            .message_rate = RuntimeBucket.init(config.messages, now_ms),
            .byte_rate = RuntimeBucket.init(config.bytes, now_ms),
            .command_rate = RuntimeBucket.init(config.commands, now_ms),
            .target_change_rate = RuntimeBucket.init(config.target_changes, now_ms),
            .excess = RuntimeExcess.init(config.excess, now_ms),
        };
    }

    /// Retune a live guard to new policy (REHASH). Accumulated token/excess state
    /// is preserved and clamped, so a client mid-flood is neither pardoned nor
    /// double-charged by the config change.
    pub fn reconfigure(self: *FloodGuard, config: GuardConfig) void {
        self.config = config;
        self.message_rate.reconfigure(config.messages);
        self.byte_rate.reconfigure(config.bytes);
        self.command_rate.reconfigure(config.commands);
        self.target_change_rate.reconfigure(config.target_changes);
        self.excess.reconfigure(config.excess);
    }

    pub fn classifyRaw(self: *FloodGuard, now_ms: i64, raw_line: []const u8) Decision {
        return self.classifyParsed(now_ms, parseRaw(raw_line));
    }

    pub fn classifyParsed(self: *FloodGuard, now_ms: i64, line: ParsedLine) Decision {
        // Keep-alives never count against flood; the connection still has the
        // recv-buffer ceiling as a backstop against raw PING/PONG spam.
        const weight = self.commandWeight(line.command);
        if (weight == 0) {
            self.excess.decay(now_ms);
            if (self.excess.tripped()) return .disconnect;
            return .allow;
        }

        // All-or-nothing: peek every dimension first, charge only when the whole
        // line is admitted. A partial charge (e.g. message tokens drained while
        // the command bucket refused) left clients under-recovered after a brief
        // burst — the next legitimate PRIVMSG still throttled on the drained
        // dimension even though the refusing one had refilled. Throttle/disconnect
        // never mutates token balances; only excess accrues.
        //
        // Verdict surface is {allow, throttle, disconnect} only. The guard never
        // invents a TEMPORARILY_UNAVAILABLE / FAIL code — that class of reply is
        // a mesh/session concern, not flood. Callers that still process `.throttle`
        // lines (the live daemon) keep user input flowing; only `.disconnect`
        // tears the socket down with Excess Flood.
        const message_ok = self.message_rate.canConsume(now_ms, 1);
        const bytes_ok = self.byte_rate.canConsume(now_ms, line.byte_count);
        const command_ok = self.command_rate.canConsume(now_ms, weight);
        const target = self.inspectTargetChange(now_ms, line);

        if (message_ok and bytes_ok and command_ok and target.ok) {
            self.message_rate.consume(1);
            self.byte_rate.consume(line.byte_count);
            self.command_rate.consume(weight);
            if (target.charge) {
                self.target_change_rate.consume(1);
                self.rememberTarget(target.key);
            }
            self.excess.decay(now_ms);
            if (self.excess.tripped()) return .disconnect;
            return .allow;
        }

        const penalty = if (!target.ok) self.config.target_change_penalty else self.config.throttle_penalty;
        return self.excess.add(now_ms, penalty);
    }

    pub fn decay(self: *FloodGuard, now_ms: i64) void {
        self.message_rate.refill(now_ms);
        self.byte_rate.refill(now_ms);
        self.command_rate.refill(now_ms);
        self.target_change_rate.refill(now_ms);
        self.excess.decay(now_ms);
    }

    pub fn snapshot(self: *const FloodGuard) Snapshot {
        return .{
            .message_tokens = self.message_rate.available(),
            .byte_tokens = self.byte_rate.available(),
            .command_tokens = self.command_rate.available(),
            .target_change_tokens = self.target_change_rate.available(),
            .excess_points = self.excess.current(),
            .tracked_targets = self.target_count,
        };
    }

    /// Seal every metering dimension and target-ring cursor without decaying it.
    /// A malformed live image fails the pre-COMMIT snapshot instead of granting
    /// the successor fresh flood credit.
    pub fn exportCarry(self: *const FloodGuard) CarryError!CarryState {
        if (!std.meta.eql(self.message_rate.cfg, self.config.messages) or
            !std.meta.eql(self.byte_rate.cfg, self.config.bytes) or
            !std.meta.eql(self.command_rate.cfg, self.config.commands) or
            !std.meta.eql(self.target_change_rate.cfg, self.config.target_changes) or
            !std.meta.eql(self.excess.cfg, self.config.excess) or
            self.target_count > target_slots or self.next_target_slot >= target_slots)
            return error.InvalidCarryState;
        var targets: [target_slots]TargetCarry = @splat(TargetCarry.empty);
        for (self.targets, 0..) |key, index| {
            targets[index] = .{
                .hash = key.hash,
                .len = std.math.cast(u64, key.len) orelse return error.InvalidCarryState,
            };
        }
        const state = CarryState{
            .policy = self.config,
            .message_rate = bucketCarry(self.message_rate),
            .byte_rate = bucketCarry(self.byte_rate),
            .command_rate = bucketCarry(self.command_rate),
            .target_change_rate = bucketCarry(self.target_change_rate),
            .excess = excessCarry(self.excess),
            .targets = targets,
            .target_count = std.math.cast(u8, self.target_count) orelse return error.InvalidCarryState,
            .next_target_slot = std.math.cast(u8, self.next_target_slot) orelse return error.InvalidCarryState,
        };
        try validateCarry(state, self.config, null);
        return state;
    }

    /// Restore only under the exact policy independently derived for this
    /// connection on the successor. All checks precede construction, so a
    /// failed import cannot publish partial credit or target history.
    pub fn importCarry(expected_policy: GuardConfig, now_ms: i64, state: CarryState) CarryError!FloodGuard {
        try validateCarry(state, expected_policy, now_ms);
        var guard = FloodGuard.init(expected_policy, now_ms);
        guard.message_rate.tokens = state.message_rate.tokens;
        guard.message_rate.last_ms = state.message_rate.last_ms;
        guard.message_rate.carry = state.message_rate.carry;
        guard.byte_rate.tokens = state.byte_rate.tokens;
        guard.byte_rate.last_ms = state.byte_rate.last_ms;
        guard.byte_rate.carry = state.byte_rate.carry;
        guard.command_rate.tokens = state.command_rate.tokens;
        guard.command_rate.last_ms = state.command_rate.last_ms;
        guard.command_rate.carry = state.command_rate.carry;
        guard.target_change_rate.tokens = state.target_change_rate.tokens;
        guard.target_change_rate.last_ms = state.target_change_rate.last_ms;
        guard.target_change_rate.carry = state.target_change_rate.carry;
        guard.excess.points = state.excess.points;
        guard.excess.last_ms = state.excess.last_ms;
        guard.excess.carry = state.excess.carry;
        for (state.targets, 0..) |key, index| {
            guard.targets[index] = .{ .hash = key.hash, .len = @intCast(key.len) };
        }
        guard.target_count = state.target_count;
        guard.next_target_slot = state.next_target_slot;
        return guard;
    }

    fn commandWeight(self: *const FloodGuard, command: []const u8) u64 {
        if (eqIgnoreCase(command, "PING") or eqIgnoreCase(command, "PONG")) return 0;
        if (eqIgnoreCase(command, "PRIVMSG") or eqIgnoreCase(command, "NOTICE") or eqIgnoreCase(command, "TAGMSG")) {
            return self.config.privmsg_weight;
        }
        if (eqIgnoreCase(command, "JOIN")) return self.config.join_weight;
        return self.config.default_weight;
    }

    const TargetInspect = struct {
        ok: bool,
        /// True when admitting the line must burn one target-change token and
        /// remember `key` (a not-yet-seen PRIVMSG target with budget remaining).
        charge: bool = false,
        key: TargetKey = TargetKey.empty,
    };

    /// Peek the distinct-target (spread-spam) dimension without mutating state.
    /// Only PRIVMSG with a non-empty first parameter is tracked; NOTICE/TAGMSG
    /// and bare PRIVMSG (no target) pass through free.
    fn inspectTargetChange(self: *FloodGuard, now_ms: i64, line: ParsedLine) TargetInspect {
        if (!eqIgnoreCase(line.command, "PRIVMSG")) return .{ .ok = true };
        if (line.first_param.len == 0) return .{ .ok = true };

        const key = TargetKey.init(line.first_param);
        if (self.hasTarget(key)) return .{ .ok = true, .key = key };
        if (!self.target_change_rate.canConsume(now_ms, 1)) return .{ .ok = false, .key = key };
        return .{ .ok = true, .charge = true, .key = key };
    }

    fn hasTarget(self: *const FloodGuard, key: TargetKey) bool {
        for (self.targets[0..self.target_count]) |target| {
            if (target.eql(key)) return true;
        }
        return false;
    }

    fn rememberTarget(self: *FloodGuard, key: TargetKey) void {
        if (self.target_count < self.targets.len) {
            self.targets[self.target_count] = key;
            self.target_count += 1;
            return;
        }
        self.targets[self.next_target_slot] = key;
        self.next_target_slot = (self.next_target_slot + 1) % self.targets.len;
    }
};

fn parseRaw(raw_line: []const u8) ParsedLine {
    const body = trimLineEnding(raw_line);
    var cursor = skipSpaces(body, 0);

    if (cursor < body.len and body[cursor] == '@') {
        cursor = skipSpaces(body, findSpace(body, cursor) orelse body.len);
    }
    if (cursor < body.len and body[cursor] == ':') {
        cursor = skipSpaces(body, findSpace(body, cursor) orelse body.len);
    }

    const command_start = cursor;
    const command_end = findSpace(body, cursor) orelse body.len;
    cursor = skipSpaces(body, command_end);

    var first_param: []const u8 = "";
    if (cursor < body.len) {
        if (body[cursor] == ':') {
            first_param = body[cursor + 1 ..];
        } else {
            const param_end = findSpace(body, cursor) orelse body.len;
            first_param = body[cursor..param_end];
        }
    }

    return .{
        .command = body[command_start..command_end],
        .first_param = first_param,
        .byte_count = @intCast(raw_line.len),
    };
}

fn trimLineEnding(input: []const u8) []const u8 {
    if (input.len >= 2 and input[input.len - 2] == '\r' and input[input.len - 1] == '\n') {
        return input[0 .. input.len - 2];
    }
    if (input.len >= 1 and (input[input.len - 1] == '\r' or input[input.len - 1] == '\n')) {
        return input[0 .. input.len - 1];
    }
    return input;
}

fn skipSpaces(input: []const u8, start: usize) usize {
    var cursor = start;
    while (cursor < input.len and input[cursor] == ' ') : (cursor += 1) {}
    return cursor;
}

fn findSpace(input: []const u8, start: usize) ?usize {
    var cursor = start;
    while (cursor < input.len) : (cursor += 1) {
        if (input[cursor] == ' ') return cursor;
    }
    return null;
}

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn hashFoldedAscii(input: []const u8) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (input) |byte| {
        hash ^= asciiLower(byte);
        hash *%= 0x100000001b3;
    }
    return hash;
}

fn asciiLower(byte: u8) u8 {
    if (byte >= 'A' and byte <= 'Z') return byte + ('a' - 'A');
    return byte;
}

fn elapsedMillis(last_ms: i64, now_ms: i64) u64 {
    const delta = @as(i128, now_ms) - @as(i128, last_ms);
    if (delta <= 0) return 0;
    if (delta > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(delta);
}

fn saturatingAdd(a: u64, b: u64) u64 {
    const max = std.math.maxInt(u64);
    if (max - a < b) return max;
    return a + b;
}

const testing = std.testing;

fn testConfig() GuardConfig {
    return .{
        .enabled = true,
        .messages = .{},
        .bytes = .{},
        .commands = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 },
        .target_changes = .{ .capacity = 8, .refill_tokens = 8, .refill_period_ms = 1000 },
        .excess = .{ .threshold = 10, .decay_points = 1, .decay_period_ms = 1000 },
    };
}

test "a valid config passes validation" {
    try testConfig().validate();
}

test "burst then throttle then recover" {
    var guard = FloodGuard.init(testConfig(), 0);
    const line = "WHOIS onyx\r\n";
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(1000, line));
}

test "keep-alives are never metered" {
    var guard = FloodGuard.init(testConfig(), 0);
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PING :x\r\n"));
    }
}

test "command weighting makes PRIVMSG cost more" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 4, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.privmsg_weight = 2;
    var guard = FloodGuard.init(cfg, 0);
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :hi\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :hi\r\n"));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "PRIVMSG #a :hi\r\n"));
}

test "distinct-target spread throttles" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 100, .refill_tokens = 100, .refill_period_ms = 1000 };
    cfg.target_changes = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :one\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "privmsg #A :two\r\n")); // same target, case-folded
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #b :three\r\n"));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "PRIVMSG #c :four\r\n"));
}

test "disabled dimension never blocks" {
    var cfg = testConfig();
    cfg.commands = .{};
    cfg.target_changes = .{};
    var guard = FloodGuard.init(cfg, 0);
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :spam\r\n"));
    }
}

test "threshold zero throttles forever but never disconnects" {
    var cfg = testConfig();
    cfg.excess = .{ .threshold = 0, .decay_points = 1, .decay_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "WHOIS a\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "WHOIS a\r\n"));
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "WHOIS a\r\n"));
    }
}

test "excess accumulation eventually disconnects" {
    var cfg = testConfig();
    cfg.excess = .{ .threshold = 3, .decay_points = 1, .decay_period_ms = 100000 };
    var guard = FloodGuard.init(cfg, 0);
    _ = guard.classifyRaw(0, "WHOIS a\r\n"); // allow
    _ = guard.classifyRaw(0, "WHOIS a\r\n"); // allow (bucket now empty)
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "WHOIS a\r\n")); // +1
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "WHOIS a\r\n")); // +1
    try testing.expectEqual(Decision.disconnect, guard.classifyRaw(0, "WHOIS a\r\n")); // +1 => 3
}

test "reconfigure clamps tokens and retunes live" {
    var guard = FloodGuard.init(testConfig(), 0);
    _ = guard.classifyRaw(0, "WHOIS a\r\n");
    var tighter = testConfig();
    tighter.commands = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 1000 };
    guard.reconfigure(tighter);
    try testing.expect(guard.snapshot().command_tokens <= 1);
}

test "carry state preserves all flood dimensions, excess decay, and wrapped target ring" {
    var cfg = testConfig();
    cfg.messages = .{ .capacity = 18, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.bytes = .{ .capacity = 2048, .refill_tokens = 5, .refill_period_ms = 1000 };
    cfg.commands = .{ .capacity = 18, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.target_changes = .{ .capacity = 18, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.excess = .{ .threshold = 10, .decay_points = 1, .decay_period_ms = 1000 };
    var source = FloodGuard.init(cfg, 100);
    for (0..target_slots + 1) |index| {
        var line_buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buf, "PRIVMSG #t{d} :hello\r\n", .{index});
        try testing.expectEqual(Decision.allow, source.classifyRaw(100, line));
    }
    try testing.expectEqual(Decision.allow, source.classifyRaw(100, "WHOIS x\r\n"));
    try testing.expectEqual(Decision.throttle, source.classifyRaw(100, "WHOIS x\r\n"));
    source.decay(175);

    const sealed = try source.exportCarry();
    try testing.expectEqual(@as(u8, target_slots), sealed.target_count);
    try testing.expectEqual(@as(u8, 1), sealed.next_target_slot);
    try testing.expectEqual(@as(u64, 1), sealed.excess.points);
    try testing.expect(sealed.message_rate.carry != 0);
    try testing.expect(sealed.byte_rate.carry != 0);
    try testing.expect(sealed.command_rate.carry != 0);
    try testing.expect(sealed.target_change_rate.carry != 0);
    try testing.expect(sealed.excess.carry != 0);

    var restored = try FloodGuard.importCarry(cfg, 200, sealed);
    try testing.expectEqualDeep(sealed, try restored.exportCarry());
    const lines = [_][]const u8{ "PRIVMSG #t1 :repeat\r\n", "PRIVMSG #new :new\r\n", "WHOIS x\r\n" };
    const times = [_]i64{ 200, 1200, 1200 };
    for (lines, times) |line, now_ms| {
        try testing.expectEqual(source.classifyRaw(now_ms, line), restored.classifyRaw(now_ms, line));
        try testing.expectEqualDeep(try source.exportCarry(), try restored.exportCarry());
    }
}

test "carry import rejects policy drift, future clocks, and malformed bounded state" {
    const cfg = testConfig();
    var source = FloodGuard.init(cfg, 100);
    try testing.expectEqual(Decision.allow, source.classifyRaw(100, "PRIVMSG #a :hi\r\n"));
    const sealed = try source.exportCarry();

    var changed_policy = cfg;
    changed_policy.commands.capacity += 1;
    try testing.expectError(error.PolicyMismatch, FloodGuard.importCarry(changed_policy, 101, sealed));
    var altered = sealed;
    altered.command_rate.tokens = cfg.commands.capacity + 1;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 101, altered));
    altered = sealed;
    altered.message_rate.last_ms = 102;
    try testing.expectError(error.ClockRegression, FloodGuard.importCarry(cfg, 101, altered));
    altered = sealed;
    altered.excess.last_ms = 102;
    try testing.expectError(error.ClockRegression, FloodGuard.importCarry(cfg, 101, altered));
    altered = sealed;
    altered.target_count = target_slots + 1;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 101, altered));
    altered = sealed;
    altered.next_target_slot = 1;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 101, altered));
    altered = sealed;
    altered.targets[1] = altered.targets[0];
    altered.target_count = 2;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 101, altered));
    altered = sealed;
    altered.targets[1] = .{ .hash = 0x55, .len = 2 };
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 101, altered));

    source.command_rate.tokens = cfg.commands.capacity + 1;
    try testing.expectError(error.InvalidCarryState, source.exportCarry());
}

test "carry import rejects out-of-range fractional refill and decay" {
    var cfg = testConfig();
    cfg.messages = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 101 };
    cfg.bytes = .{ .capacity = 20, .refill_tokens = 3, .refill_period_ms = 103 };
    cfg.commands.refill_period_ms = 107;
    cfg.target_changes.refill_period_ms = 109;
    cfg.excess.decay_period_ms = 113;
    var source = FloodGuard.init(cfg, 100);
    const sealed = try source.exportCarry();

    var altered = sealed;
    altered.message_rate.carry = cfg.messages.refill_period_ms;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 100, altered));
    altered = sealed;
    altered.byte_rate.carry = cfg.bytes.refill_period_ms;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 100, altered));
    altered = sealed;
    altered.command_rate.carry = cfg.commands.refill_period_ms;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 100, altered));
    altered = sealed;
    altered.target_change_rate.carry = cfg.target_changes.refill_period_ms;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 100, altered));
    altered = sealed;
    altered.excess.carry = cfg.excess.decay_period_ms;
    try testing.expectError(error.InvalidCarryState, FloodGuard.importCarry(cfg, 100, altered));

    source.command_rate.carry = cfg.commands.refill_period_ms;
    try testing.expectError(error.InvalidCarryState, source.exportCarry());
}

test "reconfigure resets fractional carry when a rate denominator changes" {
    var cfg = testConfig();
    var source = FloodGuard.init(cfg, 100);
    _ = source.classifyRaw(100, "WHOIS a\r\n");
    source.decay(175);
    try testing.expect(source.command_rate.carry != 0);
    cfg.commands.refill_period_ms = 50;
    source.reconfigure(cfg);
    try testing.expectEqual(@as(u64, 0), source.command_rate.carry);
    _ = try source.exportCarry();
}

test "deterministic for identical inputs" {
    var a = FloodGuard.init(testConfig(), 50);
    var b = FloodGuard.init(testConfig(), 50);
    const lines = [_][]const u8{ "PING :a\r\n", "PRIVMSG nick :b\r\n", "PRIVMSG #chan :c\r\n", "WHOIS d\r\n" };
    const times = [_]i64{ 50, 50, 40, 1050, 2050, 2050 };
    const idxs = [_]usize{ 0, 1, 2, 3, 0, 1 };
    for (times, idxs) |now_ms, idx| {
        try testing.expectEqual(a.classifyRaw(now_ms, lines[idx]), b.classifyRaw(now_ms, lines[idx]));
    }
    try testing.expectEqual(a.snapshot(), b.snapshot());
}

test "invalid config rejected" {
    var bad = testConfig();
    bad.throttle_penalty = 0;
    try testing.expectError(GuardConfig.Error.InvalidFloodConfig, bad.validate());
}

test "PRIVMSG charge is all-or-nothing across dimensions" {
    // A command-bucket miss must not drain the message bucket: partial charge
    // used to leave a client under-recovered after a brief burst (next legitimate
    // PRIVMSG still throttled on the drained dimension while the refusing one
    // had already refilled).
    var cfg = testConfig();
    cfg.messages = .{ .capacity = 2, .refill_tokens = 2, .refill_period_ms = 1000 };
    cfg.commands = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.target_changes = .{};
    cfg.excess = .{ .threshold = 0, .decay_points = 1, .decay_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);

    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :one\r\n"));
    // Command empty; message still has 1. Throttle must not spend that 1.
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "PRIVMSG #a :two\r\n"));
    try testing.expectEqual(@as(u64, 1), guard.snapshot().message_tokens);
    try testing.expectEqual(@as(u64, 0), guard.snapshot().command_tokens);

    // Command refills at t=1000; message token preserved → admit, not a second wait.
    try testing.expectEqual(Decision.allow, guard.classifyRaw(1000, "PRIVMSG #a :three\r\n"));
}

test "same-target PRIVMSG burst does not trip spread throttle" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 100, .refill_tokens = 100, .refill_period_ms = 1000 };
    cfg.target_changes = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);
    // First sight of #a burns one target token; every repeat is free.
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #chat :1\r\n"));
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #chat :spam\r\n"));
    }
    try testing.expectEqual(@as(usize, 1), guard.snapshot().tracked_targets);
}

test "production-like class rate admits normal PRIVMSG chat" {
    // Mirrors live [class.user] knobs (flood_lines=120 / 10s / targets=30 /
    // excess=200): a user talking in a few channels at a few lines/sec must not
    // throttle, and the guard must never surface anything beyond allow/throttle/
    // disconnect (no TEMPORARILY_UNAVAILABLE inventing).
    const cfg = GuardConfig{
        .enabled = true,
        .messages = .{},
        .bytes = .{},
        .commands = .{ .capacity = 120, .refill_tokens = 120, .refill_period_ms = 10_000 },
        .target_changes = .{ .capacity = 30, .refill_tokens = 30, .refill_period_ms = 10_000 },
        .excess = .{ .threshold = 200, .decay_points = 1, .decay_period_ms = 1000 },
    };
    try cfg.validate();
    var guard = FloodGuard.init(cfg, 0);

    // ~5 channels × 4 lines in one second — well under 120/10s and 30 targets.
    const channels = [_][]const u8{ "#a", "#b", "#c", "#d", "#e" };
    var t: i64 = 0;
    for (channels) |ch| {
        var n: usize = 0;
        while (n < 4) : (n += 1) {
            var buf: [64]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "PRIVMSG {s} :hello {d}\r\n", .{ ch, n }) catch unreachable;
            try testing.expectEqual(Decision.allow, guard.classifyRaw(t, line));
            t += 50; // 20 lines/sec peak, brief
        }
    }
    const snap = guard.snapshot();
    try testing.expect(snap.command_tokens > 90); // most of the budget remains
    try testing.expectEqual(@as(usize, 5), snap.tracked_targets);
    try testing.expectEqual(@as(u64, 0), snap.excess_points);
}

test "throttle never remembers a new target (no partial target charge)" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.target_changes = .{ .capacity = 8, .refill_tokens = 8, .refill_period_ms = 1000 };
    cfg.excess = .{ .threshold = 0, .decay_points = 1, .decay_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);

    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #a :one\r\n"));
    try testing.expectEqual(@as(u64, 7), guard.snapshot().target_change_tokens); // #a spent one
    // Command empty → throttle. #b must NOT be remembered or charged.
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "PRIVMSG #b :two\r\n"));
    try testing.expectEqual(@as(usize, 1), guard.snapshot().tracked_targets);
    try testing.expectEqual(@as(u64, 7), guard.snapshot().target_change_tokens); // unchanged

    // After refill, #b is still a new target and burns one token on allow.
    try testing.expectEqual(Decision.allow, guard.classifyRaw(1000, "PRIVMSG #b :three\r\n"));
    try testing.expectEqual(@as(usize, 2), guard.snapshot().tracked_targets);
}

test "NOTICE is weighted like PRIVMSG but skips target tracking" {
    var cfg = testConfig();
    cfg.commands = .{ .capacity = 2, .refill_tokens = 1, .refill_period_ms = 1000 };
    cfg.privmsg_weight = 1;
    cfg.target_changes = .{ .capacity = 1, .refill_tokens = 1, .refill_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);
    // Many distinct NOTICE targets: target dimension must not bite.
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "NOTICE #a :x\r\n"));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "NOTICE #b :y\r\n"));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, "NOTICE #c :z\r\n")); // command only
    try testing.expectEqual(@as(usize, 0), guard.snapshot().tracked_targets);
}

// --- Exploit corpus: PRIVMSG flood must throttle/disconnect the subject and
// then RECOVER after the refill window — never permanently brick the meter
// for a well-behaved later timeline (CWE-400). Assert recovers, not "works".

test "exploit: PRIVMSG flood recovers after window (no permanent brick)" {
    var cfg = testConfig();
    cfg.messages = .{ .capacity = 2, .refill_tokens = 2, .refill_period_ms = 1000 };
    cfg.commands = .{ .capacity = 2, .refill_tokens = 2, .refill_period_ms = 1000 };
    cfg.excess = .{ .threshold = 4, .decay_points = 4, .decay_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);

    const line = "PRIVMSG #chan :flood\r\n";
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, line));
    // Bucket empty: throttle, then accumulate excess toward disconnect.
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.throttle, guard.classifyRaw(0, line));
    try testing.expectEqual(Decision.disconnect, guard.classifyRaw(0, line));

    // After the refill + excess-decay window the same subject is allowed again
    // (a new connection would re-init; this proves the math itself recovers
    // and is not a sticky permanent brick of the meter state).
    try testing.expectEqual(Decision.allow, guard.classifyRaw(1000, line));
    try testing.expectEqual(Decision.allow, guard.classifyRaw(1000, line));
}

test "exploit: PRIVMSG flood is bounded work per classify (no unbounded growth)" {
    // Spray many distinct targets then hammer one channel: target slots are
    // fixed (target_slots), so classify stays O(1) and never allocates.
    var cfg = testConfig();
    cfg.messages = .{};
    cfg.commands = .{};
    cfg.target_changes = .{ .capacity = 4, .refill_tokens = 4, .refill_period_ms = 1000 };
    cfg.excess = .{ .threshold = 0, .decay_points = 1, .decay_period_ms = 1000 };
    var guard = FloodGuard.init(cfg, 0);

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var buf: [64]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "PRIVMSG #t{d} :x\r\n", .{i}) catch unreachable;
        // After the first 4 distinct targets every new target throttles; never
        // panics, never grows past target_slots.
        _ = guard.classifyRaw(0, line);
    }
    try testing.expect(guard.snapshot().tracked_targets <= target_slots);

    // Same-target spam after the spray still classifies (target already known
    // or ring-evicted) without sticky failure beyond throttle.
    try testing.expectEqual(Decision.allow, guard.classifyRaw(0, "PRIVMSG #t0 :again\r\n"));
}
