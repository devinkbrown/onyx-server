// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Projection-free observational coordinator for the inactive OCG2 authority.
//!
//! The runtime owns only bounded C2/C3/C4 scratch and an acknowledged advisory
//! baseline. It may renew the durable security horizon and inspect exact work,
//! but it cannot project, grant, revoke, mutate sessions, emit, or transmit.

const std = @import("std");
const durable_oper_authority = @import("durable_oper_authority.zig");
const ocg2_reconcile_schedule = @import("ocg2_reconcile_schedule.zig");
const ocg2_reconcile_workset = @import("ocg2_reconcile_workset.zig");
const services_mod = @import("services.zig");
const store_mod = @import("store.zig");

const Services = services_mod.Services;
const max_records = durable_oper_authority.max_records;

pub const Retryable = enum {
    out_of_memory,
    busy,
    store_failure,
    inventory_changed,
};

pub const Failure = union(enum) {
    authority_disabled,
    authority_unavailable,
    restart_required: Services.DurableOperRestartReason,
    invalid_clock_sample,
    monotonic_rollback,
    clock_overflow,
    capacity,
    inventory_invariant,
    schedule_invariant,
    workset_invariant,
    observation_invariant,
};

pub const Summary = struct {
    observing: bool = false,
    failed: bool = false,
    baseline_count: usize = 0,
    ticks_completed: u64 = 0,
    retryable_ticks: u64 = 0,
    work_inspected: u64 = 0,
    last_security_now_ms: ?u64 = null,
    last_candidate_count: usize = 0,
    last_work_count: usize = 0,
    last_active_count: usize = 0,
    last_terminal_count: usize = 0,
    earliest_transition_ms: ?u64 = null,
};

pub const TickResult = union(enum) {
    disabled,
    complete: Summary,
    retryable: Retryable,
    failed: Failure,
};

const Mode = enum { disabled, observing, failed };

/// Opaque observation-only handle. The private Impl owns the borrowed Services
/// capability and bounded scratch; neither can be recovered through reflection
/// on the public type.
pub const Runtime = opaque {
    pub fn summary(self: *const Runtime) Summary {
        return asImplConst(self).counters;
    }

    pub fn failMonotonicRollback(self: *Runtime) TickResult {
        return failMonotonicRollbackInner(self);
    }

    pub fn tick(self: *Runtime, raw_realtime_ms: u64, monotonic_elapsed_ms: u64) TickResult {
        return tickInner(self, raw_realtime_ms, monotonic_elapsed_ms);
    }
};

const Impl = struct {
    allocator: std.mem.Allocator,
    mode: Mode = .disabled,
    services: *Services,
    failure: Failure = .authority_disabled,
    counters: Summary = .{},
    last_monotonic_elapsed_ms: ?u64 = null,
    previous_security_now_ms: ?u64 = null,
    baseline_count: usize = 0,
    transactions: [max_records]Services.DurableOperTransactionCopy = undefined,
    hints: [max_records]ocg2_reconcile_schedule.ReinspectHint = undefined,
    baseline: [max_records]ocg2_reconcile_workset.BaselineEntry = undefined,
    candidates: [max_records]ocg2_reconcile_workset.BaselineEntry = undefined,
    work: [max_records]ocg2_reconcile_workset.WorkItem = undefined,
};

fn asImpl(self: *Runtime) *Impl {
    return @ptrCast(@alignCast(self));
}

fn asImplConst(self: *const Runtime) *const Impl {
    return @ptrCast(@alignCast(self));
}

fn asHandle(inner: *Impl) *Runtime {
    return @ptrCast(inner);
}

pub fn createObserve(allocator: std.mem.Allocator, services: *Services) !*Runtime {
    const inner = try allocator.create(Impl);
    inner.* = .{
        .allocator = allocator,
        .mode = .observing,
        .services = services,
        .counters = .{ .observing = true },
    };
    return asHandle(inner);
}

pub fn destroy(self: *Runtime) void {
    const inner = asImpl(self);
    const allocator = inner.allocator;
    inner.* = undefined;
    allocator.destroy(inner);
}

/// Terminally reject an integration-level rollback that cannot be expressed
/// as an elapsed `u64` sample (for example, a monotonic clock preceding the
/// exact origin paired with the synchronous prime). This poisons the same
/// Services image borrowed by the Runtime; callers cannot accidentally
/// fail-close an unrelated account service.
fn failMonotonicRollbackInner(self: *Runtime) TickResult {
    const inner = asImpl(self);
    return switch (inner.mode) {
        .disabled => .disabled,
        .failed => .{ .failed = inner.failure },
        .observing => fail(inner, .monotonic_rollback),
    };
}

fn fail(self: *Impl, reason: Failure) TickResult {
    switch (reason) {
        .authority_disabled => {},
        else => self.services.failClosedDurableOperAuthority(),
    }
    self.mode = .failed;
    self.failure = reason;
    self.counters.observing = false;
    self.counters.failed = true;
    return .{ .failed = reason };
}

fn retry(self: *Impl, reason: Services.DurableOperPreadmission) TickResult {
    const classified: Retryable = switch (reason) {
        .out_of_memory => .out_of_memory,
        .busy => .busy,
        .store_failure => .store_failure,
        .capacity => return fail(self, .capacity),
        .invalid_record => return fail(self, .invalid_clock_sample),
        .exhausted => return fail(self, .clock_overflow),
    };
    self.counters.retryable_ticks +|= 1;
    return .{ .retryable = classified };
}

fn tickInner(self: *Runtime, raw_realtime_ms: u64, monotonic_elapsed_ms: u64) TickResult {
    const inner = asImpl(self);
    switch (inner.mode) {
        .disabled => return .disabled,
        .failed => return .{ .failed = inner.failure },
        .observing => {},
    }
    if (inner.previous_security_now_ms == null and monotonic_elapsed_ms != 0)
        return fail(inner, .invalid_clock_sample);
    if (inner.last_monotonic_elapsed_ms) |previous| {
        if (monotonic_elapsed_ms < previous) return fail(inner, .monotonic_rollback);
    }
    const services = inner.services;

    const security_now_ms = switch (services.ensureDurableOperSecurityHorizon(
        raw_realtime_ms,
        monotonic_elapsed_ms,
    )) {
        .disabled => return fail(inner, .authority_disabled),
        .unavailable => return fail(inner, .authority_unavailable),
        .current => |horizon| horizon.effective_now_ms,
        .renewed => |horizon| horizon.effective_now_ms,
        .preadmission => |reason| return retry(inner, reason),
        .restart_required => |reason| return fail(inner, .{ .restart_required = reason }),
    };
    inner.last_monotonic_elapsed_ms = monotonic_elapsed_ms;

    const transaction_count = switch (services.copyDurableOperTransactions(&inner.transactions)) {
        .disabled => return fail(inner, .authority_disabled),
        .unavailable => return fail(inner, .authority_unavailable),
        .copied => |count| count,
        .preadmission => |reason| return switch (reason) {
            .out_of_memory, .busy, .store_failure => retry(inner, reason),
            .capacity => fail(inner, .capacity),
            .invalid_record, .exhausted => fail(inner, .inventory_invariant),
        },
        .restart_required => |reason| return fail(inner, .{ .restart_required = reason }),
    };
    if (transaction_count > max_records) return fail(inner, .inventory_invariant);

    const schedule_summary = switch (ocg2_reconcile_schedule.build(
        inner.transactions[0..transaction_count],
        security_now_ms,
        &inner.hints,
    )) {
        .complete => |complete| complete,
        .insufficient_output, .invalid => return fail(inner, .schedule_invariant),
    };

    const work_summary = switch (ocg2_reconcile_workset.build(
        inner.baseline[0..inner.baseline_count],
        inner.previous_security_now_ms,
        inner.hints[0..schedule_summary.count],
        security_now_ms,
        &inner.candidates,
        &inner.work,
    )) {
        .complete => |complete| complete,
        else => return fail(inner, .workset_invariant),
    };

    var active_count: usize = 0;
    var terminal_count: usize = 0;
    var first_failure: ?Failure = null;
    var inventory_changed = false;
    for (inner.work[0..work_summary.work_count]) |item| {
        inner.counters.work_inspected +|= 1;
        switch (classifyObservation(services.inspectDurableOperReconcileWork(item, security_now_ms))) {
            .accepted_active => active_count += 1,
            .accepted_other => {},
            .accepted_terminal => terminal_count += 1,
            .fatal_disabled => if (first_failure == null) {
                first_failure = .authority_disabled;
            },
            .fatal_unavailable => if (first_failure == null) {
                first_failure = .authority_unavailable;
            },
            .fatal_invariant => if (first_failure == null) {
                first_failure = .observation_invariant;
            },
            .retry_inventory => inventory_changed = true,
        }
    }
    if (first_failure) |reason| return fail(inner, reason);
    if (inventory_changed) {
        inner.counters.retryable_ticks +|= 1;
        return .{ .retryable = .inventory_changed };
    }

    @memcpy(inner.baseline[0..work_summary.candidate_count], inner.candidates[0..work_summary.candidate_count]);
    inner.baseline_count = work_summary.candidate_count;
    inner.previous_security_now_ms = security_now_ms;
    inner.counters.baseline_count = inner.baseline_count;
    inner.counters.ticks_completed +|= 1;
    inner.counters.last_security_now_ms = security_now_ms;
    inner.counters.last_candidate_count = work_summary.candidate_count;
    inner.counters.last_work_count = work_summary.work_count;
    inner.counters.last_active_count = active_count;
    inner.counters.last_terminal_count = terminal_count;
    inner.counters.earliest_transition_ms = work_summary.earliest_transition_ms;
    return .{ .complete = inner.counters };
}

fn rejectPointers(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("OCG2 runtime summaries must not expose pointers or slices"),
        .optional => |info| rejectPointers(info.child),
        .array => |info| rejectPointers(info.child),
        .@"struct" => |info| for (info.field_types) |field_type| rejectPointers(field_type),
        .@"union" => |info| for (info.field_types) |field_type| rejectPointers(field_type),
        else => {},
    }
}

comptime {
    if (max_records != 256) @compileError("OCG2 runtime bound is frozen at 256");
    switch (@typeInfo(Runtime)) {
        .@"opaque" => {},
        else => @compileError("Runtime must remain an opaque handle"),
    }
    rejectPointers(Retryable);
    rejectPointers(Failure);
    rejectPointers(Summary);
    rejectPointers(TickResult);

    const tick_info = @typeInfo(@TypeOf(Runtime.tick)).@"fn";
    if (tick_info.param_types.len != 3 or tick_info.param_types[1] != u64 or tick_info.param_types[2] != u64)
        @compileError("Runtime.tick has a fixed (self, realtime, monotonic elapsed) surface");
    for (tick_info.param_types) |param_type| {
        if (param_type == std.mem.Allocator) @compileError("Runtime.tick must remain allocation-free");
    }

    for (.{
        "apply", "execute", "grant",    "revoke",  "project",  "issuer",    "command",
        "mesh",  "event",   "callback", "session", "transmit", "allocator",
    }) |name| {
        if (@hasDecl(@This(), name) or @hasDecl(Runtime, name))
            @compileError("OCG2 observational runtime exposes a forbidden capability");
    }
}

const durable_oper_authority_boot = @import("durable_oper_authority_boot.zig");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const oper_cred_share = @import("../proto/oper_cred_share.zig");

const accepted_storage = store_mod.Config{
    .max_record_bytes = durable_oper_authority.max_store_payload_bytes,
    .max_wal_bytes = durable_oper_authority.max_store_wal_record_bytes,
};

fn testAuthority(seed: u8) !struct { std.crypto.sign.Ed25519.KeyPair, durable_oper_authority.Config } {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(seed)));
    const public_key = kp.public_key.toBytes();
    return .{ kp, .{
        .authority_node_id = node_short_id.shortId(node_identity.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    } };
}

fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !services_mod.OroStore {
    return services_mod.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, name, accepted_storage);
}

fn signGrant(
    kp: std.crypto.sign.Ed25519.KeyPair,
    authority: durable_oper_authority.Config,
    account: []const u8,
    issued_ms: u64,
    expiry_ms: u64,
    out: []u8,
) ![]const u8 {
    const len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = account,
        .revision = 1,
        .privilege_bits = @as(u64, 1) << 3,
        .class = "moderator",
        .title = "Observer test",
        .authority_node_id = authority.authority_node_id,
        .authority_pubkey = authority.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
    }, issued_ms, out);
    return out[0..len];
}

test "OCG2 runtime handle is opaque and private state is inaccessible" {
    try std.testing.expect(@typeInfo(Runtime) == .@"opaque");
    try std.testing.expect(!@hasDecl(Runtime, "services"));
    try std.testing.expect(!@hasDecl(Runtime, "Impl"));
    try std.testing.expect(!@hasDecl(Runtime, "allocator"));
    try std.testing.expect(!@hasDecl(Runtime, "initObserve"));
}

test "OCG2 runtime observe establishes an empty durable horizon" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0x61);
    var store = try openTestStore(tmp, "runtime-empty.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth[1]);
    defer state.deinit();
    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    const runtime = try createObserve(std.testing.allocator, &services);
    defer destroy(runtime);
    switch (runtime.tick(1_000, 0)) {
        .complete => |summary| {
            try std.testing.expectEqual(@as(usize, 0), summary.baseline_count);
            try std.testing.expectEqual(@as(usize, 0), summary.last_work_count);
            try std.testing.expectEqual(@as(?u64, 1_000), summary.last_security_now_ms);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(state.securityTimeAuthorized());
}

test "OCG2 runtime stable inventory produces no repeated work and temporal work is observed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0x62);
    var store = try openTestStore(tmp, "runtime-temporal.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth[1]);
    defer state.deinit();
    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    const runtime = try createObserve(std.testing.allocator, &services);
    defer destroy(runtime);
    _ = runtime.tick(1_000, 0);

    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const wire = try signGrant(auth[0], auth[1], "alice", 1_000, 2_000, &wire_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(wire, 1_000));
    const added = runtime.tick(1_000, 0);
    try std.testing.expectEqual(@as(usize, 1), added.complete.last_work_count);
    try std.testing.expectEqual(@as(usize, 1), added.complete.last_active_count);
    const stable = runtime.tick(1_500, 500);
    try std.testing.expectEqual(@as(usize, 0), stable.complete.last_work_count);
    const expired = runtime.tick(2_000, 1_000);
    try std.testing.expectEqual(@as(usize, 1), expired.complete.last_work_count);
    try std.testing.expectEqual(@as(usize, 1), expired.complete.last_terminal_count);
    try std.testing.expectEqual(@as(u64, 2), runtime.summary().work_inspected);
}

test "OCG2 runtime disabled and unavailable Services fail once and stay failed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "runtime-disabled.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    const disabled = try createObserve(std.testing.allocator, &services);
    defer destroy(disabled);
    try std.testing.expectEqual(Failure.authority_disabled, disabled.tick(0, 0).failed);
    try std.testing.expectEqual(Failure.authority_disabled, disabled.tick(1, 1).failed);

    const auth = try testAuthority(0x63);
    var live_store = try openTestStore(tmp, "runtime-unavailable.wal");
    defer live_store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &live_store, auth[1]);
    defer state.deinit();
    var live_services = Services.init(&live_store, null);
    try live_services.activateDurableOperAuthority(&state);
    const unavailable = try createObserve(std.testing.allocator, &live_services);
    defer destroy(unavailable);
    _ = unavailable.tick(1_000, 0);
    live_services.failClosedDurableOperAuthority();
    try std.testing.expectEqual(Failure.authority_unavailable, unavailable.tick(1_001, 1).failed);
    try std.testing.expectEqual(Failure.authority_unavailable, unavailable.tick(2_000, 1_000).failed);
}

test "OCG2 runtime monotonic rollback and overflow fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0x64);
    var store = try openTestStore(tmp, "runtime-clock.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth[1]);
    defer state.deinit();
    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    const runtime = try createObserve(std.testing.allocator, &services);
    defer destroy(runtime);
    _ = runtime.tick(1_000, 0);
    _ = runtime.tick(1_100, 100);
    try std.testing.expectEqual(Failure.monotonic_rollback, runtime.tick(1_200, 99).failed);
    var copies: [max_records]Services.DurableOperTransactionCopy = undefined;
    try std.testing.expectEqual(Services.DurableOperTransactionsResult.unavailable, services.copyDurableOperTransactions(&copies));

    const auth_overflow = try testAuthority(0x65);
    var overflow_store = try openTestStore(tmp, "runtime-overflow.wal");
    defer overflow_store.deinit();
    var overflow_state = try durable_oper_authority_boot.initialize(std.testing.allocator, &overflow_store, auth_overflow[1]);
    defer overflow_state.deinit();
    var overflow_services = Services.init(&overflow_store, null);
    try overflow_services.activateDurableOperAuthority(&overflow_state);
    const overflow = try createObserve(std.testing.allocator, &overflow_services);
    defer destroy(overflow);
    try std.testing.expectEqual(Failure.clock_overflow, overflow.tick(std.math.maxInt(u64), 0).failed);
}

test "OCG2 runtime integration rollback poisons its own Services image" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0x68);
    var store = try openTestStore(tmp, "runtime-integration-rollback.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth[1]);
    defer state.deinit();
    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    const runtime = try createObserve(std.testing.allocator, &services);
    defer destroy(runtime);
    _ = runtime.tick(1_000, 0);

    try std.testing.expectEqual(Failure.monotonic_rollback, runtime.failMonotonicRollback().failed);
    var copies: [max_records]Services.DurableOperTransactionCopy = undefined;
    try std.testing.expectEqual(
        Services.DurableOperTransactionsResult.unavailable,
        services.copyDurableOperTransactions(&copies),
    );
}

test "OCG2 runtime authority unavailable failure poisons a serving Services image" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0x69);
    var store = try openTestStore(tmp, "runtime-unavailable-poison.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth[1]);
    defer state.deinit();
    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    const runtime = try createObserve(std.testing.allocator, &services);
    defer destroy(runtime);
    try std.testing.expect(runtime.tick(1_000, 0) == .complete);

    try std.testing.expectEqual(Failure.authority_unavailable, fail(asImpl(runtime), .authority_unavailable).failed);
    var copies: [max_records]Services.DurableOperTransactionCopy = undefined;
    try std.testing.expectEqual(
        Services.DurableOperTransactionsResult.unavailable,
        services.copyDurableOperTransactions(&copies),
    );
}

test "OCG2 runtime retries first horizon preadmission without consuming zero elapsed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0x66);
    var store = try openTestStore(tmp, "runtime-first-retry.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth[1]);
    defer state.deinit();
    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    var held = try state.prepareSecurityTimeReservation(0, 1);
    const runtime = try createObserve(std.testing.allocator, &services);
    defer destroy(runtime);
    try std.testing.expectEqual(Retryable.busy, runtime.tick(1_000, 0).retryable);
    try std.testing.expectEqual(@as(?u64, null), runtime.summary().last_security_now_ms);
    held.update.abort();
    switch (runtime.tick(1_000, 0)) {
        .complete => {},
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2 runtime classifies a superseded inspect race as retryable" {
    try std.testing.expectEqual(ObservationClass.retry_inventory, classifyObservation(.superseded));
}

test "OCG2 runtime public surface forbids projection and mutation capabilities" {
    inline for (.{
        "Session", "Projection", "Issuer",  "Command", "Mesh",    "Event",    "Callback",
        "grant",   "revoke",     "project", "apply",   "execute", "transmit",
    }) |name| {
        try std.testing.expect(!@hasDecl(@This(), name));
        try std.testing.expect(!@hasDecl(Runtime, name));
    }
    const tick_info = @typeInfo(@TypeOf(Runtime.tick)).@"fn";
    inline for (tick_info.param_types) |param_type| try std.testing.expect(param_type != std.mem.Allocator);
    try std.testing.expectEqual(max_records, runtimeArrayLen(@TypeOf(@as(Impl, undefined).transactions)));
    try std.testing.expectEqual(max_records, runtimeArrayLen(@TypeOf(@as(Impl, undefined).baseline)));
}

fn runtimeArrayLen(comptime T: type) usize {
    return @typeInfo(T).array.len;
}

const ObservationClass = enum { accepted_active, accepted_other, accepted_terminal, retry_inventory, fatal_disabled, fatal_unavailable, fatal_invariant };

fn classifyObservation(observation: Services.DurableOperReconcileObservation) ObservationClass {
    return switch (observation) {
        .matched_active => .accepted_active,
        .matched_not_yet_valid => .accepted_other,
        .matched_expired, .matched_tombstone, .matched_equivocation => .accepted_terminal,
        .superseded => .retry_inventory,
        .disabled => .fatal_disabled,
        .authority_unavailable => .fatal_unavailable,
        .invalid_work => .fatal_invariant,
    };
}
