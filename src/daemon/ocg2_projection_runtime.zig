// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transactional OCG2 projection runtime.
//!
//! This leaf is intentionally narrower than the daemon's session and mesh
//! layers.  It turns the durable OCG2 observation image into a bounded,
//! by-value work queue.  A prepared queue is only made the next baseline by
//! `ack` after its caller has drained every item.  `abort` discards the queue
//! and leaves the previously acknowledged baseline untouched.
//!
//! There is no grant, mint, session, mesh, callback, or OCG1 surface here.
//! Configured-local authority is consequently left to the integrator's
//! precedence layer; every item emitted by this module is explicitly OCG2.

const std = @import("std");
const durable_oper_authority = @import("durable_oper_authority.zig");
const ocg2_reconcile_schedule = @import("ocg2_reconcile_schedule.zig");
const ocg2_reconcile_workset = @import("ocg2_reconcile_workset.zig");
const oper_session_provenance = @import("oper_session_provenance.zig");
const services_mod = @import("services.zig");

const Services = services_mod.Services;
const TransactionCopy = durable_oper_authority.TransactionCopy;
const BaselineEntry = ocg2_reconcile_workset.BaselineEntry;
const WorkItem = ocg2_reconcile_workset.WorkItem;
const ReinspectHint = ocg2_reconcile_schedule.ReinspectHint;
const Phase = ocg2_reconcile_schedule.Phase;
const Cause = ocg2_reconcile_workset.Cause;

pub const max_records: usize = durable_oper_authority.max_records;
pub const max_account_len: usize = durable_oper_authority.max_account_len;

/// Fatal reasons poison this runtime until it is explicitly destroyed.  A
/// terminal value is part of every result surface so the integrator cannot
/// mistake a failed authority image for an empty projection.
pub const Failure = union(enum) {
    authority_disabled,
    authority_unavailable,
    out_of_memory,
    store_failure,
    capacity,
    invariant,
    monotonic_rollback,
    clock_overflow,
    generation_exhausted,
    restart_required: Services.DurableOperRestartReason,
};

/// These are transient pre-admission conditions.  They never advance the
/// acknowledged baseline and do not poison the runtime.
pub const Retryable = enum {
    busy,
    inventory_changed,
};

/// An opaque generation/cursor pair.  The cursor is deliberately caller-owned
/// and checked against the runtime's cursor on every `next`; copied or stale
/// tickets therefore cannot silently skip or replay a different generation.
pub const Ticket = struct {
    generation: u64,
    cursor: usize = 0,
};

/// One OCG2 projection item.  All variable-length data is inline.  Terminal
/// authority is represented by `phase` (`expired`, `tombstone`, or
/// `equivocation`) with `active == false`; no borrowed durable-state slice can
/// escape the runtime.
pub const ProjectionItem = struct {
    account_buf: [max_account_len]u8 = @splat(0),
    account_len: usize = 0,
    cause: Cause = .inventory_added,
    phase: Phase = .expired,
    next_transition_ms: ?u64 = null,
    revision: u64 = 0,
    digest: [durable_oper_authority.digest_len]u8 = @splat(0),
    wire_sha256: [durable_oper_authority.digest_len]u8 = @splat(0),
    active: bool = false,
    privilege_bits: u64 = 0,
    class_buf: [oper_session_provenance.max_class_len]u8 = @splat(0),
    class_len: usize = 0,
    title_buf: [oper_session_provenance.max_title_len]u8 = @splat(0),
    title_len: usize = 0,
    authority_node_id: u64 = 0,
    authority_pubkey: [oper_session_provenance.authority_pubkey_len]u8 = @splat(0),
    issued_ms: u64 = 0,
    expiry_ms: u64 = 0,

    pub fn account(self: *const ProjectionItem) []const u8 {
        return self.account_buf[0..self.account_len];
    }

    pub fn className(self: *const ProjectionItem) []const u8 {
        return self.class_buf[0..self.class_len];
    }

    pub fn titleText(self: *const ProjectionItem) []const u8 {
        return self.title_buf[0..self.title_len];
    }
};

/// Synchronous account inspection at the latest security-clock sample.  The
/// active payload is the existing copied Services value; all other states are
/// empty and therefore cannot carry stale grant metadata.
pub const AccountInspection = union(enum) {
    unavailable,
    absent,
    not_yet_valid,
    expired,
    tombstone,
    equivocation,
    active: Services.DurableOperGrantCopy,
    terminal: Failure,
};

pub const PrepareResult = union(enum) {
    ready: Ticket,
    busy,
    retryable: Retryable,
    terminal: Failure,
};

pub const NextResult = union(enum) {
    item: ProjectionItem,
    done,
    stale,
    terminal: Failure,
};

pub const AckResult = union(enum) {
    committed,
    stale,
    not_drained,
    terminal: Failure,
};

pub const AbortResult = union(enum) {
    aborted,
    stale,
    terminal: Failure,
};

pub const Summary = struct {
    terminal: bool = false,
    failure: ?Failure = null,
    generation: u64 = 0,
    baseline_count: usize = 0,
    pending_count: usize = 0,
    cursor: usize = 0,
    last_security_now_ms: ?u64 = null,
    acknowledged_security_now_ms: ?u64 = null,
};

const Mode = enum { ready, terminal };

/// Publicly opaque heap-owned runtime.  `initDefault` and `deinit` are the
/// only lifetime operations; callers never receive the Services pointer or
/// any of the fixed scratch arrays.
pub const Runtime = opaque {
    pub fn initDefault(allocator: std.mem.Allocator, services: *Services) !*Runtime {
        return create(allocator, services);
    }

    pub fn deinit(self: *Runtime) void {
        destroy(self);
    }

    pub fn prepare(
        self: *Runtime,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) PrepareResult {
        return prepareInner(self, raw_realtime_ms, monotonic_elapsed_ms);
    }

    pub fn next(self: *Runtime, ticket: *Ticket) NextResult {
        return nextInner(self, ticket);
    }

    pub fn ack(self: *Runtime, ticket: Ticket) AckResult {
        return ackInner(self, ticket);
    }

    pub fn abort(self: *Runtime, ticket: Ticket) AbortResult {
        return abortInner(self, ticket);
    }

    pub fn inspectAccount(self: *Runtime, account: []const u8) AccountInspection {
        return inspectAccountInner(self, account);
    }

    pub fn summary(self: *const Runtime) Summary {
        return asImplConst(self).summary();
    }
};

const Impl = struct {
    allocator: std.mem.Allocator,
    services: *Services,
    mode: Mode = .ready,
    failure: ?Failure = null,
    generation: u64 = 0,
    active_generation: ?u64 = null,
    active_cursor: usize = 0,
    item_count: usize = 0,
    candidate_count: usize = 0,
    security_now_ms: ?u64 = null,
    acknowledged_security_now_ms: ?u64 = null,
    last_monotonic_elapsed_ms: ?u64 = null,
    baseline_count: usize = 0,
    baseline: [max_records]BaselineEntry = undefined,
    candidates: [max_records]BaselineEntry = undefined,
    transactions: [max_records]TransactionCopy = undefined,
    hints: [max_records]ReinspectHint = undefined,
    work: [max_records]WorkItem = undefined,
    items: [max_records]ProjectionItem = undefined,

    fn summary(self: *const Impl) Summary {
        return .{
            .terminal = self.mode == .terminal,
            .failure = self.failure,
            .generation = self.generation,
            .baseline_count = self.baseline_count,
            .pending_count = if (self.active_generation != null) self.item_count else 0,
            .cursor = if (self.active_generation != null) self.active_cursor else 0,
            .last_security_now_ms = self.security_now_ms,
            .acknowledged_security_now_ms = self.acknowledged_security_now_ms,
        };
    }
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

fn create(allocator: std.mem.Allocator, services: *Services) !*Runtime {
    const inner = try allocator.create(Impl);
    inner.* = .{ .allocator = allocator, .services = services };
    return asHandle(inner);
}

fn destroy(self: *Runtime) void {
    const inner = asImpl(self);
    const allocator = inner.allocator;
    inner.* = undefined;
    allocator.destroy(inner);
}

fn terminal(inner: *Impl, reason: Failure) Failure {
    inner.mode = .terminal;
    inner.failure = reason;
    inner.active_generation = null;
    inner.active_cursor = 0;
    inner.item_count = 0;
    inner.candidate_count = 0;
    return reason;
}

fn preadmissionFailure(reason: Services.DurableOperPreadmission) Failure {
    return switch (reason) {
        .out_of_memory => .out_of_memory,
        .capacity => .capacity,
        .store_failure => .store_failure,
        .invalid_record => .invariant,
        .exhausted => .clock_overflow,
        .busy => .store_failure,
    };
}

fn prepareInner(self: *Runtime, raw_realtime_ms: u64, monotonic_elapsed_ms: u64) PrepareResult {
    const inner = asImpl(self);
    if (inner.mode == .terminal) return .{ .terminal = inner.failure.? };
    if (inner.active_generation != null) return .busy;

    if (inner.last_monotonic_elapsed_ms) |previous| {
        if (monotonic_elapsed_ms < previous)
            return .{ .terminal = terminal(inner, .monotonic_rollback) };
    }

    const security_now_ms = switch (inner.services.ensureDurableOperSecurityHorizon(
        raw_realtime_ms,
        monotonic_elapsed_ms,
    )) {
        .disabled => return .{ .terminal = terminal(inner, .authority_disabled) },
        .unavailable => return .{ .terminal = terminal(inner, .authority_unavailable) },
        .current => |horizon| horizon.effective_now_ms,
        .renewed => |horizon| horizon.effective_now_ms,
        .preadmission => |reason| switch (reason) {
            .busy => return .{ .retryable = .busy },
            else => return .{ .terminal = terminal(inner, preadmissionFailure(reason)) },
        },
        .restart_required => |reason| return .{ .terminal = terminal(inner, .{ .restart_required = reason }) },
    };
    inner.last_monotonic_elapsed_ms = monotonic_elapsed_ms;
    inner.security_now_ms = security_now_ms;

    const transaction_count = switch (inner.services.copyDurableOperTransactions(&inner.transactions)) {
        .disabled => return .{ .terminal = terminal(inner, .authority_disabled) },
        .unavailable => return .{ .terminal = terminal(inner, .authority_unavailable) },
        .copied => |count| count,
        .preadmission => |reason| switch (reason) {
            .busy => return .{ .retryable = .busy },
            else => return .{ .terminal = terminal(inner, preadmissionFailure(reason)) },
        },
        .restart_required => |reason| return .{ .terminal = terminal(inner, .{ .restart_required = reason }) },
    };
    if (transaction_count > max_records)
        return .{ .terminal = terminal(inner, .capacity) };

    const schedule_summary = switch (ocg2_reconcile_schedule.build(
        inner.transactions[0..transaction_count],
        security_now_ms,
        &inner.hints,
    )) {
        .complete => |value| value,
        .insufficient_output, .invalid => return .{ .terminal = terminal(inner, .invariant) },
    };
    if (schedule_summary.count > max_records)
        return .{ .terminal = terminal(inner, .capacity) };

    const work_summary = switch (ocg2_reconcile_workset.build(
        inner.baseline[0..inner.baseline_count],
        inner.acknowledged_security_now_ms,
        inner.hints[0..schedule_summary.count],
        security_now_ms,
        &inner.candidates,
        &inner.work,
    )) {
        .complete => |value| value,
        .security_time_rollback => return .{ .terminal = terminal(inner, .monotonic_rollback) },
        .insufficient_candidate_output, .insufficient_work_output => return .{ .terminal = terminal(inner, .capacity) },
        else => return .{ .terminal = terminal(inner, .invariant) },
    };
    if (work_summary.candidate_count > max_records or work_summary.work_count > max_records)
        return .{ .terminal = terminal(inner, .capacity) };

    var item_count: usize = 0;
    for (inner.work[0..work_summary.work_count]) |work_item| {
        const observation = inner.services.inspectDurableOperReconcileWork(work_item, security_now_ms);
        switch (observation) {
            .disabled => return .{ .terminal = terminal(inner, .authority_disabled) },
            .authority_unavailable => return .{ .terminal = terminal(inner, .authority_unavailable) },
            .invalid_work => return .{ .terminal = terminal(inner, .invariant) },
            .superseded => return .{ .retryable = .inventory_changed },
            .matched_not_yet_valid => {
                inner.items[item_count] = itemFromExpected(work_item, .not_yet_valid);
                item_count += 1;
            },
            .matched_expired => {
                inner.items[item_count] = itemFromExpected(work_item, .expired);
                item_count += 1;
            },
            .matched_tombstone => {
                inner.items[item_count] = itemFromExpected(work_item, .tombstone);
                item_count += 1;
            },
            .matched_equivocation => {
                inner.items[item_count] = itemFromExpected(work_item, .equivocation);
                item_count += 1;
            },
            .matched_active => |grant| {
                inner.items[item_count] = itemFromGrant(work_item, grant);
                item_count += 1;
            },
        }
    }

    const next_generation = std.math.add(u64, inner.generation, 1) catch
        return .{ .terminal = terminal(inner, .generation_exhausted) };
    if (next_generation == 0)
        return .{ .terminal = terminal(inner, .generation_exhausted) };
    inner.generation = next_generation;
    inner.active_generation = next_generation;
    inner.active_cursor = 0;
    inner.item_count = item_count;
    inner.candidate_count = work_summary.candidate_count;
    return .{ .ready = .{ .generation = next_generation } };
}

fn itemFromExpected(work_item: WorkItem, phase: Phase) ProjectionItem {
    var item = ProjectionItem{
        .account_len = work_item.expected.account_len,
        .cause = work_item.cause,
        .phase = phase,
        .next_transition_ms = work_item.expected.next_transition_ms,
        .revision = work_item.expected.revision,
        .digest = work_item.expected.digest,
        .wire_sha256 = work_item.expected.wire_sha256,
    };
    @memcpy(item.account_buf[0..item.account_len], work_item.expected.account_buf[0..item.account_len]);
    return item;
}

fn itemFromGrant(work_item: WorkItem, grant: Services.DurableOperGrantCopy) ProjectionItem {
    var item = ProjectionItem{
        .account_len = grant.account_len,
        .cause = work_item.cause,
        .phase = .active,
        .next_transition_ms = grant.expiry_ms,
        .revision = grant.revision,
        .digest = grant.digest,
        .wire_sha256 = grant.wire_sha256,
        .active = true,
        .privilege_bits = grant.privilege_bits,
        .class_len = grant.class_len,
        .title_len = grant.title_len,
        .authority_node_id = grant.authority_node_id,
        .authority_pubkey = grant.authority_pubkey,
        .issued_ms = grant.issued_ms,
        .expiry_ms = grant.expiry_ms,
    };
    @memcpy(item.account_buf[0..item.account_len], grant.account_buf[0..grant.account_len]);
    @memcpy(item.class_buf[0..item.class_len], grant.class_buf[0..grant.class_len]);
    @memcpy(item.title_buf[0..item.title_len], grant.title_buf[0..grant.title_len]);
    return item;
}

fn ticketMatches(inner: *const Impl, ticket: Ticket) bool {
    return inner.active_generation != null and
        inner.active_generation.? == ticket.generation and
        ticket.cursor == inner.active_cursor;
}

fn nextInner(self: *Runtime, ticket: *Ticket) NextResult {
    const inner = asImpl(self);
    if (inner.mode == .terminal) return .{ .terminal = inner.failure.? };
    if (!ticketMatches(inner, ticket.*)) return .stale;
    if (inner.active_cursor == inner.item_count) return .done;
    const item = inner.items[inner.active_cursor];
    inner.active_cursor += 1;
    ticket.cursor += 1;
    return .{ .item = item };
}

fn ackInner(self: *Runtime, ticket: Ticket) AckResult {
    const inner = asImpl(self);
    if (inner.mode == .terminal) return .{ .terminal = inner.failure.? };
    if (!ticketMatches(inner, ticket)) return .stale;
    if (inner.active_cursor != inner.item_count) return .not_drained;
    @memcpy(inner.baseline[0..inner.candidate_count], inner.candidates[0..inner.candidate_count]);
    inner.baseline_count = inner.candidate_count;
    inner.acknowledged_security_now_ms = inner.security_now_ms;
    inner.active_generation = null;
    inner.active_cursor = 0;
    inner.item_count = 0;
    inner.candidate_count = 0;
    return .committed;
}

fn abortInner(self: *Runtime, ticket: Ticket) AbortResult {
    const inner = asImpl(self);
    if (inner.mode == .terminal) return .{ .terminal = inner.failure.? };
    if (!ticketMatches(inner, ticket)) return .stale;
    inner.active_generation = null;
    inner.active_cursor = 0;
    inner.item_count = 0;
    inner.candidate_count = 0;
    return .aborted;
}

fn inspectAccountInner(self: *Runtime, account: []const u8) AccountInspection {
    const inner = asImpl(self);
    if (inner.mode == .terminal) return .{ .terminal = inner.failure.? };
    const now_ms = inner.security_now_ms orelse return .unavailable;
    return switch (inner.services.inspectDurableOperAuthority(account, now_ms)) {
        .disabled, .unavailable => .unavailable,
        .absent => .absent,
        .not_yet_valid => .not_yet_valid,
        .expired => .expired,
        .tombstone => .tombstone,
        .equivocation => .equivocation,
        .active => |grant| .{ .active = grant },
    };
}

fn rejectPointers(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("OCG2 projection public values must not hold pointers or slices"),
        .optional => |info| {
            rejectPointers(info.child);
        },
        .array => |info| {
            rejectPointers(info.child);
        },
        .@"struct" => |info| {
            for (info.field_types) |field_type| rejectPointers(field_type);
        },
        .@"union" => |info| {
            for (info.field_types) |field_type| rejectPointers(field_type);
        },
        else => {},
    }
}

comptime {
    if (max_records != 256) @compileError("OCG2 projection bound is frozen at 256");
    if (@typeInfo(Runtime) != .@"opaque") @compileError("projection Runtime must remain opaque");
    for (.{ Ticket, ProjectionItem, AccountInspection, PrepareResult, NextResult, AckResult, AbortResult, Summary, Failure, Retryable }) |T|
        rejectPointers(T);
    for (.{
        "callback",          "session",        "mesh",              "issuer", "mint", "grant", "revoke", "transmit",
        "executeAuthorized", "ProjectionData", "DurableOperLookup", "Store",
    }) |name| {
        if (@hasDecl(@This(), name) or @hasDecl(Runtime, name))
            @compileError("OCG2 projection runtime exposes a forbidden capability");
    }
}

// ───────────────────────────── focused tests ──────────────────────────────

const accepted_storage = @import("store.zig").Config{
    .max_record_bytes = durable_oper_authority.max_store_payload_bytes,
    .max_wal_bytes = durable_oper_authority.max_store_wal_record_bytes,
};
const durable_oper_authority_boot = @import("durable_oper_authority_boot.zig");
const node_identity = @import("node_identity.zig");
const node_short_id = @import("../crypto/node_short_id.zig");
const oper_cred_share = @import("../proto/oper_cred_share.zig");

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

const TestSetup = struct {
    store: services_mod.OroStore,
    state: durable_oper_authority.State,
};

fn setupServices(
    tmp: std.testing.TmpDir,
    name: []const u8,
    auth: durable_oper_authority.Config,
) !TestSetup {
    var store = try openTestStore(tmp, name);
    errdefer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth);
    errdefer state.deinit();
    return .{ .store = store, .state = state };
}

fn makeServices(setup: *TestSetup) !Services {
    var services = Services.init(&setup.store, null);
    try services.activateDurableOperAuthority(&setup.state);
    return services;
}

fn signGrant(
    kp: std.crypto.sign.Ed25519.KeyPair,
    auth: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    title: []const u8,
    issued_ms: u64,
    expiry_ms: u64,
    out: []u8,
) ![]const u8 {
    const len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = account,
        .revision = revision,
        .privilege_bits = @as(u64, 1) << 3,
        .class = "moderator",
        .title = title,
        .authority_node_id = auth.authority_node_id,
        .authority_pubkey = auth.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
    }, issued_ms, out);
    return out[0..len];
}

fn signTombstone(
    kp: std.crypto.sign.Ed25519.KeyPair,
    auth: durable_oper_authority.Config,
    account: []const u8,
    revision: u64,
    issued_ms: u64,
    out: []u8,
) ![]const u8 {
    const len = try oper_cred_share.signOcg2(kp, .{
        .kind = .tombstone,
        .account = account,
        .revision = revision,
        .privilege_bits = 0,
        .class = "",
        .title = "",
        .authority_node_id = auth.authority_node_id,
        .authority_pubkey = auth.authority_pubkey,
        .issued_ms = issued_ms,
        .expiry_ms = 0,
    }, issued_ms, out);
    return out[0..len];
}

fn prepareAndAck(runtime: *Runtime, raw_ms: u64, elapsed_ms: u64) !void {
    const prepared = runtime.prepare(raw_ms, elapsed_ms);
    const ticket = switch (prepared) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var cursor = ticket;
    while (true) switch (runtime.next(&cursor)) {
        .item => {},
        .done => break,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(AckResult.committed, runtime.ack(cursor));
}

test "OCG2 projection runtime default construction and public values are bounded" {
    try std.testing.expectEqual(@as(usize, 256), max_records);
    try std.testing.expect(@typeInfo(Runtime) == .@"opaque");
    try std.testing.expect(@sizeOf(Ticket) >= @sizeOf(u64));
    try std.testing.expect(!@hasDecl(Runtime, "services"));
    try std.testing.expect(!@hasDecl(Runtime, "Impl"));
    try std.testing.expect(!@hasDecl(Runtime, "callback"));
    try std.testing.expect(!@hasDecl(Runtime, "session"));
    try std.testing.expect(!@hasDecl(Runtime, "mesh"));
}

test "OCG2 projection runtime initial inventory is unacked until drained and acknowledged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA1);
    var live = try setupServices(tmp, "projection-initial.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();
    try prepareAndAck(runtime, 1_000, 0);

    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const wire = try signGrant(auth[0], auth[1], "alice", 1, "Initial", 1_000, 2_000, &wire_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(wire, 1_000));

    const prepared = runtime.prepare(1_000, 0);
    var ticket = switch (prepared) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), runtime.summary().pending_count);
    try std.testing.expectEqual(AckResult.not_drained, runtime.ack(ticket));
    const item = switch (runtime.next(&ticket)) {
        .item => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("alice", item.account());
    try std.testing.expectEqual(Phase.active, item.phase);
    try std.testing.expect(item.active);
    try std.testing.expectEqualStrings("Initial", item.titleText());
    try std.testing.expectEqual(NextResult.done, runtime.next(&ticket));
    try std.testing.expectEqual(AckResult.committed, runtime.ack(ticket));
    try std.testing.expectEqual(@as(usize, 1), runtime.summary().baseline_count);
    try std.testing.expectEqual(@as(usize, 0), runtime.summary().pending_count);
}

test "OCG2 projection runtime abort retains baseline and retry emits by-value item" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA2);
    var live = try setupServices(tmp, "projection-abort.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();
    try prepareAndAck(runtime, 1_000, 0);

    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const wire = try signGrant(auth[0], auth[1], "alice", 1, "Retry", 1_000, 2_000, &wire_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(wire, 1_000));
    var ticket = switch (runtime.prepare(1_000, 0)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    const stale_cursor = ticket;
    const first = switch (runtime.next(&ticket)) {
        .item => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(AbortResult.stale, runtime.abort(stale_cursor));
    try std.testing.expectEqual(AbortResult.aborted, runtime.abort(ticket));
    try std.testing.expectEqual(@as(usize, 0), runtime.summary().baseline_count);
    try std.testing.expectEqual(NextResult.stale, runtime.next(&ticket));

    var retry = switch (runtime.prepare(1_000, 0)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    const second = switch (runtime.next(&retry)) {
        .item => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings(first.account(), second.account());
    try std.testing.expectEqualSlices(u8, &first.digest, &second.digest);
    try std.testing.expectEqual(NextResult.done, runtime.next(&retry));
    try std.testing.expectEqual(AckResult.committed, runtime.ack(retry));
}

test "OCG2 projection runtime handles zero, one, and the frozen 256-record inventory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA8);
    var live = try setupServices(tmp, "projection-capacity.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();

    // Zero inventory still yields a real ticket and an acknowledged empty
    // baseline; it must not be confused with disabled authority.
    try prepareAndAck(runtime, 1_000, 0);

    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    var account_buf: [max_account_len]u8 = undefined;
    const first_account = try std.fmt.bufPrint(&account_buf, "a{d:0>3}", .{0});
    const first_wire = try signGrant(auth[0], auth[1], first_account, 1, "Bulk", 1_000, 2_000, &wire_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(first_wire, 1_000));

    var one_ticket = switch (runtime.prepare(1_000, 0)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var one_count: usize = 0;
    while (true) switch (runtime.next(&one_ticket)) {
        .item => |item| {
            try std.testing.expectEqual(Phase.active, item.phase);
            one_count += 1;
        },
        .done => break,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(@as(usize, 1), one_count);
    try std.testing.expectEqual(AckResult.committed, runtime.ack(one_ticket));

    for (1..max_records) |index| {
        const account = try std.fmt.bufPrint(&account_buf, "a{d:0>3}", .{index});
        const wire = try signGrant(auth[0], auth[1], account, 1, "Bulk", 1_000, 2_000, &wire_buf);
        try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(wire, 1_000));
    }

    var ticket = switch (runtime.prepare(1_000, 0)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var count: usize = 0;
    while (true) switch (runtime.next(&ticket)) {
        .item => |item| {
            try std.testing.expectEqual(Phase.active, item.phase);
            count += 1;
        },
        .done => break,
        else => return error.TestUnexpectedResult,
    };
    // The first record was already acknowledged above, so this generation
    // carries the remaining 255 inventory additions while the resulting
    // acknowledged baseline reaches the full frozen capacity.
    try std.testing.expectEqual(max_records - 1, count);
    try std.testing.expectEqual(AckResult.committed, runtime.ack(ticket));
    try std.testing.expectEqual(max_records, runtime.summary().baseline_count);
}

test "OCG2 projection runtime busy and stale generations cannot mutate baseline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA3);
    var live = try setupServices(tmp, "projection-ticket.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();

    var ticket = switch (runtime.prepare(1_000, 0)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(PrepareResult.busy, runtime.prepare(1_001, 1));
    try std.testing.expectEqual(AbortResult.aborted, runtime.abort(ticket));
    try std.testing.expectEqual(AckResult.stale, runtime.ack(ticket));
    try std.testing.expectEqual(AbortResult.stale, runtime.abort(ticket));
    const replacement = switch (runtime.prepare(1_001, 1)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(replacement.generation > ticket.generation);
    try std.testing.expectEqual(NextResult.stale, runtime.next(&ticket));
    var current = replacement;
    try std.testing.expectEqual(NextResult.done, runtime.next(&current));
    try std.testing.expectEqual(AckResult.committed, runtime.ack(current));
}

test "OCG2 projection runtime busy retry preserves the acknowledged baseline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA9);
    var live = try setupServices(tmp, "projection-retry-busy.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();

    // Hold the underlying durable reservation so Services reports a real
    // pre-admission busy condition.  The runtime must not poison itself or
    // mutate its empty acknowledged baseline while that mutation is held.
    var held = try live.state.prepareSecurityTimeReservation(0, 1);
    switch (runtime.prepare(1_000, 0)) {
        .retryable => |reason| try std.testing.expectEqual(Retryable.busy, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!runtime.summary().terminal);
    try std.testing.expectEqual(@as(usize, 0), runtime.summary().baseline_count);
    held.update.abort();
    try prepareAndAck(runtime, 1_000, 0);
    try std.testing.expectEqual(@as(usize, 0), runtime.summary().baseline_count);
}

test "OCG2 projection runtime fail-closed mappings cover invariant generation and clock overflow" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xAA);

    var invariant_live = try setupServices(tmp, "projection-invariant.wal", auth[1]);
    defer invariant_live.store.deinit();
    defer invariant_live.state.deinit();
    var invariant_services = try makeServices(&invariant_live);
    const invariant_runtime = try Runtime.initDefault(std.testing.allocator, &invariant_services);
    defer invariant_runtime.deinit();
    const invariant_impl = asImpl(invariant_runtime);
    invariant_impl.baseline_count = 1;
    invariant_impl.baseline[0] = .{};
    switch (invariant_runtime.prepare(1_000, 0)) {
        .terminal => |reason| try std.testing.expectEqual(Failure.invariant, reason),
        else => return error.TestUnexpectedResult,
    }

    var generation_live = try setupServices(tmp, "projection-generation.wal", auth[1]);
    defer generation_live.store.deinit();
    defer generation_live.state.deinit();
    var generation_services = try makeServices(&generation_live);
    const generation_runtime = try Runtime.initDefault(std.testing.allocator, &generation_services);
    defer generation_runtime.deinit();
    asImpl(generation_runtime).generation = std.math.maxInt(u64);
    switch (generation_runtime.prepare(1_000, 0)) {
        .terminal => |reason| try std.testing.expectEqual(Failure.generation_exhausted, reason),
        else => return error.TestUnexpectedResult,
    }

    var overflow_live = try setupServices(tmp, "projection-clock-overflow.wal", auth[1]);
    defer overflow_live.store.deinit();
    defer overflow_live.state.deinit();
    var overflow_services = try makeServices(&overflow_live);
    const overflow_runtime = try Runtime.initDefault(std.testing.allocator, &overflow_services);
    defer overflow_runtime.deinit();
    switch (overflow_runtime.prepare(std.math.maxInt(u64), 0)) {
        .terminal => |reason| try std.testing.expectEqual(Failure.clock_overflow, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2 projection runtime retryable and store/restart mapping taxonomy is explicit" {
    try std.testing.expectEqual(Failure.out_of_memory, preadmissionFailure(.out_of_memory));
    try std.testing.expectEqual(Failure.store_failure, preadmissionFailure(.store_failure));
    try std.testing.expectEqual(Failure.capacity, preadmissionFailure(.capacity));
    try std.testing.expectEqual(Failure.invariant, preadmissionFailure(.invalid_record));
    try std.testing.expectEqual(Failure.clock_overflow, preadmissionFailure(.exhausted));

    // Services' post-copy race hook is intentionally private to services.zig;
    // this leaf has no callback seam.  A deterministic direct runtime trigger
    // for `.retryable.inventory_changed` would therefore broaden the public
    // interface.  Keep the result constructor and tag covered here while the
    // production branch remains driven by Services' superseded observation.
    const inventory_retry: PrepareResult = .{ .retryable = .inventory_changed };
    switch (inventory_retry) {
        .retryable => |reason| try std.testing.expectEqual(Retryable.inventory_changed, reason),
        else => return error.TestUnexpectedResult,
    }
    const busy_retry: PrepareResult = .{ .retryable = .busy };
    switch (busy_retry) {
        .retryable => |reason| try std.testing.expectEqual(Retryable.busy, reason),
        else => return error.TestUnexpectedResult,
    }
    const restart: Failure = .{ .restart_required = .ambiguous_store };
    const restart_result: PrepareResult = .{ .terminal = restart };
    switch (restart_result) {
        .terminal => |reason| switch (reason) {
            .restart_required => |kind| try std.testing.expectEqual(Services.DurableOperRestartReason.ambiguous_store, kind),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2 projection runtime terminal phases and synchronous inspection share security clock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA4);
    var live = try setupServices(tmp, "projection-phases.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();
    try prepareAndAck(runtime, 1_000, 0);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signGrant(auth[0], auth[1], "alice", 1, "Active", 1_000, 2_000, &alice_buf);
    var bob_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob = try signTombstone(auth[0], auth[1], "bob", 1, 1_000, &bob_buf);
    var carol_initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const carol_initial = try signGrant(auth[0], auth[1], "carol", 1, "One", 1_000, 2_000, &carol_initial_buf);
    var carol_conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const carol_conflict = try signGrant(auth[0], auth[1], "carol", 1, "Conflict", 1_000, 2_000, &carol_conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(bob, 1_000));
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(carol_initial, 1_000));
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(carol_conflict, 1_000));

    var ticket = switch (runtime.prepare(1_000, 0)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var saw_active = false;
    var saw_tombstone = false;
    var saw_equivocation = false;
    while (true) switch (runtime.next(&ticket)) {
        .item => |item| switch (item.phase) {
            .active => saw_active = true,
            .tombstone => saw_tombstone = true,
            .equivocation => saw_equivocation = true,
            else => {},
        },
        .done => break,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(saw_active and saw_tombstone and saw_equivocation);
    try std.testing.expectEqual(AckResult.committed, runtime.ack(ticket));
    switch (runtime.inspectAccount("alice")) {
        .active => |grant| try std.testing.expectEqualStrings("Active", grant.title()),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(AccountInspection.tombstone, runtime.inspectAccount("bob"));
    try std.testing.expectEqual(AccountInspection.equivocation, runtime.inspectAccount("carol"));

    var expiry = switch (runtime.prepare(2_000, 1_000)) {
        .ready => |value| value,
        else => return error.TestUnexpectedResult,
    };
    var saw_expired = false;
    while (true) switch (runtime.next(&expiry)) {
        .item => |item| if (std.mem.eql(u8, item.account(), "alice")) {
            try std.testing.expectEqual(Phase.expired, item.phase);
            try std.testing.expect(!item.active);
            saw_expired = true;
        },
        .done => break,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expect(saw_expired);
    try std.testing.expectEqual(AckResult.committed, runtime.ack(expiry));
    try std.testing.expectEqual(AccountInspection.expired, runtime.inspectAccount("alice"));
}

test "OCG2 projection runtime store unavailability is terminal and representable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA5);
    var live = try setupServices(tmp, "projection-unavailable.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();
    try prepareAndAck(runtime, 1_000, 0);
    services.failClosedDurableOperAuthority();
    switch (runtime.prepare(1_001, 1)) {
        .terminal => |reason| try std.testing.expectEqual(Failure.authority_unavailable, reason),
        else => return error.TestUnexpectedResult,
    }
    switch (runtime.inspectAccount("alice")) {
        .terminal => |reason| try std.testing.expectEqual(Failure.authority_unavailable, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(runtime.summary().terminal);
    switch (runtime.prepare(1_002, 2)) {
        .terminal => {},
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2 projection runtime monotonic rollback and first-sample clock rules fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA6);
    var live = try setupServices(tmp, "projection-clock.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    const runtime = try Runtime.initDefault(std.testing.allocator, &services);
    defer runtime.deinit();
    switch (runtime.prepare(1_000, 1)) {
        .terminal => {},
        else => return error.TestUnexpectedResult,
    }

    var live2 = try setupServices(tmp, "projection-clock-rollback.wal", auth[1]);
    defer live2.store.deinit();
    defer live2.state.deinit();
    var services2 = try makeServices(&live2);
    const runtime2 = try Runtime.initDefault(std.testing.allocator, &services2);
    defer runtime2.deinit();
    try prepareAndAck(runtime2, 1_000, 0);
    try prepareAndAck(runtime2, 1_100, 100);
    switch (runtime2.prepare(1_200, 99)) {
        .terminal => |reason| try std.testing.expectEqual(Failure.monotonic_rollback, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2 projection runtime construction reports allocator OOM before authority use" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const auth = try testAuthority(0xA7);
    var live = try setupServices(tmp, "projection-oom.wal", auth[1]);
    defer live.store.deinit();
    defer live.state.deinit();
    var services = try makeServices(&live);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Runtime.initDefault(failing.allocator(), &services));
}
