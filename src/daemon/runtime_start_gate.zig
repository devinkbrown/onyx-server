// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One candidate's shared, one-shot startup barrier. Owns every spawned thread
//! handle through its Control; borrowed Views cannot release, cancel or join.
//! Workers cannot invoke their real owner until releaseAll publishes the
//! complete runtime. This primitive supplies synchronization, not service-owner
//! authentication: main must join its actual configured owner inventory.
//!
//! All coordinator operations are serialized by one owning thread. Only the
//! generated Runner touches arrival/decision atomics concurrently. Owner contexts,
//! Io, allocators, the Gate and borrowed Slots must remain live until all workers
//! join. Release does not request shutdown: running owners supply their own stop
//! flags/wakes before join. No worker is detached.

const std = @import("std");
const builtin = @import("builtin");

/// Stable local inventory identities. A wire schema must version and map these
/// explicitly; extending this enum does not extend an existing capsule schema.
pub const Kind = enum(u8) {
    reactor,
    rdns,
    dnsbl,
    mail,
    acme,
    ocsp,
    webpush,
    metrics,
    webhook,
    history,
    native_media,
    media_plane,
    webtransport,
    native_service,
    geo = 14,
};

/// Canonical ascending (kind, instance), unique even if owner pointers differ.
/// Zero thread rows are legal; the inline reactor is main's separate owner row.
pub const ParticipantSpec = struct {
    kind: Kind,
    instance: u16,
    owner_identity: *const anyopaque,
    options: std.Thread.SpawnConfig = .{},
};
pub const Slot = struct { view: *const View, identity: u64, index: u32 };
pub const Phase = enum { preparing, released, canceled };
pub const Status = struct {
    phase: Phase,
    expected: usize,
    spawned: usize,
    arrived: usize,
    joined: usize,
};
pub const SlotStatus = struct {
    kind: Kind,
    instance: u16,
    spawned: bool,
    arrived: bool,
    joined: bool,
};
pub const Error = std.mem.Allocator.Error || std.Thread.SpawnError || error{
    NonCanonicalSpecs,
    TooManyParticipants,
    CounterExhausted,
    InvalidSlot,
    InvalidGate,
    NotJoined,
    InvalidOptions,
    InvalidDeadline,
    AlreadySpawned,
    NotPreparing,
    NotReleased,
    Incomplete,
    Timeout,
    Canceled,
};

const Decision = enum(u8) { pending, release, cancel };
const Record = struct {
    spec: ParticipantSpec,
    thread: ?std.Thread = null,
    arrived: std.atomic.Value(bool) = .init(false),
    completed: std.atomic.Value(bool) = .init(false),
    completed_event: std.Io.Event = .unset,
    spawned: bool = false,
    joined: bool = false,
};
const TestControls = if (builtin.is_test) struct {
    fail_at: ?usize = null,
    attempts: usize = 0,
    hold_index: ?usize = null,
    entry_held: std.Io.Event = .unset,
    allow_arrival: std.Io.Event = .unset,
} else void;
const ControlRecord = struct { marker: u8 = 0 };
const ViewRecord = struct { marker: u8 = 0 };
const Backing = struct {
    control: ControlRecord = .{},
    view: ViewRecord = .{},
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: u64,
    records: []Record,
    spawned: usize = 0,
    joined: usize = 0,
    arrived: std.atomic.Value(usize) = .init(0),
    decision: std.atomic.Value(Decision) = .init(.pending),
    arrived_event: std.Io.Event = .unset,
    decision_event: std.Io.Event = .unset,
    fixture: TestControls = if (builtin.is_test) .{} else {},
};
var next_identity: std.atomic.Value(u64) = .init(1);

fn issueIdentity() Error!u64 {
    var old = next_identity.load(.monotonic);
    while (true) {
        if (old == std.math.maxInt(u64)) return error.CounterExhausted;
        if (next_identity.cmpxchgWeak(old, old + 1, .monotonic, .monotonic)) |actual| {
            old = actual;
        } else return old;
    }
}
fn owned(self: *Control) *Backing {
    const inner: *ControlRecord = @ptrCast(self);
    return @alignCast(@fieldParentPtr("control", inner));
}
fn backing(self: *const View) *const Backing {
    const inner: *const ViewRecord = @ptrCast(self);
    return @alignCast(@fieldParentPtr("view", inner));
}

fn before(a: ParticipantSpec, b: ParticipantSpec) bool {
    return @intFromEnum(a.kind) < @intFromEnum(b.kind) or
        (a.kind == b.kind and a.instance < b.instance);
}
fn optionsEqual(a: std.Thread.SpawnConfig, b: std.Thread.SpawnConfig) bool {
    if (a.stack_size != b.stack_size) return false;
    if (a.allocator) |aa| {
        const bb = b.allocator orelse return false;
        return aa.ptr == bb.ptr and aa.vtable == bb.vtable;
    }
    return b.allocator == null;
}
fn record(self: *const View, token: Slot) Error!*const Record {
    const b = backing(self);
    if (token.view != self or token.identity != b.identity or token.index >= b.records.len)
        return error.InvalidSlot;
    return &b.records[token.index];
}
fn ownedRecord(self: *Control, token: Slot) Error!*Record {
    _ = try record(self.view(), token);
    return &owned(self).records[token.index];
}

fn decisionPhase(value: Decision) Phase {
    return switch (value) {
        .pending => .preparing,
        .release => .released,
        .cancel => .canceled,
    };
}

pub const Created = struct { control: *Control, view: *const View };

pub fn create(allocator: std.mem.Allocator, io: std.Io, specs: []const ParticipantSpec) Error!Created {
    if (specs.len > std.math.maxInt(u32)) return error.TooManyParticipants;
    for (specs, 0..) |spec, i| {
        if (i != 0 and !before(specs[i - 1], spec)) return error.NonCanonicalSpecs;
    }
    const identity = try issueIdentity(); // Burned even if allocation fails.
    const b = try allocator.create(Backing);
    errdefer allocator.destroy(b);
    const records = try allocator.alloc(Record, specs.len);
    errdefer allocator.free(records);
    for (records, specs) |*r, spec| r.* = .{ .spec = spec };
    b.* = .{ .allocator = allocator, .io = io, .identity = identity, .records = records };
    return .{ .control = @ptrCast(&b.control), .view = @ptrCast(&b.view) };
}

/// Read-only coordinator observations; no destructive operation or owner getter.
/// Calls remain serialized with coordinator operations. Worker bodies use their
/// source-owned entry/exit atomics, not these non-atomic handle observations.
pub const View = opaque {
    /// Worker-side observation of the one-shot decision only. Unlike inspect,
    /// this does not read creator-owned spawn/join accounting during shutdown.
    pub fn requireReleased(self: *const View) Error!void {
        switch (backing(self).decision.load(.acquire)) {
            .release => {},
            .pending => return error.NotReleased,
            .cancel => return error.Canceled,
        }
    }
    pub fn slot(self: *const View, kind: Kind, instance: u16, owner_identity: *const anyopaque) Error!Slot {
        const b = backing(self);
        const key: ParticipantSpec = .{ .kind = kind, .instance = instance, .owner_identity = owner_identity };
        var lo: usize = 0;
        var hi = b.records.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (before(b.records[mid].spec, key)) lo = mid + 1 else hi = mid;
        }
        if (lo == b.records.len) return error.InvalidSlot;
        const spec = b.records[lo].spec;
        if (spec.kind != kind or spec.instance != instance or spec.owner_identity != owner_identity)
            return error.InvalidSlot;
        return .{ .view = self, .identity = b.identity, .index = @intCast(lo) };
    }

    pub fn inspect(self: *const View) Status {
        const b = backing(self);
        return .{ .phase = decisionPhase(b.decision.load(.acquire)), .expected = b.records.len, .spawned = b.spawned, .arrived = b.arrived.load(.acquire), .joined = b.joined };
    }

    pub fn inspectSlot(self: *const View, token: Slot) Error!SlotStatus {
        const r = try record(self, token);
        return .{ .kind = r.spec.kind, .instance = r.spec.instance, .spawned = r.spawned, .arrived = r.arrived.load(.acquire), .joined = r.joined };
    }

    /// Validate a source owner's demanded registration without returning its
    /// pointer or allocator. The caller supplies its already-owned identity.
    pub fn requireSlot(self: *const View, token: Slot, kind: Kind, instance: u16, expected_owner: *const anyopaque, demanded_options: std.Thread.SpawnConfig) Error!void {
        const r = try record(self, token);
        if (r.spec.kind != kind or r.spec.instance != instance or r.spec.owner_identity != expected_owner)
            return error.InvalidSlot;
        if (!optionsEqual(r.spec.options, demanded_options)) return error.InvalidOptions;
    }

    pub fn requireSlotParked(self: *const View, token: Slot) Error!void {
        const r = try record(self, token);
        if (backing(self).decision.load(.acquire) != .pending) return error.NotPreparing;
        if (!r.spawned or !r.arrived.load(.acquire) or r.joined) return error.Incomplete;
    }

    pub fn requireAllParked(self: *const View) Error!void {
        const b = backing(self);
        if (b.decision.load(.acquire) != .pending) return error.NotPreparing;
        if (b.spawned != b.records.len or b.arrived.load(.acquire) != b.records.len or b.joined != 0)
            return error.Incomplete;
    }

    /// A canceled row that never acquired a handle is safe to detach too.
    pub fn requireSlotJoined(self: *const View, token: Slot) Error!void {
        const r = try record(self, token);
        const decision = backing(self).decision.load(.acquire);
        if (decision == .pending) return error.NotJoined;
        if (!r.spawned) {
            if (decision != .cancel) return error.NotJoined;
        } else if (!r.joined) return error.NotJoined;
    }

    pub fn requireAllJoined(self: *const View) Error!void {
        const b = backing(self);
        if (b.decision.load(.acquire) == .pending or b.joined != b.spawned)
            return error.NotJoined;
    }
};

/// Exclusive coordinator authority returned only by create, never by a View.
pub const Control = opaque {
    pub fn view(self: *Control) *const View {
        return @ptrCast(&owned(self).view);
    }
    /// Compare our known address before inspecting any foreign supplied view.
    pub fn requireView(self: *Control, borrowed: *const View) Error!void {
        if (borrowed != self.view()) return error.InvalidGate;
    }

    pub fn spawn(self: *Control, token: Slot, comptime Context: type, ctx: Context, comptime workerFn: fn (Context) void, options: std.Thread.SpawnConfig) Error!void {
        const b = owned(self);
        const r = try ownedRecord(self, token);
        if (b.decision.load(.acquire) != .pending) return error.NotPreparing;
        if (r.spawned) return error.AlreadySpawned;
        if (!optionsEqual(r.spec.options, options)) return error.InvalidOptions;
        const Runner = struct {
            fn entry(g: *const View, index: u32, c: Context) void {
                const owner = @constCast(backing(g));
                const row = &owner.records[index];
                defer {
                    row.completed.store(true, .release);
                    row.completed_event.set(owner.io);
                }
                if (builtin.is_test) {
                    if (owner.fixture.hold_index == index) {
                        owner.fixture.entry_held.set(owner.io);
                        owner.fixture.allow_arrival.waitUncancelable(owner.io);
                    }
                }
                if (row.arrived.swap(true, .acq_rel)) @panic("duplicate startup arrival");
                const arrived = owner.arrived.fetchAdd(1, .acq_rel) + 1;
                if (arrived == owner.records.len) owner.arrived_event.set(owner.io);
                owner.decision_event.waitUncancelable(owner.io);
                switch (owner.decision.load(.acquire)) {
                    .release => workerFn(c),
                    .cancel => {},
                    .pending => unreachable,
                }
            }
        };
        errdefer self.cancelAllAndJoin();
        if (builtin.is_test) {
            const attempt = b.fixture.attempts;
            b.fixture.attempts += 1;
            if (b.fixture.fail_at == attempt) return error.SystemResources;
        }
        // The child can arrive before spawn returns. It touches only immutable
        // spec storage and atomics, never the not-yet-stored thread handle.
        r.thread = try std.Thread.spawn(r.spec.options, Runner.entry, .{ self.view(), token.index, ctx });
        r.spawned = true;
        b.spawned += 1;
    }

    /// One finite absolute awake-clock deadline. Wait failure leaves the
    /// candidate owned; cancel/join must precede freeing any borrowed context.
    pub fn awaitAllParked(self: *Control, deadline: std.Io.Clock.Timestamp) Error!void {
        const b = owned(self);
        if (deadline.clock != .awake) return error.InvalidDeadline;
        if (b.decision.load(.acquire) != .pending) return error.NotPreparing;
        if (b.spawned != b.records.len) return error.Incomplete;
        while (true) {
            if (b.arrived.load(.acquire) == b.records.len) return self.view().requireAllParked();
            if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(b.io, .awake), .gte, deadline))
                return error.Timeout;
            b.arrived_event.waitTimeout(b.io, .{ .deadline = deadline }) catch |err| switch (err) {
                error.Timeout => continue,
                error.Canceled => return error.Canceled,
            };
        }
    }

    /// The sole no-fail release, after every prepared owner has been published.
    pub fn releaseAll(self: *Control) void {
        self.view().requireAllParked() catch @panic("release requires complete parked runtime");
        const b = owned(self);
        b.decision.store(.release, .release);
        b.decision_event.set(b.io);
    }

    pub fn cancelAllAndJoin(self: *Control) void {
        const b = owned(self);
        if (b.decision.load(.acquire) == .release) @panic("cannot cancel released runtime");
        b.decision.store(.cancel, .release);
        if (builtin.is_test) b.fixture.allow_arrival.set(b.io);
        b.decision_event.set(b.io);
        self.joinAll();
    }

    fn joinSlot(self: *Control, token: Slot) void {
        const r = ownedRecord(self, token) catch @panic("invalid startup join slot");
        const b = owned(self);
        if (b.decision.load(.acquire) == .pending) @panic("join requires release or cancel");
        if (!r.spawned or r.joined) return;
        r.thread.?.join();
        r.thread = null;
        r.joined = true;
        b.joined += 1;
    }

    /// Join one original owner without waiting for still-running consumers.
    /// The creator serializes this operation with all other Control methods.
    /// Source shutdown must precede this call; it neither stops nor detaches
    /// the participant. Foreign/stale slots and an undecided gate are rejected
    /// before any handle or accounting is changed.
    pub fn joinParticipant(self: *Control, token: Slot) Error!void {
        _ = try ownedRecord(self, token);
        if (owned(self).decision.load(.acquire) == .pending) return error.NotReleased;
        self.joinSlot(token);
    }

    /// Wait for the original wrapper to return before joining its thread.
    /// A timeout retains its handle and borrowed owner; no detach or teardown
    /// is permitted until a later actual join succeeds. The final OS thread
    /// join follows wrapper completion, never unfinished network/source work.
    pub fn joinParticipantUntil(self: *Control, token: Slot, deadline: std.Io.Clock.Timestamp) Error!void {
        const r = try ownedRecord(self, token);
        const b = owned(self);
        if (deadline.clock != .awake) return error.InvalidDeadline;
        if (b.decision.load(.acquire) == .pending) return error.NotReleased;
        if (!r.spawned or r.joined) return;
        while (!r.completed.load(.acquire)) {
            if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(b.io, .awake), .gte, deadline)) return error.Timeout;
            r.completed_event.waitTimeout(b.io, .{ .deadline = deadline }) catch |err| switch (err) {
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Canceled,
            };
        }
        self.joinSlot(token);
    }

    pub fn joinAllUntil(self: *Control, deadline: std.Io.Clock.Timestamp) Error!void {
        const b = owned(self);
        if (deadline.clock != .awake) return error.InvalidDeadline;
        if (b.decision.load(.acquire) == .pending) return error.NotReleased;
        for (b.records, 0..) |_, i| try self.joinParticipantUntil(.{ .view = self.view(), .identity = b.identity, .index = @intCast(i) }, deadline);
    }

    pub fn joinAll(self: *Control) void {
        const b = owned(self);
        if (b.decision.load(.acquire) == .pending) @panic("join requires release or cancel");
        for (b.records, 0..) |_, i| self.joinSlot(.{ .view = self.view(), .identity = b.identity, .index = @intCast(i) });
    }

    /// Caller has already canceled, or stopped every running source and joined.
    /// This method never implicitly cancels or joins borrowed owner contexts.
    pub fn destroyJoined(self: *Control) void {
        self.view().requireAllJoined() catch @panic("destroy requires joined startup handles");
        const b = owned(self);
        const allocator = b.allocator;
        allocator.free(b.records);
        allocator.destroy(b);
    }
};

/// No production failure/arrival injection surface. Must configure before spawn.
pub const Fixture = if (builtin.is_test) struct {
    pub fn failSpawn(g: *Control, attempt: usize) void {
        const b = owned(g);
        std.debug.assert(b.spawned == 0 and b.fixture.attempts == 0);
        b.fixture.fail_at = attempt;
    }
    pub fn holdArrival(g: *Control, slot_token: Slot) Error!void {
        const b = owned(g);
        _ = try record(g.view(), slot_token);
        if (b.spawned != 0 or b.fixture.attempts != 0) return error.AlreadySpawned;
        b.fixture.hold_index = slot_token.index;
    }
    pub fn awaitHeld(g: *Control, deadline: std.Io.Clock.Timestamp) Error!void {
        const b = owned(g);
        while (!b.fixture.entry_held.isSet()) {
            if (std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(b.io, .awake), .gte, deadline)) return error.Timeout;
            b.fixture.entry_held.waitTimeout(b.io, .{ .deadline = deadline }) catch |e| switch (e) {
                error.Timeout => continue,
                error.Canceled => return error.Canceled,
            };
        }
    }
    pub fn allowArrival(g: *Control) void {
        const b = owned(g);
        b.fixture.allow_arrival.set(b.io);
    }
} else struct {};

const testing = std.testing;
fn finishTest(g: Created) void {
    if (g.view.inspect().phase == .preparing) g.control.cancelAllAndJoin() else g.control.joinAll();
    g.control.destroyJoined();
}
fn afterMs(ms: i64) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.fromNow(testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(ms) });
}
const Actor = struct {
    calls: std.atomic.Value(usize) = .init(0),
    saw_published: std.atomic.Value(bool) = .init(false),
    published: usize = 0,
    fn run(a: *@This()) void {
        a.saw_published.store(a.published == 731, .release);
        _ = a.calls.fetchAdd(1, .release);
    }
};

test "shared release publishes all owners before actual reactor and companion bodies" {
    var a: Actor = .{};
    var b: Actor = .{};
    const specs = [_]ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &a },
        .{ .kind = .metrics, .instance = 0, .owner_identity = &b },
    };
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    const sa = try g.view.slot(.reactor, 0, &a);
    const sb = try g.view.slot(.metrics, 0, &b);
    try g.control.spawn(sa, *Actor, &a, Actor.run, .{});
    try g.control.spawn(sb, *Actor, &b, Actor.run, .{});
    try g.control.awaitAllParked(afterMs(5000));
    try testing.expectEqual(@as(usize, 0), a.calls.load(.acquire));
    try testing.expectEqual(@as(usize, 0), b.calls.load(.acquire));
    a.published = 731;
    b.published = 731;
    g.control.releaseAll();
    g.control.joinAll();
    g.control.joinAll();
    g.control.joinAll(); // One actual handle owner, even through repeated joins.
    try testing.expectEqual(@as(usize, 2), g.view.inspect().joined);
    try testing.expectEqual(@as(usize, 1), a.calls.load(.acquire));
    try testing.expectEqual(@as(usize, 1), b.calls.load(.acquire));
    try testing.expect(a.saw_published.load(.acquire) and b.saw_published.load(.acquire));
    try testing.expectError(error.NotPreparing, g.view.requireAllParked());
}

test "selective join retires producer while original consumer remains live" {
    const Consumer = struct {
        io: std.Io,
        entered: std.Io.Event = .unset,
        stop: std.Io.Event = .unset,
        exited: std.atomic.Value(bool) = .init(false),
        timed_out: std.atomic.Value(bool) = .init(false),
        fn run(self: *@This()) void {
            self.entered.set(self.io);
            // A broken selective join must fail rather than wait forever on
            // the very consumer that this test requires it to leave running.
            self.stop.waitTimeout(self.io, .{ .deadline = afterMs(5000) }) catch {
                self.timed_out.store(true, .release);
            };
            self.exited.store(true, .release);
        }
    };
    var consumer: Consumer = .{ .io = testing.io };
    var producer: Actor = .{};
    const specs = [_]ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &consumer },
        .{ .kind = .webhook, .instance = 0, .owner_identity = &producer },
    };
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    // Unblock before the gate cleanup even if an intermediate assertion fails.
    defer consumer.stop.set(testing.io);
    const sc = try g.view.slot(.reactor, 0, &consumer);
    const sp = try g.view.slot(.webhook, 0, &producer);
    const foreign = try create(testing.allocator, testing.io, &specs);
    defer finishTest(foreign);
    const foreign_slot = try foreign.view.slot(.webhook, 0, &producer);
    try testing.expectError(error.InvalidSlot, g.control.joinParticipant(foreign_slot));
    foreign.control.cancelAllAndJoin();
    try testing.expectError(error.Canceled, foreign.view.requireReleased());
    try testing.expectError(error.NotReleased, g.control.joinParticipant(sp));
    try testing.expectError(error.NotReleased, g.view.requireReleased());
    try testing.expectEqual(@as(usize, 0), g.view.inspect().joined);
    try g.control.spawn(sc, *Consumer, &consumer, Consumer.run, .{});
    try g.control.spawn(sp, *Actor, &producer, Actor.run, .{});
    try g.control.awaitAllParked(afterMs(5000));
    g.control.releaseAll();
    try g.view.requireReleased();
    try consumer.entered.waitTimeout(testing.io, .{ .deadline = afterMs(5000) });
    try g.control.joinParticipant(sp);
    try g.control.joinParticipant(sp);
    try g.view.requireSlotJoined(sp);
    try testing.expectEqual(@as(usize, 1), producer.calls.load(.acquire));
    try testing.expectEqual(@as(usize, 1), g.view.inspect().joined);
    try testing.expect(!(try g.view.inspectSlot(sc)).joined);
    try testing.expect(!consumer.exited.load(.acquire));
    try testing.expect(!consumer.timed_out.load(.acquire));
    // The real consumer is still blocked. A deadline failure must retain its
    // original handle and permit the same owned slot to join after release.
    try testing.expectError(error.Timeout, g.control.joinParticipantUntil(sc, afterMs(0)));
    try testing.expectError(error.NotJoined, g.view.requireSlotJoined(sc));
    try testing.expectEqual(@as(usize, 1), g.view.inspect().joined);
    consumer.stop.set(testing.io);
    try g.control.joinParticipantUntil(sc, afterMs(5000));
    try g.control.joinAllUntil(afterMs(5000));
    try g.view.requireAllJoined();
    try testing.expect(consumer.exited.load(.acquire));
    try testing.expect(!consumer.timed_out.load(.acquire));
    try testing.expectEqual(@as(usize, 2), g.view.inspect().joined);
}

test "GEO appends after every existing kind and exact canonical owner is required" {
    const original = [_]Kind{ .reactor, .rdns, .dnsbl, .mail, .acme, .ocsp, .webpush, .metrics, .webhook, .history, .native_media, .media_plane, .webtransport, .native_service };
    for (original, 0..) |kind, value| try testing.expectEqual(@as(u8, @intCast(value)), @intFromEnum(kind));
    try testing.expectEqual(@as(u8, 14), @intFromEnum(Kind.geo));
    var owner: Actor = .{};
    var foreign: Actor = .{};
    const specs = [_]ParticipantSpec{
        .{ .kind = .native_service, .instance = 0, .owner_identity = &owner },
        .{ .kind = .geo, .instance = 0, .owner_identity = &owner },
    };
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    const slot = try g.view.slot(.geo, 0, &owner);
    try testing.expectEqual(@as(u32, 1), slot.index);
    const status = try g.view.inspectSlot(slot);
    try testing.expectEqual(Kind.geo, status.kind);
    try g.view.requireSlot(slot, .geo, 0, &owner, .{});
    try testing.expectError(error.InvalidSlot, g.view.requireSlot(slot, .geo, 0, &foreign, .{}));
    try testing.expectError(error.InvalidSlot, g.view.requireSlot(slot, .native_service, 0, &owner, .{}));
    try testing.expectError(error.InvalidSlot, g.view.requireSlot(slot, .geo, 1, &owner, .{}));
    try testing.expectError(error.InvalidOptions, g.view.requireSlot(slot, .geo, 0, &owner, .{ .stack_size = 2 * 1024 * 1024 }));
    try testing.expectError(error.InvalidSlot, g.view.slot(.geo, 0, &foreign));
    try testing.expectError(error.InvalidSlot, g.view.slot(.geo, 1, &owner));
    try testing.expectError(error.Incomplete, g.view.requireSlotParked(slot));
    var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const reversed = [_]ParticipantSpec{ specs[1], specs[0] };
    try testing.expectError(error.NonCanonicalSpecs, create(fail.allocator(), testing.io, &reversed));
    const duplicate = [_]ParticipantSpec{ specs[1], .{ .kind = .geo, .instance = 0, .owner_identity = &foreign } };
    try testing.expectError(error.NonCanonicalSpecs, create(fail.allocator(), testing.io, &duplicate));
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
}

test "actual GEO worker remains parked until shared release and cancels without invocation" {
    for ([_]bool{ false, true }) |release| {
        var service: Actor = .{};
        var geo: Actor = .{};
        const specs = [_]ParticipantSpec{
            .{ .kind = .native_service, .instance = 0, .owner_identity = &service },
            .{ .kind = .geo, .instance = 0, .owner_identity = &geo },
        };
        const g = try create(testing.allocator, testing.io, &specs);
        defer finishTest(g);
        const service_slot = try g.view.slot(.native_service, 0, &service);
        const geo_slot = try g.view.slot(.geo, 0, &geo);
        try g.control.spawn(service_slot, *Actor, &service, Actor.run, .{});
        try g.control.spawn(geo_slot, *Actor, &geo, Actor.run, .{});
        try g.control.awaitAllParked(afterMs(5000));
        try g.view.requireSlotParked(geo_slot);
        try testing.expectEqual(@as(usize, 0), geo.calls.load(.acquire));
        try testing.expectEqual(@as(usize, 0), service.calls.load(.acquire));
        service.published = 731;
        geo.published = 731;
        if (release) g.control.releaseAll() else g.control.cancelAllAndJoin();
        g.control.joinAll();
        const expected: usize = if (release) 1 else 0;
        try testing.expectEqual(expected, geo.calls.load(.acquire));
        try testing.expectEqual(expected, service.calls.load(.acquire));
        try testing.expectEqual(release, geo.saw_published.load(.acquire));
        try testing.expectEqual(@as(usize, 2), g.view.inspect().joined);
    }
}

test "one late real worker prevents all-owner readiness and cancellation wakes it" {
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &a }};
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    const s = try g.view.slot(.mail, 0, &a);
    try Fixture.holdArrival(g.control, s);
    try g.control.spawn(s, *Actor, &a, Actor.run, .{});
    try Fixture.awaitHeld(g.control, afterMs(5000));
    try testing.expectError(error.Incomplete, g.view.requireAllParked());
    try testing.expectError(error.Timeout, g.control.awaitAllParked(afterMs(5)));
    g.control.cancelAllAndJoin();
    g.control.cancelAllAndJoin();
    try testing.expectEqual(@as(usize, 1), g.view.inspect().joined);
    try testing.expectEqual(@as(usize, 0), a.calls.load(.acquire));
    try testing.expectError(error.NotPreparing, g.view.requireAllParked());
}

test "kth injected spawn failure joins earlier real threads without invoking any body" {
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &a },
        .{ .kind = .reactor, .instance = 1, .owner_identity = &a },
        .{ .kind = .webhook, .instance = 0, .owner_identity = &a },
    };
    for (0..specs.len) |fail_at| {
        const g = try create(testing.allocator, testing.io, &specs);
        defer finishTest(g);
        Fixture.failSpawn(g.control, fail_at);
        for (specs, 0..) |spec, i| {
            const s = try g.view.slot(spec.kind, spec.instance, &a);
            if (i == fail_at) {
                try testing.expectError(error.SystemResources, g.control.spawn(s, *Actor, &a, Actor.run, .{}));
                break;
            }
            try g.control.spawn(s, *Actor, &a, Actor.run, .{});
        }
        try testing.expectEqual(Phase.canceled, g.view.inspect().phase);
        try testing.expectEqual(fail_at, g.view.inspect().spawned);
        try testing.expectEqual(fail_at, g.view.inspect().joined);
        try testing.expectEqual(@as(usize, 0), a.calls.load(.acquire));
    }
}

test "slots bind live gate identity canonical owner and exact spawn options" {
    var a: Actor = .{};
    var other: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .ocsp, .instance = 4, .owner_identity = &a }};
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    const g2 = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g2);
    const s = try g.view.slot(.ocsp, 4, &a);
    try testing.expectError(error.InvalidSlot, g.view.slot(.ocsp, 4, &other));
    try testing.expectError(error.InvalidSlot, g.view.slot(.ocsp, 5, &a));
    try testing.expectError(error.InvalidSlot, g2.view.inspectSlot(s));
    var bad = s;
    bad.identity += 1;
    try testing.expectError(error.InvalidSlot, g.view.inspectSlot(bad));
    bad = s;
    bad.index += 1;
    try testing.expectError(error.InvalidSlot, g.view.inspectSlot(bad));
    try testing.expectError(error.InvalidOptions, g.control.spawn(s, *Actor, &a, Actor.run, .{ .stack_size = 2 * 1024 * 1024 }));
    try testing.expectEqual(@as(usize, 0), g.view.inspect().spawned);
    try g.control.spawn(s, *Actor, &a, Actor.run, .{});
    try testing.expectError(error.AlreadySpawned, g.control.spawn(s, *Actor, &a, Actor.run, .{}));
    try g.control.awaitAllParked(afterMs(5000));
    g.control.cancelAllAndJoin();
    try testing.expectEqual(@as(usize, 0), a.calls.load(.acquire));
}

fn oomCreate(allocator: std.mem.Allocator) !void {
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .reactor, .instance = 0, .owner_identity = &a }};
    const g = try create(allocator, testing.io, &specs);
    defer finishTest(g);
    try testing.expectEqual(@as(usize, 0), g.view.inspect().spawned);
    try testing.expectError(error.Incomplete, g.view.requireAllParked());
}
test "both actual metadata allocations unwind at every failure index and retry" {
    try testing.checkAllAllocationFailures(testing.allocator, oomCreate, .{});
    try oomCreate(testing.allocator);
}

test "canonical invalid input refuses before backend and empty inline gate is explicit" {
    var a: Actor = .{};
    var fail = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const duplicate = [_]ParticipantSpec{
        .{ .kind = .reactor, .instance = 0, .owner_identity = &a },
        .{ .kind = .reactor, .instance = 0, .owner_identity = &a },
    };
    try testing.expectError(error.NonCanonicalSpecs, create(fail.allocator(), testing.io, &duplicate));
    try testing.expectEqual(@as(usize, 0), fail.alloc_index);
    const g = try create(testing.allocator, testing.io, &.{});
    defer finishTest(g);
    try g.control.awaitAllParked(afterMs(0));
    try testing.expectError(error.InvalidDeadline, g.control.awaitAllParked(.{ .clock = .real, .raw = .zero }));
    g.control.releaseAll();
    g.control.joinAll();
    try testing.expectEqual(@as(usize, 0), g.view.inspect().joined);
}

test "last identity cleanup cannot wrap and address reuse rejects old slot" {
    var arena: [16384]u8 align(@alignOf(Backing)) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena);
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .reactor, .instance = 0, .owner_identity = &a }};
    const g = try create(fba.allocator(), testing.io, &specs);
    const old_slot = try g.view.slot(.reactor, 0, &a);
    finishTest(g);
    fba.reset();
    const next = try create(fba.allocator(), testing.io, &specs);
    defer finishTest(next);
    try testing.expectEqual(@intFromPtr(g.view), @intFromPtr(next.view));
    try testing.expectError(error.InvalidSlot, next.view.inspectSlot(old_slot));
    const saved = next_identity.swap(std.math.maxInt(u64) - 1, .monotonic);
    defer next_identity.store(saved, .monotonic);
    const last = try create(testing.allocator, testing.io, &specs);
    defer finishTest(last);
    try testing.expectError(error.CounterExhausted, create(testing.allocator, testing.io, &specs));
    last.control.cancelAllAndJoin();
}

test "distinct opaque control and view share only the original two metadata allocations" {
    try testing.expect(@typeInfo(Control) == .@"opaque");
    try testing.expect(@typeInfo(View) == .@"opaque");
    inline for (.{ "spawn", "releaseAll", "cancelAllAndJoin", "joinParticipant", "joinParticipantUntil", "joinAll", "joinAllUntil", "destroyJoined", "control", "backing" }) |name|
        try testing.expect(!@hasDecl(View, name));
    try testing.expect(!@hasField(SlotStatus, "owner_identity"));
    try testing.expect(!@hasField(SlotStatus, "options"));
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .reactor, .instance = 0, .owner_identity = &a }};
    var allocations = testing.FailingAllocator.init(testing.allocator, .{});
    const g = try create(allocations.allocator(), testing.io, &specs);
    defer finishTest(g);
    try testing.expectEqual(@as(usize, 2), allocations.alloc_index);
    try testing.expectEqual(@sizeOf(Backing) + @sizeOf(Record), allocations.allocated_bytes);
    try testing.expect(@intFromPtr(g.control) != @intFromPtr(g.view));
    try testing.expect(g.control.view() == g.view);
    try g.control.requireView(g.view);
    try testing.expectError(error.NotJoined, g.view.requireAllJoined());
}

test "another actual control cannot use this view or slot and cannot cancel its workers" {
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &a }};
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    const foreign = try create(testing.allocator, testing.io, &specs);
    defer finishTest(foreign);
    const slot = try g.view.slot(.mail, 0, &a);
    try testing.expectError(error.InvalidGate, foreign.control.requireView(g.view));
    try testing.expectError(error.InvalidSlot, foreign.control.spawn(slot, *Actor, &a, Actor.run, .{}));
    try testing.expectEqual(@as(usize, 0), foreign.view.inspect().spawned);
    try testing.expectEqual(@as(usize, 0), g.view.inspect().spawned);
    try g.control.spawn(slot, *Actor, &a, Actor.run, .{});
    try g.control.awaitAllParked(afterMs(5000));
    foreign.control.cancelAllAndJoin();
    try g.view.requireSlotParked(slot);
    try testing.expectEqual(@as(usize, 0), a.calls.load(.acquire));
    a.published = 731;
    g.control.releaseAll();
    // Actual source exit is not a kernel handle join or detach authorization.
    try testing.expectError(error.NotJoined, g.view.requireSlotJoined(slot));
    g.control.joinAll();
    try g.view.requireSlotJoined(slot);
    try g.view.requireAllJoined();
    try testing.expectEqual(@as(usize, 1), a.calls.load(.acquire));
}

test "canceled unspawned rows detach without inventing thread arrivals or joins" {
    var a: Actor = .{};
    const specs = [_]ParticipantSpec{.{ .kind = .geo, .instance = 0, .owner_identity = &a }};
    const g = try create(testing.allocator, testing.io, &specs);
    defer finishTest(g);
    const slot = try g.view.slot(.geo, 0, &a);
    try testing.expectError(error.NotJoined, g.view.requireSlotJoined(slot));
    g.control.cancelAllAndJoin();
    try g.view.requireSlotJoined(slot);
    try g.view.requireAllJoined();
    const status = try g.view.inspectSlot(slot);
    try testing.expect(!status.spawned and !status.arrived and !status.joined);
    const totals = g.view.inspect();
    try testing.expectEqual(@as(usize, 0), totals.spawned);
    try testing.expectEqual(@as(usize, 0), totals.arrived);
    try testing.expectEqual(@as(usize, 0), totals.joined);
    try testing.expectEqual(@as(usize, 0), a.calls.load(.acquire));
}

test {
    testing.refAllDecls(@This());
}
