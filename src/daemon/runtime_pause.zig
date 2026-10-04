// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reusable retained-worker pause at a complete-operation boundary. Stable
//! owner/Io lifetime is required through the final worker join. No thread handle
//! is stored here. A pause is not a proof that the owner's producers are frozen.
//! The whole runtime stops producers before it captures the parked owner.
const std = @import("std");
pub const start_gate = @import("runtime_start_gate.zig");

pub const Error = error{ InvalidToken, InvalidEpoch, Busy, IoMismatch, NotPaused, NotPrepared, InvalidDeadline, Timeout, Canceled };
pub const Token = struct { owner: *Pause, epoch: u64 };

pub const Pause = struct {
    mutex: std.atomic.Mutex = .unlocked,
    io: ?std.Io = null,
    request_epoch: u64 = 0,
    parked_epoch: u64 = 0,
    departed_epoch: u64 = 0,
    decision: enum { resumed, pending } = .resumed,
    waiters: usize = 0,
    signalers: usize = 0,
    arrival: std.Io.Event = .unset,
    release: std.Io.Event = .unset,

    /// Before a worker escapes; never replace a live Io/backend.
    pub fn bindIo(self: *Pause, io: std.Io) Error!void {
        lock(&self.mutex);
        defer self.mutex.unlock();
        if (self.io != null or self.request_epoch != 0) return error.Busy;
        self.io = io;
    }

    /// Source-owner cold preparation before any worker escapes. A configured
    /// constructor may already have selected this exact Io. Confirmation and
    /// first binding share one lock; used pause state can never be reset here.
    /// The enclosing owner separately refuses existing/previous workers.
    pub fn prepareIo(self: *Pause, io: std.Io) Error!void {
        lock(&self.mutex);
        defer self.mutex.unlock();
        if (self.request_epoch != 0 or self.parked_epoch != 0 or self.departed_epoch != 0 or
            self.decision != .resumed or self.waiters != 0 or self.signalers != 0) return error.Busy;
        if (self.io) |selected| {
            if (selected.userdata != io.userdata or selected.vtable != io.vtable) return error.IoMismatch;
            return;
        }
        self.io = io;
    }

    /// The caller supplies its checked whole-runtime epoch. Failed requests do
    /// not consume it. An exhausted caller cannot reset this owner to epoch zero.
    pub fn request(self: *Pause, epoch: u64) Error!Token {
        lock(&self.mutex);
        defer self.mutex.unlock();
        if (self.io == null) return error.NotPrepared;
        if (epoch == 0 or epoch <= self.request_epoch) return error.InvalidEpoch;
        if (self.decision == .pending or self.departed_epoch != self.request_epoch or
            self.waiters != 0 or self.signalers != 0) return error.Busy;
        // No previous worker or coordinator can still use these events.
        self.arrival.reset();
        self.release.reset();
        self.request_epoch = epoch;
        self.decision = .pending;
        return .{ .owner = self, .epoch = epoch };
    }

    fn check(self: *Pause, token: Token) Error!void {
        if (token.owner != self or token.epoch == 0 or token.epoch != self.request_epoch)
            return error.InvalidToken;
    }

    pub fn requirePaused(self: *Pause, token: Token) Error!void {
        lock(&self.mutex);
        defer self.mutex.unlock();
        try self.check(token);
        if (self.decision != .pending or self.parked_epoch != token.epoch) return error.NotPaused;
    }

    /// Lifecycle owners use this under their own startup exclusion to observe
    /// a requested pause of a genuinely unstarted lazy resource. It does not
    /// fabricate arrival and awaitPaused still requires the actual worker.
    pub fn requireRequested(self: *Pause, token: Token) Error!void {
        lock(&self.mutex);
        defer self.mutex.unlock();
        try self.check(token);
        if (self.decision != .pending) return error.NotPaused;
    }

    pub fn awaitPaused(self: *Pause, token: Token, deadline: std.Io.Clock.Timestamp) Error!void {
        if (deadline.clock != .awake) return error.InvalidDeadline;
        lock(&self.mutex);
        self.check(token) catch |err| {
            self.mutex.unlock();
            return err;
        };
        const io = self.io orelse {
            self.mutex.unlock();
            return error.NotPrepared;
        };
        self.waiters += 1;
        self.mutex.unlock();
        defer {
            lock(&self.mutex);
            self.waiters -= 1;
            self.mutex.unlock();
        }
        while (true) {
            lock(&self.mutex);
            const pending = self.decision == .pending;
            const arrived = self.parked_epoch == token.epoch;
            self.mutex.unlock();
            if (!pending) return error.Canceled;
            if (arrived) return;
            if (expired(io, deadline)) return error.Timeout;
            self.arrival.waitTimeout(io, .{ .deadline = deadline }) catch |err| switch (err) {
                error.Timeout => continue, // preserve the original absolute deadline
                error.Canceled => return error.Canceled,
            };
        }
    }

    /// No allocation/spawn. Publishing the decision before setting the Event
    /// handles resume-before-wait. Reset is forbidden until every signaler exits.
    pub fn resumePaused(self: *Pause, token: Token) Error!void {
        lock(&self.mutex);
        self.check(token) catch |err| {
            self.mutex.unlock();
            return err;
        };
        if (self.decision == .resumed) {
            self.mutex.unlock();
            return;
        }
        const io = self.io.?;
        self.decision = .resumed;
        if (self.parked_epoch != token.epoch) self.departed_epoch = token.epoch;
        self.signalers += 1;
        self.mutex.unlock();
        self.release.set(io);
        self.arrival.set(io); // a coordinator awaiting arrival observes cancellation
        lock(&self.mutex);
        self.signalers -= 1;
        self.mutex.unlock();
    }

    /// Stop path wakes a retained worker without issuing a new epoch.
    pub fn resumeCurrent(self: *Pause) void {
        lock(&self.mutex);
        const epoch = self.request_epoch;
        self.mutex.unlock();
        if (epoch != 0) self.resumePaused(.{ .owner = self, .epoch = epoch }) catch unreachable;
    }

    /// Only the actual single worker calls this, after finishing the entire
    /// preceding operation and its cleanup. It never holds an owner/data lock.
    pub fn boundary(self: *Pause) void {
        lock(&self.mutex);
        if (self.decision != .pending) {
            self.mutex.unlock();
            return;
        }
        const io = self.io.?;
        const epoch = self.request_epoch;
        std.debug.assert(self.parked_epoch != epoch);
        self.parked_epoch = epoch;
        self.signalers += 1;
        self.mutex.unlock();
        self.arrival.set(io);
        lock(&self.mutex);
        self.signalers -= 1;
        self.mutex.unlock();
        self.release.waitUncancelable(io);
        lock(&self.mutex);
        std.debug.assert(self.request_epoch == epoch and self.decision == .resumed);
        self.departed_epoch = epoch;
        self.mutex.unlock();
        // No access to either old event after publishing departure.
    }
};

/// New workers have only Gate/Slot custody. Legacy owner APIs retain their
/// separate handle until callers migrate; owners reject mixing the two lanes.
pub const WorkerState = struct {
    pause: Pause = .{},
    view: ?*const start_gate.View = null,
    slot: ?start_gate.Slot = null,
    entered: std.atomic.Value(bool) = .init(false),
    exited: std.atomic.Value(bool) = .init(false),

    /// Control is borrowed only for this synchronous spawn; workers and owner
    /// state retain the observation View, never lifecycle authority.
    pub fn validateRegistration(self: *const WorkerState, control: *start_gate.Control, view: *const start_gate.View, slot: start_gate.Slot, kind: start_gate.Kind, instance: u16, owner: *const anyopaque, options: std.Thread.SpawnConfig) !void {
        try control.requireView(view);
        try view.requireSlot(slot, kind, instance, owner, options);
        if (self.view != null or self.slot != null or self.entered.load(.acquire) or self.exited.load(.acquire)) return error.NotPrepared;
        if ((try view.inspectSlot(slot)).spawned) return error.InvalidSlot;
    }

    pub fn validatePreparation(self: *const WorkerState, control: *start_gate.Control, view: *const start_gate.View, slot: start_gate.Slot, kind: start_gate.Kind, instance: u16, owner: *const anyopaque, options: std.Thread.SpawnConfig) !void {
        try self.validateRegistration(control, view, slot, kind, instance, owner, options);
        if (self.pause.io == null) return error.NotPrepared;
    }

    pub fn prepare(self: *WorkerState, control: *start_gate.Control, view: *const start_gate.View, slot: start_gate.Slot, kind: start_gate.Kind, instance: u16, comptime Owner: type, owner: *Owner, comptime worker: fn (*Owner) void, options: std.Thread.SpawnConfig) !void {
        try self.validatePreparation(control, view, slot, kind, instance, owner, options);
        self.view = view;
        self.slot = slot;
        // Failed spawn retains this observation pin until actual Control
        // cancellation/join; an owner can never free a pending borrowed row.
        try control.spawn(slot, *Owner, owner, worker, options);
    }

    pub fn requireParked(self: *WorkerState) !void {
        const view = self.view orelse return error.NotPrepared;
        try view.requireSlotParked(self.slot.?);
    }

    /// Actual worker publishes this only from its real body, after Gate release.
    /// Constructors must already have finished required bind/FD preparation.
    /// It does not claim that a network job succeeded or that the runtime's
    /// other owners activated. No non-atomic Gate query occurs in the worker.
    pub fn markEntered(self: *WorkerState) void {
        self.entered.store(true, .release);
    }
    pub fn markExited(self: *WorkerState) void {
        self.exited.store(true, .release);
    }
    pub fn requireActivated(self: *WorkerState) Error!void {
        if (self.view == null) return error.NotPrepared;
        if (!self.entered.load(.acquire) or self.exited.load(.acquire)) return error.NotPrepared;
    }

    /// Own stop/wake never joins or changes another owner's Gate decision.
    pub fn wakeForStop(self: *WorkerState) void {
        self.pause.resumeCurrent();
    }

    pub fn detachAfterJoined(self: *WorkerState) !void {
        const view = self.view orelse return;
        try view.requireSlotJoined(self.slot orelse return error.InvalidSlot);
        self.view = null;
        self.slot = null;
    }

    /// Destructors must retain every resource while a managed row still borrows
    /// it. Only the Control owner may join, then source detach clears this pin.
    pub fn requireDetached(self: *const WorkerState) !void {
        if (self.view != null or self.slot != null) return error.SharedGateOwned;
    }
};

/// Source-issued producer fence. The enclosing owner MUST hold its actual
/// producer mutex for every state method and acceptance check. No queue or
/// worker disposition can be inferred from this token alone.
pub const ProducerFence = struct { anchor: *const anyopaque, identity: u64, epoch: u64 };
var next_producer_identity: std.atomic.Value(u64) = .init(1);
pub const ProducerState = struct {
    identity: u64 = 0,
    epoch: u64 = 0,
    frozen: bool = false,

    pub fn freezeLocked(self: *ProducerState) !ProducerFence {
        if (self.frozen) return error.ProducersFrozen;
        if (self.epoch == std.math.maxInt(u64)) return error.SequenceExhausted;
        if (self.identity == 0) {
            var current = next_producer_identity.load(.acquire);
            while (true) {
                if (current == std.math.maxInt(u64)) return error.SequenceExhausted;
                if (next_producer_identity.cmpxchgWeak(current, current + 1, .acq_rel, .acquire)) |actual| current = actual else break;
            }
            self.identity = current;
        }
        self.epoch += 1;
        self.frozen = true;
        return .{ .anchor = self, .identity = self.identity, .epoch = self.epoch };
    }
    pub fn requireLocked(self: *const ProducerState, token: ProducerFence) !void {
        if (token.anchor != @as(*const anyopaque, self) or token.identity == 0 or token.identity != self.identity or token.epoch == 0 or token.epoch != self.epoch) return error.InvalidProducerFence;
        if (!self.frozen) return error.ProducersNotFrozen;
    }
    pub fn resumeLocked(self: *ProducerState, token: ProducerFence) !void {
        try self.requireLocked(token);
        self.frozen = false;
    }
};

fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.Thread.yield() catch {};
}
fn expired(io: std.Io, deadline: std.Io.Clock.Timestamp) bool {
    return std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds >= deadline.raw.nanoseconds;
}
fn testDeadline() std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.now(std.testing.io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(2) });
}

/// Dynamic configuration commitments use length prefixes, never raw struct
/// padding or concatenation without boundaries. These are context pins, not
/// authenticated inherited-FD or provider authority proofs.
pub fn hashBytes(hash: *std.crypto.hash.sha2.Sha256, bytes: []const u8) !void {
    const len = std.math.cast(u32, bytes.len) orelse return error.Capacity;
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, len, .big);
    hash.update(&prefix);
    hash.update(bytes);
}
pub fn hashOptional(hash: *std.crypto.hash.sha2.Sha256, bytes: ?[]const u8) !void {
    hash.update(&.{@intFromBool(bytes != null)});
    if (bytes) |value| try hashBytes(hash, value);
}

test "companion runtime pause timeout retains operation and cancels late entry" {
    var pause: Pause = .{};
    try pause.bindIo(std.testing.io);
    const old = try pause.request(1);
    try std.testing.expectError(error.Timeout, pause.awaitPaused(old, std.Io.Clock.Timestamp.now(std.testing.io, .awake)));
    try std.testing.expectError(error.NotPaused, pause.requirePaused(old));
    try pause.resumePaused(old);
    pause.boundary(); // actual late entry cannot park after canceled decision
    const next = try pause.request(2);
    try std.testing.expectError(error.InvalidToken, pause.resumePaused(old));
    try std.testing.expectError(error.Busy, pause.request(3));
    try pause.resumePaused(next);
    try std.testing.expectError(error.InvalidEpoch, pause.request(0));
    const last = try pause.request(std.math.maxInt(u64));
    try pause.resumePaused(last);
    try std.testing.expectError(error.InvalidEpoch, pause.request(std.math.maxInt(u64)));
}

test "companion runtime pause retains same thread across copied resume and reuse" {
    const Context = struct {
        pause: *Pause,
        enter: std.Io.Event = .unset,
        departed: std.Io.Event = .unset,
        completed: std.atomic.Value(u32) = .init(0),
        fn run(self: *@This()) void {
            self.enter.waitUncancelable(std.testing.io);
            self.pause.boundary();
            _ = self.completed.fetchAdd(1, .release);
            self.departed.set(std.testing.io);
        }
    };
    var pause: Pause = .{};
    try pause.bindIo(std.testing.io);
    var ctx: Context = .{ .pause = &pause };
    const token = try pause.request(1);
    const thread = try std.Thread.spawn(.{}, Context.run, .{&ctx});
    defer {
        pause.resumeCurrent();
        ctx.enter.set(std.testing.io);
        thread.join();
    }
    ctx.enter.set(std.testing.io);
    try pause.awaitPaused(token, testDeadline());
    try pause.requirePaused(token);
    try std.testing.expectEqual(@as(u32, 0), ctx.completed.load(.acquire));
    try pause.resumePaused(token);
    try pause.resumePaused(token); // copied current token cannot consume another epoch
    try ctx.departed.waitTimeout(std.testing.io, .{ .deadline = testDeadline() });
    try std.testing.expectEqual(@as(u32, 1), ctx.completed.load(.acquire));
    const next = try pause.request(2);
    try std.testing.expectError(error.InvalidToken, pause.resumePaused(token));
    try pause.resumePaused(next);
}

test "companion runtime pause repeated epochs park one real looping worker" {
    const Context = struct {
        pause: *Pause,
        begin: [2]std.Io.Event = @splat(.unset),
        end: [2]std.Io.Event = @splat(.unset),
        calls: std.atomic.Value(u32) = .init(0),
        completed: std.atomic.Value(u32) = .init(0),
        fn run(self: *@This()) void {
            _ = self.calls.fetchAdd(1, .release);
            for (0..2) |i| {
                self.begin[i].waitUncancelable(std.testing.io);
                self.pause.boundary();
                _ = self.completed.fetchAdd(1, .release);
                self.end[i].set(std.testing.io);
            }
        }
    };
    var pause: Pause = .{};
    try pause.bindIo(std.testing.io);
    var ctx: Context = .{ .pause = &pause };
    const thread = try std.Thread.spawn(.{}, Context.run, .{&ctx});
    defer {
        pause.resumeCurrent();
        for (&ctx.begin) |*event| event.set(std.testing.io);
        thread.join();
    }
    var previous: ?Token = null;
    for (0..2) |i| {
        const token = try pause.request(i + 1);
        ctx.begin[i].set(std.testing.io);
        try pause.awaitPaused(token, testDeadline());
        try pause.requirePaused(token);
        try std.testing.expectEqual(@as(u32, @intCast(i)), ctx.completed.load(.acquire));
        if (previous) |old| {
            try std.testing.expectError(error.InvalidToken, pause.resumePaused(old));
            try pause.requirePaused(token);
        }
        try pause.resumePaused(token);
        try ctx.end[i].waitTimeout(std.testing.io, .{ .deadline = testDeadline() });
        previous = token;
    }
    try std.testing.expectEqual(@as(u32, 1), ctx.calls.load(.acquire));
    try std.testing.expectEqual(@as(u32, 2), ctx.completed.load(.acquire));
}

/// Canonical config pinning only; this hash is never a trust/admission proof.
/// Struct fields have declaration order, integers have typed fixed width, and
/// byte slices/optionals carry explicit length/presence. No pointer or padding
/// bytes are accepted by this helper.
pub fn hashConfigValue(hash: *std.crypto.hash.sha2.Sha256, value: anytype) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .bool => hash.update(&.{@intFromBool(value)}),
        .int => |info| {
            const width = comptime std.mem.alignForward(usize, info.bits, 8);
            const I = @Int(info.signedness, width);
            const U = @Int(.unsigned, width);
            var bytes: [width / 8]u8 = undefined;
            std.mem.writeInt(U, &bytes, @bitCast(@as(I, value)), .little);
            hash.update(&bytes);
        },
        .@"enum" => try hashConfigValue(hash, @intFromEnum(value)),
        .optional => {
            hash.update(&.{@intFromBool(value != null)});
            if (value) |inner| try hashConfigValue(hash, inner);
        },
        .pointer => |info| {
            if (info.size != .slice or info.child != u8) @compileError("config pin accepts only byte slices");
            try hashBytes(hash, value);
        },
        .@"struct" => |info| inline for (info.field_names) |name| try hashConfigValue(hash, @field(value, name)),
        else => @compileError("unsupported config pin type"),
    }
}

test "companion cold Io preparation confirms pristine exact identity without resetting used pause" {
    var pause: Pause = .{};
    try pause.prepareIo(std.testing.io);
    try pause.prepareIo(std.testing.io);
    try std.testing.expectError(error.Busy, pause.bindIo(std.testing.io));
    var different_vtable = std.testing.io.vtable.*;
    const wrong: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &different_vtable };
    try std.testing.expectError(error.IoMismatch, pause.prepareIo(wrong));
    try std.testing.expect(pause.io.?.vtable == std.testing.io.vtable);
    const token = try pause.request(1);
    try std.testing.expectError(error.Busy, pause.prepareIo(std.testing.io));
    try pause.resumePaused(token);
    try std.testing.expectError(error.Busy, pause.prepareIo(std.testing.io));
    try std.testing.expectEqual(@as(u64, 1), pause.request_epoch);
}

test "companion runtime producer fence copied epoch and same-address replacement cannot resume a newer owner" {
    var state: ProducerState = .{};
    const first = try state.freezeLocked();
    try std.testing.expectError(error.ProducersFrozen, state.freezeLocked());
    try state.requireLocked(first);
    try state.resumeLocked(first);
    try std.testing.expectError(error.ProducersNotFrozen, state.resumeLocked(first));
    const second = try state.freezeLocked();
    try std.testing.expectError(error.InvalidProducerFence, state.resumeLocked(first));
    try state.requireLocked(second);
    const prior_identity = state.identity;
    state = .{}; // actual fixture owner lifetime ended, same address reused
    const replacement = try state.freezeLocked();
    try std.testing.expect(replacement.identity != prior_identity);
    try std.testing.expectError(error.InvalidProducerFence, state.resumeLocked(second));
    try state.requireLocked(replacement);
    try state.resumeLocked(replacement);
    state.epoch = std.math.maxInt(u64);
    try std.testing.expectError(error.SequenceExhausted, state.freezeLocked());
    try std.testing.expect(!state.frozen);
    try std.testing.expectEqual(replacement.identity, state.identity);
}

const TestWorkerOwner = struct {
    state: WorkerState = .{},
    stopping: std.atomic.Value(bool) = .init(false),
    entered: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    fn run(self: *@This()) void {
        self.state.markEntered();
        defer self.state.markExited();
        self.entered.set(std.testing.io);
        self.release.waitUncancelable(std.testing.io);
        self.state.pause.boundary();
    }
};

test "companion runtime worker validates pair and demanded options before any source preparation" {
    var owner: TestWorkerOwner = .{};
    const specs = [_]start_gate.ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &owner }};
    const selected = try start_gate.create(std.testing.allocator, std.testing.io, &specs);
    defer {
        selected.control.cancelAllAndJoin();
        selected.control.destroyJoined();
    }
    const foreign = try start_gate.create(std.testing.allocator, std.testing.io, &specs);
    defer {
        foreign.control.cancelAllAndJoin();
        foreign.control.destroyJoined();
    }
    const slot = try selected.view.slot(.mail, 0, &owner);
    try std.testing.expectError(error.InvalidGate, owner.state.validateRegistration(foreign.control, selected.view, slot, .mail, 0, &owner, .{}));
    try std.testing.expectError(error.InvalidOptions, owner.state.validateRegistration(selected.control, selected.view, slot, .mail, 0, &owner, .{ .stack_size = 2 * 1024 * 1024 }));
    try std.testing.expectError(error.InvalidSlot, owner.state.validateRegistration(selected.control, selected.view, slot, .mail, 1, &owner, .{}));
    try std.testing.expect(owner.state.pause.io == null);
    try std.testing.expect(owner.state.view == null and owner.state.slot == null);
    try std.testing.expectEqual(@as(usize, 0), selected.view.inspect().spawned);
    try std.testing.expectError(error.NotPrepared, owner.state.prepare(selected.control, selected.view, slot, .mail, 0, TestWorkerOwner, &owner, TestWorkerOwner.run, .{}));
    try owner.state.pause.prepareIo(std.testing.io);
    try owner.state.validatePreparation(selected.control, selected.view, slot, .mail, 0, &owner, .{});
}

test "companion runtime worker failed spawn retains borrowed pin until real control cancellation" {
    var owner: TestWorkerOwner = .{};
    try owner.state.pause.prepareIo(std.testing.io);
    const specs = [_]start_gate.ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &owner }};
    const selected = try start_gate.create(std.testing.allocator, std.testing.io, &specs);
    defer {
        selected.control.cancelAllAndJoin();
        owner.state.detachAfterJoined() catch unreachable;
        selected.control.destroyJoined();
    }
    start_gate.Fixture.failSpawn(selected.control, 0);
    try std.testing.expectError(error.SystemResources, owner.state.prepare(selected.control, selected.view, try selected.view.slot(.mail, 0, &owner), .mail, 0, TestWorkerOwner, &owner, TestWorkerOwner.run, .{}));
    try std.testing.expectError(error.SharedGateOwned, owner.state.requireDetached());
    try std.testing.expectEqual(start_gate.Phase.canceled, selected.view.inspect().phase);
    try std.testing.expectEqual(@as(usize, 0), selected.view.inspect().spawned);
    try std.testing.expectEqual(@as(usize, 0), selected.view.inspect().arrived);
    try selected.view.requireAllJoined();
    try std.testing.expect(owner.state.view == selected.view and owner.state.slot != null);
    try std.testing.expect(!owner.state.entered.load(.acquire));
    selected.control.cancelAllAndJoin();
    try owner.state.detachAfterJoined();
    try owner.state.requireDetached();
}

test "companion runtime real worker cannot detach until current body exited and control joined" {
    var owner: TestWorkerOwner = .{};
    try owner.state.pause.prepareIo(std.testing.io);
    const specs = [_]start_gate.ParticipantSpec{.{ .kind = .mail, .instance = 0, .owner_identity = &owner }};
    const selected = try start_gate.create(std.testing.allocator, std.testing.io, &specs);
    defer {
        owner.state.wakeForStop();
        owner.release.set(std.testing.io);
        if (selected.view.inspect().phase == .preparing) selected.control.cancelAllAndJoin() else selected.control.joinAll();
        owner.state.detachAfterJoined() catch unreachable;
        selected.control.destroyJoined();
    }
    try owner.state.prepare(selected.control, selected.view, try selected.view.slot(.mail, 0, &owner), .mail, 0, TestWorkerOwner, &owner, TestWorkerOwner.run, .{});
    try selected.control.awaitAllParked(testDeadline());
    try owner.state.requireParked();
    try std.testing.expectError(error.NotPrepared, owner.state.requireActivated());
    selected.control.releaseAll();
    try owner.entered.waitTimeout(std.testing.io, .{ .deadline = testDeadline() });
    try owner.state.requireActivated();
    try std.testing.expectError(error.NotJoined, owner.state.detachAfterJoined());
    owner.release.set(std.testing.io);
    selected.control.joinAll();
    try std.testing.expectError(error.NotPrepared, owner.state.requireActivated());
    try owner.state.detachAfterJoined();
    try owner.state.requireDetached();
}
