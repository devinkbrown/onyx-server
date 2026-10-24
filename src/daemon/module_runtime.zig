// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Instance-owned module lifecycle, availability, and diagnostic counters.
//!
//! The host serializes mutations and command/hook readers on its exclusive
//! policy lane (the daemon uses World, including REHASH from any shard). It
//! must quiesce module readers before stop or the config-publication/commit
//! interval; availability
//! gates prevent new entry but do not revoke an invocation already in flight.
//! Modules may not retain unsynchronized background borrows of module policy.
//! A module with private workers must fence its own readers in reload prepare,
//! retain that fence through commit/abort, and join workers in deinit. The host
//! policy lane is not a claim that unrelated transport/config readers stopped.
//! Prepare runs against a borrowed candidate without changing active policy.
//! Successful prepare must eventually be followed by commit or abort. No runtime
//! field or callback pointer belongs in a Helix capsule: recreate the runtime in
//! the successor, then initialize against the adopted host services.
//!
//! Register is non-owning setup. Init must clean up its own partial failure;
//! every successful init (including a missing callback) earns exactly one deinit.
//! Ready failure therefore still tears down the initialized module. Runtime
//! health is sampled atomically but is not a coherent multi-field transaction.
const std = @import("std");
const registry = @import("registry.zig");
const module_bus = @import("module_bus.zig");
const lifecycle = @import("module_lifecycle.zig");

pub const State = enum(u8) {
    unloaded,
    registered,
    initialized,
    ready,
    failed,
    blocked,
    stopped,

    pub fn token(self: State) []const u8 {
        return @tagName(self);
    }
};

pub const Health = struct {
    load_position: usize,
    module_index: usize,
    id: []const u8,
    version: registry.Version,
    category: registry.Category,
    priority: registry.Priority,
    state: State,
    required_at_boot: bool,
    blocked_by: ?usize,
    reload_count: u64,
    rollback_count: u64,
    last_error: ?anyerror,
    failed_phase: ?lifecycle.Phase,

    pub fn degraded(self: Health) bool {
        return self.state == .failed or self.state == .blocked;
    }
};

pub const ReloadFailure = struct {
    module_index: ?usize = null,
    err: anyerror,
};

pub const PrepareOutcome = union(enum) {
    prepared,
    rejected: ReloadFailure,
};

pub fn Runtime(comptime mods: []const registry.Module) type {
    return struct {
        const Self = @This();
        pub const Registry = blk: {
            // Match modules/manifest.zig: the live command surface exceeds the
            // compiler default quota even when the Runtime type itself is lazy.
            @setEvalBranchQuota(200_000);
            break :blk registry.Registry(mods);
        };
        pub const Bus = module_bus.Bus(mods);
        pub const count = mods.len;
        pub const modules = mods;
        pub const load_order = Registry.load_order;
        const no_index = std.math.maxInt(usize);
        const no_phase = std.math.maxInt(u8);
        const ErrorCode = @TypeOf(@intFromError(error.Sentinel));
        const DriverState = enum { cold, running, prepared, stopped };
        const Row = struct {
            state: std.atomic.Value(u8) = .init(@backingInt(State.unloaded)),
            blocked_by: std.atomic.Value(usize) = .init(no_index),
            reload_count: std.atomic.Value(u64) = .init(0),
            rollback_count: std.atomic.Value(u64) = .init(0),
            last_error: std.atomic.Value(ErrorCode) = .init(0),
            failed_phase: std.atomic.Value(u8) = .init(no_phase),
        };

        rows: [count]Row = @splat(.{}),
        bus: Bus.Instance = .{},
        online: std.atomic.Value(bool) = .init(false),
        engaged_flag: std.atomic.Value(bool) = .init(false),
        config_generation: std.atomic.Value(u64) = .init(0),
        // Only the single lifecycle driver accesses the following fields.
        driver: DriverState = .cold,
        initialized: [count]bool = @splat(false),
        prepared: [count]bool = @splat(false),
        prepared_host: ?*anyopaque = null,
        prepared_generation: u64 = 0,

        /// Seed from the host's already-active configuration generation, including
        /// a successor's adopted config. Runtime health itself is never adopted.
        pub fn init(active_generation: u64) Self {
            return .{ .config_generation = .init(active_generation) };
        }

        pub fn start(self: *Self, host: *anyopaque) error{ AlreadyStarted, ModuleStartupFailed }!void {
            if (self.driver != .cold) return error.AlreadyStarted;
            self.engaged_flag.store(true, .release);
            inline for (.{ lifecycle.Phase.register, .init, .ready }) |phase| {
                self.drivePhase(host, phase);
                if (self.requiredFailure()) {
                    self.teardown(host);
                    self.driver = .stopped;
                    return error.ModuleStartupFailed;
                }
            }
            // Optional callbacks may fail while leaving successfully initialized
            // dependents blocked. Such modules have no published availability,
            // so release their initialized resources before exposing startup
            // success. Healthy optional and required modules remain live.
            self.teardownUnavailableInitialized(host);
            self.driver = .running;
            self.online.store(true, .release);
        }

        fn drivePhase(self: *Self, host: *anyopaque, comptime phase: lifecycle.Phase) void {
            const needed: State = switch (phase) {
                .register => .registered,
                .init => .initialized,
                .ready => .ready,
                else => unreachable,
            };
            inline for (load_order) |index| {
                const module = mods[index];
                const current = self.stateOf(index);
                if (current != .failed and current != .blocked) {
                    if (self.blockingDependency(index, needed)) |dependency| {
                        self.rows[index].blocked_by.store(dependency, .monotonic);
                        self.setState(index, .blocked);
                    } else {
                        const callback = comptime switch (phase) {
                            .register => module.on_register,
                            .init => module.on_init,
                            .ready => module.on_ready,
                            else => unreachable,
                        };
                        var succeeded = true;
                        if (callback) |f| f(host) catch |err| {
                            self.recordError(index, phase, err);
                            self.setState(index, .failed);
                            succeeded = false;
                        };
                        if (succeeded) {
                            if (phase == .init) self.initialized[index] = true;
                            self.setState(index, needed);
                        }
                    }
                }
            }
        }

        fn blockingDependency(self: *const Self, comptime index: usize, needed: State) ?usize {
            inline for (mods[index].requires) |required| {
                const dependency = comptime indexOf(required);
                if (self.stateOf(dependency) != needed) return dependency;
            }
            return null;
        }

        fn requiredFailure(self: *const Self) bool {
            inline for (mods, 0..) |module, i| {
                if (module.required_at_boot) {
                    const state = self.stateOf(i);
                    if (state == .failed or state == .blocked) return true;
                }
            }
            return false;
        }

        /// Stop is idempotent. The host must have quiesced active invocations.
        pub fn stop(self: *Self, host: *anyopaque) void {
            if (self.driver == .stopped) return;
            _ = self.abortReload();
            self.online.store(false, .release);
            self.teardown(host);
            self.driver = .stopped;
        }

        fn teardown(self: *Self, host: *anyopaque) void {
            inline for (0..count) |offset| {
                const index = load_order[count - 1 - offset];
                if (self.initialized[index]) {
                    if (mods[index].on_deinit) |f| f(host);
                    self.initialized[index] = false;
                    // Preserve the failure/blocked verdict and its history.
                    const state = self.stateOf(index);
                    if (state != .failed and state != .blocked) self.setState(index, .stopped);
                }
            }
        }

        /// Release initialized modules that failed a lifecycle phase or were
        /// blocked by one, in reverse dependency order. Preserve their failed /
        /// blocked health and make the cleanup exactly once across later stop.
        fn teardownUnavailableInitialized(self: *Self, host: *anyopaque) void {
            inline for (0..count) |offset| {
                const index = load_order[count - 1 - offset];
                if (self.initialized[index]) {
                    const state = self.stateOf(index);
                    if (state == .failed or state == .blocked) {
                        if (mods[index].on_deinit) |f| f(host);
                        self.initialized[index] = false;
                    }
                }
            }
        }

        /// Prepare is atomic with respect to active module state. It deliberately
        /// rejects legacy on_reload callbacks, whose partial mutations cannot be
        /// undone by the driver. Rejection is recoverable; readiness is unchanged.
        pub fn prepareReload(self: *Self, host: *anyopaque, candidate: registry.ReloadCandidate) PrepareOutcome {
            if (self.driver != .running) return .{ .rejected = .{ .err = error.InvalidModuleRuntimeState } };
            if (candidate.generation <= self.generation()) return .{ .rejected = .{ .err = error.StaleConfigGeneration } };
            inline for (load_order) |index| {
                if (mods[index].on_reload != null and self.stateOf(index) == .ready) {
                    self.recordError(index, .reload, error.LegacyReloadUnsupported);
                    return .{ .rejected = .{ .module_index = index, .err = error.LegacyReloadUnsupported } };
                }
            }
            self.prepared_host = host;
            self.prepared_generation = candidate.generation;
            self.driver = .prepared;
            inline for (load_order) |index| {
                if (mods[index].reload) |hooks| {
                    if (self.stateOf(index) == .ready) {
                        // Mark BEFORE prepare so abort also cleans up a callback
                        // which allocated staging and then failed.
                        self.prepared[index] = true;
                        hooks.prepare(host, candidate) catch |err| {
                            self.recordError(index, .reload, err);
                            _ = self.abortReload();
                            return .{ .rejected = .{ .module_index = index, .err = err } };
                        };
                    }
                }
            }
            return .prepared;
        }

        /// The host publishes its candidate config and calls this while module
        /// readers are quiesced. Only nonfallible swaps remain after prepare.
        pub fn commitReload(self: *Self) error{NoPreparedReload}!void {
            if (self.driver != .prepared) return error.NoPreparedReload;
            const host = self.prepared_host.?;
            inline for (load_order) |index| {
                if (mods[index].reload) |hooks| {
                    if (self.prepared[index]) {
                        hooks.commit(host);
                        self.prepared[index] = false;
                        _ = self.rows[index].reload_count.fetchAdd(1, .monotonic);
                    }
                }
            }
            self.config_generation.store(self.prepared_generation, .release);
            self.prepared_host = null;
            self.prepared_generation = 0;
            self.driver = .running;
        }

        pub fn abortReload(self: *Self) bool {
            if (self.driver != .prepared) return false;
            const host = self.prepared_host.?;
            inline for (0..count) |offset| {
                const index = load_order[count - 1 - offset];
                if (mods[index].reload) |hooks| {
                    if (self.prepared[index]) {
                        hooks.abort(host);
                        self.prepared[index] = false;
                        _ = self.rows[index].rollback_count.fetchAdd(1, .monotonic);
                    }
                }
            }
            self.prepared_host = null;
            self.prepared_generation = 0;
            self.driver = .running;
            return true;
        }

        pub fn generation(self: *const Self) u64 {
            return self.config_generation.load(.acquire);
        }

        pub fn engaged(self: *const Self) bool {
            return self.engaged_flag.load(.acquire);
        }

        pub fn gate(self: *const Self) registry.ModuleGate {
            return .{ .ctx = self, .available = availableErased };
        }

        fn availableErased(ctx: *const anyopaque, index: usize) bool {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.available(index);
        }

        pub fn available(self: *const Self, index: usize) bool {
            return index < count and self.online.load(.acquire) and self.stateOf(index) == .ready;
        }

        pub fn dispatch(self: *Self, ctx: *anyopaque, name: []const u8, params: []const []const u8, caps: registry.DispatchCaps) anyerror!registry.DispatchResult {
            var gated = caps;
            gated.module_gate = self.gate();
            return Registry.dispatchGated(ctx, name, params, gated);
        }

        pub fn commandAvailable(self: *const Self, entry: registry.CommandEntry, caps: registry.DispatchCaps) bool {
            return self.available(entry.module_index) and registry.commandAvailable(entry.spec, caps);
        }

        pub fn emit(self: *Self, comptime id: registry.HookId, ctx: *anyopaque, payload: registry.HookPayload(id)) registry.HookResult {
            return self.bus.emit(id, ctx, payload, self.gate());
        }

        pub fn approve(self: *Self, comptime id: registry.HookId, ctx: *anyopaque, payload: registry.HookPayload(id)) bool {
            return self.bus.approve(id, ctx, payload, self.gate());
        }

        pub fn stateOf(self: *const Self, index: usize) State {
            return @fromBackingInt(@intCast(self.rows[index].state.load(.acquire)));
        }

        pub fn health(self: *const Self, index: usize) Health {
            const row = &self.rows[index];
            const error_code = row.last_error.load(.monotonic);
            const failed_phase = row.failed_phase.load(.monotonic);
            const blocked_by = row.blocked_by.load(.monotonic);
            return .{
                .load_position = position_table[index],
                .module_index = index,
                .id = mods[index].id,
                .version = mods[index].version,
                .category = mods[index].category,
                .priority = mods[index].priority,
                .required_at_boot = mods[index].required_at_boot,
                .state = self.stateOf(index),
                .blocked_by = if (blocked_by == no_index) null else blocked_by,
                .reload_count = row.reload_count.load(.monotonic),
                .rollback_count = row.rollback_count.load(.monotonic),
                .last_error = if (error_code == 0) null else @errorFromInt(error_code),
                .failed_phase = if (failed_phase == no_phase) null else @fromBackingInt(@intCast(failed_phase)),
            };
        }

        pub fn healthTable(self: *const Self) [count]Health {
            var rows: [count]Health = undefined;
            for (&rows, 0..) |*row, index| row.* = self.health(index);
            return rows;
        }

        /// Return the earliest real lifecycle failure in dependency load order.
        /// Blocked rows retain useful dependency information but are not the root
        /// cause; the server can log this row before returning a generic startup
        /// error, even after `start` has unwound initialized state.
        pub fn firstFailure(self: *const Self) ?Health {
            var first: ?Health = null;
            for (0..count) |index| {
                const row = self.health(index);
                if (row.state != .failed or row.last_error == null or row.failed_phase == null) continue;
                if (first == null or row.load_position < first.?.load_position) first = row;
            }
            return first;
        }

        /// Return the concrete cause of required startup failure, ignoring an
        /// unrelated optional failure that may have occurred earlier. A required
        /// row blocked by another row follows `blocked_by` to the failed owner.
        pub fn startupFailure(self: *const Self) ?Health {
            var required: ?Health = null;
            for (0..count) |index| {
                if (!mods[index].required_at_boot) continue;
                const row = self.health(index);
                if (row.state != .failed and row.state != .blocked) continue;
                if (required == null or row.load_position < required.?.load_position) required = row;
            }
            var row = required orelse return null;
            for (0..count) |_| {
                if (row.state == .failed and row.last_error != null and row.failed_phase != null) return row;
                const dependency = row.blocked_by orelse return row;
                if (dependency >= count) return row;
                row = self.health(dependency);
            }
            return row;
        }

        pub fn degradedCount(self: *const Self) usize {
            var total: usize = 0;
            for (0..count) |index| {
                const state = self.stateOf(index);
                if (state == .failed or state == .blocked) total += 1;
            }
            return total;
        }

        fn setState(self: *Self, index: usize, state: State) void {
            self.rows[index].state.store(@backingInt(state), .release);
        }

        fn recordError(self: *Self, index: usize, phase: lifecycle.Phase, err: anyerror) void {
            self.rows[index].last_error.store(@intFromError(err), .monotonic);
            self.rows[index].failed_phase.store(@backingInt(phase), .monotonic);
        }

        fn indexOf(comptime id: []const u8) usize {
            inline for (mods, 0..) |module, index| {
                if (comptime std.mem.eql(u8, module.id, id)) return index;
            }
            @compileError("required module absent from validated registry");
        }

        const position_table = blk: {
            var positions: [count]usize = undefined;
            for (load_order, 0..) |index, position| positions[index] = position;
            break :blk positions;
        };
    };
}

const Probe = struct {
    allocator: std.mem.Allocator = std.testing.allocator,
    events: [128]u8 = @splat(0),
    event_count: usize = 0,
    fail_init: ?usize = null,
    fail_ready: ?usize = null,
    fail_prepare: ?usize = null,
    active: [3]u64 = .{ 10, 10, 10 },
    staged: [3]?*u64 = .{ null, null, null },
    commands: usize = 0,
    hooks: usize = 0,

    fn from(ctx: *anyopaque) *Probe {
        return @ptrCast(@alignCast(ctx));
    }

    fn note(self: *Probe, value: u8) void {
        self.events[self.event_count] = value;
        self.event_count += 1;
    }

    fn clear(self: *Probe) void {
        self.event_count = 0;
    }

    fn seen(self: *const Probe) []const u8 {
        return self.events[0..self.event_count];
    }

    fn command(ctx: *anyopaque, _: registry.CommandInvocation) anyerror!void {
        from(ctx).commands += 1;
    }

    fn info(ctx: *anyopaque, _: *anyopaque) anyerror!registry.HookResult {
        from(ctx).hooks += 1;
        return .continue_;
    }

    fn veto(ctx: *anyopaque, payload: *anyopaque) anyerror!registry.HookResult {
        from(ctx).hooks += 1;
        const message: *registry.MessagePreDeliverPayload = @ptrCast(@alignCast(payload));
        message.approved = true; // A prior denial must prevent even this call.
        return .continue_;
    }

    fn legacy(ctx: *anyopaque) anyerror!void {
        from(ctx).note('L');
    }
};

fn fake(comptime index: usize, comptime required: bool, comptime requires: []const []const u8) registry.Module {
    const F = struct {
        fn register(ctx: *anyopaque) anyerror!void {
            Probe.from(ctx).note('a' + index);
        }
        fn init(ctx: *anyopaque) anyerror!void {
            const probe = Probe.from(ctx);
            probe.note('A' + index);
            if (probe.fail_init == index) return error.InitRejected;
        }
        fn ready(ctx: *anyopaque) anyerror!void {
            const probe = Probe.from(ctx);
            probe.note('D' + index);
            if (probe.fail_ready == index) return error.ReadyRejected;
        }
        fn deinit(ctx: *anyopaque) void {
            Probe.from(ctx).note('x' + index);
        }
        fn prepare(ctx: *anyopaque, candidate: registry.ReloadCandidate) anyerror!void {
            const probe = Probe.from(ctx);
            probe.note('P' + index);
            const value: *const u64 = @ptrCast(@alignCast(candidate.config));
            const staged = try probe.allocator.create(u64);
            staged.* = value.*;
            probe.staged[index] = staged;
            // Deliberately fail AFTER allocation: abort must include this module.
            if (probe.fail_prepare == index) return error.PrepareRejected;
        }
        fn commit(ctx: *anyopaque) void {
            const probe = Probe.from(ctx);
            probe.note('K' + index);
            const staged = probe.staged[index].?;
            probe.active[index] = staged.*;
            probe.allocator.destroy(staged);
            probe.staged[index] = null;
        }
        fn abort(ctx: *anyopaque) void {
            const probe = Probe.from(ctx);
            probe.note('U' + index);
            if (probe.staged[index]) |staged| probe.allocator.destroy(staged);
            probe.staged[index] = null;
        }
    };
    return .{
        .id = &.{ 'm', '0' + index },
        .required_at_boot = required,
        .requires = requires,
        .on_register = F.register,
        .on_init = F.init,
        .on_ready = F.ready,
        .on_deinit = F.deinit,
        .reload = .{ .prepare = F.prepare, .commit = F.commit, .abort = F.abort },
        .commands = if (index == 0) &.{.{ .name = "TEST", .aliases = &.{"TESTALIAS"}, .handler = Probe.command }} else &.{},
        .hooks = if (index == 0) &.{
            .{ .hook = .client_registered, .handler = Probe.info },
            .{ .hook = .message_pre_deliver, .handler = Probe.veto },
        } else &.{},
    };
}

const chain = [_]registry.Module{
    fake(2, true, &.{"m1"}),
    fake(1, true, &.{"m0"}),
    fake(0, true, &.{}),
};

const testing = std.testing;

test "module runtime: dependency lifecycle and teardown are instance owned and ordered" {
    var runtime: Runtime(&chain) = .{};
    var other: Runtime(&chain) = .{};
    var probe = Probe{};
    try runtime.start(&probe);
    try testing.expectEqualStrings("abcABCDEF", probe.seen());
    try testing.expect(runtime.available(0));
    try testing.expect(!other.available(0));
    try testing.expect(!other.engaged());
    try testing.expectEqual(State.unloaded, other.health(0).state);
    try testing.expectError(error.AlreadyStarted, runtime.start(&probe));
    probe.clear();
    runtime.stop(&probe);
    runtime.stop(&probe);
    try testing.expectEqualStrings("zyx", probe.seen());
    try testing.expect(!runtime.available(0));
    try testing.expectError(error.AlreadyStarted, runtime.start(&probe));
}

test "module runtime: required initialization failure blocks dependents and unwinds only owned state" {
    var runtime: Runtime(&chain) = .{};
    var probe = Probe{ .fail_init = 1 };
    try testing.expectError(error.ModuleStartupFailed, runtime.start(&probe));
    try testing.expectEqualStrings("abcABx", probe.seen());
    try testing.expectEqual(State.failed, runtime.health(1).state);
    try testing.expectEqual(State.blocked, runtime.health(0).state);
    try testing.expectEqual(@as(?usize, 1), runtime.health(0).blocked_by);
    try testing.expectEqual(@as(?anyerror, error.InitRejected), runtime.health(1).last_error);
    try testing.expectEqual(@as(usize, 2), runtime.degradedCount());
    try testing.expect(!runtime.available(2));
    const failure = runtime.firstFailure().?;
    try testing.expectEqualStrings("m1", failure.id);
    try testing.expectEqual(@as(?lifecycle.Phase, .init), failure.failed_phase);
    try testing.expectEqual(@as(?anyerror, error.InitRejected), failure.last_error);
    runtime.stop(&probe);
    try testing.expectEqualStrings("abcABx", probe.seen());
}

test "module runtime: ready failure tears down successfully initialized dependents first" {
    var runtime: Runtime(&chain) = .{};
    var probe = Probe{ .fail_ready = 0 };
    try testing.expectError(error.ModuleStartupFailed, runtime.start(&probe));
    try testing.expectEqualStrings("abcABCDzyx", probe.seen());
    try testing.expectEqual(@as(usize, 3), runtime.degradedCount());
}

test "module runtime: optional ready failure tears down unavailable dependency closure before success" {
    const mods = comptime [_]registry.Module{
        fake(0, false, &.{}),
        fake(1, false, &.{"m0"}),
        fake(2, true, &.{}),
    };
    var runtime: Runtime(&mods) = .{};
    var probe = Probe{ .fail_ready = 0 };

    try runtime.start(&probe);
    // `start` returns only after the failed optional parent and blocked child
    // release in reverse dependency order. The independent required module is
    // healthy and remains available.
    try testing.expectEqualStrings("abcABCDFyx", probe.seen());
    try testing.expect(!runtime.available(0));
    try testing.expect(!runtime.available(1));
    try testing.expect(runtime.available(2));
    try testing.expectEqual(State.failed, runtime.stateOf(0));
    try testing.expectEqual(State.blocked, runtime.stateOf(1));
    try testing.expectEqual(@as(usize, 2), runtime.degradedCount());

    runtime.stop(&probe);
    try testing.expectEqualStrings("abcABCDFyxz", probe.seen());
}

test "module runtime: optional failure gates commands and informational hooks and denies veto hooks" {
    const mods = comptime [_]registry.Module{ fake(0, false, &.{}), fake(1, false, &.{"m0"}), fake(2, true, &.{}) };
    var runtime: Runtime(&mods) = .{};
    var probe = Probe{ .fail_init = 0 };
    try runtime.start(&probe);
    defer runtime.stop(&probe);
    try testing.expect(!runtime.available(0));
    try testing.expect(!runtime.available(1));
    try testing.expect(runtime.available(2));
    const result = try runtime.dispatch(&probe, "testalias", &.{}, .{ .registered = true, .oper = true });
    try testing.expectEqual(registry.DispatchResult.disabled, result);
    try testing.expectEqual(@as(usize, 0), probe.commands);
    var info = registry.ClientRegisteredPayload{ .client_id = 1 };
    _ = runtime.emit(.client_registered, &probe, &info);
    var message = registry.MessagePreDeliverPayload{ .source_id = 1, .target = "#test", .text = "hello" };
    try testing.expect(!runtime.approve(.message_pre_deliver, &probe, &message));
    try testing.expect(!message.approved);
    try testing.expectEqual(@as(usize, 0), probe.hooks);
    try testing.expectEqual(@as(u64, 1), runtime.bus.stats(.client_registered).unavailable);
    try testing.expectEqual(@as(u64, 1), runtime.bus.stats(.message_pre_deliver).vetoed);
}

test "module runtime: reload aborts failing partial prepare LIFO and permits retry without losing readiness" {
    var runtime: Runtime(&chain) = .{};
    var probe = Probe{};
    try runtime.start(&probe);
    defer runtime.stop(&probe);
    probe.clear();
    probe.fail_prepare = 1;
    const candidate: u64 = 20;
    const outcome = runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 1 });
    try testing.expectEqual(@as(?usize, 1), outcome.rejected.module_index);
    try testing.expectEqual(error.PrepareRejected, outcome.rejected.err);
    try testing.expectEqualStrings("PQVU", probe.seen());
    try testing.expectEqualSlices(u64, &.{ 10, 10, 10 }, &probe.active);
    for (probe.staged) |staged| try testing.expect(staged == null);
    try testing.expectEqual(@as(u64, 0), runtime.generation());
    try testing.expectEqual(@as(u64, 0), runtime.health(2).reload_count);
    try testing.expectEqual(@as(u64, 1), runtime.health(2).rollback_count);
    try testing.expect(runtime.available(1));
    try testing.expectError(error.NoPreparedReload, runtime.commitReload());
    probe.fail_prepare = null;
    probe.clear();
    try testing.expectEqual(PrepareOutcome.prepared, runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 1 }));
    try testing.expectEqualSlices(u64, &.{ 10, 10, 10 }, &probe.active);
    const nested = runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 2 });
    try testing.expectEqual(error.InvalidModuleRuntimeState, nested.rejected.err);
    try runtime.commitReload();
    try testing.expectEqualStrings("PQRKLM", probe.seen());
    try testing.expectEqualSlices(u64, &.{ 20, 20, 20 }, &probe.active);
    try testing.expectEqual(@as(u64, 1), runtime.generation());
    try testing.expectEqual(@as(u64, 1), runtime.health(1).reload_count);
    try testing.expectEqual(@as(?anyerror, error.PrepareRejected), runtime.health(1).last_error);
    try testing.expectEqual(State.ready, runtime.health(1).state);
    const stale = runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 1 });
    try testing.expectEqual(error.StaleConfigGeneration, stale.rejected.err);
}

test "module runtime: external abort and shutdown release staged state without commit" {
    var runtime: Runtime(&chain) = .{};
    var probe = Probe{};
    try runtime.start(&probe);
    const candidate: u64 = 42;
    probe.clear();
    try testing.expectEqual(PrepareOutcome.prepared, runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 7 }));
    try testing.expect(runtime.abortReload());
    try testing.expect(!runtime.abortReload());
    try testing.expectEqualStrings("PQRWVU", probe.seen());
    try testing.expectEqualSlices(u64, &.{ 10, 10, 10 }, &probe.active);
    probe.clear();
    try testing.expectEqual(PrepareOutcome.prepared, runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 8 }));
    runtime.stop(&probe);
    try testing.expectEqualStrings("PQRWVUzyx", probe.seen());
    for (probe.staged) |staged| try testing.expect(staged == null);
    try testing.expectEqual(@as(u64, 0), runtime.generation());
}

test "module runtime: legacy reload is rejected before any managed preparation" {
    const mods = comptime [_]registry.Module{ fake(0, true, &.{}), .{ .id = "legacy", .on_reload = Probe.legacy } };
    var runtime: Runtime(&mods) = .{};
    var probe = Probe{};
    try runtime.start(&probe);
    defer runtime.stop(&probe);
    probe.clear();
    const candidate: u64 = 42;
    const outcome = runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 1 });
    try testing.expectEqual(error.LegacyReloadUnsupported, outcome.rejected.err);
    try testing.expectEqual(@as(?usize, 1), outcome.rejected.module_index);
    try testing.expectEqualStrings("", probe.seen());
    try testing.expectEqual(@as(u64, 0), runtime.generation());
    try testing.expect(runtime.available(1));
}

fn allocationSweep(allocator: std.mem.Allocator) !void {
    var runtime: Runtime(&chain) = .{};
    var probe = Probe{ .allocator = allocator };
    try runtime.start(&probe);
    defer runtime.stop(&probe);
    const candidate: u64 = 42;
    switch (runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 1 })) {
        .prepared => try runtime.commitReload(),
        .rejected => |failure| {
            for (probe.staged) |staged| try testing.expect(staged == null);
            try testing.expectEqualSlices(u64, &.{ 10, 10, 10 }, &probe.active);
            try testing.expectEqual(@as(u64, 0), runtime.generation());
            for (0..chain.len) |index| try testing.expect(runtime.available(index));
            return failure.err;
        },
    }
    try testing.expectEqualSlices(u64, &.{ 42, 42, 42 }, &probe.active);
}

test "module runtime: every staging allocation failure preserves active state and releases ownership" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationSweep, .{});
}

test "module runtime: predenied payload stays denied and event counters do not leak across instances" {
    var first: Runtime(&chain) = .{};
    var second: Runtime(&chain) = .{};
    var a = Probe{};
    var b = Probe{};
    try first.start(&a);
    defer first.stop(&a);
    try second.start(&b);
    defer second.stop(&b);
    var message = registry.MessagePreDeliverPayload{ .source_id = 1, .target = "#test", .text = "hi", .approved = false };
    try testing.expect(!first.approve(.message_pre_deliver, &a, &message));
    try testing.expectEqual(@as(usize, 0), a.hooks);
    var info = registry.ClientRegisteredPayload{ .client_id = 1 };
    _ = first.emit(.client_registered, &a, &info);
    try testing.expectEqual(@as(usize, 1), a.hooks);
    try testing.expectEqual(@as(u64, 2), first.bus.totalEmitted());
    try testing.expectEqual(@as(u64, 0), second.bus.totalEmitted());
    try testing.expectEqual(registry.DispatchResult.handled, try first.dispatch(&a, "TESTALIAS", &.{}, .{ .registered = true, .oper = false }));
    try testing.expectEqual(@as(usize, 1), a.commands);
    first.stop(&a);
    try testing.expect(second.available(0));
}

test "module runtime: empty manifest and adopted generation preserve lifecycle rules" {
    var runtime = Runtime(&.{}).init(15);
    var probe = Probe{};
    const candidate: u64 = 42;
    const cold = runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 16 });
    try testing.expectEqual(error.InvalidModuleRuntimeState, cold.rejected.err);
    try runtime.start(&probe);
    try testing.expect(!runtime.available(0));
    try testing.expectEqual(@as(u64, 15), runtime.generation());
    try testing.expectEqual(PrepareOutcome.prepared, runtime.prepareReload(&probe, .{ .config = &candidate, .generation = 16 }));
    try runtime.commitReload();
    try testing.expectEqual(@as(u64, 16), runtime.generation());
    runtime.stop(&probe);
    try testing.expectEqualStrings("", probe.seen());
}

test "module runtime: register failure blocks required child before any init owns resources" {
    const F = struct {
        fn fail(ctx: *anyopaque) anyerror!void {
            Probe.from(ctx).note('!');
            return error.RegisterRejected;
        }
    };
    const mods = comptime [_]registry.Module{
        .{ .id = "base", .required_at_boot = false, .on_register = F.fail },
        fake(1, true, &.{"base"}),
    };
    var runtime: Runtime(&mods) = .{};
    var probe = Probe{};
    try testing.expectError(error.ModuleStartupFailed, runtime.start(&probe));
    try testing.expectEqualStrings("!", probe.seen());
    try testing.expectEqual(State.failed, runtime.stateOf(0));
    try testing.expectEqual(State.blocked, runtime.stateOf(1));
    try testing.expectEqual(@as(?usize, 0), runtime.health(1).blocked_by);
}

test "module runtime: startup diagnostic selects required cause after optional failure" {
    const F = struct {
        fn optionalFailure(ctx: *anyopaque) anyerror!void {
            Probe.from(ctx).note('o');
            return error.OptionalRejected;
        }
        fn requiredFailure(ctx: *anyopaque) anyerror!void {
            Probe.from(ctx).note('r');
            return error.RequiredRejected;
        }
    };
    const mods = comptime [_]registry.Module{
        .{ .id = "optional", .required_at_boot = false, .on_register = F.optionalFailure },
        .{ .id = "required", .required_at_boot = true, .on_register = F.requiredFailure },
    };
    var runtime: Runtime(&mods) = .{};
    var probe = Probe{};
    try testing.expectError(error.ModuleStartupFailed, runtime.start(&probe));
    try testing.expectEqualStrings("or", probe.seen());
    try testing.expectEqualStrings("optional", runtime.firstFailure().?.id);
    const startup = runtime.startupFailure().?;
    try testing.expectEqualStrings("required", startup.id);
    try testing.expectEqual(@as(?lifecycle.Phase, .register), startup.failed_phase);
    try testing.expectEqual(@as(?anyerror, error.RequiredRejected), startup.last_error);
}

test "module runtime accepts the complete production manifest" {
    const manifest = @import("modules/manifest.zig");
    const Live = Runtime(&manifest.enabled);
    const runtime = Live.init(0);
    try std.testing.expect(!runtime.engaged());
    try std.testing.expectEqual(@as(usize, 0), runtime.degradedCount());
    inline for (manifest.enabled, 0..) |_, index| try std.testing.expect(!runtime.available(index));
    try std.testing.expectEqual(manifest.Live.commands.len, Live.Registry.commands.len);
}
