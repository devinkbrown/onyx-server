// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Module lifecycle driver — dependency-ordered phase execution, per-module
//! runtime health, and REHASH with LIFO rollback.
//!
//! `registry.Module` declares the phase hooks (`on_register`, `on_init`,
//! `on_ready`, `on_reload`, `on_deinit`); this file is what actually drives
//! them, in `registry.loadOrder` order, and what remembers how each module
//! fared. See `docs/architecture/MODULE-SYSTEM.md`.
//!
//! Two properties are the reason this is a separate driver rather than an
//! `inline for` at each call site:
//!
//! 1. **Dependency-ordered phases, LIFO teardown.** Startup phases run in
//!    dependency order so a module never initialises before something it
//!    requires. `on_deinit` runs in the exact reverse, which is ownership
//!    invariant (d) — a dependency outlives its dependents.
//! 2. **REHASH rolls back.** A configuration reload is all-or-nothing across
//!    modules. If module N's `on_reload` fails, the driver restores the
//!    previous configuration (via the caller's `RestoreFn`) and re-invokes
//!    `on_reload` on the modules that already succeeded, in reverse order, so
//!    the daemon ends up wholly on the old configuration rather than half-way
//!    between two. A partially-applied REHASH is the failure mode this exists
//!    to prevent.
//!
//! This is why `on_reload` MUST be idempotent and MUST re-derive from the
//! configuration rather than apply a delta: the rollback path calls it a second
//! time, with the configuration restored, and expects that to reproduce the
//! prior state.
//!
//! Concurrency: phase driving is single-threaded by construction — startup and
//! shutdown are pre/post-reactor, and REHASH is primary-reactor-gated work
//! (`rx() == &reactors[0]`). Health is read from *any* reactor thread by the
//! `MODULES` command, so every health field is an independent relaxed atomic
//! and `last_error` is stored as an error CODE (`@intFromError`) rather than a
//! string — an integer store is atomic where a `[]const u8` would not be.
const std = @import("std");
const registry = @import("registry.zig");

/// Integer representation of `anyerror`, used so `last_error` can live in an
/// atomic. Zero is not a valid error code, so it doubles as "no error".
const ErrorCode = @TypeOf(@intFromError(error.Sentinel));

/// Lifecycle phase, in the order a healthy module passes through them.
pub const Phase = enum(u8) {
    register,
    init,
    ready,
    reload,
    deinit,

    pub fn token(self: Phase) []const u8 {
        return @tagName(self);
    }
};

/// Runtime state of a single module.
pub const State = enum(u8) {
    /// No phase has been driven yet.
    unloaded,
    /// `on_register` completed (or the module declares none).
    registered,
    /// `on_init` completed.
    initialized,
    /// `on_ready` completed — the steady state for a healthy module.
    ready,
    /// A phase returned an error. `Health.failed_phase` says which.
    failed,
    /// Shut down via `on_deinit`.
    stopped,

    pub fn token(self: State) []const u8 {
        return @tagName(self);
    }
};

/// Point-in-time view of one module, for `MODULES` and for tests.
pub const Health = struct {
    /// Position in the dependency-ordered load sequence.
    load_position: usize,
    /// Index into the manifest.
    module_index: usize,
    id: []const u8,
    version: registry.Version,
    category: registry.Category,
    priority: registry.Priority,
    state: State,
    /// Successful configuration reloads applied to this module. Rollback
    /// re-invocations are counted separately and do not inflate this.
    reload_count: u32,
    /// Times this module's state was rewound by a failed REHASH.
    rollback_count: u32,
    /// Most recent phase error, or `null` if the module has never failed. It is
    /// NOT cleared by a later success, so an operator can still see that a past
    /// REHASH was rejected; `state` carries the current verdict.
    last_error: ?anyerror,
    /// Phase that produced `last_error`.
    failed_phase: ?Phase,

    /// Whether the module is in a state that needs operator attention.
    pub fn degraded(self: Health) bool {
        return self.state == .failed;
    }
};

/// Result of a REHASH sweep.
pub const ReloadOutcome = union(enum) {
    /// Every module accepted the new configuration. Payload is the number of
    /// modules that actually ran an `on_reload`.
    ok: usize,
    /// A module rejected it; the sweep was rolled back.
    failed: Failure,

    /// The error a failed sweep reported, or `null` when it succeeded.
    pub fn err(self: ReloadOutcome) ?anyerror {
        return switch (self) {
            .ok => null,
            .failed => |f| f.err,
        };
    }
};

/// Detail of a rejected REHASH.
pub const Failure = struct {
    /// Module whose `on_reload` returned the error.
    module_id: []const u8,
    module_index: usize,
    err: anyerror,
    /// Modules whose `on_reload` was re-invoked to rewind them.
    rolled_back: usize,
    /// Whether the caller's configuration-restore callback ran before rollback.
    /// When false, rollback re-derived from the configuration still in place —
    /// correct only if the caller restores it itself.
    restore_invoked: bool,
    /// A module that also failed *while rolling back*. Non-null here means the
    /// daemon could not be returned to a known-good state and the operator must
    /// be told to restart rather than trust the running configuration.
    rollback_failed: ?[]const u8 = null,
};

/// Called by the driver, before rollback, to put the previous configuration
/// back in place so re-invoked `on_reload` handlers re-derive the old state.
pub const RestoreFn = *const fn (ctx: *anyopaque) void;

/// Optional sink for phase diagnostics, so the driver does not have to depend
/// on `server.zig`'s logger (which would make this file unusable from a test).
pub const LogFn = *const fn (
    module_id: []const u8,
    phase: Phase,
    err: anyerror,
) void;

/// Build the lifecycle driver for a comptime module set.
///
/// Like `registry.Registry` and `module_bus.Bus`, this is a namespace whose
/// state is process-global: instantiating it twice with the same `mods` yields
/// the same type, so `server.zig` drives the phases and an introspection module
/// reads the resulting health without a handle being threaded between them.
pub fn Lifecycle(comptime mods: []const registry.Module) type {
    return struct {
        /// Dependency-ordered manifest indices.
        pub const load_order = registry.loadOrder(mods);
        /// Number of modules under management.
        pub const count = mods.len;
        /// The managed module set, for callers that want the comptime metadata.
        pub const modules = mods;

        var states: [count]std.atomic.Value(u8) = @splat(.init(@intFromEnum(State.unloaded)));
        var reload_counts: [count]std.atomic.Value(u32) = @splat(.init(0));
        var rollback_counts: [count]std.atomic.Value(u32) = @splat(.init(0));
        var last_errors: [count]std.atomic.Value(ErrorCode) = @splat(.init(0));
        /// `no_phase` means "never failed".
        var failed_phases: [count]std.atomic.Value(u8) = @splat(.init(no_phase));
        var log_sink: ?LogFn = null;

        const no_phase: u8 = std.math.maxInt(u8);

        /// Install a diagnostic sink for phase errors. `null` discards them
        /// (the driver's return values remain authoritative either way).
        pub fn setLogger(sink: ?LogFn) void {
            log_sink = sink;
        }

        /// Drive `on_register` across every module in dependency order.
        ///
        /// Registration is the only phase that may not fail the boot: a module
        /// that cannot register is recorded `.failed` and skipped by later
        /// phases, because refusing to start the daemon over one optional
        /// module's registration is a worse outcome than running without it.
        pub fn driveRegister(ctx: *anyopaque) void {
            drivePhase(ctx, .register);
        }

        /// Drive `on_init` across every module in dependency order.
        pub fn driveInit(ctx: *anyopaque) void {
            drivePhase(ctx, .init);
        }

        /// Drive `on_ready` across every module in dependency order.
        pub fn driveReady(ctx: *anyopaque) void {
            drivePhase(ctx, .ready);
        }

        fn drivePhase(ctx: *anyopaque, comptime phase: Phase) void {
            inline for (load_order) |module_index| {
                const module = mods[module_index];
                const fn_opt = comptime switch (phase) {
                    .register => module.on_register,
                    .init => module.on_init,
                    .ready => module.on_ready,
                    .reload, .deinit => @compileError("drivePhase: use driveReload/driveDeinit"),
                };
                // A module that already failed an earlier phase is not
                // advanced: its invariants are unknown, so calling further
                // phases on it would operate on state it never finished
                // building. Expressed as nested `if`s rather than `continue`
                // because `continue` inside an `inline for` is comptime control
                // flow, and these conditions are runtime.
                if (stateOf(module_index) != .failed) {
                    var advanced = true;
                    if (fn_opt) |f| {
                        f(ctx) catch |e| {
                            recordFailure(module_index, module.id, phase, e);
                            advanced = false;
                        };
                    }
                    if (advanced) setState(module_index, switch (phase) {
                        .register => .registered,
                        .init => .initialized,
                        .ready => .ready,
                        .reload, .deinit => unreachable,
                    });
                }
            }
        }

        /// Apply a configuration REHASH to every module, rolling back on the
        /// first refusal.
        ///
        /// On success every module that declares `on_reload` has re-derived its
        /// cached policy from the new configuration and its `reload_count` has
        /// advanced. On failure the driver calls `restore` (so the previous
        /// configuration is live again) and then re-invokes `on_reload` in
        /// REVERSE dependency order across the modules that had already
        /// accepted it — leaving the daemon wholly on the old configuration.
        ///
        /// Rollback deliberately continues past an error: a module left on the
        /// rejected configuration is worse than one that failed to rewind, so
        /// every module in the prefix is attempted and the first rewind failure
        /// is reported in `Failure.rollback_failed`.
        ///
        /// Never drops or mutates live connections — REHASH is zero-disconnect.
        pub fn driveReload(ctx: *anyopaque, restore: ?RestoreFn) ReloadOutcome {
            var ran: usize = 0;

            inline for (load_order, 0..) |module_index, position| {
                const module = mods[module_index];
                if (module.on_reload) |f| {
                    if (stateOf(module_index) != .failed) {
                        f(ctx) catch |e| {
                            recordFailure(module_index, module.id, .reload, e);
                            const rolled = rollback(ctx, position, restore);
                            return .{ .failed = .{
                                .module_id = module.id,
                                .module_index = module_index,
                                .err = e,
                                .rolled_back = rolled.count,
                                .restore_invoked = restore != null,
                                .rollback_failed = rolled.first_failure,
                            } };
                        };
                        _ = reload_counts[module_index].fetchAdd(1, .monotonic);
                        ran += 1;
                        // A module that previously failed a REHASH and has now
                        // accepted one is healthy again.
                        setState(module_index, .ready);
                    }
                }
            }

            return .{ .ok = ran };
        }

        const RollbackResult = struct {
            count: usize = 0,
            first_failure: ?[]const u8 = null,
        };

        /// Re-invoke `on_reload` over `load_order[0..prefix_len]` in reverse,
        /// after restoring the previous configuration.
        fn rollback(ctx: *anyopaque, prefix_len: usize, restore: ?RestoreFn) RollbackResult {
            if (restore) |r| r(ctx);

            var result = RollbackResult{};
            var i = prefix_len;
            while (i > 0) {
                i -= 1;
                const module_index = load_order[i];
                const module = mods[module_index];
                const f = module.on_reload orelse continue;
                if (stateOf(module_index) == .failed) continue;

                f(ctx) catch |e| {
                    recordFailure(module_index, module.id, .reload, e);
                    if (result.first_failure == null) result.first_failure = module.id;
                    continue;
                };
                _ = rollback_counts[module_index].fetchAdd(1, .monotonic);
                result.count += 1;
            }
            return result;
        }

        /// Drive `on_deinit` in REVERSE dependency order, so a module is torn
        /// down before anything it depends on. Cannot fail.
        pub fn driveDeinit(ctx: *anyopaque) void {
            inline for (0..count) |i| {
                const module_index = load_order[count - 1 - i];
                const module = mods[module_index];
                if (module.on_deinit) |f| f(ctx);
                setState(module_index, .stopped);
            }
        }

        /// Health of the module at `module_index` (a manifest index).
        pub fn health(module_index: usize) Health {
            return healthTable()[module_index];
        }

        /// Health of every module, in MANIFEST order. Allocation-free.
        pub fn healthTable() [count]Health {
            var out: [count]Health = undefined;
            inline for (mods, 0..) |module, i| {
                out[i] = .{
                    .load_position = positionOf(i),
                    .module_index = i,
                    .id = module.id,
                    .version = module.version,
                    .category = module.category,
                    .priority = module.priority,
                    .state = stateOf(i),
                    .reload_count = reload_counts[i].load(.monotonic),
                    .rollback_count = rollback_counts[i].load(.monotonic),
                    .last_error = errorOf(i),
                    .failed_phase = phaseOf(i),
                };
            }
            return out;
        }

        /// Whether any phase has been driven yet.
        ///
        /// `MODULES` needs this to tell "nothing has been started" apart from
        /// "modules are running but unhealthy": every state reads `.unloaded`
        /// in both cases, and only the second is a fault worth alarming an
        /// operator about.
        pub fn engaged() bool {
            for (0..count) |i| {
                if (stateOf(i) != .unloaded) return true;
            }
            return false;
        }

        /// Number of modules currently in `.failed`.
        pub fn degradedCount() usize {
            var total: usize = 0;
            for (0..count) |i| {
                if (stateOf(i) == .failed) total += 1;
            }
            return total;
        }

        /// Inverse of `load_order`: manifest index -> load position. Built at
        /// comptime so `positionOf` is a table lookup with no scan and no
        /// `unreachable` (`load_order` is a permutation of `0..count`).
        const position_table = blk: {
            var table: [count]usize = @splat(0);
            for (load_order, 0..) |module_index, position| table[module_index] = position;
            break :blk table;
        };

        /// Position of manifest index `module_index` in the load order.
        pub fn positionOf(module_index: usize) usize {
            return position_table[module_index];
        }

        pub fn stateOf(module_index: usize) State {
            return @enumFromInt(states[module_index].load(.monotonic));
        }

        fn errorOf(module_index: usize) ?anyerror {
            const code = last_errors[module_index].load(.monotonic);
            if (code == 0) return null;
            return @errorFromInt(code);
        }

        fn phaseOf(module_index: usize) ?Phase {
            const raw = failed_phases[module_index].load(.monotonic);
            if (raw == no_phase) return null;
            return @enumFromInt(raw);
        }

        fn setState(module_index: usize, state: State) void {
            states[module_index].store(@intFromEnum(state), .monotonic);
        }

        fn recordFailure(
            module_index: usize,
            module_id: []const u8,
            phase: Phase,
            e: anyerror,
        ) void {
            last_errors[module_index].store(@intFromError(e), .monotonic);
            failed_phases[module_index].store(@intFromEnum(phase), .monotonic);
            setState(module_index, .failed);
            if (log_sink) |sink| sink(module_id, phase, e);
        }

        /// Reset every module to `.unloaded` with no recorded error. Tests
        /// only: the health arrays are process-global, so a test asserting on
        /// them must start from a known baseline.
        pub fn resetHealth() void {
            for (0..count) |i| {
                setState(i, .unloaded);
                reload_counts[i].store(0, .monotonic);
                rollback_counts[i].store(0, .monotonic);
                last_errors[i].store(0, .monotonic);
                failed_phases[i].store(no_phase, .monotonic);
            }
            log_sink = null;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
//
// Mechanism-level coverage of the driver itself. The end-to-end fake-module
// scenarios (load order across a dependency graph, REHASH rollback across
// several modules, bus delivery) live in `module_harness.zig`.
// ---------------------------------------------------------------------------

const testing = std.testing;

const Counter = struct {
    inits: usize = 0,
    readies: usize = 0,
    deinits: usize = 0,

    fn from(ctx: *anyopaque) *Counter {
        return @ptrCast(@alignCast(ctx));
    }
};

fn bumpInit(ctx: *anyopaque) anyerror!void {
    Counter.from(ctx).inits += 1;
}

fn bumpReady(ctx: *anyopaque) anyerror!void {
    Counter.from(ctx).readies += 1;
}

fn bumpDeinit(ctx: *anyopaque) void {
    Counter.from(ctx).deinits += 1;
}

fn failInit(_: *anyopaque) anyerror!void {
    return error.InitRefused;
}

const plainModule = registry.Module{
    .id = "life.plain",
    .version = .{ .major = 1, .minor = 2, .patch = 3 },
    .on_init = bumpInit,
    .on_ready = bumpReady,
    .on_deinit = bumpDeinit,
};

const failingInitModule = registry.Module{
    .id = "life.badinit",
    .on_init = failInit,
    .on_ready = bumpReady,
};

test "phases advance a healthy module to ready and deinit stops it" {
    const L = Lifecycle(&.{plainModule});
    L.resetHealth();
    var ctx = Counter{};

    try testing.expectEqual(State.unloaded, L.stateOf(0));
    L.driveRegister(&ctx);
    // No on_register declared, so registration is a no-op advance.
    try testing.expectEqual(State.registered, L.stateOf(0));

    L.driveInit(&ctx);
    try testing.expectEqual(State.initialized, L.stateOf(0));
    L.driveReady(&ctx);
    try testing.expectEqual(State.ready, L.stateOf(0));

    try testing.expectEqual(@as(usize, 1), ctx.inits);
    try testing.expectEqual(@as(usize, 1), ctx.readies);

    L.driveDeinit(&ctx);
    try testing.expectEqual(State.stopped, L.stateOf(0));
    try testing.expectEqual(@as(usize, 1), ctx.deinits);
}

test "a failed init is recorded and later phases skip that module" {
    const L = Lifecycle(&.{failingInitModule});
    L.resetHealth();
    var ctx = Counter{};

    L.driveInit(&ctx);
    const h = L.health(0);
    try testing.expectEqual(State.failed, h.state);
    try testing.expectEqual(Phase.init, h.failed_phase.?);
    try testing.expectEqual(@as(anyerror, error.InitRefused), h.last_error.?);
    try testing.expect(h.degraded());

    // on_ready must NOT run for a module whose init failed.
    L.driveReady(&ctx);
    try testing.expectEqual(@as(usize, 0), ctx.readies);
    try testing.expectEqual(State.failed, L.stateOf(0));
    try testing.expectEqual(@as(usize, 1), L.degradedCount());
}

test "health reports comptime metadata alongside runtime state" {
    const L = Lifecycle(&.{plainModule});
    L.resetHealth();
    const h = L.health(0);
    try testing.expectEqualStrings("life.plain", h.id);
    try testing.expectEqual(@as(u16, 1), h.version.major);
    try testing.expectEqual(@as(u16, 2), h.version.minor);
    try testing.expectEqual(@as(u16, 3), h.version.patch);
    try testing.expectEqual(@as(usize, 0), h.load_position);
    try testing.expectEqual(@as(?anyerror, null), h.last_error);
}

test "load order is a permutation and positionOf agrees with it" {
    const alpha = registry.Module{ .id = "life.alpha", .requires = &.{"life.beta"} };
    const beta = registry.Module{ .id = "life.beta" };
    const L = Lifecycle(&.{ alpha, beta });

    // beta must be placed before alpha even though alpha is declared first.
    try testing.expectEqual(@as(usize, 1), L.load_order[0]);
    try testing.expectEqual(@as(usize, 0), L.load_order[1]);
    try testing.expectEqual(@as(usize, 1), L.positionOf(0));
    try testing.expectEqual(@as(usize, 0), L.positionOf(1));
}
