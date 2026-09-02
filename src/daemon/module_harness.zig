// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fake-module test harness for the SerpentRegistry module system.
//!
//! The live modules in `modules/` are wired to the real daemon, so they cannot
//! be used to test the *module system itself*: you cannot ask `channel_ops` to
//! fail its `on_reload` on demand, and you cannot assert a load order without
//! also asserting the whole manifest. This harness supplies synthetic modules
//! whose lifecycle and hook behaviour is scripted by a `Probe`, so the three
//! properties that actually matter can be pinned:
//!
//!   1. **Load order** — dependencies before dependents, priority as the
//!      tiebreak, declaration order as the final tiebreak.
//!   2. **REHASH rollback** — a mid-sweep `on_reload` failure rewinds every
//!      module that already accepted the new config, in LIFO order, after the
//!      previous configuration has been restored.
//!   3. **Bus delivery** — priority-ordered fan-out, and a veto that is FINAL
//!      (no later subscriber can resurrect a denied action).
//!
//! Every fake handler records what it did into the `Probe` the caller passes as
//! the erased lifecycle ctx, so a test asserts on an observed call *sequence*
//! rather than on a return code. The probe is fixed-capacity and
//! allocation-free: these run inside `zig build test` with no allocator.
//!
//! This file is test-only scaffolding — nothing here is referenced by the live
//! server. It is compiled by the test build so that a change to the module
//! system's contract breaks here first.

const std = @import("std");
const registry = @import("registry.zig");
const module_bus = @import("module_bus.zig");
const module_lifecycle = @import("module_lifecycle.zig");

/// One observable thing a fake module did.
pub const Step = enum {
    register,
    init,
    ready,
    /// `on_reload` during the forward sweep.
    reload,
    /// `on_reload` during a rollback sweep (after `restore` ran).
    rewind,
    deinit,
    /// A hook handler ran.
    hook,
    /// The host's `RestoreFn` ran — the boundary between the forward sweep and
    /// the rollback sweep.
    restore,
};

/// A single recorded call.
pub const Record = struct {
    module: []const u8,
    step: Step,
};

/// Scripted behaviour plus an observation log, passed to fakes as the erased
/// lifecycle ctx. Fixed capacity so the harness never allocates.
pub const Probe = struct {
    pub const capacity = 64;

    /// Pseudo-module id recorded for the host-level restore callback.
    pub const host_id = "<host>";

    log: [capacity]Record = undefined,
    len: usize = 0,
    /// Set when more than `capacity` calls were recorded. A test that trips
    /// this is asserting against a truncated sequence, so `sequence()` callers
    /// should check it rather than silently comparing a prefix.
    overflowed: bool = false,

    /// True once `restore` has run, which is what distinguishes a rollback
    /// `on_reload` from a forward one.
    in_rollback: bool = false,
    restores: usize = 0,

    /// Module id whose `on_init` returns `fail_err`.
    fail_init_on: ?[]const u8 = null,
    /// Module id whose FORWARD `on_reload` returns `fail_err`.
    fail_reload_on: ?[]const u8 = null,
    /// Module id whose ROLLBACK `on_reload` returns `fail_err`. Lets a test
    /// drive the "rewind itself failed" path, which must be reported without
    /// aborting the rest of the rewind.
    fail_rewind_on: ?[]const u8 = null,
    fail_err: anyerror = error.FakeModuleRejected,

    /// Module id whose hook handler flips `approved = false` on a veto-capable
    /// payload.
    veto_on: ?[]const u8 = null,
    /// Module id whose hook handler returns `fail_err`.
    fail_hook_on: ?[]const u8 = null,

    /// Clear the log and all scripted behaviour.
    pub fn reset(self: *Probe) void {
        self.* = .{};
    }

    /// Clear only the log, keeping the scripted behaviour.
    pub fn clearLog(self: *Probe) void {
        self.len = 0;
        self.overflowed = false;
    }

    fn push(self: *Probe, module: []const u8, step: Step) void {
        if (self.len == capacity) {
            self.overflowed = true;
            return;
        }
        self.log[self.len] = .{ .module = module, .step = step };
        self.len += 1;
    }

    /// Record a lifecycle phase and apply whatever failure the test scripted
    /// for it. A forward `reload` is logged as `.reload`; the same callback
    /// during a rollback is logged as `.rewind`.
    fn enter(self: *Probe, module: []const u8, step: Step) anyerror!void {
        switch (step) {
            .reload => {
                if (self.in_rollback) {
                    self.push(module, .rewind);
                    if (self.fail_rewind_on) |target| {
                        if (std.mem.eql(u8, target, module)) return self.fail_err;
                    }
                    return;
                }
                self.push(module, .reload);
                if (self.fail_reload_on) |target| {
                    if (std.mem.eql(u8, target, module)) return self.fail_err;
                }
            },
            .init => {
                self.push(module, .init);
                if (self.fail_init_on) |target| {
                    if (std.mem.eql(u8, target, module)) return self.fail_err;
                }
            },
            else => self.push(module, step),
        }
    }

    /// Everything recorded, in call order.
    pub fn sequence(self: *const Probe) []const Record {
        return self.log[0..self.len];
    }

    /// Comma-joined module ids for the calls matching `step`, in call order —
    /// e.g. `"base,mid,leaf"`. Lets a test assert an ordering with a single
    /// `expectEqualStrings`, which reports a readable diff when it breaks.
    /// Returns `error.HarnessBufferTooSmall` rather than truncating, so a
    /// too-small buffer can never masquerade as a passing prefix match.
    pub fn order(self: *const Probe, step: Step, buf: []u8) ![]const u8 {
        var written: usize = 0;
        for (self.sequence()) |record| {
            if (record.step != step) continue;
            const sep: usize = if (written == 0) 0 else 1;
            if (written + sep + record.module.len > buf.len) return error.HarnessBufferTooSmall;
            if (sep == 1) {
                buf[written] = ',';
                written += 1;
            }
            @memcpy(buf[written..][0..record.module.len], record.module);
            written += record.module.len;
        }
        return buf[0..written];
    }

    /// How many recorded calls match `step`.
    pub fn countOf(self: *const Probe, step: Step) usize {
        var total: usize = 0;
        for (self.sequence()) |record| {
            if (record.step == step) total += 1;
        }
        return total;
    }

    /// Whether `module` ever performed `step`.
    pub fn did(self: *const Probe, module: []const u8, step: Step) bool {
        for (self.sequence()) |record| {
            if (record.step == step and std.mem.eql(u8, record.module, module)) return true;
        }
        return false;
    }

    /// Position of `module`'s `step` in the log, for "A happened before B"
    /// assertions.
    pub fn indexOf(self: *const Probe, module: []const u8, step: Step) ?usize {
        for (self.sequence(), 0..) |record, i| {
            if (record.step == step and std.mem.eql(u8, record.module, module)) return i;
        }
        return null;
    }
};

fn probeFrom(ctx: *anyopaque) *Probe {
    return @ptrCast(@alignCast(ctx));
}

/// Host-level restore callback to hand to `driveReload`. Marks the probe as
/// being in a rollback sweep, which is what the fakes key their `.rewind`
/// logging off.
pub fn restore(ctx: *anyopaque) void {
    const probe = probeFrom(ctx);
    probe.in_rollback = true;
    probe.restores += 1;
    probe.push(Probe.host_id, .restore);
}

pub const restore_fn: module_lifecycle.RestoreFn = restore;

/// Shape of a fake module. Defaults give a module that implements every
/// lifecycle phase and no hooks — the common case for a load-order test.
pub const FakeOptions = struct {
    version: registry.Version = .{ .major = 1 },
    category: registry.Category = .feature,
    priority: registry.Priority = .normal,
    requires: []const []const u8 = &.{},
    optional_requires: []const []const u8 = &.{},

    with_register: bool = true,
    with_init: bool = true,
    with_ready: bool = true,
    with_reload: bool = true,
    with_deinit: bool = true,

    /// Hook to subscribe to, if any.
    hook: ?registry.HookId = null,
    hook_priority: registry.HookPriority = .normal,
    /// What the hook handler returns when it does not fail.
    hook_result: registry.HookResult = .continue_,
};

fn Lifecycles(comptime id: []const u8) type {
    return struct {
        fn onRegister(ctx: *anyopaque) anyerror!void {
            return probeFrom(ctx).enter(id, .register);
        }
        fn onInit(ctx: *anyopaque) anyerror!void {
            return probeFrom(ctx).enter(id, .init);
        }
        fn onReady(ctx: *anyopaque) anyerror!void {
            return probeFrom(ctx).enter(id, .ready);
        }
        fn onReload(ctx: *anyopaque) anyerror!void {
            return probeFrom(ctx).enter(id, .reload);
        }
        fn onDeinit(ctx: *anyopaque) void {
            probeFrom(ctx).push(id, .deinit);
        }
    };
}

fn Hooks(
    comptime id: []const u8,
    comptime hook_id: registry.HookId,
    comptime result: registry.HookResult,
) type {
    return struct {
        fn run(ctx: *anyopaque, payload: *anyopaque) anyerror!registry.HookResult {
            const probe = probeFrom(ctx);
            probe.push(id, .hook);

            if (probe.fail_hook_on) |target| {
                if (std.mem.eql(u8, target, id)) return probe.fail_err;
            }

            // Only a veto-capable payload has `approved`; asking a fake to veto
            // an informational hook is a test-authoring mistake, so it is a
            // compile error at the point the fake is built, not a silent no-op.
            if (comptime registry.hookIsVetoCapable(hook_id)) {
                if (probe.veto_on) |target| {
                    if (std.mem.eql(u8, target, id)) {
                        const typed: registry.HookPayload(hook_id) = @ptrCast(@alignCast(payload));
                        typed.approved = false;
                    }
                }
            }

            return result;
        }
    };
}

/// Build a fake module whose behaviour is driven by the `Probe` passed as ctx.
pub fn fake(comptime id: []const u8, comptime opts: FakeOptions) registry.Module {
    const L = Lifecycles(id);
    const hooks: []const registry.HookBinding = comptime if (opts.hook) |hook_id| &[_]registry.HookBinding{
        .{
            .hook = hook_id,
            .priority = opts.hook_priority,
            .handler = Hooks(id, hook_id, opts.hook_result).run,
        },
    } else &.{};

    return .{
        .id = id,
        .version = opts.version,
        .category = opts.category,
        .priority = opts.priority,
        .requires = opts.requires,
        .optional_requires = opts.optional_requires,
        .hooks = hooks,
        .on_register = if (opts.with_register) L.onRegister else null,
        .on_init = if (opts.with_init) L.onInit else null,
        .on_ready = if (opts.with_ready) L.onReady else null,
        .on_reload = if (opts.with_reload) L.onReload else null,
        .on_deinit = if (opts.with_deinit) L.onDeinit else null,
    };
}

// =========================================================================
// Load order
// =========================================================================

// Declared in an order that is deliberately NOT the dependency order.
const chain_mods: []const registry.Module = &.{
    fake("leaf", .{ .requires = &.{"mid"} }),
    fake("mid", .{ .requires = &.{"base"} }),
    fake("base", .{}),
};

test "harness: lifecycle phases run in dependency order, not manifest order" {
    const L = module_lifecycle.Lifecycle(chain_mods);
    L.resetHealth();

    var probe = Probe{};
    var buf: [64]u8 = undefined;

    L.driveRegister(&probe);
    try std.testing.expectEqualStrings("base,mid,leaf", try probe.order(.register, &buf));

    L.driveInit(&probe);
    try std.testing.expectEqualStrings("base,mid,leaf", try probe.order(.init, &buf));

    L.driveReady(&probe);
    try std.testing.expectEqualStrings("base,mid,leaf", try probe.order(.ready, &buf));

    try std.testing.expect(!probe.overflowed);
    for (0..chain_mods.len) |i| {
        try std.testing.expectEqual(module_lifecycle.State.ready, L.stateOf(i));
    }
    try std.testing.expectEqual(@as(usize, 0), L.degradedCount());
}

test "harness: teardown runs in reverse dependency order" {
    const L = module_lifecycle.Lifecycle(chain_mods);
    L.resetHealth();

    var probe = Probe{};
    var buf: [64]u8 = undefined;

    L.driveInit(&probe);
    probe.clearLog();

    // A module must be torn down before anything it depends on, so the
    // dependency (`base`) is destroyed last.
    L.driveDeinit(&probe);
    try std.testing.expectEqualStrings("leaf,mid,base", try probe.order(.deinit, &buf));
    for (0..chain_mods.len) |i| {
        try std.testing.expectEqual(module_lifecycle.State.stopped, L.stateOf(i));
    }
}

// =========================================================================
// Init failure
// =========================================================================

const init_fail_mods: []const registry.Module = &.{
    fake("if.first", .{}),
    fake("if.broken", .{}),
    fake("if.last", .{}),
};

test "harness: a failed on_init marks only that module degraded and is excluded from REHASH" {
    const L = module_lifecycle.Lifecycle(init_fail_mods);
    L.resetHealth();

    var probe = Probe{};
    probe.fail_init_on = "if.broken";

    L.driveInit(&probe);

    // A failing module must not abort the phase for its siblings: the daemon
    // runs degraded rather than refusing to boot.
    try std.testing.expect(probe.did("if.first", .init));
    try std.testing.expect(probe.did("if.broken", .init));
    try std.testing.expect(probe.did("if.last", .init));

    try std.testing.expectEqual(module_lifecycle.State.initialized, L.stateOf(0));
    try std.testing.expectEqual(module_lifecycle.State.failed, L.stateOf(1));
    try std.testing.expectEqual(module_lifecycle.State.initialized, L.stateOf(2));
    try std.testing.expectEqual(@as(usize, 1), L.degradedCount());

    const broken = L.health(1);
    try std.testing.expectEqualStrings("if.broken", broken.id);
    try std.testing.expectEqual(module_lifecycle.Phase.init, broken.failed_phase.?);
    try std.testing.expectEqual(error.FakeModuleRejected, broken.last_error.?);

    // A module that failed init holds no valid config-derived state, so a later
    // REHASH must skip it rather than reload it into an unknown state.
    probe.clearLog();
    probe.fail_init_on = null;
    const outcome = L.driveReload(&probe, null);
    try std.testing.expectEqual(@as(usize, 2), outcome.ok);
    try std.testing.expect(!probe.did("if.broken", .reload));
    try std.testing.expect(probe.did("if.first", .reload));
    try std.testing.expect(probe.did("if.last", .reload));
}

// =========================================================================
// REHASH rollback
// =========================================================================

const reload_mods: []const registry.Module = &.{
    fake("rl.a", .{ .priority = .first }),
    fake("rl.b", .{}),
    fake("rl.c", .{}),
    fake("rl.d", .{ .priority = .last }),
};

test "harness: a clean REHASH reloads every module in load order" {
    const L = module_lifecycle.Lifecycle(reload_mods);
    L.resetHealth();

    var probe = Probe{};
    var buf: [64]u8 = undefined;
    L.driveInit(&probe);
    probe.clearLog();

    const outcome = L.driveReload(&probe, restore_fn);
    try std.testing.expectEqual(@as(usize, 4), outcome.ok);
    try std.testing.expectEqualStrings("rl.a,rl.b,rl.c,rl.d", try probe.order(.reload, &buf));

    // No failure means no rollback: the previous config is never restored and
    // nothing is rewound.
    try std.testing.expectEqual(@as(usize, 0), probe.restores);
    try std.testing.expectEqual(@as(usize, 0), probe.countOf(.rewind));

    for (0..reload_mods.len) |i| {
        try std.testing.expectEqual(@as(u32, 1), L.health(i).reload_count);
        try std.testing.expectEqual(@as(u32, 0), L.health(i).rollback_count);
    }
}

test "harness: a mid-sweep REHASH failure restores config then rewinds LIFO" {
    const L = module_lifecycle.Lifecycle(reload_mods);
    L.resetHealth();

    var probe = Probe{};
    var buf: [64]u8 = undefined;
    L.driveInit(&probe);
    probe.clearLog();

    probe.fail_reload_on = "rl.c";
    const outcome = L.driveReload(&probe, restore_fn);

    const failure = switch (outcome) {
        .ok => return error.ExpectedReloadFailure,
        .failed => |f| f,
    };
    try std.testing.expectEqualStrings("rl.c", failure.module_id);
    try std.testing.expectEqual(error.FakeModuleRejected, failure.err);
    try std.testing.expect(failure.restore_invoked);
    try std.testing.expectEqual(@as(?[]const u8, null), failure.rollback_failed);

    // Only the modules that had ALREADY accepted the new config are rewound —
    // the failing module never applied it, and `rl.d` was never reached.
    try std.testing.expectEqual(@as(usize, 2), failure.rolled_back);
    try std.testing.expectEqualStrings("rl.a,rl.b,rl.c", try probe.order(.reload, &buf));
    try std.testing.expectEqualStrings("rl.b,rl.a", try probe.order(.rewind, &buf));
    try std.testing.expect(!probe.did("rl.d", .reload));

    // The old configuration must be back in place BEFORE any module is asked to
    // re-read it, otherwise a rewind re-applies the rejected config.
    const restore_at = probe.indexOf(Probe.host_id, .restore) orelse return error.MissingRestore;
    const first_rewind = probe.indexOf("rl.b", .rewind) orelse return error.MissingRewind;
    try std.testing.expect(restore_at < first_rewind);
    try std.testing.expectEqual(@as(usize, 1), probe.restores);

    // Health: the failing module is degraded and names the phase; the rewound
    // modules are still healthy and count the rollback.
    try std.testing.expectEqual(module_lifecycle.State.failed, L.stateOf(2));
    try std.testing.expectEqual(module_lifecycle.Phase.reload, L.health(2).failed_phase.?);
    try std.testing.expectEqual(@as(usize, 1), L.degradedCount());
    try std.testing.expectEqual(@as(u32, 1), L.health(0).rollback_count);
    try std.testing.expectEqual(@as(u32, 1), L.health(1).rollback_count);
    try std.testing.expectEqual(@as(u32, 0), L.health(3).rollback_count);
}

test "harness: a rewind that itself fails is reported without abandoning the rest" {
    const L = module_lifecycle.Lifecycle(reload_mods);
    L.resetHealth();

    var probe = Probe{};
    var buf: [64]u8 = undefined;
    L.driveInit(&probe);
    probe.clearLog();

    probe.fail_reload_on = "rl.c";
    probe.fail_rewind_on = "rl.b";
    const outcome = L.driveReload(&probe, restore_fn);

    const failure = switch (outcome) {
        .ok => return error.ExpectedReloadFailure,
        .failed => |f| f,
    };

    // `rl.b` failed to rewind, but `rl.a` must still be rewound: leaving a
    // module on a rejected config is worse than a reported rewind failure.
    try std.testing.expectEqualStrings("rl.b", failure.rollback_failed.?);
    try std.testing.expectEqualStrings("rl.b,rl.a", try probe.order(.rewind, &buf));
    try std.testing.expectEqual(@as(usize, 1), failure.rolled_back);

    // Both the forward failure and the rewind failure are visible in health.
    try std.testing.expectEqual(module_lifecycle.State.failed, L.stateOf(1));
    try std.testing.expectEqual(module_lifecycle.State.failed, L.stateOf(2));
    try std.testing.expectEqual(@as(usize, 2), L.degradedCount());
}

test "harness: REHASH without a restore hook reports restore_invoked=false" {
    const L = module_lifecycle.Lifecycle(reload_mods);
    L.resetHealth();

    var probe = Probe{};
    L.driveInit(&probe);
    probe.clearLog();

    probe.fail_reload_on = "rl.b";
    const outcome = L.driveReload(&probe, null);

    const failure = switch (outcome) {
        .ok => return error.ExpectedReloadFailure,
        .failed => |f| f,
    };
    // Honest reporting: with no restore hook the rewind re-ran handlers against
    // the NEW config, so the caller must know the config was never restored.
    try std.testing.expect(!failure.restore_invoked);
    try std.testing.expectEqual(@as(usize, 0), probe.restores);
    try std.testing.expectEqual(@as(usize, 1), failure.rolled_back);
}

// =========================================================================
// Bus delivery
// =========================================================================

const bus_mods: []const registry.Module = &.{
    // Declared last-to-first so a delivery that ignored priority would produce
    // the reverse of the expected order.
    fake("bus.late", .{ .hook = .channel_joined, .hook_priority = .last }),
    fake("bus.normal", .{ .hook = .channel_joined, .hook_priority = .normal }),
    fake("bus.first", .{ .hook = .channel_joined, .hook_priority = .first }),
};

test "harness: bus delivers an informational hook in priority order" {
    const B = module_bus.Bus(bus_mods);
    B.resetStats();

    var probe = Probe{};
    var buf: [64]u8 = undefined;
    var payload = registry.ChannelJoinedPayload{ .client_id = 7, .channel = "#zig" };

    try std.testing.expectEqual(@as(usize, 3), B.subscriberCount(.channel_joined));

    const result = B.emit(.channel_joined, &probe, &payload);
    try std.testing.expectEqual(registry.HookResult.continue_, result);
    try std.testing.expectEqualStrings("bus.first,bus.normal,bus.late", try probe.order(.hook, &buf));

    const stats = B.stats(.channel_joined);
    try std.testing.expectEqual(@as(u64, 1), stats.emitted);
    try std.testing.expectEqual(@as(u64, 0), stats.handler_errors);
    try std.testing.expectEqual(@as(usize, 3), stats.subscribers);
}

test "harness: an informational hook error is counted and delivery continues" {
    const B = module_bus.Bus(bus_mods);
    B.resetStats();

    var probe = Probe{};
    var buf: [64]u8 = undefined;
    probe.fail_hook_on = "bus.normal";
    var payload = registry.ChannelJoinedPayload{ .client_id = 7, .channel = "#zig" };

    const result = B.emit(.channel_joined, &probe, &payload);
    try std.testing.expectEqual(registry.HookResult.continue_, result);

    // One misbehaving informational subscriber must not silence the others.
    try std.testing.expectEqualStrings("bus.first,bus.normal,bus.late", try probe.order(.hook, &buf));
    try std.testing.expectEqual(@as(u64, 1), B.stats(.channel_joined).handler_errors);
    try std.testing.expectEqual(@as(u64, 1), B.totalHandlerErrors());
}

const stop_mods: []const registry.Module = &.{
    fake("stop.first", .{
        .hook = .channel_joined,
        .hook_priority = .first,
        .hook_result = .stop,
    }),
    fake("stop.after", .{ .hook = .channel_joined, .hook_priority = .late }),
};

test "harness: a .stop return halts the chain" {
    const B = module_bus.Bus(stop_mods);
    B.resetStats();

    var probe = Probe{};
    var payload = registry.ChannelJoinedPayload{ .client_id = 1, .channel = "#zig" };

    const result = B.emit(.channel_joined, &probe, &payload);
    try std.testing.expectEqual(registry.HookResult.stop, result);
    try std.testing.expect(probe.did("stop.first", .hook));
    try std.testing.expect(!probe.did("stop.after", .hook));
}

// A veto-capable chain where the vetoing module returns `.continue_` rather
// than `.stop` — the shape that must NOT let a later module resurrect a denied
// action.
const veto_mods: []const registry.Module = &.{
    fake("veto.guard", .{ .hook = .channel_pre_join, .hook_priority = .first }),
    fake("veto.after", .{ .hook = .channel_pre_join, .hook_priority = .last }),
};

test "harness: a veto is final even when the vetoing hook returns continue" {
    const B = module_bus.Bus(veto_mods);
    B.resetStats();

    var probe = Probe{};
    probe.veto_on = "veto.guard";
    var payload = registry.ChannelPreJoinPayload{ .client_id = 1, .channel = "#zig" };

    const approved = B.approve(.channel_pre_join, &probe, &payload);

    // The deny stands, and no later subscriber even runs — so none can flip
    // `approved` back to true. A chain that kept walking after a veto would let
    // the last writer win, turning a ban check into a suggestion.
    try std.testing.expect(!approved);
    try std.testing.expect(!payload.approved);
    try std.testing.expect(probe.did("veto.guard", .hook));
    try std.testing.expect(!probe.did("veto.after", .hook));
    try std.testing.expectEqual(@as(u64, 1), B.stats(.channel_pre_join).vetoed);
}

test "harness: an unvetoed veto-capable chain approves and runs every subscriber" {
    const B = module_bus.Bus(veto_mods);
    B.resetStats();

    var probe = Probe{};
    var buf: [64]u8 = undefined;
    var payload = registry.ChannelPreJoinPayload{ .client_id = 1, .channel = "#zig" };

    try std.testing.expect(B.approve(.channel_pre_join, &probe, &payload));
    try std.testing.expect(payload.approved);
    try std.testing.expectEqualStrings("veto.guard,veto.after", try probe.order(.hook, &buf));
    try std.testing.expectEqual(@as(u64, 0), B.stats(.channel_pre_join).vetoed);
}

test "harness: a failing hook on a veto-capable chain fails CLOSED" {
    const B = module_bus.Bus(veto_mods);
    B.resetStats();

    var probe = Probe{};
    probe.fail_hook_on = "veto.guard";
    var payload = registry.ChannelPreJoinPayload{ .client_id = 1, .channel = "#zig" };

    const approved = B.approve(.channel_pre_join, &probe, &payload);

    // A guard that could not decide must deny. Continuing past its error would
    // admit the action the guard exists to refuse.
    try std.testing.expect(!approved);
    try std.testing.expect(!payload.approved);
    try std.testing.expect(!probe.did("veto.after", .hook));

    const stats = B.stats(.channel_pre_join);
    try std.testing.expectEqual(@as(u64, 1), stats.handler_errors);
    try std.testing.expectEqual(@as(u64, 1), stats.vetoed);
}

test "harness: a hook with no subscribers is a no-op that still counts" {
    const B = module_bus.Bus(chain_mods); // chain_mods declare no hooks
    B.resetStats();

    var probe = Probe{};
    var payload = registry.ChannelJoinedPayload{ .client_id = 1, .channel = "#zig" };

    try std.testing.expectEqual(@as(usize, 0), B.subscriberCount(.channel_joined));
    try std.testing.expectEqual(registry.HookResult.continue_, B.emit(.channel_joined, &probe, &payload));
    try std.testing.expectEqual(@as(usize, 0), probe.len);
    try std.testing.expectEqual(@as(u64, 1), B.stats(.channel_joined).emitted);
}

test "harness: probe order() refuses to truncate rather than pass on a prefix" {
    var probe = Probe{};
    probe.push("aaaa", .hook);
    probe.push("bbbb", .hook);

    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.HarnessBufferTooSmall, probe.order(.hook, &tiny));
}
