// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Module bus — typed event delivery between SerpentRegistry modules.
//!
//! The bus exists so a module can observe or veto a server event without the
//! server growing another bespoke call site. `server.zig` emits an event once;
//! every subscribed module sees it, in a deterministic order, with no knowledge
//! of who else subscribed. See `docs/architecture/MODULE-SYSTEM.md`.
//!
//! It differs from `registry.Registry.callHook` in three ways that matter:
//!
//! 1. **Per-hook partitioned dispatch.** `callHook` walks the whole hook table
//!    and filters by id, so every emit costs O(all hooks in the daemon).
//!    `Bus` partitions the table by `HookId` at comptime, so an emit only
//!    touches the handlers actually bound to that event.
//! 2. **A veto is final.** `callHook` honours only a handler's `.stop` return,
//!    so a handler that sets `approved = false` and returns `.continue_` can be
//!    silently overridden by a later handler setting it back to `true`. On this
//!    bus `approve` stops the chain the moment `approved` goes false — the
//!    decision cannot be reversed by a subscriber that runs later.
//! 3. **Error policy is explicit and split by kind.** An informational emit
//!    swallows a handler error (a faulting subscriber must never break client
//!    registration); a veto-capable `approve` **fails closed** — a handler that
//!    errors has not approved anything, so the event is denied.
//!
//! Ordering is `(priority, load-order position)`: a lower `HookPriority` runs
//! first, and handlers of equal priority run in dependency order (see
//! `registry.loadOrder`), so a module's subscriber never runs before a
//! subscriber belonging to a module it depends on.
//!
//! Concurrency: a payload is owned by the emitting reactor during dispatch.
//! Managed daemons own `Bus.Instance` counters; compatibility namespace calls
//! use a process-global instance. Counters are relaxed atomics (statistics,
//! never a control input). An optional host-owned readiness gate controls entry.
const std = @import("std");
const registry = @import("registry.zig");

/// Number of distinct hook ids, used to size the counter arrays.
const hook_id_count = @typeInfo(registry.HookId).@"enum".field_names.len;

/// Per-hook delivery counters, exposed for `MODULES`/health introspection.
pub const HookStats = struct {
    /// Events emitted for this hook (whether or not anyone subscribed).
    emitted: u64 = 0,
    /// Handler invocations that returned an error.
    handler_errors: u64 = 0,
    /// Events denied — a subscriber vetoed, or failed closed by erroring.
    vetoed: u64 = 0,
    /// Comptime count of modules bound to this hook.
    subscribers: usize = 0,
    /// Unavailable subscribers skipped (information) or denied (veto).
    unavailable: u64 = 0,
};

/// Build the event bus for a comptime module set.
///
/// Tables are immutable; `Bus(mods).Instance` owns mutable diagnostic counters.
/// Static methods retain legacy process-global counters for unconverted callers.
pub fn Bus(comptime mods: []const registry.Module) type {
    return struct {
        // Compatibility namespace for callers not yet attached to a runtime.
        // Managed daemons own Instance explicitly, so their counters are isolated.
        var legacy: Instance = .{};

        pub const Instance = struct {
            emitted: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0)),
            handler_errors: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0)),
            vetoed: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0)),
            unavailable: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0)),

            /// Informational delivery skips unavailable subscribers. Veto-capable
            /// hooks must go through approve, where unavailability fails closed.
            pub fn emit(self: *Instance, comptime id: registry.HookId, ctx: *anyopaque, payload: registry.HookPayload(id), gate: ?registry.ModuleGate) registry.HookResult {
                comptime if (registry.hookIsVetoCapable(id)) @compileError("module_bus.emit: veto-capable hooks require approve()");
                const slot = comptime @backingInt(id);
                _ = self.emitted[slot].fetchAdd(1, .monotonic);
                const erased: *anyopaque = @ptrCast(payload);
                inline for (comptime bindingsFor(mods, id)) |entry| {
                    if (gate == null or gate.?.allows(entry.module_index)) {
                        const result = entry.binding.handler(ctx, erased) catch blk: {
                            _ = self.handler_errors[slot].fetchAdd(1, .monotonic);
                            break :blk registry.HookResult.continue_;
                        };
                        if (result == .stop) return .stop;
                    } else {
                        _ = self.unavailable[slot].fetchAdd(1, .monotonic);
                    }
                }
                return .continue_;
            }

            pub fn approve(self: *Instance, comptime id: registry.HookId, ctx: *anyopaque, payload: registry.HookPayload(id), gate: ?registry.ModuleGate) bool {
                comptime if (!registry.hookIsVetoCapable(id)) @compileError("module_bus.approve: informational hooks require emit()");
                const slot = comptime @backingInt(id);
                _ = self.emitted[slot].fetchAdd(1, .monotonic);
                // A caller may already have denied the operation. No subscriber
                // may resurrect that decision, including the first subscriber.
                if (!payload.approved) {
                    _ = self.vetoed[slot].fetchAdd(1, .monotonic);
                    return false;
                }
                const erased: *anyopaque = @ptrCast(payload);
                inline for (comptime bindingsFor(mods, id)) |entry| {
                    if (gate) |availability| {
                        if (!availability.allows(entry.module_index)) {
                            _ = self.unavailable[slot].fetchAdd(1, .monotonic);
                            _ = self.vetoed[slot].fetchAdd(1, .monotonic);
                            payload.approved = false;
                            return false;
                        }
                    }
                    const result = entry.binding.handler(ctx, erased) catch {
                        _ = self.handler_errors[slot].fetchAdd(1, .monotonic);
                        _ = self.vetoed[slot].fetchAdd(1, .monotonic);
                        payload.approved = false;
                        return false;
                    };
                    if (!payload.approved) {
                        _ = self.vetoed[slot].fetchAdd(1, .monotonic);
                        return false;
                    }
                    if (result == .stop) break;
                }
                return payload.approved;
            }

            /// Fields are sampled independently; this is diagnostic state.
            pub fn stats(self: *const Instance, comptime id: registry.HookId) HookStats {
                const slot = comptime @backingInt(id);
                return .{
                    .emitted = self.emitted[slot].load(.monotonic),
                    .handler_errors = self.handler_errors[slot].load(.monotonic),
                    .vetoed = self.vetoed[slot].load(.monotonic),
                    .unavailable = self.unavailable[slot].load(.monotonic),
                    .subscribers = comptime bindingsFor(mods, id).len,
                };
            }

            pub fn totalEmitted(self: *const Instance) u64 {
                var total: u64 = 0;
                for (&self.emitted) |*counter| total +%= counter.load(.monotonic);
                return total;
            }

            pub fn totalHandlerErrors(self: *const Instance) u64 {
                var total: u64 = 0;
                for (&self.handler_errors) |*counter| total +%= counter.load(.monotonic);
                return total;
            }

            /// Only use with no concurrent emitters (tests or before startup).
            pub fn resetStats(self: *Instance) void {
                for (&self.emitted, &self.handler_errors, &self.vetoed, &self.unavailable) |*a, *b, *c, *d| {
                    a.store(0, .monotonic);
                    b.store(0, .monotonic);
                    c.store(0, .monotonic);
                    d.store(0, .monotonic);
                }
            }
        };

        pub fn bindings(comptime id: registry.HookId) []const registry.HookEntry {
            return comptime bindingsFor(mods, id);
        }

        pub fn subscriberCount(comptime id: registry.HookId) usize {
            return comptime bindingsFor(mods, id).len;
        }

        pub fn emit(comptime id: registry.HookId, ctx: *anyopaque, payload: registry.HookPayload(id)) registry.HookResult {
            return legacy.emit(id, ctx, payload, null);
        }

        pub fn approve(comptime id: registry.HookId, ctx: *anyopaque, payload: registry.HookPayload(id)) bool {
            return legacy.approve(id, ctx, payload, null);
        }

        pub fn stats(comptime id: registry.HookId) HookStats {
            return legacy.stats(id);
        }

        pub fn totalEmitted() u64 {
            return legacy.totalEmitted();
        }

        pub fn totalHandlerErrors() u64 {
            return legacy.totalHandlerErrors();
        }

        pub fn resetStats() void {
            legacy.resetStats();
        }
    };
}

/// Subscribers bound to `id`, ordered by `(priority, load-order position)`.
///
/// Built by walking the module set in dependency order and then stably sorting
/// by priority, so equal-priority handlers retain dependency order rather than
/// raw manifest order.
fn bindingsFor(
    comptime mods: []const registry.Module,
    comptime id: registry.HookId,
) []const registry.HookEntry {
    comptime {
        @setEvalBranchQuota(20_000 + mods.len * mods.len * 64);

        var total: usize = 0;
        for (mods) |module| {
            for (module.hooks) |binding| {
                if (binding.hook == id) total += 1;
            }
        }
        if (total == 0) return &.{};

        var rows: [total]registry.HookEntry = undefined;
        var n: usize = 0;
        for (registry.loadOrder(mods)) |module_index| {
            const module = mods[module_index];
            for (module.hooks) |binding| {
                if (binding.hook != id) continue;
                rows[n] = .{ .module_id = module.id, .module_index = module_index, .binding = binding };
                n += 1;
            }
        }

        // Stable insertion sort on priority alone: `rows` is already in
        // dependency order, so equal priorities keep that order.
        var i: usize = 1;
        while (i < total) : (i += 1) {
            var j: usize = i;
            while (j > 0 and
                @backingInt(rows[j].binding.priority) < @backingInt(rows[j - 1].binding.priority)) : (j -= 1)
            {
                const swap = rows[j];
                rows[j] = rows[j - 1];
                rows[j - 1] = swap;
            }
        }

        const frozen = rows;
        return &frozen;
    }
}

// ---------------------------------------------------------------------------
// Tests
//
// These cover the bus mechanism itself (ordering, veto finality, error policy)
// with hooks bound to trivial local modules. `module_harness.zig` holds the
// wider fake-module scenarios that exercise the bus together with the
// lifecycle driver.
// ---------------------------------------------------------------------------

const testing = std.testing;

const Recorder = struct {
    seen: [8]u8 = @splat(0),
    len: usize = 0,

    fn note(self: *Recorder, tag: u8) void {
        if (self.len < self.seen.len) {
            self.seen[self.len] = tag;
            self.len += 1;
        }
    }

    fn order(self: *const Recorder) []const u8 {
        return self.seen[0..self.len];
    }

    fn from(ctx: *anyopaque) *Recorder {
        return @ptrCast(@alignCast(ctx));
    }
};

fn noteLate(ctx: *anyopaque, _: *anyopaque) anyerror!registry.HookResult {
    Recorder.from(ctx).note('L');
    return .continue_;
}

fn noteEarly(ctx: *anyopaque, _: *anyopaque) anyerror!registry.HookResult {
    Recorder.from(ctx).note('E');
    return .continue_;
}

fn noteFirst(ctx: *anyopaque, _: *anyopaque) anyerror!registry.HookResult {
    Recorder.from(ctx).note('F');
    return .continue_;
}

/// Denies without asking the chain to stop — the shape `callHook` mishandles.
fn quietVeto(ctx: *anyopaque, payload: *anyopaque) anyerror!registry.HookResult {
    Recorder.from(ctx).note('V');
    const typed: *registry.ChannelPreJoinPayload = @ptrCast(@alignCast(payload));
    typed.approved = false;
    return .continue_;
}

/// Approves unconditionally. Must never run after a denial.
fn lateApprove(ctx: *anyopaque, payload: *anyopaque) anyerror!registry.HookResult {
    Recorder.from(ctx).note('A');
    const typed: *registry.ChannelPreJoinPayload = @ptrCast(@alignCast(payload));
    typed.approved = true;
    return .continue_;
}

fn faulting(ctx: *anyopaque, _: *anyopaque) anyerror!registry.HookResult {
    Recorder.from(ctx).note('X');
    return error.SubscriberFault;
}

const orderModule = registry.Module{
    .id = "bus.order",
    .hooks = &.{
        .{ .hook = .client_registered, .priority = .late, .handler = noteLate },
        .{ .hook = .client_registered, .priority = .first, .handler = noteFirst },
        .{ .hook = .client_registered, .priority = .early, .handler = noteEarly },
    },
};

const vetoOrderModule = registry.Module{
    .id = "bus.veto",
    .hooks = &.{
        .{ .hook = .channel_pre_join, .priority = .early, .handler = quietVeto },
        .{ .hook = .channel_pre_join, .priority = .late, .handler = lateApprove },
    },
};

const faultingVetoModule = registry.Module{
    .id = "bus.fault",
    .hooks = &.{
        .{ .hook = .channel_pre_join, .priority = .early, .handler = faulting },
        .{ .hook = .channel_pre_join, .priority = .late, .handler = lateApprove },
    },
};

const faultingInfoModule = registry.Module{
    .id = "bus.faultinfo",
    .hooks = &.{
        .{ .hook = .client_registered, .priority = .early, .handler = faulting },
        .{ .hook = .client_registered, .priority = .late, .handler = noteLate },
    },
};

test "emit delivers in priority order" {
    const B = Bus(&.{orderModule});
    var rec = Recorder{};
    var payload = registry.ClientRegisteredPayload{ .client_id = 1, .nick = "ada" };

    try testing.expectEqual(registry.HookResult.continue_, B.emit(.client_registered, &rec, &payload));
    try testing.expectEqualStrings("FEL", rec.order());
}

test "a quiet veto is final — the late approver never runs" {
    const B = Bus(&.{vetoOrderModule});
    var rec = Recorder{};
    var payload = registry.ChannelPreJoinPayload{ .client_id = 7, .channel = "#zig" };

    // The vetoing handler returns .continue_, so only the bus's own
    // stop-on-denial rule prevents `lateApprove` from reversing the decision.
    try testing.expect(!B.approve(.channel_pre_join, &rec, &payload));
    try testing.expect(!payload.approved);
    try testing.expectEqualStrings("V", rec.order());
}

test "approve fails closed when a subscriber errors" {
    const B = Bus(&.{faultingVetoModule});
    B.resetStats();
    var rec = Recorder{};
    var payload = registry.ChannelPreJoinPayload{ .client_id = 9, .channel = "#fail" };

    try testing.expect(!B.approve(.channel_pre_join, &rec, &payload));
    try testing.expect(!payload.approved);
    // Chain stopped at the fault; the approver did not get to run.
    try testing.expectEqualStrings("X", rec.order());

    const s = B.stats(.channel_pre_join);
    try testing.expectEqual(@as(u64, 1), s.handler_errors);
    try testing.expectEqual(@as(u64, 1), s.vetoed);
}

test "emit isolates a faulting subscriber and keeps delivering" {
    const B = Bus(&.{faultingInfoModule});
    B.resetStats();
    var rec = Recorder{};
    var payload = registry.ClientRegisteredPayload{ .client_id = 3, .nick = "grace" };

    try testing.expectEqual(registry.HookResult.continue_, B.emit(.client_registered, &rec, &payload));
    // The fault was swallowed and the next subscriber still ran.
    try testing.expectEqualStrings("XL", rec.order());

    const s = B.stats(.client_registered);
    try testing.expectEqual(@as(u64, 1), s.emitted);
    try testing.expectEqual(@as(u64, 1), s.handler_errors);
    try testing.expectEqual(@as(u64, 0), s.vetoed);
}

test "an unsubscribed hook still counts the emit and reports no subscribers" {
    const B = Bus(&.{orderModule});
    B.resetStats();
    var rec = Recorder{};
    var payload = registry.ClientQuitPayload{ .client_id = 4, .reason = "bye" };

    try testing.expectEqual(registry.HookResult.continue_, B.emit(.client_quit, &rec, &payload));
    try testing.expectEqual(@as(usize, 0), B.subscriberCount(.client_quit));
    try testing.expectEqual(@as(u64, 1), B.stats(.client_quit).emitted);
    try testing.expectEqual(@as(usize, 0), rec.len);
}

test "equal-priority subscribers run in dependency order, not manifest order" {
    // `late` is declared FIRST in the manifest but requires `base`, so the
    // load order — and therefore the dispatch order — puts `base` ahead of it.
    const base = registry.Module{
        .id = "bus.base",
        .hooks = &.{.{ .hook = .client_registered, .handler = noteFirst }},
    };
    const dependent = registry.Module{
        .id = "bus.dependent",
        .requires = &.{"bus.base"},
        .hooks = &.{.{ .hook = .client_registered, .handler = noteLate }},
    };

    const B = Bus(&.{ dependent, base });
    var rec = Recorder{};
    var payload = registry.ClientRegisteredPayload{ .client_id = 5, .nick = "linus" };

    _ = B.emit(.client_registered, &rec, &payload);
    try testing.expectEqualStrings("FL", rec.order());
}

test "bindings partition the hook table by id" {
    const B = Bus(&.{ orderModule, vetoOrderModule });
    try testing.expectEqual(@as(usize, 3), B.subscriberCount(.client_registered));
    try testing.expectEqual(@as(usize, 2), B.subscriberCount(.channel_pre_join));
    try testing.expectEqual(@as(usize, 0), B.subscriberCount(.mesh_peer_up));

    // Every partitioned row really belongs to the requested hook.
    for (B.bindings(.client_registered)) |entry| {
        try testing.expectEqual(registry.HookId.client_registered, entry.binding.hook);
    }
}
