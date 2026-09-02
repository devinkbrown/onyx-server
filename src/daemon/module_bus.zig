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
//! Concurrency: dispatch itself is stateless and re-entrant — the bus owns no
//! mutable per-event state, and a payload is owned by the emitting reactor for
//! the duration of the call. Only the diagnostic counters are shared, and they
//! are relaxed atomics (statistics, never a control input).
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
};

/// Build the event bus for a comptime module set.
///
/// `Bus(mods)` is a namespace, not a value: the subscriber partition is a
/// comptime table and the counters are process-global, exactly like the
/// registry tables themselves. Instantiating it twice with the same `mods`
/// yields the same type, so `server.zig` and an introspection module observe
/// the same counters without threading a handle between them.
pub fn Bus(comptime mods: []const registry.Module) type {
    return struct {
        var emitted: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0));
        var handler_errors: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0));
        var vetoed: [hook_id_count]std.atomic.Value(u64) = @splat(.init(0));

        /// Handlers bound to `id`, in dispatch order. Empty when nothing
        /// subscribes, which lets an emit compile down to a counter bump.
        pub fn bindings(comptime id: registry.HookId) []const registry.HookEntry {
            return comptime bindingsFor(mods, id);
        }

        /// How many modules subscribe to `id`.
        pub fn subscriberCount(comptime id: registry.HookId) usize {
            return comptime bindingsFor(mods, id).len;
        }

        /// Deliver an informational event to every subscriber.
        ///
        /// Returns `.stop` when a handler asked to end the chain, otherwise
        /// `.continue_`. Handler errors are counted and swallowed: an
        /// informational event has no decision to fail closed on, and a broken
        /// subscriber must not take down the emitting path.
        ///
        /// Use `approve` instead for any event whose payload carries
        /// `approved` — emitting a veto-capable event through here would
        /// discard the veto.
        pub fn emit(
            comptime id: registry.HookId,
            ctx: *anyopaque,
            payload: registry.HookPayload(id),
        ) registry.HookResult {
            const slot = comptime @intFromEnum(id);
            _ = emitted[slot].fetchAdd(1, .monotonic);

            const erased: *anyopaque = @ptrCast(payload);
            inline for (comptime bindingsFor(mods, id)) |entry| {
                // `catch |...| .continue_` rather than `catch { continue; }`:
                // `continue` inside an `inline for` is comptime control flow,
                // and a handler error is a runtime condition. Treating the
                // error as `.continue_` is the same behaviour — count it and
                // move to the next subscriber.
                const result = entry.binding.handler(ctx, erased) catch blk: {
                    _ = handler_errors[slot].fetchAdd(1, .monotonic);
                    break :blk registry.HookResult.continue_;
                };
                if (result == .stop) return .stop;
            }
            return .continue_;
        }

        /// Put a veto-capable event to every subscriber and return whether it
        /// is approved.
        ///
        /// The caller passes a payload whose `approved` still holds its `true`
        /// default. Dispatch stops at the FIRST denial — either a handler
        /// clearing `approved`, or a handler erroring (which fails closed) — so
        /// a later subscriber can never resurrect a denied event. A handler
        /// returning `.stop` ends the chain while keeping the current verdict.
        ///
        /// Passing an informational hook id is a COMPILE error: its payload has
        /// no `approved` field, so the "veto" would be silently dropped.
        pub fn approve(
            comptime id: registry.HookId,
            ctx: *anyopaque,
            payload: registry.HookPayload(id),
        ) bool {
            comptime if (!registry.hookIsVetoCapable(id)) @compileError(
                "module_bus.approve: hook '" ++ @tagName(id) ++
                    "' is informational (no `approved` field) — use emit() instead",
            );

            const slot = comptime @intFromEnum(id);
            _ = emitted[slot].fetchAdd(1, .monotonic);

            const erased: *anyopaque = @ptrCast(payload);
            inline for (comptime bindingsFor(mods, id)) |entry| {
                const result = entry.binding.handler(ctx, erased) catch {
                    // Fail closed: a subscriber that faulted has not approved.
                    _ = handler_errors[slot].fetchAdd(1, .monotonic);
                    _ = vetoed[slot].fetchAdd(1, .monotonic);
                    payload.approved = false;
                    return false;
                };
                if (!payload.approved) {
                    _ = vetoed[slot].fetchAdd(1, .monotonic);
                    return false;
                }
                if (result == .stop) break;
            }
            return payload.approved;
        }

        /// Diagnostic snapshot for one hook. Fields are read independently, so
        /// a concurrent emit may be reflected in some counters and not others;
        /// this is a statistics view, never a control input.
        pub fn stats(comptime id: registry.HookId) HookStats {
            const slot = comptime @intFromEnum(id);
            return .{
                .emitted = emitted[slot].load(.monotonic),
                .handler_errors = handler_errors[slot].load(.monotonic),
                .vetoed = vetoed[slot].load(.monotonic),
                .subscribers = comptime bindingsFor(mods, id).len,
            };
        }

        /// Total events emitted across every hook.
        pub fn totalEmitted() u64 {
            var total: u64 = 0;
            for (&emitted) |*counter| total += counter.load(.monotonic);
            return total;
        }

        /// Total handler errors across every hook — a non-zero value means some
        /// subscriber is faulting and is worth surfacing to an operator.
        pub fn totalHandlerErrors() u64 {
            var total: u64 = 0;
            for (&handler_errors) |*counter| total += counter.load(.monotonic);
            return total;
        }

        /// Zero every counter. Tests only: the counters are process-global, so
        /// a test that asserts on them must start from a known baseline.
        pub fn resetStats() void {
            for (&emitted, &handler_errors, &vetoed) |*a, *b, *c| {
                a.store(0, .monotonic);
                b.store(0, .monotonic);
                c.store(0, .monotonic);
            }
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
                rows[n] = .{ .module_id = module.id, .binding = binding };
                n += 1;
            }
        }

        // Stable insertion sort on priority alone: `rows` is already in
        // dependency order, so equal priorities keep that order.
        var i: usize = 1;
        while (i < total) : (i += 1) {
            var j: usize = i;
            while (j > 0 and
                @intFromEnum(rows[j].binding.priority) < @intFromEnum(rows[j - 1].binding.priority)) : (j -= 1)
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
