// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper clock.

const std = @import("std");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const rwlock = @import("../../substrate/rwlock.zig");
const OroStore = @import("records.zig").OroStore;
const DurableOperSecurityTimeResult = @import("contracts.zig").DurableOperSecurityTimeResult;
const DurableOperSecurityNow = @import("contracts.zig").DurableOperSecurityNow;
const durable_oper_security_horizon_renewal_threshold_ms = @import("contracts.zig").durable_oper_security_horizon_renewal_threshold_ms;
const durable_oper_security_horizon_window_ms = @import("contracts.zig").durable_oper_security_horizon_window_ms;
const DurableOperSecurityHorizonCopy = @import("contracts.zig").DurableOperSecurityHorizonCopy;
const DurableOperSecurityHorizonResult = @import("contracts.zig").DurableOperSecurityHorizonResult;
const ProjectedDurableOperSecurity = @import("contracts.zig").ProjectedDurableOperSecurity;
const oper_availability_domain = @import("oper_availability.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    lock: *rwlock.RwLock,
    durable_oper_authority_state: *?*durable_oper_authority.State,
    durable_oper_availability_epoch: *u64,

    /// Persist a monotonically increasing security-time horizon.  The raw
    /// realtime sample must be covered by the requested horizon; all state and
    /// store allocations happen before the same durable cut used by OCG2
    /// records and revision floors.
    pub fn reserveDurableOperSecurityTime(
        self: Context,
        raw_now_ms: u64,
        reserve_until_ms: u64,
    ) DurableOperSecurityTimeResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (!state.servingAvailable() and state.securityTimeAuthorized()) return .unavailable;
        if (reserve_until_ms < raw_now_ms or reserve_until_ms <= state.securityReservedUntil())
            return .{ .preadmission = .invalid_record };

        var prepared = state.prepareSecurityTimeReservation(raw_now_ms, reserve_until_ms) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.CapacityExceeded, error.BoundsExceeded => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.GenerationExhausted, error.ReservationOverflow => .{ .preadmission = .exhausted },
            error.ReservationNotExtended => .{ .preadmission = .invalid_record },
            error.StateDestroyed => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_state };
            },
            error.StateUnavailable => .unavailable,
            else => .{ .preadmission = .store_failure },
        };
        defer prepared.update.abort();

        var durable_put = self.store.*.preparePut(
            .props,
            durable_oper_authority.snapshot_key,
            prepared.update.snapshot(),
        ) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.RecordTooLarge => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.SequenceExhausted => .{ .preadmission = .exhausted },
            error.IoAmbiguous => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .ambiguous_store };
            },
            error.StorePoisoned => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_store };
            },
            else => .{ .preadmission = .store_failure },
        };
        defer durable_put.abort();
        durable_put.commit() catch |err| {
            self.markDurableOperUnavailableLocked(state);
            return switch (err) {
                error.IoAmbiguous => .{ .restart_required = .ambiguous_store },
                else => .{ .restart_required = .fatal_store },
            };
        };

        if (!prepared.update.commitIntoChecked(state)) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }
        return .{ .committed = reserve_until_ms };
    }

    /// Compute effective security time from a realtime sample plus elapsed
    /// monotonic duration, refusing to serve a value beyond the last durable
    /// reservation.  Callers must extend the reservation before crossing it.
    pub fn durableOperSecurityNow(
        self: Context,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) DurableOperSecurityNow {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (!state.servingAvailable() or !state.securityTimeAuthorized()) return .unavailable;
        const reserved_until_ms = state.securityReservedUntil();
        if (reserved_until_ms == 0) return .unavailable;
        const boot_effective_ms = if (state.security_clock_started)
            state.security_boot_effective_ms
        else
            @max(raw_realtime_ms, state.securityFloor());
        const elapsed_effective_ms = std.math.add(
            u64,
            boot_effective_ms,
            monotonic_elapsed_ms,
        ) catch return .unavailable;
        const effective_ms = @max(
            @max(state.security_last_effective_ms, elapsed_effective_ms),
            raw_realtime_ms,
        );
        if (effective_ms > reserved_until_ms) return .unavailable;
        if (!state.security_clock_started) {
            state.security_clock_started = true;
            state.security_boot_effective_ms = boot_effective_ms;
        }
        state.security_last_effective_ms = effective_ms;
        return .{ .now = effective_ms };
    }

    pub fn projectDurableOperSecurityLocked(
        state: *const durable_oper_authority.State,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) error{ FirstSampleRequiresZeroElapsed, ElapsedOverflow }!ProjectedDurableOperSecurity {
        if (!state.security_clock_started) {
            if (monotonic_elapsed_ms != 0) return error.FirstSampleRequiresZeroElapsed;
            const boot_effective_ms = @max(raw_realtime_ms, state.securityFloor());
            return .{
                .boot_effective_ms = boot_effective_ms,
                .effective_ms = boot_effective_ms,
            };
        }
        const elapsed_effective_ms = std.math.add(
            u64,
            state.security_boot_effective_ms,
            monotonic_elapsed_ms,
        ) catch return error.ElapsedOverflow;
        return .{
            .boot_effective_ms = state.security_boot_effective_ms,
            .effective_ms = @max(
                @max(state.security_last_effective_ms, elapsed_effective_ms),
                raw_realtime_ms,
            ),
        };
    }

    pub fn durableOperSecurityHorizonCopy(
        effective_ms: u64,
        floor_ms: u64,
        reserved_until_ms: u64,
    ) DurableOperSecurityHorizonCopy {
        return .{
            .effective_now_ms = effective_ms,
            .security_floor_ms = floor_ms,
            .reserved_until_ms = reserved_until_ms,
            .remaining_ms = reserved_until_ms - effective_ms,
        };
    }

    pub fn publishDurableOperSecurityAnchorsLocked(
        state: *durable_oper_authority.State,
        projected: ProjectedDurableOperSecurity,
    ) void {
        if (!state.security_clock_started) {
            state.security_clock_started = true;
            state.security_boot_effective_ms = projected.boot_effective_ms;
        }
        state.security_last_effective_ms = projected.effective_ms;
    }

    /// Ensure the inactive durable security horizon covers the frozen window.
    /// One exclusive lock, no nested public Services calls.  A non-mutating
    /// projection decides current vs renew; anchors become visible only on
    /// the current path or after a successful durable cut.
    pub fn ensureDurableOperSecurityHorizon(
        self: Context,
        raw_realtime_ms: u64,
        monotonic_elapsed_ms: u64,
    ) DurableOperSecurityHorizonResult {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return .disabled;
        if (state.destroyed) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }
        if (!state.servingAvailable() and state.securityTimeAuthorized()) return .unavailable;

        const projected = projectDurableOperSecurityLocked(
            state,
            raw_realtime_ms,
            monotonic_elapsed_ms,
        ) catch |err| return switch (err) {
            error.FirstSampleRequiresZeroElapsed => .{ .preadmission = .invalid_record },
            error.ElapsedOverflow => .{ .preadmission = .exhausted },
        };

        const reserved_until_ms = state.securityReservedUntil();
        if (state.security_clock_started and projected.effective_ms > reserved_until_ms) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }

        const remaining_ms = if (reserved_until_ms >= projected.effective_ms)
            reserved_until_ms - projected.effective_ms
        else
            0;
        const needs_renew = !state.securityTimeAuthorized() or
            reserved_until_ms < projected.effective_ms or
            remaining_ms <= durable_oper_security_horizon_renewal_threshold_ms;
        if (!needs_renew) {
            publishDurableOperSecurityAnchorsLocked(state, projected);
            return .{ .current = durableOperSecurityHorizonCopy(
                projected.effective_ms,
                state.securityFloor(),
                reserved_until_ms,
            ) };
        }

        const base_ms = @max(
            @max(raw_realtime_ms, state.securityFloor()),
            reserved_until_ms,
        );
        const target_ms = std.math.add(
            u64,
            base_ms,
            durable_oper_security_horizon_window_ms,
        ) catch return .{ .preadmission = .exhausted };

        var prepared = state.prepareSecurityTimeReservation(raw_realtime_ms, target_ms) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.CapacityExceeded, error.BoundsExceeded => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.GenerationExhausted, error.ReservationOverflow => .{ .preadmission = .exhausted },
            error.ReservationNotExtended => .{ .preadmission = .invalid_record },
            error.StateDestroyed => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_state };
            },
            error.StateUnavailable => .unavailable,
            else => .{ .preadmission = .store_failure },
        };
        defer prepared.update.abort();
        if (!state.overlayPreparedSecurityAnchors(projected.boot_effective_ms, projected.effective_ms)) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }

        var durable_put = self.store.*.preparePut(
            .props,
            durable_oper_authority.snapshot_key,
            prepared.update.snapshot(),
        ) catch |err| return switch (err) {
            error.OutOfMemory => .{ .preadmission = .out_of_memory },
            error.RecordTooLarge => .{ .preadmission = .capacity },
            error.PreparedMutationActive => .{ .preadmission = .busy },
            error.SequenceExhausted => .{ .preadmission = .exhausted },
            error.IoAmbiguous => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .ambiguous_store };
            },
            error.StorePoisoned => blk: {
                self.markDurableOperUnavailableLocked(state);
                break :blk .{ .restart_required = .fatal_store };
            },
            else => .{ .preadmission = .store_failure },
        };
        defer durable_put.abort();
        durable_put.commit() catch |err| {
            self.markDurableOperUnavailableLocked(state);
            return switch (err) {
                error.IoAmbiguous => .{ .restart_required = .ambiguous_store },
                else => .{ .restart_required = .fatal_store },
            };
        };

        if (!prepared.update.commitIntoChecked(state)) {
            self.markDurableOperUnavailableLocked(state);
            return .{ .restart_required = .fatal_state };
        }
        return .{ .renewed = durableOperSecurityHorizonCopy(
            projected.effective_ms,
            state.securityFloor(),
            state.securityReservedUntil(),
        ) };
    }

    // Narrow projections for lock-held helpers and shared policy.
    pub fn markDurableOperUnavailableLocked(
        self: Context,
        state: *durable_oper_authority.State,
    ) void {
        return (oper_availability_domain.Context{ .lock = self.lock, .durable_oper_authority_state = self.durable_oper_authority_state, .durable_oper_availability_epoch = self.durable_oper_availability_epoch }).markDurableOperUnavailableLocked(state);
    }
};
