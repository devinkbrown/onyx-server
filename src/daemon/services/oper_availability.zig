// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper availability.

const std = @import("std");
const durable_oper_authority = @import("../durable_oper_authority.zig");
const rwlock = @import("../../substrate/rwlock.zig");

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    lock: *rwlock.RwLock,
    durable_oper_authority_state: *?*durable_oper_authority.State,
    durable_oper_availability_epoch: *u64,

    pub fn attachDurableOperAuthorityForTest(self: Context, state: *durable_oper_authority.State) void {
        if (!state.securityTimeAuthorized()) {
            var reservation = state.prepareSecurityTimeReservation(0, 1_000_000_000) catch unreachable;
            reservation.update.commitInto(state);
        }
        self.durable_oper_authority_state.* = state;
    }

    pub fn attachInactiveDurableOperAuthorityForTest(self: Context, state: *durable_oper_authority.State) void {
        self.durable_oper_authority_state.* = state;
    }

    pub fn markDurableOperUnavailableLocked(
        self: Context,
        state: *durable_oper_authority.State,
    ) void {
        state.markUnavailable();
        self.durable_oper_availability_epoch.* = std.math.add(
            u64,
            self.durable_oper_availability_epoch.*,
            1,
        ) catch std.math.maxInt(u64);
    }

    pub fn markDurableOperUnavailableForTest(self: Context) void {
        self.lock.lockExclusive();
        defer self.lock.unlockExclusive();
        const state = self.durable_oper_authority_state.* orelse return;
        self.markDurableOperUnavailableLocked(state);
    }
};
