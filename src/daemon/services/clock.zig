// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clock.

const std = @import("std");
const OroStore = @import("records.zig").OroStore;

/// Borrowed addresses into one Services owner; this view owns no state.
/// Operations retain their original lock and durable publication boundaries.
pub const Context = struct {
    store: *const *OroStore,
    clock_override_ms: *const std.atomic.Value(u64),

    pub fn servicesNowMs(self: Context) u64 {
        const override = self.clock_override_ms.load(.acquire);
        if (override != 0) return override;
        const wall = std.Io.Clock.real.now(self.store.*.io).toMilliseconds();
        if (wall <= 0) return 0;
        return @intCast(wall);
    }
};
