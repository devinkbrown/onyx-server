// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper clock regression tests.

const std = @import("std");
const store_mod = @import("../store.zig");
const OroStore = @import("records.zig").OroStore;
const Config = @import("records.zig").Config;
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const durable_oper_authority = @import("../durable_oper_authority.zig");
const oper_cred_share = @import("../../proto/oper_cred_share.zig");
const DurableOperMergeOutcome = @import("contracts.zig").DurableOperMergeOutcome;
const signOcg2RaceWire = @import("test_support.zig").signOcg2RaceWire;
const Internal = @import("core.zig").Internal;
const sign = @import("../../crypto/sign.zig");
const durable_oper_authority_boot = @import("../durable_oper_authority_boot.zig");
const node_identity_mod = @import("../node_identity.zig");
const node_short_id_mod = @import("../../crypto/node_short_id.zig");
const DurableOperPreadmission = @import("contracts.zig").DurableOperPreadmission;
const DurableOperRestart = @import("contracts.zig").DurableOperRestart;
const DurableOperTransactionCopy = @import("contracts.zig").DurableOperTransactionCopy;
const DurableOperSecurityNow = @import("contracts.zig").DurableOperSecurityNow;
const durable_oper_security_horizon_renewal_threshold_ms = @import("contracts.zig").durable_oper_security_horizon_renewal_threshold_ms;
const durable_oper_security_horizon_window_ms = @import("contracts.zig").durable_oper_security_horizon_window_ms;
const DurableOperSecurityHorizonResult = @import("contracts.zig").DurableOperSecurityHorizonResult;
const DurableOperTransactionsResult = @import("contracts.zig").DurableOperTransactionsResult;
const S6c2Horizon = @import("test_support.zig").S6c2Horizon;
const expectHorizonCopy = @import("test_support.zig").expectHorizonCopy;

test "S6C2 Services horizon constants match the frozen window" {
    try std.testing.expectEqual(@as(u64, 3_600_000), Services.durable_oper_security_horizon_renewal_threshold_ms);
    try std.testing.expectEqual(@as(u64, 90_000_000), Services.durable_oper_security_horizon_window_ms);
    try std.testing.expectEqual(oper_cred_share.ocg2_max_ttl_ms + Services.durable_oper_security_horizon_renewal_threshold_ms, Services.durable_oper_security_horizon_window_ms);
}

test "S6C2 Services ensure first use requires zero elapsed then renews the window" {
    const auth = try S6c2Horizon.init(0xA1);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c2-first.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try std.testing.expectEqual(Services.DurableOperSecurityHorizonResult.disabled, services.ensureDurableOperSecurityHorizon(1_000, 0));

    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
    switch (services.ensureDurableOperSecurityHorizon(1_000, 1)) {
        .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!state.security_clock_started);
    try std.testing.expectEqual(@as(u64, 0), state.securityReservedUntil());
    try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(1_000, 0));

    const window = Services.durable_oper_security_horizon_window_ms;
    switch (services.ensureDurableOperSecurityHorizon(1_000, 0)) {
        .renewed => |copy| try expectHorizonCopy(copy, 1_000, 1_000 + window, 1_000 + window),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(state.security_clock_started);
    try std.testing.expectEqual(1_000 + window, state.securityReservedUntil());
    try std.testing.expectEqual(@as(u64, 1_000), state.security_last_effective_ms);
    switch (services.ensureDurableOperSecurityHorizon(1_000, 0)) {
        .current => |copy| try expectHorizonCopy(copy, 1_000, 1_000 + window, 1_000 + window),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(1_000 + window, state.securityReservedUntil());
}

test "S6C2 Services ensure remaining 1h+1 stays current and 1h below and zero renew" {
    const auth = try S6c2Horizon.init(0xA2);
    const threshold = Services.durable_oper_security_horizon_renewal_threshold_ms;
    const window = Services.durable_oper_security_horizon_window_ms;
    const raw: u64 = 10_000;

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "services-s6c2-plus1.wal");
        defer store.deinit();
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.reserveDurableOperSecurityTime(raw, raw + threshold + 1)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(raw, 0)) {
            .current => |copy| try expectHorizonCopy(copy, raw, raw + threshold + 1, raw + threshold + 1),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(raw + threshold + 1, state.securityReservedUntil());
    }

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "services-s6c2-1h.wal");
        defer store.deinit();
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.reserveDurableOperSecurityTime(raw, raw + threshold)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        const expected = raw + threshold + window;
        switch (services.ensureDurableOperSecurityHorizon(raw, 0)) {
            .renewed => |copy| try expectHorizonCopy(copy, raw, expected, expected),
            else => return error.TestUnexpectedResult,
        }
    }

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "services-s6c2-below.wal");
        defer store.deinit();
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.reserveDurableOperSecurityTime(raw, raw + threshold - 1)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        const expected = raw + threshold - 1 + window;
        switch (services.ensureDurableOperSecurityHorizon(raw, 0)) {
            .renewed => |copy| try expectHorizonCopy(copy, raw, expected, expected),
            else => return error.TestUnexpectedResult,
        }
    }

    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var store = try openTestStore(tmp, "services-s6c2-zero.wal");
        defer store.deinit();
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.reserveDurableOperSecurityTime(raw, raw + window)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(raw, 0)) {
            .current => |copy| try expectHorizonCopy(copy, raw, raw + window, raw + window),
            else => return error.TestUnexpectedResult,
        }
        const expected = raw + window + window;
        switch (services.ensureDurableOperSecurityHorizon(raw, window)) {
            .renewed => |copy| try expectHorizonCopy(copy, raw + window, expected, expected),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(raw + window, state.security_last_effective_ms);
    }
}

test "S6C2 Services ensure reopen raw forward rollback and monotonic crossing" {
    const auth = try S6c2Horizon.init(0xA3);
    const threshold = Services.durable_oper_security_horizon_renewal_threshold_ms;
    const window = Services.durable_oper_security_horizon_window_ms;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-s6c2-clock.wal");
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        var services = Services.init(&store, null);
        defer state.deinit();
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.ensureDurableOperSecurityHorizon(1_000, 0)) {
            .renewed => |copy| try expectHorizonCopy(copy, 1_000, 1_000 + window, 1_000 + window),
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(2_000, 0)) {
            .current => |copy| try expectHorizonCopy(copy, 2_000, 1_000 + window, 1_000 + window),
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(900, 5)) {
            .current => |copy| try expectHorizonCopy(copy, 2_000, 1_000 + window, 1_000 + window),
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(900, 1_005)) {
            .current => |copy| try expectHorizonCopy(copy, 2_005, 1_000 + window, 1_000 + window),
            else => return error.TestUnexpectedResult,
        }
        store.deinit();
    }

    var reopened = try openTestStore(tmp, "services-s6c2-clock.wal");
    defer reopened.deinit();
    const snapshot = reopened.get(.props, durable_oper_authority.snapshot_key) orelse return error.TestUnexpectedResult;
    var restored = try durable_oper_authority.decode(std.testing.allocator, auth.config, snapshot);
    defer restored.deinit();
    try std.testing.expect(!restored.security_clock_started);
    var restored_services = Services.init(&reopened, null);
    Internal.attachInactiveDurableOperAuthorityForTest(&restored_services, &restored);
    switch (restored_services.ensureDurableOperSecurityHorizon(1_000, 1)) {
        .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!restored.security_clock_started);
    const reopen_effective = restored.securityFloor();
    const reopen_target = reopen_effective + window;
    switch (restored_services.ensureDurableOperSecurityHorizon(1_000, 0)) {
        .renewed => |copy| try expectHorizonCopy(copy, reopen_effective, reopen_target, reopen_target),
        else => return error.TestUnexpectedResult,
    }

    var cross_store = try openTestStore(tmp, "services-s6c2-cross.wal");
    defer cross_store.deinit();
    var cross_state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer cross_state.deinit();
    var cross_services = Services.init(&cross_store, null);
    Internal.attachInactiveDurableOperAuthorityForTest(&cross_services, &cross_state);
    switch (cross_services.reserveDurableOperSecurityTime(1_000, 1_000 + threshold + 5)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    switch (cross_services.ensureDurableOperSecurityHorizon(1_000, 0)) {
        .current => |copy| try std.testing.expectEqual(threshold + 5, copy.remaining_ms),
        else => return error.TestUnexpectedResult,
    }
    const crossed = 1_000 + threshold + 5 + window;
    switch (cross_services.ensureDurableOperSecurityHorizon(1_000, 6)) {
        .renewed => |copy| try expectHorizonCopy(copy, 1_006, crossed, crossed),
        else => return error.TestUnexpectedResult,
    }
}

test "S6C2 Services ensure established beyond horizon is sticky fatal" {
    const auth = try S6c2Horizon.init(0xA4);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c2-fatal.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
    switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    const epoch = services.durable_oper_availability_epoch;
    switch (services.ensureDurableOperSecurityHorizon(1_000, 4_001)) {
        .restart_required => |reason| try std.testing.expectEqual(Services.DurableOperRestart.fatal_state, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!state.servingAvailable());
    try std.testing.expectEqual(epoch + 1, services.durable_oper_availability_epoch);
    try std.testing.expectEqual(@as(u64, 5_000), state.securityReservedUntil());
    try std.testing.expectEqual(Services.DurableOperSecurityHorizonResult.unavailable, services.ensureDurableOperSecurityHorizon(1_000, 0));
    try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(1_000, 0));
}

test "S6C2 Services ensure overflow and first-sample errors are preadmission" {
    const auth = try S6c2Horizon.init(0xA5);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c2-overflow.wal");
    defer store.deinit();
    const max = std.math.maxInt(u64);

    {
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.ensureDurableOperSecurityHorizon(1_000, 1)) {
            .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expect(!state.security_clock_started);
    }

    {
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.reserveDurableOperSecurityTime(max - 2, max)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(max - 2, 3)) {
            .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.exhausted, reason),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(max, state.securityReservedUntil());
        try std.testing.expect(state.servingAvailable());
    }

    {
        var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
        switch (services.reserveDurableOperSecurityTime(max - 1_000, max)) {
            .committed => {},
            else => return error.TestUnexpectedResult,
        }
        switch (services.ensureDurableOperSecurityHorizon(max - 1_000, 0)) {
            .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.exhausted, reason),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(max, state.securityReservedUntil());
        try std.testing.expectEqual(max - 1_000, state.security_last_effective_ms);
    }
}

test "S6C2 Services ensure OOM and store faults expose no projection" {
    const auth = try S6c2Horizon.init(0xA6);
    const cases = [_]struct {
        name: []const u8,
        fault: store_mod.PreparedIoFault,
        candidate_replays: bool,
    }{
        .{ .name = "services-s6c2-write-failed.wal", .fault = .{ .write = .failed }, .candidate_replays = false },
        .{ .name = "services-s6c2-write-short.wal", .fault = .{ .write = .short }, .candidate_replays = false },
        .{ .name = "services-s6c2-sync.wal", .fault = .{ .sync = true }, .candidate_replays = true },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, case.name);
            var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, auth.config);
            defer state.deinit();
            var services = Services.init(&store, null);
            try services.activateDurableOperAuthority(&state);
            store.setPreparedIoFault(case.fault);
            switch (services.ensureDurableOperSecurityHorizon(1_000, 0)) {
                .restart_required => |reason| try std.testing.expectEqual(Services.DurableOperRestart.ambiguous_store, reason),
                else => return error.TestUnexpectedResult,
            }
            try std.testing.expect(!state.servingAvailable());
            try std.testing.expect(!state.security_clock_started);
            try std.testing.expectEqual(@as(u64, 0), state.securityReservedUntil());
            try std.testing.expectEqual(@as(u64, 0), state.security_last_effective_ms);
            try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(1_000, 0));
            store.deinit();
        }

        var reopened = try openTestStore(tmp, case.name);
        defer reopened.deinit();
        var restored = try durable_oper_authority_boot.load(std.testing.allocator, &reopened, auth.config);
        defer restored.deinit();
        if (case.candidate_replays) {
            try std.testing.expect(restored.servingAvailable());
            try std.testing.expectEqual(1_000 + Services.durable_oper_security_horizon_window_ms, restored.securityReservedUntil());
        } else {
            try std.testing.expect(!restored.servingAvailable());
            try std.testing.expectEqual(@as(u64, 0), restored.securityReservedUntil());
        }
    }
}

test "S6C2 Services ensure full cut is allocation-failure atomic" {
    const auth = try S6c2Horizon.init(0xA7);
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: durable_oper_authority.Config) !void {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var store = try store_mod.OroStore.openWithConfig(allocator, std.testing.io, tmp.dir, "services-s6c2-alloc.wal", .{});
            defer store.deinit();
            var state = try durable_oper_authority_boot.initialize(allocator, &store, cfg);
            defer state.deinit();
            var services = Services.init(&store, null);
            try services.activateDurableOperAuthority(&state);
            switch (services.ensureDurableOperSecurityHorizon(1_000, 0)) {
                .renewed => |copy| {
                    try expectHorizonCopy(copy, 1_000, 1_000 + Services.durable_oper_security_horizon_window_ms, 1_000 + Services.durable_oper_security_horizon_window_ms);
                },
                .preadmission => |reason| if (reason == .out_of_memory) return error.OutOfMemory else return error.TestUnexpectedResult,
                else => return error.TestUnexpectedResult,
            }
            try std.testing.expectEqual(1_000 + Services.durable_oper_security_horizon_window_ms, state.securityFloor());
            try std.testing.expectEqual(@as(u64, 1_000), state.security_last_effective_ms);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{auth.config});
}

test "S6C2 Services ensure concurrent current and renew serialize" {
    const auth = try S6c2Horizon.init(0xA8);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c2-conc.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);

    const Worker = struct {
        services: *Services,
        result: Services.DurableOperSecurityHorizonResult = .disabled,
        fn run(self: *@This()) void {
            self.result = self.services.ensureDurableOperSecurityHorizon(1_000, 0);
        }
    };
    var workers = [_]Worker{
        .{ .services = &services },
        .{ .services = &services },
    };
    var threads: [workers.len]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |thread| thread.join();
    for (&workers, 0..) |*worker, index| {
        threads[index] = std.Thread.spawn(.{}, Worker.run, .{worker}) catch return error.SkipZigTest;
        spawned += 1;
    }
    for (threads[0..spawned]) |thread| thread.join();

    var renewed: usize = 0;
    var current: usize = 0;
    for (workers) |worker| {
        switch (worker.result) {
            .renewed => renewed += 1,
            .current => current += 1,
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(@as(usize, 1), renewed);
    try std.testing.expectEqual(@as(usize, 1), current);
    try std.testing.expectEqual(1_000 + Services.durable_oper_security_horizon_window_ms, state.securityReservedUntil());
    try std.testing.expectEqual(@as(u64, 1_000), state.security_last_effective_ms);
}

test "S6C2 Services copyDurableOperTransactions empty exact over under and all kinds" {
    const auth = try S6c2Horizon.init(0xA9);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c2-list.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    var empty_disabled: [1]Services.DurableOperTransactionCopy = .{.{ .revision = 9 }};
    try std.testing.expectEqual(Services.DurableOperTransactionsResult.disabled, services.copyDurableOperTransactions(&empty_disabled));
    try std.testing.expectEqual(@as(u64, 9), empty_disabled[0].revision);

    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
    switch (services.copyDurableOperTransactions(empty_disabled[0..0])) {
        .copied => |n| try std.testing.expectEqual(@as(usize, 0), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 9), empty_disabled[0].revision);

    Internal.attachDurableOperAuthorityForTest(&services, &state);
    var car_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const car = try signOcg2RaceWire(auth.kp, auth.config, "car", 1, .grant, "Future", 4_000, 9_000, &car_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(car, 1_000));
    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Live", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    var zed_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const zed = try signOcg2RaceWire(auth.kp, auth.config, "zed", 1, .tombstone, "", 1_200, 0, &zed_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(zed, 1_200));
    var bob_first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob_first = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "First", 1_000, 5_000, &bob_first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(bob_first, 1_000));
    var bob_conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob_conflict = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "Conflict", 1_000, 5_000, &bob_conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(bob_conflict, 1_000));

    const sentinel = Services.DurableOperTransactionCopy{ .revision = 11 };
    var under = [_]Services.DurableOperTransactionCopy{sentinel};
    switch (services.copyDurableOperTransactions(&under)) {
        .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.capacity, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 11), under[0].revision);
    try std.testing.expectEqual(@as(usize, 0), under[0].account_len);

    var exact: [4]Services.DurableOperTransactionCopy = .{ sentinel, sentinel, sentinel, sentinel };
    switch (services.copyDurableOperTransactions(&exact)) {
        .copied => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("alice", exact[0].account());
    try std.testing.expectEqualStrings("bob", exact[1].account());
    try std.testing.expectEqualStrings("car", exact[2].account());
    try std.testing.expectEqualStrings("zed", exact[3].account());
    try std.testing.expectEqualSlices(u8, alice, exact[0].signedWire());
    try std.testing.expect(exact[1].equivocation);
    try std.testing.expectEqualSlices(u8, car, exact[2].signedWire());
    try std.testing.expectEqual(oper_cred_share.Ocg2Kind.tombstone, exact[3].kind);
    try std.testing.expectEqual(auth.config.authority_node_id, exact[0].authority_node_id);
    try std.testing.expectEqualSlices(u8, &auth.config.authority_pubkey, &exact[0].authority_pubkey);
    try std.testing.expect(exact[0].signedWire().ptr != alice.ptr);

    var over: [5]Services.DurableOperTransactionCopy = .{ sentinel, sentinel, sentinel, sentinel, sentinel };
    switch (services.copyDurableOperTransactions(&over)) {
        .copied => |n| try std.testing.expectEqual(@as(usize, 4), n),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 11), over[4].revision);
}

test "S6C2 Services copyDurableOperTransactions lifetime and invariant fatal" {
    const auth = try S6c2Horizon.init(0xAA);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c2-life.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Owned", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    var held: [1]Services.DurableOperTransactionCopy = undefined;
    switch (services.copyDurableOperTransactions(&held)) {
        .copied => |n| try std.testing.expectEqual(@as(usize, 1), n),
        else => return error.TestUnexpectedResult,
    }
    var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor = try signOcg2RaceWire(auth.kp, auth.config, "alice", 2, .grant, "Next", 1_100, 6_000, &successor_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(successor, 1_100));
    try std.testing.expectEqual(@as(u64, 1), held[0].revision);
    try std.testing.expectEqualSlices(u8, alice, held[0].signedWire());

    state.testXorRecordDigest(0);
    const epoch = services.durable_oper_availability_epoch;
    switch (services.copyDurableOperTransactions(&held)) {
        .restart_required => |reason| try std.testing.expectEqual(Services.DurableOperRestart.fatal_state, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!state.servingAvailable());
    try std.testing.expectEqual(epoch + 1, services.durable_oper_availability_epoch);
    try std.testing.expectEqual(Services.DurableOperTransactionsResult.unavailable, services.copyDurableOperTransactions(&held));
}

test "OCG2CLOCK Services reservation cut rollback restart and boundary" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xD1)));
    const public_key = kp.public_key.toBytes();
    const config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        var store = try openTestStore(tmp, "services-ocg2clock.wal");
        var state = try durable_oper_authority.State.init(std.testing.allocator, config);
        var services = Services.init(&store, null);
        defer state.deinit();
        Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);

        try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(1_000, 0));
        switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
            .committed => |until| try std.testing.expectEqual(@as(u64, 5_000), until),
            else => return error.TestUnexpectedResult,
        }
        switch (services.durableOperSecurityNow(1_000, 0)) {
            .now => |effective| try std.testing.expectEqual(@as(u64, 1_000), effective),
            else => return error.TestUnexpectedResult,
        }
        switch (services.durableOperSecurityNow(1_000, 1)) {
            .now => |effective| try std.testing.expectEqual(@as(u64, 1_001), effective),
            else => return error.TestUnexpectedResult,
        }
        switch (services.durableOperSecurityNow(900, 2)) {
            .now => |effective| try std.testing.expectEqual(@as(u64, 1_002), effective),
            else => return error.TestUnexpectedResult,
        }
        switch (services.durableOperSecurityNow(1_000, 4_000)) {
            .now => |effective| try std.testing.expectEqual(@as(u64, 5_000), effective),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(1_000, 4_001));
        try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(5_001, 0));
        switch (services.reserveDurableOperSecurityTime(1_000, 4_999)) {
            .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.invalid_record, reason),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expectEqual(@as(u64, 5_000), state.securityReservedUntil());

        store.setPreparedIoFault(.{ .sync = true });
        switch (services.reserveDurableOperSecurityTime(1_000, 6_000)) {
            .restart_required => |reason| try std.testing.expectEqual(Services.DurableOperRestart.ambiguous_store, reason),
            else => return error.TestUnexpectedResult,
        }
        try std.testing.expect(!state.servingAvailable());
        try std.testing.expectEqual(@as(u64, 5_000), state.securityReservedUntil());
        store.deinit();
    }

    var reopened = try openTestStore(tmp, "services-ocg2clock.wal");
    defer reopened.deinit();
    const snapshot = reopened.get(.props, durable_oper_authority.snapshot_key) orelse return error.TestUnexpectedResult;
    var restored = try durable_oper_authority.decode(std.testing.allocator, config, snapshot);
    defer restored.deinit();
    try std.testing.expect(restored.servingAvailable());
    // The ambiguous sync may have crossed the store cut.  Recovery trusts WAL
    // replay rather than the unavailable in-memory predecessor and therefore
    // restores the candidate horizon if it was durable.
    try std.testing.expectEqual(@as(u64, 6_000), restored.securityReservedUntil());
    var restored_services = Services.init(&reopened, null);
    Internal.attachDurableOperAuthorityForTest(&restored_services, &restored);
    switch (restored_services.durableOperSecurityNow(1_000, 0)) {
        .now => |effective| try std.testing.expectEqual(@as(u64, 6_000), effective),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, restored_services.durableOperSecurityNow(1_000, 1));
    // A restart begins at the last durable horizon.  Reserving the next window
    // preserves that boot anchor in memory while advancing the next restart's
    // durable floor.
    switch (restored_services.reserveDurableOperSecurityTime(1_000, 9_000)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    switch (restored_services.durableOperSecurityNow(1_000, 1)) {
        .now => |effective| try std.testing.expectEqual(@as(u64, 6_001), effective),
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2CLOCK reservation write short and sync ambiguity resolve only by reopen" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xD3)));
    const public_key = kp.public_key.toBytes();
    const config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    const cases = [_]struct {
        name: []const u8,
        fault: store_mod.PreparedIoFault,
        candidate_replays: bool,
    }{
        .{ .name = "ocg2clock-write-failed.wal", .fault = .{ .write = .failed }, .candidate_replays = false },
        .{ .name = "ocg2clock-write-short.wal", .fault = .{ .write = .short }, .candidate_replays = false },
        .{ .name = "ocg2clock-sync.wal", .fault = .{ .sync = true }, .candidate_replays = true },
    };

    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var store = try openTestStore(tmp, case.name);
            var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, config);
            defer state.deinit();
            var services = Services.init(&store, null);
            try services.activateDurableOperAuthority(&state);
            store.setPreparedIoFault(case.fault);
            switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
                .restart_required => |reason| try std.testing.expectEqual(Services.DurableOperRestart.ambiguous_store, reason),
                else => return error.TestUnexpectedResult,
            }
            try std.testing.expect(!state.servingAvailable());
            try std.testing.expectEqual(@as(u64, 0), state.securityReservedUntil());
            try std.testing.expectEqual(@as(u64, 1), services.durable_oper_availability_epoch);
            store.deinit();
        }

        var reopened = try openTestStore(tmp, case.name);
        defer reopened.deinit();
        var restored = try durable_oper_authority_boot.load(std.testing.allocator, &reopened, config);
        defer restored.deinit();
        if (case.candidate_replays) {
            try std.testing.expect(restored.servingAvailable());
            try std.testing.expect(restored.securityTimeAuthorized());
            try std.testing.expectEqual(@as(u64, 5_000), restored.securityFloor());
            try std.testing.expectEqual(@as(u64, 5_000), restored.securityReservedUntil());
        } else {
            try std.testing.expect(!restored.servingAvailable());
            try std.testing.expect(!restored.securityTimeAuthorized());
            try std.testing.expectEqual(@as(u64, 0), restored.securityFloor());
            try std.testing.expectEqual(@as(u64, 0), restored.securityReservedUntil());
        }
    }
}

test "OCG2CLOCK security time max u64 boundary and overflow fail closed" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xD4)));
    const public_key = kp.public_key.toBytes();
    const config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2clock-max.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
    const max = std.math.maxInt(u64);
    switch (services.reserveDurableOperSecurityTime(max - 2, max)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    switch (services.durableOperSecurityNow(max - 2, 0)) {
        .now => |value| try std.testing.expectEqual(max - 2, value),
        else => return error.TestUnexpectedResult,
    }
    switch (services.durableOperSecurityNow(max - 3, 1)) {
        .now => |value| try std.testing.expectEqual(max - 1, value),
        else => return error.TestUnexpectedResult,
    }
    switch (services.durableOperSecurityNow(max - 3, 2)) {
        .now => |value| try std.testing.expectEqual(max, value),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(Services.DurableOperSecurityNow.unavailable, services.durableOperSecurityNow(max - 3, 3));

    var fresh = try durable_oper_authority.State.init(std.testing.allocator, config);
    defer fresh.deinit();
    var fresh_services = Services.init(&store, null);
    Internal.attachInactiveDurableOperAuthorityForTest(&fresh_services, &fresh);
    switch (fresh_services.reserveDurableOperSecurityTime(max, max)) {
        .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.exhausted, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2CLOCK full reservation cut is allocation-failure atomic" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xD5)));
    const public_key = kp.public_key.toBytes();
    const config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, cfg: durable_oper_authority.Config) !void {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var store = try store_mod.OroStore.openWithConfig(allocator, std.testing.io, tmp.dir, "services-ocg2clock-alloc.wal", .{});
            defer store.deinit();
            var state = try durable_oper_authority_boot.initialize(allocator, &store, cfg);
            defer state.deinit();
            var services = Services.init(&store, null);
            try services.activateDurableOperAuthority(&state);
            switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
                .committed => {},
                .preadmission => |reason| if (reason == .out_of_memory) return error.OutOfMemory else return error.TestUnexpectedResult,
                else => return error.TestUnexpectedResult,
            }
            try std.testing.expectEqual(@as(u64, 5_000), state.securityFloor());
            try std.testing.expectEqual(@as(u64, 5_000), state.securityReservedUntil());
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{config});
}
