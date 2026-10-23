// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper reconcile races regression tests.

const std = @import("std");
const openTestStore = @import("test_support.zig").openTestStore;
const Services = @import("core.zig").Services;
const durable_oper_authority = @import("../durable_oper_authority.zig");
const ocg2_reconcile_schedule = @import("../ocg2_reconcile_schedule.zig");
const ocg2_reconcile_workset = @import("../ocg2_reconcile_workset.zig");
const oper_cred_share = @import("../../proto/oper_cred_share.zig");
const DurableOperReconcileObservation = @import("contracts.zig").DurableOperReconcileObservation;
const DurableOperMergeOutcome = @import("contracts.zig").DurableOperMergeOutcome;
const signOcg2RaceWire = @import("test_support.zig").signOcg2RaceWire;
const S6c5Auth = @import("test_support.zig").S6c5Auth;
const s6c5WorkForAccount = @import("test_support.zig").s6c5WorkForAccount;
const Internal = @import("core.zig").Internal;
const markDurableOperUnavailableAfterCopy = @import("test_support.zig").markDurableOperUnavailableAfterCopy;
const Ocg2AfterCopyRaceCtx = @import("test_support.zig").Ocg2AfterCopyRaceCtx;
const DurableOperTransactionCopy = @import("contracts.zig").DurableOperTransactionCopy;
const s6c5Copied = @import("test_support.zig").s6c5Copied;
const s6c5XorConflictDigest = @import("test_support.zig").s6c5XorConflictDigest;
const S6c5MtCtx = @import("test_support.zig").S6c5MtCtx;

test "S6C5 Services signature authority wire tuple and conflict corruption are unavailable" {
    const auth = try S6c5Auth.init(0x57);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-corrupt.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Live", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    const work = try s6c5WorkForAccount(&services, "alice", 1_000, .inventory_added);

    const view = state.latest("alice").?;
    @constCast(view.wire)[view.wire.len - 1] ^= 0x01;
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(work, 1_000));
    @constCast(view.wire)[view.wire.len - 1] ^= 0x01;

    const saved_node = state.config.authority_node_id;
    state.config.authority_node_id ^= 1;
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(work, 1_000));
    state.config.authority_node_id = saved_node;

    state.testXorRecordDigest(0);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(work, 1_000));
    state.testXorRecordDigest(0);

    var first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const first = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "First", 1_000, 5_000, &first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(first, 1_000));
    var conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const conflict = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "Conflict", 1_000, 5_000, &conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(conflict, 1_000));
    const equiv_work = try s6c5WorkForAccount(&services, "bob", 1_000, .equivocation);
    s6c5XorConflictDigest(&state, "bob");
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(equiv_work, 1_000));
}

test "S6C5 Services post-copy races successor tombstone equivocation and unrelated" {
    const auth = try S6c5Auth.init(0x58);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-races.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    const expected = try s6c5WorkForAccount(&services, "alice", 1_000, .successor);

    var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor = try signOcg2RaceWire(auth.kp, auth.config, "alice", 2, .grant, "Successor", 1_000, 7_000, &successor_buf);
    var successor_race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .successor, .wires = .{ successor, "" } };
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, Internal.inspectDurableOperReconcileWorkInner(&services, expected, 1_000, successor_race.asHook()));

    var tess_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tess = try signOcg2RaceWire(auth.kp, auth.config, "tess", 1, .grant, "Tess", 1_000, 6_000, &tess_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(tess, 1_000));
    var tomb_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tomb = try signOcg2RaceWire(auth.kp, auth.config, "tess", 2, .tombstone, "", 1_000, 0, &tomb_buf);
    const tomb_expected = try s6c5WorkForAccount(&services, "tess", 1_000, .successor);
    var tomb_race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .tombstone, .wires = .{ tomb, "" } };
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, Internal.inspectDurableOperReconcileWorkInner(&services, tomb_expected, 1_000, tomb_race.asHook()));

    var first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const first = try signOcg2RaceWire(auth.kp, auth.config, "carol", 1, .grant, "First", 1_000, 5_000, &first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(first, 1_000));
    var conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const conflict = try signOcg2RaceWire(auth.kp, auth.config, "carol", 1, .grant, "Conflict", 1_000, 5_000, &conflict_buf);
    const carol_expected = try s6c5WorkForAccount(&services, "carol", 1_000, .equivocation);
    var equiv_race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .equivocation, .wires = .{ conflict, "" } };
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, Internal.inspectDurableOperReconcileWorkInner(&services, carol_expected, 1_000, equiv_race.asHook()));

    var dave_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const dave = try signOcg2RaceWire(auth.kp, auth.config, "dave", 1, .grant, "Dave", 1_000, 6_000, &dave_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(dave, 1_000));
    const dave_expected = try s6c5WorkForAccount(&services, "dave", 1_000, .inventory_added);
    var eve_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const eve = try signOcg2RaceWire(auth.kp, auth.config, "eve", 1, .grant, "Eve", 1_000, 6_000, &eve_buf);
    var unrelated = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .unrelated_account, .wires = .{ eve, "" } };
    switch (Internal.inspectDurableOperReconcileWorkInner(&services, dave_expected, 1_000, unrelated.asHook())) {
        .matched_active => |grant| {
            try std.testing.expectEqualStrings("Dave", grant.title());
            try std.testing.expectEqual(@as(u64, 1), grant.revision);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 1), state.latest("eve").?.revision);
}

test "S6C5 Services second instability and epoch change are unavailable" {
    const auth = try S6c5Auth.init(0x59);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-unstable.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    const expected = try s6c5WorkForAccount(&services, "alice", 1_000, .successor);
    var one_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const one = try signOcg2RaceWire(auth.kp, auth.config, "alice", 2, .grant, "One", 1_000, 6_000, &one_buf);
    var two_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const two = try signOcg2RaceWire(auth.kp, auth.config, "alice", 3, .grant, "Two", 1_000, 6_000, &two_buf);
    var race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .two_successors, .wires = .{ one, two } };
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, Internal.inspectDurableOperReconcileWorkInner(&services, expected, 1_000, race.asHook()));
    try std.testing.expectEqual(@as(usize, 2), race.calls);

    var bob_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "Bob", 1_000, 6_000, &bob_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(bob, 1_000));
    const bob_expected = try s6c5WorkForAccount(&services, "bob", 1_000, .inventory_added);
    const epoch = services.durable_oper_availability_epoch;
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, Internal.inspectDurableOperReconcileWorkInner(&services, bob_expected, 1_000, .{ .callback = markDurableOperUnavailableAfterCopy, .context = &services }));
    try std.testing.expect(!state.servingAvailable());
    try std.testing.expectEqual(epoch + 1, services.durable_oper_availability_epoch);
}

test "S6C5 Services active copy outlives later merge and inspect performs no allocator activity" {
    const public_info = @typeInfo(@TypeOf(Services.inspectDurableOperReconcileWork)).@"fn";
    const inner_info = @typeInfo(@TypeOf(Internal.inspectDurableOperReconcileWorkInner)).@"fn";
    inline for (public_info.param_types ++ inner_info.param_types) |param_type| {
        try std.testing.expect(param_type != std.mem.Allocator);
    }
    try std.testing.expect(public_info.return_type != std.mem.Allocator);
    try std.testing.expect(inner_info.return_type != std.mem.Allocator);

    const src = @embedFile("oper_authority.zig");
    const public_fn = "pub fn inspectReconcileWork(";
    const inner_fn = "fn inspectDurableOperReconcileWorkInner(";
    const live_fn = "fn ocg2ReconcileCopyStillLive(";
    const next_fn = "fn inspectDurableOperTransactionInner(";
    const public_at = std.mem.indexOf(u8, src, public_fn) orelse return error.TestUnexpectedResult;
    const inner_at = std.mem.indexOf(u8, src, inner_fn) orelse return error.TestUnexpectedResult;
    const live_at = std.mem.indexOf(u8, src, live_fn) orelse return error.TestUnexpectedResult;
    const next_at = std.mem.indexOf(u8, src, next_fn) orelse return error.TestUnexpectedResult;
    try std.testing.expect(public_at < inner_at and inner_at < live_at and live_at < next_at);
    // The public adapter and its borrowed view must also remain allocation-free.
    const owner_src = @embedFile("core.zig");
    const adapter_at = std.mem.indexOf(u8, owner_src, "pub fn inspectDurableOperReconcileWork(") orelse return error.TestUnexpectedResult;
    const adapter_end = adapter_at + (std.mem.indexOf(u8, owner_src[adapter_at..], "comptime {") orelse return error.TestUnexpectedResult);
    const view_at = std.mem.indexOf(u8, owner_src, "fn oper_authorityView(") orelse return error.TestUnexpectedResult;
    const view_end = std.mem.indexOf(u8, owner_src, "fn oper_availabilityView(") orelse return error.TestUnexpectedResult;
    inline for (.{ src[inner_at..next_at], src[public_at..inner_at], owner_src[adapter_at..adapter_end], owner_src[view_at..view_end], @embedFile("oper_shared.zig") }) |body| {
        inline for (.{ "allocator(", ".allocator", "alloc(", "create(", "dupe(" }) |needle| {
            try std.testing.expect(std.mem.indexOf(u8, body, needle) == null);
        }
    }

    const auth = try S6c5Auth.init(0x5A);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-life.wal");
    defer store.deinit();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var state = try durable_oper_authority.State.init(failing.allocator(), auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Owned", 1_000, 5_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    const work = try s6c5WorkForAccount(&services, "alice", 1_000, .inventory_added);

    const allocs_before = failing.allocations;
    const bytes_before = failing.allocated_bytes;
    const index_before = failing.alloc_index;
    const resize_before = failing.resize_index;
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;

    const observed = services.inspectDurableOperReconcileWork(work, 1_000);
    try std.testing.expectEqual(allocs_before, failing.allocations);
    try std.testing.expectEqual(bytes_before, failing.allocated_bytes);
    try std.testing.expectEqual(index_before, failing.alloc_index);
    try std.testing.expectEqual(resize_before, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);

    switch (observed) {
        .matched_active => |grant| {
            var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
            const successor = try signOcg2RaceWire(auth.kp, auth.config, "alice", 2, .grant, "Next", 1_100, 6_000, &successor_buf);
            try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(successor, 1_100));
            try std.testing.expectEqualStrings("Owned", grant.title());
            try std.testing.expectEqual(@as(u64, 1), grant.revision);
            try std.testing.expectEqualSlices(u8, initial, grant.signedWire());
        },
        else => return error.TestUnexpectedResult,
    }
}

test "S6C5 Services inspect leaves snapshot WAL sequence and security clock identical" {
    const auth = try S6c5Auth.init(0x5B);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-identity.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Clock", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    const work = try s6c5WorkForAccount(&services, "alice", 1_000, .inventory_added);

    const snap_before = try std.testing.allocator.dupe(u8, state.snapshot());
    defer std.testing.allocator.free(snap_before);
    const seq_before = store.next_seq;
    const wal_before = store.wal_offset;
    const gen_before = store.next_prepared_generation;
    const state_gen = state.generation;
    const state_epoch = state.epoch;
    const floor = state.securityFloor();
    const reserved = state.securityReservedUntil();
    const last = state.security_last_effective_ms;
    const boot = state.security_boot_effective_ms;
    const avail = services.durable_oper_availability_epoch;
    const count = state.count();

    switch (services.inspectDurableOperReconcileWork(work, 1_000)) {
        .matched_active => {},
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expectEqualSlices(u8, snap_before, state.snapshot());
    try std.testing.expectEqual(seq_before, store.next_seq);
    try std.testing.expectEqual(wal_before, store.wal_offset);
    try std.testing.expectEqual(gen_before, store.next_prepared_generation);
    try std.testing.expectEqual(state_gen, state.generation);
    try std.testing.expectEqual(state_epoch, state.epoch);
    try std.testing.expectEqual(floor, state.securityFloor());
    try std.testing.expectEqual(reserved, state.securityReservedUntil());
    try std.testing.expectEqual(last, state.security_last_effective_ms);
    try std.testing.expectEqual(boot, state.security_boot_effective_ms);
    try std.testing.expectEqual(avail, services.durable_oper_availability_epoch);
    try std.testing.expectEqual(count, state.count());
    try std.testing.expect(state.servingAvailable());
}

test "S6C5 Services concurrent reader writer never returns a predecessor grant" {
    const auth = try S6c5Auth.init(0x5C);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-conc.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    const expected = try s6c5WorkForAccount(&services, "alice", 2_001, .successor);
    var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor = try signOcg2RaceWire(auth.kp, auth.config, "alice", 2, .grant, "Successor", 2_001, 7_000, &successor_buf);

    var failures = std.atomic.Value(u32).init(0);
    var published = std.atomic.Value(bool).init(false);
    var ctx = S6c5MtCtx{
        .services = &services,
        .expected = expected,
        .successor_wire = successor,
        .failures = &failures,
        .published = &published,
    };
    var reader = try std.Thread.spawn(.{}, S6c5MtCtx.reader, .{&ctx});
    var writer = try std.Thread.spawn(.{}, S6c5MtCtx.writer, .{&ctx});
    reader.join();
    writer.join();
    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    try std.testing.expect(published.load(.acquire));
    try std.testing.expect(ctx.saw_stale_after_publish);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, ctx.last);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, services.inspectDurableOperReconcileWork(expected, 2_001));
    const live = try s6c5WorkForAccount(&services, "alice", 2_001, .successor);
    switch (services.inspectDurableOperReconcileWork(live, 2_001)) {
        .matched_active => |grant| {
            try std.testing.expectEqualStrings("Successor", grant.title());
            try std.testing.expectEqual(@as(u64, 2), grant.revision);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "S6C5 Services C2 C3 C4 C5 integration covers all phases and the 256 bound" {
    const auth = try S6c5Auth.init(0x5D);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-integrate.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Expired", 500, 900, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 500));
    var bob_first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob_first = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "First", 1_000, 5_000, &bob_first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(bob_first, 1_000));
    var bob_conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob_conflict = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "Conflict", 1_000, 5_000, &bob_conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(bob_conflict, 1_000));
    var car_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const car = try signOcg2RaceWire(auth.kp, auth.config, "car", 1, .grant, "Future", 4_000, 9_000, &car_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(car, 1_000));
    var zed_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const zed = try signOcg2RaceWire(auth.kp, auth.config, "zed", 1, .tombstone, "", 1_200, 0, &zed_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(zed, 1_200));
    var live_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const live = try signOcg2RaceWire(auth.kp, auth.config, "mia", 1, .grant, "Live", 1_000, 5_000, &live_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(live, 1_000));

    var copies: [6]Services.DurableOperTransactionCopy = undefined;
    const listed = try s6c5Copied(&services, &copies);
    try std.testing.expectEqual(@as(usize, 5), listed.len);
    var hints: [5]ocg2_reconcile_schedule.ReinspectHint = undefined;
    try std.testing.expectEqual(std.meta.Tag(ocg2_reconcile_schedule.BuildResult).complete, std.meta.activeTag(ocg2_reconcile_schedule.build(listed, 1_000, &hints)));
    var candidates: [5]ocg2_reconcile_workset.BaselineEntry = undefined;
    var work: [5]ocg2_reconcile_workset.WorkItem = undefined;
    try std.testing.expectEqual(std.meta.Tag(ocg2_reconcile_workset.BuildResult).complete, std.meta.activeTag(ocg2_reconcile_workset.build(&.{}, null, &hints, 1_000, &candidates, &work)));
    var saw_expired = false;
    var saw_equiv = false;
    var saw_future = false;
    var saw_tomb = false;
    var saw_active = false;
    for (work) |item| {
        switch (services.inspectDurableOperReconcileWork(item, 1_000)) {
            .matched_expired => saw_expired = true,
            .matched_equivocation => saw_equiv = true,
            .matched_not_yet_valid => saw_future = true,
            .matched_tombstone => saw_tomb = true,
            .matched_active => saw_active = true,
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_expired and saw_equiv and saw_future and saw_tomb and saw_active);

    var full_state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer full_state.deinit();
    var full_store = try openTestStore(tmp, "services-s6c5-256.wal");
    defer full_store.deinit();
    var full = Services.init(&full_store, null);
    Internal.attachDurableOperAuthorityForTest(&full, &full_state);
    var i: usize = 0;
    while (i < durable_oper_authority.max_records) : (i += 1) {
        var name = [4]u8{ 'n', '0', '0', '0' };
        var value = i;
        name[3] = '0' + @as(u8, @intCast(value % 10));
        value /= 10;
        name[2] = '0' + @as(u8, @intCast(value % 10));
        value /= 10;
        name[1] = '0' + @as(u8, @intCast(value % 10));
        var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
        const wire = try signOcg2RaceWire(auth.kp, auth.config, &name, 1, .grant, "N", 1_000, 5_000, &wire_buf);
        try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, full.commitDurableOperRecord(wire, 1_000));
    }
    var full_copies: [durable_oper_authority.max_records]Services.DurableOperTransactionCopy = undefined;
    const full_listed = try s6c5Copied(&full, &full_copies);
    try std.testing.expectEqual(durable_oper_authority.max_records, full_listed.len);
    var full_hints: [durable_oper_authority.max_records]ocg2_reconcile_schedule.ReinspectHint = undefined;
    try std.testing.expectEqual(std.meta.Tag(ocg2_reconcile_schedule.BuildResult).complete, std.meta.activeTag(ocg2_reconcile_schedule.build(full_listed, 1_000, &full_hints)));
    var full_candidates: [durable_oper_authority.max_records]ocg2_reconcile_workset.BaselineEntry = undefined;
    var full_work: [durable_oper_authority.max_records]ocg2_reconcile_workset.WorkItem = undefined;
    try std.testing.expectEqual(std.meta.Tag(ocg2_reconcile_workset.BuildResult).complete, std.meta.activeTag(ocg2_reconcile_workset.build(&.{}, null, &full_hints, 1_000, &full_candidates, &full_work)));
    try std.testing.expectEqual(durable_oper_authority.max_records, full_work.len);
    for (full_work) |item| {
        switch (full.inspectDurableOperReconcileWork(item, 1_000)) {
            .matched_active => |grant| try std.testing.expectEqual(@as(u64, 1), grant.revision),
            else => return error.TestUnexpectedResult,
        }
    }
}

test "S6C5 Services reflection keeps C4 private and production callers at zero" {
    try std.testing.expect(!@hasDecl(Services, "WorkItem"));
    try std.testing.expect(!@hasDecl(Services, "BaselineEntry"));
    try std.testing.expect(!@hasDecl(Services, "Cause"));
    try std.testing.expect(!@hasDecl(Services, "ReinspectHint"));
    try std.testing.expect(!@hasDecl(Services, "ocg2_reconcile_workset"));
    try std.testing.expect(!@hasDecl(Services, "ocg2_reconcile_schedule"));
    try std.testing.expect(!@hasDecl(Services, "AfterCopyHook"));
    try std.testing.expect(@hasDecl(Services, "DurableOperReconcileObservation"));
    try std.testing.expect(@hasDecl(Services, "inspectDurableOperReconcileWork"));
    const public_decls = @typeInfo(Services).@"struct".decl_names;
    var saw_observation = false;
    var saw_inspect = false;
    inline for (public_decls) |name| {
        try std.testing.expect(!std.mem.eql(u8, name, "inspectDurableOperReconcileWorkInner"));
        try std.testing.expect(!std.mem.eql(u8, name, "WorkItem"));
        try std.testing.expect(!std.mem.eql(u8, name, "BaselineEntry"));
        try std.testing.expect(!std.mem.eql(u8, name, "AfterCopyHook"));
        if (std.mem.eql(u8, name, "DurableOperReconcileObservation")) saw_observation = true;
        if (std.mem.eql(u8, name, "inspectDurableOperReconcileWork")) saw_inspect = true;
    }
    try std.testing.expect(saw_observation and saw_inspect);
    inline for (.{
        "applyDurableOperReconcileWork",
        "executeDurableOperReconcileWork",
        "grantDurableOperReconcileWork",
        "revokeDurableOperReconcileWork",
        "acknowledgeDurableOperReconcileWork",
        "reconcileDurableOperWork",
    }) |name| {
        try std.testing.expect(!@hasDecl(Services, name));
    }

    // Scan every production module after decomposition; tests are separate.
    const production = @embedFile("../services.zig") ++
        @embedFile("records.zig") ++
        @embedFile("contracts.zig") ++
        @embedFile("oper_shared.zig") ++
        @embedFile("account_props.zig") ++
        @embedFile("accounts.zig") ++
        @embedFile("channel_props.zig") ++
        @embedFile("channels.zig") ++
        @embedFile("clock.zig") ++
        @embedFile("credentials.zig") ++
        @embedFile("device_facts.zig") ++
        @embedFile("key_transparency.zig") ++
        @embedFile("mfa.zig") ++
        @embedFile("oper_authority.zig") ++
        @embedFile("oper_availability.zig") ++
        @embedFile("oper_clock.zig") ++
        @embedFile("persistence.zig") ++
        @embedFile("sessions.zig") ++
        @embedFile("webpush.zig") ++
        @embedFile("core.zig");
    const call = ".inspectDurableOperReconcileWork(";
    var search: usize = 0;
    var production_calls: usize = 0;
    while (std.mem.indexOfPos(u8, production, search, call)) |at| {
        const after = production[at + ".inspectDurableOperReconcileWork".len ..];
        if (!std.mem.startsWith(u8, after, "Inner")) production_calls += 1;
        search = at + call.len;
    }
    try std.testing.expectEqual(@as(usize, 0), production_calls);
}
