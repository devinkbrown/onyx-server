// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper reconcile regression tests.

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

test "S6C5 Services disabled unavailable and missing expected are observational" {
    const auth = try S6c5Auth.init(0x51);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-disabled.wal");
    defer store.deinit();
    var services = Services.init(&store, null);

    var expected = ocg2_reconcile_workset.BaselineEntry{
        .revision = 1,
        .phase = .expired,
        .account_len = 5,
    };
    @memcpy(expected.account_buf[0..5], "alice");
    const work = ocg2_reconcile_workset.WorkItem{ .cause = .inventory_added, .expected = expected };
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.disabled, services.inspectDurableOperReconcileWork(work, 1_000));

    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &state);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(work, 1_000));

    Internal.attachDurableOperAuthorityForTest(&services, &state);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(work, 1_000));

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Live", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    var bob_expected = expected;
    bob_expected.account_buf[0] = 'b';
    bob_expected.account_buf[1] = 'o';
    bob_expected.account_buf[2] = 'b';
    bob_expected.account_len = 3;
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.authority_unavailable, services.inspectDurableOperReconcileWork(.{ .expected = bob_expected }, 1_000));
}

test "S6C5 Services exact active copy wire and authority" {
    const auth = try S6c5Auth.init(0x52);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-active.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Moderator", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    const work = try s6c5WorkForAccount(&services, "alice", 1_000, .inventory_added);
    switch (services.inspectDurableOperReconcileWork(work, 1_000)) {
        .matched_active => |grant| {
            try std.testing.expectEqualStrings("alice", grant.account());
            try std.testing.expectEqualStrings("moderator", grant.class());
            try std.testing.expectEqualStrings("Moderator", grant.title());
            try std.testing.expectEqual(@as(u64, 1), grant.revision);
            try std.testing.expectEqual(@as(u64, 1_000), grant.issued_ms);
            try std.testing.expectEqual(@as(u64, 5_000), grant.expiry_ms);
            try std.testing.expectEqual(auth.config.authority_node_id, grant.authority_node_id);
            try std.testing.expectEqualSlices(u8, &auth.config.authority_pubkey, &grant.authority_pubkey);
            try std.testing.expectEqualSlices(u8, alice, grant.signedWire());
            try std.testing.expect(grant.signedWire().ptr != alice.ptr);
            try std.testing.expectEqualSlices(u8, &work.expected.digest, &grant.digest);
            try std.testing.expectEqualSlices(u8, &work.expected.wire_sha256, &grant.wire_sha256);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "S6C5 Services time boundaries future exact issue active exact expiry expired" {
    const auth = try S6c5Auth.init(0x53);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-time.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Clock", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));

    const future = try s6c5WorkForAccount(&services, "alice", 999, .temporal_transition);
    try std.testing.expectEqual(ocg2_reconcile_schedule.Phase.not_yet_valid, future.expected.phase);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.matched_not_yet_valid, services.inspectDurableOperReconcileWork(future, 999));

    const at_issue = try s6c5WorkForAccount(&services, "alice", 1_000, .temporal_transition);
    try std.testing.expectEqual(ocg2_reconcile_schedule.Phase.active, at_issue.expected.phase);
    switch (services.inspectDurableOperReconcileWork(at_issue, 1_000)) {
        .matched_active => |grant| try std.testing.expectEqualStrings("Clock", grant.title()),
        else => return error.TestUnexpectedResult,
    }

    const mid = try s6c5WorkForAccount(&services, "alice", 2_500, .inventory_added);
    switch (services.inspectDurableOperReconcileWork(mid, 2_500)) {
        .matched_active => |grant| try std.testing.expectEqual(@as(u64, 1), grant.revision),
        else => return error.TestUnexpectedResult,
    }

    const last_active = try s6c5WorkForAccount(&services, "alice", 4_999, .inventory_added);
    switch (services.inspectDurableOperReconcileWork(last_active, 4_999)) {
        .matched_active => {},
        else => return error.TestUnexpectedResult,
    }

    const at_expiry = try s6c5WorkForAccount(&services, "alice", 5_000, .temporal_transition);
    try std.testing.expectEqual(ocg2_reconcile_schedule.Phase.expired, at_expiry.expected.phase);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.matched_expired, services.inspectDurableOperReconcileWork(at_expiry, 5_000));

    const later = try s6c5WorkForAccount(&services, "alice", 6_000, .inventory_added);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.matched_expired, services.inspectDurableOperReconcileWork(later, 6_000));
}

test "S6C5 Services tombstone equivocation and every C4 cause" {
    const auth = try S6c5Auth.init(0x54);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-terminal.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var tomb_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tomb = try signOcg2RaceWire(auth.kp, auth.config, "zed", 1, .tombstone, "", 1_200, 0, &tomb_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(tomb, 1_200));
    const tomb_work = try s6c5WorkForAccount(&services, "zed", 1_200, .inventory_added);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.matched_tombstone, services.inspectDurableOperReconcileWork(tomb_work, 1_200));

    var first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const first = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "First", 1_000, 5_000, &first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(first, 1_000));
    var conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const conflict = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "Conflict", 1_000, 5_000, &conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(conflict, 1_000));
    const equiv_work = try s6c5WorkForAccount(&services, "bob", 1_000, .equivocation);
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.matched_equivocation, services.inspectDurableOperReconcileWork(equiv_work, 1_000));

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Cause", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    for ([_]ocg2_reconcile_workset.Cause{ .inventory_added, .successor, .equivocation, .temporal_transition }) |cause| {
        const work = try s6c5WorkForAccount(&services, "alice", 1_000, cause);
        switch (services.inspectDurableOperReconcileWork(work, 1_000)) {
            .matched_active => |grant| try std.testing.expectEqualStrings("Cause", grant.title()),
            else => return error.TestUnexpectedResult,
        }
    }
}

test "S6C5 Services malformed expected is invalid_work without state access" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-malformed.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    const epoch = services.durable_oper_availability_epoch;
    var valid = ocg2_reconcile_workset.BaselineEntry{
        .revision = 1,
        .phase = .expired,
        .account_len = 5,
    };
    @memcpy(valid.account_buf[0..5], "alice");

    var empty = valid;
    empty.account_len = 0;
    var too_long = valid;
    too_long.account_len = durable_oper_authority.max_account_len + 1;
    var overflow = valid;
    overflow.account_len = std.math.maxInt(usize);
    var upper = valid;
    upper.account_buf[0] = 'A';
    var punct = valid;
    punct.account_buf[0] = '!';
    var zero_rev = valid;
    zero_rev.revision = 0;
    var active_null = valid;
    active_null.phase = .active;
    active_null.next_transition_ms = null;
    var active_past = valid;
    active_past.phase = .active;
    active_past.next_transition_ms = 1_000;
    var future_null = valid;
    future_null.phase = .not_yet_valid;
    future_null.next_transition_ms = null;
    var expired_deadline = valid;
    expired_deadline.next_transition_ms = 9_000;
    var tomb_deadline = valid;
    tomb_deadline.phase = .tombstone;
    tomb_deadline.next_transition_ms = 4_000;
    var equiv_deadline = valid;
    equiv_deadline.phase = .equivocation;
    equiv_deadline.next_transition_ms = 4_000;

    const cases = [_]ocg2_reconcile_workset.BaselineEntry{
        empty,
        too_long,
        overflow,
        upper,
        punct,
        zero_rev,
        active_null,
        active_past,
        future_null,
        expired_deadline,
        tomb_deadline,
        equiv_deadline,
    };
    for (cases) |expected| {
        try std.testing.expectEqual(Services.DurableOperReconcileObservation.invalid_work, services.inspectDurableOperReconcileWork(.{ .expected = expected }, 1_000));
    }
    try std.testing.expectEqual(epoch, services.durable_oper_availability_epoch);
    try std.testing.expect(services.durable_oper_authority_state == null);
}

test "S6C5 Services each identity mismatch is superseded" {
    const auth = try S6c5Auth.init(0x55);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-mismatch.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var alice_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const alice = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Live", 1_000, 5_000, &alice_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(alice, 1_000));
    var bob_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob = try signOcg2RaceWire(auth.kp, auth.config, "bob", 1, .grant, "Other", 1_000, 5_000, &bob_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(bob, 1_000));

    const base = try s6c5WorkForAccount(&services, "alice", 1_000, .inventory_added);
    var account = base;
    @memcpy(account.expected.account_buf[0..3], "bob");
    account.expected.account_len = 3;
    var revision = base;
    revision.expected.revision = 9;
    var digest = base;
    digest.expected.digest[0] ^= 0xff;
    var sha = base;
    sha.expected.wire_sha256[0] ^= 0xff;
    var phase = base;
    phase.expected.phase = .expired;
    phase.expected.next_transition_ms = null;
    var deadline = base;
    deadline.expected.next_transition_ms = 9_000;

    for ([_]ocg2_reconcile_workset.WorkItem{ account, revision, digest, sha, phase, deadline }) |work| {
        try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, services.inspectDurableOperReconcileWork(work, 1_000));
    }
}

test "S6C5 Services stable successor tombstone and equivocation are superseded" {
    const auth = try S6c5Auth.init(0x56);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-s6c5-supersede.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, auth.config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(auth.kp, auth.config, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    const stale = try s6c5WorkForAccount(&services, "alice", 1_000, .successor);

    var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor = try signOcg2RaceWire(auth.kp, auth.config, "alice", 2, .grant, "Successor", 1_000, 7_000, &successor_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(successor, 1_000));
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, services.inspectDurableOperReconcileWork(stale, 1_000));

    var tomb_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tomb = try signOcg2RaceWire(auth.kp, auth.config, "alice", 3, .tombstone, "", 1_000, 0, &tomb_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(tomb, 1_000));
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, services.inspectDurableOperReconcileWork(stale, 1_000));

    var first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const first = try signOcg2RaceWire(auth.kp, auth.config, "carol", 1, .grant, "First", 1_000, 5_000, &first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(first, 1_000));
    const carol_stale = try s6c5WorkForAccount(&services, "carol", 1_000, .equivocation);
    var conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const conflict = try signOcg2RaceWire(auth.kp, auth.config, "carol", 1, .grant, "Conflict", 1_000, 5_000, &conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(conflict, 1_000));
    try std.testing.expectEqual(Services.DurableOperReconcileObservation.superseded, services.inspectDurableOperReconcileWork(carol_stale, 1_000));
}
