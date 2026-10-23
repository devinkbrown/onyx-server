// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Oper authority regression tests.

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
const oper_session_provenance = @import("../oper_session_provenance.zig");
const node_identity_mod = @import("../node_identity.zig");
const node_short_id_mod = @import("../../crypto/node_short_id.zig");
const DurableOperLookup = @import("contracts.zig").DurableOperLookup;
const DurableOperPreadmission = @import("contracts.zig").DurableOperPreadmission;
const DurableOperRestart = @import("contracts.zig").DurableOperRestart;
const Ocg2ProvMtCtx = @import("test_support.zig").Ocg2ProvMtCtx;
const markDurableOperUnavailableAfterCopy = @import("test_support.zig").markDurableOperUnavailableAfterCopy;
const Ocg2AfterCopyRaceCtx = @import("test_support.zig").Ocg2AfterCopyRaceCtx;
const DurableOperTransaction = @import("contracts.zig").DurableOperTransaction;
const DurableOperAuthorityMatch = @import("contracts.zig").DurableOperAuthorityMatch;

test "OCG2PROV Services copied lookup races a later merge without borrowed slices" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xB2)));
    const public_key = kp.public_key.toBytes();
    const authority_config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2prov-race.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority_config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Initial",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 1_000,
        .expiry_ms = 6_000,
    }, 1_000, &initial_wire);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial_wire[0..initial_len], 1_000));

    var successor_wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 2,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Successor",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 2_001,
        .expiry_ms = 7_000,
    }, 2_001, &successor_wire);
    var failures = std.atomic.Value(u32).init(0);
    var ctx = Ocg2ProvMtCtx{
        .services = &services,
        .successor_wire = successor_wire[0..successor_len],
        .failures = &failures,
    };
    var reader = try std.Thread.spawn(.{}, Ocg2ProvMtCtx.reader, .{&ctx});
    var writer = try std.Thread.spawn(.{}, Ocg2ProvMtCtx.writer, .{&ctx});
    reader.join();
    writer.join();

    try std.testing.expectEqual(@as(u32, 0), failures.load(.monotonic));
    switch (ctx.result) {
        .active => |grant| {
            try std.testing.expectEqualStrings("alice", grant.account());
            try std.testing.expect(std.mem.eql(u8, grant.title(), "Initial") or std.mem.eql(u8, grant.title(), "Successor"));
        },
        else => return error.TestUnexpectedResult,
    }
    // The detached copy remains readable after the writer has committed its
    // successor, proving that no state-owned slice escaped the locked read.
    const final = services.inspectDurableOperAuthority("alice", 2_001);
    switch (final) {
        .active => |grant| try std.testing.expectEqualStrings("Successor", grant.title()),
        else => return error.TestUnexpectedResult,
    }
    switch (ctx.result) {
        .active => |grant| try std.testing.expect(std.mem.eql(u8, grant.title(), "Initial") or std.mem.eql(u8, grant.title(), "Successor")),
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2PROV Services detached lookup observes unavailable transition after copy" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xB3)));
    const public_key = kp.public_key.toBytes();
    const authority_config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2prov-unavailable-race.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority_config);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const wire_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Initial",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 1_000,
        .expiry_ms = 6_000,
    }, 1_000, &wire);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(wire[0..wire_len], 1_000));

    const result = Internal.inspectDurableOperAuthorityInner(&services, "alice", 1_000, .{ .callback = markDurableOperUnavailableAfterCopy, .context = &services });
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.unavailable, result);
    try std.testing.expect(!state.servingAvailable());
    try std.testing.expectEqual(@as(u64, 1), services.durable_oper_availability_epoch);
}

test "OCG2PROV post-copy same-account successor never returns predecessor" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xC1)));
    const public_key = kp.public_key.toBytes();
    const authority = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2-race-successor.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(kp, authority, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor = try signOcg2RaceWire(kp, authority, "alice", 2, .grant, "Successor", 1_000, 7_000, &successor_buf);
    var race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .successor, .wires = .{ successor, "" } };

    const lookup = Internal.inspectDurableOperAuthorityInner(&services, "alice", 1_000, race.asHook());
    switch (lookup) {
        .active => |grant| {
            try std.testing.expectEqualStrings("Successor", grant.title());
            try std.testing.expectEqual(@as(u64, 2), grant.revision);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 2), race.calls);
    try std.testing.expectEqual(@as(u64, 2), state.latest("alice").?.revision);
}

test "OCG2PROV post-copy same-account tombstone never returns predecessor" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xC2)));
    const public_key = kp.public_key.toBytes();
    const authority = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2-race-tombstone.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(kp, authority, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    var tombstone_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tombstone = try signOcg2RaceWire(kp, authority, "alice", 2, .tombstone, "", 1_000, 0, &tombstone_buf);
    var race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .tombstone, .wires = .{ tombstone, "" } };

    const lookup = Internal.inspectDurableOperAuthorityInner(&services, "alice", 1_000, race.asHook());
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.tombstone, lookup);
    try std.testing.expectEqual(@as(usize, 1), race.calls);
    try std.testing.expectEqual(oper_cred_share.Ocg2Kind.tombstone, state.latest("alice").?.kind);
}

test "OCG2PROV post-copy same-revision equivocation never returns predecessor" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xC3)));
    const public_key = kp.public_key.toBytes();
    const authority = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2-race-equivocation.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(kp, authority, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    var conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const conflict = try signOcg2RaceWire(kp, authority, "alice", 1, .grant, "Conflict", 1_000, 6_000, &conflict_buf);
    var race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .equivocation, .wires = .{ conflict, "" } };

    const lookup = Internal.inspectDurableOperAuthorityInner(&services, "alice", 1_000, race.asHook());
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.equivocation, lookup);
    try std.testing.expectEqual(@as(usize, 1), race.calls);
    try std.testing.expect(state.latest("alice").?.equivocation);
}

test "OCG2PROV post-copy unrelated-account merge may preserve predecessor" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xC4)));
    const public_key = kp.public_key.toBytes();
    const authority = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2-race-unrelated.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(kp, authority, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    var bob_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const bob = try signOcg2RaceWire(kp, authority, "bob", 1, .grant, "Bob", 1_000, 6_000, &bob_buf);
    var race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .unrelated_account, .wires = .{ bob, "" } };

    const lookup = Internal.inspectDurableOperAuthorityInner(&services, "alice", 1_000, race.asHook());
    switch (lookup) {
        .active => |grant| {
            try std.testing.expectEqualStrings("Initial", grant.title());
            try std.testing.expectEqual(@as(u64, 1), grant.revision);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), race.calls);
    try std.testing.expectEqual(@as(u64, 1), state.latest("bob").?.revision);
}

test "OCG2PROV post-copy second same-account instability fails unavailable" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xC5)));
    const public_key = kp.public_key.toBytes();
    const authority = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2-race-unstable.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority);
    defer state.deinit();
    var services = Services.init(&store, null);
    Internal.attachDurableOperAuthorityForTest(&services, &state);

    var initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const initial = try signOcg2RaceWire(kp, authority, "alice", 1, .grant, "Initial", 1_000, 6_000, &initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(initial, 1_000));
    var successor_one_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor_one = try signOcg2RaceWire(kp, authority, "alice", 2, .grant, "Successor One", 1_000, 6_000, &successor_one_buf);
    var successor_two_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor_two = try signOcg2RaceWire(kp, authority, "alice", 3, .grant, "Successor Two", 1_000, 6_000, &successor_two_buf);
    var race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .two_successors, .wires = .{ successor_one, successor_two } };

    const lookup = Internal.inspectDurableOperAuthorityInner(&services, "alice", 1_000, race.asHook());
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.unavailable, lookup);
    try std.testing.expectEqual(@as(usize, 2), race.calls);
    try std.testing.expectEqual(@as(u64, 3), state.latest("alice").?.revision);
}

test "OCG2AUTH Services durable commit revision restart and ambiguous poison" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xA1)));
    const public_key = kp.public_key.toBytes();
    const authority_config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var wire_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const wire_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Moderator",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 1000,
        .expiry_ms = 5000,
    }, 1000, &wire_buf);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var store = try openTestStore(tmp, "services-ocg2auth.wal");
        defer store.deinit();
        var state = try durable_oper_authority.State.init(std.testing.allocator, authority_config);
        defer state.deinit();
        var services = Services.init(&store, null);
        Internal.attachDurableOperAuthorityForTest(&services, &state);
        try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(wire_buf[0..wire_len], 1000));
        const revision = services.allocateDurableOperRevision("alice");
        switch (revision) {
            .committed => |value| try std.testing.expectEqual(@as(u64, 2), value),
            else => return error.TestUnexpectedResult,
        }
    }
    {
        var reopened = try openTestStore(tmp, "services-ocg2auth.wal");
        defer reopened.deinit();
        const image = reopened.get(.props, durable_oper_authority.snapshot_key) orelse return error.TestUnexpectedResult;
        var restored = try durable_oper_authority.decode(std.testing.allocator, authority_config, image);
        defer restored.deinit();
        var next = try restored.prepareRevision("alice");
        defer next.update.abort();
        try std.testing.expectEqual(@as(u64, 3), next.revision);
    }

    var poison_store = try openTestStore(tmp, "services-ocg2auth-poison.wal");
    defer poison_store.deinit();
    var poison_state = try durable_oper_authority.State.init(std.testing.allocator, authority_config);
    defer poison_state.deinit();
    var poisoned_services = Services.init(&poison_store, null);
    Internal.attachDurableOperAuthorityForTest(&poisoned_services, &poison_state);
    poison_store.setPreparedIoFault(.{ .sync = true });
    const ambiguous = poisoned_services.commitDurableOperRecord(wire_buf[0..wire_len], 1000);
    switch (ambiguous) {
        .restart_required => |reason| try std.testing.expectEqual(Services.DurableOperRestart.ambiguous_store, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(!poison_state.servingAvailable());
    try std.testing.expect(poison_state.effective("alice", 1000) == null);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.unavailable, poisoned_services.commitDurableOperRecord(wire_buf[0..wire_len], 1000));

    var constrained_store = try store_mod.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "services-ocg2auth-capacity.wal", .{
        .max_record_bytes = 64,
    });
    defer constrained_store.deinit();
    var constrained_state = try durable_oper_authority.State.init(std.testing.allocator, authority_config);
    defer constrained_state.deinit();
    var constrained_services = Services.init(&constrained_store, null);
    Internal.attachDurableOperAuthorityForTest(&constrained_services, &constrained_state);
    const rejected = constrained_services.commitDurableOperRecord(wire_buf[0..wire_len], 1000);
    switch (rejected) {
        .preadmission => |reason| try std.testing.expectEqual(Services.DurableOperPreadmission.capacity, reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 0), constrained_state.count());
    try std.testing.expect(constrained_state.servingAvailable());
    try std.testing.expect(constrained_store.get(.props, durable_oper_authority.snapshot_key) == null);
}

test "OCG2AUTH Services activation requires exact durable image and rejects unavailable duplicate receiver" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xA5)));
    const public_key = kp.public_key.toBytes();
    const authority_config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2-activation.wal");
    defer store.deinit();
    var state = try durable_oper_authority_boot.initialize(std.testing.allocator, &store, authority_config);
    defer state.deinit();

    var services = Services.init(&store, null);
    try services.activateDurableOperAuthority(&state);
    try std.testing.expectError(error.AlreadyActive, services.activateDurableOperAuthority(&state));
    switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }

    var unavailable = try durable_oper_authority_boot.load(std.testing.allocator, &store, authority_config);
    defer unavailable.deinit();
    unavailable.markUnavailable();
    var unavailable_services = Services.init(&store, null);
    try std.testing.expectError(error.AuthorityUnavailable, unavailable_services.activateDurableOperAuthority(&unavailable));

    var other_store = try openTestStore(tmp, "services-ocg2-receiver-empty.wal");
    defer other_store.deinit();
    var receiver_services = Services.init(&other_store, null);
    try std.testing.expectError(error.MissingDurableMarker, receiver_services.activateDurableOperAuthority(&state));
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.disabled, receiver_services.commitDurableOperRecord("", 0));
}

test "OCG2PROV Services copied lookup classifies lifecycle and survives later merge" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xB1)));
    const public_key = kp.public_key.toBytes();
    const authority_config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2prov.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, authority_config);
    defer state.deinit();
    var services = Services.init(&store, null);

    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.disabled, services.inspectDurableOperAuthority("alice", 1000));
    Internal.attachDurableOperAuthorityForTest(&services, &state);
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.absent, services.inspectDurableOperAuthority("alice", 1000));

    var future_wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const future_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Future",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 2000,
        .expiry_ms = 5000,
    }, 1000, &future_wire);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(future_wire[0..future_len], 1000));
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.not_yet_valid, services.inspectDurableOperAuthority("alice", 1000));
    const copied = services.inspectDurableOperAuthority("alice", 2000);
    switch (copied) {
        .active => |grant| {
            try std.testing.expectEqualStrings("alice", grant.account());
            try std.testing.expectEqualStrings("Future", grant.title());
            try std.testing.expectEqual(@as(u64, 1), grant.revision);
            try std.testing.expectEqual(@as(u64, 2000), grant.issued_ms);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.expired, services.inspectDurableOperAuthority("alice", 5000));

    var successor_wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 2,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Successor",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 2001,
        .expiry_ms = 6000,
    }, 2001, &successor_wire);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(successor_wire[0..successor_len], 2001));
    switch (copied) {
        .active => |grant| try std.testing.expectEqualStrings("Future", grant.title()),
        else => return error.TestUnexpectedResult,
    }

    var tombstone_wire: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tombstone_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .tombstone,
        .account = "bob",
        .revision = 1,
        .privilege_bits = 0,
        .class = "",
        .title = "",
        .authority_node_id = authority_config.authority_node_id,
        .authority_pubkey = authority_config.authority_pubkey,
        .issued_ms = 2000,
        .expiry_ms = 0,
    }, 2000, &tombstone_wire);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(tombstone_wire[0..tombstone_len], 2000));
    try std.testing.expectEqual(oper_session_provenance.DurableOperLookup.tombstone, services.inspectDurableOperAuthority("bob", 2000));
}

test "OCG2TXN Services copied active terminal identities are exact and canonical" {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xD2)));
    const public_key = kp.public_key.toBytes();
    const config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2txn.wal");
    defer store.deinit();
    var state = try durable_oper_authority.State.init(std.testing.allocator, config);
    defer state.deinit();
    var services = Services.init(&store, null);
    try std.testing.expectEqual(Services.DurableOperTransaction.disabled, services.inspectDurableOperTransaction("alice", 1_000));
    Internal.attachDurableOperAuthorityForTest(&services, &state);
    try std.testing.expectEqual(Services.DurableOperTransaction.absent, services.inspectDurableOperTransaction("alice", 1_000));

    var grant_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const grant_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "alice",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Exact",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = 1_000,
        .expiry_ms = 5_000,
    }, 1_000, &grant_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(grant_buf[0..grant_len], 1_000));
    const grant_wire = grant_buf[0..grant_len];
    switch (services.inspectDurableOperTransaction("ALICE", 1_000)) {
        .active => |copy| {
            try std.testing.expectEqualStrings("alice", copy.account());
            try std.testing.expectEqual(@as(u64, 1), copy.revision);
            try std.testing.expectEqual(oper_cred_share.Ocg2Kind.grant, copy.kind);
            try std.testing.expectEqual(@as(u64, 1_000), copy.issued_ms);
            try std.testing.expectEqual(@as(u64, 5_000), copy.expiry_ms);
            try std.testing.expectEqual(config.authority_node_id, copy.authority_node_id);
            try std.testing.expectEqualSlices(u8, &config.authority_pubkey, &copy.authority_pubkey);
            var expected_blake3: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.Blake3.hash(grant_wire, &expected_blake3, .{});
            try std.testing.expectEqualSlices(u8, &expected_blake3, &copy.digest);
            var expected_sha256: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(grant_wire, &expected_sha256, .{});
            try std.testing.expectEqualSlices(u8, &expected_sha256, &copy.wire_sha256);
            try std.testing.expectEqualSlices(u8, grant_wire, copy.signedWire());
            try std.testing.expect(std.mem.allEqual(u8, &copy.conflict_digest, 0));
        },
        else => return error.TestUnexpectedResult,
    }

    var successor_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const successor = try signOcg2RaceWire(kp, config, "alice", 2, .grant, "Successor", 1_000, 6_000, &successor_buf);
    var stable_race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .successor, .wires = .{ successor, "" } };
    switch (Internal.inspectDurableOperTransactionInner(&services, "alice", 1_000, stable_race.asHook())) {
        .active => |copy| {
            try std.testing.expectEqual(@as(u64, 2), copy.revision);
            try std.testing.expectEqualStrings("alice", copy.account());
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 2), stable_race.calls);

    var car_initial_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const car_initial = try signOcg2RaceWire(kp, config, "car", 1, .grant, "Initial", 1_000, 6_000, &car_initial_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(car_initial, 1_000));
    var car_successor_one_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const car_successor_one = try signOcg2RaceWire(kp, config, "car", 2, .grant, "One", 1_000, 6_000, &car_successor_one_buf);
    var car_successor_two_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const car_successor_two = try signOcg2RaceWire(kp, config, "car", 3, .grant, "Two", 1_000, 6_000, &car_successor_two_buf);
    var unstable_race = Ocg2AfterCopyRaceCtx{ .services = &services, .action = .two_successors, .wires = .{ car_successor_one, car_successor_two } };
    try std.testing.expectEqual(Services.DurableOperTransaction.unavailable, Internal.inspectDurableOperTransactionInner(&services, "car", 1_000, unstable_race.asHook()));
    try std.testing.expectEqual(@as(usize, 2), unstable_race.calls);
    try std.testing.expectEqual(@as(u64, 3), state.latest("car").?.revision);

    var tombstone_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const tombstone_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .tombstone,
        .account = "alice",
        .revision = 3,
        .privilege_bits = 0,
        .class = "",
        .title = "",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = 1_100,
        .expiry_ms = 0,
    }, 1_100, &tombstone_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(tombstone_buf[0..tombstone_len], 1_100));
    switch (services.inspectDurableOperTransaction("alice", 1_100)) {
        .tombstone => |copy| {
            try std.testing.expectEqualStrings("alice", copy.account());
            try std.testing.expectEqual(oper_cred_share.Ocg2Kind.tombstone, copy.kind);
            try std.testing.expectEqual(config.authority_node_id, copy.authority_node_id);
            try std.testing.expectEqualSlices(u8, &config.authority_pubkey, &copy.authority_pubkey);
            try std.testing.expectEqualSlices(u8, tombstone_buf[0..tombstone_len], copy.signedWire());
            var tombstone_blake3: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.Blake3.hash(copy.signedWire(), &tombstone_blake3, .{});
            try std.testing.expectEqualSlices(u8, &tombstone_blake3, &copy.digest);
            var tombstone_sha256: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(copy.signedWire(), &tombstone_sha256, .{});
            try std.testing.expectEqualSlices(u8, &tombstone_sha256, &copy.wire_sha256);
            try std.testing.expect(std.mem.allEqual(u8, &copy.conflict_digest, 0));
        },
        else => return error.TestUnexpectedResult,
    }

    var first_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const first_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "bob",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "First",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = 1_000,
        .expiry_ms = 5_000,
    }, 1_000, &first_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.committed, services.commitDurableOperRecord(first_buf[0..first_len], 1_000));
    var conflict_buf: [oper_cred_share.ocg2_max_wire_len]u8 = undefined;
    const conflict_len = try oper_cred_share.signOcg2(kp, .{
        .kind = .grant,
        .account = "bob",
        .revision = 1,
        .privilege_bits = 1 << 3,
        .class = "moderator",
        .title = "Conflict",
        .authority_node_id = config.authority_node_id,
        .authority_pubkey = config.authority_pubkey,
        .issued_ms = 1_000,
        .expiry_ms = 5_000,
    }, 1_000, &conflict_buf);
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.equivocation_committed, services.commitDurableOperRecord(conflict_buf[0..conflict_len], 1_000));
    switch (services.inspectDurableOperTransaction("BOB", 1_000)) {
        .equivocation => |copy| {
            try std.testing.expectEqualStrings("bob", copy.account());
            try std.testing.expect(copy.equivocation);
            try std.testing.expectEqual(config.authority_node_id, copy.authority_node_id);
            try std.testing.expectEqualSlices(u8, &config.authority_pubkey, &copy.authority_pubkey);
            try std.testing.expect(!std.mem.allEqual(u8, &copy.conflict_digest, 0));
            try std.testing.expect(!std.mem.eql(u8, &copy.digest, &copy.conflict_digest));
            try std.testing.expect(copy.signedWire().len != 0);
            var stored_blake3: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.Blake3.hash(copy.signedWire(), &stored_blake3, .{});
            try std.testing.expectEqualSlices(u8, &stored_blake3, &copy.digest);
            var stored_sha256: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(copy.signedWire(), &stored_sha256, .{});
            try std.testing.expectEqualSlices(u8, &stored_sha256, &copy.wire_sha256);
            var first_digest: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.Blake3.hash(first_buf[0..first_len], &first_digest, .{});
            var conflicting_digest: [durable_oper_authority.digest_len]u8 = undefined;
            std.crypto.hash.Blake3.hash(conflict_buf[0..conflict_len], &conflicting_digest, .{});
            const low = if (std.mem.order(u8, &first_digest, &conflicting_digest) == .lt) first_digest else conflicting_digest;
            const high = if (std.mem.order(u8, &first_digest, &conflicting_digest) == .lt) conflicting_digest else first_digest;
            try std.testing.expectEqualSlices(u8, &low, &copy.digest);
            try std.testing.expectEqualSlices(u8, &high, &copy.conflict_digest);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "OCG2ISSUER Services authority match and one-way fail-closed" {
    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xE1)));
    const public_key = kp.public_key.toBytes();
    const config = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(public_key)),
        .authority_pubkey = public_key,
    };
    const other_kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0xE2)));
    const other_key = other_kp.public_key.toBytes();
    const other = durable_oper_authority.Config{
        .authority_node_id = node_short_id_mod.shortId(node_identity_mod.nodeIdFromPublicKey(other_key)),
        .authority_pubkey = other_key,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try openTestStore(tmp, "services-ocg2issuer-match.wal");
    defer store.deinit();
    var services = Services.init(&store, null);
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.disabled, services.matchDurableOperAuthority(config));
    services.failClosedDurableOperAuthority();
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.disabled, services.matchDurableOperAuthority(config));

    var inactive = try durable_oper_authority.State.init(std.testing.allocator, config);
    defer inactive.deinit();
    Internal.attachInactiveDurableOperAuthorityForTest(&services, &inactive);
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.unavailable, services.matchDurableOperAuthority(config));
    switch (services.reserveDurableOperSecurityTime(1_000, 5_000)) {
        .committed => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.ready, services.matchDurableOperAuthority(config));
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.mismatch, services.matchDurableOperAuthority(other));
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.mismatch, services.matchDurableOperAuthority(.{
        .authority_node_id = 0,
        .authority_pubkey = public_key,
    }));
    const epoch = services.durable_oper_availability_epoch;
    services.failClosedDurableOperAuthority();
    try std.testing.expect(!inactive.servingAvailable());
    try std.testing.expectEqual(epoch + 1, services.durable_oper_availability_epoch);
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.unavailable, services.matchDurableOperAuthority(config));
    try std.testing.expectEqual(Services.DurableOperMergeOutcome.unavailable, services.commitDurableOperRecord("", 1_000));
    services.failClosedDurableOperAuthority();
    try std.testing.expectEqual(epoch + 2, services.durable_oper_availability_epoch);
    try std.testing.expectEqual(Services.DurableOperAuthorityMatch.unavailable, services.matchDurableOperAuthority(config));
}
