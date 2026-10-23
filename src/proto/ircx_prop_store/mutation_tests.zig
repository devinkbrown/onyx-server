// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! mutation tests.

const std = @import("std");
const model = @import("model.zig");
const prop_store = @import("store.zig");
const protocol = @import("protocol.zig");

test "set get overwrite delete and list properties" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try model.Entity.fromId("#Onyx");
    const setter = model.Setter{ .id = "alice", .access = .owner };

    const first = try store.setProp(entity, "topic", "first", setter);
    try std.testing.expectEqualStrings("TOPIC", first.key);
    try std.testing.expectEqualStrings("first", first.value);
    try std.testing.expectEqualStrings("alice", first.owner);
    try std.testing.expectEqual(model.AccessLevel.owner, first.access);

    _ = try store.setProp(entity, "TOPIC", "second", .{ .id = "bob", .access = .owner });
    const got = try store.getProp(entity, "topic");
    try std.testing.expectEqualStrings("second", got.value);
    try std.testing.expectEqualStrings("bob", got.owner);

    _ = try store.setProp(entity, "SUBJECT", "zig", setter);
    var out: [4]model.EntryView = undefined;
    const listed = try store.listProps(try model.Entity.fromId("#onyx"), &out);
    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqualStrings("SUBJECT", listed[0].key);
    try std.testing.expectEqualStrings("TOPIC", listed[1].key);

    try store.deleteProp(entity, "topic");
    try std.testing.expectError(error.PropMissing, store.getProp(entity, "topic"));
    try std.testing.expectEqual(@as(usize, 1), (try store.listProps(entity, &out)).len);
    try store.deleteProp(entity, "subject");
    try std.testing.expectEqual(@as(usize, 0), (try store.listProps(entity, &out)).len);
}

test "user PROP capacity coexists to 128 while channel bound remains 64" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try model.Entity.fromId("DeviceHeavyUser");
    const channel = try model.Entity.fromId("#bounded");
    var key_buf: [32]u8 = undefined;
    for (0..model.user_max_props_per_entity) |index| {
        const key = try std.fmt.bufPrint(&key_buf, "device.fact.{d}", .{index});
        _ = try store.setProp(user, key, "v", .{ .id = "DeviceHeavyUser", .access = .user });
    }
    try std.testing.expectError(
        error.LimitReached,
        store.setProp(user, "device.fact.overflow", "v", .{ .id = "DeviceHeavyUser", .access = .user }),
    );
    for (0..model.default_max_props_per_entity) |index| {
        const key = try std.fmt.bufPrint(&key_buf, "channel.fact.{d}", .{index});
        _ = try store.setProp(channel, key, "v", .{ .id = "host", .access = .host });
    }
    try std.testing.expectError(
        error.LimitReached,
        store.setProp(channel, "channel.fact.overflow", "v", .{ .id = "host", .access = .host }),
    );
}

test "prepared delete is allocation complete copy safe stale safe and missing inert" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var store = prop_store.DefaultStore.init(failing.allocator());
    defer {
        failing.fail_index = std.math.maxInt(usize);
        store.deinit();
    }
    const user = try model.Entity.fromId("DeleteUser");
    _ = try store.setProp(user, "keep", "yes", .{ .id = "DeleteUser", .access = .user });
    _ = try store.setProp(user, "remove", "yes", .{ .id = "DeleteUser", .access = .user });

    const ticket = try store.prepareDeleteProp(user, "remove");
    const copied = ticket;
    failing.fail_index = failing.alloc_index;
    try std.testing.expect(ticket.commit());
    try std.testing.expect(!copied.commit());
    copied.abort();
    copied.deinit();
    try std.testing.expectError(error.PropMissing, store.getPropRaw(user, "remove"));
    try std.testing.expectEqualStrings("yes", (try store.getPropRaw(user, "keep")).value);

    failing.fail_index = std.math.maxInt(usize);
    const stale = try store.prepareDeleteProp(user, "keep");
    const missing = try store.prepareDeleteProp(user, "absent");
    try std.testing.expect(!stale.commit());
    failing.fail_index = failing.alloc_index;
    try std.testing.expect(!missing.commit());
    try std.testing.expectEqualStrings("yes", (try store.getPropRaw(user, "keep")).value);
}

test "prepared SET serializes destructive mutations until lifecycle release" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try model.Entity.fromId("SerializedSetUser");
    const setter = model.Setter{ .id = "SerializedSetUser", .access = .user };
    _ = try store.setProp(user, "only", "old", setter);

    var set_ticket = try store.prepareSetProp(user, "only", "new", setter);
    try std.testing.expectError(error.PreparedMutationActive, store.prepareDeleteProp(user, "only"));
    try std.testing.expectError(error.PreparedMutationActive, store.prepareUserPropPrefixPurge(user, "on"));
    try std.testing.expectError(error.PreparedMutationActive, store.deleteProp(user, "only"));
    try std.testing.expectError(error.PreparedMutationActive, store.clearEntity(user));
    try std.testing.expectEqualStrings("old", (try store.getPropRaw(user, "only")).value);
    const committed = set_ticket.commit();
    try std.testing.expectEqualStrings("new", committed.value);
    try std.testing.expectEqualStrings("new", (try store.getPropRaw(user, "only")).value);

    var aborted = try store.prepareSetProp(user, "other", "value", setter);
    aborted.abort();
    var deletion = try store.prepareDeleteProp(user, "only");
    try std.testing.expect(deletion.commit());
    store.clearChannel("#unrelated");
}

test "prepared SET and public channel clone serialize in both directions" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try model.Entity.fromId("#CloneSource");
    const destination = try model.Entity.fromId("#CloneDestination");
    const user = try model.Entity.fromId("CloneSetUser");
    _ = try store.setProp(source, "CUSTOM", "source", .{ .id = "host", .access = .host });
    _ = try store.setProp(destination, "CUSTOM", "old", .{ .id = "host", .access = .host });
    _ = try store.setProp(user, "keep", "old", .{ .id = "CloneSetUser", .access = .user });

    var set_first = try store.prepareSetProp(user, "keep", "new", .{ .id = "CloneSetUser", .access = .user });
    try std.testing.expectError(
        error.PreparedMutationActive,
        store.preparePublicChannelClone(source.id, destination.id),
    );
    _ = set_first.commit();
    var clone_after = try store.preparePublicChannelClone(source.id, destination.id);
    clone_after.abort();

    var clone_first = try store.preparePublicChannelClone(source.id, destination.id);
    try std.testing.expectError(
        error.PreparedMutationActive,
        store.prepareSetProp(user, "later", "value", .{ .id = "CloneSetUser", .access = .user }),
    );
    try std.testing.expectError(error.PreparedMutationActive, store.deleteProp(destination, "CUSTOM"));
    try std.testing.expectError(error.PreparedMutationActive, store.clearEntity(destination));
    clone_first.commit();
    try std.testing.expectEqualStrings("source", (try store.getPropRaw(destination, "CUSTOM")).value);
    var set_after = try store.prepareSetProp(user, "later", "value", .{ .id = "CloneSetUser", .access = .user });
    _ = set_after.commit();
    try std.testing.expectEqualStrings("value", (try store.getPropRaw(user, "later")).value);
}

test "prepared delete and purge become stale when SET preparation wins" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try model.Entity.fromId("SetWinsUser");
    const setter = model.Setter{ .id = "SetWinsUser", .access = .user };
    _ = try store.setProp(user, "e2ee.device.old", "old", setter);
    _ = try store.setProp(user, "keep", "keep", setter);

    const deletion = try store.prepareDeleteProp(user, "keep");
    var first_set = try store.prepareSetProp(user, "new", "new", setter);
    try std.testing.expect(!deletion.commit());
    _ = first_set.commit();
    try std.testing.expectEqualStrings("keep", (try store.getPropRaw(user, "keep")).value);

    const purge = try store.prepareUserPropPrefixPurge(user, "e2ee.device.");
    var second_set = try store.prepareSetProp(user, "newer", "newer", setter);
    try std.testing.expectEqual(@as(usize, 0), purge.commit());
    _ = second_set.commit();
    try std.testing.expectEqualStrings("old", (try store.getPropRaw(user, "e2ee.device.old")).value);
}

test "prepared delete and purge generation exhaustion is fail closed" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try model.Entity.fromId("ExhaustedGenerationUser");
    const setter = model.Setter{ .id = "ExhaustedGenerationUser", .access = .user };
    _ = try store.setProp(user, "e2ee.device.old", "old", setter);

    store.prepared_delete_generation = std.math.maxInt(u64) - 1;
    const last_delete = try store.prepareDeleteProp(user, "e2ee.device.old");
    const copied_delete = last_delete;
    try std.testing.expect(last_delete.commit());
    try std.testing.expect(!copied_delete.commit());
    try std.testing.expectError(error.PreparedGenerationExhausted, store.prepareDeleteProp(user, "missing"));

    _ = try store.setProp(user, "e2ee.device.new", "new", setter);
    store.prepared_purge_generation = std.math.maxInt(u64) - 1;
    const last_purge = try store.prepareUserPropPrefixPurge(user, "e2ee.device.");
    const copied_purge = last_purge;
    try std.testing.expectEqual(@as(usize, 1), last_purge.commit());
    try std.testing.expectEqual(@as(usize, 0), copied_purge.commit());
    try std.testing.expectError(
        error.PreparedGenerationExhausted,
        store.prepareUserPropPrefixPurge(user, "e2ee.device."),
    );
}

test "prepared user prefix purge is exact allocation complete and copy safe" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var store = prop_store.DefaultStore.init(failing.allocator());
    defer {
        failing.fail_index = std.math.maxInt(usize);
        store.deinit();
    }
    const user = try model.Entity.fromId("PurgeUser");
    const other = try model.Entity.fromId("OtherUser");
    const setter = model.Setter{ .id = "PurgeUser", .access = .user };
    _ = try store.setProp(user, "e2ee.device.alpha", "a", setter);
    _ = try store.setProp(user, "E2EE.DEVICE.beta", "b", setter);
    _ = try store.setProp(user, "e2ee.deviceX.near", "near", setter);
    _ = try store.setProp(user, "profile.keep", "keep", setter);
    _ = try store.setProp(other, "e2ee.device.alpha", "other", .{ .id = "OtherUser", .access = .user });

    const ticket = try store.prepareUserPropPrefixPurge(user, "E2EE.DEVICE.");
    const copied = ticket;
    try std.testing.expectEqual(@as(usize, 2), ticket.count());
    failing.fail_index = failing.alloc_index;
    try std.testing.expectEqual(@as(usize, 2), ticket.commit());
    try std.testing.expectEqual(@as(usize, 0), copied.commit());
    copied.abort();
    copied.deinit();
    try std.testing.expectError(error.PropMissing, store.getPropRaw(user, "e2ee.device.alpha"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(user, "e2ee.device.beta"));
    try std.testing.expectEqualStrings("near", (try store.getPropRaw(user, "e2ee.deviceX.near")).value);
    try std.testing.expectEqualStrings("keep", (try store.getPropRaw(user, "profile.keep")).value);
    try std.testing.expectEqualStrings("other", (try store.getPropRaw(other, "e2ee.device.alpha")).value);

    failing.fail_index = std.math.maxInt(usize);
    const stale = try store.prepareUserPropPrefixPurge(user, "no.match.");
    const replacement = try store.prepareUserPropPrefixPurge(user, "still.none.");
    try std.testing.expectEqual(@as(usize, 0), stale.commit());
    try std.testing.expectEqual(@as(usize, 0), replacement.commit());
    try std.testing.expectError(
        error.InvalidEntity,
        store.prepareUserPropPrefixPurge(try model.Entity.fromId("#not-user"), "e2ee.device."),
    );
}

test "prepared user prefix purge preparation is allocation failure atomic" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 16);
        const complete = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = prop_store.DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const user = try model.Entity.fromId("AtomicPurgeUser");
            const setter = model.Setter{ .id = "AtomicPurgeUser", .access = .user };
            _ = try store.setProp(user, "e2ee.device.one", "one", setter);
            _ = try store.setProp(user, "e2ee.device.two", "two", setter);
            _ = try store.setProp(user, "keep", "keep", setter);

            failing.fail_index = failing.alloc_index + fail_offset;
            const ticket = store.prepareUserPropPrefixPurge(user, "e2ee.device.") catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.LimitReached, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqualStrings("one", (try store.getPropRaw(user, "e2ee.device.one")).value);
                try std.testing.expectEqualStrings("two", (try store.getPropRaw(user, "e2ee.device.two")).value);
                try std.testing.expectEqualStrings("keep", (try store.getPropRaw(user, "keep")).value);
                break :blk false;
            };
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(@as(usize, 2), ticket.count());
            ticket.abort();
            ticket.abort();
            ticket.deinit();
            try std.testing.expectEqualStrings("one", (try store.getPropRaw(user, "e2ee.device.one")).value);
            break :blk true;
        };
        if (complete) break;
    }
}

test "128 user properties survive PROP checkpoint round trip" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try model.Entity.fromId("CheckpointDeviceUser");
    var key_buf: [32]u8 = undefined;
    for (0..model.user_max_props_per_entity) |index| {
        const key = try std.fmt.bufPrint(&key_buf, "device.checkpoint.{d}", .{index});
        _ = try store.setProp(user, key, "v", .{ .id = "CheckpointDeviceUser", .access = .user });
    }
    const checkpoint = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);
    var restored = try prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, checkpoint);
    defer restored.deinit();
    var views: [model.user_max_props_per_entity]model.EntryView = undefined;
    try std.testing.expectEqual(model.user_max_props_per_entity, (try restored.listPropsRaw(user, &views)).len);
}

test "global user prefix purge removes every folded and malformed match only" {
    try std.testing.expect(@hasDecl(prop_store.DefaultStore, "prepareGlobalDevicePropPurge"));
    try std.testing.expect(!@hasDecl(prop_store.DefaultStore, "prepareGlobalUserPropPrefixPurge"));
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const alice = try model.Entity.fromId("Alice");
    const bob = try model.Entity.fromId("Bob");
    const absent = try model.Entity.fromId("AbsentFromDprop");
    const channel = try model.Entity.fromId("#device-channel");
    const member = try model.Entity.fromId("#device-channel:Alice");
    _ = try store.setProp(alice, "e2ee.device.phone", "a", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(alice, "E2EE.DEVICE.", "malformed-empty", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(alice, "e2ee.device..odd", "malformed-dot", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(alice, "profile.keep", "keep-a", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(bob, "E2eE.DeViCe.tablet", "b", .{ .id = "Bob", .access = .user });
    _ = try store.setProp(bob, "e2ee.deviceX.near", "near", .{ .id = "Bob", .access = .user });
    _ = try store.setProp(bob, "e2ee.profile.keep", "broader", .{ .id = "Bob", .access = .user });
    _ = try store.setProp(bob, "device.phone", "narrower", .{ .id = "Bob", .access = .user });
    _ = try store.setProp(absent, "profile.keep", "keep-absent", .{ .id = "AbsentFromDprop", .access = .user });
    _ = try store.setProp(channel, "e2ee.device.phone", "channel", .{ .id = "host", .access = .host });
    _ = try store.setProp(member, "e2ee.device.phone", "member", .{ .id = "Alice", .access = .member });
    const initial_entities = store.entity_count;

    const ticket = try store.prepareGlobalDevicePropPurge();
    const copy = ticket;
    try std.testing.expectEqual(@as(usize, 4), ticket.count());
    try std.testing.expectEqual(@as(usize, 4), ticket.commit());
    try std.testing.expectEqual(@as(usize, 0), copy.commit());
    copy.abort();
    copy.deinit();

    try std.testing.expectError(error.PropMissing, store.getPropRaw(alice, "e2ee.device.phone"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(alice, "e2ee.device."));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(alice, "e2ee.device..odd"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(bob, "e2ee.device.tablet"));
    try std.testing.expectEqualStrings("keep-a", (try store.getPropRaw(alice, "profile.keep")).value);
    try std.testing.expectEqualStrings("near", (try store.getPropRaw(bob, "e2ee.deviceX.near")).value);
    try std.testing.expectEqualStrings("broader", (try store.getPropRaw(bob, "e2ee.profile.keep")).value);
    try std.testing.expectEqualStrings("narrower", (try store.getPropRaw(bob, "device.phone")).value);
    try std.testing.expectEqualStrings("keep-absent", (try store.getPropRaw(absent, "profile.keep")).value);
    try std.testing.expectEqualStrings("channel", (try store.getPropRaw(channel, "e2ee.device.phone")).value);
    try std.testing.expectEqualStrings("member", (try store.getPropRaw(member, "e2ee.device.phone")).value);
    try std.testing.expectEqual(initial_entities, store.entity_count);
}

test "global user prefix purge removes empty users and zero match is inert" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const only = try model.Entity.fromId("OnlyDevice");
    _ = try store.setProp(only, "e2ee.device.one", "one", .{ .id = "OnlyDevice", .access = .user });
    const before = store.entity_count;
    const purge = try store.prepareGlobalDevicePropPurge();
    try std.testing.expectEqual(@as(usize, 1), purge.commit());
    try std.testing.expectEqual(before - 1, store.entity_count);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(only, "e2ee.device.one"));

    const zero = try store.prepareGlobalDevicePropPurge();
    const zero_copy = zero;
    try std.testing.expectEqual(@as(usize, 0), zero.count());
    try std.testing.expectEqual(@as(usize, 0), zero.commit());
    try std.testing.expectEqual(@as(usize, 0), zero_copy.commit());
}

test "E5E1 global identity purge folds case includes malformed user suffixes and preserves near member channel" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = model.Entity{ .kind = .user, .id = "Alice" };
    _ = try store.setProp(user, "IDENTITY.KEY.Primary", "key", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(user, "Identity.Residence.abc", "proof", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(user, "identity.keyX.keep", "near", .{ .id = "Alice", .access = .user });
    _ = try store.setProp(.{ .kind = .member, .id = "#room:Alice" }, "identity.key.member", "member", .{ .id = "Alice", .access = .member });
    _ = try store.setProp(.{ .kind = .channel, .id = "#room" }, "identity.residence.channel", "channel", .{ .id = "Alice", .access = .host });

    const purge = try store.prepareGlobalIdentityPropPurge();
    try std.testing.expectEqual(@as(usize, 2), purge.count());
    try std.testing.expectEqual(@as(usize, 2), purge.commit());
    try std.testing.expectError(error.PropMissing, store.getPropRaw(user, "identity.key.primary"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(user, "identity.residence.abc"));
    try std.testing.expectEqualStrings("near", (try store.getPropRaw(user, "identity.keyX.keep")).value);
    try std.testing.expectEqualStrings("member", (try store.getPropRaw(.{ .kind = .member, .id = "#room:Alice" }, "identity.key.member")).value);
    try std.testing.expectEqualStrings("channel", (try store.getPropRaw(.{ .kind = .channel, .id = "#room" }, "identity.residence.channel")).value);
}

test "global user prefix purge preparation is allocation failure atomic" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 32);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = prop_store.DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const one = try model.Entity.fromId("GlobalOne");
            const two = try model.Entity.fromId("GlobalTwo");
            _ = try store.setProp(one, "e2ee.device.one", "one", .{ .id = "GlobalOne", .access = .user });
            _ = try store.setProp(two, "e2ee.device.two", "two", .{ .id = "GlobalTwo", .access = .user });
            _ = try store.setProp(two, "keep", "keep", .{ .id = "GlobalTwo", .access = .user });
            failing.fail_index = failing.alloc_index + fail_offset;
            const ticket = store.prepareGlobalDevicePropPurge() catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqualStrings("one", (try store.getPropRaw(one, "e2ee.device.one")).value);
                try std.testing.expectEqualStrings("two", (try store.getPropRaw(two, "e2ee.device.two")).value);
                break :blk false;
            };
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(@as(usize, 2), ticket.count());
            ticket.abort();
            ticket.deinit();
            try std.testing.expectEqualStrings("one", (try store.getPropRaw(one, "e2ee.device.one")).value);
            break :blk true;
        };
        if (completed) break;
    }
}

test "allocation-aware prepared set reports OOM while true entity capacity stays LimitReached" {
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = prop_store.DefaultStore.init(allocator);
            defer store.deinit();
            _ = try store.setPropAllocationAware(
                try model.Entity.fromId("AllocationAwareUser"),
                "profile.atomic",
                "value",
                .{ .id = "AllocationAwareUser", .access = .user },
            );
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});

    const OneEntityStore = prop_store.PropStore(.{ .max_entities = 1 });
    var full = OneEntityStore.init(std.testing.allocator);
    defer full.deinit();
    _ = try full.setPropAllocationAware(
        try model.Entity.fromId("FirstUser"),
        "profile.atomic",
        "first",
        .{ .id = "FirstUser", .access = .user },
    );
    try std.testing.expectError(
        error.LimitReached,
        full.prepareSetPropAllocationAware(
            try model.Entity.fromId("SecondUser"),
            "profile.atomic",
            "second",
            .{ .id = "SecondUser", .access = .user },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), full.entity_count);
    try std.testing.expectError(error.PropMissing, full.getPropRaw(try model.Entity.fromId("SecondUser"), "profile.atomic"));
}

test "global user prefix purge serializes prepared lanes and exhausts fail closed" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try model.Entity.fromId("GlobalSerial");
    const source = try model.Entity.fromId("#GlobalSource");
    const destination = try model.Entity.fromId("#GlobalDestination");
    const setter = model.Setter{ .id = "GlobalSerial", .access = .user };
    _ = try store.setProp(user, "e2ee.device.one", "one", setter);
    _ = try store.setProp(source, "CUSTOM", "source", .{ .id = "host", .access = .host });

    var set_first = try store.prepareSetProp(user, "keep", "keep", setter);
    try std.testing.expectError(error.PreparedMutationActive, store.prepareGlobalDevicePropPurge());
    set_first.abort();
    const delete_first = try store.prepareDeleteProp(user, "e2ee.device.one");
    try std.testing.expectError(error.PreparedMutationActive, store.prepareGlobalDevicePropPurge());
    delete_first.abort();
    const per_user_first = try store.prepareUserPropPrefixPurge(user, "e2ee.device.");
    try std.testing.expectError(error.PreparedMutationActive, store.prepareGlobalDevicePropPurge());
    per_user_first.abort();
    var clone_first = try store.preparePublicChannelClone(source.id, destination.id);
    try std.testing.expectError(error.PreparedMutationActive, store.prepareGlobalDevicePropPurge());
    clone_first.abort();

    var global = try store.prepareGlobalDevicePropPurge();
    try std.testing.expectError(error.PreparedMutationActive, store.prepareDeleteProp(user, "e2ee.device.one"));
    try std.testing.expectError(error.PreparedMutationActive, store.prepareUserPropPrefixPurge(user, "e2ee.device."));
    try std.testing.expectError(error.PreparedMutationActive, store.preparePublicChannelClone(source.id, destination.id));
    var set_wins = try store.prepareSetProp(user, "keep", "keep", setter);
    try std.testing.expectEqual(@as(usize, 0), global.commit());
    _ = set_wins.commit();
    try std.testing.expectEqualStrings("one", (try store.getPropRaw(user, "e2ee.device.one")).value);

    store.prepared_global_purge_generation = std.math.maxInt(u64) - 1;
    const last = try store.prepareGlobalDevicePropPurge();
    const last_copy = last;
    try std.testing.expectEqual(@as(usize, 1), last.commit());
    try std.testing.expectEqual(@as(usize, 0), last_copy.commit());
    try std.testing.expectError(
        error.PreparedGenerationExhausted,
        store.prepareGlobalDevicePropPurge(),
    );
}
