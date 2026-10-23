// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! clone tests.

const std = @import("std");
const model = @import("model.zig");
const prop_store = @import("store.zig");
const protocol = @import("protocol.zig");

test "prepared public channel clone is exact deterministic and independently owned" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const source = try model.Entity.fromId("#Template");
    const destination = try model.Entity.fromId("#Clone");
    const member_a = try model.Entity.fromId("#Clone:Alice");
    const member_b = try model.Entity.fromId("#clone:Bob");
    const near_prefix_member = try model.Entity.fromId("#Clone2:Eve");
    const unrelated = try model.Entity.fromId("Watcher");
    try std.testing.expectEqual(model.EntityKind.member, member_a.kind);
    try std.testing.expectEqual(model.EntityKind.member, member_b.kind);

    _ = try store.setProp(source, "TOPIC", "source topic", .{ .id = "source-host", .access = .host });
    _ = try store.setProp(source, "CUSTOM", "source custom", .{ .id = "source-host", .access = .host });
    _ = try store.setProp(source, "HOSTKEY", "source-secret", .{ .id = "source-owner", .access = .owner });
    _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "old-host", .access = .host });
    _ = try store.setProp(destination, "HOSTKEY", "destination-secret", .{ .id = "old-owner", .access = .owner });
    _ = try store.setProp(member_a, "ROLE", "old-op", .{ .id = "Alice", .access = .member });
    _ = try store.setProp(member_b, "NOTE", "old-note", .{ .id = "Bob", .access = .member });
    _ = try store.setProp(near_prefix_member, "ROLE", "keep-op", .{ .id = "Eve", .access = .member });
    _ = try store.setProp(unrelated, "BIO", "untouched", .{ .id = "Watcher", .access = .user });
    try std.testing.expectEqual(@as(usize, 6), store.entity_count);

    var ticket = try store.preparePublicChannelClone(source.id, destination.id);
    const replacements = ticket.replacementFacts();
    try std.testing.expectEqual(@as(usize, 2), replacements.len);
    try std.testing.expectEqualStrings("CUSTOM", replacements[0].key);
    try std.testing.expectEqualStrings("TOPIC", replacements[1].key);
    try std.testing.expectEqualStrings("source custom", replacements[0].value);
    try std.testing.expectEqualStrings("source-host", replacements[0].owner);
    try std.testing.expectEqual(model.AccessLevel.host, replacements[0].access);
    try std.testing.expectEqualStrings("source topic", replacements[1].value);
    try std.testing.expectEqualStrings("source-host", replacements[1].owner);
    try std.testing.expectEqual(model.AccessLevel.host, replacements[1].access);
    for (replacements) |fact| try std.testing.expectEqualStrings(destination.id, fact.entity.id);

    const purged = ticket.purgedFacts();
    try std.testing.expectEqual(@as(usize, 4), purged.len);
    try std.testing.expectEqual(model.EntityKind.channel, purged[0].entity.kind);
    try std.testing.expectEqualStrings("CUSTOM", purged[0].key);
    try std.testing.expectEqualStrings("HOSTKEY", purged[1].key);
    try std.testing.expectEqualStrings(member_a.id, purged[2].entity.id);
    try std.testing.expectEqualStrings("ROLE", purged[2].key);
    try std.testing.expectEqualStrings(member_b.id, purged[3].entity.id);
    try std.testing.expectEqualStrings("NOTE", purged[3].key);
    try std.testing.expectEqual(@as(usize, 3), ticket.purge_entity_keys.len);

    const staged = if (ticket.staged_state) |*state| state else return error.TestUnexpectedResult;
    try std.testing.expect(@intFromPtr(ticket.staged_outer_key.?.ptr) != @intFromPtr(staged.entity.id.ptr));
    try std.testing.expect(@intFromPtr(replacements[0].entity.id.ptr) != @intFromPtr(staged.entity.id.ptr));
    try std.testing.expect(@intFromPtr(replacements[0].entity.id.ptr) != @intFromPtr(replacements[1].entity.id.ptr));
    var staged_it = staged.props.iterator();
    while (staged_it.next()) |entry| {
        var preview: ?*const prop_store.DefaultStore.PreparedPropFact = null;
        for (replacements) |*fact| {
            if (std.mem.eql(u8, fact.key, entry.value_ptr.key)) {
                preview = fact;
                break;
            }
        }
        const fact = preview orelse return error.TestUnexpectedResult;
        try std.testing.expect(@intFromPtr(entry.key_ptr.*.ptr) != @intFromPtr(entry.value_ptr.key.ptr));
        try std.testing.expect(@intFromPtr(fact.key.ptr) != @intFromPtr(entry.key_ptr.*.ptr));
        try std.testing.expect(@intFromPtr(fact.key.ptr) != @intFromPtr(entry.value_ptr.key.ptr));
        try std.testing.expect(@intFromPtr(fact.value.ptr) != @intFromPtr(entry.value_ptr.value.ptr));
        try std.testing.expect(@intFromPtr(fact.owner.ptr) != @intFromPtr(entry.value_ptr.owner.ptr));
    }
    const live_source_custom = try store.getPropRaw(source, "CUSTOM");
    try std.testing.expect(@intFromPtr(live_source_custom.value.ptr) != @intFromPtr(replacements[0].value.ptr));
    const live_destination_secret = try store.getPropRaw(destination, "HOSTKEY");
    try std.testing.expect(@intFromPtr(live_destination_secret.value.ptr) != @intFromPtr(purged[1].value.ptr));

    // Abort is exact and every lifecycle operation is idempotent.
    ticket.abort();
    ticket.abort();
    ticket.deinit();
    try std.testing.expectEqual(@as(usize, 6), store.entity_count);
    try std.testing.expectEqualStrings("stale", (try store.getPropRaw(destination, "CUSTOM")).value);
    try std.testing.expectEqualStrings("destination-secret", (try store.getPropRaw(destination, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("old-op", (try store.getPropRaw(member_a, "ROLE")).value);

    var committed = try store.preparePublicChannelClone(source.id, destination.id);
    committed.commit();
    committed.commit();
    committed.abort();
    committed.deinit();
    try std.testing.expectEqual(@as(usize, 4), store.entity_count);
    try std.testing.expectEqualStrings("source custom", (try store.getPropRaw(destination, "CUSTOM")).value);
    try std.testing.expectEqualStrings("source topic", (try store.getPropRaw(destination, "TOPIC")).value);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "HOSTKEY"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_a, "ROLE"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_b, "NOTE"));
    try std.testing.expectEqualStrings("keep-op", (try store.getPropRaw(near_prefix_member, "ROLE")).value);
    try std.testing.expectEqualStrings("source-secret", (try store.getPropRaw(source, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("untouched", (try store.getPropRaw(unrelated, "BIO")).value);

    // The committed replacement owns bytes independently of the source.
    _ = try store.setProp(source, "CUSTOM", "source changed", .{ .id = "new-source", .access = .host });
    try std.testing.expectEqualStrings("source custom", (try store.getPropRaw(destination, "CUSTOM")).value);
    _ = try store.setProp(destination, "TOPIC", "destination changed", .{ .id = "new-dst", .access = .host });
    try std.testing.expectEqualStrings("source topic", (try store.getPropRaw(source, "TOPIC")).value);
}

test "prepared public channel clone rejects same fold and parser members round trip" {
    const member_request = try protocol.parseLine("PROP #room:Nick SET ROLE :operator");
    try std.testing.expectEqual(model.Request.set, @as(std.meta.Tag(model.Request), member_request));
    try std.testing.expectEqual(model.EntityKind.member, member_request.set.entity.kind);
    try std.testing.expectEqualStrings("#room:Nick", member_request.set.entity.id);

    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try model.Entity.fromId("#Same");
    _ = try store.setProp(source, "CUSTOM", "preserved", .{ .id = "host", .access = .host });
    try std.testing.expectError(error.InvalidEntity, store.preparePublicChannelClone("#Same", "#sAME"));
    try std.testing.expectEqual(@as(usize, 1), store.entity_count);
    try std.testing.expectEqualStrings("preserved", (try store.getPropRaw(source, "CUSTOM")).value);
    try std.testing.expectError(
        error.InvalidEntity,
        store.setProp(.{ .kind = .channel, .id = "#room:Nick" }, "CUSTOM", "bad", .{ .id = "host", .access = .host }),
    );
}

test "prepared public channel clone secret-only source clears destination exactly" {
    var store = prop_store.DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try model.Entity.fromId("#SecretTemplate");
    const destination = try model.Entity.fromId("#ClearMe");
    const member_a = try model.Entity.fromId("#ClearMe:Alice");
    const member_b = try model.Entity.fromId("#clearme:Bob");
    const unrelated = try model.Entity.fromId("Other");
    _ = try store.setProp(source, "HOSTKEY", "never-copy", .{ .id = "owner", .access = .owner });
    _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "host", .access = .host });
    _ = try store.setProp(member_a, "ROLE", "op", .{ .id = "Alice", .access = .member });
    _ = try store.setProp(member_b, "ROLE", "voice", .{ .id = "Bob", .access = .member });
    _ = try store.setProp(unrelated, "CUSTOM", "keep", .{ .id = "Other", .access = .user });
    try std.testing.expectEqual(@as(usize, 5), store.entity_count);

    var ticket = try store.preparePublicChannelClone(source.id, destination.id);
    try std.testing.expectEqual(@as(usize, 0), ticket.replacementFacts().len);
    try std.testing.expectEqual(@as(usize, 3), ticket.purgedFacts().len);
    try std.testing.expect(ticket.staged_outer_key == null);
    try std.testing.expect(ticket.staged_state == null);
    ticket.commit();
    defer ticket.deinit();

    try std.testing.expectEqual(@as(usize, 2), store.entity_count);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "CUSTOM"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_a, "ROLE"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_b, "ROLE"));
    try std.testing.expectEqualStrings("never-copy", (try store.getPropRaw(source, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("keep", (try store.getPropRaw(unrelated, "CUSTOM")).value);
}

test "prepared public channel clone uses post-purge entity cap math" {
    const Capped = prop_store.PropStore(.{ .max_entities = 5 });
    var store = Capped.init(std.testing.allocator);
    defer store.deinit();
    const source = try model.Entity.fromId("#Src");
    const destination = try model.Entity.fromId("#Dst");
    const member_a = try model.Entity.fromId("#Dst:A");
    const member_b = try model.Entity.fromId("#dst:B");
    const unrelated = try model.Entity.fromId("Other");
    _ = try store.setProp(source, "CUSTOM", "copy", .{ .id = "host", .access = .host });
    _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "host", .access = .host });
    _ = try store.setProp(member_a, "ROLE", "a", .{ .id = "A", .access = .member });
    _ = try store.setProp(member_b, "ROLE", "b", .{ .id = "B", .access = .member });
    _ = try store.setProp(unrelated, "CUSTOM", "keep", .{ .id = "Other", .access = .user });
    try std.testing.expectEqual(@as(usize, 5), store.entity_count);
    var ticket = try store.preparePublicChannelClone(source.id, destination.id);
    ticket.commit();
    defer ticket.deinit();
    try std.testing.expectEqual(@as(usize, 3), store.entity_count);
    try std.testing.expectEqualStrings("copy", (try store.getPropRaw(destination, "CUSTOM")).value);
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_a, "ROLE"));
    try std.testing.expectError(error.PropMissing, store.getPropRaw(member_b, "ROLE"));

    const NoRoom = prop_store.PropStore(.{ .max_entities = 2 });
    var no_room = NoRoom.init(std.testing.allocator);
    defer no_room.deinit();
    _ = try no_room.setProp(source, "CUSTOM", "copy", .{ .id = "host", .access = .host });
    _ = try no_room.setProp(unrelated, "CUSTOM", "keep", .{ .id = "Other", .access = .user });
    try std.testing.expectError(error.LimitReached, no_room.preparePublicChannelClone(source.id, "#Absent"));
    try std.testing.expectEqual(@as(usize, 2), no_room.entity_count);
    try std.testing.expectEqualStrings("copy", (try no_room.getPropRaw(source, "CUSTOM")).value);
    try std.testing.expectEqualStrings("keep", (try no_room.getPropRaw(unrelated, "CUSTOM")).value);
}

test "prepared public channel clone is atomic on every allocation boundary" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 256);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = prop_store.DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }

            const source = try model.Entity.fromId("#AllocSource");
            const destination = try model.Entity.fromId("#AllocDestination");
            const member = try model.Entity.fromId("#allocdestination:Nick");
            const unrelated = try model.Entity.fromId("Other");
            _ = try store.setProp(source, "CUSTOM", "copy", .{ .id = "source-host", .access = .host });
            _ = try store.setProp(source, "TOPIC", "copy-topic", .{ .id = "source-host", .access = .host });
            _ = try store.setProp(source, "HOSTKEY", "source-secret", .{ .id = "source-owner", .access = .owner });
            _ = try store.setProp(destination, "CUSTOM", "stale", .{ .id = "old-host", .access = .host });
            _ = try store.setProp(destination, "HOSTKEY", "destination-secret", .{ .id = "old-owner", .access = .owner });
            _ = try store.setProp(member, "ROLE", "old-role", .{ .id = "Nick", .access = .member });
            _ = try store.setProp(unrelated, "CUSTOM", "untouched", .{ .id = "Other", .access = .user });
            try std.testing.expectEqual(@as(usize, 4), store.entity_count);

            failing.fail_index = failing.alloc_index + fail_offset;
            var prepared = store.preparePublicChannelClone(source.id, destination.id) catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.LimitReached, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(@as(usize, 4), store.entity_count);
                try std.testing.expectEqualStrings("copy", (try store.getPropRaw(source, "CUSTOM")).value);
                try std.testing.expectEqualStrings("copy-topic", (try store.getPropRaw(source, "TOPIC")).value);
                try std.testing.expectEqualStrings("source-secret", (try store.getPropRaw(source, "HOSTKEY")).value);
                try std.testing.expectEqualStrings("stale", (try store.getPropRaw(destination, "CUSTOM")).value);
                try std.testing.expectEqualStrings("destination-secret", (try store.getPropRaw(destination, "HOSTKEY")).value);
                try std.testing.expectEqualStrings("old-role", (try store.getPropRaw(member, "ROLE")).value);
                try std.testing.expectEqualStrings("untouched", (try store.getPropRaw(unrelated, "CUSTOM")).value);
                break :blk false;
            };
            try std.testing.expect(!failing.has_induced_failure);

            // Once preparation succeeds, abort remains allocation-free even
            // when the allocator would reject the very next allocation.
            failing.fail_index = failing.alloc_index;
            failing.has_induced_failure = false;
            prepared.abort();
            prepared.abort();
            prepared.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 4), store.entity_count);
            try std.testing.expectEqualStrings("stale", (try store.getPropRaw(destination, "CUSTOM")).value);
            try std.testing.expectEqualStrings("old-role", (try store.getPropRaw(member, "ROLE")).value);

            // Re-prepare without injection, then prove commit is also fully
            // allocation-free under an immediate-failure allocator.
            failing.fail_index = std.math.maxInt(usize);
            var committed = try store.preparePublicChannelClone(source.id, destination.id);
            failing.has_induced_failure = false;
            failing.fail_index = failing.alloc_index;
            committed.commit();
            committed.commit();
            committed.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 3), store.entity_count);
            try std.testing.expectEqualStrings("copy", (try store.getPropRaw(destination, "CUSTOM")).value);
            try std.testing.expectEqualStrings("copy-topic", (try store.getPropRaw(destination, "TOPIC")).value);
            try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "HOSTKEY"));
            try std.testing.expectError(error.PropMissing, store.getPropRaw(member, "ROLE"));
            try std.testing.expectEqualStrings("source-secret", (try store.getPropRaw(source, "HOSTKEY")).value);
            try std.testing.expectEqualStrings("untouched", (try store.getPropRaw(unrelated, "CUSTOM")).value);
            break :blk true;
        };
        if (completed) break;
    }
}

test "prepared public channel clone reserves a fresh target and handles an all-zero plan" {
    // Missing source plus missing destination is a valid no-op ticket, including
    // zero-length owned plans and repeated lifecycle calls.
    var empty_store = prop_store.DefaultStore.init(std.testing.allocator);
    defer empty_store.deinit();
    var empty = try empty_store.preparePublicChannelClone("#Missing", "#FreshEmpty");
    try std.testing.expectEqual(@as(usize, 0), empty.replacementFacts().len);
    try std.testing.expectEqual(@as(usize, 0), empty.purgedFacts().len);
    empty.commit();
    empty.commit();
    empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_store.entity_count);

    // Fill the live outer map to its load threshold so the absent-destination
    // branch must reserve a new map before returning a prepared ticket.
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 128);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = prop_store.DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const source = try model.Entity.fromId("#FreshSource");
            const destination = try model.Entity.fromId("#FreshTarget");
            _ = try store.setProp(source, "CUSTOM", "fresh-copy", .{ .id = "host", .access = .host });

            const load_limit = (store.entities.capacity() * std.hash_map.default_max_load_percentage) / 100;
            var filler_index: usize = 0;
            var filler_buf: [32]u8 = undefined;
            while (store.entities.count() < load_limit) : (filler_index += 1) {
                const filler_id = std.fmt.bufPrint(&filler_buf, "Filler-{d}", .{filler_index}) catch unreachable;
                _ = try store.setProp(try model.Entity.fromId(filler_id), "CUSTOM", "keep", .{ .id = "filler", .access = .user });
            }
            try std.testing.expectEqual(load_limit, store.entities.count());
            const initial_count = store.entity_count;

            failing.fail_index = failing.alloc_index + fail_offset;
            var prepared = store.preparePublicChannelClone(source.id, destination.id) catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.LimitReached, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(initial_count, store.entity_count);
                try std.testing.expectEqualStrings("fresh-copy", (try store.getPropRaw(source, "CUSTOM")).value);
                try std.testing.expectError(error.PropMissing, store.getPropRaw(destination, "CUSTOM"));
                break :blk false;
            };
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 1), prepared.replacementFacts().len);
            try std.testing.expectEqual(@as(usize, 0), prepared.purgedFacts().len);

            failing.has_induced_failure = false;
            failing.fail_index = failing.alloc_index;
            prepared.commit();
            prepared.deinit();
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(initial_count + 1, store.entity_count);
            try std.testing.expectEqualStrings("fresh-copy", (try store.getPropRaw(source, "CUSTOM")).value);
            try std.testing.expectEqualStrings("fresh-copy", (try store.getPropRaw(destination, "CUSTOM")).value);
            break :blk true;
        };
        if (completed) break;
    }
}
