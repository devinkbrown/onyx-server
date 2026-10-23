// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! checkpoint tests.

const std = @import("std");
const model = @import("model.zig");
const checkpoint_codec = @import("checkpoint.zig");
const prop_store = @import("store.zig");
const protocol = @import("protocol.zig");
const support = @import("test_support.zig");

test "PROP checkpoint is deterministic complete and independently owned" {
    var first = prop_store.DefaultStore.init(std.testing.allocator);
    defer first.deinit();
    var second = prop_store.DefaultStore.init(std.testing.allocator);
    defer second.deinit();
    try support.installPropCheckpointFixture(&first, false);
    try support.installPropCheckpointFixture(&second, true);

    const first_bytes = try first.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(first_bytes);
    const second_bytes = try second.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(second_bytes);
    try std.testing.expectEqualSlices(u8, first_bytes, second_bytes);

    var restored = try prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, first_bytes);
    defer restored.deinit();
    try std.testing.expectEqual(first.entity_count, restored.entity_count);
    try std.testing.expectEqual(@as(usize, 6), restored.entity_count);
    const mixed = try model.Entity.fromId("#MiXeD");
    try std.testing.expectEqualStrings("mesh-secret", (try restored.getPropRaw(mixed, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("future-value", (try restored.getPropRaw(mixed, "future-x")).value);
    const restored_topic = try restored.getPropRaw(mixed, "TOPIC");
    try std.testing.expectEqual(@as(usize, 200), restored_topic.value.len);
    try std.testing.expectEqualStrings("legacy-user", restored_topic.owner);
    try std.testing.expectEqual(model.AccessLevel.user, restored_topic.access);
    try std.testing.expectEqualStrings(
        "case-preserved",
        (try restored.getPropRaw(try model.Entity.fromId("CaseUser"), "BIO")).value,
    );
    try std.testing.expectEqualStrings(
        "operator",
        (try restored.getPropRaw(try model.Entity.fromId("#MiXeD:Alice"), "ROLE")).value,
    );

    var zero_key_buf: [support.default_max_entity_key]u8 = undefined;
    const zero_entity = try model.Entity.fromId("ZeroState");
    const zero_key = try model.writeEntityKey(&zero_key_buf, zero_entity, model.default_max_entity_id);
    const zero_state = restored.entities.getPtr(zero_key) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), zero_state.prop_count);
    try std.testing.expectEqual(@as(usize, 0), zero_state.props.count());

    var mixed_key_buf: [support.default_max_entity_key]u8 = undefined;
    const mixed_key = try model.writeEntityKey(&mixed_key_buf, mixed, model.default_max_entity_id);
    const outer = restored.entities.getEntry(mixed_key) orelse return error.TestUnexpectedResult;
    try std.testing.expect(@intFromPtr(outer.key_ptr.*.ptr) != @intFromPtr(outer.value_ptr.entity.id.ptr));
    try std.testing.expect(!support.testSliceAliasesBytes(first_bytes, outer.key_ptr.*));
    try std.testing.expect(!support.testSliceAliasesBytes(first_bytes, outer.value_ptr.entity.id));
    var prop_key_buf: [model.default_max_key]u8 = undefined;
    const prop_key = try model.writePropKey(&prop_key_buf, "FuTuRe-X", model.default_max_key);
    const prop = outer.value_ptr.props.getEntry(prop_key) orelse return error.TestUnexpectedResult;
    try std.testing.expect(@intFromPtr(prop.key_ptr.*.ptr) != @intFromPtr(prop.value_ptr.key.ptr));
    try std.testing.expect(!support.testSliceAliasesBytes(first_bytes, prop.key_ptr.*));
    try std.testing.expect(!support.testSliceAliasesBytes(first_bytes, prop.value_ptr.key));
    try std.testing.expect(!support.testSliceAliasesBytes(first_bytes, prop.value_ptr.value));
    try std.testing.expect(!support.testSliceAliasesBytes(first_bytes, prop.value_ptr.owner));

    const round_trip = try restored.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(round_trip);
    try std.testing.expectEqualSlices(u8, first_bytes, round_trip);

    var empty = prop_store.DefaultStore.init(std.testing.allocator);
    defer empty.deinit();
    const empty_bytes = try empty.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(empty_bytes);
    try std.testing.expectEqual(
        checkpoint_codec.prop_checkpoint_header_len + checkpoint_codec.prop_checkpoint_checksum_len,
        empty_bytes.len,
    );
    var empty_restored = try prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, empty_bytes);
    defer empty_restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_restored.entity_count);
}

test "PROP checkpoint replacement is atomic and validates private cached state" {
    var source = prop_store.DefaultStore.init(std.testing.allocator);
    defer source.deinit();
    try support.installPropCheckpointFixture(&source, false);
    const checkpoint = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);

    var target = prop_store.DefaultStore.init(std.testing.allocator);
    defer target.deinit();
    const sentinel = try model.Entity.fromId("Sentinel");
    _ = try target.setProp(sentinel, "CUSTOM", "old-state", .{ .id = "Sentinel", .access = .user });
    try target.replaceFromCheckpoint(checkpoint);
    try std.testing.expectError(error.PropMissing, target.getPropRaw(sentinel, "CUSTOM"));
    try std.testing.expectEqualStrings(
        "mesh-secret",
        (try target.getPropRaw(try model.Entity.fromId("#MiXeD"), "HOSTKEY")).value,
    );

    source.entity_count += 1;
    try std.testing.expectError(error.CachedCountMismatch, source.encodeCheckpoint(std.testing.allocator));
    source.entity_count -= 1;
    var entity_it = source.entities.iterator();
    const entity_entry = entity_it.next() orelse return error.TestUnexpectedResult;
    entity_entry.value_ptr.prop_count += 1;
    try std.testing.expectError(error.CachedCountMismatch, source.encodeCheckpoint(std.testing.allocator));
    entity_entry.value_ptr.prop_count -= 1;

    const mutable_outer_key = @constCast(entity_entry.key_ptr.*);
    const saved_outer_byte = mutable_outer_key[mutable_outer_key.len - 1];
    mutable_outer_key[mutable_outer_key.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidField, source.encodeCheckpoint(std.testing.allocator));
    mutable_outer_key[mutable_outer_key.len - 1] = saved_outer_byte;
    const mixed = try model.Entity.fromId("#MiXeD");
    var mixed_key_buf: [support.default_max_entity_key]u8 = undefined;
    const mixed_key = try model.writeEntityKey(&mixed_key_buf, mixed, model.default_max_entity_id);
    const nonempty_state = source.entities.getPtr(mixed_key) orelse return error.TestUnexpectedResult;
    const prop_entry = nonempty_state.props.getEntry("alpha") orelse return error.TestUnexpectedResult;
    const mutable_prop_key = @constCast(prop_entry.key_ptr.*);
    const saved_prop_byte = mutable_prop_key[0];
    mutable_prop_key[0] ^= 1;
    try std.testing.expectError(error.InvalidField, source.encodeCheckpoint(std.testing.allocator));
    mutable_prop_key[0] = saved_prop_byte;
}

test "PROP checkpoint rejects corrupt noncanonical duplicate and out-of-bounds wires" {
    var source = prop_store.DefaultStore.init(std.testing.allocator);
    defer source.deinit();
    try support.installPropCheckpointFixture(&source, false);
    const checkpoint = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);

    // Every strict prefix is rejected; none can be mistaken for an empty or
    // partially valid predecessor state.
    for (0..checkpoint.len) |prefix_len| {
        if (prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, checkpoint[0..prefix_len])) |decoded_value| {
            var decoded = decoded_value;
            decoded.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const bad_magic = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try std.testing.expectError(error.BadMagic, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, bad_magic));
    const bad_version = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    try std.testing.expectError(error.UnsupportedVersion, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, bad_version));

    const trailing = try std.testing.allocator.alloc(u8, checkpoint.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0xa5;
    try std.testing.expectError(error.TrailingBytes, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, trailing));

    const bitflip = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(bitflip);
    bitflip[checkpoint_codec.prop_checkpoint_header_len + checkpoint_codec.prop_checkpoint_entity_prefix_len] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, bitflip));

    const alpha_start = support.testFindCheckpointEntity(checkpoint, "#Alpha") orelse return error.TestUnexpectedResult;
    const bravo_start = support.testFindCheckpointEntity(checkpoint, "#Bravo") orelse return error.TestUnexpectedResult;
    const mixed_start = support.testFindCheckpointEntity(checkpoint, "#MiXeD") orelse return error.TestUnexpectedResult;
    const mixed_alpha = support.testFindCheckpointProp(checkpoint, mixed_start, "ALPHA") orelse return error.TestUnexpectedResult;
    const mixed_bravo = support.testFindCheckpointProp(checkpoint, mixed_start, "BRAVO") orelse return error.TestUnexpectedResult;
    const mixed_topic = support.testFindCheckpointProp(checkpoint, mixed_start, "TOPIC") orelse return error.TestUnexpectedResult;

    const invalid_kind = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(invalid_kind);
    invalid_kind[alpha_start] = 0xff;
    support.rewritePropCheckpointChecksum(invalid_kind);
    try std.testing.expectError(error.InvalidField, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, invalid_kind));

    const invalid_access = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(invalid_access);
    invalid_access[mixed_alpha + 12] = 0xff;
    support.rewritePropCheckpointChecksum(invalid_access);
    try std.testing.expectError(error.InvalidField, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, invalid_access));
    const invalid_bool = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(invalid_bool);
    invalid_bool[mixed_alpha + 13] = 1;
    support.rewritePropCheckpointChecksum(invalid_bool);
    try std.testing.expectError(error.InvalidField, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, invalid_bool));

    const oversized_key = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(oversized_key);
    checkpoint_codec.checkpointWriteU32(oversized_key[mixed_alpha..][0..4], model.default_max_key + 1);
    support.rewritePropCheckpointChecksum(oversized_key);
    try std.testing.expectError(error.CapacityExceeded, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, oversized_key));
    const empty_owner = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(empty_owner);
    checkpoint_codec.checkpointWriteU32(empty_owner[mixed_alpha + 8 ..][0..4], 0);
    support.rewritePropCheckpointChecksum(empty_owner);
    try std.testing.expectError(error.CapacityExceeded, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, empty_owner));

    const too_many_entities = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(too_many_entities);
    checkpoint_codec.checkpointWriteU32(too_many_entities[5..9], model.default_max_entities + 1);
    support.rewritePropCheckpointChecksum(too_many_entities);
    try std.testing.expectError(error.CapacityExceeded, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, too_many_entities));
    const too_many_props = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(too_many_props);
    checkpoint_codec.checkpointWriteU32(too_many_props[mixed_start + 5 ..][0..4], model.default_max_props_per_entity + 1);
    support.rewritePropCheckpointChecksum(too_many_props);
    try std.testing.expectError(error.CapacityExceeded, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, too_many_props));
    const mismatched_total = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(mismatched_total);
    checkpoint_codec.checkpointWriteU32(mismatched_total[9..13], checkpoint_codec.checkpointReadU32(mismatched_total[9..13]) + 1);
    support.rewritePropCheckpointChecksum(mismatched_total);
    try std.testing.expectError(error.CachedCountMismatch, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, mismatched_total));
    const huge_body = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(huge_body);
    checkpoint_codec.checkpointWriteU32(huge_body[13..17], std.math.maxInt(u32));
    try std.testing.expectError(error.CheckpointTooLarge, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, huge_body));

    // Counts remain within configured caps but cannot fit in the authenticated
    // body. Shape validation must reject this before the allocator is touched.
    const allocation_bomb = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(allocation_bomb);
    checkpoint_codec.checkpointWriteU32(allocation_bomb[5..9], model.default_max_entities);
    support.rewritePropCheckpointChecksum(allocation_bomb);
    var fail_immediately = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.Truncated,
        prop_store.DefaultStore.decodeCheckpoint(fail_immediately.allocator(), allocation_bomb),
    );
    try std.testing.expect(!fail_immediately.has_induced_failure);

    const duplicate_entity = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(duplicate_entity);
    @memcpy(
        duplicate_entity[bravo_start + checkpoint_codec.prop_checkpoint_entity_prefix_len ..][0..6],
        "#aLpHa",
    );
    support.rewritePropCheckpointChecksum(duplicate_entity);
    try std.testing.expectError(error.DuplicateEntity, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, duplicate_entity));
    const reversed_entities = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(reversed_entities);
    var saved_alpha_id: [6]u8 = undefined;
    @memcpy(&saved_alpha_id, reversed_entities[alpha_start + checkpoint_codec.prop_checkpoint_entity_prefix_len ..][0..6]);
    @memcpy(
        reversed_entities[alpha_start + checkpoint_codec.prop_checkpoint_entity_prefix_len ..][0..6],
        reversed_entities[bravo_start + checkpoint_codec.prop_checkpoint_entity_prefix_len ..][0..6],
    );
    @memcpy(
        reversed_entities[bravo_start + checkpoint_codec.prop_checkpoint_entity_prefix_len ..][0..6],
        &saved_alpha_id,
    );
    support.rewritePropCheckpointChecksum(reversed_entities);
    try std.testing.expectError(error.NonCanonicalOrder, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, reversed_entities));

    const duplicate_prop = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(duplicate_prop);
    @memcpy(
        duplicate_prop[mixed_bravo + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5],
        "aLpHa",
    );
    support.rewritePropCheckpointChecksum(duplicate_prop);
    try std.testing.expectError(error.DuplicateProperty, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, duplicate_prop));
    const reversed_props = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(reversed_props);
    var saved_alpha_key: [5]u8 = undefined;
    @memcpy(&saved_alpha_key, reversed_props[mixed_alpha + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5]);
    @memcpy(
        reversed_props[mixed_alpha + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5],
        reversed_props[mixed_bravo + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5],
    );
    @memcpy(
        reversed_props[mixed_bravo + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5],
        &saved_alpha_key,
    );
    support.rewritePropCheckpointChecksum(reversed_props);
    try std.testing.expectError(error.NonCanonicalOrder, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, reversed_props));

    const noncanonical_known = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(noncanonical_known);
    @memcpy(
        noncanonical_known[mixed_topic + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5],
        "topic",
    );
    support.rewritePropCheckpointChecksum(noncanonical_known);
    try std.testing.expectError(error.InvalidField, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, noncanonical_known));
    const unsafe_key = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(unsafe_key);
    @memcpy(unsafe_key[mixed_alpha + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..5], "ALP!A");
    support.rewritePropCheckpointChecksum(unsafe_key);
    try std.testing.expectError(error.InvalidField, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, unsafe_key));
    const unsafe_value = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(unsafe_value);
    const alpha_value_start = mixed_alpha + checkpoint_codec.prop_checkpoint_prop_prefix_len + 5;
    unsafe_value[alpha_value_start] = '\n';
    support.rewritePropCheckpointChecksum(unsafe_value);
    try std.testing.expectError(error.InvalidField, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, unsafe_value));

    // The extra byte is inside the authenticated body. Declared records decode,
    // then exact EOF rejects the hidden extension.
    const authenticated_trailing = try std.testing.allocator.alloc(u8, checkpoint.len + 1);
    defer std.testing.allocator.free(authenticated_trailing);
    const old_prefix_len = checkpoint.len - checkpoint_codec.prop_checkpoint_checksum_len;
    @memcpy(authenticated_trailing[0..old_prefix_len], checkpoint[0..old_prefix_len]);
    authenticated_trailing[old_prefix_len] = 0xa5;
    checkpoint_codec.checkpointWriteU32(
        authenticated_trailing[13..17],
        checkpoint_codec.checkpointReadU32(checkpoint[13..17]) + 1,
    );
    support.rewritePropCheckpointChecksum(authenticated_trailing);
    try std.testing.expectError(error.TrailingBytes, prop_store.DefaultStore.decodeCheckpoint(std.testing.allocator, authenticated_trailing));

    // A corrupt replacement never displaces the live sentinel.
    var target = prop_store.DefaultStore.init(std.testing.allocator);
    defer target.deinit();
    const sentinel = try model.Entity.fromId("Sentinel");
    _ = try target.setProp(sentinel, "CUSTOM", "old-state", .{ .id = "Sentinel", .access = .user });
    const corrupt_replacements = [_][]const u8{
        bitflip,
        invalid_kind,
        invalid_access,
        allocation_bomb,
        duplicate_entity,
        reversed_entities,
        duplicate_prop,
        noncanonical_known,
        unsafe_value,
        trailing,
        authenticated_trailing,
    };
    for (corrupt_replacements) |corrupt| {
        if (target.replaceFromCheckpoint(corrupt)) |_| return error.TestUnexpectedResult else |_| {}
        try std.testing.expectEqualStrings("old-state", (try target.getPropRaw(sentinel, "CUSTOM")).value);
        try std.testing.expectEqual(@as(usize, 1), target.entity_count);
    }
}

test "PROP checkpoint encode decode and atomic replace exhaust allocation failures" {
    var source = prop_store.DefaultStore.init(std.testing.allocator);
    defer source.deinit();
    try support.installPropCheckpointFixture(&source, false);

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const prop_store.DefaultStore) !void {
            const bytes = try store.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
            try std.testing.expect(bytes.len > checkpoint_codec.prop_checkpoint_header_len + checkpoint_codec.prop_checkpoint_checksum_len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});

    const checkpoint = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try prop_store.DefaultStore.decodeCheckpoint(allocator, bytes);
            defer decoded.deinit();
            try std.testing.expectEqual(@as(usize, 6), decoded.entity_count);
            try std.testing.expectEqualStrings(
                "mesh-secret",
                (try decoded.getPropRaw(try model.Entity.fromId("#MiXeD"), "HOSTKEY")).value,
            );
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, DecodeSweep.run, .{checkpoint});

    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 512);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var target = prop_store.DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                target.deinit();
            }
            const sentinel = try model.Entity.fromId("Sentinel");
            _ = try target.setProp(sentinel, "CUSTOM", "old-state", .{ .id = "Sentinel", .access = .user });

            failing.fail_index = failing.alloc_index + fail_offset;
            target.replaceFromCheckpoint(checkpoint) catch |err| {
                failing.fail_index = std.math.maxInt(usize);
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(@as(usize, 1), target.entity_count);
                try std.testing.expectEqualStrings("old-state", (try target.getPropRaw(sentinel, "CUSTOM")).value);
                try std.testing.expectError(
                    error.PropMissing,
                    target.getPropRaw(try model.Entity.fromId("#MiXeD"), "HOSTKEY"),
                );
                break :blk false;
            };
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectError(error.PropMissing, target.getPropRaw(sentinel, "CUSTOM"));
            try std.testing.expectEqual(@as(usize, 6), target.entity_count);
            try std.testing.expectEqualStrings(
                "mesh-secret",
                (try target.getPropRaw(try model.Entity.fromId("#MiXeD"), "HOSTKEY")).value,
            );
            break :blk true;
        };
        if (completed) break;
    }
}
