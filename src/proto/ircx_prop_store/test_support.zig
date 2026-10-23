// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raw-store fixtures and checkpoint corruption helpers for property tests.

const std = @import("std");
const model = @import("model.zig");
const checkpoint_codec = @import("checkpoint.zig");
const prop_store = @import("store.zig");
const storage = @import("storage.zig");

pub const default_max_entity_key = model.EntityKind.member.token().len + 1 + model.default_max_entity_id;

pub fn testAddEmptyPropEntity(store: *prop_store.DefaultStore, entity: model.Entity) !void {
    var outer_buf: [default_max_entity_key]u8 = undefined;
    const outer_view = try model.writeEntityKey(&outer_buf, entity, model.default_max_entity_id);
    try store.entities.ensureUnusedCapacity(1);
    const outer_key = try store.allocator.dupe(u8, outer_view);
    errdefer store.allocator.free(outer_key);
    const id = try store.allocator.dupe(u8, entity.id);
    store.entities.putAssumeCapacityNoClobber(
        outer_key,
        storage.EntityState.init(store.allocator, .{ .kind = entity.kind, .id = id }),
    );
    store.entity_count += 1;
}

pub fn testAddRawProp(
    store: *prop_store.DefaultStore,
    entity: model.Entity,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
    access: model.AccessLevel,
) !void {
    var outer_buf: [default_max_entity_key]u8 = undefined;
    const outer_key = try model.writeEntityKey(&outer_buf, entity, model.default_max_entity_id);
    const state = store.entities.getPtr(outer_key) orelse return error.TestUnexpectedResult;
    try state.props.ensureUnusedCapacity(1);
    var normalized_buf: [model.default_max_key]u8 = undefined;
    const normalized = try model.writePropKey(&normalized_buf, key, model.default_max_key);
    var cloned = try storage.cloneCheckpointEntry(
        store.allocator,
        normalized,
        key,
        value,
        owner,
        access,
    );
    state.props.putAssumeCapacityNoClobber(cloned.normalized_key, cloned.entry);
    cloned = undefined;
    state.prop_count += 1;
}

pub fn installPropCheckpointFixture(store: *prop_store.DefaultStore, reverse: bool) !void {
    const alpha = try model.Entity.fromId("#Alpha");
    const bravo = try model.Entity.fromId("#Bravo");
    const mixed = try model.Entity.fromId("#MiXeD");
    const user = try model.Entity.fromId("CaseUser");
    const member = try model.Entity.fromId("#MiXeD:Alice");
    const zero = try model.Entity.fromId("ZeroState");
    var policy_drift_topic: [200]u8 = @splat('t');

    const add_mixed = struct {
        fn run(target: *prop_store.DefaultStore, entity: model.Entity, topic: []const u8, reversed: bool) !void {
            try testAddEmptyPropEntity(target, entity);
            if (reversed) {
                try testAddRawProp(target, entity, "TOPIC", topic, "legacy-user", .user);
                try testAddRawProp(target, entity, "HOSTKEY", "mesh-secret", "founder", .owner);
                try testAddRawProp(target, entity, "FuTuRe-X", "future-value", "legacy-user", .user);
                try testAddRawProp(target, entity, "BRAVO", "second", "host", .host);
                try testAddRawProp(target, entity, "ALPHA", "first", "host", .host);
            } else {
                try testAddRawProp(target, entity, "ALPHA", "first", "host", .host);
                try testAddRawProp(target, entity, "BRAVO", "second", "host", .host);
                try testAddRawProp(target, entity, "FuTuRe-X", "future-value", "legacy-user", .user);
                try testAddRawProp(target, entity, "HOSTKEY", "mesh-secret", "founder", .owner);
                try testAddRawProp(target, entity, "TOPIC", topic, "legacy-user", .user);
            }
        }
    }.run;

    if (reverse) {
        try testAddEmptyPropEntity(store, zero);
        _ = try store.setProp(member, "ROLE", "operator", .{ .id = "Alice", .access = .member });
        _ = try store.setProp(user, "BIO", "case-preserved", .{ .id = "CaseUser", .access = .user });
        try add_mixed(store, mixed, &policy_drift_topic, true);
        _ = try store.setProp(bravo, "CUSTOM", "bravo", .{ .id = "host", .access = .host });
        _ = try store.setProp(alpha, "CUSTOM", "alpha", .{ .id = "host", .access = .host });
    } else {
        _ = try store.setProp(alpha, "CUSTOM", "alpha", .{ .id = "host", .access = .host });
        _ = try store.setProp(bravo, "CUSTOM", "bravo", .{ .id = "host", .access = .host });
        try add_mixed(store, mixed, &policy_drift_topic, false);
        _ = try store.setProp(user, "BIO", "case-preserved", .{ .id = "CaseUser", .access = .user });
        _ = try store.setProp(member, "ROLE", "operator", .{ .id = "Alice", .access = .member });
        try testAddEmptyPropEntity(store, zero);
    }
}

pub fn testCheckpointEntityEnd(bytes: []const u8, entity_start: usize) usize {
    const id_len: usize = checkpoint_codec.checkpointReadU32(bytes[entity_start + 1 ..][0..4]);
    const prop_count: usize = checkpoint_codec.checkpointReadU32(bytes[entity_start + 5 ..][0..4]);
    var pos = entity_start + checkpoint_codec.prop_checkpoint_entity_prefix_len + id_len;
    for (0..prop_count) |_| {
        const key_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos..][0..4]);
        const value_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos + 4 ..][0..4]);
        const owner_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos + 8 ..][0..4]);
        pos += checkpoint_codec.prop_checkpoint_prop_prefix_len + key_len + value_len + owner_len;
    }
    return pos;
}

pub fn testFindCheckpointEntity(bytes: []const u8, wanted_id: []const u8) ?usize {
    const entity_count: usize = checkpoint_codec.checkpointReadU32(bytes[5..9]);
    var pos: usize = checkpoint_codec.prop_checkpoint_header_len;
    for (0..entity_count) |_| {
        const id_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos + 1 ..][0..4]);
        const id = bytes[pos + checkpoint_codec.prop_checkpoint_entity_prefix_len ..][0..id_len];
        if (std.mem.eql(u8, id, wanted_id)) return pos;
        pos = testCheckpointEntityEnd(bytes, pos);
    }
    return null;
}

pub fn testFindCheckpointProp(bytes: []const u8, entity_start: usize, wanted_key: []const u8) ?usize {
    const id_len: usize = checkpoint_codec.checkpointReadU32(bytes[entity_start + 1 ..][0..4]);
    const prop_count: usize = checkpoint_codec.checkpointReadU32(bytes[entity_start + 5 ..][0..4]);
    var pos = entity_start + checkpoint_codec.prop_checkpoint_entity_prefix_len + id_len;
    for (0..prop_count) |_| {
        const key_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos..][0..4]);
        const value_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos + 4 ..][0..4]);
        const owner_len: usize = checkpoint_codec.checkpointReadU32(bytes[pos + 8 ..][0..4]);
        const key = bytes[pos + checkpoint_codec.prop_checkpoint_prop_prefix_len ..][0..key_len];
        if (std.mem.eql(u8, key, wanted_key)) return pos;
        pos += checkpoint_codec.prop_checkpoint_prop_prefix_len + key_len + value_len + owner_len;
    }
    return null;
}

pub fn rewritePropCheckpointChecksum(bytes: []u8) void {
    const body_len: usize = checkpoint_codec.checkpointReadU32(bytes[13..17]);
    const prefix_len = checkpoint_codec.prop_checkpoint_header_len + body_len;
    std.debug.assert(bytes.len == prefix_len + checkpoint_codec.prop_checkpoint_checksum_len);
    checkpoint_codec.propCheckpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..checkpoint_codec.prop_checkpoint_checksum_len]);
}

pub fn testSliceAliasesBytes(bytes: []const u8, slice: []const u8) bool {
    const bytes_start = @intFromPtr(bytes.ptr);
    const bytes_end = bytes_start + bytes.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;
    return slice_start < bytes_end and bytes_start < slice_end;
}
