// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frozen PRPS checkpoint grammar, canonical encoding, and detached decoding.

const std = @import("std");
const model = @import("model.zig");
const storage = @import("storage.zig");

const prop_checkpoint_magic = [_]u8{ 'P', 'R', 'P', 'S' };
const prop_checkpoint_version: u8 = 1;
pub const prop_checkpoint_header_len: usize = 17;
pub const prop_checkpoint_checksum_len: usize = std.crypto.hash.Blake3.digest_length;
pub const prop_checkpoint_entity_prefix_len: usize = 1 + 4 + 4;
pub const prop_checkpoint_prop_prefix_len: usize = 4 + 4 + 4 + 1 + 1;
const prop_checkpoint_checksum_domain = "onyx-ircx-prop-store-checkpoint-v1";

fn checkpointAdd(lhs: usize, rhs: usize) error{Overflow}!usize {
    return std.math.add(usize, lhs, rhs);
}

pub fn checkpointReadU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

pub fn checkpointWriteU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn checkpointTake(
    bytes: []const u8,
    pos: *usize,
    limit: usize,
    len: usize,
) model.CheckpointError![]const u8 {
    if (pos.* > limit or len > limit - pos.*) return error.Truncated;
    const out = bytes[pos.* .. pos.* + len];
    pos.* += len;
    return out;
}

pub fn propCheckpointChecksum(prefix: []const u8, out: *[prop_checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(prop_checkpoint_checksum_domain);
    hasher.update(prefix);
    hasher.final(out);
}

/// PRPS v1's display-key canon is immutable wire grammar, not live policy.
/// Future channel keys remain valid unknown keys without changing v1 decode.
fn checkpointV1CanonicalChannelKey(raw: []const u8) ?[]const u8 {
    const canonical_keys = [_][]const u8{
        "OID",
        "NAME",
        "CREATION",
        "MEMBERCOUNT",
        "MEMBERLIMIT",
        "LANGUAGE",
        "FOUNDERKEY",
        "OWNERKEY",
        "HOSTKEY",
        "VOICEKEY",
        "MEMBERKEY",
        "PICS",
        "TOPIC",
        "SUBJECT",
        "CLIENT",
        "ONJOIN",
        "ONPART",
        "LAG",
        "ACCOUNT",
        "CLIENTGUID",
        "SERVICEPATH",
        "no-ai",
        "local-only",
        "server-ai-ok",
        "history-policy",
        "encryption-policy",
    };
    for (canonical_keys) |canonical| {
        if (std.ascii.eqlIgnoreCase(raw, canonical)) return canonical;
    }
    return null;
}

/// Specializes checkpoint validation to the concrete store limits. The codec
/// constructs detached stores; the store owns publication and ticket invalidation.
pub fn Codec(comptime Store: type, comptime params: model.Params) type {
    return struct {
        const max_entity_key = model.EntityKind.member.token().len + 1 + params.max_entity_id;

        /// Encode the complete raw store, including secret channel properties
        /// and member/user entities, into a canonical checksummed checkpoint.
        /// The returned allocation belongs to `allocator`.
        pub fn encodeCheckpoint(self: *const Store, allocator: std.mem.Allocator) model.CheckpointError![]u8 {
            if (self.entity_count != self.entities.count()) return error.CachedCountMismatch;
            if (self.entity_count > params.max_entities or self.entity_count > std.math.maxInt(u32))
                return error.CapacityExceeded;

            const OrderedEntity = struct {
                state: *const storage.EntityState,

                fn less(_: void, lhs: @This(), rhs: @This()) bool {
                    if (lhs.state.entity.kind != rhs.state.entity.kind)
                        return @backingInt(lhs.state.entity.kind) < @backingInt(rhs.state.entity.kind);
                    return model.asciiFoldOrder(lhs.state.entity.id, rhs.state.entity.id) == .lt;
                }
            };
            const OrderedProp = struct {
                normalized_key: []const u8,
                entry: *const storage.Entry,

                fn less(_: void, lhs: @This(), rhs: @This()) bool {
                    return std.mem.lessThan(u8, lhs.normalized_key, rhs.normalized_key);
                }
            };

            const ordered_entities = try allocator.alloc(OrderedEntity, self.entity_count);
            defer allocator.free(ordered_entities);

            var body_len: usize = 0;
            var total_prop_count: usize = 0;
            var max_prop_count: usize = 0;
            var entity_index: usize = 0;
            var entity_it = self.entities.iterator();
            while (entity_it.next()) |outer| : (entity_index += 1) {
                const state = outer.value_ptr;
                model.validateEntity(state.entity, params.max_entity_id) catch return error.InvalidField;
                if (state.prop_count != state.props.count()) return error.CachedCountMismatch;
                if (state.prop_count > model.maxPropsFor(params, state.entity.kind) or state.prop_count > std.math.maxInt(u32))
                    return error.CapacityExceeded;

                var expected_outer_buf: [max_entity_key]u8 = undefined;
                const expected_outer = model.writeEntityKey(&expected_outer_buf, state.entity, params.max_entity_id) catch
                    return error.InvalidField;
                if (!std.mem.eql(u8, outer.key_ptr.*, expected_outer)) return error.InvalidField;

                body_len = checkpointAdd(body_len, prop_checkpoint_entity_prefix_len) catch
                    return error.CheckpointTooLarge;
                body_len = checkpointAdd(body_len, state.entity.id.len) catch
                    return error.CheckpointTooLarge;
                total_prop_count = checkpointAdd(total_prop_count, state.prop_count) catch
                    return error.CheckpointTooLarge;
                if (total_prop_count > std.math.maxInt(u32)) return error.CapacityExceeded;
                max_prop_count = @max(max_prop_count, state.prop_count);

                var prop_it = state.props.iterator();
                while (prop_it.next()) |prop| {
                    try validateCheckpointFields(
                        state.entity,
                        prop.value_ptr.key,
                        prop.value_ptr.value,
                        prop.value_ptr.owner,
                        prop.value_ptr.access,
                    );
                    var expected_prop_buf: [params.max_key]u8 = undefined;
                    const expected_prop = model.writePropKey(&expected_prop_buf, prop.value_ptr.key, params.max_key) catch
                        return error.InvalidField;
                    if (!std.mem.eql(u8, prop.key_ptr.*, expected_prop)) return error.InvalidField;
                    body_len = checkpointAdd(body_len, prop_checkpoint_prop_prefix_len) catch
                        return error.CheckpointTooLarge;
                    body_len = checkpointAdd(body_len, prop.value_ptr.key.len) catch
                        return error.CheckpointTooLarge;
                    body_len = checkpointAdd(body_len, prop.value_ptr.value.len) catch
                        return error.CheckpointTooLarge;
                    body_len = checkpointAdd(body_len, prop.value_ptr.owner.len) catch
                        return error.CheckpointTooLarge;
                }
                if (body_len > model.prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
                ordered_entities[entity_index] = .{ .state = state };
            }
            std.debug.assert(entity_index == ordered_entities.len);
            std.mem.sort(OrderedEntity, ordered_entities, {}, OrderedEntity.less);

            const ordered_props = try allocator.alloc(OrderedProp, max_prop_count);
            defer allocator.free(ordered_props);
            const prefix_len = checkpointAdd(prop_checkpoint_header_len, body_len) catch
                return error.CheckpointTooLarge;
            const total_len = checkpointAdd(prefix_len, prop_checkpoint_checksum_len) catch
                return error.CheckpointTooLarge;
            if (total_len > model.prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
            const out = try allocator.alloc(u8, total_len);
            errdefer allocator.free(out);

            @memcpy(out[0..prop_checkpoint_magic.len], &prop_checkpoint_magic);
            out[prop_checkpoint_magic.len] = prop_checkpoint_version;
            checkpointWriteU32(out[5..9], @intCast(self.entity_count));
            checkpointWriteU32(out[9..13], @intCast(total_prop_count));
            checkpointWriteU32(out[13..17], @intCast(body_len));

            var pos: usize = prop_checkpoint_header_len;
            for (ordered_entities) |ordered_entity| {
                const state = ordered_entity.state;
                out[pos] = @backingInt(state.entity.kind);
                pos += 1;
                checkpointWriteU32(out[pos..][0..4], @intCast(state.entity.id.len));
                pos += 4;
                checkpointWriteU32(out[pos..][0..4], @intCast(state.prop_count));
                pos += 4;
                @memcpy(out[pos..][0..state.entity.id.len], state.entity.id);
                pos += state.entity.id.len;

                var prop_index: usize = 0;
                var prop_it = state.props.iterator();
                while (prop_it.next()) |prop| : (prop_index += 1) {
                    ordered_props[prop_index] = .{
                        .normalized_key = prop.key_ptr.*,
                        .entry = prop.value_ptr,
                    };
                }
                std.debug.assert(prop_index == state.prop_count);
                const entity_props = ordered_props[0..prop_index];
                std.mem.sort(OrderedProp, entity_props, {}, OrderedProp.less);
                for (entity_props) |ordered_prop| {
                    const entry = ordered_prop.entry;
                    checkpointWriteU32(out[pos..][0..4], @intCast(entry.key.len));
                    pos += 4;
                    checkpointWriteU32(out[pos..][0..4], @intCast(entry.value.len));
                    pos += 4;
                    checkpointWriteU32(out[pos..][0..4], @intCast(entry.owner.len));
                    pos += 4;
                    out[pos] = @backingInt(entry.access);
                    pos += 1;
                    // Reserved v1 boolean. Keep this independent of mutable
                    // property policy so upgrades cannot reinterpret old state.
                    out[pos] = 0;
                    pos += 1;
                    @memcpy(out[pos..][0..entry.key.len], entry.key);
                    pos += entry.key.len;
                    @memcpy(out[pos..][0..entry.value.len], entry.value);
                    pos += entry.value.len;
                    @memcpy(out[pos..][0..entry.owner.len], entry.owner);
                    pos += entry.owner.len;
                }
            }
            std.debug.assert(pos == prefix_len);
            propCheckpointChecksum(out[0..prefix_len], out[prefix_len..][0..prop_checkpoint_checksum_len]);
            return out;
        }

        /// Decode a complete independently-owned store. Validation and checksum
        /// verification finish before the returned state can become live.
        pub fn decodeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) model.CheckpointError!Store {
            if (bytes.len < prop_checkpoint_header_len + prop_checkpoint_checksum_len)
                return error.Truncated;
            if (!std.mem.eql(u8, bytes[0..prop_checkpoint_magic.len], &prop_checkpoint_magic))
                return error.BadMagic;
            if (bytes[prop_checkpoint_magic.len] != prop_checkpoint_version)
                return error.UnsupportedVersion;

            const encoded_entity_count: usize = checkpointReadU32(bytes[5..9]);
            const encoded_prop_count: usize = checkpointReadU32(bytes[9..13]);
            const body_len: usize = checkpointReadU32(bytes[13..17]);
            if (encoded_entity_count > params.max_entities) return error.CapacityExceeded;
            const max_total_props = std.math.mul(usize, params.max_entities, @max(params.max_props_per_entity, model.user_max_props_per_entity)) catch
                std.math.maxInt(usize);
            if (encoded_prop_count > max_total_props) return error.CapacityExceeded;
            const encoded_entity_prop_limit = std.math.mul(usize, encoded_entity_count, @max(params.max_props_per_entity, model.user_max_props_per_entity)) catch
                return error.CapacityExceeded;
            if (encoded_prop_count > encoded_entity_prop_limit) return error.CapacityExceeded;
            if (body_len > model.prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
            const prefix_len = checkpointAdd(prop_checkpoint_header_len, body_len) catch
                return error.CheckpointTooLarge;
            const expected_len = checkpointAdd(prefix_len, prop_checkpoint_checksum_len) catch
                return error.CheckpointTooLarge;
            if (expected_len > model.prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
            if (bytes.len < expected_len) return error.Truncated;
            if (bytes.len > expected_len) return error.TrailingBytes;
            var actual_checksum: [prop_checkpoint_checksum_len]u8 = undefined;
            propCheckpointChecksum(bytes[0..prefix_len], &actual_checksum);
            const expected_checksum: [prop_checkpoint_checksum_len]u8 = bytes[prefix_len..][0..prop_checkpoint_checksum_len].*;
            if (!std.crypto.timing_safe.eql(
                [prop_checkpoint_checksum_len]u8,
                actual_checksum,
                expected_checksum,
            ))
                return error.ChecksumMismatch;

            var minimum_body_len = std.math.mul(
                usize,
                encoded_entity_count,
                prop_checkpoint_entity_prefix_len + 1,
            ) catch return error.CheckpointTooLarge;
            minimum_body_len = checkpointAdd(
                minimum_body_len,
                std.math.mul(
                    usize,
                    encoded_prop_count,
                    prop_checkpoint_prop_prefix_len + 2,
                ) catch return error.CheckpointTooLarge,
            ) catch return error.CheckpointTooLarge;
            if (minimum_body_len > body_len) return error.Truncated;

            var restored = Store.init(allocator);
            errdefer restored.deinit();
            try restored.entities.ensureTotalCapacity(@intCast(encoded_entity_count));

            var pos: usize = prop_checkpoint_header_len;
            var observed_prop_count: usize = 0;
            var previous_kind: ?model.EntityKind = null;
            var previous_entity_id: ?[]const u8 = null;
            for (0..encoded_entity_count) |_| {
                if (prefix_len - pos < prop_checkpoint_entity_prefix_len) return error.Truncated;
                const kind_raw = bytes[pos];
                pos += 1;
                const kind: model.EntityKind = switch (kind_raw) {
                    @backingInt(model.EntityKind.channel) => .channel,
                    @backingInt(model.EntityKind.user) => .user,
                    @backingInt(model.EntityKind.member) => .member,
                    else => return error.InvalidField,
                };
                const id_len: usize = checkpointReadU32(bytes[pos..][0..4]);
                pos += 4;
                const prop_count: usize = checkpointReadU32(bytes[pos..][0..4]);
                pos += 4;
                if (id_len == 0 or id_len > params.max_entity_id) return error.CapacityExceeded;
                if (prop_count > model.maxPropsFor(params, kind)) return error.CapacityExceeded;
                const min_props_len = std.math.mul(usize, prop_count, prop_checkpoint_prop_prefix_len) catch
                    return error.CheckpointTooLarge;
                const min_remaining = checkpointAdd(id_len, min_props_len) catch
                    return error.CheckpointTooLarge;
                if (min_remaining > prefix_len - pos) return error.Truncated;
                const entity_id = try checkpointTake(bytes, &pos, prefix_len, id_len);
                const entity = model.Entity{ .kind = kind, .id = entity_id };
                model.validateEntity(entity, params.max_entity_id) catch return error.InvalidField;

                if (previous_kind) |prev_kind| {
                    if (@backingInt(kind) < @backingInt(prev_kind)) return error.NonCanonicalOrder;
                    if (kind == prev_kind) {
                        const order = model.asciiFoldOrder(previous_entity_id.?, entity_id);
                        if (order == .eq) return error.DuplicateEntity;
                        if (order != .lt) return error.NonCanonicalOrder;
                    }
                }
                previous_kind = kind;
                previous_entity_id = entity_id;

                var outer_key_buf: [max_entity_key]u8 = undefined;
                const outer_key_view = model.writeEntityKey(&outer_key_buf, entity, params.max_entity_id) catch
                    return error.InvalidField;
                const outer_key = try allocator.dupe(u8, outer_key_view);
                var outer_key_owned = true;
                errdefer if (outer_key_owned) allocator.free(outer_key);
                const entity_id_copy = try allocator.dupe(u8, entity_id);
                var state = storage.EntityState.init(allocator, .{ .kind = kind, .id = entity_id_copy });
                var state_owned = true;
                errdefer if (state_owned) state.deinit(allocator);
                try state.props.ensureTotalCapacity(@intCast(prop_count));

                var previous_prop_key: ?[]const u8 = null;
                for (0..prop_count) |_| {
                    if (prefix_len - pos < prop_checkpoint_prop_prefix_len) return error.Truncated;
                    const key_len: usize = checkpointReadU32(bytes[pos..][0..4]);
                    pos += 4;
                    const value_len: usize = checkpointReadU32(bytes[pos..][0..4]);
                    pos += 4;
                    const owner_len: usize = checkpointReadU32(bytes[pos..][0..4]);
                    pos += 4;
                    const access_raw = bytes[pos];
                    pos += 1;
                    const reserved_bool = bytes[pos];
                    pos += 1;
                    if (key_len == 0 or key_len > params.max_key) return error.CapacityExceeded;
                    if (value_len > params.max_value) return error.CapacityExceeded;
                    if (owner_len == 0 or owner_len > params.max_owner_bytes) return error.CapacityExceeded;
                    if (access_raw > @backingInt(model.AccessLevel.server) or reserved_bool != 0)
                        return error.InvalidField;
                    var fields_len = checkpointAdd(key_len, value_len) catch
                        return error.CheckpointTooLarge;
                    fields_len = checkpointAdd(fields_len, owner_len) catch
                        return error.CheckpointTooLarge;
                    if (fields_len > prefix_len - pos) return error.Truncated;
                    const key = try checkpointTake(bytes, &pos, prefix_len, key_len);
                    const value = try checkpointTake(bytes, &pos, prefix_len, value_len);
                    const owner = try checkpointTake(bytes, &pos, prefix_len, owner_len);
                    const access: model.AccessLevel = @fromBackingInt(@intCast(access_raw));
                    try validateCheckpointFields(entity, key, value, owner, access);

                    if (previous_prop_key) |previous| {
                        const order = model.asciiFoldOrder(previous, key);
                        if (order == .eq) return error.DuplicateProperty;
                        if (order != .lt) return error.NonCanonicalOrder;
                    }
                    previous_prop_key = key;

                    var normalized_key_buf: [params.max_key]u8 = undefined;
                    const normalized_key_view = model.writePropKey(&normalized_key_buf, key, params.max_key) catch
                        return error.InvalidField;
                    var cloned = try storage.cloneCheckpointEntry(
                        allocator,
                        normalized_key_view,
                        key,
                        value,
                        owner,
                        access,
                    );
                    state.props.putAssumeCapacityNoClobber(cloned.normalized_key, cloned.entry);
                    state.prop_count += 1;
                    cloned = undefined;
                }
                if (state.prop_count != prop_count or state.props.count() != prop_count)
                    return error.CachedCountMismatch;
                observed_prop_count = checkpointAdd(observed_prop_count, prop_count) catch
                    return error.CheckpointTooLarge;
                if (observed_prop_count > encoded_prop_count) return error.CachedCountMismatch;

                restored.entities.putAssumeCapacityNoClobber(outer_key, state);
                restored.entity_count += 1;
                outer_key_owned = false;
                state_owned = false;
            }
            if (observed_prop_count != encoded_prop_count) return error.CachedCountMismatch;
            if (pos < prefix_len) return error.TrailingBytes;
            if (pos > prefix_len) return error.Truncated;
            if (restored.entity_count != encoded_entity_count or restored.entities.count() != encoded_entity_count)
                return error.CachedCountMismatch;
            return restored;
        }

        fn validateCheckpointFields(
            entity: model.Entity,
            key: []const u8,
            value: []const u8,
            owner: []const u8,
            access: model.AccessLevel,
        ) model.CheckpointError!void {
            model.validateKeyWithLimit(key, params.max_key) catch return error.InvalidField;
            model.validateOwner(owner, params.max_owner_bytes) catch return error.InvalidField;
            if (entity.kind == .channel) {
                if (checkpointV1CanonicalChannelKey(key)) |canonical| {
                    if (!std.mem.eql(u8, key, canonical)) return error.InvalidField;
                }
            }
            _ = access;
            model.validateValue(value, params.max_value) catch return error.InvalidField;
        }
    };
}
