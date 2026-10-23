// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property ownership, serialized prepared mutations, and atomic checkpoint publication.

const std = @import("std");
const ircx = @import("../ircx.zig");
const model = @import("model.zig");
const storage = @import("storage.zig");
const checkpoint = @import("checkpoint.zig");

pub fn PropStore(comptime params: model.Params) type {
    comptime {
        if (params.max_entities == 0) @compileError("PROP store needs at least one entity");
        if (params.max_props_per_entity == 0) @compileError("PROP store needs at least one property per entity");
        if (params.max_entity_id == 0) @compileError("PROP entity ids need storage");
        if (params.max_key == 0) @compileError("PROP keys need storage");
        if (params.max_value > ircx.MAX_PROP_VALUE) @compileError("PROP values exceed IRCX advertised limit");
        if (params.max_owner_bytes == 0) @compileError("PROP owner ids need storage");
    }

    return struct {
        const Self = @This();
        const max_entity_key = model.EntityKind.member.token().len + 1 + params.max_entity_id;

        allocator: std.mem.Allocator,
        entities: std.StringHashMap(storage.EntityState),
        entity_count: usize = 0,
        prepared_delete_generation: u64 = 1,
        active_prepared_delete: ?PreparedDeletePlan = null,
        prepared_purge_generation: u64 = 1,
        active_prepared_purge: ?PreparedPurgePlan = null,
        prepared_global_purge_generation: u64 = 1,
        active_prepared_global_purge: ?PreparedGlobalPurgePlan = null,
        prepared_set_generation: u64 = 1,
        active_prepared_set_generation: ?u64 = null,
        active_prepared_channel_clone: bool = false,

        const PreparedDeletePlan = struct {
            entity_key: [max_entity_key]u8,
            entity_key_len: usize,
            prop_key: [params.max_key]u8,
            prop_key_len: usize,
            present: bool,
        };

        const PreparedPurgePlan = struct {
            entity_key: [max_entity_key]u8,
            entity_key_len: usize,
            prop_keys: [][]u8,
        };

        const GlobalPurgeSelector = struct {
            entity_key: []u8,
            prop_key: []u8,
        };

        const PreparedGlobalPurgePlan = struct {
            selectors: []GlobalPurgeSelector,
        };

        /// Stable, ticket-owned fact preview used by the daemon to prepare the
        /// matching mesh-clock transaction from the exact store image that will
        /// commit. Every slice owns independent bytes; none aliases the live
        /// store, the detached replacement state, or another fact.
        pub const PreparedPropFact = struct {
            entity: model.Entity,
            key: []const u8,
            value: []const u8,
            owner: []const u8,
            access: model.AccessLevel,

            fn deinit(self: *PreparedPropFact, allocator: std.mem.Allocator) void {
                allocator.free(@constCast(self.entity.id));
                allocator.free(@constCast(self.key));
                allocator.free(@constCast(self.value));
                allocator.free(@constCast(self.owner));
                self.* = undefined;
            }
        };

        /// Allocation-complete public-channel clone plan. The ticket is
        /// logically non-copyable: retain one mutable value and call commit,
        /// abort, or deinit exactly as with the daemon's other prepared tickets.
        /// Replacement/purge previews remain stable only while state=prepared.
        pub const PreparedPublicChannelClone = struct {
            const State = enum { prepared, committed, aborted };

            store: *Self,
            /// Independently-owned normalized lookup keys for every destination
            /// channel/member entity that commit will remove.
            purge_entity_keys: [][]u8,
            /// Independently-owned stable views for clock/tombstone preparation.
            replacement_facts: []PreparedPropFact,
            purge_facts: []PreparedPropFact,
            /// Detached destination channel state and its distinct outer map key.
            /// Null means the source has no public properties, so commit is an
            /// exact destination clear with no replacement entity.
            staged_outer_key: ?[]u8,
            staged_state: ?storage.EntityState,
            state: State = .prepared,

            pub fn replacementFacts(self: *const PreparedPublicChannelClone) []const PreparedPropFact {
                std.debug.assert(self.state == .prepared);
                if (self.state != .prepared) return &.{};
                return self.replacement_facts;
            }

            pub fn purgedFacts(self: *const PreparedPublicChannelClone) []const PreparedPropFact {
                std.debug.assert(self.state == .prepared);
                if (self.state != .prepared) return &.{};
                return self.purge_facts;
            }

            /// Publish the complete prepared image without allocating. Callers
            /// serialize prepare->commit under the daemon's World write lock, so
            /// every copied purge key is guaranteed to remain present here.
            pub fn commit(self: *PreparedPublicChannelClone) void {
                if (self.state != .prepared) return;
                if (!self.store.active_prepared_channel_clone) @panic("prepared channel clone ownership lost");
                self.store.active_prepared_channel_clone = false;
                self.store.invalidatePreparedDelete();
                self.store.invalidatePreparedPurge();
                self.store.invalidatePreparedGlobalPurge();
                for (self.purge_entity_keys) |lookup_key| {
                    const removed = self.store.entities.fetchRemove(lookup_key) orelse unreachable;
                    self.store.allocator.free(removed.key);
                    var removed_state = removed.value;
                    removed_state.deinit(self.store.allocator);
                    std.debug.assert(self.store.entity_count != 0);
                    self.store.entity_count -= 1;
                }
                if (self.staged_outer_key) |outer_key| {
                    const staged = self.staged_state orelse unreachable;
                    self.store.entities.putAssumeCapacityNoClobber(outer_key, staged);
                    self.store.entity_count += 1;
                    self.staged_outer_key = null;
                    self.staged_state = null;
                }
                self.destroyPlanOwned();
                self.state = .committed;
            }

            /// Discard the detached image. Idempotent before or after another
            /// lifecycle method, so `defer ticket.deinit()` is always safe.
            pub fn abort(self: *PreparedPublicChannelClone) void {
                if (self.state != .prepared) return;
                if (!self.store.active_prepared_channel_clone) @panic("prepared channel clone ownership lost");
                self.store.active_prepared_channel_clone = false;
                if (self.staged_state) |*staged| staged.deinit(self.store.allocator);
                self.staged_state = null;
                if (self.staged_outer_key) |key| self.store.allocator.free(key);
                self.staged_outer_key = null;
                self.destroyPlanOwned();
                self.state = .aborted;
            }

            pub fn deinit(self: *PreparedPublicChannelClone) void {
                self.abort();
            }

            fn destroyPlanOwned(self: *PreparedPublicChannelClone) void {
                for (self.purge_entity_keys) |key| self.store.allocator.free(key);
                self.store.allocator.free(self.purge_entity_keys);
                self.purge_entity_keys = undefined;
                for (self.replacement_facts) |*fact| fact.deinit(self.store.allocator);
                self.store.allocator.free(self.replacement_facts);
                self.replacement_facts = undefined;
                for (self.purge_facts) |*fact| fact.deinit(self.store.allocator);
                self.store.allocator.free(self.purge_facts);
                self.purge_facts = undefined;
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .entities = std.StringHashMap(storage.EntityState).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.assertNoPreparedExclusiveMutation();
            self.invalidatePreparedPurge();
            self.invalidatePreparedDelete();
            self.invalidatePreparedGlobalPurge();
            self.clear();
            self.entities.deinit();
            self.* = undefined;
        }

        pub fn clear(self: *Self) void {
            self.assertNoPreparedExclusiveMutation();
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();
            var it = self.entities.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(self.allocator);
            }
            self.entities.clearRetainingCapacity();
            self.entity_count = 0;
        }

        fn advancePreparedGeneration(current: *u64) void {
            if (current.* != std.math.maxInt(u64)) current.* += 1;
        }

        fn assertNoPreparedExclusiveMutation(self: *const Self) void {
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone)
                @panic("PROP destructive mutation while prepared mutation is active");
        }

        fn invalidatePreparedDelete(self: *Self) void {
            self.active_prepared_delete = null;
            advancePreparedGeneration(&self.prepared_delete_generation);
        }

        fn invalidatePreparedPurge(self: *Self) void {
            if (self.active_prepared_purge) |plan| {
                for (plan.prop_keys) |key| self.allocator.free(key);
                self.allocator.free(plan.prop_keys);
            }
            self.active_prepared_purge = null;
            advancePreparedGeneration(&self.prepared_purge_generation);
        }

        fn invalidatePreparedGlobalPurge(self: *Self) void {
            if (self.active_prepared_global_purge) |plan| {
                for (plan.selectors) |selector| {
                    self.allocator.free(selector.entity_key);
                    self.allocator.free(selector.prop_key);
                }
                self.allocator.free(plan.selectors);
            }
            self.active_prepared_global_purge = null;
            advancePreparedGeneration(&self.prepared_global_purge_generation);
        }

        /// Remove the channel entity and every member entity for `channel`, so a
        /// recreated same-named channel never inherits stale (possibly secret)
        /// properties. Scan-and-remove-one to avoid iterator invalidation.
        pub fn clearChannel(self: *Self, channel: []const u8) void {
            self.assertNoPreparedExclusiveMutation();
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();
            while (true) {
                var found: ?[]const u8 = null;
                var it = self.entities.iterator();
                while (it.next()) |entry| {
                    if (entityInChannel(entry.value_ptr.entity, channel)) {
                        found = entry.key_ptr.*;
                        break;
                    }
                }
                const key = found orelse break;
                if (self.entities.fetchRemove(key)) |kv| {
                    self.allocator.free(kv.key);
                    var state = kv.value;
                    state.deinit(self.allocator);
                    if (self.entity_count > 0) self.entity_count -= 1;
                } else break;
            }
        }

        fn entityInChannel(entity: model.Entity, channel: []const u8) bool {
            return switch (entity.kind) {
                .channel => std.ascii.eqlIgnoreCase(entity.id, channel),
                .member => blk: {
                    const split = std.mem.indexOfScalar(u8, entity.id, ':') orelse break :blk false;
                    break :blk std.ascii.eqlIgnoreCase(entity.id[0..split], channel);
                },
                .user => false,
            };
        }

        /// Prepare an exact public-PROP image for a newly-created channel clone.
        /// Public source channel properties are deep-copied; secret source keys
        /// are deliberately excluded. Commit also removes every stale destination
        /// channel and `channel:nick` member entity, matching clearChannel's new-
        /// incarnation semantics. No live state changes until commit.
        pub fn preparePublicChannelClone(
            self: *Self,
            source_channel: []const u8,
            destination_channel: []const u8,
        ) model.PropError!PreparedPublicChannelClone {
            const source_entity = model.Entity{ .kind = .channel, .id = source_channel };
            const destination_entity = model.Entity{ .kind = .channel, .id = destination_channel };
            try model.validateEntity(source_entity, params.max_entity_id);
            try model.validateEntity(destination_entity, params.max_entity_id);
            if (!model.isChannelEntityId(source_channel) or !model.isChannelEntityId(destination_channel))
                return error.InvalidEntity;
            if (std.ascii.eqlIgnoreCase(source_channel, destination_channel))
                return error.InvalidEntity;
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var source_key_buf: [max_entity_key]u8 = undefined;
            const source_key = try model.writeEntityKey(&source_key_buf, source_entity, params.max_entity_id);
            const source_state = self.entities.getPtr(source_key);

            var replacement_count: usize = 0;
            if (source_state) |state| {
                var props_it = state.props.iterator();
                while (props_it.next()) |entry| {
                    if (!model.isSecretChannelProp(source_entity, entry.value_ptr.key))
                        replacement_count = std.math.add(usize, replacement_count, 1) catch return error.LimitReached;
                }
            }

            var purge_entity_count: usize = 0;
            var purge_fact_count: usize = 0;
            var entity_it = self.entities.iterator();
            while (entity_it.next()) |entry| {
                if (!entityInChannel(entry.value_ptr.entity, destination_channel)) continue;
                purge_entity_count = std.math.add(usize, purge_entity_count, 1) catch return error.LimitReached;
                purge_fact_count = std.math.add(usize, purge_fact_count, entry.value_ptr.prop_count) catch return error.LimitReached;
            }
            std.debug.assert(purge_entity_count <= self.entity_count);
            const retained_count = self.entity_count - purge_entity_count;
            if (replacement_count != 0 and retained_count >= params.max_entities)
                return error.LimitReached;

            const purge_entity_keys = self.allocator.alloc([]u8, purge_entity_count) catch return error.LimitReached;
            var purge_entity_keys_init: usize = 0;
            errdefer {
                for (purge_entity_keys[0..purge_entity_keys_init]) |key| self.allocator.free(key);
                self.allocator.free(purge_entity_keys);
            }
            const replacement_facts = self.allocator.alloc(PreparedPropFact, replacement_count) catch return error.LimitReached;
            var replacement_facts_init: usize = 0;
            errdefer {
                for (replacement_facts[0..replacement_facts_init]) |*fact| fact.deinit(self.allocator);
                self.allocator.free(replacement_facts);
            }
            const purge_facts = self.allocator.alloc(PreparedPropFact, purge_fact_count) catch return error.LimitReached;
            var purge_facts_init: usize = 0;
            errdefer {
                for (purge_facts[0..purge_facts_init]) |*fact| fact.deinit(self.allocator);
                self.allocator.free(purge_facts);
            }

            // Snapshot all purge selectors/facts before any outer-map capacity
            // reservation can rehash and invalidate iterator entry pointers.
            entity_it = self.entities.iterator();
            while (entity_it.next()) |entry| {
                if (!entityInChannel(entry.value_ptr.entity, destination_channel)) continue;
                purge_entity_keys[purge_entity_keys_init] = self.allocator.dupe(u8, entry.key_ptr.*) catch return error.LimitReached;
                purge_entity_keys_init += 1;
                var props_it = entry.value_ptr.props.iterator();
                while (props_it.next()) |prop_entry| {
                    purge_facts[purge_facts_init] = try clonePreparedPropFact(
                        self.allocator,
                        entry.value_ptr.entity,
                        prop_entry.value_ptr,
                    );
                    purge_facts_init += 1;
                }
            }
            std.debug.assert(purge_entity_keys_init == purge_entity_keys.len);
            std.debug.assert(purge_facts_init == purge_facts.len);

            // Build stable replacement previews separately from the detached
            // EntityState so clock preparation cannot alias bytes commit moves.
            if (source_state) |state| {
                var props_it = state.props.iterator();
                while (props_it.next()) |entry| {
                    if (model.isSecretChannelProp(source_entity, entry.value_ptr.key)) continue;
                    replacement_facts[replacement_facts_init] = try clonePreparedPropFact(
                        self.allocator,
                        destination_entity,
                        entry.value_ptr,
                    );
                    replacement_facts_init += 1;
                }
            }
            std.debug.assert(replacement_facts_init == replacement_facts.len);
            std.mem.sort(PreparedPropFact, replacement_facts, {}, preparedPropFactLessThan);
            std.mem.sort(PreparedPropFact, purge_facts, {}, preparedPropFactLessThan);

            var staged_outer_key: ?[]u8 = null;
            errdefer if (staged_outer_key) |key| self.allocator.free(key);
            var staged_state: ?storage.EntityState = null;
            errdefer if (staged_state) |*state| state.deinit(self.allocator);
            if (replacement_count != 0) {
                var destination_key_buf: [max_entity_key]u8 = undefined;
                const destination_key = try model.writeEntityKey(
                    &destination_key_buf,
                    destination_entity,
                    params.max_entity_id,
                );
                staged_outer_key = self.allocator.dupe(u8, destination_key) catch return error.LimitReached;
                const destination_id = self.allocator.dupe(u8, destination_channel) catch return error.LimitReached;
                staged_state = storage.EntityState.init(self.allocator, .{ .kind = .channel, .id = destination_id });
                const state = &staged_state.?;
                if (source_state) |source| {
                    var props_it = source.props.iterator();
                    while (props_it.next()) |entry| {
                        if (model.isSecretChannelProp(source_entity, entry.value_ptr.key)) continue;
                        var cloned = try clonePreparedEntry(self.allocator, entry.key_ptr.*, entry.value_ptr);
                        state.props.put(cloned.normalized_key, cloned.entry) catch {
                            self.allocator.free(cloned.normalized_key);
                            cloned.entry.deinit(self.allocator);
                            return error.LimitReached;
                        };
                        state.prop_count += 1;
                    }
                }
                std.debug.assert(state.prop_count == replacement_count);

                // The detached source image and every lookup/preview byte are now
                // owned. Only now may the live outer map rehash.
                if (purge_entity_count == 0)
                    self.entities.ensureUnusedCapacity(1) catch return error.LimitReached;
            }

            const out = PreparedPublicChannelClone{
                .store = self,
                .purge_entity_keys = purge_entity_keys,
                .replacement_facts = replacement_facts,
                .purge_facts = purge_facts,
                .staged_outer_key = staged_outer_key,
                .staged_state = staged_state,
            };
            staged_outer_key = null;
            staged_state = null;
            purge_entity_keys_init = 0;
            replacement_facts_init = 0;
            purge_facts_init = 0;
            self.active_prepared_channel_clone = true;
            return out;
        }

        fn clonePreparedPropFact(
            allocator: std.mem.Allocator,
            entity: model.Entity,
            entry: *const storage.Entry,
        ) model.PropError!PreparedPropFact {
            const entity_id = allocator.dupe(u8, entity.id) catch return error.LimitReached;
            errdefer allocator.free(entity_id);
            const key = allocator.dupe(u8, entry.key) catch return error.LimitReached;
            errdefer allocator.free(key);
            const value = allocator.dupe(u8, entry.value) catch return error.LimitReached;
            errdefer allocator.free(value);
            const owner = allocator.dupe(u8, entry.owner) catch return error.LimitReached;
            return .{
                .entity = .{ .kind = entity.kind, .id = entity_id },
                .key = key,
                .value = value,
                .owner = owner,
                .access = entry.access,
            };
        }

        fn clonePreparedEntry(
            allocator: std.mem.Allocator,
            normalized_key_source: []const u8,
            entry: *const storage.Entry,
        ) model.PropError!struct { normalized_key: []u8, entry: storage.Entry } {
            const normalized_key = allocator.dupe(u8, normalized_key_source) catch return error.LimitReached;
            errdefer allocator.free(normalized_key);
            const display_key = allocator.dupe(u8, entry.key) catch return error.LimitReached;
            errdefer allocator.free(display_key);
            const value = allocator.dupe(u8, entry.value) catch return error.LimitReached;
            errdefer allocator.free(value);
            const owner = allocator.dupe(u8, entry.owner) catch return error.LimitReached;
            return .{
                .normalized_key = normalized_key,
                .entry = .{
                    .key = display_key,
                    .value = value,
                    .owner = owner,
                    .access = entry.access,
                },
            };
        }

        fn preparedPropFactLessThan(_: void, lhs: PreparedPropFact, rhs: PreparedPropFact) bool {
            if (lhs.entity.kind != rhs.entity.kind)
                return @backingInt(lhs.entity.kind) < @backingInt(rhs.entity.kind);
            const entity_order = std.mem.order(u8, lhs.entity.id, rhs.entity.id);
            if (entity_order != .eq) return entity_order == .lt;
            const key_order = std.mem.order(u8, lhs.key, rhs.key);
            if (key_order != .eq) return key_order == .lt;
            const value_order = std.mem.order(u8, lhs.value, rhs.value);
            if (value_order != .eq) return value_order == .lt;
            const owner_order = std.mem.order(u8, lhs.owner, rhs.owner);
            if (owner_order != .eq) return owner_order == .lt;
            return @backingInt(lhs.access) < @backingInt(rhs.access);
        }

        /// Encode the complete raw store, including secret channel properties
        /// and member/user entities, into a canonical checksummed checkpoint.
        /// The returned allocation belongs to `allocator`.
        pub fn encodeCheckpoint(self: *const Self, allocator: std.mem.Allocator) model.CheckpointError![]u8 {
            return checkpoint.Codec(Self, params).encodeCheckpoint(self, allocator);
        }

        /// Decode a complete independently-owned store. Validation and checksum
        /// verification finish before the returned state can become live.
        pub fn decodeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) model.CheckpointError!Self {
            return checkpoint.Codec(Self, params).decodeCheckpoint(allocator, bytes);
        }

        /// Atomically replace this store from a verified checkpoint. Any decode,
        /// validation, or allocation error leaves the previous store untouched.
        pub fn replaceFromCheckpoint(self: *Self, bytes: []const u8) model.CheckpointError!void {
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            var replacement = try Self.decodeCheckpoint(self.allocator, bytes);
            replacement.prepared_delete_generation = self.prepared_delete_generation;
            advancePreparedGeneration(&replacement.prepared_delete_generation);
            replacement.prepared_purge_generation = self.prepared_purge_generation;
            advancePreparedGeneration(&replacement.prepared_purge_generation);
            replacement.prepared_global_purge_generation = self.prepared_global_purge_generation;
            advancePreparedGeneration(&replacement.prepared_global_purge_generation);
            replacement.prepared_set_generation = self.prepared_set_generation;
            advancePreparedGeneration(&replacement.prepared_set_generation);
            const previous = self.*;
            self.* = replacement;
            replacement = previous;
            replacement.deinit();
        }

        /// Copy-safe handle for an allocation-complete deletion. The store owns
        /// the plan; committing, aborting, or superseding it advances the
        /// generation, so copied and stale handles are harmless no-ops.
        pub const PreparedDeleteProp = struct {
            store: *Self,
            generation: u64,

            /// Returns true only when this live ticket removed a property.
            /// Missing properties are deliberately prepared and consumed as an
            /// inert false result, which simplifies reconciliation transactions.
            pub fn commit(self: PreparedDeleteProp) bool {
                if (self.store.prepared_delete_generation != self.generation) return false;
                const plan = self.store.active_prepared_delete orelse return false;
                self.store.active_prepared_delete = null;
                advancePreparedGeneration(&self.store.prepared_delete_generation);
                self.store.invalidatePreparedPurge();
                if (!plan.present) return false;

                const entity_key = plan.entity_key[0..plan.entity_key_len];
                const state = self.store.entities.getPtr(entity_key) orelse return false;
                const prop_key = plan.prop_key[0..plan.prop_key_len];
                const removed = state.props.fetchRemove(prop_key) orelse return false;
                self.store.allocator.free(removed.key);
                removed.value.deinit(self.store.allocator);
                state.prop_count -= 1;
                if (state.prop_count == 0) {
                    const removed_entity = self.store.entities.fetchRemove(entity_key) orelse unreachable;
                    self.store.allocator.free(removed_entity.key);
                    var empty_state = removed_entity.value;
                    empty_state.deinit(self.store.allocator);
                    self.store.entity_count -= 1;
                }
                return true;
            }

            pub fn abort(self: PreparedDeleteProp) void {
                if (self.store.prepared_delete_generation != self.generation) return;
                self.store.invalidatePreparedDelete();
            }

            pub fn deinit(self: PreparedDeleteProp) void {
                self.abort();
            }
        };

        /// Validate and snapshot a DELETE selector. Preparation never mutates
        /// live PROP state and commit performs no allocation and cannot fail.
        pub fn prepareDeleteProp(self: *Self, entity: model.Entity, key: []const u8) model.PropError!PreparedDeleteProp {
            try model.validateEntity(entity, params.max_entity_id);
            try model.validateKeyWithLimit(key, params.max_key);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            if (self.prepared_delete_generation == std.math.maxInt(u64)) return error.PreparedGenerationExhausted;
            self.invalidatePreparedDelete();

            var plan: PreparedDeletePlan = undefined;
            const entity_key = try model.writeEntityKey(&plan.entity_key, entity, params.max_entity_id);
            plan.entity_key_len = entity_key.len;
            const prop_key = try model.writePropKey(&plan.prop_key, key, params.max_key);
            plan.prop_key_len = prop_key.len;
            plan.present = if (self.entities.getPtr(entity_key)) |state| state.props.contains(prop_key) else false;
            self.active_prepared_delete = plan;
            return .{ .store = self, .generation = self.prepared_delete_generation };
        }

        /// Copy-safe, allocation-complete boot reconciliation plan. Only user
        /// entities are accepted. Matching is performed on normalized keys and
        /// is an exact prefix match; commit allocates nothing and cannot fail.
        pub const PreparedUserPropPrefixPurge = struct {
            store: *Self,
            generation: u64,

            pub fn count(self: PreparedUserPropPrefixPurge) usize {
                if (self.store.prepared_purge_generation != self.generation) return 0;
                return if (self.store.active_prepared_purge) |plan| plan.prop_keys.len else 0;
            }

            pub fn commit(self: PreparedUserPropPrefixPurge) usize {
                if (self.store.prepared_purge_generation != self.generation) return 0;
                const plan = self.store.active_prepared_purge orelse return 0;
                self.store.active_prepared_purge = null;
                advancePreparedGeneration(&self.store.prepared_purge_generation);
                self.store.invalidatePreparedDelete();

                var removed_count: usize = 0;
                const entity_key = plan.entity_key[0..plan.entity_key_len];
                if (self.store.entities.getPtr(entity_key)) |state| {
                    for (plan.prop_keys) |prop_key| {
                        if (state.props.fetchRemove(prop_key)) |removed| {
                            self.store.allocator.free(removed.key);
                            removed.value.deinit(self.store.allocator);
                            state.prop_count -= 1;
                            removed_count += 1;
                        }
                        self.store.allocator.free(prop_key);
                    }
                    self.store.allocator.free(plan.prop_keys);
                    if (state.prop_count == 0) {
                        const removed_entity = self.store.entities.fetchRemove(entity_key) orelse unreachable;
                        self.store.allocator.free(removed_entity.key);
                        var empty_state = removed_entity.value;
                        empty_state.deinit(self.store.allocator);
                        self.store.entity_count -= 1;
                    }
                } else {
                    for (plan.prop_keys) |prop_key| self.store.allocator.free(prop_key);
                    self.store.allocator.free(plan.prop_keys);
                }
                return removed_count;
            }

            pub fn abort(self: PreparedUserPropPrefixPurge) void {
                if (self.store.prepared_purge_generation != self.generation) return;
                self.store.invalidatePreparedPurge();
            }

            pub fn deinit(self: PreparedUserPropPrefixPurge) void {
                self.abort();
            }
        };

        /// Prepare a boot-only purge such as `e2ee.device.*` on a candidate
        /// store before it becomes visible to runtime readers.
        pub fn prepareUserPropPrefixPurge(
            self: *Self,
            entity: model.Entity,
            prefix: []const u8,
        ) model.PropError!PreparedUserPropPrefixPurge {
            try model.validateEntity(entity, params.max_entity_id);
            if (entity.kind != .user) return error.InvalidEntity;
            try model.validateKeyWithLimit(prefix, params.max_key);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            if (self.prepared_purge_generation == std.math.maxInt(u64)) return error.PreparedGenerationExhausted;
            self.invalidatePreparedPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var prefix_buf: [params.max_key]u8 = undefined;
            const normalized_prefix = try model.writePropKey(&prefix_buf, prefix, params.max_key);
            var match_count: usize = 0;
            if (self.entities.getPtr(entity_key)) |state| {
                var it = state.props.iterator();
                while (it.next()) |entry| {
                    if (std.mem.startsWith(u8, entry.key_ptr.*, normalized_prefix)) match_count += 1;
                }
            }

            const keys = self.allocator.alloc([]u8, match_count) catch return error.LimitReached;
            var initialized: usize = 0;
            errdefer {
                for (keys[0..initialized]) |key| self.allocator.free(key);
                self.allocator.free(keys);
            }
            if (self.entities.getPtr(entity_key)) |state| {
                var it = state.props.iterator();
                while (it.next()) |entry| {
                    if (!std.mem.startsWith(u8, entry.key_ptr.*, normalized_prefix)) continue;
                    keys[initialized] = self.allocator.dupe(u8, entry.key_ptr.*) catch return error.LimitReached;
                    initialized += 1;
                }
            }
            std.debug.assert(initialized == keys.len);

            var plan: PreparedPurgePlan = undefined;
            @memcpy(plan.entity_key[0..entity_key.len], entity_key);
            plan.entity_key_len = entity_key.len;
            plan.prop_keys = keys;
            self.active_prepared_purge = plan;
            initialized = 0;
            return .{ .store = self, .generation = self.prepared_purge_generation };
        }

        /// Store-owned, copy-safe token for a boot-only purge spanning every
        /// user entity. Selectors are exact normalized entity/property keys;
        /// malformed suffixes are intentionally included whenever the folded
        /// key starts with the requested namespace prefix.
        pub const PreparedGlobalDevicePropPurge = struct {
            store: *Self,
            generation: u64,

            pub fn count(self: PreparedGlobalDevicePropPurge) usize {
                if (self.store.prepared_global_purge_generation != self.generation) return 0;
                return if (self.store.active_prepared_global_purge) |plan| plan.selectors.len else 0;
            }

            pub fn commit(self: PreparedGlobalDevicePropPurge) usize {
                if (self.store.prepared_global_purge_generation != self.generation) return 0;
                const plan = self.store.active_prepared_global_purge orelse return 0;
                self.store.active_prepared_global_purge = null;
                advancePreparedGeneration(&self.store.prepared_global_purge_generation);
                self.store.invalidatePreparedDelete();
                self.store.invalidatePreparedPurge();

                var removed_count: usize = 0;
                for (plan.selectors) |selector| {
                    if (self.store.entities.getPtr(selector.entity_key)) |state| {
                        if (state.props.fetchRemove(selector.prop_key)) |removed| {
                            self.store.allocator.free(removed.key);
                            removed.value.deinit(self.store.allocator);
                            state.prop_count -= 1;
                            removed_count += 1;
                        }
                        if (state.prop_count == 0) {
                            const removed_entity = self.store.entities.fetchRemove(selector.entity_key) orelse unreachable;
                            self.store.allocator.free(removed_entity.key);
                            var empty_state = removed_entity.value;
                            empty_state.deinit(self.store.allocator);
                            self.store.entity_count -= 1;
                        }
                    }
                    self.store.allocator.free(selector.entity_key);
                    self.store.allocator.free(selector.prop_key);
                }
                self.store.allocator.free(plan.selectors);
                return removed_count;
            }

            pub fn abort(self: PreparedGlobalDevicePropPurge) void {
                if (self.store.prepared_global_purge_generation != self.generation) return;
                self.store.invalidatePreparedGlobalPurge();
            }

            pub fn deinit(self: PreparedGlobalDevicePropPurge) void {
                self.abort();
            }
        };

        /// Prepare an allocation-complete namespace purge over every user in a
        /// candidate store. Commit performs only map removals and frees.
        pub fn prepareGlobalDevicePropPurge(
            self: *Self,
        ) model.PreparedGlobalPurgeError!PreparedGlobalDevicePropPurge {
            return self.prepareGlobalUserNamespacePurge(&.{"e2ee.device."});
        }

        /// Prepare the E5E1 hot-candidate purge for both folded identity
        /// namespaces. Prefixes are frozen here so a caller cannot broaden a
        /// process-wide deletion by typo or untrusted input.
        pub fn prepareGlobalIdentityPropPurge(
            self: *Self,
        ) model.PreparedGlobalPurgeError!PreparedGlobalDevicePropPurge {
            return self.prepareGlobalUserNamespacePurge(&.{ "identity.key.", "identity.residence." });
        }

        fn prepareGlobalUserNamespacePurge(
            self: *Self,
            comptime normalized_prefixes: []const []const u8,
        ) model.PreparedGlobalPurgeError!PreparedGlobalDevicePropPurge {
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or
                self.active_prepared_delete != null or self.active_prepared_purge != null or
                self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            if (self.prepared_global_purge_generation == std.math.maxInt(u64))
                return error.PreparedGenerationExhausted;

            var match_count: usize = 0;
            var entities_it = self.entities.iterator();
            while (entities_it.next()) |entity_entry| {
                if (entity_entry.value_ptr.entity.kind != .user) continue;
                var props_it = entity_entry.value_ptr.props.iterator();
                while (props_it.next()) |prop_entry| {
                    if (inline for (normalized_prefixes) |prefix| {
                        if (std.mem.startsWith(u8, prop_entry.key_ptr.*, prefix)) break true;
                    } else false)
                        match_count = std.math.add(usize, match_count, 1) catch return error.LimitReached;
                }
            }

            const selectors = try self.allocator.alloc(GlobalPurgeSelector, match_count);
            var initialized: usize = 0;
            errdefer {
                for (selectors[0..initialized]) |selector| {
                    self.allocator.free(selector.entity_key);
                    self.allocator.free(selector.prop_key);
                }
                self.allocator.free(selectors);
            }
            entities_it = self.entities.iterator();
            while (entities_it.next()) |entity_entry| {
                if (entity_entry.value_ptr.entity.kind != .user) continue;
                var props_it = entity_entry.value_ptr.props.iterator();
                while (props_it.next()) |prop_entry| {
                    const matches = inline for (normalized_prefixes) |prefix| {
                        if (std.mem.startsWith(u8, prop_entry.key_ptr.*, prefix)) break true;
                    } else false;
                    if (!matches) continue;
                    const entity_key = try self.allocator.dupe(u8, entity_entry.key_ptr.*);
                    errdefer self.allocator.free(entity_key);
                    const prop_key = try self.allocator.dupe(u8, prop_entry.key_ptr.*);
                    selectors[initialized] = .{ .entity_key = entity_key, .prop_key = prop_key };
                    initialized += 1;
                }
            }
            std.debug.assert(initialized == selectors.len);
            self.active_prepared_global_purge = .{ .selectors = selectors };
            initialized = 0;
            return .{ .store = self, .generation = self.prepared_global_purge_generation };
        }

        /// Validate every deterministic policy and capacity condition for a SET
        /// without allocating or mutating the store. Allocation can still make a
        /// later `setProp` fail with `LimitReached`; callers that need a no-fail
        /// commit must use `prepareSetProp` rather than treating this as a
        /// reservation.
        pub fn preflightSetProp(
            self: *const Self,
            entity: model.Entity,
            key: []const u8,
            value: []const u8,
            setter: model.Setter,
        ) model.PropError!void {
            try model.validateEntity(entity, params.max_entity_id);
            try model.validateKeyWithLimit(key, params.max_key);
            try model.validateOwner(setter.id, params.max_owner_bytes);
            try model.validateValueFor(entity, key, value, setter.access, params.max_value);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse {
                if (self.entity_count >= params.max_entities) return error.LimitReached;
                return;
            };

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try model.writePropKey(&prop_key_buf, key, params.max_key);
            if (!state.props.contains(prop_key) and state.prop_count >= model.maxPropsFor(params, entity.kind))
                return error.LimitReached;
        }

        /// Allocation-complete SET ticket. Every byte `commit` could ever need —
        /// the value/owner copies, and, only when genuinely required, a new
        /// prop's key bytes or a brand-new (still-detached) `EntityState` with
        /// its own inner-map capacity already reserved — is allocated by
        /// `prepareSetProp` before this ticket exists. `commit` therefore
        /// performs no allocation and cannot fail; `abort`/`deinit` free
        /// whatever `commit` never claimed. Logically non-copyable: retain one
        /// mutable value and call exactly one of commit/abort/deinit, as with
        /// the store's other prepared tickets.
        pub const PreparedSetProp = struct {
            const State = enum { prepared, committed, aborted };

            store: *Self,
            access: model.AccessLevel,
            value_copy: []u8,
            owner_copy: []u8,
            /// Replacement commits need a lookup key after the caller's
            /// input buffers may have gone out of scope. Keep that normalized
            /// key inline so the ticket has no borrowed key/entity pointers.
            replacement_key: [params.max_key]u8 = undefined,
            replacement_key_len: usize = 0,
            existing_entity_key: [max_entity_key]u8 = undefined,
            existing_entity_key_len: usize = 0,
            /// Non-null only when the prop is new (whether its entity already
            /// existed or is created by this same commit): the normalized
            /// lookup key and the display key are pre-allocated, and capacity
            /// for one more prop was already reserved on the entity's
            /// (live-or-detached) inner map in `prepareSetProp`.
            new_map_key: ?[]u8 = null,
            new_display_key: ?[]u8 = null,
            /// Non-null only when the entity itself must be created: a
            /// fully-initialized, still-detached `EntityState` (inner-map
            /// capacity already reserved) plus its independently-owned
            /// outer-map key. Outer-map capacity for this insert was already
            /// reserved in `prepareSetProp`.
            new_entity_outer_key: ?[]u8 = null,
            new_entity_state: ?storage.EntityState = null,
            generation: u64,
            state: State = .prepared,

            /// Publish the fully-reserved mutation. Nothing below this point
            /// allocates: every insert is `putAssumeCapacity*`/`getOrPutAssumeCapacity`
            /// into a map whose capacity `prepareSetProp` already reserved.
            pub fn commit(self: *PreparedSetProp) model.EntryView {
                std.debug.assert(self.state == .prepared);
                std.debug.assert(self.store.active_prepared_set_generation == self.generation);
                self.state = .committed;
                self.store.active_prepared_set_generation = null;
                advancePreparedGeneration(&self.store.prepared_set_generation);
                self.store.invalidatePreparedDelete();
                self.store.invalidatePreparedPurge();

                var state_ptr: *storage.EntityState = undefined;
                if (self.new_entity_outer_key) |outer_key| {
                    self.store.entities.putAssumeCapacityNoClobber(outer_key, self.new_entity_state.?);
                    self.store.entity_count += 1;
                    self.new_entity_outer_key = null;
                    self.new_entity_state = null;
                    state_ptr = self.store.entities.getPtr(outer_key).?;
                } else {
                    const entity_key = self.existing_entity_key[0..self.existing_entity_key_len];
                    state_ptr = self.store.entities.getPtr(entity_key) orelse unreachable;
                }

                if (self.new_map_key) |map_key| {
                    const gop = state_ptr.props.getOrPutAssumeCapacity(map_key);
                    std.debug.assert(!gop.found_existing);
                    gop.key_ptr.* = map_key;
                    gop.value_ptr.* = .{
                        .key = self.new_display_key.?,
                        .value = self.value_copy,
                        .owner = self.owner_copy,
                        .access = self.access,
                    };
                    state_ptr.prop_count += 1;
                    self.new_map_key = null;
                    self.new_display_key = null;
                    return view(state_ptr, gop.value_ptr);
                }

                const prop_key = self.replacement_key[0..self.replacement_key_len];
                const entry = state_ptr.props.getPtr(prop_key) orelse unreachable;
                self.store.allocator.free(entry.value);
                self.store.allocator.free(entry.owner);
                entry.value = self.value_copy;
                entry.owner = self.owner_copy;
                entry.access = self.access;
                return view(state_ptr, entry);
            }

            /// Discard the reservation. Idempotent before or after commit, so
            /// `defer ticket.deinit()` is always safe.
            pub fn abort(self: *PreparedSetProp) void {
                if (self.state != .prepared) return;
                if (self.store.active_prepared_set_generation == self.generation) {
                    self.store.active_prepared_set_generation = null;
                    advancePreparedGeneration(&self.store.prepared_set_generation);
                }
                self.store.allocator.free(self.value_copy);
                self.store.allocator.free(self.owner_copy);
                if (self.new_map_key) |k| self.store.allocator.free(k);
                if (self.new_display_key) |k| self.store.allocator.free(k);
                if (self.new_entity_outer_key) |k| self.store.allocator.free(k);
                if (self.new_entity_state) |*st| st.deinit(self.store.allocator);
                self.state = .aborted;
            }

            pub fn deinit(self: *PreparedSetProp) void {
                self.abort();
            }
        };

        /// Reserve EVERY fallible allocation a SET could ever require, without
        /// mutating any live state. This is the reservation `preflightSetProp`
        /// explicitly disclaims being: preflight alone still leaves a later
        /// `setProp` free to insert a brand-new entity and then fail to insert
        /// its first prop, stranding an empty entity the caller never asked
        /// for. On any failure here every allocation this call itself made is
        /// freed and the store is provably untouched — callers that need a
        /// no-fail commit call `prepareSetProp` then `commit()` once every
        /// other fallible step of their own transaction has also succeeded.
        /// Allocation-aware form used by boot/reconciliation copy paths. Unlike
        /// the legacy IRCX mutation API, allocator exhaustion is preserved as
        /// `OutOfMemory`; deterministic entity/property ceilings remain
        /// `LimitReached`.
        pub fn prepareSetPropAllocationAware(
            self: *Self,
            entity: model.Entity,
            key: []const u8,
            value: []const u8,
            setter: model.Setter,
        ) model.PreparedSetAllocationError!PreparedSetProp {
            try model.validateEntity(entity, params.max_entity_id);
            try model.validateKeyWithLimit(key, params.max_key);
            try model.validateOwner(setter.id, params.max_owner_bytes);
            try model.validateValueFor(entity, key, value, setter.access, params.max_value);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone)
                return error.PreparedMutationActive;
            if (self.prepared_set_generation == std.math.maxInt(u64)) return error.PreparedGenerationExhausted;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try model.writePropKey(&prop_key_buf, key, params.max_key);

            const value_copy = try self.allocator.dupe(u8, value);
            const owner_copy = self.allocator.dupe(u8, setter.id) catch |err| {
                self.allocator.free(value_copy);
                return err;
            };

            var out = PreparedSetProp{
                .store = self,
                .access = setter.access,
                .value_copy = value_copy,
                .owner_copy = owner_copy,
                .generation = self.prepared_set_generation,
            };

            if (self.entities.getPtr(entity_key)) |state| {
                @memcpy(out.existing_entity_key[0..entity_key.len], entity_key);
                out.existing_entity_key_len = entity_key.len;
                if (state.props.contains(prop_key)) {
                    // Replace-in-place: `out` as built above is already the
                    // complete reservation — no new entity, no new prop, no
                    // capacity growth anywhere.
                    @memcpy(out.replacement_key[0..prop_key.len], prop_key);
                    out.replacement_key_len = prop_key.len;
                    self.active_prepared_set_generation = out.generation;
                    return out;
                }
                if (state.prop_count >= model.maxPropsFor(params, entity.kind)) {
                    out.abort();
                    return error.LimitReached;
                }
                state.props.ensureUnusedCapacity(1) catch |err| {
                    out.abort();
                    return err;
                };
                out.new_map_key = model.makePropKeyAllocationAware(self.allocator, key) catch |err| {
                    out.abort();
                    return err;
                };
                out.new_display_key = model.makeDisplayKeyAllocationAware(self.allocator, entity, key) catch |err| {
                    out.abort();
                    return err;
                };
                self.active_prepared_set_generation = out.generation;
                return out;
            }

            if (self.entity_count >= params.max_entities) {
                out.abort();
                return error.LimitReached;
            }
            const id_copy = self.allocator.dupe(u8, entity.id) catch |err| {
                out.abort();
                return err;
            };
            var new_state = storage.EntityState.init(self.allocator, .{ .kind = entity.kind, .id = id_copy });
            new_state.props.ensureUnusedCapacity(1) catch |err| {
                new_state.deinit(self.allocator);
                out.abort();
                return err;
            };
            self.entities.ensureUnusedCapacity(1) catch |err| {
                new_state.deinit(self.allocator);
                out.abort();
                return err;
            };
            const outer_key = self.allocator.dupe(u8, entity_key) catch |err| {
                new_state.deinit(self.allocator);
                out.abort();
                return err;
            };
            const new_map_key = model.makePropKeyAllocationAware(self.allocator, key) catch |err| {
                new_state.deinit(self.allocator);
                self.allocator.free(outer_key);
                out.abort();
                return err;
            };
            const new_display_key = model.makeDisplayKeyAllocationAware(self.allocator, entity, key) catch |err| {
                new_state.deinit(self.allocator);
                self.allocator.free(outer_key);
                self.allocator.free(new_map_key);
                out.abort();
                return err;
            };

            out.new_entity_outer_key = outer_key;
            out.new_entity_state = new_state;
            out.new_map_key = new_map_key;
            out.new_display_key = new_display_key;
            self.active_prepared_set_generation = out.generation;
            return out;
        }

        /// Compatibility surface for live IRCX callers: historical allocation
        /// failures remain `LimitReached`. Security-sensitive copy paths use the
        /// allocation-aware variant above and never lose OOM taxonomy.
        pub fn prepareSetProp(
            self: *Self,
            entity: model.Entity,
            key: []const u8,
            value: []const u8,
            setter: model.Setter,
        ) model.PropError!PreparedSetProp {
            return self.prepareSetPropAllocationAware(entity, key, value, setter) catch |err| switch (err) {
                error.OutOfMemory => return error.LimitReached,
                else => return @errorCast(err),
            };
        }

        pub fn setPropAllocationAware(
            self: *Self,
            entity: model.Entity,
            key: []const u8,
            value: []const u8,
            setter: model.Setter,
        ) model.PreparedSetAllocationError!model.EntryView {
            var prepared = try self.prepareSetPropAllocationAware(entity, key, value, setter);
            return prepared.commit();
        }

        /// Atomic SET: either the store gains exactly the requested value (and,
        /// if needed, exactly one new entity) or it is left byte-for-byte as it
        /// was — never a created-then-abandoned entity. Thin wrapper over
        /// `prepareSetProp`+`commit` so every caller gets the no-partial-
        /// mutation guarantee without managing the ticket itself.
        pub fn setProp(self: *Self, entity: model.Entity, key: []const u8, value: []const u8, setter: model.Setter) model.PropError!model.EntryView {
            var prepared = try self.prepareSetProp(entity, key, value, setter);
            return prepared.commit();
        }

        pub fn getProp(self: *const Self, entity: model.Entity, key: []const u8) model.PropError!model.EntryView {
            return self.getPropInternal(entity, key, false);
        }

        pub fn getPropRaw(self: *const Self, entity: model.Entity, key: []const u8) model.PropError!model.EntryView {
            return self.getPropInternal(entity, key, true);
        }

        fn getPropInternal(self: *const Self, entity: model.Entity, key: []const u8, include_secret: bool) model.PropError!model.EntryView {
            try model.validateEntity(entity, params.max_entity_id);
            try model.validateKeyWithLimit(key, params.max_key);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try model.writePropKey(&prop_key_buf, key, params.max_key);
            const entry = state.props.getPtr(prop_key) orelse return error.PropMissing;
            if (!include_secret and model.isSecretChannelProp(entity, entry.key)) return error.PropMissing;
            return view(state, entry);
        }

        pub fn deleteProp(self: *Self, entity: model.Entity, key: []const u8) model.PropError!void {
            try model.validateEntity(entity, params.max_entity_id);
            try model.validateKeyWithLimit(key, params.max_key);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try model.writePropKey(&prop_key_buf, key, params.max_key);
            const removed = state.props.fetchRemove(prop_key) orelse return error.PropMissing;
            self.allocator.free(removed.key);
            removed.value.deinit(self.allocator);
            state.prop_count -= 1;

            if (state.prop_count == 0) {
                const removed_entity = self.entities.fetchRemove(entity_key).?;
                self.allocator.free(removed_entity.key);
                var empty_state = removed_entity.value;
                empty_state.deinit(self.allocator);
                self.entity_count -= 1;
            }
        }

        pub fn clearEntity(self: *Self, entity: model.Entity) model.PropError!void {
            try model.validateEntity(entity, params.max_entity_id);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const removed_entity = self.entities.fetchRemove(entity_key) orelse return;
            self.allocator.free(removed_entity.key);
            var state = removed_entity.value;
            state.deinit(self.allocator);
            if (self.entity_count > 0) self.entity_count -= 1;
        }

        /// List an entity's props, OMITTING secret channel keys. Use this for any
        /// untrusted/unauthenticated enumeration — secret values never appear.
        pub fn listProps(self: *const Self, entity: model.Entity, out: []model.EntryView) model.PropError![]model.EntryView {
            return self.listPropsInternal(entity, out, false);
        }

        /// List an entity's props INCLUDING secret channel keys. Callers MUST apply
        /// their own per-recipient visibility gate to each returned secret entry
        /// (the daemon's `maySeeSecretKey`); the store cannot know membership rank.
        pub fn listPropsRaw(self: *const Self, entity: model.Entity, out: []model.EntryView) model.PropError![]model.EntryView {
            return self.listPropsInternal(entity, out, true);
        }

        fn listPropsInternal(self: *const Self, entity: model.Entity, out: []model.EntryView, include_secret: bool) model.PropError![]model.EntryView {
            try model.validateEntity(entity, params.max_entity_id);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try model.writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return out[0..0];

            var count: usize = 0;
            var it = state.props.iterator();
            while (it.next()) |entry| {
                if (!include_secret and model.isSecretChannelProp(entity, entry.value_ptr.key)) continue;
                if (count >= out.len) return error.OutputTooSmall;
                out[count] = view(state, entry.value_ptr);
                count += 1;
            }

            const listed = out[0..count];
            std.sort.insertion(model.EntryView, listed, {}, model.entryLessThan);
            return listed;
        }

        fn view(state: *const storage.EntityState, entry: *const storage.Entry) model.EntryView {
            return .{
                .entity = state.entity,
                .key = entry.key,
                .value = entry.value,
                .owner = entry.owner,
                .access = entry.access,
            };
        }
    };
}

pub const DefaultStore = PropStore(.{});
