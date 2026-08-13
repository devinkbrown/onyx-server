// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocator-backed IRCX PROP storage, parsing, and reply rendering.
const std = @import("std");
const irc_line = @import("irc_line.zig");
const ircx = @import("ircx.zig");
const limits_config = @import("limits_config.zig");

pub const default_max_entities: usize = 1024;
pub const default_max_props_per_entity: usize = 64;
/// Device-directory facts coexist with ordinary profile properties.  Users get
/// this larger live ceiling while channel/member policy remains governed by
/// `max_props_per_entity` (64 by default).
pub const user_max_props_per_entity: usize = 128;
pub const default_max_entity_id: usize = ircx.MAX_ENTITY_ID;
pub const default_max_key: usize = ircx.MAX_PROP_NAME;
pub const default_max_value: usize = ircx.MAX_PROP_VALUE;
pub const default_max_owner_bytes: usize = 128;
pub const default_max_request_keys: usize = 16;
pub const user_profile_max_value: usize = 200;

pub const Params = struct {
    max_entities: usize = default_max_entities,
    max_props_per_entity: usize = default_max_props_per_entity,
    max_entity_id: usize = default_max_entity_id,
    max_key: usize = default_max_key,
    max_value: usize = default_max_value,
    max_owner_bytes: usize = default_max_owner_bytes,
    max_request_keys: usize = default_max_request_keys,

    /// Derive `Params` from the central policy limits (config-driven).
    pub fn fromLimits(limits: *const limits_config.Limits) Params {
        return .{
            .max_entities = limits.ircx_max_entities,
            .max_props_per_entity = limits.ircx_props_per_entity,
            .max_entity_id = limits.ircx_entity_id_len,
            .max_key = limits.ircx_prop_name_len,
            .max_value = limits.ircx_prop_value_len,
            .max_owner_bytes = limits.ircx_prop_owner_len,
            .max_request_keys = limits.ircx_prop_request_keys,
        };
    }
};

pub const PropError = irc_line.ParseError || error{
    AccessDenied,
    InvalidCommand,
    InvalidEntity,
    InvalidKey,
    InvalidOwner,
    InvalidValue,
    LimitReached,
    NeedMoreParams,
    OutputTooSmall,
    PropMissing,
    PreparedGenerationExhausted,
    PreparedMutationActive,
    ReadOnlyProperty,
    TooManyParams,
};

/// The boot-only global namespace purge has a narrower, allocation-aware
/// contract than ordinary IRCX mutations. Callers must be able to distinguish
/// allocator exhaustion from a deterministic store/row limit so an OOM sweep
/// is retryable and a real capacity violation remains a policy error.
pub const PreparedGlobalPurgeError = PropError || std.mem.Allocator.Error;
pub const PreparedSetAllocationError = PropError || std.mem.Allocator.Error;

pub const CheckpointError = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    CapacityExceeded,
    CheckpointTooLarge,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    DuplicateEntity,
    DuplicateProperty,
    NonCanonicalOrder,
    PreparedMutationActive,
    InvalidField,
    CachedCountMismatch,
};

pub const prop_checkpoint_max_bytes: usize = 512 * 1024 * 1024;

const prop_checkpoint_magic = [_]u8{ 'P', 'R', 'P', 'S' };
const prop_checkpoint_version: u8 = 1;
const prop_checkpoint_header_len: usize = 17;
const prop_checkpoint_checksum_len: usize = std.crypto.hash.Blake3.digest_length;
const prop_checkpoint_entity_prefix_len: usize = 1 + 4 + 4;
const prop_checkpoint_prop_prefix_len: usize = 4 + 4 + 4 + 1 + 1;
const prop_checkpoint_checksum_domain = "onyx-ircx-prop-store-checkpoint-v1";

pub const EntityKind = enum {
    channel,
    user,
    member,

    pub fn token(self: EntityKind) []const u8 {
        return switch (self) {
            .channel => "channel",
            .user => "user",
            .member => "member",
        };
    }
};

pub const Entity = struct {
    kind: EntityKind,
    id: []const u8,

    pub fn fromId(id: []const u8) PropError!Entity {
        if (id.len == 0) return error.InvalidEntity;
        // Member entities use `<channel>:<nick>` and therefore also begin with
        // a channel sigil. Classify the delimiter before the leading sigil.
        const kind: EntityKind = if (std.mem.indexOfScalar(u8, id, ':') != null) .member else if (isChannelEntityId(id)) .channel else .user;
        const entity = Entity{ .kind = kind, .id = id };
        try validateEntity(entity, default_max_entity_id);
        return entity;
    }
};

fn isChannelEntityId(id: []const u8) bool {
    return switch (id[0]) {
        '#', '&' => true,
        '%' => id.len >= 2 and (id[1] == '#' or id[1] == '&'),
        else => false,
    };
}

pub const AccessLevel = enum(u8) {
    user = 0,
    member = 1,
    host = 2,
    owner = 3,
    sysop = 4,
    sysop_manager = 5,
    server = 6,

    pub fn allows(self: AccessLevel, required: AccessLevel) bool {
        return @intFromEnum(self) >= @intFromEnum(required);
    }
};

pub const Setter = struct {
    id: []const u8,
    access: AccessLevel,
};

pub const ChannelPropKey = enum {
    oid,
    name,
    creation,
    membercount,
    memberlimit,
    language,
    founderkey,
    ownerkey,
    hostkey,
    voicekey,
    memberkey,
    pics,
    topic,
    subject,
    client,
    onjoin,
    onpart,
    lag,
    account,
    clientguid,
    servicepath,
    no_ai,
    local_only,
    server_ai_ok,
    history_policy,
    encryption_policy,

    pub fn token(self: ChannelPropKey) []const u8 {
        return switch (self) {
            .oid => "OID",
            .name => "NAME",
            .creation => "CREATION",
            .membercount => "MEMBERCOUNT",
            .memberlimit => "MEMBERLIMIT",
            .language => "LANGUAGE",
            .founderkey => "FOUNDERKEY",
            .ownerkey => "OWNERKEY",
            .hostkey => "HOSTKEY",
            .voicekey => "VOICEKEY",
            .memberkey => "MEMBERKEY",
            .pics => "PICS",
            .topic => "TOPIC",
            .subject => "SUBJECT",
            .client => "CLIENT",
            .onjoin => "ONJOIN",
            .onpart => "ONPART",
            .lag => "LAG",
            .account => "ACCOUNT",
            .clientguid => "CLIENTGUID",
            .servicepath => "SERVICEPATH",
            .no_ai => "no-ai",
            .local_only => "local-only",
            .server_ai_ok => "server-ai-ok",
            .history_policy => "history-policy",
            .encryption_policy => "encryption-policy",
        };
    }
};

pub const ChannelPropInfo = struct {
    key: ChannelPropKey,
    max_value: usize,
    min_setter: AccessLevel,
    read_only: bool = false,
    secret: bool = false,
};

pub fn channelPropKey(raw: []const u8) ?ChannelPropKey {
    inline for (@typeInfo(ChannelPropKey).@"enum".field_names) |field_name| {
        const key: ChannelPropKey = @field(ChannelPropKey, field_name);
        if (std.ascii.eqlIgnoreCase(raw, key.token())) return key;
    }
    return null;
}

pub fn channelPropInfo(raw: []const u8) ?ChannelPropInfo {
    const key = channelPropKey(raw) orelse return null;
    return switch (key) {
        .oid, .name, .creation => .{ .key = key, .max_value = 63, .min_setter = .server, .read_only = true },
        // MEMBERCOUNT is a live computed value; never client-writable.
        .membercount => .{ .key = key, .max_value = 20, .min_setter = .server, .read_only = true },
        // MEMBERLIMIT mirrors channel mode +l; host may set it (the daemon links
        // the write to the MODE change before the generic store is consulted).
        .memberlimit => .{ .key = key, .max_value = 20, .min_setter = .host },
        .language => .{ .key = key, .max_value = 31, .min_setter = .host },
        // FOUNDERKEY grants the top FOUNDER tier on join; like OWNERKEY it is
        // owner-set (the prop AccessLevel ladder tops out at owner — founder is a
        // membership rank, not a setter tier) and its value is secret.
        .founderkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        .ownerkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        .hostkey, .memberkey => .{ .key = key, .max_value = 31, .min_setter = .owner, .secret = true },
        // VOICEKEY is settable by operators and above (op-tier), unlike the
        // owner-set OWNER/HOST/MEMBER keys; its value is still secret.
        .voicekey => .{ .key = key, .max_value = 31, .min_setter = .host, .secret = true },
        .pics => .{ .key = key, .max_value = 255, .min_setter = .sysop_manager },
        .topic => .{ .key = key, .max_value = 160, .min_setter = .host },
        .subject => .{ .key = key, .max_value = 31, .min_setter = .host },
        .client, .onjoin, .onpart => .{ .key = key, .max_value = 255, .min_setter = .host },
        .lag => .{ .key = key, .max_value = 1, .min_setter = .owner },
        .account => .{ .key = key, .max_value = 31, .min_setter = .sysop_manager },
        .clientguid, .servicepath => .{ .key = key, .max_value = default_max_value, .min_setter = .owner },
        // AI policy flags are intentionally small, public channel props: later
        // AI/plugin/MCP paths can enforce them without inventing a second policy
        // store. The daemon validates values as boolean tokens before storage.
        .no_ai, .local_only, .server_ai_ok => .{ .key = key, .max_value = 1, .min_setter = .host },
        .history_policy => .{ .key = key, .max_value = 16, .min_setter = .host },
        .encryption_policy => .{ .key = key, .max_value = 16, .min_setter = .host },
    };
}

pub const UserProfilePropKey = enum {
    url,
    gender,
    picture,
    bio,
    email,

    pub fn token(self: UserProfilePropKey) []const u8 {
        return switch (self) {
            .url => "URL",
            .gender => "GENDER",
            .picture => "PICTURE",
            .bio => "BIO",
            .email => "EMAIL",
        };
    }
};

pub const UserProfilePropInfo = struct {
    key: UserProfilePropKey,
    max_value: usize,
};

pub fn userProfilePropKey(raw: []const u8) ?UserProfilePropKey {
    inline for (@typeInfo(UserProfilePropKey).@"enum".field_names) |field_name| {
        const key: UserProfilePropKey = @field(UserProfilePropKey, field_name);
        if (std.ascii.eqlIgnoreCase(raw, key.token())) return key;
    }
    return null;
}

pub fn userProfilePropInfo(raw: []const u8) ?UserProfilePropInfo {
    const key = userProfilePropKey(raw) orelse return null;
    return .{ .key = key, .max_value = user_profile_max_value };
}

pub const EntryView = struct {
    entity: Entity,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
    access: AccessLevel,
};

pub const QueryRequest = struct {
    entity: Entity,
    keys: []const u8,
};

pub const MutationRequest = struct {
    entity: Entity,
    key: []const u8,
    value: []const u8,
};

pub const KeyRequest = struct {
    entity: Entity,
    key: []const u8,
};

pub const Request = union(enum) {
    list: Entity,
    get: QueryRequest,
    set: MutationRequest,
    delete: KeyRequest,
};

pub fn PropStore(comptime params: Params) type {
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
        const max_entity_key = EntityKind.member.token().len + 1 + params.max_entity_id;

        allocator: std.mem.Allocator,
        entities: std.StringHashMap(EntityState),
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

        const Entry = struct {
            key: []u8,
            value: []u8,
            owner: []u8,
            access: AccessLevel,

            fn deinit(self: Entry, allocator: std.mem.Allocator) void {
                allocator.free(self.key);
                allocator.free(self.value);
                allocator.free(self.owner);
            }
        };

        const EntityState = struct {
            entity: Entity,
            props: std.StringHashMap(Entry),
            prop_count: usize = 0,

            fn init(allocator: std.mem.Allocator, entity: Entity) EntityState {
                return .{
                    .entity = entity,
                    .props = std.StringHashMap(Entry).init(allocator),
                };
            }

            fn deinit(self: *EntityState, allocator: std.mem.Allocator) void {
                allocator.free(self.entity.id);
                var it = self.props.iterator();
                while (it.next()) |entry| {
                    allocator.free(entry.key_ptr.*);
                    entry.value_ptr.deinit(allocator);
                }
                self.props.deinit();
                self.* = undefined;
            }
        };

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
            entity: Entity,
            key: []const u8,
            value: []const u8,
            owner: []const u8,
            access: AccessLevel,

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
            staged_state: ?EntityState,
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
                .entities = std.StringHashMap(EntityState).init(allocator),
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

        fn entityInChannel(entity: Entity, channel: []const u8) bool {
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
        ) PropError!PreparedPublicChannelClone {
            const source_entity = Entity{ .kind = .channel, .id = source_channel };
            const destination_entity = Entity{ .kind = .channel, .id = destination_channel };
            try validateEntity(source_entity, params.max_entity_id);
            try validateEntity(destination_entity, params.max_entity_id);
            if (!isChannelEntityId(source_channel) or !isChannelEntityId(destination_channel))
                return error.InvalidEntity;
            if (std.ascii.eqlIgnoreCase(source_channel, destination_channel))
                return error.InvalidEntity;
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var source_key_buf: [max_entity_key]u8 = undefined;
            const source_key = try writeEntityKey(&source_key_buf, source_entity, params.max_entity_id);
            const source_state = self.entities.getPtr(source_key);

            var replacement_count: usize = 0;
            if (source_state) |state| {
                var props_it = state.props.iterator();
                while (props_it.next()) |entry| {
                    if (!isSecretChannelProp(source_entity, entry.value_ptr.key))
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
                    if (isSecretChannelProp(source_entity, entry.value_ptr.key)) continue;
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
            var staged_state: ?EntityState = null;
            errdefer if (staged_state) |*state| state.deinit(self.allocator);
            if (replacement_count != 0) {
                var destination_key_buf: [max_entity_key]u8 = undefined;
                const destination_key = try writeEntityKey(
                    &destination_key_buf,
                    destination_entity,
                    params.max_entity_id,
                );
                staged_outer_key = self.allocator.dupe(u8, destination_key) catch return error.LimitReached;
                const destination_id = self.allocator.dupe(u8, destination_channel) catch return error.LimitReached;
                staged_state = EntityState.init(self.allocator, .{ .kind = .channel, .id = destination_id });
                const state = &staged_state.?;
                if (source_state) |source| {
                    var props_it = source.props.iterator();
                    while (props_it.next()) |entry| {
                        if (isSecretChannelProp(source_entity, entry.value_ptr.key)) continue;
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
            entity: Entity,
            entry: *const Entry,
        ) PropError!PreparedPropFact {
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
            entry: *const Entry,
        ) PropError!struct { normalized_key: []u8, entry: Entry } {
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
                return @intFromEnum(lhs.entity.kind) < @intFromEnum(rhs.entity.kind);
            const entity_order = std.mem.order(u8, lhs.entity.id, rhs.entity.id);
            if (entity_order != .eq) return entity_order == .lt;
            const key_order = std.mem.order(u8, lhs.key, rhs.key);
            if (key_order != .eq) return key_order == .lt;
            const value_order = std.mem.order(u8, lhs.value, rhs.value);
            if (value_order != .eq) return value_order == .lt;
            const owner_order = std.mem.order(u8, lhs.owner, rhs.owner);
            if (owner_order != .eq) return owner_order == .lt;
            return @intFromEnum(lhs.access) < @intFromEnum(rhs.access);
        }

        /// Encode the complete raw store, including secret channel properties
        /// and member/user entities, into a canonical checksummed checkpoint.
        /// The returned allocation belongs to `allocator`.
        pub fn encodeCheckpoint(self: *const Self, allocator: std.mem.Allocator) CheckpointError![]u8 {
            if (self.entity_count != self.entities.count()) return error.CachedCountMismatch;
            if (self.entity_count > params.max_entities or self.entity_count > std.math.maxInt(u32))
                return error.CapacityExceeded;

            const OrderedEntity = struct {
                state: *const EntityState,

                fn less(_: void, lhs: @This(), rhs: @This()) bool {
                    if (lhs.state.entity.kind != rhs.state.entity.kind)
                        return @intFromEnum(lhs.state.entity.kind) < @intFromEnum(rhs.state.entity.kind);
                    return asciiFoldOrder(lhs.state.entity.id, rhs.state.entity.id) == .lt;
                }
            };
            const OrderedProp = struct {
                normalized_key: []const u8,
                entry: *const Entry,

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
                validateEntity(state.entity, params.max_entity_id) catch return error.InvalidField;
                if (state.prop_count != state.props.count()) return error.CachedCountMismatch;
                if (state.prop_count > maxPropsFor(state.entity.kind) or state.prop_count > std.math.maxInt(u32))
                    return error.CapacityExceeded;

                var expected_outer_buf: [max_entity_key]u8 = undefined;
                const expected_outer = writeEntityKey(&expected_outer_buf, state.entity, params.max_entity_id) catch
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
                    const expected_prop = writePropKey(&expected_prop_buf, prop.value_ptr.key, params.max_key) catch
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
                if (body_len > prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
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
            if (total_len > prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
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
                out[pos] = @intFromEnum(state.entity.kind);
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
                    out[pos] = @intFromEnum(entry.access);
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
        pub fn decodeCheckpoint(allocator: std.mem.Allocator, bytes: []const u8) CheckpointError!Self {
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
            const max_total_props = std.math.mul(usize, params.max_entities, @max(params.max_props_per_entity, user_max_props_per_entity)) catch
                std.math.maxInt(usize);
            if (encoded_prop_count > max_total_props) return error.CapacityExceeded;
            const encoded_entity_prop_limit = std.math.mul(usize, encoded_entity_count, @max(params.max_props_per_entity, user_max_props_per_entity)) catch
                return error.CapacityExceeded;
            if (encoded_prop_count > encoded_entity_prop_limit) return error.CapacityExceeded;
            if (body_len > prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
            const prefix_len = checkpointAdd(prop_checkpoint_header_len, body_len) catch
                return error.CheckpointTooLarge;
            const expected_len = checkpointAdd(prefix_len, prop_checkpoint_checksum_len) catch
                return error.CheckpointTooLarge;
            if (expected_len > prop_checkpoint_max_bytes) return error.CheckpointTooLarge;
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

            var restored = Self.init(allocator);
            errdefer restored.deinit();
            try restored.entities.ensureTotalCapacity(@intCast(encoded_entity_count));

            var pos: usize = prop_checkpoint_header_len;
            var observed_prop_count: usize = 0;
            var previous_kind: ?EntityKind = null;
            var previous_entity_id: ?[]const u8 = null;
            for (0..encoded_entity_count) |_| {
                if (prefix_len - pos < prop_checkpoint_entity_prefix_len) return error.Truncated;
                const kind_raw = bytes[pos];
                pos += 1;
                const kind: EntityKind = switch (kind_raw) {
                    @intFromEnum(EntityKind.channel) => .channel,
                    @intFromEnum(EntityKind.user) => .user,
                    @intFromEnum(EntityKind.member) => .member,
                    else => return error.InvalidField,
                };
                const id_len: usize = checkpointReadU32(bytes[pos..][0..4]);
                pos += 4;
                const prop_count: usize = checkpointReadU32(bytes[pos..][0..4]);
                pos += 4;
                if (id_len == 0 or id_len > params.max_entity_id) return error.CapacityExceeded;
                if (prop_count > maxPropsFor(kind)) return error.CapacityExceeded;
                const min_props_len = std.math.mul(usize, prop_count, prop_checkpoint_prop_prefix_len) catch
                    return error.CheckpointTooLarge;
                const min_remaining = checkpointAdd(id_len, min_props_len) catch
                    return error.CheckpointTooLarge;
                if (min_remaining > prefix_len - pos) return error.Truncated;
                const entity_id = try checkpointTake(bytes, &pos, prefix_len, id_len);
                const entity = Entity{ .kind = kind, .id = entity_id };
                validateEntity(entity, params.max_entity_id) catch return error.InvalidField;

                if (previous_kind) |prev_kind| {
                    if (@intFromEnum(kind) < @intFromEnum(prev_kind)) return error.NonCanonicalOrder;
                    if (kind == prev_kind) {
                        const order = asciiFoldOrder(previous_entity_id.?, entity_id);
                        if (order == .eq) return error.DuplicateEntity;
                        if (order != .lt) return error.NonCanonicalOrder;
                    }
                }
                previous_kind = kind;
                previous_entity_id = entity_id;

                var outer_key_buf: [max_entity_key]u8 = undefined;
                const outer_key_view = writeEntityKey(&outer_key_buf, entity, params.max_entity_id) catch
                    return error.InvalidField;
                const outer_key = try allocator.dupe(u8, outer_key_view);
                var outer_key_owned = true;
                errdefer if (outer_key_owned) allocator.free(outer_key);
                const entity_id_copy = try allocator.dupe(u8, entity_id);
                var state = EntityState.init(allocator, .{ .kind = kind, .id = entity_id_copy });
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
                    if (access_raw > @intFromEnum(AccessLevel.server) or reserved_bool != 0)
                        return error.InvalidField;
                    var fields_len = checkpointAdd(key_len, value_len) catch
                        return error.CheckpointTooLarge;
                    fields_len = checkpointAdd(fields_len, owner_len) catch
                        return error.CheckpointTooLarge;
                    if (fields_len > prefix_len - pos) return error.Truncated;
                    const key = try checkpointTake(bytes, &pos, prefix_len, key_len);
                    const value = try checkpointTake(bytes, &pos, prefix_len, value_len);
                    const owner = try checkpointTake(bytes, &pos, prefix_len, owner_len);
                    const access: AccessLevel = @enumFromInt(access_raw);
                    try validateCheckpointFields(entity, key, value, owner, access);

                    if (previous_prop_key) |previous| {
                        const order = asciiFoldOrder(previous, key);
                        if (order == .eq) return error.DuplicateProperty;
                        if (order != .lt) return error.NonCanonicalOrder;
                    }
                    previous_prop_key = key;

                    var normalized_key_buf: [params.max_key]u8 = undefined;
                    const normalized_key_view = writePropKey(&normalized_key_buf, key, params.max_key) catch
                        return error.InvalidField;
                    var cloned = try cloneCheckpointEntry(
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

        /// Atomically replace this store from a verified checkpoint. Any decode,
        /// validation, or allocation error leaves the previous store untouched.
        pub fn replaceFromCheckpoint(self: *Self, bytes: []const u8) CheckpointError!void {
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

        fn validateCheckpointFields(
            entity: Entity,
            key: []const u8,
            value: []const u8,
            owner: []const u8,
            access: AccessLevel,
        ) CheckpointError!void {
            validateKeyWithLimit(key, params.max_key) catch return error.InvalidField;
            validateOwner(owner, params.max_owner_bytes) catch return error.InvalidField;
            if (entity.kind == .channel) {
                if (checkpointV1CanonicalChannelKey(key)) |canonical| {
                    if (!std.mem.eql(u8, key, canonical)) return error.InvalidField;
                }
            }
            _ = access;
            validateValue(value, params.max_value) catch return error.InvalidField;
        }

        fn cloneCheckpointEntry(
            allocator: std.mem.Allocator,
            normalized_key_source: []const u8,
            key_source: []const u8,
            value_source: []const u8,
            owner_source: []const u8,
            access: AccessLevel,
        ) std.mem.Allocator.Error!struct { normalized_key: []u8, entry: Entry } {
            const normalized_key = try allocator.dupe(u8, normalized_key_source);
            errdefer allocator.free(normalized_key);
            const key = try allocator.dupe(u8, key_source);
            errdefer allocator.free(key);
            const value = try allocator.dupe(u8, value_source);
            errdefer allocator.free(value);
            const owner = try allocator.dupe(u8, owner_source);
            return .{
                .normalized_key = normalized_key,
                .entry = .{ .key = key, .value = value, .owner = owner, .access = access },
            };
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
        pub fn prepareDeleteProp(self: *Self, entity: Entity, key: []const u8) PropError!PreparedDeleteProp {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            if (self.prepared_delete_generation == std.math.maxInt(u64)) return error.PreparedGenerationExhausted;
            self.invalidatePreparedDelete();

            var plan: PreparedDeletePlan = undefined;
            const entity_key = try writeEntityKey(&plan.entity_key, entity, params.max_entity_id);
            plan.entity_key_len = entity_key.len;
            const prop_key = try writePropKey(&plan.prop_key, key, params.max_key);
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
            entity: Entity,
            prefix: []const u8,
        ) PropError!PreparedUserPropPrefixPurge {
            try validateEntity(entity, params.max_entity_id);
            if (entity.kind != .user) return error.InvalidEntity;
            try validateKeyWithLimit(prefix, params.max_key);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            if (self.prepared_purge_generation == std.math.maxInt(u64)) return error.PreparedGenerationExhausted;
            self.invalidatePreparedPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var prefix_buf: [params.max_key]u8 = undefined;
            const normalized_prefix = try writePropKey(&prefix_buf, prefix, params.max_key);
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
        ) PreparedGlobalPurgeError!PreparedGlobalDevicePropPurge {
            return self.prepareGlobalUserNamespacePurge(&.{"e2ee.device."});
        }

        /// Prepare the E5E1 hot-candidate purge for both folded identity
        /// namespaces. Prefixes are frozen here so a caller cannot broaden a
        /// process-wide deletion by typo or untrusted input.
        pub fn prepareGlobalIdentityPropPurge(
            self: *Self,
        ) PreparedGlobalPurgeError!PreparedGlobalDevicePropPurge {
            return self.prepareGlobalUserNamespacePurge(&.{ "identity.key.", "identity.residence." });
        }

        fn prepareGlobalUserNamespacePurge(
            self: *Self,
            comptime normalized_prefixes: []const []const u8,
        ) PreparedGlobalPurgeError!PreparedGlobalDevicePropPurge {
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

        fn maxPropsFor(kind: EntityKind) usize {
            return if (kind == .user) @max(params.max_props_per_entity, user_max_props_per_entity) else params.max_props_per_entity;
        }

        /// Validate every deterministic policy and capacity condition for a SET
        /// without allocating or mutating the store. Allocation can still make a
        /// later `setProp` fail with `LimitReached`; callers that need a no-fail
        /// commit must use `prepareSetProp` rather than treating this as a
        /// reservation.
        pub fn preflightSetProp(
            self: *const Self,
            entity: Entity,
            key: []const u8,
            value: []const u8,
            setter: Setter,
        ) PropError!void {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);
            try validateOwner(setter.id, params.max_owner_bytes);
            try validateValueFor(entity, key, value, setter.access, params.max_value);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse {
                if (self.entity_count >= params.max_entities) return error.LimitReached;
                return;
            };

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);
            if (!state.props.contains(prop_key) and state.prop_count >= maxPropsFor(entity.kind))
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
            access: AccessLevel,
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
            new_entity_state: ?EntityState = null,
            generation: u64,
            state: State = .prepared,

            /// Publish the fully-reserved mutation. Nothing below this point
            /// allocates: every insert is `putAssumeCapacity*`/`getOrPutAssumeCapacity`
            /// into a map whose capacity `prepareSetProp` already reserved.
            pub fn commit(self: *PreparedSetProp) EntryView {
                std.debug.assert(self.state == .prepared);
                std.debug.assert(self.store.active_prepared_set_generation == self.generation);
                self.state = .committed;
                self.store.active_prepared_set_generation = null;
                advancePreparedGeneration(&self.store.prepared_set_generation);
                self.store.invalidatePreparedDelete();
                self.store.invalidatePreparedPurge();

                var state_ptr: *EntityState = undefined;
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
            entity: Entity,
            key: []const u8,
            value: []const u8,
            setter: Setter,
        ) PreparedSetAllocationError!PreparedSetProp {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);
            try validateOwner(setter.id, params.max_owner_bytes);
            try validateValueFor(entity, key, value, setter.access, params.max_value);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone)
                return error.PreparedMutationActive;
            if (self.prepared_set_generation == std.math.maxInt(u64)) return error.PreparedGenerationExhausted;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);

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
                if (state.prop_count >= maxPropsFor(entity.kind)) {
                    out.abort();
                    return error.LimitReached;
                }
                state.props.ensureUnusedCapacity(1) catch |err| {
                    out.abort();
                    return err;
                };
                out.new_map_key = makePropKeyAllocationAware(self.allocator, key) catch |err| {
                    out.abort();
                    return err;
                };
                out.new_display_key = makeDisplayKeyAllocationAware(self.allocator, entity, key) catch |err| {
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
            var new_state = EntityState.init(self.allocator, .{ .kind = entity.kind, .id = id_copy });
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
            const new_map_key = makePropKeyAllocationAware(self.allocator, key) catch |err| {
                new_state.deinit(self.allocator);
                self.allocator.free(outer_key);
                out.abort();
                return err;
            };
            const new_display_key = makeDisplayKeyAllocationAware(self.allocator, entity, key) catch |err| {
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
            entity: Entity,
            key: []const u8,
            value: []const u8,
            setter: Setter,
        ) PropError!PreparedSetProp {
            return self.prepareSetPropAllocationAware(entity, key, value, setter) catch |err| switch (err) {
                error.OutOfMemory => return error.LimitReached,
                else => return @errorCast(err),
            };
        }

        pub fn setPropAllocationAware(
            self: *Self,
            entity: Entity,
            key: []const u8,
            value: []const u8,
            setter: Setter,
        ) PreparedSetAllocationError!EntryView {
            var prepared = try self.prepareSetPropAllocationAware(entity, key, value, setter);
            return prepared.commit();
        }

        /// Atomic SET: either the store gains exactly the requested value (and,
        /// if needed, exactly one new entity) or it is left byte-for-byte as it
        /// was — never a created-then-abandoned entity. Thin wrapper over
        /// `prepareSetProp`+`commit` so every caller gets the no-partial-
        /// mutation guarantee without managing the ticket itself.
        pub fn setProp(self: *Self, entity: Entity, key: []const u8, value: []const u8, setter: Setter) PropError!EntryView {
            var prepared = try self.prepareSetProp(entity, key, value, setter);
            return prepared.commit();
        }

        pub fn getProp(self: *const Self, entity: Entity, key: []const u8) PropError!EntryView {
            return self.getPropInternal(entity, key, false);
        }

        pub fn getPropRaw(self: *const Self, entity: Entity, key: []const u8) PropError!EntryView {
            return self.getPropInternal(entity, key, true);
        }

        fn getPropInternal(self: *const Self, entity: Entity, key: []const u8, include_secret: bool) PropError!EntryView {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);
            const entry = state.props.getPtr(prop_key) orelse return error.PropMissing;
            if (!include_secret and isSecretChannelProp(entity, entry.key)) return error.PropMissing;
            return view(state, entry);
        }

        pub fn deleteProp(self: *Self, entity: Entity, key: []const u8) PropError!void {
            try validateEntity(entity, params.max_entity_id);
            try validateKeyWithLimit(key, params.max_key);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            var state = self.entities.getPtr(entity_key) orelse return error.PropMissing;

            var prop_key_buf: [params.max_key]u8 = undefined;
            const prop_key = try writePropKey(&prop_key_buf, key, params.max_key);
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

        pub fn clearEntity(self: *Self, entity: Entity) PropError!void {
            try validateEntity(entity, params.max_entity_id);
            if (self.active_prepared_set_generation != null or self.active_prepared_channel_clone or self.active_prepared_global_purge != null)
                return error.PreparedMutationActive;
            self.invalidatePreparedDelete();
            self.invalidatePreparedPurge();
            self.invalidatePreparedGlobalPurge();

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const removed_entity = self.entities.fetchRemove(entity_key) orelse return;
            self.allocator.free(removed_entity.key);
            var state = removed_entity.value;
            state.deinit(self.allocator);
            if (self.entity_count > 0) self.entity_count -= 1;
        }

        /// List an entity's props, OMITTING secret channel keys. Use this for any
        /// untrusted/unauthenticated enumeration — secret values never appear.
        pub fn listProps(self: *const Self, entity: Entity, out: []EntryView) PropError![]EntryView {
            return self.listPropsInternal(entity, out, false);
        }

        /// List an entity's props INCLUDING secret channel keys. Callers MUST apply
        /// their own per-recipient visibility gate to each returned secret entry
        /// (the daemon's `maySeeSecretKey`); the store cannot know membership rank.
        pub fn listPropsRaw(self: *const Self, entity: Entity, out: []EntryView) PropError![]EntryView {
            return self.listPropsInternal(entity, out, true);
        }

        fn listPropsInternal(self: *const Self, entity: Entity, out: []EntryView, include_secret: bool) PropError![]EntryView {
            try validateEntity(entity, params.max_entity_id);

            var entity_key_buf: [max_entity_key]u8 = undefined;
            const entity_key = try writeEntityKey(&entity_key_buf, entity, params.max_entity_id);
            const state = self.entities.getPtr(entity_key) orelse return out[0..0];

            var count: usize = 0;
            var it = state.props.iterator();
            while (it.next()) |entry| {
                if (!include_secret and isSecretChannelProp(entity, entry.value_ptr.key)) continue;
                if (count >= out.len) return error.OutputTooSmall;
                out[count] = view(state, entry.value_ptr);
                count += 1;
            }

            const listed = out[0..count];
            std.sort.insertion(EntryView, listed, {}, entryLessThan);
            return listed;
        }

        fn view(state: *const EntityState, entry: *const Entry) EntryView {
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

pub fn parseLine(line: []const u8) PropError!Request {
    return parseLineBounded(.{}, line);
}

pub fn parseLineBounded(comptime params: Params, line: []const u8) PropError!Request {
    const parsed = try irc_line.parseLine(line);
    if (!std.ascii.eqlIgnoreCase(parsed.command, "PROP")) return error.InvalidCommand;
    return parseParamsBounded(params, parsed.paramSlice(), parsed.trailing != null);
}

pub fn parseParamsBounded(comptime params: Params, params_slice: []const []const u8, had_trailing: bool) PropError!Request {
    if (params_slice.len == 0) return error.NeedMoreParams;
    if (params_slice.len > 4) return error.TooManyParams;

    const entity = try Entity.fromId(params_slice[0]);
    try validateEntity(entity, params.max_entity_id);

    if (params_slice.len == 1) return .{ .list = entity };

    if (std.ascii.eqlIgnoreCase(params_slice[1], "CLEAR")) {
        if (params_slice.len != 2) return error.TooManyParams;
        return .{ .delete = .{ .entity = entity, .key = "" } };
    }

    if (std.ascii.eqlIgnoreCase(params_slice[1], "GET")) {
        if (params_slice.len < 3) return error.NeedMoreParams;
        if (params_slice.len > 3) return error.TooManyParams;
        const keys = params_slice[2];
        try validateKeyList(keys, params.max_key, params.max_request_keys);
        return .{ .get = .{ .entity = entity, .keys = keys } };
    }

    if (std.ascii.eqlIgnoreCase(params_slice[1], "SET")) {
        if (params_slice.len < 3) return error.NeedMoreParams;
        const key = params_slice[2];
        try validateKeyWithLimit(key, params.max_key);
        if (std.mem.indexOfScalar(u8, key, ',') != null) return error.InvalidKey;
        if (params_slice.len == 3) return .{ .delete = .{ .entity = entity, .key = key } };

        const value = params_slice[3];
        if (had_trailing and value.len == 0) {
            return .{ .delete = .{ .entity = entity, .key = key } };
        }

        try validateValue(value, params.max_value);
        return .{ .set = .{ .entity = entity, .key = key, .value = value } };
    }

    if (params_slice.len > 3) return error.TooManyParams;

    const key = params_slice[1];
    try validateKeyList(key, params.max_key, params.max_request_keys);

    if (params_slice.len == 2) return .{ .get = .{ .entity = entity, .keys = key } };
    if (std.mem.indexOfScalar(u8, key, ',') != null) return error.InvalidKey;

    const value = params_slice[2];
    if (had_trailing and value.len == 0) {
        return .{ .delete = .{ .entity = entity, .key = key } };
    }

    try validateValue(value, params.max_value);
    return .{ .set = .{ .entity = entity, .key = key, .value = value } };
}

pub fn buildPropMessage(entity: Entity, key: []const u8, value: []const u8, out: []u8) PropError![]const u8 {
    try validateEntity(entity, default_max_entity_id);
    try validateKeyWithLimit(key, default_max_key);
    try validateValue(value, default_max_value);
    return std.fmt.bufPrint(out, "PROP {s} {s} :{s}", .{ entity.id, key, value }) catch error.OutputTooSmall;
}

pub fn buildPropListReply(server: []const u8, nick: []const u8, entry: EntryView, out: []u8) PropError![]const u8 {
    try validateReplyAtom(server);
    try validateReplyAtom(nick);
    return std.fmt.bufPrint(out, ":{s} 818 {s} {s} {s} :{s}", .{
        server,
        nick,
        entry.entity.id,
        entry.key,
        entry.value,
    }) catch error.OutputTooSmall;
}

pub fn buildPropEndReply(server: []const u8, nick: []const u8, entity: Entity, out: []u8) PropError![]const u8 {
    try validateReplyAtom(server);
    try validateReplyAtom(nick);
    try validateEntity(entity, default_max_entity_id);
    return std.fmt.bufPrint(out, ":{s} 819 {s} {s} :End of properties", .{ server, nick, entity.id }) catch error.OutputTooSmall;
}

fn validateEntity(entity: Entity, max_entity_id: usize) PropError!void {
    if (entity.id.len == 0 or entity.id.len > max_entity_id) return error.InvalidEntity;
    try validateSafeText(entity.id, error.InvalidEntity);
    for (entity.id) |byte| {
        if (byte <= 0x20 or byte == ',' or byte == 0x7f) return error.InvalidEntity;
    }

    switch (entity.kind) {
        .channel => {
            if (std.mem.indexOfScalar(u8, entity.id, ':') != null) return error.InvalidEntity;
            switch (entity.id[0]) {
                '#', '&', '+', '%' => {},
                else => return error.InvalidEntity,
            }
        },
        .user => if (std.mem.indexOfScalar(u8, entity.id, ':') != null) return error.InvalidEntity,
        .member => {
            const split = std.mem.indexOfScalar(u8, entity.id, ':') orelse return error.InvalidEntity;
            if (split == 0 or split + 1 >= entity.id.len) return error.InvalidEntity;
        },
    }
}

fn validateKeyList(raw: []const u8, max_key: usize, max_request_keys: usize) PropError!void {
    if (raw.len == 0) return error.InvalidKey;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |key| {
        count += 1;
        if (count > max_request_keys) return error.TooManyParams;
        try validateKeyWithLimit(key, max_key);
    }
}

fn validateKeyWithLimit(key: []const u8, max_key: usize) PropError!void {
    if (key.len == 0 or key.len > max_key) return error.InvalidKey;
    for (key) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidKey,
        }
    }
}

fn validateValueFor(entity: Entity, key: []const u8, value: []const u8, access: AccessLevel, max_value: usize) PropError!void {
    var limit = max_value;
    if (entity.kind == .channel) {
        if (channelPropInfo(key)) |info| {
            if (info.read_only) return error.ReadOnlyProperty;
            if (!access.allows(info.min_setter)) return error.AccessDenied;
            limit = @min(limit, info.max_value);
        } else if (!access.allows(.host)) {
            return error.AccessDenied;
        }
    } else if (entity.kind == .user) {
        if (userProfilePropInfo(key)) |info| {
            limit = @min(limit, info.max_value);
        }
    }
    try validateValue(value, limit);
}

fn isSecretChannelProp(entity: Entity, key: []const u8) bool {
    if (entity.kind != .channel) return false;
    const info = channelPropInfo(key) orelse return false;
    return info.secret;
}

fn validateValue(value: []const u8, max_value: usize) PropError!void {
    if (value.len > max_value) return error.InvalidValue;
    try validateSafeText(value, error.InvalidValue);
}

fn validateOwner(owner: []const u8, max_owner_bytes: usize) PropError!void {
    if (owner.len == 0 or owner.len > max_owner_bytes) return error.InvalidOwner;
    for (owner) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == ':') return error.InvalidOwner;
    }
}

fn validateReplyAtom(raw: []const u8) PropError!void {
    if (raw.len == 0) return error.InvalidEntity;
    try validateSafeText(raw, error.InvalidEntity);
    for (raw) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidEntity;
    }
}

fn validateSafeText(bytes: []const u8, comptime err: PropError) PropError!void {
    for (bytes) |byte| {
        switch (byte) {
            0, '\r', '\n' => return err,
            1...8, 11, 12, 14...31, 127 => return err,
            else => {},
        }
    }
}

fn makePropKey(allocator: std.mem.Allocator, key: []const u8) PropError![]u8 {
    const out = allocator.alloc(u8, key.len) catch return error.LimitReached;
    errdefer allocator.free(out);
    _ = try writePropKey(out, key, key.len);
    return out;
}

fn makeDisplayKey(allocator: std.mem.Allocator, entity: Entity, key: []const u8) PropError![]u8 {
    if (entity.kind == .channel) {
        if (channelPropKey(key)) |known| return allocator.dupe(u8, known.token()) catch return error.LimitReached;
    }
    return allocator.dupe(u8, key) catch return error.LimitReached;
}

fn makePropKeyAllocationAware(allocator: std.mem.Allocator, key: []const u8) PreparedSetAllocationError![]u8 {
    const out = try allocator.alloc(u8, key.len);
    errdefer allocator.free(out);
    _ = try writePropKey(out, key, key.len);
    return out;
}

fn makeDisplayKeyAllocationAware(allocator: std.mem.Allocator, entity: Entity, key: []const u8) PreparedSetAllocationError![]u8 {
    if (entity.kind == .channel) {
        if (channelPropKey(key)) |known| return try allocator.dupe(u8, known.token());
    }
    return try allocator.dupe(u8, key);
}

fn writePropKey(out: []u8, key: []const u8, max_key: usize) PropError![]const u8 {
    try validateKeyWithLimit(key, max_key);
    if (out.len < key.len) return error.OutputTooSmall;
    for (key, 0..) |byte, index| out[index] = std.ascii.toLower(byte);
    return out[0..key.len];
}

fn writeEntityKey(out: []u8, entity: Entity, max_entity_id: usize) PropError![]const u8 {
    try validateEntity(entity, max_entity_id);
    const prefix = entity.kind.token();
    const len = prefix.len + 1 + entity.id.len;
    if (out.len < len) return error.OutputTooSmall;
    @memcpy(out[0..prefix.len], prefix);
    out[prefix.len] = 0x1f;
    for (entity.id, 0..) |byte, index| out[prefix.len + 1 + index] = std.ascii.toLower(byte);
    return out[0..len];
}

fn entryLessThan(_: void, lhs: EntryView, rhs: EntryView) bool {
    return std.mem.lessThan(u8, lhs.key, rhs.key);
}

fn asciiFoldOrder(lhs: []const u8, rhs: []const u8) std.math.Order {
    const common_len = @min(lhs.len, rhs.len);
    for (lhs[0..common_len], rhs[0..common_len]) |lhs_byte, rhs_byte| {
        const folded_lhs = std.ascii.toLower(lhs_byte);
        const folded_rhs = std.ascii.toLower(rhs_byte);
        if (folded_lhs < folded_rhs) return .lt;
        if (folded_lhs > folded_rhs) return .gt;
    }
    return std.math.order(lhs.len, rhs.len);
}

fn checkpointAdd(lhs: usize, rhs: usize) error{Overflow}!usize {
    return std.math.add(usize, lhs, rhs);
}

fn checkpointReadU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn checkpointWriteU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn checkpointTake(
    bytes: []const u8,
    pos: *usize,
    limit: usize,
    len: usize,
) CheckpointError![]const u8 {
    if (pos.* > limit or len > limit - pos.*) return error.Truncated;
    const out = bytes[pos.* .. pos.* + len];
    pos.* += len;
    return out;
}

fn propCheckpointChecksum(prefix: []const u8, out: *[prop_checkpoint_checksum_len]u8) void {
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

fn testAddEmptyPropEntity(store: *DefaultStore, entity: Entity) !void {
    var outer_buf: [DefaultStore.max_entity_key]u8 = undefined;
    const outer_view = try writeEntityKey(&outer_buf, entity, default_max_entity_id);
    try store.entities.ensureUnusedCapacity(1);
    const outer_key = try store.allocator.dupe(u8, outer_view);
    errdefer store.allocator.free(outer_key);
    const id = try store.allocator.dupe(u8, entity.id);
    store.entities.putAssumeCapacityNoClobber(
        outer_key,
        DefaultStore.EntityState.init(store.allocator, .{ .kind = entity.kind, .id = id }),
    );
    store.entity_count += 1;
}

fn testAddRawProp(
    store: *DefaultStore,
    entity: Entity,
    key: []const u8,
    value: []const u8,
    owner: []const u8,
    access: AccessLevel,
) !void {
    var outer_buf: [DefaultStore.max_entity_key]u8 = undefined;
    const outer_key = try writeEntityKey(&outer_buf, entity, default_max_entity_id);
    const state = store.entities.getPtr(outer_key) orelse return error.TestUnexpectedResult;
    try state.props.ensureUnusedCapacity(1);
    var normalized_buf: [default_max_key]u8 = undefined;
    const normalized = try writePropKey(&normalized_buf, key, default_max_key);
    var cloned = try DefaultStore.cloneCheckpointEntry(
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

fn installPropCheckpointFixture(store: *DefaultStore, reverse: bool) !void {
    const alpha = try Entity.fromId("#Alpha");
    const bravo = try Entity.fromId("#Bravo");
    const mixed = try Entity.fromId("#MiXeD");
    const user = try Entity.fromId("CaseUser");
    const member = try Entity.fromId("#MiXeD:Alice");
    const zero = try Entity.fromId("ZeroState");
    var policy_drift_topic: [200]u8 = @splat('t');

    const add_mixed = struct {
        fn run(target: *DefaultStore, entity: Entity, topic: []const u8, reversed: bool) !void {
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

fn testCheckpointEntityEnd(bytes: []const u8, entity_start: usize) usize {
    const id_len: usize = checkpointReadU32(bytes[entity_start + 1 ..][0..4]);
    const prop_count: usize = checkpointReadU32(bytes[entity_start + 5 ..][0..4]);
    var pos = entity_start + prop_checkpoint_entity_prefix_len + id_len;
    for (0..prop_count) |_| {
        const key_len: usize = checkpointReadU32(bytes[pos..][0..4]);
        const value_len: usize = checkpointReadU32(bytes[pos + 4 ..][0..4]);
        const owner_len: usize = checkpointReadU32(bytes[pos + 8 ..][0..4]);
        pos += prop_checkpoint_prop_prefix_len + key_len + value_len + owner_len;
    }
    return pos;
}

fn testFindCheckpointEntity(bytes: []const u8, wanted_id: []const u8) ?usize {
    const entity_count: usize = checkpointReadU32(bytes[5..9]);
    var pos: usize = prop_checkpoint_header_len;
    for (0..entity_count) |_| {
        const id_len: usize = checkpointReadU32(bytes[pos + 1 ..][0..4]);
        const id = bytes[pos + prop_checkpoint_entity_prefix_len ..][0..id_len];
        if (std.mem.eql(u8, id, wanted_id)) return pos;
        pos = testCheckpointEntityEnd(bytes, pos);
    }
    return null;
}

fn testFindCheckpointProp(bytes: []const u8, entity_start: usize, wanted_key: []const u8) ?usize {
    const id_len: usize = checkpointReadU32(bytes[entity_start + 1 ..][0..4]);
    const prop_count: usize = checkpointReadU32(bytes[entity_start + 5 ..][0..4]);
    var pos = entity_start + prop_checkpoint_entity_prefix_len + id_len;
    for (0..prop_count) |_| {
        const key_len: usize = checkpointReadU32(bytes[pos..][0..4]);
        const value_len: usize = checkpointReadU32(bytes[pos + 4 ..][0..4]);
        const owner_len: usize = checkpointReadU32(bytes[pos + 8 ..][0..4]);
        const key = bytes[pos + prop_checkpoint_prop_prefix_len ..][0..key_len];
        if (std.mem.eql(u8, key, wanted_key)) return pos;
        pos += prop_checkpoint_prop_prefix_len + key_len + value_len + owner_len;
    }
    return null;
}

fn rewritePropCheckpointChecksum(bytes: []u8) void {
    const body_len: usize = checkpointReadU32(bytes[13..17]);
    const prefix_len = prop_checkpoint_header_len + body_len;
    std.debug.assert(bytes.len == prefix_len + prop_checkpoint_checksum_len);
    propCheckpointChecksum(bytes[0..prefix_len], bytes[prefix_len..][0..prop_checkpoint_checksum_len]);
}

fn testSliceAliasesBytes(bytes: []const u8, slice: []const u8) bool {
    const bytes_start = @intFromPtr(bytes.ptr);
    const bytes_end = bytes_start + bytes.len;
    const slice_start = @intFromPtr(slice.ptr);
    const slice_end = slice_start + slice.len;
    return slice_start < bytes_end and bytes_start < slice_end;
}

test "set get overwrite delete and list properties" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#Onyx");
    const setter = Setter{ .id = "alice", .access = .owner };

    const first = try store.setProp(entity, "topic", "first", setter);
    try std.testing.expectEqualStrings("TOPIC", first.key);
    try std.testing.expectEqualStrings("first", first.value);
    try std.testing.expectEqualStrings("alice", first.owner);
    try std.testing.expectEqual(AccessLevel.owner, first.access);

    _ = try store.setProp(entity, "TOPIC", "second", .{ .id = "bob", .access = .owner });
    const got = try store.getProp(entity, "topic");
    try std.testing.expectEqualStrings("second", got.value);
    try std.testing.expectEqualStrings("bob", got.owner);

    _ = try store.setProp(entity, "SUBJECT", "zig", setter);
    var out: [4]EntryView = undefined;
    const listed = try store.listProps(try Entity.fromId("#onyx"), &out);
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try Entity.fromId("DeviceHeavyUser");
    const channel = try Entity.fromId("#bounded");
    var key_buf: [32]u8 = undefined;
    for (0..user_max_props_per_entity) |index| {
        const key = try std.fmt.bufPrint(&key_buf, "device.fact.{d}", .{index});
        _ = try store.setProp(user, key, "v", .{ .id = "DeviceHeavyUser", .access = .user });
    }
    try std.testing.expectError(
        error.LimitReached,
        store.setProp(user, "device.fact.overflow", "v", .{ .id = "DeviceHeavyUser", .access = .user }),
    );
    for (0..default_max_props_per_entity) |index| {
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
    var store = DefaultStore.init(failing.allocator());
    defer {
        failing.fail_index = std.math.maxInt(usize);
        store.deinit();
    }
    const user = try Entity.fromId("DeleteUser");
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try Entity.fromId("SerializedSetUser");
    const setter = Setter{ .id = "SerializedSetUser", .access = .user };
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#CloneSource");
    const destination = try Entity.fromId("#CloneDestination");
    const user = try Entity.fromId("CloneSetUser");
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try Entity.fromId("SetWinsUser");
    const setter = Setter{ .id = "SetWinsUser", .access = .user };
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try Entity.fromId("ExhaustedGenerationUser");
    const setter = Setter{ .id = "ExhaustedGenerationUser", .access = .user };
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
    var store = DefaultStore.init(failing.allocator());
    defer {
        failing.fail_index = std.math.maxInt(usize);
        store.deinit();
    }
    const user = try Entity.fromId("PurgeUser");
    const other = try Entity.fromId("OtherUser");
    const setter = Setter{ .id = "PurgeUser", .access = .user };
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
        store.prepareUserPropPrefixPurge(try Entity.fromId("#not-user"), "e2ee.device."),
    );
}

test "prepared user prefix purge preparation is allocation failure atomic" {
    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 16);
        const complete = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var store = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const user = try Entity.fromId("AtomicPurgeUser");
            const setter = Setter{ .id = "AtomicPurgeUser", .access = .user };
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try Entity.fromId("CheckpointDeviceUser");
    var key_buf: [32]u8 = undefined;
    for (0..user_max_props_per_entity) |index| {
        const key = try std.fmt.bufPrint(&key_buf, "device.checkpoint.{d}", .{index});
        _ = try store.setProp(user, key, "v", .{ .id = "CheckpointDeviceUser", .access = .user });
    }
    const checkpoint = try store.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);
    var restored = try DefaultStore.decodeCheckpoint(std.testing.allocator, checkpoint);
    defer restored.deinit();
    var views: [user_max_props_per_entity]EntryView = undefined;
    try std.testing.expectEqual(user_max_props_per_entity, (try restored.listPropsRaw(user, &views)).len);
}

test "global user prefix purge removes every folded and malformed match only" {
    try std.testing.expect(@hasDecl(DefaultStore, "prepareGlobalDevicePropPurge"));
    try std.testing.expect(!@hasDecl(DefaultStore, "prepareGlobalUserPropPrefixPurge"));
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const alice = try Entity.fromId("Alice");
    const bob = try Entity.fromId("Bob");
    const absent = try Entity.fromId("AbsentFromDprop");
    const channel = try Entity.fromId("#device-channel");
    const member = try Entity.fromId("#device-channel:Alice");
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const only = try Entity.fromId("OnlyDevice");
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = Entity{ .kind = .user, .id = "Alice" };
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
            var store = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const one = try Entity.fromId("GlobalOne");
            const two = try Entity.fromId("GlobalTwo");
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
            var store = DefaultStore.init(allocator);
            defer store.deinit();
            _ = try store.setPropAllocationAware(
                try Entity.fromId("AllocationAwareUser"),
                "profile.atomic",
                "value",
                .{ .id = "AllocationAwareUser", .access = .user },
            );
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Sweep.run, .{});

    const OneEntityStore = PropStore(.{ .max_entities = 1 });
    var full = OneEntityStore.init(std.testing.allocator);
    defer full.deinit();
    _ = try full.setPropAllocationAware(
        try Entity.fromId("FirstUser"),
        "profile.atomic",
        "first",
        .{ .id = "FirstUser", .access = .user },
    );
    try std.testing.expectError(
        error.LimitReached,
        full.prepareSetPropAllocationAware(
            try Entity.fromId("SecondUser"),
            "profile.atomic",
            "second",
            .{ .id = "SecondUser", .access = .user },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), full.entity_count);
    try std.testing.expectError(error.PropMissing, full.getPropRaw(try Entity.fromId("SecondUser"), "profile.atomic"));
}

test "global user prefix purge serializes prepared lanes and exhausts fail closed" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const user = try Entity.fromId("GlobalSerial");
    const source = try Entity.fromId("#GlobalSource");
    const destination = try Entity.fromId("#GlobalDestination");
    const setter = Setter{ .id = "GlobalSerial", .access = .user };
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

test "parse each PROP request form" {
    const list = try parseLine("PROP #chan");
    try std.testing.expectEqual(Request.list, @as(std.meta.Tag(Request), list));
    try std.testing.expectEqualStrings("#chan", list.list.id);

    const get = try parseLine("PROP #chan TOPIC,ONJOIN");
    try std.testing.expectEqual(Request.get, @as(std.meta.Tag(Request), get));
    try std.testing.expectEqualStrings("TOPIC,ONJOIN", get.get.keys);

    const set = try parseLine("PROP #chan TOPIC :hello world");
    try std.testing.expectEqual(Request.set, @as(std.meta.Tag(Request), set));
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try parseLine("PROP #chan TOPIC :");
    try std.testing.expectEqual(Request.delete, @as(std.meta.Tag(Request), del));
    try std.testing.expectEqualStrings("TOPIC", del.delete.key);

    try std.testing.expectError(error.InvalidCommand, parseLine("PRIVMSG #chan :no"));
    try std.testing.expectError(error.NeedMoreParams, parseLine("PROP"));
    try std.testing.expectError(error.TooManyParams, parseLine("PROP #c A B C"));
}

test "parse IRCX PROP verb request forms" {
    const clear = try parseLine("PROP #chan CLEAR");
    try std.testing.expectEqual(Request.delete, @as(std.meta.Tag(Request), clear));
    try std.testing.expectEqualStrings("#chan", clear.delete.entity.id);
    try std.testing.expectEqualStrings("", clear.delete.key);

    const get = try parseLine("PROP #chan GET TOPIC,NAME");
    try std.testing.expectEqual(Request.get, @as(std.meta.Tag(Request), get));
    try std.testing.expectEqualStrings("TOPIC,NAME", get.get.keys);

    const set = try parseLine("PROP #chan SET TOPIC :hello world");
    try std.testing.expectEqual(Request.set, @as(std.meta.Tag(Request), set));
    try std.testing.expectEqualStrings("TOPIC", set.set.key);
    try std.testing.expectEqualStrings("hello world", set.set.value);

    const del = try parseLine("PROP #chan SET TOPIC :");
    try std.testing.expectEqual(Request.delete, @as(std.meta.Tag(Request), del));
    try std.testing.expectEqualStrings("TOPIC", del.delete.key);

    try std.testing.expectError(error.NeedMoreParams, parseLine("PROP #chan GET"));
    try std.testing.expectError(error.TooManyParams, parseLine("PROP #chan CLEAR TOPIC"));
}

test "secret channel props stay hidden except raw internal lookup" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#keys");
    _ = try store.setProp(entity, "HOSTKEY", "s3cret", .{ .id = "owner", .access = .owner });

    try std.testing.expectError(error.PropMissing, store.getProp(entity, "HOSTKEY"));
    const raw = try store.getPropRaw(entity, "HOSTKEY");
    try std.testing.expectEqualStrings("HOSTKEY", raw.key);
    try std.testing.expectEqualStrings("s3cret", raw.value);

    // FOUNDERKEY is a secret tier key too — hidden from getProp, visible RAW.
    _ = try store.setProp(entity, "FOUNDERKEY", "topkey", .{ .id = "owner", .access = .owner });
    try std.testing.expect((channelPropInfo("FOUNDERKEY").?).secret);
    try std.testing.expect(channelPropKey("no-ai") == .no_ai);
    try std.testing.expect(channelPropKey("LOCAL-ONLY") == .local_only);
    try std.testing.expect(channelPropKey("server-ai-ok") == .server_ai_ok);
    try std.testing.expect(channelPropKey("history-policy") == .history_policy);
    try std.testing.expectError(error.PropMissing, store.getProp(entity, "FOUNDERKEY"));
    try std.testing.expectEqualStrings("topkey", (try store.getPropRaw(entity, "FOUNDERKEY")).value);

    // A plain LIST omits every secret key; listPropsRaw surfaces them for the
    // caller to gate (here: a non-secret CUSTOM plus the two secret tier keys).
    _ = try store.setProp(entity, "CUSTOM", "v", .{ .id = "owner", .access = .host });
    var views: [8]EntryView = undefined;
    const plain = try store.listProps(entity, &views);
    try std.testing.expectEqual(@as(usize, 1), plain.len);
    try std.testing.expectEqualStrings("CUSTOM", plain[0].key);
    var raw_views: [8]EntryView = undefined;
    const all = try store.listPropsRaw(entity, &raw_views);
    try std.testing.expectEqual(@as(usize, 3), all.len); // CUSTOM + HOSTKEY + FOUNDERKEY
}

test "limits and built-in channel property metadata are enforced" {
    const Tiny = PropStore(.{
        .max_entities = 1,
        .max_props_per_entity = 1,
        .max_entity_id = 8,
        .max_key = 8,
        .max_value = 8,
        .max_owner_bytes = 8,
    });
    var store = Tiny.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#c");
    _ = try store.setProp(entity, "custom", "12345678", .{ .id = "owner", .access = .host });
    // Capacity checks use the normalized lookup key: a differently-cased
    // spelling updates the existing row even when the entity is otherwise full.
    try store.preflightSetProp(entity, "CUSTOM", "changed", .{ .id = "owner", .access = .host });
    _ = try store.setProp(entity, "CUSTOM", "changed", .{ .id = "owner", .access = .host });
    try std.testing.expectEqualStrings("changed", (try store.getPropRaw(entity, "custom")).value);
    try std.testing.expectError(error.LimitReached, store.setProp(entity, "other", "1", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.LimitReached, store.setProp(try Entity.fromId("#d"), "custom", "1", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.InvalidValue, store.setProp(entity, "custom", "123456789", .{ .id = "owner", .access = .host }));
    try std.testing.expectError(error.InvalidOwner, store.setProp(entity, "custom", "1", .{ .id = "bad owner", .access = .host }));

    try std.testing.expect(channelPropKey("OWNERKEY").? == .ownerkey);
    try std.testing.expect((channelPropInfo("OWNERKEY").?).secret);
    try std.testing.expectError(error.ReadOnlyProperty, store.setProp(entity, "OID", "1", .{ .id = "server", .access = .server }));
    try std.testing.expectError(error.AccessDenied, store.setProp(entity, "PICS", "safe", .{ .id = "owner", .access = .owner }));

    // MEMBERCOUNT is a computed read-only builtin; MEMBERLIMIT is host-settable.
    // (Checked via metadata + a default-limit store; the Tiny store's 8-byte key
    // cap would reject these long key names before the read-only rule applies.)
    try std.testing.expect(channelPropKey("MEMBERCOUNT").? == .membercount);
    try std.testing.expect(channelPropInfo("MEMBERCOUNT").?.read_only);
    try std.testing.expect(!channelPropInfo("MEMBERLIMIT").?.read_only);

    var full = DefaultStore.init(std.testing.allocator);
    defer full.deinit();
    const chan = try Entity.fromId("#mc");
    try std.testing.expectError(error.ReadOnlyProperty, full.setProp(chan, "MEMBERCOUNT", "1", .{ .id = "server", .access = .server }));
    _ = try full.setProp(chan, "MEMBERLIMIT", "50", .{ .id = "host", .access = .host });
}

test "user profile properties use the profile value limit" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("Alice");
    const setter = Setter{ .id = "Alice", .access = .member };
    const cases = [_]struct {
        key: []const u8,
        value: []const u8,
    }{
        .{ .key = "URL", .value = "https://example.test/alice" },
        .{ .key = "GENDER", .value = "nonbinary" },
        .{ .key = "PICTURE", .value = "https://example.test/a.png" },
        .{ .key = "BIO", .value = "Onyx operator" },
        .{ .key = "EMAIL", .value = "alice@example.test" },
    };

    for (cases) |case| {
        const ev = try store.setProp(entity, case.key, case.value, setter);
        try std.testing.expectEqualStrings(case.key, ev.key);
        try std.testing.expectEqualStrings(case.value, ev.value);
        try std.testing.expect(userProfilePropKey(case.key) != null);
    }

    var too_long = @as([(user_profile_max_value + 1)]u8, @splat('x'));
    try std.testing.expectError(error.InvalidValue, store.setProp(entity, "URL", too_long[0..], setter));

    // The tighter cap applies only to the newly added user-profile fields.
    // Existing Onyx Server profile keys and generic user props retain the store-wide
    // value budget.
    _ = try store.setProp(entity, "display", too_long[0..], setter);
    _ = try store.setProp(entity, "custom", too_long[0..], setter);
}

test "reply builders and no-leak clear path" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const entity = try Entity.fromId("#reply");
    const entry = try store.setProp(entity, "TOPIC", "hello", .{ .id = "oper", .access = .owner });

    var out: [160]u8 = undefined;
    try std.testing.expectEqualStrings("PROP #reply TOPIC :hello", try buildPropMessage(entity, entry.key, entry.value, &out));
    try std.testing.expectEqualStrings(":irc.example 818 nick #reply TOPIC :hello", try buildPropListReply("irc.example", "nick", entry, &out));
    try std.testing.expectEqualStrings(":irc.example 819 nick #reply :End of properties", try buildPropEndReply("irc.example", "nick", entity, &out));
    try std.testing.expectError(error.OutputTooSmall, buildPropListReply("irc.example", "nick", entry, out[0..8]));

    store.clear();
    _ = try store.setProp(try Entity.fromId("nick"), "away", "no", .{ .id = "nick", .access = .user });
}

test "prepared public channel clone is exact deterministic and independently owned" {
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();

    const source = try Entity.fromId("#Template");
    const destination = try Entity.fromId("#Clone");
    const member_a = try Entity.fromId("#Clone:Alice");
    const member_b = try Entity.fromId("#clone:Bob");
    const near_prefix_member = try Entity.fromId("#Clone2:Eve");
    const unrelated = try Entity.fromId("Watcher");
    try std.testing.expectEqual(EntityKind.member, member_a.kind);
    try std.testing.expectEqual(EntityKind.member, member_b.kind);

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
    try std.testing.expectEqual(AccessLevel.host, replacements[0].access);
    try std.testing.expectEqualStrings("source topic", replacements[1].value);
    try std.testing.expectEqualStrings("source-host", replacements[1].owner);
    try std.testing.expectEqual(AccessLevel.host, replacements[1].access);
    for (replacements) |fact| try std.testing.expectEqualStrings(destination.id, fact.entity.id);

    const purged = ticket.purgedFacts();
    try std.testing.expectEqual(@as(usize, 4), purged.len);
    try std.testing.expectEqual(EntityKind.channel, purged[0].entity.kind);
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
        var preview: ?*const DefaultStore.PreparedPropFact = null;
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
    const member_request = try parseLine("PROP #room:Nick SET ROLE :operator");
    try std.testing.expectEqual(Request.set, @as(std.meta.Tag(Request), member_request));
    try std.testing.expectEqual(EntityKind.member, member_request.set.entity.kind);
    try std.testing.expectEqualStrings("#room:Nick", member_request.set.entity.id);

    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#Same");
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
    var store = DefaultStore.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#SecretTemplate");
    const destination = try Entity.fromId("#ClearMe");
    const member_a = try Entity.fromId("#ClearMe:Alice");
    const member_b = try Entity.fromId("#clearme:Bob");
    const unrelated = try Entity.fromId("Other");
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
    const Capped = PropStore(.{ .max_entities = 5 });
    var store = Capped.init(std.testing.allocator);
    defer store.deinit();
    const source = try Entity.fromId("#Src");
    const destination = try Entity.fromId("#Dst");
    const member_a = try Entity.fromId("#Dst:A");
    const member_b = try Entity.fromId("#dst:B");
    const unrelated = try Entity.fromId("Other");
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

    const NoRoom = PropStore(.{ .max_entities = 2 });
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
            var store = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }

            const source = try Entity.fromId("#AllocSource");
            const destination = try Entity.fromId("#AllocDestination");
            const member = try Entity.fromId("#allocdestination:Nick");
            const unrelated = try Entity.fromId("Other");
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
    var empty_store = DefaultStore.init(std.testing.allocator);
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
            var store = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                store.deinit();
            }
            const source = try Entity.fromId("#FreshSource");
            const destination = try Entity.fromId("#FreshTarget");
            _ = try store.setProp(source, "CUSTOM", "fresh-copy", .{ .id = "host", .access = .host });

            const load_limit = (store.entities.capacity() * std.hash_map.default_max_load_percentage) / 100;
            var filler_index: usize = 0;
            var filler_buf: [32]u8 = undefined;
            while (store.entities.count() < load_limit) : (filler_index += 1) {
                const filler_id = std.fmt.bufPrint(&filler_buf, "Filler-{d}", .{filler_index}) catch unreachable;
                _ = try store.setProp(try Entity.fromId(filler_id), "CUSTOM", "keep", .{ .id = "filler", .access = .user });
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

test "PROP checkpoint is deterministic complete and independently owned" {
    var first = DefaultStore.init(std.testing.allocator);
    defer first.deinit();
    var second = DefaultStore.init(std.testing.allocator);
    defer second.deinit();
    try installPropCheckpointFixture(&first, false);
    try installPropCheckpointFixture(&second, true);

    const first_bytes = try first.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(first_bytes);
    const second_bytes = try second.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(second_bytes);
    try std.testing.expectEqualSlices(u8, first_bytes, second_bytes);

    var restored = try DefaultStore.decodeCheckpoint(std.testing.allocator, first_bytes);
    defer restored.deinit();
    try std.testing.expectEqual(first.entity_count, restored.entity_count);
    try std.testing.expectEqual(@as(usize, 6), restored.entity_count);
    const mixed = try Entity.fromId("#MiXeD");
    try std.testing.expectEqualStrings("mesh-secret", (try restored.getPropRaw(mixed, "HOSTKEY")).value);
    try std.testing.expectEqualStrings("future-value", (try restored.getPropRaw(mixed, "future-x")).value);
    const restored_topic = try restored.getPropRaw(mixed, "TOPIC");
    try std.testing.expectEqual(@as(usize, 200), restored_topic.value.len);
    try std.testing.expectEqualStrings("legacy-user", restored_topic.owner);
    try std.testing.expectEqual(AccessLevel.user, restored_topic.access);
    try std.testing.expectEqualStrings(
        "case-preserved",
        (try restored.getPropRaw(try Entity.fromId("CaseUser"), "BIO")).value,
    );
    try std.testing.expectEqualStrings(
        "operator",
        (try restored.getPropRaw(try Entity.fromId("#MiXeD:Alice"), "ROLE")).value,
    );

    var zero_key_buf: [DefaultStore.max_entity_key]u8 = undefined;
    const zero_entity = try Entity.fromId("ZeroState");
    const zero_key = try writeEntityKey(&zero_key_buf, zero_entity, default_max_entity_id);
    const zero_state = restored.entities.getPtr(zero_key) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), zero_state.prop_count);
    try std.testing.expectEqual(@as(usize, 0), zero_state.props.count());

    var mixed_key_buf: [DefaultStore.max_entity_key]u8 = undefined;
    const mixed_key = try writeEntityKey(&mixed_key_buf, mixed, default_max_entity_id);
    const outer = restored.entities.getEntry(mixed_key) orelse return error.TestUnexpectedResult;
    try std.testing.expect(@intFromPtr(outer.key_ptr.*.ptr) != @intFromPtr(outer.value_ptr.entity.id.ptr));
    try std.testing.expect(!testSliceAliasesBytes(first_bytes, outer.key_ptr.*));
    try std.testing.expect(!testSliceAliasesBytes(first_bytes, outer.value_ptr.entity.id));
    var prop_key_buf: [default_max_key]u8 = undefined;
    const prop_key = try writePropKey(&prop_key_buf, "FuTuRe-X", default_max_key);
    const prop = outer.value_ptr.props.getEntry(prop_key) orelse return error.TestUnexpectedResult;
    try std.testing.expect(@intFromPtr(prop.key_ptr.*.ptr) != @intFromPtr(prop.value_ptr.key.ptr));
    try std.testing.expect(!testSliceAliasesBytes(first_bytes, prop.key_ptr.*));
    try std.testing.expect(!testSliceAliasesBytes(first_bytes, prop.value_ptr.key));
    try std.testing.expect(!testSliceAliasesBytes(first_bytes, prop.value_ptr.value));
    try std.testing.expect(!testSliceAliasesBytes(first_bytes, prop.value_ptr.owner));

    const round_trip = try restored.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(round_trip);
    try std.testing.expectEqualSlices(u8, first_bytes, round_trip);

    var empty = DefaultStore.init(std.testing.allocator);
    defer empty.deinit();
    const empty_bytes = try empty.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(empty_bytes);
    try std.testing.expectEqual(
        prop_checkpoint_header_len + prop_checkpoint_checksum_len,
        empty_bytes.len,
    );
    var empty_restored = try DefaultStore.decodeCheckpoint(std.testing.allocator, empty_bytes);
    defer empty_restored.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty_restored.entity_count);
}

test "PROP checkpoint replacement is atomic and validates private cached state" {
    var source = DefaultStore.init(std.testing.allocator);
    defer source.deinit();
    try installPropCheckpointFixture(&source, false);
    const checkpoint = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);

    var target = DefaultStore.init(std.testing.allocator);
    defer target.deinit();
    const sentinel = try Entity.fromId("Sentinel");
    _ = try target.setProp(sentinel, "CUSTOM", "old-state", .{ .id = "Sentinel", .access = .user });
    try target.replaceFromCheckpoint(checkpoint);
    try std.testing.expectError(error.PropMissing, target.getPropRaw(sentinel, "CUSTOM"));
    try std.testing.expectEqualStrings(
        "mesh-secret",
        (try target.getPropRaw(try Entity.fromId("#MiXeD"), "HOSTKEY")).value,
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
    const mixed = try Entity.fromId("#MiXeD");
    var mixed_key_buf: [DefaultStore.max_entity_key]u8 = undefined;
    const mixed_key = try writeEntityKey(&mixed_key_buf, mixed, default_max_entity_id);
    const nonempty_state = source.entities.getPtr(mixed_key) orelse return error.TestUnexpectedResult;
    const prop_entry = nonempty_state.props.getEntry("alpha") orelse return error.TestUnexpectedResult;
    const mutable_prop_key = @constCast(prop_entry.key_ptr.*);
    const saved_prop_byte = mutable_prop_key[0];
    mutable_prop_key[0] ^= 1;
    try std.testing.expectError(error.InvalidField, source.encodeCheckpoint(std.testing.allocator));
    mutable_prop_key[0] = saved_prop_byte;
}

test "PROP checkpoint rejects corrupt noncanonical duplicate and out-of-bounds wires" {
    var source = DefaultStore.init(std.testing.allocator);
    defer source.deinit();
    try installPropCheckpointFixture(&source, false);
    const checkpoint = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);

    // Every strict prefix is rejected; none can be mistaken for an empty or
    // partially valid predecessor state.
    for (0..checkpoint.len) |prefix_len| {
        if (DefaultStore.decodeCheckpoint(std.testing.allocator, checkpoint[0..prefix_len])) |decoded_value| {
            var decoded = decoded_value;
            decoded.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const bad_magic = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(bad_magic);
    bad_magic[0] ^= 1;
    try std.testing.expectError(error.BadMagic, DefaultStore.decodeCheckpoint(std.testing.allocator, bad_magic));
    const bad_version = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(bad_version);
    bad_version[4] +%= 1;
    try std.testing.expectError(error.UnsupportedVersion, DefaultStore.decodeCheckpoint(std.testing.allocator, bad_version));

    const trailing = try std.testing.allocator.alloc(u8, checkpoint.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..checkpoint.len], checkpoint);
    trailing[checkpoint.len] = 0xa5;
    try std.testing.expectError(error.TrailingBytes, DefaultStore.decodeCheckpoint(std.testing.allocator, trailing));

    const bitflip = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(bitflip);
    bitflip[prop_checkpoint_header_len + prop_checkpoint_entity_prefix_len] ^= 1;
    try std.testing.expectError(error.ChecksumMismatch, DefaultStore.decodeCheckpoint(std.testing.allocator, bitflip));

    const alpha_start = testFindCheckpointEntity(checkpoint, "#Alpha") orelse return error.TestUnexpectedResult;
    const bravo_start = testFindCheckpointEntity(checkpoint, "#Bravo") orelse return error.TestUnexpectedResult;
    const mixed_start = testFindCheckpointEntity(checkpoint, "#MiXeD") orelse return error.TestUnexpectedResult;
    const mixed_alpha = testFindCheckpointProp(checkpoint, mixed_start, "ALPHA") orelse return error.TestUnexpectedResult;
    const mixed_bravo = testFindCheckpointProp(checkpoint, mixed_start, "BRAVO") orelse return error.TestUnexpectedResult;
    const mixed_topic = testFindCheckpointProp(checkpoint, mixed_start, "TOPIC") orelse return error.TestUnexpectedResult;

    const invalid_kind = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(invalid_kind);
    invalid_kind[alpha_start] = 0xff;
    rewritePropCheckpointChecksum(invalid_kind);
    try std.testing.expectError(error.InvalidField, DefaultStore.decodeCheckpoint(std.testing.allocator, invalid_kind));

    const invalid_access = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(invalid_access);
    invalid_access[mixed_alpha + 12] = 0xff;
    rewritePropCheckpointChecksum(invalid_access);
    try std.testing.expectError(error.InvalidField, DefaultStore.decodeCheckpoint(std.testing.allocator, invalid_access));
    const invalid_bool = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(invalid_bool);
    invalid_bool[mixed_alpha + 13] = 1;
    rewritePropCheckpointChecksum(invalid_bool);
    try std.testing.expectError(error.InvalidField, DefaultStore.decodeCheckpoint(std.testing.allocator, invalid_bool));

    const oversized_key = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(oversized_key);
    checkpointWriteU32(oversized_key[mixed_alpha..][0..4], default_max_key + 1);
    rewritePropCheckpointChecksum(oversized_key);
    try std.testing.expectError(error.CapacityExceeded, DefaultStore.decodeCheckpoint(std.testing.allocator, oversized_key));
    const empty_owner = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(empty_owner);
    checkpointWriteU32(empty_owner[mixed_alpha + 8 ..][0..4], 0);
    rewritePropCheckpointChecksum(empty_owner);
    try std.testing.expectError(error.CapacityExceeded, DefaultStore.decodeCheckpoint(std.testing.allocator, empty_owner));

    const too_many_entities = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(too_many_entities);
    checkpointWriteU32(too_many_entities[5..9], default_max_entities + 1);
    rewritePropCheckpointChecksum(too_many_entities);
    try std.testing.expectError(error.CapacityExceeded, DefaultStore.decodeCheckpoint(std.testing.allocator, too_many_entities));
    const too_many_props = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(too_many_props);
    checkpointWriteU32(too_many_props[mixed_start + 5 ..][0..4], default_max_props_per_entity + 1);
    rewritePropCheckpointChecksum(too_many_props);
    try std.testing.expectError(error.CapacityExceeded, DefaultStore.decodeCheckpoint(std.testing.allocator, too_many_props));
    const mismatched_total = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(mismatched_total);
    checkpointWriteU32(mismatched_total[9..13], checkpointReadU32(mismatched_total[9..13]) + 1);
    rewritePropCheckpointChecksum(mismatched_total);
    try std.testing.expectError(error.CachedCountMismatch, DefaultStore.decodeCheckpoint(std.testing.allocator, mismatched_total));
    const huge_body = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(huge_body);
    checkpointWriteU32(huge_body[13..17], std.math.maxInt(u32));
    try std.testing.expectError(error.CheckpointTooLarge, DefaultStore.decodeCheckpoint(std.testing.allocator, huge_body));

    // Counts remain within configured caps but cannot fit in the authenticated
    // body. Shape validation must reject this before the allocator is touched.
    const allocation_bomb = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(allocation_bomb);
    checkpointWriteU32(allocation_bomb[5..9], default_max_entities);
    rewritePropCheckpointChecksum(allocation_bomb);
    var fail_immediately = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.Truncated,
        DefaultStore.decodeCheckpoint(fail_immediately.allocator(), allocation_bomb),
    );
    try std.testing.expect(!fail_immediately.has_induced_failure);

    const duplicate_entity = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(duplicate_entity);
    @memcpy(
        duplicate_entity[bravo_start + prop_checkpoint_entity_prefix_len ..][0..6],
        "#aLpHa",
    );
    rewritePropCheckpointChecksum(duplicate_entity);
    try std.testing.expectError(error.DuplicateEntity, DefaultStore.decodeCheckpoint(std.testing.allocator, duplicate_entity));
    const reversed_entities = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(reversed_entities);
    var saved_alpha_id: [6]u8 = undefined;
    @memcpy(&saved_alpha_id, reversed_entities[alpha_start + prop_checkpoint_entity_prefix_len ..][0..6]);
    @memcpy(
        reversed_entities[alpha_start + prop_checkpoint_entity_prefix_len ..][0..6],
        reversed_entities[bravo_start + prop_checkpoint_entity_prefix_len ..][0..6],
    );
    @memcpy(
        reversed_entities[bravo_start + prop_checkpoint_entity_prefix_len ..][0..6],
        &saved_alpha_id,
    );
    rewritePropCheckpointChecksum(reversed_entities);
    try std.testing.expectError(error.NonCanonicalOrder, DefaultStore.decodeCheckpoint(std.testing.allocator, reversed_entities));

    const duplicate_prop = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(duplicate_prop);
    @memcpy(
        duplicate_prop[mixed_bravo + prop_checkpoint_prop_prefix_len ..][0..5],
        "aLpHa",
    );
    rewritePropCheckpointChecksum(duplicate_prop);
    try std.testing.expectError(error.DuplicateProperty, DefaultStore.decodeCheckpoint(std.testing.allocator, duplicate_prop));
    const reversed_props = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(reversed_props);
    var saved_alpha_key: [5]u8 = undefined;
    @memcpy(&saved_alpha_key, reversed_props[mixed_alpha + prop_checkpoint_prop_prefix_len ..][0..5]);
    @memcpy(
        reversed_props[mixed_alpha + prop_checkpoint_prop_prefix_len ..][0..5],
        reversed_props[mixed_bravo + prop_checkpoint_prop_prefix_len ..][0..5],
    );
    @memcpy(
        reversed_props[mixed_bravo + prop_checkpoint_prop_prefix_len ..][0..5],
        &saved_alpha_key,
    );
    rewritePropCheckpointChecksum(reversed_props);
    try std.testing.expectError(error.NonCanonicalOrder, DefaultStore.decodeCheckpoint(std.testing.allocator, reversed_props));

    const noncanonical_known = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(noncanonical_known);
    @memcpy(
        noncanonical_known[mixed_topic + prop_checkpoint_prop_prefix_len ..][0..5],
        "topic",
    );
    rewritePropCheckpointChecksum(noncanonical_known);
    try std.testing.expectError(error.InvalidField, DefaultStore.decodeCheckpoint(std.testing.allocator, noncanonical_known));
    const unsafe_key = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(unsafe_key);
    @memcpy(unsafe_key[mixed_alpha + prop_checkpoint_prop_prefix_len ..][0..5], "ALP!A");
    rewritePropCheckpointChecksum(unsafe_key);
    try std.testing.expectError(error.InvalidField, DefaultStore.decodeCheckpoint(std.testing.allocator, unsafe_key));
    const unsafe_value = try std.testing.allocator.dupe(u8, checkpoint);
    defer std.testing.allocator.free(unsafe_value);
    const alpha_value_start = mixed_alpha + prop_checkpoint_prop_prefix_len + 5;
    unsafe_value[alpha_value_start] = '\n';
    rewritePropCheckpointChecksum(unsafe_value);
    try std.testing.expectError(error.InvalidField, DefaultStore.decodeCheckpoint(std.testing.allocator, unsafe_value));

    // The extra byte is inside the authenticated body. Declared records decode,
    // then exact EOF rejects the hidden extension.
    const authenticated_trailing = try std.testing.allocator.alloc(u8, checkpoint.len + 1);
    defer std.testing.allocator.free(authenticated_trailing);
    const old_prefix_len = checkpoint.len - prop_checkpoint_checksum_len;
    @memcpy(authenticated_trailing[0..old_prefix_len], checkpoint[0..old_prefix_len]);
    authenticated_trailing[old_prefix_len] = 0xa5;
    checkpointWriteU32(
        authenticated_trailing[13..17],
        checkpointReadU32(checkpoint[13..17]) + 1,
    );
    rewritePropCheckpointChecksum(authenticated_trailing);
    try std.testing.expectError(error.TrailingBytes, DefaultStore.decodeCheckpoint(std.testing.allocator, authenticated_trailing));

    // A corrupt replacement never displaces the live sentinel.
    var target = DefaultStore.init(std.testing.allocator);
    defer target.deinit();
    const sentinel = try Entity.fromId("Sentinel");
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
    var source = DefaultStore.init(std.testing.allocator);
    defer source.deinit();
    try installPropCheckpointFixture(&source, false);

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, store: *const DefaultStore) !void {
            const bytes = try store.encodeCheckpoint(allocator);
            defer allocator.free(bytes);
            try std.testing.expect(bytes.len > prop_checkpoint_header_len + prop_checkpoint_checksum_len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, EncodeSweep.run, .{&source});

    const checkpoint = try source.encodeCheckpoint(std.testing.allocator);
    defer std.testing.allocator.free(checkpoint);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try DefaultStore.decodeCheckpoint(allocator, bytes);
            defer decoded.deinit();
            try std.testing.expectEqual(@as(usize, 6), decoded.entity_count);
            try std.testing.expectEqualStrings(
                "mesh-secret",
                (try decoded.getPropRaw(try Entity.fromId("#MiXeD"), "HOSTKEY")).value,
            );
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, DecodeSweep.run, .{checkpoint});

    var fail_offset: usize = 0;
    while (true) : (fail_offset += 1) {
        try std.testing.expect(fail_offset < 512);
        const completed = blk: {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
            var target = DefaultStore.init(failing.allocator());
            defer {
                failing.fail_index = std.math.maxInt(usize);
                target.deinit();
            }
            const sentinel = try Entity.fromId("Sentinel");
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
                    target.getPropRaw(try Entity.fromId("#MiXeD"), "HOSTKEY"),
                );
                break :blk false;
            };
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectError(error.PropMissing, target.getPropRaw(sentinel, "CUSTOM"));
            try std.testing.expectEqual(@as(usize, 6), target.entity_count);
            try std.testing.expectEqualStrings(
                "mesh-secret",
                (try target.getPropRaw(try Entity.fromId("#MiXeD"), "HOSTKEY")).value,
            );
            break :blk true;
        };
        if (completed) break;
    }
}
