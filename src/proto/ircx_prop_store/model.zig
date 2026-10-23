// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property contracts, canonical keys, access policy, and field validation.

const std = @import("std");
const irc_line = @import("../irc_line.zig");
const ircx = @import("../ircx.zig");
const limits_config = @import("../limits_config.zig");

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

pub fn isChannelEntityId(id: []const u8) bool {
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
        return @backingInt(self) >= @backingInt(required);
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

/// Draft channel LAG, in whole seconds. Only `0`, `1`, and `2` are legal.
/// Any other spelling, including a longer number, is not a lag.
pub fn lagSeconds(value: []const u8) ?u8 {
    if (value.len != 1) return null;
    return switch (value[0]) {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        else => null,
    };
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
        // Draft LAG is one digit: 0, 1, or 2 seconds. `lagSeconds` rejects the rest.
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

pub fn validateEntity(entity: Entity, max_entity_id: usize) PropError!void {
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

pub fn validateKeyList(raw: []const u8, max_key: usize, max_request_keys: usize) PropError!void {
    if (raw.len == 0) return error.InvalidKey;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |key| {
        count += 1;
        if (count > max_request_keys) return error.TooManyParams;
        try validateKeyWithLimit(key, max_key);
    }
}

pub fn validateKeyWithLimit(key: []const u8, max_key: usize) PropError!void {
    if (key.len == 0 or key.len > max_key) return error.InvalidKey;
    for (key) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
            else => return error.InvalidKey,
        }
    }
}

pub fn validateValueFor(entity: Entity, key: []const u8, value: []const u8, access: AccessLevel, max_value: usize) PropError!void {
    var limit = max_value;
    if (entity.kind == .channel) {
        if (channelPropInfo(key)) |info| {
            if (info.read_only) return error.ReadOnlyProperty;
            if (!access.allows(info.min_setter)) return error.AccessDenied;
            if (info.key == .lag and lagSeconds(value) == null) return error.InvalidValue;
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

pub fn isSecretChannelProp(entity: Entity, key: []const u8) bool {
    if (entity.kind != .channel) return false;
    const info = channelPropInfo(key) orelse return false;
    return info.secret;
}

pub fn validateValue(value: []const u8, max_value: usize) PropError!void {
    if (value.len > max_value) return error.InvalidValue;
    try validateSafeText(value, error.InvalidValue);
}

pub fn validateOwner(owner: []const u8, max_owner_bytes: usize) PropError!void {
    if (owner.len == 0 or owner.len > max_owner_bytes) return error.InvalidOwner;
    for (owner) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == ':') return error.InvalidOwner;
    }
}

pub fn validateReplyAtom(raw: []const u8) PropError!void {
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

pub fn makePropKeyAllocationAware(allocator: std.mem.Allocator, key: []const u8) PreparedSetAllocationError![]u8 {
    const out = try allocator.alloc(u8, key.len);
    errdefer allocator.free(out);
    _ = try writePropKey(out, key, key.len);
    return out;
}

pub fn makeDisplayKeyAllocationAware(allocator: std.mem.Allocator, entity: Entity, key: []const u8) PreparedSetAllocationError![]u8 {
    if (entity.kind == .channel) {
        if (channelPropKey(key)) |known| return try allocator.dupe(u8, known.token());
    }
    return try allocator.dupe(u8, key);
}

pub fn writePropKey(out: []u8, key: []const u8, max_key: usize) PropError![]const u8 {
    try validateKeyWithLimit(key, max_key);
    if (out.len < key.len) return error.OutputTooSmall;
    for (key, 0..) |byte, index| out[index] = std.ascii.toLower(byte);
    return out[0..key.len];
}

pub fn writeEntityKey(out: []u8, entity: Entity, max_entity_id: usize) PropError![]const u8 {
    try validateEntity(entity, max_entity_id);
    const prefix = entity.kind.token();
    const len = prefix.len + 1 + entity.id.len;
    if (out.len < len) return error.OutputTooSmall;
    @memcpy(out[0..prefix.len], prefix);
    out[prefix.len] = 0x1f;
    for (entity.id, 0..) |byte, index| out[prefix.len + 1 + index] = std.ascii.toLower(byte);
    return out[0..len];
}

pub fn entryLessThan(_: void, lhs: EntryView, rhs: EntryView) bool {
    return std.mem.lessThan(u8, lhs.key, rhs.key);
}

pub fn asciiFoldOrder(lhs: []const u8, rhs: []const u8) std.math.Order {
    const common_len = @min(lhs.len, rhs.len);
    for (lhs[0..common_len], rhs[0..common_len]) |lhs_byte, rhs_byte| {
        const folded_lhs = std.ascii.toLower(lhs_byte);
        const folded_rhs = std.ascii.toLower(rhs_byte);
        if (folded_lhs < folded_rhs) return .lt;
        if (folded_lhs > folded_rhs) return .gt;
    }
    return std.math.order(lhs.len, rhs.len);
}

pub fn maxPropsFor(comptime params: Params, kind: EntityKind) usize {
    return if (kind == .user) @max(params.max_props_per_entity, user_max_props_per_entity) else params.max_props_per_entity;
}
