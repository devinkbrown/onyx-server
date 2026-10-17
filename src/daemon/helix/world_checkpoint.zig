// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact, deterministic Helix checkpoint for the complete local channel World.
//!
//! ClientIds are process-local and therefore never cross exec. Each physical
//! membership/invite instead carries an opaque join key; production Helix uses
//! the inherited socket fd shared with the matching client capsule. Decode
//! builds an owned detached World plus exact fd/nick relation expectations for
//! validation before publication and again after all clients are adopted.

const std = @import("std");
const world_mod = @import("../world.zig");

pub const version: u16 = 2;
pub const magic = [_]u8{ 'H', 'W', 'C', '2' };

const checksum_len = std.crypto.hash.Blake3.digest_length;
const checksum_domain = "onyx-helix-world-checkpoint-v2";
const header_len: usize = 40;
const max_checkpoint_bytes: usize = 64 * 1024 * 1024;
const max_string_bytes: usize = 1024 * 1024;
const max_channels: usize = 65_535;
const max_relations: usize = 1_000_000;
const max_list_entries: usize = 65_535;
const known_member_mode_mask: u8 = 0x0f;

pub const Error = std.mem.Allocator.Error || error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    ChecksumMismatch,
    CheckpointTooLarge,
    InvalidField,
    InvalidRecordLength,
    InvalidChannelName,
    InvalidModeBits,
    DuplicateChannel,
    DuplicateOid,
    DuplicateMember,
    DuplicateInvite,
    DuplicateListEntry,
    NonCanonicalOrder,
    MissingClientNick,
    CountMismatch,
    ListFull,
};

pub const MemberExpectation = struct {
    /// Borrows the owned channel key inside `Restored.world`.
    channel: []const u8,
    /// Opaque physical owner key. Production Helix uses the inherited socket
    /// fd, which is also carried by the matching `.clients` capsule.
    join_key: u64,
    /// Owned by Restored.
    nick: []u8,
    modes: world_mod.MemberModes,
};

pub const InviteExpectation = struct {
    /// Borrows the owned channel key inside `Restored.world`.
    channel: []const u8,
    join_key: u64,
    /// Owned by Restored.
    nick: []u8,
};

pub const ClientProjection = struct {
    join_key: u64,
    nick: []const u8,
};

/// One member relation projected from decoded client snapshots before World is
/// published. Callers may build this in any order; validation is allocation-free.
pub const MemberProjection = struct {
    channel: []const u8,
    join_key: u64,
    nick: []const u8,
    modes: world_mod.MemberModes,
};

/// Resolve a process-local World ClientId to its rendered nick while sealing or
/// validating a live server.  World itself intentionally retains only one
/// global lookup owner for a multi-attachment reusable session, while the
/// server's ConnState table retains the display identity of every attachment.
pub const MemberIdentity = struct {
    join_key: u64,
    nick: []const u8,
};

pub const NickResolver = struct {
    context: *anyopaque,
    resolve: *const fn (*anyopaque, world_mod.ClientId) ?MemberIdentity,
    lookup: *const fn (*anyopaque, u64) ?world_mod.ClientId,

    fn identity(self: NickResolver, client: world_mod.ClientId) ?MemberIdentity {
        return self.resolve(self.context, client);
    }

    fn clientForKey(self: NickResolver, join_key: u64) ?world_mod.ClientId {
        return self.lookup(self.context, join_key);
    }
};

pub const RelationValidationError = error{
    RelationCountMismatch,
    DuplicateProjection,
    UnexpectedMember,
    MissingMember,
    MemberModeMismatch,
    MissingClient,
    MissingChannel,
};

pub const InviteApplyError = RelationValidationError || std.mem.Allocator.Error;

/// Fully-owned successor image. The World contains channel metadata but no
/// process-local nick or ClientId state. Relations are applied after clients
/// have been adopted and assigned successor ClientIds.
pub const Restored = struct {
    allocator: std.mem.Allocator,
    world: world_mod.World,
    member_expectations: []MemberExpectation,
    invite_expectations: []InviteExpectation,
    initialized_members: usize = 0,
    initialized_invites: usize = 0,

    /// Swap the detached image into a quiescent, unlocked live World without
    /// allocating. The displaced World becomes owned by `self` and is destroyed
    /// by the caller's existing `defer restored.deinit()`.
    pub fn swapWorldInto(self: *Restored, target: *world_mod.World) void {
        std.mem.swap(world_mod.World, &self.world, target);
    }

    /// Validate the complete client-snapshot projection before publication.
    /// Exact cardinality plus bidirectional membership checks reject missing,
    /// extra, duplicate, or mode-mismatched relations without allocating.
    pub fn validateMemberProjection(
        self: *const Restored,
        projection: []const MemberProjection,
    ) RelationValidationError!void {
        if (projection.len != self.member_expectations.len)
            return error.RelationCountMismatch;
        for (projection, 0..) |candidate, index| {
            for (projection[0..index]) |prior| {
                if (ciOrder(prior.channel, candidate.channel) == .eq and
                    prior.join_key == candidate.join_key)
                    return error.DuplicateProjection;
            }
            var key_match: ?MemberExpectation = null;
            for (self.member_expectations) |expected| {
                if (ciOrder(expected.channel, candidate.channel) == .eq and
                    expected.join_key == candidate.join_key)
                {
                    key_match = expected;
                    break;
                }
            }
            const expected = key_match orelse return error.UnexpectedMember;
            if (!std.mem.eql(u8, expected.nick, candidate.nick))
                return error.UnexpectedMember;
            if (expected.modes.bits != candidate.modes.bits)
                return error.MemberModeMismatch;
        }
        for (self.member_expectations) |expected| {
            var found = false;
            for (projection) |candidate| {
                if (ciOrder(expected.channel, candidate.channel) == .eq and
                    expected.join_key == candidate.join_key)
                {
                    found = true;
                    break;
                }
            }
            if (!found) return error.MissingMember;
        }
    }

    /// Every fd-keyed invite must name exactly one carried client capsule with
    /// the same rendered identity. Clients need not have a channel membership,
    /// so this is validated against the complete client projection separately.
    pub fn validateInviteProjection(
        self: *const Restored,
        clients: []const ClientProjection,
    ) RelationValidationError!void {
        for (clients, 0..) |candidate, index| {
            for (clients[0..index]) |prior|
                if (prior.join_key == candidate.join_key)
                    return error.DuplicateProjection;
        }
        for (self.invite_expectations) |expected| {
            var found = false;
            for (clients) |candidate| {
                if (candidate.join_key != expected.join_key) continue;
                if (!std.mem.eql(u8, candidate.nick, expected.nick))
                    return error.UnexpectedMember;
                found = true;
                break;
            }
            if (!found) return error.MissingClient;
        }
    }

    /// After client adoption, verify that every expected nick resolves, carries
    /// the exact mode set, and that each channel has no extra members. This does
    /// not allocate and does not mutate World.
    pub fn validateAdoptedMembers(
        self: *const Restored,
        target: *world_mod.World,
    ) RelationValidationError!void {
        return self.validateAdoptedMembersResolved(target, null);
    }

    /// Validate the complete transport-level membership multiset after client
    /// adoption.  `resolver` is required for reusable-session siblings that are
    /// real members but intentionally are not the sole global nick lookup owner.
    pub fn validateAdoptedMembersResolved(
        self: *const Restored,
        target: *world_mod.World,
        resolver: ?NickResolver,
    ) RelationValidationError!void {
        var channels = target.checkpointChannelIterator();
        while (channels.next()) |channel| {
            var expected_count: usize = 0;
            for (self.member_expectations) |expected| {
                if (ciOrder(channel.name, expected.channel) == .eq) expected_count += 1;
            }
            if (channel.member_count != expected_count) return error.UnexpectedMember;

            var actual = target.checkpointMemberIdIterator(channel.name) orelse
                return error.MissingChannel;
            while (actual.next()) |member| {
                const identity = if (resolver) |r|
                    r.identity(member.client)
                else if (target.nickOf(member.client)) |nick|
                    MemberIdentity{ .join_key = @bitCast(member.client), .nick = nick }
                else
                    null;
                const resolved = identity orelse return error.MissingClient;
                var matched = false;
                var key_matched = false;
                var nick_matched = false;
                for (self.member_expectations) |expected| {
                    if (ciOrder(channel.name, expected.channel) != .eq or
                        resolved.join_key != expected.join_key) continue;
                    key_matched = true;
                    if (!std.mem.eql(u8, resolved.nick, expected.nick)) continue;
                    nick_matched = true;
                    if (member.modes.bits == expected.modes.bits) matched = true;
                }
                if (!matched)
                    return if (key_matched and nick_matched)
                        error.MemberModeMismatch
                    else
                        error.UnexpectedMember;
            }
        }
    }

    /// Apply pending invites only after complete member and invite-client
    /// validation. This may allocate in World; callers that already swapped the
    /// image can restore the displaced World on error for atomic publication.
    pub fn applyInvites(
        self: *const Restored,
        target: *world_mod.World,
    ) InviteApplyError!void {
        return self.applyInvitesResolved(target, null);
    }

    pub fn applyInvitesResolved(
        self: *const Restored,
        target: *world_mod.World,
        resolver: ?NickResolver,
    ) InviteApplyError!void {
        // Preflight all references before the first mutation.
        for (self.invite_expectations) |expected| {
            if (!target.channelExists(expected.channel)) return error.MissingChannel;
            const client = if (resolver) |r|
                r.clientForKey(expected.join_key) orelse return error.MissingClient
            else
                @as(world_mod.ClientId, @bitCast(expected.join_key));
            const identity = if (resolver) |r|
                r.identity(client)
            else if (target.nickOf(client)) |nick|
                MemberIdentity{ .join_key = expected.join_key, .nick = nick }
            else
                null;
            const actual = identity orelse return error.MissingClient;
            if (actual.join_key != expected.join_key or
                !std.mem.eql(u8, actual.nick, expected.nick))
                return error.MissingClient;
        }
        for (self.invite_expectations) |expected| {
            const client = if (resolver) |r|
                r.clientForKey(expected.join_key) orelse unreachable
            else
                @as(world_mod.ClientId, @bitCast(expected.join_key));
            target.addInvite(expected.channel, client) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.NoSuchChannel => return error.MissingChannel,
                else => unreachable,
            };
        }
    }

    pub fn deinit(self: *Restored) void {
        for (self.member_expectations[0..self.initialized_members]) |relation|
            self.allocator.free(relation.nick);
        for (self.invite_expectations[0..self.initialized_invites]) |relation|
            self.allocator.free(relation.nick);
        self.allocator.free(self.member_expectations);
        self.allocator.free(self.invite_expectations);
        self.world.deinit();
        self.* = undefined;
    }
};

pub fn isWorldCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

const MemberRow = struct {
    join_key: u64,
    nick: []const u8,
    modes: world_mod.MemberModes,
};

const InviteRow = struct {
    join_key: u64,
    nick: []const u8,
};

/// Encode one exact snapshot. The read lock spans collection and serialization,
/// so all borrowed channel/nick slices remain stable and one logical instant is
/// represented on the wire.
pub fn encode(allocator: std.mem.Allocator, world: *world_mod.World) Error![]u8 {
    world.lockRead();
    defer world.unlockRead();

    return encodeLocked(allocator, world);
}

/// Encode while the caller already holds World's read or write lock. Helix's
/// stable-seal path owns the write lock across every mandatory subsystem and
/// must use this entry point to avoid recursively acquiring the non-reentrant
/// lock. The caller must keep the lock held for the complete call.
pub fn encodeLocked(allocator: std.mem.Allocator, world: *world_mod.World) Error![]u8 {
    return encodeLockedResolved(allocator, world, null);
}

/// Server sealing variant that resolves every transport member through the
/// live ConnState table.  This preserves the exact multiplicity of a reusable
/// session whose sibling transports intentionally share one rendered nick.
pub fn encodeLockedResolved(
    allocator: std.mem.Allocator,
    world: *world_mod.World,
    resolver: ?NickResolver,
) Error![]u8 {
    const channel_count = world.channelCount();
    if (channel_count > max_channels) return error.CheckpointTooLarge;
    if (world.checkpointMaxListEntries() > max_list_entries) return error.CheckpointTooLarge;

    const channels = try allocator.alloc(world_mod.World.CheckpointChannelView, channel_count);
    defer allocator.free(channels);
    var channel_it = world.checkpointChannelIterator();
    var channel_index: usize = 0;
    while (channel_it.next()) |channel| : (channel_index += 1) {
        if (channel_index >= channels.len) return error.CountMismatch;
        channels[channel_index] = channel;
    }
    if (channel_index != channels.len) return error.CountMismatch;
    std.mem.sort(world_mod.World.CheckpointChannelView, channels, {}, channelLess);
    for (channels, 0..) |channel, i| {
        try validateChannelView(channel);
        if (i != 0) {
            const order = ciOrder(channels[i - 1].name, channel.name);
            if (order == .eq) return error.DuplicateChannel;
            if (order != .lt) return error.NonCanonicalOrder;
        }
    }

    const encoded_len = try encodedCheckpointLen(allocator, world, channels, resolver);

    var writer = Writer{ .allocator = allocator };
    errdefer writer.deinit();
    try writer.bytes.ensureTotalCapacityPrecise(allocator, encoded_len);
    try writer.writeBytes(&magic);
    try writer.writeU16(version);
    try writer.writeU16(0); // flags, reserved
    try writer.writeU32(0); // body length, patched below
    try writer.writeU32(@intCast(channel_count));
    try writer.writeU32(0); // total members, patched below
    try writer.writeU32(0); // total invites, patched below
    try writer.writeU32(world.checkpointNextOid());
    try writer.writeU32(@intCast(world.checkpointMaxListEntries()));
    try writer.writeI64(world.checkpointClockUnix());
    std.debug.assert(writer.bytes.items.len == header_len);

    var member_total: usize = 0;
    var invite_total: usize = 0;
    for (channels) |channel| {
        const row_len_offset = writer.bytes.items.len;
        try writer.writeU32(0);
        const row_start = writer.bytes.items.len;

        try writer.writeStr(channel.name);
        try writer.writeOptStr(channel.topic);
        try writer.writeOptStr(channel.topic_setter);
        try writer.writeI64(channel.topic_time);
        try writer.writeU16(channel.base_mode_bits);
        try writer.writeU32(channel.ext_mode_bits);
        try writer.writeBool(channel.private);
        try writer.writeBool(channel.hidden);
        try writer.writeOptStr(channel.key);
        try writer.writeOptU32(channel.limit);
        try writer.writeOptStr(channel.forward);
        try writer.writeU32(channel.oid);
        try writer.writeI64(channel.created_unix);
        try writer.writeU16(channel.throttle_joins);
        try writer.writeU32(channel.throttle_secs);
        if (channel.throttle_times.len > max_relations) return error.CheckpointTooLarge;
        try writer.writeU32(@intCast(channel.throttle_times.len));
        for (channel.throttle_times) |timestamp| try writer.writeI64(timestamp);
        try writer.writeI64(channel.throttle_alert_ms);

        try writeList(allocator, &writer, channel.bans);
        try writeList(allocator, &writer, channel.exempts);
        try writeList(allocator, &writer, channel.invex);
        try writeList(allocator, &writer, channel.mutes);

        const members = try collectMembers(allocator, world, channel, resolver);
        defer allocator.free(members);
        member_total = std.math.add(usize, member_total, members.len) catch
            return error.CheckpointTooLarge;
        if (member_total > max_relations or member_total > std.math.maxInt(u32))
            return error.CheckpointTooLarge;
        try writer.writeU32(@intCast(members.len));
        for (members) |member| {
            try writer.writeU64(member.join_key);
            try writer.writeStr(member.nick);
            try writer.writeByte(member.modes.bits);
        }

        const invites = try collectInvites(allocator, world, channel, resolver);
        defer allocator.free(invites);
        invite_total = std.math.add(usize, invite_total, invites.len) catch
            return error.CheckpointTooLarge;
        if (invite_total > max_relations or invite_total > std.math.maxInt(u32))
            return error.CheckpointTooLarge;
        try writer.writeU32(@intCast(invites.len));
        for (invites) |invite| {
            try writer.writeU64(invite.join_key);
            try writer.writeStr(invite.nick);
        }

        const row_len = writer.bytes.items.len - row_start;
        if (row_len > std.math.maxInt(u32)) return error.CheckpointTooLarge;
        writeU32At(writer.bytes.items[row_len_offset..][0..4], @intCast(row_len));
    }

    const body_len = writer.bytes.items.len - header_len;
    if (body_len > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    writeU32At(writer.bytes.items[8..12], @intCast(body_len));
    writeU32At(writer.bytes.items[16..20], @intCast(member_total));
    writeU32At(writer.bytes.items[20..24], @intCast(invite_total));
    var checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(writer.bytes.items, &checksum);
    try writer.writeBytes(&checksum);
    std.debug.assert(writer.bytes.items.len == encoded_len);
    return writer.bytes.toOwnedSlice(allocator);
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) Error!Restored {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (!isWorldCheckpoint(bytes)) return error.BadMagic;
    if (readU16At(bytes[4..6]) != version) return error.UnsupportedVersion;
    if (readU16At(bytes[6..8]) != 0) return error.InvalidField;

    const body_len: usize = readU32At(bytes[8..12]);
    const channel_count: usize = readU32At(bytes[12..16]);
    const member_count: usize = readU32At(bytes[16..20]);
    const invite_count: usize = readU32At(bytes[20..24]);
    const next_oid = readU32At(bytes[24..28]);
    const list_limit: usize = readU32At(bytes[28..32]);
    const clock_unix = readI64At(bytes[32..40]);
    if (channel_count > max_channels or member_count > max_relations or
        invite_count > max_relations or list_limit > max_list_entries)
        return error.CheckpointTooLarge;
    const prefix_len = std.math.add(usize, header_len, body_len) catch
        return error.CheckpointTooLarge;
    const expected_len = std.math.add(usize, prefix_len, checksum_len) catch
        return error.CheckpointTooLarge;
    if (expected_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (bytes.len < expected_len) return error.Truncated;
    if (bytes.len > expected_len) return error.TrailingBytes;
    var actual_checksum: [checksum_len]u8 = undefined;
    checkpointChecksum(bytes[0..prefix_len], &actual_checksum);
    const expected_checksum: [checksum_len]u8 = bytes[prefix_len..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, actual_checksum, expected_checksum))
        return error.ChecksumMismatch;

    const members = try allocator.alloc(MemberExpectation, member_count);
    var owns_members = true;
    errdefer if (owns_members) allocator.free(members);
    const invites = try allocator.alloc(InviteExpectation, invite_count);
    var owns_invites = true;
    errdefer if (owns_invites) allocator.free(invites);
    var restored = Restored{
        .allocator = allocator,
        .world = world_mod.World.init(allocator),
        .member_expectations = members,
        .invite_expectations = invites,
    };
    owns_members = false;
    owns_invites = false;
    errdefer restored.deinit();
    restored.world.initializeCheckpointImage(list_limit, next_oid, clock_unix) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidField,
    };

    var oids: std.AutoHashMapUnmanaged(u32, void) = .empty;
    defer oids.deinit(allocator);
    try oids.ensureTotalCapacity(allocator, @intCast(channel_count));
    var reader = Reader{ .bytes = bytes[header_len..prefix_len] };
    var previous_channel: ?[]const u8 = null;
    for (0..channel_count) |_| {
        const row_len: usize = try reader.readU32();
        if (row_len > reader.remaining()) return error.InvalidRecordLength;
        const row_bytes = try reader.readBytes(row_len);
        var row = Reader{ .bytes = row_bytes };
        const channel_name = try decodeChannel(allocator, &restored, &row, &oids);
        if (row.remaining() != 0) return error.InvalidRecordLength;
        if (previous_channel) |previous| {
            const order = ciOrder(previous, channel_name);
            if (order == .eq) return error.DuplicateChannel;
            if (order != .lt) return error.NonCanonicalOrder;
        }
        previous_channel = channel_name;
    }
    if (reader.remaining() != 0) return error.TrailingBytes;
    if (restored.initialized_members != member_count or
        restored.initialized_invites != invite_count)
        return error.CountMismatch;
    return restored;
}

fn decodeChannel(
    allocator: std.mem.Allocator,
    restored: *Restored,
    row: *Reader,
    oids: *std.AutoHashMapUnmanaged(u32, void),
) Error![]const u8 {
    const name = try row.readStr();
    if (!world_mod.isChannelName(name)) return error.InvalidChannelName;
    const topic = try row.readOptStr();
    const topic_setter = try row.readOptStr();
    const topic_time = try row.readI64();
    const base_mode_bits = try row.readU16();
    if ((base_mode_bits & ~@as(u16, 0x3fff)) != 0) return error.InvalidModeBits;
    const ext_mode_bits = try row.readU32();
    if ((ext_mode_bits & ~@as(u32, 0x007f_ffff)) != 0) return error.InvalidModeBits;
    const private = try row.readBool();
    const hidden = try row.readBool();
    const key = try row.readOptStr();
    const limit = try row.readOptU32();
    const forward = try row.readOptStr();
    const oid = try row.readU32();
    if (oid != 0) {
        const oid_entry = oids.getOrPut(allocator, oid) catch return error.OutOfMemory;
        if (oid_entry.found_existing) return error.DuplicateOid;
    }
    const created_unix = try row.readI64();
    const throttle_joins = try row.readU16();
    const throttle_secs = try row.readU32();
    const throttle_count: usize = try row.readU32();
    if (throttle_count > max_relations) return error.CheckpointTooLarge;
    const throttle_times = try allocator.alloc(i64, throttle_count);
    defer allocator.free(throttle_times);
    for (throttle_times) |*timestamp| timestamp.* = try row.readI64();
    const throttle_alert_ms = try row.readI64();

    const bans = try decodeList(allocator, row, restored.world.checkpointMaxListEntries());
    defer allocator.free(bans);
    const exempts = try decodeList(allocator, row, restored.world.checkpointMaxListEntries());
    defer allocator.free(exempts);
    const invex = try decodeList(allocator, row, restored.world.checkpointMaxListEntries());
    defer allocator.free(invex);
    const mutes = try decodeList(allocator, row, restored.world.checkpointMaxListEntries());
    defer allocator.free(mutes);

    const canonical_name = restored.world.restoreCheckpointChannel(.{
        .name = name,
        .topic = topic,
        .topic_setter = topic_setter,
        .topic_time = topic_time,
        .base_mode_bits = base_mode_bits,
        .ext_mode_bits = ext_mode_bits,
        .private = private,
        .hidden = hidden,
        .key = key,
        .limit = limit,
        .forward = forward,
        .oid = oid,
        .created_unix = created_unix,
        .bans = bans,
        .exempts = exempts,
        .invex = invex,
        .mutes = mutes,
        .throttle_joins = throttle_joins,
        .throttle_secs = throttle_secs,
        .throttle_times = throttle_times,
        .throttle_alert_ms = throttle_alert_ms,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.DuplicateChannel => return error.DuplicateChannel,
        error.InvalidChannelName => return error.InvalidChannelName,
        error.InvalidModeBits => return error.InvalidModeBits,
        error.ListFull => return error.ListFull,
        error.ActiveWorld => return error.InvalidField,
    };

    const member_count: usize = try row.readU32();
    if (member_count > restored.member_expectations.len - restored.initialized_members)
        return error.CountMismatch;
    var previous_member_key: ?u64 = null;
    for (0..member_count) |_| {
        const join_key = try row.readU64();
        const nick = try row.readStr();
        if (nick.len == 0) return error.InvalidField;
        const mode_bits = try row.readByte();
        if ((mode_bits & ~known_member_mode_mask) != 0) return error.InvalidModeBits;
        if (previous_member_key) |previous| {
            if (previous == join_key) return error.DuplicateMember;
            if (previous > join_key) return error.NonCanonicalOrder;
        }
        const owned_nick = try allocator.dupe(u8, nick);
        restored.member_expectations[restored.initialized_members] = .{
            .channel = canonical_name,
            .join_key = join_key,
            .nick = owned_nick,
            .modes = .{ .bits = mode_bits },
        };
        restored.initialized_members += 1;
        previous_member_key = join_key;
    }

    const invite_count: usize = try row.readU32();
    if (invite_count > restored.invite_expectations.len - restored.initialized_invites)
        return error.CountMismatch;
    var previous_invite_key: ?u64 = null;
    for (0..invite_count) |_| {
        const join_key = try row.readU64();
        const nick = try row.readStr();
        if (nick.len == 0) return error.InvalidField;
        if (previous_invite_key) |previous| {
            if (previous == join_key) return error.DuplicateInvite;
            if (previous > join_key) return error.NonCanonicalOrder;
        }
        const owned_nick = try allocator.dupe(u8, nick);
        restored.invite_expectations[restored.initialized_invites] = .{
            .channel = canonical_name,
            .join_key = join_key,
            .nick = owned_nick,
        };
        restored.initialized_invites += 1;
        previous_invite_key = join_key;
    }
    return canonical_name;
}

fn collectMembers(
    allocator: std.mem.Allocator,
    world: *world_mod.World,
    channel: world_mod.World.CheckpointChannelView,
    resolver: ?NickResolver,
) Error![]MemberRow {
    if (channel.member_count > max_relations) return error.CheckpointTooLarge;
    const rows = try allocator.alloc(MemberRow, channel.member_count);
    errdefer allocator.free(rows);
    var it = world.checkpointMemberIdIterator(channel.name) orelse return error.CountMismatch;
    var index: usize = 0;
    while (it.next()) |member| : (index += 1) {
        if (index >= rows.len) return error.CountMismatch;
        const identity = if (resolver) |r|
            r.identity(member.client)
        else if (world.nickOf(member.client)) |nick|
            MemberIdentity{ .join_key = @bitCast(member.client), .nick = nick }
        else
            null;
        const resolved = identity orelse return error.MissingClientNick;
        if (resolved.nick.len == 0) return error.InvalidField;
        if ((member.modes.bits & ~known_member_mode_mask) != 0) return error.InvalidModeBits;
        rows[index] = .{ .join_key = resolved.join_key, .nick = resolved.nick, .modes = member.modes };
    }
    if (index != rows.len) return error.CountMismatch;
    std.mem.sort(MemberRow, rows, {}, memberLess);
    if (rows.len > 1) {
        for (rows[1..], rows[0 .. rows.len - 1]) |current, previous| {
            if (previous.join_key == current.join_key) return error.DuplicateMember;
        }
    }
    return rows;
}

fn collectInvites(
    allocator: std.mem.Allocator,
    world: *world_mod.World,
    channel: world_mod.World.CheckpointChannelView,
    resolver: ?NickResolver,
) Error![]InviteRow {
    if (channel.invite_count > max_relations) return error.CheckpointTooLarge;
    const rows = try allocator.alloc(InviteRow, channel.invite_count);
    errdefer allocator.free(rows);
    var it = world.checkpointInviteIdIterator(channel.name) orelse return error.CountMismatch;
    var index: usize = 0;
    while (it.next()) |client| : (index += 1) {
        if (index >= rows.len) return error.CountMismatch;
        const identity = if (resolver) |r|
            r.identity(client)
        else if (world.nickOf(client)) |nick|
            MemberIdentity{ .join_key = @bitCast(client), .nick = nick }
        else
            null;
        const resolved = identity orelse return error.MissingClientNick;
        if (resolved.nick.len == 0) return error.InvalidField;
        rows[index] = .{ .join_key = resolved.join_key, .nick = resolved.nick };
    }
    if (index != rows.len) return error.CountMismatch;
    std.mem.sort(InviteRow, rows, {}, inviteLess);
    if (rows.len > 1) {
        for (rows[1..], rows[0 .. rows.len - 1]) |current, previous| {
            if (previous.join_key == current.join_key) return error.DuplicateInvite;
        }
    }
    return rows;
}

fn writeList(
    allocator: std.mem.Allocator,
    writer: *Writer,
    source: []const world_mod.ListEntry,
) Error!void {
    if (source.len > max_list_entries) return error.CheckpointTooLarge;
    const ordered = try allocator.alloc(*const world_mod.ListEntry, source.len);
    defer allocator.free(ordered);
    for (source, ordered) |*entry, *slot| slot.* = entry;
    std.mem.sort(*const world_mod.ListEntry, ordered, {}, listLess);
    if (ordered.len > 1) {
        for (ordered[1..], ordered[0 .. ordered.len - 1]) |current, previous| {
            if (std.mem.eql(u8, previous.mask, current.mask)) return error.DuplicateListEntry;
        }
    }
    try writer.writeU32(@intCast(ordered.len));
    for (ordered) |entry| {
        try writer.writeStr(entry.mask);
        try writer.writeStr(entry.setter);
        try writer.writeI64(entry.set_at);
    }
}

fn decodeList(
    allocator: std.mem.Allocator,
    reader: *Reader,
    configured_limit: usize,
) Error![]world_mod.World.CheckpointListEntry {
    const count: usize = try reader.readU32();
    if (count > configured_limit or count > max_list_entries) return error.ListFull;
    const entries = try allocator.alloc(world_mod.World.CheckpointListEntry, count);
    errdefer allocator.free(entries);
    var previous: ?world_mod.World.CheckpointListEntry = null;
    for (entries) |*entry| {
        entry.* = .{
            .mask = try reader.readStr(),
            .setter = try reader.readStr(),
            .set_at = try reader.readI64(),
        };
        if (previous) |prior| {
            if (std.mem.eql(u8, prior.mask, entry.mask)) return error.DuplicateListEntry;
            if (!listValueLess({}, prior, entry.*)) return error.NonCanonicalOrder;
        }
        previous = entry.*;
    }
    return entries;
}

fn validateChannelView(channel: world_mod.World.CheckpointChannelView) Error!void {
    if (!world_mod.isChannelName(channel.name)) return error.InvalidChannelName;
    if ((channel.base_mode_bits & ~@as(u16, 0x3fff)) != 0 or
        (channel.ext_mode_bits & ~@as(u32, 0x007f_ffff)) != 0)
        return error.InvalidModeBits;
    if (channel.bans.len > max_list_entries or channel.exempts.len > max_list_entries or
        channel.invex.len > max_list_entries or channel.mutes.len > max_list_entries)
        return error.CheckpointTooLarge;
    const strings = [_]?[]const u8{
        channel.name,
        channel.topic,
        channel.topic_setter,
        channel.key,
        channel.forward,
    };
    for (strings) |maybe| if (maybe) |value| {
        if (value.len > max_string_bytes) return error.CheckpointTooLarge;
    };
}

fn encodedCheckpointLen(
    allocator: std.mem.Allocator,
    world: *world_mod.World,
    channels: []const world_mod.World.CheckpointChannelView,
    resolver: ?NickResolver,
) Error!usize {
    var total: usize = header_len + checksum_len;
    for (channels) |channel| {
        try addEncodedLen(&total, 4); // row length
        try addStrLen(&total, channel.name);
        try addOptStrLen(&total, channel.topic);
        try addOptStrLen(&total, channel.topic_setter);
        // topic time, base/ext modes, private/hidden
        try addEncodedLen(&total, 8 + 2 + 4 + 1 + 1);
        try addOptStrLen(&total, channel.key);
        try addEncodedLen(&total, 1 + if (channel.limit != null) @as(usize, 4) else 0);
        try addOptStrLen(&total, channel.forward);
        // OID, creation, throttle config/count/timestamps/alert.
        try addEncodedLen(&total, 4 + 8 + 2 + 4 + 4);
        try addEncodedLen(&total, std.math.mul(usize, channel.throttle_times.len, 8) catch
            return error.CheckpointTooLarge);
        try addEncodedLen(&total, 8);
        try addListLen(&total, channel.bans);
        try addListLen(&total, channel.exempts);
        try addListLen(&total, channel.invex);
        try addListLen(&total, channel.mutes);

        try addEncodedLen(&total, 4); // member count
        const members = try collectMembers(allocator, world, channel, resolver);
        defer allocator.free(members);
        for (members) |member| {
            try addEncodedLen(&total, 8);
            try addStrLen(&total, member.nick);
            try addEncodedLen(&total, 1);
        }
        try addEncodedLen(&total, 4); // invite count
        const invites = try collectInvites(allocator, world, channel, resolver);
        defer allocator.free(invites);
        for (invites) |invite| {
            try addEncodedLen(&total, 8);
            try addStrLen(&total, invite.nick);
        }
    }
    if (total > max_checkpoint_bytes) return error.CheckpointTooLarge;
    return total;
}

fn addListLen(total: *usize, entries: []const world_mod.ListEntry) Error!void {
    try addEncodedLen(total, 4);
    for (entries) |entry| {
        try addStrLen(total, entry.mask);
        try addStrLen(total, entry.setter);
        try addEncodedLen(total, 8);
    }
}

fn addOptStrLen(total: *usize, value: ?[]const u8) Error!void {
    try addEncodedLen(total, 1);
    if (value) |present| try addStrLen(total, present);
}

fn addStrLen(total: *usize, value: []const u8) Error!void {
    if (value.len > max_string_bytes or value.len > std.math.maxInt(u32))
        return error.CheckpointTooLarge;
    try addEncodedLen(total, 4);
    try addEncodedLen(total, value.len);
}

fn addEncodedLen(total: *usize, amount: usize) Error!void {
    total.* = std.math.add(usize, total.*, amount) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

const Writer = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *Writer) void {
        self.bytes.deinit(self.allocator);
    }

    fn writeBytes(self: *Writer, value: []const u8) Error!void {
        const new_len = std.math.add(usize, self.bytes.items.len, value.len) catch
            return error.CheckpointTooLarge;
        if (new_len > max_checkpoint_bytes) return error.CheckpointTooLarge;
        try self.bytes.appendSlice(self.allocator, value);
    }

    fn writeByte(self: *Writer, value: u8) Error!void {
        try self.writeBytes(&.{value});
    }

    fn writeBool(self: *Writer, value: bool) Error!void {
        try self.writeByte(@intFromBool(value));
    }

    fn writeU16(self: *Writer, value: u16) Error!void {
        var buffer: [2]u8 = undefined;
        std.mem.writeInt(u16, &buffer, value, .big);
        try self.writeBytes(&buffer);
    }

    fn writeU32(self: *Writer, value: u32) Error!void {
        var buffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &buffer, value, .big);
        try self.writeBytes(&buffer);
    }

    fn writeU64(self: *Writer, value: u64) Error!void {
        var buffer: [8]u8 = undefined;
        std.mem.writeInt(u64, &buffer, value, .big);
        try self.writeBytes(&buffer);
    }

    fn writeI64(self: *Writer, value: i64) Error!void {
        var buffer: [8]u8 = undefined;
        std.mem.writeInt(i64, &buffer, value, .big);
        try self.writeBytes(&buffer);
    }

    fn writeStr(self: *Writer, value: []const u8) Error!void {
        if (value.len > max_string_bytes or value.len > std.math.maxInt(u32))
            return error.CheckpointTooLarge;
        try self.writeU32(@intCast(value.len));
        try self.writeBytes(value);
    }

    fn writeOptStr(self: *Writer, value: ?[]const u8) Error!void {
        if (value) |present| {
            try self.writeByte(1);
            try self.writeStr(present);
        } else try self.writeByte(0);
    }

    fn writeOptU32(self: *Writer, value: ?u32) Error!void {
        if (value) |present| {
            try self.writeByte(1);
            try self.writeU32(present);
        } else try self.writeByte(0);
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: Reader) usize {
        return self.bytes.len - self.pos;
    }

    fn readBytes(self: *Reader, count: usize) Error![]const u8 {
        if (count > self.remaining()) return error.Truncated;
        const out = self.bytes[self.pos..][0..count];
        self.pos += count;
        return out;
    }

    fn readByte(self: *Reader) Error!u8 {
        return (try self.readBytes(1))[0];
    }

    fn readBool(self: *Reader) Error!bool {
        return switch (try self.readByte()) {
            0 => false,
            1 => true,
            else => error.InvalidField,
        };
    }

    fn readU16(self: *Reader) Error!u16 {
        const value = try self.readBytes(2);
        return readU16At(value[0..][0..2]);
    }

    fn readU32(self: *Reader) Error!u32 {
        const value = try self.readBytes(4);
        return readU32At(value[0..][0..4]);
    }

    fn readU64(self: *Reader) Error!u64 {
        const bytes = try self.readBytes(8);
        return std.mem.readInt(u64, bytes[0..8], .big);
    }

    fn readI64(self: *Reader) Error!i64 {
        const value = try self.readBytes(8);
        return readI64At(value[0..][0..8]);
    }

    fn readStr(self: *Reader) Error![]const u8 {
        const len: usize = try self.readU32();
        if (len > max_string_bytes) return error.CheckpointTooLarge;
        return self.readBytes(len);
    }

    fn readOptStr(self: *Reader) Error!?[]const u8 {
        return switch (try self.readByte()) {
            0 => null,
            1 => try self.readStr(),
            else => error.InvalidField,
        };
    }

    fn readOptU32(self: *Reader) Error!?u32 {
        return switch (try self.readByte()) {
            0 => null,
            1 => try self.readU32(),
            else => error.InvalidField,
        };
    }
};

fn channelLess(_: void, a: world_mod.World.CheckpointChannelView, b: world_mod.World.CheckpointChannelView) bool {
    return ciOrder(a.name, b.name) == .lt;
}

fn memberLess(_: void, a: MemberRow, b: MemberRow) bool {
    return a.join_key < b.join_key;
}

fn inviteLess(_: void, a: InviteRow, b: InviteRow) bool {
    return a.join_key < b.join_key;
}

fn nickLess(_: void, a: []const u8, b: []const u8) bool {
    return ciOrder(a, b) == .lt;
}

fn listLess(_: void, a: *const world_mod.ListEntry, b: *const world_mod.ListEntry) bool {
    return listValueLess({}, .{ .mask = a.mask, .setter = a.setter, .set_at = a.set_at }, .{
        .mask = b.mask,
        .setter = b.setter,
        .set_at = b.set_at,
    });
}

fn listValueLess(
    _: void,
    a: world_mod.World.CheckpointListEntry,
    b: world_mod.World.CheckpointListEntry,
) bool {
    const mask_order = std.mem.order(u8, a.mask, b.mask);
    if (mask_order != .eq) return mask_order == .lt;
    const setter_order = std.mem.order(u8, a.setter, b.setter);
    if (setter_order != .eq) return setter_order == .lt;
    return a.set_at < b.set_at;
}

fn ciOrder(a: []const u8, b: []const u8) std.math.Order {
    const common = @min(a.len, b.len);
    for (a[0..common], b[0..common]) |left, right| {
        const folded_left = std.ascii.toLower(left);
        const folded_right = std.ascii.toLower(right);
        if (folded_left < folded_right) return .lt;
        if (folded_left > folded_right) return .gt;
    }
    if (a.len < b.len) return .lt;
    if (a.len > b.len) return .gt;
    return .eq;
}

fn writeU32At(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

fn readU16At(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .big);
}

fn readU32At(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

fn readI64At(bytes: *const [8]u8) i64 {
    return std.mem.readInt(i64, bytes, .big);
}

fn checkpointChecksum(bytes: []const u8, out: *[checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(checksum_domain);
    hasher.update(bytes);
    hasher.final(out);
}

const testing = std.testing;
const chanmode_ext = @import("../../proto/chanmode_ext.zig");

fn testClient(slot: u20) world_mod.ClientId {
    return .{ .shard = 0, .slot = slot, .gen = 1 };
}

const TestRelationResolver = struct {
    const Pair = struct { key: u64, client: world_mod.ClientId, nick: []const u8 };
    world: *world_mod.World,
    pairs: []const Pair,

    fn resolve(context: *anyopaque, client: world_mod.ClientId) ?MemberIdentity {
        const self: *@This() = @ptrCast(@alignCast(context));
        for (self.pairs) |pair| {
            if (!pair.client.eql(client)) continue;
            return .{ .join_key = pair.key, .nick = pair.nick };
        }
        return null;
    }

    fn lookup(context: *anyopaque, key: u64) ?world_mod.ClientId {
        const self: *@This() = @ptrCast(@alignCast(context));
        for (self.pairs) |pair| if (pair.key == key) return pair.client;
        return null;
    }

    fn resolver(self: *@This()) NickResolver {
        return .{ .context = self, .resolve = resolve, .lookup = lookup };
    }
};

fn populateRichWorld(world: *world_mod.World) !void {
    try world.initializeCheckpointImage(8, 101, 1_700_000_000);
    const alice = testClient(1);
    const bob = testClient(2);
    try world.registerNick("Alice", alice);
    try world.registerNick("bob", bob);
    try world.restoreMember("#Rich", bob, world_mod.MemberModes.fromModes(&.{ .op, .voice }));
    try world.restoreMember("#Rich", alice, world_mod.MemberModes.fromModes(&.{.founder}));

    const base_flags = [_]world_mod.ChannelMode{
        .invite_only,
        .moderated,
        .no_external,
        .topic_ops,
        .secret,
        .no_ctcp,
        .no_notice,
        .no_nick,
        .free_invite,
        .tls_only,
        .mod_reg,
        .news_wire,
        .oper_only,
        .admin_only,
    };
    for (base_flags) |flag| _ = try world.setChannelFlag("#Rich", flag, true);
    inline for (std.meta.tags(chanmode_ext.ExtChannelFlag)) |flag|
        _ = try world.setChannelExtFlag("#Rich", flag, true);
    _ = try world.setPrivate("#Rich", true);
    _ = try world.setHidden("#Rich", true);
    try world.setTopic("#Rich", "portable topic", "Alice!u@host", 1_700_000_123);
    try world.setChannelKey("#Rich", "sekret");
    try world.setChannelLimit("#Rich", 42);
    try world.setForward("#Rich", "#Overflow");
    _ = try world.addBan("#Rich", "z!*@*", "setter-z", 9);
    _ = try world.addBan("#Rich", "a!*@*", "setter-a", 1);
    _ = try world.addExempt("#Rich", "friend!*@*", "setter-e", 2);
    _ = try world.addInvex("#Rich", "vip!*@*", "setter-i", 3);
    _ = try world.addMute("#Rich", "loud!*@*", "setter-m", 4);
    try world.setThrottle("#Rich", 2, 10);
    try testing.expectEqual(world_mod.World.ThrottleResult.admitted, world.throttleAdmit("#Rich", 1000, 0, 0));
    try testing.expectEqual(world_mod.World.ThrottleResult.admitted, world.throttleAdmit("#Rich", 2000, 0, 0));
    try testing.expectEqual(world_mod.World.ThrottleResult.throttled_alert, world.throttleAdmit("#Rich", 3000, 0, 0));
    try world.addInvite("#Rich", bob);

    // A registered empty channel is an entity in its own right and must not be
    // reconstructed indirectly from client membership.
    _ = try world.markRegistered("#Empty", true);
}

fn findCheckpointChannel(
    world: *world_mod.World,
    name: []const u8,
) ?world_mod.World.CheckpointChannelView {
    var it = world.checkpointChannelIterator();
    while (it.next()) |channel| {
        if (std.ascii.eqlIgnoreCase(channel.name, name)) return channel;
    }
    return null;
}

test "World v2 checkpoint round trips every channel field and nick relation" {
    var source = world_mod.World.init(testing.allocator);
    defer source.deinit();
    try populateRichWorld(&source);

    const wire = try encode(testing.allocator, &source);
    defer testing.allocator.free(wire);
    var restored = try decode(testing.allocator, wire);
    defer restored.deinit();

    try testing.expectEqual(@as(usize, 2), restored.world.channelCount());
    try testing.expectEqual(@as(u32, 103), restored.world.checkpointNextOid());
    try testing.expectEqual(@as(i64, 1_700_000_000), restored.world.checkpointClockUnix());
    try testing.expectEqual(@as(usize, 8), restored.world.checkpointMaxListEntries());
    try testing.expect(restored.world.channelHasExtFlag("#empty", .registered));
    try testing.expectEqual(@as(usize, 0), findCheckpointChannel(&restored.world, "#empty").?.member_count);

    const rich = findCheckpointChannel(&restored.world, "#rich").?;
    try testing.expectEqualStrings("portable topic", rich.topic.?);
    try testing.expectEqualStrings("Alice!u@host", rich.topic_setter.?);
    try testing.expectEqual(@as(i64, 1_700_000_123), rich.topic_time);
    try testing.expectEqual(@as(u16, 0x3fff), rich.base_mode_bits);
    try testing.expectEqual(@as(u32, 0x007f_ffff), rich.ext_mode_bits);
    try testing.expect(rich.private and rich.hidden);
    try testing.expectEqualStrings("sekret", rich.key.?);
    try testing.expectEqual(@as(?u32, 42), rich.limit);
    try testing.expectEqualStrings("#Overflow", rich.forward.?);
    try testing.expectEqual(@as(u32, 101), rich.oid);
    try testing.expectEqual(@as(i64, 1_700_000_000), rich.created_unix);
    try testing.expectEqual(@as(usize, 2), rich.bans.len);
    try testing.expectEqualStrings("a!*@*", rich.bans[0].mask);
    try testing.expectEqualStrings("z!*@*", rich.bans[1].mask);
    try testing.expectEqualStrings("friend!*@*", rich.exempts[0].mask);
    try testing.expectEqualStrings("vip!*@*", rich.invex[0].mask);
    try testing.expectEqualStrings("loud!*@*", rich.mutes[0].mask);
    try testing.expectEqual(@as(u16, 2), rich.throttle_joins);
    try testing.expectEqual(@as(u32, 10), rich.throttle_secs);
    try testing.expectEqualSlices(i64, &.{ 1000, 2000 }, rich.throttle_times);
    try testing.expectEqual(@as(i64, 3000), rich.throttle_alert_ms);
    // ClientIds are intentionally absent from the detached World.
    try testing.expectEqual(@as(usize, 0), rich.member_count);
    try testing.expectEqual(@as(usize, 0), rich.invite_count);

    try testing.expectEqual(@as(usize, 2), restored.member_expectations.len);
    try testing.expectEqualStrings("Alice", restored.member_expectations[0].nick);
    try testing.expectEqual(world_mod.MemberModes.fromModes(&.{.founder}).bits, restored.member_expectations[0].modes.bits);
    try testing.expectEqualStrings("bob", restored.member_expectations[1].nick);
    try testing.expectEqual(world_mod.MemberModes.fromModes(&.{ .op, .voice }).bits, restored.member_expectations[1].modes.bits);
    try testing.expectEqual(@as(usize, 1), restored.invite_expectations.len);
    try testing.expectEqualStrings("bob", restored.invite_expectations[0].nick);
    try testing.expectEqualStrings("#Rich", restored.invite_expectations[0].channel);

    const valid_projection = [_]MemberProjection{
        .{ .channel = "#rich", .join_key = @bitCast(testClient(2)), .nick = "bob", .modes = world_mod.MemberModes.fromModes(&.{ .op, .voice }) },
        .{ .channel = "#RICH", .join_key = @bitCast(testClient(1)), .nick = "Alice", .modes = world_mod.MemberModes.fromModes(&.{.founder}) },
    };
    try restored.validateMemberProjection(&valid_projection);
    try restored.validateInviteProjection(&.{
        .{ .join_key = @bitCast(testClient(1)), .nick = "Alice" },
        .{ .join_key = @bitCast(testClient(2)), .nick = "bob" },
    });
    try testing.expectError(
        error.RelationCountMismatch,
        restored.validateMemberProjection(valid_projection[0..1]),
    );
    var wrong_mode = valid_projection;
    wrong_mode[0].modes = world_mod.MemberModes.empty();
    try testing.expectError(
        error.MemberModeMismatch,
        restored.validateMemberProjection(&wrong_mode),
    );
    const duplicate_projection = [_]MemberProjection{
        valid_projection[0],
        valid_projection[0],
    };
    try testing.expectError(
        error.DuplicateProjection,
        restored.validateMemberProjection(&duplicate_projection),
    );
}

test "World v2 fd relations preserve same-nick physical members and invites" {
    var source = world_mod.World.init(testing.allocator);
    defer source.deinit();
    const first = testClient(20);
    const second = testClient(21);
    try source.registerNick("Shared", first);
    try source.restoreMember("#shared", first, world_mod.MemberModes.fromModes(&.{.op}));
    try source.restoreMember("#shared", second, world_mod.MemberModes.fromModes(&.{.op}));
    try source.addInvite("#shared", first);
    try source.addInvite("#shared", second);
    const source_pairs = [_]TestRelationResolver.Pair{
        .{ .key = 100, .client = first, .nick = "Shared" },
        .{ .key = 101, .client = second, .nick = "Shared" },
    };
    const duplicate_pairs = [_]TestRelationResolver.Pair{
        .{ .key = 100, .client = first, .nick = "Shared" },
        .{ .key = 100, .client = second, .nick = "Shared" },
    };
    var duplicate_resolver = TestRelationResolver{ .world = &source, .pairs = &duplicate_pairs };
    source.lockRead();
    try testing.expectError(
        error.DuplicateMember,
        encodeLockedResolved(testing.allocator, &source, duplicate_resolver.resolver()),
    );
    source.unlockRead();
    var missing_resolver = TestRelationResolver{ .world = &source, .pairs = source_pairs[0..1] };
    source.lockRead();
    try testing.expectError(
        error.MissingClientNick,
        encodeLockedResolved(testing.allocator, &source, missing_resolver.resolver()),
    );
    source.unlockRead();
    var source_resolver = TestRelationResolver{ .world = &source, .pairs = &source_pairs };
    source.lockRead();
    const wire = encodeLockedResolved(testing.allocator, &source, source_resolver.resolver()) catch |err| {
        source.unlockRead();
        return err;
    };
    source.unlockRead();
    defer testing.allocator.free(wire);

    var restored = try decode(testing.allocator, wire);
    defer restored.deinit();
    try testing.expectEqual(@as(usize, 2), restored.member_expectations.len);
    try testing.expectEqual(@as(usize, 2), restored.invite_expectations.len);
    try testing.expectEqualStrings("Shared", restored.member_expectations[0].nick);
    try testing.expectEqualStrings("Shared", restored.member_expectations[1].nick);
    try restored.validateMemberProjection(&.{
        .{ .channel = "#shared", .join_key = 101, .nick = "Shared", .modes = world_mod.MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#SHARED", .join_key = 100, .nick = "Shared", .modes = world_mod.MemberModes.fromModes(&.{.op}) },
    });
    try testing.expectError(error.UnexpectedMember, restored.validateMemberProjection(&.{
        .{ .channel = "#shared", .join_key = 101, .nick = "shared", .modes = world_mod.MemberModes.fromModes(&.{.op}) },
        .{ .channel = "#SHARED", .join_key = 100, .nick = "Shared", .modes = world_mod.MemberModes.fromModes(&.{.op}) },
    }));
    try restored.validateInviteProjection(&.{
        .{ .join_key = 100, .nick = "Shared" },
        .{ .join_key = 101, .nick = "Shared" },
    });
    try testing.expectError(error.UnexpectedMember, restored.validateInviteProjection(&.{
        .{ .join_key = 100, .nick = "Shared" },
        .{ .join_key = 101, .nick = "shared" },
    }));
    try testing.expectError(error.MissingClient, restored.validateInviteProjection(&.{
        .{ .join_key = 100, .nick = "Shared" },
    }));
    try testing.expectError(error.DuplicateProjection, restored.validateInviteProjection(&.{
        .{ .join_key = 100, .nick = "Shared" },
        .{ .join_key = 100, .nick = "Shared" },
    }));

    var target = world_mod.World.init(testing.allocator);
    defer target.deinit();
    restored.swapWorldInto(&target);
    const successor_first = testClient(30);
    const successor_second = testClient(31);
    try target.registerNick("Shared", successor_first);
    try target.restoreMember("#shared", successor_first, world_mod.MemberModes.fromModes(&.{.op}));
    try target.restoreMember("#shared", successor_second, world_mod.MemberModes.fromModes(&.{.op}));
    const target_pairs = [_]TestRelationResolver.Pair{
        .{ .key = 100, .client = successor_first, .nick = "Shared" },
        .{ .key = 101, .client = successor_second, .nick = "Shared" },
    };
    const missing_target_pairs = target_pairs[0..1];
    var missing_target_resolver = TestRelationResolver{ .world = &target, .pairs = missing_target_pairs };
    try testing.expectError(
        error.MissingClient,
        restored.validateAdoptedMembersResolved(&target, missing_target_resolver.resolver()),
    );
    try testing.expectError(
        error.MissingClient,
        restored.applyInvitesResolved(&target, missing_target_resolver.resolver()),
    );
    try testing.expect(!target.hasInvite("#shared", successor_first));
    try testing.expect(!target.hasInvite("#shared", successor_second));

    const case_only_target_pairs = [_]TestRelationResolver.Pair{
        .{ .key = 100, .client = successor_first, .nick = "Shared" },
        .{ .key = 101, .client = successor_second, .nick = "shared" },
    };
    var case_only_target_resolver = TestRelationResolver{ .world = &target, .pairs = &case_only_target_pairs };
    try testing.expectError(
        error.UnexpectedMember,
        restored.validateAdoptedMembersResolved(&target, case_only_target_resolver.resolver()),
    );
    try testing.expectError(
        error.MissingClient,
        restored.applyInvitesResolved(&target, case_only_target_resolver.resolver()),
    );
    try testing.expect(!target.hasInvite("#shared", successor_first));
    try testing.expect(!target.hasInvite("#shared", successor_second));

    var target_resolver = TestRelationResolver{ .world = &target, .pairs = &target_pairs };
    try restored.validateAdoptedMembersResolved(&target, target_resolver.resolver());
    try restored.applyInvitesResolved(&target, target_resolver.resolver());
    try testing.expect(target.hasInvite("#shared", successor_first));
    try testing.expect(target.hasInvite("#shared", successor_second));
}

fn populateDeterministicWorld(world: *world_mod.World, reverse: bool) !void {
    try world.initializeCheckpointImage(4, 50, 77);
    const rows = [_]world_mod.World.CheckpointChannelState{
        .{
            .name = "#alpha",
            .topic = null,
            .topic_setter = null,
            .topic_time = 0,
            .base_mode_bits = 0,
            .ext_mode_bits = 0,
            .private = false,
            .hidden = false,
            .key = null,
            .limit = null,
            .forward = null,
            .oid = 10,
            .created_unix = 1,
            .bans = &.{},
            .exempts = &.{},
            .invex = &.{},
            .mutes = &.{},
            .throttle_joins = 0,
            .throttle_secs = 0,
            .throttle_times = &.{},
            .throttle_alert_ms = 0,
        },
        .{
            .name = "#bravo",
            .topic = "topic",
            .topic_setter = "setter",
            .topic_time = 2,
            .base_mode_bits = 3,
            .ext_mode_bits = 5,
            .private = true,
            .hidden = false,
            .key = null,
            .limit = 9,
            .forward = null,
            .oid = 11,
            .created_unix = 2,
            .bans = &.{},
            .exempts = &.{},
            .invex = &.{},
            .mutes = &.{},
            .throttle_joins = 0,
            .throttle_secs = 0,
            .throttle_times = &.{},
            .throttle_alert_ms = 0,
        },
    };
    if (reverse) {
        _ = try world.restoreCheckpointChannel(rows[1]);
        _ = try world.restoreCheckpointChannel(rows[0]);
    } else {
        _ = try world.restoreCheckpointChannel(rows[0]);
        _ = try world.restoreCheckpointChannel(rows[1]);
    }
    const aa = testClient(10);
    const zz = testClient(11);
    if (reverse) {
        try world.registerNick("zz", zz);
        try world.registerNick("aa", aa);
        try world.restoreMember("#alpha", zz, world_mod.MemberModes.fromModes(&.{.voice}));
        try world.restoreMember("#alpha", aa, world_mod.MemberModes.fromModes(&.{.op}));
        try world.addInvite("#bravo", zz);
        try world.addInvite("#bravo", aa);
    } else {
        try world.registerNick("aa", aa);
        try world.registerNick("zz", zz);
        try world.restoreMember("#alpha", aa, world_mod.MemberModes.fromModes(&.{.op}));
        try world.restoreMember("#alpha", zz, world_mod.MemberModes.fromModes(&.{.voice}));
        try world.addInvite("#bravo", aa);
        try world.addInvite("#bravo", zz);
    }
}

test "World v2 checkpoint is deterministic across map insertion order" {
    var first = world_mod.World.init(testing.allocator);
    defer first.deinit();
    var second = world_mod.World.init(testing.allocator);
    defer second.deinit();
    try populateDeterministicWorld(&first, false);
    try populateDeterministicWorld(&second, true);
    const a = try encode(testing.allocator, &first);
    defer testing.allocator.free(a);
    const b = try encode(testing.allocator, &second);
    defer testing.allocator.free(b);
    try testing.expectEqualSlices(u8, a, b);
}

fn rechecksum(bytes: []u8) void {
    const body_end = bytes.len - checksum_len;
    checkpointChecksum(bytes[0..body_end], bytes[body_end..][0..checksum_len]);
}

test "World v2 checkpoint rejects corruption duplicates truncation and trailing bytes" {
    var source = world_mod.World.init(testing.allocator);
    defer source.deinit();
    try populateDeterministicWorld(&source, false);
    const wire = try encode(testing.allocator, &source);
    defer testing.allocator.free(wire);

    for (0..wire.len) |prefix_len| {
        if (decode(testing.allocator, wire[0..prefix_len])) |unexpected_value| {
            var unexpected = unexpected_value;
            unexpected.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }

    const corrupt = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(corrupt);
    corrupt[header_len + 8] ^= 0x01;
    try testing.expectError(error.ChecksumMismatch, decode(testing.allocator, corrupt));

    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.TrailingBytes, decode(testing.allocator, trailing));

    // Both deterministic test channel names are six bytes. Replace #bravo with
    // #alpha and recompute the outer checksum: semantic duplicate validation,
    // not the checksum, must reject the forged image.
    const duplicate = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(duplicate);
    var body = Reader{ .bytes = duplicate[header_len .. duplicate.len - checksum_len] };
    const first_len: usize = try body.readU32();
    _ = try body.readBytes(first_len);
    const second_len: usize = try body.readU32();
    _ = second_len;
    const name_len = try body.readU32();
    try testing.expectEqual(@as(u32, 6), name_len);
    @memcpy(@constCast((try body.readBytes(name_len))), "#alpha");
    rechecksum(duplicate);
    try testing.expectError(error.DuplicateChannel, decode(testing.allocator, duplicate));
}

test "World v2 checkpoint fails closed when a member or invite has no nick" {
    var source = world_mod.World.init(testing.allocator);
    defer source.deinit();
    const orphan = testClient(99);
    try source.restoreMember("#orphan", orphan, world_mod.MemberModes.empty());
    try testing.expectError(error.MissingClientNick, encode(testing.allocator, &source));
}

test "World v2 checkpoint encode and atomic decode survive every allocation failure" {
    var source = world_mod.World.init(testing.allocator);
    defer source.deinit();
    try populateRichWorld(&source);

    const EncodeSweep = struct {
        fn run(allocator: std.mem.Allocator, world: *world_mod.World) !void {
            const bytes = try encode(allocator, world);
            defer allocator.free(bytes);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, EncodeSweep.run, .{&source});

    const wire = try encode(testing.allocator, &source);
    defer testing.allocator.free(wire);
    const DecodeSweep = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var restored = try decode(allocator, bytes);
            defer restored.deinit();
            try testing.expectEqual(@as(usize, 2), restored.world.channelCount());
            try testing.expectEqual(@as(usize, 2), restored.member_expectations.len);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, DecodeSweep.run, .{wire});

    var target = world_mod.World.init(testing.allocator);
    defer target.deinit();
    const keeper = testClient(55);
    try target.registerNick("keeper", keeper);
    _ = try target.join("#old", keeper);
    var restored = try decode(testing.allocator, wire);
    defer restored.deinit();
    restored.swapWorldInto(&target);
    try testing.expect(target.channelExists("#Rich"));
    try testing.expect(!target.channelExists("#old"));
    try testing.expect(restored.world.channelExists("#old"));

    // Successor ClientIds are different from predecessor ids. The rebuilt RCU
    // mirrors accept exact relation application immediately after nick adoption.
    const successor_alice = testClient(70);
    const successor_bob = testClient(71);
    try target.registerNick("Alice", successor_alice);
    try target.registerNick("bob", successor_bob);
    try target.restoreMember("#Rich", successor_alice, world_mod.MemberModes.fromModes(&.{.founder}));
    try target.restoreMember("#Rich", successor_bob, world_mod.MemberModes.fromModes(&.{ .op, .voice }));
    const pairs = [_]TestRelationResolver.Pair{
        .{ .key = @bitCast(testClient(1)), .client = successor_alice, .nick = "Alice" },
        .{ .key = @bitCast(testClient(2)), .client = successor_bob, .nick = "bob" },
    };
    var relation_resolver = TestRelationResolver{ .world = &target, .pairs = &pairs };
    try restored.validateAdoptedMembersResolved(&target, relation_resolver.resolver());
    try restored.applyInvitesResolved(&target, relation_resolver.resolver());
    try testing.expect(target.hasInvite("#Rich", successor_bob));
}
