// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic conflict-resolution helpers for concurrent channel CRDT ops.
//!
//! These functions are pure and total: equal clocks, equal replicas, and odd
//! duplicate operations still resolve by a stable canonical order.
const std = @import("std");

const channel = @import("channel_crdt.zig");

pub const Hlc = channel.Hlc;
pub const ReplicaId = channel.ReplicaId;
pub const MemberId = channel.MemberId;
pub const MemberStatus = channel.MemberStatus;
pub const ModeUpdate = channel.ModeUpdate;
pub const KeyMode = channel.KeyMode;
pub const LimitMode = channel.LimitMode;

pub const MembershipPolicy = enum {
    add_wins,
    remove_wins,
};

pub const StatusFlag = enum(u2) {
    voice,
    op,
    owner,
    founder,
};

pub const ModeSet = struct {
    update: ModeUpdate,
    hlc: Hlc,
    replica_id: ReplicaId,
};

pub const MembershipAdd = struct {
    member_id: MemberId,
    status: MemberStatus = .{},
    hlc: Hlc,
    replica_id: ReplicaId,
};

pub const MembershipRemove = struct {
    member_id: MemberId,
    hlc: Hlc,
    replica_id: ReplicaId,
};

pub const MembershipDecision = struct {
    present: bool,
    member_id: MemberId,
    status: MemberStatus = .{},
    hlc: Hlc,
    replica_id: ReplicaId,
};

pub const StatusChange = struct {
    flag: StatusFlag,
    grant: bool,
    actor_status: MemberStatus,
    hlc: Hlc,
    replica_id: ReplicaId,
};

/// Resolve concurrent writes to the same channel mode by LWW `(HLC, replica)`.
pub fn resolveModeSet(a: ModeSet, b: ModeSet) ModeSet {
    return switch (compareEvent(a.hlc, a.replica_id, b.hlc, b.replica_id)) {
        .gt => a,
        .lt => b,
        .eq => switch (compareModeUpdate(a.update, b.update)) {
            .gt, .eq => a,
            .lt => b,
        },
    };
}

/// Resolve concurrent status mutations, preferring the higher actor tier before
/// LWW. Founder outranks owner, owner outranks op, op outranks voice.
pub fn resolveStatusChange(a: StatusChange, b: StatusChange) StatusChange {
    return switch (compareStatusChange(a, b)) {
        .gt, .eq => a,
        .lt => b,
    };
}

pub fn applyStatusChange(base: MemberStatus, change: StatusChange) MemberStatus {
    return setStatusFlag(normalizeStatus(base), change.flag, change.grant);
}

pub fn resolveStatus(base: MemberStatus, a: StatusChange, b: StatusChange) MemberStatus {
    return applyStatusChange(base, resolveStatusChange(a, b));
}

/// Resolve a concurrent add/remove pair using the selected membership policy.
pub fn resolveMembership(
    add: MembershipAdd,
    remove: MembershipRemove,
    policy: MembershipPolicy,
) MembershipDecision {
    const winner_hlc, const winner_replica = switch (compareEvent(
        add.hlc,
        add.replica_id,
        remove.hlc,
        remove.replica_id,
    )) {
        .gt, .eq => .{ add.hlc, add.replica_id },
        .lt => .{ remove.hlc, remove.replica_id },
    };

    const add_member_id = add.member_id;
    const remove_member_id = remove.member_id;
    const member_id = if (add_member_id <= remove_member_id) add_member_id else remove_member_id;
    const present = switch (policy) {
        .add_wins => true,
        .remove_wins => false,
    };

    return .{
        .present = present,
        .member_id = member_id,
        .status = if (present) normalizeStatus(add.status) else .{},
        .hlc = winner_hlc,
        .replica_id = winner_replica,
    };
}

pub fn statusTier(status: MemberStatus) u3 {
    const normalized = normalizeStatus(status);
    if (normalized.founder) return 4;
    if (normalized.owner) return 3;
    if (normalized.op) return 2;
    if (normalized.voice) return 1;
    return 0;
}

fn compareStatusChange(a: StatusChange, b: StatusChange) std.math.Order {
    const tier_order = compareInt(u3, statusTier(a.actor_status), statusTier(b.actor_status));
    if (tier_order != .eq) return tier_order;

    const event_order = compareEvent(a.hlc, a.replica_id, b.hlc, b.replica_id);
    if (event_order != .eq) return event_order;

    const flag_order = compareInt(u2, @backingInt(a.flag), @backingInt(b.flag));
    if (flag_order != .eq) return flag_order;
    return compareBool(a.grant, b.grant);
}

fn compareEvent(a_hlc: Hlc, a_replica: ReplicaId, b_hlc: Hlc, b_replica: ReplicaId) std.math.Order {
    const hlc_order = Hlc.compare(a_hlc, b_hlc);
    if (hlc_order != .eq) return hlc_order;
    return compareInt(ReplicaId, a_replica, b_replica);
}

fn compareModeUpdate(a: ModeUpdate, b: ModeUpdate) std.math.Order {
    const tag_order = compareInt(
        u8,
        modeTagOrdinal(std.meta.activeTag(a)),
        modeTagOrdinal(std.meta.activeTag(b)),
    );
    if (tag_order != .eq) return tag_order;

    return switch (a) {
        .invite_only => |value| compareBool(value, b.invite_only),
        .moderated => |value| compareBool(value, b.moderated),
        .no_external => |value| compareBool(value, b.no_external),
        .topic_protected => |value| compareBool(value, b.topic_protected),
        .secret => |value| compareBool(value, b.secret),
        .key => |value| compareKeyMode(value, b.key),
        .limit => |value| compareLimitMode(value, b.limit),
    };
}

fn modeTagOrdinal(tag: std.meta.Tag(ModeUpdate)) u8 {
    return switch (tag) {
        .invite_only => 0,
        .moderated => 1,
        .no_external => 2,
        .topic_protected => 3,
        .secret => 4,
        .key => 5,
        .limit => 6,
    };
}

fn compareKeyMode(a: KeyMode, b: KeyMode) std.math.Order {
    const present_order = compareBool(a.present, b.present);
    if (present_order != .eq) return present_order;

    const len_order = compareInt(u8, a.len, b.len);
    if (len_order != .eq) return len_order;

    const len = @min(a.len, b.len);
    for (a.bytes[0..len], b.bytes[0..len]) |a_byte, b_byte| {
        const byte_order = compareInt(u8, a_byte, b_byte);
        if (byte_order != .eq) return byte_order;
    }
    return .eq;
}

fn compareLimitMode(a: LimitMode, b: LimitMode) std.math.Order {
    const present_order = compareBool(a.present, b.present);
    if (present_order != .eq) return present_order;
    return compareInt(u32, a.value, b.value);
}

fn compareBool(a: bool, b: bool) std.math.Order {
    if (a == b) return .eq;
    return if (a) .gt else .lt;
}

fn compareInt(comptime T: type, a: T, b: T) std.math.Order {
    if (a < b) return .lt;
    if (a > b) return .gt;
    return .eq;
}

fn normalizeStatus(status: MemberStatus) MemberStatus {
    return MemberStatus.init(status.bits());
}

fn setStatusFlag(status: MemberStatus, flag: StatusFlag, enabled: bool) MemberStatus {
    var out = status;
    switch (flag) {
        .voice => out.voice = enabled,
        .op => out.op = enabled,
        .owner => out.owner = enabled,
        .founder => out.founder = enabled,
    }
    out.reserved = 0;
    return out;
}

test "concurrent +l with different values resolves identically on both sides" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const a = ModeSet{
        .update = .{ .limit = LimitMode.set(10) },
        .hlc = try Hlc.init(1000, 0),
        .replica_id = 1,
    };
    const b = ModeSet{
        .update = .{ .limit = LimitMode.set(20) },
        .hlc = try Hlc.init(1000, 0),
        .replica_id = 2,
    };

    const left = resolveModeSet(a, b);
    const right = resolveModeSet(b, a);

    try std.testing.expect(std.meta.eql(left, right));
    try std.testing.expectEqual(@as(ReplicaId, 2), left.replica_id);
    try std.testing.expectEqual(@as(u32, 20), left.update.limit.value);
}

test "concurrent op grant vs deop resolves by tier and HLC" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const grant = StatusChange{
        .flag = .op,
        .grant = true,
        .actor_status = .{ .owner = true },
        .hlc = try Hlc.init(2000, 9),
        .replica_id = 9,
    };
    const deop = StatusChange{
        .flag = .op,
        .grant = false,
        .actor_status = .{ .founder = true },
        .hlc = try Hlc.init(1000, 0),
        .replica_id = 1,
    };

    const left = resolveStatus(.{ .op = true }, grant, deop);
    const right = resolveStatus(.{ .op = true }, deop, grant);

    try std.testing.expect(std.meta.eql(left, right));
    try std.testing.expect(!left.op);

    const later_owner_deop = StatusChange{
        .flag = .op,
        .grant = false,
        .actor_status = .{ .owner = true },
        .hlc = try Hlc.init(2001, 0),
        .replica_id = 1,
    };
    const same_tier = resolveStatus(.{}, grant, later_owner_deop);
    try std.testing.expect(!same_tier.op);
}

test "commutative regardless of arg order" {
    const allocator = std.testing.allocator;
    _ = allocator;

    const key_a = ModeSet{
        .update = .{ .key = try KeyMode.init("alpha") },
        .hlc = try Hlc.init(3000, 1),
        .replica_id = 7,
    };
    const key_b = ModeSet{
        .update = .{ .key = try KeyMode.init("beta") },
        .hlc = try Hlc.init(3000, 1),
        .replica_id = 7,
    };
    try std.testing.expect(std.meta.eql(resolveModeSet(key_a, key_b), resolveModeSet(key_b, key_a)));

    const add = MembershipAdd{
        .member_id = 42,
        .status = .{ .voice = true },
        .hlc = try Hlc.init(4000, 0),
        .replica_id = 1,
    };
    const remove = MembershipRemove{
        .member_id = 42,
        .hlc = try Hlc.init(4000, 0),
        .replica_id = 2,
    };

    const add_wins = resolveMembership(add, remove, .add_wins);
    const add_wins_again = resolveMembership(add, remove, .add_wins);
    try std.testing.expect(std.meta.eql(add_wins, add_wins_again));
    try std.testing.expect(add_wins.present);
    try std.testing.expect(add_wins.status.voice);

    const remove_wins = resolveMembership(add, remove, .remove_wins);
    try std.testing.expect(!remove_wins.present);
    try std.testing.expectEqual(@as(MemberId, 42), remove_wins.member_id);
    try std.testing.expectEqual(@as(ReplicaId, 2), remove_wins.replica_id);
}
