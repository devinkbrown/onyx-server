// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure CRDT model for one IRC channel.
//!
//! Membership is an add-wins observed-remove set keyed by stable member id.
//! Channel modes are LWW registers ordered by `(HLC, replica_id)`.
const std = @import("std");

const clock = @import("clock.zig");
const delta_codec = @import("delta_codec.zig");
const goryu = @import("goryu.zig");

pub const Hlc = clock.Hlc;
pub const VersionVector = clock.VersionVector;
pub const WireFamily = delta_codec.EntityFamily.channel_modes;

pub const ReplicaId = u64;
pub const MemberId = u64;

pub const Dot = struct {
    replica_id: ReplicaId,
    counter: u64,
};

pub const MemberStatus = packed struct(u8) {
    voice: bool = false,
    op: bool = false,
    owner: bool = false,
    founder: bool = false,
    reserved: u4 = 0,

    pub fn init(bits_value: u4) MemberStatus {
        return @bitCast(@as(u8, bits_value));
    }

    pub fn bits(self: MemberStatus) u4 {
        return @intCast(@as(u8, @bitCast(self)) & 0x0f);
    }

    fn unionWith(a: MemberStatus, b: MemberStatus) MemberStatus {
        return MemberStatus.init(a.bits() | b.bits());
    }
};

pub const KeyMode = struct {
    pub const max_len = 64;
    pub const Error = error{KeyTooLong};

    present: bool = false,
    bytes: [max_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn init(key: []const u8) Error!KeyMode {
        if (key.len > max_len) return error.KeyTooLong;
        var out = KeyMode{ .present = true, .len = @intCast(key.len) };
        if (key.len != 0) @memcpy(out.bytes[0..key.len], key);
        return out;
    }

    pub fn none() KeyMode {
        return .{};
    }

    pub fn asSlice(self: *const KeyMode) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const LimitMode = struct {
    present: bool = false,
    value: u32 = 0,

    pub fn set(value: u32) LimitMode {
        return .{ .present = true, .value = value };
    }

    pub fn none() LimitMode {
        return .{};
    }
};

pub const ModeUpdate = union(enum) {
    invite_only: bool,
    moderated: bool,
    no_external: bool,
    topic_protected: bool,
    secret: bool,
    key: KeyMode,
    limit: LimitMode,
};

const BoolRegister = goryu.LwwRegister(bool);
const KeyRegister = goryu.LwwRegister(KeyMode);
const LimitRegister = goryu.LwwRegister(LimitMode);

pub const ChannelModes = struct {
    invite_only: BoolRegister = BoolRegister.init(),
    moderated: BoolRegister = BoolRegister.init(),
    no_external: BoolRegister = BoolRegister.init(),
    topic_protected: BoolRegister = BoolRegister.init(),
    secret: BoolRegister = BoolRegister.init(),
    key: KeyRegister = KeyRegister.init(),
    limit: LimitRegister = LimitRegister.init(),

    pub fn merge(self: *ChannelModes, other: ChannelModes) void {
        self.invite_only.merge(other.invite_only);
        self.moderated.merge(other.moderated);
        self.no_external.merge(other.no_external);
        self.topic_protected.merge(other.topic_protected);
        self.secret.merge(other.secret);
        self.key.merge(other.key);
        self.limit.merge(other.limit);
    }

    pub fn eql(a: ChannelModes, b: ChannelModes) bool {
        return BoolRegister.eql(a.invite_only, b.invite_only) and
            BoolRegister.eql(a.moderated, b.moderated) and
            BoolRegister.eql(a.no_external, b.no_external) and
            BoolRegister.eql(a.topic_protected, b.topic_protected) and
            BoolRegister.eql(a.secret, b.secret) and
            KeyRegister.eql(a.key, b.key) and
            LimitRegister.eql(a.limit, b.limit);
    }

    fn set(self: *ChannelModes, update: ModeUpdate, hlc: Hlc, replica_id: ReplicaId) void {
        const timestamp = hlc.toU64();
        const rid: u64 = replica_id;
        switch (update) {
            .invite_only => |value| _ = self.invite_only.set(value, timestamp, rid),
            .moderated => |value| _ = self.moderated.set(value, timestamp, rid),
            .no_external => |value| _ = self.no_external.set(value, timestamp, rid),
            .topic_protected => |value| _ = self.topic_protected.set(value, timestamp, rid),
            .secret => |value| _ = self.secret.set(value, timestamp, rid),
            .key => |value| _ = self.key.set(value, timestamp, rid),
            .limit => |value| _ = self.limit.set(value, timestamp, rid),
        }
    }
};

const MemberAdd = struct {
    dot: Dot,
    hlc: Hlc,
    status: MemberStatus,
};

const MemberEntry = struct {
    member_id: MemberId,
    adds: std.ArrayList(MemberAdd) = .empty,
    context: VersionVector = VersionVector.init(),

    fn deinit(self: *MemberEntry, allocator: std.mem.Allocator) void {
        self.adds.deinit(allocator);
    }
};

pub const ChannelCrdt = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    replica_id: ReplicaId,
    hlc: Hlc = .{},
    vv: VersionVector = VersionVector.init(),
    members: std.ArrayList(MemberEntry) = .empty,
    modes: ChannelModes = .{},

    pub fn init(allocator: std.mem.Allocator, replica_id: ReplicaId) Self {
        return .{
            .allocator = allocator,
            .replica_id = replica_id,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.members.items) |*entry| entry.deinit(self.allocator);
        self.members.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn localJoin(self: *Self, member_id: MemberId, status: MemberStatus, physical_ms: u64) !Self {
        const dot = try self.nextDot();
        const timestamp = try self.hlc.now(physical_ms);

        var delta = Self.init(self.allocator, self.replica_id);
        errdefer delta.deinit();
        delta.hlc = timestamp;
        delta.vv = self.vv;

        const entry = try self.ensureMember(member_id);
        const delta_entry = try delta.ensureMember(member_id);
        delta_entry.context = entry.context;
        try observeDot(&entry.context, dot);
        try observeDot(&delta_entry.context, dot);

        removeAddsCoveredByDots(entry, delta_entry.context, &.{dot});

        const add = MemberAdd{ .dot = dot, .hlc = timestamp, .status = status };
        try entry.adds.append(self.allocator, add);
        try delta_entry.adds.append(delta.allocator, add);
        return delta;
    }

    pub fn localPart(self: *Self, member_id: MemberId) !Self {
        var delta = Self.init(self.allocator, self.replica_id);
        errdefer delta.deinit();
        delta.hlc = self.hlc;
        delta.vv = self.vv;

        const idx = self.findMemberIndex(member_id) orelse return delta;
        const entry = &self.members.items[idx];
        const delta_entry = try delta.ensureMember(member_id);
        delta_entry.context = entry.context;
        entry.adds.clearRetainingCapacity();
        return delta;
    }

    pub fn localSetMode(self: *Self, update: ModeUpdate, physical_ms: u64) !Self {
        const timestamp = try self.hlc.now(physical_ms);
        self.modes.set(update, timestamp, self.replica_id);

        var delta = Self.init(self.allocator, self.replica_id);
        errdefer delta.deinit();
        delta.hlc = timestamp;
        delta.vv = self.vv;
        delta.modes.set(update, timestamp, self.replica_id);
        return delta;
    }

    pub fn merge(self: *Self, other: *const Self) !void {
        // Merge must be all-or-nothing. The version-vector merges below fail
        // with error.CapacityExceeded once a channel has seen more than
        // `VersionVector.max_entries` (64) distinct writing replicas, and the
        // original code bumped `self.hlc` and merged some members BEFORE that
        // error surfaced — leaving `self` half-merged with `self.modes` never
        // merged, permanently wedging convergence. Validate every fallible VV
        // merge (the top-level vector and each existing member's causal
        // context) up front so nothing observable mutates unless the whole
        // merge can complete. A brand-new member starts from an empty context,
        // so its merged context is just `other`'s (a valid vector, already
        // within the cap) and needs no pre-check. `member_id`s are unique
        // within any ChannelCrdt by construction (every mutator routes through
        // `ensureMember`, and a decoded delta carries exactly one member), so
        // no member is validated or committed twice.
        if (self.vv.mergedLen(&other.vv) > VersionVector.max_entries) {
            return error.CapacityExceeded;
        }
        for (other.members.items) |*other_entry| {
            if (self.findMemberIndex(other_entry.member_id)) |idx| {
                if (self.members.items[idx].context.mergedLen(&other_entry.context) > VersionVector.max_entries) {
                    return error.CapacityExceeded;
                }
            }
        }

        // Validation passed: the version-vector merges below can no longer
        // exceed the cap, so the merge commits. (Only OOM on an append can
        // still fail, which is a fatal allocation failure, not a silent
        // convergence wedge.)
        if (Hlc.compare(other.hlc, self.hlc) == .gt) self.hlc = other.hlc;
        try self.vv.merge(&other.vv);

        for (other.members.items) |other_entry| {
            const entry = try self.ensureMember(other_entry.member_id);

            removeAddsCoveredByAdds(entry, other_entry.context, other_entry.adds.items);
            for (other_entry.adds.items) |add| {
                if (!entry.context.contains(toClockDot(add.dot)) and !containsAdd(entry.adds.items, add.dot)) {
                    try entry.adds.append(self.allocator, add);
                }
            }
            try entry.context.merge(&other_entry.context);
        }

        self.modes.merge(other.modes);
    }

    pub fn clone(self: *const Self) !Self {
        var out = Self.init(self.allocator, self.replica_id);
        errdefer out.deinit();
        out.hlc = self.hlc;
        out.vv = self.vv;
        out.modes = self.modes;

        for (self.members.items) |entry| {
            var adds = std.ArrayList(MemberAdd).empty;
            errdefer adds.deinit(out.allocator);
            try adds.appendSlice(out.allocator, entry.adds.items);
            try out.members.append(out.allocator, .{
                .member_id = entry.member_id,
                .adds = adds,
                .context = entry.context,
            });
        }
        return out;
    }

    pub fn containsMember(self: *const Self, member_id: MemberId) bool {
        const idx = self.findMemberIndex(member_id) orelse return false;
        return self.members.items[idx].adds.items.len != 0;
    }

    pub fn memberStatus(self: *const Self, member_id: MemberId) ?MemberStatus {
        const idx = self.findMemberIndex(member_id) orelse return null;
        var status = MemberStatus{};
        var found = false;
        for (self.members.items[idx].adds.items) |add| {
            status = MemberStatus.unionWith(status, add.status);
            found = true;
        }
        return if (found) status else null;
    }

    pub fn eql(a: *const Self, b: *const Self) bool {
        return Hlc.compare(a.hlc, b.hlc) == .eq and
            vvEql(a.vv, b.vv) and
            memberListsEql(a.members.items, b.members.items) and
            ChannelModes.eql(a.modes, b.modes);
    }

    fn nextDot(self: *Self) !Dot {
        const dot = try self.vv.increment(self.replica_id);
        return fromClockDot(dot);
    }

    fn ensureMember(self: *Self, member_id: MemberId) !*MemberEntry {
        if (self.findMemberIndex(member_id)) |idx| return &self.members.items[idx];
        try self.members.append(self.allocator, .{ .member_id = member_id });
        return &self.members.items[self.members.items.len - 1];
    }

    fn findMemberIndex(self: *const Self, member_id: MemberId) ?usize {
        for (self.members.items, 0..) |entry, idx| {
            if (entry.member_id == member_id) return idx;
        }
        return null;
    }
};

fn fromClockDot(dot: clock.Dot) !Dot {
    if (dot.replica > std.math.maxInt(ReplicaId)) return error.ReplicaIdOutOfRange;
    return .{ .replica_id = @intCast(dot.replica), .counter = dot.counter };
}

fn toClockDot(dot: Dot) clock.Dot {
    return .{ .replica = dot.replica_id, .counter = dot.counter };
}

fn observeDot(vv: *VersionVector, dot: Dot) !void {
    var single = VersionVector.init();
    single.entries[0] = .{ .replica = dot.replica_id, .counter = dot.counter };
    single.len = 1;
    try vv.merge(&single);
}

fn removeAddsCoveredByDots(entry: *MemberEntry, context: VersionVector, keep: []const Dot) void {
    var idx: usize = 0;
    while (idx < entry.adds.items.len) {
        const add = entry.adds.items[idx];
        if (context.contains(toClockDot(add.dot)) and !containsDot(keep, add.dot)) {
            _ = entry.adds.swapRemove(idx);
        } else {
            idx += 1;
        }
    }
}

fn removeAddsCoveredByAdds(entry: *MemberEntry, context: VersionVector, keep: []const MemberAdd) void {
    var idx: usize = 0;
    while (idx < entry.adds.items.len) {
        const add = entry.adds.items[idx];
        if (context.contains(toClockDot(add.dot)) and !containsLiveDot(keep, add.dot)) {
            _ = entry.adds.swapRemove(idx);
        } else {
            idx += 1;
        }
    }
}

fn containsDot(dots: []const Dot, dot: Dot) bool {
    for (dots) |candidate| {
        if (dotEql(candidate, dot)) return true;
    }
    return false;
}

fn containsLiveDot(adds: []const MemberAdd, dot: Dot) bool {
    for (adds) |add| {
        if (dotEql(add.dot, dot)) return true;
    }
    return false;
}

fn containsAdd(adds: []const MemberAdd, dot: Dot) bool {
    return containsLiveDot(adds, dot);
}

fn dotEql(a: Dot, b: Dot) bool {
    return a.replica_id == b.replica_id and a.counter == b.counter;
}

fn memberListsEql(a: []const MemberEntry, b: []const MemberEntry) bool {
    if (a.len != b.len) return false;
    for (a) |entry_a| {
        const entry_b = findEntry(b, entry_a.member_id) orelse return false;
        if (!vvEql(entry_a.context, entry_b.context)) return false;
        if (!addListsEql(entry_a.adds.items, entry_b.adds.items)) return false;
    }
    return true;
}

fn findEntry(entries: []const MemberEntry, member_id: MemberId) ?MemberEntry {
    for (entries) |entry| {
        if (entry.member_id == member_id) return entry;
    }
    return null;
}

fn addListsEql(a: []const MemberAdd, b: []const MemberAdd) bool {
    if (a.len != b.len) return false;
    for (a) |add_a| {
        var found = false;
        for (b) |add_b| {
            if (dotEql(add_a.dot, add_b.dot) and
                Hlc.compare(add_a.hlc, add_b.hlc) == .eq and
                std.meta.eql(add_a.status, add_b.status))
            {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn vvEql(a: VersionVector, b: VersionVector) bool {
    if (a.len != b.len) return false;
    for (a.entries[0..a.len]) |entry| {
        if (b.counter(entry.replica) != entry.counter) return false;
    }
    return true;
}

fn applyRandomOp(state: *ChannelCrdt, random: std.Random, step: u64) !void {
    const member = @as(MemberId, 1000 + random.intRangeLessThan(u16, 0, 12));
    const physical = 10_000 + step;
    switch (random.intRangeLessThan(u8, 0, 9)) {
        0, 1, 2, 3 => {
            var delta = try state.localJoin(member, MemberStatus.init(@intCast(1 + random.intRangeLessThan(u4, 0, 8))), physical);
            delta.deinit();
        },
        4, 5 => {
            var delta = try state.localPart(member);
            delta.deinit();
        },
        6 => {
            var delta = try state.localSetMode(.{ .invite_only = random.boolean() }, physical);
            delta.deinit();
        },
        7 => {
            const value = if (random.boolean()) LimitMode.set(10 + random.intRangeLessThan(u32, 0, 50)) else LimitMode.none();
            var delta = try state.localSetMode(.{ .limit = value }, physical);
            delta.deinit();
        },
        8 => {
            const value = if (random.boolean()) try KeyMode.init("split-key") else KeyMode.none();
            var delta = try state.localSetMode(.{ .key = value }, physical);
            delta.deinit();
        },
        else => unreachable,
    }
}

/// Fold one distinct writing replica into `dst` by merging a single-member
/// join delta authored by `replica_id`. Using `replica_id` as the member id
/// too keeps every member's causal context at length 1, so only the
/// top-level version vector grows — letting a test drive `dst.vv.len` toward
/// the 64-replica cap without tripping the per-member context cap.
fn seedReplica(dst: *ChannelCrdt, replica_id: u64, physical: u64) !void {
    var src = ChannelCrdt.init(dst.allocator, replica_id);
    defer src.deinit();
    var delta = try src.localJoin(replica_id, .{ .voice = true }, physical);
    defer delta.deinit();
    try dst.merge(&delta);
}

test "merge exceeding the version-vector cap leaves self unchanged and does not advance hlc" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    // `a` observes 40 distinct writing replicas, `b` another disjoint 40; their
    // union (80) exceeds VersionVector.max_entries (64), so a.merge(&b) must
    // fail. `b` is seeded with strictly later physical time so its HLC beats
    // a's — the pre-fix bug advanced a.hlc to b.hlc before the merge failed.
    var r: u64 = 0;
    while (r < 40) : (r += 1) try seedReplica(&a, 100 + r, 1_000 + r);
    r = 0;
    while (r < 40) : (r += 1) try seedReplica(&b, 200 + r, 2_000 + r);
    try std.testing.expectEqual(@as(usize, 40), a.vv.len);

    var before = try a.clone();
    defer before.deinit();

    try std.testing.expectError(error.CapacityExceeded, a.merge(&b));

    // Self is byte-for-byte the pre-merge state: hlc not advanced, no partial
    // vv / member / mode mutation.
    try std.testing.expect(ChannelCrdt.eql(&a, &before));
    try std.testing.expectEqual(before.hlc.toU64(), a.hlc.toU64());
    try std.testing.expectEqual(@as(usize, 40), a.vv.len);
}

test "merge exceeding a single member's context cap fails closed with self unchanged" {
    const allocator = std.testing.allocator;

    // This state is built directly to violate the natural `context ⊆ vv`
    // invariant, so the *per-member* context-cap guard is reached while the
    // top-level version-vector check still passes — the only way to exercise
    // that defensive branch. It proves the merge stays all-or-nothing even if a
    // future path let a member context outgrow the top vector.
    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var a_ctx = VersionVector.init();
    var rr: u64 = 1;
    while (rr <= 40) : (rr += 1) {
        a.vv.entries[a.vv.len] = .{ .replica = rr, .counter = 1 };
        a.vv.len += 1;
        a_ctx.entries[a_ctx.len] = .{ .replica = rr, .counter = 1 };
        a_ctx.len += 1;
    }
    try a.members.append(allocator, .{ .member_id = 1, .context = a_ctx });

    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    // b's top vv is a subset of a's (union stays at 40 <= 64), but member 1's
    // context carries 50 disjoint replicas (41..90) — so ONLY the per-member
    // union (90) exceeds the 64 cap.
    b.vv.entries[0] = .{ .replica = 1, .counter = 1 };
    b.vv.len = 1;
    var b_ctx = VersionVector.init();
    rr = 41;
    while (rr <= 90) : (rr += 1) {
        b_ctx.entries[b_ctx.len] = .{ .replica = rr, .counter = 1 };
        b_ctx.len += 1;
    }
    try b.members.append(allocator, .{ .member_id = 1, .context = b_ctx });

    var before = try a.clone();
    defer before.deinit();

    try std.testing.expectError(error.CapacityExceeded, a.merge(&b));
    try std.testing.expect(ChannelCrdt.eql(&a, &before));
    try std.testing.expectEqual(@as(usize, 40), a.vv.len);
}

test "merge at exactly the version-vector cap converges and is idempotent on replay" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    // 32 distinct replicas each; the union is exactly max_entries (64) — the
    // merge must succeed at the boundary and carry every member across.
    var r: u64 = 0;
    while (r < 32) : (r += 1) try seedReplica(&a, 300 + r, 3_000 + r);
    r = 0;
    while (r < 32) : (r += 1) try seedReplica(&b, 400 + r, 4_000 + r);

    try a.merge(&b);
    try std.testing.expectEqual(@as(usize, VersionVector.max_entries), a.vv.len);
    for (300..332) |m| try std.testing.expect(a.containsMember(@intCast(m)));
    for (400..432) |m| try std.testing.expect(a.containsMember(@intCast(m)));

    // Replaying the identical merge converges to the same state (idempotent).
    var snapshot = try a.clone();
    defer snapshot.deinit();
    try a.merge(&b);
    try std.testing.expect(ChannelCrdt.eql(&a, &snapshot));
}

test "merge commutativity and idempotence on deterministic random ops" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7c_7d_ca_fe);
    const random = prng.random();

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    var step: u64 = 0;
    while (step < 96) : (step += 1) {
        if (random.boolean()) {
            try applyRandomOp(&a, random, step);
        } else {
            try applyRandomOp(&b, random, step);
        }
    }

    var left = try a.clone();
    defer left.deinit();
    try left.merge(&b);

    var right = try b.clone();
    defer right.deinit();
    try right.merge(&a);

    try std.testing.expect(ChannelCrdt.eql(&left, &right));

    var idem = try left.clone();
    defer idem.deinit();
    try idem.merge(&left);
    try std.testing.expect(ChannelCrdt.eql(&idem, &left));
}

test "three replicas converge after disjoint op sets and all merge orders" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    var c = ChannelCrdt.init(allocator, 3);
    defer c.deinit();

    var da1 = try a.localJoin(1, .{ .op = true }, 1);
    defer da1.deinit();
    var da2 = try a.localSetMode(.{ .topic_protected = true }, 2);
    defer da2.deinit();

    var db1 = try b.localJoin(2, .{ .voice = true }, 3);
    defer db1.deinit();
    var db2 = try b.localSetMode(.{ .key = try KeyMode.init("mesh") }, 4);
    defer db2.deinit();

    var dc1 = try c.localJoin(3, .{ .owner = true }, 5);
    defer dc1.deinit();
    var dc2 = try c.localSetMode(.{ .limit = LimitMode.set(42) }, 6);
    defer dc2.deinit();

    var abc = try a.clone();
    defer abc.deinit();
    try abc.merge(&b);
    try abc.merge(&c);

    var bca = try b.clone();
    defer bca.deinit();
    try bca.merge(&c);
    try bca.merge(&a);

    var cab = try c.clone();
    defer cab.deinit();
    try cab.merge(&a);
    try cab.merge(&b);

    try std.testing.expect(ChannelCrdt.eql(&abc, &bca));
    try std.testing.expect(ChannelCrdt.eql(&abc, &cab));
}

test "add wins when observed part races with rejoin" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();

    var initial = try a.localJoin(42, .{ .voice = true }, 100);
    defer initial.deinit();
    try b.merge(&initial);

    var part = try b.localPart(42);
    defer part.deinit();
    var rejoin = try a.localJoin(42, .{ .op = true }, 101);
    defer rejoin.deinit();

    var left = try a.clone();
    defer left.deinit();
    try left.merge(&part);

    var right = try b.clone();
    defer right.deinit();
    try right.merge(&rejoin);

    try std.testing.expect(left.containsMember(42));
    try std.testing.expect(right.containsMember(42));
    try std.testing.expectEqual(@as(u4, 0b0010), left.memberStatus(42).?.bits());

    try left.merge(&right);
    try right.merge(&left);
    try std.testing.expect(ChannelCrdt.eql(&left, &right));
    try std.testing.expect(right.containsMember(42));
}

test "netsplit and heal converge channel membership and modes" {
    const allocator = std.testing.allocator;

    var a = ChannelCrdt.init(allocator, 1);
    defer a.deinit();
    var b = ChannelCrdt.init(allocator, 2);
    defer b.deinit();
    var c = ChannelCrdt.init(allocator, 3);
    defer c.deinit();

    var seed_join = try a.localJoin(7, .{ .voice = true }, 1);
    defer seed_join.deinit();
    try b.merge(&seed_join);
    try c.merge(&seed_join);

    var a_rejoin = try a.localJoin(7, .{ .op = true }, 10);
    defer a_rejoin.deinit();
    var a_secret = try a.localSetMode(.{ .secret = true }, 11);
    defer a_secret.deinit();
    var a_key = try a.localSetMode(.{ .key = try KeyMode.init("alpha") }, 12);
    defer a_key.deinit();

    var b_part = try b.localPart(7);
    defer b_part.deinit();
    var b_join = try b.localJoin(8, .{ .voice = true }, 13);
    defer b_join.deinit();

    var c_limit = try c.localSetMode(.{ .limit = LimitMode.set(128) }, 14);
    defer c_limit.deinit();
    var c_invite = try c.localSetMode(.{ .invite_only = true }, 15);
    defer c_invite.deinit();

    var x = try a.clone();
    defer x.deinit();
    try x.merge(&b);
    try x.merge(&c);

    var y = try b.clone();
    defer y.deinit();
    try y.merge(&c);
    try y.merge(&a);

    var z = try c.clone();
    defer z.deinit();
    try z.merge(&a);
    try z.merge(&b);

    try std.testing.expect(ChannelCrdt.eql(&x, &y));
    try std.testing.expect(ChannelCrdt.eql(&x, &z));
    try std.testing.expect(x.containsMember(7));
    try std.testing.expect(x.containsMember(8));
    try std.testing.expectEqual(true, x.modes.secret.get().?);
    try std.testing.expectEqual(true, x.modes.invite_only.get().?);
    try std.testing.expectEqual(@as(u32, 128), x.modes.limit.get().?.value);
    try std.testing.expect(std.mem.eql(u8, "alpha", x.modes.key.get().?.asSlice()));
}
