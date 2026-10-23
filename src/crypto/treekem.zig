// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A small, self-contained TreeKEM-style ratchet tree.
//!
//! This module intentionally imports only Zig's standard library. It models an
//! MLS-like left-balanced binary tree whose leaves are X25519 member keys and
//! whose parent/path secrets are derived with HKDF-SHA256. Operations produce a
//! commit carrying one X25519/HKDF envelope per current member, allowing all
//! retained members to converge on the same root secret while omitted members
//! cannot decrypt the new epoch.
const std = @import("std");
const random = @import("random.zig");
const zig_compat = @import("zig_compat.zig");

const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const testing = std.testing;
const toml = @import("../proto/toml.zig");

pub const member_seed_len = X25519.seed_length;
pub const public_key_len = X25519.public_length;
pub const secret_key_len = X25519.secret_length;
pub const secret_len = 32;

pub const MemberId = u64;
pub const MemberSeed = [member_seed_len]u8;
pub const PublicKey = [public_key_len]u8;
pub const SecretKey = [secret_key_len]u8;
pub const Secret = [secret_len]u8;

const suite_label = "onyx-treekem-v1";

/// Historic default for the maximum TreeKEM group size.
pub const default_max_members: usize = 1024;

/// Operationally tunable maximum TreeKEM group members. Overridable via
/// `[tls].treekem_max_members`; defaults preserve prior behavior.
pub var max_members: usize = default_max_members;

/// Overlay `[tls].treekem_max_members` onto the module-level member cap. Absent
/// or zero values leave the current cap unchanged (behavior preserved).
pub fn applyToml(doc: *const toml.Document) void {
    if (doc.getUint("tls.treekem_max_members")) |v| {
        if (v != 0) max_members = @intCast(v);
    }
}

pub const Error = error{
    EmptyGroup,
    TooManyMembers,
    UnknownMember,
    Evicted,
    MissingEnvelope,
    InvalidEnvelope,
    KeyChangedWithoutSecret,
    InvalidPublicKey,
};

pub const Operation = enum(u8) {
    init = 0,
    update = 1,
    add = 2,
    remove = 3,
};

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    pub fn fromSeed(seed_value: MemberSeed) Error!KeyPair {
        return keyPairFromMaterial("member-seed", &seed_value);
    }

    pub fn wipe(self: *KeyPair) void {
        secureZero(&self.secret_key);
    }
};

pub const MemberPublic = struct {
    id: MemberId,
    public_key: PublicKey,
};

const Member = struct {
    id: MemberId,
    key_pair: KeyPair,
};

pub const Envelope = struct {
    member_id: MemberId,
    ephemeral_public: PublicKey,
    ciphertext: Secret,
};

pub const Commit = struct {
    allocator: std.mem.Allocator,
    epoch: u64,
    operation: Operation,
    sender_id: MemberId,
    roster: []MemberPublic,
    envelopes: []Envelope,
    tree_hash: Secret,

    pub fn deinit(self: Commit) void {
        self.allocator.free(self.roster);
        self.allocator.free(self.envelopes);
    }
};

pub const MemberView = struct {
    allocator: std.mem.Allocator,
    member_id: MemberId,
    key_pair: KeyPair,
    epoch: u64,
    root_secret: Secret,
    roster: []MemberPublic,

    pub fn initFromSeed(
        allocator: std.mem.Allocator,
        member_id: MemberId,
        seed_value: MemberSeed,
        commit: *const Commit,
    ) (std.mem.Allocator.Error || Error)!MemberView {
        var key_pair = try KeyPair.fromSeed(seed_value);
        errdefer key_pair.wipe();

        var root_secret = try decryptCommitRoot(member_id, key_pair.secret_key, commit);
        errdefer secureZero(&root_secret);

        const roster = try copyRosterSlice(allocator, commit.roster);
        errdefer allocator.free(roster);

        const roster_public = findPublic(roster, member_id) orelse return error.Evicted;
        if (!equalPublic(roster_public.public_key, key_pair.public_key)) {
            return error.KeyChangedWithoutSecret;
        }

        return .{
            .allocator = allocator,
            .member_id = member_id,
            .key_pair = key_pair,
            .epoch = commit.epoch,
            .root_secret = root_secret,
            .roster = roster,
        };
    }

    pub fn deinit(self: *MemberView) void {
        self.key_pair.wipe();
        secureZero(&self.root_secret);
        self.allocator.free(self.roster);
        self.* = undefined;
    }

    pub fn apply(self: *MemberView, commit: *const Commit) (std.mem.Allocator.Error || Error)!Secret {
        if (findPublic(commit.roster, self.member_id) == null) return error.Evicted;

        try self.refreshOwnKey(commit);
        const new_root = try decryptCommitRoot(self.member_id, self.key_pair.secret_key, commit);

        const new_roster = try copyRosterSlice(self.allocator, commit.roster);
        errdefer self.allocator.free(new_roster);

        secureZero(&self.root_secret);
        self.allocator.free(self.roster);
        self.root_secret = new_root;
        self.roster = new_roster;
        self.epoch = commit.epoch;
        return new_root;
    }

    fn refreshOwnKey(self: *MemberView, commit: *const Commit) Error!void {
        const current = findPublic(commit.roster, self.member_id) orelse return error.Evicted;
        if (equalPublic(current.public_key, self.key_pair.public_key)) return;

        if (commit.sender_id != self.member_id) return error.KeyChangedWithoutSecret;

        const label = switch (commit.operation) {
            .update => "op-update",
            .remove => "op-remove",
            else => return error.KeyChangedWithoutSecret,
        };
        const next_key = try operationKeyPair(self.member_id, commit.epoch, label, self.root_secret);
        if (!equalPublic(current.public_key, next_key.public_key)) return error.KeyChangedWithoutSecret;

        self.key_pair.wipe();
        self.key_pair = next_key;
    }
};

pub const Group = struct {
    allocator: std.mem.Allocator,
    members: std.ArrayList(Member) = .empty,
    next_id: MemberId = 1,
    epoch: u64 = 0,
    root_secret: Secret = @splat(0),

    pub fn init(allocator: std.mem.Allocator, seeds: []const MemberSeed) (std.mem.Allocator.Error || Error)!Group {
        if (seeds.len == 0) return error.EmptyGroup;
        if (seeds.len > max_members) return error.TooManyMembers;

        var group = Group{ .allocator = allocator };
        errdefer group.deinit();

        for (seeds) |seed_value| {
            try group.members.append(allocator, .{
                .id = group.next_id,
                .key_pair = try KeyPair.fromSeed(seed_value),
            });
            group.next_id += 1;
        }
        group.root_secret = try deriveRoot(group.members.items);
        return group;
    }

    pub fn deinit(self: *Group) void {
        for (self.members.items) |*member| member.key_pair.wipe();
        secureZero(&self.root_secret);
        self.members.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn rootSecret(self: *const Group) Secret {
        return self.root_secret;
    }

    pub fn viewFor(self: *const Group, member_id: MemberId) (std.mem.Allocator.Error || Error)!MemberView {
        const member = self.findMember(member_id) orelse return error.UnknownMember;
        const roster = try self.copyRoster();
        errdefer self.allocator.free(roster);

        return .{
            .allocator = self.allocator,
            .member_id = member_id,
            .key_pair = member.key_pair,
            .epoch = self.epoch,
            .root_secret = self.root_secret,
            .roster = roster,
        };
    }

    pub fn update(self: *Group, member_id: MemberId) (std.mem.Allocator.Error || Error)!Commit {
        const idx = self.findMemberIndex(member_id) orelse return error.UnknownMember;
        self.epoch += 1;
        const previous_root = self.root_secret;
        self.members.items[idx].key_pair.wipe();
        self.members.items[idx].key_pair = try operationKeyPair(member_id, self.epoch, "op-update", previous_root);
        self.root_secret = try deriveRoot(self.members.items);
        return self.makeCommit(.update, member_id);
    }

    pub fn add(self: *Group, seed_value: MemberSeed) (std.mem.Allocator.Error || Error)!Commit {
        if (self.members.items.len >= max_members) return error.TooManyMembers;

        const member_id = self.next_id;
        self.epoch += 1;
        try self.members.append(self.allocator, .{
            .id = member_id,
            .key_pair = try KeyPair.fromSeed(seed_value),
        });
        self.next_id += 1;
        self.root_secret = try deriveRoot(self.members.items);
        return self.makeCommit(.add, member_id);
    }

    pub fn remove(self: *Group, member_id: MemberId) (std.mem.Allocator.Error || Error)!Commit {
        const idx = self.findMemberIndex(member_id) orelse return error.UnknownMember;
        if (self.members.items.len <= 1) return error.EmptyGroup;

        var removed = self.members.orderedRemove(idx);
        removed.key_pair.wipe();

        self.epoch += 1;
        const sender_id = self.members.items[0].id;
        const previous_root = self.root_secret;
        self.members.items[0].key_pair.wipe();
        self.members.items[0].key_pair = try operationKeyPair(sender_id, self.epoch, "op-remove", previous_root);
        self.root_secret = try deriveRoot(self.members.items);
        return self.makeCommit(.remove, sender_id);
    }

    fn makeCommit(
        self: *const Group,
        operation: Operation,
        sender_id: MemberId,
    ) (std.mem.Allocator.Error || Error)!Commit {
        const roster = try self.copyRoster();
        errdefer self.allocator.free(roster);

        var envelopes: std.ArrayList(Envelope) = .empty;
        errdefer envelopes.deinit(self.allocator);

        for (self.members.items) |member| {
            try envelopes.append(self.allocator, try sealRootFor(
                self.root_secret,
                self.epoch,
                operation,
                member.id,
                member.key_pair.public_key,
            ));
        }

        return .{
            .allocator = self.allocator,
            .epoch = self.epoch,
            .operation = operation,
            .sender_id = sender_id,
            .roster = roster,
            .envelopes = try envelopes.toOwnedSlice(self.allocator),
            .tree_hash = rosterHash(roster, self.epoch, operation),
        };
    }

    fn copyRoster(self: *const Group) std.mem.Allocator.Error![]MemberPublic {
        var out: std.ArrayList(MemberPublic) = .empty;
        errdefer out.deinit(self.allocator);
        for (self.members.items) |member| {
            try out.append(self.allocator, .{
                .id = member.id,
                .public_key = member.key_pair.public_key,
            });
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn findMember(self: *const Group, member_id: MemberId) ?Member {
        const idx = self.findMemberIndex(member_id) orelse return null;
        return self.members.items[idx];
    }

    fn findMemberIndex(self: *const Group, member_id: MemberId) ?usize {
        for (self.members.items, 0..) |member, i| {
            if (member.id == member_id) return i;
        }
        return null;
    }
};

fn deriveRoot(members: []const Member) Error!Secret {
    if (members.len == 0) return error.EmptyGroup;
    return deriveRange(members, 0, members.len);
}

fn deriveRange(members: []const Member, start: usize, count: usize) Error!Secret {
    if (count == 1) return leafSecret(&members[start]);

    const left_count = leftBalancedSplit(count);
    var left = try deriveRange(members, start, left_count);
    defer secureZero(&left);
    var right = try deriveRange(members, start + left_count, count - left_count);
    defer secureZero(&right);
    return parentSecret(left, right, start, count);
}

fn leafSecret(member: *const Member) Error!Secret {
    var ikm: [8 + public_key_len + secret_key_len]u8 = undefined;
    std.mem.writeInt(u64, ikm[0..8], member.id, .big);
    @memcpy(ikm[8..][0..public_key_len], &member.key_pair.public_key);
    @memcpy(ikm[8 + public_key_len ..], &member.key_pair.secret_key);
    return labeledSecret("leaf", &ikm);
}

fn parentSecret(left: Secret, right: Secret, start: usize, count: usize) Secret {
    var ikm: [secret_len * 2 + 16]u8 = undefined;
    @memcpy(ikm[0..secret_len], &left);
    @memcpy(ikm[secret_len..][0..secret_len], &right);
    std.mem.writeInt(u64, ikm[secret_len * 2 ..][0..8], @intCast(start), .big);
    std.mem.writeInt(u64, ikm[secret_len * 2 + 8 ..], @intCast(count), .big);
    return labeledSecret("parent", &ikm);
}

fn leftBalancedSplit(count: usize) usize {
    std.debug.assert(count > 1);
    var p: usize = 1;
    while (p < count) p <<= 1;
    p >>= 1;
    if (p == count) p >>= 1;
    return p;
}

fn sealRootFor(
    root_secret: Secret,
    epoch: u64,
    operation: Operation,
    member_id: MemberId,
    recipient_public: PublicKey,
) Error!Envelope {
    var eph = try envelopeKeyPair();
    defer eph.wipe();
    var dh = X25519.scalarmult(eph.secret_key, recipient_public) catch return error.InvalidPublicKey;
    defer secureZero(&dh);

    const mask = envelopeMask(dh, epoch, operation, member_id, eph.public_key);
    return .{
        .member_id = member_id,
        .ephemeral_public = eph.public_key,
        .ciphertext = xorSecret(root_secret, mask),
    };
}

fn decryptCommitRoot(
    member_id: MemberId,
    secret_key: SecretKey,
    commit: *const Commit,
) Error!Secret {
    const envelope = findEnvelope(commit.envelopes, member_id) orelse return error.MissingEnvelope;
    var dh = X25519.scalarmult(secret_key, envelope.ephemeral_public) catch return error.InvalidEnvelope;
    defer secureZero(&dh);

    const mask = envelopeMask(dh, commit.epoch, commit.operation, member_id, envelope.ephemeral_public);
    return xorSecret(envelope.ciphertext, mask);
}

fn envelopeMask(
    dh: [X25519.shared_length]u8,
    epoch: u64,
    operation: Operation,
    member_id: MemberId,
    ephemeral_public: PublicKey,
) Secret {
    var ctx: [8 + 1 + 8 + public_key_len]u8 = undefined;
    std.mem.writeInt(u64, ctx[0..8], epoch, .big);
    ctx[8] = @backingInt(operation);
    std.mem.writeInt(u64, ctx[9..17], member_id, .big);
    @memcpy(ctx[17..], &ephemeral_public);
    return hkdfExpand(&dh, "envelope", &ctx);
}

fn operationKeyPair(member_id: MemberId, epoch: u64, label: []const u8, previous_root: Secret) Error!KeyPair {
    var material: [16 + secret_len]u8 = undefined;
    std.mem.writeInt(u64, material[0..8], member_id, .big);
    std.mem.writeInt(u64, material[8..16], epoch, .big);
    @memcpy(material[16..], &previous_root);
    return keyPairFromMaterial(label, &material);
}

fn envelopeKeyPair() Error!KeyPair {
    var seed: MemberSeed = undefined;
    random.fillOsEntropy(&seed) catch return error.InvalidPublicKey;
    defer secureZero(&seed);
    const kp = zig_compat.x25519GenerateDeterministic(seed) catch return error.InvalidPublicKey;
    return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
}

fn keyPairFromMaterial(label: []const u8, material: []const u8) Error!KeyPair {
    var counter: u8 = 0;
    while (true) : (counter +%= 1) {
        var seed_ctx: [1]u8 = .{counter};
        const seed_bytes = hkdfExpand(material, label, &seed_ctx);
        const kp = zig_compat.x25519GenerateDeterministic(seed_bytes) catch {
            if (counter == std.math.maxInt(u8)) return error.InvalidPublicKey;
            continue;
        };
        return .{ .public_key = kp.public_key, .secret_key = kp.secret_key };
    }
}

fn labeledSecret(label: []const u8, ikm: []const u8) Secret {
    return hkdfExpand(ikm, label, suite_label);
}

fn rosterHash(roster: []const MemberPublic, epoch: u64, operation: Operation) Secret {
    var prk = HkdfSha256.extract(suite_label, "roster-hash");
    var out: Secret = undefined;
    var ctx: [9]u8 = undefined;
    std.mem.writeInt(u64, ctx[0..8], epoch, .big);
    ctx[8] = @backingInt(operation);
    HkdfSha256.expand(&out, &ctx, prk);
    for (roster) |member| {
        var ikm: [secret_len + 8 + public_key_len]u8 = undefined;
        @memcpy(ikm[0..secret_len], &out);
        std.mem.writeInt(u64, ikm[secret_len..][0..8], member.id, .big);
        @memcpy(ikm[secret_len + 8 ..], &member.public_key);
        prk = HkdfSha256.extract(suite_label, &ikm);
        HkdfSha256.expand(&out, "roster-member", prk);
    }
    return out;
}

fn hkdfExpand(ikm: []const u8, label: []const u8, ctx: []const u8) Secret {
    var prk = HkdfSha256.extract(label, ikm);
    defer secureZero(&prk);

    var out: Secret = undefined;
    HkdfSha256.expand(&out, ctx, prk);
    return out;
}

fn copyRosterSlice(
    allocator: std.mem.Allocator,
    roster: []const MemberPublic,
) std.mem.Allocator.Error![]MemberPublic {
    const out = try allocator.alloc(MemberPublic, roster.len);
    @memcpy(out, roster);
    return out;
}

fn findPublic(roster: []const MemberPublic, member_id: MemberId) ?MemberPublic {
    for (roster) |member| {
        if (member.id == member_id) return member;
    }
    return null;
}

fn findEnvelope(envelopes: []const Envelope, member_id: MemberId) ?Envelope {
    for (envelopes) |envelope| {
        if (envelope.member_id == member_id) return envelope;
    }
    return null;
}

fn xorSecret(a: Secret, b: Secret) Secret {
    var out: Secret = undefined;
    for (&out, a, b) |*o, x, y| o.* = x ^ y;
    return out;
}

fn equalPublic(a: PublicKey, b: PublicKey) bool {
    return std.mem.eql(u8, &a, &b);
}

fn secureZero(ptr: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(ptr));
}

fn fixedSeed(byte: u8) MemberSeed {
    return @as([member_seed_len]u8, @splat(byte));
}

fn expectSameRoot(group: *const Group, views: []const MemberView) !void {
    const root = group.rootSecret();
    for (views) |view| {
        try testing.expectEqualSlices(u8, &root, &view.root_secret);
    }
}

test "left-balanced split shapes power-of-two and uneven trees" {
    try testing.expectEqual(@as(usize, 1), leftBalancedSplit(2));
    try testing.expectEqual(@as(usize, 2), leftBalancedSplit(3));
    try testing.expectEqual(@as(usize, 2), leftBalancedSplit(4));
    try testing.expectEqual(@as(usize, 4), leftBalancedSplit(5));
    try testing.expectEqual(@as(usize, 4), leftBalancedSplit(7));
    try testing.expectEqual(@as(usize, 4), leftBalancedSplit(8));
}

test "initial group members derive the same root secret" {
    const allocator = testing.allocator;
    const seeds = [_]MemberSeed{ fixedSeed(0x11), fixedSeed(0x22), fixedSeed(0x33), fixedSeed(0x44) };

    var group = try Group.init(allocator, &seeds);
    defer group.deinit();

    var views = [_]MemberView{
        try group.viewFor(1),
        try group.viewFor(2),
        try group.viewFor(3),
        try group.viewFor(4),
    };
    defer for (&views) |*view| view.deinit();

    try expectSameRoot(&group, &views);
}

test "update changes root and all retained members converge" {
    const allocator = testing.allocator;
    const seeds = [_]MemberSeed{ fixedSeed(0x10), fixedSeed(0x20), fixedSeed(0x30) };

    var group = try Group.init(allocator, &seeds);
    defer group.deinit();

    var views = [_]MemberView{
        try group.viewFor(1),
        try group.viewFor(2),
        try group.viewFor(3),
    };
    defer for (&views) |*view| view.deinit();

    const old_root = group.rootSecret();
    var commit = try group.update(2);
    defer commit.deinit();

    for (&views) |*view| _ = try view.apply(&commit);

    try testing.expect(!std.mem.eql(u8, &old_root, &group.root_secret));
    try expectSameRoot(&group, &views);
}

test "add grows the tree and re-keys the group" {
    const allocator = testing.allocator;
    const seeds = [_]MemberSeed{ fixedSeed(0xa1), fixedSeed(0xa2), fixedSeed(0xa3) };

    var group = try Group.init(allocator, &seeds);
    defer group.deinit();

    var views = [_]MemberView{
        try group.viewFor(1),
        try group.viewFor(2),
        try group.viewFor(3),
    };
    defer for (&views) |*view| view.deinit();

    const old_root = group.rootSecret();
    var commit = try group.add(fixedSeed(0xa4));
    defer commit.deinit();

    for (&views) |*view| _ = try view.apply(&commit);
    var added = try MemberView.initFromSeed(allocator, 4, fixedSeed(0xa4), &commit);
    defer added.deinit();

    try testing.expectEqual(@as(usize, 4), commit.roster.len);
    try testing.expect(!std.mem.eql(u8, &old_root, &group.root_secret));
    try expectSameRoot(&group, &views);
    try testing.expectEqualSlices(u8, &group.root_secret, &added.root_secret);
}

test "remove evicts a member and retained members converge" {
    const allocator = testing.allocator;
    const seeds = [_]MemberSeed{ fixedSeed(0xb1), fixedSeed(0xb2), fixedSeed(0xb3), fixedSeed(0xb4) };

    var group = try Group.init(allocator, &seeds);
    defer group.deinit();

    var one = try group.viewFor(1);
    defer one.deinit();
    var two = try group.viewFor(2);
    defer two.deinit();
    var three = try group.viewFor(3);
    defer three.deinit();
    var four = try group.viewFor(4);
    defer four.deinit();

    const old_root = group.rootSecret();
    var commit = try group.remove(3);
    defer commit.deinit();

    _ = try one.apply(&commit);
    _ = try two.apply(&commit);
    try testing.expectError(error.Evicted, three.apply(&commit));
    _ = try four.apply(&commit);

    try testing.expectEqual(@as(usize, 3), commit.roster.len);
    try testing.expect(!std.mem.eql(u8, &old_root, &group.root_secret));
    try testing.expectEqualSlices(u8, &group.root_secret, &one.root_secret);
    try testing.expectEqualSlices(u8, &group.root_secret, &two.root_secret);
    try testing.expectEqualSlices(u8, &group.root_secret, &four.root_secret);
    try testing.expect(!std.mem.eql(u8, &group.root_secret, &three.root_secret));
}

test "deterministic fixed seeds reproduce roots and public commit metadata" {
    const allocator = testing.allocator;
    const seeds = [_]MemberSeed{ fixedSeed(0xc1), fixedSeed(0xc2), fixedSeed(0xc3) };

    var left = try Group.init(allocator, &seeds);
    defer left.deinit();
    var right = try Group.init(allocator, &seeds);
    defer right.deinit();

    try testing.expectEqualSlices(u8, &left.root_secret, &right.root_secret);

    var left_commit = try left.update(1);
    defer left_commit.deinit();
    var right_commit = try right.update(1);
    defer right_commit.deinit();

    try testing.expectEqualSlices(u8, &left.root_secret, &right.root_secret);
    try testing.expectEqualSlices(u8, &left_commit.tree_hash, &right_commit.tree_hash);
    try testing.expectEqual(left_commit.envelopes.len, right_commit.envelopes.len);
    var saw_randomized_envelope = false;
    for (left_commit.envelopes, right_commit.envelopes) |a, b| {
        try testing.expectEqual(a.member_id, b.member_id);
        if (!std.mem.eql(u8, &a.ephemeral_public, &b.ephemeral_public) or
            !std.mem.eql(u8, &a.ciphertext, &b.ciphertext))
        {
            saw_randomized_envelope = true;
        }
    }
    try testing.expect(saw_randomized_envelope);
}

test "applyToml overrides treekem_max_members and enforces the new cap" {
    const saved = max_members;
    defer max_members = saved; // never leak the override into other tests
    const allocator = testing.allocator;

    var doc = try toml.parse(allocator, "[tls]\ntreekem_max_members = 2\n");
    defer doc.deinit(allocator);
    applyToml(&doc);
    try testing.expectEqual(@as(usize, 2), max_members);

    // A 3-member init now exceeds the cap.
    const seeds = [_]MemberSeed{ fixedSeed(0xd1), fixedSeed(0xd2), fixedSeed(0xd3) };
    try testing.expectError(error.TooManyMembers, Group.init(allocator, &seeds));

    // Absent / zero leaves the current value unchanged.
    max_members = default_max_members;
    var zero = try toml.parse(allocator, "[tls]\ntreekem_max_members = 0\n");
    defer zero.deinit(allocator);
    applyToml(&zero);
    try testing.expectEqual(default_max_members, max_members);
}
