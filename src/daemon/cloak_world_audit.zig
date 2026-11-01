// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Detached HWC2 audit with explicit host witnesses and preserved relations.
//! It neither infers missing provenance nor applies or authorizes live policy.
const std = @import("std");
const world = @import("world.zig");
const checkpoint = @import("helix/world_checkpoint.zig");
const shared = @import("cloak_migration_audit.zig");

const Pair = struct { key: u64, nick: []const u8, client: world.ClientId };
const Relations = struct {
    allocator: std.mem.Allocator,
    pairs: std.ArrayList(Pair) = .empty,
    by_key: std.AutoHashMap(u64, usize),
    fn init(a: std.mem.Allocator) Relations {
        return .{ .allocator = a, .by_key = std.AutoHashMap(u64, usize).init(a) };
    }
    fn deinit(self: *Relations) void {
        self.by_key.deinit();
        self.pairs.deinit(self.allocator);
    }
    fn add(self: *Relations, key: u64, nick: []const u8) !void {
        if (self.by_key.get(key)) |index| {
            if (!std.mem.eql(u8, self.pairs.items[index].nick, nick)) return error.InconsistentRelationIdentity;
            return;
        }
        if (self.pairs.items.len > std.math.maxInt(u20)) return error.TooManyRelationIdentities;
        const id: world.ClientId = .{ .shard = 0, .slot = @intCast(self.pairs.items.len), .gen = 1 };
        try self.pairs.append(self.allocator, .{ .key = key, .nick = nick, .client = id });
        errdefer _ = self.pairs.pop();
        try self.by_key.putNoClobber(key, self.pairs.items.len - 1);
    }
    fn resolve(ctx: *anyopaque, client: world.ClientId) ?checkpoint.MemberIdentity {
        const self: *Relations = @ptrCast(@alignCast(ctx));
        const index: usize = client.slot;
        if (client.shard != 0 or client.gen != 1 or index >= self.pairs.items.len) return null;
        const pair = self.pairs.items[index];
        return .{ .join_key = pair.key, .nick = pair.nick };
    }
    fn lookup(ctx: *anyopaque, key: u64) ?world.ClientId {
        const self: *Relations = @ptrCast(@alignCast(ctx));
        return self.pairs.items[self.by_key.get(key) orelse return null].client;
    }
    fn resolver(self: *Relations) checkpoint.NickResolver {
        return .{ .context = self, .resolve = resolve, .lookup = lookup };
    }
};

fn rehydrate(restored: *checkpoint.Restored, relations: *Relations) !void {
    for (restored.*.member_expectations) |row| try relations.*.add(row.join_key, row.nick);
    for (restored.*.invite_expectations) |row| try relations.*.add(row.join_key, row.nick);
    const resolver = relations.*.resolver();
    for (restored.*.member_expectations) |row| {
        const client = relations.*.pairs.items[relations.*.by_key.get(row.join_key) orelse return error.MissingRelationIdentity].client;
        try restored.*.world.restoreMember(row.channel, client, row.modes);
    }
    try restored.*.validateAdoptedMembersResolved(&restored.*.world, resolver);
    try restored.*.applyInvitesResolved(&restored.*.world, resolver);
}

/// Produces a separately owned byte-exact validated image, or fails closed. The
/// synthetic IDs are local and carry no evidence of real source clients.
pub fn baseline(a: std.mem.Allocator, input: []const u8) ![]u8 {
    var restored = try checkpoint.decode(a, input);
    defer restored.deinit();
    var relations = Relations.init(a);
    defer relations.deinit();
    try rehydrate(&restored, &relations);
    const resolver = relations.resolver();
    restored.world.lockRead();
    const encoded = checkpoint.encodeLockedResolved(a, &restored.world, resolver) catch |err| {
        restored.world.unlockRead();
        return err;
    };
    restored.world.unlockRead();
    errdefer a.free(encoded);
    if (!std.mem.eql(u8, encoded, input)) return error.InexactBaseline;
    return encoded;
}

pub const Limits = shared.Limits;
pub const Witness = shared.Witness;
pub const Target = shared.Target;
pub const Classification = union(enum) {
    mask: shared.Classification,
    metadata_gap,
    unsupported_mask_shape,
    pub fn name(self: Classification) []const u8 {
        return switch (self) {
            .mask => |value| @tagName(value),
            else => @tagName(self),
        };
    }
};
pub const Report = struct { row: usize, classification: Classification };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    checkpoint: []u8,
    reports: []Report,
    pub fn deinit(self: *Plan) void {
        std.crypto.secureZero(u8, self.checkpoint);
        self.allocator.free(self.checkpoint);
        self.allocator.free(self.reports);
        self.* = undefined;
    }
    pub fn forEachSummary(self: *const Plan, ctx: anytype, comptime emit: fn (@TypeOf(ctx), []const u8) anyerror!void) !void {
        var buf: [96]u8 = undefined;
        for (self.reports) |row| try emit(ctx, try std.fmt.bufPrint(&buf, "row={d} classification={s}\n", .{ row.row, row.classification.name() }));
    }
};
const Family = enum { ban, exempt, invex, mute };
const Proposal = struct {
    channel: []const u8,
    family: Family,
    old: []u8,
    new: []u8,
    setter: []u8,
    set_at: i64,
    fn deinit(self: Proposal, a: std.mem.Allocator) void {
        a.free(self.old);
        a.free(self.new);
        a.free(self.setter);
    }
};
fn lessChannel(_: void, a: world.World.CheckpointChannelView, b: world.World.CheckpointChannelView) bool {
    const common = @min(a.name.len, b.name.len);
    for (a.name[0..common], b.name[0..common]) |x, y| {
        const left = std.ascii.toLower(x);
        const right = std.ascii.toLower(y);
        if (left != right) return left < right;
    }
    return a.name.len < b.name.len;
}
fn lessEntry(_: void, a: *const world.ListEntry, b: *const world.ListEntry) bool {
    const mask = std.mem.order(u8, a.mask, b.mask);
    if (mask != .eq) return mask == .lt;
    const setter = std.mem.order(u8, a.setter, b.setter);
    if (setter != .eq) return setter == .lt;
    return a.set_at < b.set_at;
}
fn standardMask(mask: []const u8) bool {
    const bang = std.mem.indexOfScalar(u8, mask, '!') orelse return false;
    const at = std.mem.indexOfScalar(u8, mask, '@') orelse return false;
    return bang != 0 and at > bang + 1 and at + 1 < mask.len and
        std.mem.indexOfScalar(u8, mask[bang + 1 ..], '!') == null and
        std.mem.indexOfScalar(u8, mask[at + 1 ..], '@') == null;
}
fn add(w: *world.World, p: Proposal) !bool {
    return switch (p.family) {
        .ban => w.addBan(p.channel, p.new, p.setter, p.set_at),
        .exempt => w.addExempt(p.channel, p.new, p.setter, p.set_at),
        .invex => w.addInvex(p.channel, p.new, p.setter, p.set_at),
        .mute => w.addMute(p.channel, p.new, p.setter, p.set_at),
    };
}
fn remove(w: *world.World, p: Proposal) !bool {
    return switch (p.family) {
        .ban => w.removeBan(p.channel, p.old),
        .exempt => w.removeExempt(p.channel, p.old),
        .invex => w.removeInvex(p.channel, p.old),
        .mute => w.removeMute(p.channel, p.old),
    };
}
/// Ordinals follow original HWC2 channel case-fold order, family b/e/I/Z,
/// then checkpoint byte-lexicographic list order. No live state is touched.
pub fn audit(a: std.mem.Allocator, input: []const u8, witnesses: []const Witness, target: Target, limits: Limits) !Plan {
    if (limits.max_rows > 4096 or limits.max_bytes > 8 * 1024 * 1024 or input.len > limits.max_bytes or witnesses.len > limits.max_rows) return error.LimitExceeded;
    for (witnesses, 0..) |item, i| if (i != 0 and witnesses[i - 1].row >= item.row) return error.InvalidWitnessOrder;
    const base = try baseline(a, input);
    defer a.free(base);
    var restored = try checkpoint.decode(a, input);
    defer restored.deinit();
    var relations = Relations.init(a);
    defer relations.deinit();
    try rehydrate(&restored, &relations);
    const channels = try a.alloc(world.World.CheckpointChannelView, restored.world.channelCount());
    defer a.free(channels);
    var it = restored.world.checkpointChannelIterator();
    var n: usize = 0;
    while (it.next()) |c| {
        if (n == channels.len) return error.CountMismatch;
        channels[n] = c;
        n += 1;
    }
    if (n != channels.len) return error.CountMismatch;
    std.mem.sort(world.World.CheckpointChannelView, channels, {}, lessChannel);
    var count: usize = 0;
    for (channels) |c| {
        for ([_][]const world.ListEntry{ c.bans, c.exempts, c.invex, c.mutes }) |list| {
            count = std.math.add(usize, count, list.len) catch return error.LimitExceeded;
            if (count > limits.max_rows) return error.LimitExceeded;
        }
    }
    for (witnesses) |item| if (item.row >= count) return error.WitnessOutOfRange;
    const reports = try a.alloc(Report, count);
    errdefer a.free(reports);
    var proposals: std.ArrayList(Proposal) = .empty;
    defer {
        for (proposals.items) |p| p.deinit(a);
        proposals.deinit(a);
    }
    var row: usize = 0;
    var next_witness: usize = 0;
    for (channels) |c| {
        const lists = [_][]const world.ListEntry{ c.bans, c.exempts, c.invex, c.mutes };
        const families = [_]Family{ .ban, .exempt, .invex, .mute };
        for (lists, families) |list, family| {
            const ordered = try a.alloc(*const world.ListEntry, list.len);
            defer a.free(ordered);
            for (list, ordered) |*entry, *slot| slot.* = entry;
            std.mem.sort(*const world.ListEntry, ordered, {}, lessEntry);
            for (ordered) |entry| {
                const witness: ?Witness = if (next_witness < witnesses.len and witnesses[next_witness].row == row) blk: {
                    const v = witnesses[next_witness];
                    next_witness += 1;
                    break :blk v;
                } else null;
                var classification: Classification = undefined;
                if (entry.mask.len != 0 and entry.mask[0] == '$') classification = .metadata_gap else if (!standardMask(entry.mask)) classification = .unsupported_mask_shape else {
                    var replacement: [512]u8 = undefined;
                    defer std.crypto.secureZero(u8, &replacement);
                    const decision = shared.classifyMask(entry.mask, witness, target, &replacement);
                    classification = .{ .mask = decision.classification };
                    if (decision.replacement) |new_mask| {
                        // Reject targets already present or targeted in this exact
                        // family/channel, even when another proposal would move it.
                        for (list) |other| if (std.mem.eql(u8, other.mask, new_mask)) return error.DuplicateListEntry;
                        for (proposals.items) |other| if (other.family == family and std.ascii.eqlIgnoreCase(other.channel, c.name) and std.mem.eql(u8, other.new, new_mask)) return error.DuplicateListEntry;
                        const old = try a.dupe(u8, entry.mask);
                        errdefer a.free(old);
                        const new = try a.dupe(u8, new_mask);
                        errdefer a.free(new);
                        const setter = try a.dupe(u8, entry.setter);
                        errdefer a.free(setter);
                        try proposals.append(a, .{ .channel = c.name, .family = family, .old = old, .new = new, .setter = setter, .set_at = entry.set_at });
                    }
                }
                reports[row] = .{ .row = row, .classification = classification };
                row += 1;
            }
        }
    }
    for (proposals.items) |proposal| {
        if (!try remove(&restored.world, proposal)) return error.MissingListEntry;
        if (!try add(&restored.world, proposal)) return error.DuplicateListEntry;
    }
    restored.world.lockRead();
    const encoded = checkpoint.encodeLockedResolved(a, &restored.world, relations.resolver()) catch |err| {
        restored.world.unlockRead();
        return err;
    };
    restored.world.unlockRead();
    errdefer {
        std.crypto.secureZero(u8, encoded);
        a.free(encoded);
    }
    if (encoded.len > limits.max_bytes) return error.LimitExceeded;
    return .{ .allocator = a, .checkpoint = encoded, .reports = reports };
}
