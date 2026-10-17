// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Live mesh-presence v2 subjects and a separate next-hop table.
//! The store decides identity. The path is the secured link that carried the
//! original bytes, never a consequence of the signature. Epoch 1 and the
//! caller's guest counter are runtime facts: Helix does not adopt this table,
//! and the durable v1 issuer is not on this path.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const wire = @import("../proto/mesh_presence_v2.zig");
const store_mod = @import("mesh_presence_store.zig");

pub const max_sent_peers = 16;
pub const direct_capacity = 128;
pub const direct_max_age_ms: i64 = 120_000;
pub const Error = store_mod.Error || error{ UnroutableHop, Duplicate, Saturated };
pub const Disposition = store_mod.Disposition;

const Path = struct {
    next_hop: u64 = 0,
    local: bool = false,
    sent: [max_sent_peers]u64 = @splat(0),
    sent_count: u8 = 0,
};

const DirectSlot = struct {
    used: bool = false,
    origin: sign.PublicKey = @splat(0),
    hlc: u64 = 0,
    issued_ms: i64 = 0,
};

pub const SubjectView = struct {
    index: usize,
    origin: sign.PublicKey,
    guest: wire.GuestId,
    revision: u64,
    class_revision: u64,
    claim_hlc: u64,
    claim_revision: u64,
    issued_ms: i64,
    expires_ms: i64,
    operation: wire.Operation,
    routing_class: wire.RoutingClass,
    nick: []const u8,
    username: []const u8,
    host: []const u8,
    realname: []const u8,
    server: []const u8,
    description: []const u8,
    wire: []const u8,
    next_hop: u64,
    local: bool,
};

pub const Forward = struct {
    index: usize,
    wire: []const u8,
    next_hop: u64,
    local: bool,
};

pub const Authority = struct {
    allocator: std.mem.Allocator,
    store: store_mod.Store,
    paths: std.ArrayList(Path),
    directs: [direct_capacity]DirectSlot = @splat(.{}),

    pub fn create(allocator: std.mem.Allocator) !*Authority {
        const self = try allocator.create(Authority);
        errdefer allocator.destroy(self);
        var store = try store_mod.Store.init(allocator, .{});
        errdefer store.deinit();
        const paths = try std.ArrayList(Path).initCapacity(allocator, store.config.max_entries);
        self.* = .{ .allocator = allocator, .store = store, .paths = paths };
        return self;
    }

    pub fn destroy(self: *Authority) void {
        const allocator = self.allocator;
        self.store.deinit();
        self.paths.deinit(allocator);
        allocator.destroy(self);
    }

    /// `local` publishes this node's own original. A remote admit requires the
    /// ingress link's node id; zero is not a hop and does not become local.
    pub fn admit(
        self: *Authority,
        original: []const u8,
        roots: []const sign.PublicKey,
        now_ms: i64,
        hop: u64,
        local: bool,
    ) Error!Disposition {
        if (!local and hop == 0) return error.UnroutableHop;
        var prepared = try self.store.prepare(original, roots, now_ms);
        defer prepared.abort();
        if (prepared.disposition == .duplicate or prepared.disposition == .obsolete) return prepared.disposition;
        const index = prepared.index;
        if (index == self.paths.items.len) try self.paths.append(self.allocator, .{});
        const disposition = prepared.commit();
        if (disposition == .inserted or disposition == .updated) {
            self.paths.items[index] = .{ .next_hop = if (local) 0 else hop, .local = local };
        } else if (disposition == .quarantined) {
            self.paths.items[index] = .{};
        }
        return disposition;
    }

    pub fn retainedCount(self: *const Authority) usize {
        return self.store.entries.items.len;
    }

    pub fn liveByNick(self: *const Authority, nick: []const u8, now_ms: i64) ?SubjectView {
        var best: ?SubjectView = null;
        for (self.store.entries.items, 0..) |entry, index| {
            if (!self.usable(entry, now_ms) or !nickEq(entry.decoded.record.nick, nick)) continue;
            const subject = self.view(index);
            if (best == null or precedes(subject, best.?)) best = subject;
        }
        return best;
    }

    pub fn liveByGuest(self: *const Authority, origin: sign.PublicKey, guest: wire.GuestId, now_ms: i64) ?SubjectView {
        const index = self.find(origin, guest) orelse return null;
        const entry = self.store.entries.items[index];
        if (!self.usable(entry, now_ms)) return null;
        return self.view(index);
    }

    /// Includes an expired or quit subject so the origin can author the next
    /// revision. A quarantined contradiction stays hidden.
    pub fn retainedByGuest(self: *const Authority, origin: sign.PublicKey, guest: wire.GuestId) ?SubjectView {
        const index = self.find(origin, guest) orelse return null;
        if (self.store.entries.items[index].conflict != null) return null;
        return self.view(index);
    }

    pub fn forwardAt(self: *const Authority, index: usize, now_ms: i64) ?Forward {
        if (index >= self.store.entries.items.len or index >= self.paths.items.len) return null;
        const entry = self.store.entries.items[index];
        if (entry.conflict != null) return null;
        self.store.config.clock.validate(entry.decoded.record, now_ms) catch return null;
        const path = self.paths.items[index];
        return .{ .index = index, .wire = entry.original, .next_hop = path.next_hop, .local = path.local };
    }

    pub fn wantsSend(self: *const Authority, index: usize, peer: u64) bool {
        if (peer == 0 or index >= self.paths.items.len) return false;
        const path = &self.paths.items[index];
        if (path.sent_count == max_sent_peers) return false;
        for (path.sent[0..path.sent_count]) |item| if (item == peer) return false;
        return true;
    }

    pub fn markSent(self: *Authority, index: usize, peer: u64) bool {
        if (!self.wantsSend(index, peer)) return false;
        const path = &self.paths.items[index];
        path.sent[path.sent_count] = peer;
        path.sent_count += 1;
        return true;
    }

    /// Remember one fresh `(origin, hlc)` before delivery. A full set of still
    /// fresh identities refuses the new body instead of forgetting one.
    pub fn observeDirect(self: *Authority, origin: sign.PublicKey, hlc: u64, issued_ms: i64, now_ms: i64) Error!void {
        if (hlc == 0 or issued_ms < 0 or now_ms < 0) return error.InvalidField;
        for (self.directs) |slot| {
            if (slot.used and slot.hlc == hlc and std.mem.eql(u8, &slot.origin, &origin)) return error.Duplicate;
        }
        var slot_index: ?usize = null;
        for (&self.directs, 0..) |*slot, index| {
            if (!slot.used or directExpired(slot.issued_ms, now_ms)) {
                slot_index = index;
                break;
            }
        }
        const chosen = slot_index orelse return error.Saturated;
        self.directs[chosen] = .{ .used = true, .origin = origin, .hlc = hlc, .issued_ms = issued_ms };
    }

    fn find(self: *const Authority, origin: sign.PublicKey, guest: wire.GuestId) ?usize {
        for (self.store.entries.items, 0..) |entry, index| {
            const record = entry.decoded.record;
            if (std.mem.eql(u8, &record.origin, &origin) and std.mem.eql(u8, &record.guest, &guest)) return index;
        }
        return null;
    }

    fn usable(self: *const Authority, entry: store_mod.Entry, now_ms: i64) bool {
        if (entry.terminal()) return false;
        const record = entry.decoded.record;
        if (record.operation != .present or record.routing_class != .true_guest) return false;
        self.store.config.clock.validate(record, now_ms) catch return false;
        return true;
    }

    fn view(self: *const Authority, index: usize) SubjectView {
        const entry = self.store.entries.items[index];
        const record = entry.decoded.record;
        const path = self.paths.items[index];
        return .{
            .index = index,
            .origin = record.origin,
            .guest = record.guest,
            .revision = record.revision,
            .class_revision = record.class_revision,
            .claim_hlc = record.claim_hlc,
            .claim_revision = record.claim_revision,
            .issued_ms = record.issued_ms,
            .expires_ms = record.expires_ms,
            .operation = record.operation,
            .routing_class = record.routing_class,
            .nick = record.nick,
            .username = record.username,
            .host = record.host,
            .realname = record.realname,
            .server = record.server,
            .description = record.description,
            .wire = entry.original,
            .next_hop = path.next_hop,
            .local = path.local,
        };
    }
};

fn directExpired(issued_ms: i64, now_ms: i64) bool {
    return now_ms >= issued_ms and now_ms - issued_ms >= direct_max_age_ms;
}

fn nickEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (std.ascii.toLower(left) != std.ascii.toLower(right)) return false;
    return true;
}

fn precedes(a: SubjectView, b: SubjectView) bool {
    const origin = std.mem.order(u8, &a.origin, &b.origin);
    if (origin == .lt) return true;
    if (origin == .gt) return false;
    return std.mem.order(u8, &a.guest, &b.guest) == .lt;
}

fn present(key: *const sign.KeyPair, guest_byte: u8, nick: []const u8, revision: u64) ![]const u8 {
    const record: wire.Record = .{
        .operation = .present,
        .origin = key.public_key,
        .guest = try wire.guestId(.{ .epoch = 1, .counter = guest_byte }),
        .revision = revision,
        .routing_class = .true_guest,
        .class_revision = 1,
        .claim_hlc = 7,
        .claim_revision = 1,
        .issued_ms = 1_000,
        .expires_ms = 1_000 + 120_000,
        .nick = nick,
        .username = "ordinary",
        .host = "127.0.0.1",
        .realname = "Independent",
        .server = "origin.test",
        .description = "Onyx Server",
    };
    const buffer = try std.testing.allocator.alloc(u8, wire.max_wire_len);
    errdefer std.testing.allocator.free(buffer);
    const encoded = try wire.encode(record, key, buffer);
    const owned = try std.testing.allocator.dupe(u8, encoded);
    std.testing.allocator.free(buffer);
    return owned;
}

test "guest route keeps the first hop, replaces it on update, and hides quarantine" {
    const allocator = std.testing.allocator;
    var key = try sign.KeyPair.fromSeed(@splat(21));
    defer key.deinit();
    var authority = try Authority.create(allocator);
    defer authority.destroy();
    const first = try present(&key, 1, "GuestC", 1);
    defer allocator.free(first);
    try std.testing.expectEqual(Disposition.inserted, try authority.admit(first, &.{key.public_key}, 1_000, 44, false));
    try std.testing.expectEqual(Disposition.duplicate, try authority.admit(first, &.{key.public_key}, 1_000, 99, false));
    const live = authority.liveByNick("guestc", 1_000).?;
    try std.testing.expectEqual(@as(u64, 44), live.next_hop);
    try std.testing.expectEqualStrings("origin.test", live.server);
    var renewed = (try wire.decode(first)).record;
    renewed.revision = 2;
    renewed.issued_ms = 2_000;
    renewed.expires_ms = 2_000 + 120_000;
    const second_buf = try allocator.alloc(u8, wire.max_wire_len);
    defer allocator.free(second_buf);
    const second = try wire.encode(renewed, &key, second_buf);
    try std.testing.expectEqual(Disposition.updated, try authority.admit(second, &.{key.public_key}, 2_000, 55, false));
    try std.testing.expectEqual(@as(u64, 55), authority.liveByNick("GuestC", 2_000).?.next_hop);
    try std.testing.expect(authority.wantsSend(0, 55));
    try std.testing.expect(authority.markSent(0, 55));
    try std.testing.expect(!authority.wantsSend(0, 55));
    var conflict = renewed;
    conflict.realname = "contradiction";
    const conflict_buf = try allocator.alloc(u8, wire.max_wire_len);
    defer allocator.free(conflict_buf);
    const conflicted = try wire.encode(conflict, &key, conflict_buf);
    try std.testing.expectEqual(Disposition.quarantined, try authority.admit(conflicted, &.{key.public_key}, 2_000, 66, false));
    try std.testing.expect(authority.liveByNick("GuestC", 2_000) == null);
    try std.testing.expect(authority.forwardAt(0, 2_000) == null);
    try std.testing.expectError(error.UnroutableHop, authority.admit(first, &.{key.public_key}, 1_000, 0, false));
}

test "guest route tie-break is origin then guest and direct identities do not evict a fresh body" {
    const allocator = std.testing.allocator;
    var low = try sign.KeyPair.fromSeed(@splat(1));
    defer low.deinit();
    var high = try sign.KeyPair.fromSeed(@splat(255));
    defer high.deinit();
    var authority = try Authority.create(allocator);
    defer authority.destroy();
    const a = try present(&high, 2, "Same", 1);
    defer allocator.free(a);
    const b = try present(&low, 9, "Same", 1);
    defer allocator.free(b);
    try std.testing.expectEqual(Disposition.inserted, try authority.admit(a, &.{ high.public_key, low.public_key }, 1_000, 1, false));
    try std.testing.expectEqual(Disposition.inserted, try authority.admit(b, &.{ high.public_key, low.public_key }, 1_000, 2, false));
    const winner = authority.liveByNick("Same", 1_000).?;
    const smaller = std.mem.order(u8, &low.public_key, &high.public_key) == .lt;
    try std.testing.expectEqualSlices(u8, if (smaller) &low.public_key else &high.public_key, &winner.origin);
    try authority.observeDirect(low.public_key, 4, 1_000, 1_000);
    try std.testing.expectError(error.Duplicate, authority.observeDirect(low.public_key, 4, 1_000, 1_500));
    var index: usize = 0;
    while (index < direct_capacity - 1) : (index += 1) {
        try authority.observeDirect(low.public_key, 100 + index, 1_000, 1_000);
    }
    try std.testing.expectError(error.Saturated, authority.observeDirect(high.public_key, 999, 1_000, 1_000));
    try authority.observeDirect(high.public_key, 999, 1_000, 1_000 + direct_max_age_ms);
}
