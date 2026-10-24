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
const frontier = @import("../proto/mesh_presence_frontier.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");
const store_mod = @import("mesh_presence_store.zig");

pub const max_sent_peers = 16;
pub const direct_capacity = 128;
pub const direct_max_age_ms: i64 = 120_000;
pub const Error = store_mod.Error || error{ UnroutableHop, Duplicate, Saturated, RoutePlanActive };
pub const Disposition = store_mod.Disposition;

/// Route identity is independent of retained-store order. A complete frontier
/// may compact and reorder entries while the signed subject key stays stable.
pub const RouteKey = struct {
    origin: sign.PublicKey,
    guest: wire.GuestId,
};

/// One path per accepted complete origin frontier. Its subject routes may all
/// be retired by the proof, so this identity must remain separately routable.
pub const FrontierKey = struct {
    origin: sign.PublicKey,
    epoch: u64,
    revision: u64,
};

pub const FrontierProjection = struct {
    proof: frontier.Decoded,
    hop: u64,
    local: bool,
};

const FrontierPath = struct {
    next_hop: u64,
    local: bool,
    sent: [max_sent_peers]u64 = @splat(0),
    sent_count: u8 = 0,
};

const FrontierMap = std.AutoHashMapUnmanaged(FrontierKey, FrontierPath);

const ManagerPath = struct {
    revision: u64,
    operation: wire.Operation,
    next_hop: u64,
    local: bool,
    sent: [max_sent_peers]u64 = @splat(0),
    sent_count: u8 = 0,
};

const RouteMap = std.AutoHashMapUnmanaged(RouteKey, ManagerPath);

/// Path-only state for the durable mesh-presence authority. It deliberately
/// does not own a Store: the persistent authority prepares record mutations,
/// then this manager reserves its complete post-commit route image. Both
/// commits occur under the same external lock.
pub const RouteManager = struct {
    pub const Config = struct {
        max_routes: usize = 4096,
        clock: wire.ClockPolicy = .{ .max_lifetime_ms = 120_000, .max_future_skew_ms = 30_000 },
    };

    pub const Admission = struct {
        original: []const u8,
        roots: []const sign.PublicKey,
        now_ms: i64,
        hop: u64,
        local: bool,
    };

    pub const RouteView = struct {
        revision: u64,
        next_hop: u64,
        local: bool,
    };

    pub const FrontierView = struct {
        next_hop: u64,
        local: bool,
    };

    allocator: std.mem.Allocator,
    config: Config,
    routes: RouteMap = .empty,
    frontier_routes: FrontierMap = .empty,
    active_plan: bool = false,

    pub fn init(allocator: std.mem.Allocator, config: Config) !RouteManager {
        if (config.max_routes == 0 or config.clock.max_lifetime_ms <= 0 or config.clock.max_future_skew_ms < 0) return error.InvalidPlan;
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *RouteManager) void {
        std.debug.assert(!self.active_plan);
        self.routes.deinit(self.allocator);
        self.frontier_routes.deinit(self.allocator);
        self.* = undefined;
    }

    /// Validate every admission first, then build a complete candidate image.
    /// Removals run after upserts; an authenticated complete frontier projection
    /// is final and can retire only the exact origin+guest subjects it proves.
    pub fn prepareBatch(
        self: *RouteManager,
        admissions: []const Admission,
        removes: []const RouteKey,
        projection: ?FrontierProjection,
    ) Error!PreparedRoute {
        if (self.active_plan) return error.RoutePlanActive;
        if (admissions.len > self.config.max_routes or removes.len > self.config.max_routes or self.routes.count() > self.config.max_routes or self.frontier_routes.count() > self.config.max_routes) return error.Capacity;
        self.active_plan = true;
        errdefer self.active_plan = false;

        const validated = try self.allocator.alloc(ValidatedAdmission, admissions.len);
        defer self.allocator.free(validated);
        for (admissions, 0..) |admission, index| validated[index] = try self.validateAdmission(admission);

        const verified_projection: ?ValidatedProjection = if (projection) |value| try validateProjection(value) else null;

        const temporary_capacity = std.math.add(usize, self.routes.count(), admissions.len) catch return error.Capacity;
        const map_capacity: u32 = std.math.cast(u32, temporary_capacity) orelse return error.Capacity;
        const temporary_frontier_capacity = std.math.add(usize, self.frontier_routes.count(), if (projection == null) @as(usize, 0) else 1) catch return error.Capacity;
        const frontier_map_capacity: u32 = std.math.cast(u32, temporary_frontier_capacity) orelse return error.Capacity;
        var candidate: RouteMap = .empty;
        errdefer candidate.deinit(self.allocator);
        try candidate.ensureTotalCapacity(self.allocator, map_capacity);
        var candidate_frontiers: FrontierMap = .empty;
        errdefer candidate_frontiers.deinit(self.allocator);
        try candidate_frontiers.ensureTotalCapacity(self.allocator, frontier_map_capacity);
        var current = self.routes.iterator();
        while (current.next()) |entry| candidate.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);
        var current_frontiers = self.frontier_routes.iterator();
        while (current_frontiers.next()) |entry| candidate_frontiers.putAssumeCapacity(entry.key_ptr.*, entry.value_ptr.*);

        for (validated) |admission| {
            if (candidate.getPtr(admission.key)) |path| {
                // A duplicate or obsolete original cannot redirect a retained
                // valid path or erase its sent-peer history. Invalidation
                // clears next_hop, allowing this authenticated copy to recover
                // routing without permitting a live route redirect.
                if (admission.path.revision > path.revision) path.* = admission.path;
                if (admission.path.revision == path.revision and path.next_hop == 0 and !path.local) {
                    path.next_hop = admission.path.next_hop;
                    path.local = admission.path.local;
                }
            } else {
                candidate.putAssumeCapacity(admission.key, admission.path);
            }
        }

        for (removes) |key| {
            // A signed QUIT remains routable until an authenticated complete
            // frontier proves that its subject can be retired.
            if (candidate.get(key)) |path| {
                if (path.operation != .quit) _ = candidate.remove(key);
            }
        }

        if (verified_projection) |projection_value| {
            var iterator = candidate.iterator();
            while (iterator.next()) |entry| {
                const subject_id = wire.subject(entry.key_ptr.guest) catch return error.InvalidPlan;
                if (projection_value.proof.retires(entry.key_ptr.origin, subject_id.epoch, subject_id.counter)) candidate.removeByPtr(entry.key_ptr);
            }
            stageFrontierProjection(&candidate_frontiers, projection_value);
        }
        if (candidate.count() > self.config.max_routes or candidate_frontiers.count() > self.config.max_routes) return error.Capacity;

        return .{ .manager = self, .candidate = candidate, .candidate_frontiers = candidate_frontiers };
    }

    pub fn prepareAdmit(
        self: *RouteManager,
        original: []const u8,
        roots: []const sign.PublicKey,
        now_ms: i64,
        hop: u64,
        local: bool,
    ) Error!PreparedRoute {
        const admission = Admission{ .original = original, .roots = roots, .now_ms = now_ms, .hop = hop, .local = local };
        return self.prepareBatch(&.{admission}, &.{}, null);
    }

    pub fn prepareRemove(self: *RouteManager, origin: sign.PublicKey, guest: wire.GuestId) Error!PreparedRoute {
        return self.prepareBatch(&.{}, &.{.{ .origin = origin, .guest = guest }}, null);
    }

    pub fn prepareFrontierProjection(self: *RouteManager, proof: frontier.Decoded, hop: u64, local: bool) Error!PreparedRoute {
        return self.prepareBatch(&.{}, &.{}, .{ .proof = proof, .hop = hop, .local = local });
    }

    /// Rebuild only paths already known for exact retained subjects. A record
    /// without a matching route cannot manufacture a local owner or next hop.
    /// Matching revision preserves both route identity and sent-peer state.
    pub fn prepareRebuildFrom(self: *RouteManager, entries: []const store_mod.Entry, frontiers: []const store_mod.OriginFrontier) Error!PreparedRoute {
        if (self.active_plan) return error.RoutePlanActive;
        if (entries.len > self.config.max_routes or frontiers.len > self.config.max_routes or self.routes.count() > self.config.max_routes or self.frontier_routes.count() > self.config.max_routes) return error.Capacity;
        self.active_plan = true;
        errdefer self.active_plan = false;

        var candidate: RouteMap = .empty;
        errdefer candidate.deinit(self.allocator);
        const map_capacity: u32 = @intCast(@min(entries.len, self.routes.count()));
        try candidate.ensureTotalCapacity(self.allocator, map_capacity);
        var candidate_frontiers: FrontierMap = .empty;
        errdefer candidate_frontiers.deinit(self.allocator);
        const frontier_map_capacity: u32 = std.math.cast(u32, frontiers.len) orelse return error.Capacity;
        try candidate_frontiers.ensureTotalCapacity(self.allocator, frontier_map_capacity);

        for (entries) |entry| {
            const decoded = try wire.decode(entry.original);
            try decoded.verify();
            if (!sameRouteRecord(decoded.record, entry.decoded.record)) return error.InvalidPlan;
            const record = decoded.record;
            const key: RouteKey = .{ .origin = record.origin, .guest = record.guest };
            if (candidate.contains(key)) return error.InvalidPlan;
            const path = self.routes.get(key) orelse continue;
            if (path.revision != record.revision) continue;
            candidate.putAssumeCapacity(key, path);
        }

        for (frontiers) |item| {
            if (item.conflict != null or item.conflict_admission != null) continue;
            const decoded = try frontier.decode(item.original);
            try decoded.verify();
            if (!sameFrontierRecord(decoded, item.decoded)) return error.InvalidPlan;
            const key: FrontierKey = .{ .origin = decoded.origin, .epoch = decoded.epoch, .revision = decoded.revision };
            var existing = candidate_frontiers.iterator();
            while (existing.next()) |entry| if (std.mem.eql(u8, &entry.key_ptr.origin, &key.origin)) return error.InvalidPlan;
            candidate_frontiers.putAssumeCapacity(key, .{ .next_hop = 0, .local = false });
        }

        return .{ .manager = self, .candidate = candidate, .candidate_frontiers = candidate_frontiers };
    }

    pub fn routeFor(self: *const RouteManager, origin: sign.PublicKey, guest: wire.GuestId) ?RouteView {
        const path = self.routes.get(.{ .origin = origin, .guest = guest }) orelse return null;
        return .{ .revision = path.revision, .next_hop = path.next_hop, .local = path.local };
    }

    pub fn wantsSend(self: *const RouteManager, origin: sign.PublicKey, guest: wire.GuestId, peer: u64) bool {
        if (self.active_plan or peer == 0) return false;
        const path = self.routes.get(.{ .origin = origin, .guest = guest }) orelse return false;
        if (path.sent_count == max_sent_peers) return false;
        for (path.sent[0..path.sent_count]) |item| if (item == peer) return false;
        return true;
    }

    pub fn markSent(self: *RouteManager, origin: sign.PublicKey, guest: wire.GuestId, peer: u64) bool {
        if (!self.wantsSend(origin, guest, peer)) return false;
        const path = self.routes.getPtr(.{ .origin = origin, .guest = guest }).?;
        path.sent[path.sent_count] = peer;
        path.sent_count += 1;
        return true;
    }

    pub fn frontierFor(self: *const RouteManager, key: FrontierKey) ?FrontierView {
        const path = self.frontier_routes.get(key) orelse return null;
        return .{ .next_hop = path.next_hop, .local = path.local };
    }

    pub fn wantsFrontierSend(self: *const RouteManager, key: FrontierKey, peer: u64) bool {
        if (self.active_plan or peer == 0) return false;
        const path = self.frontier_routes.get(key) orelse return false;
        if (path.sent_count == max_sent_peers) return false;
        for (path.sent[0..path.sent_count]) |item| if (item == peer) return false;
        return true;
    }

    pub fn markFrontierSent(self: *RouteManager, key: FrontierKey, peer: u64) bool {
        if (!self.wantsFrontierSend(key, peer)) return false;
        const path = self.frontier_routes.getPtr(key).?;
        path.sent[path.sent_count] = peer;
        path.sent_count += 1;
        return true;
    }

    /// Clear this secured peer's per-round suppression on every exact subject.
    /// Call on reconnect or a bounded anti-entropy round so dropped ingress
    /// cannot remain suppressed indefinitely. No allocation or route eviction.
    pub fn resetSentPeer(self: *RouteManager, peer: u64) bool {
        if (peer == 0 or self.active_plan) return false;
        var paths = self.routes.valueIterator();
        while (paths.next()) |path| resetPathSent(path, peer);
        var frontier_paths = self.frontier_routes.valueIterator();
        while (frontier_paths.next()) |path| resetPathSent(path, peer);
        return true;
    }

    /// Link loss makes only routes that depended on this ingress unknown. A
    /// later authenticated duplicate can fill that empty path without
    /// redirecting a still-valid route. Local routes do not depend on links.
    pub fn invalidatePeer(self: *RouteManager, peer: u64) bool {
        if (peer == 0 or self.active_plan) return false;
        var paths = self.routes.valueIterator();
        while (paths.next()) |path| {
            if (!path.local and path.next_hop == peer) {
                path.next_hop = 0;
                path.local = false;
            }
            resetPathSent(path, peer);
        }
        var frontier_paths = self.frontier_routes.valueIterator();
        while (frontier_paths.next()) |path| {
            if (!path.local and path.next_hop == peer) {
                path.next_hop = 0;
                path.local = false;
            }
            resetPathSent(path, peer);
        }
        return true;
    }

    const ValidatedAdmission = struct {
        key: RouteKey,
        path: ManagerPath,
    };

    const ValidatedProjection = struct {
        proof: frontier.Decoded,
        key: FrontierKey,
        path: FrontierPath,
    };

    fn validateAdmission(self: *const RouteManager, admission: Admission) Error!ValidatedAdmission {
        if (admission.local != (admission.hop == 0)) return error.UnroutableHop;
        const decoded = try wire.decode(admission.original);
        try decoded.verify();
        try approved(decoded.record.origin, admission.roots);
        self.config.clock.validate(decoded.record, admission.now_ms) catch |err| {
            // Expired signed tombstones may be repaired by the durable store;
            // positive records remain bound to the current clock policy.
            if (decoded.record.operation != .quit or err != error.Expired) return err;
        };
        return .{
            .key = .{ .origin = decoded.record.origin, .guest = decoded.record.guest },
            .path = .{
                .revision = decoded.record.revision,
                .operation = decoded.record.operation,
                .next_hop = admission.hop,
                .local = admission.local,
            },
        };
    }

    pub const PreparedRoute = struct {
        manager: *RouteManager,
        candidate: RouteMap,
        candidate_frontiers: FrontierMap,
        done: bool = false,

        pub fn abort(self: *PreparedRoute) void {
            if (self.done) return;
            self.candidate.deinit(self.manager.allocator);
            self.candidate_frontiers.deinit(self.manager.allocator);
            self.manager.active_plan = false;
            self.done = true;
        }

        /// Swap the fully allocated image after durable authority commits.
        /// This operation cannot allocate or fail.
        pub fn commit(self: *PreparedRoute) void {
            std.debug.assert(!self.done and self.manager.active_plan);
            var previous = self.manager.routes;
            var previous_frontiers = self.manager.frontier_routes;
            self.manager.routes = self.candidate;
            self.manager.frontier_routes = self.candidate_frontiers;
            self.candidate = .empty;
            self.candidate_frontiers = .empty;
            previous.deinit(self.manager.allocator);
            previous_frontiers.deinit(self.manager.allocator);
            self.manager.active_plan = false;
            self.done = true;
        }

        pub fn deinit(self: *PreparedRoute) void {
            self.abort();
        }
    };
};

fn approved(origin: sign.PublicKey, roots: []const sign.PublicKey) Error!void {
    var found = false;
    const short = signed_frame.originShortId(origin);
    for (roots) |root| {
        if (std.mem.eql(u8, &root, &origin)) found = true else if (signed_frame.originShortId(root) == short) return error.OriginCollision;
    }
    if (!found) return error.UnapprovedOrigin;
}

fn validateProjection(projection: FrontierProjection) Error!RouteManager.ValidatedProjection {
    if (projection.local != (projection.hop == 0)) return error.UnroutableHop;
    const decoded = try frontier.decode(projection.proof.wire);
    try decoded.verify();
    if (!std.mem.eql(u8, &decoded.origin, &projection.proof.origin) or decoded.epoch != projection.proof.epoch or decoded.revision != projection.proof.revision or decoded.through != projection.proof.through or decoded.issued_ms != projection.proof.issued_ms or !std.mem.eql(u8, decoded.active_bytes, projection.proof.active_bytes)) return error.InvalidPlan;
    return .{
        .proof = decoded,
        .key = .{ .origin = decoded.origin, .epoch = decoded.epoch, .revision = decoded.revision },
        .path = .{ .next_hop = projection.hop, .local = projection.local },
    };
}

fn stageFrontierProjection(routes: *FrontierMap, projection: RouteManager.ValidatedProjection) void {
    var latest_key: ?FrontierKey = null;
    var iterator = routes.iterator();
    while (iterator.next()) |entry| {
        if (!std.mem.eql(u8, &entry.key_ptr.origin, &projection.key.origin)) continue;
        if (latest_key == null or frontierKeyPrecedes(latest_key.?, entry.key_ptr.*)) {
            latest_key = entry.key_ptr.*;
        }
    }
    if (latest_key) |current| {
        if (frontierKeyPrecedes(current, projection.key)) {
            _ = routes.remove(current);
            routes.putAssumeCapacity(projection.key, projection.path);
        } else if (std.meta.eql(current, projection.key)) {
            const path = routes.getPtr(current).?;
            if (path.next_hop == 0 and !path.local) {
                path.next_hop = projection.path.next_hop;
                path.local = projection.path.local;
            }
        }
    } else {
        routes.putAssumeCapacity(projection.key, projection.path);
    }
}

fn frontierKeyPrecedes(a: FrontierKey, b: FrontierKey) bool {
    return a.epoch < b.epoch or (a.epoch == b.epoch and a.revision < b.revision);
}

fn sameFrontierRecord(a: frontier.Decoded, b: frontier.Decoded) bool {
    return std.mem.eql(u8, &a.origin, &b.origin) and a.epoch == b.epoch and a.revision == b.revision and a.through == b.through and a.issued_ms == b.issued_ms and std.mem.eql(u8, a.active_bytes, b.active_bytes);
}

fn resetPathSent(path: anytype, peer: u64) void {
    var write_index: usize = 0;
    for (path.sent[0..path.sent_count]) |sent_peer| {
        if (sent_peer == peer) continue;
        path.sent[write_index] = sent_peer;
        write_index += 1;
    }
    @memset(path.sent[write_index..], 0);
    path.sent_count = @intCast(write_index);
}

fn sameRouteRecord(a: wire.Record, b: wire.Record) bool {
    return std.mem.eql(u8, &a.origin, &b.origin) and std.mem.eql(u8, &a.guest, &b.guest) and a.revision == b.revision and a.operation == b.operation;
}

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

test "route manager keys exact origin and guest, preserves duplicates, and resets sent peers on renewal" {
    const allocator = std.testing.allocator;
    var first_key = try sign.KeyPair.fromSeed(@splat(31));
    defer first_key.deinit();
    var second_key = try sign.KeyPair.fromSeed(@splat(32));
    defer second_key.deinit();

    const first = try present(&first_key, 17, "First", 1);
    defer allocator.free(first);
    const other_origin = try present(&second_key, 17, "OtherOrigin", 1);
    defer allocator.free(other_origin);
    const other_guest = try present(&first_key, 18, "OtherGuest", 1);
    defer allocator.free(other_guest);

    var manager = try RouteManager.init(allocator, .{});
    defer manager.deinit();
    var initial = try manager.prepareAdmit(first, &.{ first_key.public_key, second_key.public_key }, 1_000, 41, false);
    try std.testing.expect(!manager.resetSentPeer(90));
    try std.testing.expect(manager.routeFor(first_key.public_key, (try wire.decode(first)).record.guest) == null);
    initial.commit();

    var second = try manager.prepareAdmit(other_origin, &.{ first_key.public_key, second_key.public_key }, 1_000, 42, false);
    second.commit();
    var third = try manager.prepareAdmit(other_guest, &.{ first_key.public_key, second_key.public_key }, 1_000, 43, false);
    third.commit();

    const first_guest = (try wire.decode(first)).record.guest;
    const other_origin_guest = (try wire.decode(other_origin)).record.guest;
    const other_guest_id = (try wire.decode(other_guest)).record.guest;
    try std.testing.expectEqual(@as(u64, 41), manager.routeFor(first_key.public_key, first_guest).?.next_hop);
    try std.testing.expectEqual(@as(u64, 42), manager.routeFor(second_key.public_key, other_origin_guest).?.next_hop);
    try std.testing.expectEqual(@as(u64, 43), manager.routeFor(first_key.public_key, other_guest_id).?.next_hop);

    try std.testing.expect(manager.markSent(first_key.public_key, first_guest, 90));
    try std.testing.expect(manager.markSent(first_key.public_key, first_guest, 91));
    try std.testing.expect(manager.markSent(second_key.public_key, other_origin_guest, 90));
    var duplicate = try manager.prepareAdmit(first, &.{ first_key.public_key, second_key.public_key }, 1_000, 99, false);
    duplicate.commit();
    try std.testing.expectEqual(@as(u64, 41), manager.routeFor(first_key.public_key, first_guest).?.next_hop);
    try std.testing.expect(!manager.wantsSend(first_key.public_key, first_guest, 90));
    try std.testing.expect(!manager.resetSentPeer(0));
    try std.testing.expect(manager.resetSentPeer(90));
    try std.testing.expect(manager.wantsSend(first_key.public_key, first_guest, 90));
    try std.testing.expect(!manager.wantsSend(first_key.public_key, first_guest, 91));
    try std.testing.expect(manager.wantsSend(second_key.public_key, other_origin_guest, 90));

    var renewed_record = (try wire.decode(first)).record;
    renewed_record.revision = 2;
    renewed_record.issued_ms = 2_000;
    renewed_record.expires_ms = 122_000;
    var renewed_buffer: [wire.max_wire_len]u8 = undefined;
    const renewed = try wire.encode(renewed_record, &first_key, &renewed_buffer);
    var renewal = try manager.prepareAdmit(renewed, &.{ first_key.public_key, second_key.public_key }, 2_000, 44, false);
    renewal.commit();
    try std.testing.expectEqual(@as(u64, 2), manager.routeFor(first_key.public_key, first_guest).?.revision);
    try std.testing.expectEqual(@as(u64, 44), manager.routeFor(first_key.public_key, first_guest).?.next_hop);
    try std.testing.expect(manager.wantsSend(first_key.public_key, first_guest, 90));
}

test "route manager retains quit paths until a verified frontier projection commits" {
    const allocator = std.testing.allocator;
    var origin = try sign.KeyPair.fromSeed(@splat(41));
    defer origin.deinit();
    var other_origin = try sign.KeyPair.fromSeed(@splat(42));
    defer other_origin.deinit();

    const present_target = try present(&origin, 24, "Target", 1);
    defer allocator.free(present_target);
    const present_sibling = try present(&origin, 25, "Sibling", 1);
    defer allocator.free(present_sibling);
    const present_other = try present(&other_origin, 24, "Other", 1);
    defer allocator.free(present_other);

    var quit_record = (try wire.decode(present_target)).record;
    quit_record.operation = .quit;
    quit_record.revision = 2;
    quit_record.issued_ms = 2_000;
    quit_record.expires_ms = 122_000;
    var quit_buffer: [wire.max_wire_len]u8 = undefined;
    const quit = try wire.encode(quit_record, &origin, &quit_buffer);

    var manager = try RouteManager.init(allocator, .{});
    defer manager.deinit();
    var first = try manager.prepareAdmit(present_target, &.{ origin.public_key, other_origin.public_key }, 1_000, 51, false);
    first.commit();
    var sibling = try manager.prepareAdmit(present_sibling, &.{ origin.public_key, other_origin.public_key }, 1_000, 52, false);
    sibling.commit();
    var other = try manager.prepareAdmit(present_other, &.{ origin.public_key, other_origin.public_key }, 1_000, 53, false);
    other.commit();
    var tombstone = try manager.prepareAdmit(quit, &.{origin.public_key}, 2_000, 54, false);
    tombstone.commit();

    const target_guest = quit_record.guest;
    const sibling_guest = (try wire.decode(present_sibling)).record.guest;
    const other_guest_id = (try wire.decode(present_other)).record.guest;
    try std.testing.expectEqual(@as(u64, 2), manager.routeFor(origin.public_key, target_guest).?.revision);
    try std.testing.expectEqual(@as(u64, 54), manager.routeFor(origin.public_key, target_guest).?.next_hop);

    var premature_remove = try manager.prepareRemove(origin.public_key, target_guest);
    premature_remove.commit();
    try std.testing.expect(manager.routeFor(origin.public_key, target_guest) != null);

    var proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const target_subject = try wire.subject(target_guest);
    const proof_wire = try frontier.encode(.{ .origin = origin.public_key, .epoch = target_subject.epoch, .revision = 1, .through = target_subject.counter + 1, .issued_ms = 2_000, .active = &.{} }, &origin, &proof_buffer);
    const proof = try frontier.decode(proof_wire);
    const frontier_key: FrontierKey = .{ .origin = proof.origin, .epoch = proof.epoch, .revision = proof.revision };
    var projection = try manager.prepareFrontierProjection(proof, 58, false);
    try std.testing.expect(manager.routeFor(origin.public_key, target_guest) != null);
    try std.testing.expect(manager.frontierFor(frontier_key) == null);
    projection.commit();

    try std.testing.expect(manager.routeFor(origin.public_key, target_guest) == null);
    try std.testing.expect(manager.routeFor(origin.public_key, sibling_guest) == null);
    try std.testing.expect(manager.routeFor(other_origin.public_key, other_guest_id) != null);
    try std.testing.expectEqual(@as(u64, 58), manager.frontierFor(frontier_key).?.next_hop);

    var other_proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const other_proof_wire = try frontier.encode(.{ .origin = other_origin.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 2_000, .active = &.{} }, &other_origin, &other_proof_buffer);
    const other_proof = try frontier.decode(other_proof_wire);
    const other_frontier_key: FrontierKey = .{ .origin = other_proof.origin, .epoch = other_proof.epoch, .revision = other_proof.revision };
    var other_projection = try manager.prepareFrontierProjection(other_proof, 60, false);
    other_projection.commit();
    try std.testing.expectEqual(@as(u64, 58), manager.frontierFor(frontier_key).?.next_hop);
    try std.testing.expectEqual(@as(u64, 60), manager.frontierFor(other_frontier_key).?.next_hop);

    try std.testing.expect(manager.markFrontierSent(frontier_key, 99));
    try std.testing.expect(!manager.wantsFrontierSend(frontier_key, 99));
    try std.testing.expect(manager.markSent(other_origin.public_key, other_guest_id, 99));
    try std.testing.expect(!manager.wantsSend(other_origin.public_key, other_guest_id, 99));
    try std.testing.expect(manager.resetSentPeer(99));
    try std.testing.expect(manager.wantsFrontierSend(frontier_key, 99));
    try std.testing.expect(manager.wantsSend(other_origin.public_key, other_guest_id, 99));
    try std.testing.expect(manager.markFrontierSent(frontier_key, 99));
    try std.testing.expect(manager.markSent(other_origin.public_key, other_guest_id, 99));
    var duplicate_projection = try manager.prepareFrontierProjection(proof, 59, false);
    duplicate_projection.commit();
    try std.testing.expectEqual(@as(u64, 58), manager.frontierFor(frontier_key).?.next_hop);
    try std.testing.expect(!manager.wantsFrontierSend(frontier_key, 99));
    try std.testing.expect(!manager.wantsSend(other_origin.public_key, other_guest_id, 99));

    var newer_proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const newer_wire = try frontier.encode(.{ .origin = origin.public_key, .epoch = proof.epoch, .revision = 2, .through = proof.through, .issued_ms = 2_100, .active = &.{} }, &origin, &newer_proof_buffer);
    const newer_proof = try frontier.decode(newer_wire);
    const newer_key: FrontierKey = .{ .origin = newer_proof.origin, .epoch = newer_proof.epoch, .revision = newer_proof.revision };
    var newer_projection = try manager.prepareFrontierProjection(newer_proof, 59, false);
    newer_projection.commit();
    try std.testing.expect(manager.frontierFor(frontier_key) == null);
    try std.testing.expectEqual(@as(u64, 59), manager.frontierFor(newer_key).?.next_hop);
    try std.testing.expect(manager.frontierFor(other_frontier_key) != null);
}

test "failed route preparation preserves published paths and batch removal can free bounded capacity" {
    const allocator = std.testing.allocator;
    var origin = try sign.KeyPair.fromSeed(@splat(51));
    defer origin.deinit();
    const first = try present(&origin, 31, "First", 1);
    defer allocator.free(first);
    const second = try present(&origin, 32, "Second", 1);
    defer allocator.free(second);
    const first_guest = (try wire.decode(first)).record.guest;
    const second_guest = (try wire.decode(second)).record.guest;

    var manager = try RouteManager.init(allocator, .{ .max_routes = 1 });
    defer manager.deinit();
    var initial = try manager.prepareAdmit(first, &.{origin.public_key}, 1_000, 61, false);
    initial.commit();

    try std.testing.expectError(error.Capacity, manager.prepareAdmit(second, &.{origin.public_key}, 1_000, 62, false));
    try std.testing.expectEqual(@as(u64, 61), manager.routeFor(origin.public_key, first_guest).?.next_hop);
    try std.testing.expect(manager.routeFor(origin.public_key, second_guest) == null);

    var replacement = try manager.prepareBatch(
        &.{.{ .original = second, .roots = &.{origin.public_key}, .now_ms = 1_000, .hop = 62, .local = false }},
        &.{.{ .origin = origin.public_key, .guest = first_guest }},
        null,
    );
    replacement.commit();
    try std.testing.expect(manager.routeFor(origin.public_key, first_guest) == null);
    try std.testing.expectEqual(@as(u64, 62), manager.routeFor(origin.public_key, second_guest).?.next_hop);
}

test "route manager batch preparation retries every allocation failure and abort keeps the old image" {
    const allocator = std.testing.allocator;
    var origin = try sign.KeyPair.fromSeed(@splat(56));
    defer origin.deinit();
    const first = try present(&origin, 36, "First", 1);
    defer allocator.free(first);
    const second = try present(&origin, 37, "Second", 1);
    defer allocator.free(second);
    const first_guest = (try wire.decode(first)).record.guest;
    const second_guest = (try wire.decode(second)).record.guest;
    const admission = RouteManager.Admission{ .original = second, .roots = &.{origin.public_key}, .now_ms = 1_000, .hop = 82, .local = false };
    var proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const proof_wire = try frontier.encode(.{ .origin = origin.public_key, .epoch = 1, .revision = 1, .through = 36, .issued_ms = 1_000, .active = &.{} }, &origin, &proof_buffer);
    const proof = try frontier.decode(proof_wire);
    const projection: ?FrontierProjection = .{ .proof = proof, .hop = 83, .local = false };
    const frontier_key: FrontierKey = .{ .origin = origin.public_key, .epoch = 1, .revision = 1 };

    var failures: usize = 0;
    var saw_success_sentinel = false;
    for (0..16) |fail_at| {
        var fault = std.testing.FailingAllocator.init(allocator, .{});
        {
            var manager = try RouteManager.init(fault.allocator(), .{});
            var initial = try manager.prepareAdmit(first, &.{origin.public_key}, 1_000, 81, false);
            initial.commit();
            try std.testing.expect(manager.markSent(origin.public_key, first_guest, 91));
            const before = manager.routeFor(origin.public_key, first_guest).?;

            // Re-arm at each index after setup so the sweep covers only the
            // candidate allocation points in this batch.
            fault.alloc_index = 0;
            fault.fail_index = fail_at;
            const attempted = manager.prepareBatch(&.{admission}, &.{}, projection);
            if (attempted) |prepared_value| {
                var prepared = prepared_value;
                try std.testing.expect(!fault.has_induced_failure);
                saw_success_sentinel = true;
                prepared.abort();
                try std.testing.expectEqualDeep(before, manager.routeFor(origin.public_key, first_guest).?);
                try std.testing.expect(manager.wantsSend(origin.public_key, first_guest, 91) == false);
                try std.testing.expect(manager.routeFor(origin.public_key, second_guest) == null);
                try std.testing.expect(manager.frontierFor(frontier_key) == null);

                fault.fail_index = std.math.maxInt(usize);
                fault.alloc_index = 0;
                var retry = try manager.prepareBatch(&.{admission}, &.{}, projection);
                retry.commit();
                try std.testing.expect(manager.routeFor(origin.public_key, first_guest) == null);
                try std.testing.expectEqual(@as(u64, 82), manager.routeFor(origin.public_key, second_guest).?.next_hop);
                try std.testing.expectEqual(@as(u64, 83), manager.frontierFor(frontier_key).?.next_hop);
                manager.deinit();
                try std.testing.expectEqual(fault.allocated_bytes, fault.freed_bytes);
                break;
            } else |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(fault.has_induced_failure);
                failures += 1;
                try std.testing.expectEqualDeep(before, manager.routeFor(origin.public_key, first_guest).?);
                try std.testing.expect(!manager.wantsSend(origin.public_key, first_guest, 91));
                try std.testing.expect(manager.routeFor(origin.public_key, second_guest) == null);
                try std.testing.expect(manager.frontierFor(frontier_key) == null);

                // A completed allocation plan can be aborted without changing
                // any route; the next completed plan is safe to publish.
                fault.fail_index = std.math.maxInt(usize);
                fault.alloc_index = 0;
                var abort_plan = try manager.prepareBatch(&.{admission}, &.{}, projection);
                abort_plan.abort();
                try std.testing.expectEqualDeep(before, manager.routeFor(origin.public_key, first_guest).?);
                try std.testing.expect(manager.routeFor(origin.public_key, second_guest) == null);
                try std.testing.expect(manager.frontierFor(frontier_key) == null);
                var retry = try manager.prepareBatch(&.{admission}, &.{}, projection);
                retry.commit();
                try std.testing.expect(manager.routeFor(origin.public_key, first_guest) == null);
                try std.testing.expectEqual(@as(u64, 82), manager.routeFor(origin.public_key, second_guest).?.next_hop);
                try std.testing.expectEqual(@as(u64, 83), manager.frontierFor(frontier_key).?.next_hop);
                manager.deinit();
                try std.testing.expectEqual(fault.allocated_bytes, fault.freed_bytes);
            }
        }
    }
    try std.testing.expect(failures > 0);
    try std.testing.expect(saw_success_sentinel);
}

test "route rebuild preserves only exact known paths and never invents a local owner" {
    const allocator = std.testing.allocator;
    var origin = try sign.KeyPair.fromSeed(@splat(61));
    defer origin.deinit();
    var absent_origin = try sign.KeyPair.fromSeed(@splat(62));
    defer absent_origin.deinit();
    const known = try present(&origin, 41, "Known", 1);
    defer allocator.free(known);
    const without_route = try present(&absent_origin, 42, "NoRoute", 1);
    defer allocator.free(without_route);
    const known_guest = (try wire.decode(known)).record.guest;
    const absent_guest = (try wire.decode(without_route)).record.guest;

    var manager = try RouteManager.init(allocator, .{});
    defer manager.deinit();
    var admitted = try manager.prepareAdmit(known, &.{origin.public_key}, 1_000, 71, false);
    admitted.commit();
    try std.testing.expect(manager.markSent(origin.public_key, known_guest, 77));

    var store = try store_mod.Store.init(allocator, .{});
    defer store.deinit();
    var known_plan = try store.prepare(known, &.{origin.public_key}, 1_000);
    defer known_plan.abort();
    _ = known_plan.commit();
    var absent_plan = try store.prepare(without_route, &.{absent_origin.public_key}, 1_000);
    defer absent_plan.abort();
    _ = absent_plan.commit();

    var proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const retained_proof = try frontier.encode(.{ .origin = absent_origin.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 1_000, .active = &.{} }, &absent_origin, &proof_buffer);
    var frontier_plan = try store.prepareFrontier(retained_proof, &.{absent_origin.public_key}, 1_000);
    defer frontier_plan.abort();
    _ = frontier_plan.commit();

    var rebuilt = try manager.prepareRebuildFrom(store.entries.items, store.frontiers.items);
    rebuilt.commit();
    const retained_path = manager.routeFor(origin.public_key, known_guest).?;
    try std.testing.expectEqual(@as(u64, 71), retained_path.next_hop);
    try std.testing.expect(!retained_path.local);
    try std.testing.expect(!manager.wantsSend(origin.public_key, known_guest, 77));
    try std.testing.expect(manager.routeFor(absent_origin.public_key, absent_guest) == null);
    const retained_frontier: FrontierKey = .{ .origin = absent_origin.public_key, .epoch = 1, .revision = 1 };
    const frontier_path = manager.frontierFor(retained_frontier).?;
    try std.testing.expectEqual(@as(u64, 0), frontier_path.next_hop);
    try std.testing.expect(!frontier_path.local);
    try std.testing.expect(manager.wantsFrontierSend(retained_frontier, 77));
}

test "route peer invalidation clears suppression and authenticated duplicates refresh only unknown paths" {
    const allocator = std.testing.allocator;
    var remote = try sign.KeyPair.fromSeed(@splat(71));
    defer remote.deinit();
    var local = try sign.KeyPair.fromSeed(@splat(72));
    defer local.deinit();
    const remote_original = try present(&remote, 51, "Remote", 1);
    defer allocator.free(remote_original);
    const local_original = try present(&local, 52, "Local", 1);
    defer allocator.free(local_original);
    const remote_guest = (try wire.decode(remote_original)).record.guest;
    const local_guest = (try wire.decode(local_original)).record.guest;

    var proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const proof_wire = try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 51, .issued_ms = 1_000, .active = &.{51} }, &remote, &proof_buffer);
    const proof = try frontier.decode(proof_wire);
    const frontier_key: FrontierKey = .{ .origin = remote.public_key, .epoch = proof.epoch, .revision = proof.revision };
    var local_proof_buffer: [frontier.max_wire_len]u8 = undefined;
    const local_proof_wire = try frontier.encode(.{ .origin = local.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 1_000, .active = &.{} }, &local, &local_proof_buffer);
    const local_proof = try frontier.decode(local_proof_wire);
    const local_frontier_key: FrontierKey = .{ .origin = local.public_key, .epoch = 1, .revision = 1 };

    var manager = try RouteManager.init(allocator, .{});
    defer manager.deinit();
    var remote_plan = try manager.prepareAdmit(remote_original, &.{remote.public_key}, 1_000, 70, false);
    remote_plan.commit();
    var local_plan = try manager.prepareAdmit(local_original, &.{local.public_key}, 1_000, 0, true);
    local_plan.commit();
    var frontier_plan = try manager.prepareFrontierProjection(proof, 70, false);
    frontier_plan.commit();
    var local_frontier_plan = try manager.prepareFrontierProjection(local_proof, 0, true);
    local_frontier_plan.commit();

    try std.testing.expect(manager.markSent(remote.public_key, remote_guest, 70));
    try std.testing.expect(manager.markSent(remote.public_key, remote_guest, 88));
    try std.testing.expect(manager.markSent(local.public_key, local_guest, 70));
    try std.testing.expect(manager.markSent(local.public_key, local_guest, 88));
    try std.testing.expect(manager.markFrontierSent(frontier_key, 70));
    try std.testing.expect(manager.markFrontierSent(frontier_key, 88));
    try std.testing.expect(manager.markFrontierSent(local_frontier_key, 70));
    try std.testing.expect(manager.markFrontierSent(local_frontier_key, 88));

    try std.testing.expect(manager.invalidatePeer(70));
    try std.testing.expectEqual(@as(u64, 0), manager.routeFor(remote.public_key, remote_guest).?.next_hop);
    try std.testing.expect(!manager.routeFor(remote.public_key, remote_guest).?.local);
    try std.testing.expectEqual(@as(u64, 0), manager.frontierFor(frontier_key).?.next_hop);
    try std.testing.expect(!manager.frontierFor(frontier_key).?.local);
    try std.testing.expectEqual(@as(u64, 0), manager.frontierFor(local_frontier_key).?.next_hop);
    try std.testing.expect(manager.frontierFor(local_frontier_key).?.local);
    try std.testing.expectEqual(@as(u64, 0), manager.routeFor(local.public_key, local_guest).?.next_hop);
    try std.testing.expect(manager.routeFor(local.public_key, local_guest).?.local);
    try std.testing.expect(manager.wantsSend(remote.public_key, remote_guest, 70));
    try std.testing.expect(!manager.wantsSend(remote.public_key, remote_guest, 88));
    try std.testing.expect(manager.wantsSend(local.public_key, local_guest, 70));
    try std.testing.expect(!manager.wantsSend(local.public_key, local_guest, 88));
    try std.testing.expect(manager.wantsFrontierSend(frontier_key, 70));
    try std.testing.expect(!manager.wantsFrontierSend(frontier_key, 88));
    try std.testing.expect(manager.wantsFrontierSend(local_frontier_key, 70));
    try std.testing.expect(!manager.wantsFrontierSend(local_frontier_key, 88));

    var refresh = try manager.prepareAdmit(remote_original, &.{remote.public_key}, 1_000, 72, false);
    refresh.commit();
    try std.testing.expectEqual(@as(u64, 72), manager.routeFor(remote.public_key, remote_guest).?.next_hop);
    var still_valid = try manager.prepareAdmit(remote_original, &.{remote.public_key}, 1_000, 73, false);
    still_valid.commit();
    try std.testing.expectEqual(@as(u64, 72), manager.routeFor(remote.public_key, remote_guest).?.next_hop);

    var frontier_refresh = try manager.prepareFrontierProjection(proof, 72, false);
    frontier_refresh.commit();
    try std.testing.expectEqual(@as(u64, 72), manager.frontierFor(frontier_key).?.next_hop);
    var frontier_still_valid = try manager.prepareFrontierProjection(proof, 73, false);
    frontier_still_valid.commit();
    try std.testing.expectEqual(@as(u64, 72), manager.frontierFor(frontier_key).?.next_hop);
}
