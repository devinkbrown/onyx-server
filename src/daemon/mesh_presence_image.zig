// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical complete retained-presence image. Encoding projects a prepared
//! change before RAM publication; restoration authenticates the local durable
//! envelope first and owns all reconstructed bytes until a no-fail swap.
//! All borrowed store/plan/durable rows require the same external owner lock.
//! This leaf grants no path, physical attachment or hot issuer custody.
const std = @import("std");
const retained = @import("mesh_presence_retained.zig");
const presence = @import("mesh_presence_store.zig");
const persistence = @import("store.zig");
const wire = @import("../proto/mesh_presence_v2.zig");
const frontier = @import("../proto/mesh_presence_frontier.zig");

pub const header_len: usize = 13;
pub const max_row_overhead: usize = 9 + 2 * presence.AdmissionStamp.encoded_len;
pub const Error = error{ InvalidImage, InvalidPlan, Capacity, AccountingMismatch };
pub const Change = presence.Store.ProjectionChange;

pub const Image = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    entries: u32,
    frontiers: u32,
    retained_bytes: usize,

    pub fn deinit(self: *Image) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn maxEncodedLen(config: presence.Config) Error!usize {
    const rows = std.math.add(usize, config.max_entries, config.max_origins) catch return error.Capacity;
    const overhead = std.math.mul(usize, rows, max_row_overhead) catch return error.Capacity;
    const bytes = std.math.add(usize, config.max_bytes, overhead) catch return error.Capacity;
    return std.math.add(usize, header_len, bytes) catch return error.Capacity;
}

fn add(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.Capacity;
}

fn entryLess(_: void, a: presence.Entry, b: presence.Entry) bool {
    const before = a.decoded.record;
    const after = b.decoded.record;
    const order = std.mem.order(u8, &before.origin, &after.origin);
    return order == .lt or (order == .eq and std.mem.order(u8, &before.guest, &after.guest) == .lt);
}
fn frontierLess(_: void, a: presence.OriginFrontier, b: presence.OriginFrontier) bool {
    return std.mem.order(u8, &a.decoded.origin, &b.decoded.origin) == .lt;
}

fn validateEntry(entry: presence.Entry) !presence.Entry {
    var result = entry;
    result.decoded = try wire.decode(entry.original);
    try entry.admission.validatePresence(result.decoded);
    if (entry.conflict) |bytes| {
        const stamp = entry.conflict_admission orelse return error.InvalidImage;
        const decoded = try wire.decode(bytes);
        try stamp.validatePresence(decoded);
        if ((try presence.Store.comparePresence(result.decoded, decoded)) != .quarantined) return error.InvalidImage;
    } else if (entry.conflict_admission != null) return error.InvalidImage;
    return result;
}
fn validateFrontier(item: presence.OriginFrontier) !presence.OriginFrontier {
    var result = item;
    result.decoded = try frontier.decode(item.original);
    try item.admission.validateFrontier(result.decoded);
    if (item.conflict) |bytes| {
        const stamp = item.conflict_admission orelse return error.InvalidImage;
        const decoded = try frontier.decode(bytes);
        try stamp.validateFrontier(decoded);
        if ((try frontier.compare(result.decoded, decoded)) != .conflict) return error.InvalidImage;
    } else if (item.conflict_admission != null) return error.InvalidImage;
    return result;
}

fn covered(entry: presence.Entry, item: presence.OriginFrontier) bool {
    if (entry.conflict != null or item.conflict != null) return false;
    const id = wire.subject(entry.decoded.record.guest) catch unreachable;
    return item.decoded.retires(entry.decoded.record.origin, id.epoch, id.counter);
}

fn normalized(entries: []const presence.Entry, frontiers: []const presence.OriginFrontier) Error!void {
    var index: usize = 0;
    for (entries) |entry| {
        while (index < frontiers.len and std.mem.order(u8, &frontiers[index].decoded.origin, &entry.decoded.record.origin) == .lt) index += 1;
        if (index < frontiers.len and covered(entry, frontiers[index])) return error.InvalidImage;
    }
}

/// Project exactly one sole prepared handle under its owner lock. This returns
/// owned bytes only; no plan is consumed and no live state is changed. Caller
/// must durably publish the authenticated aggregate before committing RAM.
pub fn encodeProjection(allocator: std.mem.Allocator, store: *const presence.Store, change: Change) !Image {
    _ = try maxEncodedLen(store.config);
    const projection = try store.project(change);
    // A normalized terminal candidate still requires its signed admission.
    // Certified GC cannot turn invalid original bytes into a valid image.
    if (projection.entry_candidate) |candidate| if (!projection.candidate_survives) {
        _ = try validateEntry(candidate);
    };
    for (projection.subject_changes) |subject| if (subject.candidate) |candidate| if (!subject.candidate_survives) {
        _ = try validateEntry(candidate);
    };
    if (projection.frontier_candidate) |candidate| _ = try validateFrontier(candidate);
    if (projection.retirement) |proof| for (store.entries.items) |entry| {
        if (entry.conflict != null) continue;
        const record = (try wire.decode(entry.original)).record;
        const id = try wire.subject(record.guest);
        if (proof.retires(record.origin, id.epoch, id.counter)) _ = try validateEntry(entry);
    };
    var entries: std.ArrayList(presence.Entry) = .empty;
    defer entries.deinit(allocator);
    var frontiers: std.ArrayList(presence.OriginFrontier) = .empty;
    defer frontiers.deinit(allocator);
    var entry_iterator = projection.entries();
    while (entry_iterator.next()) |entry| try entries.append(allocator, try validateEntry(entry));
    var frontier_iterator = projection.frontiers();
    while (frontier_iterator.next()) |item| try frontiers.append(allocator, try validateFrontier(item));
    if (entries.items.len != projection.final_entry_count or frontiers.items.len != projection.final_frontier_count) return error.AccountingMismatch;
    if (entries.items.len > store.config.max_entries or frontiers.items.len > store.config.max_origins or entries.items.len > std.math.maxInt(u32) or frontiers.items.len > std.math.maxInt(u32)) return error.Capacity;
    std.mem.sort(presence.Entry, entries.items, {}, entryLess);
    std.mem.sort(presence.OriginFrontier, frontiers.items, {}, frontierLess);
    for (entries.items, 0..) |entry, index| if (index > 0 and !entryLess({}, entries.items[index - 1], entry)) return error.InvalidImage;
    for (frontiers.items, 0..) |item, index| if (index > 0 and !frontierLess({}, frontiers.items[index - 1], item)) return error.InvalidImage;
    try normalized(entries.items, frontiers.items);
    var length: usize = header_len;
    var raw_bytes: usize = 0;
    for (entries.items) |entry| try measure(entry.original, entry.conflict, &length, &raw_bytes);
    for (frontiers.items) |item| try measure(item.original, item.conflict, &length, &raw_bytes);
    if (raw_bytes != projection.final_bytes) return error.AccountingMismatch;
    if (raw_bytes > store.config.max_bytes or length > try maxEncodedLen(store.config)) return error.Capacity;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    var writer: Writer = .{ .bytes = bytes };
    writer.put("OPRI");
    writer.put(&.{2});
    writer.int(u32, @intCast(entries.items.len));
    writer.int(u32, @intCast(frontiers.items.len));
    for (entries.items) |entry| try writer.row(entry.original, entry.admission, entry.conflict, entry.conflict_admission);
    for (frontiers.items) |item| try writer.row(item.original, item.admission, item.conflict, item.conflict_admission);
    std.debug.assert(writer.offset == bytes.len);
    return .{ .allocator = allocator, .bytes = bytes, .entries = @intCast(entries.items.len), .frontiers = @intCast(frontiers.items.len), .retained_bytes = raw_bytes };
}

fn measure(original: []const u8, conflict: ?[]const u8, length: *usize, raw_bytes: *usize) Error!void {
    if (original.len > std.math.maxInt(u32)) return error.Capacity;
    const raw = try add(original.len, if (conflict) |bytes| bytes.len else 0);
    if (conflict) |bytes| if (bytes.len > std.math.maxInt(u32)) return error.Capacity;
    raw_bytes.* = try add(raw_bytes.*, raw);
    const overhead: usize = if (conflict != null) max_row_overhead else 5 + presence.AdmissionStamp.encoded_len;
    length.* = try add(length.*, try add(raw, overhead));
}

const Writer = struct {
    bytes: []u8,
    offset: usize = 0,
    fn put(self: *Writer, bytes: []const u8) void {
        @memcpy(self.bytes[self.offset..][0..bytes.len], bytes);
        self.offset += bytes.len;
    }
    fn int(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.offset..][0..@sizeOf(T)], value, .big);
        self.offset += @sizeOf(T);
    }
    fn row(self: *Writer, original: []const u8, stamp: presence.AdmissionStamp, conflict: ?[]const u8, conflict_stamp: ?presence.AdmissionStamp) !void {
        self.int(u32, @intCast(original.len));
        self.put(original);
        self.put(&(try stamp.encode()));
        self.put(&.{@intFromBool(conflict != null)});
        if (conflict) |bytes| {
            self.int(u32, @intCast(bytes.len));
            self.put(bytes);
            self.put(&(try conflict_stamp.?.encode()));
        }
    }
};
const Row = struct { original: []const u8, admission: presence.AdmissionStamp, conflict: ?[]const u8, conflict_admission: ?presence.AdmissionStamp };
const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,
    fn take(self: *Reader, length: usize) Error![]const u8 {
        if (length > self.bytes.len - self.offset) return error.InvalidImage;
        const bytes = self.bytes[self.offset..][0..length];
        self.offset += length;
        return bytes;
    }
    fn int(self: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    fn row(self: *Reader, max_wire_len: usize, raw_bytes: *usize, max_bytes: usize) !Row {
        const length = try self.int(u32);
        if (length > max_wire_len) return error.Capacity;
        const original = try self.take(length);
        const stamp = try presence.AdmissionStamp.decode(try self.take(presence.AdmissionStamp.encoded_len));
        const flag = (try self.take(1))[0];
        if (flag > 1) return error.InvalidImage;
        var result: Row = .{ .original = original, .admission = stamp, .conflict = null, .conflict_admission = null };
        if (flag == 1) {
            const conflict_len = try self.int(u32);
            if (conflict_len > max_wire_len) return error.Capacity;
            result.conflict = try self.take(conflict_len);
            result.conflict_admission = try presence.AdmissionStamp.decode(try self.take(presence.AdmissionStamp.encoded_len));
        }
        raw_bytes.* = try add(raw_bytes.*, try add(original.len, if (result.conflict) |bytes| bytes.len else 0));
        if (raw_bytes.* > max_bytes) return error.Capacity;
        return result;
    }
};

pub const RestoreCandidate = struct {
    store: presence.Store,
    head: retained.Head,
    /// Derived from authenticated local-origin conflict witnesses. The issuer
    /// integration must refuse new local authorship while this is true.
    local_authoring_disabled: bool = false,

    pub fn deinit(self: *RestoreCandidate) void {
        self.store.deinit();
        self.* = undefined;
    }

    /// No allocations. The caller owns the full graph publication lock and
    /// aborts every old prepared handle and projects World/attachments separately
    /// before exposing the restored cut. No old handle may survive this swap.
    /// Expiry observation floor is returned in head; Store.winner does not yet
    /// consume it. This swap alone is not the clock-rollback integration.
    pub fn swapInto(self: *RestoreCandidate, destination: *presence.Store) void {
        std.mem.swap(presence.Store, &self.store, destination);
    }
};

/// No arbitrary raw-image restore entry point. Only the local mandatory durable
/// envelope supplies authenticated historical stamps to the private decoder.
/// Roots are intentionally absent: withdrawn origins remain dormant and their
/// proofs survive reapproval; current Store.winner still gates visibility.
pub fn stageRestore(allocator: std.mem.Allocator, durable: *const persistence.OroStore, context: retained.LocalContext, config: presence.Config) !RestoreCandidate {
    const envelope = try retained.readCommittedEnvelope(durable, context);
    return reconstruct(allocator, envelope.image, envelope.head, envelope.rows.frontier, config);
}

fn reconstruct(allocator: std.mem.Allocator, bytes: []const u8, head: retained.Head, local_frontier: []const u8, config: presence.Config) !RestoreCandidate {
    if (bytes.len > try maxEncodedLen(config)) return error.Capacity;
    var reader: Reader = .{ .bytes = bytes };
    if (!std.mem.eql(u8, try reader.take(4), "OPRI") or (try reader.take(1))[0] != 2) return error.InvalidImage;
    const entry_count = try reader.int(u32);
    const frontier_count = try reader.int(u32);
    if (entry_count != head.entries or frontier_count != head.frontiers) return error.AccountingMismatch;
    if (entry_count > config.max_entries or frontier_count > config.max_origins or head.retained_bytes > config.max_bytes) return error.Capacity;
    var candidate: RestoreCandidate = .{ .store = try presence.Store.init(allocator, config), .head = head };
    errdefer candidate.deinit();
    var raw_bytes: usize = 0;
    for (0..entry_count) |_| {
        const row = try reader.row(wire.max_wire_len, &raw_bytes, config.max_bytes);
        const original = try allocator.dupe(u8, row.original);
        errdefer allocator.free(original);
        const conflict = if (row.conflict) |value| try allocator.dupe(u8, value) else null;
        errdefer if (conflict) |value| allocator.free(value);
        const entry = try validateEntry(.{ .original = original, .decoded = undefined, .admission = row.admission, .conflict = conflict, .conflict_admission = row.conflict_admission });
        if (candidate.store.entries.items.len > 0 and !entryLess({}, candidate.store.entries.items[candidate.store.entries.items.len - 1], entry)) return error.InvalidImage;
        candidate.store.entries.appendAssumeCapacity(entry);
    }
    for (0..frontier_count) |_| {
        const row = try reader.row(frontier.max_wire_len, &raw_bytes, config.max_bytes);
        const original = try allocator.dupe(u8, row.original);
        errdefer allocator.free(original);
        const conflict = if (row.conflict) |value| try allocator.dupe(u8, value) else null;
        errdefer if (conflict) |value| allocator.free(value);
        const item = try validateFrontier(.{ .original = original, .decoded = undefined, .admission = row.admission, .conflict = conflict, .conflict_admission = row.conflict_admission });
        if (candidate.store.frontiers.items.len > 0 and !frontierLess({}, candidate.store.frontiers.items[candidate.store.frontiers.items.len - 1], item)) return error.InvalidImage;
        candidate.store.frontiers.appendAssumeCapacity(item);
    }
    if (reader.offset != bytes.len) return error.InvalidImage;
    if (raw_bytes != head.retained_bytes) return error.AccountingMismatch;
    try normalized(candidate.store.entries.items, candidate.store.frontiers.items);
    var local_found = false;
    for (candidate.store.frontiers.items) |item| {
        if (!std.mem.eql(u8, &item.decoded.origin, &head.context.origin)) continue;
        if (item.conflict != null) {
            candidate.local_authoring_disabled = true;
        } else if (!std.mem.eql(u8, item.original, local_frontier)) return error.InvalidImage;
        local_found = true;
    }
    if (!local_found) return error.InvalidImage;
    for (candidate.store.entries.items) |entry| {
        if (!std.mem.eql(u8, &entry.decoded.record.origin, &head.context.origin) or candidate.local_authoring_disabled or entry.terminal()) continue;
        const id = try wire.subject(entry.decoded.record.guest);
        if (id.epoch > head.epoch or (id.epoch == head.epoch and id.counter > head.issued_through)) return error.InvalidImage;
    }
    candidate.store.bytes = raw_bytes;
    // This counter belongs to fresh RAM, not durable head image generation.
    // No predecessor prepared handle can address this distinct Store object.
    return candidate;
}

const sign = @import("../crypto/sign.zig");
const issuer = @import("mesh_presence_issuer.zig");

fn fixture(origin: sign.PublicKey, counter: u64) !wire.Record {
    return .{ .operation = .present, .origin = origin, .guest = try wire.guestId(.{ .epoch = 1, .counter = counter }), .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 7, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "Guest", .username = "guest", .host = "cloak.onyx", .realname = "Guest", .server = "node-c", .description = "Origin" };
}
fn apply(store: *presence.Store, record: wire.Record, key: *const sign.KeyPair, now: i64) !void {
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try store.prepare(try wire.encode(record, key, &buffer), &.{key.public_key}, now);
    defer plan.abort();
    _ = plan.commit();
}
fn applyFrontier(store: *presence.Store, record: frontier.Record, key: *const sign.KeyPair, now: i64) !void {
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var plan = try store.prepareFrontier(try frontier.encode(record, key, buffer), &.{key.public_key}, now);
    defer plan.abort();
    _ = plan.commit();
}
fn publishFixture(owner: *issuer.Issuer, key: *const sign.KeyPair, bytes: []const u8, entries: u32, frontiers: u32, raw_bytes: usize) !retained.LocalContext {
    const context: retained.LocalContext = .{ .origin = key.public_key, .realm = @splat(5) };
    const head: retained.Head = .{
        .context = context,
        .store_id = @splat(4),
        .commit_generation = 1,
        .image_generation = 1,
        .previous_head_digest = @splat(0),
        .image_digest = retained.digest(bytes),
        .image_len = bytes.len,
        .entries = entries,
        .frontiers = frontiers,
        .retained_bytes = raw_bytes,
        .metadata_digest = retained.digest(owner.store.get(.props, issuer.metadata_key).?),
        .frontier_digest = retained.digest(owner.originalFrontier()),
        .epoch = owner.metadata.epoch,
        .issued_through = owner.metadata.issued_through,
        .frontier_revision = owner.metadata.frontier_revision,
        .frontier_through = owner.metadata.frontier_through,
        .expiry_floor_ms = 3000,
    };
    const raw = try head.encode(key);
    var batch = try owner.store.prepareBatch(&.{
        .{ .family = .props, .kind = .put, .key = retained.image_key, .value = bytes },
        .{ .family = .props, .kind = .put, .key = retained.head_key, .value = &raw },
    });
    defer batch.abort();
    try batch.commit();
    return context;
}
fn addLocalFrontier(store: *presence.Store, owner: *issuer.Issuer) !void {
    var plan = try store.prepareFrontier(owner.originalFrontier(), &.{owner.metadata.origin}, 1000);
    defer plan.abort();
    _ = plan.commit();
}
fn complexFixture(store: *presence.Store, a: *const sign.KeyPair, b: *const sign.KeyPair) !void {
    try apply(store, try fixture(a.public_key, 1), a, 1000);
    var quit = try fixture(a.public_key, 2);
    quit.operation = .quit;
    quit.revision = 2;
    var buffer: [wire.max_wire_len]u8 = undefined;
    var repair = try store.prepareQuitRepair(try wire.encode(quit, a, &buffer), &.{a.public_key}, 2100);
    defer repair.abort();
    _ = repair.commit();
    var conflict = try fixture(a.public_key, 3);
    conflict.nick = "Fork";
    try apply(store, conflict, a, 1000);
    conflict.realname = "Contradiction";
    try apply(store, conflict, a, 1100);
    try apply(store, try fixture(b.public_key, 1), b, 1000);
    try applyFrontier(store, .{ .origin = a.public_key, .epoch = 1, .revision = 1, .through = 3, .issued_ms = 1000, .active = &.{ 1, 3 } }, a, 1000);
    try applyFrontier(store, .{ .origin = b.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{1} }, b, 1000);
    try applyFrontier(store, .{ .origin = b.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1100, .active = &.{} }, b, 1100);
}

test "mesh presence image restores exact witnesses admission times and dormant roots" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(121));
    defer local.deinit();
    var a = try sign.KeyPair.fromSeed(@splat(122));
    defer a.deinit();
    var b = try sign.KeyPair.fromSeed(@splat(123));
    defer b.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "image.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try complexFixture(&store, &a, &b);
    try addLocalFrontier(&store, &owner);
    var image = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer image.deinit();
    try std.testing.expectEqual(@as(u32, 3), image.entries);
    try std.testing.expectEqual(@as(u32, 3), image.frontiers);
    const context = try publishFixture(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    var candidate = try stageRestore(std.testing.allocator, &owner.store, context, .{});
    defer candidate.deinit();
    var reproduced = try encodeProjection(std.testing.allocator, &candidate.store, .unchanged);
    defer reproduced.deinit();
    try std.testing.expectEqualSlices(u8, image.bytes, reproduced.bytes);
    try std.testing.expectEqual(store.bytes, candidate.store.bytes);
    try std.testing.expect(candidate.store.winner("Guest", 1200, &.{}) == null);
    try std.testing.expect(candidate.store.winner("Guest", 1200, &.{a.public_key}) != null);
    try std.testing.expect(candidate.store.winner("Guest", 1200, &.{b.public_key}) == null);
    try std.testing.expect(candidate.store.winner("Fork", 1200, &.{a.public_key}) == null);
    // No current wall time entered restoration. Historical future/expiry checks
    // use each separate signed-local stamp, preserving irreversible negatives.
    for (candidate.store.entries.items) |entry| if (entry.conflict != null) {
        try std.testing.expectEqual(@as(i64, 1000), entry.admission.admitted_at_ms);
        try std.testing.expectEqual(@as(i64, 1100), entry.conflict_admission.?.admitted_at_ms);
    };
    for (candidate.store.frontiers.items) |item| if (item.conflict != null) {
        try std.testing.expectEqual(@as(i64, 1000), item.admission.admitted_at_ms);
        try std.testing.expectEqual(@as(i64, 1100), item.conflict_admission.?.admitted_at_ms);
    };
    // Destruction/replacement of durable backing cannot invalidate owned rows.
    try owner.store.put(.props, retained.image_key, "changed");
    for (candidate.store.entries.items) |entry| try entry.decoded.verify();
    var destination = try presence.Store.init(std.testing.allocator, .{});
    defer destination.deinit();
    candidate.swapInto(&destination);
    try std.testing.expectEqual(@as(usize, 3), destination.entries.items.len);
    try std.testing.expectEqual(@as(usize, 0), candidate.store.entries.items.len);
}

test "mesh presence image projects frontier GC before RAM publication and keeps conflicts" {
    var key = try sign.KeyPair.fromSeed(@splat(124));
    defer key.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try fixture(key.public_key, 1);
    try apply(&store, value, &key, 1000);
    value.guest = try wire.guestId(.{ .epoch = 1, .counter = 2 });
    try apply(&store, value, &key, 1000);
    value.realname = "Conflict";
    try apply(&store, value, &key, 1100);
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var plan = try store.prepareFrontier(try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 2, .issued_ms = 1100, .active = &.{} }, &key, buffer), &.{key.public_key}, 1100);
    defer plan.abort();
    const generation = store.generation;
    const old_bytes = store.bytes;
    var projected = try encodeProjection(std.testing.allocator, &store, .{ .frontier = &plan });
    defer projected.deinit();
    try std.testing.expectEqual(@as(u32, 1), projected.entries);
    try std.testing.expectEqual(@as(u32, 1), projected.frontiers);
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqual(old_bytes, store.bytes);
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    _ = plan.commit();
    var committed = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer committed.deinit();
    try std.testing.expectEqualSlices(u8, projected.bytes, committed.bytes);
    try std.testing.expectError(error.InvalidPlan, encodeProjection(std.testing.allocator, &store, .{ .frontier = &plan }));
    try std.testing.expect(store.entries.items[0].conflict != null);
}

test "mesh presence image projects subject updates rejects stale foreign and invalid handles" {
    var key = try sign.KeyPair.fromSeed(@splat(125));
    defer key.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var other = try presence.Store.init(std.testing.allocator, .{});
    defer other.deinit();
    const value = try fixture(key.public_key, 1);
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1000);
    defer plan.abort();
    var projected = try encodeProjection(std.testing.allocator, &store, .{ .presence = &plan });
    defer projected.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expectEqual(@as(u32, 1), projected.entries);
    try std.testing.expectError(error.InvalidPlan, encodeProjection(std.testing.allocator, &other, .{ .presence = &plan }));
    plan.generation += 1;
    try std.testing.expectError(error.InvalidPlan, encodeProjection(std.testing.allocator, &store, .{ .presence = &plan }));
    plan.generation -= 1;
    plan.candidate_bytes += 1;
    try std.testing.expectError(error.AccountingMismatch, encodeProjection(std.testing.allocator, &store, .{ .presence = &plan }));
    plan.candidate_bytes -= 1;
    _ = plan.commit();
    var committed = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer committed.deinit();
    try std.testing.expectEqualSlices(u8, projected.bytes, committed.bytes);
}

/// Test-only malformed writer: never exposed by the restoration API.
fn uncheckedFixtureImage(entries: []const presence.Entry, frontiers: []const presence.OriginFrontier) !Image {
    var length: usize = header_len;
    var raw_bytes: usize = 0;
    for (entries) |entry| try measure(entry.original, entry.conflict, &length, &raw_bytes);
    for (frontiers) |item| try measure(item.original, item.conflict, &length, &raw_bytes);
    const bytes = try std.testing.allocator.alloc(u8, length);
    errdefer std.testing.allocator.free(bytes);
    var writer: Writer = .{ .bytes = bytes };
    writer.put("OPRI");
    writer.put(&.{2});
    writer.int(u32, @intCast(entries.len));
    writer.int(u32, @intCast(frontiers.len));
    for (entries) |entry| try writer.row(entry.original, entry.admission, entry.conflict, entry.conflict_admission);
    for (frontiers) |item| try writer.row(item.original, item.admission, item.conflict, item.conflict_admission);
    return .{ .allocator = std.testing.allocator, .bytes = bytes, .entries = @intCast(entries.len), .frontiers = @intCast(frontiers.len), .retained_bytes = raw_bytes };
}
fn expectRejected(owner: *issuer.Issuer, local: *const sign.KeyPair, bytes: []const u8, entries: u32, frontiers: u32, raw_bytes: usize) !void {
    const context = try publishFixture(owner, local, bytes, entries, frontiers, @min(raw_bytes, bytes.len));
    if (stageRestore(std.testing.allocator, &owner.store, context, .{})) |value| {
        var accepted = value;
        accepted.deinit();
        return error.UnexpectedAcceptance;
    } else |err| {
        try std.testing.expect(err != error.OutOfMemory);
    }
}

test "mesh presence image rejects locally signed malformed framing ordering signatures and stamps" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(126));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(127));
    defer remote.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "malformed.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try apply(&store, try fixture(remote.public_key, 1), &remote, 1000);
    try apply(&store, try fixture(remote.public_key, 2), &remote, 1000);
    try addLocalFrontier(&store, &owner);
    var image = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer image.deinit();
    // Each altered image is resigned locally; the image layer must reject its
    // internal evidence rather than relying solely on the enclosing hash.
    const stamp_offset = header_len + 4 + store.entries.items[0].original.len;
    const flag_offset = stamp_offset + presence.AdmissionStamp.encoded_len;
    const offsets = [_]usize{ 0, 4, header_len + 4 + store.entries.items[0].original.len - 1, stamp_offset, stamp_offset + 1, stamp_offset + 2, stamp_offset + 3 };
    for (offsets) |offset| {
        const saved = image.bytes[offset];
        image.bytes[offset] ^= 0x40;
        try expectRejected(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
        image.bytes[offset] = saved;
    }
    image.bytes[flag_offset] = 2;
    try expectRejected(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    image.bytes[flag_offset] = 0;
    const time_bytes = image.bytes[stamp_offset + 35 ..][0..8].*;
    std.mem.writeInt(i64, image.bytes[stamp_offset + 35 ..][0..8], 3000, .big);
    try expectRejected(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    image.bytes[stamp_offset + 35 ..][0..8].* = time_bytes;
    const lifetime_bytes = image.bytes[stamp_offset + 43 ..][0..8].*;
    std.mem.writeInt(i64, image.bytes[stamp_offset + 43 ..][0..8], 500, .big);
    try expectRejected(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    image.bytes[stamp_offset + 43 ..][0..8].* = lifetime_bytes;
    // Truncated headers, wire, missing stamps/flags/final-row data and suffix.
    for ([_]usize{ 1, 4, 5, 12, 13, stamp_offset, stamp_offset + 58, flag_offset, image.bytes.len - 1 }) |length| try expectRejected(&owner, &local, image.bytes[0..length], image.entries, image.frontiers, image.retained_bytes);
    const trailing = try std.mem.concat(std.testing.allocator, u8, &.{ image.bytes, &.{0} });
    defer std.testing.allocator.free(trailing);
    try expectRejected(&owner, &local, trailing, image.entries, image.frontiers, image.retained_bytes);
    try expectRejected(&owner, &local, image.bytes, image.entries + 1, image.frontiers, image.retained_bytes);
    try expectRejected(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes - 1);
    const reversed = [_]presence.Entry{ store.entries.items[1], store.entries.items[0] };
    var order = try uncheckedFixtureImage(&reversed, store.frontiers.items);
    defer order.deinit();
    try expectRejected(&owner, &local, order.bytes, order.entries, order.frontiers, order.retained_bytes);
    const duplicates = [_]presence.Entry{ store.entries.items[0], store.entries.items[0] };
    var duplicate = try uncheckedFixtureImage(&duplicates, store.frontiers.items);
    defer duplicate.deinit();
    try expectRejected(&owner, &local, duplicate.bytes, duplicate.entries, duplicate.frontiers, duplicate.retained_bytes);
    const duplicate_frontiers = [_]presence.OriginFrontier{ store.frontiers.items[0], store.frontiers.items[0] };
    var duplicate_origin = try uncheckedFixtureImage(store.entries.items, &duplicate_frontiers);
    defer duplicate_origin.deinit();
    try expectRejected(&owner, &local, duplicate_origin.bytes, duplicate_origin.entries, duplicate_origin.frontiers, duplicate_origin.retained_bytes);
}

test "mesh presence image refuses fabricated quarantine and unnormalized retirement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(128));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(129));
    defer remote.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "quarantine.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try fixture(remote.public_key, 1);
    try apply(&store, value, &remote, 1000);
    try addLocalFrontier(&store, &owner);
    var fabricated = store.entries.items[0];
    // Two valid renewal signatures are not an equivocation witness.
    value.revision = 2;
    value.issued_ms = 1100;
    value.expires_ms = 2100;
    var buffer: [wire.max_wire_len]u8 = undefined;
    var renewal = try store.prepare(try wire.encode(value, &remote, &buffer), &.{remote.public_key}, 1100);
    defer renewal.abort();
    fabricated.conflict = renewal.candidate.?.original;
    fabricated.conflict_admission = renewal.candidate.?.admission;
    var image = try uncheckedFixtureImage(&.{fabricated}, store.frontiers.items);
    defer image.deinit();
    try expectRejected(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    fabricated.conflict = fabricated.original;
    fabricated.conflict_admission = fabricated.admission;
    var same = try uncheckedFixtureImage(&.{fabricated}, store.frontiers.items);
    defer same.deinit();
    try expectRejected(&owner, &local, same.bytes, same.entries, same.frontiers, same.retained_bytes);
    // Same full root but different subject must not quarantine either subject.
    value.guest = try wire.guestId(.{ .epoch = 1, .counter = 2 });
    const foreign_subject = try wire.encode(value, &remote, &buffer);
    fabricated.conflict = @constCast(foreign_subject);
    var foreign = try uncheckedFixtureImage(&.{fabricated}, store.frontiers.items);
    defer foreign.deinit();
    try expectRejected(&owner, &local, foreign.bytes, foreign.entries, foreign.frontiers, foreign.retained_bytes);
    // A duplicate frontier pair cannot manufacture permanent origin quarantine.
    var false_frontier = store.frontiers.items[0];
    false_frontier.conflict = false_frontier.original;
    false_frontier.conflict_admission = false_frontier.admission;
    var bad_frontier = try uncheckedFixtureImage(store.entries.items, &.{false_frontier});
    defer bad_frontier.deinit();
    try expectRejected(&owner, &local, bad_frontier.bytes, bad_frontier.entries, bad_frontier.frontiers, bad_frontier.retained_bytes);
    renewal.abort();
    // Keep a retirement plan uncommitted so a test-only image can retain a row
    // which a normalized writer must remove. Restoration must not repair it.
    const frontier_buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(frontier_buffer);
    var cut = try store.prepareFrontier(try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &remote, frontier_buffer), &.{remote.public_key}, 1000);
    defer cut.abort();
    var rows = [_]presence.OriginFrontier{ store.frontiers.items[0], cut.candidate.? };
    std.mem.sort(presence.OriginFrontier, &rows, {}, frontierLess);
    var unnormalized = try uncheckedFixtureImage(store.entries.items, &rows);
    defer unnormalized.deinit();
    try expectRejected(&owner, &local, unnormalized.bytes, unnormalized.entries, unnormalized.frontiers, unnormalized.retained_bytes);
}

fn stateFingerprint(store: *const presence.Store) [32]u8 {
    var hash = std.crypto.hash.Blake3.init(.{});
    for (store.entries.items) |entry| {
        hash.update(entry.original);
        hash.update(&(entry.admission.encode() catch unreachable));
        if (entry.conflict) |bytes| {
            hash.update(bytes);
            hash.update(&(entry.conflict_admission.?.encode() catch unreachable));
        }
    }
    for (store.frontiers.items) |item| {
        hash.update(item.original);
        hash.update(&(item.admission.encode() catch unreachable));
        if (item.conflict) |bytes| {
            hash.update(bytes);
            hash.update(&(item.conflict_admission.?.encode() catch unreachable));
        }
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn allocationScenario(allocator: std.mem.Allocator, store: *const presence.Store, durable: *const persistence.OroStore, context: retained.LocalContext) !void {
    const generation = store.generation;
    const before_bytes = store.bytes;
    const before_state = stateFingerprint(store);
    const before_image = retained.digest(durable.get(.props, retained.image_key).?);
    const before_head = retained.digest(durable.get(.props, retained.head_key).?);
    defer {
        std.debug.assert(generation == store.generation and before_bytes == store.bytes);
        std.debug.assert(std.mem.eql(u8, &before_state, &stateFingerprint(store)));
        std.debug.assert(std.mem.eql(u8, &before_image, &retained.digest(durable.get(.props, retained.image_key).?)));
        std.debug.assert(std.mem.eql(u8, &before_head, &retained.digest(durable.get(.props, retained.head_key).?)));
    }
    var image = encodeProjection(allocator, store, .unchanged) catch |err| {
        if (err == error.OutOfMemory) {
            var retry = try encodeProjection(std.testing.allocator, store, .unchanged);
            defer retry.deinit();
        }
        return err;
    };
    defer image.deinit();
    var candidate = stageRestore(allocator, durable, context, store.config) catch |err| {
        if (err == error.OutOfMemory) {
            var retry = try stageRestore(std.testing.allocator, durable, context, store.config);
            defer retry.deinit();
        }
        return err;
    };
    defer candidate.deinit();
    try std.testing.expectEqualSlices(u8, image.bytes, durable.get(.props, retained.image_key).?);
    try std.testing.expectEqual(store.entries.items.len, candidate.store.entries.items.len);
    try std.testing.expectEqual(store.frontiers.items.len, candidate.store.frontiers.items.len);
}

test "mesh presence image exhaustive allocation failures preserve exact durable cut and retry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(130));
    defer local.deinit();
    var a = try sign.KeyPair.fromSeed(@splat(131));
    defer a.deinit();
    var b = try sign.KeyPair.fromSeed(@splat(132));
    defer b.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "oom.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try complexFixture(&store, &a, &b);
    try addLocalFrontier(&store, &owner);
    var image = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer image.deinit();
    const context = try publishFixture(&owner, &local, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{ &store, &owner.store, context });
}

test "mesh presence image bounds are checked before authority and empty local state is explicit" {
    try std.testing.expectError(error.Capacity, maxEncodedLen(.{ .max_entries = std.math.maxInt(usize) }));
    try std.testing.expectError(error.Capacity, maxEncodedLen(.{ .max_bytes = std.math.maxInt(usize) }));
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(133));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "bounds.wal", &key, 1000);
    defer owner.deinit();
    const context: retained.LocalContext = .{ .origin = key.public_key, .realm = @splat(5) };
    try std.testing.expectError(error.MissingState, stageRestore(std.testing.allocator, &owner.store, context, .{}));
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var empty = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer empty.deinit();
    try expectRejected(&owner, &key, empty.bytes, empty.entries, empty.frontiers, empty.retained_bytes);
    try addLocalFrontier(&store, &owner);
    var image = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer image.deinit();
    _ = try publishFixture(&owner, &key, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    var candidate = try stageRestore(std.testing.allocator, &owner.store, context, .{});
    defer candidate.deinit();
    try std.testing.expectEqual(@as(usize, 0), candidate.store.entries.items.len);
    try std.testing.expectEqual(@as(usize, 1), candidate.store.frontiers.items.len);
    try std.testing.expectError(error.Capacity, stageRestore(std.testing.allocator, &owner.store, context, .{ .max_bytes = image.retained_bytes - 1 }));
    // Locally signed presence cannot escape issuer reservations or future epoch.
    try apply(&store, try fixture(key.public_key, 1), &key, 1000);
    var unissued = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer unissued.deinit();
    try expectRejected(&owner, &key, unissued.bytes, unissued.entries, unissued.frontiers, unissued.retained_bytes);
    // Return to the valid predecessor after the deliberately malformed image.
    // Once retained state exists, a legacy issuer-only reservation must never
    // bypass its bound head. Stage the fixture's reservation and presence as
    // one complete four-row cut instead.
    _ = try publishFixture(&owner, &key, image.bytes, image.entries, image.frontiers, image.retained_bytes);
    const previous = try retained.readCommittedEnvelope(&owner.store, context);
    var next_metadata = try issuer.validateRows(previous.rows.metadata, previous.rows.frontier, key.public_key);
    next_metadata.issued_through = 1;
    const metadata_raw = next_metadata.encode();
    var next_head = previous.head;
    next_head.commit_generation += 1;
    next_head.image_generation += 1;
    next_head.previous_head_digest = retained.digest(owner.store.get(.props, retained.head_key).?);
    next_head.image_digest = retained.digest(unissued.bytes);
    next_head.image_len = unissued.bytes.len;
    next_head.entries = unissued.entries;
    next_head.frontiers = unissued.frontiers;
    next_head.retained_bytes = unissued.retained_bytes;
    next_head.metadata_digest = retained.digest(&metadata_raw);
    next_head.issued_through = next_metadata.issued_through;
    const head_raw = try next_head.encode(&key);
    var issuance = try owner.store.prepareBatch(&.{
        .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &metadata_raw },
        .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = previous.rows.frontier },
        .{ .family = .props, .kind = .put, .key = retained.image_key, .value = unissued.bytes },
        .{ .family = .props, .kind = .put, .key = retained.head_key, .value = &head_raw },
    });
    defer issuance.abort();
    try issuance.commit();
    owner.metadata = next_metadata; // Fixture bookkeeping after complete commit.
    var issued = try stageRestore(std.testing.allocator, &owner.store, context, .{});
    defer issued.deinit();
    try std.testing.expectEqual(@as(usize, 1), issued.store.entries.items.len);
    var future = try fixture(key.public_key, 1);
    future.guest = try wire.guestId(.{ .epoch = 2, .counter = 1 });
    try apply(&store, future, &key, 1000);
    var future_image = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer future_image.deinit();
    try expectRejected(&owner, &key, future_image.bytes, future_image.entries, future_image.frontiers, future_image.retained_bytes);
}

test "mesh presence image preserves local quarantine and signed out of range negative evidence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(134));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "local-conflict.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalFrontier(&store, &owner);
    var quit = try fixture(key.public_key, 99);
    quit.operation = .quit;
    quit.revision = 2;
    var quit_buffer: [wire.max_wire_len]u8 = undefined;
    var repair = try store.prepareQuitRepair(try wire.encode(quit, &key, &quit_buffer), &.{key.public_key}, 2100);
    defer repair.abort();
    _ = repair.commit();
    var subject_conflict = try fixture(key.public_key, 98);
    try apply(&store, subject_conflict, &key, 1000);
    subject_conflict.realname = "Signed fork";
    try apply(&store, subject_conflict, &key, 1100);
    var negative = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer negative.deinit();
    const context = try publishFixture(&owner, &key, negative.bytes, negative.entries, negative.frontiers, negative.retained_bytes);
    var restored = try stageRestore(std.testing.allocator, &owner.store, context, .{});
    defer restored.deinit();
    try std.testing.expect(!restored.local_authoring_disabled);
    try std.testing.expectEqual(@as(usize, 2), restored.store.entries.items.len);
    for (restored.store.entries.items) |entry| {
        try std.testing.expect(entry.terminal());
        if (entry.decoded.record.operation == .quit) {
            try std.testing.expectEqual(@FieldType(presence.AdmissionStamp, "mode").expired_quit_repair, entry.admission.mode);
            try std.testing.expectEqual(@as(i64, 2100), entry.admission.admitted_at_ms);
        }
    }
    // A valid positive outside the issuer namespace remains fatal unless its
    // whole local origin is already irreversibly quarantined.
    try apply(&store, try fixture(key.public_key, 100), &key, 1000);
    var outside = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer outside.deinit();
    try expectRejected(&owner, &key, outside.bytes, outside.entries, outside.frontiers, outside.retained_bytes);
    try applyFrontier(&store, .{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 1100, .active = &.{} }, &key, 1100);
    var quarantined = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer quarantined.deinit();
    _ = try publishFixture(&owner, &key, quarantined.bytes, quarantined.entries, quarantined.frontiers, quarantined.retained_bytes);
    var inactive = try stageRestore(std.testing.allocator, &owner.store, context, .{});
    defer inactive.deinit();
    try std.testing.expect(inactive.local_authoring_disabled);
    try std.testing.expectEqual(@as(usize, 3), inactive.store.entries.items.len);
    try std.testing.expect(inactive.store.winner("Guest", 1200, &.{key.public_key}) == null);
    const frontier_row = inactive.store.frontiers.items[0];
    try std.testing.expectEqual(@as(i64, 1000), frontier_row.admission.admitted_at_ms);
    try std.testing.expectEqual(@as(i64, 1100), frontier_row.conflict_admission.?.admitted_at_ms);
    var reproduced = try encodeProjection(std.testing.allocator, &inactive.store, .unchanged);
    defer reproduced.deinit();
    try std.testing.expectEqualSlices(u8, quarantined.bytes, reproduced.bytes);
}

test "mesh presence image requires exact unquarantined local issuer cut" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(135));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "local-cut.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalFrontier(&store, &owner);
    try applyFrontier(&store, .{ .origin = key.public_key, .epoch = 1, .revision = 2, .through = 0, .issued_ms = 1000, .active = &.{} }, &key, 1000);
    var mismatched = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer mismatched.deinit();
    try expectRejected(&owner, &key, mismatched.bytes, mismatched.entries, mismatched.frontiers, mismatched.retained_bytes);
}

fn projectedAllocationScenario(allocator: std.mem.Allocator, store: *const presence.Store, plan: *const presence.Store.PreparedFrontier) !void {
    const generation = store.generation;
    const raw_bytes = store.bytes;
    const entries = store.entries.items.len;
    const before_state = stateFingerprint(store);
    const proof_hash = retained.digest(plan.candidate.?.original);
    defer {
        std.debug.assert(store.generation == generation and store.bytes == raw_bytes and store.entries.items.len == entries);
        std.debug.assert(std.mem.eql(u8, &before_state, &stateFingerprint(store)));
        std.debug.assert(!plan.done and std.mem.eql(u8, &proof_hash, &retained.digest(plan.candidate.?.original)));
    }
    var image = encodeProjection(allocator, store, .{ .frontier = plan }) catch |err| {
        if (err == error.OutOfMemory) {
            var retry = try encodeProjection(std.testing.allocator, store, .{ .frontier = plan });
            defer retry.deinit();
            try std.testing.expectEqual(@as(u32, 1), retry.entries);
        }
        return err;
    };
    defer image.deinit();
    try std.testing.expectEqual(@as(u32, 1), image.entries);
}

test "mesh presence image exhaustive projected GC allocations leave live plan retryable" {
    var key = try sign.KeyPair.fromSeed(@splat(136));
    defer key.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try apply(&store, try fixture(key.public_key, 1), &key, 1000);
    try apply(&store, try fixture(key.public_key, 2), &key, 1000);
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var plan = try store.prepareFrontier(try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 2, .issued_ms = 1000, .active = &.{2} }, &key, buffer), &.{key.public_key}, 1000);
    defer plan.abort();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, projectedAllocationScenario, .{ &store, &plan });
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    _ = plan.commit();
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
    try std.testing.expectEqual(@as(u64, 2), (try wire.subject(store.entries.items[0].decoded.record.guest)).counter);
}

test "mesh presence image v2 class chronology witnesses survive either order and fabricated pairs refuse" {
    var local = try sign.KeyPair.fromSeed(@splat(238));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(239));
    defer remote.deinit();
    for ([_]bool{ false, true }) |reverse| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "class-pair.wal", &local, 1000);
        defer owner.deinit();
        var store = try presence.Store.init(std.testing.allocator, .{});
        defer store.deinit();
        const before = try fixture(remote.public_key, 1);
        var fork = before;
        fork.revision = 2;
        fork.routing_class = .exact_reusable_attachment;
        // A changed class retaining revision1 provenance is contradictory,
        // although both original records are individually valid and signed.
        try apply(&store, if (reverse) fork else before, &remote, 1000);
        try apply(&store, if (reverse) before else fork, &remote, 1100);
        try addLocalFrontier(&store, &owner);
        try std.testing.expect(store.entries.items[0].conflict != null);
        var encoded = try encodeProjection(std.testing.allocator, &store, .unchanged);
        defer encoded.deinit();
        const context = try publishFixture(&owner, &local, encoded.bytes, encoded.entries, encoded.frontiers, encoded.retained_bytes);
        var restored = try stageRestore(std.testing.allocator, &owner.store, context, .{});
        defer restored.deinit();
        const entry = restored.store.entries.items[0];
        try std.testing.expectEqualSlices(u8, store.entries.items[0].original, entry.original);
        try std.testing.expectEqualSlices(u8, store.entries.items[0].conflict.?, entry.conflict.?);
        try std.testing.expectEqualDeep(store.entries.items[0].admission, entry.admission);
        try std.testing.expectEqualDeep(store.entries.items[0].conflict_admission, entry.conflict_admission);
        try std.testing.expectEqual(presence.Disposition.quarantined, try presence.Store.comparePresence(entry.decoded, try wire.decode(entry.conflict.?)));
        try std.testing.expect(restored.store.winner("Guest", 1200, &.{remote.public_key}) == null);

        var legal = before;
        legal.revision = 2;
        legal.class_revision = 2;
        legal.routing_class = .authenticated_untracked;
        var buffers: [2][wire.max_wire_len]u8 = undefined;
        const a = try wire.encode(before, &remote, &buffers[0]);
        const b = try wire.encode(legal, &remote, &buffers[1]);
        var fabricated = store.entries.items[0];
        fabricated.original = @constCast(if (reverse) b else a);
        fabricated.conflict = @constCast(if (reverse) a else b);
        var fake = try uncheckedFixtureImage(&.{fabricated}, store.frontiers.items);
        defer fake.deinit();
        try expectRejected(&owner, &local, fake.bytes, fake.entries, fake.frontiers, fake.retained_bytes);
    }
}

test "mesh presence image v2 rejects signed v1 original and stale cached class without class inference" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(240));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(241));
    defer remote.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "mixed-row.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try fixture(remote.public_key, 1);
    value.routing_class = .exact_reusable_attachment;
    try apply(&store, value, &remote, 1000);
    try addLocalFrontier(&store, &owner);
    const v1 = @import("../proto/mesh_presence.zig");
    var buffer: [v1.max_wire_len]u8 = undefined;
    const old = try v1.encode(.{ .operation = value.operation, .origin = value.origin, .guest = value.guest, .revision = value.revision, .claim_hlc = value.claim_hlc, .claim_revision = value.claim_revision, .issued_ms = value.issued_ms, .expires_ms = value.expires_ms, .nick = value.nick, .username = value.username, .host = value.host, .realname = value.realname, .server = value.server, .description = value.description }, &remote, &buffer);
    try (try v1.decode(old)).verify();
    var fake_entry = store.entries.items[0];
    fake_entry.original = @constCast(old);
    var mixed = try uncheckedFixtureImage(&.{fake_entry}, store.frontiers.items);
    defer mixed.deinit();
    try expectRejected(&owner, &local, mixed.bytes, mixed.entries, mixed.frontiers, mixed.retained_bytes);
    store.entries.items[0].decoded.record.routing_class = .true_guest;
    try std.testing.expectError(error.InvalidPlan, encodeProjection(std.testing.allocator, &store, .unchanged));
    store.entries.items[0].decoded.record.routing_class = .exact_reusable_attachment;
    store.entries.items[0].decoded.record.class_revision = 2;
    try std.testing.expectError(error.InvalidPlan, encodeProjection(std.testing.allocator, &store, .unchanged));
    store.entries.items[0].decoded.record.class_revision = 1;
    var correct = try encodeProjection(std.testing.allocator, &store, .unchanged);
    defer correct.deinit();
    const context = try publishFixture(&owner, &local, correct.bytes, correct.entries, correct.frontiers, correct.retained_bytes);
    var restored = try stageRestore(std.testing.allocator, &owner.store, context, .{});
    defer restored.deinit();
    try std.testing.expectEqual(wire.RoutingClass.exact_reusable_attachment, restored.store.entries.items[0].decoded.record.routing_class);
}
