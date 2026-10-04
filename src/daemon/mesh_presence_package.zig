// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prepared image/head contributions for the single leased authority WAL.
//! This leaf never prepares or commits an OroStore batch or publishes RAM.
//! The aggregate owner combines these contributions with both issuer rows,
//! revalidates the unchanged, unconsumed RAM handle before durable commit,
//! fsyncs once, then consumes that corresponding sole prepared RAM handle.
//! All borrowed stores, plans and durable rows require one external owner lock.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const wire = @import("../proto/mesh_presence_v2.zig");
const frontier = @import("../proto/mesh_presence_frontier.zig");
const presence = @import("mesh_presence_store.zig");
const image = @import("mesh_presence_image.zig");
const retained = @import("mesh_presence_retained.zig");
const issuer = @import("mesh_presence_issuer.zig");
const persistence = @import("store.zig");

pub const Error = error{ InvalidTransition, GenerationExhausted, InvalidLocalState, PredecessorMismatch };
pub const EncodedHead = struct {
    head: retained.Head,
    bytes: [retained.head_len]u8,

    pub fn mutation(self: *const EncodedHead) persistence.BatchMutation {
        return .{ .family = .props, .kind = .put, .key = retained.head_key, .value = &self.bytes };
    }
};
pub const Package = struct {
    image: image.Image,
    head: EncodedHead,
    local_authoring_disabled: bool,

    pub fn deinit(self: *Package) void {
        self.image.deinit();
        self.* = undefined;
    }

    /// Borrowed contributions only. Keep Package alive and immovable until the
    /// aggregate owner has copied/prepared these alongside its issuer rows.
    pub fn mutations(self: *const Package) [2]persistence.BatchMutation {
        return .{
            .{ .family = .props, .kind = .put, .key = retained.image_key, .value = self.image.bytes },
            self.head.mutation(),
        };
    }
};

fn requireKey(context: retained.LocalContext, key: *const sign.KeyPair) !void {
    if (!std.mem.eql(u8, &context.origin, &key.public_key)) return error.ContextMismatch;
}
fn advance(value: u64) Error!u64 {
    return std.math.add(u64, value, 1) catch error.GenerationExhausted;
}
fn bindIssuer(head: *retained.Head, rows: retained.IssuerRows, metadata: issuer.Metadata) void {
    head.metadata_digest = retained.digest(rows.metadata);
    head.frontier_digest = retained.digest(rows.frontier);
    head.epoch = metadata.epoch;
    head.issued_through = metadata.issued_through;
    head.frontier_revision = metadata.frontier_revision;
    head.frontier_through = metadata.frontier_through;
}

fn validateTransition(old: retained.Envelope, rows: retained.IssuerRows, context: retained.LocalContext) !issuer.Metadata {
    const metadata = try issuer.validateRows(rows.metadata, rows.frontier, context.origin);
    const before = try frontier.decode(old.rows.frontier);
    const after = try frontier.decode(rows.frontier);
    if (metadata.epoch == old.head.epoch) {
        if (metadata.issued_through < old.head.issued_through) return error.InvalidTransition;
        const update = try frontier.compare(before, after);
        if (update != .advance and update != .duplicate) return error.InvalidTransition;
    } else {
        if (metadata.epoch != try advance(old.head.epoch) or metadata.issued_through != 0 or metadata.frontier_revision != 1 or metadata.frontier_through != 0 or after.count() != 0 or (try frontier.compare(before, after)) != .advance) return error.InvalidTransition;
    }
    return metadata;
}

fn checkLocalEntry(entry: presence.Entry, local: sign.PublicKey, metadata: issuer.Metadata, disabled: bool) !void {
    const record = (try wire.decode(entry.original)).record;
    if (!std.mem.eql(u8, &record.origin, &local) or disabled or entry.conflict != null or record.operation == .quit) return;
    const id = try wire.subject(record.guest);
    if (id.epoch > metadata.epoch or (id.epoch == metadata.epoch and id.counter > metadata.issued_through)) return error.InvalidLocalState;
}

/// Called only after the image encoder validates the whole selected projection.
/// No raw-image trust argument or temporary volatile-WAL restoration shortcut.
fn localRelation(store: *const presence.Store, change: image.Change, rows: retained.IssuerRows, metadata: issuer.Metadata) !bool {
    const projection = try store.project(change);
    var selected: ?presence.OriginFrontier = null;
    var frontiers = projection.frontiers();
    while (frontiers.next()) |item| {
        if (std.mem.eql(u8, &(try frontier.decode(item.original)).origin, &metadata.origin)) selected = item;
    }
    const cut = selected orelse return error.InvalidLocalState;
    const disabled = cut.conflict != null;
    if (!disabled and !std.mem.eql(u8, cut.original, rows.frontier)) return error.InvalidLocalState;
    var entries = projection.entries();
    while (entries.next()) |entry| try checkLocalEntry(entry, metadata.origin, metadata, disabled);
    return disabled;
}

/// Explicit first provisioning only. Caller proves no enabled package exists,
/// supplies a fresh nonzero store UUID, and stages all four rows together.
pub fn encodeInitial(allocator: std.mem.Allocator, context: retained.LocalContext, store_id: [16]u8, store: *const presence.Store, rows: retained.IssuerRows, key: *const sign.KeyPair) !Package {
    try requireKey(context, key);
    const metadata = try issuer.validateRows(rows.metadata, rows.frontier, context.origin);
    var encoded = try image.encodeProjection(allocator, store, .unchanged);
    errdefer encoded.deinit();
    const disabled = try localRelation(store, .unchanged, rows, metadata);
    var head: retained.Head = .{
        .context = context,
        .store_id = store_id,
        .commit_generation = 1,
        .image_generation = 1,
        .previous_head_digest = @splat(0),
        .image_digest = retained.digest(encoded.bytes),
        .image_len = encoded.bytes.len,
        .entries = encoded.entries,
        .frontiers = encoded.frontiers,
        .retained_bytes = encoded.retained_bytes,
        .metadata_digest = undefined,
        .frontier_digest = undefined,
        .epoch = undefined,
        .issued_through = undefined,
        .frontier_revision = undefined,
        .frontier_through = undefined,
        .expiry_floor_ms = 0,
    };
    bindIssuer(&head, rows, metadata);
    return .{ .image = encoded, .head = .{ .head = head, .bytes = try head.encode(key) }, .local_authoring_disabled = disabled };
}

/// Encode a complete successor cut without consuming its RAM plan. Exact
/// predecessor binding prevents a stale/wrong RAM Store from dropping retained
/// negatives while otherwise manufacturing a valid successor local signature.
pub fn prepareImage(allocator: std.mem.Allocator, durable: *const persistence.OroStore, context: retained.LocalContext, store: *const presence.Store, change: image.Change, rows: retained.IssuerRows, expiry_floor_ms: i64, key: *const sign.KeyPair) !Package {
    try requireKey(context, key);
    const old = try retained.readCommittedEnvelope(durable, context);
    if (expiry_floor_ms < old.head.expiry_floor_ms) return error.InvalidTransition;
    const commit_generation = try advance(old.head.commit_generation);
    const image_generation = try advance(old.head.image_generation);
    const metadata = try validateTransition(old, rows, context);
    var predecessor = try image.encodeProjection(allocator, store, .unchanged);
    defer predecessor.deinit();
    if (!std.mem.eql(u8, predecessor.bytes, old.image) or predecessor.entries != old.head.entries or predecessor.frontiers != old.head.frontiers or predecessor.retained_bytes != old.head.retained_bytes) return error.PredecessorMismatch;
    _ = try localRelation(store, .unchanged, old.rows, try issuer.validateRows(old.rows.metadata, old.rows.frontier, context.origin));
    var encoded = try image.encodeProjection(allocator, store, change);
    errdefer encoded.deinit();
    const disabled = try localRelation(store, change, rows, metadata);
    var head = old.head;
    head.commit_generation = commit_generation;
    head.image_generation = image_generation;
    head.previous_head_digest = retained.digest(durable.get(.props, retained.head_key).?);
    head.image_digest = retained.digest(encoded.bytes);
    head.image_len = encoded.bytes.len;
    head.entries = encoded.entries;
    head.frontiers = encoded.frontiers;
    head.retained_bytes = encoded.retained_bytes;
    head.expiry_floor_ms = expiry_floor_ms;
    bindIssuer(&head, rows, metadata);
    return .{ .image = encoded, .head = .{ .head = head, .bytes = try head.encode(key) }, .local_authoring_disabled = disabled };
}

/// Reservations and expiry observations preserve the exact image. An issuer
/// Caller must have already strictly restored/activated the committed image.
/// This API authenticates the envelope and preserves those exact image bytes.
/// A frontier/epoch change needs prepareImage so its negative cut is represented
/// by the same aggregate publication; this API cannot silently change it.
pub fn prepareHeadUpdate(durable: *const persistence.OroStore, context: retained.LocalContext, rows: retained.IssuerRows, expiry_floor_ms: i64, key: *const sign.KeyPair) !EncodedHead {
    try requireKey(context, key);
    const old = try retained.readCommittedEnvelope(durable, context);
    if (expiry_floor_ms < old.head.expiry_floor_ms) return error.InvalidTransition;
    const metadata = try validateTransition(old, rows, context);
    if (metadata.epoch != old.head.epoch or !std.mem.eql(u8, rows.frontier, old.rows.frontier)) return error.InvalidTransition;
    var head = old.head;
    head.commit_generation = try advance(old.head.commit_generation);
    head.previous_head_digest = retained.digest(durable.get(.props, retained.head_key).?);
    head.expiry_floor_ms = expiry_floor_ms;
    bindIssuer(&head, rows, metadata);
    return .{ .head = head, .bytes = try head.encode(key) };
}

fn contextFor(key: *const sign.KeyPair) retained.LocalContext {
    return .{ .origin = key.public_key, .realm = @splat(9) };
}
fn currentRows(owner: *const issuer.Issuer) retained.IssuerRows {
    return .{ .metadata = owner.store.get(.props, issuer.metadata_key).?, .frontier = owner.store.get(.props, issuer.frontier_key).? };
}
fn addLocalCut(store: *presence.Store, owner: *const issuer.Issuer) !void {
    var plan = try store.prepareFrontier(currentRows(owner).frontier, &.{owner.metadata.origin}, 1000);
    defer plan.abort();
    _ = plan.commit();
}
fn provision(owner: *issuer.Issuer, store: *presence.Store, key: *const sign.KeyPair) !void {
    var package = try encodeInitial(std.testing.allocator, contextFor(key), @splat(1), store, currentRows(owner), key);
    defer package.deinit();
    var batch = try owner.store.prepareBatch(&package.mutations());
    defer batch.abort();
    try batch.commit();
}
fn commitFixture(owner: *issuer.Issuer, package: *const Package, rows: retained.IssuerRows) !void {
    const mutations = package.mutations();
    var batch = try owner.store.prepareBatch(&.{
        .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = rows.metadata },
        .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = rows.frontier },
        mutations[0],
        mutations[1],
    });
    defer batch.abort();
    try batch.commit();
}
fn fixtureRecord(origin: sign.PublicKey, counter: u64) !wire.Record {
    return .{ .operation = .present, .origin = origin, .guest = try wire.guestId(.{ .epoch = 1, .counter = counter }), .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 7, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "Guest", .username = "guest", .host = "cloak.onyx", .realname = "Guest", .server = "node-c", .description = "Origin" };
}

test "mesh presence package initial provisioning binds contributions without publishing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(140));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(141));
    defer foreign.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "initial.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    const generation = store.generation;
    const context = contextFor(&key);
    const rows = currentRows(&owner);
    var package = try encodeInitial(std.testing.allocator, context, @splat(1), &store, rows, &key);
    defer package.deinit();
    const head = try retained.verifyEnvelope(&package.head.bytes, package.image.bytes, rows, context);
    try std.testing.expectEqual(@as(u64, 1), head.commit_generation);
    try std.testing.expectEqual(@as(u64, 1), head.image_generation);
    try std.testing.expectEqual(@as(i64, 0), head.expiry_floor_ms);
    try std.testing.expect(!package.local_authoring_disabled);
    try std.testing.expect(owner.store.get(.props, retained.head_key) == null);
    try std.testing.expectEqual(generation, store.generation);
    const contributions = package.mutations();
    try std.testing.expectEqualSlices(u8, retained.image_key, contributions[0].key);
    try std.testing.expectEqualSlices(u8, package.image.bytes, contributions[0].value.?);
    try std.testing.expectEqualSlices(u8, retained.head_key, contributions[1].key);
    try std.testing.expectEqualSlices(u8, &package.head.bytes, contributions[1].value.?);
    var prepared = try owner.store.prepareBatch(&contributions);
    prepared.abort();
    try std.testing.expect(owner.store.get(.props, retained.head_key) == null);
    try std.testing.expectError(error.InvalidHead, encodeInitial(std.testing.allocator, context, @splat(0), &store, rows, &key));
    try std.testing.expectError(error.ContextMismatch, encodeInitial(std.testing.allocator, context, @splat(1), &store, rows, &foreign));
}

test "mesh presence package successor image binds predecessor and prepared RAM publication" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(142));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(143));
    defer remote.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "successor.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    try provision(&owner, &store, &local);
    const old_head = retained.digest(owner.store.get(.props, retained.head_key).?);
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try store.prepare(try wire.encode(try fixtureRecord(remote.public_key, 1), &remote, &buffer), &.{remote.public_key}, 1000);
    defer plan.abort();
    var package = try prepareImage(std.testing.allocator, &owner.store, contextFor(&local), &store, .{ .presence = &plan }, currentRows(&owner), 1500, &local);
    defer package.deinit();
    try std.testing.expectEqual(@as(u64, 2), package.head.head.commit_generation);
    try std.testing.expectEqual(@as(u64, 2), package.head.head.image_generation);
    try std.testing.expectEqualSlices(u8, &old_head, &package.head.head.previous_head_digest);
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expectEqualSlices(u8, &old_head, &retained.digest(owner.store.get(.props, retained.head_key).?));
    var other = try presence.Store.init(std.testing.allocator, .{});
    defer other.deinit();
    try std.testing.expectError(error.PredecessorMismatch, prepareImage(std.testing.allocator, &owner.store, contextFor(&local), &other, .unchanged, currentRows(&owner), 1500, &local));
    try commitFixture(&owner, &package, currentRows(&owner));
    // The package has never consumed the owning RAM handle.
    try std.testing.expect(!plan.done);
    _ = plan.commit();
    var restored = try image.stageRestore(std.testing.allocator, &owner.store, contextFor(&local), .{});
    defer restored.deinit();
    try std.testing.expectEqual(@as(usize, 1), restored.store.entries.items.len);
    try std.testing.expectEqualDeep(package.head.head, restored.head);
    try std.testing.expectError(error.InvalidTransition, prepareImage(std.testing.allocator, &owner.store, contextFor(&local), &store, .unchanged, currentRows(&owner), 1499, &local));
    var wrong_realm = contextFor(&local);
    wrong_realm.realm[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, prepareImage(std.testing.allocator, &owner.store, wrong_realm, &store, .unchanged, currentRows(&owner), 1500, &local));
}

test "mesh presence package head only reservation preserves image generation and floor" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(144));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "head.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    try provision(&owner, &store, &key);
    const initial = (try retained.readCommittedEnvelope(&owner.store, contextFor(&key))).head;
    const old_image = retained.digest(owner.store.get(.props, retained.image_key).?);
    var metadata = owner.metadata;
    metadata.issued_through = 1;
    const raw = metadata.encode();
    const rows: retained.IssuerRows = .{ .metadata = &raw, .frontier = currentRows(&owner).frontier };
    const next = try prepareHeadUpdate(&owner.store, contextFor(&key), rows, 3000, &key);
    try std.testing.expectEqual(@as(u64, 2), next.head.commit_generation);
    try std.testing.expectEqual(initial.image_generation, next.head.image_generation);
    try std.testing.expectEqualSlices(u8, &initial.image_digest, &next.head.image_digest);
    try std.testing.expectEqual(@as(u64, 1), next.head.issued_through);
    try std.testing.expectEqual(@as(i64, 3000), next.head.expiry_floor_ms);
    try std.testing.expectEqualSlices(u8, &old_image, &retained.digest(owner.store.get(.props, retained.image_key).?));
    var batch = try owner.store.prepareBatch(&.{ .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw }, next.mutation() });
    defer batch.abort();
    try batch.commit();
    const observed = try prepareHeadUpdate(&owner.store, contextFor(&key), currentRows(&owner), 3000, &key);
    try std.testing.expectEqual(@as(u64, 3), observed.head.commit_generation);
    try std.testing.expectEqual(@as(u64, 1), observed.head.image_generation);
    try std.testing.expectError(error.InvalidTransition, prepareHeadUpdate(&owner.store, contextFor(&key), currentRows(&owner), 2999, &key));
    try std.testing.expectError(error.InvalidTransition, prepareHeadUpdate(&owner.store, contextFor(&key), .{ .metadata = &owner.metadata.encode(), .frontier = currentRows(&owner).frontier }, 3000, &key));
    var candidate = try image.stageRestore(std.testing.allocator, &owner.store, contextFor(&key), .{});
    defer candidate.deinit();
    try std.testing.expectEqual(@as(u64, 1), candidate.head.image_generation);
    try std.testing.expectEqual(@as(i64, 3000), candidate.head.expiry_floor_ms);
}

test "mesh presence package stages exact cold epoch and rejects issuer regressions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(145));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "transitions.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    try provision(&owner, &store, &key);
    const original_metadata = owner.metadata.encode();
    const original_frontier = try std.testing.allocator.dupe(u8, currentRows(&owner).frontier);
    defer std.testing.allocator.free(original_frontier);
    var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const next_proof = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 2, .through = 0, .issued_ms = 1100, .active = &.{} }, &key, &buffer);
    var metadata = owner.metadata;
    metadata.frontier_revision = 2;
    metadata.frontier_digest = retained.digest(next_proof);
    var raw = metadata.encode();
    var rows: retained.IssuerRows = .{ .metadata = &raw, .frontier = next_proof };
    try std.testing.expectError(error.InvalidTransition, prepareHeadUpdate(&owner.store, contextFor(&key), rows, 0, &key));
    try std.testing.expectError(error.InvalidLocalState, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, rows, 0, &key));
    var plan = try store.prepareFrontier(next_proof, &.{key.public_key}, 1100);
    defer plan.abort();
    var advance_package = try prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .frontier = &plan }, rows, 0, &key);
    defer advance_package.deinit();
    try commitFixture(&owner, &advance_package, rows);
    _ = plan.commit();
    try std.testing.expectError(error.InvalidTransition, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, .{ .metadata = &original_metadata, .frontier = original_frontier }, 0, &key));
    // Same revision with changed signed body is issuer equivocation, never an
    // ordinary advance. Quarantine lives in the image rather than this issuer.
    const contradictory = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 2, .through = 0, .issued_ms = 1200, .active = &.{} }, &key, &buffer);
    metadata.frontier_digest = retained.digest(contradictory);
    raw = metadata.encode();
    try std.testing.expectError(error.InvalidTransition, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, .{ .metadata = &raw, .frontier = contradictory }, 0, &key));
    for ([_]u64{ 3, 2 }) |epoch| {
        const proof = try frontier.encode(.{ .origin = key.public_key, .epoch = epoch, .revision = 1, .through = 0, .issued_ms = 1200, .active = &.{} }, &key, &buffer);
        metadata.epoch = epoch;
        metadata.issued_through = if (epoch == 2) 1 else 0;
        metadata.frontier_revision = 1;
        metadata.frontier_through = 0;
        metadata.frontier_digest = retained.digest(proof);
        raw = metadata.encode();
        try std.testing.expectError(error.InvalidTransition, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, .{ .metadata = &raw, .frontier = proof }, 0, &key));
    }
    const cold_proof = try frontier.encode(.{ .origin = key.public_key, .epoch = 2, .revision = 1, .through = 0, .issued_ms = 1200, .active = &.{} }, &key, &buffer);
    metadata.epoch = 2;
    metadata.issued_through = 0;
    metadata.frontier_revision = 1;
    metadata.frontier_through = 0;
    metadata.frontier_digest = retained.digest(cold_proof);
    raw = metadata.encode();
    rows = .{ .metadata = &raw, .frontier = cold_proof };
    var cold_plan = try store.prepareFrontier(cold_proof, &.{key.public_key}, 1200);
    defer cold_plan.abort();
    var cold = try prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .frontier = &cold_plan }, rows, 0, &key);
    defer cold.deinit();
    try std.testing.expectEqual(@as(u64, 2), cold.head.head.epoch);
    try std.testing.expectEqual(@as(u64, 3), cold.head.head.commit_generation);
    try std.testing.expectEqual(@as(u64, 3), cold.head.head.image_generation);
    cold_plan.abort();
    try std.testing.expectEqual(@as(u64, 1), store.frontiers.items[0].decoded.epoch);
    // Aborting RAM preparation cannot invalidate separately owned image bytes.
    const staged_proof = cold.image.bytes;
    try std.testing.expect(staged_proof.len > image.header_len);
    try std.testing.expectEqualSlices(u8, &cold.head.head.image_digest, &retained.digest(staged_proof));
    try std.testing.expectEqual(@as(u64, 1), (try retained.readCommittedEnvelope(&owner.store, contextFor(&key))).head.epoch);
}

test "mesh presence package preserves genuine local quarantine without manufacturing authoring authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(146));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "quarantine.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    try provision(&owner, &store, &key);
    var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const proof = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = 1100, .active = &.{} }, &key, &buffer);
    var plan = try store.prepareFrontier(proof, &.{key.public_key}, 1100);
    defer plan.abort();
    var package = try prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .frontier = &plan }, currentRows(&owner), 0, &key);
    defer package.deinit();
    try std.testing.expect(package.local_authoring_disabled);
    try std.testing.expect(store.frontiers.items[0].conflict == null);
    try commitFixture(&owner, &package, currentRows(&owner));
    _ = plan.commit();
    var restored = try image.stageRestore(std.testing.allocator, &owner.store, contextFor(&key), .{});
    defer restored.deinit();
    try std.testing.expect(restored.local_authoring_disabled);
    try std.testing.expect(restored.store.frontiers.items[0].conflict != null);
}

test "mesh presence package rejects exhausted generations missing package and bad issuer relation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(147));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(148));
    defer foreign.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "invalid.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    try std.testing.expectError(error.MissingState, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, currentRows(&owner), 0, &key));
    try std.testing.expectError(error.MissingState, prepareHeadUpdate(&owner.store, contextFor(&key), currentRows(&owner), 0, &key));
    try provision(&owner, &store, &key);
    var bad_metadata = owner.metadata;
    bad_metadata.origin = foreign.public_key;
    try std.testing.expectError(error.OriginMismatch, prepareHeadUpdate(&owner.store, contextFor(&key), .{ .metadata = &bad_metadata.encode(), .frontier = currentRows(&owner).frontier }, 0, &key));
    bad_metadata = owner.metadata;
    bad_metadata.frontier_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidState, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, .{ .metadata = &bad_metadata.encode(), .frontier = currentRows(&owner).frontier }, 0, &key));
    var head = (try retained.readCommittedEnvelope(&owner.store, contextFor(&key))).head;
    head.commit_generation = std.math.maxInt(u64);
    head.image_generation = std.math.maxInt(u64);
    head.previous_head_digest = @splat(1);
    const raw = try head.encode(&key);
    try owner.store.put(.props, retained.head_key, &raw);
    try std.testing.expectError(error.GenerationExhausted, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .unchanged, currentRows(&owner), 0, &key));
    try std.testing.expectError(error.GenerationExhausted, prepareHeadUpdate(&owner.store, contextFor(&key), currentRows(&owner), 0, &key));
    try std.testing.expectEqualSlices(u8, &raw, owner.store.get(.props, retained.head_key).?);
}

fn allocationScenario(allocator: std.mem.Allocator, owner: *const issuer.Issuer, store: *const presence.Store, plan: *const presence.Store.Prepared, key: *const sign.KeyPair) !void {
    const generation = store.generation;
    const count = store.entries.items.len;
    const raw_bytes = store.bytes;
    const before_head = retained.digest(owner.store.get(.props, retained.head_key).?);
    const before_image = retained.digest(owner.store.get(.props, retained.image_key).?);
    const before_candidate = retained.digest(plan.candidate.?.original);
    defer {
        std.debug.assert(store.generation == generation and store.entries.items.len == count and store.bytes == raw_bytes);
        std.debug.assert(!plan.done and std.mem.eql(u8, &before_candidate, &retained.digest(plan.candidate.?.original)));
        std.debug.assert(std.mem.eql(u8, &before_head, &retained.digest(owner.store.get(.props, retained.head_key).?)));
        std.debug.assert(std.mem.eql(u8, &before_image, &retained.digest(owner.store.get(.props, retained.image_key).?)));
    }
    var package = prepareImage(allocator, &owner.store, contextFor(key), store, .{ .presence = plan }, currentRows(owner), 1000, key) catch |err| {
        if (err == error.OutOfMemory) {
            var retry = try prepareImage(std.testing.allocator, &owner.store, contextFor(key), store, .{ .presence = plan }, currentRows(owner), 1000, key);
            defer retry.deinit();
            try std.testing.expectEqual(@as(u32, 1), retry.image.entries);
        }
        return err;
    };
    defer package.deinit();
    try std.testing.expectEqual(@as(u32, 1), package.image.entries);
}
fn initialAllocationScenario(allocator: std.mem.Allocator, owner: *const issuer.Issuer, store: *const presence.Store, key: *const sign.KeyPair) !void {
    const before = retained.digest(currentRows(owner).metadata);
    defer std.debug.assert(std.mem.eql(u8, &before, &retained.digest(currentRows(owner).metadata)));
    var package = encodeInitial(allocator, contextFor(key), @splat(1), store, currentRows(owner), key) catch |err| {
        if (err == error.OutOfMemory) {
            var retry = try encodeInitial(std.testing.allocator, contextFor(key), @splat(1), store, currentRows(owner), key);
            defer retry.deinit();
        }
        return err;
    };
    defer package.deinit();
    try std.testing.expectEqual(@as(u32, 1), package.image.frontiers);
}

test "mesh presence package exhaustive allocation failures leave durable state and prepared handle retryable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(149));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(150));
    defer remote.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "oom.wal", &local, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try addLocalCut(&store, &owner);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initialAllocationScenario, .{ &owner, &store, &local });
    try std.testing.expect(owner.store.get(.props, retained.head_key) == null);
    try provision(&owner, &store, &local);
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try store.prepare(try wire.encode(try fixtureRecord(remote.public_key, 1), &remote, &buffer), &.{remote.public_key}, 1000);
    defer plan.abort();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{ &owner, &store, &plan, &local });
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    plan.abort();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
}

test "mesh presence package local positives require staged issuer reservation while negatives survive" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(151));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "local-ids.wal", &key, 1000);
    defer owner.deinit();
    var store = try presence.Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try std.testing.expectError(error.InvalidLocalState, encodeInitial(std.testing.allocator, contextFor(&key), @splat(1), &store, currentRows(&owner), &key));
    try addLocalCut(&store, &owner);
    try provision(&owner, &store, &key);
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try store.prepare(try wire.encode(try fixtureRecord(key.public_key, 1), &key, &buffer), &.{key.public_key}, 1000);
    defer plan.abort();
    try std.testing.expectError(error.InvalidLocalState, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .presence = &plan }, currentRows(&owner), 0, &key));
    var metadata = owner.metadata;
    metadata.issued_through = 1;
    const raw = metadata.encode();
    const rows: retained.IssuerRows = .{ .metadata = &raw, .frontier = currentRows(&owner).frontier };
    var package = try prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .presence = &plan }, rows, 0, &key);
    defer package.deinit();
    try commitFixture(&owner, &package, rows);
    _ = plan.commit();
    var restored = try image.stageRestore(std.testing.allocator, &owner.store, contextFor(&key), .{});
    defer restored.deinit();
    try std.testing.expectEqual(@as(u64, 1), restored.head.issued_through);
    try std.testing.expectEqual(@as(usize, 1), restored.store.entries.items.len);
    var future = try fixtureRecord(key.public_key, 1);
    future.guest = try wire.guestId(.{ .epoch = 2, .counter = 1 });
    var future_plan = try store.prepare(try wire.encode(future, &key, &buffer), &.{key.public_key}, 1000);
    defer future_plan.abort();
    try std.testing.expectError(error.InvalidLocalState, prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .presence = &future_plan }, currentRows(&owner), 0, &key));
    future_plan.abort();
    var quit = try fixtureRecord(key.public_key, 99);
    quit.operation = .quit;
    quit.revision = 2;
    var negative_plan = try store.prepareQuitRepair(try wire.encode(quit, &key, &buffer), &.{key.public_key}, 2100);
    defer negative_plan.abort();
    var negative = try prepareImage(std.testing.allocator, &owner.store, contextFor(&key), &store, .{ .presence = &negative_plan }, currentRows(&owner), 0, &key);
    defer negative.deinit();
    try std.testing.expect(!negative.local_authoring_disabled);
    try std.testing.expectEqual(@as(u32, 2), negative.image.entries);
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
}
