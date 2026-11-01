// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated node-local durable guest identity issuer. One canonical store path
//! per full origin, with a stable lock inode: never rename or unlink its .lock.
//! Acquire custody before WAL open/repair. Close-only release preserves shared
//! descriptor custody during Helix transfer. All mutations require one external owner lock.
const std = @import("std");
const target = @import("builtin");
const persistence = @import("store.zig");
const sign = @import("../crypto/sign.zig");
const presence = @import("../proto/mesh_presence.zig");
const frontier = @import("../proto/mesh_presence_frontier.zig");

pub const metadata_key = "presence-issuer/meta/v1";
pub const frontier_key = "presence-issuer/frontier/v1";
pub const metadata_len = 4 + 1 + 32 + 8 * 4 + 32;
const permissions: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode")) .fromMode(0o600) else .default_file;
pub const Error = error{ InvalidState, AlreadyInitialized, OriginMismatch, IssuanceExhausted, MutationActive, AlreadyConsumed, InvalidFrontier, InvalidClock, AggregateStatePresent };

pub const Metadata = struct {
    origin: sign.PublicKey,
    epoch: u64,
    issued_through: u64,
    frontier_revision: u64,
    frontier_through: u64,
    frontier_digest: [32]u8,

    pub fn encode(self: Metadata) [metadata_len]u8 {
        var out: [metadata_len]u8 = undefined;
        @memcpy(out[0..4], "OPIS");
        out[4] = 1;
        @memcpy(out[5..37], &self.origin);
        std.mem.writeInt(u64, out[37..45], self.epoch, .big);
        std.mem.writeInt(u64, out[45..53], self.issued_through, .big);
        std.mem.writeInt(u64, out[53..61], self.frontier_revision, .big);
        std.mem.writeInt(u64, out[61..69], self.frontier_through, .big);
        @memcpy(out[69..101], &self.frontier_digest);
        return out;
    }

    fn decode(raw: []const u8) Error!Metadata {
        if (raw.len != metadata_len or !std.mem.eql(u8, raw[0..4], "OPIS") or raw[4] != 1) return error.InvalidState;
        const result: Metadata = .{
            .origin = raw[5..37].*,
            .epoch = std.mem.readInt(u64, raw[37..45], .big),
            .issued_through = std.mem.readInt(u64, raw[45..53], .big),
            .frontier_revision = std.mem.readInt(u64, raw[53..61], .big),
            .frontier_through = std.mem.readInt(u64, raw[61..69], .big),
            .frontier_digest = raw[69..101].*,
        };
        if (result.epoch == 0 or result.frontier_revision == 0 or result.frontier_through > result.issued_through) return error.InvalidState;
        return result;
    }
};

fn digest(original: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(original, &out, .{});
    return out;
}

/// Acquire storage custody only, before open/replay/repair. This grants no
/// issuer or retained-image authoring authority; the aggregate must validate
/// its entire mandatory state before returning any live owner.
pub fn acquireLease(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    const lock_path = try std.mem.concat(allocator, u8, &.{ path, ".lock" });
    defer allocator.free(lock_path);
    const file = if (comptime target.os.tag == .windows)
        dir.createFile(io, lock_path, .{ .read = true, .truncate = false, .exclusive = true, .permissions = permissions }) catch |err| switch (err) {
            error.PathAlreadyExists => blk: {
                var opened = try dir.openFile(io, lock_path, .{ .mode = .read_write, .follow_symlinks = false, .allow_directory = false });
                // Zig's no-follow Windows open uses NT asynchronous I/O, but
                // reports blocking flags. Keep positional writes/sync honest.
                opened.flags.nonblocking = true;
                break :blk opened;
            },
            else => return err,
        }
    else
        try dir.createFile(io, lock_path, .{ .read = true, .truncate = false, .permissions = permissions });
    errdefer file.close(io);
    if ((try file.stat(io)).kind != .file) return error.InvalidState;
    if (comptime target.os.tag == .windows) _ = try @import("mesh_presence_lease.zig").statRegular(file.handle);
    if (!try file.tryLock(io, .exclusive)) return error.WouldBlock;
    if (comptime target.os.tag == .windows) {
        const lease = @import("mesh_presence_lease.zig");
        const identity = try lease.statRegular(file.handle);
        const configured = try dir.openFile(io, lock_path, .{ .mode = .read_only, .follow_symlinks = false, .allow_directory = false });
        defer configured.close(io);
        if (!std.meta.eql(identity, try lease.statRegular(configured.handle))) return error.IdentityMismatch;
        // Windows byte-range custody validation must read within the locked
        // range. Preserve an existing lock-file byte; initialize an empty file
        // only after this handle owns the lock.
        if ((try file.stat(io)).size == 0) {
            try file.writePositionalAll(io, "L", 0);
            try file.sync(io);
        }
    }
    return file;
}

// These keys are the mandatory aggregate envelope rows, including malformed or
// partial enablement. A two-row issuer must never author into that format.
fn requireStandalone(store: *const persistence.OroStore) Error!void {
    if (store.get(.props, "presence-retained/image/v1") != null or
        store.get(.props, "presence-retained/head/v1") != null) return error.AggregateStatePresent;
}

fn readMetadata(store: *persistence.OroStore, origin: sign.PublicKey) !Metadata {
    const raw = store.get(.props, metadata_key) orelse return error.InvalidState;
    const original = store.get(.props, frontier_key) orelse return error.InvalidState;
    return validateRows(raw, original, origin);
}

/// Strict borrowed pair validation for a staged aggregate image transaction.
/// This grants no lease custody, authoring authority or mutation permission.
pub fn validateRows(raw: []const u8, original: []const u8, origin: sign.PublicKey) !Metadata {
    const metadata = try Metadata.decode(raw);
    if (!std.mem.eql(u8, &metadata.origin, &origin)) return error.OriginMismatch;
    if (!std.mem.eql(u8, &metadata.frontier_digest, &digest(original))) return error.InvalidState;
    const proof = frontier.decode(original) catch return error.InvalidState;
    proof.verify() catch return error.InvalidState;
    if (!std.mem.eql(u8, &proof.origin, &origin) or proof.epoch != metadata.epoch or proof.revision != metadata.frontier_revision or proof.through != metadata.frontier_through) return error.InvalidState;
    return metadata;
}

pub const Issuer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    lease: std.Io.File,
    store: persistence.OroStore,
    metadata: Metadata,
    next_generation: u64 = 1,
    prepared_generation: ?u64 = null,
    handoff: enum { writable, frozen, retired } = .writable,
    handoff_generation: u64 = 0,

    /// A trusted handoff record: the enclosing authenticated Helix transaction
    /// must bind it to this owner and inherited lease. It is not authority by
    /// itself. Caller serializes the issuer lane and keeps this owner alive.
    const HotCheckpointBacking = struct {
        allocator: std.mem.Allocator,
        source: *Issuer,
        metadata: Metadata,
        frontier_bytes: []u8,
        lease_identity: @import("mesh_presence_lease.zig").Identity,
        generation: u64,
    };
    fn checkpointBacking(checkpoint: *const HotCheckpoint) *const HotCheckpointBacking {
        return @ptrCast(@alignCast(checkpoint));
    }
    pub const HotCheckpoint = opaque {
        pub fn generation(self: *const HotCheckpoint) u64 {
            return checkpointBacking(self).generation;
        }
        pub fn deinit(self: *HotCheckpoint) void {
            const backing: *HotCheckpointBacking = @ptrCast(@alignCast(self));
            const allocator = backing.allocator;
            allocator.free(backing.frontier_bytes);
            allocator.destroy(backing);
        }
    };

    /// No writer may run concurrently. All filesystem work is outside World
    /// and SessionStore cuts; caller ensures operator-controlled directory.
    /// Failure leaves this owner writable; successful capture freezes it.
    pub fn freezeForHotHandoff(self: *Issuer, dir: std.Io.Dir, path: []const u8, expected_origin: sign.PublicKey, identity: @import("mesh_presence_lease.zig").Identity) !*HotCheckpoint {
        if (comptime target.os.tag != .linux) return error.Unsupported;
        try self.requireOwnedReady(dir, path, expected_origin, identity);
        if (self.store.active_prepared != null or self.store.active_batch != null) return error.MutationActive;
        if (self.handoff_generation == std.math.maxInt(u64)) return error.IssuanceExhausted;
        const original = self.originalFrontier();
        _ = try validateRows(&self.metadata.encode(), original, expected_origin);
        const checkpoint = try self.allocator.create(HotCheckpointBacking);
        errdefer self.allocator.destroy(checkpoint);
        const copied = try self.allocator.dupe(u8, original);
        self.handoff_generation += 1;
        checkpoint.* = .{ .allocator = self.allocator, .source = self, .metadata = self.metadata, .frontier_bytes = copied, .lease_identity = identity, .generation = self.handoff_generation };
        self.handoff = .frozen;
        return @ptrCast(checkpoint);
    }

    /// Abort before authenticated commit only. A retired predecessor can
    /// never be thawed; Core must sequence retirement before successor activation.
    pub fn abortHotHandoff(self: *Issuer, generation: u64) !void {
        if (self.handoff != .frozen or self.handoff_generation != generation) return error.StaleHandoff;
        self.handoff = .writable;
    }
    pub fn retireHotHandoff(self: *Issuer, generation: u64) !void {
        if (self.handoff != .frozen or self.handoff_generation != generation) return error.StaleHandoff;
        self.handoff = .retired;
    }

    /// Data-only export for the authenticated mandatory Core capsule. The
    /// frontier slice is borrowed from the live checkpoint. This is not itself
    /// proof of a frozen predecessor or of descriptor custody.
    pub const HotTransferImage = struct {
        metadata: Metadata,
        frontier_bytes: []const u8,
        lease_identity: @import("mesh_presence_lease.zig").Identity,
        generation: u64,
    };
    pub fn hotTransferImage(checkpoint: *const HotCheckpoint) !HotTransferImage {
        const record = checkpointBacking(checkpoint);
        if (record.source.handoff != .frozen or record.source.handoff_generation != record.generation) return error.StaleHandoff;
        return .{ .metadata = record.metadata, .frontier_bytes = record.frontier_bytes, .lease_identity = record.lease_identity, .generation = record.generation };
    }

    /// An inert cross-process candidate. Core must authenticate the mandatory
    /// capsule and descriptor association while the source remains frozen;
    /// COMMIT must irrevocably fence that source before activate. Calling this
    /// API without those external proofs does not establish issuer authority.
    pub const TransferredHotIssuer = struct {
        issuer: ?Issuer,
        pub fn deinit(self: *TransferredHotIssuer) void {
            if (self.issuer) |*issuer| issuer.deinit();
            self.issuer = null;
        }
        /// Core-owned authenticated COMMIT and predecessor fence are required.
        /// No I/O, allocation, epoch mutation or replay occurs here.
        pub fn activateAfterCoreCommit(self: *TransferredHotIssuer) Issuer {
            var issuer = self.issuer orelse unreachable;
            issuer.store.promotePrepared();
            self.issuer = null;
            return issuer;
        }
    };
    /// Consumes an independently owned inherited lease on all paths. The
    /// caller must bind image + descriptor to the live frozen predecessor via
    /// the authenticated Core handoff; this function only checks filesystem
    /// custody and exact durable rows. Unsupported platforms fail closed.
    pub fn stageTransferredHot(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, inherited: std.Io.File, image: HotTransferImage, expected_origin: sign.PublicKey) !TransferredHotIssuer {
        errdefer inherited.close(io);
        if (comptime target.os.tag != .linux) return error.Unsupported;
        if (image.generation == 0 or !std.mem.eql(u8, &image.metadata.origin, &expected_origin)) return error.InvalidState;
        _ = try @import("mesh_presence_lease.zig").validateInherited(a, io, dir, path, inherited, image.lease_identity);
        var staged = try persistence.OroStore.openReadOnlyWithConfig(a, io, dir, path, .{});
        errdefer staged.deinit();
        try requireStandalone(&staged);
        const metadata = try readMetadata(&staged, expected_origin);
        if (!std.mem.eql(u8, &metadata.encode(), &image.metadata.encode()) or
            !std.mem.eql(u8, staged.get(.props, frontier_key).?, image.frontier_bytes)) return error.InvalidState;
        try staged.preparePromotion();
        try staged.releaseReadHandleForPreparedPromotion();
        return .{ .issuer = .{ .allocator = a, .io = io, .lease = inherited, .store = staged, .metadata = metadata } };
    }

    /// Same-process staging proof only: source must outlive the stage, and the
    /// caller must hold the source owner lane across stage, abort and activate.
    /// Cross-process authenticated handoff requires a separate Core protocol.
    /// The inherited file must be a separately owned duplicate
    /// of the live predecessor's locked open-file description; this consumes it
    /// on both success and failure. Trusted capsule and live predecessor prove
    /// provenance; same inode or a successful flock alone cannot establish it.
    /// Core fences predecessor, validates all mandatory state and physical IDs,
    /// and authenticates COMMIT before calling activate. No cold epoch bump.
    pub const StagedHotIssuer = struct {
        issuer: ?Issuer,
        source: *Issuer,
        generation: u64,
        pub fn deinit(self: *StagedHotIssuer) void {
            if (self.issuer) |*issuer| issuer.deinit();
            self.issuer = null;
        }
        pub fn activate(self: *StagedHotIssuer) !Issuer {
            if (self.issuer == null or self.source.handoff != .frozen or self.source.handoff_generation != self.generation) return error.StaleHandoff;
            var issuer = self.issuer.?;
            self.source.handoff = .retired;
            issuer.store.promotePrepared();
            self.issuer = null;
            return issuer;
        }
    };

    pub fn stageHotAdoption(a: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, inherited: std.Io.File, checkpoint: *const HotCheckpoint, expected_origin: sign.PublicKey) !StagedHotIssuer {
        errdefer inherited.close(io);
        if (comptime target.os.tag != .linux) return error.Unsupported;
        const record = checkpointBacking(checkpoint);
        if (record.source.handoff != .frozen or record.source.handoff_generation != record.generation) return error.StaleHandoff;
        if (!std.mem.eql(u8, &record.metadata.origin, &expected_origin)) return error.OriginMismatch;
        _ = try @import("mesh_presence_lease.zig").validateInherited(a, io, dir, path, inherited, record.lease_identity);
        var staged = try persistence.OroStore.openReadOnlyWithConfig(a, io, dir, path, .{});
        errdefer staged.deinit();
        try requireStandalone(&staged);
        const metadata = try readMetadata(&staged, expected_origin);
        if (!std.mem.eql(u8, &metadata.encode(), &record.metadata.encode()) or
            !std.mem.eql(u8, staged.get(.props, frontier_key).?, record.frontier_bytes)) return error.InvalidState;
        try staged.preparePromotion();
        try staged.releaseReadHandleForPreparedPromotion();
        return .{ .issuer = .{ .allocator = a, .io = io, .lease = inherited, .store = staged, .metadata = metadata }, .source = record.source, .generation = record.generation };
    }

    /// Explicit first provisioning only. Missing rows on a later cold open are
    /// never interpreted as a fresh issuer. A partial pair is always refused.
    pub fn initialize(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, key: *const sign.KeyPair, now_ms: i64) !Issuer {
        if (now_ms < 0) return error.InvalidClock;
        const lease = try acquireLease(allocator, io, dir, path);
        errdefer lease.close(io);
        var store = try persistence.OroStore.open(allocator, io, dir, path);
        errdefer store.deinit();
        try requireStandalone(&store);
        const meta = store.get(.props, metadata_key);
        const proof = store.get(.props, frontier_key);
        if (meta != null and proof != null) return error.AlreadyInitialized;
        if (meta != null or proof != null) return error.InvalidState;
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const original = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 0, .issued_ms = now_ms, .active = &.{} }, key, &buffer);
        const metadata: Metadata = .{ .origin = key.public_key, .epoch = 1, .issued_through = 0, .frontier_revision = 1, .frontier_through = 0, .frontier_digest = digest(original) };
        const raw = metadata.encode();
        var batch = try store.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = frontier_key, .value = original },
        });
        defer batch.abort();
        try batch.commit();
        return .{ .allocator = allocator, .io = io, .lease = lease, .store = store, .metadata = metadata };
    }

    /// Strict existing cold boot. Durably advance epoch BEFORE returning any
    /// authoring authority. Failure closes custody; retry may burn an epoch.
    /// Do not call during Helix: staged adoption must preserve the epoch exactly.
    pub fn openCold(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, key: *const sign.KeyPair, now_ms: i64) !Issuer {
        if (now_ms < 0) return error.InvalidClock;
        const lease = try acquireLease(allocator, io, dir, path);
        errdefer lease.close(io);
        // A missing durable file is not silently created by ordinary open.
        const existing = try dir.openFile(io, path, .{});
        existing.close(io);
        var store = try persistence.OroStore.open(allocator, io, dir, path);
        errdefer store.deinit();
        try requireStandalone(&store);
        var metadata = try readMetadata(&store, key.public_key);
        if (metadata.epoch == std.math.maxInt(u64)) return error.IssuanceExhausted;
        metadata.epoch += 1;
        metadata.issued_through = 0;
        metadata.frontier_revision = 1;
        metadata.frontier_through = 0;
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const original = try frontier.encode(.{ .origin = key.public_key, .epoch = metadata.epoch, .revision = 1, .through = 0, .issued_ms = now_ms, .active = &.{} }, key, &buffer);
        metadata.frontier_digest = digest(original);
        const raw = metadata.encode();
        var batch = try store.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = frontier_key, .value = original },
        });
        defer batch.abort();
        try batch.commit();
        return .{ .allocator = allocator, .io = io, .lease = lease, .store = store, .metadata = metadata };
    }

    pub fn deinit(self: *Issuer) void {
        self.store.deinit();
        // Never unlock explicitly: an adopted duplicate shares this same lock.
        self.lease.close(self.io);
        self.* = undefined;
    }

    fn writable(self: *const Issuer) !void {
        if (self.handoff != .writable) return error.IssuerHandoffFrozen;
        try requireStandalone(&self.store);
        if (self.store.preparedWritesPoisoned()) return error.StorePoisoned;
        if (self.store.isReadOnly()) return error.ReadOnlyStore;
        if (self.prepared_generation != null) return error.MutationActive;
    }

    /// Revalidate the original owned standalone issuer and its configured
    /// canonical lease. This is filesystem I/O: call only outside World and
    /// SessionStore cuts, while the caller serializes the issuer lane.
    pub fn requireOwnedReadyNoIo(self: *const Issuer, expected_origin: sign.PublicKey) !void {
        try self.writable();
        if (!std.mem.eql(u8, &self.metadata.origin, &expected_origin)) return error.OriginMismatch;
    }

    pub fn requireOwnedReady(self: *const Issuer, dir: std.Io.Dir, path: []const u8, expected_origin: sign.PublicKey, lease_identity: @import("mesh_presence_lease.zig").Identity) !void {
        try self.requireOwnedReadyNoIo(expected_origin);
        _ = try @import("mesh_presence_lease.zig").validateInherited(self.allocator, self.io, dir, path, self.lease, lease_identity);
    }

    /// Reservation is durable BEFORE the subject escapes. A failed downstream
    /// registration burns it. It does not enlarge the advertised retirement cut.
    pub fn reserveSubject(self: *Issuer) !presence.Subject {
        try self.writable();
        if (self.metadata.issued_through == std.math.maxInt(u64)) return error.IssuanceExhausted;
        var candidate = self.metadata;
        candidate.issued_through += 1;
        const raw = candidate.encode();
        var put = try self.store.preparePut(.props, metadata_key, &raw);
        defer put.abort();
        try put.commit();
        self.metadata = candidate;
        return .{ .epoch = candidate.epoch, .counter = candidate.issued_through };
    }

    /// Sole owner handle under the same lock as the World/presence candidate.
    /// Durable commit must precede their no-fail joint RAM publication. Copying
    /// this handle or moving Issuer while it is outstanding is forbidden.
    pub const Prepared = struct {
        issuer: *Issuer,
        generation: u64,
        batch: persistence.PreparedBatch,
        metadata: Metadata,
        done: bool = false,

        pub fn abort(self: *Prepared) void {
            if (self.done) return;
            if (self.issuer.prepared_generation == self.generation) {
                self.batch.abort();
                self.issuer.prepared_generation = null;
            }
            self.done = true;
        }

        pub fn commitDurable(self: *Prepared) !void {
            if (self.done or self.issuer.prepared_generation != self.generation) return error.AlreadyConsumed;
            try requireStandalone(&self.issuer.store);
            try self.batch.commit();
            self.issuer.metadata = self.metadata;
            self.issuer.prepared_generation = null;
            self.done = true;
        }
    };

    /// The caller supplies the COMPLETE active physical-counter set for the
    /// selected prefix, including prepared registrations that will publish in
    /// the same joint cut. No pending registration may be omitted accidentally.
    /// The codec refuses unsorted, duplicate or over-limit partial sets.
    pub fn prepareFrontierPublication(self: *Issuer, through: u64, active: []const u64, key: *const sign.KeyPair, now_ms: i64) !Prepared {
        try self.writable();
        if (!std.mem.eql(u8, &key.public_key, &self.metadata.origin)) return error.OriginMismatch;
        if (through > self.metadata.issued_through or through < self.metadata.frontier_through) return error.InvalidFrontier;
        if (self.metadata.frontier_revision == std.math.maxInt(u64) or self.next_generation == std.math.maxInt(u64)) return error.IssuanceExhausted;
        var candidate = self.metadata;
        candidate.frontier_revision += 1;
        candidate.frontier_through = through;
        const buffer = try self.allocator.alloc(u8, frontier.max_wire_len);
        defer self.allocator.free(buffer);
        const original = try frontier.encode(.{ .origin = candidate.origin, .epoch = candidate.epoch, .revision = candidate.frontier_revision, .through = through, .issued_ms = now_ms, .active = active }, key, buffer);
        const current = try frontier.decode(self.store.get(.props, frontier_key) orelse return error.InvalidState);
        if (try frontier.compare(current, try frontier.decode(original)) != .advance) return error.InvalidFrontier;
        candidate.frontier_digest = digest(original);
        const raw = candidate.encode();
        const batch = try self.store.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = frontier_key, .value = original },
        });
        const generation = self.next_generation;
        self.next_generation += 1;
        self.prepared_generation = generation;
        return .{ .issuer = self, .generation = generation, .batch = batch, .metadata = candidate };
    }

    /// Borrowed immutable original proof; do not keep across a durable commit.
    pub fn originalFrontier(self: *const Issuer) []const u8 {
        return self.store.get(.props, frontier_key).?;
    }
};

test "mesh presence issuer cold boot advances epoch and burns reserved counters" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(101));
    defer key.deinit();
    {
        var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
        defer issuer.deinit();
        const first = try issuer.reserveSubject();
        // Simulate failed registration: no frontier publication for first.
        const second = try issuer.reserveSubject();
        try std.testing.expectEqual(@as(u64, 1), first.epoch);
        try std.testing.expectEqual(@as(u64, 1), first.counter);
        try std.testing.expectEqual(@as(u64, 2), second.counter);
        try std.testing.expectEqual(@as(u64, 0), issuer.metadata.frontier_through);
        var cut = try issuer.prepareFrontierPublication(2, &.{2}, &key, 1000);
        defer cut.abort();
        try cut.commitDurable();
        const proof = try frontier.decode(issuer.originalFrontier());
        try proof.verify();
        try std.testing.expect(proof.retires(key.public_key, 1, 1));
        try std.testing.expect(!proof.retires(key.public_key, 1, 2));
    }
    var reopened = try Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 0);
    defer reopened.deinit();
    const next = try reopened.reserveSubject();
    try std.testing.expectEqual(@as(u64, 2), next.epoch);
    try std.testing.expectEqual(@as(u64, 1), next.counter);
    const proof = try frontier.decode(reopened.originalFrontier());
    try proof.verify();
    try std.testing.expect(proof.retires(key.public_key, 1, 2));
}

test "mesh presence issuer kernel custody excludes second store before opening WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(102));
    defer key.deinit();
    var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
    defer issuer.deinit();
    const offset = issuer.store.wal_offset;
    try std.testing.expectError(error.WouldBlock, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000));
    try std.testing.expectError(error.WouldBlock, Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000));
    try std.testing.expectEqual(offset, issuer.store.wal_offset);
    try std.testing.expectEqual(@as(u64, 1), issuer.metadata.epoch);
}

test "mesh presence issuer strict load refuses missing partial and malformed state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(103));
    defer key.deinit();
    try std.testing.expectError(error.FileNotFound, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "missing.wal", &key, 1000));
    {
        var store = try persistence.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "empty.wal");
        store.deinit();
    }
    try std.testing.expectError(error.InvalidState, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "empty.wal", &key, 1000));
    {
        var store = try persistence.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "partial.wal");
        defer store.deinit();
        try store.put(.props, metadata_key, "Malformed");
    }
    try std.testing.expectError(error.InvalidState, Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "partial.wal", &key, 1000));
    try std.testing.expectError(error.InvalidState, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "partial.wal", &key, 1000));
    {
        var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "valid.wal", &key, 1000);
        try issuer.store.put(.props, metadata_key, "Malformed");
        issuer.deinit();
    }
    try std.testing.expectError(error.InvalidState, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "valid.wal", &key, 1000));
}

test "mesh presence issuer prepared abort keeps original proof and reserved highwater" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(104));
    defer key.deinit();
    var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
    defer issuer.deinit();
    _ = try issuer.reserveSubject();
    const before = issuer.metadata;
    const proof = issuer.originalFrontier();
    const offset = issuer.store.wal_offset;
    var cut = try issuer.prepareFrontierPublication(1, &.{1}, &key, 1000);
    try std.testing.expectError(error.MutationActive, issuer.reserveSubject());
    cut.abort();
    try std.testing.expectEqual(before, issuer.metadata);
    try std.testing.expectEqual(proof.ptr, issuer.originalFrontier().ptr);
    try std.testing.expectEqual(offset, issuer.store.wal_offset);
    var published = try issuer.prepareFrontierPublication(1, &.{1}, &key, 1000);
    defer published.abort();
    try published.commitDurable();
    try std.testing.expectError(error.AlreadyConsumed, published.commitDurable());
    var retired = try issuer.prepareFrontierPublication(1, &.{}, &key, 1000);
    defer retired.abort();
    try retired.commitDurable();
    try std.testing.expectError(error.InvalidFrontier, issuer.prepareFrontierPublication(1, &.{1}, &key, 1000));
    try std.testing.expectError(error.InvalidFrontier, issuer.prepareFrontierPublication(2, &.{}, &key, 1000));
    try std.testing.expectError(error.InvalidFrontier, issuer.prepareFrontierPublication(0, &.{}, &key, 1000));
}

test "mesh presence issuer ambiguous writes deny issuance and recover complete durable pair" {
    var key = try sign.KeyPair.fromSeed(@splat(105));
    defer key.deinit();
    const faults = [_]persistence.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } };
    for (faults) |fault| for ([_]bool{ false, true }) |publish| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
        defer issuer.deinit();
        _ = try issuer.reserveSubject();
        const before = issuer.metadata;
        issuer.store.setPreparedIoFault(fault);
        if (publish) {
            var candidate = try issuer.prepareFrontierPublication(1, &.{1}, &key, 1000);
            defer candidate.abort();
            try std.testing.expectError(error.IoAmbiguous, candidate.commitDurable());
        } else try std.testing.expectError(error.IoAmbiguous, issuer.reserveSubject());
        try std.testing.expectEqual(before, issuer.metadata);
        try std.testing.expectError(error.StorePoisoned, issuer.reserveSubject());
        // Keep custody while a test-only recovery handle repairs a torn tail.
        // Production closes/reopens the issuer under the same canonical lease.
        var recovered = try persistence.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal");
        defer recovered.deinit();
        const metadata = try readMetadata(&recovered, key.public_key);
        try std.testing.expectEqual(@as(u64, 1), metadata.epoch);
        if (publish) {
            try std.testing.expect(metadata.frontier_through == 0 or metadata.frontier_through == 1);
            try std.testing.expectEqual(@as(u64, 1), metadata.issued_through);
        } else {
            try std.testing.expect(metadata.issued_through == 1 or metadata.issued_through == 2);
            try std.testing.expectEqual(@as(u64, 0), metadata.frontier_through);
        }
    };
}

fn allocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, publication: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var issuer = try Issuer.initialize(allocator, std.testing.io, tmp.dir, "issuer.wal", key, 1000);
    defer issuer.deinit();
    _ = try issuer.reserveSubject();
    const metadata = issuer.metadata;
    const offset = issuer.store.wal_offset;
    const proof = issuer.originalFrontier().ptr;
    if (publication) {
        var prepared = issuer.prepareFrontierPublication(1, &.{1}, key, 1000) catch |err| {
            try std.testing.expectEqual(metadata, issuer.metadata);
            try std.testing.expectEqual(offset, issuer.store.wal_offset);
            try std.testing.expectEqual(proof, issuer.originalFrontier().ptr);
            try std.testing.expect(issuer.prepared_generation == null);
            return err;
        };
        defer prepared.abort();
        try prepared.commitDurable();
    } else {
        _ = issuer.reserveSubject() catch |err| {
            try std.testing.expectEqual(metadata, issuer.metadata);
            try std.testing.expectEqual(offset, issuer.store.wal_offset);
            try std.testing.expectEqual(proof, issuer.originalFrontier().ptr);
            return err;
        };
    }
}

test "mesh presence issuer allocation failures preserve published metadata and proof" {
    var key = try sign.KeyPair.fromSeed(@splat(106));
    defer key.deinit();
    for ([_]bool{ false, true }) |publication| try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{ &key, publication });
}

test "mesh presence issuer origin digest and exhaustion checks refuse invented authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(107));
    defer key.deinit();
    var wrong = try sign.KeyPair.fromSeed(@splat(108));
    defer wrong.deinit();
    {
        var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
        defer issuer.deinit();
        try std.testing.expectError(error.OriginMismatch, issuer.prepareFrontierPublication(0, &.{}, &wrong, 1000));
        issuer.metadata.issued_through = std.math.maxInt(u64);
        try std.testing.expectError(error.IssuanceExhausted, issuer.reserveSubject());
        issuer.metadata.issued_through = 0;
        issuer.metadata.frontier_revision = std.math.maxInt(u64);
        try std.testing.expectError(error.IssuanceExhausted, issuer.prepareFrontierPublication(0, &.{}, &key, 1000));
    }
    try std.testing.expectError(error.OriginMismatch, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &wrong, 1000));
    {
        var store = try persistence.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal");
        defer store.deinit();
        var metadata = try readMetadata(&store, key.public_key);
        metadata.epoch = std.math.maxInt(u64);
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const original = try frontier.encode(.{ .origin = key.public_key, .epoch = metadata.epoch, .revision = 1, .through = 0, .issued_ms = 1000, .active = &.{} }, &key, &buffer);
        metadata.frontier_digest = digest(original);
        const raw = metadata.encode();
        var pair = try store.prepareBatch(&.{ .{ .family = .props, .kind = .put, .key = metadata_key, .value = &raw }, .{ .family = .props, .kind = .put, .key = frontier_key, .value = original } });
        defer pair.abort();
        try pair.commit();
    }
    try std.testing.expectError(error.IssuanceExhausted, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000));
    {
        var store = try persistence.OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal");
        defer store.deinit();
        var metadata = try readMetadata(&store, key.public_key);
        metadata.frontier_digest[0] ^= 1;
        const raw = metadata.encode();
        try store.put(.props, metadata_key, &raw);
    }
    try std.testing.expectError(error.InvalidState, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000));
}

fn coldAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var provisioned = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", key, 1000);
        _ = try provisioned.reserveSubject();
        provisioned.deinit();
    }
    var cold = Issuer.openCold(allocator, std.testing.io, tmp.dir, "issuer.wal", key, 1000) catch |err| {
        const lease = try acquireLease(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal");
        defer lease.close(std.testing.io);
        var store = try persistence.OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", .{});
        defer store.deinit();
        const retained = try readMetadata(&store, key.public_key);
        try std.testing.expectEqual(@as(u64, 1), retained.epoch);
        try std.testing.expectEqual(@as(u64, 1), retained.issued_through);
        return err;
    };
    defer cold.deinit();
    try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
    try std.testing.expectEqual(@as(u64, 0), cold.metadata.issued_through);
    try std.testing.expectEqual(cold.metadata, try readMetadata(&cold.store, key.public_key));
}

test "mesh presence issuer cold advance allocation failures preserve previous durable image" {
    var key = try sign.KeyPair.fromSeed(@splat(109));
    defer key.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, coldAllocationScenario, .{&key});
}

test "mesh presence issuer duplicate close preserves exclusive custody until last owner" {
    const builtin = @import("builtin");
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd and builtin.os.tag != .freebsd) return error.SkipZigTest;
    const runtime = @import("os_runtime.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(110));
    defer key.deinit();
    var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
    const copy = try runtime.duplicate(issuer.lease.handle);
    issuer.deinit();
    var copy_owned = true;
    defer if (copy_owned) runtime.close(copy);
    try std.testing.expectError(error.WouldBlock, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000));
    runtime.close(copy);
    copy_owned = false;
    var cold = try Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
    defer cold.deinit();
    try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
}

fn linuxContender(dir: std.Io.Dir, denied: bool) !void {
    const linux = std.os.linux;
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.TestUnexpectedResult;
    if (forked == 0) {
        // Only raw syscalls after fork: no allocator/Io locks in the child.
        const opened = linux.openat(dir.handle, "issuer.wal.lock", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        if (linux.errno(opened) != .SUCCESS) linux.exit(10);
        const result = linux.errno(linux.flock(@intCast(opened), std.posix.LOCK.EX | std.posix.LOCK.NB));
        const correct = if (denied) result == .AGAIN else result == .SUCCESS;
        linux.exit(if (correct) 0 else 11);
    }
    var status: i32 = 0;
    while (true) {
        const waited = linux.wait4(@intCast(forked), &status, 0, null);
        switch (linux.errno(waited)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqual(@as(i32, 0), status);
}

test "mesh presence issuer independent process contender obeys last-close custody" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(111));
    defer key.deinit();
    var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
    var issuer_owned = true;
    defer if (issuer_owned) issuer.deinit();
    try linuxContender(tmp.dir, true);
    // Child exit closed its inherited descriptor without unlocking the parent.
    try linuxContender(tmp.dir, true);
    issuer.deinit();
    issuer_owned = false;
    try linuxContender(tmp.dir, false);
}

test "mesh presence issuer refuses aggregate and partial envelopes without authoring" {
    var key = try sign.KeyPair.fromSeed(@splat(117));
    defer key.deinit();
    const keys = [_][]const u8{ "presence-retained/image/v1", "presence-retained/head/v1" };
    for (keys) |aggregate_key| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var old_metadata: Metadata = undefined;
        {
            var owner = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "legacy.wal", &key, 1000);
            defer owner.deinit();
            _ = try owner.reserveSubject();
            try owner.store.put(.props, aggregate_key, "partial-or-malformed-must-still-refuse");
            const offset = owner.store.wal_offset;
            old_metadata = owner.metadata;
            try std.testing.expectError(error.AggregateStatePresent, owner.reserveSubject());
            try std.testing.expectError(error.AggregateStatePresent, owner.prepareFrontierPublication(1, &.{1}, &key, 1000));
            try std.testing.expectEqualDeep(old_metadata, owner.metadata);
            try std.testing.expectEqual(offset, owner.store.wal_offset);
        }
        const before = try tmp.dir.readFileAlloc(std.testing.io, "legacy.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(before);
        try std.testing.expectError(error.AggregateStatePresent, Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "legacy.wal", &key, 1000));
        try std.testing.expectError(error.AggregateStatePresent, Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "legacy.wal", &key, 1000));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "legacy.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        // Rejection released custody; aggregate-format inspection can reopen.
        var recovered = try persistence.OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "legacy.wal", .{ .changefeed_capacity = 0 });
        defer recovered.deinit();
        try std.testing.expectEqualDeep(old_metadata, try readMetadata(&recovered, key.public_key));
    }
}

test "owned issuer readiness verifies origin canonical lease and active mutation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(117));
    defer key.deinit();
    var wrong = try sign.KeyPair.fromSeed(@splat(118));
    defer wrong.deinit();
    var issuer = try Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "issuer.wal", &key, 1000);
    defer issuer.deinit();
    const lease = @import("mesh_presence_lease.zig");
    const identity = try lease.statRegular(issuer.lease.handle);
    try issuer.requireOwnedReady(tmp.dir, "issuer.wal", key.public_key, identity);
    try std.testing.expectError(error.OriginMismatch, issuer.requireOwnedReady(tmp.dir, "issuer.wal", wrong.public_key, identity));
    var altered = identity;
    altered.inode +%= 1;
    try std.testing.expectError(error.IdentityMismatch, issuer.requireOwnedReady(tmp.dir, "issuer.wal", key.public_key, altered));
    var prepared = try issuer.prepareFrontierPublication(0, &.{}, &key, 1000);
    defer prepared.abort();
    try std.testing.expectError(error.MutationActive, issuer.requireOwnedReady(tmp.dir, "issuer.wal", key.public_key, identity));
}

test "issuer hot custody staged transfer preserves epoch and fences old writer" {
    if (comptime target.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.generate(io);
    defer key.deinit();
    var source = try Issuer.initialize(a, io, tmp.dir, "issuer.wal", &key, 1000);
    defer source.deinit();
    const first = try source.reserveSubject();
    const original = try a.dupe(u8, source.originalFrontier());
    defer a.free(original);
    const identity = try @import("mesh_presence_lease.zig").statRegular(source.lease.handle);
    const checkpoint = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer checkpoint.deinit();
    try std.testing.expectError(error.IssuerHandoffFrozen, source.reserveSubject());
    const duplicate: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.lease.handle), .flags = source.lease.flags };
    const image = try Issuer.hotTransferImage(checkpoint);
    var staged = try Issuer.stageTransferredHot(a, io, tmp.dir, "issuer.wal", duplicate, image, key.public_key);
    defer staged.deinit();
    try std.testing.expectEqual(first.epoch, source.metadata.epoch);
    try std.testing.expectEqualSlices(u8, original, source.originalFrontier());
    try source.retireHotHandoff(checkpoint.generation());
    var successor = staged.activateAfterCoreCommit();
    defer successor.deinit();
    try std.testing.expectError(error.IssuerHandoffFrozen, source.reserveSubject());
    try std.testing.expectError(error.StaleHandoff, source.abortHotHandoff(checkpoint.generation()));
    try std.testing.expectEqualSlices(u8, original, successor.originalFrontier());
    const second = try successor.reserveSubject();
    try std.testing.expectEqual(first.epoch, second.epoch);
    try std.testing.expectEqual(first.counter + 1, second.counter);
}

test "issuer hot custody abort rejects stale stage and reopened lease" {
    if (comptime target.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.generate(io);
    defer key.deinit();
    var source = try Issuer.initialize(a, io, tmp.dir, "issuer.wal", &key, 1000);
    defer source.deinit();
    const identity = try @import("mesh_presence_lease.zig").statRegular(source.lease.handle);
    const checkpoint = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer checkpoint.deinit();
    const reopened = try tmp.dir.openFile(io, "issuer.wal.lock", .{ .mode = .read_write });
    try std.testing.expectError(error.WouldBlock, Issuer.stageHotAdoption(a, io, tmp.dir, "issuer.wal", reopened, checkpoint, key.public_key));
    const duplicate: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.lease.handle), .flags = source.lease.flags };
    var staged = try Issuer.stageHotAdoption(a, io, tmp.dir, "issuer.wal", duplicate, checkpoint, key.public_key);
    defer staged.deinit();
    try source.abortHotHandoff(checkpoint.generation());
    try std.testing.expectError(error.StaleHandoff, staged.activate());
    _ = try source.reserveSubject();
}

test "issuer hot custody rejects prepared mutation and mismatched durable image" {
    if (comptime target.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(0xd4));
    defer key.deinit();
    var source = try Issuer.initialize(a, io, tmp.dir, "issuer.wal", &key, 1000);
    defer source.deinit();
    const identity = try @import("mesh_presence_lease.zig").statRegular(source.lease.handle);
    var prepared = try source.prepareFrontierPublication(0, &.{}, &key, 1001);
    try std.testing.expectError(error.MutationActive, source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity));
    prepared.abort();
    const checkpoint = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer checkpoint.deinit();
    var image = try Issuer.hotTransferImage(checkpoint);
    image.metadata.issued_through += 1;
    const duplicate: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.lease.handle), .flags = source.lease.flags };
    try std.testing.expectError(error.InvalidState, Issuer.stageTransferredHot(a, io, tmp.dir, "issuer.wal", duplicate, image, key.public_key));
    try source.abortHotHandoff(checkpoint.generation());
    const first = try source.reserveSubject();
    try std.testing.expectEqual(@as(u64, 1), first.epoch);
    try std.testing.expectEqual(@as(u64, 1), first.counter);
}

test "issuer hot custody allocation sweeps preserve source and descriptor ownership" {
    if (comptime target.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(0xd5));
    defer key.deinit();
    var source = try Issuer.initialize(a, io, tmp.dir, "issuer.wal", &key, 1000);
    defer source.deinit();
    const identity = try @import("mesh_presence_lease.zig").statRegular(source.lease.handle);
    const before = source.metadata;
    var freeze_success = false;
    for (0..512) |i| {
        var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = i });
        source.allocator = failing.allocator();
        const result = source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
        if (result) |checkpoint| {
            try std.testing.expect(!failing.has_induced_failure);
            try source.abortHotHandoff(checkpoint.generation());
            checkpoint.deinit();
            freeze_success = true;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expect(source.handoff == .writable);
            try std.testing.expectEqualDeep(before, source.metadata);
        }
        source.allocator = a;
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (freeze_success) break;
    }
    try std.testing.expect(freeze_success);
    const checkpoint = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer checkpoint.deinit();
    defer source.abortHotHandoff(checkpoint.generation()) catch unreachable;
    const image = try Issuer.hotTransferImage(checkpoint);
    for ([_]bool{ false, true }) |transferred| {
        var success = false;
        for (0..512) |i| {
            var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = i });
            const duplicate: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.lease.handle), .flags = source.lease.flags };
            const fd = duplicate.handle;
            if (transferred) {
                if (Issuer.stageTransferredHot(failing.allocator(), io, tmp.dir, "issuer.wal", duplicate, image, key.public_key)) |value| {
                    var stage = value;
                    stage.deinit();
                    try std.testing.expect(!failing.has_induced_failure);
                    success = true;
                } else |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    try std.testing.expect(failing.has_induced_failure);
                }
            } else {
                if (Issuer.stageHotAdoption(failing.allocator(), io, tmp.dir, "issuer.wal", duplicate, checkpoint, key.public_key)) |value| {
                    var stage = value;
                    stage.deinit();
                    try std.testing.expect(!failing.has_induced_failure);
                    success = true;
                } else |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    try std.testing.expect(failing.has_induced_failure);
                }
            }
            try std.testing.expect(!@import("os_runtime.zig").fdValid(fd));
            try std.testing.expect(@import("os_runtime.zig").fdValid(source.lease.handle));
            try std.testing.expectEqualDeep(before, source.metadata);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            if (success) break;
        }
        try std.testing.expect(success);
    }
}

test "issuer hot custody poisoned source and stale generation refuse handoff" {
    if (comptime target.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(0xd6));
    defer key.deinit();
    var source = try Issuer.initialize(a, io, tmp.dir, "issuer.wal", &key, 1000);
    defer source.deinit();
    const identity = try @import("mesh_presence_lease.zig").statRegular(source.lease.handle);
    const old = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer old.deinit();
    try source.abortHotHandoff(old.generation());
    const current = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer current.deinit();
    try std.testing.expectError(error.StaleHandoff, source.abortHotHandoff(old.generation()));
    try std.testing.expectError(error.StaleHandoff, Issuer.hotTransferImage(old));
    try source.abortHotHandoff(current.generation());
    source.store.setPreparedIoFault(.{ .write = .failed });
    try std.testing.expectError(error.IoAmbiguous, source.reserveSubject());
    try std.testing.expectError(error.StorePoisoned, source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity));
}

test "issuer hot custody rejects mismatch and torn tail without changing WAL bytes" {
    if (comptime target.os.tag != .linux) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(0xd7));
    defer key.deinit();
    var source = try Issuer.initialize(a, io, tmp.dir, "issuer.wal", &key, 1000);
    defer source.deinit();
    const identity = try @import("mesh_presence_lease.zig").statRegular(source.lease.handle);
    const checkpoint = try source.freezeForHotHandoff(tmp.dir, "issuer.wal", key.public_key, identity);
    defer checkpoint.deinit();
    defer source.abortHotHandoff(checkpoint.generation()) catch unreachable;
    var image = try Issuer.hotTransferImage(checkpoint);
    const original = try tmp.dir.readFileAlloc(io, "issuer.wal", a, .unlimited);
    defer a.free(original);
    image.metadata.issued_through += 1;
    const first: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.lease.handle), .flags = source.lease.flags };
    try std.testing.expectError(error.InvalidState, Issuer.stageTransferredHot(a, io, tmp.dir, "issuer.wal", first, image, key.public_key));
    const after = try tmp.dir.readFileAlloc(io, "issuer.wal", a, .unlimited);
    defer a.free(after);
    try std.testing.expectEqualSlices(u8, original, after);
    const writer = try tmp.dir.openFile(io, "issuer.wal", .{ .mode = .read_write });
    defer writer.close(io);
    try writer.writePositionalAll(io, "torn", original.len);
    const torn = try tmp.dir.readFileAlloc(io, "issuer.wal", a, .unlimited);
    defer a.free(torn);
    image = try Issuer.hotTransferImage(checkpoint);
    const second: std.Io.File = .{ .handle = try @import("os_runtime.zig").duplicate(source.lease.handle), .flags = source.lease.flags };
    try std.testing.expectError(error.BadRecord, Issuer.stageTransferredHot(a, io, tmp.dir, "issuer.wal", second, image, key.public_key));
    const torn_after = try tmp.dir.readFileAlloc(io, "issuer.wal", a, .unlimited);
    defer a.free(torn_after);
    try std.testing.expectEqualSlices(u8, torn, torn_after);
}
