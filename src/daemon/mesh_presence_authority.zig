// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single leased WAL owner for issuer and retained presence. Constructors and
//! prepared transitions allocate everything before durable publication; RAM
//! publication is no-fail after the one batch commit. Hot staging remains inert
//! until authenticated COMMIT and predecessor exit are proved by its caller.
//! Every operation requires one external graph/owner lock. Do not move this
//! owner while a prepared handle exists; do not mutate its stores out of band.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const wire = @import("../proto/mesh_presence_v2.zig");
const frontier = @import("../proto/mesh_presence_frontier.zig");
const issuer = @import("mesh_presence_issuer.zig");
const presence = @import("mesh_presence_store.zig");
const image = @import("mesh_presence_image.zig");
const retained = @import("mesh_presence_retained.zig");
const package = @import("mesh_presence_package.zig");
const persistence = @import("store.zig");
const lease_custody = @import("mesh_presence_lease.zig");

pub const Error = error{ InvalidState, AlreadyInitialized, AuthoringDisabled, MutationActive, AlreadyConsumed, GenerationExhausted, InvalidClock, InvalidFrontier, MigrationRequired };
pub const Config = struct {
    retained: presence.Config = .{},
    storage: persistence.Config = .{ .changefeed_capacity = 0 },
};

pub const Authority = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    lease: std.Io.File,
    durable: persistence.OroStore,
    retained_store: presence.Store,
    context: retained.LocalContext,
    metadata: issuer.Metadata,
    head: retained.Head,
    local_authoring_disabled: bool,
    published_generation: u64,
    next_generation: u64 = 1,
    active_generation: ?u64 = null,

    /// Explicit first provisioning. All four rows are one durable cut; no
    /// issuer is exposed after an intermediate two-row initialization.
    pub fn initialize(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, context: retained.LocalContext, store_id: [16]u8, key: *const sign.KeyPair, now_ms: i64, config: Config) !Authority {
        try requireKey(context, key);
        if (now_ms < 0) return error.InvalidClock;
        if (try existingColdNamespace(allocator, io, dir, path)) return error.AlreadyInitialized;
        const lease = try acquireProvisioningLease(allocator, io, dir, path);
        errdefer lease.close(io);
        if (try existingColdNamespace(allocator, io, dir, path)) return error.AlreadyInitialized;
        var provisioning = try persistence.FirstProvisionStage.init(allocator, io, dir, path, lease, config.storage);
        defer provisioning.deinit();
        var store = try presence.Store.init(allocator, config.retained);
        errdefer store.deinit();
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const proof = try frontier.encode(.{ .origin = context.origin, .epoch = 1, .revision = 1, .through = 0, .issued_ms = now_ms, .active = &.{} }, key, &buffer);
        const metadata: issuer.Metadata = .{ .origin = context.origin, .epoch = 1, .issued_through = 0, .frontier_revision = 1, .frontier_through = 0, .frontier_digest = retained.digest(proof) };
        const raw = metadata.encode();
        // This store is inert and rollback-owned until the durable cut succeeds.
        var initial = try store.prepareFrontier(proof, &.{context.origin}, now_ms);
        defer initial.abort();
        _ = initial.commit();
        var assembled = try package.encodeInitial(allocator, context, store_id, &store, .{ .metadata = &raw, .frontier = proof }, key);
        defer assembled.deinit();
        const contributions = assembled.mutations();
        try provisioning.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = proof },
            contributions[0],
            contributions[1],
        });
        try provisioning.commit();
        const durable = provisioning.takeCommittedStore();
        return .{ .allocator = allocator, .io = io, .lease = lease, .durable = durable, .retained_store = store, .context = context, .metadata = metadata, .head = assembled.head.head, .local_authoring_disabled = assembled.local_authoring_disabled, .published_generation = store.generation };
    }

    /// Strict existing cold boot. Authenticate/reconstruct the entire OLD cut
    /// before staging the new epoch and retirement proof. No state is exposed
    /// until all four successor rows have durably committed together.
    pub fn openCold(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, context: retained.LocalContext, key: *const sign.KeyPair, now_ms: i64, config: Config) !Authority {
        // Cold custody needs POSIX fds; unreachable in Windows production
        // (plaintext PortableServer only), so tests skip via this one gate.
        if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
        try requireKey(context, key);
        if (now_ms < 0) return error.InvalidClock;
        const lease = try acquireExistingColdLease(allocator, io, dir, path);
        errdefer lease.close(io);
        var recovery = try persistence.ColdRecoveryStage.open(allocator, io, dir, path, lease, config.storage);
        defer recovery.deinit();
        const durable = recovery.view();
        if (durable.get(.props, retained.head_key)) |raw_head| {
            // This is negative schema classification only, never legacy
            // authentication or migration, and the WAL is still untouched.
            if (raw_head.len == retained.head_len and std.mem.eql(u8, raw_head[0..4], "OPRH") and raw_head[4] == 1) return error.MigrationRequired;
        }
        const predecessor_digest = retained.digest(durable.get(.props, retained.head_key) orelse return error.MissingState);
        var restored = try image.stageRestore(allocator, durable, context, config.retained);
        errdefer restored.deinit();
        var metadata = try issuer.validateRows(durable.get(.props, issuer.metadata_key).?, durable.get(.props, issuer.frontier_key).?, context.origin);
        metadata.epoch = std.math.add(u64, metadata.epoch, 1) catch return error.GenerationExhausted;
        metadata.issued_through = 0;
        metadata.frontier_revision = 1;
        metadata.frontier_through = 0;
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const proof = try frontier.encode(.{ .origin = context.origin, .epoch = metadata.epoch, .revision = 1, .through = 0, .issued_ms = now_ms, .active = &.{} }, key, &buffer);
        metadata.frontier_digest = retained.digest(proof);
        const raw = metadata.encode();
        var plan = try restored.store.prepareFrontier(proof, &.{context.origin}, now_ms);
        defer plan.abort();
        var assembled = try package.prepareImage(allocator, durable, context, &restored.store, .{ .frontier = &plan }, .{ .metadata = &raw, .frontier = proof }, restored.head.expiry_floor_ms, key);
        defer assembled.deinit();
        const contributions = assembled.mutations();
        var batch = try recovery.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = proof },
            contributions[0],
            contributions[1],
        });
        defer batch.abort();
        try recovery.validate();
        if (!std.mem.eql(u8, &predecessor_digest, &retained.digest(durable.get(.props, retained.head_key).?))) return error.InvalidState;
        _ = try restored.store.project(.{ .frontier = &plan });
        try batch.commit();
        _ = plan.commit();
        const published = recovery.takeCommittedStore();
        return .{ .allocator = allocator, .io = io, .lease = lease, .durable = published, .retained_store = restored.store, .context = context, .metadata = metadata, .head = assembled.head.head, .local_authoring_disabled = assembled.local_authoring_disabled, .published_generation = restored.store.generation };
    }

    /// Capture under the quiesced graph lock before sealing mandatory hot state.
    /// This binds real current authority, not reconstructed maximum counters or
    /// an independently guessed inode. Physical inventory is a separate gate.
    pub fn captureHotCheckpoint(self: *const Authority) !HotCheckpoint {
        // Lease-identity custody needs POSIX fds; unreachable in Windows
        // production, so tests skip via this one gate.
        if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
        if (self.durable.preparedWritesPoisoned() or self.durable.isReadOnly() or self.active_generation != null or self.durable.active_batch != null or self.durable.active_prepared != null or self.published_generation != self.retained_store.generation) return error.InvalidState;
        const envelope = try retained.readCommittedEnvelope(&self.durable, self.context);
        const metadata = try issuer.validateRows(envelope.rows.metadata, envelope.rows.frontier, self.context.origin);
        if (!std.meta.eql(envelope.head, self.head) or !std.meta.eql(metadata, self.metadata)) return error.InvalidState;
        var canonical = try image.encodeProjection(self.allocator, &self.retained_store, .unchanged);
        defer canonical.deinit();
        if (canonical.entries != envelope.head.entries or canonical.frontiers != envelope.head.frontiers or canonical.retained_bytes != envelope.head.retained_bytes or !std.mem.eql(u8, canonical.bytes, envelope.image)) return error.InvalidState;
        const identity = try lease_custody.statRegular(self.lease.handle);
        try validateAuthorityLease(self.allocator, self.io, self.durable.dir, self.durable.wal_path, self.lease, identity);
        return .{ .lease_identity = identity, .context = self.context, .store_id = self.head.store_id, .head_digest = retained.digest(self.durable.get(.props, retained.head_key).?), .commit_generation = self.head.commit_generation, .image_generation = self.head.image_generation };
    }

    pub fn deinit(self: *Authority) void {
        std.debug.assert(self.active_generation == null);
        self.retained_store.deinit();
        self.durable.deinit();
        // Close only: an eventual hot duplicate must retain its shared lock.
        self.lease.close(self.io);
        self.* = undefined;
    }

    fn writable(self: *const Authority, key: *const sign.KeyPair, authoring: bool) !void {
        try requireKey(self.context, key);
        if (self.durable.preparedWritesPoisoned()) return error.StorePoisoned;
        if (self.durable.isReadOnly()) return error.ReadOnlyStore;
        if (self.active_generation != null) return error.MutationActive;
        if (self.published_generation != self.retained_store.generation) return error.InvalidState;
        if (authoring and self.local_authoring_disabled) return error.AuthoringDisabled;
    }

    /// Durable reservation before any physical registration receives the ID.
    /// The metadata and signed head advance together; image stays byte-exact.
    pub fn reserveSubject(self: *Authority, key: *const sign.KeyPair) !wire.Subject {
        try self.writable(key, true);
        var candidate = self.metadata;
        candidate.issued_through = std.math.add(u64, candidate.issued_through, 1) catch return error.GenerationExhausted;
        const raw = candidate.encode();
        const encoded = try package.prepareHeadUpdate(&self.durable, self.context, .{ .metadata = &raw, .frontier = self.durable.get(.props, issuer.frontier_key).? }, self.head.expiry_floor_ms, key);
        var batch = try self.durable.prepareBatch(&.{ .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw }, encoded.mutation() });
        defer batch.abort();
        try batch.commit();
        self.metadata = candidate;
        self.head = encoded.head;
        return .{ .epoch = candidate.epoch, .counter = candidate.issued_through };
    }

    /// Call BEFORE an irreversible expiry projection. A failed or ambiguous
    /// commit cannot advance the in-memory floor. The caller controls cadence;
    /// this leaf does not write on every wall-clock read.
    pub fn observeExpiry(self: *Authority, now_ms: i64, key: *const sign.KeyPair) !void {
        try self.writable(key, false);
        if (now_ms < 0) return error.InvalidClock;
        if (now_ms <= self.head.expiry_floor_ms) return;
        const rows: retained.IssuerRows = .{ .metadata = self.durable.get(.props, issuer.metadata_key).?, .frontier = self.durable.get(.props, issuer.frontier_key).? };
        const encoded = try package.prepareHeadUpdate(&self.durable, self.context, rows, now_ms, key);
        var batch = try self.durable.prepareBatch(&.{encoded.mutation()});
        defer batch.abort();
        try batch.commit();
        self.head = encoded.head;
    }

    pub fn winner(self: *const Authority, nick: []const u8, now_ms: i64, roots: []const sign.PublicKey) ?*const presence.Entry {
        // A poisoned WAL may contain an unknown complete successor retirement
        // cut. Refuse positive authority until strict cold reconstruction.
        if (self.durable.preparedWritesPoisoned() or self.published_generation != self.retained_store.generation) return null;
        return self.retained_store.winnerWithExpiryFloor(nick, now_ms, self.head.expiry_floor_ms, roots);
    }

    const RamChange = union(enum) {
        presence: presence.Store.Prepared,
        frontier: presence.Store.PreparedFrontier,
        local_lifecycle: presence.Store.PreparedLocalLifecycle,
        local_lifecycles: presence.Store.PreparedLocalLifecycles,
        fn borrowed(self: *const RamChange) image.Change {
            return switch (self.*) {
                .presence => |*plan| .{ .presence = plan },
                .frontier => |*plan| .{ .frontier = plan },
                .local_lifecycle => |*plan| .{ .local_lifecycle = plan },
                .local_lifecycles => |*plan| .{ .local_lifecycles = plan },
            };
        }
        fn abort(self: *RamChange) void {
            switch (self.*) {
                .presence => |*plan| plan.abort(),
                .frontier => |*plan| plan.abort(),
                .local_lifecycle => |*plan| plan.abort(),
                .local_lifecycles => |*plan| plan.abort(),
            }
        }
        fn commit(self: *RamChange) void {
            switch (self.*) {
                .presence => |*plan| _ = plan.commit(),
                .frontier => |*plan| _ = plan.commit(),
                .local_lifecycle => |*plan| plan.commit(),
                .local_lifecycles => |*plan| plan.commit(),
            }
        }
    };

    /// Sole owning handle. Do not copy; commit or abort under the owner lock.
    pub const Prepared = struct {
        owner: *Authority,
        generation: u64,
        batch: persistence.PreparedBatch,
        ram: RamChange,
        metadata: issuer.Metadata,
        head: retained.Head,
        disabled: bool,
        done: bool = false,

        /// Borrow exact signed lifecycle bytes, including QUIT normalized out
        /// of retained state. Valid until abort/deinit; retain egress first.
        pub fn originalCount(self: *const Prepared) usize {
            return if (self.ram == .local_lifecycles) self.ram.local_lifecycles.subject_count else 0;
        }
        pub fn original(self: *const Prepared, index: usize) ?[]const u8 {
            if (self.ram != .local_lifecycles or index >= self.ram.local_lifecycles.subject_count) return null;
            return self.ram.local_lifecycles.subjects[index].original;
        }
        pub fn deinit(self: *Prepared) void {
            self.abort();
        }

        /// Also releases grouped signed output evidence after commit. Borrowed
        /// originals expire here; callers must retain output ownership first.
        pub fn abort(self: *Prepared) void {
            if (self.done) {
                self.ram.abort();
                return;
            }
            std.debug.assert(self.owner.active_generation == self.generation);
            self.batch.abort();
            self.ram.abort();
            self.owner.active_generation = null;
            self.done = true;
        }
        pub fn commit(self: *Prepared) !void {
            if (self.done or self.owner.active_generation != self.generation) return error.AlreadyConsumed;
            _ = try self.owner.retained_store.project(self.ram.borrowed());
            try self.batch.commit();
            // No allocation or failure after fsync. World/physical projection
            // must publish in this same external graph lock before output.
            self.ram.commit();
            self.owner.metadata = self.metadata;
            self.owner.head = self.head;
            self.owner.local_authoring_disabled = self.disabled;
            self.owner.published_generation = self.owner.retained_store.generation;
            self.owner.active_generation = null;
            self.done = true;
        }
    };

    fn prepareChange(self: *Authority, ram_value: RamChange, metadata: issuer.Metadata, proof: []const u8, key: *const sign.KeyPair) !Prepared {
        var ram = ram_value;
        errdefer ram.abort();
        if (self.next_generation == std.math.maxInt(u64)) return error.GenerationExhausted;
        const raw = metadata.encode();
        var assembled = try package.prepareImage(self.allocator, &self.durable, self.context, &self.retained_store, ram.borrowed(), .{ .metadata = &raw, .frontier = proof }, self.head.expiry_floor_ms, key);
        defer assembled.deinit();
        const contributions = assembled.mutations();
        const batch = try self.durable.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = proof },
            contributions[0],
            contributions[1],
        });
        const generation = self.next_generation;
        self.next_generation += 1;
        self.active_generation = generation;
        return .{ .owner = self, .generation = generation, .batch = batch, .ram = ram, .metadata = metadata, .head = assembled.head.head, .disabled = assembled.local_authoring_disabled };
    }

    pub fn preparePresence(self: *Authority, original: []const u8, roots: []const sign.PublicKey, now_ms: i64, key: *const sign.KeyPair) !Prepared {
        try self.writable(key, false);
        var plan = try self.retained_store.prepare(original, roots, now_ms);
        // Ordinary signature/approval/clock checks have already succeeded.
        // A rolled-back wall clock cannot admit an observed-expired positive.
        const record = (wire.decode(original) catch unreachable).record;
        if (record.operation == .present and record.expires_ms <= self.head.expiry_floor_ms) {
            plan.abort();
            return error.Expired;
        }
        return self.prepareChange(.{ .presence = plan }, self.metadata, self.durable.get(.props, issuer.frontier_key).?, key);
    }
    pub fn prepareQuitRepair(self: *Authority, original: []const u8, roots: []const sign.PublicKey, now_ms: i64, key: *const sign.KeyPair) !Prepared {
        try self.writable(key, false);
        const plan = try self.retained_store.prepareQuitRepair(original, roots, now_ms);
        return self.prepareChange(.{ .presence = plan }, self.metadata, self.durable.get(.props, issuer.frontier_key).?, key);
    }
    pub fn prepareRemoteFrontier(self: *Authority, original: []const u8, roots: []const sign.PublicKey, now_ms: i64, key: *const sign.KeyPair) !Prepared {
        try self.writable(key, false);
        const plan = try self.retained_store.prepareFrontier(original, roots, now_ms);
        return self.prepareChange(.{ .frontier = plan }, self.metadata, self.durable.get(.props, issuer.frontier_key).?, key);
    }
    /// One durable/local RAM cut for a physical lifecycle and its complete
    /// active inventory. The daemon graph owner must derive that inventory
    /// under the same lock; this API does not infer physical attachments.
    pub fn prepareLocalLifecycle(self: *Authority, original: []const u8, through: u64, active: []const u64, now_ms: i64, key: *const sign.KeyPair) !Prepared {
        return self.prepareLocalLifecycles(&.{original}, through, active, now_ms, key);
    }

    /// One exclusive generation and four-row WAL batch for every supplied
    /// physical lifecycle. The graph caller proves COMPLETE active inventory;
    /// this leaf verifies supplied PRESENT/QUIT relations, not hidden sockets.
    pub fn prepareLocalLifecycles(self: *Authority, originals: []const []const u8, through: u64, complete_active: []const u64, now_ms: i64, key: *const sign.KeyPair) !Prepared {
        try self.writable(key, true);
        if (originals.len == 0 or originals.len > frontier.max_active) return error.InvalidLocalLifecycle;
        if (through > self.metadata.issued_through or through < self.metadata.frontier_through) return error.InvalidFrontier;
        for (originals, 0..) |original, i| {
            const decoded = try wire.decode(original);
            if (!std.mem.eql(u8, &decoded.record.origin, &self.context.origin)) return error.ContextMismatch;
            const subject = try wire.subject(decoded.record.guest);
            if (subject.epoch != self.metadata.epoch or subject.counter > self.metadata.issued_through) return error.InvalidState;
            for (originals[0..i]) |before| if (std.mem.eql(u8, &(try wire.decode(before)).record.guest, &decoded.record.guest)) return error.InvalidLocalLifecycle;
            if (decoded.record.operation == .present and decoded.record.expires_ms <= self.head.expiry_floor_ms) return error.Expired;
        }
        var metadata = self.metadata;
        metadata.frontier_revision = std.math.add(u64, metadata.frontier_revision, 1) catch return error.GenerationExhausted;
        metadata.frontier_through = through;
        const buffer = try self.allocator.alloc(u8, frontier.max_wire_len);
        defer self.allocator.free(buffer);
        const proof = try frontier.encode(.{ .origin = metadata.origin, .epoch = metadata.epoch, .revision = metadata.frontier_revision, .through = through, .issued_ms = now_ms, .active = complete_active }, key, buffer);
        metadata.frontier_digest = retained.digest(proof);
        const plan = try self.retained_store.prepareLocalLifecycles(originals, proof, metadata.origin, &.{metadata.origin}, now_ms);
        return self.prepareChange(.{ .local_lifecycles = plan }, metadata, proof, key);
    }

    pub fn prepareLocalFrontier(self: *Authority, through: u64, active: []const u64, now_ms: i64, key: *const sign.KeyPair) !Prepared {
        try self.writable(key, true);
        if (through > self.metadata.issued_through or through < self.metadata.frontier_through) return error.InvalidFrontier;
        var metadata = self.metadata;
        metadata.frontier_revision = std.math.add(u64, metadata.frontier_revision, 1) catch return error.GenerationExhausted;
        metadata.frontier_through = through;
        const buffer = try self.allocator.alloc(u8, frontier.max_wire_len);
        defer self.allocator.free(buffer);
        const original = try frontier.encode(.{ .origin = metadata.origin, .epoch = metadata.epoch, .revision = metadata.frontier_revision, .through = through, .issued_ms = now_ms, .active = active }, key, buffer);
        metadata.frontier_digest = retained.digest(original);
        const plan = try self.retained_store.prepareFrontier(original, &.{metadata.origin}, now_ms);
        return self.prepareChange(.{ .frontier = plan }, metadata, original, key);
    }
};

pub const HotCheckpoint = struct {
    lease_identity: lease_custody.Identity,
    context: retained.LocalContext,
    store_id: [16]u8,
    head_digest: [32]u8,
    commit_generation: u64,
    image_generation: u64,
};

/// Sole rollback-owned successor stage. No mutable Authority is returned before
/// activation. The authenticated descriptor transfer and live, quiesced parent
/// phase are caller prerequisites; flock alone cannot attest this phase after
/// all predecessor references have closed. Physical mappings, native capsule
/// binding and the actual COMMIT/parent-exit barrier remain separate callers.
pub const HotAuthorityStage = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    lease: std.Io.File,
    durable: persistence.OroStore,
    restored: image.RestoreCandidate,
    context: retained.LocalContext,
    metadata: issuer.Metadata,
    done: bool = false,

    /// Takes ownership of inherited on ENTRY, including key/context/OOM errors.
    /// All validation, restoration, writable-handle preparation and descriptor
    /// closes occur before READY. Opens no cold constructor and performs no WAL
    /// creation, repair, epoch advance, compaction or ordinary mutation.
    pub fn prepare(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, context: retained.LocalContext, inherited: std.Io.File, checkpoint: HotCheckpoint, key: *const sign.KeyPair, config: Config) !HotAuthorityStage {
        errdefer inherited.close(io);
        try requireKey(context, key);
        if (!std.meta.eql(checkpoint.context, context)) return error.ContextMismatch;
        try hot_runtime.setCloexec(inherited.handle, true);
        try validateAuthorityLease(allocator, io, dir, path, inherited, checkpoint.lease_identity);
        var durable = try persistence.OroStore.openReadOnlyWithConfig(allocator, io, dir, path, config.storage);
        errdefer durable.deinit();
        const envelope = try retained.readCommittedEnvelope(&durable, context);
        if (!std.mem.eql(u8, &checkpoint.store_id, &envelope.head.store_id) or !std.mem.eql(u8, &checkpoint.head_digest, &retained.digest(durable.get(.props, retained.head_key).?)) or checkpoint.commit_generation != envelope.head.commit_generation or checkpoint.image_generation != envelope.head.image_generation) return error.InvalidState;
        var restored = try image.stageRestore(allocator, &durable, context, config.retained);
        errdefer restored.deinit();
        const metadata = try issuer.validateRows(envelope.rows.metadata, envelope.rows.frontier, context.origin);
        try durable.preparePromotion();
        if (!std.meta.eql(try lease_custody.statRegular(durable.wal_file.?.handle), try lease_custody.statRegular(durable.staged_write_file.?.handle))) return error.InvalidState;
        try durable.releaseReadHandleForPreparedPromotion();
        return .{ .allocator = allocator, .io = io, .lease = inherited, .durable = durable, .restored = restored, .context = context, .metadata = metadata };
    }

    /// Close-only rollback. Never unlock the shared lease, signal the parent,
    /// truncate or repair WAL, or unlink/replace the configured lock inode.
    pub fn abort(self: *HotAuthorityStage) void {
        if (self.done) return;
        self.restored.deinit();
        self.durable.deinit();
        self.lease.close(self.io);
        self.done = true;
    }
    pub fn deinit(self: *HotAuthorityStage) void {
        self.abort();
    }

    pub fn head(self: *const HotAuthorityStage) retained.Head {
        std.debug.assert(!self.done);
        return self.restored.head;
    }

    /// No-fail move with no allocation, I/O or descriptor close. CALL ONLY after
    /// the caller has authenticated COMMIT AND observed predecessor exit. Shared
    /// custody does not exclude concurrent predecessor/successor writers; this
    /// API does not manufacture or verify the external process barrier.
    pub fn activateAfterAuthenticatedCommitAndPredecessorExit(self: *HotAuthorityStage) Authority {
        std.debug.assert(!self.done and self.durable.isReadOnly() and self.durable.wal_file == null and self.durable.staged_write_file != null);
        self.durable.promotePrepared();
        self.done = true;
        return .{ .allocator = self.allocator, .io = self.io, .lease = self.lease, .durable = self.durable, .retained_store = self.restored.store, .context = self.context, .metadata = self.metadata, .head = self.restored.head, .local_authoring_disabled = self.restored.local_authoring_disabled, .published_generation = self.restored.store.generation };
    }
};

fn requireKey(context: retained.LocalContext, key: *const sign.KeyPair) !void {
    if (!std.mem.eql(u8, &context.origin, &key.public_key)) return error.ContextMismatch;
}

fn contextFor(key: *const sign.KeyPair) retained.LocalContext {
    return .{ .origin = key.public_key, .realm = @splat(11) };
}
fn recordFor(origin: sign.PublicKey, id: wire.Subject) !wire.Record {
    return .{ .operation = .present, .origin = origin, .guest = try wire.guestId(id), .revision = 1, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 9, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "Guest", .username = "guest", .host = "cloak.onyx", .realname = "Guest", .server = "node-c", .description = "Origin" };
}
fn publish(owner: *Authority, value: wire.Record, origin: *const sign.KeyPair, local: *const sign.KeyPair, now_ms: i64) !void {
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try owner.preparePresence(try wire.encode(value, origin, &buffer), &.{origin.public_key}, now_ms, local);
    defer plan.abort();
    try plan.commit();
}

test "mesh presence authority atomically provisions reserves publishes and advances cold epoch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(131));
    defer key.deinit();
    const context = contextFor(&key);
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "authority.wal", context, @splat(1), &key, 1000, .{});
        defer owner.deinit();
        const burned = try owner.reserveSubject(&key);
        const guest = try owner.reserveSubject(&key);
        try std.testing.expectEqual(@as(u64, 1), burned.counter);
        try std.testing.expectEqual(@as(u64, 2), guest.counter);
        try publish(&owner, try recordFor(key.public_key, guest), &key, &key, 1000);
        var cut = try owner.prepareLocalFrontier(2, &.{2}, 1000, &key);
        defer cut.abort();
        try cut.commit();
        try std.testing.expect(owner.winner("Guest", 1500, &.{key.public_key}) != null);
        var restored = try image.stageRestore(std.testing.allocator, &owner.durable, context, .{});
        defer restored.deinit();
        try std.testing.expectEqualDeep(owner.head, restored.head);
        try std.testing.expectEqual(@as(usize, 1), restored.store.entries.items.len);
        const proof = try frontier.decode(owner.durable.get(.props, issuer.frontier_key).?);
        try std.testing.expect(proof.retires(key.public_key, burned.epoch, burned.counter));
        try std.testing.expect(!proof.retires(key.public_key, guest.epoch, guest.counter));
    }
    var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "authority.wal", context, &key, 500, .{});
    defer cold.deinit();
    try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
    try std.testing.expectEqual(@as(u64, 0), cold.metadata.issued_through);
    try std.testing.expectEqual(@as(usize, 0), cold.retained_store.entries.items.len);
    try std.testing.expect(cold.winner("Guest", 1500, &.{key.public_key}) == null);
    const guest = try cold.reserveSubject(&key);
    try std.testing.expectEqualDeep(wire.Subject{ .epoch = 2, .counter = 1 }, guest);
    var restored = try image.stageRestore(std.testing.allocator, &cold.durable, context, .{});
    defer restored.deinit();
    try std.testing.expectEqualDeep(cold.head, restored.head);
}

test "mesh presence authority durable expiry floor survives rollback renewal and cold boot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(132));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(133));
    defer remote.deinit();
    const context = contextFor(&local);
    const config: Config = .{ .retained = .{ .clock = .{ .max_lifetime_ms = 120_000, .max_future_skew_ms = 0 } } };
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "expiry.wal", context, @splat(2), &local, 1000, config);
        defer owner.deinit();
        var value = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 });
        try publish(&owner, value, &remote, &local, 1000);
        const image_generation = owner.head.image_generation;
        const image_digest = owner.head.image_digest;
        try owner.observeExpiry(2100, &local);
        try std.testing.expectEqual(image_generation, owner.head.image_generation);
        try std.testing.expectEqual(image_digest, owner.head.image_digest);
        try std.testing.expect(owner.winner("Guest", 1500, &.{remote.public_key}) == null);
        // A fresh positive whose deadline is below the durable observation
        // floor must be refused even when the wall clock has rolled back.
        var expired = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 4 });
        expired.nick = "AlreadyExpired";
        const expiry_cut = owner.head;
        try std.testing.expectError(error.Expired, publish(&owner, expired, &remote, &local, 1500));
        try std.testing.expectEqualDeep(expiry_cut, owner.head);
        try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
        const generation = owner.head.commit_generation;
        try owner.observeExpiry(1500, &local);
        try std.testing.expectEqual(generation, owner.head.commit_generation);
        // A genuinely renewed signed lease can extend beyond the observed floor.
        value.revision = 2;
        value.expires_ms = 5000;
        try publish(&owner, value, &remote, &local, 1500);
        try std.testing.expect(owner.winner("Guest", 1500, &.{remote.public_key}) != null);
        // The floor must never replace the raw wall clock for future checks.
        value = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 2 });
        value.nick = "FutureIssue";
        value.issued_ms = 1600;
        value.expires_ms = 5000;
        try publish(&owner, value, &remote, &local, 1700);
        try std.testing.expect(owner.winner("FutureIssue", 1500, &.{remote.public_key}) == null);
        value.guest = try wire.guestId(.{ .epoch = 1, .counter = 3 });
        value.nick = "FutureClaim";
        value.issued_ms = 1000;
        value.claim_hlc = (@as(u64, 1600) << 16) + 1;
        try publish(&owner, value, &remote, &local, 1700);
        try std.testing.expect(owner.winner("FutureClaim", 1500, &.{remote.public_key}) == null);
    }
    var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "expiry.wal", context, &local, 1500, config);
    defer cold.deinit();
    try std.testing.expectEqual(@as(i64, 2100), cold.head.expiry_floor_ms);
    try std.testing.expect(cold.winner("Guest", 1500, &.{remote.public_key}) != null);
    try std.testing.expect(cold.winner("FutureIssue", 1500, &.{remote.public_key}) == null);
    try std.testing.expect(cold.winner("FutureClaim", 1500, &.{remote.public_key}) == null);
}

test "mesh presence authority abort and poisoned four row frontier commit never publish mixed RAM" {
    var local = try sign.KeyPair.fromSeed(@splat(134));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(135));
    defer remote.deinit();
    for ([_]persistence.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "fault.wal", contextFor(&local), @splat(3), &local, 1000, .{});
        defer owner.deinit();
        try publish(&owner, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), &remote, &local, 1000);
        const before = owner.head;
        const generation = owner.retained_store.generation;
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const proof = try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &remote, &buffer);
        var aborted = try owner.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
        try std.testing.expectError(error.MutationActive, owner.reserveSubject(&local));
        aborted.abort();
        try std.testing.expectEqualDeep(before, owner.head);
        try std.testing.expectEqual(generation, owner.retained_store.generation);
        try std.testing.expect(owner.winner("Guest", 1500, &.{remote.public_key}) != null);
        var plan = try owner.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
        owner.durable.setPreparedIoFault(fault);
        try std.testing.expectError(error.IoAmbiguous, plan.commit());
        plan.abort();
        try std.testing.expectEqualDeep(before, owner.head);
        try std.testing.expectEqual(generation, owner.retained_store.generation);
        try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
        try std.testing.expect(owner.winner("Guest", 1500, &.{remote.public_key}) == null);
        try std.testing.expectError(error.StorePoisoned, owner.reserveSubject(&local));
        // Test-only replay under the held lease; poisoned owner cannot write.
        var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "fault.wal", .{ .changefeed_capacity = 0 });
        defer recovered.deinit();
        var restored = try image.stageRestore(std.testing.allocator, &recovered, owner.context, .{});
        defer restored.deinit();
        const old = restored.head.commit_generation == before.commit_generation;
        try std.testing.expect(old or restored.head.commit_generation == before.commit_generation + 1);
        try std.testing.expectEqual(if (old) @as(usize, 1) else 0, restored.store.entries.items.len);
        try std.testing.expectEqual(if (old) @as(usize, 1) else 2, restored.store.frontiers.items.len);
        try std.testing.expectEqual(owner.metadata.epoch, restored.head.epoch);
        try std.testing.expectEqual(owner.metadata.issued_through, restored.head.issued_through);
    }
}

test "mesh presence authority preserves local quarantine across cold epoch and disables issuance" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(136));
    defer key.deinit();
    const context = contextFor(&key);
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "quarantine.wal", context, @splat(4), &key, 1000, .{});
        defer owner.deinit();
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const fork = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &key, &buffer);
        var plan = try owner.prepareRemoteFrontier(fork, &.{key.public_key}, 1000, &key);
        defer plan.abort();
        try plan.commit();
        try std.testing.expect(owner.local_authoring_disabled);
        try std.testing.expectError(error.AuthoringDisabled, owner.reserveSubject(&key));
    }
    var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "quarantine.wal", context, &key, 1500, .{});
    defer cold.deinit();
    try std.testing.expect(cold.local_authoring_disabled);
    try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
    try std.testing.expect(cold.retained_store.frontiers.items[0].conflict != null);
    try std.testing.expectError(error.AuthoringDisabled, cold.reserveSubject(&key));
}

test "mesh presence authority uses actual WAL limits and refuses partial enabled state" {
    // Cold authority custody is POSIX-only; Windows cannot run this end-to-end
    // lease/provisioning proof until native cold custody is implemented.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(137));
    defer key.deinit();
    const context = contextFor(&key);
    try std.testing.expectError(error.RecordTooLarge, Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "limit.wal", context, @splat(5), &key, 1000, .{ .storage = .{ .max_record_bytes = 500, .changefeed_capacity = 0 } }));
    // Failed provisioning returns no ID and closes custody; explicit retry works.
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "limit.wal", context, @splat(5), &key, 1000, .{});
        defer owner.deinit();
        try std.testing.expectEqual(@as(u64, 0), owner.metadata.issued_through);
    }
    try std.testing.expectError(error.AlreadyInitialized, Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "limit.wal", context, @splat(5), &key, 1000, .{}));
    {
        var store = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "limit.wal", .{ .changefeed_capacity = 0 });
        defer store.deinit();
        try store.delete(.props, retained.image_key);
    }
    try std.testing.expectError(error.MissingState, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "limit.wal", context, &key, 1500, .{}));
    var store = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "limit.wal", .{ .changefeed_capacity = 0 });
    defer store.deinit();
    const metadata = try issuer.validateRows(store.get(.props, issuer.metadata_key).?, store.get(.props, issuer.frontier_key).?, key.public_key);
    try std.testing.expectEqual(@as(u64, 1), metadata.epoch);
}

fn constructorAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, cold: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const context = contextFor(key);
    const config: Config = .{ .retained = .{ .max_entries = 4, .max_origins = 4 } };
    var before: ?retained.Head = null;
    if (cold) {
        var seed = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "alloc.wal", context, @splat(6), key, 1000, config);
        defer seed.deinit();
        const guest = try seed.reserveSubject(key);
        try publish(&seed, try recordFor(key.public_key, guest), key, key, 1000);
        try seed.observeExpiry(2100, key);
        before = seed.head;
    }
    var result = (if (cold)
        Authority.openCold(allocator, std.testing.io, tmp.dir, "alloc.wal", context, key, 1500, config)
    else
        Authority.initialize(allocator, std.testing.io, tmp.dir, "alloc.wal", context, @splat(6), key, 1000, config)) catch |err| {
        if (err == error.OutOfMemory) {
            if (before) |old| {
                // Read-only inspection cannot create/repair storage during the
                // OOM rollback assertion.
                var inspected = try persistence.OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "alloc.wal", .{ .changefeed_capacity = 0 });
                defer inspected.deinit();
                var snapshot = try image.stageRestore(std.testing.allocator, &inspected, context, config.retained);
                defer snapshot.deinit();
                try std.testing.expectEqualDeep(old, snapshot.head);
                try std.testing.expectEqual(@as(usize, 1), snapshot.store.entries.items.len);
            } else {
                try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "alloc.wal", .{}));
                try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "alloc.wal.snap", .{}));
            }
            var retry = if (cold)
                try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "alloc.wal", context, key, 1500, config)
            else
                try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "alloc.wal", context, @splat(6), key, 1000, config);
            defer retry.deinit();
            try std.testing.expectEqual(if (cold) @as(u64, 2) else 1, retry.metadata.epoch);
            try std.testing.expectEqual(@as(u64, 0), retry.metadata.issued_through);
        }
        return err;
    };
    defer result.deinit();
    try std.testing.expectEqual(if (cold) @as(u64, 2) else 1, result.metadata.epoch);
    try std.testing.expectEqual(@as(u64, 0), result.metadata.issued_through);
    if (cold) {
        try std.testing.expectEqual(@as(i64, 2100), result.head.expiry_floor_ms);
        try std.testing.expectEqual(@as(usize, 0), result.retained_store.entries.items.len);
    }
}

test "mesh presence authority exhaustive constructor allocation failures preserve whole old cut and custody retry" {
    var key = try sign.KeyPair.fromSeed(@splat(138));
    defer key.deinit();
    for ([_]bool{ false, true }) |cold| try std.testing.checkAllAllocationFailures(std.testing.allocator, constructorAllocationScenario, .{ &key, cold });
}

fn mutationAllocationScenario(allocator: std.mem.Allocator, local: *const sign.KeyPair, remote: *const sign.KeyPair, retire: bool) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config: Config = .{ .retained = .{ .max_entries = 4, .max_origins = 4 } };
    var owner = try Authority.initialize(allocator, std.testing.io, tmp.dir, "mutation.wal", contextFor(local), @splat(7), local, 1000, config);
    var live = true;
    defer if (live) owner.deinit();
    if (retire) try publish(&owner, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), remote, local, 1000);
    const before = owner.head;
    const generation = owner.retained_store.generation;
    var fingerprint = try image.encodeProjection(std.testing.allocator, &owner.retained_store, .unchanged);
    defer fingerprint.deinit();
    var record_buffer: [wire.max_wire_len]u8 = undefined;
    const original = try wire.encode(try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), remote, &record_buffer);
    var proof_buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const proof = try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, remote, &proof_buffer);
    var plan = (if (retire)
        owner.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, local)
    else
        owner.preparePresence(original, &.{remote.public_key}, 1000, local)) catch |err| {
        if (err == error.OutOfMemory) {
            try std.testing.expectEqualDeep(before, owner.head);
            try std.testing.expectEqual(generation, owner.retained_store.generation);
            try std.testing.expect(owner.active_generation == null);
            const envelope = try retained.readCommittedEnvelope(&owner.durable, owner.context);
            try std.testing.expectEqualSlices(u8, fingerprint.bytes, envelope.image);
            var current = try image.encodeProjection(std.testing.allocator, &owner.retained_store, .unchanged);
            defer current.deinit();
            try std.testing.expectEqualSlices(u8, fingerprint.bytes, current.bytes);
            // Close the failed allocation owner's custody, then perform a
            // genuine cold retry with an ordinary allocator and the same cut.
            owner.deinit();
            live = false;
            var retry = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "mutation.wal", contextFor(local), local, 1500, config);
            defer retry.deinit();
            var retried = if (retire)
                try retry.prepareRemoteFrontier(proof, &.{remote.public_key}, 1500, local)
            else
                try retry.preparePresence(original, &.{remote.public_key}, 1500, local);
            defer retried.abort();
            try retried.commit();
            try std.testing.expectEqual(if (retire) @as(usize, 0) else 1, retry.retained_store.entries.items.len);
        }
        return err;
    };
    defer plan.abort();
    try plan.commit();
    try std.testing.expectEqual(if (retire) @as(usize, 0) else 1, owner.retained_store.entries.items.len);
}

test "mesh presence authority exhaustive admission and frontier GC allocations preserve exact cut and retry" {
    var local = try sign.KeyPair.fromSeed(@splat(139));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(140));
    defer remote.deinit();
    for ([_]bool{ false, true }) |retire| try std.testing.checkAllAllocationFailures(std.testing.allocator, mutationAllocationScenario, .{ &local, &remote, retire });
}

test "mesh presence authority reservation and expiry faults leave cache old and replay a coherent head" {
    var local = try sign.KeyPair.fromSeed(@splat(141));
    defer local.deinit();
    for ([_]bool{ false, true }) |expiry| for ([_]persistence.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "headfault.wal", contextFor(&local), @splat(8), &local, 1000, .{});
        defer owner.deinit();
        const before = owner.head;
        owner.durable.setPreparedIoFault(fault);
        if (expiry) {
            try std.testing.expectError(error.IoAmbiguous, owner.observeExpiry(2100, &local));
        } else try std.testing.expectError(error.IoAmbiguous, owner.reserveSubject(&local));
        try std.testing.expectEqualDeep(before, owner.head);
        try std.testing.expectEqual(@as(u64, 0), owner.metadata.issued_through);
        try std.testing.expectError(error.StorePoisoned, owner.observeExpiry(2200, &local));
        try std.testing.expectError(error.StorePoisoned, owner.reserveSubject(&local));
        var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "headfault.wal", .{ .changefeed_capacity = 0 });
        defer recovered.deinit();
        var restored = try image.stageRestore(std.testing.allocator, &recovered, owner.context, .{});
        defer restored.deinit();
        const old = restored.head.commit_generation == before.commit_generation;
        try std.testing.expect(old or restored.head.commit_generation == before.commit_generation + 1);
        try std.testing.expectEqual(before.image_generation, restored.head.image_generation);
        try std.testing.expectEqual(before.image_digest, restored.head.image_digest);
        try std.testing.expectEqual(if (expiry and !old) @as(i64, 2100) else 0, restored.head.expiry_floor_ms);
        try std.testing.expectEqual(if (!expiry and !old) @as(u64, 1) else 0, restored.head.issued_through);
    };
}

test "mesh presence authority enabled package excludes legacy issuer with byte identical WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(150));
    defer key.deinit();
    const context = contextFor(&key);
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "aggregate.wal", context, @splat(9), &key, 1000, .{});
        defer owner.deinit();
        _ = try owner.reserveSubject(&key);
    }
    const before = try tmp.dir.readFileAlloc(std.testing.io, "aggregate.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    try std.testing.expectError(error.AggregateStatePresent, issuer.Issuer.openCold(std.testing.allocator, std.testing.io, tmp.dir, "aggregate.wal", &key, 1000));
    try std.testing.expectError(error.AggregateStatePresent, issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "aggregate.wal", &key, 1000));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "aggregate.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "aggregate.wal", context, &key, 1000, .{});
    defer cold.deinit();
    try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
    try std.testing.expectEqual(@as(u64, 0), cold.metadata.issued_through);
}

test "mesh presence authority every four row negative cut append prefix recovers whole package and retries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(151));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(152));
    defer remote.deinit();
    const context = contextFor(&local);
    var proof_buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const proof = try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &remote, &proof_buffer);
    var append_offset: usize = undefined;
    var old_head: retained.Head = undefined;
    var new_head: retained.Head = undefined;
    const bytes = block: {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "complete.wal", context, @splat(10), &local, 1000, .{});
        defer owner.deinit();
        try publish(&owner, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), &remote, &local, 1000);
        old_head = owner.head;
        append_offset = @intCast(owner.durable.wal_offset);
        var plan = try owner.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
        defer plan.abort();
        try plan.commit();
        new_head = owner.head;
        break :block try tmp.dir.readFileAlloc(std.testing.io, "complete.wal", std.testing.allocator, .unlimited);
    };
    defer std.testing.allocator.free(bytes);
    // Include the complete append, not only torn prefixes. The negative proof
    // must become permanent exactly when the whole four-row record is present.
    for (append_offset..bytes.len + 1) |cut| {
        {
            const file = try tmp.dir.createFile(std.testing.io, "cut.wal", .{ .read = true, .truncate = true });
            defer file.close(std.testing.io);
            try file.writePositionalAll(std.testing.io, bytes[0..cut], 0);
            try file.sync(std.testing.io);
        }
        const complete = cut == bytes.len;
        {
            var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "cut.wal", .{ .changefeed_capacity = 0 });
            defer recovered.deinit();
            var restored = try image.stageRestore(std.testing.allocator, &recovered, context, .{});
            defer restored.deinit();
            try std.testing.expectEqualDeep(if (complete) new_head else old_head, restored.head);
            try std.testing.expectEqual(if (complete) @as(usize, 0) else 1, restored.store.entries.items.len);
            try std.testing.expectEqual(if (complete) @as(usize, 2) else 1, restored.store.frontiers.items.len);
            try std.testing.expectEqual(!complete, restored.store.winner("Guest", 1500, &.{remote.public_key}) != null);
        }
        // Retry through the real leased cold constructor and aggregate API.
        // Local cold retirement may advance; the remote negative cut cannot.
        // The copied raw-WAL fixture needs an explicit stable lock. Restore
        // the torn prefix after generic inspection so THIS cold constructor
        // itself proves authenticated-prefix recovery, not a pre-repaired input.
        {
            const fixture_lock = try tmp.dir.createFile(std.testing.io, "cut.wal.lock", .{ .read = true, .truncate = false });
            fixture_lock.close(std.testing.io);
            const file = try tmp.dir.openFile(std.testing.io, "cut.wal", .{ .mode = .read_write });
            defer file.close(std.testing.io);
            try file.setLength(std.testing.io, cut);
            try file.writePositionalAll(std.testing.io, bytes[0..cut], 0);
            try file.sync(std.testing.io);
        }
        var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "cut.wal", context, &local, 1000, .{});
        defer cold.deinit();
        try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
        var retry = try cold.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
        defer retry.abort();
        try retry.commit();
        try std.testing.expect(cold.winner("Guest", 1500, &.{remote.public_key}) == null);
        try std.testing.expectEqual(@as(usize, 0), cold.retained_store.entries.items.len);
        try std.testing.expectEqual(@as(usize, 2), cold.retained_store.frontiers.items.len);
        var found_remote = false;
        for (cold.retained_store.frontiers.items) |item| {
            if (!std.mem.eql(u8, &(try frontier.decode(item.original)).origin, &remote.public_key)) continue;
            try std.testing.expectEqualSlices(u8, proof, item.original);
            found_remote = true;
        }
        try std.testing.expect(found_remote);
    }
}

test "mesh presence authority snapshot truncate faults preserve authenticated negative cut floor and cold retry" {
    var local = try sign.KeyPair.fromSeed(@splat(153));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(154));
    defer remote.deinit();
    const context = contextFor(&local);
    const faults = [_]persistence.PreparedIoFault{
        .{},                         .{ .snapshot_sync = true }, .{ .wal_truncate = .failed },
        .{ .wal_truncate = .short }, .{ .wal_sync = true },
    };
    var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const proof = try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &remote, &buffer);
    for (faults, 0..) |fault, index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var before: retained.Head = undefined;
        {
            var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "snapshot.wal", context, @splat(12), &local, 1000, .{});
            defer owner.deinit();
            _ = try owner.reserveSubject(&local);
            try publish(&owner, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), &remote, &local, 1000);
            var cut = try owner.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
            defer cut.abort();
            try cut.commit();
            try owner.observeExpiry(2100, &local);
            before = owner.head;
            owner.durable.setPreparedIoFault(fault);
            if (index == 0) {
                try owner.durable.snapshotAndTruncate();
            } else if (index == 1) {
                try std.testing.expectError(error.SnapshotSyncFailed, owner.durable.snapshotAndTruncate());
                try std.testing.expect(!owner.durable.preparedWritesPoisoned());
            } else {
                try std.testing.expectError(error.IoAmbiguous, owner.durable.snapshotAndTruncate());
                try std.testing.expect(owner.durable.preparedWritesPoisoned());
                try std.testing.expectError(error.StorePoisoned, owner.reserveSubject(&local));
            }
            try std.testing.expectEqualDeep(before, owner.head);
        }
        {
            var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "snapshot.wal", .{ .changefeed_capacity = 0 });
            defer recovered.deinit();
            var restored = try image.stageRestore(std.testing.allocator, &recovered, context, .{});
            defer restored.deinit();
            try std.testing.expectEqualDeep(before, restored.head);
            try std.testing.expectEqual(@as(usize, 0), restored.store.entries.items.len);
            try std.testing.expectEqual(@as(usize, 2), restored.store.frontiers.items.len);
        }
        var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "snapshot.wal", context, &local, 1000, .{});
        defer cold.deinit();
        try std.testing.expectEqual(@as(i64, 2100), cold.head.expiry_floor_ms);
        try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
        try std.testing.expect(cold.winner("Guest", 1500, &.{remote.public_key}) == null);
        var found_remote = false;
        for (cold.retained_store.frontiers.items) |item| {
            if (!std.mem.eql(u8, &(try frontier.decode(item.original)).origin, &remote.public_key)) continue;
            try std.testing.expectEqualSlices(u8, proof, item.original);
            found_remote = true;
        }
        try std.testing.expect(found_remote);
        const id = try cold.reserveSubject(&local);
        try std.testing.expectEqualDeep(wire.Subject{ .epoch = 2, .counter = 1 }, id);
    }
}

/// Linux fault fixture: the child uses only raw syscalls after fork. It writes
/// the actual prepared four-row record, syncs the chosen prefix, then SIGKILLs
/// itself without running destructors or publishing RAM. This covers process
/// death at serialized WAL boundaries, not a live daemon/relay receipt gate.
fn killAfterPreparedAppend(fd: std.posix.fd_t, offset: u64, bytes: []const u8) !void {
    const linux = std.os.linux;
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) return error.TestUnexpectedResult;
    if (forked == 0) {
        var written: usize = 0;
        while (written < bytes.len) {
            const result = linux.pwrite(fd, bytes.ptr + written, bytes.len - written, @intCast(offset + written));
            switch (linux.errno(result)) {
                .SUCCESS => if (result == 0) linux.exit(21) else {
                    written += result;
                },
                .INTR => continue,
                else => linux.exit(22),
            }
        }
        if (linux.errno(linux.fsync(fd)) != .SUCCESS) linux.exit(23);
        _ = linux.kill(linux.getpid(), .KILL);
        linux.exit(24); // Reaching here means the expected death did not happen.
    }
    var status: i32 = 0;
    while (true) {
        const result = linux.wait4(@intCast(forked), &status, 0, null);
        switch (linux.errno(result)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return error.TestUnexpectedResult,
        }
    }
    // wait4 encodes a signal death in the low seven bits, with no exit code.
    try std.testing.expectEqual(@as(i32, 9), status);
}

test "mesh presence authority actual Linux SIGKILL at prepared WAL boundaries recovers exact package" {
    if (comptime @import("builtin").os.tag != .linux) return error.SkipZigTest;
    var local = try sign.KeyPair.fromSeed(@splat(155));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(156));
    defer remote.deinit();
    const context = contextFor(&local);
    var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const proof = try frontier.encode(.{ .origin = remote.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &remote, &buffer);
    for (0..4) |boundary| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var expected: retained.Head = undefined;
        {
            var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "kill.wal", context, @splat(13), &local, 1000, .{});
            defer owner.deinit();
            try publish(&owner, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), &remote, &local, 1000);
            const old = owner.head;
            var plan = try owner.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
            defer plan.abort();
            const serialized = owner.durable.active_batch.?.record.?;
            const prefix = switch (boundary) {
                0 => 0,
                1 => 4,
                2 => serialized.len / 2,
                else => serialized.len,
            };
            expected = if (boundary == 3) plan.head else old;
            try killAfterPreparedAppend(owner.durable.wal_file.?.handle, owner.durable.wal_offset, serialized[0..prefix]);
            // Child performed no Authority RAM publication. Close the parent
            // fixture too, releasing the last inherited lease before recovery.
            try std.testing.expectEqualDeep(old, owner.head);
            try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
        }
        {
            var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "kill.wal", .{ .changefeed_capacity = 0 });
            defer recovered.deinit();
            var restored = try image.stageRestore(std.testing.allocator, &recovered, context, .{});
            defer restored.deinit();
            try std.testing.expectEqualDeep(expected, restored.head);
            try std.testing.expectEqual(if (boundary == 3) @as(usize, 0) else 1, restored.store.entries.items.len);
            try std.testing.expectEqual(if (boundary == 3) @as(usize, 2) else 1, restored.store.frontiers.items.len);
        }
        var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "kill.wal", context, &local, 1000, .{});
        defer cold.deinit();
        var retry = try cold.prepareRemoteFrontier(proof, &.{remote.public_key}, 1000, &local);
        defer retry.abort();
        try retry.commit();
        try std.testing.expect(cold.winner("Guest", 1500, &.{remote.public_key}) == null);
        try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
        try std.testing.expectEqual(@as(usize, 0), cold.retained_store.entries.items.len);
    }
}

fn expectAuthorityDiskProjection(owner: *Authority) !void {
    var restored = try image.stageRestore(std.testing.allocator, &owner.durable, owner.context, owner.retained_store.config);
    defer restored.deinit();
    try std.testing.expectEqualDeep(owner.head, restored.head);
    var current = try image.encodeProjection(std.testing.allocator, &owner.retained_store, .unchanged);
    defer current.deinit();
    var disk = try image.encodeProjection(std.testing.allocator, &restored.store, .unchanged);
    defer disk.deinit();
    try std.testing.expectEqualSlices(u8, current.bytes, disk.bytes);
    try std.testing.expectEqualSlices(u8, current.bytes, owner.durable.get(.props, retained.image_key).?);
}
fn publishLifecycle(owner: *Authority, value: wire.Record, through: u64, active: []const u64, now_ms: i64, key: *const sign.KeyPair) !void {
    var buffer: [wire.max_wire_len]u8 = undefined;
    const generation = owner.retained_store.generation;
    const head_generation = owner.head.commit_generation;
    const image_generation = owner.head.image_generation;
    var plan = try owner.prepareLocalLifecycle(try wire.encode(value, key, &buffer), through, active, now_ms, key);
    defer plan.abort();
    try plan.commit();
    try std.testing.expectEqual(generation + 1, owner.retained_store.generation);
    try std.testing.expectEqual(head_generation + 1, owner.head.commit_generation);
    try std.testing.expectEqual(image_generation + 1, owner.head.image_generation);
    try expectAuthorityDiskProjection(owner);
}

test "mesh presence authority compound lifecycle replaces at capacity renews renames and certifies quit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(157));
    defer key.deinit();
    const context = contextFor(&key);
    const config: Config = .{ .retained = .{ .max_entries = 1, .max_bytes = 4096 } };
    var old: wire.Record = undefined;
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "compound.wal", context, @splat(14), &key, 1000, config);
        defer owner.deinit();
        var value = try recordFor(key.public_key, try owner.reserveSubject(&key));
        try publishLifecycle(&owner, value, 1, &.{1}, 1000, &key);
        value.guest = try wire.guestId(try owner.reserveSubject(&key));
        var buffer: [wire.max_wire_len]u8 = undefined;
        const raw = try wire.encode(value, &key, &buffer);
        const before = owner.head;
        try std.testing.expectError(error.InvalidLocalLifecycle, owner.prepareLocalLifecycle(raw, 2, &.{1}, 1000, &key));
        try std.testing.expectEqualDeep(before, owner.head);
        try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
        // Final capacity fits because this same certified cut retires counter1.
        try publishLifecycle(&owner, value, 2, &.{2}, 1000, &key);
        value.revision = 2;
        value.issued_ms = 1100;
        value.expires_ms = 2100;
        try publishLifecycle(&owner, value, 2, &.{2}, 1100, &key);
        value.revision = 3;
        value.claim_revision = 3;
        value.claim_hlc = 10;
        value.nick = "Renamed";
        value.issued_ms = 1200;
        value.expires_ms = 2200;
        try publishLifecycle(&owner, value, 2, &.{2}, 1200, &key);
        // A missed away/back rename is a real new signed claim, not renewal.
        value.revision = 5;
        value.claim_revision = 5;
        value.claim_hlc = 11;
        value.issued_ms = 1300;
        value.expires_ms = 2300;
        try publishLifecycle(&owner, value, 2, &.{2}, 1300, &key);
        old = value;
        value.operation = .quit;
        value.revision = 6;
        value.issued_ms = 1400;
        value.expires_ms = 2400;
        try publishLifecycle(&owner, value, 2, &.{}, 1400, &key);
        try std.testing.expectEqual(@as(usize, 0), owner.retained_store.entries.items.len);
        try std.testing.expect(owner.winner("Renamed", 1500, &.{key.public_key}) == null);
        try std.testing.expectError(error.RetiredSubject, owner.preparePresence(try wire.encode(old, &key, &buffer), &.{key.public_key}, 1500, &key));
    }
    var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "compound.wal", context, &key, 1500, config);
    defer cold.deinit();
    var buffer: [wire.max_wire_len]u8 = undefined;
    try std.testing.expectError(error.RetiredSubject, cold.preparePresence(try wire.encode(old, &key, &buffer), &.{key.public_key}, 1500, &key));
    try expectAuthorityDiskProjection(&cold);
}

test "mesh presence authority compound stale plan fails before WAL and abort remains owned" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(158));
    defer key.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "stale.wal", contextFor(&key), @splat(15), &key, 1000, .{});
    defer owner.deinit();
    const id = try owner.reserveSubject(&key);
    var buffer: [wire.max_wire_len]u8 = undefined;
    const raw = try wire.encode(try recordFor(key.public_key, id), &key, &buffer);
    const before = owner.head;
    const offset = owner.durable.wal_offset;
    var plan = try owner.prepareLocalLifecycle(raw, 1, &.{1}, 1000, &key);
    const generation = owner.retained_store.generation;
    // Deliberate unsupported out-of-band mutation: revalidation must refuse
    // before disk publication rather than asserting after the durable commit.
    owner.retained_store.generation += 1;
    try std.testing.expectError(error.InvalidPlan, plan.commit());
    try std.testing.expectEqual(offset, owner.durable.wal_offset);
    try std.testing.expectEqualDeep(before, owner.head);
    owner.retained_store.generation = generation;
    plan.abort();
    plan.abort();
    try std.testing.expectError(error.AlreadyConsumed, plan.commit());
    try publishLifecycle(&owner, try recordFor(key.public_key, id), 1, &.{1}, 1000, &key);
}

fn lifecycleAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config: Config = .{ .retained = .{ .max_entries = 1, .max_origins = 2 } };
    var owner = try Authority.initialize(allocator, std.testing.io, tmp.dir, "lifecycle-oom.wal", contextFor(key), @splat(16), key, 1000, config);
    var live = true;
    defer if (live) owner.deinit();
    var value = try recordFor(key.public_key, try owner.reserveSubject(key));
    try publishLifecycle(&owner, value, 1, &.{1}, 1000, key);
    value.guest = try wire.guestId(try owner.reserveSubject(key));
    var buffer: [wire.max_wire_len]u8 = undefined;
    const original = try wire.encode(value, key, &buffer);
    const before = owner.head;
    const generation = owner.retained_store.generation;
    const offset = owner.durable.wal_offset;
    var fingerprint = try image.encodeProjection(std.testing.allocator, &owner.retained_store, .unchanged);
    defer fingerprint.deinit();
    var plan = owner.prepareLocalLifecycle(original, 2, &.{2}, 1000, key) catch |err| {
        if (err == error.OutOfMemory) {
            try std.testing.expectEqualDeep(before, owner.head);
            try std.testing.expectEqual(generation, owner.retained_store.generation);
            try std.testing.expectEqual(offset, owner.durable.wal_offset);
            try std.testing.expect(owner.active_generation == null);
            var current = try image.encodeProjection(std.testing.allocator, &owner.retained_store, .unchanged);
            defer current.deinit();
            try std.testing.expectEqualSlices(u8, fingerprint.bytes, current.bytes);
            try std.testing.expectEqualSlices(u8, fingerprint.bytes, owner.durable.get(.props, retained.image_key).?);
            try expectAuthorityDiskProjection(&owner);
            owner.deinit();
            live = false;
            var retry = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "lifecycle-oom.wal", contextFor(key), key, 1000, config);
            defer retry.deinit();
            value.guest = try wire.guestId(try retry.reserveSubject(key));
            try publishLifecycle(&retry, value, 1, &.{1}, 1000, key);
        }
        return err;
    };
    defer plan.abort();
    try plan.commit();
    try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
    try std.testing.expectEqual(generation + 1, owner.retained_store.generation);
    try expectAuthorityDiskProjection(&owner);
}

test "mesh presence authority compound lifecycle exhaustive allocation failures preserve predecessor and cold retry" {
    var key = try sign.KeyPair.fromSeed(@splat(159));
    defer key.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, lifecycleAllocationScenario, .{&key});
}

test "mesh presence authority compound WAL quit every append prefix restores old or whole terminal cut" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(160));
    defer key.deinit();
    const context = contextFor(&key);
    var append_offset: usize = undefined;
    var old_head: retained.Head = undefined;
    var new_head: retained.Head = undefined;
    const bytes = block: {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "quit-complete.wal", context, @splat(17), &key, 1000, .{});
        defer owner.deinit();
        var value = try recordFor(key.public_key, try owner.reserveSubject(&key));
        try publishLifecycle(&owner, value, 1, &.{1}, 1000, &key);
        old_head = owner.head;
        append_offset = @intCast(owner.durable.wal_offset);
        value.operation = .quit;
        value.revision = 2;
        var buffer: [wire.max_wire_len]u8 = undefined;
        var plan = try owner.prepareLocalLifecycle(try wire.encode(value, &key, &buffer), 1, &.{}, 1000, &key);
        defer plan.abort();
        try plan.commit();
        new_head = owner.head;
        break :block try tmp.dir.readFileAlloc(std.testing.io, "quit-complete.wal", std.testing.allocator, .unlimited);
    };
    defer std.testing.allocator.free(bytes);
    for (append_offset..bytes.len + 1) |cut| {
        {
            const file = try tmp.dir.createFile(std.testing.io, "quit-cut.wal", .{ .read = true, .truncate = true });
            defer file.close(std.testing.io);
            try file.writePositionalAll(std.testing.io, bytes[0..cut], 0);
            try file.sync(std.testing.io);
        }
        const complete = cut == bytes.len;
        {
            var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "quit-cut.wal", .{ .changefeed_capacity = 0 });
            defer recovered.deinit();
            var restored = try image.stageRestore(std.testing.allocator, &recovered, context, .{});
            defer restored.deinit();
            try std.testing.expectEqualDeep(if (complete) new_head else old_head, restored.head);
            try std.testing.expectEqual(if (complete) @as(usize, 0) else 1, restored.store.entries.items.len);
            try std.testing.expectEqual(!complete, restored.store.winner("Guest", 1500, &.{key.public_key}) != null);
            const proof = restored.store.frontiers.items[0].decoded;
            try std.testing.expectEqual(complete, proof.retires(key.public_key, 1, 1));
            try std.testing.expectEqualSlices(u8, restored.store.frontiers.items[0].original, recovered.get(.props, issuer.frontier_key).?);
        }
        // Real cold boot retires the previous physical incarnation in either
        // outcome; subsequent new issuance and lifecycle publication remain live.
        // The copied raw-WAL fixture needs an explicit stable lock. Restore
        // the torn prefix after generic inspection so THIS cold constructor
        // itself proves authenticated-prefix recovery, not a pre-repaired input.
        {
            const fixture_lock = try tmp.dir.createFile(std.testing.io, "quit-cut.wal.lock", .{ .read = true, .truncate = false });
            fixture_lock.close(std.testing.io);
            const file = try tmp.dir.openFile(std.testing.io, "quit-cut.wal", .{ .mode = .read_write });
            defer file.close(std.testing.io);
            try file.setLength(std.testing.io, cut);
            try file.writePositionalAll(std.testing.io, bytes[0..cut], 0);
            try file.sync(std.testing.io);
        }
        var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "quit-cut.wal", context, &key, 1000, .{});
        defer cold.deinit();
        const id = try cold.reserveSubject(&key);
        try std.testing.expectEqualDeep(wire.Subject{ .epoch = 2, .counter = 1 }, id);
        try publishLifecycle(&cold, try recordFor(key.public_key, id), 1, &.{1}, 1000, &key);
        const proof = cold.retained_store.frontiers.items[0].decoded;
        try std.testing.expect(proof.retires(key.public_key, 1, 1));
        try std.testing.expect(!proof.retires(key.public_key, 2, 1));
    }
}

test "mesh presence authority compound ambiguous commit keeps old RAM and recovers one exact package" {
    var key = try sign.KeyPair.fromSeed(@splat(161));
    defer key.deinit();
    for ([_]persistence.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "compound-fault.wal", contextFor(&key), @splat(18), &key, 1000, .{});
        defer owner.deinit();
        var value = try recordFor(key.public_key, try owner.reserveSubject(&key));
        try publishLifecycle(&owner, value, 1, &.{1}, 1000, &key);
        const before = owner.head;
        const generation = owner.retained_store.generation;
        value.operation = .quit;
        value.revision = 2;
        var buffer: [wire.max_wire_len]u8 = undefined;
        var plan = try owner.prepareLocalLifecycle(try wire.encode(value, &key, &buffer), 1, &.{}, 1000, &key);
        const successor = plan.head;
        owner.durable.setPreparedIoFault(fault);
        try std.testing.expectError(error.IoAmbiguous, plan.commit());
        plan.abort();
        try std.testing.expectEqualDeep(before, owner.head);
        try std.testing.expectEqual(generation, owner.retained_store.generation);
        try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
        try std.testing.expect(owner.winner("Guest", 1500, &.{key.public_key}) == null);
        try std.testing.expectError(error.StorePoisoned, owner.reserveSubject(&key));
        // Test-only inspection while poisoned owner holds custody. No further
        // writes or output are authorized until it closes and cold reconstruction.
        var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "compound-fault.wal", .{ .changefeed_capacity = 0 });
        defer recovered.deinit();
        var restored = try image.stageRestore(std.testing.allocator, &recovered, owner.context, .{});
        defer restored.deinit();
        const old = restored.head.commit_generation == before.commit_generation;
        try std.testing.expectEqualDeep(if (old) before else successor, restored.head);
        try std.testing.expectEqual(if (old) @as(usize, 1) else 0, restored.store.entries.items.len);
        const proof = restored.store.frontiers.items[0].decoded;
        try std.testing.expectEqual(!old, proof.retires(key.public_key, 1, 1));
        try std.testing.expectEqualSlices(u8, restored.store.frontiers.items[0].original, recovered.get(.props, issuer.frontier_key).?);
    }
}

// Safe namespace revalidation for capture/adoption as well as cold constructors.
// This does not change the inherited-description proof or activation boundary.
fn validateAuthorityLease(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, file: std.Io.File, expected: lease_custody.Identity) !void {
    // Cold custody needs POSIX fds; unreachable in Windows production
    // (plaintext PortableServer only), so tests skip via this one gate.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (!std.meta.eql(expected, try lease_custody.statRegular(file.handle))) return error.IdentityMismatch;
    const lock_path = try std.mem.concat(allocator, u8, &.{ path, ".lock" });
    defer allocator.free(lock_path);
    const configured = try persistence.openColdExisting(io, dir, lock_path, .read_only);
    defer configured.close(io);
    if (!std.meta.eql(expected, try lease_custody.statRegular(configured.handle))) return error.IdentityMismatch;
    try lease_custody.reaffirmExclusive(file.handle);
}

// Existing-state custody is open-only; provisioning is the sole creator.
fn existingColdNamespace(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !bool {
    const snapshot = try std.mem.concat(allocator, u8, &.{ path, ".snap" });
    defer allocator.free(snapshot);
    for ([_][]const u8{ path, snapshot }) |name| {
        if (persistence.openColdExisting(io, dir, name, .read_only)) |file| {
            file.close(io);
            return true;
        } else |err| {
            // `openColdExisting` only supports linux/openbsd/freebsd; compare
            // so this compiles where `FileNotFound` is absent from its set.
            if (err != error.FileNotFound) {
                // Windows has no cold namespace at all; report absent so
                // callers reach their own Windows gates (SkipZigTest).
                if (@import("builtin").os.tag == .windows and err == error.Unsupported) return false;
                return err;
            }
        }
    }
    return false;
}

fn acquireExistingColdLease(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    // Raw-fd lease custody; Windows HANDLEs cannot compile the body below.
    // Unreachable in Windows production; tests skip via this.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const lock_path = try std.mem.concat(allocator, u8, &.{ path, ".lock" });
    defer allocator.free(lock_path);
    const file = try persistence.openColdExisting(io, dir, lock_path, .read_write);
    errdefer file.close(io);
    const identity = try lease_custody.statRegular(file.handle);
    try lease_custody.reaffirmExclusive(file.handle);
    const configured = try persistence.openColdExisting(io, dir, lock_path, .read_only);
    defer configured.close(io);
    if (!std.meta.eql(identity, try lease_custody.statRegular(configured.handle))) return error.IdentityMismatch;
    return file;
}

fn acquireProvisioningLease(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    // Same Windows gate as `acquireExistingColdLease`: raw-fd custody below.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const lock_path = try std.mem.concat(allocator, u8, &.{ path, ".lock" });
    defer allocator.free(lock_path);
    const permissions: std.Io.File.Permissions = if (@hasDecl(std.Io.File.Permissions, "fromMode")) .fromMode(0o600) else .default_file;
    const file = dir.createFile(io, lock_path, .{ .read = true, .truncate = false, .exclusive = true, .permissions = permissions }) catch |err| switch (err) {
        error.PathAlreadyExists => return acquireExistingColdLease(allocator, io, dir, path),
        else => return err,
    };
    errdefer file.close(io);
    const identity = try lease_custody.statRegular(file.handle);
    try lease_custody.reaffirmExclusive(file.handle);
    const configured = try persistence.openColdExisting(io, dir, lock_path, .read_only);
    defer configured.close(io);
    if (!std.meta.eql(identity, try lease_custody.statRegular(configured.handle))) return error.IdentityMismatch;
    return file;
}

const hot_runtime = @import("os_runtime.zig");
test "retained v2 causal existing cold state must not create missing lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(231));
    defer key.deinit();
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "no-create.wal", contextFor(&key), @splat(31), &key, 1000, .{});
        owner.deinit();
    }
    try tmp.dir.deleteFile(std.testing.io, "no-create.wal.lock");
    const before = try tmp.dir.readFileAlloc(std.testing.io, "no-create.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    if (Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "no-create.wal", contextFor(&key), &key, 1000, .{})) |result| {
        var unexpected = result;
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(error.FileNotFound, err);
    try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "no-create.wal.lock", .{}));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "no-create.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}
fn hotDuplicate(file: std.Io.File) !std.Io.File {
    return .{ .handle = try hot_runtime.duplicate(file.handle), .flags = file.flags };
}
fn hotSupported() bool {
    return switch (@import("builtin").os.tag) {
        .linux, .openbsd, .freebsd => true,
        else => false,
    };
}

test "mesh presence hot authority stage preserves exact epoch floor negatives and readonly barrier" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var local = try sign.KeyPair.fromSeed(@splat(180));
    defer local.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(181));
    defer remote.deinit();
    const context = contextFor(&local);
    var parent = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "hot.wal", context, @splat(18), &local, 1000, .{});
    var parent_owned = true;
    defer if (parent_owned) parent.deinit();
    const burned = try parent.reserveSubject(&local);
    var cut = try parent.prepareLocalFrontier(burned.counter, &.{}, 1000, &local);
    defer cut.abort();
    try cut.commit();
    var value = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 });
    value.expires_ms = 5000;
    try publish(&parent, value, &remote, &local, 1000);
    try parent.observeExpiry(3000, &local);
    const checkpoint = try parent.captureHotCheckpoint();
    const before = try tmp.dir.readFileAlloc(std.testing.io, "hot.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    var staged = try HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot.wal", context, try hotDuplicate(parent.lease), checkpoint, &local, .{});
    defer staged.deinit();
    try std.testing.expectEqualDeep(parent.head, staged.head());
    try std.testing.expectEqualDeep(parent.metadata, staged.metadata);
    try std.testing.expectEqual(@as(u64, 1), staged.metadata.epoch);
    try std.testing.expectEqual(@as(u64, 1), staged.metadata.issued_through);
    try std.testing.expectEqual(@as(i64, 3000), staged.head().expiry_floor_ms);
    try std.testing.expect(staged.restored.store.frontiers.items[0].decoded.retires(local.public_key, burned.epoch, burned.counter));
    try std.testing.expect(staged.durable.isReadOnly());
    try std.testing.expect(staged.durable.wal_file == null);
    try std.testing.expect(staged.durable.staged_write_file != null);
    try std.testing.expectError(error.ReadOnlyStore, staged.durable.put(.props, "forbidden", "stage"));
    try std.testing.expectError(error.ReadOnlyStore, staged.durable.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "forbidden", .value = "stage" }}));
    try std.testing.expectError(error.ReadOnlyStore, staged.durable.snapshotAndTruncate());
    const still = try tmp.dir.readFileAlloc(std.testing.io, "hot.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(still);
    try std.testing.expectEqualSlices(u8, before, still);
    const identity = checkpoint.lease_identity;
    const epoch = parent.metadata.epoch;
    // Model predecessor closure in this leaf test. Actual authenticated process
    // exit, exec and native SCM_RIGHTS acceptance belong to the barrier caller.
    parent.deinit();
    parent_owned = false;
    var successor = staged.activateAfterAuthenticatedCommitAndPredecessorExit();
    defer successor.deinit();
    try std.testing.expectEqual(epoch, successor.metadata.epoch);
    try std.testing.expectEqualDeep(checkpoint, try successor.captureHotCheckpoint());
    try std.testing.expectEqualDeep(identity, try lease_custody.statRegular(successor.lease.handle));
    try std.testing.expect(successor.winner("Guest", 1500, &.{remote.public_key}) != null);
    const next = try successor.reserveSubject(&local);
    try std.testing.expectEqualDeep(wire.Subject{ .epoch = epoch, .counter = 2 }, next);
}

test "mesh presence hot authority abort closes duplicate only and leaves predecessor WAL custody" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(182));
    defer key.deinit();
    const context = contextFor(&key);
    var parent = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "hot-abort.wal", context, @splat(19), &key, 1000, .{});
    defer parent.deinit();
    const checkpoint = try parent.captureHotCheckpoint();
    const before = try tmp.dir.readFileAlloc(std.testing.io, "hot-abort.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const duplicate = try hotDuplicate(parent.lease);
    var staged = try HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-abort.wal", context, duplicate, checkpoint, &key, .{});
    staged.abort();
    staged.abort();
    try std.testing.expectError(error.StatFailed, lease_custody.statRegular(duplicate.handle));
    try std.testing.expectEqualDeep(checkpoint, try parent.captureHotCheckpoint());
    const reopened = try tmp.dir.openFile(std.testing.io, "hot-abort.wal.lock", .{ .mode = .read_write });
    defer reopened.close(std.testing.io);
    try std.testing.expectError(error.WouldBlock, lease_custody.reaffirmExclusive(reopened.handle));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "hot-abort.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualDeep(wire.Subject{ .epoch = 1, .counter = 1 }, try parent.reserveSubject(&key));
}

test "mesh presence hot authority rejects reopened type inode context UUID and stale head before publication" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(183));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(184));
    defer foreign.deinit();
    const context = contextFor(&key);
    var parent = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, @splat(20), &key, 1000, .{});
    defer parent.deinit();
    const checkpoint = try parent.captureHotCheckpoint();
    const before_head = retained.digest(parent.durable.get(.props, retained.head_key).?);
    const reopened = try tmp.dir.openFile(std.testing.io, "hot-invalid.wal.lock", .{ .mode = .read_write });
    try std.testing.expectError(error.WouldBlock, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, reopened, checkpoint, &key, .{}));
    try std.testing.expectError(error.StatFailed, lease_custody.statRegular(reopened.handle));
    const directory: std.Io.File = .{ .handle = try hot_runtime.duplicate(tmp.dir.handle), .flags = .{ .nonblocking = false } };
    try std.testing.expectError(error.NotRegular, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, directory, checkpoint, &key, .{}));
    for (0..6) |kind| {
        var invalid = checkpoint;
        switch (kind) {
            0 => invalid.lease_identity.device ^= 1,
            1 => invalid.lease_identity.inode ^= 1,
            2 => invalid.store_id[0] ^= 1,
            3 => invalid.head_digest[0] ^= 1,
            4 => invalid.commit_generation += 1,
            5 => invalid.image_generation += 1,
            else => unreachable,
        }
        const inherited = try hotDuplicate(parent.lease);
        if (kind < 2) {
            try std.testing.expectError(error.IdentityMismatch, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, inherited, invalid, &key, .{}));
        } else {
            try std.testing.expectError(error.InvalidState, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, inherited, invalid, &key, .{}));
        }
        try std.testing.expectError(error.StatFailed, lease_custody.statRegular(inherited.handle));
    }
    var wrong_context = checkpoint;
    wrong_context.context.realm[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, try hotDuplicate(parent.lease), wrong_context, &key, .{}));
    try std.testing.expectError(error.ContextMismatch, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, try hotDuplicate(parent.lease), checkpoint, &foreign, .{}));
    try std.testing.expectEqualSlices(u8, &before_head, &retained.digest(parent.durable.get(.props, retained.head_key).?));
    try std.testing.expectEqualDeep(checkpoint, try parent.captureHotCheckpoint());
    _ = try parent.reserveSubject(&key); // The otherwise valid old checkpoint is stale.
    try std.testing.expectError(error.InvalidState, HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-invalid.wal", context, try hotDuplicate(parent.lease), checkpoint, &key, .{}));
}

fn hotStageAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, remote: *const sign.KeyPair) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var parent = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "hot-oom.wal", contextFor(key), @splat(21), key, 1000, .{});
    defer parent.deinit();
    try publish(&parent, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), remote, key, 1000);
    try parent.observeExpiry(2100, key);
    const checkpoint = try parent.captureHotCheckpoint();
    const before = try tmp.dir.readFileAlloc(std.testing.io, "hot-oom.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const inherited = try hotDuplicate(parent.lease);
    var staged = HotAuthorityStage.prepare(allocator, std.testing.io, tmp.dir, "hot-oom.wal", parent.context, inherited, checkpoint, key, .{}) catch |err| {
        if (err == error.OutOfMemory) {
            try std.testing.expectError(error.StatFailed, lease_custody.statRegular(inherited.handle));
            try std.testing.expectEqualDeep(checkpoint, try parent.captureHotCheckpoint());
            const after = try tmp.dir.readFileAlloc(std.testing.io, "hot-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            const contender = try tmp.dir.openFile(std.testing.io, "hot-oom.wal.lock", .{ .mode = .read_write });
            defer contender.close(std.testing.io);
            try std.testing.expectError(error.WouldBlock, lease_custody.reaffirmExclusive(contender.handle));
            var retry = try HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "hot-oom.wal", parent.context, try hotDuplicate(parent.lease), checkpoint, key, .{});
            defer retry.deinit();
            try std.testing.expectEqualDeep(parent.head, retry.head());
            try std.testing.expectEqual(@as(usize, 1), retry.restored.store.entries.items.len);
            try std.testing.expect(retry.restored.store.winnerWithExpiryFloor("Guest", 1500, retry.head().expiry_floor_ms, &.{remote.public_key}) == null);
        }
        return err;
    };
    defer staged.deinit();
    try std.testing.expectEqualDeep(parent.head, staged.head());
    try std.testing.expectEqualDeep(checkpoint, try parent.captureHotCheckpoint());
}

test "mesh presence hot authority exhaustive allocation failures close only and preserve exact cut and retry" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(185));
    defer key.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(186));
    defer remote.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, hotStageAllocationScenario, .{ &key, &remote });
}

test "mesh presence hot checkpoint refuses active mutations readonly poison generation and cached authority mismatch" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(187));
    defer key.deinit();
    var parent = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "hot-capture.wal", contextFor(&key), @splat(22), &key, 1000, .{});
    defer parent.deinit();
    const checkpoint = try parent.captureHotCheckpoint();
    var plan = try parent.prepareLocalFrontier(0, &.{}, 1100, &key);
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    plan.abort();
    var batch = try parent.durable.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "unused", .value = "unpublished" }});
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    batch.abort();
    var single = try parent.durable.preparePut(.props, "unused", "unpublished");
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    single.abort();
    parent.durable.staged_read_only = true;
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    parent.durable.staged_read_only = false;
    parent.published_generation += 1;
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    parent.published_generation -= 1;
    parent.head.expiry_floor_ms += 1;
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    parent.head.expiry_floor_ms -= 1;
    parent.metadata.issued_through += 1;
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
    parent.metadata.issued_through -= 1;
    try std.testing.expectEqualDeep(checkpoint, try parent.captureHotCheckpoint());
    parent.durable.setPreparedIoFault(.{ .write = .failed });
    try std.testing.expectError(error.IoAmbiguous, parent.reserveSubject(&key));
    try std.testing.expect(parent.durable.preparedWritesPoisoned());
    try std.testing.expectError(error.InvalidState, parent.captureHotCheckpoint());
}

fn hotForbiddenClose(_: ?*anyopaque, _: []const std.Io.File) void {
    @panic("hot activation issued a descriptor close after the barrier");
}

test "mesh presence group causal grouped rejection preserves both then atomic rename advances once" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(189));
    defer key.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "group-before.wal", contextFor(&key), @splat(24), &key, 1000, .{});
    defer owner.deinit();
    const first = try owner.reserveSubject(&key);
    const second = try owner.reserveSubject(&key);
    var a = try recordFor(key.public_key, first);
    var b = try recordFor(key.public_key, second);
    b.nick = "Other";
    try publishLifecycle(&owner, a, 2, &.{ 1, 2 }, 1000, &key);
    try publishLifecycle(&owner, b, 2, &.{ 1, 2 }, 1000, &key);
    a.nick = "Renamed";
    a.revision = 2;
    a.claim_revision = 2;
    a.claim_hlc = 10;
    b.nick = "AlsoRenamed";
    b.revision = 2;
    b.claim_revision = 2;
    b.claim_hlc = 10;
    var a_buffer: [wire.max_wire_len]u8 = undefined;
    var b_buffer: [wire.max_wire_len]u8 = undefined;
    const a_raw = try wire.encode(a, &key, &a_buffer);
    const b_raw = try wire.encode(b, &key, &b_buffer);
    const before = owner.head;
    var first_plan = try owner.prepareLocalLifecycle(a_raw, 2, &.{ 1, 2 }, 1000, &key);
    defer first_plan.abort();
    try std.testing.expectError(error.MutationActive, owner.prepareLocalLifecycle(b_raw, 2, &.{ 1, 2 }, 1000, &key));
    first_plan.abort();
    b_buffer[b_raw.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, owner.prepareLocalLifecycles(&.{ a_raw, b_raw }, 2, &.{ 1, 2 }, 1000, &key));
    try std.testing.expectEqualDeep(before, owner.head);
    try std.testing.expect(owner.winner("Guest", 1000, &.{key.public_key}) != null);
    try std.testing.expect(owner.winner("Other", 1000, &.{key.public_key}) != null);
    b_buffer[b_raw.len - 1] ^= 1;
    const generation = owner.retained_store.generation;
    var grouped = try owner.prepareLocalLifecycles(&.{ a_raw, b_raw }, 2, &.{ 1, 2 }, 1000, &key);
    defer grouped.deinit();
    try std.testing.expectEqualDeep(before, owner.head);
    try grouped.commit();
    try std.testing.expectEqual(generation + 1, owner.retained_store.generation);
    try std.testing.expectEqual(before.commit_generation + 1, owner.head.commit_generation);
    try std.testing.expectEqual(before.image_generation + 1, owner.head.image_generation);
    try std.testing.expect(owner.winner("Guest", 1000, &.{key.public_key}) == null);
    try std.testing.expect(owner.winner("Other", 1000, &.{key.public_key}) == null);
    try std.testing.expect(owner.winner("Renamed", 1000, &.{key.public_key}) != null);
    try std.testing.expect(owner.winner("AlsoRenamed", 1000, &.{key.public_key}) != null);
    try std.testing.expectEqualSlices(u8, a_raw, grouped.original(0).?);
    try std.testing.expectEqualSlices(u8, b_raw, grouped.original(1).?);
    try expectAuthorityDiskProjection(&owner);
}

fn initializeGroupFixture(owner: *Authority, key: *const sign.KeyPair) ![2]wire.Record {
    var first = try recordFor(key.public_key, try owner.reserveSubject(key));
    var second = try recordFor(key.public_key, try owner.reserveSubject(key));
    first.nick = "First";
    second.nick = "Second";
    try publishLifecycle(owner, first, 2, &.{ 1, 2 }, 1000, key);
    try publishLifecycle(owner, second, 2, &.{ 1, 2 }, 1000, key);
    return .{ first, second };
}

test "mesh presence group authority mixed quit rename owns originals and strictly restores normalized package" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(190));
    defer key.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "group-mixed.wal", contextFor(&key), @splat(25), &key, 1000, .{ .retained = .{ .max_entries = 2, .max_origins = 1 } });
    defer owner.deinit();
    var values = try initializeGroupFixture(&owner, &key);
    values[0].operation = .quit;
    values[0].revision = 2;
    values[1].revision = 2;
    values[1].claim_revision = 2;
    values[1].claim_hlc = 10;
    values[1].nick = "Renamed";
    var buffers: [2][wire.max_wire_len]u8 = undefined;
    const originals = [_][]const u8{ try wire.encode(values[0], &key, &buffers[0]), try wire.encode(values[1], &key, &buffers[1]) };
    const before = owner.head;
    var aborted = try owner.prepareLocalLifecycles(&originals, 2, &.{2}, 1000, &key);
    aborted.deinit();
    aborted.deinit();
    try std.testing.expectEqualDeep(before, owner.head);
    var plan = try owner.prepareLocalLifecycles(&originals, 2, &.{2}, 1000, &key);
    defer plan.deinit();
    try plan.commit();
    try std.testing.expectEqual(@as(usize, 1), owner.retained_store.entries.items.len);
    try std.testing.expect(owner.retained_store.frontiers.items[0].decoded.retires(key.public_key, 1, 1));
    try std.testing.expect(owner.winner("First", 1000, &.{key.public_key}) == null);
    try std.testing.expect(owner.winner("Second", 1000, &.{key.public_key}) == null);
    try std.testing.expect(owner.winner("Renamed", 1000, &.{key.public_key}) != null);
    try std.testing.expectEqual(@as(usize, 2), plan.originalCount());
    for (originals, 0..) |original, i| {
        try std.testing.expectEqualSlices(u8, original, plan.original(i).?);
        try (try wire.decode(plan.original(i).?)).verify();
    }
    try std.testing.expectError(error.AlreadyConsumed, plan.commit());
    try expectAuthorityDiskProjection(&owner);
    var restored_disk = try persistence.OroStore.openReadOnlyWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "group-mixed.wal", .{ .changefeed_capacity = 0 });
    defer restored_disk.deinit();
    var restored = try image.stageRestore(std.testing.allocator, &restored_disk, owner.context, owner.retained_store.config);
    defer restored.deinit();
    try std.testing.expectEqualDeep(owner.head, restored.head);
    try std.testing.expectEqual(@as(usize, 1), restored.store.entries.items.len);
    try std.testing.expectEqualSlices(u8, originals[1], restored.store.entries.items[0].original);
    plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), plan.originalCount());
}

test "mesh presence group authority rejects empty duplicate foreign epoch highwater active and tampered tickets before WAL" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(191));
    defer key.deinit();
    var other = try sign.KeyPair.fromSeed(@splat(192));
    defer other.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "group-invalid.wal", contextFor(&key), @splat(26), &key, 1000, .{});
    defer owner.deinit();
    var values = try initializeGroupFixture(&owner, &key);
    for (&values) |*value| value.revision = 2;
    var buffers: [2][wire.max_wire_len]u8 = undefined;
    const a = try wire.encode(values[0], &key, &buffers[0]);
    var b = try wire.encode(values[1], &key, &buffers[1]);
    const before = owner.head;
    const before_wal = try tmp.dir.readFileAlloc(std.testing.io, "group-invalid.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before_wal);
    try std.testing.expectError(error.InvalidLocalLifecycle, owner.prepareLocalLifecycles(&.{}, 2, &.{ 1, 2 }, 1000, &key));
    try std.testing.expectError(error.InvalidLocalLifecycle, owner.prepareLocalLifecycles(&.{ a, a }, 2, &.{ 1, 2 }, 1000, &key));
    try std.testing.expectError(error.InvalidLocalLifecycle, owner.prepareLocalLifecycles(&.{ a, b }, 2, &.{1}, 1000, &key));
    values[1].origin = other.public_key;
    b = try wire.encode(values[1], &other, &buffers[1]);
    try std.testing.expectError(error.ContextMismatch, owner.prepareLocalLifecycles(&.{ a, b }, 2, &.{ 1, 2 }, 1000, &key));
    values[1].origin = key.public_key;
    values[1].guest = try wire.guestId(.{ .epoch = 2, .counter = 2 });
    b = try wire.encode(values[1], &key, &buffers[1]);
    try std.testing.expectError(error.InvalidState, owner.prepareLocalLifecycles(&.{ a, b }, 2, &.{ 1, 2 }, 1000, &key));
    values[1].guest = try wire.guestId(.{ .epoch = 1, .counter = 3 });
    b = try wire.encode(values[1], &key, &buffers[1]);
    try std.testing.expectError(error.InvalidState, owner.prepareLocalLifecycles(&.{ a, b }, 2, &.{ 1, 2 }, 1000, &key));
    values[1].guest = try wire.guestId(.{ .epoch = 1, .counter = 2 });
    b = try wire.encode(values[1], &key, &buffers[1]);
    var plan = try owner.prepareLocalLifecycles(&.{ a, b }, 2, &.{ 1, 2 }, 1000, &key);
    defer plan.deinit();
    const group = &plan.ram.local_lifecycles;
    group.subjects[1].original[group.subjects[1].original.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidPlan, plan.commit());
    group.subjects[1].original[group.subjects[1].original.len - 1] ^= 1;
    group.subjects[1].index = 0;
    try std.testing.expectError(error.InvalidPlan, plan.commit());
    group.subjects[1].index = 1;
    owner.retained_store.generation += 1;
    try std.testing.expectError(error.InvalidPlan, plan.commit());
    owner.retained_store.generation -= 1;
    const after_wal = try tmp.dir.readFileAlloc(std.testing.io, "group-invalid.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after_wal);
    try std.testing.expectEqualSlices(u8, before_wal, after_wal);
    try std.testing.expectEqualDeep(before, owner.head);
    plan.abort();
    try std.testing.expect(owner.active_generation == null);
    try std.testing.expect(owner.winner("First", 1000, &.{key.public_key}) != null);
    try std.testing.expect(owner.winner("Second", 1000, &.{key.public_key}) != null);
}

test "mesh presence group authority exhaustive allocation rollback retry and no fail multi quit publication" {
    var key = try sign.KeyPair.fromSeed(@splat(193));
    defer key.deinit();
    var index: usize = 0;
    while (index < 10000) : (index += 1) {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var owner = try Authority.initialize(failing.allocator(), std.testing.io, tmp.dir, "group-oom.wal", contextFor(&key), @splat(27), &key, 1000, .{ .retained = .{ .max_entries = 2, .max_origins = 1 } });
        defer owner.deinit();
        var values = try initializeGroupFixture(&owner, &key);
        for (&values) |*value| {
            value.operation = .quit;
            value.revision = 2;
        }
        var buffers: [2][wire.max_wire_len]u8 = undefined;
        const originals = [_][]const u8{ try wire.encode(values[0], &key, &buffers[0]), try wire.encode(values[1], &key, &buffers[1]) };
        const before = owner.head;
        const generation = owner.retained_store.generation;
        const wal = try tmp.dir.readFileAlloc(std.testing.io, "group-oom.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(wal);
        failing.fail_index = failing.alloc_index + index;
        var plan = owner.prepareLocalLifecycles(&originals, 2, &.{}, 1000, &key) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expectEqualDeep(before, owner.head);
            try std.testing.expectEqual(generation, owner.retained_store.generation);
            try std.testing.expect(owner.active_generation == null);
            try std.testing.expect(owner.durable.active_batch == null);
            try std.testing.expect(!owner.durable.preparedWritesPoisoned());
            const after = try tmp.dir.readFileAlloc(std.testing.io, "group-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, wal, after);
            try std.testing.expect(owner.winner("First", 1000, &.{key.public_key}) != null);
            try std.testing.expect(owner.winner("Second", 1000, &.{key.public_key}) != null);
            failing.fail_index = std.math.maxInt(usize);
            try expectAuthorityDiskProjection(&owner);
            var retry = try owner.prepareLocalLifecycles(&originals, 2, &.{}, 1000, &key);
            defer retry.deinit();
            const allocations = failing.allocations;
            failing.fail_index = failing.alloc_index;
            try retry.commit();
            try std.testing.expectEqual(allocations, failing.allocations);
            try std.testing.expectEqual(@as(usize, 0), owner.retained_store.entries.items.len);
            try std.testing.expectEqual(@as(usize, 2), retry.originalCount());
            for (originals, 0..) |original, i| try std.testing.expectEqualSlices(u8, original, retry.original(i).?);
            continue;
        };
        defer plan.deinit();
        const allocations = failing.allocations;
        failing.fail_index = failing.alloc_index;
        try plan.commit();
        try std.testing.expectEqual(allocations, failing.allocations);
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(generation + 1, owner.retained_store.generation);
        try std.testing.expectEqual(before.commit_generation + 1, owner.head.commit_generation);
        try std.testing.expectEqual(@as(usize, 0), owner.retained_store.entries.items.len);
        for (originals, 0..) |original, i| try std.testing.expectEqualSlices(u8, original, plan.original(i).?);
        try std.testing.expect(index > 0);
        return;
    }
    return error.TestUnexpectedResult;
}

test "mesh presence group authority failed and ambiguous WAL never publish partial RAM and cold restore exact cut" {
    var key = try sign.KeyPair.fromSeed(@splat(194));
    defer key.deinit();
    for ([_]persistence.PreparedIoFault{ .{ .write = .failed }, .{ .write = .short }, .{ .sync = true } }, 0..) |fault, i| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "group-fault.wal", contextFor(&key), @splat(28), &key, 1000, .{});
        var owned = true;
        defer if (owned) owner.deinit();
        var values = try initializeGroupFixture(&owner, &key);
        for (&values) |*value| {
            value.operation = .quit;
            value.revision = 2;
        }
        var buffers: [2][wire.max_wire_len]u8 = undefined;
        const originals = [_][]const u8{ try wire.encode(values[0], &key, &buffers[0]), try wire.encode(values[1], &key, &buffers[1]) };
        const before = owner.head;
        const generation = owner.retained_store.generation;
        var plan = try owner.prepareLocalLifecycles(&originals, 2, &.{}, 1000, &key);
        const successor_head = plan.head;
        owner.durable.setPreparedIoFault(fault);
        try std.testing.expectError(error.IoAmbiguous, plan.commit());
        plan.abort();
        try std.testing.expect(owner.durable.preparedWritesPoisoned());
        try std.testing.expectEqualDeep(before, owner.head);
        try std.testing.expectEqual(generation, owner.retained_store.generation);
        try std.testing.expectEqual(@as(usize, 2), owner.retained_store.entries.items.len);
        try std.testing.expect(owner.winner("First", 1000, &.{key.public_key}) == null);
        try std.testing.expect(owner.winner("Second", 1000, &.{key.public_key}) == null);
        try std.testing.expectError(error.StorePoisoned, owner.prepareLocalLifecycles(&originals, 2, &.{}, 1000, &key));
        owner.deinit();
        owned = false;
        // Source-owned recovery is the only writable repair boundary. The
        // four-row package is wholly predecessor or wholly successor, never
        // a single-subject intermediate image after the failed batch.
        {
            var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "group-fault.wal", .{ .changefeed_capacity = 0 });
            defer recovered.deinit();
            var restored = try image.stageRestore(std.testing.allocator, &recovered, contextFor(&key), .{});
            defer restored.deinit();
            try std.testing.expectEqualDeep(if (i == 2) successor_head else before, restored.head);
            try std.testing.expectEqual(@as(usize, if (i == 2) 0 else 2), restored.store.entries.items.len);
        }
        var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "group-fault.wal", contextFor(&key), &key, 1000, .{});
        defer cold.deinit();
        try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
        try std.testing.expectEqual(@as(usize, 0), cold.retained_store.entries.items.len);
        try std.testing.expectError(error.InvalidState, cold.prepareLocalLifecycles(&originals, 0, &.{}, 1000, &key));
    }
}

test "mesh presence group authority every multi quit append prefix restores old or whole group" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(195));
    defer key.deinit();
    var offset: usize = undefined;
    var old_head: retained.Head = undefined;
    var new_head: retained.Head = undefined;
    const bytes = block: {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "group-complete.wal", contextFor(&key), @splat(29), &key, 1000, .{});
        defer owner.deinit();
        var values = try initializeGroupFixture(&owner, &key);
        old_head = owner.head;
        offset = @intCast(owner.durable.wal_offset);
        for (&values) |*value| {
            value.operation = .quit;
            value.revision = 2;
        }
        var buffers: [2][wire.max_wire_len]u8 = undefined;
        const originals = [_][]const u8{ try wire.encode(values[0], &key, &buffers[0]), try wire.encode(values[1], &key, &buffers[1]) };
        var plan = try owner.prepareLocalLifecycles(&originals, 2, &.{}, 1000, &key);
        defer plan.deinit();
        try plan.commit();
        new_head = owner.head;
        break :block try tmp.dir.readFileAlloc(std.testing.io, "group-complete.wal", std.testing.allocator, .unlimited);
    };
    defer std.testing.allocator.free(bytes);
    for (offset..bytes.len + 1) |cut| {
        {
            const file = try tmp.dir.createFile(std.testing.io, "group-cut.wal", .{ .read = true, .truncate = true });
            defer file.close(std.testing.io);
            try file.writePositionalAll(std.testing.io, bytes[0..cut], 0);
            try file.sync(std.testing.io);
        }
        var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "group-cut.wal", .{ .changefeed_capacity = 0 });
        defer recovered.deinit();
        var restored = try image.stageRestore(std.testing.allocator, &recovered, contextFor(&key), .{});
        defer restored.deinit();
        const complete = cut == bytes.len;
        try std.testing.expectEqualDeep(if (complete) new_head else old_head, restored.head);
        try std.testing.expectEqual(@as(usize, if (complete) 0 else 2), restored.store.entries.items.len);
        try std.testing.expectEqual(!complete, restored.store.winner("First", 1000, &.{key.public_key}) != null);
        try std.testing.expectEqual(!complete, restored.store.winner("Second", 1000, &.{key.public_key}) != null);
        try std.testing.expectEqual(complete, restored.store.frontiers.items[0].decoded.retires(key.public_key, 1, 1));
        try std.testing.expectEqual(complete, restored.store.frontiers.items[0].decoded.retires(key.public_key, 1, 2));
    }
}

/// Existing target ABI, matching native_process's post-fork custody rules.
/// The BSD child performs only pwrite/fsync/kill/_exit; no inherited allocator,
/// logging, World mutex or destructor is touched before its intentional death.
fn killAfterGroupedPreparedAppend(fd: std.posix.fd_t, offset: u64, bytes: []const u8) !void {
    const os = @import("builtin").os.tag;
    if (comptime os == .linux) {
        return killAfterPreparedAppend(fd, offset, bytes);
    } else if (comptime os == .openbsd or os == .freebsd) {
        const posix = std.posix;
        const sys = posix.system;
        const pid = sys.fork();
        if (pid < 0) return error.TestUnexpectedResult;
        if (pid == 0) {
            var written: usize = 0;
            while (written < bytes.len) {
                const result = sys.pwrite(fd, bytes.ptr + written, bytes.len - written, @intCast(offset + written));
                if (result > 0) {
                    written += @intCast(result);
                } else if (result < 0 and posix.errno(result) == .INTR) {
                    continue;
                } else sys._exit(21);
            }
            while (sys.fsync(fd) != 0) {
                if (posix.errno(@as(c_int, -1)) != .INTR) sys._exit(22);
            }
            _ = sys.kill(sys.getpid(), posix.SIG.KILL);
            sys._exit(23);
        }
        var status: c_int = 0;
        while (true) {
            const result = sys.waitpid(pid, &status, 0);
            if (result == pid) break;
            if (result < 0 and posix.errno(result) == .INTR) continue;
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqual(@as(c_int, 9), status);
    } else return error.SkipZigTest;
}

test "mesh presence group authority actual supported POSIX SIGKILL at grouped prepared WAL boundaries" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(196));
    defer key.deinit();
    for (0..4) |boundary| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var expected: retained.Head = undefined;
        {
            var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "group-kill.wal", contextFor(&key), @splat(30), &key, 1000, .{});
            defer owner.deinit();
            var values = try initializeGroupFixture(&owner, &key);
            const before = owner.head;
            for (&values) |*value| {
                value.operation = .quit;
                value.revision = 2;
            }
            var buffers: [2][wire.max_wire_len]u8 = undefined;
            const originals = [_][]const u8{ try wire.encode(values[0], &key, &buffers[0]), try wire.encode(values[1], &key, &buffers[1]) };
            var plan = try owner.prepareLocalLifecycles(&originals, 2, &.{}, 1000, &key);
            defer plan.deinit();
            const packet = owner.durable.active_batch.?.record.?;
            const prefix = switch (boundary) {
                0 => 0,
                1 => 4,
                2 => packet.len / 2,
                else => packet.len,
            };
            expected = if (boundary == 3) plan.head else before;
            try killAfterGroupedPreparedAppend(owner.durable.wal_file.?.handle, owner.durable.wal_offset, packet[0..prefix]);
            try std.testing.expectEqualDeep(before, owner.head);
            try std.testing.expectEqual(@as(usize, 2), owner.retained_store.entries.items.len);
        }
        var recovered = try persistence.OroStore.openWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "group-kill.wal", .{ .changefeed_capacity = 0 });
        defer recovered.deinit();
        var restored = try image.stageRestore(std.testing.allocator, &recovered, contextFor(&key), .{});
        defer restored.deinit();
        try std.testing.expectEqualDeep(expected, restored.head);
        try std.testing.expectEqual(@as(usize, if (boundary == 3) 0 else 2), restored.store.entries.items.len);
    }
}

test "mesh presence hot activation preserves local quarantine with no allocation or descriptor close" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(188));
    defer key.deinit();
    var parent = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "hot-quarantine.wal", contextFor(&key), @splat(23), &key, 1000, .{});
    var parent_owned = true;
    defer if (parent_owned) parent.deinit();
    var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
    const fork = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{} }, &key, &buffer);
    var plan = try parent.prepareRemoteFrontier(fork, &.{key.public_key}, 1000, &key);
    defer plan.abort();
    try plan.commit();
    const checkpoint = try parent.captureHotCheckpoint();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var staged = try HotAuthorityStage.prepare(failing.allocator(), std.testing.io, tmp.dir, "hot-quarantine.wal", parent.context, try hotDuplicate(parent.lease), checkpoint, &key, .{});
    defer staged.deinit();
    try std.testing.expect(staged.restored.local_authoring_disabled);
    try std.testing.expect(staged.restored.store.frontiers.items[0].conflict != null);
    parent.deinit();
    parent_owned = false;
    const allocations = failing.allocations;
    failing.fail_index = failing.alloc_index;
    var forbidden_io = std.testing.io.vtable.*;
    forbidden_io.fileClose = hotForbiddenClose;
    staged.io.vtable = &forbidden_io;
    staged.durable.io.vtable = &forbidden_io;
    var successor = staged.activateAfterAuthenticatedCommitAndPredecessorExit();
    successor.io = std.testing.io;
    successor.durable.io = std.testing.io;
    defer successor.deinit();
    try std.testing.expectEqual(allocations, failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqualDeep(checkpoint, try successor.captureHotCheckpoint());
    try std.testing.expectEqual(@as(u64, 1), successor.metadata.epoch);
    try std.testing.expect(successor.local_authoring_disabled);
    try std.testing.expectError(error.AuthoringDisabled, successor.reserveSubject(&key));
}

test "mesh presence retained v2 grouped class changes preserve hot exact originals and cold negatives" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(233));
    defer key.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "classes.wal", contextFor(&key), @splat(33), &key, 1000, .{ .retained = .{ .max_entries = 3 } });
    var owner_owned = true;
    defer if (owner_owned) owner.deinit();
    const classes = [_]wire.RoutingClass{ .true_guest, .authenticated_untracked, .exact_reusable_attachment };
    const names = [_][]const u8{ "Guest", "Account", "Attached" };
    var records: [3]wire.Record = undefined;
    var buffers: [3][wire.max_wire_len]u8 = undefined;
    var originals: [3][]const u8 = undefined;
    for (&records, classes, names, 0..) |*record, class, nick, i| {
        record.* = try recordFor(key.public_key, try owner.reserveSubject(&key));
        record.routing_class = class;
        record.nick = nick;
        originals[i] = try wire.encode(record.*, &key, &buffers[i]);
    }
    {
        var group = try owner.prepareLocalLifecycles(&originals, 3, &.{ 1, 2, 3 }, 1000, &key);
        defer group.deinit();
        try group.commit();
    }
    try expectAuthorityDiskProjection(&owner);
    const checkpoint = try owner.captureHotCheckpoint();
    var hot = try HotAuthorityStage.prepare(std.testing.allocator, std.testing.io, tmp.dir, "classes.wal", owner.context, try hotDuplicate(owner.lease), checkpoint, &key, .{ .retained = .{ .max_entries = 3 } });
    defer hot.deinit();
    for (hot.restored.store.entries.items) |entry| {
        const id = try wire.subject(entry.decoded.record.guest);
        try std.testing.expectEqual(classes[id.counter - 1], entry.decoded.record.routing_class);
        try std.testing.expectEqual(@as(u64, 1), entry.decoded.record.class_revision);
        try std.testing.expectEqualSlices(u8, originals[id.counter - 1], entry.original);
    }
    owner.deinit();
    owner_owned = false;
    var successor = hot.activateAfterAuthenticatedCommitAndPredecessorExit();
    var successor_owned = true;
    defer if (successor_owned) successor.deinit();
    // Class-only, nickname-only, and terminal transitions share one old cut.
    records[0].revision = 2;
    records[0].class_revision = 2;
    records[0].routing_class = .authenticated_untracked;
    records[1].revision = 2;
    records[1].claim_revision = 2;
    records[1].claim_hlc += 1;
    records[1].nick = "RenamedAccount";
    records[2].revision = 2;
    records[2].operation = .quit;
    for (records, 0..) |record, i| originals[i] = try wire.encode(record, &key, &buffers[i]);
    {
        var group = try successor.prepareLocalLifecycles(&originals, 3, &.{ 1, 2 }, 1000, &key);
        defer group.deinit();
        try group.commit();
        try std.testing.expectEqual(@as(usize, 2), successor.retained_store.entries.items.len);
        // The signed QUIT remains explicitly owned even after image compaction.
        try std.testing.expectEqualSlices(u8, originals[2], group.original(2).?);
    }
    try expectAuthorityDiskProjection(&successor);
    successor.deinit();
    successor_owned = false;
    var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "classes.wal", contextFor(&key), &key, 1000, .{});
    defer cold.deinit();
    try std.testing.expectEqual(@as(u64, 2), cold.metadata.epoch);
    try std.testing.expectEqual(@as(usize, 0), cold.retained_store.entries.items.len);
    try std.testing.expectError(error.RetiredSubject, cold.preparePresence(originals[2], &.{key.public_key}, 1000, &key));
}

fn namespaceFingerprintForTest(dir: std.Io.Dir) ![32]u8 {
    const opened = try dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer opened.close(std.testing.io);
    var iterator = opened.iterate();
    var result: [32]u8 = @splat(0);
    while (try iterator.next(std.testing.io)) |entry| {
        var hash = std.crypto.hash.Blake3.init(.{});
        hash.update(entry.name);
        hash.update(&.{@intFromEnum(entry.kind)});
        var part: [32]u8 = undefined;
        hash.final(&part);
        for (&result, part) |*byte, value| byte.* ^= value;
    }
    return result;
}

fn legacyHeadForTest(head: retained.Head, image_bytes: []const u8, key: *const sign.KeyPair) ![retained.head_len]u8 {
    var value = head;
    value.image_digest = retained.digest(image_bytes);
    value.image_len = image_bytes.len;
    var raw = try value.encode(key);
    raw[4] = 1;
    raw[retained.body_len..].* = try key.signCtx("onyx-mesh-presence-retained-local-v1", raw[0..retained.body_len]);
    // This is a real old-domain signature fixture, not a production fallback.
    try std.testing.expect(try sign.verifyCtx("onyx-mesh-presence-retained-local-v1", raw[0..retained.body_len], raw[retained.body_len..].*, key.public_key));
    return raw;
}

test "mesh presence retained v2 cold refuses legacy unknown mixed realm and key without repairing suffix" {
    // Raw-fd lease custody; Windows HANDLEs cannot compile it.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(234));
    defer key.deinit();
    var wrong = try sign.KeyPair.fromSeed(@splat(235));
    defer wrong.deinit();
    for (0..5) |kind| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "schema.wal", contextFor(&key), @splat(34), &key, 1000, .{});
            defer owner.deinit();
            if (kind <= 2) {
                const bytes = try std.testing.allocator.dupe(u8, owner.durable.get(.props, retained.image_key).?);
                defer std.testing.allocator.free(bytes);
                bytes[4] = 1; // A complete v1 frontier-only image.
                var head = owner.head;
                head.image_digest = retained.digest(bytes);
                var raw = if (kind == 0) try legacyHeadForTest(head, bytes, &key) else try head.encode(&key);
                if (kind == 1) {
                    raw[4] = 99;
                    raw[retained.body_len..].* = try key.signCtx(retained.domain, raw[0..retained.body_len]);
                }
                var batch = try owner.durable.prepareBatch(&.{
                    .{ .family = .props, .kind = .put, .key = retained.image_key, .value = bytes },
                    .{ .family = .props, .kind = .put, .key = retained.head_key, .value = &raw },
                });
                defer batch.abort();
                try batch.commit();
            }
            try owner.durable.snapshotAndTruncate();
            // This tolerated suffix must remain byte-identical on schema refusal.
            try owner.durable.wal_file.?.writePositionalAll(std.testing.io, &.{ 0, 0, 0 }, owner.durable.wal_offset);
            try owner.durable.wal_file.?.sync(std.testing.io);
        }
        const namespace = try namespaceFingerprintForTest(tmp.dir);
        const wal = try tmp.dir.readFileAlloc(std.testing.io, "schema.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(wal);
        const snap = try tmp.dir.readFileAlloc(std.testing.io, "schema.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(snap);
        const file = try tmp.dir.openFile(std.testing.io, "schema.wal", .{});
        defer file.close(std.testing.io);
        const identity = try lease_custody.statRegular(file.handle);
        var context = contextFor(&key);
        if (kind == 3) context.realm[0] ^= 1;
        if (kind == 4) context.origin = wrong.public_key;
        const selected_key = if (kind == 4) &wrong else &key;
        if (Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "schema.wal", context, selected_key, 1000, .{})) |result| {
            var unexpected = result;
            unexpected.deinit();
            return error.TestUnexpectedResult;
        } else |err| switch (kind) {
            0 => try std.testing.expectEqual(error.MigrationRequired, err),
            1 => try std.testing.expectEqual(error.InvalidHead, err),
            2 => try std.testing.expectEqual(error.InvalidImage, err),
            3 => try std.testing.expectEqual(error.ContextMismatch, err),
            else => try std.testing.expectEqual(error.BadSignature, err),
        }
        const after = try tmp.dir.readFileAlloc(std.testing.io, "schema.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        const after_snap = try tmp.dir.readFileAlloc(std.testing.io, "schema.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after_snap);
        try std.testing.expectEqualSlices(u8, wal, after);
        try std.testing.expectEqualSlices(u8, snap, after_snap);
        const current = try tmp.dir.openFile(std.testing.io, "schema.wal", .{});
        defer current.close(std.testing.io);
        try std.testing.expectEqualDeep(identity, try lease_custody.statRegular(current.handle));
        try std.testing.expectEqualDeep(namespace, try namespaceFingerprintForTest(tmp.dir));
    }
}

fn coldRawSync(fd: std.posix.fd_t) bool {
    if (comptime @import("builtin").os.tag == .linux) return std.os.linux.errno(std.os.linux.fsync(fd)) == .SUCCESS;
    return std.posix.system.fsync(fd) == 0;
}
fn coldRawRename(fd: std.posix.fd_t, source: [*:0]const u8, destination: [*:0]const u8) bool {
    if (comptime @import("builtin").os.tag == .linux) return std.os.linux.errno(std.os.linux.renameat(fd, source, fd, destination)) == .SUCCESS;
    return std.posix.system.renameat(fd, source, fd, destination) == 0;
}
fn coldRawExit(code: u8) noreturn {
    if (comptime @import("builtin").os.tag == .linux) std.os.linux.exit(code);
    std.posix.system._exit(code);
}
fn coldKillSelf() noreturn {
    if (comptime @import("builtin").os.tag == .linux) {
        _ = std.os.linux.kill(std.os.linux.getpid(), .KILL);
    } else _ = std.posix.system.kill(std.posix.system.getpid(), std.posix.SIG.KILL);
    coldRawExit(29);
}

/// Post-fork child uses only target raw rename/pwrite/fsync/kill syscalls, never
/// std.Io's inherited worker state or allocator. All complete files and the
/// exact source-owned successor packet have been reserved in the parent.
fn killColdPreparedBoundary(stage: *persistence.ColdRecoveryStage, boundary: usize) !void {
    const plan = &stage.backing.?.plan.?;
    const wal = plan.wal_atomic.?;
    const wal_hex = std.fmt.hex(wal.file_basename_hex);
    var wal_name: [16:0]u8 = undefined;
    @memcpy(wal_name[0..16], &wal_hex);
    wal_name[16] = 0;
    var snap_name: [16:0]u8 = @splat(0);
    if (plan.snapshot_atomic) |snapshot| @memcpy(snap_name[0..16], &std.fmt.hex(snapshot.file_basename_hex));
    const packet = stage.backing.?.store.active_batch.?.record.?;
    const os = @import("builtin").os.tag;
    const pid: i32 = if (comptime os == .linux) block: {
        const result = std.os.linux.fork();
        if (std.os.linux.errno(result) != .SUCCESS) return error.TestUnexpectedResult;
        break :block @intCast(result);
    } else std.posix.system.fork();
    if (pid < 0) return error.TestUnexpectedResult;
    if (pid == 0) {
        if (boundary >= 8) {
            // Interrupt creation of the private epoch inode at EVERY0..25
            // length. Its authoritative predecessor must stay available.
            const truncated = if (comptime os == .linux) std.os.linux.errno(std.os.linux.ftruncate(plan.writer.handle, 0)) == .SUCCESS else std.posix.system.ftruncate(plan.writer.handle, 0) == 0;
            if (!truncated) coldRawExit(30);
            const length = boundary - 8;
            var written: usize = 0;
            while (written < length) {
                if (comptime os == .linux) {
                    const result = std.os.linux.pwrite(plan.writer.handle, plan.epoch[0..].ptr + written, length - written, @intCast(written));
                    switch (std.os.linux.errno(result)) {
                        .SUCCESS => if (result == 0) coldRawExit(31) else {
                            written += result;
                        },
                        .INTR => continue,
                        else => coldRawExit(32),
                    }
                } else {
                    const result = std.posix.system.pwrite(plan.writer.handle, plan.epoch[0..].ptr + written, length - written, @intCast(written));
                    if (result > 0) written += @intCast(result) else if (result < 0 and std.posix.errno(result) == .INTR) continue else coldRawExit(32);
                }
            }
            if (!coldRawSync(plan.writer.handle)) coldRawExit(33);
            coldKillSelf();
        }
        if (boundary == 0) coldKillSelf();
        if (plan.snapshot_atomic) |snapshot| {
            if (!coldRawRename(snapshot.dir.handle, &snap_name, "cold-kill.wal.snap")) coldRawExit(21);
        }
        if (boundary == 1) coldKillSelf();
        if (!coldRawSync(plan.directory.handle)) coldRawExit(22);
        if (boundary == 2) coldKillSelf();
        if (!coldRawRename(wal.dir.handle, &wal_name, "cold-kill.wal")) coldRawExit(23);
        if (boundary == 3) coldKillSelf();
        if (!coldRawSync(plan.directory.handle)) coldRawExit(24);
        if (boundary == 4) coldKillSelf();
        const length = switch (boundary) {
            5 => 4,
            6 => packet.len / 2,
            else => packet.len,
        };
        var written: usize = 0;
        while (written < length) {
            if (comptime os == .linux) {
                const result = std.os.linux.pwrite(plan.writer.handle, packet.ptr + written, length - written, @intCast(25 + written));
                switch (std.os.linux.errno(result)) {
                    .SUCCESS => if (result == 0) coldRawExit(25) else {
                        written += result;
                    },
                    .INTR => continue,
                    else => coldRawExit(26),
                }
            } else {
                const result = std.posix.system.pwrite(plan.writer.handle, packet.ptr + written, length - written, @intCast(25 + written));
                if (result > 0) written += @intCast(result) else if (result < 0 and std.posix.errno(result) == .INTR) continue else coldRawExit(26);
            }
        }
        if (!coldRawSync(plan.writer.handle)) coldRawExit(27);
        coldKillSelf();
    }
    var status: i32 = 0;
    if (comptime os == .linux) {
        while (true) {
            const result = std.os.linux.wait4(pid, &status, 0, null);
            switch (std.os.linux.errno(result)) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.TestUnexpectedResult,
            }
        }
    } else {
        while (true) {
            const result = std.posix.system.waitpid(pid, &status, 0);
            if (result == pid) break;
            if (result < 0 and std.posix.errno(result) == .INTR) continue;
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expectEqual(@as(i32, 9), status);
}

test "mesh presence retained v2 actual POSIX SIGKILL cold snapshot epoch and successor boundaries" {
    // POSIX-only (SIGKILL, raw fd custody); Windows handles cannot compile it.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    if (comptime !hotSupported()) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(236));
    defer key.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(237));
    defer remote.deinit();
    const context = contextFor(&key);
    for ([_]bool{ false, true }) |empty_covered| {
        for (0..34) |boundary| {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            var expected: retained.Head = undefined;
            var before_seq: u64 = undefined;
            var old_identity: lease_custody.Identity = undefined;
            var replacement_identity: lease_custody.Identity = undefined;
            var old_file: std.Io.File = undefined;
            var old_file_owned = false;
            defer if (old_file_owned) old_file.close(std.testing.io);
            var old_bytes: []u8 = undefined;
            var old_bytes_owned = false;
            defer if (old_bytes_owned) std.testing.allocator.free(old_bytes);
            {
                var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "cold-kill.wal", context, @splat(35), &key, 1000, .{});
                defer owner.deinit();
                try publish(&owner, try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 }), &remote, &key, 1000);
                var terminal = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 2 });
                terminal.operation = .quit;
                terminal.revision = 2;
                try publish(&owner, terminal, &remote, &key, 1000);
                if (empty_covered) {
                    try owner.durable.snapshotAndTruncate();
                    try owner.durable.snapshotAndTruncate();
                    try owner.durable.wal_file.?.setLength(std.testing.io, 0);
                    try owner.durable.wal_file.?.sync(std.testing.io);
                }
            }
            {
                const lease = try acquireExistingColdLease(std.testing.allocator, std.testing.io, tmp.dir, "cold-kill.wal");
                defer lease.close(std.testing.io);
                // max half-threshold forces OLD snapshot + complete epoch temp
                // on a normal WAL; empty-covered exercises first valid slot.
                var stage = try persistence.ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-kill.wal", lease, .{ .max_wal_bytes = 8000, .changefeed_capacity = 0 });
                defer stage.deinit();
                var restored = try image.stageRestore(std.testing.allocator, stage.view(), context, .{});
                defer restored.deinit();
                before_seq = stage.view().next_seq;
                expected = restored.head;
                old_file = try tmp.dir.openFile(std.testing.io, "cold-kill.wal", .{});
                old_file_owned = true;
                old_identity = try lease_custody.statRegular(old_file.handle);
                old_bytes = try tmp.dir.readFileAlloc(std.testing.io, "cold-kill.wal", std.testing.allocator, .unlimited);
                old_bytes_owned = true;
                var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
                var metadata = try issuer.validateRows(stage.view().get(.props, issuer.metadata_key).?, stage.view().get(.props, issuer.frontier_key).?, key.public_key);
                metadata.epoch += 1;
                metadata.issued_through = 0;
                metadata.frontier_revision = 1;
                metadata.frontier_through = 0;
                const proof = try frontier.encode(.{ .origin = key.public_key, .epoch = metadata.epoch, .revision = 1, .through = 0, .issued_ms = 1000, .active = &.{} }, &key, &buffer);
                metadata.frontier_digest = retained.digest(proof);
                const raw_metadata = metadata.encode();
                var ram = try restored.store.prepareFrontier(proof, &.{key.public_key}, 1000);
                defer ram.abort();
                var assembled = try package.prepareImage(std.testing.allocator, stage.view(), context, &restored.store, .{ .frontier = &ram }, .{ .metadata = &raw_metadata, .frontier = proof }, restored.head.expiry_floor_ms, &key);
                defer assembled.deinit();
                const contributions = assembled.mutations();
                var ticket = try stage.prepareBatch(&.{
                    .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw_metadata },
                    .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = proof },
                    contributions[0],
                    contributions[1],
                });
                defer ticket.abort();
                // Assert a real rotating plan; a non-rotating vacuous test fails.
                try std.testing.expect(stage.backing.?.plan.?.rotate);
                try std.testing.expectEqual(!empty_covered, stage.backing.?.plan.?.snapshot_atomic != null);
                replacement_identity = stage.backing.?.plan.?.writer_identity;
                if (boundary == 7) expected = assembled.head.head;
                try killColdPreparedBoundary(&stage, boundary);
                try std.testing.expect(!stage.backing.?.committed);
            }
            // No successor append ever touched the old inode, even though a
            // held read descriptor keeps that inode observable after rename.
            const still_old = try std.testing.allocator.alloc(u8, old_bytes.len);
            defer std.testing.allocator.free(still_old);
            try std.testing.expectEqual(old_bytes.len, try old_file.readPositionalAll(std.testing.io, still_old, 0));
            try std.testing.expectEqualSlices(u8, old_bytes, still_old);
            {
                const lease = try acquireExistingColdLease(std.testing.allocator, std.testing.io, tmp.dir, "cold-kill.wal");
                defer lease.close(std.testing.io);
                var recovered = try persistence.ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-kill.wal", lease, .{ .changefeed_capacity = 0 });
                defer recovered.deinit();
                var restored = try image.stageRestore(std.testing.allocator, recovered.view(), context, .{});
                defer restored.deinit();
                try std.testing.expectEqualDeep(expected, restored.head);
                try std.testing.expectEqual(before_seq + @as(u64, if (boundary == 7) 4 else 0), recovered.view().next_seq);
                try std.testing.expectEqual(@as(usize, 2), restored.store.entries.items.len);
                try std.testing.expectEqual(@as(u64, if (boundary == 7) 2 else 1), restored.head.epoch);
                try std.testing.expectEqual(@as(u64, 0), restored.head.issued_through);
                try std.testing.expectEqualDeep(if (boundary >= 3 and boundary < 8) replacement_identity else old_identity, recovered.backing.?.wal.identity);
            }
            var cold = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "cold-kill.wal", context, &key, 1000, .{});
            defer cold.deinit();
            try std.testing.expectEqual(expected.commit_generation + 1, cold.head.commit_generation);
            try std.testing.expectEqual(expected.epoch + 1, cold.metadata.epoch);
            try expectAuthorityDiskProjection(&cold);
        }
    }
}

test "mesh presence retained v2 every cold replacement successor prefix authenticates whole old or new" {
    // Cold custody needs POSIX fds; Windows handles cannot compile it.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(242));
    defer key.deinit();
    const context = contextFor(&key);
    for ([_]bool{ false, true }) |empty| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "prefix-source.wal", context, @splat(36), &key, 1000, .{});
            defer owner.deinit();
            if (empty) {
                try owner.durable.snapshotAndTruncate();
                try owner.durable.snapshotAndTruncate();
                try owner.durable.wal_file.?.setLength(std.testing.io, 0);
                try owner.durable.wal_file.?.sync(std.testing.io);
            }
        }
        const lease = try acquireExistingColdLease(std.testing.allocator, std.testing.io, tmp.dir, "prefix-source.wal");
        defer lease.close(std.testing.io);
        var stage = try persistence.ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "prefix-source.wal", lease, .{ .max_wal_bytes = 3000, .changefeed_capacity = 0 });
        defer stage.deinit();
        var restored = try image.stageRestore(std.testing.allocator, stage.view(), context, .{});
        defer restored.deinit();
        var metadata = try issuer.validateRows(stage.view().get(.props, issuer.metadata_key).?, stage.view().get(.props, issuer.frontier_key).?, key.public_key);
        metadata.epoch += 1;
        metadata.frontier_revision = 1;
        var buffer: [frontier.prefix_len + sign.signature_len]u8 = undefined;
        const proof = try frontier.encode(.{ .origin = key.public_key, .epoch = 2, .revision = 1, .through = 0, .issued_ms = 1000, .active = &.{} }, &key, &buffer);
        metadata.frontier_digest = retained.digest(proof);
        const raw = metadata.encode();
        var ram = try restored.store.prepareFrontier(proof, &.{key.public_key}, 1000);
        defer ram.abort();
        var assembled = try package.prepareImage(std.testing.allocator, stage.view(), context, &restored.store, .{ .frontier = &ram }, .{ .metadata = &raw, .frontier = proof }, restored.head.expiry_floor_ms, &key);
        defer assembled.deinit();
        const contributions = assembled.mutations();
        var ticket = try stage.prepareBatch(&.{
            .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw },
            .{ .family = .props, .kind = .put, .key = issuer.frontier_key, .value = proof },
            contributions[0],
            contributions[1],
        });
        defer ticket.abort();
        try std.testing.expect(stage.backing.?.plan.?.rotate);
        const snapshot = if (stage.backing.?.plan.?.snapshot_bytes) |bytes| try std.testing.allocator.dupe(u8, bytes) else try tmp.dir.readFileAlloc(std.testing.io, "prefix-source.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(snapshot);
        const packet = stage.backing.?.store.active_batch.?.record.?;
        const epoch = stage.backing.?.plan.?.epoch;
        {
            const file = try tmp.dir.createFile(std.testing.io, "cold-prefix.wal.snap", .{ .truncate = true });
            defer file.close(std.testing.io);
            try file.writePositionalAll(std.testing.io, snapshot, 0);
            try file.sync(std.testing.io);
        }
        const cut_lease = try tmp.dir.createFile(std.testing.io, "cold-prefix.wal.lock", .{ .read = true });
        defer cut_lease.close(std.testing.io);
        try lease_custody.reaffirmExclusive(cut_lease.handle);
        for (0..packet.len + 1) |prefix| {
            {
                const file = try tmp.dir.createFile(std.testing.io, "cold-prefix.wal", .{ .read = true, .truncate = true });
                defer file.close(std.testing.io);
                try file.writePositionalAll(std.testing.io, &epoch, 0);
                try file.writePositionalAll(std.testing.io, packet[0..prefix], epoch.len);
                try file.sync(std.testing.io);
            }
            var recovered = try persistence.ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-prefix.wal", cut_lease, .{ .changefeed_capacity = 0 });
            defer recovered.deinit();
            var checked = try image.stageRestore(std.testing.allocator, recovered.view(), context, .{});
            defer checked.deinit();
            const full = prefix == packet.len;
            try std.testing.expectEqualDeep(if (full) assembled.head.head else restored.head, checked.head);
            try std.testing.expectEqual(stage.view().next_seq + @as(u64, if (full) 4 else 0), recovered.view().next_seq);
            try std.testing.expectEqual(@as(u64, if (full) 2 else 1), checked.head.epoch);
            try std.testing.expect(recovered.view().isReadOnly());
        }
        // Partial epoch is never a protocol publication; it still refuses here
        // and in the existing generic/hot readers, without guessed coverage.
        for (1..epoch.len) |length| {
            const file = try tmp.dir.createFile(std.testing.io, "cold-prefix.wal", .{ .read = true, .truncate = true });
            defer file.close(std.testing.io);
            try file.writePositionalAll(std.testing.io, epoch[0..length], 0);
            if (persistence.ColdRecoveryStage.open(std.testing.allocator, std.testing.io, tmp.dir, "cold-prefix.wal", cut_lease, .{ .changefeed_capacity = 0 })) |value| {
                var unexpected = value;
                unexpected.deinit();
                return error.TestUnexpectedResult;
            } else |_| {}
        }
    }
}

test "mesh presence retained v2 refuses bad lease symlink and existing partial namespace unchanged" {
    if (comptime !hotSupported()) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(243));
    defer key.deinit();
    for (0..4) |kind| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        {
            var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "bad-path.wal", contextFor(&key), @splat(37), &key, 1000, .{});
            defer owner.deinit();
            try owner.durable.snapshotAndTruncate();
        }
        const changed_path: []const u8 = switch (kind) {
            0, 1 => "bad-path.wal.lock",
            2 => "bad-path.wal",
            else => "bad-path.wal.snap",
        };
        try tmp.dir.rename(changed_path, tmp.dir, "original", std.testing.io);
        if (kind == 1) try tmp.dir.createDir(std.testing.io, changed_path, .default_dir) else try tmp.dir.symLink(std.testing.io, "original", changed_path, .{});
        const namespace = try namespaceFingerprintForTest(tmp.dir);
        const bytes = try tmp.dir.readFileAlloc(std.testing.io, "original", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(bytes);
        if (Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "bad-path.wal", contextFor(&key), &key, 1000, .{})) |result| {
            var unexpected = result;
            unexpected.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
        try std.testing.expectEqualDeep(namespace, try namespaceFingerprintForTest(tmp.dir));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "original", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, bytes, after);
    }
    for ([_][]const u8{ "partial.wal", "partial.wal.snap" }) |path| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const file = try tmp.dir.createFile(std.testing.io, path, .{});
        file.close(std.testing.io);
        const namespace = try namespaceFingerprintForTest(tmp.dir);
        try std.testing.expectError(error.AlreadyInitialized, Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "partial.wal", contextFor(&key), @splat(38), &key, 1000, .{}));
        try std.testing.expectEqualDeep(namespace, try namespaceFingerprintForTest(tmp.dir));
        try std.testing.expectError(error.FileNotFound, tmp.dir.openFile(std.testing.io, "partial.wal.lock", .{}));
    }
    // An interrupted genuinely absent provisioning attempt may leave only its
    // stable lock. Explicit initialize reopens that inode and retries; it never
    // guesses absence from any existing WAL or snapshot, even an empty file.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const lock = try tmp.dir.createFile(std.testing.io, "retry.wal.lock", .{ .read = true });
    const identity = try lease_custody.statRegular(lock.handle);
    lock.close(std.testing.io);
    var retry = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "retry.wal", contextFor(&key), @splat(39), &key, 1000, .{});
    defer retry.deinit();
    try std.testing.expectEqualDeep(identity, try lease_custody.statRegular(retry.lease.handle));
    try expectAuthorityDiskProjection(&retry);
}

test "mesh presence retained v2 legacy every tolerated append prefix and empty covered state refuse unchanged" {
    // Raw-fd lease custody; Windows HANDLEs cannot compile it.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(244));
    defer key.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var legacy_packet: []u8 = undefined;
    var before_wal: []u8 = undefined;
    var before_snapshot: []u8 = undefined;
    {
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "legacy-source.wal", contextFor(&key), @splat(40), &key, 1000, .{});
        defer owner.deinit();
        const image_bytes = try std.testing.allocator.dupe(u8, owner.durable.get(.props, retained.image_key).?);
        defer std.testing.allocator.free(image_bytes);
        image_bytes[4] = 1;
        const raw = try legacyHeadForTest(owner.head, image_bytes, &key);
        {
            var legacy = try owner.durable.prepareBatch(&.{
                .{ .family = .props, .kind = .put, .key = retained.image_key, .value = image_bytes },
                .{ .family = .props, .kind = .put, .key = retained.head_key, .value = &raw },
            });
            defer legacy.abort();
            try legacy.commit();
        }
        try owner.durable.snapshotAndTruncate();
        try owner.durable.snapshotAndTruncate();
        var pending = try owner.durable.prepareBatch(&.{.{ .family = .props, .kind = .put, .key = "unrelated", .value = "next" }});
        defer pending.abort();
        legacy_packet = try std.testing.allocator.dupe(u8, owner.durable.active_batch.?.record.?);
        errdefer std.testing.allocator.free(legacy_packet);
        before_wal = try tmp.dir.readFileAlloc(std.testing.io, "legacy-source.wal", std.testing.allocator, .unlimited);
        errdefer std.testing.allocator.free(before_wal);
        before_snapshot = try tmp.dir.readFileAlloc(std.testing.io, "legacy-source.wal.snap", std.testing.allocator, .unlimited);
    }
    defer std.testing.allocator.free(legacy_packet);
    defer std.testing.allocator.free(before_wal);
    defer std.testing.allocator.free(before_snapshot);
    {
        const file = try tmp.dir.createFile(std.testing.io, "legacy-cut.wal.snap", .{});
        defer file.close(std.testing.io);
        try file.writePositionalAll(std.testing.io, before_snapshot, 0);
    }
    const lock = try tmp.dir.createFile(std.testing.io, "legacy-cut.wal.lock", .{ .read = true });
    const lock_identity = try lease_custody.statRegular(lock.handle);
    lock.close(std.testing.io);
    for (0..legacy_packet.len + 2) |test_cut| {
        {
            const file = try tmp.dir.createFile(std.testing.io, "legacy-cut.wal", .{ .read = true, .truncate = true });
            defer file.close(std.testing.io);
            // Extra final iteration exercises legitimate empty-covered snapshot.
            if (test_cut <= legacy_packet.len) {
                try file.writePositionalAll(std.testing.io, before_wal, 0);
                try file.writePositionalAll(std.testing.io, legacy_packet[0..test_cut], before_wal.len);
            }
            try file.sync(std.testing.io);
        }
        const namespace = try namespaceFingerprintForTest(tmp.dir);
        const exact = try tmp.dir.readFileAlloc(std.testing.io, "legacy-cut.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(exact);
        const file = try tmp.dir.openFile(std.testing.io, "legacy-cut.wal", .{});
        const identity = try lease_custody.statRegular(file.handle);
        file.close(std.testing.io);
        try std.testing.expectError(error.MigrationRequired, Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "legacy-cut.wal", contextFor(&key), &key, 1000, .{}));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "legacy-cut.wal", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after);
        try std.testing.expectEqualSlices(u8, exact, after);
        const after_snap = try tmp.dir.readFileAlloc(std.testing.io, "legacy-cut.wal.snap", std.testing.allocator, .unlimited);
        defer std.testing.allocator.free(after_snap);
        try std.testing.expectEqualSlices(u8, before_snapshot, after_snap);
        try std.testing.expectEqualDeep(namespace, try namespaceFingerprintForTest(tmp.dir));
        const current = try tmp.dir.openFile(std.testing.io, "legacy-cut.wal", .{});
        defer current.close(std.testing.io);
        try std.testing.expectEqualDeep(identity, try lease_custody.statRegular(current.handle));
        const current_lock = try tmp.dir.openFile(std.testing.io, "legacy-cut.wal.lock", .{});
        defer current_lock.close(std.testing.io);
        try std.testing.expectEqualDeep(lock_identity, try lease_custody.statRegular(current_lock.handle));
    }
}

fn hotCaptureMismatchScenario(kind: enum { cached_class, admission, signed_original }) !void {
    // Raw-fd lease custody; Windows HANDLEs cannot compile it.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(245));
    defer key.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "capture-drift.wal", contextFor(&key), @splat(41), &key, 1000, .{});
    defer owner.deinit();
    var value = try recordFor(key.public_key, try owner.reserveSubject(&key));
    value.routing_class = .authenticated_untracked;
    try publishLifecycle(&owner, value, 1, &.{1}, 1000, &key);
    const before = try tmp.dir.readFileAlloc(std.testing.io, "capture-drift.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const entry = &owner.retained_store.entries.items[0];
    const saved = entry.*;
    const original = try std.testing.allocator.dupe(u8, entry.original);
    defer std.testing.allocator.free(original);
    defer {
        @memcpy(entry.original, original);
        entry.* = saved;
    }
    switch (kind) {
        .cached_class => entry.decoded.record.routing_class = .true_guest,
        .admission => entry.admission.admitted_at_ms += 1,
        .signed_original => {
            value.routing_class = .true_guest;
            var buffer: [wire.max_wire_len]u8 = undefined;
            @memcpy(entry.original, try wire.encode(value, &key, &buffer));
            entry.decoded = try wire.decode(entry.original);
        },
    }
    if (owner.captureHotCheckpoint()) |_| return error.TestUnexpectedResult else |err| try std.testing.expect(err != error.OutOfMemory);
    const after = try tmp.dir.readFileAlloc(std.testing.io, "capture-drift.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    try lease_custody.reaffirmExclusive(owner.lease.handle);
}
test "retained v2 causal hot capture refuses stale cached class" {
    try hotCaptureMismatchScenario(.cached_class);
}
test "retained v2 causal hot capture refuses changed admission provenance" {
    try hotCaptureMismatchScenario(.admission);
}
test "retained v2 causal hot capture refuses another self consistent signed original" {
    try hotCaptureMismatchScenario(.signed_original);
}

fn captureAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    // Raw-fd lease custody; Windows HANDLEs cannot compile it.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "capture-oom.wal", contextFor(key), @splat(54), key, 1000, .{});
    defer owner.deinit();
    const id = try owner.reserveSubject(key);
    var record = try recordFor(key.public_key, id);
    record.routing_class = .authenticated_untracked;
    record.class_revision = 1;
    var record_buffer: [1024]u8 = undefined;
    const original = try wire.encode(record, key, &record_buffer);
    var prepared = try owner.prepareLocalLifecycle(original, 1, &.{1}, 1000, key);
    defer prepared.abort();
    try prepared.commit();
    const checkpoint = try owner.captureHotCheckpoint();
    const before = try tmp.dir.readFileAlloc(std.testing.io, "capture-oom.wal", std.testing.allocator, .unlimited);
    defer std.testing.allocator.free(before);
    const entry = owner.retained_store.entries.items[0];
    owner.allocator = allocator;
    defer owner.allocator = std.testing.allocator;
    const result = owner.captureHotCheckpoint() catch |err| {
        owner.allocator = std.testing.allocator;
        if (err == error.OutOfMemory) {
            try std.testing.expectEqualDeep(entry, owner.retained_store.entries.items[0]);
            try std.testing.expectEqualDeep(checkpoint, try owner.captureHotCheckpoint());
            const after = try tmp.dir.readFileAlloc(std.testing.io, "capture-oom.wal", std.testing.allocator, .unlimited);
            defer std.testing.allocator.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
            const reopened = try persistence.openColdExisting(std.testing.io, tmp.dir, "capture-oom.wal.lock", .read_write);
            defer reopened.close(std.testing.io);
            try std.testing.expectError(error.WouldBlock, lease_custody.reaffirmExclusive(reopened.handle));
        }
        return err;
    };
    owner.allocator = std.testing.allocator;
    try std.testing.expectEqualDeep(checkpoint, result);
}
test "mesh presence retained v2 canonical hot capture exhaustive OOM rollback and retry" {
    // Scenario is a skip-stub on Windows; checkAllAllocationFailures needs a real OOM-capable fn.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(204));
    defer key.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, captureAllocationScenario, .{&key});
}

const LiveKillMode = enum { epoch, private_synced, snapshot_before_sync, snapshot_after_sync, wal_before_sync, wal_after_sync, successor };
const LiveEpochWriteWitness = struct {
    prefix: usize,
    mode: LiveKillMode = .epoch,
    expected_packet_len: usize = 0,
    epoch_fd: ?std.posix.fd_t = null,
    directory_syncs: usize = 0,
    original_sync: ?*const fn (?*anyopaque, std.Io.File) std.Io.File.SyncError!void = null,
    io: ?std.Io = null,
    original: *const fn (?*anyopaque, std.Io.File, []const u8, []const []const u8, usize, u64) std.Io.File.WritePositionalError!usize,
};
threadlocal var live_epoch_write_witness: ?*LiveEpochWriteWitness = null;
fn killLiveEpochWrite(userdata: ?*anyopaque, file: std.Io.File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) std.Io.File.WritePositionalError!usize {
    const witness = live_epoch_write_witness.?;
    const epoch = offset == 0 and header.len == 0 and data.len == 1 and data[0].len == 25 and data[0][8] == 0xFC;
    if (epoch) {
        witness.epoch_fd = file.handle;
        if (witness.mode == .epoch) killLiveBytes(file, data[0], witness.prefix, offset);
    }
    if (witness.mode == .successor and offset == 25 and header.len == 0 and data.len == 1) {
        if (data[0].len != witness.expected_packet_len) coldRawExit(46);
        killLiveBytes(file, data[0], witness.prefix, offset);
    }
    return witness.original(userdata, file, header, data, splat, offset);
}
fn killLiveBytes(file: std.Io.File, bytes: []const u8, prefix: usize, offset: u64) noreturn {
    var written: usize = 0;
    while (written < prefix) {
        if (comptime @import("builtin").os.tag == .linux) {
            const result = std.os.linux.pwrite(file.handle, bytes[written..prefix].ptr, prefix - written, @intCast(offset + written));
            switch (std.os.linux.errno(result)) {
                .SUCCESS => if (result == 0) coldRawExit(40) else {
                    written += result;
                },
                .INTR => continue,
                else => coldRawExit(41),
            }
        } else {
            const result = std.posix.system.pwrite(file.handle, bytes[written..prefix].ptr, prefix - written, @intCast(offset + written));
            if (result > 0) written += @intCast(result) else if (result < 0 and std.posix.errno(result) == .INTR) continue else coldRawExit(41);
        }
    }
    if (!coldRawSync(file.handle)) coldRawExit(42);
    coldKillSelf();
}
fn killLiveSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
    const witness = live_epoch_write_witness.?;
    const directory = (file.stat(witness.io.?) catch coldRawExit(47)).kind == .directory;
    if (directory) {
        witness.directory_syncs += 1;
        if ((witness.directory_syncs == 1 and witness.mode == .snapshot_before_sync) or (witness.directory_syncs == 2 and witness.mode == .wal_before_sync)) coldKillSelf();
    }
    try witness.original_sync.?(userdata, file);
    if ((witness.epoch_fd == file.handle and witness.mode == .private_synced) or
        (directory and witness.directory_syncs == 1 and witness.mode == .snapshot_after_sync) or
        (directory and witness.directory_syncs == 2 and witness.mode == .wal_after_sync)) coldKillSelf();
}
fn waitLiveCompactionKill(pid: std.posix.pid_t) !void {
    const os = @import("builtin").os.tag;
    var reaped = false;
    defer if (!reaped) {
        if (comptime os == .linux) _ = std.os.linux.kill(pid, .KILL) else _ = std.posix.system.kill(pid, std.posix.SIG.KILL);
        var discarded: i32 = 0;
        while (true) {
            const result = if (comptime os == .linux) @as(isize, @bitCast(std.os.linux.wait4(pid, &discarded, 0, null))) else std.posix.system.waitpid(pid, &discarded, 0);
            if (result == pid) break;
            if (result < 0 and (if (comptime os == .linux) std.os.linux.errno(@bitCast(result)) else std.posix.errno(result)) == .INTR) continue;
            break;
        }
    };
    var status: i32 = 0;
    for (0..200) |_| {
        const result = if (comptime os == .linux) @as(isize, @bitCast(std.os.linux.wait4(pid, &status, std.posix.W.NOHANG, null))) else std.posix.system.waitpid(pid, &status, std.posix.W.NOHANG);
        if (result == pid) {
            reaped = true;
            try std.testing.expectEqual(@as(i32, 9), status);
            return;
        }
        if (result < 0) {
            if ((if (comptime os == .linux) std.os.linux.errno(@bitCast(result)) else std.posix.errno(result)) == .INTR) continue;
            return error.TestUnexpectedResult;
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    }
    return error.TestUnexpectedResult;
}
test "retained v2 causal actual live Authority threshold compaction every epoch write prefix survives SIGKILL" {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var key = try sign.KeyPair.fromSeed(@splat(205));
    defer key.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(206));
    defer remote.deinit();
    var refusals: usize = 0;
    for (0..26) |prefix| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "live-prefix.wal", contextFor(&key), @splat(68), &key, 1000, .{});
        var owner_live = true;
        defer if (owner_live) owner.deinit();
        var value = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 });
        value.routing_class = .authenticated_untracked;
        try publish(&owner, value, &remote, &key, 1000);
        const old_head = owner.head;
        const old_seq = owner.durable.next_seq;
        // Force the next REAL reservation's ordinary preflight to compact.
        owner.durable.cfg.max_wal_bytes = @intCast(owner.durable.wal_offset * 2 + 1);
        const pid: std.posix.pid_t = if (comptime os == .linux) block: {
            const result = std.os.linux.fork();
            if (std.os.linux.errno(result) != .SUCCESS) return error.TestUnexpectedResult;
            break :block @intCast(result);
        } else std.posix.system.fork();
        if (pid < 0) return error.TestUnexpectedResult;
        if (pid == 0) {
            var backend: std.Io.Threaded = .init_single_threaded;
            backend.allocator = std.heap.page_allocator;
            const child_io = backend.io();
            var vtable = child_io.vtable.*;
            var witness: LiveEpochWriteWitness = .{ .prefix = prefix, .original = vtable.fileWritePositional };
            live_epoch_write_witness = &witness;
            vtable.fileWritePositional = killLiveEpochWrite;
            const child: std.Io = .{ .userdata = child_io.userdata, .vtable = &vtable };
            owner.io = child;
            owner.durable.io = child;
            owner.allocator = std.heap.page_allocator;
            owner.durable.allocator = std.heap.page_allocator;
            // Sealed signing pages intentionally wipe on Linux fork; create
            // the deterministic fixture key freshly in the child.
            var child_key = sign.KeyPair.fromSeed(@splat(205)) catch coldRawExit(45);
            _ = owner.reserveSubject(&child_key) catch |err| {
                const name = @errorName(err);
                _ = std.posix.system.write(2, name.ptr, name.len);
                coldRawExit(43);
            };
            coldRawExit(44); // Must actually enter the epoch-writing seam.
        }
        try waitLiveCompactionKill(pid);
        owner.deinit();
        owner_live = false;
        if (Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "live-prefix.wal", contextFor(&key), &key, 1000, .{})) |result| {
            var restored = result;
            defer restored.deinit();
            try std.testing.expectEqualSlices(u8, &old_head.store_id, &restored.head.store_id);
            try std.testing.expectEqual(old_head.commit_generation + 1, restored.head.commit_generation);
            try std.testing.expectEqual(old_seq + 4, restored.durable.next_seq);
            try std.testing.expectEqual(@as(u64, 2), restored.metadata.epoch);
            try std.testing.expectEqual(@as(u64, 0), restored.metadata.issued_through);
            try std.testing.expectEqual(wire.RoutingClass.authenticated_untracked, restored.retained_store.entries.items[0].decoded.record.routing_class);
            try expectAuthorityDiskProjection(&restored);
        } else |err| {
            try std.testing.expectEqual(error.SnapshotCoverageMismatch, err);
            refusals += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), refusals);
}

fn liveCompactionBoundaryScenario(mode: LiveKillMode, prefix: usize) !usize {
    const os = @import("builtin").os.tag;
    if (comptime os != .linux and os != .openbsd and os != .freebsd) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(205));
    defer key.deinit();
    var remote = try sign.KeyPair.fromSeed(@splat(206));
    defer remote.deinit();
    var owner = try Authority.initialize(std.testing.allocator, std.testing.io, tmp.dir, "live-boundary.wal", contextFor(&key), @splat(69), &key, 1000, .{});
    var owner_live = true;
    defer if (owner_live) owner.deinit();
    var value = try recordFor(remote.public_key, .{ .epoch = 1, .counter = 1 });
    value.routing_class = .exact_reusable_attachment;
    try publish(&owner, value, &remote, &key, 1000);
    const old_head = owner.head;
    const old_seq = owner.durable.next_seq;
    // Measure the exact same owned reservation packet without publication or
    // threshold compaction, then abort. No duplicated framing-size arithmetic.
    var metadata = owner.metadata;
    metadata.issued_through += 1;
    const raw = metadata.encode();
    const head = try package.prepareHeadUpdate(&owner.durable, owner.context, .{ .metadata = &raw, .frontier = owner.durable.get(.props, issuer.frontier_key).? }, owner.head.expiry_floor_ms, &key);
    var measuring = try owner.durable.prepareBatch(&.{ .{ .family = .props, .kind = .put, .key = issuer.metadata_key, .value = &raw }, head.mutation() });
    const packet_len = owner.durable.active_batch.?.record.?.len;
    measuring.abort();
    if (mode == .successor) try std.testing.expect(prefix <= packet_len);
    owner.durable.cfg.max_wal_bytes = @intCast(owner.durable.wal_offset * 2 + 1);
    const pid: std.posix.pid_t = if (comptime os == .linux) block: {
        const result = std.os.linux.fork();
        if (std.os.linux.errno(result) != .SUCCESS) return error.TestUnexpectedResult;
        break :block @intCast(result);
    } else std.posix.system.fork();
    if (pid < 0) return error.TestUnexpectedResult;
    if (pid == 0) {
        var backend: std.Io.Threaded = .init_single_threaded;
        backend.allocator = std.heap.page_allocator;
        const child_io = backend.io();
        var vtable = child_io.vtable.*;
        var witness: LiveEpochWriteWitness = .{ .prefix = prefix, .mode = mode, .expected_packet_len = packet_len, .original = vtable.fileWritePositional, .original_sync = vtable.fileSync, .io = child_io };
        live_epoch_write_witness = &witness;
        vtable.fileWritePositional = killLiveEpochWrite;
        vtable.fileSync = killLiveSync;
        const child: std.Io = .{ .userdata = child_io.userdata, .vtable = &vtable };
        owner.io = child;
        owner.durable.io = child;
        owner.allocator = std.heap.page_allocator;
        owner.durable.allocator = std.heap.page_allocator;
        var child_key = sign.KeyPair.fromSeed(@splat(205)) catch coldRawExit(45);
        _ = owner.reserveSubject(&child_key) catch coldRawExit(43);
        coldRawExit(44);
    }
    try waitLiveCompactionKill(pid);
    owner.deinit();
    owner_live = false;
    var restored = try Authority.openCold(std.testing.allocator, std.testing.io, tmp.dir, "live-boundary.wal", contextFor(&key), &key, 1000, .{});
    defer restored.deinit();
    const complete = mode == .successor and prefix == packet_len;
    try std.testing.expectEqualSlices(u8, &old_head.store_id, &restored.head.store_id);
    try std.testing.expectEqual(old_head.commit_generation + 1 + @as(u64, @intFromBool(complete)), restored.head.commit_generation);
    try std.testing.expectEqual(old_seq + 4 + if (complete) @as(u64, 2) else 0, restored.durable.next_seq);
    try std.testing.expectEqual(@as(u64, 2), restored.metadata.epoch);
    try std.testing.expectEqual(@as(u64, 0), restored.metadata.issued_through);
    try std.testing.expectEqual(wire.RoutingClass.exact_reusable_attachment, restored.retained_store.entries.items[0].decoded.record.routing_class);
    try expectAuthorityDiskProjection(&restored);
    return packet_len;
}
test "mesh presence retained v2 actual live compaction SIGKILL private snapshot epoch publication boundaries" {
    for ([_]LiveKillMode{ .private_synced, .snapshot_before_sync, .snapshot_after_sync, .wal_before_sync, .wal_after_sync }) |mode| _ = try liveCompactionBoundaryScenario(mode, 0);
}
test "mesh presence retained v2 actual live compaction every successor batch prefix SIGKILL restores whole cut" {
    const packet_len = try liveCompactionBoundaryScenario(.successor, 0);
    for (1..packet_len + 1) |prefix| _ = try liveCompactionBoundaryScenario(.successor, prefix);
    std.debug.print("live compaction actual successor SIGKILL prefixes: {d} (0..{d})\n", .{ packet_len + 1, packet_len });
}
