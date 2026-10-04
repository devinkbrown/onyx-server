// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prepared original-presence retention. No path, account or channel authority.
//! All calls require one external owner lock, including prepare through commit.
//! Covered subjects are removed only after publishing a retained complete origin
//! frontier. Conflict witnesses and origin quarantine are never evicted.
const std = @import("std");
const wire = @import("../proto/mesh_presence_v2.zig");
const frontier = @import("../proto/mesh_presence_frontier.zig");
const sign = @import("../crypto/sign.zig");
const signed_frame = @import("../substrate/undertow/signed_frame.zig");

pub const Config = struct {
    max_entries: usize = 4096,
    max_origins: usize = 256,
    /// Published retained-byte quota. Prepared ownership temporarily needs
    /// additional memory; allocation failure leaves the published cut intact.
    max_bytes: usize = 8 * 1024 * 1024,
    clock: wire.ClockPolicy = .{ .max_lifetime_ms = 120_000, .max_future_skew_ms = 30_000 },
};
pub const Error = wire.Error || frontier.Error || std.mem.Allocator.Error || error{ UnapprovedOrigin, OriginCollision, Capacity, TerminalSubject, InvalidClaim, RetiredSubject, QuarantinedOrigin, InvalidAdmission, InvalidPlan, InvalidLocalLifecycle, GenerationExhausted, AccountingMismatch };
pub const Disposition = enum { inserted, updated, duplicate, obsolete, quarantined };

/// Local admission evidence, not remote authority. A persistence reader must
/// authenticate the entire local image before trusting these historical facts.
/// Policy 1 identifies the full-key roots/collision rule used by this store;
/// it is not a claim that the origin is still approved by current policy.
pub const AdmissionStamp = struct {
    pub const encoded_len: usize = 3 + sign.public_key_len + 8 * 3;
    version: u8,
    mode: enum(u8) { live_presence = 1, expired_quit_repair = 2, origin_frontier = 3 },
    approval_policy: u8,
    approved_origin: sign.PublicKey,
    admitted_at_ms: i64,
    max_lifetime_ms: i64,
    max_future_skew_ms: i64,

    fn mint(origin: sign.PublicKey, now_ms: i64, clock: wire.ClockPolicy, mode: @FieldType(AdmissionStamp, "mode")) AdmissionStamp {
        return .{ .version = 1, .mode = mode, .approval_policy = 1, .approved_origin = origin, .admitted_at_ms = now_ms, .max_lifetime_ms = clock.max_lifetime_ms, .max_future_skew_ms = clock.max_future_skew_ms };
    }

    fn validate(self: AdmissionStamp, origin: sign.PublicKey) Error!void {
        if (self.version != 1 or self.approval_policy != 1 or !std.mem.eql(u8, &self.approved_origin, &origin) or self.admitted_at_ms < 0 or self.max_lifetime_ms <= 0 or self.max_future_skew_ms < 0) return error.InvalidAdmission;
    }

    /// Canonical local-image field. No signature or trust is supplied by this
    /// encoding; the eventual local image head must authenticate these bytes.
    pub fn encode(self: AdmissionStamp) Error![encoded_len]u8 {
        try self.validate(self.approved_origin);
        var out: [encoded_len]u8 = undefined;
        out[0] = self.version;
        out[1] = @intFromEnum(self.mode);
        out[2] = self.approval_policy;
        out[3..35].* = self.approved_origin;
        std.mem.writeInt(i64, out[35..43], self.admitted_at_ms, .big);
        std.mem.writeInt(i64, out[43..51], self.max_lifetime_ms, .big);
        std.mem.writeInt(i64, out[51..59], self.max_future_skew_ms, .big);
        return out;
    }

    /// Strict framing and policy versions. The caller still has to authenticate
    /// the image and bind/check this stamp against its original signed record.
    pub fn decode(bytes: []const u8) Error!AdmissionStamp {
        if (bytes.len != encoded_len) return error.InvalidAdmission;
        const result: AdmissionStamp = .{
            .version = bytes[0],
            .mode = switch (bytes[1]) {
                1 => .live_presence,
                2 => .expired_quit_repair,
                3 => .origin_frontier,
                else => return error.InvalidAdmission,
            },
            .approval_policy = bytes[2],
            .approved_origin = bytes[3..35].*,
            .admitted_at_ms = std.mem.readInt(i64, bytes[35..43], .big),
            .max_lifetime_ms = std.mem.readInt(i64, bytes[43..51], .big),
            .max_future_skew_ms = std.mem.readInt(i64, bytes[51..59], .big),
        };
        try result.validate(result.approved_origin);
        return result;
    }

    /// Checks the original signature and historical clock decision. This alone
    /// does not authenticate the stamp, restore a store, or authorize a winner.
    pub fn validatePresence(self: AdmissionStamp, decoded: wire.Decoded) Error!void {
        try self.validate(decoded.record.origin);
        try decoded.verify();
        if (self.mode == .origin_frontier) return error.InvalidAdmission;
        if (self.mode == .expired_quit_repair and decoded.record.operation != .quit) return error.InvalidAdmission;
        const clock: wire.ClockPolicy = .{ .max_lifetime_ms = self.max_lifetime_ms, .max_future_skew_ms = self.max_future_skew_ms };
        var expired = false;
        clock.validate(decoded.record, self.admitted_at_ms) catch |err| {
            if (self.mode != .expired_quit_repair or err != error.Expired) return err;
            expired = true;
        };
        if (self.mode == .expired_quit_repair and !expired) return error.InvalidAdmission;
        try validateClaim(decoded.record, self.admitted_at_ms, self.max_future_skew_ms);
    }

    pub fn validateFrontier(self: AdmissionStamp, decoded: frontier.Decoded) Error!void {
        try self.validate(decoded.origin);
        if (self.mode != .origin_frontier) return error.InvalidAdmission;
        try decoded.verify();
        try decoded.validateClock(self.admitted_at_ms, self.max_future_skew_ms);
    }
};

fn validateClaim(record: wire.Record, now_ms: i64, future_skew_ms: i64) Error!void {
    const claim_ms: i64 = @intCast(record.claim_hlc >> 16);
    if (claim_ms > now_ms and claim_ms - now_ms > future_skew_ms) return error.InvalidClaim;
}

pub const Entry = struct {
    original: []u8,
    decoded: wire.Decoded,
    admission: AdmissionStamp,
    /// Original signed equivocation/terminal contradiction. Never cleared.
    conflict: ?[]u8 = null,
    conflict_admission: ?AdmissionStamp = null,

    pub fn terminal(self: Entry) bool {
        return self.decoded.record.operation == .quit or self.conflict != null;
    }
};

pub const OriginFrontier = struct {
    original: []u8,
    decoded: frontier.Decoded,
    admission: AdmissionStamp,
    /// First signed contradiction; quarantine survives every later epoch.
    conflict: ?[]u8 = null,
    conflict_admission: ?AdmissionStamp = null,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    config: Config,
    entries: std.ArrayList(Entry),
    frontiers: std.ArrayList(OriginFrontier),
    bytes: usize = 0,
    generation: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Store {
        if (config.max_entries == 0 or config.max_origins == 0 or config.max_bytes == 0 or config.clock.max_lifetime_ms <= 0 or config.clock.max_future_skew_ms < 0) return error.InvalidClock;
        var entries: std.ArrayList(Entry) = try .initCapacity(allocator, config.max_entries);
        errdefer entries.deinit(allocator);
        return .{ .allocator = allocator, .config = config, .entries = entries, .frontiers = try .initCapacity(allocator, config.max_origins) };
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |entry| self.freeEntry(entry);
        self.entries.deinit(self.allocator);
        for (self.frontiers.items) |item| self.freeFrontier(item);
        self.frontiers.deinit(self.allocator);
        self.* = undefined;
    }

    fn freeEntry(self: *Store, entry: Entry) void {
        self.allocator.free(entry.original);
        if (entry.conflict) |conflict| self.allocator.free(conflict);
    }

    fn freeFrontier(self: *Store, item: OriginFrontier) void {
        self.allocator.free(item.original);
        if (item.conflict) |conflict| self.allocator.free(conflict);
    }

    fn originIndex(self: *const Store, origin: sign.PublicKey) ?usize {
        for (self.frontiers.items, 0..) |item, index| {
            if (std.mem.eql(u8, &item.decoded.origin, &origin)) return index;
        }
        return null;
    }

    fn checkSubject(self: *const Store, record: wire.Record) Error!void {
        if (self.originIndex(record.origin)) |index| {
            const item = self.frontiers.items[index];
            if (item.conflict != null) return error.QuarantinedOrigin;
            const id = try wire.subject(record.guest);
            if (item.decoded.retires(record.origin, id.epoch, id.counter)) return error.RetiredSubject;
        }
    }

    fn covered(entry: Entry, proof: frontier.Decoded) bool {
        // A retirement cut cannot erase retained subject equivocation witnesses.
        if (entry.conflict != null) return false;
        const id = wire.subject(entry.decoded.record.guest) catch unreachable;
        return proof.retires(entry.decoded.record.origin, id.epoch, id.counter);
    }

    /// Same sole-handle and external-lock contract as Prepared. All allocations
    /// precede publication. No reader may observe between proof and compaction.
    pub const PreparedFrontier = struct {
        store: *Store,
        generation: u64,
        index: usize,
        disposition: frontier.Update,
        candidate: ?OriginFrontier = null,
        candidate_bytes: usize = 0,
        done: bool = false,

        pub fn abort(self: *PreparedFrontier) void {
            if (self.done) return;
            if (self.candidate) |item| self.store.freeFrontier(item);
            self.candidate = null;
            self.done = true;
        }

        pub fn commit(self: *PreparedFrontier) frontier.Update {
            std.debug.assert(!self.done and self.store.generation == self.generation);
            if (self.candidate) |item| {
                // Install the replacement negative proof BEFORE freeing records.
                if (self.index == self.store.frontiers.items.len) {
                    self.store.frontiers.appendAssumeCapacity(item);
                } else {
                    self.store.freeFrontier(self.store.frontiers.items[self.index]);
                    self.store.frontiers.items[self.index] = item;
                }
                if (item.conflict == null) {
                    var index: usize = 0;
                    while (index < self.store.entries.items.len) {
                        if (covered(self.store.entries.items[index], item.decoded)) {
                            self.store.freeEntry(self.store.entries.swapRemove(index));
                        } else index += 1;
                    }
                }
                self.store.bytes = self.candidate_bytes;
                self.store.generation +%= 1;
                self.candidate = null;
            }
            self.done = true;
            return self.disposition;
        }
    };

    /// Admit a complete signed origin cut, retaining exact bytes. No expiry or
    /// clock recheck can later revoke this permanent negative proof. No origin
    /// is evicted on pressure; an incomplete inventory never reaches this API.
    pub fn prepareFrontier(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64) Error!PreparedFrontier {
        return self.buildFrontier(original, roots, now_ms, true);
    }

    /// Internal candidate construction. Only the compound local plan defers
    /// quotas until both replacements and certified GC have been normalized.
    fn buildFrontier(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64, enforce_capacity: bool) Error!PreparedFrontier {
        const decoded = try frontier.decode(original);
        try decoded.verify();
        try approved(decoded.origin, roots);
        try decoded.validateClock(now_ms, self.config.clock.max_future_skew_ms);
        const index = self.originIndex(decoded.origin) orelse self.frontiers.items.len;
        var plan: PreparedFrontier = .{ .store = self, .generation = self.generation, .index = index, .disposition = .advance };
        var old_bytes: usize = 0;
        if (index < self.frontiers.items.len) {
            const old = self.frontiers.items[index];
            plan.disposition = try frontier.compare(old.decoded, decoded);
            if (old.conflict != null) {
                plan.disposition = .conflict;
                return plan;
            }
            if (plan.disposition == .duplicate or plan.disposition == .obsolete) return plan;
            old_bytes = old.original.len;
        } else if (enforce_capacity and index == self.config.max_origins) return error.Capacity;
        const conflict = plan.disposition == .conflict;
        var removed_bytes: usize = 0;
        if (!conflict) for (self.entries.items) |entry| {
            if (covered(entry, decoded)) removed_bytes += entry.original.len;
        };
        const retained_bytes = self.bytes - old_bytes - removed_bytes;
        const needed = std.math.add(usize, original.len, if (conflict) old_bytes else @as(usize, 0)) catch return error.Capacity;
        if (enforce_capacity and (needed > self.config.max_bytes or retained_bytes > self.config.max_bytes - needed)) return error.Capacity;
        const candidate_bytes = std.math.add(usize, retained_bytes, needed) catch return error.Capacity;
        const owned = try self.allocator.dupe(u8, original);
        errdefer self.allocator.free(owned);
        var candidate: OriginFrontier = .{ .original = owned, .decoded = frontier.decode(owned) catch unreachable, .admission = AdmissionStamp.mint(decoded.origin, now_ms, self.config.clock, .origin_frontier) };
        if (conflict) {
            candidate.original = try self.allocator.dupe(u8, self.frontiers.items[index].original);
            candidate.decoded = frontier.decode(candidate.original) catch unreachable;
            candidate.conflict = owned;
            candidate.conflict_admission = candidate.admission;
            candidate.admission = self.frontiers.items[index].admission;
        }
        plan.candidate = candidate;
        plan.candidate_bytes = candidate_bytes;
        return plan;
    }

    /// Sole owning handle: do not copy. Only one outstanding plan per store;
    /// commit/abort it before preparing another under the external owner lock.
    pub const Prepared = struct {
        store: *Store,
        generation: u64,
        index: usize,
        disposition: Disposition,
        candidate: ?Entry = null,
        candidate_bytes: usize = 0,
        done: bool = false,

        pub fn abort(self: *Prepared) void {
            if (self.done) return;
            if (self.candidate) |candidate| self.store.freeEntry(candidate);
            self.candidate = null;
            self.done = true;
        }

        /// No-fail publication under the same owner lock as prepare. Readers
        /// cannot retain entry pointers or borrowed slices across this commit.
        pub fn commit(self: *Prepared) Disposition {
            std.debug.assert(!self.done and self.store.generation == self.generation);
            if (self.candidate) |candidate| {
                if (self.index == self.store.entries.items.len) {
                    self.store.entries.appendAssumeCapacity(candidate);
                } else {
                    self.store.freeEntry(self.store.entries.items[self.index]);
                    self.store.entries.items[self.index] = candidate;
                }
                self.store.bytes = self.candidate_bytes;
                self.store.generation +%= 1;
                self.candidate = null;
            }
            self.done = true;
            return self.disposition;
        }
    };

    /// Approval pins full keys. Gossiped node names or short IDs cannot admit an
    /// origin. Every approved key sharing the selected short ID must agree.
    fn approved(origin: sign.PublicKey, roots: []const sign.PublicKey) Error!void {
        var found = false;
        const short = signed_frame.originShortId(origin);
        for (roots) |root| {
            if (std.mem.eql(u8, &root, &origin)) found = true else if (signed_frame.originShortId(root) == short) return error.OriginCollision;
        }
        if (!found) return error.UnapprovedOrigin;
    }

    fn sameBody(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a[0 .. a.len - sign.signature_len], b[0 .. b.len - sign.signature_len]);
    }

    /// Shared v2 chronology for admission and retained pair validation. Each
    /// original signature/admission remains a caller prerequisite.
    pub fn comparePresence(old: wire.Decoded, incoming: wire.Decoded) Error!Disposition {
        return switch (try wire.comparePresence(old, incoming)) {
            .duplicate => .duplicate,
            .obsolete => .obsolete,
            .updated => .updated,
            .quarantined => .quarantined,
        };
    }

    fn subjectIndex(self: *const Store, origin: sign.PublicKey, guest: wire.GuestId) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            const record = entry.decoded.record;
            if (std.mem.eql(u8, &record.origin, &origin) and std.mem.eql(u8, &record.guest, &guest)) return index;
        }
        return null;
    }

    pub fn prepare(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64) Error!Prepared {
        return self.prepareAdmitted(original, roots, now_ms, false);
    }

    /// Live negative repair only. Expiry cannot erase a signed irreversible
    /// QUIT, but signature/full-origin approval, bounded lifetime, initial
    /// future eligibility and claim consistency remain mandatory. This is not
    /// a trusted checkpoint loader and cannot admit an expired positive.
    pub fn prepareQuitRepair(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64) Error!Prepared {
        return self.prepareAdmitted(original, roots, now_ms, true);
    }

    fn prepareAdmitted(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64, quit_repair: bool) Error!Prepared {
        return self.buildAdmitted(original, roots, now_ms, quit_repair, true);
    }

    fn buildAdmitted(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64, quit_repair: bool, enforce_capacity: bool) Error!Prepared {
        const decoded = try wire.decode(original);
        try decoded.verify();
        const record = decoded.record;
        try approved(record.origin, roots);
        try self.checkSubject(record);
        if (quit_repair and record.operation != .quit) return error.InvalidField;
        var expired_repair = false;
        self.config.clock.validate(record, now_ms) catch |err| {
            if (!quit_repair or err != error.Expired) return err;
            expired_repair = true;
        };
        try validateClaim(record, now_ms, self.config.clock.max_future_skew_ms);
        const index = self.subjectIndex(record.origin, record.guest) orelse self.entries.items.len;
        var prepared: Prepared = .{ .store = self, .generation = self.generation, .index = index, .disposition = .inserted };
        var old_bytes: usize = 0;
        var conflict = false;
        if (index < self.entries.items.len) {
            const entry = self.entries.items[index];
            if (sameBody(entry.original, original) or (entry.conflict != null and sameBody(entry.conflict.?, original))) {
                prepared.disposition = .duplicate;
                return prepared;
            }
            if (entry.conflict != null) {
                prepared.disposition = .quarantined;
                return prepared;
            }
            prepared.disposition = try comparePresence(entry.decoded, decoded);
            if (prepared.disposition == .obsolete) return prepared;
            conflict = prepared.disposition == .quarantined;
            old_bytes = entry.original.len;
        } else if (enforce_capacity and index == self.config.max_entries) return error.Capacity;
        const retained_bytes = self.bytes - old_bytes;
        const needed = std.math.add(usize, original.len, if (conflict) old_bytes else @as(usize, 0)) catch return error.Capacity;
        if (enforce_capacity and (needed > self.config.max_bytes or retained_bytes > self.config.max_bytes - needed)) return error.Capacity;
        const candidate_bytes = std.math.add(usize, retained_bytes, needed) catch return error.Capacity;
        const owned = try self.allocator.dupe(u8, original);
        errdefer self.allocator.free(owned);
        var candidate: Entry = .{ .original = owned, .decoded = try wire.decode(owned), .admission = AdmissionStamp.mint(record.origin, now_ms, self.config.clock, if (expired_repair) .expired_quit_repair else .live_presence) };
        if (conflict) {
            candidate.original = try self.allocator.dupe(u8, self.entries.items[index].original);
            candidate.decoded = wire.decode(candidate.original) catch unreachable;
            candidate.conflict = owned;
            candidate.conflict_admission = candidate.admission;
            candidate.admission = self.entries.items[index].admission;
        }
        prepared.candidate = candidate;
        prepared.candidate_bytes = candidate_bytes;
        return prepared;
    }

    pub const ProjectionChange = union(enum) {
        unchanged,
        presence: *const Prepared,
        frontier: *const PreparedFrontier,
        local_lifecycle: *const PreparedLocalLifecycle,
        local_lifecycles: *const PreparedLocalLifecycles,
    };

    /// Borrowed selected rows over an unchanged predecessor. This is selection
    /// and accounting, not signature/stamp restoration authority. Keep the
    /// external owner lock and invalidate every view when the store commits.
    pub const Projection = struct {
        store: *const Store,
        generation: u64,
        entry_replacement_index: ?usize = null,
        entry_candidate: ?Entry = null,
        frontier_replacement_index: ?usize = null,
        frontier_candidate: ?OriginFrontier = null,
        retirement: ?frontier.Decoded = null,
        final_bytes: usize = 0,
        final_entry_count: usize = 0,
        final_frontier_count: usize = 0,
        candidate_survives: bool = false,
        subject_changes: []const LocalSubjectChange = &.{},
        subject_replacements: []const ?usize = &.{},

        pub fn entries(self: Projection) EntryIterator {
            return .{ .projection = self };
        }
        pub fn frontiers(self: Projection) FrontierIterator {
            return .{ .projection = self };
        }
        fn kept(self: Projection, entry: Entry) bool {
            return if (self.retirement) |cut| !covered(entry, cut) else true;
        }
    };
    pub const EntryIterator = struct {
        projection: Projection,
        index: usize = 0,
        candidate_done: bool = false,
        subject_index: usize = 0,

        pub fn next(self: *EntryIterator) ?Entry {
            const projection = self.projection;
            std.debug.assert(projection.store.generation == projection.generation);
            while (self.index < projection.store.entries.items.len) {
                const index = self.index;
                self.index += 1;
                if (projection.entry_replacement_index) |replaced| if (index == replaced) continue;
                if (projection.subject_replacements.len != 0 and projection.subject_replacements[index] != null) continue;
                const entry = projection.store.entries.items[index];
                if (projection.kept(entry)) return entry;
            }
            if (!self.candidate_done) {
                self.candidate_done = true;
                if (projection.entry_candidate) |entry| if (projection.kept(entry)) return entry;
            }
            while (self.subject_index < projection.subject_changes.len) {
                const subject = projection.subject_changes[self.subject_index];
                self.subject_index += 1;
                if (subject.candidate) |entry| if (projection.kept(entry)) return entry;
            }
            return null;
        }
    };
    pub const FrontierIterator = struct {
        projection: Projection,
        index: usize = 0,
        candidate_done: bool = false,

        pub fn next(self: *FrontierIterator) ?OriginFrontier {
            const projection = self.projection;
            std.debug.assert(projection.store.generation == projection.generation);
            while (self.index < projection.store.frontiers.items.len) {
                const index = self.index;
                self.index += 1;
                if (projection.frontier_replacement_index) |replaced| if (index == replaced) continue;
                return projection.store.frontiers.items[index];
            }
            if (!self.candidate_done) {
                self.candidate_done = true;
                if (projection.frontier_candidate) |item| return item;
            }
            return null;
        }
    };

    fn selectEntry(self: *const Store, projection: *Projection, index: usize, disposition: Disposition, candidate: ?Entry) Error!void {
        if (index > self.entries.items.len) return error.InvalidPlan;
        if (candidate) |entry| {
            const decoded = try wire.decode(entry.original);
            if (!std.meta.eql(decoded, entry.decoded)) return error.InvalidPlan;
            const incoming = decoded.record;
            if (index < self.entries.items.len) {
                const before = (try wire.decode(self.entries.items[index].original)).record;
                if (disposition == .inserted or !std.mem.eql(u8, &before.origin, &incoming.origin) or !std.mem.eql(u8, &before.guest, &incoming.guest)) return error.InvalidPlan;
            } else if (disposition != .inserted) return error.InvalidPlan;
            if (disposition != .inserted and disposition != .updated and disposition != .quarantined) return error.InvalidPlan;
            if ((entry.conflict != null) != (disposition == .quarantined)) return error.InvalidPlan;
            projection.entry_replacement_index = index;
            projection.entry_candidate = entry;
        } else if (index == self.entries.items.len or disposition == .inserted or disposition == .updated) return error.InvalidPlan;
    }
    fn selectFrontier(self: *const Store, projection: *Projection, index: usize, disposition: frontier.Update, candidate: ?OriginFrontier) Error!void {
        if (index > self.frontiers.items.len) return error.InvalidPlan;
        if (candidate) |item| {
            const incoming = try frontier.decode(item.original);
            if (!std.meta.eql(incoming, item.decoded)) return error.InvalidPlan;
            if (index < self.frontiers.items.len) {
                const before = try frontier.decode(self.frontiers.items[index].original);
                if (!std.mem.eql(u8, &before.origin, &incoming.origin)) return error.InvalidPlan;
            } else if (disposition != .advance) return error.InvalidPlan;
            if (disposition != .advance and disposition != .conflict) return error.InvalidPlan;
            if ((item.conflict != null) != (disposition == .conflict)) return error.InvalidPlan;
            projection.frontier_replacement_index = index;
            projection.frontier_candidate = item;
            if (item.conflict == null) projection.retirement = incoming;
        } else if (index == self.frontiers.items.len or disposition == .advance) return error.InvalidPlan;
    }

    fn validateProjectionIdentities(self: *const Store) Error!void {
        // Selection/GC must never attribute a raw original using a stale cache.
        // Cryptographic and admission-stamp validation remains the image layer.
        for (self.entries.items) |entry| {
            const decoded = try wire.decode(entry.original);
            if (!std.meta.eql(decoded, entry.decoded)) return error.InvalidPlan;
        }
        for (self.frontiers.items) |item| {
            const decoded = try frontier.decode(item.original);
            if (!std.meta.eql(decoded, item.decoded)) return error.InvalidPlan;
        }
    }

    fn measureProjection(self: *const Store, projection: *Projection) Error!void {
        var entries = projection.entries();
        while (entries.next()) |entry| {
            projection.final_entry_count = std.math.add(usize, projection.final_entry_count, 1) catch return error.Capacity;
            const bytes = std.math.add(usize, entry.original.len, if (entry.conflict) |value| value.len else 0) catch return error.Capacity;
            projection.final_bytes = std.math.add(usize, projection.final_bytes, bytes) catch return error.Capacity;
        }
        var frontiers = projection.frontiers();
        while (frontiers.next()) |item| {
            projection.final_frontier_count = std.math.add(usize, projection.final_frontier_count, 1) catch return error.Capacity;
            const bytes = std.math.add(usize, item.original.len, if (item.conflict) |value| value.len else 0) catch return error.Capacity;
            projection.final_bytes = std.math.add(usize, projection.final_bytes, bytes) catch return error.Capacity;
        }
        projection.candidate_survives = if (projection.entry_candidate) |entry| projection.kept(entry) else false;
        if (projection.final_entry_count > self.config.max_entries or projection.final_frontier_count > self.config.max_origins or projection.final_bytes > self.config.max_bytes) return error.Capacity;
    }

    /// Validate before preparing/committing the durable batch. The same source
    /// lock then remains held through no-fail RAM publication. No debug-only
    /// post-fsync check may substitute for this fallible predecessor validation.
    pub fn project(self: *const Store, change: ProjectionChange) Error!Projection {
        try self.validateProjectionIdentities();
        var projection: Projection = .{ .store = self, .generation = self.generation };
        var expected_bytes = self.bytes;
        switch (change) {
            .unchanged => {},
            .presence => |plan| {
                if (plan.store != self or plan.generation != self.generation or plan.done) return error.InvalidPlan;
                try self.selectEntry(&projection, plan.index, plan.disposition, plan.candidate);
                if (plan.candidate != null) expected_bytes = plan.candidate_bytes;
            },
            .frontier => |plan| {
                if (plan.store != self or plan.generation != self.generation or plan.done) return error.InvalidPlan;
                try self.selectFrontier(&projection, plan.index, plan.disposition, plan.candidate);
                if (plan.candidate != null) expected_bytes = plan.candidate_bytes;
            },
            .local_lifecycle => |plan| {
                if (plan.store != self or plan.generation != self.generation or plan.done or plan.generation == std.math.maxInt(u64)) return error.InvalidPlan;
                try self.selectEntry(&projection, plan.subject_index, plan.subject_disposition, plan.subject_candidate);
                try self.selectFrontier(&projection, plan.frontier_index, plan.frontier_disposition, plan.frontier_candidate);
                const selected = projection.entry_candidate orelse self.entries.items[plan.subject_index];
                if (!std.mem.eql(u8, &selected.decoded.record.guest, &plan.subject_guest)) return error.InvalidPlan;
                try self.validateLocalLifecycle(&projection, plan.local_origin, plan.subject_index, plan.subject_disposition, plan.frontier_index, plan.frontier_disposition);
                expected_bytes = plan.final_bytes;
            },
            .local_lifecycles => |plan| {
                try self.selectLocalLifecycles(&projection, plan);
                expected_bytes = plan.final_bytes;
            },
        }
        try self.measureProjection(&projection);
        if (projection.final_bytes != expected_bytes) return error.AccountingMismatch;
        if (change == .local_lifecycle) {
            const plan = change.local_lifecycle;
            if (projection.final_entry_count != plan.final_entry_count or projection.final_frontier_count != plan.final_frontier_count or projection.candidate_survives != plan.candidate_survives) return error.InvalidPlan;
        }
        if (change == .local_lifecycles) {
            const plan = change.local_lifecycles;
            if (projection.final_entry_count != plan.final_entry_count or projection.final_frontier_count != plan.final_frontier_count) return error.InvalidPlan;
            for (plan.subjects) |subject| {
                const survives = if (subject.candidate) |entry| projection.kept(entry) else false;
                if (survives != subject.candidate_survives) return error.InvalidPlan;
            }
        }
        return projection;
    }

    fn originalDigest(original: []const u8) [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(original, &digest, .{});
        return digest;
    }

    pub const LocalSubjectChange = struct {
        guest: wire.GuestId,
        index: usize,
        disposition: Disposition,
        candidate: ?Entry,
        /// Exact signed output evidence remains owned through commit. Never
        /// rediscover QUIT bytes in the normalized retained store after GC.
        original: []u8,
        original_digest: [32]u8,
        admission: AdmissionStamp,
        candidate_survives: bool = false,
    };

    fn selectLocalLifecycles(self: *const Store, projection: *Projection, plan: *const PreparedLocalLifecycles) Error!void {
        if (plan.store != self or plan.done or plan.generation != self.generation or plan.generation == std.math.maxInt(u64) or plan.subjects.len == 0 or plan.subject_count != plan.subjects.len or plan.replacements.len != self.entries.items.len) return error.InvalidPlan;
        try self.selectFrontier(projection, plan.frontier_index, plan.frontier_disposition, plan.frontier_candidate);
        if (plan.frontier_disposition != .advance and plan.frontier_disposition != .duplicate) return error.InvalidLocalLifecycle;
        const cut = projection.frontier_candidate orelse self.frontiers.items[plan.frontier_index];
        if (cut.conflict != null or !std.mem.eql(u8, &cut.decoded.origin, &plan.local_origin) or !std.mem.eql(u8, &originalDigest(cut.original), &plan.frontier_digest)) return error.InvalidPlan;
        try cut.admission.validateFrontier(cut.decoded);
        const proof = cut.decoded;
        projection.retirement = proof;
        projection.subject_changes = plan.subjects;
        projection.subject_replacements = plan.replacements;
        for (plan.replacements, 0..) |ordinal, index| {
            if (ordinal) |i| {
                if (i >= plan.subjects.len or plan.subjects[i].candidate == null or plan.subjects[i].index != index) return error.InvalidPlan;
            }
        }
        var insert_count: usize = 0;
        for (plan.subjects, 0..) |subject, ordinal| {
            if (!std.mem.eql(u8, &originalDigest(subject.original), &subject.original_digest)) return error.InvalidPlan;
            const incoming = try wire.decode(subject.original);
            try subject.admission.validatePresence(incoming);
            const record = incoming.record;
            if (!std.mem.eql(u8, &record.origin, &plan.local_origin) or !std.mem.eql(u8, &record.guest, &subject.guest)) return error.InvalidPlan;
            for (plan.subjects[0..ordinal]) |before| if (std.mem.eql(u8, &before.guest, &subject.guest)) return error.InvalidPlan;
            try self.checkSubject(record); // Always the unchanged OLD cut.
            const id = try wire.subject(record.guest);
            if (id.epoch != proof.epoch) return error.InvalidLocalLifecycle;
            switch (record.operation) {
                .present => if (!proof.contains(id.counter)) return error.InvalidLocalLifecycle,
                .quit => if (id.counter > proof.through or proof.contains(id.counter)) return error.InvalidLocalLifecycle,
            }
            if (subject.disposition == .obsolete or subject.disposition == .quarantined) return error.InvalidLocalLifecycle;
            if (subject.index < self.entries.items.len) {
                const old = self.entries.items[subject.index];
                if (old.conflict != null) return error.InvalidLocalLifecycle;
                if (!std.mem.eql(u8, &old.decoded.record.origin, &record.origin) or !std.mem.eql(u8, &old.decoded.record.guest, &record.guest)) return error.InvalidPlan;
                if (try comparePresence(old.decoded, incoming) != subject.disposition) return error.InvalidPlan;
            } else {
                if (subject.disposition != .inserted or subject.index != self.entries.items.len + insert_count or self.subjectIndex(record.origin, record.guest) != null) return error.InvalidPlan;
                insert_count += 1;
            }
            if (subject.candidate) |entry| {
                if (subject.disposition != .inserted and subject.disposition != .updated) return error.InvalidPlan;
                if (subject.index < self.entries.items.len and plan.replacements[subject.index] != ordinal) return error.InvalidPlan;
                const decoded = try wire.decode(entry.original);
                if (entry.conflict != null or entry.conflict_admission != null or !std.meta.eql(decoded, entry.decoded) or !std.mem.eql(u8, entry.original, subject.original)) return error.InvalidPlan;
                try entry.admission.validatePresence(decoded);
            } else if (subject.disposition != .duplicate or subject.index >= self.entries.items.len or plan.replacements[subject.index] != null) return error.InvalidPlan;
        }
    }

    pub const PreparedLocalLifecycles = struct {
        store: *Store,
        allocator: std.mem.Allocator,
        generation: u64,
        local_origin: sign.PublicKey,
        subjects: []LocalSubjectChange,
        subject_count: usize = 0,
        replacements: []?usize,
        frontier_index: usize = 0,
        frontier_disposition: frontier.Update = .advance,
        frontier_candidate: ?OriginFrontier = null,
        frontier_digest: [32]u8 = undefined,
        final_bytes: usize = 0,
        final_entry_count: usize = 0,
        final_frontier_count: usize = 0,
        done: bool = false,

        /// Idempotent cleanup includes output evidence AFTER commit; preserves
        /// existing defer-abort callers without losing compacted signed QUIT.
        pub fn abort(self: *PreparedLocalLifecycles) void {
            for (self.subjects[0..self.subject_count]) |subject| {
                if (subject.candidate) |entry| self.store.freeEntry(entry);
                self.allocator.free(subject.original);
            }
            if (self.frontier_candidate) |item| self.store.freeFrontier(item);
            self.allocator.free(self.subjects);
            self.allocator.free(self.replacements);
            self.subjects = &.{};
            self.subject_count = 0;
            self.replacements = &.{};
            self.frontier_candidate = null;
            self.done = true;
        }

        pub fn deinit(self: *PreparedLocalLifecycles) void {
            self.abort();
        }

        /// One frontier publication then ORIGINAL-index compaction and all
        /// prepared subjects. No allocation/error; originals stay ticket-owned.
        pub fn commit(self: *PreparedLocalLifecycles) void {
            std.debug.assert(!self.done and self.store.generation == self.generation and self.generation < std.math.maxInt(u64));
            const old_frontier = if (self.frontier_index < self.store.frontiers.items.len) self.store.frontiers.items[self.frontier_index] else null;
            if (self.frontier_candidate) |item| {
                if (self.frontier_index == self.store.frontiers.items.len) self.store.frontiers.appendAssumeCapacity(item) else self.store.frontiers.items[self.frontier_index] = item;
            }
            const proof = self.store.frontiers.items[self.frontier_index].decoded;
            var next: usize = 0;
            for (self.store.entries.items, 0..) |entry, index| {
                if (self.replacements[index] != null or covered(entry, proof)) {
                    self.store.freeEntry(entry);
                } else {
                    self.store.entries.items[next] = entry;
                    next += 1;
                }
            }
            self.store.entries.items.len = next;
            for (self.subjects) |*subject| {
                if (subject.candidate) |entry| {
                    if (subject.candidate_survives) self.store.entries.appendAssumeCapacity(entry) else self.store.freeEntry(entry);
                    subject.candidate = null;
                }
            }
            if (self.frontier_candidate != null) if (old_frontier) |item| self.store.freeFrontier(item);
            self.frontier_candidate = null;
            self.store.bytes = self.final_bytes;
            self.store.generation += 1;
            self.done = true;
        }
    };

    fn buildLocalSubject(self: *Store, original: []const u8, roots: []const sign.PublicKey, now_ms: i64) Error!LocalSubjectChange {
        const record = (try wire.decode(original)).record;
        var plan = try self.buildAdmitted(original, roots, now_ms, record.operation == .quit, false);
        defer plan.abort();
        if (plan.disposition == .obsolete or plan.disposition == .quarantined) return error.InvalidLocalLifecycle;
        const owned = try self.allocator.dupe(u8, original);
        const result: LocalSubjectChange = .{ .guest = record.guest, .index = plan.index, .disposition = plan.disposition, .candidate = plan.candidate, .original = owned, .original_digest = originalDigest(owned), .admission = AdmissionStamp.mint(record.origin, now_ms, self.config.clock, if (record.operation == .quit and now_ms >= record.expires_ms) .expired_quit_repair else .live_presence) };
        plan.candidate = null;
        return result;
    }

    /// All inputs are independently admitted under the OLD origin cut; only
    /// the final normalized union pays quotas. Empty groups are explicit error:
    /// use prepareFrontier for a frontier-only cut. The graph caller derives
    /// the COMPLETE inventory; this leaf proves only supplied record relations.
    pub fn prepareLocalLifecycles(self: *Store, originals: []const []const u8, origin_frontier: []const u8, local_origin: sign.PublicKey, roots: []const sign.PublicKey, now_ms: i64) Error!PreparedLocalLifecycles {
        if (originals.len == 0 or originals.len > frontier.max_active) return error.InvalidLocalLifecycle;
        if (self.generation == std.math.maxInt(u64)) return error.GenerationExhausted;
        try self.validateProjectionIdentities();
        for (originals, 0..) |original, i| {
            const record = (try wire.decode(original)).record;
            if (!std.mem.eql(u8, &record.origin, &local_origin)) return error.InvalidLocalLifecycle;
            for (originals[0..i]) |before| if (std.mem.eql(u8, &(try wire.decode(before)).record.guest, &record.guest)) return error.InvalidLocalLifecycle;
        }
        const subjects = try self.allocator.alloc(LocalSubjectChange, originals.len);
        errdefer self.allocator.free(subjects);
        const replacements = try self.allocator.alloc(?usize, self.entries.items.len);
        @memset(replacements, null);
        var plan: PreparedLocalLifecycles = .{ .store = self, .allocator = self.allocator, .generation = self.generation, .local_origin = local_origin, .subjects = subjects, .replacements = replacements };
        // A separate guard owns the slice until the complete plan is returned.
        errdefer {
            for (plan.subjects[0..plan.subject_count]) |subject| {
                if (subject.candidate) |entry| self.freeEntry(entry);
                self.allocator.free(subject.original);
            }
            if (plan.frontier_candidate) |item| self.freeFrontier(item);
            self.allocator.free(replacements);
        }
        var inserted: usize = 0;
        for (originals, 0..) |original, ordinal| {
            var subject = try self.buildLocalSubject(original, roots, now_ms);
            if (subject.index == self.entries.items.len) {
                subject.index += inserted;
                inserted += 1;
            } else if (subject.candidate != null) replacements[subject.index] = ordinal;
            subjects[ordinal] = subject;
            plan.subject_count += 1;
        }
        var cut = try self.buildFrontier(origin_frontier, roots, now_ms, false);
        defer cut.abort();
        plan.frontier_index = cut.index;
        plan.frontier_disposition = cut.disposition;
        plan.frontier_candidate = cut.candidate;
        cut.candidate = null;
        const selected_cut = plan.frontier_candidate orelse self.frontiers.items[plan.frontier_index];
        plan.frontier_digest = originalDigest(selected_cut.original);
        var projection: Projection = .{ .store = self, .generation = self.generation };
        try self.selectLocalLifecycles(&projection, &plan);
        try self.measureProjection(&projection);
        plan.final_bytes = projection.final_bytes;
        plan.final_entry_count = projection.final_entry_count;
        plan.final_frontier_count = projection.final_frontier_count;
        for (subjects) |*subject| subject.candidate_survives = if (subject.candidate) |entry| projection.kept(entry) else false;
        return plan;
    }

    fn validateLocalLifecycle(self: *const Store, projection: *Projection, local_origin: sign.PublicKey, subject_index: usize, subject_disposition: Disposition, frontier_index: usize, frontier_disposition: frontier.Update) Error!void {
        if (subject_disposition == .obsolete or subject_disposition == .quarantined or (frontier_disposition != .advance and frontier_disposition != .duplicate)) return error.InvalidLocalLifecycle;
        const selected_entry = projection.entry_candidate orelse self.entries.items[subject_index];
        const record = (try wire.decode(selected_entry.original)).record;
        const selected_frontier = projection.frontier_candidate orelse self.frontiers.items[frontier_index];
        const proof = try frontier.decode(selected_frontier.original);
        if (!std.mem.eql(u8, &record.origin, &local_origin) or !std.mem.eql(u8, &proof.origin, &local_origin) or selected_entry.conflict != null or selected_frontier.conflict != null) return error.InvalidLocalLifecycle;
        try self.checkSubject(record); // OLD cut; never reintroduce retired IDs.
        const id = try wire.subject(record.guest);
        if (id.epoch != proof.epoch) return error.InvalidLocalLifecycle;
        switch (record.operation) {
            .present => if (proof.retires(record.origin, id.epoch, id.counter) or (id.counter <= proof.through and !proof.contains(id.counter))) return error.InvalidLocalLifecycle,
            .quit => if (id.counter > proof.through or proof.contains(id.counter)) return error.InvalidLocalLifecycle,
        }
        // A duplicate frontier still defines the normalized candidate cut.
        projection.retirement = proof;
    }

    /// One uncopied owning delta. Never independently commit its components.
    /// All allocation and source validation precede the aggregate WAL commit.
    pub const PreparedLocalLifecycle = struct {
        store: *Store,
        generation: u64,
        local_origin: sign.PublicKey,
        /// Expected admitted key survives a duplicate with no owned candidate.
        subject_guest: wire.GuestId,
        subject_index: usize,
        subject_disposition: Disposition,
        subject_candidate: ?Entry,
        frontier_index: usize,
        frontier_disposition: frontier.Update,
        frontier_candidate: ?OriginFrontier,
        final_bytes: usize,
        final_entry_count: usize,
        final_frontier_count: usize,
        candidate_survives: bool,
        done: bool = false,

        pub fn abort(self: *PreparedLocalLifecycle) void {
            if (self.done) return;
            if (self.subject_candidate) |entry| self.store.freeEntry(entry);
            if (self.frontier_candidate) |item| self.store.freeFrontier(item);
            self.subject_candidate = null;
            self.frontier_candidate = null;
            self.done = true;
        }

        /// Exactly one generation; no allocation, error or interim visibility.
        /// The caller already validated project() before durable publication.
        pub fn commit(self: *PreparedLocalLifecycle) void {
            std.debug.assert(!self.done and self.store.generation == self.generation and self.generation < std.math.maxInt(u64));
            const old_frontier = if (self.frontier_index < self.store.frontiers.items.len) self.store.frontiers.items[self.frontier_index] else null;
            // Install the negative proof BEFORE discarding any subject bytes.
            if (self.frontier_candidate) |item| {
                if (self.frontier_index == self.store.frontiers.items.len) {
                    self.store.frontiers.appendAssumeCapacity(item);
                } else self.store.frontiers.items[self.frontier_index] = item;
            }
            const proof = self.store.frontiers.items[self.frontier_index].decoded;
            var write_index: usize = 0;
            // Original-index compaction: a removed row can never shift or swap
            // another physical subject under the saved replacement index.
            for (self.store.entries.items, 0..) |entry, index| {
                if ((self.subject_candidate != null and index == self.subject_index) or covered(entry, proof)) {
                    self.store.freeEntry(entry);
                    continue;
                }
                self.store.entries.items[write_index] = entry;
                write_index += 1;
            }
            self.store.entries.items.len = write_index;
            if (self.subject_candidate) |entry| {
                if (self.candidate_survives) self.store.entries.appendAssumeCapacity(entry) else self.store.freeEntry(entry);
            }
            if (self.frontier_candidate != null) if (old_frontier) |item| self.store.freeFrontier(item);
            self.store.bytes = self.final_bytes;
            self.store.generation += 1;
            self.subject_candidate = null;
            self.frontier_candidate = null;
            self.done = true;
        }
    };

    /// Pure local authorship cut over the unchanged predecessor. Subject
    /// admission uses the OLD retirement/quarantine state. Only final normalized
    /// quotas apply, so registration/renewal can replace certified retired rows
    /// while the previous store is full. Caller supplies the complete inventory.
    pub fn prepareLocalLifecycle(self: *Store, original: []const u8, origin_frontier: []const u8, local_origin: sign.PublicKey, roots: []const sign.PublicKey, now_ms: i64) Error!PreparedLocalLifecycle {
        var group = try self.prepareLocalLifecycles(&.{original}, origin_frontier, local_origin, roots, now_ms);
        defer group.abort();
        const subject = group.subjects[0];
        const result: PreparedLocalLifecycle = .{
            .store = self,
            .generation = group.generation,
            .local_origin = local_origin,
            .subject_guest = subject.guest,
            .subject_index = subject.index,
            .subject_disposition = subject.disposition,
            .subject_candidate = subject.candidate,
            .frontier_index = group.frontier_index,
            .frontier_disposition = group.frontier_disposition,
            .frontier_candidate = group.frontier_candidate,
            .final_bytes = group.final_bytes,
            .final_entry_count = group.final_entry_count,
            .final_frontier_count = group.final_frontier_count,
            .candidate_survives = subject.candidate_survives,
        };
        group.subjects[0].candidate = null;
        group.frontier_candidate = null;
        return result;
    }

    /// One consistent identity winner for WHOIS/nick/DM consumers. Reachability
    /// is deliberately absent: callers must separately establish an active path.
    pub fn winner(self: *const Store, nick: []const u8, now_ms: i64, roots: []const sign.PublicKey) ?*const Entry {
        return self.winnerWithExpiryFloor(nick, now_ms, 0, roots);
    }

    /// The caller must durably publish an observed expiry floor before any
    /// irreversible expiry projection. Future issue/claim checks still use the
    /// raw wall clock; raising it to the floor would admit future claims.
    pub fn winnerWithExpiryFloor(self: *const Store, nick: []const u8, now_ms: i64, expiry_floor_ms: i64, roots: []const sign.PublicKey) ?*const Entry {
        if (expiry_floor_ms < 0) return null;
        const expiry_ms = @max(now_ms, expiry_floor_ms);
        var best: ?*const Entry = null;
        for (self.entries.items) |*entry| {
            const record = entry.decoded.record;
            approved(record.origin, roots) catch continue;
            self.checkSubject(record) catch continue;
            self.config.clock.validate(record, now_ms) catch continue;
            const claim_ms: i64 = @intCast(record.claim_hlc >> 16);
            if (claim_ms > now_ms and claim_ms - now_ms > self.config.clock.max_future_skew_ms) continue;
            if (entry.terminal() or now_ms < 0 or expiry_ms >= record.expires_ms or !std.ascii.eqlIgnoreCase(record.nick, nick)) continue;
            if (best) |current| {
                const old = current.decoded.record;
                if (record.claim_hlc < old.claim_hlc) continue;
                if (record.claim_hlc == old.claim_hlc) {
                    const node = signed_frame.originShortId(record.origin);
                    const old_node = signed_frame.originShortId(old.origin);
                    if (node < old_node or (node == old_node and std.mem.order(u8, &record.guest, &old.guest) != .gt)) continue;
                }
            }
            best = entry;
        }
        return best;
    }
};

fn fixtureRecord(key: sign.PublicKey, revision: u64) wire.Record {
    return .{ .operation = .present, .origin = key, .guest = @splat(7), .revision = revision, .routing_class = .true_guest, .class_revision = 1, .claim_hlc = 9, .claim_revision = 1, .issued_ms = 1000, .expires_ms = 2000, .nick = "Guest", .username = "guest", .host = "cloak.onyx", .realname = "Guest", .server = "node-c", .description = "Origin" };
}

fn apply(store: *Store, value: wire.Record, key: *const sign.KeyPair) !Disposition {
    var buffer: [wire.max_wire_len]u8 = undefined;
    var prepared = try store.prepare(try wire.encode(value, key, &buffer), &.{key.public_key}, 1000);
    defer prepared.abort();
    return prepared.commit();
}

test "mesh presence admission preserves original decision through duplicate abort and conflict" {
    var key = try sign.KeyPair.fromSeed(@splat(91));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    _ = try apply(&store, value, &key);
    const original_stamp = store.entries.items[0].admission;
    var buffer: [wire.max_wire_len]u8 = undefined;
    // Changing policy and receiving an identical repair cannot rewrite history.
    store.config.clock = .{ .max_lifetime_ms = 1500, .max_future_skew_ms = 10 };
    var duplicate = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1100);
    try std.testing.expectEqual(Disposition.duplicate, duplicate.commit());
    try std.testing.expectEqualDeep(original_stamp, store.entries.items[0].admission);
    value.realname = "Contradiction";
    var aborted = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1200);
    try std.testing.expectEqual(@as(i64, 1200), aborted.candidate.?.conflict_admission.?.admitted_at_ms);
    aborted.abort();
    try std.testing.expect(store.entries.items[0].conflict_admission == null);
    var conflict = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1300);
    _ = conflict.commit();
    const entry = store.entries.items[0];
    try std.testing.expectEqualDeep(original_stamp, entry.admission);
    try std.testing.expectEqual(@as(i64, 1300), entry.conflict_admission.?.admitted_at_ms);
    try std.testing.expectEqual(@as(i64, 1500), entry.conflict_admission.?.max_lifetime_ms);
    try entry.admission.validatePresence(entry.decoded);
    try entry.conflict_admission.?.validatePresence(try wire.decode(entry.conflict.?));
    value.guest = @splat(9);
    var inserted = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1400);
    _ = inserted.commit();
    value.revision = 2;
    var updated = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1500);
    _ = updated.commit();
    try std.testing.expectEqual(@as(i64, 1500), store.entries.items[1].admission.admitted_at_ms);
}

test "mesh presence admission expired repair records actual bypass and rejects false provenance" {
    var key = try sign.KeyPair.fromSeed(@splat(92));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    value.operation = .quit;
    value.revision = 2;
    var buffer: [wire.max_wire_len]u8 = undefined;
    var live = try store.prepareQuitRepair(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1000);
    _ = live.commit();
    try std.testing.expectEqual(.live_presence, store.entries.items[0].admission.mode);
    value.guest = @splat(9);
    var repair = try store.prepareQuitRepair(try wire.encode(value, &key, &buffer), &.{key.public_key}, 3000);
    _ = repair.commit();
    const entry = store.entries.items[1];
    try std.testing.expectEqual(.expired_quit_repair, entry.admission.mode);
    try entry.admission.validatePresence(entry.decoded);
    var invalid = entry.admission;
    invalid.mode = .live_presence;
    try std.testing.expectError(error.Expired, invalid.validatePresence(entry.decoded));
    invalid = entry.admission;
    invalid.admitted_at_ms = 1000;
    try std.testing.expectError(error.InvalidAdmission, invalid.validatePresence(entry.decoded));
    invalid = entry.admission;
    invalid.approved_origin[0] ^= 1;
    try std.testing.expectError(error.InvalidAdmission, invalid.validatePresence(entry.decoded));
    invalid = entry.admission;
    invalid.version = 2;
    try std.testing.expectError(error.InvalidAdmission, invalid.validatePresence(entry.decoded));
    invalid = entry.admission;
    invalid.approval_policy = 2;
    try std.testing.expectError(error.InvalidAdmission, invalid.validatePresence(entry.decoded));
    invalid = entry.admission;
    invalid.max_lifetime_ms = 999;
    try std.testing.expectError(error.InvalidClock, invalid.validatePresence(entry.decoded));
    invalid = entry.admission;
    invalid.admitted_at_ms = -1;
    try std.testing.expectError(error.InvalidAdmission, invalid.validatePresence(entry.decoded));
    value.operation = .present;
    const positive = try wire.decode(try wire.encode(value, &key, &buffer));
    try std.testing.expectError(error.InvalidAdmission, entry.admission.validatePresence(positive));
    const length = positive.wire.len;
    buffer[length - 1] ^= 1;
    invalid = entry.admission;
    invalid.mode = .live_presence;
    invalid.admitted_at_ms = 1000;
    try std.testing.expectError(error.BadSignature, invalid.validatePresence(positive));
}

test "mesh presence admission frontier conflict retains distinct historical decisions" {
    var key = try sign.KeyPair.fromSeed(@splat(93));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    _ = try applyCut(&store, cutRecord(key.public_key, 1, 2, &.{1}), &key);
    const original_stamp = store.frontiers.items[0].admission;
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var duplicate = try store.prepareFrontier(try frontier.encode(cutRecord(key.public_key, 1, 2, &.{1}), &key, buffer), &.{key.public_key}, 2000);
    _ = duplicate.commit();
    try std.testing.expectEqualDeep(original_stamp, store.frontiers.items[0].admission);
    store.config.clock.max_future_skew_ms = 7;
    var conflict = try store.prepareFrontier(try frontier.encode(cutRecord(key.public_key, 1, 2, &.{2}), &key, buffer), &.{key.public_key}, 3000);
    _ = conflict.commit();
    const item = store.frontiers.items[0];
    try std.testing.expectEqualDeep(original_stamp, item.admission);
    try std.testing.expectEqual(@as(i64, 3000), item.conflict_admission.?.admitted_at_ms);
    try std.testing.expectEqual(@as(i64, 7), item.conflict_admission.?.max_future_skew_ms);
    try item.admission.validateFrontier(item.decoded);
    try item.conflict_admission.?.validateFrontier(try frontier.decode(item.conflict.?));
    var invalid = item.admission;
    invalid.mode = .live_presence;
    try std.testing.expectError(error.InvalidAdmission, invalid.validateFrontier(item.decoded));
    invalid = item.admission;
    invalid.admitted_at_ms = 0;
    invalid.max_future_skew_ms = 0;
    try std.testing.expectError(error.FutureIssued, invalid.validateFrontier(item.decoded));
}

test "mesh presence admission encoding is exact and rejects every incomplete or unknown stamp" {
    const stamp = AdmissionStamp.mint(@splat(94), 0x0102030405060708, .{ .max_lifetime_ms = 120_000, .max_future_skew_ms = 0 }, .live_presence);
    const encoded = try stamp.encode();
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1 }, encoded[0..3]);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, encoded[35..43]);
    try std.testing.expectEqualDeep(stamp, try AdmissionStamp.decode(&encoded));
    for (0..encoded.len) |length| try std.testing.expectError(error.InvalidAdmission, AdmissionStamp.decode(encoded[0..length]));
    const extended = encoded ++ [_]u8{0};
    try std.testing.expectError(error.InvalidAdmission, AdmissionStamp.decode(&extended));
    for ([_]usize{ 0, 1, 2 }) |offset| {
        var invalid = encoded;
        invalid[offset] = 0;
        try std.testing.expectError(error.InvalidAdmission, AdmissionStamp.decode(&invalid));
        invalid[offset] = 255;
        try std.testing.expectError(error.InvalidAdmission, AdmissionStamp.decode(&invalid));
    }
    for ([_]usize{ 35, 43, 51 }) |offset| {
        var invalid = encoded;
        invalid[offset] = 0x80;
        try std.testing.expectError(error.InvalidAdmission, AdmissionStamp.decode(&invalid));
    }
    var invalid = encoded;
    @memset(invalid[43..51], 0);
    try std.testing.expectError(error.InvalidAdmission, AdmissionStamp.decode(&invalid));
    for ([_]@FieldType(AdmissionStamp, "mode"){ .expired_quit_repair, .origin_frontier }) |mode| {
        var alternative = stamp;
        alternative.mode = mode;
        try std.testing.expectEqualDeep(alternative, try AdmissionStamp.decode(&(try alternative.encode())));
    }
}

test "mesh presence pair classifier refuses fabricated quarantine and unrelated subjects" {
    var key = try sign.KeyPair.fromSeed(@splat(95));
    defer key.deinit();
    var first_buffer: [wire.max_wire_len]u8 = undefined;
    var second_buffer: [wire.max_wire_len]u8 = undefined;
    var first = fixtureRecord(key.public_key, 1);
    var second = first;
    const original = try wire.decode(try wire.encode(first, &key, &first_buffer));
    var other = try wire.decode(try wire.encode(second, &key, &second_buffer));
    try std.testing.expectEqual(Disposition.duplicate, try Store.comparePresence(original, other));
    second.revision = 2;
    other = try wire.decode(try wire.encode(second, &key, &second_buffer));
    try std.testing.expectEqual(Disposition.updated, try Store.comparePresence(original, other));
    try std.testing.expectEqual(Disposition.obsolete, try Store.comparePresence(other, original));
    second.revision = 1;
    second.realname = "Equivocation";
    other = try wire.decode(try wire.encode(second, &key, &second_buffer));
    try std.testing.expectEqual(Disposition.quarantined, try Store.comparePresence(original, other));
    try std.testing.expectEqual(Disposition.quarantined, try Store.comparePresence(other, original));
    second.guest = @splat(9);
    other = try wire.decode(try wire.encode(second, &key, &second_buffer));
    try std.testing.expectError(error.InvalidField, Store.comparePresence(original, other));
    first.operation = .quit;
    first.revision = 2;
    const quit = try wire.decode(try wire.encode(first, &key, &first_buffer));
    second = fixtureRecord(key.public_key, 3);
    other = try wire.decode(try wire.encode(second, &key, &second_buffer));
    try std.testing.expectEqual(Disposition.quarantined, try Store.comparePresence(quit, other));
    try std.testing.expectEqual(Disposition.quarantined, try Store.comparePresence(other, quit));
}

test "mesh presence store prepared abort retains exact published bytes" {
    var key = try sign.KeyPair.fromSeed(@splat(61));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    try std.testing.expectEqual(Disposition.inserted, try apply(&store, fixtureRecord(key.public_key, 1), &key));
    const old = store.entries.items[0].original;
    const generation = store.generation;
    var buffer: [wire.max_wire_len]u8 = undefined;
    var candidate = try store.prepare(try wire.encode(fixtureRecord(key.public_key, 2), &key, &buffer), &.{key.public_key}, 1000);
    candidate.abort();
    try std.testing.expectEqual(old.ptr, store.entries.items[0].original.ptr);
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqual(@as(u64, 1), store.winner("guest", 1000, &.{key.public_key}).?.decoded.record.revision);
}

test "mesh presence store equivocation and quit never restore a winner" {
    var key = try sign.KeyPair.fromSeed(@splat(62));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    _ = try apply(&store, value, &key);
    value.realname = "Contradiction";
    try std.testing.expectEqual(Disposition.quarantined, try apply(&store, value, &key));
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
    value.revision = 2;
    try std.testing.expectEqual(Disposition.quarantined, try apply(&store, value, &key));
    value.guest = @splat(8);
    _ = try apply(&store, value, &key);
    value.operation = .quit;
    value.revision = 3;
    _ = try apply(&store, value, &key);
    value.operation = .present;
    value.revision = 4;
    try std.testing.expectEqual(Disposition.quarantined, try apply(&store, value, &key));
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
}

test "mesh presence store renewals cannot improve claim and duplicates cannot renew expiry" {
    var key = try sign.KeyPair.fromSeed(@splat(63));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    _ = try apply(&store, value, &key);
    const generation = store.generation;
    try std.testing.expectEqual(Disposition.duplicate, try apply(&store, value, &key));
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expect(store.winner("Guest", 2000, &.{key.public_key}) == null);
    value.revision = 2;
    value.claim_hlc = 8;
    try std.testing.expectEqual(Disposition.quarantined, try apply(&store, value, &key));
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
    value = fixtureRecord(key.public_key, 1);
    value.guest = @splat(8);
    _ = try apply(&store, value, &key);
    value.revision = 2;
    value.nick = "Renamed";
    value.claim_hlc = 10;
    value.claim_revision = value.revision;
    _ = try apply(&store, value, &key);
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
    try std.testing.expect(store.winner("Renamed", 1000, &.{key.public_key}) != null);
}

test "mesh presence store pins origin and fails closed at negative capacity" {
    var key = try sign.KeyPair.fromSeed(@splat(64));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 1 });
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    var buffer: [wire.max_wire_len]u8 = undefined;
    try std.testing.expectError(error.UnapprovedOrigin, store.prepare(try wire.encode(value, &key, &buffer), &.{}, 1000));
    value.operation = .quit;
    value.revision = 2;
    _ = try apply(&store, value, &key);
    value.guest = @splat(9);
    try std.testing.expectError(error.Capacity, apply(&store, value, &key));
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
}

fn allocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, contradictory_claim: bool) !void {
    var store = try Store.init(allocator, .{ .max_entries = 2 });
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    _ = try apply(&store, value, key);
    const original = store.entries.items[0].original;
    const generation = store.generation;
    if (contradictory_claim) {
        value.revision = 2;
        value.nick = "ConflictingNick";
    } else value.realname = "Conflicting";
    _ = apply(&store, value, key) catch |err| {
        try std.testing.expectEqual(original.ptr, store.entries.items[0].original.ptr);
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) != null);
        return err;
    };
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
}

test "mesh presence store allocation failures preserve published state" {
    var key = try sign.KeyPair.fromSeed(@splat(65));
    defer key.deinit();
    for ([_]bool{ false, true }) |contradictory_claim| try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationScenario, .{ &key, contradictory_claim });
}

test "mesh presence store collision winner is independent of arrival and renewals" {
    var first = try sign.KeyPair.fromSeed(@splat(66));
    defer first.deinit();
    var second = try sign.KeyPair.fromSeed(@splat(67));
    defer second.deinit();
    for ([_]bool{ false, true }) |reverse| {
        var store = try Store.init(std.testing.allocator, .{ .max_entries = 2 });
        defer store.deinit();
        var low = fixtureRecord(first.public_key, 1);
        var high = fixtureRecord(second.public_key, 1);
        low.claim_hlc = 8;
        high.claim_hlc = 9;
        if (reverse) {
            _ = try apply(&store, high, &second);
            _ = try apply(&store, low, &first);
        } else {
            _ = try apply(&store, low, &first);
            _ = try apply(&store, high, &second);
        }
        try std.testing.expectEqual(second.public_key, store.winner("guest", 1000, &.{ first.public_key, second.public_key }).?.decoded.record.origin);
        low.revision = 2;
        low.expires_ms = 3000;
        _ = try apply(&store, low, &first);
        try std.testing.expectEqual(second.public_key, store.winner("guest", 1000, &.{ first.public_key, second.public_key }).?.decoded.record.origin);
        // Expiry affects eligibility, not priority or original lease duration.
        try std.testing.expectEqual(first.public_key, store.winner("guest", 2000, &.{ first.public_key, second.public_key }).?.decoded.record.origin);
    }
}

test "mesh presence store rejects future claim and byte pressure before publication" {
    var key = try sign.KeyPair.fromSeed(@splat(68));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_bytes = wire.max_wire_len });
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    value.claim_hlc = @as(u64, 31_001) << 16;
    try std.testing.expectError(error.InvalidClaim, apply(&store, value, &key));
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    value.claim_hlc = 9;
    _ = try apply(&store, value, &key);
    const bytes = store.bytes;
    const generation = store.generation;
    // Configure pressure at the live byte cut; no implicit old-fact eviction.
    store.config.max_bytes = bytes;
    value.realname = "Longer conflicting wire";
    try std.testing.expectError(error.Capacity, apply(&store, value, &key));
    try std.testing.expectEqual(bytes, store.bytes);
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) != null);
}

test "mesh presence store alternate accepted signature is duplicate not equivocation" {
    const seed: sign.Seed = @splat(69);
    var key = try sign.KeyPair.fromSeed(seed);
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const value = fixtureRecord(key.public_key, 1);
    _ = try apply(&store, value, &key);
    const generation = store.generation;
    const held = store.entries.items[0].original;
    var buffer: [wire.max_wire_len]u8 = undefined;
    const original = try wire.encode(value, &key, &buffer);
    const body = original[0 .. original.len - sign.signature_len];
    const alt_magic = "onyx-ed25519ctx-v1";
    var transcript: [alt_magic.len + 1 + wire.domain.len + wire.max_wire_len]u8 = undefined;
    @memcpy(transcript[0..alt_magic.len], alt_magic);
    transcript[alt_magic.len] = @intCast(wire.domain.len);
    @memcpy(transcript[alt_magic.len + 1 ..][0..wire.domain.len], wire.domain);
    const prefix_len = alt_magic.len + 1 + wire.domain.len;
    @memcpy(transcript[prefix_len..][0..body.len], body);
    var alt_key = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&alt_key.secret_key));
    const signature = (try alt_key.sign(transcript[0 .. prefix_len + body.len], null)).toBytes();
    @memcpy(buffer[body.len..][0..sign.signature_len], &signature);
    try (try wire.decode(original)).verify();
    var prepared = try store.prepare(original, &.{key.public_key}, 1000);
    defer prepared.abort();
    try std.testing.expectEqual(Disposition.duplicate, prepared.commit());
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqual(held.ptr, store.entries.items[0].original.ptr);
    try std.testing.expect(store.entries.items[0].conflict == null);
    // A later approval cut cannot publish a formerly admitted key's identity.
    try std.testing.expect(store.winner("Guest", 1000, &.{}) == null);
}

test "mesh presence store current clock rollback revokes future identity" {
    var key = try sign.KeyPair.fromSeed(@splat(70));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 1);
    value.issued_ms = 100_000;
    value.expires_ms = 101_000;
    var buffer: [wire.max_wire_len]u8 = undefined;
    var prepared = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 100_000);
    defer prepared.abort();
    _ = prepared.commit();
    try std.testing.expect(store.winner("Guest", 100_000, &.{key.public_key}) != null);
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
}

test "mesh presence store reordered signed quit revokes contradictory newer present" {
    var key = try sign.KeyPair.fromSeed(@splat(71));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = fixtureRecord(key.public_key, 3);
    _ = try apply(&store, value, &key);
    value.revision = 2;
    value.operation = .quit;
    try std.testing.expectEqual(Disposition.quarantined, try apply(&store, value, &key));
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
}

fn cutRecord(origin: sign.PublicKey, revision: u64, through: u64, active: []const u64) frontier.Record {
    return .{ .origin = origin, .epoch = 3, .revision = revision, .through = through, .issued_ms = 1000, .active = active };
}

fn applyCut(store: *Store, record: frontier.Record, key: *const sign.KeyPair) !frontier.Update {
    const buffer = try store.allocator.alloc(u8, frontier.max_wire_len);
    defer store.allocator.free(buffer);
    var plan = try store.prepareFrontier(try frontier.encode(record, key, buffer), &.{key.public_key}, 1000);
    defer plan.abort();
    return plan.commit();
}

fn numberedRecord(origin: sign.PublicKey, counter: u64) !wire.Record {
    var record = fixtureRecord(origin, 1);
    record.guest = try wire.guestId(.{ .epoch = 3, .counter = counter });
    return record;
}

test "mesh presence store frontier atomic cut preserves active and foreign subjects" {
    var key = try sign.KeyPair.fromSeed(@splat(81));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(82));
    defer foreign.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 4 });
    defer store.deinit();
    const active = try numberedRecord(key.public_key, 1);
    const retired = try numberedRecord(key.public_key, 2);
    _ = try apply(&store, active, &key);
    _ = try apply(&store, retired, &key);
    _ = try apply(&store, try numberedRecord(foreign.public_key, 2), &foreign);
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    const cut = try frontier.encode(cutRecord(key.public_key, 1, 2, &.{1}), &key, buffer);
    const generation = store.generation;
    const bytes = store.bytes;
    var aborted = try store.prepareFrontier(cut, &.{key.public_key}, 1000);
    aborted.abort();
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqual(bytes, store.bytes);
    try std.testing.expectEqual(@as(usize, 3), store.entries.items.len);
    try std.testing.expectEqual(@as(usize, 0), store.frontiers.items.len);
    var plan = try store.prepareFrontier(cut, &.{key.public_key}, 1000);
    defer plan.abort();
    try std.testing.expectEqual(frontier.Update.advance, plan.commit());
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expect(store.subjectIndex(key.public_key, active.guest) != null);
    try std.testing.expect(store.subjectIndex(foreign.public_key, retired.guest) != null);
    try std.testing.expectEqualSlices(u8, cut, store.frontiers.items[0].original);
    try std.testing.expectError(error.RetiredSubject, apply(&store, retired, &key));
    var old_epoch = active;
    old_epoch.guest = try wire.guestId(.{ .epoch = 2, .counter = 1 });
    try std.testing.expectError(error.RetiredSubject, apply(&store, old_epoch, &key));
    // A rollback cannot erase the admitted negative proof.
    var presence_buffer: [wire.max_wire_len]u8 = undefined;
    try std.testing.expectError(error.RetiredSubject, store.prepare(try wire.encode(retired, &key, &presence_buffer), &.{key.public_key}, 0));
    const held = store.frontiers.items[0].original.ptr;
    const published_generation = store.generation;
    try std.testing.expectEqual(frontier.Update.duplicate, try applyCut(&store, cutRecord(key.public_key, 1, 2, &.{1}), &key));
    try std.testing.expectEqual(held, store.frontiers.items[0].original.ptr);
    try std.testing.expectEqual(published_generation, store.generation);
}

test "mesh presence store frontier quarantine survives later epochs and arrival order" {
    var key = try sign.KeyPair.fromSeed(@splat(83));
    defer key.deinit();
    for ([_]bool{ false, true }) |reverse| {
        var store = try Store.init(std.testing.allocator, .{});
        defer store.deinit();
        _ = try apply(&store, try numberedRecord(key.public_key, 1), &key);
        const older = cutRecord(key.public_key, 1, 3, &.{1});
        const newer = cutRecord(key.public_key, 2, 4, &.{ 1, 2 });
        _ = try applyCut(&store, if (reverse) newer else older, &key);
        try std.testing.expectEqual(frontier.Update.conflict, try applyCut(&store, if (reverse) older else newer, &key));
        try std.testing.expect(store.frontiers.items[0].conflict != null);
        try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
        const original = store.frontiers.items[0].original.ptr;
        const conflict = store.frontiers.items[0].conflict.?.ptr;
        const bytes = store.bytes;
        var cold = cutRecord(key.public_key, 1, 0, &.{});
        cold.epoch = 4;
        try std.testing.expectEqual(frontier.Update.conflict, try applyCut(&store, cold, &key));
        try std.testing.expectEqual(original, store.frontiers.items[0].original.ptr);
        try std.testing.expectEqual(conflict, store.frontiers.items[0].conflict.?.ptr);
        try std.testing.expectEqual(bytes, store.bytes);
        try std.testing.expectError(error.QuarantinedOrigin, apply(&store, try numberedRecord(key.public_key, 5), &key));
    }
}

test "mesh presence store frontier compaction retains subject conflict witnesses" {
    var key = try sign.KeyPair.fromSeed(@splat(84));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try numberedRecord(key.public_key, 2);
    _ = try apply(&store, value, &key);
    value.realname = "Equivocation";
    _ = try apply(&store, value, &key);
    const original = store.entries.items[0].original.ptr;
    const conflict = store.entries.items[0].conflict.?.ptr;
    _ = try applyCut(&store, cutRecord(key.public_key, 1, 2, &.{}), &key);
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
    try std.testing.expectEqual(original, store.entries.items[0].original.ptr);
    try std.testing.expectEqual(conflict, store.entries.items[0].conflict.?.ptr);
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
}

test "mesh presence store frontier pressure uses final cut without evicting origins" {
    var key = try sign.KeyPair.fromSeed(@splat(85));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(86));
    defer foreign.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 1, .max_origins = 1 });
    defer store.deinit();
    var value = try numberedRecord(key.public_key, 2);
    value.operation = .quit;
    value.revision = 2;
    _ = try apply(&store, value, &key);
    store.config.max_bytes = store.bytes;
    // Enough for final proof, though proof + old negative exceed the cut.
    _ = try applyCut(&store, cutRecord(key.public_key, 1, 2, &.{}), &key);
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expectEqual(store.frontiers.items[0].original.len, store.bytes);
    const generation = store.generation;
    try std.testing.expectError(error.Capacity, applyCut(&store, cutRecord(foreign.public_key, 1, 0, &.{}), &foreign));
    store.config.max_bytes = store.bytes;
    try std.testing.expectError(error.Capacity, applyCut(&store, cutRecord(key.public_key, 1, 2, &.{1}), &key));
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqual(@as(usize, 1), store.frontiers.items.len);
    try std.testing.expect(store.frontiers.items[0].conflict == null);
    try std.testing.expectError(error.RetiredSubject, apply(&store, value, &key));
}

fn frontierAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, conflict: bool) !void {
    var store = try Store.init(allocator, .{ .max_entries = 1, .max_origins = 1 });
    defer store.deinit();
    const value = try numberedRecord(key.public_key, 1);
    _ = try apply(&store, value, key);
    _ = try applyCut(&store, cutRecord(key.public_key, 1, 1, &.{1}), key);
    const original = store.frontiers.items[0].original.ptr;
    const subject_original = store.entries.items[0].original.ptr;
    const bytes = store.bytes;
    const generation = store.generation;
    const next = if (conflict) cutRecord(key.public_key, 1, 1, &.{}) else cutRecord(key.public_key, 2, 1, &.{});
    _ = applyCut(&store, next, key) catch |err| {
        try std.testing.expectEqual(original, store.frontiers.items[0].original.ptr);
        try std.testing.expectEqual(subject_original, store.entries.items[0].original.ptr);
        try std.testing.expectEqual(bytes, store.bytes);
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expect(store.frontiers.items[0].conflict == null);
        try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) != null);
        return err;
    };
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
    try std.testing.expectEqual(@as(usize, if (conflict) 1 else 0), store.entries.items.len);
    try std.testing.expectEqual(conflict, store.frontiers.items[0].conflict != null);
}

test "mesh presence store frontier allocation failures preserve entire published cut" {
    var key = try sign.KeyPair.fromSeed(@splat(87));
    defer key.deinit();
    for ([_]bool{ false, true }) |conflict| try std.testing.checkAllAllocationFailures(std.testing.allocator, frontierAllocationScenario, .{ &key, conflict });
}

test "mesh presence store frontier long lived counter permits bounded negative churn" {
    var key = try sign.KeyPair.fromSeed(@splat(88));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 2, .max_origins = 1 });
    defer store.deinit();
    _ = try apply(&store, try numberedRecord(key.public_key, 1), &key);
    for (2..42) |counter| {
        var retired = try numberedRecord(key.public_key, counter);
        retired.operation = .quit;
        retired.revision = 2;
        _ = try apply(&store, retired, &key);
        _ = try applyCut(&store, cutRecord(key.public_key, counter, counter, &.{1}), &key);
        try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
        try std.testing.expectEqual(@as(usize, 1), store.frontiers.items.len);
        retired.operation = .present;
        try std.testing.expectError(error.RetiredSubject, apply(&store, retired, &key));
        retired.operation = .quit;
        try std.testing.expectError(error.RetiredSubject, apply(&store, retired, &key));
    }
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) != null);
    // A new counter beyond the certified prefix is not invented by the cut,
    // but its independently signed presence remains eligible for admission.
    _ = try apply(&store, try numberedRecord(key.public_key, 42), &key);
    const original = store.frontiers.items[0].original.ptr;
    const generation = store.generation;
    const bytes = store.bytes;
    try std.testing.expectEqual(frontier.Update.obsolete, try applyCut(&store, cutRecord(key.public_key, 2, 2, &.{1}), &key));
    try std.testing.expectEqual(original, store.frontiers.items[0].original.ptr);
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqual(bytes, store.bytes);
    // Age does not expire a cut. Higher epoch can compact prior active rows.
    var cold = cutRecord(key.public_key, 1, 0, &.{});
    cold.epoch = 4;
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var plan = try store.prepareFrontier(try frontier.encode(cold, &key, buffer), &.{key.public_key}, std.math.maxInt(i64));
    defer plan.abort();
    _ = plan.commit();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expectError(error.RetiredSubject, apply(&store, try numberedRecord(key.public_key, 42), &key));
}

fn initialFrontierAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, original: []const u8) !void {
    var store = try Store.init(allocator, .{ .max_entries = 1, .max_origins = 1 });
    defer store.deinit();
    _ = try apply(&store, try numberedRecord(key.public_key, 1), key);
    const bytes = store.bytes;
    const generation = store.generation;
    const subject_original = store.entries.items[0].original.ptr;
    var plan = store.prepareFrontier(original, &.{key.public_key}, 1000) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), store.frontiers.items.len);
        try std.testing.expectEqual(subject_original, store.entries.items[0].original.ptr);
        try std.testing.expectEqual(bytes, store.bytes);
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) != null);
        return err;
    };
    defer plan.abort();
    _ = plan.commit();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expectEqualSlices(u8, original, store.frontiers.items[0].original);
}

test "mesh presence store first frontier allocation failures cannot lose subjects" {
    var key = try sign.KeyPair.fromSeed(@splat(89));
    defer key.deinit();
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    const original = try frontier.encode(cutRecord(key.public_key, 1, 1, &.{}), &key, buffer);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, initialFrontierAllocationScenario, .{ &key, original });
}

test "mesh presence store frontier abort replacement and conflict preserve exact cut" {
    var key = try sign.KeyPair.fromSeed(@splat(90));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 1, .max_origins = 1 });
    defer store.deinit();
    _ = try apply(&store, try numberedRecord(key.public_key, 1), &key);
    _ = try applyCut(&store, cutRecord(key.public_key, 1, 1, &.{1}), &key);
    const original = store.frontiers.items[0].original.ptr;
    const subject_original = store.entries.items[0].original.ptr;
    const bytes = store.bytes;
    const generation = store.generation;
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    for ([_]u64{ 1, 2 }) |revision| {
        const cut = try frontier.encode(cutRecord(key.public_key, revision, 1, &.{}), &key, buffer);
        var plan = try store.prepareFrontier(cut, &.{key.public_key}, 1000);
        plan.abort();
        try std.testing.expectEqual(original, store.frontiers.items[0].original.ptr);
        try std.testing.expectEqual(subject_original, store.entries.items[0].original.ptr);
        try std.testing.expectEqual(bytes, store.bytes);
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expect(store.frontiers.items[0].conflict == null);
    }
    const cut = try frontier.encode(cutRecord(key.public_key, 2, 1, &.{}), &key, buffer);
    try std.testing.expectError(error.UnapprovedOrigin, store.prepareFrontier(cut, &.{}, 1000));
    store.config.clock.max_future_skew_ms = 0;
    try std.testing.expectError(error.FutureIssued, store.prepareFrontier(cut, &.{key.public_key}, 0));
    buffer[cut.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, store.prepareFrontier(cut, &.{key.public_key}, 1000));
    try std.testing.expectEqual(generation, store.generation);
}

test "mesh presence store skipped rename round trip converges to latest claim" {
    var key = try sign.KeyPair.fromSeed(@splat(91));
    defer key.deinit();
    var complete = try Store.init(std.testing.allocator, .{});
    defer complete.deinit();
    var skipped = try Store.init(std.testing.allocator, .{});
    defer skipped.deinit();
    var value = try numberedRecord(key.public_key, 1);
    value.claim_hlc = 10;
    _ = try apply(&complete, value, &key);
    _ = try apply(&skipped, value, &key);
    value.revision = 2;
    value.nick = "Away";
    value.claim_hlc = 20;
    value.claim_revision = value.revision;
    _ = try apply(&complete, value, &key);
    value.revision = 3;
    value.nick = "Guest";
    value.claim_hlc = 30;
    value.claim_revision = value.revision;
    _ = try apply(&complete, value, &key);
    _ = try apply(&skipped, value, &key);
    try std.testing.expectEqual(@as(u64, 30), skipped.winner("Guest", 1000, &.{key.public_key}).?.decoded.record.claim_hlc);
    try std.testing.expectEqualSlices(u8, complete.entries.items[0].original, skipped.entries.items[0].original);
}

test "mesh presence store contradictory claim declarations quarantine in either order" {
    var key = try sign.KeyPair.fromSeed(@splat(93));
    defer key.deinit();
    // Same declaration with drifting HLC or nick; retroactive new declaration;
    // adjacent exact-nick priority increase with no room for an intervening rename.
    for (0..6) |kind| {
        var older = try numberedRecord(key.public_key, 1);
        older.revision = 3;
        var newer = older;
        newer.revision = 5;
        switch (kind) {
            0 => newer.claim_hlc += 1,
            1 => newer.nick = "NewNick",
            5 => newer.issued_ms -= 1,
            2, 3, 4 => {
                newer.claim_hlc += 1;
                newer.claim_revision = kind;
            },
            else => unreachable,
        }
        for ([_]bool{ false, true }) |reverse| {
            var store = try Store.init(std.testing.allocator, .{});
            defer store.deinit();
            _ = try apply(&store, if (reverse) newer else older, &key);
            try std.testing.expectEqual(Disposition.quarantined, try apply(&store, if (reverse) older else newer, &key));
            try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) == null);
            try std.testing.expect(store.winner("NewNick", 1000, &.{key.public_key}) == null);
            try std.testing.expect(store.entries.items[0].conflict != null);
            var later = newer;
            later.revision += 1;
            try std.testing.expectEqual(Disposition.quarantined, try apply(&store, later, &key));
        }
    }
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try numberedRecord(key.public_key, 1);
    value.revision = 3;
    _ = try apply(&store, value, &key);
    value.revision = 5;
    value.nick = "NewNick";
    value.claim_hlc += 1;
    value.claim_revision = 4;
    _ = try apply(&store, value, &key);
    value.revision = 6;
    _ = try apply(&store, value, &key);
    try std.testing.expectEqual(@as(u64, 4), store.winner("NewNick", 1000, &.{key.public_key}).?.decoded.record.claim_revision);
}

test "mesh presence store contradictory claim prepared abort preserves winner" {
    var key = try sign.KeyPair.fromSeed(@splat(94));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try numberedRecord(key.public_key, 1);
    _ = try apply(&store, value, &key);
    const original = store.entries.items[0].original.ptr;
    const bytes = store.bytes;
    const generation = store.generation;
    value.revision = 2;
    value.nick = "Contradiction";
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1000);
    try std.testing.expectEqual(Disposition.quarantined, plan.disposition);
    plan.abort();
    try std.testing.expectEqual(original, store.entries.items[0].original.ptr);
    try std.testing.expectEqual(bytes, store.bytes);
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expect(store.entries.items[0].conflict == null);
    try std.testing.expect(store.winner("Guest", 1000, &.{key.public_key}) != null);
}

test "mesh presence store expired quit repair retains terminal proof without positive admission" {
    var key = try sign.KeyPair.fromSeed(@splat(95));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try numberedRecord(key.public_key, 1);
    var buffer: [wire.max_wire_len]u8 = undefined;
    const positive = try wire.encode(value, &key, &buffer);
    try std.testing.expectError(error.Expired, store.prepare(positive, &.{key.public_key}, 3000));
    try std.testing.expectError(error.InvalidField, store.prepareQuitRepair(positive, &.{key.public_key}, 3000));
    value.operation = .quit;
    value.revision = 2;
    const original = try wire.encode(value, &key, &buffer);
    var repaired = try store.prepareQuitRepair(original, &.{key.public_key}, 3000);
    defer repaired.abort();
    try std.testing.expectEqual(Disposition.inserted, repaired.commit());
    try std.testing.expectEqualSlices(u8, original, store.entries.items[0].original);
    try std.testing.expect(store.winner("Guest", 3000, &.{key.public_key}) == null);
    // Subsequent valid positive lease cannot resurrect this exact subject.
    value.operation = .present;
    value.revision = 3;
    value.issued_ms = 3000;
    value.expires_ms = 4000;
    var resurrection = try store.prepare(try wire.encode(value, &key, &buffer), &.{key.public_key}, 3000);
    defer resurrection.abort();
    try std.testing.expectEqual(Disposition.quarantined, resurrection.disposition);
}

test "mesh presence store expired quit repair retains all nonexpiry admission checks" {
    var key = try sign.KeyPair.fromSeed(@splat(96));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try numberedRecord(key.public_key, 1);
    value.operation = .quit;
    value.revision = 2;
    var buffer: [wire.max_wire_len]u8 = undefined;
    const original = try wire.encode(value, &key, &buffer);
    try std.testing.expectError(error.UnapprovedOrigin, store.prepareQuitRepair(original, &.{}, 3000));
    try std.testing.expectError(error.InvalidClock, store.prepareQuitRepair(original, &.{key.public_key}, -1));
    buffer[original.len - 1] ^= 1;
    try std.testing.expectError(error.BadSignature, store.prepareQuitRepair(original, &.{key.public_key}, 3000));
    value.expires_ms = value.issued_ms + store.config.clock.max_lifetime_ms + 1;
    try std.testing.expectError(error.InvalidClock, store.prepareQuitRepair(try wire.encode(value, &key, &buffer), &.{key.public_key}, 200_000));
    value.issued_ms = 40_000;
    value.expires_ms = 41_000;
    try std.testing.expectError(error.FutureIssued, store.prepareQuitRepair(try wire.encode(value, &key, &buffer), &.{key.public_key}, 1000));
    value.issued_ms = 1000;
    value.expires_ms = 2000;
    value.claim_hlc = @as(u64, 40_000) << 16;
    try std.testing.expectError(error.InvalidClaim, store.prepareQuitRepair(try wire.encode(value, &key, &buffer), &.{key.public_key}, 3000));
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    _ = try applyCut(&store, cutRecord(key.public_key, 1, 1, &.{}), &key);
    value.claim_hlc = 9;
    try std.testing.expectError(error.RetiredSubject, store.prepareQuitRepair(try wire.encode(value, &key, &buffer), &.{key.public_key}, 3000));
}

fn quitRepairAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair) !void {
    var store = try Store.init(allocator, .{});
    defer store.deinit();
    var current = try numberedRecord(key.public_key, 1);
    current.revision = 3;
    current.expires_ms = 4000;
    _ = try apply(&store, current, key);
    const original = store.entries.items[0].original.ptr;
    const bytes = store.bytes;
    const generation = store.generation;
    var quit = current;
    quit.operation = .quit;
    quit.revision = 2;
    quit.expires_ms = 2000;
    var buffer: [wire.max_wire_len]u8 = undefined;
    var plan = store.prepareQuitRepair(try wire.encode(quit, key, &buffer), &.{key.public_key}, 3000) catch |err| {
        try std.testing.expectEqual(original, store.entries.items[0].original.ptr);
        try std.testing.expectEqual(bytes, store.bytes);
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expect(store.entries.items[0].conflict == null);
        try std.testing.expect(store.winner("Guest", 3000, &.{key.public_key}) != null);
        return err;
    };
    defer plan.abort();
    // Aborting repair cannot remove the still valid positive; committing its
    // independently prepared retry preserves both contradictory signed wires.
    plan.abort();
    try std.testing.expectEqual(original, store.entries.items[0].original.ptr);
    try std.testing.expectEqual(generation, store.generation);
    var retry = store.prepareQuitRepair(try wire.encode(quit, key, &buffer), &.{key.public_key}, 3000) catch |err| {
        try std.testing.expectEqual(original, store.entries.items[0].original.ptr);
        try std.testing.expectEqual(bytes, store.bytes);
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expect(store.entries.items[0].conflict == null);
        try std.testing.expect(store.winner("Guest", 3000, &.{key.public_key}) != null);
        return err;
    };
    defer retry.abort();
    try std.testing.expectEqual(Disposition.quarantined, retry.commit());
    try std.testing.expect(store.winner("Guest", 3000, &.{key.public_key}) == null);
}

test "mesh presence store expired quit repair allocation failures preserve live authority" {
    var key = try sign.KeyPair.fromSeed(@splat(97));
    defer key.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, quitRepairAllocationScenario, .{&key});
}

fn lifecycleRecord(origin: sign.PublicKey, counter: u64, revision: u64) !wire.Record {
    var value = fixtureRecord(origin, revision);
    value.guest = try wire.guestId(.{ .epoch = 1, .counter = counter });
    return value;
}
fn prepareLifecycleFixture(store: *Store, record: wire.Record, key: *const sign.KeyPair, frontier_revision: u64, through: u64, active: []const u64, now_ms: i64) !Store.PreparedLocalLifecycle {
    var original: [wire.max_wire_len]u8 = undefined;
    const proof_buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(proof_buffer);
    const subject_wire = try wire.encode(record, key, &original);
    const proof = try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = frontier_revision, .through = through, .issued_ms = now_ms, .active = active }, key, proof_buffer);
    return store.prepareLocalLifecycle(subject_wire, proof, key.public_key, &.{key.public_key}, now_ms);
}
fn applyLifecycleFixture(store: *Store, record: wire.Record, key: *const sign.KeyPair, frontier_revision: u64, through: u64, active: []const u64, now_ms: i64) !void {
    var plan = try prepareLifecycleFixture(store, record, key, frontier_revision, through, active, now_ms);
    defer plan.abort();
    _ = try store.project(.{ .local_lifecycle = &plan });
    plan.commit();
}
fn lifecycleStateHash(store: *const Store) [32]u8 {
    var hash = std.crypto.hash.Blake3.init(.{});
    for (store.entries.items) |entry| {
        hash.update(entry.original);
        hash.update(&(entry.admission.encode() catch unreachable));
        if (entry.conflict) |value| {
            hash.update(value);
            hash.update(&(entry.conflict_admission.?.encode() catch unreachable));
        }
    }
    for (store.frontiers.items) |item| {
        hash.update(item.original);
        hash.update(&(item.admission.encode() catch unreachable));
        if (item.conflict) |value| {
            hash.update(value);
            hash.update(&(item.conflict_admission.?.encode() catch unreachable));
        }
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

test "mesh presence local lifecycle full capacity registration fits only after certified GC" {
    var key = try sign.KeyPair.fromSeed(@splat(160));
    defer key.deinit();
    const value = try lifecycleRecord(key.public_key, 1, 1);
    const entry_len = try wire.encodedLen(value);
    const limit = entry_len * 2 + frontier.prefix_len + sign.signature_len + 2 * 8;
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 2, .max_origins = 1, .max_bytes = limit });
    defer store.deinit();
    _ = try apply(&store, value, &key);
    _ = try apply(&store, try lifecycleRecord(key.public_key, 2, 1), &key);
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var initial = try store.prepareFrontier(try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 2, .issued_ms = 1000, .active = &.{ 1, 2 } }, &key, buffer), &.{key.public_key}, 1000);
    defer initial.abort();
    _ = initial.commit();
    try std.testing.expectEqual(limit, store.bytes);
    const next = try lifecycleRecord(key.public_key, 3, 1);
    var original: [wire.max_wire_len]u8 = undefined;
    try std.testing.expectError(error.Capacity, store.prepare(try wire.encode(next, &key, &original), &.{key.public_key}, 1000));
    const before = lifecycleStateHash(&store);
    const generation = store.generation;
    var plan = try prepareLifecycleFixture(&store, next, &key, 2, 3, &.{ 2, 3 }, 1000);
    defer plan.abort();
    const projection = try store.project(.{ .local_lifecycle = &plan });
    try std.testing.expectEqual(@as(usize, 2), projection.final_entry_count);
    try std.testing.expectEqual(@as(usize, 1), projection.final_frontier_count);
    try std.testing.expectEqual(limit, projection.final_bytes);
    try std.testing.expect(projection.candidate_survives);
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    var entries = projection.entries();
    try std.testing.expectEqual(@as(u64, 2), (try wire.subject(entries.next().?.decoded.record.guest)).counter);
    try std.testing.expectEqual(@as(u64, 3), (try wire.subject(entries.next().?.decoded.record.guest)).counter);
    try std.testing.expect(entries.next() == null);
    plan.commit();
    try std.testing.expectEqual(generation + 1, store.generation);
    try std.testing.expectEqual(limit, store.bytes);
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expectEqual(@as(u64, 2), (try wire.subject(store.entries.items[0].decoded.record.guest)).counter);
    try std.testing.expectEqual(@as(u64, 3), (try wire.subject(store.entries.items[1].decoded.record.guest)).counter);
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
}

test "mesh presence local lifecycle renewal replaces original index after earlier GC" {
    var key = try sign.KeyPair.fromSeed(@splat(161));
    defer key.deinit();
    const value = try lifecycleRecord(key.public_key, 1, 1);
    const entry_len = try wire.encodedLen(value);
    const limit = entry_len * 3 + frontier.prefix_len + sign.signature_len + 3 * 8;
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 3, .max_origins = 1, .max_bytes = limit });
    defer store.deinit();
    for (1..4) |counter| _ = try apply(&store, try lifecycleRecord(key.public_key, counter, 1), &key);
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var initial = try store.prepareFrontier(try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 3, .issued_ms = 1000, .active = &.{ 1, 2, 3 } }, &key, buffer), &.{key.public_key}, 1000);
    defer initial.abort();
    _ = initial.commit();
    var renewed = try lifecycleRecord(key.public_key, 3, 2);
    renewed.realname = "A longer renewed public identity that exceeds the full predecessor byte quota until another subject is retired";
    renewed.issued_ms = 1100;
    renewed.expires_ms = 2200;
    var original: [wire.max_wire_len]u8 = undefined;
    try std.testing.expectError(error.Capacity, store.prepare(try wire.encode(renewed, &key, &original), &.{key.public_key}, 1100));
    var plan = try prepareLifecycleFixture(&store, renewed, &key, 2, 3, &.{ 2, 3 }, 1100);
    defer plan.abort();
    try std.testing.expectEqual(@as(usize, 2), plan.subject_index);
    const projected = try store.project(.{ .local_lifecycle = &plan });
    try std.testing.expect(projected.final_bytes <= limit);
    plan.commit();
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expectEqual(@as(u64, 2), (try wire.subject(store.entries.items[0].decoded.record.guest)).counter);
    try std.testing.expectEqual(@as(u64, 3), (try wire.subject(store.entries.items[1].decoded.record.guest)).counter);
    try std.testing.expectEqual(@as(u64, 2), store.entries.items[1].decoded.record.revision);
    try std.testing.expectEqualStrings(renewed.realname, store.entries.items[1].decoded.record.realname);
    try std.testing.expectEqual(@as(i64, 1100), store.entries.items[1].admission.admitted_at_ms);
}

test "mesh presence local lifecycle renew rename skipped return and collected quit are one cut" {
    var key = try sign.KeyPair.fromSeed(@splat(162));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try lifecycleRecord(key.public_key, 1, 1);
    try applyLifecycleFixture(&store, value, &key, 1, 1, &.{1}, 1000);
    const initial_generation = store.generation;
    value.revision = 2;
    value.issued_ms = 1100;
    value.expires_ms = 2300;
    try applyLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 1100);
    try std.testing.expectEqual(@as(u64, 1), store.entries.items[0].decoded.record.claim_revision);
    // A skipped Guest -> Other -> Guest pair is a valid newer claim, with no
    // invented intermediate body or borrowed proof from another physical ID.
    value.revision = 4;
    value.claim_revision = 4;
    value.claim_hlc = 10;
    value.issued_ms = 1200;
    try applyLifecycleFixture(&store, value, &key, 3, 1, &.{1}, 1200);
    value.revision = 5;
    value.claim_revision = 5;
    value.claim_hlc = 11;
    value.nick = "Other";
    value.issued_ms = 1300;
    try applyLifecycleFixture(&store, value, &key, 4, 1, &.{1}, 1300);
    try std.testing.expect(store.winner("Guest", 1300, &.{key.public_key}) == null);
    try std.testing.expect(store.winner("Other", 1300, &.{key.public_key}) != null);
    value.operation = .quit;
    value.revision = 6;
    value.issued_ms = 1400;
    var quit = try prepareLifecycleFixture(&store, value, &key, 5, 1, &.{}, 1400);
    defer quit.abort();
    try std.testing.expect(quit.subject_candidate.?.decoded.record.operation == .quit);
    try std.testing.expect(!quit.candidate_survives);
    const projection = try store.project(.{ .local_lifecycle = &quit });
    try std.testing.expectEqual(@as(usize, 0), projection.final_entry_count);
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
    quit.commit();
    try std.testing.expectEqual(initial_generation + 4, store.generation);
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expect(store.frontiers.items[0].decoded.retires(key.public_key, 1, 1));
    var original: [wire.max_wire_len]u8 = undefined;
    value.operation = .present;
    value.revision = 7;
    try std.testing.expectError(error.RetiredSubject, store.prepare(try wire.encode(value, &key, &original), &.{key.public_key}, 1400));
    try std.testing.expectError(error.RetiredSubject, prepareLifecycleFixture(&store, value, &key, 6, 1, &.{1}, 1400));
}

test "mesh presence local lifecycle rejects invalid inventory obsolete contradiction and wrong origin" {
    var key = try sign.KeyPair.fromSeed(@splat(163));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(164));
    defer foreign.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try lifecycleRecord(key.public_key, 1, 2);
    try applyLifecycleFixture(&store, value, &key, 1, 1, &.{1}, 1000);
    const before = lifecycleStateHash(&store);
    const generation = store.generation;
    value.revision = 3;
    value.issued_ms = 1100;
    value.expires_ms = 2200;
    try std.testing.expectError(error.InvalidLocalLifecycle, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{}, 1100));
    value.operation = .quit;
    try std.testing.expectError(error.InvalidLocalLifecycle, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 1100));
    try std.testing.expectError(error.InvalidLocalLifecycle, prepareLifecycleFixture(&store, value, &key, 2, 0, &.{}, 1100));
    value = try lifecycleRecord(key.public_key, 1, 1);
    try std.testing.expectError(error.InvalidLocalLifecycle, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 1000));
    value.revision = 2;
    value.realname = "Contradictory same revision";
    try std.testing.expectError(error.InvalidLocalLifecycle, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 1000));
    var original: [wire.max_wire_len]u8 = undefined;
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    const proof = try frontier.encode(.{ .origin = foreign.public_key, .epoch = 1, .revision = 1, .through = 1, .issued_ms = 1000, .active = &.{1} }, &foreign, buffer);
    try std.testing.expectError(error.InvalidLocalLifecycle, store.prepareLocalLifecycle(try wire.encode(value, &key, &original), proof, key.public_key, &.{ key.public_key, foreign.public_key }, 1000));
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    try std.testing.expect(store.entries.items[0].conflict == null);
    try std.testing.expect(store.frontiers.items[0].conflict == null);
}

test "mesh presence local lifecycle preserves prior subject conflict through certified GC" {
    var key = try sign.KeyPair.fromSeed(@splat(165));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var value = try lifecycleRecord(key.public_key, 1, 1);
    _ = try apply(&store, value, &key);
    value.realname = "Original signed fork";
    _ = try apply(&store, value, &key);
    const original_hash = retainedWitnessHash(store.entries.items[0]);
    var plan = try prepareLifecycleFixture(&store, try lifecycleRecord(key.public_key, 2, 1), &key, 1, 2, &.{2}, 1000);
    defer plan.abort();
    const projection = try store.project(.{ .local_lifecycle = &plan });
    try std.testing.expectEqual(@as(usize, 2), projection.final_entry_count);
    plan.commit();
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expect(store.frontiers.items[0].decoded.retires(key.public_key, 1, 1));
    try std.testing.expect(store.entries.items[0].conflict != null);
    try std.testing.expectEqualSlices(u8, &original_hash, &retainedWitnessHash(store.entries.items[0]));
    try std.testing.expectError(error.RetiredSubject, prepareLifecycleFixture(&store, value, &key, 2, 2, &.{ 1, 2 }, 1000));
    // Full-origin quarantine similarly remains irreversible and blocks local
    // lifecycle admission; the compound cut must not clear its witness.
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var fork = try store.prepareFrontier(try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 2, .issued_ms = 1000, .active = &.{} }, &key, buffer), &.{key.public_key}, 1000);
    defer fork.abort();
    _ = fork.commit();
    const before = lifecycleStateHash(&store);
    try std.testing.expectError(error.QuarantinedOrigin, prepareLifecycleFixture(&store, try lifecycleRecord(key.public_key, 2, 2), &key, 2, 2, &.{2}, 1000));
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
}
fn retainedWitnessHash(entry: Entry) [32]u8 {
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update(entry.original);
    hash.update(&(entry.admission.encode() catch unreachable));
    if (entry.conflict) |value| {
        hash.update(value);
        hash.update(&(entry.conflict_admission.?.encode() catch unreachable));
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

test "mesh presence local lifecycle abort stale generation forged indices and caches are fail closed" {
    var key = try sign.KeyPair.fromSeed(@splat(166));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(167));
    defer foreign.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    var other = try Store.init(std.testing.allocator, .{});
    defer other.deinit();
    _ = try apply(&store, try lifecycleRecord(foreign.public_key, 1, 1), &foreign);
    try applyLifecycleFixture(&store, try lifecycleRecord(key.public_key, 1, 1), &key, 1, 1, &.{1}, 1000);
    const before = lifecycleStateHash(&store);
    const generation = store.generation;
    var value = try lifecycleRecord(key.public_key, 1, 2);
    value.issued_ms = 1100;
    var plan = try prepareLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 1100);
    defer plan.abort();
    try std.testing.expectError(error.InvalidPlan, other.project(.{ .local_lifecycle = &plan }));
    plan.generation += 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.generation -= 1;
    const index = plan.subject_index;
    plan.subject_index = 0; // The foreign row has the same public counter.
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.subject_index = index;
    plan.frontier_index = store.frontiers.items.len + 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.frontier_index = 0;
    plan.final_bytes += 1;
    try std.testing.expectError(error.AccountingMismatch, store.project(.{ .local_lifecycle = &plan }));
    plan.final_bytes -= 1;
    plan.final_entry_count += 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.final_entry_count -= 1;
    plan.candidate_survives = false;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.candidate_survives = true;
    plan.subject_candidate.?.decoded.record.guest[15] ^= 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.subject_candidate.?.decoded.record.guest[15] ^= 1;
    plan.frontier_candidate.?.decoded.through += 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.frontier_candidate.?.decoded.through -= 1;
    store.entries.items[0].decoded.record.guest[15] ^= 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    store.entries.items[0].decoded.record.guest[15] ^= 1;
    _ = try store.project(.{ .local_lifecycle = &plan });
    plan.abort();
    plan.abort();
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    try std.testing.expectEqual(generation, store.generation);
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    store.generation = std.math.maxInt(u64);
    try std.testing.expectError(error.GenerationExhausted, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 1100));
    store.generation = generation;
}

test "mesh presence local lifecycle refuses final quotas and admits only true expired quit repair" {
    var key = try sign.KeyPair.fromSeed(@splat(168));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 1, .max_origins = 1 });
    defer store.deinit();
    try applyLifecycleFixture(&store, try lifecycleRecord(key.public_key, 1, 1), &key, 1, 1, &.{1}, 1000);
    const before = lifecycleStateHash(&store);
    try std.testing.expectError(error.Capacity, prepareLifecycleFixture(&store, try lifecycleRecord(key.public_key, 2, 1), &key, 2, 2, &.{ 1, 2 }, 1000));
    var value = try lifecycleRecord(key.public_key, 1, 2);
    try std.testing.expectError(error.Expired, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{1}, 2100));
    value.operation = .quit;
    value.expires_ms = 200_000; // Repair still enforces lifetime bounds.
    try std.testing.expectError(error.InvalidClock, prepareLifecycleFixture(&store, value, &key, 2, 1, &.{}, 2100));
    value.expires_ms = 2000;
    var quit = try prepareLifecycleFixture(&store, value, &key, 2, 1, &.{}, 2100);
    defer quit.abort();
    try std.testing.expectEqual(@FieldType(AdmissionStamp, "mode").expired_quit_repair, quit.subject_candidate.?.admission.mode);
    try std.testing.expect(!quit.candidate_survives);
    _ = try store.project(.{ .local_lifecycle = &quit });
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    quit.commit();
    try std.testing.expectEqual(@as(usize, 0), store.entries.items.len);
    try std.testing.expect(store.frontiers.items[0].decoded.retires(key.public_key, 1, 1));
}

test "mesh presence local lifecycle duplicate retains expected subject key before durable publication" {
    var key = try sign.KeyPair.fromSeed(@splat(169));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{});
    defer store.deinit();
    const first = try lifecycleRecord(key.public_key, 1, 1);
    try applyLifecycleFixture(&store, first, &key, 1, 1, &.{1}, 1000);
    try applyLifecycleFixture(&store, try lifecycleRecord(key.public_key, 2, 1), &key, 2, 2, &.{ 1, 2 }, 1000);
    var plan = try prepareLifecycleFixture(&store, first, &key, 3, 2, &.{ 1, 2 }, 1000);
    defer plan.abort();
    try std.testing.expectEqual(Disposition.duplicate, plan.subject_disposition);
    try std.testing.expect(plan.subject_candidate == null);
    const index = plan.subject_index;
    plan.subject_index = 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycle = &plan }));
    plan.subject_index = index;
    _ = try store.project(.{ .local_lifecycle = &plan });
    plan.commit();
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expectEqual(@as(u64, 1), (try wire.subject(store.entries.items[0].decoded.record.guest)).counter);
}

fn lifecycleAllocationScenario(allocator: std.mem.Allocator, key: *const sign.KeyPair, mode: u8) !void {
    const value = try lifecycleRecord(key.public_key, 1, 1);
    const entry_len = try wire.encodedLen(value);
    const limit = entry_len * 2 + frontier.prefix_len + sign.signature_len + 2 * 8;
    var store = try Store.init(allocator, .{ .max_entries = 2, .max_origins = 1, .max_bytes = limit });
    defer store.deinit();
    _ = try apply(&store, value, key);
    _ = try apply(&store, try lifecycleRecord(key.public_key, 2, 1), key);
    const buffer = try std.testing.allocator.alloc(u8, frontier.max_wire_len);
    defer std.testing.allocator.free(buffer);
    var initial = try store.prepareFrontier(try frontier.encode(.{ .origin = key.public_key, .epoch = 1, .revision = 1, .through = 2, .issued_ms = 1000, .active = &.{ 1, 2 } }, key, buffer), &.{key.public_key}, 1000);
    defer initial.abort();
    _ = initial.commit();
    var next = try lifecycleRecord(key.public_key, if (mode == 0) 3 else 2, if (mode == 0) 1 else 2);
    if (mode == 1) {
        next.realname = "A larger renewal that fits the exact final cut after collection";
        next.issued_ms = 1100;
        next.expires_ms = 2200;
    }
    if (mode == 2) next.operation = .quit;
    const through: u64 = if (mode == 0) 3 else 2;
    const active: []const u64 = if (mode == 0) &.{ 2, 3 } else if (mode == 1) &.{2} else &.{};
    const now_ms: i64 = if (mode == 2) 2100 else 1100;
    const before = lifecycleStateHash(&store);
    const generation = store.generation;
    const old_bytes = store.bytes;
    var plan = prepareLifecycleFixture(&store, next, key, 2, through, active, now_ms) catch |err| {
        try std.testing.expectEqual(generation, store.generation);
        try std.testing.expectEqual(old_bytes, store.bytes);
        try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
        if (err == error.OutOfMemory) {
            // Retry only preparation with a separate allocator. The immutable
            // predecessor still owns its original failing-allocator buffers.
            const previous_allocator = store.allocator;
            store.allocator = std.testing.allocator;
            defer store.allocator = previous_allocator;
            var retry = try prepareLifecycleFixture(&store, next, key, 2, through, active, now_ms);
            defer retry.abort();
            const projected = try store.project(.{ .local_lifecycle = &retry });
            try std.testing.expectEqual(@as(usize, if (mode == 0) 2 else if (mode == 1) 1 else 0), projected.final_entry_count);
        }
        return err;
    };
    defer plan.abort();
    const projection = try store.project(.{ .local_lifecycle = &plan });
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    try std.testing.expectEqual(@as(usize, if (mode == 0) 2 else if (mode == 1) 1 else 0), projection.final_entry_count);
    plan.commit();
    try std.testing.expectEqual(generation + 1, store.generation);
    try std.testing.expectEqual(projection.final_entry_count, store.entries.items.len);
    try std.testing.expectEqual(projection.final_bytes, store.bytes);
    if (mode == 2) try std.testing.expect(store.frontiers.items[0].decoded.retires(key.public_key, 1, 2));
}

test "mesh presence local lifecycle exhaustive allocation failure preserves registration renewal quit and retry" {
    var key = try sign.KeyPair.fromSeed(@splat(170));
    defer key.deinit();
    for (0..3) |mode| try std.testing.checkAllAllocationFailures(std.testing.allocator, lifecycleAllocationScenario, .{ &key, @as(u8, @intCast(mode)) });
}

fn groupCutRecord(origin: sign.PublicKey, revision: u64, through: u64, active: []const u64) frontier.Record {
    return .{ .origin = origin, .epoch = 1, .revision = revision, .through = through, .issued_ms = 1000, .active = active };
}

test "mesh presence group store capacity checks final two replacements over unchanged old cut" {
    var key = try sign.KeyPair.fromSeed(@splat(171));
    defer key.deinit();
    const value = try lifecycleRecord(key.public_key, 1, 1);
    const limit = (try wire.encodedLen(value)) * 2 + frontier.prefix_len + sign.signature_len + 2 * 8;
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 2, .max_origins = 1, .max_bytes = limit });
    defer store.deinit();
    _ = try apply(&store, value, &key);
    _ = try apply(&store, try lifecycleRecord(key.public_key, 2, 1), &key);
    _ = try applyCut(&store, groupCutRecord(key.public_key, 1, 2, &.{ 1, 2 }), &key);
    var a_buffer: [wire.max_wire_len]u8 = undefined;
    var b_buffer: [wire.max_wire_len]u8 = undefined;
    var proof_buffer: [frontier.prefix_len + sign.signature_len + 16]u8 = undefined;
    const a = try wire.encode(try lifecycleRecord(key.public_key, 3, 1), &key, &a_buffer);
    const b = try wire.encode(try lifecycleRecord(key.public_key, 4, 1), &key, &b_buffer);
    const cut = try frontier.encode(groupCutRecord(key.public_key, 2, 4, &.{ 3, 4 }), &key, &proof_buffer);
    try std.testing.expectError(error.Capacity, store.prepare(a, &.{key.public_key}, 1000));
    const before = lifecycleStateHash(&store);
    const generation = store.generation;
    var plan = try store.prepareLocalLifecycles(&.{ a, b }, cut, key.public_key, &.{key.public_key}, 1000);
    defer plan.deinit();
    const projection = try store.project(.{ .local_lifecycles = &plan });
    try std.testing.expectEqual(@as(usize, 2), projection.final_entry_count);
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    plan.commit();
    try std.testing.expectEqual(generation + 1, store.generation);
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expectEqualSlices(u8, a, store.entries.items[0].original);
    try std.testing.expectEqualSlices(u8, b, store.entries.items[1].original);
    try std.testing.expect(store.frontiers.items[0].decoded.retires(key.public_key, 1, 1));
    try std.testing.expect(store.frontiers.items[0].decoded.retires(key.public_key, 1, 2));
    try std.testing.expectEqualSlices(u8, a, plan.subjects[0].original);
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycles = &plan }));
}

test "mesh presence group store mixed quit renewal owns terminal evidence and rejects forged mappings" {
    var key = try sign.KeyPair.fromSeed(@splat(172));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 2, .max_origins = 1 });
    defer store.deinit();
    _ = try apply(&store, try lifecycleRecord(key.public_key, 1, 1), &key);
    _ = try apply(&store, try lifecycleRecord(key.public_key, 2, 1), &key);
    _ = try applyCut(&store, groupCutRecord(key.public_key, 1, 2, &.{ 1, 2 }), &key);
    var a_buffer: [wire.max_wire_len]u8 = undefined;
    var b_buffer: [wire.max_wire_len]u8 = undefined;
    var proof_buffer: [frontier.prefix_len + sign.signature_len + 8]u8 = undefined;
    var quit = try lifecycleRecord(key.public_key, 1, 2);
    quit.operation = .quit;
    const a = try wire.encode(quit, &key, &a_buffer);
    const b = try wire.encode(try lifecycleRecord(key.public_key, 2, 2), &key, &b_buffer);
    const cut = try frontier.encode(groupCutRecord(key.public_key, 2, 2, &.{2}), &key, &proof_buffer);
    const before = lifecycleStateHash(&store);
    var plan = try store.prepareLocalLifecycles(&.{ a, b }, cut, key.public_key, &.{key.public_key}, 1000);
    defer plan.deinit();
    plan.subjects[0].index = 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycles = &plan }));
    plan.subjects[0].index = 0;
    plan.replacements[0] = 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycles = &plan }));
    plan.replacements[0] = 0;
    plan.subjects[1].original[plan.subjects[1].original.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycles = &plan }));
    plan.subjects[1].original[plan.subjects[1].original.len - 1] ^= 1;
    plan.final_bytes += 1;
    try std.testing.expectError(error.AccountingMismatch, store.project(.{ .local_lifecycles = &plan }));
    plan.final_bytes -= 1;
    plan.generation += 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycles = &plan }));
    plan.generation -= 1;
    var other = try Store.init(std.testing.allocator, .{});
    defer other.deinit();
    try std.testing.expectError(error.InvalidPlan, other.project(.{ .local_lifecycles = &plan }));
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    _ = try store.project(.{ .local_lifecycles = &plan });
    plan.commit();
    try std.testing.expectEqual(@as(usize, 1), store.entries.items.len);
    try std.testing.expectEqualSlices(u8, b, store.entries.items[0].original);
    try std.testing.expectEqualSlices(u8, a, plan.subjects[0].original);
    try (try wire.decode(plan.subjects[0].original)).verify();
    plan.deinit();
    plan.deinit();
}

test "mesh presence group store duplicate and later obsolete retired equivocal members reject entire old cut" {
    var key = try sign.KeyPair.fromSeed(@splat(173));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 3, .max_origins = 1 });
    defer store.deinit();
    _ = try apply(&store, try lifecycleRecord(key.public_key, 1, 2), &key);
    _ = try apply(&store, try lifecycleRecord(key.public_key, 2, 2), &key);
    _ = try applyCut(&store, groupCutRecord(key.public_key, 1, 3, &.{ 1, 2 }), &key);
    var a_buffer: [wire.max_wire_len]u8 = undefined;
    var b_buffer: [wire.max_wire_len]u8 = undefined;
    var proof_buffer: [frontier.prefix_len + sign.signature_len + 16]u8 = undefined;
    const a = try wire.encode(try lifecycleRecord(key.public_key, 1, 3), &key, &a_buffer);
    const cut = try frontier.encode(groupCutRecord(key.public_key, 2, 3, &.{ 1, 2 }), &key, &proof_buffer);
    const before = lifecycleStateHash(&store);
    try std.testing.expectError(error.InvalidLocalLifecycle, store.prepareLocalLifecycles(&.{ a, a }, cut, key.public_key, &.{key.public_key}, 1000));
    const obsolete = try wire.encode(try lifecycleRecord(key.public_key, 2, 1), &key, &b_buffer);
    try std.testing.expectError(error.InvalidLocalLifecycle, store.prepareLocalLifecycles(&.{ a, obsolete }, cut, key.public_key, &.{key.public_key}, 1000));
    const retired = try wire.encode(try lifecycleRecord(key.public_key, 3, 1), &key, &b_buffer);
    try std.testing.expectError(error.RetiredSubject, store.prepareLocalLifecycles(&.{ a, retired }, cut, key.public_key, &.{key.public_key}, 1000));
    var fork = try lifecycleRecord(key.public_key, 2, 2);
    fork.realname = "Fork";
    const equivocal = try wire.encode(fork, &key, &b_buffer);
    try std.testing.expectError(error.InvalidLocalLifecycle, store.prepareLocalLifecycles(&.{ a, equivocal }, cut, key.public_key, &.{key.public_key}, 1000));
    try std.testing.expectEqualSlices(u8, &before, &lifecycleStateHash(&store));
    try std.testing.expectEqual(@as(usize, 2), store.entries.items.len);
    try std.testing.expect(store.entries.items[1].conflict == null);
}

test "mesh presence group store duplicate no candidate cannot retarget sibling and conflict witnesses survive GC" {
    var key = try sign.KeyPair.fromSeed(@splat(174));
    defer key.deinit();
    var store = try Store.init(std.testing.allocator, .{ .max_entries = 3, .max_origins = 1 });
    defer store.deinit();
    _ = try apply(&store, try lifecycleRecord(key.public_key, 1, 1), &key);
    _ = try apply(&store, try lifecycleRecord(key.public_key, 2, 1), &key);
    _ = try applyCut(&store, groupCutRecord(key.public_key, 1, 2, &.{ 1, 2 }), &key);
    var a_buffer: [wire.max_wire_len]u8 = undefined;
    var b_buffer: [wire.max_wire_len]u8 = undefined;
    var proof_buffer: [frontier.prefix_len + sign.signature_len + 16]u8 = undefined;
    const a = try wire.encode(try lifecycleRecord(key.public_key, 1, 1), &key, &a_buffer);
    const b = try wire.encode(try lifecycleRecord(key.public_key, 2, 1), &key, &b_buffer);
    const cut = try frontier.encode(groupCutRecord(key.public_key, 2, 2, &.{ 1, 2 }), &key, &proof_buffer);
    var duplicate = try store.prepareLocalLifecycles(&.{ a, b }, cut, key.public_key, &.{key.public_key}, 1000);
    try std.testing.expect(duplicate.subjects[0].candidate == null);
    duplicate.subjects[0].index = 1;
    try std.testing.expectError(error.InvalidPlan, store.project(.{ .local_lifecycles = &duplicate }));
    duplicate.subjects[0].index = 0;
    duplicate.deinit();
    var fork = try lifecycleRecord(key.public_key, 1, 1);
    fork.realname = "Conflict";
    try std.testing.expectEqual(Disposition.quarantined, try apply(&store, fork, &key));
    const original = store.entries.items[0].original;
    const conflict = store.entries.items[0].conflict.?;
    const first_stamp = store.entries.items[0].admission;
    const conflict_stamp = store.entries.items[0].conflict_admission.?;
    const next_a = try wire.encode(try lifecycleRecord(key.public_key, 3, 1), &key, &a_buffer);
    const next_b = try wire.encode(try lifecycleRecord(key.public_key, 4, 1), &key, &b_buffer);
    const next_cut = try frontier.encode(groupCutRecord(key.public_key, 2, 4, &.{ 3, 4 }), &key, &proof_buffer);
    var plan = try store.prepareLocalLifecycles(&.{ next_a, next_b }, next_cut, key.public_key, &.{key.public_key}, 1000);
    defer plan.deinit();
    _ = try store.project(.{ .local_lifecycles = &plan });
    plan.commit();
    try std.testing.expectEqual(@as(usize, 3), store.entries.items.len);
    try std.testing.expectEqualSlices(u8, original, store.entries.items[0].original);
    try std.testing.expectEqualSlices(u8, conflict, store.entries.items[0].conflict.?);
    try std.testing.expectEqualDeep(first_stamp, store.entries.items[0].admission);
    try std.testing.expectEqualDeep(conflict_stamp, store.entries.items[0].conflict_admission.?);
    try std.testing.expectEqual(@as(u64, 3), (try wire.subject(store.entries.items[1].decoded.record.guest)).counter);
    try std.testing.expectEqual(@as(u64, 4), (try wire.subject(store.entries.items[2].decoded.record.guest)).counter);
}
