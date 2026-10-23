// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed resource-namespace adapter for the concrete store owner.

const EngineAccess = @import("engine.zig").Internal;
const std = @import("std");
const OwnedMutation = @import("changefeed.zig").OwnedMutation;
const BatchMutation = @import("contracts.zig").BatchMutation;
const Config = @import("contracts.zig").Config;
const Family = @import("contracts.zig").Family;
const batch_format_version = @import("contracts.zig").batch_format_version;
const batch_guard_len = @import("contracts.zig").batch_guard_len;
const families = @import("contracts.zig").families;
const familyIndex = @import("contracts.zig").familyIndex;
const family_count = @import("contracts.zig").family_count;
const max_batch_mutations = @import("contracts.zig").max_batch_mutations;
const meta_kind_batch = @import("contracts.zig").meta_kind_batch;
const record_header_len = @import("contracts.zig").record_header_len;
const BatchEntry = @import("engine.zig").BatchEntry;
const PreparedPut = @import("engine.zig").PreparedPut;
const AllocatorObservation = @import("source_owner.zig").AllocatorObservation;
const ReadLease = @import("source_owner.zig").ReadLease;
const SourceIdentity = @import("source_owner.zig").SourceIdentity;
const StoreExclusive = @import("source_owner.zig").StoreExclusive;
const StoreOwnerBacking = @import("source_owner.zig").StoreOwnerBacking;
const StoreResourceOwner = @import("source_owner.zig").StoreResourceOwner;
const createStoreResourceOwnerReserved = @import("source_owner.zig").createStoreResourceOwnerReserved;
const destroyStoreResourceOwner = @import("source_owner.zig").destroyStoreResourceOwner;
const ownerBacking = @import("source_owner.zig").ownerBacking;
const reserveOwnerLifetime = @import("source_owner.zig").reserveOwnerLifetime;
const observeAllocator = @import("source_owner.zig").observeAllocator;
const validateSourceExclusive = @import("source_owner.zig").validateExclusive;
const KvTable = @import("table.zig").KvTable;
const test_fixture = if (@import("builtin").is_test) @import("test_fixture.zig") else struct {};
const checkedPayloadLen = @import("wal.zig").checkedPayloadLen;
const checksum = @import("wal.zig").checksum;
const decodeBatch = @import("wal.zig").decodeBatch;
const encodeBatchGuard = @import("wal.zig").encodeBatchGuard;
const encodeMutation = @import("wal.zig").encodeMutation;
const readU32 = @import("wal.zig").readU32;
const writeU32 = @import("wal.zig").writeU32;

// S2 closed source bridge. Public methods exist only for the canonical static
// Physical -> Store adapter. They never export a Store or an original backend.
pub const CreationArgs = struct {
    metadata_allocator: std.mem.Allocator,
    store_allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    config: Config,
    read_only: bool = false,
};

pub const CreationIdentity = struct {
    metadata_allocator: AllocatorObservation,
    store_allocator: AllocatorObservation,
    io_context: usize,
    io_vtable: usize,
    directory: @FieldType(std.Io.Dir, "handle"),
    path_digest: [32]u8,
    path_length: usize,
    config: Config,
    read_only: bool,
    pub fn from(args: CreationArgs) CreationIdentity {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(args.path, &digest, .{});
        return .{ .metadata_allocator = observeAllocator(args.metadata_allocator), .store_allocator = observeAllocator(args.store_allocator), .io_context = if (args.io.userdata) |p| @intFromPtr(p) else 0, .io_vtable = @intFromPtr(args.io.vtable), .directory = args.dir.handle, .path_digest = digest, .path_length = args.path.len, .config = args.config, .read_only = args.read_only };
    }
};

pub const CandidateUse = enum { packet, new_key, scratch_key, value, feed_key, feed_value, table_backing };

pub const RootKey = struct {
    pub const Position = struct { family: Family, slot: usize };
    pub const Location = union(enum) {
        bridge_box,
        owner_box,
        wal_path,
        snapshot_path,
        feed_ring,
        table_backing: Family,
        live_key: Position,
        live_value: Position,
        feed_key: usize,
        feed_value: usize,
        retired_bytes: usize,
        retired_table: usize,
        retired_key: usize,
        retired_value: usize,
    };
    source: SourceIdentity,
    location: Location,
};

pub const RootDescriptor = struct {
    key: RootKey,
    locator: usize,
    requested_bytes: usize,
    alignment: usize,
    original_allocator: AllocatorObservation,
    ownership: enum { resident, retiring },
};

pub fn ManagedBridge(comptime R: type) type {
    return struct {
        const Bridge = @This();
        const max_allocations = 1 + max_batch_mutations * 5;
        pub const Owner = opaque {
            // Captures the actual namespace, not merely aliased handle types.
            pub const ResourceNamespace = R;
            pub fn construct(c: R.StoreConstruction, args: CreationArgs) !*Owner {
                return Bridge.construct(c, args);
            }
            pub fn constructionIdentity(self: *Owner, c: R.StoreConstruction) !SourceIdentity {
                if (try R.resolveConstructingStore(c) != self) return error.InvalidLease;
                return Bridge.backing(self).sourceIdentity();
            }
            pub fn bindConstructed(self: *Owner, c: R.StoreConstruction, id: R.StoreOwnerId) !void {
                if (try R.resolveConstructingStore(c) != self or try R.resolveStoreOwner(id) != self) return error.InvalidLease;
                const b = Bridge.backing(self);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                if (b.id != null) return error.InvalidLease;
                b.id = id;
            }
            pub fn abortConstruction(self: *Owner, c: R.StoreConstruction) !void {
                try R.beginAbortStoreConstruction(c, self);
                const b = Bridge.backing(self);
                try b.checkIdle(false);
                if (b.exclusive) |x| try x.finish();
                const a = b.metadata_allocator;
                try destroyStoreResourceOwner(b.source);
                a.destroy(b);
            }
            pub fn borrowRead(self: *Owner, id: R.StoreOwnerId) !ReadLease {
                if (try R.resolveStoreOwner(id) != self) return error.InvalidLease;
                return Bridge.backing(self).source.borrowRead();
            }
            pub fn acquireExclusive(self: *Owner, id: R.StoreOwnerId) !Exclusive {
                if (try R.resolveStoreOwner(id) != self) return error.InvalidLease;
                const b = Bridge.backing(self);
                const sb = ownerBacking(b.source);
                if (!sb.gate.tryLockExclusive()) return error.Busy;
                if (b.id == null or !std.meta.eql(b.id.?, id) or b.exclusive != null or b.operation_active) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                sb.gate.unlockExclusive();
                const x = try b.source.tryAcquireExclusive();
                sb.gate.lockExclusive();
                // The root serializes this source; another entrant still must
                // not replace a genuine exclusion after the short gate gap.
                if (b.exclusive != null) {
                    sb.gate.unlockExclusive();
                    try x.finish();
                    return error.Busy;
                }
                b.exclusive = x;
                sb.gate.unlockExclusive();
                return .{ .source = self, .id = id, .serial = x.serial, .lifetime = x.lifetime };
            }
            pub fn catalog(self: *Owner, x: Exclusive) !Catalog {
                const b = try Bridge.resolveExclusive(self, x);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(x);
                if (b.catalog_serial != 0 or b.operation_active or b.candidate != null) return error.Busy;
                const serial = try sb.issue();
                b.catalog_serial = serial;
                b.cursor = .{};
                return .{ .source = self, .exclusion = x, .serial = serial };
            }
            pub fn beginCandidate(self: *Owner, x: Exclusive, loan: R.ParticipantLoan) !Candidate {
                if (try R.resolveIssuedStore(loan) != self) return error.InvalidLease;
                const limit = try R.storeWorkLimit(loan);
                if (limit == 0 or limit == std.math.maxInt(u64)) return error.TableWorkExceeded;
                const b = try Bridge.resolveExclusive(self, x);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(x);
                if (b.operation_active or b.candidate != null or b.catalog_serial != 0) return error.Busy;
                if (sb.store.prepared_poisoned) return error.StorePoisoned;
                if (sb.store.staged_read_only) return error.ReadOnlyStore;
                if (sb.store.active_prepared != null or sb.store.active_batch != null or sb.store.staged_write_file != null) return error.SourceCustodyActive;
                if (b.last_transaction == loan.transaction) return error.InvalidLease;
                const serial = try sb.issue();
                b.work = .{ .limit = limit };
                b.candidate = .{ .serial = serial, .loan = loan, .source = sb.identity() };
                b.last_transaction = loan.transaction;
                return .{ .source = self, .serial = serial, .lifetime = sb.lifetime, .transaction = loan.transaction, .loan = loan };
            }
            pub fn prepareBatch(self: *Owner, c: Candidate, mutations: []const BatchMutation) !void {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                b.validateCandidate(c) catch |err| {
                    sb.gate.unlockExclusive();
                    return err;
                };
                if (b.operation_active or b.candidate.?.state != .reserved) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                b.operation_active = true;
                b.candidate.?.state = .preparing;
                sb.gate.unlockExclusive();
                errdefer {
                    sb.gate.lockExclusive();
                    b.candidate.?.state = .failed;
                    b.operation_active = false;
                    sb.gate.unlockExclusive();
                }
                try b.prepare(mutations);
                sb.gate.lockExclusive();
                b.candidate.?.state = .prepared;
                b.operation_active = false;
                sb.gate.unlockExclusive();
            }
            pub fn inspectCandidate(self: *Owner, c: Candidate) !CandidateView {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateCandidate(c);
                if (b.operation_active) return error.Busy;
                return .{ .source = b.sourceIdentity(), .serial = c.serial, .state = b.candidate.?.state, .allocation_count = b.candidate.?.allocation_count, .work_used = b.work.total, .work_limit = b.work.limit, .mutation_count = b.candidate.?.count };
            }
            pub fn inspectCandidateAllocation(self: *Owner, c: Candidate, index: usize) !?CandidateAllocation {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateCandidate(c);
                if (b.operation_active) return error.Busy;
                if (index >= b.candidate.?.allocation_count) return null;
                const a = b.candidate.?.allocations[index];
                return .{ .use = a.use, .locator = @intFromPtr(a.bytes.ptr), .requested_bytes = a.bytes.len, .alignment = a.alignment.toByteUnits(), .id = a.id, .role = a.role };
            }
            pub fn abortPreAttempt(self: *Owner, c: Candidate) !void {
                const b = try Bridge.resolveCandidate(self, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                b.validateCandidate(c) catch |err| {
                    sb.gate.unlockExclusive();
                    return err;
                };
                if (b.operation_active) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                b.operation_active = true;
                sb.gate.unlockExclusive();
                // The root retains issued homes until this real source abort.
                // A genuine Plan abort frees through its captured private table
                // facade, which removes that exact NEW root from the ledger.
                // Other partial allocations, including binding failures, remain
                // owned until the reverse ledger cleanup below.
                const active = &b.candidate.?;
                for (&active.plans) |*p| if (p.*) |*plan| {
                    plan.abort();
                };
                var n = active.allocation_count;
                while (n != 0) {
                    n -= 1;
                    const a = active.allocations[n];
                    a.allocator.rawFree(a.bytes, a.alignment, @returnAddress());
                }
                sb.gate.lockExclusive();
                b.candidate = null;
                b.operation_active = false;
                sb.gate.unlockExclusive();
            }
            pub fn inspectQuiescence(self: *Owner, x: Exclusive) !QuiescenceView {
                const b = try Bridge.resolveExclusive(self, x);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(x);
                if (b.operation_active) return error.Busy;
                var readers: usize = 0;
                for (sb.reads) |slot| if (slot.serial != 0) {
                    readers += 1;
                };
                return .{ .source = sb.identity(), .candidate_active = b.candidate != null, .catalog_active = b.catalog_serial != 0, .ordinary_active = sb.store.active_prepared != null or sb.store.active_batch != null, .staged_active = sb.store.staged_read_only or sb.store.staged_write_file != null, .readers = readers, .poisoned = sb.store.prepared_poisoned };
            }
            pub fn inspectPendingFree(self: *Owner, d: R.StoreDestruction) !?RootDescriptor {
                if (try R.resolveDestroyingStore(d) != self) return error.InvalidLease;
                return Bridge.backing(self).pending_free;
            }
            pub fn destroyRegistered(self: *Owner, d: R.StoreDestruction) !void {
                try R.beginStoreDestruction(d, self);
                const b = Bridge.backing(self);
                try b.checkIdle(true);
                const sb = ownerBacking(b.source);
                // External root ownership has joined all callers/waiters. These
                // checks are source quiescence, not that external lifetime proof.
                if (b.exclusive) |x| {
                    try x.finish();
                    b.exclusive = null;
                }
                sb.gate.lockExclusive();
                if (sb.exclusive != 0 or sb.closing) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                for (sb.reads) |slot| if (slot.serial != 0) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                };
                sb.closing = true;
                sb.gate.unlockExclusive();
                if (sb.store.wal_file) |f| {
                    f.close(sb.store.io);
                    sb.store.wal_file = null;
                }
                if (sb.store.staged_write_file) |f| {
                    f.close(sb.store.io);
                    sb.store.staged_write_file = null;
                }
                // No cursor escapes; all roots still exist while descriptors
                // are derived. Destructive detach occurs only after root has
                // prevalidated this entire exact graph.
                var cursor: Cursor = .{};
                // Wrapper boxes are deliberately delayed until every payload.
                _ = b.nextRoot(&cursor); // bridge box
                _ = b.nextRoot(&cursor); // source box
                while (b.nextRoot(&cursor)) |descriptor| {
                    try b.detach(descriptor.key);
                    b.pending_free = descriptor;
                    try R.freeStoreRoot(d, self, descriptor.key);
                    b.pending_free = null;
                }
                const owner_descriptor = b.descriptor(.owner_box, @intFromPtr(sb), @sizeOf(StoreOwnerBacking), @alignOf(StoreOwnerBacking), sb.metadata_allocator, .resident);
                b.pending_free = owner_descriptor;
                try R.freeStoreRoot(d, self, owner_descriptor.key);
                // No source pointer dereference follows its actual free.
                const bridge_descriptor = RootDescriptor{ .key = .{ .source = owner_descriptor.key.source, .location = .bridge_box }, .locator = @intFromPtr(b), .requested_bytes = @sizeOf(Backing), .alignment = @alignOf(Backing), .original_allocator = observeAllocator(b.metadata_allocator), .ownership = .resident };
                b.pending_free = bridge_descriptor;
                try R.freeStoreRoot(d, self, bridge_descriptor.key);
                // Both boxes have been freed; do not clear state or defer unlock.
            }
        };
        pub const Exclusive = struct {
            source: *Owner,
            id: R.StoreOwnerId,
            serial: u64,
            lifetime: u64,
            pub fn finish(self: Exclusive) !void {
                const b = try Bridge.resolveExclusive(self.source, self);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                b.validateExclusive(self) catch |err| {
                    sb.gate.unlockExclusive();
                    return err;
                };
                if (b.catalog_serial != 0 or b.candidate != null or b.operation_active) {
                    sb.gate.unlockExclusive();
                    return error.Busy;
                }
                const x = b.exclusive.?;
                sb.gate.unlockExclusive();
                try x.finish();
                sb.gate.lockExclusive();
                b.exclusive = null;
                sb.gate.unlockExclusive();
            }
        };
        pub const Catalog = struct {
            source: *Owner,
            exclusion: Exclusive,
            serial: u64,
            pub fn next(self: Catalog) !?RootDescriptor {
                const b = try Bridge.resolveExclusive(self.source, self.exclusion);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(self.exclusion);
                if (b.catalog_serial != self.serial or self.serial == 0) return error.InvalidLease;
                return b.nextRoot(&b.cursor);
            }
            pub fn finish(self: Catalog) !void {
                const b = try Bridge.resolveExclusive(self.source, self.exclusion);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateExclusive(self.exclusion);
                if (b.catalog_serial != self.serial or self.serial == 0) return error.InvalidLease;
                b.catalog_serial = 0;
            }
        };
        pub const Candidate = struct { source: *Owner, serial: u64, lifetime: u64, transaction: u64, loan: R.ParticipantLoan };
        pub const CandidateState = enum { reserved, preparing, prepared, failed };
        pub const CandidateView = struct { source: SourceIdentity, serial: u64, state: CandidateState, allocation_count: usize, work_used: u64, work_limit: u64, mutation_count: usize };
        pub const CandidateAllocation = struct { use: CandidateUse, locator: usize, requested_bytes: usize, alignment: usize, id: ?R.AllocationId, role: R.RoleId };
        pub const QuiescenceView = struct { source: SourceIdentity, candidate_active: bool, catalog_active: bool, ordinary_active: bool, staged_active: bool, readers: usize, poisoned: bool };
        pub const TestFixture = if (@import("builtin").is_test) struct {
            pub fn seedPending(source: *Owner, c: R.StoreConstruction) !void {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                const b = Bridge.backing(source);
                if (b.exclusive != null or b.candidate != null or b.catalog_serial != 0) return error.Busy;
                try test_fixture.seedOwnerForCensus(b.source);
            }
            pub fn seedRetirementSlotsPending(source: *Owner, c: R.StoreConstruction) !void {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                const b = Bridge.backing(source);
                if (b.exclusive != null or b.candidate != null or b.catalog_serial != 0) return error.Busy;
                const s = &ownerBacking(b.source).store;
                if (s.retirement_count != 0) return error.SourceCustodyActive;
                for (0..s.retirements.len) |i| switch (i % 3) {
                    0 => {
                        const bytes_ = try s.allocator.dupe(u8, "retired bytes");
                        EngineAccess.retireBytes(s, bytes_);
                    },
                    1 => {
                        const mutation = try OwnedMutation.from(s.allocator, .{ .seq = 1, .family = .props, .kind = .put, .key = "retired key", .value = "retired value" });
                        EngineAccess.retireMutation(s, mutation);
                    },
                    else => {
                        const slots = try s.allocator.alloc(KvTable.Slot, 8);
                        @memset(slots, .{});
                        EngineAccess.retireTable(s, slots);
                    },
                };
            }
            pub fn poisonPending(source: *Owner, c: R.StoreConstruction) !void {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                ownerBacking(Bridge.backing(source).source).store.prepared_poisoned = true;
            }
            pub fn armOrdinaryPut(source: *Owner, c: R.StoreConstruction) !PreparedPut {
                if (try R.resolveConstructingStore(c) != source) return error.InvalidLease;
                return ownerBacking(Bridge.backing(source).source).store.preparePut(.props, "ordinary", "candidate");
            }
            pub fn requireOwnedCandidate(source: *Owner, c: Candidate, expected: []const BatchMutation) !void {
                const b = try Bridge.resolveCandidate(source, c);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                try b.validateCandidate(c);
                if (b.operation_active or b.candidate.?.state != .prepared) return error.Busy;
                const active = &b.candidate.?;
                try std.testing.expectEqual(expected.len, active.count);
                const record = active.record.?;
                const outer = record[batch_guard_len..];
                try std.testing.expectEqual(readU32(outer[4..8]), checksum(outer[record_header_len..]));
                var decoded: [max_batch_mutations]BatchMutation = undefined;
                try std.testing.expectEqual(expected.len, try decodeBatch(outer[record_header_len..], &decoded));
                for (expected, decoded[0..expected.len], active.entries[0..expected.len]) |want, wire, entry| {
                    try std.testing.expectEqual(want.family, wire.family);
                    try std.testing.expectEqual(want.kind, wire.kind);
                    try std.testing.expectEqualStrings(want.key, wire.key);
                    try std.testing.expectEqualStrings(want.key, entry.key.?);
                    if (want.value) |v| {
                        try std.testing.expectEqualStrings(v, wire.value.?);
                        try std.testing.expectEqualStrings(v, entry.value.?);
                    }
                    if (entry.change) |feed| {
                        try std.testing.expectEqualStrings(want.key, feed.key);
                        if (want.value) |v| try std.testing.expectEqualStrings(v, feed.value.?);
                    }
                }
            }
            pub fn observe(source: *Owner, id: R.StoreOwnerId) !struct { source: SourceIdentity, next_sequence: u64, wal_offset: u64, wal_epoch: [16]u8, retirement_count: usize, feed_count: usize, memory_digest: [32]u8, table_backings: [family_count]usize, table_lengths: [family_count]usize, table_revisions: [family_count]u64 } {
                if (try R.resolveStoreOwner(id) != source) return error.InvalidLease;
                const b = Bridge.backing(source);
                const sb = ownerBacking(b.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                var h = std.crypto.hash.Blake3.init(.{});
                for (sb.store.maps) |m| for (m.map.slots) |slot| {
                    KvTable.hashNumber(&h, @backingInt(slot.state));
                    if (slot.state == .used) {
                        KvTable.hashSlotPointers(&h, slot);
                        h.update(slot.key);
                        h.update(slot.value);
                    }
                };
                KvTable.hashNumber(&h, sb.store.changefeed.start);
                KvTable.hashNumber(&h, sb.store.changefeed.count);
                for (sb.store.changefeed.entries) |entry| {
                    KvTable.hashNumber(&h, @intFromBool(entry != null));
                    if (entry) |m| {
                        KvTable.hashNumber(&h, m.seq);
                        KvTable.hashNumber(&h, @backingInt(m.family));
                        KvTable.hashNumber(&h, @backingInt(m.kind));
                        h.update(m.key);
                        if (m.value) |v| h.update(v);
                    }
                }
                var digest: [32]u8 = undefined;
                h.final(&digest);
                var ptrs: [family_count]usize = undefined;
                var lengths: [family_count]usize = undefined;
                var revisions: [family_count]u64 = undefined;
                for (sb.store.maps, 0..) |m, i| {
                    ptrs[i] = @intFromPtr(m.map.slots.ptr);
                    lengths[i] = m.map.slots.len;
                    revisions[i] = m.map.revision;
                }
                return .{ .source = sb.identity(), .next_sequence = sb.store.next_seq, .wal_offset = sb.store.wal_offset, .wal_epoch = sb.store.wal_epoch, .retirement_count = sb.store.retirement_count, .feed_count = sb.store.changefeed.count, .memory_digest = digest, .table_backings = ptrs, .table_lengths = lengths, .table_revisions = revisions };
            }
        } else void;
        const Cursor = struct { phase: enum { bridge, box, paths, tables, ring, feed, retiring, done } = .bridge, family: usize = 0, slot: usize = 0, part: usize = 0 };
        const Allocation = struct { use: CandidateUse, bytes: []u8, alignment: std.mem.Alignment, allocator: std.mem.Allocator, role: R.RoleId, id: ?R.AllocationId = null };
        const ManagedCandidate = struct {
            serial: u64,
            loan: R.ParticipantLoan,
            source: SourceIdentity,
            state: CandidateState = .reserved,
            entries: [max_batch_mutations]BatchEntry = undefined,
            count: usize = 0,
            record: ?[]u8 = null,
            plans: [family_count]?KvTable.Plan = @splat(null),
            allocations: [max_allocations]Allocation = undefined,
            allocation_count: usize = 0,
        };
        const Backing = struct {
            metadata_allocator: std.mem.Allocator,
            source: *StoreResourceOwner,
            id: ?R.StoreOwnerId = null,
            exclusive: ?StoreExclusive = null,
            catalog_serial: u64 = 0,
            cursor: Cursor = .{},
            candidate: ?ManagedCandidate = null,
            work: KvTable.Work = .{},
            operation_active: bool = false,
            last_transaction: u64 = 0,
            table_allocation_error: ?anyerror = null,
            pending_free: ?RootDescriptor = null,
            fn sourceIdentity(self: *Backing) SourceIdentity {
                return ownerBacking(self.source).identity();
            }
            fn validateExclusive(self: *Backing, x: Exclusive) !void {
                const saved = self.exclusive orelse return error.InvalidLease;
                if (x.serial != saved.serial or x.lifetime != saved.lifetime or self.id == null or !std.meta.eql(self.id.?, x.id)) return error.InvalidLease;
                try validateSourceExclusive(saved, ownerBacking(self.source));
            }
            fn validateCandidate(self: *Backing, c: Candidate) !void {
                const active = if (self.candidate) |*a| a else return error.InvalidLease;
                if (c.lifetime != active.source.lifetime or c.serial != active.serial or c.transaction != active.loan.transaction or !std.meta.eql(c.loan, active.loan) or !std.meta.eql(active.source, self.sourceIdentity())) return error.InvalidLease;
            }
            fn checkIdle(self: *Backing, reject_readonly: bool) !void {
                const sb = ownerBacking(self.source);
                sb.gate.lockExclusive();
                defer sb.gate.unlockExclusive();
                if (self.operation_active or self.candidate != null or self.catalog_serial != 0 or sb.exclusive_children != 0) return error.Busy;
                if (sb.store.active_prepared != null or sb.store.active_batch != null or (reject_readonly and sb.store.staged_read_only) or sb.store.staged_write_file != null) return error.SourceCustodyActive;
                for (sb.reads) |slot| if (slot.serial != 0) return error.Busy;
            }
            fn descriptor(self: *Backing, location: RootKey.Location, ptr: usize, len: usize, alignment: usize, a: std.mem.Allocator, ownership: @FieldType(RootDescriptor, "ownership")) RootDescriptor {
                return .{ .key = .{ .source = self.sourceIdentity(), .location = location }, .locator = ptr, .requested_bytes = len, .alignment = alignment, .original_allocator = observeAllocator(a), .ownership = ownership };
            }
            fn nextRoot(self: *Backing, cursor: *Cursor) ?RootDescriptor {
                const sb = ownerBacking(self.source);
                const s = &sb.store;
                while (true) switch (cursor.phase) {
                    .bridge => {
                        cursor.phase = .box;
                        return self.descriptor(.bridge_box, @intFromPtr(self), @sizeOf(Backing), @alignOf(Backing), self.metadata_allocator, .resident);
                    },
                    .box => {
                        cursor.phase = .paths;
                        return self.descriptor(.owner_box, @intFromPtr(sb), @sizeOf(StoreOwnerBacking), @alignOf(StoreOwnerBacking), sb.metadata_allocator, .resident);
                    },
                    .paths => {
                        const n = cursor.slot;
                        cursor.slot += 1;
                        if (n >= 2) {
                            cursor.phase = .tables;
                            cursor.slot = 0;
                            continue;
                        }
                        const bytes = if (n == 0) s.wal_path else s.snapshot_path;
                        if (bytes.len != 0) return self.descriptor(if (n == 0) .wal_path else .snapshot_path, @intFromPtr(bytes.ptr), bytes.len, 1, s.allocator, .resident);
                    },
                    .tables => {
                        if (cursor.family == family_count) {
                            cursor.phase = .feed;
                            cursor.slot = 0;
                            cursor.part = 0;
                            continue;
                        }
                        const family_ = families[cursor.family];
                        const map = &s.maps[cursor.family];
                        if (cursor.part == 0) cursor.part = 1;
                        if (cursor.slot == map.map.slots.len) {
                            cursor.family += 1;
                            cursor.slot = 0;
                            cursor.part = 0;
                            if (map.map.slots.len != 0) return self.descriptor(.{ .table_backing = family_ }, @intFromPtr(map.map.slots.ptr), map.map.slots.len * @sizeOf(KvTable.Slot), @alignOf(KvTable.Slot), map.map.allocator, .resident);
                            continue;
                        }
                        const i = cursor.slot;
                        const slot = map.map.slots[i];
                        if (slot.state != .used) {
                            cursor.slot += 1;
                            cursor.part = 1;
                            continue;
                        }
                        const key = cursor.part == 1;
                        if (key) cursor.part = 2 else {
                            cursor.part = 1;
                            cursor.slot += 1;
                        }
                        const bytes = if (key) slot.key else slot.value;
                        if (bytes.len != 0) return self.descriptor(if (key) .{ .live_key = .{ .family = family_, .slot = i } } else .{ .live_value = .{ .family = family_, .slot = i } }, @intFromPtr(bytes.ptr), bytes.len, 1, map.allocator, .resident);
                    },
                    .ring => {
                        cursor.phase = .retiring;
                        if (s.changefeed.entries.len != 0) return self.descriptor(.feed_ring, @intFromPtr(s.changefeed.entries.ptr), s.changefeed.entries.len * @sizeOf(?OwnedMutation), @alignOf(?OwnedMutation), s.changefeed.allocator, .resident);
                    },
                    .feed => {
                        if (cursor.slot == s.changefeed.entries.len) {
                            cursor.phase = .ring;
                            cursor.slot = 0;
                            cursor.part = 0;
                            continue;
                        }
                        const i = cursor.slot;
                        const m = s.changefeed.entries[i] orelse {
                            cursor.slot += 1;
                            cursor.part = 0;
                            continue;
                        };
                        const key = cursor.part == 0;
                        if (key) cursor.part = 1 else {
                            cursor.part = 0;
                            cursor.slot += 1;
                        }
                        const bytes = if (key) m.key else m.value orelse continue;
                        if (bytes.len != 0) return self.descriptor(if (key) .{ .feed_key = i } else .{ .feed_value = i }, @intFromPtr(bytes.ptr), bytes.len, 1, s.changefeed.allocator, .resident);
                    },
                    .retiring => {
                        if (cursor.slot == s.retirements.len) {
                            cursor.phase = .done;
                            continue;
                        }
                        const i = cursor.slot;
                        const r = s.retirements[i] orelse {
                            cursor.slot += 1;
                            cursor.part = 0;
                            continue;
                        };
                        switch (r) {
                            .bytes => |bytes| {
                                cursor.slot += 1;
                                if (bytes.len != 0) return self.descriptor(.{ .retired_bytes = i }, @intFromPtr(bytes.ptr), bytes.len, 1, s.allocator, .retiring);
                            },
                            .table_slots => |slots| {
                                cursor.slot += 1;
                                if (slots.len != 0) return self.descriptor(.{ .retired_table = i }, @intFromPtr(slots.ptr), slots.len * @sizeOf(KvTable.Slot), @alignOf(KvTable.Slot), s.allocator, .retiring);
                            },
                            .mutation => |m| {
                                const key = cursor.part == 0;
                                if (key) cursor.part = 1 else {
                                    cursor.part = 0;
                                    cursor.slot += 1;
                                }
                                const bytes = if (key) m.key else m.value orelse continue;
                                if (bytes.len != 0) return self.descriptor(if (key) .{ .retired_key = i } else .{ .retired_value = i }, @intFromPtr(bytes.ptr), bytes.len, 1, s.allocator, .retiring);
                            },
                        }
                    },
                    .done => return null,
                };
            }
            fn detach(self: *Backing, key: RootKey) !void {
                if (!std.meta.eql(key.source, self.sourceIdentity())) return error.InvalidLease;
                const s = &ownerBacking(self.source).store;
                switch (key.location) {
                    .wal_path => s.wal_path = &.{},
                    .snapshot_path => s.snapshot_path = &.{},
                    .table_backing => |f| s.maps[familyIndex(f)].map.slots = &.{},
                    .live_key => |p| s.maps[familyIndex(p.family)].map.slots[p.slot].key = &.{},
                    .live_value => |p| s.maps[familyIndex(p.family)].map.slots[p.slot].value = &.{},
                    .feed_ring => s.changefeed.entries = &.{},
                    .feed_key => |i| s.changefeed.entries[i].?.key = &.{},
                    .feed_value => |i| s.changefeed.entries[i].?.value = null,
                    .retired_bytes, .retired_table => |i| s.retirements[i] = null,
                    .retired_key => |i| s.retirements[i].?.mutation.key = &.{},
                    .retired_value => |i| s.retirements[i].?.mutation.value = null,
                    .bridge_box, .owner_box => return error.InvalidLease,
                }
            }
            fn remember(self: *Backing, purpose: CandidateUse, bytes: []u8, alignment: std.mem.Alignment, allocator: std.mem.Allocator, binding: R.StoreAllocationBinding) !void {
                if (bytes.len == 0) return;
                const c = &self.candidate.?;
                std.debug.assert(c.allocation_count < c.allocations.len);
                const i = c.allocation_count;
                c.allocation_count += 1;
                c.allocations[i] = .{ .use = purpose, .bytes = bytes, .alignment = alignment, .allocator = allocator, .role = binding.role };
                const id = try binding.scope.allocationId(bytes, alignment);
                c.allocations[i].id = id;
                try c.loan.bindNewAllocation(id, binding.role);
            }
            fn allocateBytes(self: *Backing, purpose: CandidateUse, len: usize) ![]u8 {
                try self.work.charge(&self.work.bytes, len);
                if (len == 0) return &.{}; // No positive allocation or role is required.
                const binding = try R.storeAllocationBinding(self.candidate.?.loan, purpose);
                const allocator = try binding.scope.allocator();
                const result = try allocator.alloc(u8, len);
                try self.remember(purpose, result, .@"1", allocator, binding);
                return result;
            }
            fn copy(self: *Backing, purpose: CandidateUse, input: []const u8) ![]u8 {
                const result = try self.allocateBytes(purpose, input.len);
                try self.work.charge(&self.work.bytes, input.len);
                @memcpy(result, input);
                return result;
            }
            // Lazy PRIVATE table facade: sparse plans need no table role or
            // allocation. Growth resolves the canonical funded role only at
            // its actual allocation, after the table core charged its Work.
            fn tableAllocator(self: *Backing) std.mem.Allocator {
                return .{ .ptr = self, .vtable = &.{ .alloc = tableAlloc, .resize = tableResize, .remap = tableRemap, .free = tableFree } };
            }
            fn tableAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
                const self: *Backing = @ptrCast(@alignCast(ctx));
                const binding = R.storeAllocationBinding(self.candidate.?.loan, .table_backing) catch |err| {
                    self.table_allocation_error = err;
                    return null;
                };
                const allocator = binding.scope.allocator() catch |err| {
                    self.table_allocation_error = err;
                    return null;
                };
                const ptr = allocator.rawAlloc(len, alignment, ret_addr) orelse return null;
                self.remember(.table_backing, ptr[0..len], alignment, allocator, binding) catch |err| {
                    self.table_allocation_error = err;
                    return null;
                };
                return ptr;
            }
            fn tableResize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
                return false;
            }
            fn tableRemap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
                return null;
            }
            fn tableFree(ctx: *anyopaque, bytes_: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
                const self: *Backing = @ptrCast(@alignCast(ctx));
                const c = &self.candidate.?;
                for (c.allocations[0..c.allocation_count], 0..) |a, i| if (a.use == .table_backing and a.bytes.ptr == bytes_.ptr and a.bytes.len == bytes_.len and a.alignment == alignment) {
                    a.allocator.rawFree(bytes_, alignment, ret_addr);
                    c.allocation_count -= 1;
                    c.allocations[i] = c.allocations[c.allocation_count];
                    return;
                };
                unreachable; // A table may free only its source-owned backing.
            }
            fn prepare(self: *Backing, mutations: []const BatchMutation) !void {
                const c = &self.candidate.?;
                const s = &ownerBacking(self.source).store;
                if (mutations.len == 0 or mutations.len > max_batch_mutations) return error.BadRecord;
                var payload_len: usize = 3;
                for (mutations, 0..) |m, i| {
                    if ((m.kind == .put) != (m.value != null)) return error.BadRecord;
                    for (mutations[0..i]) |prior| if (m.family == prior.family and try self.work.compare(m.key, prior.key)) return error.BadRecord;
                    const part = try checkedPayloadLen(m.kind, m.key, m.value orelse "", s.cfg.max_record_bytes);
                    payload_len = std.math.add(usize, payload_len, 4 + part) catch return error.RecordTooLarge;
                    try s.maps[familyIndex(m.family)].map.checkRevision();
                }
                if (payload_len > s.cfg.max_record_bytes or payload_len > std.math.maxInt(u32)) return error.RecordTooLarge;
                _ = std.math.add(u64, s.next_seq, mutations.len) catch return error.SequenceExhausted;
                const record_len = std.math.add(usize, batch_guard_len + record_header_len, payload_len) catch return error.RecordTooLarge;
                const final_offset = std.math.add(u64, s.wal_offset, record_len) catch return error.RecordTooLarge;
                if (final_offset > s.cfg.max_wal_bytes) return error.RecordTooLarge;
                const record = try self.allocateBytes(.packet, record_len);
                c.record = record;
                try self.work.charge(&self.work.bytes, record_len);
                encodeBatchGuard(record[0..batch_guard_len]);
                const outer = record[batch_guard_len..];
                writeU32(outer[0..4], @intCast(payload_len));
                const payload = outer[record_header_len..];
                payload[0] = meta_kind_batch;
                payload[1] = batch_format_version;
                payload[2] = @intCast(mutations.len);
                var offset: usize = 3;
                for (mutations, 0..) |m, i| {
                    const part = try checkedPayloadLen(m.kind, m.key, m.value orelse "", s.cfg.max_record_bytes);
                    writeU32(payload[offset..][0..4], @intCast(part));
                    offset += 4;
                    encodeMutation(payload[offset..][0..part], m);
                    offset += part;
                    c.entries[i] = .{ .family = m.family, .kind = m.kind };
                    c.count += 1;
                    const e = &c.entries[i];
                    const table = &s.maps[familyIndex(m.family)].map;
                    const old = try table.find(m.key, &self.work);
                    if (old) |index| {
                        e.old_key = @constCast(table.slots[index].key);
                        e.old_value = table.slots[index].value;
                    }
                    e.key = try self.copy(if (m.kind == .put and old == null) .new_key else .scratch_key, m.key);
                    if (m.value) |v| e.value = try self.copy(.value, v);
                    if (s.changefeed.entries.len != 0) {
                        // Independent payload ownership, not views into FINAL.
                        e.change = .{ .seq = s.next_seq + i, .family = m.family, .kind = m.kind, .key = &.{}, .value = null };
                        e.change.?.key = try self.copy(.feed_key, m.key);
                        if (m.value) |v| e.change.?.value = try self.copy(.feed_value, v);
                    }
                }
                for (0..family_count) |f| {
                    var edits: [max_batch_mutations]KvTable.Edit = undefined;
                    var n: usize = 0;
                    for (c.entries[0..c.count]) |e| if (familyIndex(e.family) == f) {
                        edits[n] = .{ .key = e.key.?, .value = e.value };
                        n += 1;
                    };
                    if (n == 0) continue;
                    self.table_allocation_error = null;
                    c.plans[f] = s.maps[f].map.prepareWithStorage(edits[0..n], self.tableAllocator(), &self.work) catch |err| return self.table_allocation_error orelse err;
                }
                try self.work.charge(&self.work.bytes, payload.len);
                writeU32(outer[4..8], checksum(payload));
                for (&c.plans) |*p| if (p.*) |*plan| try plan.validate();
            }
        };
        fn backing(source: *Owner) *Backing {
            return @ptrCast(@alignCast(source));
        }
        pub fn construct(c: R.StoreConstruction, args: CreationArgs) !*Owner {
            try R.beginStoreConstruction(c, CreationIdentity.from(args));
            const lifetime = try reserveOwnerLifetime();
            const b = try args.metadata_allocator.create(Backing);
            errdefer args.metadata_allocator.destroy(b);
            const source = try createStoreResourceOwnerReserved(args.metadata_allocator, args.store_allocator, args.io, args.dir, args.path, args.config, args.read_only, lifetime);
            b.* = .{ .metadata_allocator = args.metadata_allocator, .source = source };
            return @ptrCast(b);
        }
        fn resolveExclusive(source: *Owner, x: Exclusive) !*Backing {
            if (x.source != source or try R.resolveStoreOwner(x.id) != source) return error.InvalidLease;
            return backing(source);
        }
        fn resolveCandidate(source: *Owner, c: Candidate) !*Backing {
            if (c.source != source) return error.InvalidLease;
            // A copied token is not allowed to reinterpret an arbitrary address.
            // Resolve the actual private registered source via its original loan.
            // Candidate's root id is retained by backing; first validate known
            // owner from the public source association without following c.source.
            const known = try R.resolveIssuedStore(c.loan);
            if (known != source) return error.InvalidLease;
            return backing(source); // Candidate fields are checked under its metadata gate.
        }
    };
}
