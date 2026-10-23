// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-owned read/exclusive leases, lifetime identity and resource census.

const std = @import("std");
const OwnedMutation = @import("changefeed.zig").OwnedMutation;
const Config = @import("contracts.zig").Config;
const Family = @import("contracts.zig").Family;
const Mutation = @import("contracts.zig").Mutation;
const familyIndex = @import("contracts.zig").familyIndex;
const family_count = @import("contracts.zig").family_count;
const OroStore = @import("engine.zig").OroStore;
const KvTable = @import("table.zig").KvTable;

// The S1 observation surface exports no mutable Store or original allocator.
// The closed S2 bridge below requires the canonical source-owned root protocol.
// Borrowed contexts must outlive this entire owner.
pub const SourceAccessError = error{ Busy, InvalidLease, LeaseChildren, SourceCustodyActive, IdentityExhausted, Capacity };

pub const SourceIdentity = struct { lifetime: u64, owner_revision: u64, census_revision: u64 };

/// Non-callable original std.mem.Allocator ABI/context observation. This does
/// not extend the backend object lifetime or authorize allocation/deallocation.
pub const AllocatorObservation = struct {
    context: usize,
    vtable: usize,
    fn from(a: std.mem.Allocator) AllocatorObservation {
        return .{ .context = @intFromPtr(a.ptr), .vtable = @intFromPtr(a.vtable) };
    }
};

pub const OwnedCapacityDescriptor = struct {
    source: SourceIdentity,
    kind: enum { owner_box, wal_path, snapshot_path, table_backing, live_key, live_value, feed_ring, feed_key, feed_value, retired_bytes, retired_key, retired_value, retired_table },
    locator: usize,
    requested_bytes: usize,
    alignment: usize,
    original_allocator: AllocatorObservation,
    ownership: enum { resident, retiring },
    deallocation_convention: enum { original_std_allocator } = .original_std_allocator,
};

pub const SourceCustodyView = struct {
    source: SourceIdentity,
    next_sequence: u64,
    poisoned: bool,
    owned_wal_descriptor: bool,
    owned_staged_descriptor: bool,
    borrowed_directory: @FieldType(std.Io.Dir, "handle"),
    borrowed_io_context: usize,
    borrowed_io_vtable: usize,
    // These observations do not pin the supplied directory/Io/allocator objects.
};

pub const StoreEntryView = struct { key: []const u8, value: []const u8 };

pub const StoreResourceOwner = opaque {
    pub fn borrowRead(self: *StoreResourceOwner) SourceAccessError!ReadLease {
        const b = ownerBacking(self);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        if (b.closing or b.exclusive != 0) return error.Busy;
        for (&b.reads, 0..) |*slot, i| if (slot.serial == 0) {
            const serial = try b.issue();
            slot.* = .{ .serial = serial };
            return .{ .owner = self, .lifetime = b.lifetime, .serial = serial, .slot = i };
        };
        return error.Capacity;
    }
    pub fn tryAcquireExclusive(self: *StoreResourceOwner) SourceAccessError!StoreExclusive {
        const b = ownerBacking(self);
        if (!b.gate.tryLockExclusive()) return error.Busy;
        defer b.gate.unlockExclusive();
        if (b.closing or b.exclusive != 0) return error.Busy;
        for (b.reads) |slot| if (slot.serial != 0) return error.Busy;
        if (b.store.active_prepared != null or b.store.active_batch != null or b.store.staged_read_only or b.store.staged_write_file != null) return error.SourceCustodyActive;
        const serial = try b.issue();
        b.exclusive = serial;
        return .{ .owner = self, .lifetime = b.lifetime, .serial = serial };
    }
};

pub const ResourceOwner = StoreResourceOwner;

/// Slices from get/changeAt and iterator results borrow this real lease. All
/// actual users must finish before finish(); escaped slice copies are not revoked.
pub const ReadLease = struct {
    owner: *StoreResourceOwner,
    lifetime: u64,
    serial: u64,
    slot: usize,
    fn validate(self: ReadLease, b: *StoreOwnerBacking) SourceAccessError!void {
        if (b.closing or b.lifetime != self.lifetime or self.slot >= b.reads.len or self.serial == 0 or b.reads[self.slot].serial != self.serial) return error.InvalidLease;
    }
    pub fn get(self: ReadLease, family_: Family, key: []const u8) SourceAccessError!?[]const u8 {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        return b.store.get(family_, key);
    }
    pub fn changeAt(self: ReadLease, index: usize) SourceAccessError!?Mutation {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        return b.store.changeAt(index);
    }
    pub fn iterate(self: ReadLease, family_: Family) SourceAccessError!ReadIterator {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        for (&b.children, 0..) |*child, i| if (child.serial == 0) {
            const serial = try b.issue();
            child.* = .{ .serial = serial, .parent = self.serial, .kind = .read_iterator, .family = familyIndex(family_) };
            b.reads[self.slot].children += 1;
            return .{ .parent = self, .serial = serial, .slot = i };
        };
        return error.Capacity;
    }
    pub fn finish(self: ReadLease) SourceAccessError!void {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        if (b.reads[self.slot].children != 0) return error.LeaseChildren;
        b.reads[self.slot] = .{};
    }
};

pub const ReadIterator = struct {
    parent: ReadLease,
    serial: u64,
    slot: usize,
    fn validate(self: ReadIterator, b: *StoreOwnerBacking) SourceAccessError!*StoreOwnerChild {
        try self.parent.validate(b);
        if (self.slot >= b.children.len or self.serial == 0) return error.InvalidLease;
        const child = &b.children[self.slot];
        if (child.serial != self.serial or child.parent != self.parent.serial or child.kind != .read_iterator) return error.InvalidLease;
        return child;
    }
    pub fn next(self: ReadIterator) SourceAccessError!?StoreEntryView {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const child = try self.validate(b);
        const table = &b.store.maps[child.family].map;
        while (child.index < table.slots.len) {
            const slot = table.slots[child.index];
            child.index += 1;
            if (slot.state == .used) return .{ .key = slot.key, .value = slot.value };
        }
        return null;
    }
    pub fn finish(self: ReadIterator) SourceAccessError!void {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const child = try self.validate(b);
        child.* = .{};
        b.reads[self.parent.slot].children -= 1;
    }
};

pub const StoreExclusive = struct {
    owner: *StoreResourceOwner,
    lifetime: u64,
    serial: u64,
    fn validate(self: StoreExclusive, b: *StoreOwnerBacking) SourceAccessError!void {
        if (b.closing or b.lifetime != self.lifetime or self.serial == 0 or b.exclusive != self.serial) return error.InvalidLease;
    }
    pub fn sourceState(self: StoreExclusive) SourceAccessError!SourceCustodyView {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        return .{ .source = b.identity(), .next_sequence = b.store.next_seq, .poisoned = b.store.prepared_poisoned, .owned_wal_descriptor = b.store.wal_file != null, .owned_staged_descriptor = b.store.staged_write_file != null, .borrowed_directory = b.store.dir.handle, .borrowed_io_context = if (b.store.io.userdata) |ptr| @intFromPtr(ptr) else 0, .borrowed_io_vtable = @intFromPtr(b.store.io.vtable) };
    }
    pub fn catalog(self: StoreExclusive) SourceAccessError!CatalogCursor {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        for (&b.children, 0..) |*child, i| if (child.serial == 0) {
            const serial = try b.issue();
            child.* = .{ .serial = serial, .parent = self.serial, .kind = .catalog };
            b.exclusive_children += 1;
            return .{ .parent = self, .serial = serial, .slot = i };
        };
        return error.Capacity;
    }
    pub fn finish(self: StoreExclusive) SourceAccessError!void {
        const b = ownerBacking(self.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        try self.validate(b);
        if (b.exclusive_children != 0) return error.LeaseChildren;
        b.exclusive = 0;
    }
};

pub const CatalogCursor = struct {
    parent: StoreExclusive,
    serial: u64,
    slot: usize,
    fn validate(self: CatalogCursor, b: *StoreOwnerBacking) SourceAccessError!*StoreOwnerChild {
        try self.parent.validate(b);
        if (self.slot >= b.children.len or self.serial == 0) return error.InvalidLease;
        const child = &b.children[self.slot];
        if (child.serial != self.serial or child.parent != self.parent.serial or child.kind != .catalog) return error.InvalidLease;
        return child;
    }
    pub fn next(self: CatalogCursor) SourceAccessError!?OwnedCapacityDescriptor {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const c = try self.validate(b);
        // Source-owned cursor advances once; a copied token cannot replay rows.
        while (true) switch (c.phase) {
            .box => {
                c.phase = .paths;
                return b.describe(.owner_box, @intFromPtr(b), @sizeOf(StoreOwnerBacking), @alignOf(StoreOwnerBacking), b.metadata_allocator, .resident);
            },
            .paths => {
                const i = c.index;
                c.index += 1;
                if (i >= 2) {
                    c.phase = .tables;
                    c.index = 0;
                    continue;
                }
                const bytes = if (i == 0) b.store.wal_path else b.store.snapshot_path;
                if (bytes.len == 0) continue;
                return b.describe(if (i == 0) .wal_path else .snapshot_path, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.allocator, .resident);
            },
            .tables => {
                if (c.family == family_count) {
                    c.phase = .feed_ring;
                    c.index = 0;
                    c.part = 0;
                    continue;
                }
                const map = &b.store.maps[c.family];
                if (c.part == 0) {
                    c.part = 1;
                    if (map.map.slots.len == 0) continue;
                    const bytes = std.math.mul(usize, map.map.slots.len, @sizeOf(KvTable.Slot)) catch return error.Capacity;
                    return b.describe(.table_backing, @intFromPtr(map.map.slots.ptr), bytes, @alignOf(KvTable.Slot), map.map.allocator, .resident);
                }
                if (c.index == map.map.slots.len) {
                    c.family += 1;
                    c.index = 0;
                    c.part = 0;
                    continue;
                }
                const slot = map.map.slots[c.index];
                if (slot.state != .used) {
                    c.index += 1;
                    continue;
                }
                const key = c.part == 1;
                if (key) c.part = 2 else {
                    c.part = 1;
                    c.index += 1;
                }
                const bytes = if (key) slot.key else slot.value;
                if (bytes.len == 0) continue;
                return b.describe(if (key) .live_key else .live_value, @intFromPtr(bytes.ptr), bytes.len, 1, map.allocator, .resident);
            },
            .feed_ring => {
                c.phase = .feed;
                c.index = 0;
                c.part = 0;
                const entries = b.store.changefeed.entries;
                if (entries.len == 0) continue;
                const bytes = std.math.mul(usize, entries.len, @sizeOf(?OwnedMutation)) catch return error.Capacity;
                return b.describe(.feed_ring, @intFromPtr(entries.ptr), bytes, @alignOf(?OwnedMutation), b.store.changefeed.allocator, .resident);
            },
            .feed => {
                if (c.index == b.store.changefeed.entries.len) {
                    c.phase = .retirements;
                    c.index = 0;
                    c.part = 0;
                    continue;
                }
                const mutation = b.store.changefeed.entries[c.index] orelse {
                    c.index += 1;
                    continue;
                };
                const key = c.part == 0;
                if (key) c.part = 1 else {
                    c.part = 0;
                    c.index += 1;
                }
                const bytes = if (key) mutation.key else mutation.value orelse continue;
                if (bytes.len == 0) continue;
                return b.describe(if (key) .feed_key else .feed_value, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.changefeed.allocator, .resident);
            },
            .retirements => {
                if (c.index == b.store.retirements.len) {
                    c.phase = .done;
                    continue;
                }
                const retired = b.store.retirements[c.index] orelse {
                    c.index += 1;
                    continue;
                };
                switch (retired) {
                    .bytes => |bytes| {
                        c.index += 1;
                        if (bytes.len == 0) continue;
                        return b.describe(.retired_bytes, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.allocator, .retiring);
                    },
                    .table_slots => |slots| {
                        c.index += 1;
                        if (slots.len == 0) continue;
                        const bytes = std.math.mul(usize, slots.len, @sizeOf(KvTable.Slot)) catch return error.Capacity;
                        return b.describe(.retired_table, @intFromPtr(slots.ptr), bytes, @alignOf(KvTable.Slot), b.store.allocator, .retiring);
                    },
                    .mutation => |mutation| {
                        const key = c.part == 0;
                        if (key) c.part = 1 else {
                            c.part = 0;
                            c.index += 1;
                        }
                        const bytes = if (key) mutation.key else mutation.value orelse continue;
                        if (bytes.len == 0) continue;
                        return b.describe(if (key) .retired_key else .retired_value, @intFromPtr(bytes.ptr), bytes.len, 1, b.store.allocator, .retiring);
                    },
                }
            },
            .done => return null,
        };
    }
    pub fn finish(self: CatalogCursor) SourceAccessError!void {
        const b = ownerBacking(self.parent.owner);
        b.gate.lockExclusive();
        defer b.gate.unlockExclusive();
        const c = try self.validate(b);
        c.* = .{};
        b.exclusive_children -= 1;
    }
};

pub const StoreOwnerChild = struct {
    serial: u64 = 0,
    parent: u64 = 0,
    kind: enum { read_iterator, catalog } = .catalog,
    family: usize = 0,
    index: usize = 0,
    part: u8 = 0,
    phase: enum { box, paths, tables, feed_ring, feed, retirements, done } = .box,
};

pub const StoreOwnerBacking = struct {
    // Synchronous source reads/traversal remain under this gate; no operation
    // escapes it except slices covered by real read/child slots. No async source
    // work or caller callback exists in S1. Future work needs actual retained pins.
    gate: @import("../../substrate/rwlock.zig").RwLock = .{},
    metadata_allocator: std.mem.Allocator,
    store: OroStore,
    lifetime: u64,
    owner_revision: u64 = 1,
    census_revision: u64 = 1,
    next_serial: u64 = 1,
    reads: [16]struct { serial: u64 = 0, children: usize = 0 } = @splat(.{}),
    children: [16]StoreOwnerChild = @splat(.{}),
    exclusive: u64 = 0,
    exclusive_children: usize = 0,
    closing: bool = false,
    pub fn identity(self: *const StoreOwnerBacking) SourceIdentity {
        return .{ .lifetime = self.lifetime, .owner_revision = self.owner_revision, .census_revision = self.census_revision };
    }
    pub fn issue(self: *StoreOwnerBacking) SourceAccessError!u64 {
        if (self.next_serial == std.math.maxInt(u64)) return error.IdentityExhausted;
        const serial = self.next_serial;
        self.next_serial += 1;
        return serial;
    }
    fn describe(self: *const StoreOwnerBacking, kind: @FieldType(OwnedCapacityDescriptor, "kind"), ptr: usize, len: usize, alignment: usize, a: std.mem.Allocator, ownership: @FieldType(OwnedCapacityDescriptor, "ownership")) OwnedCapacityDescriptor {
        return .{ .source = self.identity(), .kind = kind, .locator = ptr, .requested_bytes = len, .alignment = alignment, .original_allocator = AllocatorObservation.from(a), .ownership = ownership };
    }
};

var store_owner_lifetimes: std.atomic.Value(u64) = .init(1);

pub fn reserveStoreLifetime(counter: *std.atomic.Value(u64)) SourceAccessError!u64 {
    var current = counter.load(.monotonic);
    while (true) {
        if (current == 0 or current == std.math.maxInt(u64)) return error.IdentityExhausted;
        if (counter.cmpxchgWeak(current, current + 1, .monotonic, .monotonic)) |actual| current = actual else return current;
    }
}

pub fn ownerBacking(owner: *StoreResourceOwner) *StoreOwnerBacking {
    return @ptrCast(@alignCast(owner));
}

// Only this source creates the actual Store; no by-value move of an escaped Store.
pub fn createStoreResourceOwner(metadata_allocator: std.mem.Allocator, store_allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, cfg: Config, read_only: bool) !*StoreResourceOwner {
    return createStoreResourceOwnerWithCounter(metadata_allocator, store_allocator, io, dir, path, cfg, read_only, &store_owner_lifetimes);
}

pub fn createStoreResourceOwnerWithCounter(metadata_allocator: std.mem.Allocator, store_allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, cfg: Config, read_only: bool, counter: *std.atomic.Value(u64)) !*StoreResourceOwner {
    const lifetime = try reserveStoreLifetime(counter);
    return createStoreResourceOwnerReserved(metadata_allocator, store_allocator, io, dir, path, cfg, read_only, lifetime);
}

pub fn createStoreResourceOwnerReserved(metadata_allocator: std.mem.Allocator, store_allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, path: []const u8, cfg: Config, read_only: bool, lifetime: u64) !*StoreResourceOwner {
    const b = try metadata_allocator.create(StoreOwnerBacking);
    errdefer metadata_allocator.destroy(b);
    const store = if (read_only) try OroStore.openReadOnlyWithConfig(store_allocator, io, dir, path, cfg) else try OroStore.openWithConfig(store_allocator, io, dir, path, cfg);
    b.* = .{ .metadata_allocator = metadata_allocator, .store = store, .lifetime = lifetime };
    return @ptrCast(b);
}

pub fn destroyStoreResourceOwner(owner: *StoreResourceOwner) SourceAccessError!void {
    const b = ownerBacking(owner);
    b.gate.lockExclusive();
    if (b.closing or b.exclusive != 0) {
        b.gate.unlockExclusive();
        return error.Busy;
    }
    for (b.reads) |slot| if (slot.serial != 0) {
        b.gate.unlockExclusive();
        return error.Busy;
    };
    if (b.store.active_prepared != null or b.store.active_batch != null or b.store.staged_write_file != null) {
        b.gate.unlockExclusive();
        return error.SourceCustodyActive;
    }
    b.closing = true;
    b.gate.unlockExclusive();
    // No public mutator/factory exists. S3 must establish real external lifetime
    // ownership before making construction/destruction reachable by live owners.
    const allocator = b.metadata_allocator;
    b.store.deinit();
    allocator.destroy(b);
}

/// Internal allocator observation shared with the closed managed adapter.
pub const observeAllocator = AllocatorObservation.from;

/// Reserve from the one process-wide source lifetime counter.
pub fn reserveOwnerLifetime() SourceAccessError!u64 {
    return reserveStoreLifetime(&store_owner_lifetimes);
}

/// Validate the concrete exclusive token without expanding its public API.
pub const validateExclusive = StoreExclusive.validate;
