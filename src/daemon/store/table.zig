// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed table plans, exact slot publication and owned key/value maps.

const std = @import("std");
const StoreError = @import("contracts.zig").StoreError;
const family_count = @import("contracts.zig").family_count;
const max_batch_mutations = @import("contracts.zig").max_batch_mutations;

pub fn initMaps(allocator: std.mem.Allocator) [family_count]KvMap {
    var maps: [family_count]KvMap = undefined;
    for (&maps) |*map| map.* = KvMap.init(allocator);
    return maps;
}

/// Source-owned open-addressed table. Payloads belong to KvMap/its prepared
/// owner; backing owns only slots. Deletion never relocates another key.
pub const KvTable = struct {
    const Self = @This();
    pub const max_edits = max_batch_mutations * 2;
    pub const State = enum(u8) { free, used, tombstone };
    pub const Slot = struct {
        state: State = .free,
        hash: u64 = 0,
        key: []const u8 = &.{},
        value: []u8 = &.{},
    };
    pub const Entry = struct { key_ptr: *[]const u8, value_ptr: *[]u8 };
    pub const GetOrPut = struct { key_ptr: *[]const u8, value_ptr: *[]u8, found_existing: bool };
    pub const Iterator = struct {
        table: *const Self,
        index: usize = 0,
        pub fn next(self: *Iterator) ?Entry {
            while (self.index < self.table.slots.len) {
                const i = self.index;
                self.index += 1;
                if (self.table.slots[i].state == .used) {
                    const slot = @constCast(&self.table.slots[i]);
                    return .{ .key_ptr = &slot.key, .value_ptr = &slot.value };
                }
            }
            return null;
        }
    };
    pub const Work = struct {
        probes: u64 = 0,
        comparisons: u64 = 0,
        rows: u64 = 0,
        bytes: u64 = 0,
        rebuilt_bytes: u64 = 0,
        total: u64 = 0,
        limit: u64 = std.math.maxInt(u64),
        pub fn charge(self: *Work, counter: *u64, n: usize) !void {
            const next = std.math.add(u64, self.total, n) catch return StoreError.TableWorkExceeded;
            if (next > self.limit) return StoreError.TableWorkExceeded;
            counter.* = std.math.add(u64, counter.*, n) catch return StoreError.TableWorkExceeded;
            self.total = next;
        }
        pub fn compare(self: *Work, a: []const u8, b: []const u8) !bool {
            try self.charge(&self.comparisons, 1);
            if (a.len != b.len) return false;
            try self.charge(&self.bytes, a.len);
            return std.mem.eql(u8, a, b);
        }
    };
    pub const Edit = struct { key: []const u8, value: ?[]u8 };
    pub const Patch = struct { index: usize, before: Slot, after: Slot, before_digest: [32]u8, after_digest: [32]u8 };
    /// Private bounded candidate: source owner owns all borrowed payloads. Its
    /// detached backing is freed without touching any borrowed OLD payload.
    pub const Plan = struct {
        owner: *Self,
        expected_slots: []Slot,
        expected_count: u32,
        expected_tombstones: u32,
        expected_revision: u64,
        patches: [max_edits]Patch = undefined,
        patch_count: usize = 0,
        replacement: ?[]Slot = null,
        replacement_digest: [32]u8 = undefined,
        final_count: u32,
        final_tombstones: u32,
        work: Work,
        shared_work: ?*Work = null,
        replacement_allocator: std.mem.Allocator,
        edits: [max_edits]Edit = undefined,
        edit_count: usize = 0,
        edit_digest: [32]u8 = undefined,
        seal: [32]u8 = undefined,
        done: bool = false,

        fn workAccount(self: *Plan) *Work {
            return self.shared_work orelse &self.work;
        }

        pub fn at(self: *Plan, index: usize) !Slot {
            for (self.patches[0..self.patch_count]) |patch| {
                try self.workAccount().charge(&self.workAccount().comparisons, 1);
                if (patch.index == index) return patch.after;
            }
            return self.expected_slots[index];
        }
        fn set(self: *Plan, index: usize, after: Slot) !void {
            for (self.patches[0..self.patch_count]) |*patch| {
                try self.workAccount().charge(&self.workAccount().comparisons, 1);
                if (patch.index == index) {
                    patch.after = after;
                    patch.after_digest = try slotDigest(after, self.workAccount());
                    return;
                }
            }
            if (self.patch_count == max_edits) return StoreError.InvalidTablePlan;
            const before = self.expected_slots[index];
            self.patches[self.patch_count] = .{ .index = index, .before = before, .after = after, .before_digest = try slotDigest(before, self.workAccount()), .after_digest = try slotDigest(after, self.workAccount()) };
            self.patch_count += 1;
        }
        fn insertion(self: *Plan, hash: u64, key: []const u8) !usize {
            const cap = self.expected_slots.len;
            if (cap == 0) return StoreError.InvalidTablePlan;
            var tombstone: ?usize = null;
            for (0..cap) |probe| {
                try self.workAccount().charge(&self.workAccount().probes, 1);
                const index = (@as(usize, @truncate(hash)) +% probe) & (cap - 1);
                const slot = try self.at(index);
                switch (slot.state) {
                    .free => return tombstone orelse index,
                    .tombstone => if (tombstone == null) {
                        tombstone = index;
                    },
                    .used => if (slot.hash == hash and try self.workAccount().compare(slot.key, key)) return StoreError.InvalidTablePlan,
                }
            }
            return tombstone orelse StoreError.InvalidTablePlan;
        }
        fn digest(self: *const Plan) [32]u8 {
            var h = std.crypto.hash.Blake3.init(.{});
            h.update("onyx-store-private-table-plan-v1");
            hashNumber(&h, @intFromPtr(self.owner));
            hashNumber(&h, @intFromPtr(self.expected_slots.ptr));
            hashNumber(&h, self.expected_slots.len);
            hashNumber(&h, self.expected_count);
            hashNumber(&h, self.expected_tombstones);
            hashNumber(&h, self.expected_revision);
            hashNumber(&h, self.final_count);
            hashNumber(&h, self.final_tombstones);
            hashNumber(&h, self.patch_count);
            hashNumber(&h, if (self.shared_work) |w| w.limit else self.work.limit);
            hashNumber(&h, if (self.shared_work) |w| @intFromPtr(w) else 0);
            hashNumber(&h, @intFromPtr(self.replacement_allocator.ptr));
            hashNumber(&h, @intFromPtr(self.replacement_allocator.vtable));
            hashNumber(&h, self.edit_count);
            h.update(&self.edit_digest);
            for (self.edits[0..self.edit_count]) |edit| {
                hashNumber(&h, @intFromPtr(edit.key.ptr));
                hashNumber(&h, edit.key.len);
                hashNumber(&h, if (edit.value) |value| @intFromPtr(value.ptr) else 0);
                hashNumber(&h, if (edit.value) |value| value.len else 0);
            }
            for (self.patches[0..self.patch_count]) |patch| {
                hashNumber(&h, patch.index);
                h.update(&patch.before_digest);
                h.update(&patch.after_digest);
                hashSlotPointers(&h, patch.before);
                hashSlotPointers(&h, patch.after);
            }
            if (self.replacement) |slots| {
                hashNumber(&h, @intFromPtr(slots.ptr));
                hashNumber(&h, slots.len);
                h.update(&self.replacement_digest);
            } else hashNumber(&h, 0);
            var out: [32]u8 = undefined;
            h.final(&out);
            return out;
        }
        pub fn validate(self: *Plan) !void {
            if (self.done or self.edit_count == 0 or self.edit_count > max_edits or self.patch_count > max_edits or self.expected_revision == std.math.maxInt(u64)) return StoreError.InvalidTablePlan;
            const table = self.owner;
            if (table.slots.ptr != self.expected_slots.ptr or table.slots.len != self.expected_slots.len or table.used != self.expected_count or table.tombstones != self.expected_tombstones or table.revision != self.expected_revision) return StoreError.InvalidTablePlan;
            const work = self.workAccount();
            try work.charge(&work.bytes, self.sealByteCount());
            if (!std.mem.eql(u8, &self.seal, &self.digest())) return StoreError.InvalidTablePlan;
            if (!std.mem.eql(u8, &self.edit_digest, &try editsDigest(self.edits[0..self.edit_count], work))) return StoreError.InvalidTablePlan;
            for (self.patches[0..self.patch_count]) |patch| {
                if (patch.index >= table.slots.len or !slotSame(table.slots[patch.index], patch.before) or !std.mem.eql(u8, &patch.before_digest, &try slotDigest(table.slots[patch.index], work)) or !std.mem.eql(u8, &patch.after_digest, &try slotDigest(patch.after, work))) return StoreError.InvalidTablePlan;
            }
            if (self.replacement) |slots| if (!std.mem.eql(u8, &self.replacement_digest, &try backingDigest(slots, work))) return StoreError.InvalidTablePlan;
        }
        fn sealByteCount(self: *const Plan) usize {
            return "onyx-store-private-table-plan-v1".len + 14 * 8 + 32 + self.edit_count * 32 + self.patch_count * 136 + (if (self.replacement != null) @as(usize, 48) else 8);
        }
        pub fn matchesEdit(self: *const Plan, key: []const u8, value: ?[]u8) bool {
            return self.editIndex(key, value) != null;
        }
        pub fn editIndex(self: *const Plan, key: []const u8, value: ?[]u8) ?usize {
            for (self.edits[0..self.edit_count], 0..) |edit, i| {
                if (edit.key.ptr != key.ptr or edit.key.len != key.len or (edit.value == null) != (value == null)) continue;
                if (edit.value) |expected| {
                    if (expected.ptr != value.?.ptr or expected.len != value.?.len) continue;
                }
                return i;
            }
            return null;
        }
        /// Caller has validated under its exclusive lane BEFORE I/O. Only
        /// fixed patches/swap/scalars below; no hash, probe, free or allocation.
        pub fn publish(self: *Plan) ?[]Slot {
            std.debug.assert(!self.done);
            const table = self.owner;
            var retired: ?[]Slot = null;
            if (self.replacement) |slots| {
                if (table.slots.len != 0) retired = table.slots;
                table.slots = slots;
                self.replacement = null;
            } else for (self.patches[0..self.patch_count]) |patch| table.slots[patch.index] = patch.after;
            table.used = self.final_count;
            table.tombstones = self.final_tombstones;
            table.revision = self.expected_revision + 1;
            self.done = true;
            return retired;
        }
        pub fn abort(self: *Plan) void {
            if (self.done) return;
            if (self.replacement) |slots| self.replacement_allocator.free(slots);
            self.replacement = null;
            self.done = true;
        }
    };

    allocator: std.mem.Allocator,
    slots: []Slot = &.{},
    used: u32 = 0,
    tombstones: u32 = 0,
    revision: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{ .allocator = allocator };
    }
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.slots);
        self.* = init(self.allocator);
    }
    pub fn count(self: *const Self) u32 {
        return self.used;
    }
    pub fn capacity(self: *const Self) u32 {
        return @intCast(self.slots.len);
    }
    pub fn iterator(self: *const Self) Iterator {
        return .{ .table = self };
    }
    pub fn keyHash(key: []const u8) u64 {
        return std.hash.Wyhash.hash(0, key);
    }
    fn maxLoad(cap: usize) usize {
        return cap - cap / 4;
    }
    pub fn checkRevision(self: *const Self) !void {
        if (self.revision == std.math.maxInt(u64)) return StoreError.SequenceExhausted;
    }
    fn capacityFor(required: usize, initial: usize) !usize {
        var cap = @max(initial, 8);
        while (required > maxLoad(cap)) cap = std.math.mul(usize, cap, 2) catch return error.OutOfMemory;
        if (cap > std.math.maxInt(u32)) return error.OutOfMemory;
        return cap;
    }
    pub fn find(self: *const Self, key: []const u8, work: ?*Work) !?usize {
        const cap = self.slots.len;
        if (cap == 0) return null;
        if (work) |w| try w.charge(&w.bytes, key.len);
        const hash = keyHash(key);
        for (0..cap) |probe| {
            if (work) |w| try w.charge(&w.probes, 1);
            const index = (@as(usize, @truncate(hash)) +% probe) & (cap - 1);
            const slot = self.slots[index];
            if (slot.state == .free) return null;
            if (slot.state == .used and slot.hash == hash) {
                const equal = if (work) |w| try w.compare(slot.key, key) else std.mem.eql(u8, slot.key, key);
                if (equal) return index;
            }
        }
        return null;
    }
    pub fn getEntry(self: *const Self, key: []const u8) ?Entry {
        const index = (self.find(key, null) catch unreachable) orelse return null;
        const slot = @constCast(&self.slots[index]);
        return .{ .key_ptr = &slot.key, .value_ptr = &slot.value };
    }
    pub fn get(self: *const Self, key: []const u8) ?[]u8 {
        return if (self.getEntry(key)) |entry| entry.value_ptr.* else null;
    }
    fn insertDetached(slots: []Slot, slot: Slot, work: *Work) !void {
        for (0..slots.len) |probe| {
            try work.charge(&work.probes, 1);
            const index = (@as(usize, @truncate(slot.hash)) +% probe) & (slots.len - 1);
            if (slots[index].state == .free) {
                slots[index] = slot;
                return;
            }
            if (slots[index].hash == slot.hash and try work.compare(slots[index].key, slot.key)) return StoreError.InvalidTablePlan;
        }
        return StoreError.InvalidTablePlan;
    }
    pub fn ensureUnusedCapacity(self: *Self, additional: u32) !void {
        try self.checkRevision();
        const required = std.math.add(usize, self.used, additional) catch return error.OutOfMemory;
        const cap = try capacityFor(required, self.slots.len);
        if (cap == self.slots.len and @as(usize, self.used) + self.tombstones + additional <= maxLoad(cap)) return;
        const next = try self.allocator.alloc(Slot, cap);
        errdefer self.allocator.free(next);
        @memset(next, .{});
        var work: Work = .{};
        for (self.slots) |slot| if (slot.state == .used) try insertDetached(next, slot, &work);
        self.allocator.free(self.slots);
        self.slots = next;
        self.tombstones = 0;
        self.revision += 1;
    }
    pub fn getOrPut(self: *Self, key: []const u8) !GetOrPut {
        try self.checkRevision();
        if (self.getEntry(key)) |entry| {
            self.revision += 1;
            return .{ .key_ptr = entry.key_ptr, .value_ptr = entry.value_ptr, .found_existing = true };
        }
        // Growth, placeholder install and OOM rollback each reserve one stamp.
        if (self.revision > std.math.maxInt(u64) - 3) return StoreError.SequenceExhausted;
        try self.ensureUnusedCapacity(1);
        return self.getOrPutAssumeCapacity(key);
    }
    fn getOrPutAssumeCapacity(self: *Self, key: []const u8) GetOrPut {
        std.debug.assert(self.revision < std.math.maxInt(u64));
        self.revision += 1;
        if (self.getEntry(key)) |entry| return .{ .key_ptr = entry.key_ptr, .value_ptr = entry.value_ptr, .found_existing = true };
        const hash = keyHash(key);
        var tomb: ?usize = null;
        for (0..self.slots.len) |probe| {
            const i = (@as(usize, @truncate(hash)) +% probe) & (self.slots.len - 1);
            if (self.slots[i].state == .tombstone and tomb == null) tomb = i;
            if (self.slots[i].state == .free) {
                const index = tomb orelse i;
                if (self.slots[index].state == .tombstone) self.tombstones -= 1;
                self.slots[index] = .{ .state = .used, .hash = hash, .key = key };
                self.used += 1;
                return .{ .key_ptr = &self.slots[index].key, .value_ptr = &self.slots[index].value, .found_existing = false };
            }
        }
        unreachable; // ensureUnusedCapacity maintains a genuinely free slot.
    }
    fn removeByPtr(self: *Self, key_ptr: *[]const u8) void {
        std.debug.assert(self.revision < std.math.maxInt(u64));
        const base = @intFromPtr(self.slots.ptr) + @offsetOf(Slot, "key");
        const address = @intFromPtr(key_ptr);
        std.debug.assert(address >= base and (address - base) % @sizeOf(Slot) == 0);
        const index = (address - base) / @sizeOf(Slot);
        std.debug.assert(index < self.slots.len and self.slots[index].state == .used);
        self.slots[index] = .{ .state = .tombstone };
        self.used -= 1;
        self.tombstones += 1;
        self.revision += 1;
    }
    pub fn remove(self: *Self, key: []const u8) bool {
        const entry = self.getEntry(key) orelse return false;
        self.removeByPtr(entry.key_ptr);
        return true;
    }
    pub fn slotSame(a: Slot, b: Slot) bool {
        return a.state == b.state and a.hash == b.hash and a.key.ptr == b.key.ptr and a.key.len == b.key.len and a.value.ptr == b.value.ptr and a.value.len == b.value.len;
    }
    pub fn hashNumber(h: *std.crypto.hash.Blake3, n: u64) void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, n, .little);
        h.update(&bytes);
    }
    pub fn hashSlotPointers(h: *std.crypto.hash.Blake3, slot: Slot) void {
        hashNumber(h, @intFromPtr(slot.key.ptr));
        hashNumber(h, slot.key.len);
        hashNumber(h, @intFromPtr(slot.value.ptr));
        hashNumber(h, slot.value.len);
    }
    fn slotDigest(slot: Slot, work: *Work) ![32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        hashNumber(&h, @backingInt(slot.state));
        hashNumber(&h, slot.hash);
        try work.charge(&work.bytes, if (slot.state == .used) @as(usize, 32) else 16);
        if (slot.state == .used) {
            try work.charge(&work.bytes, slot.key.len);
            try work.charge(&work.bytes, slot.value.len);
            hashNumber(&h, slot.key.len);
            h.update(slot.key);
            hashNumber(&h, slot.value.len);
            h.update(slot.value);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    fn editsDigest(edits: []const Edit, work: *Work) ![32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (edits) |edit| {
            try work.charge(&work.bytes, 24 + edit.key.len);
            hashNumber(&h, edit.key.len);
            h.update(edit.key);
            hashNumber(&h, @intFromBool(edit.value != null));
            if (edit.value) |value| {
                try work.charge(&work.bytes, value.len);
                hashNumber(&h, value.len);
                h.update(value);
            }
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    fn backingDigest(slots: []const Slot, work: *Work) ![32]u8 {
        var h = std.crypto.hash.Blake3.init(.{});
        for (slots) |slot| {
            try work.charge(&work.rows, 1);
            try work.charge(&work.bytes, 64);
            h.update(&try slotDigest(slot, work));
            hashSlotPointers(&h, slot);
        }
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
    pub fn prepare(self: *Self, edits: []const Edit, work_limit: u64) !Plan {
        return self.prepareStorage(edits, self.allocator, null, work_limit);
    }
    pub fn prepareWithStorage(self: *Self, edits: []const Edit, candidate_allocator: std.mem.Allocator, shared_work: *Work) !Plan {
        return self.prepareStorage(edits, candidate_allocator, shared_work, shared_work.limit);
    }
    fn prepareStorage(self: *Self, edits: []const Edit, candidate_allocator: std.mem.Allocator, shared_work: ?*Work, work_limit: u64) !Plan {
        if (edits.len == 0 or edits.len > max_edits) return StoreError.InvalidTablePlan;
        try self.checkRevision();
        if ((self.slots.len == 0 and (self.used != 0 or self.tombstones != 0)) or (self.slots.len != 0 and (!std.math.isPowerOfTwo(self.slots.len) or self.slots.len < 8 or @as(usize, self.used) + self.tombstones > maxLoad(self.slots.len)))) return StoreError.InvalidTablePlan;
        var plan: Plan = .{ .owner = self, .expected_slots = self.slots, .expected_count = self.used, .expected_tombstones = self.tombstones, .expected_revision = self.revision, .final_count = self.used, .final_tombstones = self.tombstones, .work = .{ .limit = work_limit }, .shared_work = shared_work, .replacement_allocator = candidate_allocator };
        errdefer plan.abort();
        @memcpy(plan.edits[0..edits.len], edits);
        plan.edit_count = edits.len;
        plan.edit_digest = try editsDigest(edits, plan.workAccount());
        var final: [max_edits]Edit = undefined;
        var old: [max_edits]?usize = undefined;
        var count_final: usize = 0;
        for (edits) |edit| {
            var existing: ?usize = null;
            for (final[0..count_final], 0..) |prior, i| if (try plan.workAccount().compare(prior.key, edit.key)) {
                existing = i;
                break;
            };
            if (existing) |i| final[i] = edit else {
                final[count_final] = edit;
                count_final += 1;
            }
        }
        // Fixed <=8 insertion sort; charge key comparisons rather than hiding work.
        for (1..count_final) |i| {
            var j = i;
            while (j > 0) : (j -= 1) {
                try plan.workAccount().charge(&plan.workAccount().comparisons, 1);
                try plan.workAccount().charge(&plan.workAccount().bytes, @min(final[j].key.len, final[j - 1].key.len));
                if (std.mem.order(u8, final[j - 1].key, final[j].key) != .gt) break;
                std.mem.swap(Edit, &final[j - 1], &final[j]);
            }
        }
        for (final[0..count_final], 0..) |edit, i| {
            old[i] = try self.find(edit.key, plan.workAccount());
            if (old[i]) |index| {
                if (edit.value) |value| {
                    var after = self.slots[index];
                    after.value = value;
                    try plan.set(index, after);
                } else {
                    plan.final_count -= 1;
                    plan.final_tombstones += 1;
                    try plan.set(index, .{ .state = .tombstone });
                }
            } else if (edit.value != null) plan.final_count = std.math.add(u32, plan.final_count, 1) catch return error.OutOfMemory;
        }
        var cap = try capacityFor(plan.final_count, self.slots.len);
        var rebuild = cap != self.slots.len;
        if (!rebuild) {
            for (final[0..count_final], 0..) |edit, i| if (old[i] == null) {
                if (edit.value) |value| {
                    try plan.workAccount().charge(&plan.workAccount().bytes, edit.key.len);
                    const hash = keyHash(edit.key);
                    const index = try plan.insertion(hash, edit.key);
                    if ((try plan.at(index)).state == .tombstone) plan.final_tombstones -= 1;
                    try plan.set(index, .{ .state = .used, .hash = hash, .key = edit.key, .value = value });
                }
            };
            rebuild = @as(usize, plan.final_count) + plan.final_tombstones > maxLoad(cap);
        }
        if (rebuild) {
            // Growth/rebuild owns ONLY slots, all payloads stay with OLD/candidate.
            cap = try capacityFor(plan.final_count, self.slots.len);
            const rebuilt_bytes = std.math.mul(usize, cap, @sizeOf(Slot)) catch return StoreError.TableWorkExceeded;
            try plan.workAccount().charge(&plan.workAccount().rebuilt_bytes, rebuilt_bytes);
            const replacement = try candidate_allocator.alloc(Slot, cap);
            plan.replacement = replacement;
            @memset(replacement, .{});
            for (self.slots) |slot| {
                try plan.workAccount().charge(&plan.workAccount().rows, 1);
                if (slot.state != .used) continue;
                var next = slot;
                for (final[0..count_final]) |edit| if (try plan.workAccount().compare(edit.key, slot.key)) {
                    if (edit.value) |value| next.value = value else next.state = .tombstone;
                    break;
                };
                if (next.state == .used) try insertDetached(replacement, next, plan.workAccount());
            }
            for (final[0..count_final], 0..) |edit, i| if (old[i] == null) if (edit.value) |value| {
                try plan.workAccount().charge(&plan.workAccount().bytes, edit.key.len);
                try insertDetached(replacement, .{ .state = .used, .hash = keyHash(edit.key), .key = edit.key, .value = value }, plan.workAccount());
            };
            plan.patch_count = 0;
            plan.final_tombstones = 0;
            plan.replacement_digest = try backingDigest(replacement, plan.workAccount());
        }
        try plan.workAccount().charge(&plan.workAccount().bytes, plan.sealByteCount());
        plan.seal = plan.digest();
        return plan;
    }
};

pub const KvMap = struct {
    allocator: std.mem.Allocator,
    map: KvTable,

    pub fn init(allocator: std.mem.Allocator) KvMap {
        return .{
            .allocator = allocator,
            .map = KvTable.init(allocator),
        };
    }

    pub fn deinit(self: *KvMap) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    pub fn put(self: *KvMap, key: []const u8, value: []const u8) !void {
        const gop = try self.map.getOrPut(key);
        if (gop.found_existing) {
            const next_value = try self.allocator.dupe(u8, value);
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = next_value;
            return;
        }

        const owned_key = self.allocator.dupe(u8, key) catch |err| {
            _ = self.map.remove(key);
            return err;
        };
        gop.key_ptr.* = owned_key;
        errdefer {
            // `remove` invalidates `gop.key_ptr`; retain the owned slice and
            // free it only after unlinking the entry. The previous order could
            // read freed map storage during an allocation-failure sweep.
            _ = self.map.removeByPtr(gop.key_ptr);
            self.allocator.free(owned_key);
        }
        gop.value_ptr.* = try self.allocator.dupe(u8, value);
    }

    pub fn get(self: *const KvMap, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }

    pub fn delete(self: *KvMap, key: []const u8) void {
        if (self.map.getEntry(key)) |entry| {
            const owned_key = entry.key_ptr.*;
            const owned_value = entry.value_ptr.*;
            self.map.removeByPtr(entry.key_ptr);
            self.allocator.free(owned_key);
            self.allocator.free(owned_value);
        }
    }
};
