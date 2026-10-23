// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded mutation feed and its independently owned payloads.

const std = @import("std");
const Family = @import("contracts.zig").Family;
const Mutation = @import("contracts.zig").Mutation;
const MutationKind = @import("contracts.zig").MutationKind;

pub const ChangeFeed = struct {
    allocator: std.mem.Allocator,
    entries: []?OwnedMutation,
    start: usize = 0,
    count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !ChangeFeed {
        const entries = try allocator.alloc(?OwnedMutation, capacity);
        @memset(entries, null);
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *ChangeFeed) void {
        for (self.entries) |*entry| {
            if (entry.*) |*mutation| mutation.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
    }

    /// Publish an already-owned entry. `PreparedPut.prepare` allocates the
    /// entry before I/O, so this path only swaps pointers and returns an
    /// evicted entry for the store's bounded deferred-retirement queue.
    pub fn publishPrepared(self: *ChangeFeed, owned: OwnedMutation) ?OwnedMutation {
        if (self.entries.len == 0) {
            return owned;
        }
        if (self.count < self.entries.len) {
            const index = (self.start + self.count) % self.entries.len;
            self.entries[index] = owned;
            self.count += 1;
            return null;
        } else {
            const index = self.start;
            const old = self.entries[index];
            self.entries[index] = owned;
            self.start = (self.start + 1) % self.entries.len;
            return old;
        }
    }

    pub fn at(self: *const ChangeFeed, index: usize) ?Mutation {
        if (index >= self.count) return null;
        const real_index = (self.start + index) % self.entries.len;
        return self.entries[real_index].?.view();
    }
};

pub const OwnedMutation = struct {
    seq: u64,
    family: Family,
    kind: MutationKind,
    key: []u8,
    value: ?[]u8,

    pub fn from(allocator: std.mem.Allocator, mutation: Mutation) !OwnedMutation {
        const owned_key = try allocator.dupe(u8, mutation.key);
        errdefer allocator.free(owned_key);
        const owned_value = if (mutation.value) |value| try allocator.dupe(u8, value) else null;
        return .{
            .seq = mutation.seq,
            .family = mutation.family,
            .kind = mutation.kind,
            .key = owned_key,
            .value = owned_value,
        };
    }

    pub fn deinit(self: *OwnedMutation, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        if (self.value) |value| allocator.free(value);
    }

    pub fn view(self: *const OwnedMutation) Mutation {
        return .{
            .seq = self.seq,
            .family = self.family,
            .kind = self.kind,
            .key = self.key,
            .value = self.value,
        };
    }
};
