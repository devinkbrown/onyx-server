// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned property records and allocation-atomic raw record cloning.

const std = @import("std");
const model = @import("model.zig");

pub const Entry = struct {
    key: []u8,
    value: []u8,
    owner: []u8,
    access: model.AccessLevel,

    pub fn deinit(self: Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
        allocator.free(self.owner);
    }
};

pub const EntityState = struct {
    entity: model.Entity,
    props: std.StringHashMap(Entry),
    prop_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, entity: model.Entity) EntityState {
        return .{
            .entity = entity,
            .props = std.StringHashMap(Entry).init(allocator),
        };
    }

    pub fn deinit(self: *EntityState, allocator: std.mem.Allocator) void {
        allocator.free(self.entity.id);
        var it = self.props.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.props.deinit();
        self.* = undefined;
    }
};

pub fn cloneCheckpointEntry(
    allocator: std.mem.Allocator,
    normalized_key_source: []const u8,
    key_source: []const u8,
    value_source: []const u8,
    owner_source: []const u8,
    access: model.AccessLevel,
) std.mem.Allocator.Error!struct { normalized_key: []u8, entry: Entry } {
    const normalized_key = try allocator.dupe(u8, normalized_key_source);
    errdefer allocator.free(normalized_key);
    const key = try allocator.dupe(u8, key_source);
    errdefer allocator.free(key);
    const value = try allocator.dupe(u8, value_source);
    errdefer allocator.free(value);
    const owner = try allocator.dupe(u8, owner_source);
    return .{
        .normalized_key = normalized_key,
        .entry = .{ .key = key, .value = value, .owner = owner, .access = access },
    };
}
