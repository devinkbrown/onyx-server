// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role-based operator groups for Onyx Server.
//!
//! Operator groups are named privilege bundles with optional parent links. They
//! compose the daemon's existing `oper.OperPrivileges` flags without redefining
//! or translating the privilege model. Storage is owned by the registry, while
//! callers pass allocators explicitly to mutating lifecycle operations.

const std = @import("std");
const oper = @import("oper.zig");

/// Maximum parent links followed while composing effective privileges.
pub const max_inheritance_depth: usize = 32;

pub const AddError = std.mem.Allocator.Error || error{
    EmptyName,
    EmptyParentName,
    DuplicateGroup,
};

/// One owned operator group.
pub const Group = struct {
    name: []u8,
    privileges: oper.OperPrivileges,
    inherits: ?[]u8 = null,

    fn deinit(self: *Group, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.inherits) |parent| allocator.free(parent);
        self.* = undefined;
    }
};

/// Owned registry of operator groups.
pub const Registry = struct {
    groups: std.StringHashMapUnmanaged(Group) = .empty,

    pub fn init() Registry {
        return .{};
    }

    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        var it = self.groups.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        self.groups.deinit(allocator);
        self.* = undefined;
    }

    /// Add a group. Names are duplicated and owned by the registry.
    pub fn add(
        self: *Registry,
        allocator: std.mem.Allocator,
        name: []const u8,
        privileges: oper.OperPrivileges,
        inherits: ?[]const u8,
    ) AddError!void {
        if (name.len == 0) return error.EmptyName;
        if (inherits) |parent| {
            if (parent.len == 0) return error.EmptyParentName;
        }
        if (self.groups.contains(name)) return error.DuplicateGroup;

        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);

        const owned_parent = if (inherits) |parent|
            try allocator.dupe(u8, parent)
        else
            null;
        errdefer if (owned_parent) |parent| allocator.free(parent);

        const group = Group{
            .name = owned_name,
            .privileges = privileges,
            .inherits = owned_parent,
        };
        const put = try self.groups.getOrPut(allocator, owned_name);
        std.debug.assert(!put.found_existing);
        put.value_ptr.* = group;
    }

    /// Return a borrowed group snapshot, or null when absent.
    pub fn get(self: *const Registry, name: []const u8) ?Group {
        return self.groups.get(name);
    }

    /// Compose own and inherited privileges. Unknown names produce empty flags.
    pub fn effectivePrivileges(self: *const Registry, name: []const u8) oper.OperPrivileges {
        var out = oper.OperPrivileges.empty;
        var next: ?[]const u8 = name;
        var depth: usize = 0;

        while (next) |group_name| {
            if (depth >= max_inheritance_depth) break;
            depth += 1;

            const group = self.get(group_name) orelse break;
            mergePrivileges(&out, group.privileges);
            next = group.inherits;
        }

        return out;
    }

    pub fn has(self: *const Registry, name: []const u8, privilege: oper.Privilege) bool {
        return self.effectivePrivileges(name).has(privilege);
    }
};

fn mergePrivileges(dst: *oper.OperPrivileges, src: oper.OperPrivileges) void {
    inline for (@typeInfo(oper.Privilege).@"enum".field_values) |field_value| {
        const privilege: oper.Privilege = @fromBackingInt(@intCast(field_value));
        if (src.has(privilege)) dst.insert(privilege);
    }
}

fn privs(items: []const oper.Privilege) oper.OperPrivileges {
    return oper.OperPrivileges.initMany(items);
}

test "inheritance unions direct parent privileges" {
    var registry = Registry.init();
    defer registry.deinit(std.testing.allocator);

    try registry.add(std.testing.allocator, "base", privs(&.{
        .audit_read,
        .event_subscribe,
    }), null);
    try registry.add(std.testing.allocator, "staff", privs(&.{
        .client_moderate,
    }), "base");

    const effective = registry.effectivePrivileges("staff");
    try std.testing.expect(effective.has(.client_moderate));
    try std.testing.expect(effective.has(.audit_read));
    try std.testing.expect(effective.has(.event_subscribe));
    try std.testing.expect(!effective.has(.server_shutdown));
}

test "two-level chain composes all ancestor privileges" {
    var registry = Registry.init();
    defer registry.deinit(std.testing.allocator);

    try registry.add(std.testing.allocator, "observer", privs(&.{
        .audit_read,
    }), null);
    try registry.add(std.testing.allocator, "moderator", privs(&.{
        .channel_moderate,
    }), "observer");
    try registry.add(std.testing.allocator, "admin", privs(&.{
        .server_rehash,
    }), "moderator");

    const effective = registry.effectivePrivileges("admin");
    try std.testing.expect(effective.has(.server_rehash));
    try std.testing.expect(effective.has(.channel_moderate));
    try std.testing.expect(effective.has(.audit_read));
    try std.testing.expectEqual(@as(usize, 3), effective.count());
}

test "cycle is bounded and still returns encountered privileges" {
    var registry = Registry.init();
    defer registry.deinit(std.testing.allocator);

    try registry.add(std.testing.allocator, "north", privs(&.{
        .service_admin,
    }), "south");
    try registry.add(std.testing.allocator, "south", privs(&.{
        .mesh_admin,
    }), "north");

    const effective = registry.effectivePrivileges("north");
    try std.testing.expect(effective.has(.service_admin));
    try std.testing.expect(effective.has(.mesh_admin));
    try std.testing.expectEqual(@as(usize, 2), effective.count());
}

test "has reflects inherited privileges" {
    var registry = Registry.init();
    defer registry.deinit(std.testing.allocator);

    try registry.add(std.testing.allocator, "root", privs(&.{
        .oper_grant,
    }), null);
    try registry.add(std.testing.allocator, "grantor", privs(&.{
        .server_rehash,
    }), "root");

    try std.testing.expect(registry.has("grantor", .oper_grant));
    try std.testing.expect(registry.has("grantor", .server_rehash));
    try std.testing.expect(!registry.has("grantor", .server_shutdown));
}

test "unknown group returns null and empty privileges" {
    var registry = Registry.init();
    defer registry.deinit(std.testing.allocator);

    try registry.add(std.testing.allocator, "known", privs(&.{
        .audit_read,
    }), null);

    try std.testing.expect(registry.get("missing") == null);
    try std.testing.expectEqual(@as(usize, 0), registry.effectivePrivileges("missing").count());
    try std.testing.expect(!registry.has("missing", .audit_read));
}

test "add owns names and rejects duplicates" {
    var registry = Registry.init();
    defer registry.deinit(std.testing.allocator);

    var name_buf = [_]u8{ 'l', 'o', 'c', 'a', 'l' };
    var parent_buf = [_]u8{ 'p', 'a', 'r', 'e', 'n', 't' };

    try registry.add(std.testing.allocator, name_buf[0..], oper.OperPrivileges.empty, parent_buf[0..]);
    name_buf[0] = 'x';
    parent_buf[0] = 'x';

    const stored = registry.get("local").?;
    try std.testing.expectEqualStrings("local", stored.name);
    try std.testing.expectEqualStrings("parent", stored.inherits.?);
    try std.testing.expectError(error.DuplicateGroup, registry.add(
        std.testing.allocator,
        "local",
        oper.OperPrivileges.empty,
        null,
    ));
}
