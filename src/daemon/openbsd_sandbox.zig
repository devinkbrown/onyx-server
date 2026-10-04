// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Configured filesystem access for the full OpenBSD daemon. Resolve parents
//! before locking unveil; merge permissions without granting a global home tree.
const std = @import("std");
const kernel = @import("kernel_other.zig");

pub const Plan = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    entries: std.ArrayList(kernel.RuntimeAccess) = .empty,

    pub fn deinit(self: *Plan) void {
        for (self.entries.items) |entry| self.allocator.free(entry.path);
        self.entries.deinit(self.allocator);
    }

    pub fn addDirectory(self: *Plan, path: []const u8, perms: [:0]const u8) !void {
        if (path.len == 0) return;
        const resolved = std.Io.Dir.cwd().realPathFileAlloc(self.io, path, self.allocator) catch |err| blk: {
            if (err != error.FileNotFound or std.mem.indexOfScalar(u8, perms, 'c') == null) return err;
            try std.Io.Dir.cwd().createDirPath(self.io, path);
            break :blk try std.Io.Dir.cwd().realPathFileAlloc(self.io, path, self.allocator);
        };
        errdefer self.allocator.free(resolved);
        try self.appendOwned(resolved, perms);
    }

    /// File writers need their parent for WAL sidecars and atomic replacement.
    /// Readers need the named file only, including a not-yet-created final name.
    pub fn addFile(self: *Plan, path: []const u8, writable: bool) !void {
        if (path.len == 0) return;
        const parent = std.fs.path.dirname(path) orelse ".";
        if (writable) return self.addDirectory(parent, "rwc");
        const resolved_parent = try std.Io.Dir.cwd().realPathFileAlloc(self.io, parent, self.allocator);
        defer self.allocator.free(resolved_parent);
        const joined = try std.fs.path.join(self.allocator, &.{ resolved_parent, std.fs.path.basename(path) });
        defer self.allocator.free(joined);
        const named = try self.allocator.dupeSentinel(u8, joined, 0);
        errdefer self.allocator.free(named);
        try self.appendOwned(named, "r");
    }

    /// Upgrade images may replace the launch file within its configured parent.
    /// Allow execute/read there, without opening any unrelated parent subtree.
    pub fn addExecutable(self: *Plan, path: []const u8) !void {
        if (path.len == 0) return error.MissingExecutablePath;
        const resolved = try std.Io.Dir.cwd().realPathFileAlloc(self.io, path, self.allocator);
        defer self.allocator.free(resolved);
        try self.addDirectory(std.fs.path.dirname(resolved) orelse return error.MissingExecutablePath, "rx");
    }

    /// This grants observation of the one root-created service namespace, not
    /// authority to create it. The managed owner separately validates its actual
    /// directory, endpoint and lease before installing the sandbox.
    pub fn addNativeServiceNamespace(self: *Plan) !void {
        const owned = try self.allocator.dupeSentinel(u8, "/var/run/onyx_server", 0);
        errdefer self.allocator.free(owned);
        try self.appendOwned(owned, "r");
    }

    fn appendOwned(self: *Plan, path: [:0]const u8, perms: [:0]const u8) !void {
        for (self.entries.items) |*entry| {
            if (!std.mem.eql(u8, entry.path, path)) continue;
            entry.perms = mergePermissions(entry.perms, perms);
            self.allocator.free(path);
            return;
        }
        try self.entries.append(self.allocator, .{ .path = path, .perms = perms });
    }

    pub fn install(self: *const Plan) !void {
        try kernel.pledgeRuntimePaths(self.entries.items);
    }
};

fn mergePermissions(a: []const u8, b: []const u8) [:0]const u8 {
    const write = std.mem.indexOfScalar(u8, a, 'w') != null or std.mem.indexOfScalar(u8, b, 'w') != null;
    const exec = std.mem.indexOfScalar(u8, a, 'x') != null or std.mem.indexOfScalar(u8, b, 'x') != null;
    return if (write) (if (exec) "rwcx" else "rwc") else (if (exec) "rx" else "r");
}

test "OpenBSD confinement plan merges exact paths and unwinds owned names" {
    var plan = Plan{ .allocator = std.testing.allocator, .io = std.testing.io };
    defer plan.deinit();
    try plan.appendOwned(try std.testing.allocator.dupeSentinel(u8, "/configured/data", 0), "r");
    try plan.appendOwned(try std.testing.allocator.dupeSentinel(u8, "/configured/data", 0), "rwc");
    try plan.appendOwned(try std.testing.allocator.dupeSentinel(u8, "/configured/bin", 0), "rx");
    try std.testing.expectEqual(@as(usize, 2), plan.entries.items.len);
    try std.testing.expectEqualStrings("rwc", plan.entries.items[0].perms);
    try std.testing.expectEqualStrings("rx", plan.entries.items[1].perms);
    try std.testing.expectEqualStrings("rwcx", mergePermissions("rwc", "rx"));
}

fn serviceNamespaceAllocation(allocator: std.mem.Allocator) !void {
    var plan: Plan = .{ .allocator = allocator, .io = std.testing.io };
    defer plan.deinit();
    try plan.addNativeServiceNamespace();
    try std.testing.expectEqual(@as(usize, 1), plan.entries.items.len);
    try std.testing.expectEqualStrings("/var/run/onyx_server", plan.entries.items[0].path);
    try std.testing.expectEqualStrings("r", plan.entries.items[0].perms);
    try plan.addNativeServiceNamespace();
    try std.testing.expectEqual(@as(usize, 1), plan.entries.items.len);
}
test "OpenBSD service confinement is exact read only and every allocation unwinds" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, serviceNamespaceAllocation, .{});
}
