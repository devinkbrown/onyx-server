// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit bootstrap password input. No terminal, argv value, environment,
//! logging, or persistent representation belongs in this leaf.
const std = @import("std");
const builtin = @import("builtin");
const workflow = @import("setup_workflow.zig");

pub const Source = union(enum) { private_file: []const u8, fd: i32 };
pub const Secret = struct {
    bytes: [515]u8 = undefined,
    len: usize = 0,
    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }
    pub fn deinit(self: *Secret) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

pub fn read(io: std.Io, source: Source, secret: *Secret) !void {
    secret.deinit();
    errdefer secret.deinit();
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    var owned: ?std.Io.File = null;
    defer if (owned) |file| file.close(io);
    const file = switch (source) {
        .private_file => |path| blk: {
            const held = try std.Io.Dir.cwd().openFile(io, path, .{ .path_only = true, .follow_symlinks = false });
            defer held.close(io);
            try requirePrivate(io, held);
            var buf: [64]u8 = undefined;
            const fd_path = try std.fmt.bufPrint(&buf, "/proc/self/fd/{d}", .{held.handle});
            owned = try std.Io.Dir.openFileAbsolute(io, fd_path, .{});
            try requirePrivate(io, owned.?);
            if ((try owned.?.stat(io)).inode != (try held.stat(io)).inode) return error.InsecurePasswordSource;
            break :blk owned.?;
        },
        .fd => |fd| blk: {
            if (fd < 3) return error.InvalidPasswordDescriptor;
            while (true) switch (std.os.linux.errno(std.os.linux.fcntl(fd, std.os.linux.F.GETFD, 0))) {
                .SUCCESS => break,
                .INTR => continue,
                else => return error.InvalidPasswordDescriptor,
            };
            const input = std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
            if (try input.isTty(io)) return error.TerminalPasswordInputRefused;
            switch ((try input.stat(io)).kind) {
                .file => try requirePrivate(io, input),
                .named_pipe => {},
                else => return error.InsecurePasswordSource,
            }
            break :blk input;
        },
    };
    while (secret.len < secret.bytes.len) {
        const n = file.readStreaming(io, &.{secret.bytes[secret.len..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        secret.len += n;
    }
    if (secret.len == secret.bytes.len) return error.InvalidPasswordInput;
    // Permit one conventional line ending, preserve intentional spaces, and
    // never trim/echo arbitrary input. Canonical Services applies policy.
    if (secret.len != 0 and secret.bytes[secret.len - 1] == '\n') {
        secret.len -= 1;
        if (secret.len != 0 and secret.bytes[secret.len - 1] == '\r') secret.len -= 1;
    }
    if (secret.len == 0 or secret.len > 512) return error.InvalidPasswordInput;
    for (secret.slice()) |c| if (c == 0 or c == '\n' or c == '\r') return error.InvalidPasswordInput;
}

fn requirePrivate(io: std.Io, file: std.Io.File) !void {
    try workflow.requireDraftOwner(file, std.os.linux.geteuid());
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.nlink != 1 or stat.permissions.toMode() & 0o077 != 0) return error.InsecurePasswordSource;
}

test "setup account secret reader preserves spaces rejects broad inputs and wipes errors" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const parent = try tmp.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(parent);
    const path = try std.fs.path.join(allocator, &.{ parent, "password" });
    defer allocator.free(path);
    try workflow.publish(std.testing.io, tmp.dir, "password", "  intentional spaces  \r\n");
    var secret: Secret = .{};
    defer secret.deinit();
    try read(std.testing.io, .{ .private_file = path }, &secret);
    try std.testing.expectEqualStrings("  intentional spaces  ", secret.slice());
    try tmp.dir.setFilePermissions(std.testing.io, "password", .fromMode(0o644), .{});
    try std.testing.expectError(error.InsecurePasswordSource, read(std.testing.io, .{ .private_file = path }, &secret));
    for (secret.bytes) |c| try std.testing.expectEqual(@as(u8, 0), c);
    try std.testing.expectError(error.InvalidPasswordDescriptor, read(std.testing.io, .{ .fd = 999999 }, &secret));
    try workflow.publish(std.testing.io, tmp.dir, "too-big", &@as([515]u8, @splat('a')));
    const oversized = try std.fs.path.join(allocator, &.{ parent, "too-big" });
    defer allocator.free(oversized);
    try std.testing.expectError(error.InvalidPasswordInput, read(std.testing.io, .{ .private_file = oversized }, &secret));
    for (secret.bytes) |c| try std.testing.expectEqual(@as(u8, 0), c);
}
