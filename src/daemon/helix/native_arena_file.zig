// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenBSD arena custody: only AEAD ciphertext reaches the filesystem. Publish
//! a read-only, unlinked descriptor after checking identity/size and closing
//! the sole writer. This is ownership-enforced, not Linux kernel memfd sealing.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const envelope = @import("native_arena_envelope.zig");
const runtime = @import("../os_runtime.zig");

pub const Error = error{ Unsupported, CreateFailed, WriteFailed, ReopenFailed, IdentityMismatch, UnlinkFailed, ReadFailed } || envelope.Error;

pub const Arena = struct {
    fd: i32 = -1,
    size: usize = 0,

    pub fn deinit(self: *Arena) void {
        runtime.close(self.fd);
        self.* = .{};
    }

    /// The caller already authenticated the actual running successor and owns
    /// encoded plaintext. Wipe that plaintext independently on every exit.
    pub fn create(allocator: std.mem.Allocator, sealer: *envelope.Sealer, plaintext: []const u8) Error!Arena {
        if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
        const wire = try sealer.seal(allocator, plaintext);
        defer allocator.free(wire);
        var name_buffer: [96]u8 = undefined;
        const name = std.fmt.bufPrintSentinel(&name_buffer, "/tmp/onyx-helix-{x}.arena", .{sealer.upgrade_id}, 0) catch return error.CreateFailed;
        const opened = sys.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(posix.mode_t, 0o600));
        if (posix.errno(opened) != .SUCCESS) return error.CreateFailed;
        const writer: i32 = @intCast(opened);
        defer runtime.close(writer);
        var named = true;
        defer if (named) {
            _ = sys.unlink(name.ptr);
        };
        var offset: usize = 0;
        while (offset < wire.len) {
            const count = runtime.write(writer, wire[offset..]) catch |err| switch (err) {
                error.Interrupted => continue,
                else => return error.WriteFailed,
            };
            if (count == 0) return error.WriteFailed;
            offset += count;
        }
        var original: posix.Stat = undefined;
        if (posix.errno(sys.fstat(writer, &original)) != .SUCCESS) return error.IdentityMismatch;
        if (original.size < 0 or @as(u64, @intCast(original.size)) != wire.len) return error.IdentityMismatch;
        const reopened = sys.open(name.ptr, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true }, @as(posix.mode_t, 0));
        if (posix.errno(reopened) != .SUCCESS) return error.ReopenFailed;
        const reader: i32 = @intCast(reopened);
        errdefer runtime.close(reader);
        var actual: posix.Stat = undefined;
        if (posix.errno(sys.fstat(reader, &actual)) != .SUCCESS or
            actual.dev != original.dev or actual.ino != original.ino or actual.size != original.size)
            return error.IdentityMismatch;
        if (posix.errno(sys.unlink(name.ptr)) != .SUCCESS) return error.UnlinkFailed;
        named = false;
        // The writer's defer runs before this descriptor reaches the caller.
        return .{ .fd = reader, .size = wire.len };
    }
};

/// Enforce the arena ceiling on the descriptor itself before allocation and
/// authenticate the entire stream before returning any plaintext to adoption.
pub fn read(allocator: std.mem.Allocator, fd: i32, key: envelope.Key, expected_id: envelope.UpgradeId) Error![]u8 {
    if (comptime builtin.os.tag != .openbsd) return error.Unsupported;
    const flags = sys.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (posix.errno(flags) != .SUCCESS) return error.ReadFailed;
    const options: posix.O = @bitCast(@as(u32, @intCast(flags)));
    if (options.ACCMODE != .RDONLY) return error.ReadFailed;
    var stat: posix.Stat = undefined;
    if (posix.errno(sys.fstat(fd, &stat)) != .SUCCESS or stat.size < 0) return error.ReadFailed;
    if ((stat.mode & posix.S.IFMT) != posix.S.IFREG) return error.ReadFailed;
    const size: usize = @intCast(stat.size);
    if (size > envelope.max_plaintext_bytes + envelope.header_len + envelope.tag_len) return error.ArenaTooLarge;
    if (size < envelope.header_len + envelope.tag_len) return error.InvalidEnvelope;
    const wire = try allocator.alloc(u8, size);
    defer allocator.free(wire);
    var offset: usize = 0;
    while (offset < wire.len) {
        const count = runtime.pread(fd, wire[offset..], offset) catch |err| switch (err) {
            error.Interrupted => continue,
            else => return error.ReadFailed,
        };
        if (count == 0) return error.ReadFailed;
        offset += count;
    }
    var trailing: [1]u8 = undefined;
    const extra = runtime.pread(fd, &trailing, offset) catch return error.ReadFailed;
    if (extra != 0) return error.InvalidEnvelope;
    return envelope.open(allocator, key, expected_id, wire);
}

test "OpenBSD native arena exposes only read-only ciphertext and authenticates before read" {
    if (comptime builtin.os.tag != .openbsd) return error.SkipZigTest;
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    const allocator = std.testing.allocator;
    const secret = "TLS Mooring private state must not reach a file";
    const writer = try runtime.openTruncateZ("/tmp/onyx-native-arena-writer-test", 0o600);
    defer runtime.close(writer);
    defer _ = sys.unlink("/tmp/onyx-native-arena-writer-test");
    try std.testing.expectError(error.ReadFailed, read(allocator, writer, sealer.key, sealer.upgrade_id));
    var arena = try Arena.create(allocator, &sealer, secret);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidDescriptor, runtime.write(arena.fd, "change"));
    try std.testing.expect(posix.errno(sys.ftruncate(arena.fd, 0)) != .SUCCESS);
    var ciphertext: [128]u8 = undefined;
    const count = try runtime.pread(arena.fd, &ciphertext, 0);
    try std.testing.expect(std.mem.indexOf(u8, ciphertext[0..count], secret) == null);
    const clear = try read(allocator, arena.fd, sealer.key, sealer.upgrade_id);
    defer {
        std.crypto.secureZero(u8, clear);
        allocator.free(clear);
    }
    try std.testing.expectEqualStrings(secret, clear);
    try std.testing.expectError(error.WrongUpgrade, read(allocator, arena.fd, sealer.key, @splat(0)));
    try std.testing.expectError(error.AuthenticationFailed, read(allocator, arena.fd, @splat(0), sealer.upgrade_id));
    const retired = arena.fd;
    arena.deinit();
    try std.testing.expect(!runtime.fdValid(retired));
}
