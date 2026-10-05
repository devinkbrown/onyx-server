// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Windows custody for one encrypted native Helix arena. The section is
//! unnamed and pagefile-backed. Only a read-only handle leaves create(); a
//! successor must authenticate its complete declared length before adoption.
const std = @import("std");
const builtin = @import("builtin");
const envelope = @import("native_arena_envelope.zig");

const invalid_handle = std.math.maxInt(usize);
const page_readwrite: u32 = 0x04;
const file_map_write: u32 = 0x0002;
const file_map_read: u32 = 0x0004;
const max_wire_bytes = envelope.max_plaintext_bytes + envelope.header_len + envelope.tag_len;

extern "kernel32" fn CreateFileMappingW(file: usize, attributes: ?*anyopaque, protect: u32, size_high: u32, size_low: u32, name: ?[*:0]const u16) callconv(.winapi) usize;
extern "kernel32" fn MapViewOfFile(handle: usize, access: u32, offset_high: u32, offset_low: u32, bytes: usize) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn UnmapViewOfFile(view: *const anyopaque) callconv(.winapi) i32;
extern "kernel32" fn DuplicateHandle(source_process: usize, source_handle: usize, target_process: usize, target_handle: *usize, desired_access: u32, inherit_handle: i32, options: u32) callconv(.winapi) i32;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

pub const Error = envelope.Error || error{
    Unsupported,
    InvalidHandle,
    InvalidSize,
    CreateFailed,
    MapFailed,
    UnmapFailed,
    DuplicateFailed,
    WritableArena,
};

fn validSize(size: usize) Error!void {
    if (size < envelope.header_len + envelope.tag_len) return error.InvalidSize;
    if (size > max_wire_bytes) return error.ArenaTooLarge;
}

pub const Arena = struct {
    handle: usize = 0,
    size: usize = 0,

    pub fn deinit(self: *Arena) void {
        if (comptime builtin.os.tag == .windows) {
            if (self.handle != 0 and self.handle != invalid_handle) _ = CloseHandle(self.handle);
        }
        self.* = .{};
    }

    /// The caller owns and wipes its plaintext; the sealer retains the key
    /// only for the authenticated private control exchange. No named object or
    /// write-capable HANDLE is retained after this function returns.
    pub fn create(allocator: std.mem.Allocator, sealer: *envelope.Sealer, plaintext: []const u8) Error!Arena {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        const wire = try sealer.seal(allocator, plaintext);
        defer allocator.free(wire);
        try validSize(wire.len);
        const length: u64 = @intCast(wire.len);
        const writer = CreateFileMappingW(invalid_handle, null, page_readwrite, @intCast(length >> 32), @truncate(length), null);
        if (writer == 0) return error.CreateFailed;
        defer _ = CloseHandle(writer);
        const view = MapViewOfFile(writer, file_map_write, 0, 0, wire.len) orelse return error.MapFailed;
        const bytes: [*]u8 = @ptrCast(view);
        @memcpy(bytes[0..wire.len], wire);
        if (UnmapViewOfFile(view) == 0) return error.UnmapFailed;

        var reader: usize = 0;
        const own_process = GetCurrentProcess();
        if (DuplicateHandle(own_process, writer, own_process, &reader, file_map_read, 0, 0) == 0 or reader == 0) return error.DuplicateFailed;
        return .{ .handle = reader, .size = wire.len };
    }

    /// The returned numeric handle is owned by target_process and must be
    /// conveyed only over the authenticated private control channel. The
    /// process HANDLE must authorize PROCESS_DUP_HANDLE.
    pub fn duplicateReadOnlyForProcess(self: *const Arena, target_process: usize) Error!usize {
        if (comptime builtin.os.tag != .windows) return error.Unsupported;
        // GetCurrentProcess() is the valid pseudo HANDLE -1. Let the kernel
        // validate every nonzero target process HANDLE during duplication.
        if (self.handle == 0 or self.handle == invalid_handle or target_process == 0) return error.InvalidHandle;
        try validSize(self.size);
        var remote: usize = 0;
        if (DuplicateHandle(GetCurrentProcess(), self.handle, target_process, &remote, file_map_read, 0, 0) == 0 or remote == 0) return error.DuplicateFailed;
        return remote;
    }
};

/// Reject a write-capable section handle. The length comes from the validated
/// private control frame, is bounded before mapping, and is fully AEAD checked
/// before plaintext can reach a capsule decoder. The caller wipes the result.
pub fn read(allocator: std.mem.Allocator, handle: usize, size: usize, key: envelope.Key, expected_id: envelope.UpgradeId) Error![]u8 {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (handle == 0 or handle == invalid_handle) return error.InvalidHandle;
    try validSize(size);
    if (MapViewOfFile(handle, file_map_write, 0, 0, size)) |writable| {
        _ = UnmapViewOfFile(writable);
        return error.WritableArena;
    }
    const view = MapViewOfFile(handle, file_map_read, 0, 0, size) orelse return error.MapFailed;
    defer _ = UnmapViewOfFile(view);
    const bytes: [*]const u8 = @ptrCast(view);
    return envelope.open(allocator, key, expected_id, bytes[0..size]);
}

test "Windows Helix arena duplicates only read-only ciphertext and authenticates before use" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var sealer = try envelope.Sealer.initRandom();
    defer sealer.deinit();
    const secret = "TLS and Mooring snapshot secret";
    var arena = try Arena.create(allocator, &sealer, secret);
    defer arena.deinit();
    try std.testing.expect(MapViewOfFile(arena.handle, file_map_write, 0, 0, arena.size) == null);
    const view = MapViewOfFile(arena.handle, file_map_read, 0, 0, arena.size) orelse return error.MapFailed;
    const wire: [*]const u8 = @ptrCast(view);
    try std.testing.expect(std.mem.indexOf(u8, wire[0..arena.size], secret) == null);
    try std.testing.expect(UnmapViewOfFile(view) != 0);

    const duplicate = try arena.duplicateReadOnlyForProcess(GetCurrentProcess());
    defer _ = CloseHandle(duplicate);
    try std.testing.expect(MapViewOfFile(duplicate, file_map_write, 0, 0, arena.size) == null);
    const clear = try read(allocator, duplicate, arena.size, sealer.key, sealer.upgrade_id);
    defer {
        std.crypto.secureZero(u8, clear);
        allocator.free(clear);
    }
    try std.testing.expectEqualStrings(secret, clear);
    try std.testing.expectError(error.WrongUpgrade, read(allocator, duplicate, arena.size, sealer.key, @splat(0)));
    try std.testing.expectError(error.AuthenticationFailed, read(allocator, duplicate, arena.size, @splat(0), sealer.upgrade_id));
    try std.testing.expectError(error.InvalidEnvelope, read(allocator, duplicate, arena.size - 1, sealer.key, sealer.upgrade_id));
}

test "Windows Helix arena rejects writable, invalid and oversized handles" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    const size = envelope.header_len + envelope.tag_len;
    const writer = CreateFileMappingW(invalid_handle, null, page_readwrite, 0, @intCast(size), null);
    if (writer == 0) return error.CreateFailed;
    defer _ = CloseHandle(writer);
    try std.testing.expectError(error.WritableArena, read(std.testing.allocator, writer, size, @splat(0), @splat(0)));
    try std.testing.expectError(error.InvalidHandle, read(std.testing.allocator, 0, size, @splat(0), @splat(0)));
    try std.testing.expectError(error.InvalidSize, read(std.testing.allocator, writer, size - 1, @splat(0), @splat(0)));
    try std.testing.expectError(error.ArenaTooLarge, read(std.testing.allocator, writer, max_wire_bytes + 1, @splat(0), @splat(0)));
    var arena = Arena{};
    try std.testing.expectError(error.InvalidHandle, arena.duplicateReadOnlyForProcess(GetCurrentProcess()));
}
