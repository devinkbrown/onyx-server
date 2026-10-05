// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! One typed, authenticated Windows Helix account-WAL custody frame. The
//! control channel authenticates the bytes; this codec verifies that a present
//! child HANDLE names the exact file object and length the predecessor sealed.
const std = @import("std");
const builtin = @import("builtin");
const store = @import("../store.zig");

pub const body_len = 112;
const magic = "HXWF";
const version: u16 = 1;
const present_flag: u16 = 1;
const file_id_info_class: i32 = 18;
const file_standard_info_class: i32 = 1;
const invalid_handle = std.math.maxInt(usize);

extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;

const StandardInfo = extern struct {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
    reserved: [2]u8,
};

comptime {
    if (@sizeOf(StandardInfo) != 24 or body_len != 104 + 8)
        @compileError("Windows WAL custody ABI mismatch");
}

pub const Error = error{ Unsupported, InvalidFrame, InvalidWitness };

/// The absent form has the same fixed size as a present descriptor. This
/// avoids changing the arena header and requires exactly one WAL turn before
/// READY even when no account store is configured.
pub fn encode(descriptor: ?*const store.WindowsWalDescriptor, target_pid: u32) Error![body_len]u8 {
    if (target_pid == 0) return error.InvalidFrame;
    var body: [body_len]u8 = @splat(0);
    @memcpy(body[0..4], magic);
    std.mem.writeInt(u16, body[4..6], version, .big);
    if (descriptor) |value| {
        if (value.handle == 0 or value.handle == invalid_handle or value.destination_pid != target_pid)
            return error.InvalidFrame;
        std.mem.writeInt(u16, body[6..8], present_flag, .big);
        std.mem.writeInt(u64, body[8..16], @intCast(value.handle), .big);
        std.mem.writeInt(u32, body[16..20], target_pid, .big);
        std.mem.writeInt(u64, body[24..32], value.witness.file.volume_serial, .big);
        @memcpy(body[32..48], &value.witness.file.file_id);
        std.mem.writeInt(u64, body[48..56], value.witness.parent_directory.volume_serial, .big);
        @memcpy(body[56..72], &value.witness.parent_directory.file_id);
        @memcpy(body[72..104], &value.witness.name_digest);
        std.mem.writeInt(u64, body[104..112], value.witness.length, .big);
    }
    return body;
}

fn actualFileWitness(handle: usize, expected: store.WindowsWalWitness) Error!void {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    var identity: store.WindowsFileIdInfo = undefined;
    if (GetFileInformationByHandleEx(handle, file_id_info_class, &identity, @sizeOf(@TypeOf(identity))) == 0 or
        !std.meta.eql(identity, expected.file)) return error.InvalidWitness;
    var standard: StandardInfo = undefined;
    if (GetFileInformationByHandleEx(handle, file_standard_info_class, &standard, @sizeOf(StandardInfo)) == 0 or
        standard.end_of_file < 0 or standard.directory != 0 or standard.delete_pending != 0 or
        @as(u64, @intCast(standard.end_of_file)) != expected.length) return error.InvalidWitness;
}

/// A malformed frame is fatal to the candidate process. `decode` never closes
/// a numeric HANDLE until it has authenticated framing, shape and exact file
/// identity; the caller owns a successful descriptor and must close or consume
/// it through OroStore. Unknown values are left for process-exit cleanup.
pub fn decode(bytes: []const u8, expected_pid: u32, forbidden_handles: []const usize) Error!?store.WindowsWalDescriptor {
    if (comptime builtin.os.tag != .windows) return error.Unsupported;
    if (expected_pid == 0 or bytes.len != body_len or !std.mem.eql(u8, bytes[0..4], magic) or
        std.mem.readInt(u16, bytes[4..6], .big) != version or
        std.mem.readInt(u32, bytes[20..24], .big) != 0) return error.InvalidFrame;
    const flag = std.mem.readInt(u16, bytes[6..8], .big);
    if (flag == 0) {
        for (bytes[8..]) |byte| if (byte != 0) return error.InvalidFrame;
        return null;
    }
    if (flag != present_flag or std.mem.readInt(u32, bytes[16..20], .big) != expected_pid)
        return error.InvalidFrame;
    const handle = std.math.cast(usize, std.mem.readInt(u64, bytes[8..16], .big)) orelse return error.InvalidFrame;
    if (handle == 0 or handle == invalid_handle) return error.InvalidFrame;
    for (forbidden_handles) |forbidden| if (handle == forbidden) return error.InvalidFrame;
    const witness = store.WindowsWalWitness{
        .file = .{ .volume_serial = std.mem.readInt(u64, bytes[24..32], .big), .file_id = bytes[32..48].* },
        .parent_directory = .{ .volume_serial = std.mem.readInt(u64, bytes[48..56], .big), .file_id = bytes[56..72].* },
        .name_digest = bytes[72..104].*,
        .length = std.mem.readInt(u64, bytes[104..112], .big),
    };
    try actualFileWitness(handle, witness);
    return .{ .handle = handle, .destination_pid = expected_pid, .witness = witness };
}

test "Windows WAL custody frame binds exact file object, length and target process" {
    if (comptime builtin.os.tag != .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const runtime = @import("../os_runtime.zig");
    const private = try runtime.createPrivateDirectoryWindows(tmp.dir, "private");
    private.close(std.testing.io);
    var account_store = try store.OroStore.openPrivateWindowsWithConfig(std.testing.allocator, std.testing.io, tmp.dir, "private/accounts.wal", .{});
    defer account_store.deinit();
    try account_store.put(.accounts, "alice", "present");
    const pid = GetCurrentProcessId();
    var transfer = try account_store.duplicatePrivateWalToWindowsProcess(GetCurrentProcess());
    defer transfer.deinit();
    const body = try encode(&transfer.descriptor, pid);
    var altered = body;
    std.mem.writeInt(u64, altered[104..112], transfer.descriptor.witness.length + 1, .big);
    try std.testing.expectError(error.InvalidWitness, decode(&altered, pid, &.{}));
    altered = body;
    altered[32] ^= 1;
    try std.testing.expectError(error.InvalidWitness, decode(&altered, pid, &.{}));
    altered = body;
    std.mem.writeInt(u32, altered[16..20], pid + 1, .big);
    try std.testing.expectError(error.InvalidFrame, decode(&altered, pid, &.{}));
    try std.testing.expectError(error.InvalidFrame, decode(&body, pid, &.{transfer.descriptor.handle}));
    var decoded = (try decode(&body, pid, &.{})) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualDeep(transfer.descriptor.witness, decoded.witness);
    _ = transfer.release();
    defer decoded.deinitReceived();
    const absent = try encode(null, pid);
    try std.testing.expect((try decode(&absent, pid, &.{})) == null);
    altered = absent;
    altered[111] = 1;
    try std.testing.expectError(error.InvalidFrame, decode(&altered, pid, &.{}));
}

extern "kernel32" fn GetCurrentProcess() callconv(.winapi) usize;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
