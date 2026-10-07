// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Correct the PE stack reserve in Windows test executables emitted by Zig's
//! self-hosted backend. That backend currently ignores `--stack` at link time.
const std = @import("std");

const old_stack_reserve: u64 = 16 * 1024 * 1024;
const test_stack_reserve: u64 = 64 * 1024 * 1024;
const invalid_handle = std.math.maxInt(usize);

const FileBasicInfo = extern struct {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
};

extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, sharing: u32, security: ?*anyopaque, disposition: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) usize;
extern "kernel32" fn GetFileType(handle: usize) callconv(.winapi) u32;
extern "kernel32" fn GetFileInformationByHandleEx(handle: usize, class: i32, info: *anyopaque, size: u32) callconv(.winapi) i32;
extern "kernel32" fn SetFilePointerEx(handle: usize, distance: i64, new_position: ?*i64, move_method: u32) callconv(.winapi) i32;
extern "kernel32" fn ReadFile(handle: usize, bytes: [*]u8, len: u32, count: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn WriteFile(handle: usize, bytes: [*]const u8, len: u32, count: *u32, overlapped: ?*anyopaque) callconv(.winapi) i32;
extern "kernel32" fn FlushFileBuffers(handle: usize) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(handle: usize) callconv(.winapi) i32;

fn readExact(handle: usize, bytes: []u8) !void {
    var total: usize = 0;
    while (total < bytes.len) {
        var count: u32 = 0;
        if (ReadFile(handle, bytes[total..].ptr, @intCast(bytes.len - total), &count, null) == 0 or count == 0)
            return error.ShortRead;
        total += count;
    }
}

fn writeExact(handle: usize, bytes: []const u8) !void {
    var total: usize = 0;
    while (total < bytes.len) {
        var count: u32 = 0;
        if (WriteFile(handle, bytes[total..].ptr, @intCast(bytes.len - total), &count, null) == 0 or count == 0)
            return error.ShortWrite;
        total += count;
    }
}

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.iterateAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const path = args.next() orelse return error.InvalidArguments;
    if (args.next() != null) return error.InvalidArguments;

    const wide = try std.unicode.utf8ToUtf16LeAllocZ(init.gpa, path);
    defer init.gpa.free(wide);
    // Open the generated file itself, never a reparse target. Allow Zig's
    // cache owner and Windows scanners to retain their read handles while the
    // build graph keeps execution ordered after this eight-byte update.
    const handle = CreateFileW(wide.ptr, 0xc0000000, 0x7, null, 3, 0x00200000, null);
    if (handle == invalid_handle) return error.OpenFailed;
    defer _ = CloseHandle(handle);
    if (GetFileType(handle) != 1) return error.InvalidPe;
    var basic: FileBasicInfo = undefined;
    if (GetFileInformationByHandleEx(handle, 0, &basic, @sizeOf(FileBasicInfo)) == 0 or
        (basic.attributes & 0x400) != 0) return error.InvalidPe;

    var dos: [64]u8 = undefined;
    try readExact(handle, &dos);
    if (!std.mem.eql(u8, dos[0..2], "MZ")) return error.InvalidPe;
    const pe_offset = std.mem.readInt(u32, dos[0x3c..0x40], .little);
    if (pe_offset > 4096) return error.InvalidPe;

    // Signature + COFF header (24 bytes), followed by enough PE32+ optional
    // header bytes to include SizeOfStackReserve at optional offset 72.
    var pe: [104]u8 = undefined;
    if (SetFilePointerEx(handle, pe_offset, null, 0) == 0) return error.SeekFailed;
    try readExact(handle, &pe);
    if (!std.mem.eql(u8, pe[0..4], "PE\x00\x00") or
        std.mem.readInt(u16, pe[20..22], .little) < 80 or
        std.mem.readInt(u16, pe[24..26], .little) != 0x20b) return error.InvalidPe;
    const current = std.mem.readInt(u64, pe[96..104], .little);
    if (current == test_stack_reserve) return;
    if (current != old_stack_reserve) return error.UnexpectedStackReserve;

    var replacement: [8]u8 = undefined;
    std.mem.writeInt(u64, &replacement, test_stack_reserve, .little);
    if (SetFilePointerEx(handle, @as(i64, pe_offset) + 96, null, 0) == 0) return error.SeekFailed;
    try writeExact(handle, &replacement);
    if (FlushFileBuffers(handle) == 0) return error.FlushFailed;
}
