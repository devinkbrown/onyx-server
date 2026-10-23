// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store regression tests: support.

const std = @import("std");
const record_header_len = @import("contracts.zig").record_header_len;
const OroStore = @import("engine.zig").OroStore;
const checksum = @import("wal.zig").checksum;
const readU32 = @import("wal.zig").readU32;
const writeU32 = @import("wal.zig").writeU32;

pub fn openTestStore(tmp: std.testing.TmpDir, name: []const u8) !OroStore {
    return OroStore.open(std.testing.allocator, std.testing.io, tmp.dir, name);
}

pub fn readWalForTest(tmp: std.testing.TmpDir, name: []const u8) ![]u8 {
    return tmp.dir.readFileAlloc(std.testing.io, name, std.testing.allocator, .unlimited);
}

pub fn rewriteTestFile(tmp: std.testing.TmpDir, name: []const u8, bytes: []const u8) !void {
    var file = try tmp.dir.createFile(std.testing.io, name, .{ .truncate = true, .read = true });
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, bytes, 0);
    try file.sync(std.testing.io);
}

pub fn refreshRecordChecksum(bytes: []u8, payload_start: usize) void {
    const payload_len = readU32(bytes[payload_start - record_header_len ..][0..4]);
    var sum_bytes: [4]u8 = undefined;
    writeU32(&sum_bytes, checksum(bytes[payload_start .. payload_start + payload_len]));
    @memcpy(bytes[payload_start - 4 .. payload_start], &sum_bytes);
}

pub fn findRecordPayloadByKind(bytes: []const u8, kind: u8) ?usize {
    var offset: usize = 0;
    while (bytes.len - offset >= record_header_len) {
        const payload_len: usize = readU32(bytes[offset..][0..4]);
        const payload_start = offset + record_header_len;
        const record_end = std.math.add(usize, payload_start, payload_len) catch return null;
        if (record_end > bytes.len) return null;
        if (payload_len != 0 and bytes[payload_start] == kind) return payload_start;
        offset = record_end;
    }
    return null;
}
