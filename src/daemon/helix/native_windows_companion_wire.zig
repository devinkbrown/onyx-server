// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-size authenticated framing for Windows companion scheduler custody.

const std = @import("std");

pub const header_len: usize = 12;
pub const checksum_len: usize = 32;
pub const Error = error{ InvalidSnapshot, ConfigMismatch } || std.mem.Allocator.Error;

pub fn isCheckpoint(bytes: []const u8, magic: [4]u8) bool {
    return bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &magic);
}

pub fn validateFrame(bytes: []const u8, magic: [4]u8, domain: []const u8, payload_len: usize) error{InvalidSnapshot}![]const u8 {
    if (bytes.len != header_len + payload_len + checksum_len or !isCheckpoint(bytes, magic)) return error.InvalidSnapshot;
    if (bytes[4] != 1 or !std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 }) or
        @as(usize, std.mem.readInt(u32, bytes[8..12], .little)) != payload_len) return error.InvalidSnapshot;
    var digest: [checksum_len]u8 = undefined;
    checksum(domain, bytes[0 .. bytes.len - checksum_len], &digest);
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, bytes[bytes.len - checksum_len ..][0..checksum_len].*))
        return error.InvalidSnapshot;
    return bytes[header_len .. bytes.len - checksum_len];
}

pub fn create(allocator: std.mem.Allocator, magic: [4]u8, payload_len: usize) std.mem.Allocator.Error![]u8 {
    std.debug.assert(payload_len <= std.math.maxInt(u32));
    const bytes = try allocator.alloc(u8, header_len + payload_len + checksum_len);
    @memcpy(bytes[0..4], &magic);
    bytes[4] = 1;
    @memset(bytes[5..8], 0);
    std.mem.writeInt(u32, bytes[8..12], @intCast(payload_len), .little);
    return bytes;
}

pub fn finish(bytes: []u8, domain: []const u8) void {
    var digest: [checksum_len]u8 = undefined;
    checksum(domain, bytes[0 .. bytes.len - checksum_len], &digest);
    @memcpy(bytes[bytes.len - checksum_len ..], &digest);
}

fn checksum(domain: []const u8, bytes: []const u8, digest: *[checksum_len]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domain);
    hasher.update(bytes);
    hasher.final(digest);
}
