// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared framing for bounded, self-checking Helix abuse-state checkpoints.

const std = @import("std");

pub const checksum_len: usize = 32;
pub const max_checkpoint_bytes: usize = 256 * 1024 * 1024;
pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TrailingBytes,
    InvalidField,
    DuplicateEntry,
    NonCanonicalOrder,
    ChecksumMismatch,
    CheckpointTooLarge,
} || std.mem.Allocator.Error;

/// Every format starts with magic, version, zero reserved bytes, and a body
/// length. Format-specific fields follow before `header_len`.
pub fn parseFrame(bytes: []const u8, magic: [4]u8, header_len: usize, domain: []const u8) Error![]const u8 {
    if (bytes.len < header_len + checksum_len) return error.Truncated;
    if (bytes.len > max_checkpoint_bytes) return error.CheckpointTooLarge;
    if (!std.mem.eql(u8, bytes[0..4], &magic)) return error.BadMagic;
    if (bytes[4] != 1) return error.UnsupportedVersion;
    if (!std.mem.eql(u8, bytes[5..8], &.{ 0, 0, 0 })) return error.InvalidField;
    const body_len: usize = std.mem.readInt(u32, bytes[8..12], .little);
    if (body_len > max_checkpoint_bytes - header_len - checksum_len) return error.CheckpointTooLarge;
    const expected = header_len + body_len + checksum_len;
    if (bytes.len < expected) return error.Truncated;
    if (bytes.len > expected) return error.TrailingBytes;
    var digest: [checksum_len]u8 = undefined;
    checksum(domain, bytes[0 .. bytes.len - checksum_len], &digest);
    const saved: [checksum_len]u8 = bytes[bytes.len - checksum_len ..][0..checksum_len].*;
    if (!std.crypto.timing_safe.eql([checksum_len]u8, digest, saved)) return error.ChecksumMismatch;
    return bytes[header_len .. bytes.len - checksum_len];
}

pub fn isCheckpoint(bytes: []const u8, magic: [4]u8) bool {
    return bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], &magic);
}

pub fn addLen(total: *usize, more: usize) Error!void {
    total.* = std.math.add(usize, total.*, more) catch return error.CheckpointTooLarge;
    if (total.* > max_checkpoint_bytes) return error.CheckpointTooLarge;
}

pub fn checksum(domain: []const u8, bytes: []const u8, out: *[checksum_len]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domain);
    hasher.update(bytes);
    hasher.final(out);
}

pub fn finish(writer: *Writer, domain: []const u8) void {
    std.debug.assert(writer.pos + checksum_len == writer.bytes.len);
    var digest: [checksum_len]u8 = undefined;
    checksum(domain, writer.bytes[0..writer.pos], &digest);
    @memcpy(writer.bytes[writer.pos..][0..checksum_len], &digest);
    writer.pos += checksum_len;
}

pub const Writer = struct {
    bytes: []u8,
    pos: usize = 0,

    pub fn writeBytes(self: *Writer, value: []const u8) void {
        std.debug.assert(value.len <= self.bytes.len - self.pos);
        @memcpy(self.bytes[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    pub fn writeByte(self: *Writer, value: u8) void {
        std.debug.assert(self.pos < self.bytes.len);
        self.bytes[self.pos] = value;
        self.pos += 1;
    }

    pub fn writeU16(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.pos..][0..2], value, .little);
        self.pos += 2;
    }

    pub fn writeU32(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.pos..][0..4], value, .little);
        self.pos += 4;
    }

    pub fn writeU64(self: *Writer, value: u64) void {
        std.mem.writeInt(u64, self.bytes[self.pos..][0..8], value, .little);
        self.pos += 8;
    }

    pub fn writeI64(self: *Writer, value: i64) void {
        self.writeU64(@bitCast(value));
    }
};

pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.pos;
    }

    pub fn take(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.remaining()) return error.Truncated;
        const result = self.bytes[self.pos..][0..len];
        self.pos += len;
        return result;
    }

    pub fn readByte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    pub fn readU16(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    pub fn readU32(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    pub fn readU64(self: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try self.take(8))[0..8], .little);
    }

    pub fn readI64(self: *Reader) Error!i64 {
        return @bitCast(try self.readU64());
    }
};
