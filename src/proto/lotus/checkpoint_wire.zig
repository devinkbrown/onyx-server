// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frozen LTHC checkpoint layout, bounded reads, checksum, and size accounting.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const types = @import("types.zig");
const retained = @import("retained_message.zig");

pub const checkpoint_magic = [4]u8{ 'L', 'T', 'H', 'C' };
pub const checkpoint_version: u8 = 1;
pub const checkpoint_header_len: usize = 52;
pub const checkpoint_checksum_len: usize = Blake3.digest_length;
pub const checkpoint_target_prefix_len: usize = 8;
pub const checkpoint_entry_prefix_len: usize = 1 + 8 + Blake3.digest_length + 5 * 4;
pub const checkpoint_flag_tombstone: u8 = 1 << 0;
pub const checkpoint_flag_has_tags: u8 = 1 << 1;

pub const CheckpointReader = struct {
    bytes: []const u8,
    pos: usize,
    end: usize,

    pub fn takeU8(self: *CheckpointReader) types.CheckpointError!u8 {
        const bytes = try self.readBytes(1);
        return bytes[0];
    }

    pub fn takeU32(self: *CheckpointReader) types.CheckpointError!u32 {
        return readU32(try self.readBytes(4));
    }

    pub fn takeU64(self: *CheckpointReader) types.CheckpointError!u64 {
        return readU64(try self.readBytes(8));
    }

    pub fn readBytes(self: *CheckpointReader, len: usize) types.CheckpointError![]const u8 {
        if (self.pos > self.end or len > self.end - self.pos) return error.Truncated;
        const out = self.bytes[self.pos .. self.pos + len];
        self.pos += len;
        return out;
    }
};

pub fn checkpointLenAdd(current: usize, additional: usize, max: usize) types.CheckpointError!usize {
    const result = std.math.add(usize, current, additional) catch return error.CheckpointTooLarge;
    if (result > max or result > std.math.maxInt(u32)) return error.CheckpointTooLarge;
    return result;
}

pub fn checkpointBodyLenAdd(current: usize, additional: usize) types.Error!usize {
    return std.math.add(usize, current, additional) catch error.CheckpointCapacityExceeded;
}

pub fn checkpointEntryBodyLen(msg: types.InputMessage) types.Error!usize {
    return checkpointEntryBodyLenFromLengths(
        msg.msgid.len,
        msg.sender.len,
        msg.text.len,
        msg.command.len,
        if (msg.client_tags) |tags| tags.len else 0,
    );
}

pub fn checkpointStoredEntryBodyLen(message: *const retained.StoredMessage) usize {
    return checkpoint_entry_prefix_len + message.msgid.len + message.sender.len + message.text.len + message.command.len + if (message.client_tags) |tags| tags.len else 0;
}

pub fn checkpointEntryBodyLenFromLengths(msgid_len: usize, sender_len: usize, text_len: usize, command_len: usize, tags_len: usize) types.Error!usize {
    var len = checkpoint_entry_prefix_len;
    len = try checkpointBodyLenAdd(len, msgid_len);
    len = try checkpointBodyLenAdd(len, sender_len);
    len = try checkpointBodyLenAdd(len, text_len);
    len = try checkpointBodyLenAdd(len, command_len);
    return checkpointBodyLenAdd(len, tags_len);
}

pub fn validateCheckpointBodyBudget(body_len: usize, max_checkpoint_bytes: usize) types.Error!void {
    const with_header = std.math.add(usize, checkpoint_header_len, body_len) catch return error.CheckpointCapacityExceeded;
    const total = std.math.add(usize, with_header, checkpoint_checksum_len) catch return error.CheckpointCapacityExceeded;
    if (total > max_checkpoint_bytes or total > std.math.maxInt(u32)) return error.CheckpointCapacityExceeded;
}

pub fn checkpointBodyFits(body_len: usize, max_checkpoint_bytes: usize) bool {
    const with_header = std.math.add(usize, checkpoint_header_len, body_len) catch return false;
    const total = std.math.add(usize, with_header, checkpoint_checksum_len) catch return false;
    return total <= max_checkpoint_bytes and total <= std.math.maxInt(u32);
}

pub fn checkpointChecksum(prefix: []const u8, out: *[checkpoint_checksum_len]u8) void {
    var hasher = Blake3.init(.{});
    hasher.update("onyx_server.lotus.checkpoint.v1");
    hasher.update(prefix);
    hasher.final(out);
}

pub fn writeU16(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .big);
}

pub fn writeU32(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .big);
}

pub fn writeU64(out: []u8, value: u64) void {
    std.mem.writeInt(u64, out[0..8], value, .big);
}

pub fn readU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

pub fn readU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

pub fn readU64(bytes: []const u8) u64 {
    return std.mem.readInt(u64, bytes[0..8], .big);
}
