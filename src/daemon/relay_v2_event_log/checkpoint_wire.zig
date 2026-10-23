// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frozen RVL2 checkpoint layout and checksum primitives.
const std = @import("std");
const message_relay_v2 = @import("../../substrate/undertow/message_relay_v2.zig");
const RelayId = message_relay_v2.RelayId;

pub const magic = [_]u8{ 'R', 'V', 'L', '2' };
pub const checkpoint_version: u8 = 3;
pub const checkpoint_header_len: usize = 46;
pub const row_origin_pubkey_offset: usize = @sizeOf(RelayId);
pub const row_origin_node_offset: usize = row_origin_pubkey_offset + message_relay_v2.pubkey_len;
pub const row_hlc_offset: usize = row_origin_node_offset + 8;
pub const row_wire_len_offset: usize = row_hlc_offset + 8;
pub const row_confirmed_count_offset: usize = row_wire_len_offset + 4;
pub const row_required_count_offset: usize = row_confirmed_count_offset + 4;
pub const row_excluded_count_offset: usize = row_required_count_offset + 4;
pub const row_prefix_len: usize = @sizeOf(RelayId) + message_relay_v2.pubkey_len + 8 + 8 + 4 + 4 + 4 + 4;
pub const cursor_entry_len: usize = @sizeOf(u64) + message_relay_v2.pubkey_len;
pub const checksum_len: usize = std.crypto.hash.Blake3.digest_length;
pub const checkpoint_checksum_domain = "onyx-relay-v2-event-log-checkpoint-v3";

pub fn checkpointChecksum(prefix: []const u8, out: *[checksum_len]u8) void {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(checkpoint_checksum_domain);
    h.update(prefix);
    h.final(out);
}

pub fn readU32(bytes: *const [4]u8) u32 {
    return std.mem.readInt(u32, bytes, .big);
}

pub fn readU64(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

pub fn writeU32(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .big);
}

pub fn writeU64(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .big);
}
