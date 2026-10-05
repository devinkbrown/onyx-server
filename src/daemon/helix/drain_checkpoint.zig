// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact native Helix custody for operator DRAIN admission state.
const std = @import("std");

const magic = "DRAN";
const version: u8 = 1;
pub const encoded_len: usize = 8;
pub const Error = error{InvalidCheckpoint};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], magic);
}

pub fn encode(draining: bool) [encoded_len]u8 {
    return .{ 'D', 'R', 'A', 'N', version, @intFromBool(draining), 0, 0 };
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    if (bytes.len != encoded_len or !isCheckpoint(bytes) or bytes[4] != version or
        bytes[5] > 1 or bytes[6] != 0 or bytes[7] != 0) return error.InvalidCheckpoint;
}

pub fn decode(bytes: []const u8) Error!bool {
    try validateCheckpoint(bytes);
    return bytes[5] == 1;
}

test "DRAIN checkpoint carries active and inactive admission exactly" {
    const active = encode(true);
    const inactive = encode(false);
    try std.testing.expect(try decode(&active));
    try std.testing.expect(!(try decode(&inactive)));
    var malformed = active;
    malformed[6] = 1;
    try std.testing.expectError(error.InvalidCheckpoint, decode(&malformed));
    malformed = active;
    malformed[5] = 2;
    try std.testing.expectError(error.InvalidCheckpoint, decode(&malformed));
}
