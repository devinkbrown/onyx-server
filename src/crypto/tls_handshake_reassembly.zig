// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded reassembly of a single TLS handshake message across TLS records.

const std = @import("std");

pub const max_message_len: usize = 1024 * 1024;

pub const Reassembly = struct {
    bytes: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Reassembly, allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
    }

    /// Append one record fragment. Declared lengths are rejected as soon as the
    /// four-byte handshake header is available, before buffering the full body.
    pub fn append(self: *Reassembly, allocator: std.mem.Allocator, fragment: []const u8) (std.mem.Allocator.Error || error{BadHandshake})!void {
        if (fragment.len == 0) return error.BadHandshake;
        const total = std.math.add(usize, self.bytes.items.len, fragment.len) catch return error.BadHandshake;
        if (total > max_message_len) return error.BadHandshake;
        try self.bytes.appendSlice(allocator, fragment);
        if (self.bytes.items.len >= 4 and declaredMessageLen(self.bytes.items) > max_message_len) return error.BadHandshake;
    }

    /// Return the complete message length when all declared bytes are present.
    /// Extra buffered bytes belong to another message and remain visible to the
    /// caller, which can reject or process them according to its state.
    pub fn completeLen(self: *const Reassembly) ?usize {
        const bytes = self.bytes.items;
        if (bytes.len < 4) return null;
        const len = declaredMessageLen(bytes);
        if (len > max_message_len or bytes.len < len) return null;
        return len;
    }

    pub fn consume(self: *Reassembly, len: usize) void {
        std.debug.assert(len <= self.bytes.items.len);
        const remaining = self.bytes.items.len - len;
        std.mem.copyForwards(u8, self.bytes.items[0..remaining], self.bytes.items[len..]);
        self.bytes.items.len = remaining;
    }
};

fn declaredMessageLen(bytes: []const u8) usize {
    const body_len = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
    return 4 + body_len;
}

test "handshake reassembly accepts header and body fragments and bounds declared length" {
    var reassembly: Reassembly = .{};
    defer reassembly.deinit(std.testing.allocator);

    try reassembly.append(std.testing.allocator, &.{ 2, 0 });
    try std.testing.expect(reassembly.completeLen() == null);
    try reassembly.append(std.testing.allocator, &.{ 0, 3, 1 });
    try std.testing.expect(reassembly.completeLen() == null);
    try reassembly.append(std.testing.allocator, &.{ 2, 3 });
    try std.testing.expectEqual(@as(?usize, 7), reassembly.completeLen());
    reassembly.consume(7);
    try std.testing.expectEqual(@as(usize, 0), reassembly.bytes.items.len);

    try std.testing.expectError(error.BadHandshake, reassembly.append(std.testing.allocator, &.{ 2, 0x10, 0, 0 }));
}
