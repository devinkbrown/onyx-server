// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for a single channel's resumable MASK LISTS.
//!
//! Companion to `world_capsule.zig` and `conn_capsule.zig`: where the world
//! capsule carries a channel's members, modes, topic, key, and limit, this one
//! carries the channel's MASK LISTS — the +b ban list, the +e ban-exception
//! list, the +I invite-exception list, and the +Z quiet/mute list — so the
//! Helix in-process upgrade (UPGRADE command) can recreate those lists in the
//! successor process after `execve`. The codec is pure and std-only: it never
//! allocates. Decoded string slices borrow the input buffer, and the returned
//! `entries` slice borrows a caller-supplied buffer; both must outlive the
//! result.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1)
//!   channel:     u16 len + bytes
//!   entry_count: u16
//!   for each entry:
//!     kind(u8)            MaskKind discriminant
//!     mask:   u16 len + bytes
//!     setter: u16 len + bytes   (len == 0 means unknown)
//!     set_ts(i64)
//!
//! An unknown `kind` byte is rejected as `error.BadVersion`.

const std = @import("std");

/// File magic identifying a ban (mask-list) capsule record.
pub const magic = [_]u8{ 'H', 'B', 'A', 'N' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Maximum encodable string length, mirroring the sibling capsule codecs.
const max_str_len: usize = 0xFFFE;

/// Which mask list an entry belongs to.
pub const MaskKind = enum(u8) {
    ban = 0,
    exempt = 1,
    invex = 2,
    mute = 3,
};

/// A single mask-list entry: the mask, who set it (empty if unknown), and when.
pub const MaskEntry = struct {
    kind: MaskKind,
    mask: []const u8,
    setter: []const u8,
    set_ts: i64,
};

/// Resumable mask-list state for a single channel.
pub const BanCapsule = struct {
    channel: []const u8,
    entries: []const MaskEntry,
};

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version, or an entry
    /// carried an unrecognized `kind` discriminant.
    BadVersion,
    /// The decoded entry count exceeded the supplied `entries_out` buffer, or
    /// there were more than 0xFFFF entries to encode.
    TooMany,
};

/// Serialize `self` into `out`. Returns the written prefix of `out`.
///
/// Returns `error.TooMany` if `out` is too small, any string exceeds the
/// maximum encodable length (0xFFFE bytes), or there are more than 0xFFFF
/// entries.
pub fn encode(self: BanCapsule, out: []u8) Error![]const u8 {
    var pos: usize = 0;

    // magic(4)
    try writeBytes(out, &pos, &magic);
    // version(1)
    try writeByte(out, &pos, version);

    // channel name
    try writeStr(out, &pos, self.channel);

    // entry_count(u16) followed by each entry.
    if (self.entries.len > 0xFFFF) return error.TooMany;
    try writeU16(out, &pos, @intCast(self.entries.len));
    for (self.entries) |e| {
        try writeByte(out, &pos, @backingInt(e.kind));
        try writeStr(out, &pos, e.mask);
        try writeStr(out, &pos, e.setter);
        try writeI64(out, &pos, e.set_ts);
    }

    return out[0..pos];
}

/// Parse a `BanCapsule` from `bytes`. Returned string slices borrow `bytes`,
/// and the returned `entries` slice borrows `entries_out`; both must outlive
/// the result.
///
/// Returns `error.TooMany` if the decoded entry count exceeds
/// `entries_out.len`, and `error.BadVersion` if an entry has an unknown kind.
pub fn decode(bytes: []const u8, entries_out: []MaskEntry) Error!BanCapsule {
    var pos: usize = 0;

    const got_magic = try readBytes(bytes, &pos, magic.len);
    if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

    const got_version = try readByte(bytes, &pos);
    if (got_version != version) return error.BadVersion;

    const channel = try readStr(bytes, &pos);

    const count = try readU16(bytes, &pos);
    if (count > entries_out.len) return error.TooMany;

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const kind_byte = try readByte(bytes, &pos);
        const kind = kindFromByte(kind_byte) orelse return error.BadVersion;
        const mask = try readStr(bytes, &pos);
        const setter = try readStr(bytes, &pos);
        const set_ts = try readI64(bytes, &pos);
        entries_out[i] = .{
            .kind = kind,
            .mask = mask,
            .setter = setter,
            .set_ts = set_ts,
        };
    }

    return .{
        .channel = channel,
        .entries = entries_out[0..count],
    };
}

fn kindFromByte(b: u8) ?MaskKind {
    return switch (b) {
        0 => .ban,
        1 => .exempt,
        2 => .invex,
        3 => .mute,
        else => null,
    };
}

// --- encode helpers ---------------------------------------------------------

fn writeBytes(out: []u8, pos: *usize, src: []const u8) Error!void {
    if (pos.* + src.len > out.len) return error.TooMany;
    @memcpy(out[pos.* .. pos.* + src.len], src);
    pos.* += src.len;
}

fn writeByte(out: []u8, pos: *usize, val: u8) Error!void {
    if (pos.* + 1 > out.len) return error.TooMany;
    out[pos.*] = val;
    pos.* += 1;
}

fn writeU16(out: []u8, pos: *usize, val: u16) Error!void {
    if (pos.* + 2 > out.len) return error.TooMany;
    std.mem.writeInt(u16, out[pos.*..][0..2], val, .big);
    pos.* += 2;
}

fn writeI64(out: []u8, pos: *usize, val: i64) Error!void {
    if (pos.* + 8 > out.len) return error.TooMany;
    std.mem.writeInt(i64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
}

fn writeStr(out: []u8, pos: *usize, str: []const u8) Error!void {
    if (str.len > max_str_len) return error.TooMany;
    try writeU16(out, pos, @intCast(str.len));
    try writeBytes(out, pos, str);
}

// --- decode helpers ---------------------------------------------------------

fn readBytes(bytes: []const u8, pos: *usize, n: usize) Error![]const u8 {
    if (pos.* + n > bytes.len) return error.Truncated;
    const slice = bytes[pos.* .. pos.* + n];
    pos.* += n;
    return slice;
}

fn readByte(bytes: []const u8, pos: *usize) Error!u8 {
    if (pos.* + 1 > bytes.len) return error.Truncated;
    const val = bytes[pos.*];
    pos.* += 1;
    return val;
}

fn readU16(bytes: []const u8, pos: *usize) Error!u16 {
    if (pos.* + 2 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u16, bytes[pos.*..][0..2], .big);
    pos.* += 2;
    return val;
}

fn readI64(bytes: []const u8, pos: *usize) Error!i64 {
    if (pos.* + 8 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(i64, bytes[pos.*..][0..8], .big);
    pos.* += 8;
    return val;
}

fn readStr(bytes: []const u8, pos: *usize) Error![]const u8 {
    const len = try readU16(bytes, pos);
    return readBytes(bytes, pos, len);
}

// --- tests ------------------------------------------------------------------

test "round-trip with four entries spanning all mask kinds" {
    const entries = [_]MaskEntry{
        .{ .kind = .ban, .mask = "*!*@spam.example.org", .setter = "op!u@host", .set_ts = 1_700_000_000 },
        .{ .kind = .exempt, .mask = "trusted!*@*.good.net", .setter = "founder!f@h", .set_ts = 1_700_000_111 },
        .{ .kind = .invex, .mask = "vip!*@vip.example.com", .setter = "", .set_ts = 1_700_000_222 },
        .{ .kind = .mute, .mask = "loud!*@*.noisy.io", .setter = "halfop!h@host", .set_ts = 1_700_000_333 },
    };

    const original = BanCapsule{
        .channel = "#onyx",
        .entries = &entries,
    };

    var buf: [1024]u8 = undefined;
    const wire = try encode(original, &buf);

    var entries_out: [16]MaskEntry = undefined;
    const decoded = try decode(wire, &entries_out);

    try std.testing.expectEqualStrings(original.channel, decoded.channel);
    try std.testing.expectEqual(entries.len, decoded.entries.len);
    for (entries, decoded.entries) |want, got| {
        try std.testing.expectEqual(want.kind, got.kind);
        try std.testing.expectEqualStrings(want.mask, got.mask);
        try std.testing.expectEqualStrings(want.setter, got.setter);
        try std.testing.expectEqual(want.set_ts, got.set_ts);
    }

    // The invex entry was deliberately given an empty (unknown) setter.
    try std.testing.expectEqualStrings("", decoded.entries[2].setter);
}

test "round-trip with zero entries" {
    const original = BanCapsule{
        .channel = "#empty",
        .entries = &[_]MaskEntry{},
    };

    var buf: [256]u8 = undefined;
    const wire = try encode(original, &buf);

    var entries_out: [4]MaskEntry = undefined;
    const decoded = try decode(wire, &entries_out);

    try std.testing.expectEqualStrings(original.channel, decoded.channel);
    try std.testing.expectEqual(@as(usize, 0), decoded.entries.len);
}

test "decode returns Truncated on a cut buffer" {
    const entries = [_]MaskEntry{
        .{ .kind = .ban, .mask = "a!*@*", .setter = "s", .set_ts = 1 },
        .{ .kind = .mute, .mask = "b!*@*", .setter = "t", .set_ts = 2 },
    };
    const original = BanCapsule{
        .channel = "#cut",
        .entries = &entries,
    };

    var buf: [512]u8 = undefined;
    const wire = try encode(original, &buf);

    var entries_out: [8]MaskEntry = undefined;

    // Cut just before the end so an entry read runs past the buffer.
    const cut = wire[0 .. wire.len - 2];
    try std.testing.expectError(error.Truncated, decode(cut, &entries_out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, decode(wire[0..0], &entries_out));
}

test "decode returns BadMagic on corrupted magic" {
    const original = BanCapsule{
        .channel = "#m",
        .entries = &[_]MaskEntry{},
    };

    var buf: [256]u8 = undefined;
    const wire = try encode(original, &buf);

    var corrupted: [256]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var entries_out: [4]MaskEntry = undefined;
    try std.testing.expectError(error.BadMagic, decode(corrupted[0..wire.len], &entries_out));
}

test "decode returns BadVersion on a future version" {
    const original = BanCapsule{
        .channel = "#m",
        .entries = &[_]MaskEntry{},
    };

    var buf: [256]u8 = undefined;
    const wire = try encode(original, &buf);

    var bumped: [256]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var entries_out: [4]MaskEntry = undefined;
    try std.testing.expectError(error.BadVersion, decode(bumped[0..wire.len], &entries_out));
}

test "decode returns BadVersion on an unknown mask kind" {
    const entries = [_]MaskEntry{
        .{ .kind = .ban, .mask = "a!*@*", .setter = "s", .set_ts = 1 },
    };
    const original = BanCapsule{
        .channel = "#k",
        .entries = &entries,
    };

    var buf: [256]u8 = undefined;
    const wire = try encode(original, &buf);

    // The kind byte sits right after: magic(4) version(1) chan-len(2) "#k"(2)
    // count(2) -> index 11.
    const kind_index = magic.len + 1 + 2 + original.channel.len + 2;
    var bad: [256]u8 = undefined;
    @memcpy(bad[0..wire.len], wire);
    bad[kind_index] = 0xEE; // not a valid MaskKind

    var entries_out: [4]MaskEntry = undefined;
    try std.testing.expectError(error.BadVersion, decode(bad[0..wire.len], &entries_out));
}

test "decode returns TooMany when entries_out is too small" {
    const entries = [_]MaskEntry{
        .{ .kind = .ban, .mask = "one!*@*", .setter = "a", .set_ts = 1 },
        .{ .kind = .exempt, .mask = "two!*@*", .setter = "b", .set_ts = 2 },
        .{ .kind = .invex, .mask = "three!*@*", .setter = "c", .set_ts = 3 },
    };
    const original = BanCapsule{
        .channel = "#crowd",
        .entries = &entries,
    };

    var buf: [256]u8 = undefined;
    const wire = try encode(original, &buf);

    // Buffer can hold only 2 of the 3 encoded entries.
    var entries_out: [2]MaskEntry = undefined;
    try std.testing.expectError(error.TooMany, decode(wire, &entries_out));
}

test "encode returns TooMany when output buffer is too small" {
    const entries = [_]MaskEntry{
        .{ .kind = .ban, .mask = "*!*@a-fairly-long-host.example.org", .setter = "setter!ident@host", .set_ts = 1 },
    };
    const original = BanCapsule{
        .channel = "#a-fairly-long-channel-name-here",
        .entries = &entries,
    };

    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.TooMany, encode(original, &tiny));
}
