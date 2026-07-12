// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Allocation-free wire codec for the Helix upgrade arena MANIFEST.
//!
//! The manifest is the table-of-contents written at the front of the handoff
//! arena. It tells the successor process which capsules follow, their kinds
//! (see `capsule.CapsuleKind`), schema versions, and the byte offset/length of
//! each capsule region within the arena, so the successor can locate and decode
//! each region without scanning.
//!
//! The codec is pure and std-only: it never allocates. `decode` borrows the
//! caller-supplied `entries_out` buffer; the returned `Manifest.entries` slice
//! aliases that buffer, which must outlive the result.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(1) epoch(u64) entry_count(u16)
//!   each entry: kind(u16) schema_version(u16) offset(u32) length(u32)

const std = @import("std");

// `capsule.zig` defines `CapsuleKind`, whose ordinals populate
// `Entry.kind`. We intentionally do NOT `@import("capsule.zig")` here: under a
// bare `zig test src/daemon/helix/upgrade_manifest.zig` invocation the test
// module is rooted at this file's directory, and capsule.zig transitively
// imports `../../proto/coilpack.zig`, which escapes that root. Keeping this
// codec free of that import lets it be tested standalone. Callers in the full
// `orochi` module pass `@intFromEnum(capsule.CapsuleKind.x)` for `kind`.

/// File magic identifying an arena manifest record.
pub const magic = [_]u8{ 'H', 'M', 'A', 'N' };

/// Wire format version. Bump on any incompatible layout change.
pub const version: u8 = 1;

/// Errors produced by the codec.
pub const Error = error{
    /// The input buffer ended before a complete record could be read,
    /// or the output buffer was too small to hold the record.
    Truncated,
    /// The magic bytes did not match.
    BadMagic,
    /// The version byte did not match the supported version.
    BadVersion,
    /// The decoded entry count exceeded the caller-supplied `entries_out`
    /// capacity, or the encoded entry count exceeded the u16 range.
    TooMany,
};

/// One table-of-contents row: where a single capsule region lives in the arena.
pub const Entry = struct {
    /// Ordinal of `capsule.CapsuleKind` for the region's payload family.
    kind: u16,
    /// Schema version of the capsule occupying the region.
    schema_version: u16,
    /// Byte offset of the region within the arena.
    offset: u32,
    /// Byte length of the region within the arena.
    length: u32,
};

/// Decoded arena manifest. `entries` borrows the caller's `entries_out` buffer.
pub const Manifest = struct {
    epoch: u64,
    entries: []const Entry,
};

/// Serialize `epoch` and `entries` into `out`. Returns the written prefix.
///
/// Returns `error.Truncated` if `out` is too small, or `error.TooMany` if more
/// than 0xFFFF entries are supplied (the wire count field is a u16).
pub fn encode(epoch: u64, entries: []const Entry, out: []u8) Error![]const u8 {
    if (entries.len > std.math.maxInt(u16)) return error.TooMany;

    var pos: usize = 0;

    // magic(4)
    try writeBytes(out, &pos, &magic);
    // version(1)
    try writeByte(out, &pos, version);
    // epoch(u64 BE)
    try writeU64(out, &pos, epoch);
    // entry_count(u16 BE)
    try writeU16(out, &pos, @intCast(entries.len));

    for (entries) |entry| {
        try writeU16(out, &pos, entry.kind);
        try writeU16(out, &pos, entry.schema_version);
        try writeU32(out, &pos, entry.offset);
        try writeU32(out, &pos, entry.length);
    }

    return out[0..pos];
}

/// Parse a `Manifest` from `bytes`, filling `entries_out`. The returned
/// `Manifest.entries` slice borrows `entries_out`, which must outlive the
/// result.
///
/// Returns `error.TooMany` if the encoded entry count exceeds the
/// `entries_out` capacity.
pub fn decode(bytes: []const u8, entries_out: []Entry) Error!Manifest {
    var pos: usize = 0;

    const got_magic = try readBytes(bytes, &pos, magic.len);
    if (!std.mem.eql(u8, got_magic, &magic)) return error.BadMagic;

    const got_version = try readByte(bytes, &pos);
    if (got_version != version) return error.BadVersion;

    const epoch = try readU64(bytes, &pos);
    const count = try readU16(bytes, &pos);

    if (count > entries_out.len) return error.TooMany;

    var i: usize = 0;
    while (i < count) : (i += 1) {
        entries_out[i] = .{
            .kind = try readU16(bytes, &pos),
            .schema_version = try readU16(bytes, &pos),
            .offset = try readU32(bytes, &pos),
            .length = try readU32(bytes, &pos),
        };
    }

    return .{ .epoch = epoch, .entries = entries_out[0..count] };
}

/// Return the first entry whose kind matches `kind`, or null if absent.
pub fn find(m: Manifest, kind: u16) ?Entry {
    for (m.entries) |entry| {
        if (entry.kind == kind) return entry;
    }
    return null;
}

// --- encode helpers ---------------------------------------------------------

fn writeBytes(out: []u8, pos: *usize, src: []const u8) Error!void {
    if (pos.* + src.len > out.len) return error.Truncated;
    @memcpy(out[pos.* .. pos.* + src.len], src);
    pos.* += src.len;
}

fn writeByte(out: []u8, pos: *usize, val: u8) Error!void {
    if (pos.* + 1 > out.len) return error.Truncated;
    out[pos.*] = val;
    pos.* += 1;
}

fn writeU16(out: []u8, pos: *usize, val: u16) Error!void {
    if (pos.* + 2 > out.len) return error.Truncated;
    std.mem.writeInt(u16, out[pos.*..][0..2], val, .big);
    pos.* += 2;
}

fn writeU32(out: []u8, pos: *usize, val: u32) Error!void {
    if (pos.* + 4 > out.len) return error.Truncated;
    std.mem.writeInt(u32, out[pos.*..][0..4], val, .big);
    pos.* += 4;
}

fn writeU64(out: []u8, pos: *usize, val: u64) Error!void {
    if (pos.* + 8 > out.len) return error.Truncated;
    std.mem.writeInt(u64, out[pos.*..][0..8], val, .big);
    pos.* += 8;
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

fn readU32(bytes: []const u8, pos: *usize) Error!u32 {
    if (pos.* + 4 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u32, bytes[pos.*..][0..4], .big);
    pos.* += 4;
    return val;
}

fn readU64(bytes: []const u8, pos: *usize) Error!u64 {
    if (pos.* + 8 > bytes.len) return error.Truncated;
    const val = std.mem.readInt(u64, bytes[pos.*..][0..8], .big);
    pos.* += 8;
    return val;
}

// --- tests ------------------------------------------------------------------

// CapsuleKind ordinals mirrored from capsule.zig for standalone testing.
const kind_clients: u16 = 1;
const kind_channels: u16 = 2;
const kind_sessions: u16 = 3;
const kind_tsumugi_ratchet: u16 = 5;
const kind_send_queue: u16 = 7;

test "round-trip a three-entry manifest with epoch" {
    const entries = [_]Entry{
        .{
            .kind = kind_clients,
            .schema_version = 1,
            .offset = 0,
            .length = 128,
        },
        .{
            .kind = kind_channels,
            .schema_version = 2,
            .offset = 128,
            .length = 4096,
        },
        .{
            .kind = kind_send_queue,
            .schema_version = 7,
            .offset = 4224,
            .length = 65535,
        },
    };
    const epoch: u64 = 0xDEAD_BEEF_CAFE_F00D;

    var buf: [256]u8 = undefined;
    const wire = try encode(epoch, &entries, &buf);

    var out: [8]Entry = undefined;
    const m = try decode(wire, &out);

    try std.testing.expectEqual(epoch, m.epoch);
    try std.testing.expectEqual(@as(usize, 3), m.entries.len);

    for (entries, 0..) |want, idx| {
        const got = m.entries[idx];
        try std.testing.expectEqual(want.kind, got.kind);
        try std.testing.expectEqual(want.schema_version, got.schema_version);
        try std.testing.expectEqual(want.offset, got.offset);
        try std.testing.expectEqual(want.length, got.length);
    }
}

test "find locates by kind and returns null for an absent kind" {
    const entries = [_]Entry{
        .{ .kind = kind_clients, .schema_version = 1, .offset = 0, .length = 16 },
        .{ .kind = kind_sessions, .schema_version = 1, .offset = 16, .length = 32 },
    };

    var buf: [128]u8 = undefined;
    const wire = try encode(99, &entries, &buf);

    var out: [4]Entry = undefined;
    const m = try decode(wire, &out);

    const sessions = find(m, kind_sessions);
    try std.testing.expect(sessions != null);
    try std.testing.expectEqual(@as(u32, 16), sessions.?.offset);
    try std.testing.expectEqual(@as(u32, 32), sessions.?.length);

    const clients = find(m, kind_clients);
    try std.testing.expect(clients != null);
    try std.testing.expectEqual(@as(u32, 0), clients.?.offset);

    try std.testing.expect(find(m, kind_tsumugi_ratchet) == null);
}

test "decode returns Truncated on a cut buffer" {
    const entries = [_]Entry{
        .{ .kind = 1, .schema_version = 1, .offset = 0, .length = 10 },
        .{ .kind = 2, .schema_version = 1, .offset = 10, .length = 20 },
    };

    var buf: [128]u8 = undefined;
    const wire = try encode(1, &entries, &buf);

    var out: [4]Entry = undefined;

    // Cut just before the end so the final entry read runs past the buffer.
    const cut = wire[0 .. wire.len - 3];
    try std.testing.expectError(error.Truncated, decode(cut, &out));

    // An empty buffer cannot even hold the magic.
    try std.testing.expectError(error.Truncated, decode(wire[0..0], &out));
}

test "decode returns BadMagic on corrupted magic" {
    const entries = [_]Entry{
        .{ .kind = 1, .schema_version = 1, .offset = 0, .length = 10 },
    };

    var buf: [64]u8 = undefined;
    const wire = try encode(1, &entries, &buf);

    var corrupted: [64]u8 = undefined;
    @memcpy(corrupted[0..wire.len], wire);
    corrupted[0] ^= 0xFF; // flip a magic byte

    var out: [4]Entry = undefined;
    try std.testing.expectError(error.BadMagic, decode(corrupted[0..wire.len], &out));
}

test "decode returns BadVersion on a future version" {
    const entries = [_]Entry{
        .{ .kind = 1, .schema_version = 1, .offset = 0, .length = 10 },
    };

    var buf: [64]u8 = undefined;
    const wire = try encode(1, &entries, &buf);

    var bumped: [64]u8 = undefined;
    @memcpy(bumped[0..wire.len], wire);
    bumped[magic.len] = version +% 1; // version byte follows the magic

    var out: [4]Entry = undefined;
    try std.testing.expectError(error.BadVersion, decode(bumped[0..wire.len], &out));
}

test "decode returns TooMany when entries_out is too small" {
    const entries = [_]Entry{
        .{ .kind = 1, .schema_version = 1, .offset = 0, .length = 10 },
        .{ .kind = 2, .schema_version = 1, .offset = 10, .length = 20 },
        .{ .kind = 3, .schema_version = 1, .offset = 30, .length = 30 },
    };

    var buf: [128]u8 = undefined;
    const wire = try encode(1, &entries, &buf);

    var out: [2]Entry = undefined; // too small for 3 entries
    try std.testing.expectError(error.TooMany, decode(wire, &out));
}

test "encode returns Truncated when output buffer is too small" {
    const entries = [_]Entry{
        .{ .kind = 1, .schema_version = 1, .offset = 0, .length = 10 },
        .{ .kind = 2, .schema_version = 1, .offset = 10, .length = 20 },
    };

    var tiny: [8]u8 = undefined; // cannot even hold the fixed header
    try std.testing.expectError(error.Truncated, encode(1, &entries, &tiny));
}
