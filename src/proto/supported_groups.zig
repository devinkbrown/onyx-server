// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS `supported_groups` / `elliptic_curves` extension inner codec
//! (RFC 8422 / RFC 7919 / RFC 8446).
//!
//! This module decodes and encodes the *inner data* of the extension only:
//!
//!     struct {
//!         NamedGroup named_group_list<2..2^16-1>;
//!     } NamedGroupList;
//!
//! On the wire that is a 2-byte big-endian list length, followed by that many
//! bytes of packed big-endian `u16` group codes.  The list length must be even.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  Callers own every
//! buffer.  Every length is bounds-checked; a truncated or malformed block
//! yields `error.Truncated` rather than reading past the slice.
const std = @import("std");

comptime {
    if (@sizeOf(usize) < 8) @compileError("supported_groups requires a 64-bit target");
}

/// Width of a single wire NamedGroup field in bytes.
const group_len: usize = 2;

/// Width of the list-length prefix in bytes.
const list_prefix_len: usize = 2;

/// TLS NamedGroup registry values used by the supported_groups extension.
/// Non-exhaustive on purpose: peers may advertise groups we do not model, and
/// those must round-trip untouched.  Use `fromInt` / `toInt` to move between
/// the wire `u16` and this enum.
pub const NamedGroup = enum(u16) {
    /// NIST P-256 (RFC 8422).
    secp256r1 = 0x0017,
    /// NIST P-384 (RFC 8422).
    secp384r1 = 0x0018,
    /// X25519 (RFC 8422).
    x25519 = 0x001d,
    /// X448 (RFC 8422).
    x448 = 0x001e,
    /// FFDHE group with 2048-bit safe prime (RFC 7919).
    ffdhe2048 = 0x0100,
    /// X25519MLKEM768 post-quantum hybrid (draft-ietf-tls-ecdhe-mlkem).
    x25519mlkem768 = 0x11ec,
    _,

    /// Wrap a raw wire `u16` as a `NamedGroup` (total over the enum).
    pub fn fromInt(value: u16) NamedGroup {
        return @fromBackingInt(@intCast(value));
    }

    /// The raw wire `u16` for this group.
    pub fn toInt(self: NamedGroup) u16 {
        return @backingInt(self);
    }
};

/// Errors produced while parsing or building a `supported_groups` body.
pub const Error = error{
    /// The block ended mid-field, declared more bytes than it carried, or had
    /// an odd-length group list.
    Truncated,
    /// A build target buffer ran out of room.  Matches `std`'s spelling so
    /// callers can mix our writes with `std` writers if they like.
    NoSpaceLeft,
    /// More groups were offered than fit in the 2-byte list length field.
    TooManyGroups,
};

/// Read a big-endian `u16` from the first two bytes of `b` (caller guarantees
/// `b.len >= 2`).
fn readU16(b: []const u8) u16 {
    return (@as(u16, b[0]) << 8) | @as(u16, b[1]);
}

/// Write a big-endian `u16` into the first two bytes of `out` (caller
/// guarantees `out.len >= 2`).
fn writeU16(out: []u8, value: u16) void {
    out[0] = @intCast(value >> 8);
    out[1] = @intCast(value & 0xff);
}

/// Cursor over the group list of a `supported_groups` body.  Yields each
/// offered `NamedGroup` in wire order.  Constructed by `parse`, which validates
/// the framing up front, so iteration itself cannot fail.
pub const Iterator = struct {
    /// The group bytes only (the 2-byte list-length prefix already stripped).
    groups: []const u8,
    /// Byte offset of the next group to yield.
    pos: usize = 0,

    /// Return the next offered group, or `null` once the list is exhausted.
    /// Unknown wire codes are preserved via the non-exhaustive enum.
    pub fn next(self: *Iterator) ?NamedGroup {
        if (self.pos + group_len > self.groups.len) return null;
        const v = readU16(self.groups[self.pos..]);
        self.pos += group_len;
        return NamedGroup.fromInt(v);
    }

    /// Like `next`, but yields the raw `u16` wire code instead of the enum.
    pub fn nextRaw(self: *Iterator) ?u16 {
        if (self.pos + group_len > self.groups.len) return null;
        const v = readU16(self.groups[self.pos..]);
        self.pos += group_len;
        return v;
    }

    /// Number of groups remaining (does not advance the cursor).
    pub fn remaining(self: *const Iterator) usize {
        return (self.groups.len - self.pos) / group_len;
    }
};

/// Parse a `supported_groups` body and return an `Iterator` over its groups.
///
/// Validates that the declared 2-byte list length matches the bytes present
/// and that the list is an even number of bytes.  Aliases `block`; copies
/// nothing.
pub fn parse(block: []const u8) Error!Iterator {
    if (block.len < list_prefix_len) return Error.Truncated;
    const list_len: usize = readU16(block[0..list_prefix_len]);
    const body = block[list_prefix_len..];
    if (body.len != list_len) return Error.Truncated;
    if (list_len % group_len != 0) return Error.Truncated;
    return Iterator{ .groups = body };
}

/// Return `true` iff `block` offers `group`.  A malformed block offers nothing,
/// so returns `false` on parse failure.
pub fn offers(block: []const u8, group: NamedGroup) bool {
    var it = parse(block) catch return false;
    const want = group.toInt();
    while (it.nextRaw()) |v| {
        if (v == want) return true;
    }
    return false;
}

/// Encode `groups` into `out` as a `supported_groups` body and return the
/// written prefix of `out`.  Writes a 2-byte big-endian list length followed
/// by each group big-endian.
pub fn build(out: []u8, groups: []const NamedGroup) Error![]const u8 {
    const body_len = groups.len * group_len;
    if (body_len > std.math.maxInt(u16)) return Error.TooManyGroups;
    const total = list_prefix_len + body_len;
    if (out.len < total) return Error.NoSpaceLeft;
    writeU16(out[0..list_prefix_len], @intCast(body_len));
    var off: usize = list_prefix_len;
    for (groups) |group| {
        writeU16(out[off..], group.toInt());
        off += group_len;
    }
    return out[0..total];
}

/// Select the first server-preferred group also offered by the client.  A
/// malformed client block selects nothing.
pub fn selectPreferred(client_block: []const u8, server_prefs: []const NamedGroup) ?NamedGroup {
    for (server_prefs) |group| {
        if (offers(client_block, group)) return group;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "build then parse round-trips common TLS groups in order" {
    // Arrange
    var buf: [16]u8 = undefined;
    const offered = [_]NamedGroup{ .x25519, .secp256r1, .ffdhe2048 };

    // Act
    const body = try build(&buf, &offered);
    var it = try parse(body);
    const first = it.next();
    const second = it.next();
    const third = it.next();
    const fourth = it.next();

    // Assert
    try testing.expectEqual(@as(usize, 8), body.len);
    try testing.expectEqual(@as(u16, 6), readU16(body[0..2]));
    try testing.expectEqual(@as(?NamedGroup, .x25519), first);
    try testing.expectEqual(@as(?NamedGroup, .secp256r1), second);
    try testing.expectEqual(@as(?NamedGroup, .ffdhe2048), third);
    try testing.expectEqual(@as(?NamedGroup, null), fourth);
}

test "known answer vector encodes RFC named group registry values" {
    // Arrange
    var buf: [16]u8 = undefined;
    const groups = [_]NamedGroup{ .secp256r1, .secp384r1, .x25519, .x448, .ffdhe2048 };
    const want = [_]u8{
        0x00, 0x0a,
        0x00, 0x17,
        0x00, 0x18,
        0x00, 0x1d,
        0x00, 0x1e,
        0x01, 0x00,
    };

    // Act
    const body = try build(&buf, &groups);

    // Assert
    try testing.expectEqualSlices(u8, &want, body);
}

test "offers finds an offered group and misses an unoffered one" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try build(&buf, &[_]NamedGroup{ .x25519, .secp256r1 });

    // Act
    const hasX25519 = offers(body, .x25519);
    const hasP256 = offers(body, .secp256r1);
    const hasX448 = offers(body, .x448);

    // Assert
    try testing.expect(hasX25519);
    try testing.expect(hasP256);
    try testing.expect(!hasX448);
}

test "selectPreferred returns the first server preference present in client list" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try build(&buf, &[_]NamedGroup{ .secp256r1, .x25519 });
    const server_prefs = [_]NamedGroup{ .x448, .x25519, .secp256r1 };

    // Act
    const selected = selectPreferred(body, &server_prefs);

    // Assert
    try testing.expectEqual(@as(?NamedGroup, .x25519), selected);
}

test "selectPreferred returns null when no server preference is offered" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try build(&buf, &[_]NamedGroup{.secp256r1});
    const server_prefs = [_]NamedGroup{ .x448, .x25519 };

    // Act
    const selected = selectPreferred(body, &server_prefs);

    // Assert
    try testing.expectEqual(@as(?NamedGroup, null), selected);
}

test "parse rejects a declared length mismatch" {
    // Arrange: declares 4 bytes of groups but only carries 2.
    const block = [_]u8{ 0x00, 0x04, 0x00, 0x1d };

    // Act
    const result = parse(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parse rejects an odd-length group list" {
    // Arrange: declares 3 bytes of groups (odd, cannot be whole u16s).
    const block = [_]u8{ 0x00, 0x03, 0x00, 0x1d, 0x00 };

    // Act
    const result = parse(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "parse rejects a truncated block with no full length prefix" {
    // Arrange
    const block = [_]u8{0x00};

    // Act
    const result = parse(&block);

    // Assert
    try testing.expectError(Error.Truncated, result);
}

test "unknown group code is preserved through parse and offers" {
    // Arrange: a private-use code point not modeled by the enum.
    const unknown: u16 = 0xfe00;
    const group = NamedGroup.fromInt(unknown);
    var buf: [8]u8 = undefined;
    const body = try build(&buf, &[_]NamedGroup{group});

    // Act
    var it = try parse(body);
    const got = it.nextRaw();
    const exhausted = it.nextRaw();
    const found = offers(body, group);

    // Assert
    try testing.expectEqual(@as(?u16, unknown), got);
    try testing.expectEqual(@as(?u16, null), exhausted);
    try testing.expect(found);
}

test "iterator remaining counts groups without advancing" {
    // Arrange
    var buf: [16]u8 = undefined;
    const body = try build(&buf, &[_]NamedGroup{ .x25519, .secp256r1 });
    var it = try parse(body);

    // Act
    const before = it.remaining();
    _ = it.next();
    const after = it.remaining();

    // Assert
    try testing.expectEqual(@as(usize, 2), before);
    try testing.expectEqual(@as(usize, 1), after);
}

test "build reports NoSpaceLeft when the buffer is too small" {
    // Arrange
    var tiny: [3]u8 = undefined;

    // Act
    const result = build(&tiny, &[_]NamedGroup{ .x25519, .secp256r1 });

    // Assert
    try testing.expectError(Error.NoSpaceLeft, result);
}

test "build reports TooManyGroups for an oversized list" {
    // Arrange
    var groups: [32768]NamedGroup = undefined;
    @memset(&groups, .x25519);
    var out: [2]u8 = undefined;

    // Act
    const result = build(&out, &groups);

    // Assert
    try testing.expectError(Error.TooManyGroups, result);
}

test "offers and selectPreferred return falsey results on malformed blocks" {
    // Arrange: length prefix claims more than is present.
    const block = [_]u8{ 0x00, 0x08, 0x00, 0x1d };
    const server_prefs = [_]NamedGroup{.x25519};

    // Act
    const found = offers(&block, .x25519);
    const selected = selectPreferred(&block, &server_prefs);

    // Assert
    try testing.expect(!found);
    try testing.expectEqual(@as(?NamedGroup, null), selected);
}

test "empty group list round-trips" {
    // Arrange
    var buf: [4]u8 = undefined;

    // Act
    const body = try build(&buf, &[_]NamedGroup{});
    var it = try parse(body);
    const first = it.next();

    // Assert
    try testing.expectEqual(@as(usize, 2), body.len);
    try testing.expectEqual(@as(u16, 0), readU16(body[0..2]));
    try testing.expectEqual(@as(usize, 0), it.remaining());
    try testing.expectEqual(@as(?NamedGroup, null), first);
}

test "NamedGroup enum values match their wire codes" {
    // Arrange / Act / Assert
    try testing.expectEqual(@as(u16, 0x0017), NamedGroup.secp256r1.toInt());
    try testing.expectEqual(@as(u16, 0x0018), NamedGroup.secp384r1.toInt());
    try testing.expectEqual(@as(u16, 0x001d), NamedGroup.x25519.toInt());
    try testing.expectEqual(@as(u16, 0x001e), NamedGroup.x448.toInt());
    try testing.expectEqual(@as(u16, 0x0100), NamedGroup.ffdhe2048.toInt());
}
