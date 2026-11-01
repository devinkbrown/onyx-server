// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 `key_share` extension inner codec (RFC 8446 §4.2.8).
//!
//! The generic extension-list walker hands us the *inner* `extension_data`
//! payload of a `key_share` extension; this module decodes / encodes that
//! payload.  Two shapes exist:
//!
//!   * ClientHello  — a `KeyShareClientHello`: a 2-byte total length followed
//!     by a packed list of `KeyShareEntry` records.
//!   * ServerHello  — a `KeyShareServerHello`: exactly one bare
//!     `KeyShareEntry` (no surrounding list length).
//!
//! A `KeyShareEntry` is `{ group: u16, key_exchange: <2-byte-len><bytes> }`.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  The caller owns every
//! buffer.  Parsing never copies — returned `key_exchange` slices alias the
//! caller's input.  Every length is bounds-checked; a short or malformed block
//! yields `error.Truncated` rather than reading past the slice.  Only `std` is
//! imported.
const std = @import("std");
const mem = std.mem;
const testing = std.testing;

/// Length of a `KeyShareEntry` header: group (u16) + key_exchange length (u16).
pub const entry_header_len: usize = 4;

/// Errors produced while walking or building a key_share payload.
pub const Error = error{
    /// The input ended in the middle of a header or declared data run, or a
    /// declared length disagrees with the bytes actually present.
    Truncated,
    /// A builder ran out of room in the caller-provided buffer.
    NoSpaceLeft,
    /// A `key_exchange` blob exceeds the u16 wire field (65535 bytes), or a
    /// ClientHello list body exceeds the u16 list-length field.
    DataTooLong,
};

/// IANA-registered "TLS Supported Groups" used in `key_share` (RFC 8446 §4.2.7
/// plus the hybrid PQC code points).  Non-exhaustive on purpose: peers may
/// advertise groups we do not model, and those must round-trip untouched.  Use
/// `fromInt` / `@intFromEnum` to move between the wire u16 and this enum.
pub const NamedGroup = enum(u16) {
    x25519 = 0x001d,
    secp256r1 = 0x0017,
    x25519mlkem768 = 0x11ec,
    _,

    /// Map a raw wire value onto the enum; unknown values land in the `_` tag
    /// while preserving the exact integer (recoverable via `@intFromEnum`).
    pub fn fromInt(value: u16) NamedGroup {
        return @fromBackingInt(@intCast(value));
    }

    /// The raw wire value for this group.
    pub fn toInt(self: NamedGroup) u16 {
        return @backingInt(self);
    }
};

/// A single decoded or to-be-encoded key share.  `group` keeps the typed enum
/// (unknown code points are still preserved exactly via the `_` tag), and
/// `key_exchange` aliases the caller's input when produced by a parser.
pub const Entry = struct {
    group: NamedGroup,
    key_exchange: []const u8,
};

/// Walks the packed `KeyShareEntry` list found inside a ClientHello key_share
/// payload.  `block` must be the inner extension data, i.e. starting at the
/// 2-byte list length.  Yields entries whose `key_exchange` aliases `block`.
pub const Iterator = struct {
    /// Remaining list body (after the leading 2-byte list length), not yet
    /// consumed.
    rest: []const u8,

    /// Returns the next entry, `null` at clean end-of-list, or `error.Truncated`
    /// if the wire bytes are malformed.
    pub fn next(self: *Iterator) Error!?Entry {
        if (self.rest.len == 0) return null;
        if (self.rest.len < entry_header_len) return Error.Truncated;

        const group = mem.readInt(u16, self.rest[0..2], .big);
        const ke_len = mem.readInt(u16, self.rest[2..4], .big);
        const body_start = entry_header_len;
        const body_end = body_start + @as(usize, ke_len);
        if (self.rest.len < body_end) return Error.Truncated;

        const entry = Entry{
            .group = NamedGroup.fromInt(group),
            .key_exchange = self.rest[body_start..body_end],
        };
        self.rest = self.rest[body_end..];
        return entry;
    }
};

/// Begins iteration over a ClientHello key_share payload.  Validates that the
/// declared 2-byte list length matches the bytes available before yielding any
/// entry; per-entry bounds are checked lazily by `Iterator.next`.
pub fn parseClientShares(block: []const u8) Error!Iterator {
    if (block.len < 2) return Error.Truncated;
    const list_len = mem.readInt(u16, block[0..2], .big);
    const body = block[2..];
    if (body.len != @as(usize, list_len)) return Error.Truncated;
    return Iterator{ .rest = body };
}

/// Decodes the single bare `KeyShareEntry` carried in a ServerHello key_share
/// payload.  Requires the entry to consume `block` exactly (no trailing bytes).
/// The returned `key_exchange` aliases `block`.
pub fn parseServerShare(block: []const u8) Error!Entry {
    if (block.len < entry_header_len) return Error.Truncated;
    const group = mem.readInt(u16, block[0..2], .big);
    const ke_len = mem.readInt(u16, block[2..4], .big);
    const body_end = entry_header_len + @as(usize, ke_len);
    if (block.len != body_end) return Error.Truncated;
    return Entry{
        .group = NamedGroup.fromInt(group),
        .key_exchange = block[entry_header_len..body_end],
    };
}

/// Serializes one entry header + body into `out` at `pos`, returning the new
/// position.  Internal helper shared by both builders.
fn writeEntry(out: []u8, pos: usize, entry: Entry) Error!usize {
    if (entry.key_exchange.len > std.math.maxInt(u16)) return Error.DataTooLong;
    const end = pos + entry_header_len + entry.key_exchange.len;
    if (end > out.len) return Error.NoSpaceLeft;

    mem.writeInt(u16, out[pos..][0..2], entry.group.toInt(), .big);
    mem.writeInt(u16, out[pos + 2 ..][0..2], @intCast(entry.key_exchange.len), .big);
    @memcpy(out[pos + entry_header_len .. end], entry.key_exchange);
    return end;
}

/// Encodes a ClientHello key_share payload (2-byte list length + packed
/// entries) into `out`, returning the written prefix slice of `out`.
pub fn buildClientShares(out: []u8, entries: []const Entry) Error![]const u8 {
    if (out.len < 2) return Error.NoSpaceLeft;
    // Reserve space for the list length; fill entries first so we can backfill
    // the exact body size.
    var pos: usize = 2;
    for (entries) |entry| {
        pos = try writeEntry(out, pos, entry);
    }
    const body_len = pos - 2;
    if (body_len > std.math.maxInt(u16)) return Error.DataTooLong;
    mem.writeInt(u16, out[0..2], @intCast(body_len), .big);
    return out[0..pos];
}

/// Encodes a ServerHello key_share payload (a single bare entry, no list
/// length) into `out`, returning the written prefix slice of `out`.
pub fn buildServerShare(out: []u8, entry: Entry) Error![]const u8 {
    const pos = try writeEntry(out, 0, entry);
    return out[0..pos];
}

test "client list round-trip with two entries" {
    // Arrange
    const ke_a = [_]u8{ 0xaa, 0xbb, 0xcc };
    const ke_b = [_]u8{ 0x11, 0x22 };
    const entries = [_]Entry{
        .{ .group = .x25519, .key_exchange = &ke_a },
        .{ .group = .x25519mlkem768, .key_exchange = &ke_b },
    };
    var buf: [64]u8 = undefined;

    // Act
    const wire = try buildClientShares(&buf, &entries);
    var it = try parseClientShares(wire);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const done = try it.next();

    // Assert
    try testing.expectEqual(NamedGroup.x25519, first.group);
    try testing.expectEqualSlices(u8, &ke_a, first.key_exchange);
    try testing.expectEqual(NamedGroup.x25519mlkem768, second.group);
    try testing.expectEqualSlices(u8, &ke_b, second.key_exchange);
    try testing.expectEqual(@as(?Entry, null), done);
}

test "server share round-trip" {
    // Arrange
    const ke = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    const entry = Entry{ .group = .secp256r1, .key_exchange = &ke };
    var buf: [32]u8 = undefined;

    // Act
    const wire = try buildServerShare(&buf, entry);
    const decoded = try parseServerShare(wire);

    // Assert
    try testing.expectEqual(NamedGroup.secp256r1, decoded.group);
    try testing.expectEqualSlices(u8, &ke, decoded.key_exchange);
    // The decoded slice aliases the source buffer rather than copying.
    try testing.expectEqual(wire.ptr + entry_header_len, decoded.key_exchange.ptr);
}

test "truncated inputs yield error.Truncated" {
    // Arrange: a server entry declaring 4 bytes of key_exchange but carrying 2.
    const short_server = [_]u8{ 0x00, 0x1d, 0x00, 0x04, 0xde, 0xad };
    // A client payload whose list length (5) overruns the 2 body bytes present.
    const short_client = [_]u8{ 0x00, 0x05, 0xde, 0xad };
    // A client list whose length (5) matches its body, but the contained entry
    // declares 3 key_exchange bytes while only 1 is present — caught lazily.
    const short_entry = [_]u8{ 0x00, 0x05, 0x00, 0x1d, 0x00, 0x03, 0x01 };

    // Act / Assert
    try testing.expectError(Error.Truncated, parseServerShare(&short_server));
    try testing.expectError(Error.Truncated, parseServerShare(short_server[0..2]));
    try testing.expectError(Error.Truncated, parseClientShares(&short_client));
    try testing.expectError(Error.Truncated, parseClientShares(short_client[0..1]));

    var it = try parseClientShares(&short_entry);
    try testing.expectError(Error.Truncated, it.next());
}

test "unknown group preserved as raw u16" {
    // Arrange: a made-up code point that is not in the NamedGroup enum.
    const unknown: u16 = 0x9a3f;
    const ke = [_]u8{ 0x42, 0x43 };
    const entry = Entry{ .group = NamedGroup.fromInt(unknown), .key_exchange = &ke };
    var buf: [32]u8 = undefined;

    // Act
    const wire = try buildServerShare(&buf, entry);
    const decoded = try parseServerShare(wire);

    // Assert: the exact integer survives the round-trip even though it has no
    // named tag.
    try testing.expectEqual(unknown, decoded.group.toInt());
    try testing.expectEqualSlices(u8, &ke, decoded.key_exchange);
}

test "builder reports NoSpaceLeft when buffer is too small" {
    // Arrange
    const ke = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const entry = Entry{ .group = .x25519, .key_exchange = &ke };
    var tiny: [4]u8 = undefined;

    // Act / Assert: needs 2 (list len) + 4 (header) + 4 (body) = 10 bytes.
    try testing.expectError(Error.NoSpaceLeft, buildClientShares(&tiny, &.{entry}));
    try testing.expectError(Error.NoSpaceLeft, buildServerShare(&tiny, entry));
}
