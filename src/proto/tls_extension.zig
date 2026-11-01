// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLS 1.3 extension-list codec (RFC 8446 §4.2).
//!
//! A pure, zero-allocation codec for the generic extension-list wire format
//! shared by ClientHello, ServerHello, EncryptedExtensions, CertificateRequest,
//! and friends.  The format is a 2-byte total length followed by a packed
//! sequence of entries, each `{ extension_type: u16, extension_data:
//! <2-byte-len><bytes> }`.
//!
//! This module deliberately knows nothing about the *contents* of any
//! particular extension — it walks the outer envelope only and hands back
//! slices that alias the caller's input (never copies).  Higher layers (SNI,
//! ECH, key_share, supported_versions, ...) parse the inner payloads.
//!
//! Pure logic: no I/O, no clock, no RNG, no allocation.  Callers own every
//! buffer.  Every length is bounds-checked; a truncated or malformed block
//! yields `error.Truncated` rather than reading past the slice.  Only `std`
//! is imported.
const std = @import("std");
const mem = std.mem;

/// Length in bytes of a single extension header: type (u16) + length (u16).
pub const header_len: usize = 4;

/// Errors produced while walking or building an extension list.
pub const Error = error{
    /// The input ended in the middle of a header or declared data run.
    Truncated,
    /// A `Builder` ran out of room in the caller-provided buffer.
    NoSpaceLeft,
    /// An extension's data exceeds the u16 wire field (65535 bytes).
    DataTooLong,
    /// A `certificate_type` vector was empty, over-long, or its declared length
    /// did not match the body (RFC 7250 §3).
    MalformedCertificateType,
};

/// Well-known TLS extension types (RFC 8446 §4.2 and the IANA registry).
/// Non-exhaustive on purpose: unknown peers advertise types we do not model,
/// and those must round-trip untouched.  Use `fromInt` / `@intFromEnum` to
/// move between the wire u16 and this enum.
pub const ExtensionType = enum(u16) {
    server_name = 0,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    alpn = 16,
    client_certificate_type = 19,
    server_certificate_type = 20,
    compress_certificate = 27,
    record_size_limit = 28,
    delegated_credential = 34,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    signature_algorithms_cert = 50,
    key_share = 51,
    _,

    /// Map a raw wire value onto the enum; unknown values land in the `_` tag
    /// while preserving the exact integer (recoverable via `@intFromEnum`).
    pub fn fromInt(value: u16) ExtensionType {
        return @fromBackingInt(@intCast(value));
    }

    /// The raw wire value for this extension type.
    pub fn toInt(self: ExtensionType) u16 {
        return @backingInt(self);
    }

    /// True when `value` is a type this module names explicitly.
    pub fn isKnown(value: u16) bool {
        return switch (fromInt(value)) {
            .server_name,
            .status_request,
            .supported_groups,
            .signature_algorithms,
            .alpn,
            .client_certificate_type,
            .server_certificate_type,
            .compress_certificate,
            .record_size_limit,
            .delegated_credential,
            .pre_shared_key,
            .early_data,
            .supported_versions,
            .cookie,
            .psk_key_exchange_modes,
            .signature_algorithms_cert,
            .key_share,
            => true,
            _ => false,
        };
    }
};

/// A single decoded extension.  `data` aliases the caller's input buffer.
pub const Extension = struct {
    ext_type: u16,
    data: []const u8,

    /// Total wire footprint of this extension (header + data).
    pub fn wireLen(self: Extension) usize {
        return header_len + self.data.len;
    }

    /// Typed view of `ext_type` (unknown values keep their integer).
    pub fn typed(self: Extension) ExtensionType {
        return ExtensionType.fromInt(self.ext_type);
    }
};

/// RFC 7250 certificate types, as negotiated by the `server_certificate_type`
/// and `client_certificate_type` extensions.  `x509` is the classic X.509
/// chain; when `raw_public_key` is selected the peer's Certificate message
/// carries a single bare `SubjectPublicKeyInfo` instead (no chain, no CA path).
/// Non-exhaustive: unknown wire values round-trip via `@intFromEnum`.  OpenPGP
/// (1, RFC 6091) is deprecated and intentionally omitted.
pub const CertificateType = enum(u8) {
    x509 = 0,
    raw_public_key = 2,
    _,

    /// Map a raw wire byte onto the enum; unknown values land in `_`.
    pub fn fromInt(value: u8) CertificateType {
        return @fromBackingInt(@intCast(value));
    }

    /// The raw wire byte for this certificate type.
    pub fn toInt(self: CertificateType) u8 {
        return @backingInt(self);
    }
};

/// RFC 7250 §3: encode a `CertificateType types<1..2^8-1>` vector — a 1-byte
/// length prefix followed by one byte per type — into `out`.  This is the
/// *client offer* body for the `server_certificate_type` /
/// `client_certificate_type` extensions.  The list must name at least one type
/// (the vector floor is 1) and at most 255.
pub fn buildCertTypeList(out: []u8, types: []const CertificateType) Error![]const u8 {
    if (types.len == 0 or types.len > std.math.maxInt(u8)) return error.MalformedCertificateType;
    const need = 1 + types.len;
    if (out.len < need) return error.NoSpaceLeft;
    out[0] = @intCast(types.len);
    for (types, 0..) |t, i| out[1 + i] = t.toInt();
    return out[0..need];
}

/// RFC 7250 §3: decode a `CertificateType types<1..2^8-1>` vector into `out`,
/// returning the filled prefix.  The 1-byte length prefix must exactly cover
/// the remaining body and name at least one type.  Used by the server side
/// (and round-trip tests) to read what a client offered.
pub fn parseCertTypeList(body: []const u8, out: []CertificateType) Error![]CertificateType {
    if (body.len == 0) return error.MalformedCertificateType;
    const count = body[0];
    if (count == 0 or body.len - 1 != count) return error.MalformedCertificateType;
    if (out.len < count) return error.NoSpaceLeft;
    for (0..count) |i| out[i] = CertificateType.fromInt(body[1 + i]);
    return out[0..count];
}

/// RFC 7250 §3: decode the peer's *single selected* `CertificateType` from a
/// `server_certificate_type` / `client_certificate_type` response body — exactly
/// one byte, with no length prefix.  The returned value is non-exhaustive; the
/// caller MUST confirm the peer selected a type it actually offered.
pub fn parseSelectedCertType(body: []const u8) Error!CertificateType {
    if (body.len != 1) return error.MalformedCertificateType;
    return CertificateType.fromInt(body[0]);
}

/// Forward iterator over the *body* of an extension list — i.e. the bytes that
/// follow the 2-byte total-length prefix.  Use `fromBlock` to validate and
/// strip that prefix first, or construct directly over an already-unwrapped
/// body.  `next` is fully bounds-checked.
pub const Iterator = struct {
    body: []const u8,
    pos: usize = 0,

    /// Iterate over `body`, which must be exactly the concatenated extension
    /// entries (no length prefix).
    pub fn init(body: []const u8) Iterator {
        return .{ .body = body };
    }

    /// Validate and unwrap a full extension *block* (2-byte total length +
    /// body) into an iterator over its body.  Returns `error.Truncated` if the
    /// declared length overruns the input.
    pub fn fromBlock(block: []const u8) Error!Iterator {
        return init(try unwrap(block));
    }

    /// Advance to the next extension, or `null` at the end.  Returns
    /// `error.Truncated` if a header or its data runs past the body.
    pub fn next(self: *Iterator) Error!?Extension {
        if (self.pos == self.body.len) return null;
        if (self.body.len - self.pos < header_len) return error.Truncated;

        const ext_type = mem.readInt(u16, self.body[self.pos..][0..2], .big);
        const data_len = mem.readInt(u16, self.body[self.pos + 2 ..][0..2], .big);
        const data_start = self.pos + header_len;
        if (self.body.len - data_start < data_len) return error.Truncated;

        const ext: Extension = .{
            .ext_type = ext_type,
            .data = self.body[data_start .. data_start + data_len],
        };
        self.pos = data_start + data_len;
        return ext;
    }

    /// Remaining unparsed bytes in the body.
    pub fn remaining(self: Iterator) usize {
        return self.body.len - self.pos;
    }
};

/// Strip and validate the 2-byte total-length prefix of an extension block,
/// returning a slice over the body alone.
pub fn unwrap(block: []const u8) Error![]const u8 {
    if (block.len < 2) return error.Truncated;
    const total = mem.readInt(u16, block[0..2], .big);
    if (block.len - 2 < total) return error.Truncated;
    return block[2 .. 2 + total];
}

/// Locate the first extension of `ext_type` within a full block and return its
/// data slice (aliasing input), or `null` if absent.  Propagates
/// `error.Truncated` for malformed blocks.
pub fn find(block: []const u8, ext_type: u16) Error!?[]const u8 {
    var it = try Iterator.fromBlock(block);
    while (try it.next()) |ext| {
        if (ext.ext_type == ext_type) return ext.data;
    }
    return null;
}

/// Streaming writer that appends extensions into a caller-owned buffer and
/// finalizes with the leading 2-byte total length.  No allocation: it reserves
/// the 2-byte prefix up front, writes entries after it, and back-patches the
/// length in `finish`.
pub const Builder = struct {
    out: []u8,
    /// Bytes written so far, including the reserved 2-byte prefix.
    len: usize,

    /// Begin a block in `out`.  Requires room for at least the length prefix.
    pub fn begin(out: []u8) Error!Builder {
        if (out.len < 2) return error.NoSpaceLeft;
        return .{ .out = out, .len = 2 };
    }

    /// Append one extension.  `ext_type` is the raw wire value; pass
    /// `@intFromEnum(ExtensionType.foo)` for named types.
    pub fn add(self: *Builder, ext_type: u16, data: []const u8) Error!void {
        if (data.len > std.math.maxInt(u16)) return error.DataTooLong;
        const need = header_len + data.len;
        if (self.out.len - self.len < need) return error.NoSpaceLeft;

        mem.writeInt(u16, self.out[self.len..][0..2], ext_type, .big);
        mem.writeInt(u16, self.out[self.len + 2 ..][0..2], @intCast(data.len), .big);
        @memcpy(self.out[self.len + header_len .. self.len + need], data);
        self.len += need;
    }

    /// Typed convenience wrapper over `add`.
    pub fn addTyped(self: *Builder, ext_type: ExtensionType, data: []const u8) Error!void {
        return self.add(ext_type.toInt(), data);
    }

    /// Back-patch the total-length prefix and return the finished block slice
    /// (a view into `out`).  The body length must fit in a u16.
    pub fn finish(self: *Builder) Error![]const u8 {
        const body_len = self.len - 2;
        if (body_len > std.math.maxInt(u16)) return error.DataTooLong;
        mem.writeInt(u16, self.out[0..2], @intCast(body_len), .big);
        return self.out[0..self.len];
    }
};

// Tests

const testing = std.testing;

test "Builder round-trips two extensions parsed back by Iterator" {
    // Arrange
    var buf: [64]u8 = undefined;
    const sv_data = [_]u8{ 0x03, 0x04 }; // a fake supported_versions body
    const ks_data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var b = try Builder.begin(&buf);
    try b.addTyped(.supported_versions, &sv_data);
    try b.addTyped(.key_share, &ks_data);

    // Act
    const block = try b.finish();
    var it = try Iterator.fromBlock(block);
    const first = (try it.next()).?;
    const second = (try it.next()).?;
    const end = try it.next();

    // Assert
    try testing.expectEqual(@as(u16, 43), first.ext_type);
    try testing.expectEqualSlices(u8, &sv_data, first.data);
    try testing.expectEqual(ExtensionType.key_share, second.typed());
    try testing.expectEqualSlices(u8, &ks_data, second.data);
    try testing.expectEqual(@as(?Extension, null), end);
}

test "find locates supported_versions and returns null for absent type" {
    // Arrange
    var buf: [64]u8 = undefined;
    const sv_data = [_]u8{ 0x03, 0x04 };
    const sni_data = [_]u8{0x00};
    var b = try Builder.begin(&buf);
    try b.addTyped(.server_name, &sni_data);
    try b.addTyped(.supported_versions, &sv_data);
    const block = try b.finish();

    // Act
    const found = try find(block, ExtensionType.supported_versions.toInt());
    const missing = try find(block, ExtensionType.cookie.toInt());

    // Assert
    try testing.expect(found != null);
    try testing.expectEqualSlices(u8, &sv_data, found.?);
    try testing.expectEqual(@as(?[]const u8, null), missing);
}

test "truncated block returns error from Iterator.fromBlock" {
    // Arrange: prefix claims 6 body bytes but only 2 are present.
    const block = [_]u8{ 0x00, 0x06, 0x00, 0x0a };

    // Act
    const result = Iterator.fromBlock(&block);

    // Assert
    try testing.expectError(error.Truncated, result);
}

test "truncated entry data inside a valid-length block errors on next" {
    // Arrange: body length 4 is honored, but the single entry's data field
    // claims 10 bytes with none following.
    const block = [_]u8{ 0x00, 0x04, 0x00, 0x10, 0x00, 0x0a };
    var it = try Iterator.fromBlock(&block);

    // Act
    const result = it.next();

    // Assert
    try testing.expectError(error.Truncated, result);
}

test "empty block yields zero iterations" {
    // Arrange
    var buf: [8]u8 = undefined;
    var b = try Builder.begin(&buf);
    const block = try b.finish();

    // Act
    var it = try Iterator.fromBlock(block);
    const first = try it.next();

    // Assert
    try testing.expectEqual(@as(usize, 2), block.len); // just the prefix
    try testing.expectEqual(@as(?Extension, null), first);
    try testing.expectEqual(@as(usize, 0), it.remaining());
}

test "unknown extension type is preserved as a raw u16" {
    // Arrange: type 0xABCD is not in ExtensionType's named set.
    var buf: [32]u8 = undefined;
    const payload = [_]u8{ 0x01, 0x02, 0x03 };
    var b = try Builder.begin(&buf);
    try b.add(0xABCD, &payload);
    const block = try b.finish();

    // Act
    var it = try Iterator.fromBlock(block);
    const ext = (try it.next()).?;

    // Assert
    try testing.expectEqual(@as(u16, 0xABCD), ext.ext_type);
    try testing.expect(!ExtensionType.isKnown(ext.ext_type));
    try testing.expectEqual(@as(u16, 0xABCD), ext.typed().toInt());
    try testing.expectEqualSlices(u8, &payload, ext.data);
}

test "Builder reports NoSpaceLeft when buffer is exhausted" {
    // Arrange: room for the prefix plus a 4-byte header but no data.
    var buf: [6]u8 = undefined;
    var b = try Builder.begin(&buf);

    // Act
    const result = b.add(0x0000, &[_]u8{0xff});

    // Assert
    try testing.expectError(error.NoSpaceLeft, result);
}

test "fromInt and isKnown agree for named and unnamed types" {
    // Arrange / Act / Assert
    try testing.expectEqual(ExtensionType.alpn, ExtensionType.fromInt(16));
    try testing.expect(ExtensionType.isKnown(13)); // signature_algorithms
    try testing.expect(!ExtensionType.isKnown(9999));
    try testing.expectEqual(@as(u16, 51), ExtensionType.key_share.toInt());
}

test "certificate_type extension types are named and known (RFC 7250)" {
    // Arrange / Act / Assert
    try testing.expectEqual(ExtensionType.client_certificate_type, ExtensionType.fromInt(19));
    try testing.expectEqual(ExtensionType.server_certificate_type, ExtensionType.fromInt(20));
    try testing.expect(ExtensionType.isKnown(19));
    try testing.expect(ExtensionType.isKnown(20));
    try testing.expectEqual(@as(u16, 20), ExtensionType.server_certificate_type.toInt());
}

test "certificate_type offer list round-trips through the list parser" {
    // Arrange: the standard client offer preferring raw public keys.
    var buf: [8]u8 = undefined;
    const offer = [_]CertificateType{ .raw_public_key, .x509 };

    // Act
    const body = try buildCertTypeList(&buf, &offer);
    var out: [4]CertificateType = undefined;
    const parsed = try parseCertTypeList(body, &out);

    // Assert: 1-byte length prefix + two type bytes, order preserved.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x02, 0x02, 0x00 }, body);
    try testing.expectEqual(@as(usize, 2), parsed.len);
    try testing.expectEqual(CertificateType.raw_public_key, parsed[0]);
    try testing.expectEqual(CertificateType.x509, parsed[1]);
}

test "parseSelectedCertType reads one server selection and rejects bad framing" {
    // Arrange / Act / Assert: a single byte decodes to the selected type.
    try testing.expectEqual(CertificateType.raw_public_key, try parseSelectedCertType(&[_]u8{0x02}));
    try testing.expectEqual(CertificateType.x509, try parseSelectedCertType(&[_]u8{0x00}));
    // An unknown value round-trips (policy is the caller's job, not the codec's).
    try testing.expectEqual(@as(u8, 0x63), (try parseSelectedCertType(&[_]u8{0x63})).toInt());
    // Zero or multiple bytes are malformed: the response is a single type.
    try testing.expectError(error.MalformedCertificateType, parseSelectedCertType(&[_]u8{}));
    try testing.expectError(error.MalformedCertificateType, parseSelectedCertType(&[_]u8{ 0x00, 0x02 }));
}

test "buildCertTypeList and parseCertTypeList are fail-closed on empty and mismatched lengths" {
    // Arrange
    var buf: [8]u8 = undefined;

    // Act / Assert: the vector floor is 1 — an empty offer is rejected.
    try testing.expectError(error.MalformedCertificateType, buildCertTypeList(&buf, &[_]CertificateType{}));
    // A one-type offer still fits and round-trips.
    const one = try buildCertTypeList(&buf, &[_]CertificateType{.x509});
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, one);
    // Declared count exceeding the body is rejected (declares 3, supplies 1).
    var out: [4]CertificateType = undefined;
    try testing.expectError(error.MalformedCertificateType, parseCertTypeList(&[_]u8{ 0x03, 0x00 }, &out));
    // A zero declared count is rejected.
    try testing.expectError(error.MalformedCertificateType, parseCertTypeList(&[_]u8{0x00}, &out));
    // An empty body is rejected (no length prefix at all).
    try testing.expectError(error.MalformedCertificateType, parseCertTypeList(&[_]u8{}, &out));
}

test "buildCertTypeList reports NoSpaceLeft when the buffer cannot hold the vector" {
    // Arrange: room for the length prefix but not the two type bytes.
    var buf: [2]u8 = undefined;

    // Act / Assert
    try testing.expectError(error.NoSpaceLeft, buildCertTypeList(&buf, &[_]CertificateType{ .raw_public_key, .x509 }));
}
