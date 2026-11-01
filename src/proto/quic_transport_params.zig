// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! QUIC transport parameters codec (RFC 9000 §18 / §18.2).
//!
//! QUIC carries its transport configuration as a TLS 1.3 extension
//! (`quic_transport_parameters`, ext type 0x39, RFC 9001 §8.2) whose body is a
//! sequence of `{ id, length, value }` records, each field encoded as a QUIC
//! variable-length integer (RFC 9000 §16). The id and length are always
//! varints; the value is `length` raw bytes whose interpretation is per-id.
//! Most parameters carry a single varint value; a few (the connection-id
//! parameters) carry an opaque byte string.
//!
//! This module encodes/decodes that body only — the surrounding TLS extension
//! envelope (type tag + 2-byte length) is added by the generic
//! `tls_extension` codec. It is socketless and allocation-light: encoding
//! writes into a caller-owned buffer, decoding aliases the caller's input for
//! connection-id byte strings. Unknown ids are skipped (RFC 9000 §18.1: "An
//! endpoint MUST ignore transport parameters that it does not support").
//!
//! All length math is bounds-checked: a malformed/truncated body returns
//! `error.Truncated` (or `error.Malformed`) rather than reading out of bounds.
//! Reuses the QUIC varint codec from `quic_frame` — no hand-rolled varints.

const std = @import("std");
const quic_frame = @import("quic_frame.zig");

/// Transport-parameter identifiers we model (RFC 9000 §18.2 + RFC 9001 §8.2).
/// Non-exhaustive: unknown ids round-trip-skip on decode. Reserved "GREASE"
/// ids (31 * N + 27) are simply unknown ids and are ignored like any other.
pub const ParamId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    /// RFC 9221 §3 — the maximum size (in bytes) of a DATAGRAM frame this
    /// endpoint is willing to receive. A non-zero value advertised by a peer is
    /// what lets the other side send DATAGRAM frames at all. WebTransport
    /// datagrams (RFC 9297/9220) ride QUIC DATAGRAM frames, so a server MUST
    /// advertise this for a browser (Chrome) to enable WT datagrams.
    max_datagram_frame_size = 0x20,
    _,

    pub fn fromInt(value: u64) ParamId {
        return @fromBackingInt(@intCast(value));
    }

    pub fn toInt(self: ParamId) u64 {
        return @backingInt(self);
    }
};

/// Maximum connection-id length QUIC v1 permits (RFC 9000 §17.2). Connection
/// ids longer than this in a decoded parameter are rejected as malformed.
pub const max_connection_id_len: usize = 20;

pub const Error = error{
    /// The body ended mid-field, or a declared value length overran the body.
    Truncated,
    /// A varint was non-canonical, a value's length disagreed with its
    /// integer-typed parameter, or a connection id exceeded the legal length.
    Malformed,
    /// A builder ran out of room in the caller-provided buffer.
    NoSpaceLeft,
};

/// A decoded set of the transport parameters this server cares about. Fields
/// default to "absent" (`null` for optionals) so a peer that omits a parameter
/// leaves the default in place — RFC 9000 §18 default values are the caller's
/// responsibility to apply where a missing optional must fall back.
///
/// Connection-id byte strings alias the decoded input buffer; copy them if they
/// must outlive it.
pub const TransportParameters = struct {
    original_destination_connection_id: ?[]const u8 = null,
    initial_source_connection_id: ?[]const u8 = null,
    retry_source_connection_id: ?[]const u8 = null,
    max_idle_timeout: ?u64 = null,
    max_udp_payload_size: ?u64 = null,
    initial_max_data: ?u64 = null,
    initial_max_stream_data_bidi_local: ?u64 = null,
    initial_max_stream_data_bidi_remote: ?u64 = null,
    initial_max_stream_data_uni: ?u64 = null,
    initial_max_streams_bidi: ?u64 = null,
    initial_max_streams_uni: ?u64 = null,
    active_connection_id_limit: ?u64 = null,
    ack_delay_exponent: ?u64 = null,
    max_ack_delay: ?u64 = null,
    /// RFC 9221 §3 — advertised maximum DATAGRAM frame size this endpoint will
    /// receive. Absent/null means DATAGRAM frames are not supported (the peer
    /// MUST NOT send them). A WebTransport server advertises a non-zero value so
    /// the browser may send WT datagrams.
    max_datagram_frame_size: ?u64 = null,
    disable_active_migration: bool = false,
};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

const EncodeError = Error || std.mem.Allocator.Error;

/// Append a QUIC varint, mapping the lower codec's errors onto this module's.
/// `appendVarInt` only fails on an out-of-range value (> 2^62-1) or allocation.
fn putVarInt(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) EncodeError!void {
    quic_frame.appendVarInt(out, allocator, value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return Error.Malformed,
    };
}

/// Append one varint-valued parameter to `out`.
fn appendVarintParam(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    id: ParamId,
    value: u64,
) EncodeError!void {
    try putVarInt(out, allocator, id.toInt());
    // length = the encoded width of the value varint.
    const vlen = quic_frame.varIntLen(value) catch return Error.Malformed;
    try putVarInt(out, allocator, vlen);
    try putVarInt(out, allocator, value);
}

/// Append one byte-string-valued parameter (a connection id) to `out`.
fn appendBytesParam(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    id: ParamId,
    bytes: []const u8,
) EncodeError!void {
    if (bytes.len > max_connection_id_len) return Error.Malformed;
    try putVarInt(out, allocator, id.toInt());
    try putVarInt(out, allocator, bytes.len);
    try out.appendSlice(allocator, bytes);
}

/// Append a zero-length (flag) parameter to `out`.
fn appendEmptyParam(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    id: ParamId,
) EncodeError!void {
    try putVarInt(out, allocator, id.toInt());
    try putVarInt(out, allocator, 0);
}

/// Encode `params` into the transport-parameters extension body, appending to
/// `out`. Only the fields that are set (non-null / true) are emitted, matching
/// the absent-parameter semantics of RFC 9000 §18. The caller owns `out`.
pub fn encode(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    params: TransportParameters,
) EncodeError!void {
    if (params.original_destination_connection_id) |cid|
        try appendBytesParam(out, allocator, .original_destination_connection_id, cid);
    if (params.initial_source_connection_id) |cid|
        try appendBytesParam(out, allocator, .initial_source_connection_id, cid);
    if (params.retry_source_connection_id) |cid|
        try appendBytesParam(out, allocator, .retry_source_connection_id, cid);
    if (params.max_idle_timeout) |v|
        try appendVarintParam(out, allocator, .max_idle_timeout, v);
    if (params.max_udp_payload_size) |v|
        try appendVarintParam(out, allocator, .max_udp_payload_size, v);
    if (params.initial_max_data) |v|
        try appendVarintParam(out, allocator, .initial_max_data, v);
    if (params.initial_max_stream_data_bidi_local) |v|
        try appendVarintParam(out, allocator, .initial_max_stream_data_bidi_local, v);
    if (params.initial_max_stream_data_bidi_remote) |v|
        try appendVarintParam(out, allocator, .initial_max_stream_data_bidi_remote, v);
    if (params.initial_max_stream_data_uni) |v|
        try appendVarintParam(out, allocator, .initial_max_stream_data_uni, v);
    if (params.initial_max_streams_bidi) |v|
        try appendVarintParam(out, allocator, .initial_max_streams_bidi, v);
    if (params.initial_max_streams_uni) |v|
        try appendVarintParam(out, allocator, .initial_max_streams_uni, v);
    if (params.active_connection_id_limit) |v|
        try appendVarintParam(out, allocator, .active_connection_id_limit, v);
    if (params.ack_delay_exponent) |v|
        try appendVarintParam(out, allocator, .ack_delay_exponent, v);
    if (params.max_ack_delay) |v|
        try appendVarintParam(out, allocator, .max_ack_delay, v);
    if (params.max_datagram_frame_size) |v|
        try appendVarintParam(out, allocator, .max_datagram_frame_size, v);
    if (params.disable_active_migration)
        try appendEmptyParam(out, allocator, .disable_active_migration);
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Read one QUIC varint from `body` at `pos`, advancing `pos`. Maps the lower
/// codec's errors onto this module's `Truncated`/`Malformed`.
fn takeVarInt(body: []const u8, pos: *usize) Error!u64 {
    const dec = quic_frame.decodeVarInt(body[pos.*..]) catch |err| switch (err) {
        error.BufferTooShort => return Error.Truncated,
        else => return Error.Malformed,
    };
    pos.* += dec.len;
    return dec.value;
}

/// Decode a transport-parameters extension body into a `TransportParameters`.
/// Unknown ids are skipped (RFC 9000 §18.1). Integer-typed parameters whose
/// value bytes are not a single canonical varint, or whose length disagrees
/// with that varint's width, are rejected. Byte-string parameters alias `body`.
pub fn decode(body: []const u8) Error!TransportParameters {
    var params: TransportParameters = .{};
    var pos: usize = 0;
    while (pos < body.len) {
        const id = ParamId.fromInt(try takeVarInt(body, &pos));
        const len = try takeVarInt(body, &pos);
        if (len > body.len - pos) return Error.Truncated;
        const value = body[pos .. pos + len];
        pos += len;

        switch (id) {
            .original_destination_connection_id => params.original_destination_connection_id = try connectionId(value),
            .initial_source_connection_id => params.initial_source_connection_id = try connectionId(value),
            .retry_source_connection_id => params.retry_source_connection_id = try connectionId(value),
            .max_idle_timeout => params.max_idle_timeout = try integerValue(value),
            .max_udp_payload_size => params.max_udp_payload_size = try integerValue(value),
            .initial_max_data => params.initial_max_data = try integerValue(value),
            .initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try integerValue(value),
            .initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try integerValue(value),
            .initial_max_stream_data_uni => params.initial_max_stream_data_uni = try integerValue(value),
            .initial_max_streams_bidi => params.initial_max_streams_bidi = try integerValue(value),
            .initial_max_streams_uni => params.initial_max_streams_uni = try integerValue(value),
            .active_connection_id_limit => params.active_connection_id_limit = try integerValue(value),
            .ack_delay_exponent => params.ack_delay_exponent = try integerValue(value),
            .max_ack_delay => params.max_ack_delay = try integerValue(value),
            .max_datagram_frame_size => params.max_datagram_frame_size = try integerValue(value),
            .disable_active_migration => {
                // A flag parameter MUST be zero-length (RFC 9000 §18.2).
                if (value.len != 0) return Error.Malformed;
                params.disable_active_migration = true;
            },
            // Unknown / unmodeled ids (including stateless_reset_token,
            // max_ack_delay siblings, GREASE) are ignored per RFC 9000 §18.1.
            else => {},
        }
    }
    return params;
}

/// Interpret an integer-typed parameter's value as exactly one canonical QUIC
/// varint that consumes the whole value field.
fn integerValue(value: []const u8) Error!u64 {
    const dec = quic_frame.decodeVarInt(value) catch |err| switch (err) {
        error.BufferTooShort => return Error.Truncated,
        else => return Error.Malformed,
    };
    if (dec.len != value.len) return Error.Malformed;
    return dec.value;
}

/// Validate a connection-id byte string's length (RFC 9000 §17.2 caps it at 20).
fn connectionId(value: []const u8) Error![]const u8 {
    if (value.len > max_connection_id_len) return Error.Malformed;
    return value;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "transport_param round-trip of a full server parameter set" {
    const allocator = testing.allocator;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const iscid = [_]u8{ 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5 };

    const in: TransportParameters = .{
        .original_destination_connection_id = &odcid,
        .initial_source_connection_id = &iscid,
        .max_idle_timeout = 30_000,
        .max_udp_payload_size = 1472,
        .initial_max_data = 1_048_576,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_stream_data_uni = 128 * 1024,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 3,
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
        .disable_active_migration = true,
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try encode(&buf, allocator, in);

    const out = try decode(buf.items);
    try testing.expectEqualSlices(u8, &odcid, out.original_destination_connection_id.?);
    try testing.expectEqualSlices(u8, &iscid, out.initial_source_connection_id.?);
    try testing.expectEqual(@as(?u64, 30_000), out.max_idle_timeout);
    try testing.expectEqual(@as(?u64, 1472), out.max_udp_payload_size);
    try testing.expectEqual(@as(?u64, 1_048_576), out.initial_max_data);
    try testing.expectEqual(@as(?u64, 256 * 1024), out.initial_max_stream_data_bidi_local);
    try testing.expectEqual(@as(?u64, 256 * 1024), out.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(?u64, 128 * 1024), out.initial_max_stream_data_uni);
    try testing.expectEqual(@as(?u64, 100), out.initial_max_streams_bidi);
    try testing.expectEqual(@as(?u64, 3), out.initial_max_streams_uni);
    try testing.expectEqual(@as(?u64, 8), out.active_connection_id_limit);
    try testing.expectEqual(@as(?u64, 1200), out.max_datagram_frame_size);
    try testing.expect(out.disable_active_migration);
    // Omitted params stay null.
    try testing.expectEqual(@as(?[]const u8, null), out.retry_source_connection_id);
    try testing.expectEqual(@as(?u64, null), out.ack_delay_exponent);
}

test "transport_param omitted fields are not emitted and stay absent" {
    const allocator = testing.allocator;
    const in: TransportParameters = .{ .initial_max_data = 42 };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try encode(&buf, allocator, in);

    const out = try decode(buf.items);
    try testing.expectEqual(@as(?u64, 42), out.initial_max_data);
    try testing.expectEqual(@as(?u64, null), out.max_idle_timeout);
    try testing.expect(!out.disable_active_migration);
}

test "transport_param decode ignores unknown ids" {
    // id = 0x1234 (unknown), len = 3, value = {0xaa,0xbb,0xcc}; then a known
    // initial_max_data = 7. The unknown record must be skipped cleanly.
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try quic_frame.appendVarInt(&buf, allocator, 0x1234);
    try quic_frame.appendVarInt(&buf, allocator, 3);
    try buf.appendSlice(allocator, &[_]u8{ 0xaa, 0xbb, 0xcc });
    try quic_frame.appendVarInt(&buf, allocator, ParamId.initial_max_data.toInt());
    try quic_frame.appendVarInt(&buf, allocator, 1);
    try quic_frame.appendVarInt(&buf, allocator, 7);

    const out = try decode(buf.items);
    try testing.expectEqual(@as(?u64, 7), out.initial_max_data);
}

test "transport_param empty body decodes to all-absent params" {
    const out = try decode(&.{});
    try testing.expectEqual(@as(?u64, null), out.initial_max_data);
    try testing.expect(!out.disable_active_migration);
}

test "transport_param decode rejects a truncated value run" {
    // id = initial_max_data (0x04), len = 4, but only 2 value bytes present.
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try quic_frame.appendVarInt(&buf, allocator, ParamId.initial_max_data.toInt());
    try quic_frame.appendVarInt(&buf, allocator, 4);
    try buf.appendSlice(allocator, &[_]u8{ 0x80, 0x00 });
    try testing.expectError(Error.Truncated, decode(buf.items));
}

test "transport_param decode rejects an integer value whose length disagrees" {
    // initial_max_data with len=2 but value bytes {0x05} would be a 1-byte
    // canonical varint — length mismatch is malformed.
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try quic_frame.appendVarInt(&buf, allocator, ParamId.initial_max_data.toInt());
    try quic_frame.appendVarInt(&buf, allocator, 2);
    // Two bytes that form a 1-byte varint (0x05) plus a stray byte.
    try buf.appendSlice(allocator, &[_]u8{ 0x05, 0x00 });
    try testing.expectError(Error.Malformed, decode(buf.items));
}

test "transport_param decode rejects an over-long connection id" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try quic_frame.appendVarInt(&buf, allocator, ParamId.initial_source_connection_id.toInt());
    try quic_frame.appendVarInt(&buf, allocator, max_connection_id_len + 1);
    try buf.appendSlice(allocator, &(@as([(max_connection_id_len + 1)]u8, @splat(0xab))));
    try testing.expectError(Error.Malformed, decode(buf.items));
}

test "transport_param encode rejects an over-long connection id" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    const big = @as([(max_connection_id_len + 1)]u8, @splat(0xcd));
    try testing.expectError(
        Error.Malformed,
        encode(&buf, allocator, .{ .initial_source_connection_id = &big }),
    );
}

test "transport_param flag parameter must be zero length" {
    const allocator = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try quic_frame.appendVarInt(&buf, allocator, ParamId.disable_active_migration.toInt());
    try quic_frame.appendVarInt(&buf, allocator, 1);
    try buf.append(allocator, 0x00);
    try testing.expectError(Error.Malformed, decode(buf.items));
}

test {
    std.testing.refAllDecls(@This());
}
