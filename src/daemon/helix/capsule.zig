// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helix upgrade capsules: schema-versioned state records over CoilPack.
//!
//! A capsule is the only state shape that may cross a Orochi binary upgrade.
//! Compatibility is negotiated per schema id and version range. Payload fields
//! use Cap'n-Proto-style ordinal evolution: append new ordinals, never reorder.

const std = @import("std");
const coilpack = @import("../../proto/coilpack.zig");

const Allocator = std.mem.Allocator;

const magic = [_]u8{ 'H', 'L', 'X', '1' };

pub const Error = error{
    BadMagic,
    UnknownKind,
    UnknownSchema,
    VersionRangeInvalid,
    VersionUnsupported,
    SchemaMismatch,
    TrailingBytes,
    FieldOrdinalOutOfOrder,
    DuplicateFieldOrdinal,
} || Allocator.Error || coilpack.DecodeError || coilpack.EncodeError;

/// Compile-time registry of Helix state families.
pub const CapsuleKind = enum(u8) {
    clients = 1,
    channels = 2,
    sessions = 3,
    tls_session = 4,
    tsumugi_ratchet = 5,
    mesh_checkpoint = 6,
    send_queue = 7,
    s2s_link = 8,
    ws_session = 9,
    tls_ticket_keys = 10,
    pending_migration = 11,
    monitor_list = 12,
    silence_list = 13,

    pub fn fromByte(byte: u8) Error!CapsuleKind {
        return switch (byte) {
            1 => .clients,
            2 => .channels,
            3 => .sessions,
            4 => .tls_session,
            5 => .tsumugi_ratchet,
            6 => .mesh_checkpoint,
            7 => .send_queue,
            8 => .s2s_link,
            9 => .ws_session,
            10 => .tls_ticket_keys,
            11 => .pending_migration,
            12 => .monitor_list,
            13 => .silence_list,
            else => error.UnknownKind,
        };
    }
};

/// Per-kind registry metadata. There is deliberately no global ABI integer.
pub const Descriptor = struct {
    kind: CapsuleKind,
    schema_id: u32,
    current_version: u16,
    min_supported: u16,
    max_supported: u16,

    pub fn supports(self: Descriptor, header: Header) bool {
        if (self.schema_id != header.schema_id) return false;
        if (self.kind != header.kind) return false;
        return rangesOverlap(
            self.min_supported,
            self.max_supported,
            header.min_supported,
            header.max_supported,
        );
    }
};

pub const registry = [_]Descriptor{
    // v2 appends a trailing `was_secured` byte to the session snapshot so the
    // successor drops a secured client that arrives without its TLS engine rather
    // than adopting it as plaintext. v3 (2026-07) appends a trailing session-token
    // block ([u8 tlen][bytes]) so a carried client re-tracks in the SessionStore
    // under the SAME reclaim token instead of becoming a registry orphan.
    // `min_supported = 1` keeps accepting v1/v2 capsules sealed by pre-bump
    // binaries; `session_snapshot.decode` reads both tails tolerantly. v4
    // (2026-07) appends a trailing [u64 umode_bits][u32 ilen][pending_in]
    // [u32 olen][pending_out] block so client-set umodes, the partial inbound
    // line, and a plaintext connection's unsent SendQ tail all survive the
    // swap (previously silently reset/dropped).
    .{ .kind = .clients, .schema_id = 0x4843_4c54, .current_version = 4, .min_supported = 1, .max_supported = 4 },
    .{ .kind = .channels, .schema_id = 0x4843_484e, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // v2 (2026-07): each session record appends the attached connection's join
    // fd (i32) and the detached restore snapshot (u32 len + bytes), so bouncer
    // sessions restore byte-identically across USR2 instead of degrading to a
    // bare reclaim token. `min_supported = 1` keeps accepting v1 capsules sealed
    // by pre-bump binaries; `session_capsule.decode` is version-aware.
    .{ .kind = .sessions, .schema_id = 0x4853_4553, .current_version = 2, .min_supported = 1, .max_supported = 2 },
    .{ .kind = .tls_session, .schema_id = 0x4854_4c53, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    .{ .kind = .tsumugi_ratchet, .schema_id = 0x4856_4549, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    .{ .kind = .mesh_checkpoint, .schema_id = 0x484d_4553, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    .{ .kind = .send_queue, .schema_id = 0x4853_4551, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // v2 (2026-07): `Established.serialize` gained a trailing `admitted_frame_families`
    // (u32), growing the embedded blob by 4 bytes. `min_supported = 1` keeps accepting
    // v1 capsules sealed by pre-bump binaries; `s2s_snapshot.decode` is version-aware.
    .{ .kind = .s2s_link, .schema_id = 0x4832_534c, .current_version = 2, .min_supported = 1, .max_supported = 2 },
    // v2 (2026-07): appends the WS adapter's partial framing state — the
    // deframer's buffered partial inbound frame + fragmentation flags and the tx
    // accumulator's partial outbound line — so a mid-frame wss client is carried
    // instead of dropped (v1 only sealed at a clean framing boundary, which an
    // active browser client almost never sits at, so every busy wss client
    // reconnected on every upgrade). `min_supported = 1` keeps accepting v1
    // capsules sealed by pre-bump binaries; `ws_snapshot.decode` is version-aware.
    .{ .kind = .ws_session, .schema_id = 0x4857_5353, .current_version = 2, .min_supported = 1, .max_supported = 2 },
    .{ .kind = .tls_ticket_keys, .schema_id = 0x4854_4b59, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // One staged cross-mesh session-migration entry (a `session_migrate.encode`
    // wire blob: token + account + verified snapshot), one capsule per entry, so
    // migrations staged by a peer just before a USR2 survive the swap instead of
    // dying with the predecessor (the client's reclaim would silently fall back
    // to the legacy redirect).
    .{ .kind = .pending_migration, .schema_id = 0x4850_4d47, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // One carried per-client MONITOR watch list (a `monitor_capsule` wire blob;
    // its client_id field carries the inherited socket FD — the same join key
    // the TLS/WS capsules use — NOT a client id, which does not survive the
    // swap). Without it every carried client silently lost its watch list on
    // USR2: the client believed it was still monitoring, but no MONONLINE/
    // MONOFFLINE ever arrived again until it re-issued MONITOR.
    .{ .kind = .monitor_list, .schema_id = 0x484d_4f4e, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // One carried per-client SILENCE list (a `silence_capsule` wire blob; its
    // client_id field carries the inherited socket FD — the Helix join key —
    // exactly like `.monitor_list`). Without it every carried client silently
    // lost its server-side ignore masks on USR2: a silenced abuser became
    // audible again after every deploy with no indication to the victim.
    .{ .kind = .silence_list, .schema_id = 0x4853_494c, .current_version = 1, .min_supported = 1, .max_supported = 1 },
};

pub fn descriptor(kind: CapsuleKind) Descriptor {
    inline for (registry) |item| {
        if (item.kind == kind) return item;
    }
    unreachable;
}

pub fn descriptorForSchema(schema_id: u32) Error!Descriptor {
    inline for (registry) |item| {
        if (item.schema_id == schema_id) return item;
    }
    return error.UnknownSchema;
}

pub const Header = struct {
    schema_id: u32,
    kind: CapsuleKind,
    version: u16,
    min_supported: u16,
    max_supported: u16,

    pub fn init(kind: CapsuleKind) Header {
        const d = descriptor(kind);
        return .{
            .schema_id = d.schema_id,
            .kind = kind,
            .version = d.current_version,
            .min_supported = d.min_supported,
            .max_supported = d.max_supported,
        };
    }
};

/// A typed payload field. Ordinals are stable schema positions; values are
/// already CoilPack-compatible byte strings owned by the caller or decoder.
pub const Field = struct {
    ordinal: u32,
    bytes: []const u8,
};

pub const Capsule = struct {
    header: Header,
    fields: []Field,

    pub fn deinit(self: *Capsule, allocator: Allocator) void {
        for (self.fields) |field| allocator.free(field.bytes);
        allocator.free(self.fields);
        self.* = .{ .header = Header.init(.clients), .fields = &.{} };
    }
};

pub fn make(kind: CapsuleKind, fields: []Field) Capsule {
    return .{ .header = Header.init(kind), .fields = fields };
}

pub fn negotiate(local: Descriptor, incoming: Header) Error!u16 {
    try validateHeader(incoming);
    if (!local.supports(incoming)) return error.VersionUnsupported;
    return @min(local.max_supported, incoming.max_supported);
}

pub fn validate(capsule: Capsule) Error!void {
    try validateHeader(capsule.header);
    const d = try descriptorForSchema(capsule.header.schema_id);
    if (d.kind != capsule.header.kind) return error.SchemaMismatch;
    _ = try negotiate(d, capsule.header);
    try validateFieldOrdinals(capsule.fields);
}

pub fn encode(allocator: Allocator, capsule: Capsule) Error![]u8 {
    try validate(capsule);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, &magic);
    try appendU32(allocator, &out, capsule.header.schema_id);
    try out.append(allocator, @intFromEnum(capsule.header.kind));
    try appendU16(allocator, &out, capsule.header.version);
    try appendU16(allocator, &out, capsule.header.min_supported);
    try appendU16(allocator, &out, capsule.header.max_supported);
    try appendVarint(allocator, &out, capsule.fields.len);
    for (capsule.fields) |field| {
        try appendU32(allocator, &out, field.ordinal);
        try appendBytes(allocator, &out, field.bytes);
    }

    return try out.toOwnedSlice(allocator);
}

pub fn decode(allocator: Allocator, bytes: []const u8) Error!Capsule {
    var r = coilpack.Cbs.init(bytes);
    const capsule = try decodeReader(allocator, &r);
    if (!r.done()) {
        var c = capsule;
        c.deinit(allocator);
        return error.TrailingBytes;
    }
    return capsule;
}

/// Decode one capsule from a shared reader, advancing it past this capsule (no
/// end-of-buffer check). Used by `decodeStream` to walk a concatenated sequence.
pub fn decodeReader(allocator: Allocator, r: *coilpack.Cbs) Error!Capsule {
    for (magic) |want| {
        const got = try r.readU8();
        if (got != want) return error.BadMagic;
    }

    const schema_id = try r.readU32Le();
    const kind = try CapsuleKind.fromByte(try r.readU8());
    const header = Header{
        .schema_id = schema_id,
        .kind = kind,
        .version = try r.readU16Le(),
        .min_supported = try r.readU16Le(),
        .max_supported = try r.readU16Le(),
    };

    const field_count64 = try r.readVarint();
    if (field_count64 > std.math.maxInt(usize)) return error.LengthTooLarge;
    const field_count: usize = @intCast(field_count64);

    var fields: std.ArrayList(Field) = .empty;
    errdefer {
        for (fields.items) |field| allocator.free(field.bytes);
        fields.deinit(allocator);
    }

    var i: usize = 0;
    while (i < field_count) : (i += 1) {
        const ordinal = try r.readU32Le();
        const payload_view = try r.readBytes();
        const payload = try allocator.dupe(u8, payload_view);
        errdefer allocator.free(payload);
        try fields.append(allocator, .{ .ordinal = ordinal, .bytes = payload });
    }

    var capsule = Capsule{ .header = header, .fields = try fields.toOwnedSlice(allocator) };
    errdefer capsule.deinit(allocator);
    try validate(capsule);
    return capsule;
}

/// Decode every capsule in a concatenated `bytes` stream (the on-arena format).
/// The caller owns the returned slice and must `deinit` each capsule and free
/// the slice.
pub fn decodeStream(allocator: Allocator, bytes: []const u8) Error![]Capsule {
    var list: std.ArrayList(Capsule) = .empty;
    errdefer {
        for (list.items) |*c| c.deinit(allocator);
        list.deinit(allocator);
    }
    var r = coilpack.Cbs.init(bytes);
    while (!r.done()) {
        const cap = try decodeReader(allocator, &r);
        try list.append(allocator, cap);
    }
    return try list.toOwnedSlice(allocator);
}

fn validateHeader(header: Header) Error!void {
    if (header.min_supported > header.version or header.version > header.max_supported) {
        return error.VersionRangeInvalid;
    }
}

fn validateFieldOrdinals(fields: []const Field) Error!void {
    if (fields.len == 0) return;
    var prev = fields[0].ordinal;
    var i: usize = 1;
    while (i < fields.len) : (i += 1) {
        const current = fields[i].ordinal;
        if (current == prev) return error.DuplicateFieldOrdinal;
        if (current < prev) return error.FieldOrdinalOutOfOrder;
        prev = current;
    }
}

fn rangesOverlap(a_min: u16, a_max: u16, b_min: u16, b_max: u16) bool {
    return @max(a_min, b_min) <= @min(a_max, b_max);
}

fn appendU16(allocator: Allocator, out: *std.ArrayList(u8), value: u16) Error!void {
    var buf: [2]u8 = undefined;
    var w = coilpack.Cbb.init(&buf);
    _ = try w.writeU16Le(value);
    try out.appendSlice(allocator, w.written());
}

fn appendU32(allocator: Allocator, out: *std.ArrayList(u8), value: u32) Error!void {
    var buf: [4]u8 = undefined;
    var w = coilpack.Cbb.init(&buf);
    _ = try w.writeU32Le(value);
    try out.appendSlice(allocator, w.written());
}

fn appendVarint(allocator: Allocator, out: *std.ArrayList(u8), value: u64) Error!void {
    var buf: [coilpack.max_varint_bytes]u8 = undefined;
    var w = coilpack.Cbb.init(&buf);
    _ = try w.writeVarint(value);
    try out.appendSlice(allocator, w.written());
}

fn appendBytes(allocator: Allocator, out: *std.ArrayList(u8), bytes: []const u8) Error!void {
    var len_buf: [coilpack.max_varint_bytes]u8 = undefined;
    var w = coilpack.Cbb.init(&len_buf);
    _ = try w.writeVarint(bytes.len);
    try out.appendSlice(allocator, w.written());
    try out.appendSlice(allocator, bytes);
}

test "capsule encodes, decodes, and validates ordinal order" {
    const allocator = std.testing.allocator;
    const fields = [_]Field{
        .{ .ordinal = 1, .bytes = "nick" },
        .{ .ordinal = 2, .bytes = "session" },
    };
    const original = make(.clients, @constCast(fields[0..]));

    const encoded = try encode(allocator, original);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(CapsuleKind.clients, decoded.header.kind);
    try std.testing.expectEqual(@as(usize, 2), decoded.fields.len);
    try std.testing.expectEqual(@as(u32, 2), decoded.fields[1].ordinal);
    try std.testing.expect(std.mem.eql(u8, "session", decoded.fields[1].bytes));
}

test "decodeStream walks a concatenated capsule sequence" {
    const allocator = std.testing.allocator;
    var f1 = [_]Field{.{ .ordinal = 1, .bytes = "alice" }};
    var f2 = [_]Field{.{ .ordinal = 1, .bytes = "#chan" }};

    const e1 = try encode(allocator, make(.clients, f1[0..]));
    defer allocator.free(e1);
    const e2 = try encode(allocator, make(.channels, f2[0..]));
    defer allocator.free(e2);

    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try stream.appendSlice(allocator, e1);
    try stream.appendSlice(allocator, e2);

    const caps = try decodeStream(allocator, stream.items);
    defer {
        for (caps) |*c| c.deinit(allocator);
        allocator.free(caps);
    }
    try std.testing.expectEqual(@as(usize, 2), caps.len);
    try std.testing.expectEqual(CapsuleKind.clients, caps[0].header.kind);
    try std.testing.expectEqual(CapsuleKind.channels, caps[1].header.kind);
    try std.testing.expect(std.mem.eql(u8, "alice", caps[0].fields[0].bytes));
    try std.testing.expect(std.mem.eql(u8, "#chan", caps[1].fields[0].bytes));
}

test "negotiation is per capsule schema range" {
    var header = Header.init(.send_queue);
    header.version = 2;
    header.min_supported = 2;
    header.max_supported = 3;

    var local = descriptor(.send_queue);
    local.min_supported = 1;
    local.max_supported = 2;
    local.current_version = 2;

    try std.testing.expectEqual(@as(u16, 2), try negotiate(local, header));
}

test "duplicate and reordered ordinals are rejected" {
    const dup = [_]Field{
        .{ .ordinal = 4, .bytes = "a" },
        .{ .ordinal = 4, .bytes = "b" },
    };
    try std.testing.expectError(error.DuplicateFieldOrdinal, validate(make(.channels, @constCast(dup[0..]))));

    const reordered = [_]Field{
        .{ .ordinal = 5, .bytes = "a" },
        .{ .ordinal = 3, .bytes = "b" },
    };
    try std.testing.expectError(error.FieldOrdinalOutOfOrder, validate(make(.channels, @constCast(reordered[0..]))));
}
