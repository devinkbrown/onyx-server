// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helix upgrade capsules: schema-versioned state records over CoilPack.
//!
//! A capsule is the only state shape that may cross an Onyx Server binary upgrade.
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
    mooring_ratchet = 5,
    mesh_checkpoint = 6,
    send_queue = 7,
    s2s_link = 8,
    ws_session = 9,
    tls_ticket_keys = 10,
    pending_migration = 11,
    monitor_list = 12,
    silence_list = 13,
    session_tombstone = 14,
    history = 15,
    webhook_store = 16,
    handoff_manifest = 17,

    pub fn fromByte(byte: u8) Error!CapsuleKind {
        return switch (byte) {
            1 => .clients,
            2 => .channels,
            3 => .sessions,
            4 => .tls_session,
            5 => .mooring_ratchet,
            6 => .mesh_checkpoint,
            7 => .send_queue,
            8 => .s2s_link,
            9 => .ws_session,
            10 => .tls_ticket_keys,
            11 => .pending_migration,
            12 => .monitor_list,
            13 => .silence_list,
            14 => .session_tombstone,
            15 => .history,
            16 => .webhook_store,
            17 => .handoff_manifest,
            else => error.UnknownKind,
        };
    }

    /// Whether a capsule of this kind carries raw cryptographic key material in
    /// its field payloads, so `Capsule.deinit` secure-zeroes the owned bytes
    /// before freeing them. Key material sealed into the successor's memfd arena
    /// (TLS 1.3/1.2 traffic secrets, the Mooring directional record keys, and the
    /// STEK ticket keys) must never linger in freed heap across a USR2 — the
    /// arena lives only in memory, but a freed-then-reused allocation could leak
    /// it to unrelated state. The switch is exhaustive so a new secret-bearing
    /// kind is a compile error until this decision is made for it.
    pub fn carriesSecrets(kind: CapsuleKind) bool {
        return switch (kind) {
            .tls_session, .mooring_ratchet, .s2s_link, .tls_ticket_keys => true,
            .clients,
            .channels,
            .sessions,
            .mesh_checkpoint,
            .send_queue,
            .ws_session,
            .pending_migration,
            .monitor_list,
            .silence_list,
            .session_tombstone,
            .history,
            .webhook_store,
            .handoff_manifest,
            => false,
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
    // v4 (2026-07) appends a trailing [u64 umode_bits][u32 ilen][pending_in]
    // [u32 olen][pending_out] block so client-set umodes, the partial inbound
    // line, and a plaintext connection's unsent SendQ tail all survive the
    // swap (previously silently reset/dropped). v5 appends the canonical
    // `was_websocket` byte. This is now an exact manifest contract: a successor
    // must understand every current transport/join field, so legacy ranges do
    // not overlap and the predecessor cold-refuses instead of degrading state.
    .{ .kind = .clients, .schema_id = 0x4843_4c54, .current_version = 5, .min_supported = 5, .max_supported = 5 },
    // v2 is the first exact World image: every channel field plus nick-keyed
    // member/invite expectations. v1 silently omitted material channel state,
    // so there is intentionally no overlap and rollback is a cold restart.
    .{ .kind = .channels, .schema_id = 0x4843_484e, .current_version = 2, .min_supported = 2, .max_supported = 2 },
    // v2 (2026-07): each session record appends the attached connection's join
    // fd (i32) and the detached restore snapshot (u32 len + bytes), so bouncer
    // sessions restore byte-identically across USR2 instead of degrading to a
    // bare reclaim token. `min_supported = 1` keeps accepting v1 capsules sealed
    // by pre-bump binaries; `session_capsule.decode` is version-aware.
    // v3 (2026-07): appends the portable-resume issuance bit so the successor
    // preserves detach-time mesh replication policy. Legacy v1/v2 decode false.
    // v4 appends each row's optional exact 16-byte stable attachment id so
    // resumed siblings retain their physical identity across an upgrade.
    // Legacy v1-v3 decode it as null.
    .{ .kind = .sessions, .schema_id = 0x4853_4553, .current_version = 4, .min_supported = 1, .max_supported = 4 },
    // v2 (2026-07): `tls_snapshot.encode` gained two trailing kTLS-offload flag
    // bytes (tx/rx) — but the encoder was widened WITHOUT bumping this version, so
    // a pre-bump predecessor seals the flag-bearing blob while STILL stamping
    // `version = 1`. Two layouts (genuine pre-kTLS = no flags, and pre-bump = with
    // flags) therefore share version 1, distinguishable only by length. v2 ends
    // that ambiguity: from here the flags are mandatory. `min_supported = 1` keeps
    // adopting both historical v1 shapes (a pre-bump predecessor's next USR2 into
    // this binary must not netsplit); `tls_snapshot.decode` is version-aware (the
    // v1 arm tolerates the flags being absent OR present, v2 requires them).
    .{ .kind = .tls_session, .schema_id = 0x4854_4c53, .current_version = 2, .min_supported = 1, .max_supported = 2 },
    .{ .kind = .mooring_ratchet, .schema_id = 0x4856_4549, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // v2 (2026-07) introduces exact property-state checkpoints. Ordinary
    // magic-discriminated mesh payloads retain the full 1..2 range so a v1
    // successor can still consume/skip them. A state piece whose loss would be
    // unsafe overrides its individual header to min_supported=2, yielding a
    // 2..2 range that an older successor must reject instead of silently
    // adopting a partial arena.
    .{ .kind = .mesh_checkpoint, .schema_id = 0x484d_4553, .current_version = 2, .min_supported = 1, .max_supported = 2 },
    .{ .kind = .send_queue, .schema_id = 0x4853_4551, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // v2 (2026-07): `Established.serialize` gained a trailing `admitted_frame_families`
    // (u32), growing the embedded blob by 4 bytes. v3 appends the `caps_ext` byte.
    // v4 (2026-07): appends the trailing converged remote-member roster block
    // ([u32 count][u32 len][records]) so the successor primes its route table
    // BEFORE the RESYNC — without it the peer's re-burst re-announced every
    // surviving remote member to local clients as a spurious JOIN on every
    // upgrade. `min_supported = 1` keeps accepting capsules sealed by pre-bump
    // binaries; `s2s_snapshot.decode` is version-aware.
    .{ .kind = .s2s_link, .schema_id = 0x4832_534c, .current_version = 4, .min_supported = 1, .max_supported = 4 },
    // v2 (2026-07) appended the WS adapter's partial framing state so a
    // mid-frame wss client is carried instead of dropped. v3 appends the
    // selected WebSocket application protocol, which controls
    // whether binary Cadence datagrams are admissible. Current Helix adoption is
    // exact-only so this security boundary can never silently downgrade to the
    // legacy no-subprotocol behavior. v1/v2 remain available only through the
    // explicit version-aware cold decoder in `ws_snapshot`.
    .{ .kind = .ws_session, .schema_id = 0x4857_5353, .current_version = 3, .min_supported = 3, .max_supported = 3 },
    .{ .kind = .tls_ticket_keys, .schema_id = 0x4854_4b59, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // v1 carried one staged migration per capsule and necessarily lost ordering,
    // lease, and consumed-token metadata. v2 carries one integrity-checked PMST
    // checkpoint for the complete PendingMigrations store, so adoption is atomic
    // and a corrupt/incomplete successor state cannot open a replay window.
    .{ .kind = .pending_migration, .schema_id = 0x4850_4d47, .current_version = 2, .min_supported = 1, .max_supported = 2 },
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
    // Consumed migration-token tombstones carried across USR2 so a delayed peer
    // offer cannot resurrect a session immediately after the swap.
    .{ .kind = .session_tombstone, .schema_id = 0x4853_544d, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // Exact-only whole-store checkpoints. Partial or per-row adoption would
    // lose history cursors or webhook delivery ownership across an exec.
    .{ .kind = .history, .schema_id = 0x4848_4953, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    .{ .kind = .webhook_store, .schema_id = 0x4857_484b, .current_version = 1, .min_supported = 1, .max_supported = 1 },
    // Canonical final capsule committing to every preceding capsule header,
    // field, byte, order, total count, and per-kind count in the arena.
    .{ .kind = .handoff_manifest, .schema_id = 0x4848_4d46, .current_version = 1, .min_supported = 1, .max_supported = 1 },
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
        // Secure-zero key-material payloads before freeing so no TLS/Mooring/
        // ticket-key bytes survive in a reused allocation. Owned (duped) field
        // bytes are the only thing deinit frees, so wiping them is in-bounds.
        wipeSecretPayloads(self.header.kind, self.fields);
        for (self.fields) |field| allocator.free(field.bytes);
        allocator.free(self.fields);
        self.* = .{ .header = Header.init(.clients), .fields = &.{} };
    }
};

pub fn make(kind: CapsuleKind, fields: []Field) Capsule {
    return .{ .header = Header.init(kind), .fields = fields };
}

/// Secure-zero the payload bytes of `fields` iff `kind` carries key material
/// (see `CapsuleKind.carriesSecrets`). Split out of `Capsule.deinit` so the wipe
/// is directly testable: `Allocator.free` overwrites freed memory with the
/// `undefined` poison in safe builds, which would mask a post-free read of the
/// wiped region — so the wipe must be observed BEFORE the free, on caller memory.
pub fn wipeSecretPayloads(kind: CapsuleKind, fields: []const Field) void {
    if (!kind.carriesSecrets()) return;
    for (fields) |field| std.crypto.secureZero(u8, @constCast(field.bytes));
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
    // M8: this generic container decoder is DELIBERATELY forward-tolerant — it
    // accepts a stamped `version` ABOVE this binary's `max_supported` (negotiate
    // only requires range OVERLAP, and clamps the RESULT). That evolvability is
    // relied upon and tested (server.zig "generic decoder intentionally accepts
    // these evolvable shapes"; helix/s2s_adopt_dst "the capsule layer
    // forward-accepts v3"). The fail-closed guarantee against a too-new version
    // is NOT left implicit: it is enforced ABOVE this layer, exhaustively, by
    //   (a) every per-family adoption selector / handoff_relations helper, which
    //       pins the version exactly (`.clients`/`.channels`/checkpoints) or
    //       requires `negotiate(...) == header.version` (the rolling `.s2s_link`/
    //       `.tls_session`/`.sessions` families) — a too-new header
    //       fails that equality and is rejected before any DATA decoder runs; and
    //   (b) every per-kind DATA decoder's explicit `else => UnsupportedVersion`.
    // So a too-new capsule NEVER reaches a progressive `if (version >= N)` arm.
    // Rejecting it here instead would abort the whole stream on a single
    // forward-versioned sidecar, breaking that intentional graceful degradation.
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

test "exact clients world history webhook and handoff descriptors fail closed" {
    const clients = descriptor(.clients);
    try std.testing.expectEqual(@as(u16, 5), clients.current_version);
    try std.testing.expectEqual(@as(u16, 5), clients.min_supported);
    try std.testing.expectEqual(@as(u16, 5), clients.max_supported);
    var legacy_clients = clients;
    legacy_clients.current_version = 4;
    legacy_clients.min_supported = 1;
    legacy_clients.max_supported = 4;
    try std.testing.expectError(
        error.VersionUnsupported,
        negotiate(legacy_clients, Header.init(.clients)),
    );

    const channels = descriptor(.channels);
    try std.testing.expectEqual(@as(u16, 2), channels.current_version);
    try std.testing.expectEqual(@as(u16, 2), channels.min_supported);
    try std.testing.expectEqual(@as(u16, 2), channels.max_supported);
    var legacy_channels = channels;
    legacy_channels.current_version = 1;
    legacy_channels.min_supported = 1;
    legacy_channels.max_supported = 1;
    try std.testing.expectError(
        error.VersionUnsupported,
        negotiate(legacy_channels, Header.init(.channels)),
    );

    inline for (.{ CapsuleKind.history, CapsuleKind.webhook_store, CapsuleKind.handoff_manifest }) |kind| {
        const exact = descriptor(kind);
        try std.testing.expectEqual(@as(u16, 1), exact.current_version);
        try std.testing.expectEqual(@as(u16, 1), exact.min_supported);
        try std.testing.expectEqual(@as(u16, 1), exact.max_supported);
        try std.testing.expectEqual(kind, try CapsuleKind.fromByte(@intFromEnum(kind)));
    }
}

test "mesh checkpoint v2 keeps ordinary pieces compatible and exact pieces fail closed" {
    const current = descriptor(.mesh_checkpoint);
    try std.testing.expectEqual(@as(u16, 2), current.current_version);
    try std.testing.expectEqual(@as(u16, 1), current.min_supported);
    try std.testing.expectEqual(@as(u16, 2), current.max_supported);

    // An ordinary v2 mesh payload advertises overlap with both generations.
    const ordinary = Header.init(.mesh_checkpoint);
    try std.testing.expectEqual(@as(u16, 2), ordinary.version);
    try std.testing.expectEqual(@as(u16, 1), ordinary.min_supported);
    try std.testing.expectEqual(@as(u16, 2), ordinary.max_supported);
    var legacy = current;
    legacy.current_version = 1;
    legacy.min_supported = 1;
    legacy.max_supported = 1;
    try std.testing.expectEqual(@as(u16, 1), try negotiate(legacy, ordinary));

    // A legacy v1 predecessor remains consumable by the current successor.
    var legacy_header = ordinary;
    legacy_header.version = 1;
    legacy_header.min_supported = 1;
    legacy_header.max_supported = 1;
    try std.testing.expectEqual(@as(u16, 1), try negotiate(current, legacy_header));

    // Exact property state raises only its own minimum. The current successor
    // accepts it, while a v1 rollback has no overlap and must refuse it.
    var exact = ordinary;
    exact.min_supported = 2;
    try std.testing.expectEqual(@as(u16, 2), try negotiate(current, exact));
    try std.testing.expectError(error.VersionUnsupported, negotiate(legacy, exact));

    var field = [_]Field{.{ .ordinal = 1, .bytes = "property-state" }};
    const exact_capsule = Capsule{ .header = exact, .fields = field[0..] };
    try validate(exact_capsule);
    try std.testing.expectEqual(@as(u32, 1), exact_capsule.fields[0].ordinal);
}

test "tls_session is a rolling v1..2 descriptor that accepts a pre-bump v1 capsule" {
    const d = descriptor(.tls_session);
    try std.testing.expectEqual(@as(u16, 2), d.current_version);
    try std.testing.expectEqual(@as(u16, 1), d.min_supported);
    try std.testing.expectEqual(@as(u16, 2), d.max_supported);
    // A pre-bump predecessor sealed the flag-bearing blob while stamping v1; it
    // must still negotiate against this binary (its next USR2 must not netsplit).
    var legacy = Header.init(.tls_session);
    legacy.version = 1;
    legacy.min_supported = 1;
    legacy.max_supported = 1;
    try std.testing.expectEqual(@as(u16, 1), try negotiate(d, legacy));
}

test "sessions is a rolling v1 through v4 descriptor" {
    const d = descriptor(.sessions);
    try std.testing.expectEqual(@as(u16, 4), d.current_version);
    try std.testing.expectEqual(@as(u16, 1), d.min_supported);
    try std.testing.expectEqual(@as(u16, 4), d.max_supported);

    for (1..4) |legacy_version| {
        var legacy = Header.init(.sessions);
        legacy.version = @intCast(legacy_version);
        legacy.min_supported = @intCast(legacy_version);
        legacy.max_supported = @intCast(legacy_version);
        try std.testing.expectEqual(
            @as(u16, @intCast(legacy_version)),
            try negotiate(d, legacy),
        );
    }
}

test "validate is forward-tolerant of a too-new version (rejection is above this layer)" {
    // M8: the generic container decoder deliberately ACCEPTS a stamped version
    // above the local max (evolvability). A too-new capsule is rejected above
    // this layer by the per-family selectors + per-kind decoders, never here.
    var too_new = Header.init(.tls_ticket_keys); // exact 1..1 descriptor locally
    too_new.version = 9;
    too_new.min_supported = 1;
    too_new.max_supported = 9;
    var field = [_]Field{.{ .ordinal = 1, .bytes = "x" }};
    try validate(Capsule{ .header = too_new, .fields = field[0..] });
    // A negotiated overlap still exists (the forward-tolerance contract): the
    // clamped result is the local max, never the too-new stamped value.
    try std.testing.expectEqual(@as(u16, 1), try negotiate(descriptor(.tls_ticket_keys), too_new));
}

test "wipeSecretPayloads zeroes secret-bearing payloads and leaves plain ones" {
    try std.testing.expect(CapsuleKind.tls_session.carriesSecrets());
    try std.testing.expect(CapsuleKind.s2s_link.carriesSecrets());
    try std.testing.expect(CapsuleKind.mooring_ratchet.carriesSecrets());
    try std.testing.expect(CapsuleKind.tls_ticket_keys.carriesSecrets());
    try std.testing.expect(!CapsuleKind.clients.carriesSecrets());
    try std.testing.expect(!CapsuleKind.channels.carriesSecrets());
    try std.testing.expect(!CapsuleKind.ws_session.carriesSecrets());

    // Wipe proof on caller-owned STACK buffers (no free ⇒ no `undefined` poison
    // to mask the result). `deinit` calls `wipeSecretPayloads` on the same owned
    // field bytes just before freeing them, so this exercises the real wipe path.
    var secret_buf = "traffic-secret-material".*;
    var plain_buf = "world-checkpoint-state".*;
    var secret_field = [_]Field{.{ .ordinal = 1, .bytes = &secret_buf }};
    var plain_field = [_]Field{.{ .ordinal = 1, .bytes = &plain_buf }};

    wipeSecretPayloads(.tls_session, &secret_field); // secret-bearing → wiped
    wipeSecretPayloads(.clients, &plain_field); // plain → untouched

    for (secret_buf) |b| try std.testing.expectEqual(@as(u8, 0), b);
    try std.testing.expectEqualStrings("world-checkpoint-state", &plain_buf);
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
