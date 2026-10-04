// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact whole-handoff integrity manifest for current-generation Helix arenas.
//!
//! The predecessor commits to every data capsule in its original order. The
//! final manifest records the total capsule count, an exact count for every
//! data-capsule kind, and a domain-separated BLAKE3 digest over each capsule's
//! effective outer header, its canonical field ordinal/length, and its bytes.
//!
//! This module deliberately knows nothing about `capsule.zig`. `live.zig`
//! adapts predecessor `StatePiece`s and successor decoded `Capsule`s into the
//! semantic views below, avoiding an import cycle and keeping verification
//! allocation-free.
//!
//! Wire layout (all integers big-endian):
//!   magic(4) version(u8) piece_count(u32) table_len(u8)
//!   17 * { kind(u8), count(u32) } digest(BLAKE3-256)
//!
//! The digest transcript is: domain, version, then for every ordered piece
//! `{index, schema, kind, version, min, max, ordinal, length, bytes}`, followed
//! by a second domain, total count, and the complete canonical kind-count table.

const std = @import("std");

pub const magic = [_]u8{ 'H', 'H', 'M', '1' };
pub const version: u8 = 2;
pub const field_ordinal: u32 = 1;

/// Exact v2 table. Kind 17 is the manifest and never hashes itself; kind 18
/// is native service state. No live legacy table or unknown kind is accepted.
pub const data_kinds = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18 };
pub const data_kind_count: usize = data_kinds.len;
fn kindIndex(kind: u8) Error!usize {
    for (data_kinds, 0..) |candidate, index| if (candidate == kind) return index;
    return error.InvalidKind;
}

const digest_len = std.crypto.hash.Blake3.digest_length;
const checksum_domain = "onyx:helix:whole-handoff:v2\x00";
const counts_domain = "onyx:helix:whole-handoff:counts:v2\x00";

/// magic + version + piece_count + table_len + (kind + count)*N + digest.
pub const encoded_len: usize = magic.len + 1 + 4 + 1 + data_kind_count * (1 + 4) + digest_len;

pub const Error = error{
    InvalidKind,
    InvalidHeaderRange,
    NonCanonicalOrdinal,
    PieceTooLarge,
    TooManyPieces,
    Truncated,
    BadMagic,
    BadVersion,
    NonCanonicalKindTable,
    TrailingBytes,
    CountMismatch,
    DigestMismatch,
    MissingManifest,
    DuplicateManifest,
    ManifestNotLast,
    WrongManifestHeader,
    NonCanonicalManifest,
    NonCanonicalPiece,
};

pub const HeaderView = struct {
    schema_id: u32,
    kind: u8,
    version: u16,
    min_supported: u16,
    max_supported: u16,
};

pub const PieceView = struct {
    header: HeaderView,
    ordinal: u32 = field_ordinal,
    bytes: []const u8,
};

pub const Manifest = struct {
    piece_count: u32,
    kind_counts: [data_kind_count]u32,
    digest: [digest_len]u8,
};

/// Streaming commitment accumulator. Both update and verification are
/// allocation-free; callers can feed their native piece/capsule collections
/// directly without constructing an intermediate view array.
pub const Accumulator = struct {
    hasher: std.crypto.hash.Blake3,
    piece_count: u32 = 0,
    kind_counts: [data_kind_count]u32 = @splat(0),

    pub fn init() Accumulator {
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(checksum_domain);
        hasher.update(&.{version});
        return .{ .hasher = hasher };
    }

    pub fn add(self: *Accumulator, piece: PieceView) Error!void {
        const header = piece.header;
        const kind_index = try kindIndex(header.kind);
        if (header.min_supported > header.version or header.version > header.max_supported) {
            return error.InvalidHeaderRange;
        }
        if (piece.ordinal != field_ordinal) return error.NonCanonicalOrdinal;
        if (self.piece_count == std.math.maxInt(u32)) return error.TooManyPieces;
        const length = std.math.cast(u64, piece.bytes.len) orelse return error.PieceTooLarge;

        // The index is redundant with stream order, but makes the ordering
        // commitment explicit and keeps future extensions unambiguous.
        hashU32(&self.hasher, self.piece_count);
        hashU32(&self.hasher, header.schema_id);
        self.hasher.update(&.{header.kind});
        hashU16(&self.hasher, header.version);
        hashU16(&self.hasher, header.min_supported);
        hashU16(&self.hasher, header.max_supported);
        hashU32(&self.hasher, piece.ordinal);
        hashU64(&self.hasher, length);
        self.hasher.update(piece.bytes);

        self.piece_count += 1;
        self.kind_counts[kind_index] += 1;
    }

    pub fn snapshot(self: Accumulator) Manifest {
        var hasher = self.hasher;
        hasher.update(counts_domain);
        hashU32(&hasher, self.piece_count);
        hasher.update(&.{@intCast(data_kind_count)});
        for (self.kind_counts, 0..) |count, i| {
            hasher.update(&.{data_kinds[i]});
            hashU32(&hasher, count);
        }
        var digest: [digest_len]u8 = undefined;
        hasher.final(&digest);
        return .{
            .piece_count = self.piece_count,
            .kind_counts = self.kind_counts,
            .digest = digest,
        };
    }

    pub fn encode(self: Accumulator, out: []u8) Error![]const u8 {
        return encodeManifest(self.snapshot(), out);
    }
};

pub fn encodeManifest(manifest: Manifest, out: []u8) Error![]const u8 {
    var count_sum: u64 = 0;
    for (manifest.kind_counts) |count| count_sum += count;
    if (count_sum != manifest.piece_count) return error.CountMismatch;
    if (out.len < encoded_len) return error.Truncated;
    var pos: usize = 0;
    writeBytes(out, &pos, &magic);
    writeByte(out, &pos, version);
    writeU32(out, &pos, manifest.piece_count);
    writeByte(out, &pos, @intCast(data_kind_count));
    for (manifest.kind_counts, 0..) |count, i| {
        writeByte(out, &pos, data_kinds[i]);
        writeU32(out, &pos, count);
    }
    writeBytes(out, &pos, &manifest.digest);
    std.debug.assert(pos == encoded_len);
    return out[0..pos];
}

pub fn decode(bytes: []const u8) Error!Manifest {
    if (bytes.len < encoded_len) return error.Truncated;
    if (bytes.len > encoded_len) return error.TrailingBytes;
    var pos: usize = 0;
    if (!std.mem.eql(u8, readBytes(bytes, &pos, magic.len), &magic)) return error.BadMagic;
    if (readByte(bytes, &pos) != version) return error.BadVersion;

    const piece_count = readU32(bytes, &pos);
    if (readByte(bytes, &pos) != data_kind_count) return error.NonCanonicalKindTable;
    var kind_counts: [data_kind_count]u32 = undefined;
    var count_sum: u64 = 0;
    for (&kind_counts, 0..) |*count, i| {
        if (readByte(bytes, &pos) != data_kinds[i]) return error.NonCanonicalKindTable;
        count.* = readU32(bytes, &pos);
        count_sum += count.*;
    }
    if (count_sum != piece_count) return error.CountMismatch;

    var digest: [digest_len]u8 = undefined;
    @memcpy(&digest, readBytes(bytes, &pos, digest_len));
    std.debug.assert(pos == encoded_len);
    return .{ .piece_count = piece_count, .kind_counts = kind_counts, .digest = digest };
}

pub fn verify(expected_bytes: []const u8, actual: Accumulator) Error!void {
    const expected = try decode(expected_bytes);
    const got = actual.snapshot();
    if (expected.piece_count != got.piece_count or
        !std.mem.eql(u32, &expected.kind_counts, &got.kind_counts))
    {
        return error.CountMismatch;
    }
    if (!std.crypto.timing_safe.eql([digest_len]u8, expected.digest, got.digest)) {
        return error.DigestMismatch;
    }
}

fn hashU16(hasher: *std.crypto.hash.Blake3, value: u16) void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    hasher.update(&buf);
}

fn hashU32(hasher: *std.crypto.hash.Blake3, value: u32) void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    hasher.update(&buf);
}

fn hashU64(hasher: *std.crypto.hash.Blake3, value: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    hasher.update(&buf);
}

fn writeBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.* .. pos.* + bytes.len], bytes);
    pos.* += bytes.len;
}

fn writeByte(out: []u8, pos: *usize, value: u8) void {
    out[pos.*] = value;
    pos.* += 1;
}

fn writeU32(out: []u8, pos: *usize, value: u32) void {
    std.mem.writeInt(u32, out[pos.*..][0..4], value, .big);
    pos.* += 4;
}

fn readBytes(bytes: []const u8, pos: *usize, len: usize) []const u8 {
    const result = bytes[pos.* .. pos.* + len];
    pos.* += len;
    return result;
}

fn readByte(bytes: []const u8, pos: *usize) u8 {
    const result = bytes[pos.*];
    pos.* += 1;
    return result;
}

fn readU32(bytes: []const u8, pos: *usize) u32 {
    const result = std.mem.readInt(u32, bytes[pos.*..][0..4], .big);
    pos.* += 4;
    return result;
}

fn samplePiece(kind: u8, schema_id: u32, bytes: []const u8) PieceView {
    return .{
        .header = .{
            .schema_id = schema_id,
            .kind = kind,
            .version = if (kind == 2) 2 else 1,
            .min_supported = if (kind == 2) 2 else 1,
            .max_supported = if (kind == 2) 2 else 1,
        },
        .bytes = bytes,
    };
}

fn manifestFor(pieces: []const PieceView, out: []u8) ![]const u8 {
    var accumulator = Accumulator.init();
    for (pieces) |item| try accumulator.add(item);
    return accumulator.encode(out);
}

fn verifyPieces(manifest: []const u8, pieces: []const PieceView) !void {
    var accumulator = Accumulator.init();
    for (pieces) |item| try accumulator.add(item);
    return verify(manifest, accumulator);
}

fn expectVerificationFailure(manifest: []const u8, pieces: []const PieceView) !void {
    if (verifyPieces(manifest, pieces)) |_| {
        return error.MutationAccepted;
    } else |_| {}
}

test "empty whole-handoff manifest is canonical and allocation free" {
    var bytes: [encoded_len]u8 = undefined;
    const wire = try manifestFor(&.{}, &bytes);
    try std.testing.expectEqual(@as(usize, encoded_len), wire.len);
    const parsed = try decode(wire);
    try std.testing.expectEqual(@as(u32, 0), parsed.piece_count);
    try std.testing.expectEqual(@as([data_kind_count]u32, @splat(0)), parsed.kind_counts);
    try verifyPieces(wire, &.{});
}

test "mixed ordered pieces commit exact headers bytes count and per-kind counts" {
    const pieces = [_]PieceView{
        samplePiece(1, 0x4843_4c54, "alice"),
        samplePiece(2, 0x4843_484e, "#mesh"),
        samplePiece(1, 0x4843_4c54, "bob"),
        samplePiece(16, 0x4857_484b, "webhooks"),
    };
    var bytes: [encoded_len]u8 = undefined;
    const wire = try manifestFor(&pieces, &bytes);
    const parsed = try decode(wire);
    try std.testing.expectEqual(@as(u32, 4), parsed.piece_count);
    try std.testing.expectEqual(@as(u32, 2), parsed.kind_counts[0]);
    try std.testing.expectEqual(@as(u32, 1), parsed.kind_counts[1]);
    try std.testing.expectEqual(@as(u32, 1), parsed.kind_counts[15]);
    try verifyPieces(wire, &pieces);
}

test "native Helix service carry: whole manifest v2 commits kind18 excludes17 and refuses old schema" {
    const original = [_]PieceView{ samplePiece(1, 0x4843_4c54, "alice"), samplePiece(18, 0x484e_5356, "service") };
    var bytes: [encoded_len]u8 = undefined;
    const wire = try manifestFor(&original, &bytes);
    const parsed = try decode(wire);
    try std.testing.expectEqual(@as(u32, 1), parsed.kind_counts[16]);
    try verifyPieces(wire, &original);
    try std.testing.expectError(error.CountMismatch, verifyPieces(wire, original[0..1]));
    var old_version = bytes;
    old_version[magic.len] = 1;
    try std.testing.expectError(error.BadVersion, decode(&old_version));
    var old_table = bytes;
    old_table[magic.len + 1 + 4 + 1 + 16 * 5] = 17;
    try std.testing.expectError(error.NonCanonicalKindTable, decode(&old_table));
    var accumulator = Accumulator.init();
    try std.testing.expectError(error.InvalidKind, accumulator.add(samplePiece(17, 1, "self")));
    try std.testing.expectError(error.InvalidKind, accumulator.add(samplePiece(19, 1, "unknown")));
}

test "drop duplicate reorder payload bitflip and wrong header all fail closed" {
    const original = [_]PieceView{
        samplePiece(1, 0x4843_4c54, "alice"),
        samplePiece(2, 0x4843_484e, "#mesh"),
        samplePiece(3, 0x4853_4553, "account"),
    };
    var bytes: [encoded_len]u8 = undefined;
    const wire = try manifestFor(&original, &bytes);

    try std.testing.expectError(error.CountMismatch, verifyPieces(wire, original[0..2]));
    const duplicated = [_]PieceView{ original[0], original[1], original[2], original[2] };
    try std.testing.expectError(error.CountMismatch, verifyPieces(wire, &duplicated));
    const reordered = [_]PieceView{ original[1], original[0], original[2] };
    try std.testing.expectError(error.DigestMismatch, verifyPieces(wire, &reordered));

    var flipped_payload = [_]u8{ '#', 'm', 'e', 's', 'h' };
    flipped_payload[2] ^= 1;
    var corrupted = original;
    corrupted[1].bytes = &flipped_payload;
    try std.testing.expectError(error.DigestMismatch, verifyPieces(wire, &corrupted));

    var wrong_header = original;
    wrong_header[1].header.schema_id ^= 1;
    try std.testing.expectError(error.DigestMismatch, verifyPieces(wire, &wrong_header));
    wrong_header = original;
    wrong_header[1].header.min_supported = 1;
    try std.testing.expectError(error.DigestMismatch, verifyPieces(wire, &wrong_header));
}

test "manifest decoder rejects truncation trailing bytes and noncanonical tables" {
    var bytes: [encoded_len]u8 = undefined;
    const wire = try manifestFor(&.{samplePiece(1, 0x4843_4c54, "alice")}, &bytes);
    try std.testing.expectError(error.Truncated, decode(wire[0 .. wire.len - 1]));

    var with_trailing: [encoded_len + 1]u8 = undefined;
    @memcpy(with_trailing[0..encoded_len], wire);
    with_trailing[encoded_len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(&with_trailing));

    var wrong_table = bytes;
    const table_len_offset = magic.len + 1 + 4;
    wrong_table[table_len_offset] -= 1;
    try std.testing.expectError(error.NonCanonicalKindTable, decode(&wrong_table));
    wrong_table = bytes;
    wrong_table[table_len_offset + 1] = 2;
    try std.testing.expectError(error.NonCanonicalKindTable, decode(&wrong_table));
}

test "manifest digest and internally inconsistent counts are rejected" {
    const pieces = [_]PieceView{samplePiece(1, 0x4843_4c54, "alice")};
    var bytes: [encoded_len]u8 = undefined;
    _ = try manifestFor(&pieces, &bytes);

    var corrupt_digest = bytes;
    corrupt_digest[corrupt_digest.len - 1] ^= 1;
    try std.testing.expectError(error.DigestMismatch, verifyPieces(&corrupt_digest, &pieces));

    var bad_count = bytes;
    // First table count immediately follows its kind byte.
    const first_count_offset = magic.len + 1 + 4 + 1 + 1;
    std.mem.writeInt(u32, bad_count[first_count_offset..][0..4], 2, .big);
    try std.testing.expectError(error.CountMismatch, decode(&bad_count));
}

test "accumulator rejects manifest kinds malformed ranges and noncanonical ordinals" {
    var accumulator = Accumulator.init();
    try std.testing.expectError(error.InvalidKind, accumulator.add(samplePiece(17, 1, "manifest")));
    var malformed = samplePiece(1, 1, "x");
    malformed.header.min_supported = 2;
    try std.testing.expectError(error.InvalidHeaderRange, accumulator.add(malformed));
    malformed = samplePiece(1, 1, "x");
    malformed.ordinal = 2;
    try std.testing.expectError(error.NonCanonicalOrdinal, accumulator.add(malformed));
}

test "exhaustive handoff manifest single-mutation campaign fails closed" {
    var payloads: [data_kind_count][2]u8 = undefined;
    var pieces: [data_kind_count]PieceView = undefined;
    for (&pieces, 0..) |*item, i| {
        const kind = data_kinds[i];
        payloads[i] = .{ kind, kind ^ 0xa5 };
        item.* = .{
            .header = .{
                .schema_id = 0x4800_0000 + @as(u32, kind),
                .kind = kind,
                .version = 1,
                .min_supported = 1,
                .max_supported = 1,
            },
            .bytes = &payloads[i],
        };
    }

    var manifest_bytes: [encoded_len]u8 = undefined;
    _ = try manifestFor(&pieces, &manifest_bytes);
    try verifyPieces(&manifest_bytes, &pieces);

    // Every bit in the manifest wire format is authenticated or canonical
    // structure. No single-bit mutation may remain acceptable.
    for (0..manifest_bytes.len) |byte_index| {
        for (0..8) |bit_index| {
            var corrupted = manifest_bytes;
            corrupted[byte_index] ^= @as(u8, 1) << @intCast(bit_index);
            try expectVerificationFailure(&corrupted, &pieces);
        }
    }

    // Every bit of every committed payload is covered by the digest.
    for (0..pieces.len) |piece_index| {
        for (0..payloads[piece_index].len) |byte_index| {
            for (0..8) |bit_index| {
                var corrupted_payload = payloads[piece_index];
                corrupted_payload[byte_index] ^= @as(u8, 1) << @intCast(bit_index);
                var mutated = pieces;
                mutated[piece_index].bytes = &corrupted_payload;
                try expectVerificationFailure(&manifest_bytes, &mutated);
            }
        }
    }

    // Completeness and ordering cover every position, not only one example.
    for (0..pieces.len) |removed_index| {
        var dropped: [data_kind_count - 1]PieceView = undefined;
        var out_index: usize = 0;
        for (pieces, 0..) |item, i| {
            if (i == removed_index) continue;
            dropped[out_index] = item;
            out_index += 1;
        }
        try expectVerificationFailure(&manifest_bytes, &dropped);
    }
    for (0..pieces.len) |duplicated_index| {
        var duplicated: [data_kind_count + 1]PieceView = undefined;
        @memcpy(duplicated[0..pieces.len], &pieces);
        duplicated[pieces.len] = pieces[duplicated_index];
        try expectVerificationFailure(&manifest_bytes, &duplicated);
    }
    for (0..pieces.len - 1) |left| {
        var reordered = pieces;
        std.mem.swap(PieceView, &reordered[left], &reordered[left + 1]);
        try expectVerificationFailure(&manifest_bytes, &reordered);
    }

    // Each effective outer-header component participates in the transcript.
    for (0..pieces.len) |piece_index| {
        var mutated = pieces;
        mutated[piece_index].header.schema_id ^= 1;
        try expectVerificationFailure(&manifest_bytes, &mutated);
        mutated = pieces;
        mutated[piece_index].header.version = 0;
        try expectVerificationFailure(&manifest_bytes, &mutated);
        mutated = pieces;
        mutated[piece_index].header.min_supported = 0;
        try expectVerificationFailure(&manifest_bytes, &mutated);
        mutated = pieces;
        mutated[piece_index].header.max_supported = 2;
        try expectVerificationFailure(&manifest_bytes, &mutated);
    }
}
