// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! SDP-lite media band descriptors for Onyx Server media negotiation.
//!
//! This is not RFC SDP. It is a compact canonical descriptor with fixed field
//! order, length-prefixed fields, and unsigned LEB128 varints for scalar values.
const std = @import("std");

const magic = "MZ-SDPLITE-1";
const min_band_id: u8 = 64;

pub const Error = error{
    BadMagic,
    BandMismatch,
    InvalidBand,
    InvalidFieldLength,
    KindMismatch,
    LengthOverflow,
    NoCommonCodec,
    NonCanonicalVarint,
    TrailingBytes,
    Truncated,
    UnknownCodec,
    UnknownDirection,
    UnknownFecScheme,
    UnknownKind,
    VarintOverflow,
};

pub const MediaKind = enum(u8) {
    audio = 1,
    video = 2,

    fn fromInt(value: u64) Error!MediaKind {
        return switch (value) {
            @backingInt(MediaKind.audio) => .audio,
            @backingInt(MediaKind.video) => .video,
            else => error.UnknownKind,
        };
    }
};

pub const CodecTag = enum(u8) {
    cadencevox = 1,
    cadencevis = 2,
    raw = 3,
    opus = 4,
    vp8 = 5,

    fn fromInt(value: u64) Error!CodecTag {
        return switch (value) {
            @backingInt(CodecTag.cadencevox) => .cadencevox,
            @backingInt(CodecTag.cadencevis) => .cadencevis,
            @backingInt(CodecTag.raw) => .raw,
            @backingInt(CodecTag.opus) => .opus,
            @backingInt(CodecTag.vp8) => .vp8,
            else => error.UnknownCodec,
        };
    }

    pub fn name(self: CodecTag) []const u8 {
        return @tagName(self);
    }

    pub fn fromName(value: []const u8) Error!CodecTag {
        if (std.ascii.eqlIgnoreCase(value, "cadencevox")) return .cadencevox;
        if (std.ascii.eqlIgnoreCase(value, "cadencevis")) return .cadencevis;
        if (std.ascii.eqlIgnoreCase(value, "raw")) return .raw;
        if (std.ascii.eqlIgnoreCase(value, "opus")) return .opus;
        if (std.ascii.eqlIgnoreCase(value, "vp8")) return .vp8;
        return error.UnknownCodec;
    }

    /// Standard RTP payload type for gateway codecs, when one is assigned.
    /// Opus uses 111 and VP8 uses 96 (dynamic range, WebRTC convention);
    /// native cadence/raw codecs have no RTP payload type.
    pub fn payloadType(self: CodecTag) ?u7 {
        return switch (self) {
            .opus => 111,
            .vp8 => 96,
            .cadencevox, .cadencevis, .raw => null,
        };
    }

    pub fn fromPayloadType(pt: u7) ?CodecTag {
        return switch (pt) {
            111 => .opus,
            96 => .vp8,
            else => null,
        };
    }

    pub fn mediaKind(self: CodecTag) ?MediaKind {
        return switch (self) {
            .cadencevox, .opus => .audio,
            .cadencevis, .vp8 => .video,
            .raw => null,
        };
    }
};

pub const FecScheme = enum(u8) {
    none = 0,
    rateless_lt = 1,
    rs_block = 2,

    fn fromInt(value: u64) Error!FecScheme {
        return switch (value) {
            @backingInt(FecScheme.none) => .none,
            @backingInt(FecScheme.rateless_lt) => .rateless_lt,
            @backingInt(FecScheme.rs_block) => .rs_block,
            else => error.UnknownFecScheme,
        };
    }
};

pub const Direction = enum(u8) {
    sendrecv = 0,
    sendonly = 1,
    recvonly = 2,
    inactive = 3,

    fn fromInt(value: u64) Error!Direction {
        return switch (value) {
            @backingInt(Direction.sendrecv) => .sendrecv,
            @backingInt(Direction.sendonly) => .sendonly,
            @backingInt(Direction.recvonly) => .recvonly,
            @backingInt(Direction.inactive) => .inactive,
            else => error.UnknownDirection,
        };
    }
};

pub const Codec = struct {
    tag: CodecTag,
    clock_rate: u32,
    params: u32,
};

pub const Fec = struct {
    scheme: FecScheme,
    redundancy: u8,
};

pub const MediaDescription = struct {
    band_id: u8,
    kind: MediaKind,
    codecs: []const Codec,
    fec: Fec,
    direction: Direction,

    pub fn deinit(self: *MediaDescription, allocator: std.mem.Allocator) void {
        allocator.free(self.codecs);
        self.codecs = &.{};
    }
};

pub fn encode(allocator: std.mem.Allocator, desc: MediaDescription) ![]u8 {
    try validate(desc);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, magic);
    try appendVarintField(allocator, &out, desc.band_id);
    try appendVarintField(allocator, &out, @backingInt(desc.kind));
    try appendCodecsField(allocator, &out, desc.codecs);
    try appendFecField(allocator, &out, desc.fec);
    try appendVarintField(allocator, &out, @backingInt(desc.direction));

    return try out.toOwnedSlice(allocator);
}

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !MediaDescription {
    var cursor = Cursor{ .input = bytes };
    if (!std.mem.eql(u8, try cursor.take(magic.len), magic)) return error.BadMagic;

    const band_id = try readBandId(try cursor.readField());
    const kind = try MediaKind.fromInt(try readVarintField(try cursor.readField()));
    const codecs = try readCodecsField(allocator, try cursor.readField());
    errdefer allocator.free(codecs);
    const fec = try readFecField(try cursor.readField());
    const direction = try Direction.fromInt(try readVarintField(try cursor.readField()));
    if (!cursor.done()) return error.TrailingBytes;

    return .{
        .band_id = band_id,
        .kind = kind,
        .codecs = codecs,
        .fec = fec,
        .direction = direction,
    };
}

pub fn offerAnswer(
    allocator: std.mem.Allocator,
    local_offer: MediaDescription,
    remote_offer: MediaDescription,
) !MediaDescription {
    try validate(local_offer);
    try validate(remote_offer);
    if (local_offer.band_id != remote_offer.band_id) return error.BandMismatch;

    var selected: std.ArrayList(Codec) = .empty;
    errdefer selected.deinit(allocator);

    for (local_offer.codecs) |codec| {
        if (!hasCodecTag(remote_offer.codecs, codec.tag)) continue;
        if (hasCodecTag(selected.items, codec.tag)) continue;
        try selected.append(allocator, codec);
    }
    if (selected.items.len == 0) return error.NoCommonCodec;
    if (local_offer.kind != remote_offer.kind) return error.KindMismatch;

    return .{
        .band_id = local_offer.band_id,
        .kind = local_offer.kind,
        .codecs = try selected.toOwnedSlice(allocator),
        .fec = chooseFec(local_offer.fec, remote_offer.fec),
        .direction = reconcileDirection(local_offer.direction, remote_offer.direction),
    };
}

fn validate(desc: MediaDescription) Error!void {
    if (desc.band_id < min_band_id) return error.InvalidBand;
}

fn chooseFec(local: Fec, remote: Fec) Fec {
    if (local.scheme == .none or remote.scheme == .none) return .{ .scheme = .none, .redundancy = 0 };
    if (local.scheme != remote.scheme) return .{ .scheme = .none, .redundancy = 0 };
    return .{
        .scheme = local.scheme,
        .redundancy = @min(local.redundancy, remote.redundancy),
    };
}

fn reconcileDirection(offer: Direction, answer: Direction) Direction {
    const offer_sends = canSend(offer);
    const offer_receives = canReceive(offer);
    const answer_sends = canSend(answer);
    const answer_receives = canReceive(answer);

    const negotiated_send = offer_sends and answer_receives;
    const negotiated_receive = answer_sends and offer_receives;

    if (negotiated_send and negotiated_receive) return .sendrecv;
    if (negotiated_send) return .sendonly;
    if (negotiated_receive) return .recvonly;
    return .inactive;
}

fn canSend(direction: Direction) bool {
    return direction == .sendrecv or direction == .sendonly;
}

fn canReceive(direction: Direction) bool {
    return direction == .sendrecv or direction == .recvonly;
}

fn hasCodecTag(codecs: []const Codec, tag: CodecTag) bool {
    for (codecs) |codec| {
        if (codec.tag == tag) return true;
    }
    return false;
}

fn appendCodecsField(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    codecs: []const Codec,
) !void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);

    try appendVarint(allocator, &payload, codecs.len);
    for (codecs) |codec| {
        try appendVarintField(allocator, &payload, @backingInt(codec.tag));
        try appendVarintField(allocator, &payload, codec.clock_rate);
        try appendVarintField(allocator, &payload, codec.params);
    }

    try appendField(allocator, out, payload.items);
}

fn appendFecField(allocator: std.mem.Allocator, out: *std.ArrayList(u8), fec: Fec) !void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);

    try appendVarintField(allocator, &payload, @backingInt(fec.scheme));
    try appendVarintField(allocator, &payload, fec.redundancy);
    try appendField(allocator, out, payload.items);
}

fn appendVarintField(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: u64) !void {
    var buf: [10]u8 = undefined;
    const encoded = writeVarint(&buf, value);
    try appendField(allocator, out, encoded);
}

fn appendField(allocator: std.mem.Allocator, out: *std.ArrayList(u8), payload: []const u8) !void {
    try appendVarint(allocator, out, payload.len);
    try out.appendSlice(allocator, payload);
}

fn appendVarint(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: u64) !void {
    var buf: [10]u8 = undefined;
    try out.appendSlice(allocator, writeVarint(&buf, value));
}

fn writeVarint(buf: *[10]u8, value: u64) []const u8 {
    var n = value;
    var i: usize = 0;
    while (true) {
        var byte: u8 = @intCast(n & 0x7f);
        n >>= 7;
        if (n != 0) byte |= 0x80;
        buf[i] = byte;
        i += 1;
        if (n == 0) return buf[0..i];
    }
}

fn readBandId(bytes: []const u8) !u8 {
    const band = try readVarintField(bytes);
    if (band > std.math.maxInt(u8)) return error.InvalidBand;
    const band_id: u8 = @intCast(band);
    if (band_id < min_band_id) return error.InvalidBand;
    return band_id;
}

fn readCodecsField(allocator: std.mem.Allocator, bytes: []const u8) ![]Codec {
    var cursor = Cursor{ .input = bytes };
    const count = try cursor.readLen();
    var codecs: std.ArrayList(Codec) = .empty;
    errdefer codecs.deinit(allocator);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        try codecs.append(allocator, .{
            .tag = try CodecTag.fromInt(try readVarintField(try cursor.readField())),
            .clock_rate = try readU32Field(try cursor.readField()),
            .params = try readU32Field(try cursor.readField()),
        });
    }
    if (!cursor.done()) return error.TrailingBytes;
    return try codecs.toOwnedSlice(allocator);
}

fn readFecField(bytes: []const u8) !Fec {
    var cursor = Cursor{ .input = bytes };
    const fec = Fec{
        .scheme = try FecScheme.fromInt(try readVarintField(try cursor.readField())),
        .redundancy = try readU8Field(try cursor.readField()),
    };
    if (!cursor.done()) return error.TrailingBytes;
    return fec;
}

fn readU32Field(bytes: []const u8) !u32 {
    const value = try readVarintField(bytes);
    if (value > std.math.maxInt(u32)) return error.InvalidFieldLength;
    return @intCast(value);
}

fn readU8Field(bytes: []const u8) !u8 {
    const value = try readVarintField(bytes);
    if (value > std.math.maxInt(u8)) return error.InvalidFieldLength;
    return @intCast(value);
}

fn readVarintField(bytes: []const u8) !u64 {
    var cursor = Cursor{ .input = bytes };
    const value = try cursor.readVarint();
    if (!cursor.done()) return error.TrailingBytes;
    return value;
}

const Cursor = struct {
    input: []const u8,
    pos: usize = 0,

    fn done(self: Cursor) bool {
        return self.pos == self.input.len;
    }

    fn take(self: *Cursor, n: usize) Error![]const u8 {
        if (n > self.input.len - self.pos) return error.Truncated;
        defer self.pos += n;
        return self.input[self.pos..][0..n];
    }

    fn readByte(self: *Cursor) Error!u8 {
        return (try self.take(1))[0];
    }

    fn readField(self: *Cursor) Error![]const u8 {
        const len = try self.readLen();
        return try self.take(len);
    }

    fn readLen(self: *Cursor) Error!usize {
        const value = try self.readVarint();
        if (value > std.math.maxInt(usize)) return error.LengthOverflow;
        return @intCast(value);
    }

    fn readVarint(self: *Cursor) Error!u64 {
        const start = self.pos;
        var value: u64 = 0;
        var shift: u6 = 0;

        while (true) {
            const byte = try self.readByte();
            const low: u64 = byte & 0x7f;
            value |= low << shift;

            if ((byte & 0x80) == 0) {
                const used = self.pos - start;
                if (used != varintLen(value)) return error.NonCanonicalVarint;
                return value;
            }
            if (shift == 63) return error.VarintOverflow;
            shift += 7;
        }
    }
};

fn varintLen(value: u64) usize {
    var n = value;
    var len: usize = 1;
    while (n >= 0x80) : (len += 1) {
        n >>= 7;
    }
    return len;
}

const testing = std.testing;

test "descriptor encode/decode round-trip" {
    const allocator = testing.allocator;
    const codecs = [_]Codec{
        .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 },
        .{ .tag = .raw, .clock_rate = 48_000, .params = 1 },
    };
    const desc = MediaDescription{
        .band_id = 64,
        .kind = .audio,
        .codecs = &codecs,
        .fec = .{ .scheme = .rateless_lt, .redundancy = 12 },
        .direction = .sendrecv,
    };

    const bytes = try encode(allocator, desc);
    defer allocator.free(bytes);

    var decoded = try decode(allocator, bytes);
    defer decoded.deinit(allocator);

    try testing.expectEqual(desc.band_id, decoded.band_id);
    try testing.expectEqual(desc.kind, decoded.kind);
    try testing.expectEqual(desc.fec.scheme, decoded.fec.scheme);
    try testing.expectEqual(desc.fec.redundancy, decoded.fec.redundancy);
    try testing.expectEqual(desc.direction, decoded.direction);
    try testing.expectEqualSlices(Codec, desc.codecs, decoded.codecs);
}

test "offer/answer intersects codecs in offerer order and picks common FEC" {
    const allocator = testing.allocator;
    const offer_codecs = [_]Codec{
        .{ .tag = .cadencevis, .clock_rate = 90_000, .params = 1 },
        .{ .tag = .raw, .clock_rate = 48_000, .params = 2 },
        .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 },
    };
    const answer_codecs = [_]Codec{
        .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 1 },
        .{ .tag = .cadencevis, .clock_rate = 90_000, .params = 3 },
    };
    const offer = MediaDescription{
        .band_id = 72,
        .kind = .video,
        .codecs = &offer_codecs,
        .fec = .{ .scheme = .rateless_lt, .redundancy = 20 },
        .direction = .sendrecv,
    };
    const answer = MediaDescription{
        .band_id = 72,
        .kind = .video,
        .codecs = &answer_codecs,
        .fec = .{ .scheme = .rateless_lt, .redundancy = 8 },
        .direction = .sendrecv,
    };

    var negotiated = try offerAnswer(allocator, offer, answer);
    defer negotiated.deinit(allocator);

    try testing.expectEqual(@as(usize, 2), negotiated.codecs.len);
    try testing.expectEqual(CodecTag.cadencevis, negotiated.codecs[0].tag);
    try testing.expectEqual(CodecTag.cadencevox, negotiated.codecs[1].tag);
    try testing.expectEqual(FecScheme.rateless_lt, negotiated.fec.scheme);
    try testing.expectEqual(@as(u8, 8), negotiated.fec.redundancy);
}

test "direction reconciliation matches sendonly with recvonly" {
    const allocator = testing.allocator;
    const codecs = [_]Codec{.{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 }};
    const offer = MediaDescription{
        .band_id = 80,
        .kind = .audio,
        .codecs = &codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendonly,
    };
    const answer = MediaDescription{
        .band_id = 80,
        .kind = .audio,
        .codecs = &codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .recvonly,
    };

    var negotiated = try offerAnswer(allocator, offer, answer);
    defer negotiated.deinit(allocator);

    try testing.expectEqual(Direction.sendonly, negotiated.direction);
}

test "offer/answer rejects no common codec" {
    const allocator = testing.allocator;
    const offer_codecs = [_]Codec{.{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 }};
    const answer_codecs = [_]Codec{.{ .tag = .cadencevis, .clock_rate = 90_000, .params = 1 }};
    const offer = MediaDescription{
        .band_id = 90,
        .kind = .video,
        .codecs = &offer_codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };
    const answer = MediaDescription{
        .band_id = 90,
        .kind = .video,
        .codecs = &answer_codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };

    try testing.expectError(error.NoCommonCodec, offerAnswer(allocator, offer, answer));
}

test "band below 64 rejected by encoder and decoder" {
    const allocator = testing.allocator;
    const codecs = [_]Codec{.{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 }};
    const desc = MediaDescription{
        .band_id = 63,
        .kind = .audio,
        .codecs = &codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };

    try testing.expectError(error.InvalidBand, encode(allocator, desc));

    var valid = try encode(allocator, .{
        .band_id = 64,
        .kind = .audio,
        .codecs = &codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    });
    defer allocator.free(valid);

    valid[magic.len + 1] = 63;
    try testing.expectError(error.InvalidBand, decode(allocator, valid));
}

test "truncated descriptor returns truncation error" {
    const allocator = testing.allocator;
    const codecs = [_]Codec{.{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 }};
    const desc = MediaDescription{
        .band_id = 100,
        .kind = .audio,
        .codecs = &codecs,
        .fec = .{ .scheme = .rs_block, .redundancy = 4 },
        .direction = .recvonly,
    };

    const bytes = try encode(allocator, desc);
    defer allocator.free(bytes);

    try testing.expectError(error.Truncated, decode(allocator, bytes[0 .. bytes.len - 1]));
}

test "offer opus-only vs vp8-only has no common codec" {
    const allocator = testing.allocator;
    const offer_codecs = [_]Codec{.{ .tag = .opus, .clock_rate = 48_000, .params = 2 }};
    const answer_codecs = [_]Codec{.{ .tag = .vp8, .clock_rate = 90_000, .params = 0 }};
    const offer = MediaDescription{
        .band_id = 91,
        .kind = .audio,
        .codecs = &offer_codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };
    const answer = MediaDescription{
        .band_id = 91,
        .kind = .video,
        .codecs = &answer_codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };
    try testing.expectError(error.NoCommonCodec, offerAnswer(allocator, offer, answer));
}

test "offer opus intersection succeeds with standard payload type" {
    const allocator = testing.allocator;
    const offer_codecs = [_]Codec{
        .{ .tag = .opus, .clock_rate = 48_000, .params = 2 },
        .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 },
    };
    const answer_codecs = [_]Codec{
        .{ .tag = .cadencevox, .clock_rate = 48_000, .params = 2 },
        .{ .tag = .opus, .clock_rate = 48_000, .params = 1 },
    };
    const offer = MediaDescription{
        .band_id = 92,
        .kind = .audio,
        .codecs = &offer_codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };
    const answer = MediaDescription{
        .band_id = 92,
        .kind = .audio,
        .codecs = &answer_codecs,
        .fec = .{ .scheme = .none, .redundancy = 0 },
        .direction = .sendrecv,
    };
    var negotiated = try offerAnswer(allocator, offer, answer);
    defer negotiated.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), negotiated.codecs.len);
    try testing.expectEqual(CodecTag.opus, negotiated.codecs[0].tag);
    try testing.expectEqual(@as(?u7, 111), negotiated.codecs[0].tag.payloadType());
    try testing.expectEqual(@as(?CodecTag, .opus), CodecTag.fromPayloadType(111));
    try testing.expectEqual(@as(?CodecTag, .vp8), CodecTag.fromPayloadType(96));
    try testing.expectEqual(@as(?u7, 96), CodecTag.vp8.payloadType());
    // Wire round-trip preserves the new tags.
    const bytes = try encode(allocator, negotiated);
    defer allocator.free(bytes);
    var decoded = try decode(allocator, bytes);
    defer decoded.deinit(allocator);
    try testing.expectEqualSlices(Codec, negotiated.codecs, decoded.codecs);
}

test "offer vp8 intersection succeeds" {
    const allocator = testing.allocator;
    const offer_codecs = [_]Codec{.{ .tag = .vp8, .clock_rate = 90_000, .params = 0 }};
    const answer_codecs = [_]Codec{.{ .tag = .vp8, .clock_rate = 90_000, .params = 0 }};
    const offer = MediaDescription{ .band_id = 93, .kind = .video, .codecs = &offer_codecs, .fec = .{ .scheme = .none, .redundancy = 0 }, .direction = .sendrecv };
    const answer = MediaDescription{ .band_id = 93, .kind = .video, .codecs = &answer_codecs, .fec = .{ .scheme = .none, .redundancy = 0 }, .direction = .sendrecv };
    var negotiated = try offerAnswer(allocator, offer, answer);
    defer negotiated.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), negotiated.codecs.len);
    try testing.expectEqual(CodecTag.vp8, negotiated.codecs[0].tag);
}

test "unknown codec string rejected" {
    try testing.expectError(error.UnknownCodec, CodecTag.fromName("h264"));
    try testing.expectError(error.UnknownCodec, CodecTag.fromName(""));
    try testing.expectEqual(CodecTag.opus, try CodecTag.fromName("opus"));
    try testing.expectEqual(CodecTag.vp8, try CodecTag.fromName("VP8"));
    try testing.expectEqual(CodecTag.cadencevox, try CodecTag.fromName("cadencevox"));
    try testing.expectEqualStrings("opus", CodecTag.opus.name());
    try testing.expectEqualStrings("vp8", CodecTag.vp8.name());
}
