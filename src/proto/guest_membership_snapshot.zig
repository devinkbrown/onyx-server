// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proposed signed membership snapshot primitives. No routing admission or wire
//! registration. Decoded wire and payload borrow immutable caller storage.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const presence = @import("mesh_presence_v2.zig");
const channel_name = @import("channel_name.zig");

pub const manifest_domain = "onyx-guest-membership-manifest-v1";
pub const chunk_domain = "onyx-guest-membership-chunk-v1";
pub const manifest_body_len = 147;
pub const manifest_wire_len = 211;
pub const chunk_overhead = 153;
pub const chunk_payload_bytes: u32 = 49152;
pub const payload_bytes = chunk_payload_bytes;
pub const max_channel_len = 256;
pub const ManifestID = [32]u8;
pub const Digest = [32]u8;
pub const Error = error{ Truncated, TrailingBytes, InvalidField, BadVersion, BadSignature, OriginMismatch, UnapprovedOrigin, BadReference, InvalidSet };

pub const Manifest = struct {
    origin: sign.PublicKey,
    guest: presence.GuestId,
    claim_hlc: u64,
    claim_revision: u64,
    routing_class: presence.RoutingClass,
    class_revision: u64,
    membership_revision: u64,
    scope: u8,
    channel_count: u64,
    encoded_bytes: u64,
    chunk_payload_bytes: u32,
    chunk_count: u64,
    set_digest: Digest,
};
pub const Chunk = struct { origin: sign.PublicKey, manifest_id: Digest, index: u64, offset: u64, payload: []const u8 };

pub fn chunkCount(bytes: u64) u64 {
    return bytes / payload_bytes + @intFromBool(bytes % payload_bytes != 0);
}
pub fn validateManifest(m: Manifest) Error!void {
    _ = presence.subject(m.guest) catch return error.InvalidField;
    if (m.claim_hlc == 0 or m.claim_revision == 0 or m.class_revision == 0 or m.membership_revision == 0) return error.InvalidField;
    if (m.scope != 1 or m.chunk_payload_bytes != chunk_payload_bytes) return error.InvalidField;
    if (m.chunk_count != chunkCount(m.encoded_bytes)) return error.InvalidField;
    if ((m.channel_count == 0) != (m.encoded_bytes == 0)) return error.InvalidField;
    if (m.channel_count > m.encoded_bytes / 3) return error.InvalidField;
    const minimum_count = m.encoded_bytes / 258 + @intFromBool(m.encoded_bytes % 258 != 0);
    if (m.channel_count < minimum_count) return error.InvalidField;
    if (m.encoded_bytes == 0 and !std.mem.eql(u8, &m.set_digest, &setDigest(""))) return error.InvalidField;
}
fn digest(domain: []const u8, bytes: []const u8) Digest {
    var h = std.crypto.hash.Blake3.init(.{});
    h.update(domain);
    h.update(&.{0});
    h.update(bytes);
    var out: Digest = undefined;
    h.final(&out);
    return out;
}
pub fn setDigest(bytes: []const u8) Digest {
    return digest("onyx-guest-membership-set-v1", bytes);
}
pub fn manifestId(wire: []const u8) Error!ManifestID {
    _ = try decodeManifest(wire);
    return digest("onyx-guest-membership-id-v1", wire[0..manifest_body_len]);
}
fn approved(origin: sign.PublicKey, allowed: []const sign.PublicKey) bool {
    for (allowed) |key| if (std.mem.eql(u8, &key, &origin)) return true;
    return false;
}
fn verifyWire(wire: []const u8, origin: sign.PublicKey, allowed: []const sign.PublicKey, comptime domain: []const u8) Error!void {
    if (!approved(origin, allowed)) return error.UnapprovedOrigin;
    const end = wire.len - sign.signature_len;
    const sig: sign.Signature = wire[end..][0..sign.signature_len].*;
    if (!(sign.verifyCtx(domain, wire[0..end], sig, origin) catch return error.BadSignature)) return error.BadSignature;
}
pub const DecodedManifest = struct {
    record: Manifest,
    wire: []const u8,
    pub fn verify(self: @This(), allowed: []const sign.PublicKey) Error!void {
        const parsed = try decodeManifest(self.wire);
        if (!std.meta.eql(parsed.record, self.record)) return error.InvalidField;
        try verifyWire(self.wire, parsed.record.origin, allowed, manifest_domain);
    }
    pub fn id(self: @This()) Error!Digest {
        const parsed = try decodeManifest(self.wire);
        if (!std.meta.eql(parsed.record, self.record)) return error.InvalidField;
        return manifestId(self.wire);
    }
};
pub fn encodeManifest(m: Manifest, key: *const sign.KeyPair, out: []u8) ![]const u8 {
    try validateManifest(m);
    if (!std.mem.eql(u8, &key.public_key, &m.origin)) return error.OriginMismatch;
    if (out.len < manifest_wire_len) return error.Truncated;
    @memcpy(out[0..4], "OGMM");
    out[4] = 1;
    @memcpy(out[5..37], &m.origin);
    @memcpy(out[37..53], &m.guest);
    std.mem.writeInt(u64, out[53..61], m.claim_hlc, .big);
    std.mem.writeInt(u64, out[61..69], m.claim_revision, .big);
    out[69] = @backingInt(m.routing_class);
    std.mem.writeInt(u64, out[70..78], m.class_revision, .big);
    std.mem.writeInt(u64, out[78..86], m.membership_revision, .big);
    out[86] = m.scope;
    std.mem.writeInt(u64, out[87..95], m.channel_count, .big);
    std.mem.writeInt(u64, out[95..103], m.encoded_bytes, .big);
    std.mem.writeInt(u32, out[103..107], m.chunk_payload_bytes, .big);
    std.mem.writeInt(u64, out[107..115], m.chunk_count, .big);
    @memcpy(out[115..147], &m.set_digest);
    const signature = try key.signCtx(manifest_domain, out[0..manifest_body_len]);
    @memcpy(out[147..211], &signature);
    return out[0..manifest_wire_len];
}
pub fn decodeManifest(wire: []const u8) Error!DecodedManifest {
    if (wire.len < manifest_wire_len) return error.Truncated;
    if (wire.len > manifest_wire_len) return error.TrailingBytes;
    if (!std.mem.eql(u8, wire[0..4], "OGMM") or wire[4] != 1) return error.BadVersion;
    if (wire[86] != 1 or std.mem.readInt(u32, wire[103..107], .big) != payload_bytes) return error.InvalidField;
    const m: Manifest = .{ .origin = wire[5..37].*, .guest = wire[37..53].*, .claim_hlc = std.mem.readInt(u64, wire[53..61], .big), .claim_revision = std.mem.readInt(u64, wire[61..69], .big), .routing_class = std.enums.fromInt(presence.RoutingClass, wire[69]) orelse return error.InvalidField, .class_revision = std.mem.readInt(u64, wire[70..78], .big), .membership_revision = std.mem.readInt(u64, wire[78..86], .big), .scope = wire[86], .channel_count = std.mem.readInt(u64, wire[87..95], .big), .encoded_bytes = std.mem.readInt(u64, wire[95..103], .big), .chunk_payload_bytes = std.mem.readInt(u32, wire[103..107], .big), .chunk_count = std.mem.readInt(u64, wire[107..115], .big), .set_digest = wire[115..147].* };
    try validateManifest(m);
    return .{ .record = m, .wire = wire };
}
pub fn chunkEncodedLen(c: Chunk) Error!usize {
    if (c.payload.len == 0 or c.payload.len > payload_bytes) return error.InvalidField;
    const expected = std.math.mul(u64, c.index, payload_bytes) catch return error.InvalidField;
    if (c.offset != expected) return error.InvalidField;
    return std.math.add(usize, chunk_overhead, c.payload.len) catch error.InvalidField;
}
pub fn encodeChunk(c: Chunk, key: *const sign.KeyPair, out: []u8) ![]const u8 {
    const len = try chunkEncodedLen(c);
    if (!std.mem.eql(u8, &c.origin, &key.public_key)) return error.OriginMismatch;
    if (out.len < len) return error.Truncated;
    @memcpy(out[0..4], "OGMC");
    out[4] = 1;
    @memcpy(out[5..37], &c.origin);
    @memcpy(out[37..69], &c.manifest_id);
    std.mem.writeInt(u64, out[69..77], c.index, .big);
    std.mem.writeInt(u64, out[77..85], c.offset, .big);
    std.mem.writeInt(u32, out[85..89], @intCast(c.payload.len), .big);
    @memcpy(out[89..][0..c.payload.len], c.payload);
    const end = len - sign.signature_len;
    const signature = try key.signCtx(chunk_domain, out[0..end]);
    @memcpy(out[end..][0..sign.signature_len], &signature);
    return out[0..len];
}
pub const DecodedChunk = struct {
    record: Chunk,
    wire: []const u8,
    pub fn verify(self: @This(), allowed: []const sign.PublicKey) Error!void {
        const c = (try decodeChunk(self.wire)).record;
        if (!sameChunk(c, self.record)) return error.InvalidField;
        try verifyWire(self.wire, c.origin, allowed, chunk_domain);
    }
    /// Structural binding only; both originals still need signature/admission.
    pub fn requireManifest(self: @This(), manifest: DecodedManifest) Error!void {
        const c = (try decodeChunk(self.wire)).record;
        if (!sameChunk(c, self.record)) return error.InvalidField;
        const m = (try decodeManifest(manifest.wire)).record;
        if (!std.meta.eql(m, manifest.record)) return error.InvalidField;
        const id = try manifest.id();
        if (!std.mem.eql(u8, &c.origin, &m.origin) or !std.mem.eql(u8, &c.manifest_id, &id)) return error.BadReference;
        if (c.index >= m.chunk_count or c.offset >= m.encoded_bytes) return error.BadReference;
        const remaining = m.encoded_bytes - c.offset;
        if (c.payload.len != @min(remaining, payload_bytes)) return error.BadReference;
    }
};
fn sameChunk(a: Chunk, b: Chunk) bool {
    return std.mem.eql(u8, &a.origin, &b.origin) and std.mem.eql(u8, &a.manifest_id, &b.manifest_id) and a.index == b.index and a.offset == b.offset and std.mem.eql(u8, a.payload, b.payload);
}
pub fn decodeChunk(wire: []const u8) Error!DecodedChunk {
    if (wire.len < chunk_overhead) return error.Truncated;
    if (!std.mem.eql(u8, wire[0..4], "OGMC") or wire[4] != 1) return error.BadVersion;
    const n = std.mem.readInt(u32, wire[85..89], .big);
    if (n == 0 or n > payload_bytes) return error.InvalidField;
    const expected = chunk_overhead + @as(usize, n);
    if (wire.len < expected) return error.Truncated;
    if (wire.len > expected) return error.TrailingBytes;
    const c: Chunk = .{ .origin = wire[5..37].*, .manifest_id = wire[37..69].*, .index = std.mem.readInt(u64, wire[69..77], .big), .offset = std.mem.readInt(u64, wire[77..85], .big), .payload = wire[89..][0..n] };
    _ = try chunkEncodedLen(c);
    return .{ .record = c, .wire = wire };
}
// World channel sigil/spoof grammar plus the registered-channel token byte
// restrictions. The snapshot never rewrites or silently filters input.
fn validCanonicalNetworkToken(name: []const u8) bool {
    if (name.len == 0 or name.len > max_channel_len or !channel_name.isNetworkChannelName(name)) return false;
    for (name) |byte| {
        if (byte <= 0x20 or byte == ',' or byte == 0x7f or (byte >= 'A' and byte <= 'Z')) return false;
    }
    return true;
}

/// Iterates an immutable contiguous canonical stream without allocation. Names
/// and previous-name storage borrow stream until iteration completes. Assembler
/// must reassemble records crossing chunk boundaries before using this API.
pub const SetIterator = struct {
    stream: []const u8,
    pos: usize = 0,
    count: u64 = 0,
    previous: ?[]const u8 = null,
    pub fn next(self: *@This()) Error!?[]const u8 {
        if (self.pos == self.stream.len) return null;
        if (self.stream.len - self.pos < 2) return error.Truncated;
        const n = std.mem.readInt(u16, self.stream[self.pos..][0..2], .big);
        self.pos += 2;
        if (n == 0 or n > max_channel_len) return error.InvalidSet;
        if (n > self.stream.len - self.pos) return error.Truncated;
        const name = self.stream[self.pos..][0..n];
        if (!validCanonicalNetworkToken(name)) return error.InvalidSet;
        if (self.previous) |before| if (std.mem.order(u8, before, name) != .lt) return error.InvalidSet;
        self.count = std.math.add(u64, self.count, 1) catch return error.InvalidSet;
        self.pos += n;
        self.previous = name;
        return name;
    }
};
pub fn validateStream(stream: []const u8, expected_count: u64) Error!void {
    var it = SetIterator{ .stream = stream };
    while (try it.next()) |_| {}
    if (it.count != expected_count) return error.InvalidSet;
}
pub fn validateSet(stream: []const u8, m: Manifest) Error!void {
    try validateManifest(m);
    if (stream.len != m.encoded_bytes) return error.InvalidSet;
    try validateStream(stream, m.channel_count);
    if (!std.mem.eql(u8, &setDigest(stream), &m.set_digest)) return error.InvalidSet;
}

fn fixture(key: *const sign.KeyPair) !Manifest {
    return .{ .origin = key.public_key, .guest = try presence.guestId(.{ .epoch = 1, .counter = 2 }), .claim_hlc = 1, .claim_revision = 1, .routing_class = .true_guest, .class_revision = 1, .membership_revision = 1, .scope = 1, .channel_count = 0, .encoded_bytes = 0, .chunk_payload_bytes = chunk_payload_bytes, .chunk_count = 0, .set_digest = setDigest("") };
}
test "manifest signed original, admission, body identity and every truncation" {
    var key = try sign.KeyPair.fromSeed(@splat(1));
    defer key.deinit();
    var other = try sign.KeyPair.fromSeed(@splat(2));
    defer other.deinit();
    const m = try fixture(&key);
    var out: [manifest_wire_len + 1]u8 = undefined;
    const wire = try encodeManifest(m, &key, &out);
    for (0..wire.len) |i| try std.testing.expectError(error.Truncated, decodeManifest(wire[0..i]));
    const decoded = try decodeManifest(wire);
    try decoded.verify(&.{key.public_key});
    try std.testing.expectError(error.UnapprovedOrigin, decoded.verify(&.{other.public_key}));
    try std.testing.expectError(error.OriginMismatch, encodeManifest(m, &other, &out));
    const id = try decoded.id();
    out[manifest_wire_len - 1] ^= 1;
    const altered = try decodeManifest(out[0..manifest_wire_len]);
    try std.testing.expectEqualDeep(id, try altered.id());
    try std.testing.expectError(error.BadSignature, altered.verify(&.{key.public_key}));
    try std.testing.expectError(error.TrailingBytes, decodeManifest(&out));
}
test "chunk signed boundaries reference and forged bodies" {
    var key = try sign.KeyPair.fromSeed(@splat(3));
    defer key.deinit();
    var m = try fixture(&key);
    m.channel_count = 191;
    m.encoded_bytes = payload_bytes + 1;
    m.chunk_count = 2;
    m.set_digest = @splat(4);
    var manifest_buf: [manifest_wire_len]u8 = undefined;
    const manifest = try decodeManifest(try encodeManifest(m, &key, &manifest_buf));
    const id = try manifest.id();
    const payload: [payload_bytes]u8 = @splat(42);
    var out: [chunk_overhead + payload_bytes + 1]u8 = undefined;
    const c: Chunk = .{ .origin = key.public_key, .manifest_id = id, .index = 0, .offset = 0, .payload = &payload };
    const wire = try encodeChunk(c, &key, &out);
    for (0..wire.len) |i| try std.testing.expectError(error.Truncated, decodeChunk(wire[0..i]));
    const decoded = try decodeChunk(wire);
    try decoded.verify(&.{key.public_key});
    try decoded.requireManifest(manifest);
    out[37] ^= 1;
    const badref = try decodeChunk(out[0..wire.len]);
    try std.testing.expectError(error.BadReference, badref.requireManifest(manifest));
    try std.testing.expectError(error.BadSignature, badref.verify(&.{key.public_key}));
    const final: Chunk = .{ .origin = key.public_key, .manifest_id = id, .index = 1, .offset = payload_bytes, .payload = "x" };
    try (try decodeChunk(try encodeChunk(final, &key, &out))).requireManifest(manifest);
    var wrong = final;
    wrong.offset = 0;
    try std.testing.expectError(error.InvalidField, chunkEncodedLen(wrong));
    wrong.index = std.math.maxInt(u64);
    try std.testing.expectError(error.InvalidField, chunkEncodedLen(wrong));
}
fn consumeSet(stream: []const u8) Error!void {
    var it = SetIterator{ .stream = stream };
    while (try it.next()) |_| {}
}
test "canonical set rejects aliases order and local channels" {
    var key = try sign.KeyPair.fromSeed(@splat(4));
    defer key.deinit();
    const stream = "\x00\x02#a\x00\x02#b";
    var m = try fixture(&key);
    m.channel_count = 2;
    m.encoded_bytes = stream.len;
    m.chunk_count = 1;
    m.set_digest = setDigest(stream);
    try validateSet(stream, m);
    for ([_][]const u8{ "\x00\x02#A", "\x00\x02&a", "\x00\x03%&a", "\x00\x02#a\x00\x02#a", "\x00\x02#b\x00\x02#a" }) |bad| {
        try std.testing.expectError(error.InvalidSet, consumeSet(bad));
    }
    var long: [258]u8 = @splat('x');
    long[0] = 1;
    long[1] = 0;
    long[2] = '#';
    var it = SetIterator{ .stream = &long };
    try std.testing.expectEqual(@as(usize, 256), (try it.next()).?.len);
    try std.testing.expect((try it.next()) == null);
}

test "canonical names retain distinct UTF8 and stream boundaries" {
    // Sorted bytes: network-wide variants only; distinct UTF-8 stays distinct.
    const names = "\x00\x03#é\x00\x03#ñ";
    var it = SetIterator{ .stream = names };
    try std.testing.expectEqualStrings("#é", (try it.next()).?);
    try std.testing.expectEqualStrings("#ñ", (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
    for (1..names.len) |n| {
        const partial = SetIterator{ .stream = names[0..n] };
        if (n == 5) { // A boundary between entries is a complete smaller set.
            try consumeSet(names[0..n]);
        } else {
            try std.testing.expectError(error.Truncated, consumeSet(partial.stream));
        }
    }
    const max_200: [202]u8 = block: {
        var bytes: [202]u8 = @splat('z');
        bytes[0] = 0;
        bytes[1] = 200;
        bytes[2] = '#';
        break :block bytes;
    };
    try consumeSet(&max_200);
}

test "canonical stream refuses IRC token delimiters" {
    for ([_][]const u8{
        "\x00\x05#a\x00bc", "\x00\x06#a\r\nbc", "\x00\x05#a\tbc",
        "\x00\x05#a bc",    "\x00\x05#a,bc",    "\x00\x05#a\x7fbc",
    }) |bad| try std.testing.expectError(error.InvalidSet, consumeSet(bad));
    try consumeSet("\x00\x03#é");
}

test "wrong signature domain cannot reflect valid manifest or chunk bodies" {
    var key = try sign.KeyPair.fromSeed(@splat(5));
    defer key.deinit();
    var m = try fixture(&key);
    var manifest_buf: [manifest_wire_len]u8 = undefined;
    _ = try encodeManifest(m, &key, &manifest_buf);
    const wrong_manifest = try key.signCtx(chunk_domain, manifest_buf[0..manifest_body_len]);
    @memcpy(manifest_buf[manifest_body_len..], &wrong_manifest);
    try std.testing.expectError(error.BadSignature, (try decodeManifest(&manifest_buf)).verify(&.{key.public_key}));
    m.channel_count = 1;
    m.encoded_bytes = 3;
    m.chunk_count = 1;
    m.set_digest = setDigest("\x00\x01#");
    _ = try encodeManifest(m, &key, &manifest_buf);
    const id = try manifestId(&manifest_buf);
    const c: Chunk = .{ .origin = key.public_key, .manifest_id = id, .index = 0, .offset = 0, .payload = "\x00\x01#" };
    var chunk_buf: [chunk_overhead + 3]u8 = undefined;
    _ = try encodeChunk(c, &key, &chunk_buf);
    const wrong_chunk = try key.signCtx(manifest_domain, chunk_buf[0 .. chunk_buf.len - sign.signature_len]);
    @memcpy(chunk_buf[chunk_buf.len - sign.signature_len ..], &wrong_chunk);
    try std.testing.expectError(error.BadSignature, (try decodeChunk(&chunk_buf)).verify(&.{key.public_key}));
}

test "manifest rejects zero claim and class clocks and unknown class" {
    var key = try sign.KeyPair.fromSeed(@splat(6));
    defer key.deinit();
    const m = try fixture(&key);
    var buf: [manifest_wire_len]u8 = undefined;
    _ = try encodeManifest(m, &key, &buf);
    const original = buf;
    for ([_]usize{ 53, 61, 70 }) |offset| {
        buf = original;
        @memset(buf[offset..][0..8], 0);
        try std.testing.expectError(error.InvalidField, decodeManifest(&buf));
    }
    buf = original;
    buf[69] = 0xff;
    try std.testing.expectError(error.InvalidField, decodeManifest(&buf));
}
