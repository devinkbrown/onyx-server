// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local retained-image authentication. Remote origin signatures cannot attest
//! the local admission time or policy. No restoration or live authority is
//! returned by this envelope layer; strict image reconstruction follows it.
//! Calls borrowing OroStore rows require its external owner lock throughout.
const std = @import("std");
const sign = @import("../crypto/sign.zig");
const issuer = @import("mesh_presence_issuer.zig");
const persistence = @import("store.zig");

pub const image_key = "presence-retained/image/v1";
pub const head_key = "presence-retained/head/v1";
pub const domain = "onyx-mesh-presence-retained-local-v2";
pub const body_len = 293;
pub const head_len = body_len + sign.signature_len;
pub const Error = error{ InvalidHead, BadSignature, ContextMismatch, InvalidPackage, MissingState };

pub const LocalContext = struct { origin: sign.PublicKey, realm: [32]u8 };
pub const IssuerRows = struct { metadata: []const u8, frontier: []const u8 };

pub fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(bytes, &result, .{});
    return result;
}

pub const Head = struct {
    context: LocalContext,
    store_id: [16]u8,
    commit_generation: u64,
    image_generation: u64,
    previous_head_digest: [32]u8,
    image_digest: [32]u8,
    image_len: u64,
    entries: u32,
    frontiers: u32,
    retained_bytes: u64,
    metadata_digest: [32]u8,
    frontier_digest: [32]u8,
    epoch: u64,
    issued_through: u64,
    frontier_revision: u64,
    frontier_through: u64,
    expiry_floor_ms: i64,

    fn validate(self: Head) Error!void {
        if (std.mem.allEqual(u8, &self.store_id, 0) or self.commit_generation == 0 or self.image_generation == 0 or self.image_generation > self.commit_generation or self.epoch == 0 or self.frontier_revision == 0 or self.frontier_through > self.issued_through or self.expiry_floor_ms < 0 or self.image_len == 0 or self.retained_bytes > self.image_len) return error.InvalidHead;
        if ((self.commit_generation == 1) != std.mem.allEqual(u8, &self.previous_head_digest, 0)) return error.InvalidHead;
    }

    pub fn encode(self: Head, key: *const sign.KeyPair) ![head_len]u8 {
        try self.validate();
        if (!std.mem.eql(u8, &self.context.origin, &key.public_key)) return error.ContextMismatch;
        var out: [head_len]u8 = undefined;
        var writer: Writer = .{ .bytes = out[0..body_len] };
        writer.put("OPRH");
        writer.put(&.{2});
        writer.put(&self.context.origin);
        writer.put(&self.context.realm);
        writer.put(&self.store_id);
        writer.int(u64, self.commit_generation);
        writer.int(u64, self.image_generation);
        writer.put(&self.previous_head_digest);
        writer.put(&self.image_digest);
        writer.int(u64, self.image_len);
        writer.int(u32, self.entries);
        writer.int(u32, self.frontiers);
        writer.int(u64, self.retained_bytes);
        writer.put(&self.metadata_digest);
        writer.put(&self.frontier_digest);
        writer.int(u64, self.epoch);
        writer.int(u64, self.issued_through);
        writer.int(u64, self.frontier_revision);
        writer.int(u64, self.frontier_through);
        writer.int(i64, self.expiry_floor_ms);
        std.debug.assert(writer.offset == body_len);
        out[body_len..].* = try key.signCtx(domain, out[0..body_len]);
        return out;
    }

    /// Authenticate before interpreting any issuer relationships or image rows.
    /// Store UUID comes from this signed local head; callers with an independent
    /// expected UUID (e.g. hot handoff) must additionally require exact equality.
    /// A valid whole-disk rollback needs an independent monotonic anchor to detect.
    pub fn verify(raw: []const u8, expected: LocalContext) !Head {
        if (raw.len != head_len) return error.InvalidHead;
        const signature: sign.Signature = raw[body_len..][0..sign.signature_len].*;
        if (!(sign.verifyCtx(domain, raw[0..body_len], signature, expected.origin) catch false)) return error.BadSignature;
        if (!std.mem.eql(u8, raw[0..4], "OPRH") or raw[4] != 2) return error.InvalidHead;
        var reader: Reader = .{ .bytes = raw[5..body_len] };
        const result: Head = .{
            .context = .{ .origin = reader.take(32).*, .realm = reader.take(32).* },
            .store_id = reader.take(16).*,
            .commit_generation = reader.int(u64),
            .image_generation = reader.int(u64),
            .previous_head_digest = reader.take(32).*,
            .image_digest = reader.take(32).*,
            .image_len = reader.int(u64),
            .entries = reader.int(u32),
            .frontiers = reader.int(u32),
            .retained_bytes = reader.int(u64),
            .metadata_digest = reader.take(32).*,
            .frontier_digest = reader.take(32).*,
            .epoch = reader.int(u64),
            .issued_through = reader.int(u64),
            .frontier_revision = reader.int(u64),
            .frontier_through = reader.int(u64),
            .expiry_floor_ms = reader.int(i64),
        };
        std.debug.assert(reader.offset == body_len - 5);
        if (!std.mem.eql(u8, &result.context.origin, &expected.origin) or !std.mem.eql(u8, &result.context.realm, &expected.realm)) return error.ContextMismatch;
        try result.validate();
        return result;
    }
};

const Writer = struct {
    bytes: []u8,
    offset: usize = 0,
    fn put(self: *Writer, bytes: []const u8) void {
        @memcpy(self.bytes[self.offset..][0..bytes.len], bytes);
        self.offset += bytes.len;
    }
    fn int(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.offset..][0..@sizeOf(T)], value, .big);
        self.offset += @sizeOf(T);
    }
};
const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,
    fn take(self: *Reader, comptime length: usize) *const [length]u8 {
        const bytes = self.bytes[self.offset..][0..length];
        self.offset += length;
        return bytes;
    }
    fn int(self: *Reader, comptime T: type) T {
        return std.mem.readInt(T, self.take(@sizeOf(T)), .big);
    }
};

/// Signed envelope plus exact issuer relationships, not a decoded presence
/// image. Arbitrary authenticated image contents still require strict whole
/// reconstruction before any lookup, World projection or retirement authority.
pub fn verifyEnvelope(raw: []const u8, image: []const u8, rows: IssuerRows, context: LocalContext) !Head {
    const head = try Head.verify(raw, context);
    if (head.image_len != image.len or !std.mem.eql(u8, &head.image_digest, &digest(image)) or !std.mem.eql(u8, &head.metadata_digest, &digest(rows.metadata)) or !std.mem.eql(u8, &head.frontier_digest, &digest(rows.frontier))) return error.InvalidPackage;
    const metadata = try issuer.validateRows(rows.metadata, rows.frontier, context.origin);
    if (head.epoch != metadata.epoch or head.issued_through != metadata.issued_through or head.frontier_revision != metadata.frontier_revision or head.frontier_through != metadata.frontier_through) return error.InvalidPackage;
    return head;
}

pub const Envelope = struct { head: Head, image: []const u8, rows: IssuerRows };

pub fn readCommittedEnvelope(store: *const persistence.OroStore, context: LocalContext) !Envelope {
    const raw = store.get(.props, head_key) orelse return error.MissingState;
    // Verify the head before traversing any other local state.
    _ = try Head.verify(raw, context);
    const image = store.get(.props, image_key) orelse return error.MissingState;
    const rows: IssuerRows = .{
        .metadata = store.get(.props, issuer.metadata_key) orelse return error.MissingState,
        .frontier = store.get(.props, issuer.frontier_key) orelse return error.MissingState,
    };
    return .{ .head = try verifyEnvelope(raw, image, rows, context), .image = image, .rows = rows };
}

fn fixtureHead(key: *const sign.KeyPair) Head {
    return .{
        .context = .{ .origin = key.public_key, .realm = @splat(7) },
        .store_id = @splat(1),
        .commit_generation = 1,
        .image_generation = 1,
        .previous_head_digest = @splat(0),
        .image_digest = digest("image fixture"),
        .image_len = "image fixture".len,
        .entries = 0,
        .frontiers = 0,
        .retained_bytes = 0,
        .metadata_digest = @splat(0),
        .frontier_digest = @splat(0),
        .epoch = 1,
        .issued_through = 0,
        .frontier_revision = 1,
        .frontier_through = 0,
        .expiry_floor_ms = 0,
    };
}

test "retained v2 causal mandatory locator must block frozen head reader" {
    var key = try sign.KeyPair.fromSeed(@splat(232));
    defer key.deinit();
    const raw = try fixtureHead(&key).encode(&key);
    const signature: sign.Signature = raw[body_len..].*;
    // The historical physical locator stays fixed. Its new mandatory value
    // must fail the actual frozen application signature domain.
    try std.testing.expectEqualStrings("presence-retained/head/v1", head_key);
    try std.testing.expect(!(try sign.verifyCtx("onyx-mesh-presence-retained-local-v1", raw[0..body_len], signature, key.public_key)));
    try std.testing.expectEqual(@as(u8, 2), raw[4]);
}

test "mesh presence retained head authenticates every byte and exact local context" {
    var key = try sign.KeyPair.fromSeed(@splat(111));
    defer key.deinit();
    var foreign = try sign.KeyPair.fromSeed(@splat(112));
    defer foreign.deinit();
    const head = fixtureHead(&key);
    const raw = try head.encode(&key);
    try std.testing.expectEqualDeep(head, try Head.verify(&raw, head.context));
    for (0..raw.len) |offset| {
        var tampered = raw;
        tampered[offset] ^= 1;
        try std.testing.expectError(error.BadSignature, Head.verify(&tampered, head.context));
    }
    for (0..raw.len) |length| try std.testing.expectError(error.InvalidHead, Head.verify(raw[0..length], head.context));
    const trailing = raw ++ [_]u8{0};
    try std.testing.expectError(error.InvalidHead, Head.verify(&trailing, head.context));
    try std.testing.expectError(error.ContextMismatch, head.encode(&foreign));
    var context = head.context;
    context.realm[0] ^= 1;
    try std.testing.expectError(error.ContextMismatch, Head.verify(&raw, context));
    context = head.context;
    context.origin = foreign.public_key;
    try std.testing.expectError(error.BadSignature, Head.verify(&raw, context));
    var remote_head = head;
    remote_head.context.origin = foreign.public_key;
    try std.testing.expectError(error.BadSignature, Head.verify(&(try remote_head.encode(&foreign)), head.context));
}

test "mesh presence retained head rejects signed malformed generations clock and format" {
    var key = try sign.KeyPair.fromSeed(@splat(113));
    defer key.deinit();
    const head = fixtureHead(&key);
    for ([_]usize{ 0, 4, 69, 85, 93, 173, 181, 285 }) |offset| {
        var raw = try head.encode(&key);
        switch (offset) {
            69 => @memset(raw[69..85], 0),
            85, 93 => @memset(raw[offset..][0..8], 0),
            173 => std.mem.writeInt(u64, raw[181..189], head.image_len + 1, .big),
            181 => std.mem.writeInt(u64, raw[93..101], 2, .big),
            285 => std.mem.writeInt(i64, raw[285..293], -1, .big),
            else => raw[offset] = 255,
        }
        raw[body_len..].* = try key.signCtx(domain, raw[0..body_len]);
        try std.testing.expectError(error.InvalidHead, Head.verify(&raw, head.context));
    }
    var next = head;
    next.commit_generation = 2;
    try std.testing.expectError(error.InvalidHead, next.encode(&key));
    next.previous_head_digest = digest(&(try head.encode(&key)));
    next.expiry_floor_ms = 3000;
    try std.testing.expectEqualDeep(next, try Head.verify(&(try next.encode(&key)), head.context));
}

test "mesh presence retained envelope binds all four rows and issuer relations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(114));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "retained.wal", &key, 1000);
    defer owner.deinit();
    var head = fixtureHead(&key);
    const rows: IssuerRows = .{ .metadata = owner.store.get(.props, issuer.metadata_key).?, .frontier = owner.originalFrontier() };
    head.metadata_digest = digest(rows.metadata);
    head.frontier_digest = digest(rows.frontier);
    const raw = try head.encode(&key);
    _ = try verifyEnvelope(&raw, "image fixture", rows, head.context);
    try std.testing.expectError(error.MissingState, readCommittedEnvelope(&owner.store, head.context));
    try std.testing.expectError(error.InvalidPackage, verifyEnvelope(&raw, "tampered image", rows, head.context));
    try std.testing.expectError(error.InvalidPackage, verifyEnvelope(&raw, "image fixture", .{ .metadata = rows.metadata, .frontier = "bad" }, head.context));
    head.issued_through = 1;
    try std.testing.expectError(error.InvalidPackage, verifyEnvelope(&(try head.encode(&key)), "image fixture", rows, head.context));
    head.issued_through = 0;
    var batch = try owner.store.prepareBatch(&.{
        .{ .family = .props, .kind = .put, .key = image_key, .value = "image fixture" },
        .{ .family = .props, .kind = .put, .key = head_key, .value = &raw },
    });
    defer batch.abort();
    try batch.commit();
    const envelope = try readCommittedEnvelope(&owner.store, head.context);
    try std.testing.expectEqualDeep(head, envelope.head);
    try std.testing.expectEqualSlices(u8, "image fixture", envelope.image);
    try std.testing.expectError(error.AggregateStatePresent, owner.reserveSubject());
    // Deliberately manufacture a mixed disk fixture through the test-owned
    // storage handle: the supported legacy writer must no longer create it.
    var advanced = owner.metadata;
    advanced.issued_through += 1;
    const advanced_raw = advanced.encode();
    try owner.store.put(.props, issuer.metadata_key, &advanced_raw);
    try std.testing.expectError(error.InvalidPackage, readCommittedEnvelope(&owner.store, head.context));
}

test "mesh presence retained envelope refuses every missing row and signed invalid issuer state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var key = try sign.KeyPair.fromSeed(@splat(115));
    defer key.deinit();
    var owner = try issuer.Issuer.initialize(std.testing.allocator, std.testing.io, tmp.dir, "missing.wal", &key, 1000);
    defer owner.deinit();
    var head = fixtureHead(&key);
    const metadata = owner.metadata.encode();
    const proof = try std.testing.allocator.dupe(u8, owner.originalFrontier());
    defer std.testing.allocator.free(proof);
    head.metadata_digest = digest(&metadata);
    head.frontier_digest = digest(proof);
    const raw = try head.encode(&key);
    const keys = [_][]const u8{ head_key, image_key, issuer.metadata_key, issuer.frontier_key };
    const values = [_][]const u8{ &raw, "image fixture", &metadata, proof };
    for (keys, values) |name, value| try owner.store.put(.props, name, value);
    for (keys, values) |name, value| {
        try owner.store.delete(.props, name);
        try std.testing.expectError(error.MissingState, readCommittedEnvelope(&owner.store, head.context));
        try owner.store.put(.props, name, value);
        _ = try readCommittedEnvelope(&owner.store, head.context);
    }
    // Re-sign an envelope around invalid issuer bytes: matching digests alone
    // must not satisfy the issuer's independent signature/metadata rules.
    var invalid_metadata = owner.metadata;
    invalid_metadata.epoch = 0;
    const invalid_raw = invalid_metadata.encode();
    head.metadata_digest = digest(&invalid_raw);
    try std.testing.expectError(error.InvalidState, verifyEnvelope(&(try head.encode(&key)), "image fixture", .{ .metadata = &invalid_raw, .frontier = proof }, head.context));
    invalid_metadata = owner.metadata;
    invalid_metadata.epoch += 1;
    const mismatch_raw = invalid_metadata.encode();
    head.metadata_digest = digest(&mismatch_raw);
    try std.testing.expectError(error.InvalidState, verifyEnvelope(&(try head.encode(&key)), "image fixture", .{ .metadata = &mismatch_raw, .frontier = proof }, head.context));
    var invalid_proof = try std.testing.allocator.dupe(u8, proof);
    defer std.testing.allocator.free(invalid_proof);
    invalid_proof[invalid_proof.len - 1] ^= 1;
    invalid_metadata = owner.metadata;
    invalid_metadata.frontier_digest = digest(invalid_proof);
    const invalid_signature_raw = invalid_metadata.encode();
    head.metadata_digest = digest(&invalid_signature_raw);
    head.frontier_digest = digest(invalid_proof);
    try std.testing.expectError(error.InvalidState, verifyEnvelope(&(try head.encode(&key)), "image fixture", .{ .metadata = &invalid_signature_raw, .frontier = invalid_proof }, head.context));
}
