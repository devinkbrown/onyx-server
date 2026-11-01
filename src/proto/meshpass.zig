// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MeshPass admission tokens.
//!
//! MeshPass is the Undertow mesh admission and capability envelope. The signed
//! payload is a fixed-order CoilPack schema so byte-for-byte canonical encoding
//! is what Ed25519 signs and verifies.
const std = @import("std");
const coilpack = @import("coilpack.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const public_key_len = Ed25519.PublicKey.encoded_length;
pub const signature_len = Ed25519.Signature.encoded_length;
pub const max_realm_len = 255;
pub const max_signed_len = 384;
pub const max_token_len = 448;
pub const default_realm = "suimyaku";

const signed_schema_id: u64 = 0x04_01;
const token_schema_id: u64 = 0x04_02;
const signed_field_bitmap: u64 = (1 << 9) - 1;
const token_field_bitmap: u64 = 0x03;

pub const PublicKeyBytes = [public_key_len]u8;
pub const SignatureBytes = [signature_len]u8;

pub const Role = enum(u6) {
    operator = 0,
    relay = 1,
    witness = 2,
    services = 3,
    media = 4,
    bridge = 5,
};

pub const FrameFamily = enum(u5) {
    control = 0,
    sync = 1,
    irc_app = 2,
    capability = 3,
    mooring = 4,
    media = 5,
};

pub const MediaRight = enum(u5) {
    voice = 0,
    video = 1,
    screen = 2,
    data = 3,
    record = 4,
    e2e = 5,
};

pub const Fields = struct {
    node_pubkey: PublicKeyBytes,
    realm: []const u8,
    roles: u64 = 0,
    issued_ms: u64,
    expiry_ms: u64,
    allowed_frame_families: u32 = 0,
    max_fanout: u32 = 0,
    media_rights: u32 = 0,
    revocation_epoch: u64 = 0,
};

pub const Token = struct {
    fields: Fields,
    signature: SignatureBytes,
};

pub const TrustRoot = struct {
    public_key: PublicKeyBytes,
    realm: []const u8 = default_realm,
    min_revocation_epoch: u64 = 0,
};

pub const IssueError = coilpack.EncodeError || error{
    InvalidRealm,
    InvalidTime,
    IdentityElement,
    NonCanonical,
    KeyMismatch,
    WeakPublicKey,
};

pub const EncodeError = coilpack.EncodeError || error{
    InvalidRealm,
    InvalidTime,
};

pub const DecodeError = coilpack.DecodeError || error{
    InvalidSchema,
    InvalidFieldBitmap,
    InvalidPublicKeyLen,
    InvalidSignatureLen,
    InvalidRealm,
    InvalidTime,
    TrailingBytes,
    ValueTooLarge,
};

pub const VerifyError = error{
    BadSig,
    Expired,
    WrongRealm,
    Revoked,
};

pub const BindError = VerifyError || error{
    PeerKeyMismatch,
    MissingFrameFamily,
};

/// Build a role bitset from a comptime list.
pub fn roles(comptime list: []const Role) u64 {
    var bits: u64 = 0;
    for (list) |role| {
        bits |= roleBit(role);
    }
    return bits;
}

/// Build a frame-family bitset from a comptime list.
pub fn frameFamilies(comptime list: []const FrameFamily) u32 {
    var bits: u32 = 0;
    for (list) |family| {
        bits |= frameFamilyBit(family);
    }
    return bits;
}

/// Build a media-rights bitset from a comptime list.
pub fn mediaRights(comptime list: []const MediaRight) u32 {
    var bits: u32 = 0;
    for (list) |right| {
        bits |= mediaRightBit(right);
    }
    return bits;
}

/// Issue a MeshPass by signing the canonical CoilPack field payload.
pub fn issue(issuer_key: Ed25519.KeyPair, fields: Fields) IssueError!Token {
    try validateFields(fields);

    var signed_buf: [max_signed_len]u8 = undefined;
    const signed = signed_buf[0..try encodeSignedFields(&signed_buf, fields)];
    const sig = try issuer_key.sign(signed, null);

    return .{
        .fields = fields,
        .signature = sig.toBytes(),
    };
}

/// Verify a token against either `TrustRoot` or raw `PublicKeyBytes`.
pub fn verify(token: Token, trust_root: anytype, now_ms: u64) VerifyError!void {
    const root = normalizeTrustRoot(trust_root);

    var signed_buf: [max_signed_len]u8 = undefined;
    const signed_len = encodeSignedFields(&signed_buf, token.fields) catch return error.BadSig;
    const signed = signed_buf[0..signed_len];

    const pk = Ed25519.PublicKey.fromBytes(root.public_key) catch return error.BadSig;
    const sig = Ed25519.Signature.fromBytes(token.signature);
    sig.verifyStrict(signed, pk) catch return error.BadSig;

    if (!std.mem.eql(u8, token.fields.realm, root.realm)) return error.WrongRealm;
    if (token.fields.revocation_epoch < root.min_revocation_epoch) return error.Revoked;
    if (now_ms < token.fields.issued_ms) return error.Expired;
    if (now_ms > token.fields.expiry_ms) return error.Expired;
}

/// Verify a decoded token, then bind it to the authenticated peer node key and
/// require every requested UNDERTOW frame family bit to be present.
pub fn bindDecodedToken(
    token: Token,
    trust_root: anytype,
    now_ms: u64,
    peer_node_pubkey: PublicKeyBytes,
    required_frame_families: u32,
) BindError!Fields {
    try verify(token, trust_root, now_ms);
    if (!std.mem.eql(u8, &token.fields.node_pubkey, &peer_node_pubkey)) return error.PeerKeyMismatch;
    if ((token.fields.allowed_frame_families & required_frame_families) != required_frame_families) {
        return error.MissingFrameFamily;
    }
    return token.fields;
}

/// Return true when `fields` carries `role`.
pub fn hasRole(fields: Fields, role: Role) bool {
    return (fields.roles & roleBit(role)) != 0;
}

/// Return true when `fields` permits the given UNDERTOW frame family.
pub fn mayUseFrameFamily(fields: Fields, family: FrameFamily) bool {
    return (fields.allowed_frame_families & frameFamilyBit(family)) != 0;
}

/// Return true when requested fanout stays within the token limit.
pub fn withinFanout(fields: Fields, requested: u32) bool {
    return requested <= fields.max_fanout;
}

/// Return true when `fields` carries `right`.
pub fn hasMediaRight(fields: Fields, right: MediaRight) bool {
    return (fields.media_rights & mediaRightBit(right)) != 0;
}

/// Encode the full token as canonical CoilPack.
pub fn encode(out: []u8, token: Token) EncodeError!usize {
    var signed_buf: [max_signed_len]u8 = undefined;
    const signed = signed_buf[0..try encodeSignedFields(&signed_buf, token.fields)];

    var w = coilpack.Cbb.init(out);
    _ = try w.writeVarint(token_schema_id);
    _ = try w.writeVarint(token_field_bitmap);
    _ = try w.writeBytes(signed);
    _ = try w.writeBytes(&token.signature);
    return w.bytesWritten();
}

/// Decode a canonical MeshPass token. Returned realm bytes borrow from `in`.
pub fn decode(in: []const u8) DecodeError!Token {
    var r = coilpack.Cbs.init(in);
    if (try r.readVarint() != token_schema_id) return error.InvalidSchema;
    if (try r.readVarint() != token_field_bitmap) return error.InvalidFieldBitmap;

    const signed = try r.readBytes();
    const sig_bytes = try r.readBytes();
    if (!r.done()) return error.TrailingBytes;
    if (sig_bytes.len != signature_len) return error.InvalidSignatureLen;

    return .{
        .fields = try decodeSignedFields(signed),
        .signature = sig_bytes[0..signature_len].*,
    };
}

/// Encode only the payload covered by the Ed25519 signature.
pub fn encodeSignedFields(out: []u8, fields: Fields) EncodeError!usize {
    try validateFields(fields);

    var w = coilpack.Cbb.init(out);
    _ = try w.writeVarint(signed_schema_id);
    _ = try w.writeVarint(signed_field_bitmap);
    _ = try w.writeBytes(&fields.node_pubkey);
    _ = try w.writeBytes(fields.realm);
    _ = try w.writeVarint(fields.roles);
    _ = try w.writeVarint(fields.issued_ms);
    _ = try w.writeVarint(fields.expiry_ms);
    _ = try w.writeVarint(fields.allowed_frame_families);
    _ = try w.writeVarint(fields.max_fanout);
    _ = try w.writeVarint(fields.media_rights);
    _ = try w.writeVarint(fields.revocation_epoch);
    return w.bytesWritten();
}

/// Decode only the payload covered by the Ed25519 signature.
pub fn decodeSignedFields(in: []const u8) DecodeError!Fields {
    var r = coilpack.Cbs.init(in);
    if (try r.readVarint() != signed_schema_id) return error.InvalidSchema;
    if (try r.readVarint() != signed_field_bitmap) return error.InvalidFieldBitmap;

    const node_pubkey = try r.readBytes();
    if (node_pubkey.len != public_key_len) return error.InvalidPublicKeyLen;

    const realm = try r.readBytes();
    const roles_value = try r.readVarint();
    const issued_ms = try r.readVarint();
    const expiry_ms = try r.readVarint();
    const families = try readU32Varint(&r);
    const max_fanout = try readU32Varint(&r);
    const media = try readU32Varint(&r);
    const revocation_epoch = try r.readVarint();
    if (!r.done()) return error.TrailingBytes;

    const fields = Fields{
        .node_pubkey = node_pubkey[0..public_key_len].*,
        .realm = realm,
        .roles = roles_value,
        .issued_ms = issued_ms,
        .expiry_ms = expiry_ms,
        .allowed_frame_families = families,
        .max_fanout = max_fanout,
        .media_rights = media,
        .revocation_epoch = revocation_epoch,
    };
    validateFields(fields) catch |err| return switch (err) {
        error.InvalidRealm => error.InvalidRealm,
        error.InvalidTime => error.InvalidTime,
        error.BufferTooSmall => unreachable,
    };
    return fields;
}

fn validateFields(fields: Fields) EncodeError!void {
    if (fields.realm.len == 0 or fields.realm.len > max_realm_len) return error.InvalidRealm;
    if (fields.issued_ms > fields.expiry_ms) return error.InvalidTime;
}

fn readU32Varint(r: *coilpack.Cbs) DecodeError!u32 {
    const value = try r.readVarint();
    if (value > std.math.maxInt(u32)) return error.ValueTooLarge;
    return @intCast(value);
}

fn normalizeTrustRoot(trust_root: anytype) TrustRoot {
    const T = @TypeOf(trust_root);
    if (T == TrustRoot) return trust_root;
    if (T == PublicKeyBytes) return .{ .public_key = trust_root };
    @compileError("trust_root must be TrustRoot or PublicKeyBytes");
}

fn roleBit(role: Role) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@backingInt(role)));
}

fn frameFamilyBit(family: FrameFamily) u32 {
    return @as(u32, 1) << @as(u5, @intCast(@backingInt(family)));
}

fn mediaRightBit(right: MediaRight) u32 {
    return @as(u32, 1) << @as(u5, @intCast(@backingInt(right)));
}

fn sampleFields(node_pubkey: PublicKeyBytes) Fields {
    return .{
        .node_pubkey = node_pubkey,
        .realm = default_realm,
        .roles = roles(&.{ .operator, .relay, .media }),
        .issued_ms = 1_000,
        .expiry_ms = 10_000,
        .allowed_frame_families = frameFamilies(&.{ .control, .sync, .irc_app, .mooring }),
        .max_fanout = 8,
        .media_rights = mediaRights(&.{ .voice, .video }),
        .revocation_epoch = 3,
    };
}

test "issue and verify happy path" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x11)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x22)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    try verify(token, issuer.public_key.toBytes(), 2_000);
    try std.testing.expect(hasRole(token.fields, .operator));
    try std.testing.expect(!hasRole(token.fields, .services));
    try std.testing.expect(mayUseFrameFamily(token.fields, .irc_app));
    try std.testing.expect(!mayUseFrameFamily(token.fields, .media));
    try std.testing.expect(withinFanout(token.fields, 8));
    try std.testing.expect(!withinFanout(token.fields, 9));
    try std.testing.expect(hasMediaRight(token.fields, .voice));
}

test "bind decoded token accepts matching peer and required frame families" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x31)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x32)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));
    var buf: [max_token_len]u8 = undefined;
    const decoded = try decode(buf[0..try encode(&buf, token)]);

    const fields = try bindDecodedToken(
        decoded,
        issuer.public_key.toBytes(),
        2_000,
        node.public_key.toBytes(),
        frameFamilies(&.{ .control, .sync, .mooring }),
    );
    try std.testing.expectEqualSlices(u8, &node.public_key.toBytes(), &fields.node_pubkey);
}

test "bind decoded token rejects peer public key mismatch" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x33)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x34)));
    const other = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x35)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    try std.testing.expectError(error.PeerKeyMismatch, bindDecodedToken(
        token,
        issuer.public_key.toBytes(),
        2_000,
        other.public_key.toBytes(),
        frameFamilies(&.{.control}),
    ));
}

test "bind decoded token rejects missing required frame family" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x36)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x37)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    try std.testing.expectError(error.MissingFrameFamily, bindDecodedToken(
        token,
        issuer.public_key.toBytes(),
        2_000,
        node.public_key.toBytes(),
        frameFamilies(&.{ .control, .media }),
    ));
}

test "bind decoded token verifies signature before binding" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x38)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x39)));
    var token = try issue(issuer, sampleFields(node.public_key.toBytes()));
    token.fields.max_fanout += 1;

    try std.testing.expectError(error.BadSig, bindDecodedToken(
        token,
        issuer.public_key.toBytes(),
        2_000,
        node.public_key.toBytes(),
        frameFamilies(&.{.control}),
    ));
}

test "tampered field or signature fails as BadSig" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x12)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x23)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    var tampered_field = token;
    tampered_field.fields.max_fanout += 1;
    try std.testing.expectError(error.BadSig, verify(tampered_field, issuer.public_key.toBytes(), 2_000));

    var tampered_sig = token;
    tampered_sig.signature[0] ^= 0x80;
    try std.testing.expectError(error.BadSig, verify(tampered_sig, issuer.public_key.toBytes(), 2_000));
}

test "expired token fails as Expired" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x13)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x24)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    try std.testing.expectError(error.Expired, verify(token, issuer.public_key.toBytes(), 10_001));
}

test "not-yet-valid token fails as Expired" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x15)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x26)));
    // sampleFields issues at 1_000ms; a clock before the not-before must be rejected.
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    try std.testing.expectError(error.Expired, verify(token, issuer.public_key.toBytes(), 999));
    // A clock exactly at issued_ms (and within expiry) is valid.
    try verify(token, issuer.public_key.toBytes(), 1_000);
    try verify(token, issuer.public_key.toBytes(), 2_000);
}

test "wrong realm fails as WrongRealm" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x14)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x25)));
    var fields = sampleFields(node.public_key.toBytes());
    fields.realm = "other";
    const token = try issue(issuer, fields);

    try std.testing.expectError(error.WrongRealm, verify(token, issuer.public_key.toBytes(), 2_000));
}

test "revoked epoch fails as Revoked" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x15)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x26)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));
    const root = TrustRoot{
        .public_key = issuer.public_key.toBytes(),
        .min_revocation_epoch = token.fields.revocation_epoch + 1,
    };

    try std.testing.expectError(error.Revoked, verify(token, root, 2_000));
}

test "canonical encoding is stable across decode and re-encode" {
    const issuer = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x16)));
    const node = try Ed25519.KeyPair.generateDeterministic(@as([32]u8, @splat(0x27)));
    const token = try issue(issuer, sampleFields(node.public_key.toBytes()));

    var a_buf: [max_token_len]u8 = undefined;
    const a = a_buf[0..try encode(&a_buf, token)];
    const decoded = try decode(a);

    var b_buf: [max_token_len]u8 = undefined;
    const b = b_buf[0..try encode(&b_buf, decoded)];

    try std.testing.expect(coilpack.canonicalEqual(a, b));
    try verify(decoded, issuer.public_key.toBytes(), 2_000);

    var signed_a_buf: [max_signed_len]u8 = undefined;
    const signed_a = signed_a_buf[0..try encodeSignedFields(&signed_a_buf, decoded.fields)];
    const signed_decoded = try decodeSignedFields(signed_a);
    var signed_b_buf: [max_signed_len]u8 = undefined;
    const signed_b = signed_b_buf[0..try encodeSignedFields(&signed_b_buf, signed_decoded)];
    try std.testing.expect(coilpack.canonicalEqual(signed_a, signed_b));
}
