// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rolling-safe textual envelope for attachment-scoped session resume.
//!
//! The envelope is intentionally opaque: this module validates and separates
//! the local reusable-token form from the already-sealed mesh credential, but
//! it never opens or reinterprets mesh authority. Physical identity uses the
//! same nonzero `AttachmentId` type as SRM2 claims.

const std = @import("std");
const reclaim_attachment = @import("session_reclaim_attachment.zig");

pub const GroupToken = reclaim_attachment.GroupToken;
pub const AttachmentId = reclaim_attachment.AttachmentId;

pub const local_prefix = "srm2l";
pub const mesh_prefix = "srm2m";
pub const token_hex_len: usize = @sizeOf(GroupToken) * 2;
pub const attachment_hex_len: usize = @sizeOf(AttachmentId) * 2;
pub const local_text_len: usize = local_prefix.len + 1 + token_hex_len + 1 + attachment_hex_len;

pub const DecodeError = error{
    InvalidFormat,
    InvalidPrefix,
    InvalidLength,
    InvalidHex,
    NonCanonical,
    ZeroGroupToken,
    ZeroAttachmentId,
    ZeroSealedCredential,
};

pub const EncodeError = DecodeError || error{BufferTooSmall};

pub const Local = struct {
    group_token: GroupToken,
    attachment_id: AttachmentId,
};

pub const Mesh = struct {
    /// Borrowed canonical lowercase hex for the existing sealed mesh token.
    sealed_hex: []const u8,
    attachment_id: AttachmentId,
};

pub const Credential = union(enum) {
    local: Local,
    mesh: Mesh,
};

/// Decode exactly three dot-separated fields. No compatibility fallback,
/// whitespace trimming, case normalization, or ignored suffix is permitted.
pub fn decode(text: []const u8) DecodeError!Credential {
    const first_dot = std.mem.indexOfScalar(u8, text, '.') orelse return error.InvalidFormat;
    const second_rel = std.mem.indexOfScalar(u8, text[first_dot + 1 ..], '.') orelse return error.InvalidFormat;
    const second_dot = first_dot + 1 + second_rel;
    if (std.mem.indexOfScalar(u8, text[second_dot + 1 ..], '.') != null) return error.InvalidFormat;

    const prefix = text[0..first_dot];
    const authority = text[first_dot + 1 .. second_dot];
    const attachment_hex = text[second_dot + 1 ..];
    const attachment_id = try parseAttachment(attachment_hex);

    if (std.mem.eql(u8, prefix, local_prefix)) {
        return .{ .local = .{
            .group_token = try parseGroupToken(authority),
            .attachment_id = attachment_id,
        } };
    }
    if (std.mem.eql(u8, prefix, mesh_prefix)) {
        try validateSealedHex(authority);
        return .{ .mesh = .{
            .sealed_hex = authority,
            .attachment_id = attachment_id,
        } };
    }
    return error.InvalidPrefix;
}

/// Produce the fixed-width local credential in canonical lowercase form.
pub fn encodeLocal(group_token: GroupToken, attachment_id: AttachmentId) EncodeError![local_text_len]u8 {
    if (std.mem.allEqual(u8, &group_token, 0)) return error.ZeroGroupToken;
    if (attachment_id.isZero()) return error.ZeroAttachmentId;
    const group_hex = std.fmt.bytesToHex(group_token, .lower);
    const attachment_hex = attachment_id.toHex();
    var out: [local_text_len]u8 = undefined;
    var pos: usize = 0;
    append(&out, &pos, local_prefix);
    append(&out, &pos, ".");
    append(&out, &pos, &group_hex);
    append(&out, &pos, ".");
    append(&out, &pos, &attachment_hex);
    std.debug.assert(pos == out.len);
    return out;
}

/// Wrap an existing sealed mesh credential without decoding or resigning it.
/// The sealed token must already be canonical lowercase hex.
pub fn encodeMesh(out: []u8, sealed_hex: []const u8, attachment_id: AttachmentId) EncodeError![]const u8 {
    try validateSealedHex(sealed_hex);
    if (attachment_id.isZero()) return error.ZeroAttachmentId;
    const needed = mesh_prefix.len + 1 + sealed_hex.len + 1 + attachment_hex_len;
    if (out.len < needed) return error.BufferTooSmall;
    const attachment_hex = attachment_id.toHex();
    var pos: usize = 0;
    append(out[0..needed], &pos, mesh_prefix);
    append(out[0..needed], &pos, ".");
    append(out[0..needed], &pos, sealed_hex);
    append(out[0..needed], &pos, ".");
    append(out[0..needed], &pos, &attachment_hex);
    std.debug.assert(pos == needed);
    return out[0..needed];
}

fn parseGroupToken(text: []const u8) DecodeError!GroupToken {
    if (text.len != token_hex_len) return error.InvalidLength;
    try validateCanonicalHex(text);
    var token: GroupToken = undefined;
    _ = std.fmt.hexToBytes(&token, text) catch return error.InvalidHex;
    if (std.mem.allEqual(u8, &token, 0)) return error.ZeroGroupToken;
    return token;
}

fn parseAttachment(text: []const u8) DecodeError!AttachmentId {
    if (text.len != attachment_hex_len) return error.InvalidLength;
    try validateCanonicalHex(text);
    return AttachmentId.parseHex(text) catch |err| switch (err) {
        error.ZeroAttachmentId => error.ZeroAttachmentId,
        error.InvalidLength => error.InvalidLength,
        error.InvalidHex => error.InvalidHex,
    };
}

fn validateSealedHex(text: []const u8) DecodeError!void {
    if (text.len == 0 or text.len % 2 != 0) return error.InvalidLength;
    try validateCanonicalHex(text);
    if (std.mem.allEqual(u8, text, '0')) return error.ZeroSealedCredential;
}

fn validateCanonicalHex(text: []const u8) DecodeError!void {
    for (text) |ch| switch (ch) {
        '0'...'9', 'a'...'f' => {},
        'A'...'F' => return error.NonCanonical,
        else => return error.InvalidHex,
    };
}

fn append(out: []u8, pos: *usize, bytes: []const u8) void {
    @memcpy(out[pos.*..][0..bytes.len], bytes);
    pos.* += bytes.len;
}

fn testAttachment(byte: u8) AttachmentId {
    return AttachmentId.fromBytes(@as([16]u8, @splat(byte))) catch unreachable;
}

test "session resume credential local form round-trips canonically" {
    const token: GroupToken = @splat(0xab);
    const attachment = testAttachment(0xcd);
    const encoded = try encodeLocal(token, attachment);
    try std.testing.expectEqualStrings(
        "srm2l.abababababababababababababababab.cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        &encoded,
    );
    const decoded = try decode(&encoded);
    try std.testing.expectEqual(token, decoded.local.group_token);
    try std.testing.expect(decoded.local.attachment_id.eql(attachment));
}

test "session resume credential mesh form preserves existing sealed hex exactly" {
    const attachment = testAttachment(0x22);
    var storage: [160]u8 = undefined;
    const encoded = try encodeMesh(&storage, "53524d01010203aabbcc", attachment);
    const decoded = try decode(encoded);
    try std.testing.expectEqualStrings("53524d01010203aabbcc", decoded.mesh.sealed_hex);
    try std.testing.expect(decoded.mesh.attachment_id.eql(attachment));
}

test "session resume credential rejects malformed trailing noncanonical and zero fields" {
    const cases = [_]struct { text: []const u8, err: DecodeError }{
        .{ .text = "", .err = error.InvalidFormat },
        .{ .text = "srm2l", .err = error.InvalidFormat },
        .{ .text = "srm2l..", .err = error.InvalidLength },
        .{ .text = "srm2x.11111111111111111111111111111111.22222222222222222222222222222222", .err = error.InvalidPrefix },
        .{ .text = "srm2l.1111111111111111111111111111111.22222222222222222222222222222222", .err = error.InvalidLength },
        .{ .text = "srm2l.1111111111111111111111111111111g.22222222222222222222222222222222", .err = error.InvalidHex },
        .{ .text = "srm2l.1111111111111111111111111111111A.22222222222222222222222222222222", .err = error.NonCanonical },
        .{ .text = "srm2l.11111111111111111111111111111111.2222222222222222222222222222222A", .err = error.NonCanonical },
        .{ .text = "srm2l.00000000000000000000000000000000.22222222222222222222222222222222", .err = error.ZeroGroupToken },
        .{ .text = "srm2l.11111111111111111111111111111111.00000000000000000000000000000000", .err = error.ZeroAttachmentId },
        .{ .text = "srm2m..22222222222222222222222222222222", .err = error.InvalidLength },
        .{ .text = "srm2m.0.22222222222222222222222222222222", .err = error.InvalidLength },
        .{ .text = "srm2m.00.22222222222222222222222222222222", .err = error.ZeroSealedCredential },
        .{ .text = "srm2m.aA.22222222222222222222222222222222", .err = error.NonCanonical },
        .{ .text = "srm2m.ag.22222222222222222222222222222222", .err = error.InvalidHex },
        .{ .text = "srm2l.11111111111111111111111111111111.22222222222222222222222222222222.trailing", .err = error.InvalidFormat },
    };
    for (cases) |case| try std.testing.expectError(case.err, decode(case.text));
}

test "session resume credential encoders reject reserved identities and undersized output" {
    const zero_token: GroupToken = @splat(0);
    const zero_attachment = AttachmentId{ .raw = @splat(0) };
    try std.testing.expectError(error.ZeroGroupToken, encodeLocal(zero_token, testAttachment(1)));
    try std.testing.expectError(error.ZeroAttachmentId, encodeLocal(@splat(1), zero_attachment));
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encodeMesh(&tiny, "abcd", testAttachment(2)));
    try std.testing.expectError(error.ZeroSealedCredential, encodeMesh(&tiny, "00", testAttachment(2)));
}
