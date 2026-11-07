// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable mesh presence authority carried across a Linux Helix UPGRADE.
//!
//! The predecessor captures `Authority.captureHotCheckpoint()` under the parked
//! seal cut and carries one non-CLOEXEC duplicate of its exclusive WAL lease in
//! the authoritative state-fd manifest. The successor never cold-opens the
//! store (which would advance the issuer epoch); it stages
//! `HotAuthorityStage.prepare` from this exact checkpoint and the inherited
//! lease, then activates only at the no-fail adoption commit edge.
//!
//! The payload is a magic-discriminated inner family of the generic
//! `.mesh_checkpoint` capsule, so the handoff manifest format is unchanged.
//!
//! Wire format (fixed size, integers little-endian):
//!   [magic "HXMP"][u8 version=1][u32 lease_fd_index]
//!   [u64 device][u64 inode][u64 inode_high]
//!   [32 origin][32 realm][16 store_id][32 head_digest]
//!   [u64 commit_generation][u64 image_generation]
const std = @import("std");
const authority = @import("../mesh_presence_authority.zig");

pub const Error = error{ Truncated, BadMagic, UnsupportedVersion, TrailingBytes, InvalidCheckpoint };

pub const magic = [_]u8{ 'H', 'X', 'M', 'P' };
pub const version: u8 = 1;
pub const encoded_len: usize = magic.len + 1 + 4 + 8 * 3 + 32 + 32 + 16 + 32 + 8 * 2;

pub const Carried = struct {
    lease_fd_index: u32,
    checkpoint: authority.HotCheckpoint,
};

pub fn isCheckpoint(bytes: []const u8) bool {
    return bytes.len >= magic.len and std.mem.eql(u8, bytes[0..magic.len], &magic);
}

pub fn encode(value: Carried) Error![encoded_len]u8 {
    try validate(value.checkpoint);
    var out: [encoded_len]u8 = undefined;
    var w: usize = 0;
    @memcpy(out[w..][0..magic.len], &magic);
    w += magic.len;
    out[w] = version;
    w += 1;
    std.mem.writeInt(u32, out[w..][0..4], value.lease_fd_index, .little);
    w += 4;
    const c = value.checkpoint;
    inline for (.{ c.lease_identity.device, c.lease_identity.inode, c.lease_identity.inode_high }) |v| {
        std.mem.writeInt(u64, out[w..][0..8], v, .little);
        w += 8;
    }
    inline for (.{ &c.context.origin, &c.context.realm, &c.store_id, &c.head_digest }) |bytes| {
        @memcpy(out[w..][0..bytes.len], bytes);
        w += bytes.len;
    }
    std.mem.writeInt(u64, out[w..][0..8], c.commit_generation, .little);
    w += 8;
    std.mem.writeInt(u64, out[w..][0..8], c.image_generation, .little);
    w += 8;
    std.debug.assert(w == encoded_len);
    return out;
}

pub fn decode(bytes: []const u8) Error!Carried {
    if (bytes.len < magic.len + 1) return error.Truncated;
    if (!isCheckpoint(bytes)) return error.BadMagic;
    if (bytes[magic.len] != version) return error.UnsupportedVersion;
    if (bytes.len < encoded_len) return error.Truncated;
    if (bytes.len != encoded_len) return error.TrailingBytes;
    var r: usize = magic.len + 1;
    const index = std.mem.readInt(u32, bytes[r..][0..4], .little);
    r += 4;
    var c: authority.HotCheckpoint = undefined;
    c.lease_identity.device = std.mem.readInt(u64, bytes[r..][0..8], .little);
    r += 8;
    c.lease_identity.inode = std.mem.readInt(u64, bytes[r..][0..8], .little);
    r += 8;
    c.lease_identity.inode_high = std.mem.readInt(u64, bytes[r..][0..8], .little);
    r += 8;
    inline for (.{ &c.context.origin, &c.context.realm, &c.store_id, &c.head_digest }) |dest| {
        @memcpy(dest, bytes[r..][0..dest.len]);
        r += dest.len;
    }
    c.commit_generation = std.mem.readInt(u64, bytes[r..][0..8], .little);
    r += 8;
    c.image_generation = std.mem.readInt(u64, bytes[r..][0..8], .little);
    r += 8;
    std.debug.assert(r == encoded_len);
    try validate(c);
    return .{ .lease_fd_index = index, .checkpoint = c };
}

pub fn validateCheckpoint(bytes: []const u8) Error!void {
    _ = try decode(bytes);
}

/// Structural sanity only. Lease identity, head digest and generations are
/// authenticated against the live WAL by `HotAuthorityStage.prepare`.
fn validate(c: authority.HotCheckpoint) Error!void {
    if (c.lease_identity.inode == 0) return error.InvalidCheckpoint;
    if (std.mem.allEqual(u8, &c.store_id, 0)) return error.InvalidCheckpoint;
    if (std.mem.allEqual(u8, &c.context.origin, 0)) return error.InvalidCheckpoint;
}

fn sample() Carried {
    return .{ .lease_fd_index = 7, .checkpoint = .{
        .lease_identity = .{ .device = 0x10, .inode = 0x2233, .inode_high = 0 },
        .context = .{ .origin = @splat(0xa1), .realm = @splat(0xb2) },
        .store_id = @splat(0xc3),
        .head_digest = @splat(0xd4),
        .commit_generation = 9,
        .image_generation = 4,
    } };
}

test "mesh presence hot checkpoint round-trips exactly" {
    const value = sample();
    const wire = try encode(value);
    try std.testing.expect(isCheckpoint(&wire));
    try std.testing.expectEqualDeep(value, try decode(&wire));
}

test "mesh presence hot checkpoint rejects short, trailing, wrong version and empty identity" {
    const wire = try encode(sample());
    try std.testing.expectError(error.Truncated, decode(wire[0..3]));
    try std.testing.expectError(error.Truncated, decode(wire[0 .. encoded_len - 1]));
    var long: [encoded_len + 1]u8 = undefined;
    @memcpy(long[0..encoded_len], &wire);
    long[encoded_len] = 0;
    try std.testing.expectError(error.TrailingBytes, decode(&long));
    var bad = wire;
    bad[magic.len] = 2;
    try std.testing.expectError(error.UnsupportedVersion, decode(&bad));
    bad = wire;
    bad[0] = 'X';
    try std.testing.expectError(error.BadMagic, decode(&bad));
    var empty = sample();
    empty.checkpoint.store_id = @splat(0);
    try std.testing.expectError(error.InvalidCheckpoint, encode(empty));
    empty = sample();
    empty.checkpoint.lease_identity.inode = 0;
    try std.testing.expectError(error.InvalidCheckpoint, encode(empty));
}
