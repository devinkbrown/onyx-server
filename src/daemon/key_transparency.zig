// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account key-transparency append log.
//!
//! This is the server-side substrate for the roadmap's verifiable-identity
//! work: account credential changes become canonical events, event digests are
//! appended to a Merkle Mountain Range, and callers can return inclusion proofs
//! for a leaf/root/size tuple. The service layer owns when events are emitted;
//! this module owns stable hashing and proof verification.

const std = @import("std");
const mmr = @import("../substrate/merkle_mountain_range.zig");

const Blake3 = std.crypto.hash.Blake3;

pub const Hash = [Blake3.digest_length]u8;

pub const CredentialKind = enum(u8) {
    certfp = 1,
    webauthn = 2,
    e2ee_device = 3,
    identity = 4,
};

pub const Action = enum(u8) {
    bind = 1,
    delete = 2,
};

pub const Event = struct {
    account: []const u8,
    kind: CredentialKind,
    action: Action,
    /// Stable credential identifier: certfp hex for CERTADD, credential-id b64
    /// for WebAuthn.
    key_id: []const u8,
    /// Hash of the credential material. For certfp this is BLAKE3(certfp); for
    /// WebAuthn this is BLAKE3(raw COSE public key). Deletes may reuse key_id.
    key_hash: Hash,
    timestamp_ms: i64 = 0,
};

pub const AppendResult = struct {
    position: usize,
    size: usize,
    root: mmr.Hash,
    leaf: mmr.Hash,
};

pub const KeyTransparencyLog = struct {
    tree: mmr.MerkleMountainRange,

    pub fn init(allocator: std.mem.Allocator) KeyTransparencyLog {
        return .{ .tree = mmr.MerkleMountainRange.init(allocator) };
    }

    pub fn deinit(self: *KeyTransparencyLog) void {
        self.tree.deinit();
        self.* = undefined;
    }

    pub fn len(self: *const KeyTransparencyLog) usize {
        return self.tree.len();
    }

    pub fn root(self: *const KeyTransparencyLog) mmr.Hash {
        return self.tree.root();
    }

    pub fn append(self: *KeyTransparencyLog, event: Event) !AppendResult {
        const leaf = eventDigest(event);
        const pos = try self.tree.append(&leaf);
        return .{
            .position = pos,
            .size = self.tree.len(),
            .root = self.tree.root(),
            .leaf = leaf,
        };
    }

    pub fn proof(self: *const KeyTransparencyLog, position: usize) !mmr.Proof {
        return self.tree.proof(position);
    }
};

pub fn eventDigest(event: Event) Hash {
    var h = Blake3.init(.{});
    h.update("ONYX-KT-EVENT-v1");
    updateInt(u8, &h, @intFromEnum(event.kind));
    updateInt(u8, &h, @intFromEnum(event.action));
    updateBytes(&h, event.account);
    updateBytes(&h, event.key_id);
    h.update(&event.key_hash);
    updateInt(i64, &h, event.timestamp_ms);
    var out: Hash = undefined;
    h.final(&out);
    return out;
}

pub fn materialHash(material: []const u8) Hash {
    var out: Hash = undefined;
    Blake3.hash(material, &out, .{});
    return out;
}

pub fn verifyInclusion(root: mmr.Hash, event: Event, proof: mmr.Proof, position: usize, size: usize) bool {
    const leaf = eventDigest(event);
    return mmr.verify(root, &leaf, proof, position, size);
}

fn updateBytes(h: *Blake3, bytes: []const u8) void {
    updateInt(u64, h, bytes.len);
    h.update(bytes);
}

fn updateInt(comptime T: type, h: *Blake3, value: T) void {
    var buf: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .little);
    h.update(&buf);
}

test "key transparency appends credential events and verifies inclusion" {
    var log = KeyTransparencyLog.init(std.testing.allocator);
    defer log.deinit();

    const e1 = Event{
        .account = "alice",
        .kind = .certfp,
        .action = .bind,
        .key_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .key_hash = materialHash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        .timestamp_ms = 10,
    };
    const e2 = Event{
        .account = "alice",
        .kind = .webauthn,
        .action = .bind,
        .key_id = "credAAA",
        .key_hash = materialHash("cose-key"),
        .timestamp_ms = 20,
    };

    const r1 = try log.append(e1);
    const r2 = try log.append(e2);
    try std.testing.expectEqual(@as(usize, 0), r1.position);
    try std.testing.expectEqual(@as(usize, 2), r2.size);
    try std.testing.expect(!std.mem.eql(u8, &r1.root, &r2.root));

    var proof = try log.proof(1);
    defer proof.deinit(std.testing.allocator);
    try std.testing.expect(verifyInclusion(r2.root, e2, proof, 1, r2.size));
    try std.testing.expect(!verifyInclusion(r2.root, e1, proof, 1, r2.size));
}

test "event digest is length framed" {
    const a = Event{
        .account = "ab",
        .kind = .certfp,
        .action = .bind,
        .key_id = "c",
        .key_hash = materialHash("k"),
    };
    const b = Event{
        .account = "a",
        .kind = .certfp,
        .action = .bind,
        .key_id = "bc",
        .key_hash = materialHash("k"),
    };
    try std.testing.expect(!std.mem.eql(u8, &eventDigest(a), &eventDigest(b)));
}

test "event digest domain-separates E2EE device and identity credentials" {
    const base = Event{
        .account = "alice",
        .kind = .e2ee_device,
        .action = .bind,
        .key_id = "phone",
        .key_hash = materialHash("mls-x25519:device-public-key"),
        .timestamp_ms = 42,
    };
    var identity = base;
    identity.kind = .identity;
    try std.testing.expect(!std.mem.eql(
        u8,
        &eventDigest(base),
        &eventDigest(identity),
    ));
}
