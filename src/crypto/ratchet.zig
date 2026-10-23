// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-contained symmetric + X25519 double ratchet for Onyx Server channels.
const std = @import("std");
const zig_compat = @import("zig_compat.zig");

const X25519 = std.crypto.dh.X25519;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Key = [32]u8;
pub const PublicKey = [32]u8;
pub const header_len = 40;

pub const RatchetError = error{
    AuthenticationFailed,
    CiphertextTooShort,
    DuplicateOrStaleMessage,
    LowOrderPoint,
    MissingDhKeyPair,
    MissingReceiveChain,
    MissingSendChain,
    SkipLimitExceeded,
};

pub const RootKey = struct {
    bytes: Key,

    pub fn init(bytes: Key) RootKey {
        return .{ .bytes = bytes };
    }

    fn derive(self: RootKey, dh_output: Key) RootStep {
        var out: [64]u8 = undefined;
        hkdf(&out, &self.bytes, &dh_output, "onyx ratchet root v1");
        return .{
            .root = .{ .bytes = out[0..32].* },
            .chain = .{ .bytes = out[32..64].* },
        };
    }
};

pub const ChainKey = struct {
    bytes: Key,

    pub fn init(bytes: Key) ChainKey {
        return .{ .bytes = bytes };
    }

    pub fn advance(self: *ChainKey) Key {
        var out: [64]u8 = undefined;
        hkdf(&out, "onyx ratchet chain salt v1", &self.bytes, "message");
        self.bytes = out[32..64].*;
        return out[0..32].*;
    }
};

pub const Header = struct {
    dh_pub: PublicKey,
    pn: u32,
    n: u32,

    pub fn encode(self: Header) [header_len]u8 {
        var out: [header_len]u8 = undefined;
        @memcpy(out[0..32], &self.dh_pub);
        std.mem.writeInt(u32, out[32..36], self.pn, .little);
        std.mem.writeInt(u32, out[36..40], self.n, .little);
        return out;
    }
};

pub const SealedMessage = struct {
    header: Header,
    ciphertext: []u8,

    pub fn deinit(self: SealedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.ciphertext);
    }
};

pub const Ratchet = struct {
    allocator: std.mem.Allocator,
    root_key: RootKey,
    dh_pair: X25519.KeyPair,
    remote_pub: ?PublicKey,
    send_chain: ?ChainKey,
    recv_chain: ?ChainKey,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: std.ArrayList(SkippedKey),
    max_skip: u32,
    next_dh_pair: ?X25519.KeyPair,

    pub fn initAlice(
        allocator: std.mem.Allocator,
        root_key: RootKey,
        own_pair: X25519.KeyPair,
        remote_pub: PublicKey,
        max_skip: u32,
    ) !Ratchet {
        const dh_output = try dh(own_pair.secret_key, remote_pub);
        const step = root_key.derive(dh_output);
        return .{
            .allocator = allocator,
            .root_key = step.root,
            .dh_pair = own_pair,
            .remote_pub = remote_pub,
            .send_chain = step.chain,
            .recv_chain = null,
            .ns = 0,
            .nr = 0,
            .pn = 0,
            .skipped = .empty,
            .max_skip = max_skip,
            .next_dh_pair = null,
        };
    }

    pub fn initBob(
        allocator: std.mem.Allocator,
        root_key: RootKey,
        own_pair: X25519.KeyPair,
        max_skip: u32,
    ) Ratchet {
        return .{
            .allocator = allocator,
            .root_key = root_key,
            .dh_pair = own_pair,
            .remote_pub = null,
            .send_chain = null,
            .recv_chain = null,
            .ns = 0,
            .nr = 0,
            .pn = 0,
            .skipped = .empty,
            .max_skip = max_skip,
            .next_dh_pair = null,
        };
    }

    pub fn deinit(self: *Ratchet) void {
        self.skipped.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn setNextDhKeyPair(self: *Ratchet, pair: X25519.KeyPair) void {
        self.next_dh_pair = pair;
    }

    pub fn encrypt(self: *Ratchet, plaintext: []const u8, associated_data: []const u8) !SealedMessage {
        const chain = self.send_chain orelse return error.MissingSendChain;
        const header = Header{
            .dh_pub = self.dh_pair.public_key,
            .pn = self.pn,
            .n = self.ns,
        };
        const aad = try makeAad(self.allocator, header, associated_data);
        defer self.allocator.free(aad);

        var ciphertext = try self.allocator.alloc(u8, plaintext.len + Aead.tag_length);
        errdefer self.allocator.free(ciphertext);

        var live_chain = chain;
        const message_key = live_chain.advance();
        const material = messageMaterial(message_key);
        var tag: [Aead.tag_length]u8 = undefined;
        Aead.encrypt(ciphertext[0..plaintext.len], &tag, plaintext, aad, material.nonce, material.key);
        @memcpy(ciphertext[plaintext.len..], &tag);

        self.send_chain = live_chain;
        self.ns += 1;
        return .{ .header = header, .ciphertext = ciphertext };
    }

    pub fn decrypt(
        self: *Ratchet,
        header: Header,
        ciphertext: []const u8,
        associated_data: []const u8,
    ) ![]u8 {
        if (try self.trySkipped(header, ciphertext, associated_data)) |plaintext| {
            return plaintext;
        }

        if (self.remote_pub == null or !std.mem.eql(u8, &self.remote_pub.?, &header.dh_pub)) {
            try self.dhRatchet(header.dh_pub, header.pn);
        }

        try self.skipMessageKeys(header.n);
        if (header.n < self.nr) return error.DuplicateOrStaleMessage;

        // Derive the message key from a COPY of the chain and verify before
        // committing: a forged/corrupt in-order packet must not advance (and thus
        // desync) the receive chain so the genuine packet stays decryptable.
        var advanced = self.recv_chain orelse return error.MissingReceiveChain;
        const message_key = advanced.advance();
        const plaintext = try open(self.allocator, message_key, header, ciphertext, associated_data);
        self.recv_chain = advanced;
        self.nr += 1;
        return plaintext;
    }

    fn dhRatchet(self: *Ratchet, remote_pub: PublicKey, previous_send_count: u32) !void {
        try self.skipMessageKeys(previous_send_count);

        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.remote_pub = remote_pub;

        const recv_dh = try dh(self.dh_pair.secret_key, remote_pub);
        const recv_step = self.root_key.derive(recv_dh);
        self.root_key = recv_step.root;
        self.recv_chain = recv_step.chain;

        const next_pair = self.next_dh_pair orelse return error.MissingDhKeyPair;
        self.next_dh_pair = null;
        self.dh_pair = next_pair;

        const send_dh = try dh(self.dh_pair.secret_key, remote_pub);
        const send_step = self.root_key.derive(send_dh);
        self.root_key = send_step.root;
        self.send_chain = send_step.chain;
    }

    fn skipMessageKeys(self: *Ratchet, until: u32) !void {
        if (until < self.nr) return;
        if (until - self.nr > self.max_skip) return error.SkipLimitExceeded;
        if (until == self.nr) return;

        var chain = self.recv_chain orelse return error.MissingReceiveChain;
        const remote_pub = self.remote_pub orelse return error.MissingReceiveChain;
        while (self.nr < until) : (self.nr += 1) {
            const key = chain.advance();
            // Bound retained skipped keys independently of the per-gap limit by
            // evicting the oldest, rather than rejecting an otherwise-valid gap
            // once the store filled from earlier ratchet steps.
            if (self.skipped.items.len >= self.max_skip) _ = self.skipped.orderedRemove(0);
            try self.skipped.append(self.allocator, .{
                .dh_pub = remote_pub,
                .n = self.nr,
                .key = key,
            });
        }
        self.recv_chain = chain;
    }

    fn trySkipped(
        self: *Ratchet,
        header: Header,
        ciphertext: []const u8,
        associated_data: []const u8,
    ) !?[]u8 {
        var i: usize = 0;
        while (i < self.skipped.items.len) : (i += 1) {
            const skipped = self.skipped.items[i];
            if (skipped.n == header.n and std.mem.eql(u8, &skipped.dh_pub, &header.dh_pub)) {
                const plaintext = try open(self.allocator, skipped.key, header, ciphertext, associated_data);
                _ = self.skipped.swapRemove(i);
                return plaintext;
            }
        }
        return null;
    }
};

const RootStep = struct {
    root: RootKey,
    chain: ChainKey,
};

const SkippedKey = struct {
    dh_pub: PublicKey,
    n: u32,
    key: Key,
};

const MessageMaterial = struct {
    key: [Aead.key_length]u8,
    nonce: [Aead.nonce_length]u8,
};

fn hkdf(out: []u8, salt: []const u8, ikm: []const u8, info: []const u8) void {
    const prk = HkdfSha256.extract(salt, ikm);
    HkdfSha256.expand(out, info, prk);
}

fn dh(secret_key: Key, public_key: PublicKey) !Key {
    const out = X25519.scalarmult(secret_key, public_key) catch return error.LowOrderPoint;
    if (allZero(&out)) return error.LowOrderPoint;
    return out;
}

fn allZero(bytes: []const u8) bool {
    var acc: u8 = 0;
    for (bytes) |b| acc |= b;
    return acc == 0;
}

fn messageMaterial(message_key: Key) MessageMaterial {
    var out: [Aead.key_length + Aead.nonce_length]u8 = undefined;
    hkdf(&out, "onyx ratchet message salt v1", &message_key, "aead");
    return .{
        .key = out[0..Aead.key_length].*,
        .nonce = out[Aead.key_length..][0..Aead.nonce_length].*,
    };
}

fn makeAad(allocator: std.mem.Allocator, header: Header, associated_data: []const u8) ![]u8 {
    const encoded = header.encode();
    var aad = try allocator.alloc(u8, associated_data.len + encoded.len);
    @memcpy(aad[0..associated_data.len], associated_data);
    @memcpy(aad[associated_data.len..], &encoded);
    return aad;
}

fn open(
    allocator: std.mem.Allocator,
    message_key: Key,
    header: Header,
    ciphertext: []const u8,
    associated_data: []const u8,
) ![]u8 {
    if (ciphertext.len < Aead.tag_length) return error.CiphertextTooShort;
    const body_len = ciphertext.len - Aead.tag_length;
    const tag = ciphertext[body_len..][0..Aead.tag_length].*;
    const aad = try makeAad(allocator, header, associated_data);
    defer allocator.free(aad);

    const plaintext = try allocator.alloc(u8, body_len);
    errdefer allocator.free(plaintext);

    const material = messageMaterial(message_key);
    Aead.decrypt(plaintext, ciphertext[0..body_len], tag, aad, material.nonce, material.key) catch {
        return error.AuthenticationFailed;
    };
    return plaintext;
}

fn seed(byte: u8) [32]u8 {
    return @as([32]u8, @splat(byte));
}

fn rootForTests() RootKey {
    var root = seed(0x42);
    root[0] = 0xa5;
    root[31] = 0x5a;
    return .init(root);
}

fn kp(byte: u8) !X25519.KeyPair {
    return try zig_compat.x25519GenerateDeterministic(seed(byte));
}

fn pairForTests(max_skip: u32) !struct { alice: Ratchet, bob: Ratchet } {
    const allocator = std.testing.allocator;
    const a0 = try kp(1);
    const b0 = try kp(2);
    const a1 = try kp(3);
    const b1 = try kp(4);
    var alice = try Ratchet.initAlice(allocator, rootForTests(), a0, b0.public_key, max_skip);
    var bob = Ratchet.initBob(allocator, rootForTests(), b0, max_skip);
    alice.setNextDhKeyPair(a1);
    bob.setNextDhKeyPair(b1);
    return .{ .alice = alice, .bob = bob };
}

test "chain key advances to distinct message keys" {
    var ck = ChainKey.init(seed(9));
    const first = ck.advance();
    const second = ck.advance();
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expect(!std.mem.eql(u8, &first, &ck.bytes));
}

test "in-order exchange both directions and first reply advances DH ratchet" {
    var pair = try pairForTests(8);
    defer pair.alice.deinit();
    defer pair.bob.deinit();

    const ad = "session transcript";
    const m1 = try pair.alice.encrypt("hello bob", ad);
    defer m1.deinit(std.testing.allocator);
    const p1 = try pair.bob.decrypt(m1.header, m1.ciphertext, ad);
    defer std.testing.allocator.free(p1);
    try std.testing.expectEqualStrings("hello bob", p1);

    const bob_dh_after_receive = pair.bob.dh_pair.public_key;
    try std.testing.expect(!std.mem.eql(u8, &bob_dh_after_receive, &m1.header.dh_pub));

    const m2 = try pair.bob.encrypt("hello alice", ad);
    defer m2.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.eql(u8, &m2.header.dh_pub, &bob_dh_after_receive));

    const p2 = try pair.alice.decrypt(m2.header, m2.ciphertext, ad);
    defer std.testing.allocator.free(p2);
    try std.testing.expectEqualStrings("hello alice", p2);
}

test "out-of-order messages within skip bound are recovered" {
    var pair = try pairForTests(4);
    defer pair.alice.deinit();
    defer pair.bob.deinit();

    const first = try pair.alice.encrypt("one", "ad");
    defer first.deinit(std.testing.allocator);
    const second = try pair.alice.encrypt("two", "ad");
    defer second.deinit(std.testing.allocator);
    const third = try pair.alice.encrypt("three", "ad");
    defer third.deinit(std.testing.allocator);

    const p3 = try pair.bob.decrypt(third.header, third.ciphertext, "ad");
    defer std.testing.allocator.free(p3);
    try std.testing.expectEqualStrings("three", p3);

    const p1 = try pair.bob.decrypt(first.header, first.ciphertext, "ad");
    defer std.testing.allocator.free(p1);
    try std.testing.expectEqualStrings("one", p1);

    const p2 = try pair.bob.decrypt(second.header, second.ciphertext, "ad");
    defer std.testing.allocator.free(p2);
    try std.testing.expectEqualStrings("two", p2);
}

test "ciphertext associated data and header tampering are rejected" {
    {
        var pair = try pairForTests(4);
        defer pair.alice.deinit();
        defer pair.bob.deinit();
        const msg = try pair.alice.encrypt("secret", "ad");
        defer msg.deinit(std.testing.allocator);
        msg.ciphertext[0] ^= 1;
        try std.testing.expectError(error.AuthenticationFailed, pair.bob.decrypt(msg.header, msg.ciphertext, "ad"));
    }
    {
        var pair = try pairForTests(4);
        defer pair.alice.deinit();
        defer pair.bob.deinit();
        const msg = try pair.alice.encrypt("secret", "ad");
        defer msg.deinit(std.testing.allocator);
        try std.testing.expectError(error.AuthenticationFailed, pair.bob.decrypt(msg.header, msg.ciphertext, "wrong ad"));
    }
    {
        var pair = try pairForTests(4);
        defer pair.alice.deinit();
        defer pair.bob.deinit();
        const msg = try pair.alice.encrypt("secret", "ad");
        defer msg.deinit(std.testing.allocator);
        var bad_header = msg.header;
        bad_header.n += 1;
        try std.testing.expectError(error.AuthenticationFailed, pair.bob.decrypt(bad_header, msg.ciphertext, "ad"));
    }
}

test "skip bound rejects large out-of-order gaps" {
    var pair = try pairForTests(2);
    defer pair.alice.deinit();
    defer pair.bob.deinit();

    var messages: std.ArrayList(SealedMessage) = .empty;
    defer {
        for (messages.items) |msg| msg.deinit(std.testing.allocator);
        messages.deinit(std.testing.allocator);
    }

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        try messages.append(std.testing.allocator, try pair.alice.encrypt("gap", "ad"));
    }
    const latest = messages.items[4];
    try std.testing.expectError(error.SkipLimitExceeded, pair.bob.decrypt(latest.header, latest.ciphertext, "ad"));
}

test "deterministic with fixed X25519 key pairs" {
    var first = try pairForTests(8);
    defer first.alice.deinit();
    defer first.bob.deinit();
    var second = try pairForTests(8);
    defer second.alice.deinit();
    defer second.bob.deinit();

    const a = try first.alice.encrypt("repeatable", "ad");
    defer a.deinit(std.testing.allocator);
    const b = try second.alice.encrypt("repeatable", "ad");
    defer b.deinit(std.testing.allocator);

    try std.testing.expectEqual(a.header, b.header);
    try std.testing.expectEqualSlices(u8, a.ciphertext, b.ciphertext);
}
