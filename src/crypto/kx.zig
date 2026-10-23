// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MOORING/TLS key exchange and key schedule.
//!
//! Zig 0.16 std was checked at `/usr/lib/zig/std/crypto`: ML-KEM is present
//! as `std.crypto.kem.ml_kem.MLKem768`, so this file implements the real
//! X25519 || ML-KEM-768 hybrid path. The hybrid combiner used here is Onyx Server's
//! MOORING v2 HMAC-based KDF: `HMAC(label, x25519_ss || mlkem_ss || transcript)`.
//! No ML-KEM code is hand-rolled.
const std = @import("std");
const hash = @import("hash.zig");
const Secret = @import("secret.zig").Secret;
const zig_compat = @import("zig_compat.zig");

const StdX25519 = std.crypto.dh.X25519;
const MlKem768 = std.crypto.kem.ml_kem.MLKem768;
const HmacSha256 = hash.HmacSha256;
const HkdfSha256 = hash.HkdfSha256;

pub const PublicKey = [32]u8;
pub const SecretKey = Secret([32]u8);
pub const SharedSecret = Secret([32]u8);
pub const RootKey = Secret([32]u8);
pub const ChainKey = Secret([32]u8);

pub const KeyExchangeError = error{
    LowOrderPoint,
};

pub const Role = enum {
    initiator,
    responder,
};

/// X25519 key exchange wrapper with MOORING's low-order shared-secret rejection.
pub const X25519Kx = struct {
    pub const public_len = StdX25519.public_length;
    pub const secret_len = StdX25519.secret_length;
    pub const shared_len = StdX25519.shared_length;
    pub const seed_len = StdX25519.seed_length;

    pub const KeyPair = struct {
        public_key: PublicKey,
        secret_key: SecretKey,

        pub fn wipe(self: *KeyPair) void {
            self.secret_key.wipe();
        }
    };

    pub fn generate(io: std.Io) KeyPair {
        const kp = StdX25519.KeyPair.generate(io);
        return .{
            .public_key = kp.public_key,
            .secret_key = SecretKey.init(kp.secret_key),
        };
    }

    pub fn generateDeterministic(seed: [seed_len]u8) !KeyPair {
        const kp = try zig_compat.x25519GenerateDeterministic(seed);
        return .{
            .public_key = kp.public_key,
            .secret_key = SecretKey.init(kp.secret_key),
        };
    }

    pub fn sharedSecret(secret_key: *const SecretKey, peer_public_key: PublicKey) !SharedSecret {
        var sk = secret_key.declassify();
        defer secureZero(&sk);

        const raw = StdX25519.scalarmult(sk, peer_public_key) catch return error.LowOrderPoint;
        try rejectAllZero(raw);
        return SharedSecret.init(raw);
    }
};

/// X25519 plus ML-KEM-768 hybrid key exchange.
///
/// The first flight advertises `PublicShare`. The peer replies with
/// `EncapsulatedShare`, and both sides combine the X25519 and ML-KEM shared
/// secrets with the public transcript bytes.
pub const HybridKx = struct {
    pub const MlKem = MlKem768;
    pub const mlkem_public_len = MlKem.PublicKey.encoded_length;
    pub const mlkem_secret_len = MlKem.SecretKey.encoded_length;
    pub const mlkem_ciphertext_len = MlKem.ciphertext_length;
    pub const mlkem_shared_len = MlKem.shared_length;
    pub const seed_len = X25519Kx.seed_len + MlKem.seed_length;
    pub const encaps_seed_len = MlKem.encaps_seed_length;

    pub const KeyPair = struct {
        x25519: X25519Kx.KeyPair,
        mlkem: MlKem.KeyPair,

        pub fn publicShare(self: *const KeyPair) PublicShare {
            return .{
                .x25519_public_key = self.x25519.public_key,
                .mlkem_public_key = self.mlkem.public_key.toBytes(),
            };
        }

        pub fn wipe(self: *KeyPair) void {
            self.x25519.wipe();
            secureZero(&self.mlkem.secret_key);
        }
    };

    pub const PublicShare = struct {
        x25519_public_key: PublicKey,
        mlkem_public_key: [mlkem_public_len]u8,
    };

    pub const EncapsulatedShare = struct {
        x25519_public_key: PublicKey,
        mlkem_ciphertext: [mlkem_ciphertext_len]u8,
    };

    pub const Encapsulation = struct {
        share: EncapsulatedShare,
        shared_secret: SharedSecret,

        pub fn wipe(self: *Encapsulation) void {
            self.shared_secret.wipe();
        }
    };

    pub fn generate(io: std.Io) KeyPair {
        return .{
            .x25519 = X25519Kx.generate(io),
            .mlkem = MlKem.KeyPair.generate(io),
        };
    }

    pub fn generateDeterministic(seed: [seed_len]u8) !KeyPair {
        comptime {
            if (seed_len != X25519Kx.seed_len + MlKem.seed_length)
                @compileError("HybridKx deterministic seed layout must be X25519 seed || ML-KEM seed");
        }
        return .{
            .x25519 = try X25519Kx.generateDeterministic(seed[0..X25519Kx.seed_len].*),
            .mlkem = try MlKem.KeyPair.generateDeterministic(seed[X25519Kx.seed_len..].*),
        };
    }

    pub fn encapsulate(
        local_x25519: *const X25519Kx.KeyPair,
        peer: PublicShare,
        transcript: []const u8,
        io: std.Io,
    ) !Encapsulation {
        const pk = try MlKem.PublicKey.fromBytes(&peer.mlkem_public_key);
        var pq = pk.encaps(io);
        defer secureZero(&pq.shared_secret);
        return finishEncapsulation(local_x25519, peer.x25519_public_key, transcript, pq);
    }

    pub fn encapsulateDeterministic(
        local_x25519: *const X25519Kx.KeyPair,
        peer: PublicShare,
        transcript: []const u8,
        seed: *const [encaps_seed_len]u8,
    ) !Encapsulation {
        const pk = try MlKem.PublicKey.fromBytes(&peer.mlkem_public_key);
        var pq = pk.encapsDeterministic(seed);
        defer secureZero(&pq.shared_secret);
        return finishEncapsulation(local_x25519, peer.x25519_public_key, transcript, pq);
    }

    pub fn decapsulate(
        local: *const KeyPair,
        peer: EncapsulatedShare,
        transcript: []const u8,
    ) !SharedSecret {
        var x_ss = try X25519Kx.sharedSecret(&local.x25519.secret_key, peer.x25519_public_key);
        defer x_ss.wipe();

        var pq_raw = try local.mlkem.secret_key.decaps(&peer.mlkem_ciphertext);
        defer secureZero(&pq_raw);
        var pq_ss = SharedSecret.init(pq_raw);
        defer pq_ss.wipe();

        return extractHybrid("onyx-mooring-v2 hybrid-kx", &x_ss, &pq_ss, transcript);
    }

    fn finishEncapsulation(
        local_x25519: *const X25519Kx.KeyPair,
        peer_x25519_public_key: PublicKey,
        transcript: []const u8,
        pq: MlKem.EncapsulatedSecret,
    ) !Encapsulation {
        var x_ss = try X25519Kx.sharedSecret(&local_x25519.secret_key, peer_x25519_public_key);
        defer x_ss.wipe();
        var pq_ss = SharedSecret.init(pq.shared_secret);
        defer pq_ss.wipe();

        return .{
            .share = .{
                .x25519_public_key = local_x25519.public_key,
                .mlkem_ciphertext = pq.ciphertext,
            },
            .shared_secret = extractHybrid("onyx-mooring-v2 hybrid-kx", &x_ss, &pq_ss, transcript),
        };
    }
};

/// MOORING/TLS root and directional chain keys derived from a shared secret.
pub const KeySchedule = struct {
    root: RootKey,
    send_chain: ChainKey,
    recv_chain: ChainKey,

    pub fn wipe(self: *KeySchedule) void {
        self.root.wipe();
        self.send_chain.wipe();
        self.recv_chain.wipe();
    }

    pub fn deriveMooringV2(
        role: Role,
        shared_secret: *const SharedSecret,
        transcript: []const u8,
    ) !KeySchedule {
        return derive("onyx-mooring-v2", role, shared_secret, transcript);
    }

    pub fn derive(
        comptime domain: []const u8,
        role: Role,
        shared_secret: *const SharedSecret,
        transcript: []const u8,
    ) !KeySchedule {
        const root_label = domain ++ " key-schedule root";
        var root = extractWithTranscript(root_label, shared_secret, transcript);
        errdefer root.wipe();

        var initiator_to_responder: [32]u8 = undefined;
        errdefer secureZero(&initiator_to_responder);
        try HkdfSha256.expand(&root, domain ++ " chain initiator-to-responder", &initiator_to_responder);

        var responder_to_initiator: [32]u8 = undefined;
        errdefer secureZero(&responder_to_initiator);
        try HkdfSha256.expand(&root, domain ++ " chain responder-to-initiator", &responder_to_initiator);

        const send = switch (role) {
            .initiator => initiator_to_responder,
            .responder => responder_to_initiator,
        };
        const recv = switch (role) {
            .initiator => responder_to_initiator,
            .responder => initiator_to_responder,
        };

        secureZero(&initiator_to_responder);
        secureZero(&responder_to_initiator);

        return .{
            .root = root,
            .send_chain = ChainKey.init(send),
            .recv_chain = ChainKey.init(recv),
        };
    }
};

fn extractHybrid(
    comptime label: []const u8,
    x25519_ss: *const SharedSecret,
    mlkem_ss: *const SharedSecret,
    transcript: []const u8,
) SharedSecret {
    var mac = HmacSha256.init(label);

    var x = x25519_ss.declassify();
    defer secureZero(&x);
    mac.update(&x);

    var pq = mlkem_ss.declassify();
    defer secureZero(&pq);
    mac.update(&pq);

    mac.update(transcript);
    return SharedSecret.init(mac.final());
}

fn extractWithTranscript(
    comptime label: []const u8,
    secret: *const SharedSecret,
    transcript: []const u8,
) RootKey {
    var mac = HmacSha256.init(label);

    var bytes = secret.declassify();
    defer secureZero(&bytes);
    mac.update(&bytes);

    mac.update(transcript);
    return RootKey.init(mac.final());
}

fn rejectAllZero(bytes: [32]u8) KeyExchangeError!void {
    var acc: u8 = 0;
    for (bytes) |b| {
        acc |= b;
    }
    if (acc == 0) return error.LowOrderPoint;
}

fn secureZero(value: anytype) void {
    const bytes = std.mem.asBytes(value);
    for (bytes) |*b| {
        const vp: *volatile u8 = @ptrCast(b);
        vp.* = 0;
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "X25519 ECDH agreement" {
    var alice = try X25519Kx.generateDeterministic(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177f3aa1c5b7987"));
    defer alice.wipe();
    var bob = try X25519Kx.generateDeterministic(hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    defer bob.wipe();

    var alice_ss = try X25519Kx.sharedSecret(&alice.secret_key, bob.public_key);
    defer alice_ss.wipe();
    var bob_ss = try X25519Kx.sharedSecret(&bob.secret_key, alice.public_key);
    defer bob_ss.wipe();

    try std.testing.expectEqualSlices(u8, &alice_ss.declassify(), &bob_ss.declassify());
}

test "X25519 all-zero shared secret is rejected" {
    var alice = try X25519Kx.generateDeterministic(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177f3aa1c5b7987"));
    defer alice.wipe();

    try std.testing.expectError(
        error.LowOrderPoint,
        X25519Kx.sharedSecret(&alice.secret_key, @as([32]u8, @splat(0))),
    );
}

test "HybridKx X25519 plus ML-KEM-768 agreement" {
    var responder_seed: [HybridKx.seed_len]u8 = undefined;
    @memset(&responder_seed, 0x42);
    var responder = try HybridKx.generateDeterministic(responder_seed);
    defer responder.wipe();

    var initiator_x = try X25519Kx.generateDeterministic(hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"));
    defer initiator_x.wipe();

    const transcript = "undertow-auth-v2 transcript bytes";
    var enc_seed: [HybridKx.encaps_seed_len]u8 = undefined;
    @memset(&enc_seed, 0x43);

    var enc = try HybridKx.encapsulateDeterministic(
        &initiator_x,
        responder.publicShare(),
        transcript,
        &enc_seed,
    );
    defer enc.wipe();

    var responder_ss = try HybridKx.decapsulate(&responder, enc.share, transcript);
    defer responder_ss.wipe();

    try std.testing.expectEqualSlices(
        u8,
        &enc.shared_secret.declassify(),
        &responder_ss.declassify(),
    );
}

test "key-schedule determinism" {
    var shared = SharedSecret.init(hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    defer shared.wipe();

    var a = try KeySchedule.deriveMooringV2(.initiator, &shared, "transcript");
    defer a.wipe();
    var b = try KeySchedule.deriveMooringV2(.initiator, &shared, "transcript");
    defer b.wipe();

    try std.testing.expectEqualSlices(u8, &a.root.declassify(), &b.root.declassify());
    try std.testing.expectEqualSlices(u8, &a.send_chain.declassify(), &b.send_chain.declassify());
    try std.testing.expectEqualSlices(u8, &a.recv_chain.declassify(), &b.recv_chain.declassify());
}

test "key-schedule domain separation" {
    var shared = SharedSecret.init(hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    defer shared.wipe();

    var mooring = try KeySchedule.derive("onyx-mooring-v2", .initiator, &shared, "transcript");
    defer mooring.wipe();
    var tls = try KeySchedule.derive("onyx-tls13-v1", .initiator, &shared, "transcript");
    defer tls.wipe();

    try std.testing.expect(!std.mem.eql(u8, &mooring.root.declassify(), &tls.root.declassify()));
    try std.testing.expect(!std.mem.eql(u8, &mooring.send_chain.declassify(), &tls.send_chain.declassify()));
}

test {
    std.testing.refAllDecls(@This());
}
