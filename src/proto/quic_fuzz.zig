// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine-level deterministic fuzzing for the QUIC server handshake and the
//! `quic_conn` Initial-packet path (Armor audit 2026-11-07, "Fuzzing misses
//! whole engines"; A1 64 KiB handshake cap).
//!
//! Three harnesses, all fully deterministic (the QUIC engines take fixed
//! X25519 seeds and randoms in tests, so a seed reproduces exact bytes):
//!
//!   1. `quic_handshake.Server.feedCrypto` fed a real ClientHello from
//!      `quic_handshake.Client`, mutated structure-aware (extension-level, with
//!      correct lengths; transport parameters and ALPN included) and delivered
//!      in random CRYPTO cuts, plus a mutated client Finished.
//!   2. `quic_conn.Conn` (server role) fed Initial datagrams we build and seal
//!      with the real Initial keys: the mutated ClientHello is chopped into
//!      CRYPTO frames with shuffled / overlapping / duplicated / far-future
//!      offsets, mixed with noise frames, coalesced, padded, and sometimes
//!      corrupted after sealing.
//!   3. A streaming attack: a ClientHello declaring a large length streamed in
//!      order over many Initial packets.
//!
//! Invariants asserted on every step: typed errors only (no panic / UB in
//! Debug), the handshake's buffered CRYPTO bytes never exceed
//! `quic_handshake.max_handshake_buffer` (64 KiB), the CRYPTO reassembly
//! window never exceeds its cap, a server never sends more than 3x what it
//! received before address validation, and the testing allocator sees no leak.
const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;

const quic_handshake = @import("quic_handshake.zig");
const quic_conn = @import("quic_conn.zig");
const quic_protect = @import("quic_protect.zig");
const quic_frame = @import("quic_frame.zig");
const quic_conn_state = @import("quic_conn_state.zig");
const quic_transport_params = @import("quic_transport_params.zig");
const x509_selfsign = @import("x509_selfsign.zig");
const fm = @import("../crypto/fuzz_mutate.zig");

const cap = quic_handshake.max_handshake_buffer;

const server_cid = [_]u8{ 0x5e, 0x5e, 0x5e, 0x5e, 0x01, 0x02, 0x03, 0x04 };
const client_cid = [_]u8{ 0xc1, 0xc1, 0xc1, 0xc1, 0x05, 0x06, 0x07, 0x08 };
const initial_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const alpn = [_][]const u8{"h3"};

const server_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &server_cid,
    .max_idle_timeout = 30_000,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};
const client_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &client_cid,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

const Fixture = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    chain: [1][]const u8,
    /// Real ClientHello (Initial CRYPTO bytes) and the real client Finished
    /// (Handshake CRYPTO bytes) for the deterministic seeds below.
    ch_buf: [2048]u8,
    ch: []const u8,
    cfin_buf: [128]u8,
    cfin: []const u8,

    fn init(self: *Fixture, alloc: Allocator) !void {
        self.kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x3a)));
        self.chain[0] = try x509_selfsign.buildSelfSigned(&self.cert_buf, .{
            .common_name = "quic.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ 0x3a, 0x01 },
            .key_pair = self.kp,
            .dns_names = &.{"quic.test"},
            .is_ca = true,
        });
        var client = try quic_handshake.Client.initConfig(alloc, clientConfig());
        defer client.deinit();
        try client.startHandshake();
        const ch = try client.takeFlight(.initial);
        defer alloc.free(ch);
        @memcpy(self.ch_buf[0..ch.len], ch);
        self.ch = self.ch_buf[0..ch.len];

        // Drive one real handshake to capture the client Finished; the server
        // is deterministic, so a fresh server reproduces the same flight.
        var server = try self.newServer(alloc);
        defer server.deinit();
        try server.feedCrypto(.initial, self.ch);
        const sh = try server.takeFlight(.initial);
        defer alloc.free(sh);
        const shs = try server.takeFlight(.handshake);
        defer alloc.free(shs);
        try client.feedCrypto(.initial, sh);
        try client.feedCrypto(.handshake, shs);
        const cfin = try client.takeFlight(.handshake);
        defer alloc.free(cfin);
        @memcpy(self.cfin_buf[0..cfin.len], cfin);
        self.cfin = self.cfin_buf[0..cfin.len];
        try server.feedCrypto(.handshake, self.cfin);
        try testing.expect(server.isComplete());
    }

    fn clientConfig() quic_handshake.ClientConfig {
        return .{
            .alpn_protocols = &alpn,
            .transport_params = client_params,
            .x25519_seed = @as([32]u8, @splat(0x42)),
            .client_random = @as([32]u8, @splat(0x11)),
        };
    }

    fn newServer(self: *const Fixture, alloc: Allocator) !quic_handshake.Server {
        return quic_handshake.Server.init(alloc, .{
            .cert_chain = &self.chain,
            .signing_key = .{ .ed25519 = self.kp },
            .alpn_protocols = &alpn,
            .transport_params = server_params,
            .x25519_seed = @as([32]u8, @splat(0x21)),
            .server_random = @as([32]u8, @splat(0x55)),
        });
    }

    fn newConn(self: *const Fixture, alloc: Allocator) !quic_conn.Conn {
        return quic_conn.Conn.initServer(alloc, .{
            .cert_chain = &self.chain,
            .signing_key = .{ .ed25519 = self.kp },
            .alpn_protocols = &alpn,
            .transport_params = server_params,
            .local_cid = &server_cid,
            .x25519_seed = @as([32]u8, @splat(0x21)),
            .server_random = @as([32]u8, @splat(0x55)),
        });
    }
};

/// Mutate a handshake message (type ‖ u24 len ‖ hello body) into `out`.
fn mutateMessage(rand: std.Random, msg: []const u8, out: []u8) []u8 {
    var scratch: [4096]u8 = undefined;
    if (msg.len >= 4 and rand.uintLessThan(u8, 4) != 0) {
        const body = fm.mutateHello(rand, .client_hello, msg[4..], out[4..], &scratch);
        out[0] = msg[0];
        const declared: usize = if (rand.uintLessThan(u8, 10) == 0) rand.uintAtMost(usize, cap + 16) else body.len;
        std.mem.writeInt(u24, out[1..4], @intCast(@min(declared, 0xffffff)), .big);
        return out[0 .. 4 + body.len];
    }
    @memcpy(out[0..msg.len], msg);
    return out[0..fm.mutateRaw(rand, out, msg.len)];
}

fn checkHandshakeBound(server: *const quic_handshake.Server) !void {
    try testing.expect(server.recv.items.len <= cap);
}

test "engine fuzz: QUIC server handshake survives mutated ClientHellos and Finished" {
    const alloc = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(alloc);
    var prng = std.Random.DefaultPrng.init(0x0F1C_5E2F_0001_0001);
    const rand = prng.random();

    var mbuf: [4096]u8 = undefined;
    var completed_ch: usize = 0;
    var iter: usize = 0;
    while (iter < 400) : (iter += 1) {
        var server = try fx.newServer(alloc);
        defer server.deinit();
        const phase2 = rand.uintLessThan(u8, 3) == 0;
        const input = if (phase2) fx.ch else mutateMessage(rand, fx.ch, &mbuf);
        var cuts: [64]usize = undefined;
        var n = fm.randomCuts(rand, input.len, &cuts);
        var start: usize = 0;
        var alive = true;
        for (cuts[0..n]) |end| {
            // Rarely feed at the wrong encryption level.
            const lvl: quic_protect.EncryptionLevel = if (rand.uintLessThan(u8, 40) == 0) .handshake else .initial;
            server.feedCrypto(lvl, input[start..end]) catch {
                alive = false;
                break;
            };
            start = end;
            try checkHandshakeBound(&server);
        }
        try checkHandshakeBound(&server);
        inline for (.{ quic_protect.EncryptionLevel.initial, quic_protect.EncryptionLevel.handshake, quic_protect.EncryptionLevel.application }) |l| {
            const out = try server.takeFlight(l);
            alloc.free(out);
        }
        if (!alive or server.handshakeKeys() == null) continue;
        completed_ch += 1;
        // Second flight: the real client Finished, mutated (phase2 always).
        const fin = if (phase2 or rand.boolean()) blk: {
            @memcpy(mbuf[0..fx.cfin.len], fx.cfin);
            break :blk mbuf[0..fm.mutateRaw(rand, &mbuf, fx.cfin.len)];
        } else fx.cfin;
        n = fm.randomCuts(rand, fin.len, &cuts);
        start = 0;
        for (cuts[0..n]) |end| {
            server.feedCrypto(.handshake, fin[start..end]) catch break;
            start = end;
            try checkHandshakeBound(&server);
        }
        try checkHandshakeBound(&server);
    }
    try testing.expect(completed_ch > 40);
}

// --- Initial packet construction (client → server) ---------------------------

const max_dgram = 4096;

/// Seal one client Initial packet carrying `frames` into `out`. Returns its
/// length. `pn` is the full packet number (encoded in 2 bytes).
fn sealInitial(out: []u8, dcid: []const u8, pn: u16, frames: []const u8, token: []const u8) !usize {
    var hdr: [64]u8 = undefined;
    var h: usize = 0;
    const pn_len: usize = 2;
    hdr[h] = 0xc0 | @as(u8, @intCast(pn_len - 1)); // long, fixed, type=Initial
    h += 1;
    std.mem.writeInt(u32, hdr[h..][0..4], 1, .big);
    h += 4;
    hdr[h] = @intCast(dcid.len);
    @memcpy(hdr[h + 1 ..][0..dcid.len], dcid);
    h += 1 + dcid.len;
    hdr[h] = client_cid.len;
    @memcpy(hdr[h + 1 ..][0..client_cid.len], &client_cid);
    h += 1 + client_cid.len;
    hdr[h] = @intCast(token.len); // token length (< 64: 1-byte varint)
    h += 1;
    @memcpy(hdr[h..][0..token.len], token);
    h += token.len;
    const length = pn_len + frames.len + quic_protect.aead_tag_len;
    std.mem.writeInt(u16, hdr[h..][0..2], 0x4000 | @as(u16, @intCast(length)), .big);
    h += 2;
    const pn_offset = h;
    std.mem.writeInt(u16, hdr[h..][0..2], pn, .big);
    h += 2;
    const keys = quic_protect.KeySet.initInitial(dcid, false);
    const r = try quic_protect.sealPacketSuite(out, hdr[0..h], pn_offset, pn_len, pn, frames, keys.write);
    return r.len;
}

fn appendCryptoFrame(frames: []u8, w: *usize, offset: u64, data: []const u8) bool {
    var tmp: [24]u8 = undefined;
    tmp[0] = 0x06;
    var t: usize = 1;
    t += quic_frame.encodeVarInt(offset, tmp[t..]) catch return false;
    t += quic_frame.encodeVarInt(data.len, tmp[t..]) catch return false;
    if (frames.len - w.* < t + data.len) return false;
    @memcpy(frames[w.*..][0..t], tmp[0..t]);
    @memcpy(frames[w.* + t ..][0..data.len], data);
    w.* += t + data.len;
    return true;
}

/// Noise frames valid-ish in the Initial space and some that are not.
fn appendNoiseFrame(rand: std.Random, frames: []u8, w: *usize) void {
    if (frames.len - w.* < 24) return;
    const f = frames[w.*..];
    switch (rand.uintLessThan(u8, 6)) {
        0 => { // PING
            f[0] = 0x01;
            w.* += 1;
        },
        1 => { // ACK largest=pn, delay, 0 ranges, first range
            f[0] = 0x02;
            f[1] = rand.int(u8) & 0x3f;
            f[2] = 0;
            f[3] = 0;
            f[4] = rand.int(u8) & 0x3f;
            w.* += 5;
        },
        2 => { // CONNECTION_CLOSE (transport) with short reason
            f[0] = 0x1c;
            f[1] = rand.int(u8) & 0x3f;
            f[2] = 0x06;
            f[3] = 2;
            f[4] = 'x';
            f[5] = 'y';
            w.* += 6;
        },
        3 => { // STREAM in the Initial space (protocol violation)
            f[0] = 0x0a;
            f[1] = 0;
            f[2] = 3;
            f[3] = 'a';
            f[4] = 'b';
            f[5] = 'c';
            w.* += 6;
        },
        4 => { // random frame type + random tail
            f[0] = rand.int(u8) & 0x3f;
            const n = rand.intRangeAtMost(usize, 0, 16);
            rand.bytes(f[1 .. 1 + n]);
            w.* += 1 + n;
        },
        else => { // PADDING run
            const n = rand.intRangeAtMost(usize, 1, 16);
            @memset(f[0..n], 0);
            w.* += n;
        },
    }
}

/// Build 1..4 datagrams carrying `crypto` (the possibly-mutated ClientHello)
/// as shuffled CRYPTO frames. Each datagram is written to `dgrams[i]` and its
/// length to `lens[i]`. Returns the datagram count.
fn buildInitialDatagrams(rand: std.Random, crypto: []const u8, dgrams: *[4][max_dgram]u8, lens: *[4]usize) !usize {
    // Chop the CRYPTO stream into pieces.
    const Piece = struct { off: u64, start: usize, end: usize };
    var pieces: [24]Piece = undefined;
    var np: usize = 0;
    var p: usize = 0;
    while (p < crypto.len and np < pieces.len - 3) {
        const step = @min(crypto.len - p, rand.intRangeAtMost(usize, 1, @max(1, crypto.len / 2 + 1)));
        pieces[np] = .{ .off = p, .start = p, .end = p + step };
        np += 1;
        p += step;
    }
    if (p < crypto.len) {
        pieces[np] = .{ .off = p, .start = p, .end = crypto.len };
        np += 1;
    }
    // Duplicate / overlap one piece; sometimes add a far-future offset piece.
    if (np > 0 and rand.uintLessThan(u8, 3) == 0) {
        const k = rand.uintLessThan(usize, np);
        var dup = pieces[k];
        if (dup.start > 0 and rand.boolean()) {
            dup.start -= 1;
            dup.off -= 1;
        }
        pieces[np] = dup;
        np += 1;
    }
    if (rand.uintLessThan(u8, 6) == 0) {
        const far: u64 = switch (rand.uintLessThan(u8, 4)) {
            0 => cap - 8,
            1 => cap + 1,
            2 => quic_frame.max_varint - 4,
            else => 1 << 32,
        };
        pieces[np] = .{ .off = far, .start = 0, .end = @min(crypto.len, 8) };
        np += 1;
    }
    rand.shuffle(Piece, pieces[0..np]);

    const nd = rand.intRangeAtMost(usize, 1, 4);
    var di: usize = 0;
    var pi: usize = 0;
    var pn: u16 = rand.uintLessThan(u16, 4);
    while (di < nd) : (di += 1) {
        var frames: [max_dgram]u8 = undefined;
        var fw: usize = 0;
        // Distribute pieces; the last datagram takes all that remain.
        const take = if (di + 1 == nd) np - pi else rand.uintAtMost(usize, np - pi);
        var t: usize = 0;
        while (t < take) : (t += 1) {
            const pc = pieces[pi];
            pi += 1;
            if (!appendCryptoFrame(frames[0 .. max_dgram - 200], &fw, pc.off, crypto[pc.start..pc.end])) break;
            if (rand.uintLessThan(u8, 5) == 0) appendNoiseFrame(rand, frames[0 .. max_dgram - 200], &fw);
        }
        if (fw == 0) appendNoiseFrame(rand, &frames, &fw);
        if (fw == 0) {
            frames[0] = 0x01;
            fw = 1;
        }
        // Header protection samples 16 bytes past pn_offset + 4.
        if (fw < 4) {
            @memset(frames[fw..4], 0);
            fw = 4;
        }
        // Pad to the 1200-byte client Initial minimum most of the time.
        if (rand.uintLessThan(u8, 8) != 0 and fw < 1200 - 64) {
            @memset(frames[fw .. 1200 - 64], 0);
            fw = 1200 - 64;
        }
        // Rarely use a different DCID length / bytes (server keys follow the
        // first Initial's DCID, so later mismatches must just fail to open).
        const dcid: []const u8 = if (rand.uintLessThan(u8, 20) == 0) initial_dcid[0..rand.intRangeAtMost(usize, 0, initial_dcid.len)] else &initial_dcid;
        const token: []const u8 = if (rand.uintLessThan(u8, 10) == 0) "tok" else "";
        var n = try sealInitial(&dgrams[di], dcid, pn, frames[0..fw], token);
        pn +%= 1;
        // Post-seal corruption (header fields or ciphertext) / coalesced junk.
        switch (rand.uintLessThan(u8, 10)) {
            0 => n = fm.mutateRaw(rand, dgrams[di][0..], n),
            1 => if (max_dgram - n >= 32) { // coalesce a garbage long-header packet
                dgrams[di][n] = 0xc0 | rand.int(u8);
                rand.bytes(dgrams[di][n + 1 .. n + 32]);
                n += 32;
            },
            2 => if (max_dgram - n >= 8) { // trailing zero padding
                @memset(dgrams[di][n .. n + 8], 0);
                n += 8;
            },
            else => {},
        }
        lens[di] = n;
    }
    return nd;
}

fn checkConnBounds(conn: *quic_conn.Conn) !void {
    try testing.expect(conn.handshake.server.recv.items.len <= cap);
    inline for (.{ quic_protect.EncryptionLevel.initial, quic_protect.EncryptionLevel.handshake, quic_protect.EncryptionLevel.application }) |l| {
        const cs = conn.engine.cryptoStream(l);
        try testing.expect(cs.staged.items.len <= cs.cap);
    }
}

/// Drain the server's output and enforce anti-amplification (RFC 9000 §8.1).
fn drainConn(alloc: Allocator, conn: *quic_conn.Conn) !usize {
    var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = conn.sendDatagrams(&out) catch {};
    if (!conn.isAddressValidated()) {
        try testing.expect(conn.bytesSentUnvalidated() <= 3 * conn.bytesReceived());
    }
    return out.items.len;
}

test "engine fuzz: QUIC conn Initial processing survives mutated Initial datagrams" {
    const alloc = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(alloc);
    var prng = std.Random.DefaultPrng.init(0x0F1C_5E2F_0002_0002);
    const rand = prng.random();

    var dgrams: [4][max_dgram]u8 = undefined;
    var lens: [4]usize = undefined;
    var mbuf: [4096]u8 = undefined;
    var keyed: usize = 0;
    var iter: usize = 0;
    while (iter < 400) : (iter += 1) {
        var conn = try fx.newConn(alloc);
        defer conn.deinit();
        const pristine = rand.uintLessThan(u8, 5) == 0;
        const crypto = if (pristine) fx.ch else mutateMessage(rand, fx.ch, &mbuf);
        const nd = try buildInitialDatagrams(rand, crypto, &dgrams, &lens);
        for (dgrams[0..nd], lens[0..nd]) |*d, l| {
            conn.recvDatagram(d[0..l]) catch {};
            try checkConnBounds(&conn);
            _ = try drainConn(alloc, &conn);
        }
        if (conn.handshake_keys != null) keyed += 1;
        // Junk 1-RTT / Handshake-level datagrams after the first flight.
        var junk: [256]u8 = undefined;
        const jl = rand.intRangeAtMost(usize, 1, junk.len);
        rand.bytes(junk[0..jl]);
        if (rand.boolean()) junk[0] = 0xe0 | (junk[0] & 0x0f); // long header, Handshake type
        conn.recvDatagram(junk[0..jl]) catch {};
        try checkConnBounds(&conn);
        _ = try drainConn(alloc, &conn);
        _ = conn.onTimeout(std.math.maxInt(u32)) catch {};
        _ = try drainConn(alloc, &conn);
    }
    // Pristine and mildly mutated hellos must still key the connection often.
    try testing.expect(keyed > 50);
}

test "engine fuzz: QUIC conn holds the 64 KiB cap against an in-order streamed ClientHello" {
    const alloc = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(alloc);
    var prng = std.Random.DefaultPrng.init(0x0F1C_5E2F_0003_0003);
    const rand = prng.random();

    var dgram: [max_dgram]u8 = undefined;
    var frames: [1200]u8 = undefined;
    var round: usize = 0;
    while (round < 6) : (round += 1) {
        var conn = try fx.newConn(alloc);
        defer conn.deinit();
        // Declared ClientHello length: oversized, at the cap, or just under it.
        const declared: u24 = switch (round % 3) {
            0 => 0xffffff,
            1 => @intCast(cap - 4),
            else => @intCast(cap - 4 - rand.intRangeAtMost(usize, 1, 2048)),
        };
        var offset: u64 = 0;
        var pn: u16 = 0;
        // Stream ~80 KiB in order: header first, then filler.
        while (offset < cap + 16 * 1024) : (pn += 1) {
            var chunk: [1000]u8 = undefined;
            rand.bytes(&chunk);
            if (offset == 0) {
                chunk[0] = 1;
                std.mem.writeInt(u24, chunk[1..4], declared, .big);
            }
            var fw: usize = 0;
            _ = appendCryptoFrame(&frames, &fw, offset, &chunk);
            @memset(frames[fw..], 0);
            const n = try sealInitial(&dgram, &initial_dcid, pn, &frames, "");
            conn.recvDatagram(dgram[0..n]) catch {};
            try checkConnBounds(&conn);
            _ = try drainConn(alloc, &conn);
            offset += chunk.len;
        }
        // No handshake can complete from filler; the cap held throughout.
        try testing.expect(conn.handshake_keys == null);
        try testing.expect(conn.handshake.server.recv.items.len <= cap);
    }
}

test "engine fuzz: QUIC Initial builder sanity — a pristine ClientHello keys the conn" {
    // Guards against a harness whose packets never open: the unmutated hello
    // in one padded Initial must install Handshake keys and elicit a reply.
    const alloc = testing.allocator;
    var fx: Fixture = undefined;
    try fx.init(alloc);
    var conn = try fx.newConn(alloc);
    defer conn.deinit();
    var frames: [1200]u8 = undefined;
    var fw: usize = 0;
    try testing.expect(appendCryptoFrame(&frames, &fw, 0, fx.ch));
    @memset(frames[fw..], 0);
    var dgram: [max_dgram]u8 = undefined;
    const n = try sealInitial(&dgram, &initial_dcid, 0, &frames, "");
    try conn.recvDatagram(dgram[0..n]);
    try testing.expect(conn.handshake_keys != null);
    try testing.expect(try drainConn(alloc, &conn) > 0);
}
