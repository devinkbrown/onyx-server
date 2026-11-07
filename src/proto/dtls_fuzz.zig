// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine-level deterministic fuzzing for the DTLS 1.2 and DTLS 1.3 server
//! terminators (`dtls12_server.Terminator`, `dtls13_server.Terminator`)
//! (Armor audit 2026-11-07, "Fuzzing misses whole engines").
//!
//! The per-engine tests already throw random bytes and random bodies inside a
//! well-formed record at `handleDatagram`. This file goes further: a minimal
//! client built from the same public codecs drives REAL handshakes, and each
//! flight is mutated before delivery:
//!
//!   * ClientHello: structure-aware extension mutation with correct lengths
//!     (use_srtp, supported_groups, key_share, cookie, supported_versions),
//!     DTLS handshake fragmentation with random fragment offsets/lengths,
//!     message_seq / epoch / record-seq noise, records split or shuffled over
//!     several datagrams, then optional raw corruption;
//!   * the second ClientHello carries the server's real cookie (so mutations
//!     get past the stateless cookie gate into session creation);
//!   * the client key-exchange / Finished flight of a real handshake: records
//!     dropped, duplicated, reordered, split across datagrams, or corrupted.
//!
//! Contract asserted for every datagram: `handleDatagram` never traps, any
//! response slice lies inside the caller's `out` buffer, and the session table
//! stays bounded (sessions are retired between cases). Both terminators are
//! seeded and allocation-free on the hot path, so runs are fully reproducible.
const std = @import("std");
const testing = std.testing;
const Sha256 = std.crypto.hash.sha2.Sha256;

const d12 = @import("dtls12_server.zig");
const d13 = @import("dtls13_server.zig");
const record = @import("dtls12_record.zig");
const record13 = @import("dtls_record.zig");
const msg = @import("dtls12_messages.zig");
const msg13 = @import("dtls13_messages.zig");
const dhs = @import("dtls_handshake.zig");
const kx = @import("dtls_keyexchange.zig");
const dtls_srtp = @import("dtls_srtp.zig");
const hkdf_tls13 = @import("../crypto/hkdf_tls13.zig");
const TransportAddress = @import("ice.zig").TransportAddress;
const fm = @import("../crypto/fuzz_mutate.zig");

const KS = hkdf_tls13.KeySchedule(.sha256);

fn addrFor(i: usize) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 10, 9, @intCast((i >> 8) & 0xff), @intCast(i & 0xff) }, 5000) catch unreachable;
}

/// Deliver one datagram and check the response lies within `out`.
fn deliver(term: anytype, addr: TransportAddress, dgram: []const u8, out: []u8) !?[]const u8 {
    const r = term.handleDatagram(addr, dgram, 1000, out) orelse return null;
    try testing.expect(r.len > 0 and r.len <= out.len);
    try testing.expect(@intFromPtr(r.ptr) >= @intFromPtr(out.ptr));
    try testing.expect(@intFromPtr(r.ptr) + r.len <= @intFromPtr(out.ptr) + out.len);
    return r;
}

/// Frame a handshake message as one or more epoch-0 DTLS records, fragmenting
/// it with random fragment sizes (and rarely inconsistent fragment headers).
/// Records go to `out`; `rec_ends` receives each record's end offset so the
/// caller can spread them over datagrams. Returns the record count.
fn frameFragmented(
    rand: std.Random,
    out: []u8,
    rec_ends: []usize,
    msg_type: dhs.HandshakeType,
    message_seq: u16,
    rec_seq_start: u48,
    body: []const u8,
) usize {
    const whole = rand.uintLessThan(u8, 3) != 0;
    var w: usize = 0;
    var nrec: usize = 0;
    var off: usize = 0;
    var seq = rec_seq_start;
    while (nrec < rec_ends.len) {
        const remaining = body.len - off;
        const frag = if (whole) remaining else @min(remaining, rand.intRangeAtMost(usize, 1, @max(1, body.len / 2 + 1)));
        var hh = dhs.Header{
            .msg_type = msg_type,
            .length = @intCast(body.len),
            .message_seq = message_seq,
            .fragment_offset = @intCast(off),
            .fragment_length = @intCast(frag),
        };
        // Rare header noise that still encodes (offset+len <= length).
        if (rand.uintLessThan(u8, 16) == 0 and off > 0) hh.fragment_offset = @intCast(off - 1);
        if (rand.uintLessThan(u8, 24) == 0) hh.message_seq +%= 1;
        const rec_len = dhs.handshake_header_len + frag;
        if (out.len - w < record.record_header_len + rec_len) break;
        const rh = record.RecordHeader{ .content_type = .handshake, .epoch = if (rand.uintLessThan(u8, 32) == 0) 1 else 0, .seq = seq, .length = @intCast(rec_len) };
        _ = rh.encode(out[w..][0..record.record_header_len]) catch break;
        _ = hh.encode(out[w + record.record_header_len ..][0..dhs.handshake_header_len]) catch break;
        @memcpy(out[w + record.record_header_len + dhs.handshake_header_len ..][0..frag], body[off..][0..frag]);
        w += record.record_header_len + rec_len;
        rec_ends[nrec] = w;
        nrec += 1;
        seq += 1;
        off += frag;
        if (off >= body.len) break;
    }
    return nrec;
}

/// Spread records (`stream`, boundaries `rec_ends[0..n]`) over 1..3 datagrams,
/// sometimes reversing record order, sometimes raw-mutating a datagram, and
/// deliver each. Returns the last non-null response (copied to `resp`).
fn deliverRecords(
    rand: std.Random,
    term: anytype,
    addr: TransportAddress,
    stream: []const u8,
    rec_ends: []const usize,
    out: []u8,
    resp: []u8,
) !?[]const u8 {
    var order: [32]usize = undefined;
    const n = @min(rec_ends.len, order.len);
    for (0..n) |i| order[i] = i;
    if (rand.uintLessThan(u8, 5) == 0) std.mem.reverse(usize, order[0..n]);
    if (rand.uintLessThan(u8, 8) == 0 and n > 1) rand.shuffle(usize, order[0..n]);
    const ndg = @min(n, rand.intRangeAtMost(usize, 1, 3));
    var got: ?[]const u8 = null;
    var idx: usize = 0;
    var d: usize = 0;
    while (d < ndg) : (d += 1) {
        var dg: [4096]u8 = undefined;
        var dl: usize = 0;
        const take = if (d + 1 == ndg) n - idx else rand.intRangeAtMost(usize, 1, n - idx - (ndg - d - 1));
        var t: usize = 0;
        while (t < take) : (t += 1) {
            const r = order[idx];
            idx += 1;
            const s = if (r == 0) 0 else rec_ends[r - 1];
            const e = rec_ends[r];
            if (dg.len - dl < e - s) break;
            @memcpy(dg[dl..][0 .. e - s], stream[s..e]);
            dl += e - s;
        }
        if (rand.uintLessThan(u8, 6) == 0) dl = fm.mutateRaw(rand, &dg, dl);
        if (try deliver(term, addr, dg[0..dl], out)) |r| {
            @memcpy(resp[0..r.len], r);
            got = resp[0..r.len];
        }
    }
    return got;
}

// --- DTLS 1.2 ---------------------------------------------------------------

const Client12 = struct {
    client_random: [32]u8,
    ecdhe: kx.KeyPair,
    cookie: [64]u8 = undefined,
    cookie_len: usize = 0,
    server_random: [32]u8 = @splat(0),
    server_point: [msg.p256_point_len]u8 = @splat(0),
    transcript: Sha256 = undefined,

    fn init(tag: u8) Client12 {
        var cr: [32]u8 = undefined;
        for (&cr, 0..) |*b, i| b.* = @as(u8, @intCast(i)) *% 13 +% tag;
        return .{ .client_random = cr, .ecdhe = kx.generateKeyPair(@splat(0x5c)) };
    }

    fn helloBody(self: *const Client12, buf: []u8) ![]const u8 {
        return msg.buildClientHello(buf, .{
            .random = self.client_random,
            .cookie = self.cookie[0..self.cookie_len],
            .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
        });
    }

    /// Record the cookie from a HelloVerifyRequest datagram, if it is one.
    fn takeCookie(self: *Client12, dg: []const u8) bool {
        const rdec = record.RecordHeader.decode(dg) catch return false;
        const hh = dhs.Header.decode(rdec.fragment) catch return false;
        if (hh.hdr.msg_type != .hello_verify_request) return false;
        if (rdec.fragment.len < dhs.handshake_header_len + hh.hdr.length) return false;
        const c = dhs.parseHelloVerifyRequest(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]) catch return false;
        if (c.len > self.cookie.len) return false;
        @memcpy(self.cookie[0..c.len], c);
        self.cookie_len = c.len;
        return true;
    }
};

fn makeTerm12(sessions: []d12.Session) !d12.Terminator {
    return d12.Terminator.init(@splat(0x44), sessions, 1_700_000_000, 1_900_000_000);
}

test "engine fuzz: DTLS 1.2 server survives mutated, fragmented ClientHellos" {
    var sessions: [8]d12.Session = undefined;
    var term = try makeTerm12(&sessions);
    defer term.deinit();
    var prng = std.Random.DefaultPrng.init(0xD7_15_0012_0001);
    const rand = prng.random();
    var out: [2048]u8 = undefined;
    var resp: [2048]u8 = undefined;
    var stream: [4096]u8 = undefined;
    var rec_ends: [32]usize = undefined;
    var body_buf: [600]u8 = undefined;
    var mut_buf: [1024]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    var cookies: usize = 0;
    var flights: usize = 0;

    var iter: usize = 0;
    while (iter < 100) : (iter += 1) {
        const addr = addrFor(iter);
        defer term.retirePeer(addr);
        var client = Client12.init(@intCast(iter & 0xff));
        // ClientHello 1 (no cookie), mutated half the time.
        const ch1 = try client.helloBody(&body_buf);
        const b1 = if (rand.boolean()) fm.mutateHello(rand, .dtls_client_hello, ch1, &mut_buf, &scratch) else ch1;
        var n = frameFragmented(rand, &stream, &rec_ends, .client_hello, 0, 0, b1);
        const r1 = try deliverRecords(rand, &term, addr, &stream, rec_ends[0..n], &out, &resp) orelse continue;
        if (!client.takeCookie(r1)) continue;
        cookies += 1;
        // ClientHello 2 with the real cookie: mutated most of the time.
        const ch2 = try client.helloBody(&body_buf);
        const b2 = if (rand.uintLessThan(u8, 4) != 0) fm.mutateHello(rand, .dtls_client_hello, ch2, &mut_buf, &scratch) else ch2;
        n = frameFragmented(rand, &stream, &rec_ends, .client_hello, 1, 1, b2);
        if (try deliverRecords(rand, &term, addr, &stream, rec_ends[0..n], &out, &resp)) |_| flights += 1;
    }
    try testing.expect(cookies > 20);
    try testing.expect(flights > 5);
}

/// Drive CH1 → HVR → CH2 → flight 4 and build the real flight 5 records into
/// `stream`. Returns the record count, or null if the server did not answer.
fn realFlight5(term: *d12.Terminator, addr: TransportAddress, client: *Client12, stream: []u8, rec_ends: []usize) !?usize {
    var out: [2048]u8 = undefined;
    var body_buf: [600]u8 = undefined;
    var dg: [1024]u8 = undefined;
    const ch1 = try client.helloBody(&body_buf);
    var n = try d12.framePlaintextHandshake(&dg, .client_hello, 0, 0, 0, ch1);
    const hvr = term.handleDatagram(addr, dg[0..n], 100, &out) orelse return null;
    if (!client.takeCookie(hvr)) return null;
    const ch2 = try client.helloBody(&body_buf);
    client.transcript = Sha256.init(.{});
    d12.feedTranscript(&client.transcript, .client_hello, 1, ch2);
    n = try d12.framePlaintextHandshake(&dg, .client_hello, 1, 0, 1, ch2);
    const f4 = term.handleDatagram(addr, dg[0..n], 101, &out) orelse return null;
    var off: usize = 0;
    while (off < f4.len) {
        const rdec = try record.RecordHeader.decode(f4[off..]);
        off += rdec.consumed;
        const hh = try dhs.Header.decode(rdec.fragment);
        const mbody = rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length];
        switch (hh.hdr.msg_type) {
            .server_hello => client.server_random = (try msg.parseServerHello(mbody)).random,
            .server_key_exchange => client.server_point = (try msg.parseServerKeyExchange(mbody)).point,
            else => {},
        }
        d12.feedTranscript(&client.transcript, hh.hdr.msg_type, hh.hdr.message_seq, mbody);
    }
    const pre = try kx.computeSharedSecret(client.ecdhe.secret, client.server_point);
    const ms = kx.masterSecret(&pre, client.client_random, client.server_random);
    const kb = msg.deriveKeyBlock(&ms, client.client_random, client.server_random);

    var w: usize = 0;
    var nrec: usize = 0;
    var cke_body: [80]u8 = undefined;
    const cke = try msg.buildClientKeyExchange(&cke_body, client.ecdhe.public);
    d12.feedTranscript(&client.transcript, .client_key_exchange, 2, cke);
    w += try d12.framePlaintextHandshake(stream[w..], .client_key_exchange, 2, 0, 2, cke);
    rec_ends[nrec] = w;
    nrec += 1;
    w += (try record.writePlaintext(.change_cipher_spec, 0, 3, &.{0x01}, stream[w..])).len;
    rec_ends[nrec] = w;
    nrec += 1;
    const vd = kx.verifyData(&ms, "client finished", client.transcript.peek());
    w += try d12.frameEncryptedHandshake(stream[w..], kb.client_write_key, kb.client_write_iv, 1, 0, .finished, 3, &vd);
    rec_ends[nrec] = w;
    nrec += 1;
    return nrec;
}

/// Mutate a record stream in place at the record level: drop, duplicate, or
/// corrupt one record (ciphertext or header). Returns the new record count.
fn mutateRecords(rand: std.Random, stream: []u8, rec_ends: []usize, n_in: usize) usize {
    var n = n_in;
    if (n == 0) return 0;
    const k = rand.uintLessThan(usize, n);
    const s = if (k == 0) 0 else rec_ends[k - 1];
    const e = rec_ends[k];
    const total = rec_ends[n - 1];
    switch (rand.uintLessThan(u8, 5)) {
        0 => { // drop record k
            std.mem.copyForwards(u8, stream[s .. total - (e - s)], stream[e..total]);
            var i = k;
            while (i + 1 < n) : (i += 1) rec_ends[i] = rec_ends[i + 1] - (e - s);
            n -= 1;
        },
        1 => if (n < rec_ends.len and stream.len - total >= e - s) { // duplicate k at the end
            @memcpy(stream[total..][0 .. e - s], stream[s..e]);
            rec_ends[n] = total + (e - s);
            n += 1;
        },
        2 => stream[s + rand.uintLessThan(usize, e - s)] ^= rand.int(u8) | 1, // corrupt a byte
        3 => if (e - s > record.record_header_len) { // corrupt the header only
            stream[s + rand.uintLessThan(usize, record.record_header_len)] ^= rand.int(u8) | 1;
        },
        else => {}, // pristine records; delivery order / datagram split only
    }
    return n;
}

test "engine fuzz: DTLS 1.2 server survives a mutated client key-exchange/Finished flight" {
    var sessions: [8]d12.Session = undefined;
    var term = try makeTerm12(&sessions);
    defer term.deinit();
    var prng = std.Random.DefaultPrng.init(0xD7_15_0012_0002);
    const rand = prng.random();
    var out: [2048]u8 = undefined;
    var resp: [2048]u8 = undefined;
    var stream: [4096]u8 = undefined;
    var rec_ends: [32]usize = undefined;
    var completed: usize = 0;
    var iter: usize = 0;
    while (iter < 16) : (iter += 1) {
        const addr = addrFor(iter + 1000);
        defer term.retirePeer(addr);
        var client = Client12.init(@intCast(iter & 0xff));
        var n = try realFlight5(&term, addr, &client, &stream, &rec_ends) orelse return error.TestUnexpectedResult;
        n = mutateRecords(rand, &stream, &rec_ends, n);
        _ = try deliverRecords(rand, &term, addr, &stream, rec_ends[0..n], &out, &resp);
        if (term.established(addr)) completed += 1;
    }
    // Unmutated orders still complete sometimes: the harness reaches the end.
    try testing.expect(completed > 0);
}

// --- DTLS 1.3 ---------------------------------------------------------------

const Client13 = struct {
    client_random: [32]u8,
    ecdhe: kx.KeyPair,
    ch1_buf: [600]u8 = undefined,
    ch1_len: usize = 0,
    cookie: [d13.cookie_len]u8 = undefined,
    have_cookie: bool = false,
    ts: Sha256 = undefined,

    fn init(tag: u8) Client13 {
        var cr: [32]u8 = undefined;
        for (&cr, 0..) |*b, i| b.* = @as(u8, @intCast(i)) *% 7 +% tag;
        return .{ .client_random = cr, .ecdhe = kx.generateKeyPair(@splat(0xC1)) };
    }

    fn hello(self: *Client13, buf: []u8, with_cookie: bool) ![]const u8 {
        return msg13.buildClientHello13(buf, .{
            .random = self.client_random,
            .key_share_point = self.ecdhe.public,
            .srtp_profiles = &.{dtls_srtp.profile_aes128_cm_sha1_80},
            .cookie = if (with_cookie) &self.cookie else &.{},
        });
    }

    fn takeCookie(self: *Client13, dg: []const u8) bool {
        const rdec = record.RecordHeader.decode(dg) catch return false;
        const hh = dhs.Header.decode(rdec.fragment) catch return false;
        if (rdec.fragment.len < dhs.handshake_header_len + hh.hdr.length) return false;
        const shv = msg13.parseServerHello13(rdec.fragment[dhs.handshake_header_len..][0..hh.hdr.length]) catch return false;
        if (!shv.isHelloRetryRequest() or shv.cookie.len != d13.cookie_len) return false;
        @memcpy(&self.cookie, shv.cookie);
        self.have_cookie = true;
        return true;
    }
};

const Term13 = struct {
    t12: d12.Terminator,
    s12: [1]d12.Session,
    term: d13.Terminator,
    sessions: [8]d13.Session,

    fn init(self: *Term13) !void {
        self.t12 = try makeTerm12(&self.s12);
        self.term = try d13.Terminator.init(@splat(0x1e), &self.sessions, self.t12.certDer(), self.t12.certKeyPair());
    }
    fn deinit(self: *Term13) void {
        self.term.deinit();
        self.t12.deinit();
    }
};

test "engine fuzz: DTLS 1.3 server survives mutated, fragmented ClientHellos" {
    var t: Term13 = undefined;
    try t.init();
    defer t.deinit();
    var prng = std.Random.DefaultPrng.init(0xD7_15_0013_0001);
    const rand = prng.random();
    var out: [2048]u8 = undefined;
    var resp: [2048]u8 = undefined;
    var stream: [4096]u8 = undefined;
    var rec_ends: [32]usize = undefined;
    var mut_buf: [1024]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    var cookies: usize = 0;
    var flights: usize = 0;

    var iter: usize = 0;
    while (iter < 100) : (iter += 1) {
        const addr = addrFor(iter + 2000);
        defer t.term.retirePeer(addr);
        var client = Client13.init(@intCast(iter & 0xff));
        const ch1 = try client.hello(&client.ch1_buf, false);
        const b1 = if (rand.boolean()) fm.mutateHello(rand, .dtls_client_hello, ch1, &mut_buf, &scratch) else ch1;
        var n = frameFragmented(rand, &stream, &rec_ends, .client_hello, 0, 0, b1);
        const r1 = try deliverRecords(rand, &t.term, addr, &stream, rec_ends[0..n], &out, &resp) orelse continue;
        if (!client.takeCookie(r1)) continue;
        cookies += 1;
        var ch2_buf: [700]u8 = undefined;
        // CH2 must hash-match CH1 via the cookie, so only an unmutated CH1
        // yields a cookie whose CH2 can pass; mutate CH2 most of the time.
        const ch2 = try client.hello(&ch2_buf, true);
        const b2 = if (rand.uintLessThan(u8, 4) != 0) fm.mutateHello(rand, .dtls_client_hello, ch2, &mut_buf, &scratch) else ch2;
        n = frameFragmented(rand, &stream, &rec_ends, .client_hello, 1, 1, b2);
        if (try deliverRecords(rand, &t.term, addr, &stream, rec_ends[0..n], &out, &resp)) |_| flights += 1;
    }
    try testing.expect(cookies > 20);
    try testing.expect(flights > 5);
}

/// Drive CH1 → HRR → CH2 → server flight against the 1.3 terminator and build
/// the real client Finished record into `stream`. Returns its length.
fn realFinished13(term: *d13.Terminator, addr: TransportAddress, client: *Client13, stream: []u8) !?usize {
    var out: [2048]u8 = undefined;
    var dg: [1024]u8 = undefined;
    const ch1 = try client.hello(&client.ch1_buf, false);
    client.ch1_len = ch1.len;
    var n = try d13.framePlaintext13(&dg, .client_hello, 0, 0, ch1);
    const hrr_dg = term.handleDatagram(addr, dg[0..n], 100, &out) orelse return null;
    if (!client.takeCookie(hrr_dg)) return null;

    client.ts = Sha256.init(.{});
    var t1 = Sha256.init(.{});
    d13.feedTranscript13(&t1, .client_hello, 0, client.ch1_buf[0..client.ch1_len]);
    d13.feedSynthetic(&client.ts, t1.peek());
    var hrr_buf: [256]u8 = undefined;
    const hrr = try msg13.buildHelloRetryRequest(&hrr_buf, &.{}, &client.cookie, false);
    d13.feedTranscript13(&client.ts, .server_hello, 0, hrr);
    var ch2_buf: [700]u8 = undefined;
    const ch2 = try client.hello(&ch2_buf, true);
    d13.feedTranscript13(&client.ts, .client_hello, 1, ch2);
    n = try d13.framePlaintext13(&dg, .client_hello, 1, 1, ch2);
    const flight = term.handleDatagram(addr, dg[0..n], 101, &out) orelse return null;

    var off: usize = 0;
    const shdec = try record.RecordHeader.decode(flight);
    off += shdec.consumed;
    const shh = try dhs.Header.decode(shdec.fragment);
    const sh_body = shdec.fragment[dhs.handshake_header_len..][0..shh.hdr.length];
    const shv = try msg13.parseServerHello13(sh_body);
    d13.feedTranscript13(&client.ts, .server_hello, 1, sh_body);

    var shared = try kx.computeSharedSecret(client.ecdhe.secret, shv.key_share_point orelse return error.TestUnexpectedResult);
    defer std.crypto.secureZero(u8, &shared);
    var early = KS.earlySecret("");
    defer early.wipe();
    var hs = try KS.handshakeSecret(&early, &shared);
    defer hs.wipe();
    const th = client.ts.peek();
    var c_hs = try KS.deriveSecret(&hs, "c hs traffic", &th);
    defer c_hs.wipe();
    var s_hs = try KS.deriveSecret(&hs, "s hs traffic", &th);
    defer s_hs.wipe();
    var server_keys = record13.deriveAes128GcmKeys(s_hs.declassify());
    defer server_keys.wipe();
    var client_keys = record13.deriveAes128GcmKeys(c_hs.declassify());
    defer client_keys.wipe();

    var read_top: u64 = 0;
    var plain: [2048]u8 = undefined;
    while (off < flight.len) {
        const dech = try record13.Header.decode(flight[off..]);
        const total = dech.consumed + @as(usize, dech.hdr.record_len);
        const opened = try d13.openEncRecord(server_keys, flight[off..][0..total], read_top, &plain);
        off += total;
        read_top = opened.seq;
        const hh = try dhs.Header.decode(opened.content);
        d13.feedTranscript13(&client.ts, hh.hdr.msg_type, hh.hdr.message_seq, opened.content[dhs.handshake_header_len..][0..hh.hdr.length]);
    }
    var c_fin_key = try KS.finishedKey(&c_hs);
    defer c_fin_key.wipe();
    const fin_th = client.ts.peek();
    const verify = try KS.finishedVerifyData(&c_fin_key, &fin_th);
    return try d13.frameEncHandshake(stream, client_keys, 0, .finished, 2, &verify);
}

test "engine fuzz: DTLS 1.3 server survives a mutated client Finished flight" {
    var t: Term13 = undefined;
    try t.init();
    defer t.deinit();
    var prng = std.Random.DefaultPrng.init(0xD7_15_0013_0002);
    const rand = prng.random();
    var out: [2048]u8 = undefined;
    var stream: [1024]u8 = undefined;
    var completed: usize = 0;
    var iter: usize = 0;
    while (iter < 16) : (iter += 1) {
        const addr = addrFor(iter + 3000);
        defer t.term.retirePeer(addr);
        var client = Client13.init(@intCast(iter & 0xff));
        var n = try realFinished13(&t.term, addr, &client, &stream) orelse return error.TestUnexpectedResult;
        switch (rand.uintLessThan(u8, 5)) {
            0, 1 => n = fm.mutateRaw(rand, &stream, n),
            2 => { // the same record twice in one datagram (replay within a datagram)
                @memcpy(stream[n .. 2 * n], stream[0..n]);
                n *= 2;
            },
            3 => { // header-only corruption (record-number mask / length)
                stream[rand.uintLessThan(usize, @min(n, 5))] ^= rand.int(u8) | 1;
            },
            else => {},
        }
        _ = try deliver(&t.term, addr, stream[0..n], &out);
        // Then a retransmission of the (possibly mutated) bytes.
        _ = try deliver(&t.term, addr, stream[0..n], &out);
        if (t.term.established(addr)) completed += 1;
    }
    try testing.expect(completed > 0);
}

test "engine fuzz: DTLS hello mutation parses the real ClientHellos structurally" {
    // Sanity: the structure-aware path must actually engage for both engines'
    // ClientHello layouts, or the fuzz silently degrades to raw noise.
    var b12: [600]u8 = undefined;
    var c12 = Client12.init(1);
    try testing.expect(fm.Hello.parse(.dtls_client_hello, try c12.helloBody(&b12)) != null);
    var c13 = Client13.init(1);
    var b13: [600]u8 = undefined;
    try testing.expect(fm.Hello.parse(.dtls_client_hello, try c13.hello(&b13, false)) != null);
}
