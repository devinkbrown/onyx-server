// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine-level deterministic fuzzing for the TLS 1.3 server and client state
//! machines (Armor audit 2026-11-07, "Fuzzing misses whole engines").
//!
//! `tls_fuzz.zig` feeds hostile bytes to individual parsers. This file drives
//! the WHOLE engines (`tls_server.Server.feed`, `tls_client.Client.feed`) with
//! flights produced by the real peer engine and then mutated:
//!
//!   * structure-aware: the Client/ServerHello is parsed into its extension
//!     list, extensions are dropped / duplicated / reordered / mutated /
//!     truncated / injected, and the message is re-encoded with CORRECT
//!     lengths so mutations reach the per-extension parsers and the
//!     negotiation logic (HRR, PSK, ECH, ALPN, cert types, groups);
//!   * record splits: the handshake bytes are re-framed into TLS records of
//!     random fragment sizes (with stray CCS / empty / alert records), then
//!     delivered over random transport cuts (including 1-byte dribbles);
//!   * raw: byte-level mutations of the framed stream, including the
//!     encrypted records of later flights.
//!
//! Contract asserted for every input: `feed` returns a value or a typed error,
//! never panics (Debug safety checks trap OOB / overflow / `unreachable`), the
//! engine latches failure (a feed after an error returns `BadState`), alert
//! construction after any error is safe, and the testing allocator sees no
//! leak. The mutation schedule is seeded and fixed; the peers' ephemeral key
//! material comes from the OS CSPRNG (the TLS engines take no entropy hook), so
//! the exact bytes differ per run while the structural coverage does not.
const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

const tls_server = @import("tls_server.zig");
const tls_client = @import("tls_client.zig");
const hpke = @import("hpke.zig");
const ech = @import("ech_seal.zig");
const ech_config = @import("../proto/ech_config.zig");
const x509_selfsign = @import("../proto/x509_selfsign.zig");
const fm = @import("fuzz_mutate.zig");

const Server = tls_server.Server;
const Client = tls_client.Client;

const record_handshake: u8 = 22;
const record_ccs: u8 = 20;
const record_alert: u8 = 21;
const record_appdata: u8 = 23;

/// Shared cert + ECH material for every case.
const Fixture = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    der: []const u8,
    ech_list_buf: [600]u8,
    ech_list: []const u8,
    ech_keys: [1]tls_server.EchKey,

    fn init(self: *Fixture) !void {
        self.kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x6e)));
        self.der = try x509_selfsign.buildSelfSigned(&self.cert_buf, .{
            .common_name = "irc.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ 0x6e, 0x01 },
            .key_pair = self.kp,
            .dns_names = &.{"irc.test"},
            .is_ca = true,
        });
        const hpke_kp = try hpke.KeyPair.generateDeterministic(@as([32]u8, @splat(0x29)));
        self.ech_list = buildEchConfigList(&self.ech_list_buf, 9, &hpke_kp.public_key, "cover.example");
        self.ech_keys = .{.{ .config = self.ech_list, .private_key = hpke_kp.secret_key }};
    }

    /// Server configuration presets: each widens the reachable engine surface.
    fn serverConfig(self: *const Fixture, preset: u8) tls_server.Config {
        var c: tls_server.Config = .{ .cert_chain = (&self.der)[0..1], .signing_key = self.kp };
        switch (preset % 6) {
            0 => {},
            1 => c.request_client_cert = true,
            2 => {
                c.enable_session_tickets = true;
                c.enable_cert_compression = true;
                c.alpn_protocols = &.{ "irc", "h2" };
            },
            3 => c.enable_raw_public_key = true,
            4 => {
                c.ech_keys = &self.ech_keys;
                c.ech_retry_config_list = self.ech_list;
            },
            else => {
                c.enforce_cert_signature_algorithms = true;
                c.receive_record_size_limit = 512;
            },
        }
        return c;
    }

    /// Client option presets (the ClientHello shapes we start from).
    fn initClient(self: *const Fixture, alloc: std.mem.Allocator, preset: u8) !Client {
        var o: tls_client.Options = .{ .server_name = "irc.test", .trust_anchors = (&self.der)[0..1] };
        switch (preset % 7) {
            1 => o.alpn_protocols = &.{ "h2", "irc" },
            2 => o.offer_raw_public_key = true,
            3 => o.ech_config_list = self.ech_list,
            else => {},
        }
        var c = try Client.init(alloc, o);
        switch (preset % 7) {
            4 => c.offerNoSharesForTest(), // forces a HelloRetryRequest
            5 => c.offerOnlyP256ForTest(),
            6 => {
                c.offerCertCompression();
                c.offerOnlyHybridForTest();
            },
            else => {},
        }
        return c;
    }
};

fn buildEchConfigList(buf: []u8, config_id: u8, pk: []const u8, public_name: []const u8) []const u8 {
    var contents: [256]u8 = undefined;
    var n: usize = 0;
    contents[n] = config_id;
    n += 1;
    std.mem.writeInt(u16, contents[n..][0..2], ech.kem_id, .big);
    std.mem.writeInt(u16, contents[n + 2 ..][0..2], @intCast(pk.len), .big);
    n += 4;
    @memcpy(contents[n..][0..pk.len], pk);
    n += pk.len;
    std.mem.writeInt(u16, contents[n..][0..2], 4, .big);
    std.mem.writeInt(u16, contents[n + 2 ..][0..2], ech.kdf_id, .big);
    std.mem.writeInt(u16, contents[n + 4 ..][0..2], ech.aead_id, .big);
    n += 6;
    contents[n] = 64; // maximum_name_length
    contents[n + 1] = @intCast(public_name.len);
    n += 2;
    @memcpy(contents[n..][0..public_name.len], public_name);
    n += public_name.len;
    std.mem.writeInt(u16, contents[n..][0..2], 0, .big);
    n += 2;
    const m = 4 + n;
    std.mem.writeInt(u16, buf[0..2], @intCast(m), .big);
    std.mem.writeInt(u16, buf[2..4], ech_config.version_draft13, .big);
    std.mem.writeInt(u16, buf[4..6], @intCast(n), .big);
    @memcpy(buf[6..][0..n], contents[0..n]);
    return buf[0 .. 2 + m];
}

/// Concatenate the fragments of every handshake-type record in `stream`
/// (plaintext records only). Returns the handshake byte length.
fn extractHandshake(stream: []const u8, out: []u8) usize {
    var p: usize = 0;
    var w: usize = 0;
    while (stream.len - p >= 5) {
        const l = std.mem.readInt(u16, stream[p + 3 ..][0..2], .big);
        if (stream.len - p - 5 < l) break;
        if (stream[p] == record_handshake and out.len - w >= l) {
            @memcpy(out[w..][0..l], stream[p + 5 ..][0..l]);
            w += l;
        }
        p += 5 + l;
    }
    return w;
}

/// Re-frame handshake bytes into records of random fragment sizes, sometimes
/// with stray CCS / zero-length / alert / app-data records interleaved.
fn frameRecords(rand: std.Random, hs: []const u8, out: []u8) usize {
    var w: usize = 0;
    var p: usize = 0;
    const max_frag: usize = switch (rand.uintLessThan(u8, 4)) {
        0 => hs.len, // single record
        1 => 1,
        2 => rand.intRangeAtMost(usize, 1, 64),
        else => rand.intRangeAtMost(usize, 1, @max(1, hs.len)),
    };
    while (true) {
        if (rand.uintLessThan(u8, 12) == 0 and out.len - w >= 6) {
            // Stray record: legacy CCS, empty handshake, alert, or app data.
            const t: u8 = switch (rand.uintLessThan(u8, 4)) {
                0 => record_ccs,
                1 => record_handshake,
                2 => record_alert,
                else => record_appdata,
            };
            const body_len: usize = if (t == record_handshake) 0 else if (t == record_alert) 2 else 1;
            if (out.len - w < 5 + body_len) break;
            out[w] = t;
            out[w + 1] = 3;
            out[w + 2] = 3;
            std.mem.writeInt(u16, out[w + 3 ..][0..2], @intCast(body_len), .big);
            if (body_len > 0) out[w + 5] = if (t == record_ccs) 1 else 2;
            if (body_len > 1) out[w + 6] = 10;
            w += 5 + body_len;
        }
        if (p >= hs.len) break;
        const frag = @min(hs.len - p, rand.intRangeAtMost(usize, 1, @max(1, max_frag)));
        if (out.len - w < 5 + frag) break;
        out[w] = record_handshake;
        out[w + 1] = 3;
        out[w + 2] = if (rand.uintLessThan(u8, 16) == 0) 1 else 3; // legacy_record_version noise
        std.mem.writeInt(u16, out[w + 3 ..][0..2], @intCast(frag), .big);
        @memcpy(out[w + 5 ..][0..frag], hs[p..][0..frag]);
        w += 5 + frag;
        p += frag;
    }
    return w;
}

/// Build one mutated first-flight from a base handshake message (`msg` =
/// type ‖ u24 len ‖ body) into `out`. `kind` selects the hello layout.
fn mutateFlight(rand: std.Random, kind: fm.Hello.Kind, msg: []const u8, out: []u8) usize {
    var hs_buf: [8192]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    var hs_len: usize = 0;
    if (msg.len >= 4 and rand.uintLessThan(u8, 4) != 0) {
        // Structure-aware body mutation with a correct (or rarely wrong) header.
        const body = fm.mutateHello(rand, kind, msg[4..], hs_buf[4..], &scratch);
        hs_buf[0] = msg[0];
        const declared: usize = if (rand.uintLessThan(u8, 10) == 0) rand.uintAtMost(usize, body.len + 8) else body.len;
        std.mem.writeInt(u24, hs_buf[1..4], @intCast(declared), .big);
        hs_len = 4 + body.len;
    } else {
        @memcpy(hs_buf[0..msg.len], msg);
        hs_len = fm.mutateRaw(rand, &hs_buf, msg.len);
    }
    // Occasionally append a second (garbage or duplicated) handshake message.
    if (rand.uintLessThan(u8, 10) == 0 and hs_buf.len - hs_len >= msg.len) {
        @memcpy(hs_buf[hs_len..][0..msg.len], msg);
        hs_len += msg.len;
    }
    var n = frameRecords(rand, hs_buf[0..hs_len], out);
    if (rand.uintLessThan(u8, 6) == 0) n = fm.mutateRaw(rand, out, n);
    return n;
}

/// Deliver `stream` to a server in random cuts. Returns true while the server
/// is still alive (no error). Enforces the fail-closed latch on error.
fn feedServer(rand: std.Random, alloc: std.mem.Allocator, server: *Server, stream: []const u8) !bool {
    var cuts: [64]usize = undefined;
    const n = fm.randomCuts(rand, stream.len, &cuts);
    var start: usize = 0;
    for (cuts[0..n]) |end| {
        const chunk = stream[start..end];
        start = end;
        const res = server.feed(chunk) catch |err| {
            // Alert construction must be safe after any engine error.
            if (server.takeAlert(err)) |a| alloc.free(a);
            try std.testing.expectError(error.BadState, server.feed("x"));
            return false;
        };
        switch (res) {
            .need_more => {},
            .bytes_to_send => |b| alloc.free(b),
        }
        if (server.handshakeDone()) return true;
    }
    return true;
}

fn feedClient(rand: std.Random, alloc: std.mem.Allocator, client: *Client, stream: []const u8, keep: ?*?[]u8) !bool {
    var cuts: [64]usize = undefined;
    const n = fm.randomCuts(rand, stream.len, &cuts);
    var start: usize = 0;
    for (cuts[0..n]) |end| {
        const chunk = stream[start..end];
        start = end;
        const res = client.feed(chunk) catch {
            try std.testing.expectError(error.BadState, client.feed("x"));
            return false;
        };
        switch (res) {
            .need_more => {},
            .bytes_to_send => |b| {
                if (keep) |k| {
                    if (k.*) |old| alloc.free(old);
                    k.* = b;
                } else alloc.free(b);
            },
        }
        if (client.handshakeDone()) return true;
    }
    return true;
}

fn expectBytes(r: anytype) ![]u8 {
    return switch (r) {
        .bytes_to_send => |b| b,
        .need_more => error.TestUnexpectedResult,
    };
}

test "engine fuzz: TLS 1.3 server survives mutated real ClientHellos with record splits" {
    const alloc = std.testing.allocator;
    var fx: Fixture = undefined;
    try fx.init();

    // Base ClientHellos from every client preset (real engine output).
    const n_bases = 7;
    var bases: [n_bases][]u8 = undefined;
    var made: usize = 0;
    defer for (bases[0..made]) |b| alloc.free(b);
    while (made < n_bases) : (made += 1) {
        var c = try fx.initClient(alloc, @intCast(made));
        defer c.deinit();
        const ch = try c.start();
        defer alloc.free(ch);
        var hs: [4096]u8 = undefined;
        const l = extractHandshake(ch, &hs);
        bases[made] = try alloc.dupe(u8, hs[0..l]);
    }

    var prng = std.Random.DefaultPrng.init(0x7153_5E2F_0001_C11E);
    const rand = prng.random();
    var flight: [16384]u8 = undefined;
    var iter: usize = 0;
    var survived: usize = 0;
    while (iter < 120) : (iter += 1) {
        const preset = rand.int(u8);
        var server = try Server.init(alloc, fx.serverConfig(preset));
        defer server.deinit();
        const base = bases[rand.uintLessThan(usize, n_bases)];
        const n = mutateFlight(rand, .client_hello, base, &flight);
        if (!try feedServer(rand, alloc, &server, flight[0..n])) continue;
        survived += 1;
        // Still alive: drive a second input. After HRR this is ClientHello2;
        // otherwise it lands on the encrypted-record path as junk.
        const base2 = bases[rand.uintLessThan(usize, n_bases)];
        const n2 = mutateFlight(rand, .client_hello, base2, &flight);
        _ = try feedServer(rand, alloc, &server, flight[0..n2]);
    }
    // The schedule must keep a meaningful fraction of inputs alive past the
    // first flight, or the harness only exercises the outer rejects.
    try std.testing.expect(survived > 8);
}

test "engine fuzz: TLS 1.3 server survives a mutated client second flight" {
    const alloc = std.testing.allocator;
    var fx: Fixture = undefined;
    try fx.init();
    var prng = std.Random.DefaultPrng.init(0x7153_5E2F_0002_F1A1);
    const rand = prng.random();

    var buf: [8192]u8 = undefined;
    var iter: usize = 0;
    while (iter < 40) : (iter += 1) {
        // Server-auth or mTLS (client declines) presets that still complete.
        const preset: u8 = switch (rand.uintLessThan(u8, 3)) {
            0 => 0,
            1 => 1,
            else => 2,
        };
        var server = try Server.init(alloc, fx.serverConfig(preset));
        defer server.deinit();
        var client = try fx.initClient(alloc, 0);
        defer client.deinit();

        const ch = try client.start();
        defer alloc.free(ch);
        const sflight = try expectBytes(try server.feed(ch));
        defer alloc.free(sflight);
        const cfin = try expectBytes(try client.feed(sflight));
        defer alloc.free(cfin);
        if (cfin.len > buf.len) return error.TestUnexpectedResult;

        // Mutate the encrypted client flight: raw bytes, record headers,
        // injected CCS / trailing garbage, truncation, then random cuts.
        @memcpy(buf[0..cfin.len], cfin);
        var n = cfin.len;
        switch (rand.uintLessThan(u8, 4)) {
            0 => n = fm.mutateRaw(rand, &buf, n),
            1 => { // corrupt a record header byte only
                if (n >= 5) buf[rand.uintLessThan(usize, 5)] ^= rand.int(u8) | 1;
            },
            2 => { // prepend a legacy CCS (allowed) or a duplicate CCS + junk
                const ccs = [_]u8{ record_ccs, 3, 3, 0, 1, 1 };
                std.mem.copyBackwards(u8, buf[ccs.len .. n + ccs.len], buf[0..n]);
                @memcpy(buf[0..ccs.len], &ccs);
                n += ccs.len;
                if (rand.boolean()) n = fm.mutateRaw(rand, &buf, n);
            },
            else => {}, // pristine bytes, random delivery cuts only
        }
        const alive = try feedServer(rand, alloc, &server, buf[0..n]);
        if (alive and server.handshakeDone()) {
            // Post-handshake: junk records into decrypt() must also fail typed.
            n = fm.mutateRaw(rand, &buf, @min(n, 64));
            if (server.decrypt(buf[0..n])) |pt| alloc.free(pt) else |_| {}
        }
    }
}

test "engine fuzz: TLS 1.3 client survives mutated real server flights" {
    const alloc = std.testing.allocator;
    var fx: Fixture = undefined;
    try fx.init();
    var prng = std.Random.DefaultPrng.init(0x7153_5E2F_0003_C0DE);
    const rand = prng.random();

    var buf: [16384]u8 = undefined;
    var hs: [16384]u8 = undefined;
    var iter: usize = 0;
    while (iter < 45) : (iter += 1) {
        const cpreset: u8 = rand.uintLessThan(u8, 7);
        var server = try Server.init(alloc, fx.serverConfig(if (cpreset == 3) 4 else rand.uintLessThan(u8, 4)));
        defer server.deinit();
        var client = try fx.initClient(alloc, cpreset);
        defer client.deinit();
        const ch = try client.start();
        defer alloc.free(ch);
        const sflight = server.feed(ch) catch continue;
        const sbytes = switch (sflight) {
            .bytes_to_send => |b| b,
            .need_more => continue,
        };
        defer alloc.free(sbytes);
        if (sbytes.len > buf.len) return error.TestUnexpectedResult;

        // Split the flight: leading plaintext ServerHello/HRR record(s) vs the
        // encrypted remainder (CCS + application_data records).
        var p: usize = 0;
        while (sbytes.len - p >= 5 and sbytes[p] == record_handshake) {
            p += 5 + std.mem.readInt(u16, sbytes[p + 3 ..][0..2], .big);
        }
        p = @min(p, sbytes.len);
        const hs_len = extractHandshake(sbytes[0..p], &hs);

        var n: usize = 0;
        switch (rand.uintLessThan(u8, 4)) {
            0, 1 => { // structure-aware ServerHello / HRR, original encrypted tail
                n = mutateFlight(rand, .server_hello, hs[0..hs_len], &buf);
                const tail = sbytes[p..];
                if (buf.len - n >= tail.len) {
                    @memcpy(buf[n..][0..tail.len], tail);
                    n += tail.len;
                }
            },
            2 => { // pristine ServerHello, mutated encrypted records
                @memcpy(buf[0..sbytes.len], sbytes);
                n = sbytes.len;
                if (n > p) {
                    const tail_len = fm.mutateRaw(rand, buf[p..], n - p);
                    n = p + tail_len;
                }
            },
            else => { // whole-flight raw mutation
                @memcpy(buf[0..sbytes.len], sbytes);
                n = fm.mutateRaw(rand, &buf, sbytes.len);
            },
        }
        var reply: ?[]u8 = null;
        defer if (reply) |r| alloc.free(r);
        const alive = try feedClient(rand, alloc, &client, buf[0..n], &reply);
        // A surviving HRR path produced ClientHello2: hand it to the server and
        // feed the server's real response through the client too.
        if (alive and !client.handshakeDone() and reply != null and server.hrr_sent) {
            const r2 = server.feed(reply.?) catch continue;
            switch (r2) {
                .bytes_to_send => |b| {
                    defer alloc.free(b);
                    if (b.len <= buf.len) {
                        @memcpy(buf[0..b.len], b);
                        const m = if (rand.boolean()) fm.mutateRaw(rand, &buf, b.len) else b.len;
                        _ = try feedClient(rand, alloc, &client, buf[0..m], null);
                    }
                },
                .need_more => {},
            }
        }
    }
}

test "engine fuzz: an unmutated schedule still completes (harness sanity)" {
    // Guards against a harness that silently mutates everything: with
    // mutation disabled, framing + random cuts alone must complete handshakes.
    const alloc = std.testing.allocator;
    var fx: Fixture = undefined;
    try fx.init();
    var prng = std.Random.DefaultPrng.init(0x7153_5E2F_0004_5A4E);
    const rand = prng.random();
    var buf: [16384]u8 = undefined;
    var iter: usize = 0;
    while (iter < 6) : (iter += 1) {
        var server = try Server.init(alloc, fx.serverConfig(0));
        defer server.deinit();
        var client = try fx.initClient(alloc, 0);
        defer client.deinit();
        const ch = try client.start();
        defer alloc.free(ch);
        var hs: [4096]u8 = undefined;
        const hl = extractHandshake(ch, &hs);
        // Re-frame without stray records: retry until a clean framing occurs.
        var n: usize = 0;
        var p: usize = 0;
        while (p < hl) {
            const frag = @min(hl - p, rand.intRangeAtMost(usize, 1, 200));
            buf[n] = record_handshake;
            buf[n + 1] = 3;
            buf[n + 2] = 3;
            std.mem.writeInt(u16, buf[n + 3 ..][0..2], @intCast(frag), .big);
            @memcpy(buf[n + 5 ..][0..frag], hs[p..][0..frag]);
            n += 5 + frag;
            p += frag;
        }
        var cuts: [64]usize = undefined;
        const nc = fm.randomCuts(rand, n, &cuts);
        var start: usize = 0;
        var sflight: ?[]u8 = null;
        defer if (sflight) |s| alloc.free(s);
        for (cuts[0..nc]) |end| {
            switch (try server.feed(buf[start..end])) {
                .bytes_to_send => |b| sflight = b,
                .need_more => {},
            }
            start = end;
        }
        const cfin = try expectBytes(try client.feed(sflight orelse return error.TestUnexpectedResult));
        defer alloc.free(cfin);
        _ = try server.feed(cfin);
        try std.testing.expect(server.handshakeDone());
        try std.testing.expect(client.handshakeDone());
    }
}
