// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Actual native workers against isolated guest SMTP/HTTPS peers.
//! Requires the test-only 198.51.100.77/32 alias on the guest's lo0 interface.
//! The runner must remove that alias on success and failure. The production
//! WebPush address guard remains active; ordinary loopback addresses are denied.
const std = @import("std");
const root = @import("onyx_server");
const posix = std.posix;
const sys = posix.system;
const net = root.daemon.native_network;
const runtime = root.daemon.os_runtime;
const platform = root.substrate.platform;
const TlsConn = root.daemon.tls_conn.TlsConn;
const Ed25519 = std.crypto.sign.Ed25519;
const ecdh = root.crypto.ecdh_p256;
const ecdsa = root.crypto.ecdsa_p256;
const expect = std.testing.expect;
const mock_address = "198.51.100.77";
const payloads = [_][]const u8{ "{\"type\":\"dm\",\"body\":\"native push\"}", "{\"type\":\"gone\"}" };

fn portOf(fd: i32) !u16 {
    var address: posix.sockaddr.in = undefined;
    var length: posix.socklen_t = @sizeOf(@TypeOf(address));
    try expect(posix.errno(sys.getsockname(fd, @ptrCast(&address), &length)) == .SUCCESS);
    try expect(length == @sizeOf(@TypeOf(address)) and address.family == posix.AF.INET);
    return std.mem.bigToNative(u16, address.port);
}
fn acceptPeer(listener: i32) !i32 {
    var ready = [_]posix.pollfd{.{ .fd = listener, .events = posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(c_int, 1), sys.poll(&ready, 1, 5000));
    const fd = sys.accept(listener, null, null);
    if (posix.errno(fd) != .SUCCESS) return error.AcceptFailed;
    errdefer runtime.close(fd);
    try net.setBlocking(fd);
    try net.setTimeout(fd, 3000);
    return fd;
}
fn clearLine(fd: i32, bytes: []u8) ![]const u8 {
    var n: usize = 0;
    while (n < bytes.len) {
        n += try net.readSome(fd, bytes[n..][0..1]);
        if (n >= 2 and std.mem.eql(u8, bytes[n - 2 .. n], "\r\n")) return bytes[0..n];
    }
    return error.LineTooLong;
}

const Stream = struct {
    fd: i32,
    tls: TlsConn,
    plaintext: [64 * 1024]u8 = undefined,
    n: usize = 0,
    fn feed(self: *Stream) !void {
        var wire: [16 * 1024]u8 = undefined;
        const n = try net.readSome(self.fd, &wire);
        const out = try self.tls.onInbound(wire[0..n]);
        if (out.handshake_bytes.len != 0) try net.writeAll(self.fd, out.handshake_bytes);
        if (out.plaintext.len > self.plaintext.len - self.n) return error.RequestTooLarge;
        @memcpy(self.plaintext[self.n..][0..out.plaintext.len], out.plaintext);
        self.n += out.plaintext.len;
    }
    fn until(self: *Stream, delimiter: []const u8) ![]const u8 {
        while (true) {
            if (std.mem.indexOf(u8, self.plaintext[0..self.n], delimiter)) |at| return self.plaintext[0 .. at + delimiter.len];
            try self.feed();
        }
    }
    fn consume(self: *Stream, n: usize) void {
        std.mem.copyForwards(u8, self.plaintext[0 .. self.n - n], self.plaintext[n..self.n]);
        self.n -= n;
    }
    fn write(self: *Stream, text: []const u8) !void {
        try net.writeAll(self.fd, try self.tls.write(text));
    }
    fn line(self: *Stream, prefix: []const u8, response: []const u8) !void {
        const command = try self.until("\r\n");
        try expect(std.mem.startsWith(u8, command, prefix));
        const n = command.len;
        try self.write(response);
        self.consume(n);
    }
};

const Peer = struct {
    allocator: std.mem.Allocator,
    listener: i32,
    certificate: []const u8,
    key: Ed25519.KeyPair,
    done: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,
    requests: usize = 0,
    ua: ecdh.KeyPair = undefined,
    auth: [16]u8 = @splat(7),
    vapid: ecdsa.KeyPair = undefined,
    port: u16 = 0,

    fn smtp(self: *Peer) !void {
        const fd = try acceptPeer(self.listener);
        defer runtime.close(fd);
        try net.writeAll(fd, "220 native.mock ESMTP\r\n");
        var line_buf: [1024]u8 = undefined;
        try std.testing.expectEqualStrings("EHLO native.test\r\n", try clearLine(fd, &line_buf));
        try net.writeAll(fd, "250-native.mock\r\n250 STARTTLS\r\n");
        try std.testing.expectEqualStrings("STARTTLS\r\n", try clearLine(fd, &line_buf));
        try net.writeAll(fd, "220 start TLS\r\n");
        var stream = Stream{ .fd = fd, .tls = try TlsConn.init(self.allocator, .{ .cert_chain = &.{self.certificate}, .signing_key = self.key }) };
        defer stream.tls.deinit();
        try stream.line("EHLO native.test\r\n", "250-native.mock\r\n250 AUTH PLAIN\r\n");
        const auth_line = try stream.until("\r\n");
        try expect(std.mem.startsWith(u8, auth_line, "AUTH PLAIN "));
        const encoded = auth_line[11 .. auth_line.len - 2];
        var decoded: [128]u8 = undefined;
        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
        try std.base64.standard.Decoder.decode(decoded[0..decoded_len], encoded);
        try std.testing.expectEqualStrings("\x00native-user\x00fixture-pass", decoded[0..decoded_len]);
        const auth_len = auth_line.len;
        try stream.write("235 authenticated\r\n");
        stream.consume(auth_len);
        try stream.line("MAIL FROM:<sender@native.test>", "250 sender ok\r\n");
        try stream.line("RCPT TO:<receiver@native.test>", "250 recipient ok\r\n");
        try stream.line("DATA\r\n", "354 send message\r\n");
        const message = try stream.until("\r\n.\r\n");
        try expect(std.mem.indexOf(u8, message, "Subject: native SMTP\r\n") != null);
        try expect(std.mem.indexOf(u8, message, "native SMTP body") != null);
        try expect(std.mem.indexOf(u8, message, "..native marker") != null);
        const message_len = message.len;
        try stream.write("250 accepted\r\n");
        stream.consume(message_len);
        try stream.line("QUIT\r\n", "221 goodbye\r\n");
        self.requests += 1;
    }
    fn smtpThread(self: *Peer) void {
        defer self.done.store(true, .release);
        self.smtp() catch |err| {
            self.failure = err;
        };
    }
    fn pushThread(self: *Peer) void {
        defer self.done.store(true, .release);
        self.push() catch |err| {
            self.failure = err;
        };
    }
    fn push(self: *Peer) !void {
        for (payloads, 0..) |payload, index| {
            const fd = try acceptPeer(self.listener);
            defer runtime.close(fd);
            var stream = Stream{ .fd = fd, .tls = try TlsConn.init(self.allocator, .{ .cert_chain = &.{self.certificate}, .signing_key = self.key }) };
            defer stream.tls.deinit();
            const header = try stream.until("\r\n\r\n");
            try expect(std.mem.startsWith(u8, header, if (index == 0) "POST /send/one HTTP/1.1\r\n" else "POST /send/gone HTTP/1.1\r\n"));
            const body_len = try std.fmt.parseInt(usize, try headerValue(header, "content-length"), 10);
            const header_len = header.len;
            try expect(body_len < 4096);
            while (stream.n < header_len + body_len) try stream.feed();
            try std.testing.expectEqualStrings("aes128gcm", try headerValue(header, "content-encoding"));
            try std.testing.expectEqualStrings("application/octet-stream", try headerValue(header, "content-type"));
            try std.testing.expectEqualStrings("43200", try headerValue(header, "ttl"));
            try verifyVapid(try headerValue(header, "authorization"), self.vapid, self.port);
            try decryptPush(self.allocator, stream.plaintext[header_len .. header_len + body_len], self.ua, self.auth, payload);
            try stream.write(if (index == 0) "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" else "HTTP/1.1 410 Gone\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            self.requests += 1;
        }
    }
};

fn headerValue(header: []const u8, name: []const u8) ![]const u8 {
    var lines = std.mem.splitSequence(u8, header, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return error.MissingHeader;
}
fn verifyVapid(auth: []const u8, key: ecdsa.KeyPair, port: u16) !void {
    try expect(std.mem.startsWith(u8, auth, "vapid t="));
    const key_at = std.mem.indexOf(u8, auth, ", k=") orelse return error.InvalidVapid;
    const jwt = auth[8..key_at];
    const encoded_key = auth[key_at + 4 ..];
    const public = try root.crypto.webpush.decodeFixed(65, encoded_key);
    try std.testing.expectEqualSlices(u8, &key.public_key.toUncompressedSec1(), &public);
    const signature_at = std.mem.lastIndexOfScalar(u8, jwt, '.') orelse return error.InvalidVapid;
    const bytes = try root.crypto.webpush.decodeFixed(64, jwt[signature_at + 1 ..]);
    const sig = ecdsa.Signature.fromBytes(bytes);
    try expect(ecdsa.verify(sig, jwt[0..signature_at], key.public_key));
    const claims_at = std.mem.indexOfScalar(u8, jwt, '.') orelse return error.InvalidVapid;
    const encoded_claims = jwt[claims_at + 1 .. signature_at];
    var decoded: [512]u8 = undefined;
    const n = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded_claims);
    try std.base64.url_safe_no_pad.Decoder.decode(decoded[0..n], encoded_claims);
    const claims = try std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, decoded[0..n], .{});
    defer claims.deinit();
    var audience: [128]u8 = undefined;
    const expected = try std.fmt.bufPrint(&audience, "https://push.native.test:{d}", .{port});
    try std.testing.expectEqualStrings(expected, claims.value.object.get("aud").?.string);
    try std.testing.expectEqualStrings("mailto:fixture@native.test", claims.value.object.get("sub").?.string);
    const exp = claims.value.object.get("exp").?.integer;
    const now = @divTrunc(platform.realtimeMillis(), 1000);
    try expect(exp > now and exp <= now + 43200);
}
fn decryptPush(allocator: std.mem.Allocator, body: []const u8, ua: ecdh.KeyPair, auth: [16]u8, expected: []const u8) !void {
    const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const aes = std.crypto.aead.aes_gcm.Aes128Gcm;
    try expect(body.len > 86 + 16 and body[20] == 65);
    try std.testing.expectEqual(@as(u32, 4096), std.mem.readInt(u32, body[16..20], .big));
    const as_public: [65]u8 = body[21..86].*;
    var shared = try ecdh.sharedSecret(ua.secret, as_public);
    defer std.crypto.secureZero(u8, &shared);
    var prk_key = hkdf.extract(&auth, &shared);
    defer std.crypto.secureZero(u8, &prk_key);
    var key_info: [14 + 65 + 65]u8 = undefined;
    @memcpy(key_info[0..14], "WebPush: info\x00");
    @memcpy(key_info[14..79], &ua.public_sec1);
    @memcpy(key_info[79..], &as_public);
    var ikm: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &ikm);
    hkdf.expand(&ikm, &key_info, prk_key);
    var prk = hkdf.extract(body[0..16], &ikm);
    defer std.crypto.secureZero(u8, &prk);
    var key: [16]u8 = undefined;
    var nonce: [12]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    defer std.crypto.secureZero(u8, &nonce);
    hkdf.expand(&key, "Content-Encoding: aes128gcm\x00", prk);
    hkdf.expand(&nonce, "Content-Encoding: nonce\x00", prk);
    const ciphertext = body[86 .. body.len - 16];
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(plaintext);
    try aes.decrypt(plaintext, ciphertext, body[body.len - 16 ..][0..16].*, "", nonce, key);
    try expect(plaintext.len == expected.len + 1 and plaintext[plaintext.len - 1] == 2);
    try std.testing.expectEqualStrings(expected, plaintext[0..expected.len]);
}

fn smtpProbe(allocator: std.mem.Allocator, der: []const u8, kp: Ed25519.KeyPair) !void {
    const listener = try root.daemon.reuseport.createOpenBsdListener("127.0.0.1", 0, 8, false);
    defer runtime.close(listener);
    var peer = Peer{ .allocator = allocator, .listener = listener, .certificate = der, .key = kp };
    const thread = try std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, Peer.smtpThread, .{&peer});
    defer thread.join();
    var sender = try root.daemon.mail_sender.Sender.init(allocator, .{
        .relay_host = "127.0.0.1",
        .relay_port = try portOf(listener),
        .starttls = true,
        .trust_anchors = &.{der},
        .ehlo_domain = "native.test",
        .from = "sender@native.test",
        .user = "native-user",
        .pass = "fixture-pass",
    });
    defer sender.deinit();
    sender.start();
    try expect(sender.thread != null);
    sender.enqueue("receiver@native.test", "native SMTP", "native SMTP body\n.native marker");
    const deadline = platform.monotonicMillis() + 5000;
    while (!peer.done.load(.acquire) and platform.monotonicMillis() < deadline) runtime.sleepMillis(10);
    try expect(peer.done.load(.acquire));
    sender.stop();
    if (peer.failure) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), peer.requests);
    try std.testing.expectEqual(@as(u64, 0), sender.failure_seq);
    std.debug.print("PASS native SMTP worker: STARTTLS, trusted TLS, encrypted AUTH, envelope, dot-stuffed DATA, QUIT, shutdown\n", .{});
}
fn pushProbe(allocator: std.mem.Allocator, io: std.Io, der: []const u8, kp: Ed25519.KeyPair) !void {
    const listener = try root.daemon.reuseport.createOpenBsdListener(mock_address, 0, 8, false);
    defer runtime.close(listener);
    var peer = Peer{ .allocator = allocator, .listener = listener, .certificate = der, .key = kp, .ua = try ecdh.generate(), .vapid = ecdsa.KeyPair.generate(io), .port = try portOf(listener) };
    const thread = try std.Thread.spawn(.{ .stack_size = 8 * 1024 * 1024 }, Peer.pushThread, .{&peer});
    defer thread.join();
    var worker = root.daemon.webpush.Worker{
        .allocator = allocator,
        .vapid = peer.vapid,
        .subject = "mailto:fixture@native.test",
        .trust_anchors = &.{der},
        .resolver = .{ .ctx = &peer, .resolveFn = struct {
            fn resolve(_: *anyopaque, host: []const u8, port: u16) !std.Io.net.IpAddress {
                try std.testing.expectEqualStrings("push.native.test", host);
                return .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 77 }, .port = port } };
            }
        }.resolve },
    };
    defer worker.shutdown();
    try expect(!root.daemon.webpush.isDisallowedPushAddr(.{ .ip4 = .{ .bytes = .{ 198, 51, 100, 77 }, .port = peer.port } }));
    try expect(root.daemon.webpush.isDisallowedPushAddr(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = peer.port } }));
    for (payloads, 0..) |payload, index| {
        var url_buf: [128]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "https://push.native.test:{d}/send/{s}", .{ peer.port, if (index == 0) "one" else "gone" });
        try std.testing.expectEqual(root.daemon.webpush.Worker.EnqueueResult.queued, worker.enqueue(url, peer.ua.public_sec1, peer.auth, payload));
    }
    try worker.spawn();
    // Join before reading worker counters; preserve its dead list for checks.
    const joining = platform.monotonicMillis();
    worker.stop_flag.store(true, .release);
    worker.thread.?.join();
    worker.thread = null;
    try expect(platform.monotonicMillis() - joining < 5000);
    const deadline = platform.monotonicMillis() + 1000;
    while (!peer.done.load(.acquire) and platform.monotonicMillis() < deadline) runtime.sleepMillis(5);
    try expect(peer.done.load(.acquire));
    if (peer.failure) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), peer.requests);
    try std.testing.expectEqual(@as(usize, 1), worker.sent);
    try std.testing.expectEqual(@as(usize, 1), worker.failed);
    const dead = worker.drainDead();
    defer {
        for (dead) |item| allocator.free(item);
        allocator.free(dead);
    }
    try std.testing.expectEqual(@as(usize, 1), dead.len);
    try expect(std.mem.endsWith(u8, dead[0], "/send/gone"));
    std.debug.print("PASS native WebPush worker: trusted HTTPS, verified VAPID JWT, exact decrypted RFC8291 payloads,201 success,410 pruning, joined counters, SSRF guard unchanged\n", .{});
}
pub fn main(init: std.process.Init) !void {
    if (comptime @import("builtin").os.tag != .openbsd) return error.Unsupported;
    const kp = try Ed25519.KeyPair.generateDeterministic(@splat(0x43));
    var certificate: [1600]u8 = undefined;
    const der = try root.proto.x509_selfsign.buildSelfSigned(&certificate, .{
        .common_name = "push.native.test",
        .dns_names = &.{"push.native.test"},
        .ip_addresses = &.{&.{ 127, 0, 0, 1 }},
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 1, 2 },
        .key_pair = kp,
        .is_ca = true,
    });
    try smtpProbe(init.gpa, der, kp);
    try pushProbe(init.gpa, init.io, der, kp);
    std.debug.print("PASS all 2 native worker protocol scenarios\n", .{});
}
