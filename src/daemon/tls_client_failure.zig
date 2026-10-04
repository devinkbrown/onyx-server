// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

/// Attempt the client's one terminal wire batch before its socket is closed.
/// The batch owns any earlier KeyUpdate response followed by the fatal alert.
/// The caller retains its original receive error; write failures are reported
/// separately. The terminal write has its own absolute, finite deadline.
pub fn sendFatal(fd: i32, client: anytype, failure: anytype) void {
    const bytes = client.takeAlert(failure) orelse return;
    defer client.allocator.free(bytes);
    writeFatalBatch(fd, bytes, 1000) catch |send_error| {
        std.log.warn("TLS fatal alert write failed: {s}", .{@errorName(send_error)});
    };
}

fn sendNonblocking(fd: i32, bytes: []const u8) error{ SendFailed, WouldBlock }!usize {
    // No libc-linked send on Windows; the TLS-fatal path reports failure.
    if (comptime @import("builtin").os.tag == .windows) return error.SendFailed;
    const posix = std.posix;
    // Winsock has neither `NOSIGNAL` nor `DONTWAIT` (nonblocking is a socket
    // mode there, set out-of-band). Byte-identical off Windows.
    const flags = if (comptime @import("builtin").os.tag == .windows) 0 else posix.MSG.NOSIGNAL | posix.MSG.DONTWAIT;
    const rc = if (comptime @import("builtin").os.tag == .linux)
        posix.system.sendto(fd, bytes.ptr, bytes.len, flags, null, 0)
    else
        posix.system.send(fd, bytes.ptr, bytes.len, flags);
    return switch (posix.errno(rc)) {
        .SUCCESS => if (rc == 0) error.SendFailed else @intCast(rc),
        .AGAIN, .INTR => error.WouldBlock,
        else => error.SendFailed,
    };
}

fn writeFatalBatch(fd: i32, bytes: []const u8, timeout_ms: u31) error{ SendFailed, SendTimeout }!void {
    // No libc-linked poll on Windows; the TLS-fatal path reports failure.
    if (comptime @import("builtin").os.tag == .windows) return error.SendFailed;
    const posix = std.posix;
    const platform = @import("../substrate/platform.zig");
    const deadline = platform.monotonicMillis() + timeout_ms;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const remaining = deadline - platform.monotonicMillis();
        if (remaining <= 0) return error.SendTimeout;
        const n = sendNonblocking(fd, bytes[offset..]) catch |err| switch (err) {
            error.SendFailed => return error.SendFailed,
            error.WouldBlock => {
                var descriptors = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                const rc = posix.system.poll(&descriptors, 1, @intCast(remaining));
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        if (rc == 0) return error.SendTimeout;
                        if (descriptors[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return error.SendFailed;
                    },
                    .INTR => {},
                    else => return error.SendFailed,
                }
                continue;
            },
        };
        offset += n;
    }
}

pub fn testReadExact(fd: i32, bytes: []u8) !void {
    const runtime = @import("os_runtime.zig");
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = try runtime.read(fd, bytes[offset..]);
        if (n == 0) return error.TestUnexpectedResult;
        offset += n;
    }
}

fn openAlert(comptime Cipher: type, server: anytype, wire: []const u8, scratch: []u8, description: u8) !void {
    const record = @import("../crypto/tls_record.zig");
    var key: [Cipher.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    @memcpy(&key, server.client_app_keys.key[0..Cipher.key_length]);
    const parsed = try record.parseCiphertext(wire);
    const length = parsed.encrypted_record.len - Cipher.tag_length;
    var tag: [Cipher.tag_length]u8 = undefined;
    @memcpy(&tag, parsed.encrypted_record[length..]);
    const aad = parsed.headerBytes();
    try Cipher.decrypt(scratch[0..length], parsed.encrypted_record[0..length], tag, &aad, record.deriveNonce(server.client_app_keys.iv, server.app_read_seq), key);
    const opened = try record.decodeInnerPlaintext(scratch[0..length]);
    try std.testing.expectEqual(record.ContentType.alert, opened.content_type);
    try std.testing.expectEqualSlices(u8, &.{ 2, description }, opened.content);
}

pub fn testExpectAlert(server: anytype, wire: []const u8, description: u8) !void {
    var scratch: [128]u8 = undefined;
    switch (server.selected_suite.?) {
        .tls_aes_128_gcm_sha256 => try openAlert(std.crypto.aead.aes_gcm.Aes128Gcm, server, wire, &scratch, description),
        .tls_aes_256_gcm_sha384 => try openAlert(std.crypto.aead.aes_gcm.Aes256Gcm, server, wire, &scratch, description),
        .tls_chacha20_poly1305_sha256 => try openAlert(std.crypto.aead.chacha_poly.ChaCha20Poly1305, server, wire, &scratch, description),
    }
}

/// Shared real-peer fixture for the three production socket writers.
pub fn testFatalTransportProof(with_key_update: bool, write_all: anytype) !void {
    const a = std.testing.allocator;
    const runtime = @import("os_runtime.zig");
    const network = @import("native_network.zig");
    const posix = std.posix;
    const peer = try TestPeer.init(a);
    defer peer.deinit();
    const server = &peer.server;
    const client = &peer.client;
    var sockets: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer for (sockets) |fd| runtime.close(fd);
    for (sockets) |fd| try network.setTimeout(fd, 1000);
    const probe = try client.encrypt("writer probe");
    defer a.free(probe);
    try write_all(sockets[0], probe);
    var probe_wire: [128]u8 = undefined;
    try testReadExact(sockets[1], probe_wire[0..probe.len]);
    const probe_plain = try server.decrypt(probe_wire[0..probe.len]);
    defer a.free(probe_plain);
    try std.testing.expectEqualStrings("writer probe", probe_plain);
    if (with_key_update) {
        const update = try server.initiateKeyUpdate(true);
        defer a.free(update);
        try std.testing.expectEqual(@import("../crypto/tls_client.zig").AppRead.control, try client.decryptApp(update));
    }
    // Deliberately violate the negotiated bound with authenticated ciphertext.
    // The receiver must reject it and send fatal record_overflow over its socket.
    server.peer_record_size_limit = 16_385;
    const payload: [64]u8 = @splat(0x41);
    const oversized = try server.encrypt(&payload);
    defer a.free(oversized);
    try std.testing.expectError(error.RecordOverflow, client.decryptApp(oversized));
    sendFatal(sockets[0], client, error.RecordOverflow);
    const sent_seq = client.app_write_seq;
    sendFatal(sockets[0], client, error.RecordOverflow);
    try std.testing.expectEqual(sent_seq, client.app_write_seq);
    runtime.shutdownBoth(sockets[0]);
    var wire: [128]u8 = undefined;
    for (0..if (with_key_update) @as(usize, 2) else @as(usize, 1)) |index| {
        try testReadExact(sockets[1], wire[0..5]);
        const n = 5 + @as(usize, std.mem.readInt(u16, wire[3..5], .big));
        try std.testing.expect(n <= wire.len);
        try testReadExact(sockets[1], wire[5..n]);
        if (with_key_update and index == 0) {
            const content = try server.decrypt(wire[0..n]);
            defer a.free(content);
            try std.testing.expectEqual(@as(usize, 0), content.len);
            try std.testing.expectEqual(@as(u64, 0), server.app_read_seq);
        } else try testExpectAlert(server, wire[0..n], 22);
    }
    try std.testing.expectEqual(@as(usize, 0), try runtime.read(sockets[1], &wire));
    try std.testing.expect((try client.takePendingSend()) == null);
}

test "TLS client fatal transport: negotiated overflow reaches peer exactly once" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try testFatalTransportProof(false, testWriteAll);
}

test "TLS client fatal transport: queued KeyUpdate precedes new epoch alert" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    try testFatalTransportProof(true, testWriteAll);
}

fn testWriteAll(fd: i32, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = try @import("os_runtime.zig").write(fd, bytes[offset..]);
        if (n == 0) return error.TestUnexpectedResult;
        offset += n;
    }
}

/// Heap-stable certificate and real authenticated peers for local transport tests.
pub const TestPeer = struct {
    cert_buffer: [1024]u8 = undefined,
    chain: [1][]const u8 = undefined,
    server: @import("../crypto/tls_server.zig").Server,
    client: @import("../crypto/tls_client.zig").Client,

    pub fn init(a: std.mem.Allocator) !*TestPeer {
        const tls_server = @import("../crypto/tls_server.zig");
        const tls_client = @import("../crypto/tls_client.zig");
        const selfsign = @import("../proto/x509_selfsign.zig");
        const peer = try a.create(TestPeer);
        errdefer a.destroy(peer);
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x7c));
        const cert = try selfsign.buildSelfSigned(&peer.cert_buffer, .{
            .common_name = "irc.test",
            .not_before = 1_704_067_200,
            .not_after = 4_102_444_800,
            .serial = &.{ 0x7c, 1 },
            .key_pair = kp,
            .dns_names = &.{"irc.test"},
            .is_ca = true,
        });
        peer.chain = .{cert};
        peer.server = try tls_server.Server.init(a, .{ .cert_chain = &peer.chain, .signing_key = kp });
        errdefer peer.server.deinit();
        peer.client = try tls_client.Client.init(a, .{ .server_name = "irc.test", .trust_anchors = &peer.chain, .receive_record_size_limit = 64 });
        errdefer peer.client.deinit();
        const hello = try peer.client.start();
        defer a.free(hello);
        const flight = switch (try peer.server.feed(hello)) {
            .bytes_to_send => |bytes| bytes,
            .need_more => return error.TestUnexpectedResult,
        };
        defer a.free(flight);
        const finished = switch (try peer.client.feed(flight)) {
            .bytes_to_send => |bytes| bytes,
            .need_more => return error.TestUnexpectedResult,
        };
        defer a.free(finished);
        _ = try peer.server.feed(finished);
        try std.testing.expect(peer.server.handshakeDone() and peer.client.handshakeDone());
        return peer;
    }

    pub fn deinit(peer: *TestPeer) void {
        const a = peer.client.allocator;
        peer.client.deinit();
        peer.server.deinit();
        a.destroy(peer);
    }
};

test "TLS client fatal transport: a blocked peer cannot extend the terminal deadline" {
    // Unix-socketpair proof; no `socketpair` on Windows.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    const posix = std.posix;
    const runtime = @import("os_runtime.zig");
    const platform = @import("../substrate/platform.zig");
    var sockets: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0, &sockets)));
    defer for (sockets) |fd| runtime.close(fd);
    const fill: [16384]u8 = @splat(0x41);
    var filled: usize = 0;
    while (true) {
        const n = sendNonblocking(sockets[0], &fill) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        filled += n;
        try std.testing.expect(filled < 16 * 1024 * 1024);
    }
    try std.testing.expect(filled > 0);
    const start_ms = platform.monotonicMillis();
    try std.testing.expectError(error.SendTimeout, writeFatalBatch(sockets[0], &.{ 2, 22 }, 30));
    const elapsed = platform.monotonicMillis() - start_ms;
    try std.testing.expect(elapsed >= 20 and elapsed < 2000);
}
