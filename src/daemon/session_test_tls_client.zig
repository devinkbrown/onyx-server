// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test-only live mutual-TLS client. Import from test bodies, never daemon
//! runtime code. Certificate DER, trust-anchor DER and signing key are borrowed
//! through deinit; this owner closes only its own socket and TLS allocations.
//! Errors are static: credentials and plaintext are never logged here.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const tls_client = @import("../crypto/tls_client.zig");
const tls_record = @import("../crypto/tls_record.zig");
const sign = @import("../crypto/sign.zig");
const platform = @import("../substrate/platform.zig");

pub const Client = struct {
    const default_timeout_ms = 5_000;
    const max_timeout_ms = 60_000;
    const max_plaintext_bytes = 256 * 1024;
    const max_ciphertext_bytes = 64 * 1024;
    const max_handshake_bytes = 256 * 1024;

    allocator: std.mem.Allocator,
    fd: posix.fd_t,
    tls: tls_client.Client,
    cipher: std.ArrayList(u8) = .empty,
    plain: std.ArrayList(u8) = .empty,

    pub fn connect(
        allocator: std.mem.Allocator,
        port: u16,
        server_name: []const u8,
        trust_anchors: []const []const u8,
        client_der: []const u8,
        client_sign: sign.KeyPair,
    ) !Client {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .openbsd) return error.Unsupported;
        const deadline = try deadlineAfter(default_timeout_ms);
        var self = Client{
            .allocator = allocator,
            .fd = try connectLoopback(port, deadline),
            .tls = undefined,
        };
        errdefer closeSocket(self.fd);
        self.tls = try tls_client.Client.init(allocator, .{
            .server_name = server_name,
            .trust_anchors = trust_anchors,
        });
        errdefer self.tls.deinit();
        errdefer self.cipher.deinit(allocator);
        errdefer self.plain.deinit(allocator);
        self.tls.setClientCertForTest(client_der, client_sign);
        const hello = try self.tls.start();
        defer allocator.free(hello);
        try self.writeWire(hello, deadline);
        var incoming: [4096]u8 = undefined;
        var received: usize = 0;
        while (!self.tls.handshakeDone()) {
            const n = try self.readWire(&incoming, deadline);
            if (n > max_handshake_bytes - received) return error.HandshakeLimitExceeded;
            received += n;
            switch (try self.tls.feed(incoming[0..n])) {
                .bytes_to_send => |bytes| {
                    defer allocator.free(bytes);
                    try self.writeWire(bytes, deadline);
                },
                .need_more => {},
            }
        }
        // Finished and the first application/control records can share a read.
        // Copy this borrowed tail once; subsequent reads use our own framer.
        try self.appendCipher(self.tls.pendingBytes());
        try self.processRecords(deadline);
        return self;
    }

    pub fn deinit(self: *Client) void {
        closeSocket(self.fd);
        self.tls.deinit();
        self.cipher.deinit(self.allocator);
        self.plain.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn send(self: *Client, bytes: []const u8) !void {
        if (bytes.len > max_plaintext_bytes) return error.OutputLimitExceeded;
        const deadline = try deadlineAfter(default_timeout_ms);
        try self.flushPending(deadline);
        const wire = try self.tls.encrypt(bytes);
        defer self.allocator.free(wire);
        try self.writeWire(wire, deadline);
    }

    /// Wait for a substring in accumulated plaintext. Call reset before sending
    /// a new marker when an earlier matching response must not satisfy the wait.
    pub fn readUntil(self: *Client, needle: []const u8, timeout_ms: i64) !void {
        if (needle.len == 0 or needle.len > max_plaintext_bytes) return error.InvalidNeedle;
        const deadline = try deadlineAfter(timeout_ms);
        var incoming: [8192]u8 = undefined;
        while (std.mem.indexOf(u8, self.plain.items, needle) == null) {
            try self.processRecords(deadline);
            if (std.mem.indexOf(u8, self.plain.items, needle) != null) return;
            const n = try self.readWire(&incoming, deadline);
            try self.appendCipher(incoming[0..n]);
        }
    }

    pub fn reset(self: *Client) void {
        self.plain.clearRetainingCapacity();
    }

    pub fn written(self: *const Client) []const u8 {
        return self.plain.items;
    }

    fn appendCipher(self: *Client, bytes: []const u8) !void {
        if (bytes.len > max_ciphertext_bytes - self.cipher.items.len) return error.InputLimitExceeded;
        try self.cipher.appendSlice(self.allocator, bytes);
    }

    fn processRecords(self: *Client, deadline: i64) !void {
        while (self.cipher.items.len >= 5) {
            const body_len = std.mem.readInt(u16, self.cipher.items[3..5], .big);
            if (body_len > tls_record.max_ciphertext_len) return error.RecordLimitExceeded;
            const wire_len = 5 + @as(usize, body_len);
            if (self.cipher.items.len < wire_len) break;
            switch (try self.tls.decryptApp(self.cipher.items[0..wire_len])) {
                .application_data => |bytes| {
                    defer self.allocator.free(bytes);
                    if (bytes.len > max_plaintext_bytes - self.plain.items.len) return error.OutputLimitExceeded;
                    try self.plain.appendSlice(self.allocator, bytes);
                },
                .control => {},
            }
            std.mem.copyForwards(u8, self.cipher.items[0 .. self.cipher.items.len - wire_len], self.cipher.items[wire_len..]);
            self.cipher.shrinkRetainingCapacity(self.cipher.items.len - wire_len);
            try self.flushPending(deadline);
        }
    }

    fn flushPending(self: *Client, deadline: i64) !void {
        if (try self.tls.takePendingSend()) |bytes| {
            defer self.allocator.free(bytes);
            try self.writeWire(bytes, deadline);
        }
    }

    fn writeWire(self: *Client, bytes: []const u8, deadline: i64) !void {
        var sent: usize = 0;
        while (sent < bytes.len) {
            try waitReady(self.fd, posix.POLL.OUT, deadline);
            const rc = posix.system.sendto(self.fd, bytes[sent..].ptr, bytes.len - sent, posix.MSG.NOSIGNAL, null, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.ConnectionClosed;
                    sent += @intCast(rc);
                },
                .INTR, .AGAIN => continue,
                else => return error.SocketWriteFailed,
            }
        }
    }

    fn readWire(self: *Client, out: []u8, deadline: i64) !usize {
        while (true) {
            try waitReady(self.fd, posix.POLL.IN, deadline);
            const rc = posix.system.read(self.fd, out.ptr, out.len);
            switch (posix.errno(rc)) {
                .SUCCESS => return if (rc == 0) error.ConnectionClosed else @intCast(rc),
                .INTR, .AGAIN => continue,
                else => return error.SocketReadFailed,
            }
        }
    }
};

fn deadlineAfter(timeout_ms: i64) !i64 {
    if (timeout_ms <= 0 or timeout_ms > Client.max_timeout_ms) return error.InvalidTimeout;
    return std.math.add(i64, platform.monotonicMillis(), timeout_ms) catch error.InvalidTimeout;
}

fn waitReady(fd: posix.fd_t, events: i16, deadline: i64) !void {
    while (true) {
        const remaining = deadline - platform.monotonicMillis();
        if (remaining <= 0) return error.TestTimeout;
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
        const count = try posix.poll(&fds, @intCast(@min(remaining, 50)));
        if (count == 0) continue;
        if (fds[0].revents & posix.POLL.NVAL != 0) return error.InvalidSocket;
        if (fds[0].revents & events != 0) return;
        if (fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) return error.ConnectionClosed;
    }
}

fn connectLoopback(port: u16, deadline: i64) !posix.fd_t {
    const rc = posix.system.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, posix.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketUnavailable;
    const fd: posix.fd_t = @intCast(rc);
    errdefer closeSocket(fd);
    var addr: posix.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
    };
    const connected = posix.system.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    switch (posix.errno(connected)) {
        .SUCCESS => return fd,
        .INPROGRESS, .INTR => {},
        .CONNREFUSED => return error.ConnectionRefused,
        else => return error.SocketConnectFailed,
    }
    try waitReady(fd, posix.POLL.OUT, deadline);
    var socket_error: i32 = 0;
    var size: posix.socklen_t = @sizeOf(i32);
    const checked = posix.system.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&socket_error).ptr, &size);
    if (posix.errno(checked) != .SUCCESS or size != @sizeOf(i32) or socket_error != 0) return error.SocketConnectFailed;
    return fd;
}

fn closeSocket(fd: posix.fd_t) void {
    _ = posix.system.shutdown(fd, posix.SHUT.RDWR);
    _ = posix.system.close(fd);
}
