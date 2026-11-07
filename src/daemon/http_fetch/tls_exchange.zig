// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded HTTP response collection and TLS record exchange.

const std = @import("std");
const builtin = @import("builtin");
const sys = if (builtin.os.tag == .windows) std.os.linux else std.posix.system;
const posix = std.posix;
const tls_client = @import("../../crypto/tls_client.zig");
const tls_client_failure = @import("../tls_client_failure.zig");
const tls12_client = @import("../../crypto/tls12_client.zig");
const http1 = @import("../../proto/http1_client.zig");
const Error = @import("contracts.zig").Error;
const Options = @import("contracts.zig").Options;
const Socket = @import("native_io.zig").Socket;
const writeAll = @import("native_io.zig").writeAll;
const readSome = @import("native_io.zig").readSome;

pub const max_tls_record = 16 * 1024 + 512;

/// TLS 1.2 variant of `getTls` (hardened `tls12_client`). Used as the fallback
/// when the TLS 1.3 handshake fails — broadens outbound reach to TLS-1.2-only
/// hosts. Mirrors `getTls` but uses the 1.2 client's `decrypt` (no KeyUpdate).
pub fn getTls12(
    allocator: std.mem.Allocator,
    fd: Socket,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
) Error![]u8 {
    var tc = try tls12_client.Client.init(allocator, .{
        .server_name = host,
        .trust_anchors = opts.trust_anchors,
        .disallowed_certs = opts.disallowed_certs,
        .windows_chain_policy = opts.windows_chain_policy,
        .alpn_protocols = &.{"http/1.1"},
        .now_unix_seconds = wallClockSeconds(),
        .crl = opts.crl,
        .require_crl = opts.require_crl,
    });
    defer tc.deinit();
    if (opts.insecure_skip_verify) tc.disableServerCertVerification();

    {
        const hello = try tc.start();
        defer allocator.free(hello);
        try writeAll(fd, hello);
    }
    var read_buf: [max_tls_record]u8 = undefined;
    while (!tc.handshakeDone()) {
        const n = try readSome(fd, &read_buf);
        switch (tc.feed(read_buf[0..n]) catch |err| {
            sendFatal(fd, &tc, err);
            return err;
        }) {
            .need_more => {},
            .bytes_to_send => |out| {
                defer allocator.free(out);
                try writeAll(fd, out);
            },
        }
    }
    {
        const record = try tc.encrypt(request_bytes);
        defer allocator.free(record);
        try writeAll(fd, record);
    }

    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(allocator);
    try pending.appendSlice(allocator, tc.pendingBytes());
    var plaintext: std.ArrayList(u8) = .empty;
    defer plaintext.deinit(allocator);

    read_loop: while (true) {
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const pt = tc.decrypt(rec) catch |err| switch (err) {
                error.TlsAlert => break :read_loop, // close_notify ends the stream
                else => {
                    sendFatal(fd, &tc, err);
                    return err;
                },
            };
            defer allocator.free(pt);
            if (plaintext.items.len + pt.len > opts.max_response_bytes) return error.ResponseTooLarge;
            try plaintext.appendSlice(allocator, pt);
            consumePrefix(&pending, rec_len);
            if (http1.isComplete(plaintext.items)) break :read_loop;
        }
        if (http1.isComplete(plaintext.items)) break;
        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }
    return plaintext.toOwnedSlice(allocator);
}

pub fn getTls(
    allocator: std.mem.Allocator,
    fd: Socket,
    host: []const u8,
    request_bytes: []const u8,
    opts: Options,
    application_phase: *bool,
) Error![]u8 {
    var tc = try tls_client.Client.init(allocator, .{
        .server_name = host,
        .trust_anchors = opts.trust_anchors,
        .disallowed_certs = opts.disallowed_certs,
        .windows_chain_policy = opts.windows_chain_policy,
        .alpn_protocols = &.{"http/1.1"},
        .now_unix_seconds = wallClockSeconds(),
        .crl = opts.crl,
        .require_crl = opts.require_crl,
        .ct_logs = opts.ct_logs,
        .enforce_sct = opts.enforce_sct,
        .require_sct = opts.require_sct,
    });
    defer tc.deinit();
    if (opts.insecure_skip_verify) tc.disableServerCertVerification();

    {
        const hello = try tc.start();
        defer allocator.free(hello);
        try writeAll(fd, hello);
    }
    var read_buf: [max_tls_record]u8 = undefined;
    while (!tc.handshakeDone()) {
        const n = try readSome(fd, &read_buf);
        switch (tc.feed(read_buf[0..n]) catch |err| {
            sendFatal(fd, &tc, err);
            return err;
        }) {
            .need_more => {},
            .bytes_to_send => |out| {
                defer allocator.free(out);
                try writeAll(fd, out);
            },
        }
    }
    application_phase.* = true;
    {
        const record = try tc.encrypt(request_bytes);
        defer allocator.free(record);
        try writeAll(fd, record);
    }

    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(allocator);
    try pending.appendSlice(allocator, tc.pendingBytes());
    var plaintext: std.ArrayList(u8) = .empty;
    defer plaintext.deinit(allocator);

    read_loop: while (true) {
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const read = tc.decryptApp(rec) catch |err| switch (err) {
                error.TlsAlert => break :read_loop, // close_notify ends the stream
                else => {
                    sendFatal(fd, &tc, err);
                    return err;
                },
            };
            switch (read) {
                .application_data => |pt| {
                    defer allocator.free(pt);
                    if (plaintext.items.len + pt.len > opts.max_response_bytes) return error.ResponseTooLarge;
                    try plaintext.appendSlice(allocator, pt);
                },
                .control => {},
            }
            // A server KeyUpdate (surfaced as .control) may queue a reply we must
            // write back before continuing to read under the rotated keys.
            if (try tc.takePendingSend()) |reply| {
                defer allocator.free(reply);
                try writeAll(fd, reply);
            }
            consumePrefix(&pending, rec_len);
            if (http1.isComplete(plaintext.items)) break :read_loop;
        }
        if (http1.isComplete(plaintext.items)) break;
        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }
    return plaintext.toOwnedSlice(allocator);
}

pub fn readHttp(allocator: std.mem.Allocator, fd: Socket, max_bytes: usize) Error![]u8 {
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(allocator);
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = readSome(fd, &buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        if (acc.items.len + n > max_bytes) return error.ResponseTooLarge;
        try acc.appendSlice(allocator, buf[0..n]);
        if (http1.isComplete(acc.items)) break;
    }
    return acc.toOwnedSlice(allocator);
}

pub fn sendFatal(fd: Socket, client: anytype, failure: anytype) void {
    tls_client_failure.sendFatal(fd, client, failure);
}

/// Wall-clock time in Unix seconds, used to reject expired server certificates.
pub fn wallClockSeconds() i64 {
    if (comptime builtin.os.tag == .windows) {
        const millis = @import("../../substrate/platform.zig").realtimeMillisChecked() orelse return 0;
        return @divTrunc(millis, 1000);
    }
    var ts: sys.timespec = undefined;
    if (posix.errno(sys.clock_gettime(posix.CLOCK.REALTIME, &ts)) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

// ---- TLS record framing (mirrors acme_runner) -------------------------------

fn frameRecordLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;
    const len = (@as(usize, buf[3]) << 8) | @as(usize, buf[4]);
    const total = 5 + len;
    if (buf.len < total) return null;
    return total;
}

fn consumePrefix(list: *std.ArrayList(u8), n: usize) void {
    const rem = list.items.len - n;
    std.mem.copyForwards(u8, list.items[0..rem], list.items[n..]);
    list.shrinkRetainingCapacity(rem);
}
