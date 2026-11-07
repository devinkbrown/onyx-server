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

/// RFC 8701 GREASE stays on for this outbound TLS 1.3 client so peers that
/// mishandle unknown values are found early; GREASE ECH stays off because the
/// daemon holds no ECHConfig for these hosts (draft-ietf-tls-esni §6.2).
pub const outbound_grease = true;
pub const outbound_ech_grease = false;

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

    var clean_close = false;
    read_loop: while (true) {
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const pt = tc.decrypt(rec) catch |err| switch (err) {
                // RFC 5246 §7.2.1: close_notify is the clean end of the stream.
                // Any other alert is a failure, never a silent EOF.
                error.EndOfStream => {
                    clean_close = true;
                    break :read_loop;
                },
                else => {
                    sendFatal(fd, &tc, err);
                    return err;
                },
            };
            defer allocator.free(pt);
            if (plaintext.items.len + pt.len > opts.max_response_bytes) return error.ResponseTooLarge;
            try plaintext.appendSlice(allocator, pt);
            consumePrefix(&pending, rec_len);
            if (responseFraming(request_bytes, plaintext.items) == .complete) break :read_loop;
        }
        if (responseFraming(request_bytes, plaintext.items) == .complete) break;
        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }
    try acceptResponse(request_bytes, plaintext.items, clean_close);
    sendCloseNotify(allocator, fd, &tc);
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
        .grease = outbound_grease,
        .ech_grease = outbound_ech_grease,
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

    var clean_close = false;
    read_loop: while (true) {
        while (frameRecordLen(pending.items)) |rec_len| {
            const rec = pending.items[0..rec_len];
            const read = tc.decryptApp(rec) catch |err| switch (err) {
                // RFC 8446 §6.1: close_notify is the clean end of the stream.
                // Any other alert is a failure, never a silent EOF.
                error.EndOfStream => {
                    clean_close = true;
                    break :read_loop;
                },
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
            if (responseFraming(request_bytes, plaintext.items) == .complete) break :read_loop;
        }
        if (responseFraming(request_bytes, plaintext.items) == .complete) break;
        const n = readSome(fd, &read_buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        try pending.appendSlice(allocator, read_buf[0..n]);
    }
    try acceptResponse(request_bytes, plaintext.items, clean_close);
    sendCloseNotify(allocator, fd, &tc);
    return plaintext.toOwnedSlice(allocator);
}

/// How far an HTTP/1.1 response buffered so far is delimited (RFC 9112 §6.3).
pub const Framing = enum {
    /// The header block, or a Content-Length / chunked body, is still short.
    need_more,
    /// The message is complete by its own framing (or has no body).
    complete,
    /// The body is delimited only by connection close (RFC 9112 §6.3 rule 8,
    /// or a non-chunked Transfer-Encoding, rule 4 for responses): only an
    /// authenticated close_notify proves it was not truncated (RFC 8446 §6.1).
    until_close,
};

/// Classify `bytes` (the response so far) for the request `request`.
pub fn responseFraming(request: []const u8, bytes: []const u8) Framing {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return .need_more;
    const head = bytes[0..head_end];
    // RFC 9112 §6.3 rule 1: a response to HEAD, and any 1xx, 204 or 304
    // response, ends at the header block. An unparseable status line is left
    // to the HTTP parser to reject.
    if (std.mem.startsWith(u8, request, "HEAD ")) return .complete;
    const status = responseStatus(head) orelse return .complete;
    if (status < 200 or status == 204 or status == 304) return .complete;
    if (headerValue(head, "transfer-encoding")) |te| {
        // Rule 4: chunked must be the final coding, else the body runs to close.
        if (!finalCodingIsChunked(te)) return .until_close;
        return if (http1.isComplete(bytes)) .complete else .need_more;
    }
    if (headerValue(head, "content-length") != null) {
        return if (http1.isComplete(bytes)) .complete else .need_more;
    }
    return .until_close;
}

/// RFC 8446 §6.1 / RFC 5246 §7.2.1 truncation check, run when the read loop
/// ends: a response complete by its own framing is accepted either way; a
/// close-delimited body only after an authenticated close_notify. A short
/// header block or Content-Length / chunked body is a truncated response even
/// after close_notify (the peer closed before sending what it promised), and
/// is reported as `error.ConnectionClosed`.
pub fn acceptResponse(request: []const u8, bytes: []const u8, clean_close: bool) Error!void {
    switch (responseFraming(request, bytes)) {
        .complete => {},
        .until_close => if (!clean_close) return error.ConnectionClosed,
        .need_more => return error.ConnectionClosed,
    }
}

/// Best-effort RFC 8446 §6.1 / RFC 5246 §7.2.1 closure of our write side once
/// the response is accepted. A failure to build or write it changes nothing:
/// the response is already final and the socket is closed by the caller.
fn sendCloseNotify(allocator: std.mem.Allocator, fd: Socket, tc: anytype) void {
    const wire = tc.closeNotify() catch return;
    defer allocator.free(wire);
    writeAll(fd, wire) catch {};
}

fn responseStatus(head: []const u8) ?u16 {
    // "HTTP/1.x NNN ..." (RFC 9112 §4).
    if (head.len < 12 or !std.mem.startsWith(u8, head, "HTTP/1.") or head[8] != ' ') return null;
    return std.fmt.parseInt(u16, head[9..12], 10) catch null;
}

fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next(); // status line
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

fn finalCodingIsChunked(te: []const u8) bool {
    const last_comma = std.mem.lastIndexOfScalar(u8, te, ',');
    const last = if (last_comma) |i| te[i + 1 ..] else te;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, last, " \t"), "chunked");
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

test "outbound TLS client keeps RFC 8701 GREASE on and GREASE ECH off" {
    try std.testing.expect(outbound_grease);
    try std.testing.expect(!outbound_ech_grease);
    var tc = try tls_client.Client.init(std.testing.allocator, .{ .server_name = "example.test", .trust_anchors = &.{}, .grease = outbound_grease, .ech_grease = outbound_ech_grease });
    defer tc.deinit();
    try std.testing.expect(tc.grease != null);
    try std.testing.expect(!tc.ech_grease);
}

test "http_fetch TLS framing: Content-Length and chunked bodies must be complete (RFC 9112 §6.3)" {
    const get_req = "GET / HTTP/1.1\r\n\r\n";
    try std.testing.expectEqual(Framing.need_more, responseFraming(get_req, "HTTP/1.1 200 OK\r\nContent-Len"));
    try std.testing.expectEqual(Framing.need_more, responseFraming(get_req, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab"));
    try std.testing.expectEqual(Framing.complete, responseFraming(get_req, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab"));
    try std.testing.expectEqual(Framing.need_more, responseFraming(get_req, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n"));
    try std.testing.expectEqual(Framing.complete, responseFraming(get_req, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n"));
    // No framing headers: the body runs to close (previously treated as
    // complete at the header block, silently dropping the body).
    try std.testing.expectEqual(Framing.until_close, responseFraming(get_req, "HTTP/1.1 200 OK\r\n\r\npartial"));
    try std.testing.expectEqual(Framing.until_close, responseFraming(get_req, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"));
    // Bodiless responses end at the header block.
    try std.testing.expectEqual(Framing.complete, responseFraming(get_req, "HTTP/1.1 204 No Content\r\n\r\n"));
    try std.testing.expectEqual(Framing.complete, responseFraming(get_req, "HTTP/1.1 304 Not Modified\r\n\r\n"));
    try std.testing.expectEqual(Framing.complete, responseFraming("HEAD / HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n"));
}

test "http_fetch TLS truncation (RFC 8446 §6.1): no truncated body is accepted, with or without close_notify" {
    const get_req = "GET / HTTP/1.1\r\n\r\n";
    const short_cl = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
    const short_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab";
    const full_cl = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    const by_close = "HTTP/1.1 200 OK\r\n\r\nabc";
    for ([_]bool{ false, true }) |clean| {
        // Framing promises more than arrived: truncated either way.
        try std.testing.expectError(error.ConnectionClosed, acceptResponse(get_req, short_cl, clean));
        try std.testing.expectError(error.ConnectionClosed, acceptResponse(get_req, short_chunk, clean));
        try std.testing.expectError(error.ConnectionClosed, acceptResponse(get_req, "HTTP/1.1 200 OK\r\nCont", clean));
        try std.testing.expectError(error.ConnectionClosed, acceptResponse(get_req, "", clean));
        // Self-delimited and complete: fine with or without close_notify.
        try acceptResponse(get_req, full_cl, clean);
    }
    // A close-delimited body is trusted only after an authenticated close_notify.
    try acceptResponse(get_req, by_close, true);
    try std.testing.expectError(error.ConnectionClosed, acceptResponse(get_req, by_close, false));
}
