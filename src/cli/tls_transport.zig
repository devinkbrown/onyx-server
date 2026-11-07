// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Socket plumbing shared by `armor s_client` and `armor s_server`: TLS record
//! framing over a `std.Io.net.Stream`, send-all, `host:port` parsing, and the
//! fatal-alert send on a failed handshake. No TLS logic lives here — the record
//! layer and handshake belong to `crypto/tls_client.zig` / `tls_server.zig`;
//! this only hands them whole records (RFC 8446 §5.1 framing), the way the
//! daemon's `tls_conn.zig` does.

const std = @import("std");

const Allocator = std.mem.Allocator;
const net = std.Io.net;

/// TLSPlaintext/TLSCiphertext header: type(1) || legacy_version(2) || length(2).
pub const record_header_len: usize = 5;
/// RFC 8446 §5.2: TLSCiphertext.length MUST NOT exceed 2^14 + 256.
pub const max_record_body: usize = (1 << 14) + 256;

pub const Error = error{
    /// A record header declared a body longer than RFC 8446 §5.2 permits.
    RecordOverflow,
    /// The peer closed the TCP stream in the middle of a record.
    TruncatedRecord,
    /// `host:port` could not be parsed.
    BadEndpoint,
};

/// Accumulates stream bytes and yields one complete TLS record at a time.
pub const RecordReader = struct {
    buf: std.ArrayList(u8) = .empty,
    /// Bytes at the front of `buf` already returned to the caller.
    consumed: usize = 0,

    pub fn deinit(self: *RecordReader, gpa: Allocator) void {
        self.buf.deinit(gpa);
        self.* = undefined;
    }

    /// Append freshly-read bytes.
    pub fn push(self: *RecordReader, gpa: Allocator, bytes: []const u8) !void {
        self.compact();
        try self.buf.appendSlice(gpa, bytes);
    }

    /// The next complete record (header included), or null if more bytes are
    /// needed. The slice is valid until the next `push`/`next`.
    pub fn next(self: *RecordReader) Error!?[]const u8 {
        const avail = self.buf.items[self.consumed..];
        if (avail.len < record_header_len) return null;
        const body_len: usize = std.mem.readInt(u16, avail[3..5], .big);
        if (body_len > max_record_body) return error.RecordOverflow;
        const total = record_header_len + body_len;
        if (avail.len < total) return null;
        self.consumed += total;
        return avail[0..total];
    }

    /// True when a partial record is buffered (EOF now would truncate it).
    pub fn hasPartial(self: *const RecordReader) bool {
        return self.buf.items.len > self.consumed;
    }

    fn compact(self: *RecordReader) void {
        if (self.consumed == 0) return;
        const rest = self.buf.items[self.consumed..];
        std.mem.copyForwards(u8, self.buf.items[0..rest.len], rest);
        self.buf.shrinkRetainingCapacity(rest.len);
        self.consumed = 0;
    }
};

/// Read once from `stream` into `scratch`; 0 means orderly EOF.
pub fn readSome(io: std.Io, stream: net.Stream, scratch: []u8) !usize {
    var bufs = [_][]u8{scratch};
    // `Stream.read` does not compile in this std (it destructures
    // ReadResult); the control-data variant with no control buffer is the
    // same recv.
    const r = stream.readWithControl(io, &bufs, &.{}) catch |err| switch (err) {
        error.ConnectionResetByPeer => return 0,
        else => return err,
    };
    return r.data_len;
}

/// Read until one full record is available. Returns null on a clean EOF at a
/// record boundary; EOF mid-record is `error.TruncatedRecord`.
pub fn readRecord(gpa: Allocator, io: std.Io, stream: net.Stream, rr: *RecordReader) !?[]const u8 {
    var scratch: [16 * 1024]u8 = undefined;
    while (true) {
        if (try rr.next()) |rec| return rec;
        const n = try readSome(io, stream, &scratch);
        if (n == 0) {
            if (rr.hasPartial()) return error.TruncatedRecord;
            return null;
        }
        try rr.push(gpa, scratch[0..n]);
    }
}

/// Write every byte of `bytes` to `stream`.
pub fn sendAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var w = stream.writer(io, &.{});
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}

/// Split `host:port` (or `[v6]:port`). The host slice aliases `spec`. Port 0
/// is accepted (an ephemeral listen); `connect` callers reject it.
pub fn splitHostPort(spec: []const u8) Error!struct { host: []const u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadEndpoint;
    if (colon == 0 or colon + 1 >= spec.len) return error.BadEndpoint;
    var host = spec[0..colon];
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
    if (host.len == 0) return error.BadEndpoint;
    const port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.BadEndpoint;
    return .{ .host = host, .port = port };
}

/// TCP-connect to `host:port`: IP literals directly, names through the std
/// resolver (which tries every A/AAAA answer).
pub fn connect(io: std.Io, host: []const u8, port: u16) !net.Stream {
    if (net.IpAddress.parse(host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream });
    } else |_| {}
    const name = try net.HostName.init(host);
    return name.connect(io, port, .{ .mode = .stream });
}

pub const max_alpn = 8;

/// Split a comma-separated ALPN list into `storage`. RFC 7301 §3.1: each
/// ProtocolName is 1..255 bytes; empty names are a usage error.
pub fn splitAlpn(text: []const u8, storage: *[max_alpn][]const u8) error{Usage}![]const []const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |p| {
        if (p.len == 0 or p.len > 255 or n == storage.len) return error.Usage;
        storage[n] = p;
        n += 1;
    }
    return storage[0..n];
}

/// Display name for a TLS NamedGroup code point (RFC 8446 §4.2.7, RFC 8422,
/// draft-ietf-tls-ecdhe-mlkem for the hybrid).
pub fn groupName(code: u16) []const u8 {
    return switch (code) {
        0x001d => "X25519",
        0x0017 => "secp256r1",
        0x0018 => "secp384r1",
        0x0019 => "secp521r1",
        0x11ec => "X25519MLKEM768",
        else => "unknown",
    };
}

const testing = std.testing;

test "armorcli tls_transport RecordReader frames records and caps length" {
    const gpa = testing.allocator;
    var rr: RecordReader = .{};
    defer rr.deinit(gpa);
    try testing.expect((try rr.next()) == null);
    try rr.push(gpa, &.{ 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa });
    try testing.expect((try rr.next()) == null);
    try testing.expect(rr.hasPartial());
    try rr.push(gpa, &.{ 0xbb, 0x16, 0x03, 0x03, 0x00, 0x00 });
    try testing.expectEqualSlices(u8, &.{ 0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb }, (try rr.next()).?);
    try testing.expectEqualSlices(u8, &.{ 0x16, 0x03, 0x03, 0x00, 0x00 }, (try rr.next()).?);
    try testing.expect(!rr.hasPartial());

    var big: RecordReader = .{};
    defer big.deinit(gpa);
    try big.push(gpa, &.{ 0x17, 0x03, 0x03, 0x41, 0x01 }); // 2^14 + 257
    try testing.expectError(error.RecordOverflow, big.next());
}

test "armorcli tls_transport splitHostPort accepts names, v4, and bracketed v6" {
    const a = try splitHostPort("irc.example:6697");
    try testing.expectEqualStrings("irc.example", a.host);
    try testing.expectEqual(@as(u16, 6697), a.port);
    const b = try splitHostPort("[::1]:443");
    try testing.expectEqualStrings("::1", b.host);
    try testing.expectError(error.BadEndpoint, splitHostPort("noport"));
    try testing.expectEqual(@as(u16, 0), (try splitHostPort("h:0")).port);
    try testing.expectError(error.BadEndpoint, splitHostPort("h:99999"));
    try testing.expectError(error.BadEndpoint, splitHostPort(":1"));
}
