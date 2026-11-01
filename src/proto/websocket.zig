// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 6455 WebSocket server helpers.
//!
//! This module is intentionally allocation-free: callers provide request,
//! response, frame, and payload buffers. It covers the browser-client side of
//! the protocol that Onyx Server needs for IRC-over-WebSocket frontends.
const std = @import("std");

const Sha1 = std.crypto.hash.Sha1;
const ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const ACCEPT_LEN = std.base64.standard.Encoder.calcSize(Sha1.digest_length);
pub const IRC_SUBPROTOCOL = "text.ircv3.net";
/// Onyx extends the IRC text stream with binary Cadence media frames on the
/// same WebSocket. It must not claim the text-only IRCv3 wire contract.
pub const ONYX_MEDIA_SUBPROTOCOL = "onyx.irc-media.v1";
pub const MAX_RESPONSE_LEN = 129 + "Sec-WebSocket-Protocol: ".len + @max(IRC_SUBPROTOCOL.len, ONYX_MEDIA_SUBPROTOCOL.len) + "\r\n".len;

/// HTTP upgrade parsing and response construction failures.
pub const HandshakeError = error{
    MissingHeaderEnd,
    EmptyRequest,
    InvalidRequestLine,
    UnsupportedMethod,
    UnsupportedProtocol,
    MalformedHeader,
    MissingHost,
    MissingUpgrade,
    MissingConnection,
    MissingKey,
    MissingVersion,
    InvalidUpgrade,
    InvalidConnection,
    InvalidKey,
    InvalidSubprotocol,
    UnsupportedVersion,
    OutputTooSmall,
};

/// Frame parse failures for attacker-controlled wire bytes.
pub const FrameError = error{
    Truncated,
    ReservedBitsSet,
    InvalidOpcode,
    FragmentedControlFrame,
    ControlFrameTooLarge,
    NonCanonicalLength,
    PayloadTooLarge,
    UnmaskedClientFrame,
    MaskedServerFrame,
    OutputTooSmall,
};

/// Frame construction failures for caller-supplied payloads.
pub const BuildError = error{
    FragmentedControlFrame,
    ControlFrameTooLarge,
    PayloadTooLarge,
    OutputTooSmall,
};

pub const Direction = enum {
    client_to_server,
    server_to_client,
};

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,

    pub fn isControl(self: Opcode) bool {
        return @backingInt(self) >= 0x8;
    }

    pub fn isData(self: Opcode) bool {
        return self == .text or self == .binary;
    }
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload: []const u8,

    pub fn isFragment(self: Frame) bool {
        return !self.fin or self.opcode == .continuation;
    }
};

pub const DecodeResult = struct {
    frame: Frame,
    consumed: usize,
};

pub const BuildOptions = struct {
    fin: bool = true,
    opcode: Opcode,
    mask_key: ?[4]u8 = null,
};

pub const IrcLine = struct {
    line: []const u8,
    consumed: usize,
};

/// Compute Sec-WebSocket-Accept into `out` after validating the client key.
pub fn computeAccept(key: []const u8, out: *[ACCEPT_LEN]u8) HandshakeError![]const u8 {
    var decoded_key: [16]u8 = undefined;
    const trimmed = trimHeaderValue(key);
    if (trimmed.len == 0) return error.InvalidKey;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidKey;
    if (decoded_len != decoded_key.len) return error.InvalidKey;
    std.base64.standard.Decoder.decode(&decoded_key, trimmed) catch return error.InvalidKey;

    var sha = Sha1.init(.{});
    sha.update(trimmed);
    sha.update(ACCEPT_GUID);
    var digest: [Sha1.digest_length]u8 = undefined;
    sha.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

/// Parse and validate an HTTP/1.1 WebSocket upgrade request.
pub fn parseHandshake(request: []const u8) HandshakeError!void {
    _ = try parseHandshakeRequest(request);
}

/// Build the complete 101 Switching Protocols response into `out`.
pub fn buildHandshakeResponse(request: []const u8, out: []u8) HandshakeError![]const u8 {
    return (try buildHandshakeResponseWithSelection(request, out)).response;
}

/// A validated opening response plus the exact application protocol selected
/// for this connection. The daemon retains this result to enforce frame types
/// and preserve the contract across Helix.
pub const HandshakeResult = struct {
    response: []const u8,
    subprotocol: ?Subprotocol,
};

pub fn buildHandshakeResponseWithSelection(request: []const u8, out: []u8) HandshakeError!HandshakeResult {
    const handshake = try parseHandshakeRequest(request);
    var accept_buf: [ACCEPT_LEN]u8 = undefined;
    const accept = try computeAccept(handshake.key, &accept_buf);
    if (handshake.subprotocol) |subprotocol| {
        const bytes = std.fmt.bufPrint(
            out,
            "HTTP/1.1 101 Switching Protocols\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: {s}\r\n" ++
                "Sec-WebSocket-Protocol: {s}\r\n\r\n",
            .{ accept, subprotocol.wireName() },
        ) catch return error.OutputTooSmall;
        return .{ .response = bytes, .subprotocol = subprotocol };
    }
    const bytes = std.fmt.bufPrint(
        out,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return error.OutputTooSmall;
    return .{ .response = bytes, .subprotocol = null };
}

/// Decode one complete WebSocket frame from `input`.
///
/// Masked payloads are unmasked into `payload_out`. Unmasked payloads are
/// returned as a slice of `input`, so `payload_out` can be empty when parsing
/// server-to-client frames.
pub fn decodeFrame(
    comptime max_frame_size: usize,
    direction: Direction,
    input: []const u8,
    payload_out: []u8,
) FrameError!DecodeResult {
    if (input.len < 2) return error.Truncated;

    const first = input[0];
    const second = input[1];
    if ((first & 0x70) != 0) return error.ReservedBitsSet;

    const fin = (first & 0x80) != 0;
    const opcode = try opcodeFromRaw(@as(u4, @truncate(first & 0x0f)));
    const masked = (second & 0x80) != 0;
    const len_tag = second & 0x7f;

    if (opcode.isControl()) {
        if (!fin) return error.FragmentedControlFrame;
        if (len_tag > 125) return error.ControlFrameTooLarge;
    }

    switch (direction) {
        .client_to_server => if (!masked) return error.UnmaskedClientFrame,
        .server_to_client => if (masked) return error.MaskedServerFrame,
    }

    var cursor: usize = 2;
    var payload_len64: u64 = len_tag;
    if (len_tag == 126) {
        if (input.len < cursor + 2) return error.Truncated;
        payload_len64 = std.mem.readInt(u16, input[cursor..][0..2], .big);
        if (payload_len64 < 126) return error.NonCanonicalLength;
        cursor += 2;
    } else if (len_tag == 127) {
        if (input.len < cursor + 8) return error.Truncated;
        payload_len64 = std.mem.readInt(u64, input[cursor..][0..8], .big);
        if ((payload_len64 & (@as(u64, 1) << 63)) != 0) return error.PayloadTooLarge;
        if (payload_len64 <= 0xffff) return error.NonCanonicalLength;
        cursor += 8;
    }

    if (payload_len64 > max_frame_size) return error.PayloadTooLarge;
    if (payload_len64 > std.math.maxInt(usize)) return error.PayloadTooLarge;
    const payload_len: usize = @intCast(payload_len64);

    var mask_key: [4]u8 = undefined;
    if (masked) {
        if (input.len < cursor + 4) return error.Truncated;
        @memcpy(&mask_key, input[cursor..][0..4]);
        cursor += 4;
    }

    if (input.len < cursor + payload_len) return error.Truncated;
    const wire_payload = input[cursor..][0..payload_len];
    const payload = if (masked) blk: {
        if (payload_out.len < payload_len) return error.OutputTooSmall;
        xorMask(payload_out[0..payload_len], wire_payload, mask_key);
        break :blk payload_out[0..payload_len];
    } else wire_payload;

    return .{
        .frame = .{
            .fin = fin,
            .opcode = opcode,
            .masked = masked,
            .payload = payload,
        },
        .consumed = cursor + payload_len,
    };
}

/// Encode one WebSocket frame into `out`.
pub fn encodeFrame(
    comptime max_frame_size: usize,
    options: BuildOptions,
    payload: []const u8,
    out: []u8,
) BuildError![]const u8 {
    if (payload.len > max_frame_size) return error.PayloadTooLarge;
    if (options.opcode.isControl()) {
        if (!options.fin) return error.FragmentedControlFrame;
        if (payload.len > 125) return error.ControlFrameTooLarge;
    }

    const masked = options.mask_key != null;
    const header_len: usize = 2 +
        (if (payload.len <= 125) @as(usize, 0) else if (payload.len <= 0xffff) @as(usize, 2) else @as(usize, 8)) +
        (if (masked) @as(usize, 4) else @as(usize, 0));
    if (out.len < header_len + payload.len) return error.OutputTooSmall;

    var cursor: usize = 0;
    out[cursor] = (if (options.fin) @as(u8, 0x80) else 0) | @as(u8, @backingInt(options.opcode));
    cursor += 1;

    const mask_bit: u8 = if (masked) 0x80 else 0;
    if (payload.len <= 125) {
        out[cursor] = mask_bit | @as(u8, @intCast(payload.len));
        cursor += 1;
    } else if (payload.len <= 0xffff) {
        out[cursor] = mask_bit | 126;
        cursor += 1;
        std.mem.writeInt(u16, out[cursor..][0..2], @intCast(payload.len), .big);
        cursor += 2;
    } else {
        out[cursor] = mask_bit | 127;
        cursor += 1;
        std.mem.writeInt(u64, out[cursor..][0..8], @intCast(payload.len), .big);
        cursor += 8;
    }

    if (options.mask_key) |key| {
        @memcpy(out[cursor..][0..4], &key);
        cursor += 4;
        xorMask(out[cursor..][0..payload.len], payload, key);
    } else {
        @memcpy(out[cursor..][0..payload.len], payload);
    }

    return out[0 .. header_len + payload.len];
}

/// Frame-stream faults surfaced by `Deframer` beyond per-frame decode errors:
/// RFC 6455 §5.4 fragmentation-state violations and reassembly-buffer overflow.
pub const DeframeError = FrameError || error{
    UnexpectedContinuation,
    NestedFragmentation,
    BufferFull,
};

/// One semantic event popped from a client-to-server frame stream.
pub const DeframeEvent = union(enum) {
    /// Unmasked payload of one text/binary/continuation DATA frame. `fin` marks
    /// the end of the WebSocket message (so a line-oriented consumer can treat
    /// the frame boundary as a message terminator even without a trailing CRLF).
    /// `continuation` preserves whether this event came from a continuation
    /// frame. Consumers must not infer that identity from the Deframer's mutable
    /// fragmentation state because a queued event may already have advanced it.
    /// `binary` reflects the message's opcode (set by its opening frame and
    /// inherited by continuations) so a consumer can route binary media datagrams
    /// away from the line-oriented text path.
    data: struct { payload: []const u8, fin: bool, binary: bool, continuation: bool },
    /// Client ping; the caller should answer with a pong echoing the payload.
    ping: []const u8,
    /// Client pong (unsolicited or answering a server ping); informational.
    pong: void,
    /// Client close; payload is the optional status code + reason. The caller
    /// should echo a close frame and tear the connection down.
    close: []const u8,
};

/// Incremental client-to-server frame decoder for a live connection: frames may
/// arrive split across arbitrary recv chunks (or TLS records), so `feed` buffers
/// wire bytes and `next` pops complete frames one at a time. Enforces the RFC
/// 6455 client rules (masking required, canonical lengths, control frames never
/// fragmented) plus cross-frame fragmentation-state validity. Allocation-free;
/// a returned `data`/`ping`/`close` payload is valid until the next `feed`/`next`.
pub fn Deframer(comptime max_frame_size: usize) type {
    return struct {
        const Self = @This();
        pub const max_frame = max_frame_size;
        /// Header (2) + extended length (8) + mask key (4) on top of the payload.
        const max_overhead = 14;
        const PendingEvent = union(enum) {
            data: struct { len: usize, fin: bool, continuation: bool },
            ping: usize,
            pong: void,
            close: usize,
        };

        /// Reassembly buffer for wire bytes of the (possibly partial) next frame.
        buf: [max_frame_size + max_overhead]u8 = undefined,
        len: usize = 0,
        /// Unmask destination; `data`/`ping`/`close` payload slices point here.
        payload_buf: [max_frame_size]u8 = undefined,
        pending: ?PendingEvent = null,
        pending_error: ?DeframeError = null,
        /// True while a fragmented DATA message is open (a non-FIN text/binary
        /// frame was seen and its closing FIN continuation has not arrived yet).
        fragmented: bool = false,
        /// Opcode of the in-flight DATA message: set when its opening text/binary
        /// frame is seen and inherited by continuation frames (RFC 6455 §5.4).
        /// Surfaced on each `.data` event so binary media is routed apart from text.
        msg_binary: bool = false,

        /// Buffer inbound wire bytes. `error.BufferFull` only when a frame's wire
        /// size exceeds capacity (oversize *declared* lengths are rejected earlier
        /// by `next` as `PayloadTooLarge`, straight from the frame header).
        pub fn feed(self: *Self, bytes: []const u8) error{BufferFull}!void {
            var rest = bytes;
            while (rest.len != 0) {
                const spare = self.buf.len - self.len;
                if (rest.len <= spare) {
                    @memcpy(self.buf[self.len..][0..rest.len], rest);
                    self.len += rest.len;
                    return;
                }

                if (spare != 0) {
                    @memcpy(self.buf[self.len..], rest[0..spare]);
                    self.len += spare;
                    rest = rest[spare..];
                }

                if (!self.drainBufferedFrame()) return error.BufferFull;
                if (self.pending_error != null) return;
            }
        }

        /// Pop the next complete frame as a semantic event, or null when more
        /// wire bytes are needed. Any error is fatal to the stream: the caller
        /// must close the connection (RFC 6455 §10.7).
        pub fn next(self: *Self) DeframeError!?DeframeEvent {
            if (self.pending_error) |err| {
                self.pending_error = null;
                return err;
            }
            if (self.pending) |pending| {
                self.pending = null;
                return self.eventFromPending(pending);
            }
            if (self.len == 0) return null;
            const res = decodeFrame(
                max_frame_size,
                .client_to_server,
                self.buf[0..self.len],
                &self.payload_buf,
            ) catch |err| switch (err) {
                error.Truncated => return null,
                else => return err,
            };
            // Consume the frame's wire bytes; the payload was already copied
            // (unmasked) into `payload_buf`, so sliding `buf` is safe.
            const rem = self.len - res.consumed;
            std.mem.copyForwards(u8, self.buf[0..rem], self.buf[res.consumed..self.len]);
            self.len = rem;

            return try self.eventFromFrame(res.frame);
        }

        fn drainBufferedFrame(self: *Self) bool {
            if (self.pending != null or self.pending_error != null) return false;
            const res = decodeFrame(
                max_frame_size,
                .client_to_server,
                self.buf[0..self.len],
                &self.payload_buf,
            ) catch |err| switch (err) {
                error.Truncated => return false,
                else => {
                    self.pending_error = err;
                    self.len = 0;
                    return true;
                },
            };

            self.queuePending(res.frame) catch |err| {
                self.pending_error = err;
                self.len = 0;
                return true;
            };
            const rem = self.len - res.consumed;
            std.mem.copyForwards(u8, self.buf[0..rem], self.buf[res.consumed..self.len]);
            self.len = rem;
            return true;
        }

        fn queuePending(self: *Self, frame: Frame) DeframeError!void {
            switch (frame.opcode) {
                .text, .binary => {
                    if (self.fragmented) return error.NestedFragmentation;
                    self.fragmented = !frame.fin;
                    self.msg_binary = frame.opcode == .binary;
                    self.pending = .{ .data = .{
                        .len = frame.payload.len,
                        .fin = frame.fin,
                        .continuation = false,
                    } };
                },
                .continuation => {
                    if (!self.fragmented) return error.UnexpectedContinuation;
                    if (frame.fin) self.fragmented = false;
                    self.pending = .{ .data = .{
                        .len = frame.payload.len,
                        .fin = frame.fin,
                        .continuation = true,
                    } };
                },
                .ping => self.pending = .{ .ping = frame.payload.len },
                .pong => self.pending = .pong,
                .close => self.pending = .{ .close = frame.payload.len },
            }
        }

        fn eventFromFrame(self: *Self, frame: Frame) DeframeError!DeframeEvent {
            switch (frame.opcode) {
                .text, .binary => {
                    if (self.fragmented) return error.NestedFragmentation;
                    self.fragmented = !frame.fin;
                    self.msg_binary = frame.opcode == .binary;
                    return .{ .data = .{
                        .payload = frame.payload,
                        .fin = frame.fin,
                        .binary = self.msg_binary,
                        .continuation = false,
                    } };
                },
                .continuation => {
                    if (!self.fragmented) return error.UnexpectedContinuation;
                    if (frame.fin) self.fragmented = false;
                    return .{ .data = .{
                        .payload = frame.payload,
                        .fin = frame.fin,
                        .binary = self.msg_binary,
                        .continuation = true,
                    } };
                },
                .ping => return .{ .ping = frame.payload },
                .pong => return .pong,
                .close => return .{ .close = frame.payload },
            }
        }

        fn eventFromPending(self: *Self, pending: PendingEvent) DeframeEvent {
            return switch (pending) {
                .data => |data| .{ .data = .{
                    .payload = self.payload_buf[0..data.len],
                    .fin = data.fin,
                    .binary = self.msg_binary,
                    .continuation = data.continuation,
                } },
                .ping => |len| .{ .ping = self.payload_buf[0..len] },
                .pong => .pong,
                .close => |len| .{ .close = self.payload_buf[0..len] },
            };
        }
    };
}

/// Return the next complete IRC line in a text-frame payload, excluding CR/LF.
pub fn nextIrcLine(payload: []const u8) ?IrcLine {
    const lf = std.mem.indexOfScalar(u8, payload, '\n') orelse return null;
    var line_end = lf;
    if (line_end > 0 and payload[line_end - 1] == '\r') line_end -= 1;
    return .{
        .line = payload[0..line_end],
        .consumed = lf + 1,
    };
}

fn requestHeaders(request: []const u8) HandshakeError![]const u8 {
    const end = std.mem.indexOf(u8, request, "\r\n\r\n") orelse return error.MissingHeaderEnd;
    return request[0 .. end + 2];
}

const ParsedHandshake = struct {
    key: []const u8,
    subprotocol: ?Subprotocol,
};

pub const Subprotocol = enum(u8) {
    ircv3_text,
    onyx_irc_media,

    pub fn wireName(self: Subprotocol) []const u8 {
        return switch (self) {
            .ircv3_text => IRC_SUBPROTOCOL,
            .onyx_irc_media => ONYX_MEDIA_SUBPROTOCOL,
        };
    }
};

fn parseHandshakeRequest(request: []const u8) HandshakeError!ParsedHandshake {
    const headers = try requestHeaders(request);
    var cursor: usize = 0;
    const request_line = nextHeaderLine(headers, &cursor) orelse return error.EmptyRequest;
    try validateRequestLine(request_line);

    var key: ?[]const u8 = null;
    var saw_host = false;
    var saw_upgrade = false;
    var saw_connection = false;
    var saw_version = false;
    var subprotocol: ?Subprotocol = null;

    while (nextHeaderLine(headers, &cursor)) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.MalformedHeader;
        const name = line[0..colon];
        const value = trimHeaderValue(line[colon + 1 ..]);
        if (!validHttpToken(name)) return error.MalformedHeader;

        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (value.len == 0) return error.MalformedHeader;
            saw_host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            if (!std.ascii.eqlIgnoreCase(value, "websocket")) return error.InvalidUpgrade;
            saw_upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (!hasHeaderToken(value, "upgrade")) return error.InvalidConnection;
            saw_connection = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key")) {
            var accept_buf: [ACCEPT_LEN]u8 = undefined;
            _ = try computeAccept(value, &accept_buf);
            key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-version")) {
            if (!std.mem.eql(u8, value, "13")) return error.UnsupportedVersion;
            saw_version = true;
        } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
            const offered = try firstSupportedSubprotocol(value);
            if (subprotocol == null) subprotocol = offered;
        }
    }

    if (!saw_host) return error.MissingHost;
    if (!saw_upgrade) return error.MissingUpgrade;
    if (!saw_connection) return error.MissingConnection;
    if (key == null) return error.MissingKey;
    if (!saw_version) return error.MissingVersion;
    return .{ .key = key.?, .subprotocol = subprotocol };
}

fn validateRequestLine(line: []const u8) HandshakeError!void {
    if (line.len == 0) return error.EmptyRequest;
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return error.InvalidRequestLine;
    const target = parts.next() orelse return error.InvalidRequestLine;
    const protocol = parts.next() orelse return error.InvalidRequestLine;
    if (target.len == 0 or parts.next() != null) return error.InvalidRequestLine;
    if (!std.mem.eql(u8, method, "GET")) return error.UnsupportedMethod;
    if (!std.mem.eql(u8, protocol, "HTTP/1.1")) return error.UnsupportedProtocol;
}

fn nextHeaderLine(headers: []const u8, cursor: *usize) ?[]const u8 {
    if (cursor.* >= headers.len) return null;
    const rest = headers[cursor.*..];
    const rel = std.mem.indexOf(u8, rest, "\r\n") orelse return null;
    const line = rest[0..rel];
    cursor.* += rel + 2;
    return line;
}

fn trimHeaderValue(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

fn hasHeaderToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(trimHeaderValue(part), token)) return true;
    }
    return false;
}

/// Parse RFC 6455's `1#token` offer. A malformed list invalidates the opening
/// handshake; silently downgrading it to the legacy no-protocol path would make
/// the server accept syntax that the WebSocket ABNF rejects.
fn firstSupportedSubprotocol(value: []const u8) HandshakeError!?Subprotocol {
    var selected: ?Subprotocol = null;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const offered = trimHeaderValue(part);
        if (!validHttpToken(offered)) return error.InvalidSubprotocol;
        if (selected == null and std.mem.eql(u8, offered, IRC_SUBPROTOCOL)) selected = .ircv3_text;
        if (selected == null and std.mem.eql(u8, offered, ONYX_MEDIA_SUBPROTOCOL)) selected = .onyx_irc_media;
    }
    return selected;
}

fn validHttpToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        const valid = std.ascii.isAlphanumeric(byte) or switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
        if (!valid) return false;
    }
    return true;
}

fn opcodeFromRaw(raw: u4) FrameError!Opcode {
    return switch (raw) {
        0x0 => .continuation,
        0x1 => .text,
        0x2 => .binary,
        0x8 => .close,
        0x9 => .ping,
        0xa => .pong,
        else => error.InvalidOpcode,
    };
}

fn xorMask(dst: []u8, src: []const u8, key: [4]u8) void {
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        dst[i] = src[i] ^ key[i & 3];
    }
}

test "canonical RFC 6455 handshake example" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n\r\n";

    var accept_buf: [ACCEPT_LEN]u8 = undefined;
    const accept = try computeAccept("dGhlIHNhbXBsZSBub25jZQ==", &accept_buf);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);

    var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
    const response = try buildHandshakeResponse(request, &response_buf);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        response,
    );
}

test "handshake selects text.ircv3.net from comma and OWS protocol offers" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive, Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: chat,\ttext.ircv3.net  , binary\r\n\r\n";

    try parseHandshake(request);
    var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
    const response = try buildHandshakeResponse(request, &response_buf);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
            "Sec-WebSocket-Protocol: text.ircv3.net\r\n\r\n",
        response,
    );
}

test "handshake never echoes absent or unrelated valid subprotocol offers" {
    const request_prefix =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n";
    const offers = [_][]const u8{
        "chat, binary",
        "TEXT.IRCV3.NET",
        "text.ircv3.net.evil",
    };

    for (offers) |offer| {
        var request_buf: [512]u8 = undefined;
        const request = try std.fmt.bufPrint(
            &request_buf,
            "{s}Sec-WebSocket-Protocol: {s}\r\n\r\n",
            .{ request_prefix, offer },
        );
        try parseHandshake(request);
        var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
        const response = try buildHandshakeResponse(request, &response_buf);
        try std.testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Protocol:") == null);
        try std.testing.expectEqual(@as(usize, 129), response.len);
    }
}

test "handshake rejects malformed subprotocol lists" {
    const request_prefix =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n";
    const malformed_offers = [_][]const u8{
        "",
        "\"text.ircv3.net\"",
        "text.ircv3.net extra",
        ",text.ircv3.net",
        "text.ircv3.net,",
        "chat,,text.ircv3.net",
        ",\t,",
    };

    for (malformed_offers) |offer| {
        var request_buf: [512]u8 = undefined;
        const request = try std.fmt.bufPrint(
            &request_buf,
            "{s}Sec-WebSocket-Protocol: {s}\r\n\r\n",
            .{ request_prefix, offer },
        );
        try std.testing.expectError(error.InvalidSubprotocol, parseHandshake(request));
    }
}

test "handshake recognizes text.ircv3.net across repeated protocol headers" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: chat\r\n" ++
        "sec-websocket-protocol:\ttext.ircv3.net\t\r\n\r\n";

    var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
    const response = try buildHandshakeResponse(request, &response_buf);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, response, "Sec-WebSocket-Protocol: text.ircv3.net"));
}

test "handshake selects the first supported offered subprotocol" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: chat, text.ircv3.net, onyx.irc-media.v1\r\n\r\n";

    var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
    const response = try buildHandshakeResponse(request, &response_buf);
    try std.testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Protocol: text.ircv3.net\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Protocol: onyx.irc-media.v1\r\n") == null);
}

test "handshake selects Onyx media when the client offers it first" {
    const request =
        "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com:8000\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: onyx.irc-media.v1, text.ircv3.net\r\n\r\n";

    var response_buf: [MAX_RESPONSE_LEN]u8 = undefined;
    const result = try buildHandshakeResponseWithSelection(request, &response_buf);
    try std.testing.expectEqual(Subprotocol.onyx_irc_media, result.subprotocol.?);
    try std.testing.expect(std.mem.indexOf(u8, result.response, "Sec-WebSocket-Protocol: onyx.irc-media.v1\r\n") != null);
}

test "handshake rejects malformed and missing required headers" {
    try std.testing.expectError(error.MalformedHeader, parseHandshake(
        "GET /chat HTTP/1.1\r\n" ++
            "Host : example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
    try std.testing.expectError(error.UnsupportedMethod, parseHandshake(
        "POST /chat HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
    try std.testing.expectError(error.MissingConnection, parseHandshake(
        "GET /chat HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
    try std.testing.expectError(error.InvalidKey, parseHandshake(
        "GET /chat HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: bad-key\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
    ));
}

test "known RFC masked frame decodes expected payload" {
    const bytes = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var payload_buf: [32]u8 = undefined;
    const decoded = try decodeFrame(128, .client_to_server, &bytes, &payload_buf);
    try std.testing.expect(decoded.frame.fin);
    try std.testing.expectEqual(Opcode.text, decoded.frame.opcode);
    try std.testing.expect(decoded.frame.masked);
    try std.testing.expectEqualStrings("Hello", decoded.frame.payload);
    try std.testing.expectEqual(bytes.len, decoded.consumed);
}

test "masked and unmasked frames round trip" {
    const client_payload = "PRIVMSG #onyx :hello\r\n";
    var encoded_buf: [128]u8 = undefined;
    const encoded = try encodeFrame(128, .{
        .opcode = .text,
        .mask_key = .{ 0x12, 0x34, 0x56, 0x78 },
    }, client_payload, &encoded_buf);

    var payload_buf: [128]u8 = undefined;
    const decoded = try decodeFrame(128, .client_to_server, encoded, &payload_buf);
    try std.testing.expectEqual(Opcode.text, decoded.frame.opcode);
    try std.testing.expectEqualStrings(client_payload, decoded.frame.payload);
    try std.testing.expectEqual(encoded.len, decoded.consumed);

    const server_payload = "PING :onyx\r\n";
    const server_encoded = try encodeFrame(128, .{ .opcode = .text }, server_payload, &encoded_buf);
    const server_decoded = try decodeFrame(128, .server_to_client, server_encoded, &.{});
    try std.testing.expect(!server_decoded.frame.masked);
    try std.testing.expectEqualStrings(server_payload, server_decoded.frame.payload);
}

test "extended length frame round trips" {
    var payload: [130]u8 = undefined;
    @memset(&payload, 'a');

    var encoded_buf: [256]u8 = undefined;
    const encoded = try encodeFrame(256, .{
        .opcode = .binary,
        .mask_key = .{ 1, 2, 3, 4 },
    }, &payload, &encoded_buf);
    try std.testing.expectEqual(@as(u8, 126 | 0x80), encoded[1]);

    var payload_buf: [130]u8 = undefined;
    const decoded = try decodeFrame(256, .client_to_server, encoded, &payload_buf);
    try std.testing.expectEqual(Opcode.binary, decoded.frame.opcode);
    try std.testing.expectEqualSlices(u8, &payload, decoded.frame.payload);
}

test "oversize truncated and unmasked client frames are rejected" {
    const unmasked = [_]u8{ 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };
    var payload_buf: [16]u8 = undefined;
    try std.testing.expectError(error.UnmaskedClientFrame, decodeFrame(16, .client_to_server, &unmasked, &payload_buf));

    const truncated = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f };
    try std.testing.expectError(error.Truncated, decodeFrame(16, .client_to_server, &truncated, &payload_buf));

    const oversized = [_]u8{ 0x81, 0x86, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.PayloadTooLarge, decodeFrame(5, .client_to_server, &oversized, &payload_buf));
}

test "invalid control and length encodings are rejected" {
    const fragmented_ping = [_]u8{ 0x09, 0x80, 1, 2, 3, 4 };
    var payload_buf: [16]u8 = undefined;
    try std.testing.expectError(error.FragmentedControlFrame, decodeFrame(16, .client_to_server, &fragmented_ping, &payload_buf));

    const noncanonical = [_]u8{ 0x81, 0xfe, 0x00, 0x7d, 1, 2, 3, 4 };
    try std.testing.expectError(error.NonCanonicalLength, decodeFrame(128, .client_to_server, &noncanonical, &payload_buf));
}

test "deframer reassembles a frame split across arbitrary feeds" {
    var d = Deframer(256){};
    const frame = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    // Feed one byte at a time: no event until the final byte lands.
    for (frame, 0..) |byte, i| {
        try d.feed(&.{byte});
        if (i + 1 < frame.len) {
            try std.testing.expect((try d.next()) == null);
        }
    }
    const ev = (try d.next()).?;
    try std.testing.expectEqualStrings("Hello", ev.data.payload);
    try std.testing.expect(ev.data.fin);
    try std.testing.expect((try d.next()) == null);
}

test "deframer pops multiple frames from one feed and tracks fragmentation" {
    var d = Deframer(256){};
    var buf_a: [64]u8 = undefined;
    var buf_b: [64]u8 = undefined;
    var buf_c: [64]u8 = undefined;
    const key = [4]u8{ 9, 8, 7, 6 };
    // text(!fin "NICK ") + ping("hb") interleaved + continuation(fin "w")
    const f1 = try encodeFrame(256, .{ .fin = false, .opcode = .text, .mask_key = key }, "NICK ", &buf_a);
    const f2 = try encodeFrame(256, .{ .opcode = .ping, .mask_key = key }, "hb", &buf_b);
    const f3 = try encodeFrame(256, .{ .opcode = .continuation, .mask_key = key }, "w", &buf_c);
    try d.feed(f1);
    try d.feed(f2);
    try d.feed(f3);

    const first = (try d.next()).?;
    try std.testing.expectEqualStrings("NICK ", first.data.payload);
    try std.testing.expect(!first.data.fin);
    const mid = (try d.next()).?;
    try std.testing.expectEqualStrings("hb", mid.ping);
    const last = (try d.next()).?;
    try std.testing.expectEqualStrings("w", last.data.payload);
    try std.testing.expect(last.data.fin);
    try std.testing.expect((try d.next()) == null);
}

test "deframer rejects fragmentation-state violations and unmasked frames" {
    // Continuation with no open message.
    {
        var d = Deframer(64){};
        var buf: [32]u8 = undefined;
        const f = try encodeFrame(64, .{ .opcode = .continuation, .mask_key = .{ 1, 2, 3, 4 } }, "x", &buf);
        try d.feed(f);
        try std.testing.expectError(error.UnexpectedContinuation, d.next());
    }
    // New text frame while a fragmented message is open.
    {
        var d = Deframer(64){};
        var buf_a: [32]u8 = undefined;
        var buf_b: [32]u8 = undefined;
        const f1 = try encodeFrame(64, .{ .fin = false, .opcode = .text, .mask_key = .{ 1, 2, 3, 4 } }, "a", &buf_a);
        const f2 = try encodeFrame(64, .{ .opcode = .text, .mask_key = .{ 1, 2, 3, 4 } }, "b", &buf_b);
        try d.feed(f1);
        try d.feed(f2);
        _ = (try d.next()).?;
        try std.testing.expectError(error.NestedFragmentation, d.next());
    }
    // Clients MUST mask: an unmasked client frame is a stream-fatal error.
    {
        var d = Deframer(64){};
        const unmasked = [_]u8{ 0x81, 0x05, 'H', 'e', 'l', 'l', 'o' };
        try d.feed(&unmasked);
        try std.testing.expectError(error.UnmaskedClientFrame, d.next());
    }
}

test "deframer surfaces close and pong and rejects oversize declared frames" {
    var d = Deframer(32){};
    var buf: [32]u8 = undefined;
    const close = try encodeFrame(32, .{ .opcode = .close, .mask_key = .{ 5, 5, 5, 5 } }, &.{ 0x03, 0xe8 }, &buf);
    try d.feed(close);
    const ev = (try d.next()).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xe8 }, ev.close);

    var d2 = Deframer(32){};
    const pong = try encodeFrame(32, .{ .opcode = .pong, .mask_key = .{ 5, 5, 5, 5 } }, "", &buf);
    try d2.feed(pong);
    try std.testing.expect(std.meta.activeTag((try d2.next()).?) == .pong);

    // Declared length above capacity is rejected from the header alone, before
    // the payload ever arrives (so feed() can never be tricked into overflow).
    var d3 = Deframer(32){};
    const oversize_header = [_]u8{ 0x81, 0x80 | 126, 0x01, 0x00 }; // 256-byte declared payload
    try d3.feed(&oversize_header);
    try std.testing.expectError(error.PayloadTooLarge, d3.next());
}

test "deframer accepts a large binary media frame above the IRC-line limit" {
    // A browser media datagram (e.g. a 1080p video keyframe) dwarfs any IRC line.
    // With a media-sized capacity the deframer must admit it as ONE binary DATA
    // frame — the regression being that rejecting it (PayloadTooLarge) tore the
    // WebSocket session down mid-call. The deframer buffers are media-sized, so
    // heap-allocate it rather than put ~2 MiB on the test stack (mirrors the
    // daemon, where WsState is `*WsState`).
    const cap = 1 << 20; // 1 MiB, media-sized
    const payload_len = 100_000; // far above the 8 KiB IRC-line ceiling
    const alloc = std.testing.allocator;

    const payload = try alloc.alloc(u8, payload_len);
    defer alloc.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    const framed = try alloc.alloc(u8, payload_len + 14); // 10-byte header + 4-byte mask + payload
    defer alloc.free(framed);
    const frame = try encodeFrame(cap, .{ .opcode = .binary, .mask_key = .{ 1, 2, 3, 4 } }, payload, framed);

    const D = Deframer(cap);
    const d = try alloc.create(D);
    defer alloc.destroy(d);
    d.* = .{};

    try d.feed(frame);
    const ev = (try d.next()).?;
    try std.testing.expect(std.meta.activeTag(ev) == .data);
    try std.testing.expect(ev.data.binary);
    try std.testing.expect(ev.data.fin);
    try std.testing.expectEqual(@as(usize, payload_len), ev.data.payload.len);
    try std.testing.expectEqualSlices(u8, payload, ev.data.payload);
}

test "irc line helper extracts complete lines only" {
    const first = nextIrcLine("NICK example\r\nUSER m 0 * :Onyx\r\n").?;
    try std.testing.expectEqualStrings("NICK example", first.line);
    try std.testing.expectEqual(@as(usize, 14), first.consumed);
    try std.testing.expect(nextIrcLine("PRIVMSG #chan :partial") == null);
}
