// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP/3 + WebTransport session layer (layer 6) over the QUIC connection
//! driver (`quic_conn.zig`, layer 5).
//!
//! Implements the SERVER side of WebTransport-over-HTTP/3:
//!   * RFC 9114 — HTTP/3: the frame codec (DATA / HEADERS / SETTINGS, plus
//!     tolerate-and-skip for GREASE and unknown frame types) and the
//!     unidirectional stream type prefix (control = 0x00, QPACK encoder/decoder
//!     = 0x02 / 0x03).
//!   * RFC 9220 — WebTransport over HTTP/3: the Extended CONNECT handshake
//!     (`:method = CONNECT`, `:protocol = webtransport`) and the WT bidi/uni
//!     stream type signals (0x41 / 0x54) from `webtransport.zig`.
//!   * RFC 9297 — HTTP Datagrams: WT datagrams carried as QUIC DATAGRAM frames
//!     prefixed with the session's quarter-stream-id.
//!
//! Socketless + layered: this module never touches a socket. It consumes the
//! `Conn` application I/O surface (`openStream` / `openUniStream` /
//! `sendStream` / `readStream` / `streamFinished`, `sendDatagram` /
//! `recvDatagramPayload`) and the lower codecs (`http3_qpack`, `webtransport`).
//! It re-implements neither QUIC streams/datagrams nor QPACK.
//!
//! QPACK simplification (intentional, standard, documented): the server
//! advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0` and
//! `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, so no dynamic table is ever used. Every
//! header block is decodable with the static table + literals alone (RFC 9204 —
//! Required Insert Count and Base are always zero). The QPACK encoder/decoder
//! unidirectional streams therefore carry no instructions; we still open the
//! encoder stream (type 0x02, empty) for spec conformance and ignore the peer's.
//!
//! Other documented simplifications:
//!   * One WebTransport session per connection is the common deployment shape; a
//!     second CONNECT is rejected. The session model itself is keyed by CONNECT
//!     stream id, so lifting this to multi-session is a small change.
//!   * No HTTP request routing beyond Extended CONNECT — a plain (non-CONNECT)
//!     request is answered 405 and the stream is finished.
//!   * WebTransport stream flow control is QUIC's; no WT-level capsule-based
//!     flow control beyond session close.
//!
//! All parsing is bounds-checked: a malformed SETTINGS, HEADERS, or stream
//! prefix returns an error and never panics or reads out of bounds.

const std = @import("std");
const Allocator = std.mem.Allocator;

const quic_conn = @import("quic_conn.zig");
const qpack = @import("http3_qpack.zig");
const webtransport = @import("webtransport.zig");

// ===========================================================================
// HTTP/3 constants (RFC 9114, RFC 9220, RFC 9297)
// ===========================================================================

/// HTTP/3 frame types (RFC 9114 §7.2 / §11.2.1). Only the ones we encode or
/// recognise are named; everything else is skipped on the wire.
pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const goaway: u64 = 0x07;
    pub const max_push_id: u64 = 0x0d;
    /// WebTransport bidirectional stream frame type when a session's bidi stream
    /// is signalled inside an HTTP/3 stream (not used on the server accept path,
    /// kept for completeness).
    pub const webtransport_stream: u64 = 0x41;
};

/// Unidirectional stream type prefixes (RFC 9114 §6.2, RFC 9204 §4.2).
pub const UniStreamType = struct {
    pub const control: u64 = 0x00;
    pub const push: u64 = 0x01;
    pub const qpack_encoder: u64 = 0x02;
    pub const qpack_decoder: u64 = 0x03;
    /// WebTransport unidirectional stream (RFC 9220 §4): 0x54 then session id.
    pub const webtransport: u64 = 0x54;
};

/// HTTP/3 SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9220 §8.2, RFC 9297 §5).
pub const Setting = struct {
    pub const qpack_max_table_capacity: u64 = 0x01;
    pub const max_field_section_size: u64 = 0x06;
    pub const qpack_blocked_streams: u64 = 0x07;
    /// RFC 9297 — enables HTTP Datagrams (the H3_DATAGRAM setting).
    pub const h3_datagram: u64 = 0x33;
    /// RFC 8441 / RFC 9220 — server allows the Extended CONNECT protocol.
    pub const enable_connect_protocol: u64 = 0x08;
    /// RFC 9220 §8.2 — enables WebTransport over HTTP/3.
    pub const enable_webtransport: u64 = 0x2b603742;
};

pub const Error = error{
    /// A frame, SETTINGS body, or stream prefix could not be parsed within
    /// bounds (truncated, oversized varint, or length running past the buffer).
    Malformed,
    /// The peer's SETTINGS did not advertise the support WebTransport requires.
    WebTransportUnsupported,
    /// A second CONNECT arrived; this layer supports one session per connection.
    SessionAlreadyEstablished,
    /// An Extended CONNECT request was missing or had the wrong pseudo-headers.
    BadConnect,
    /// The underlying QUIC connection is not established / has closed.
    NotReady,
} || Allocator.Error || qpack.DecodeError || qpack.EncodeError || webtransport.FormatError;

// ===========================================================================
// HTTP/3 frame codec (RFC 9114 §7.1) — varint type + varint length + payload
// ===========================================================================

pub const H3Frame = struct {
    frame_type: u64,
    payload: []const u8, // borrows the input
};

/// Decode one HTTP/3 frame from `input`, returning the frame and the number of
/// bytes consumed. Bounds-checked: a truncated header or a length running past
/// the buffer returns `error.Malformed`.
pub fn decodeFrame(input: []const u8) Error!struct { frame: H3Frame, consumed: usize } {
    const t = webtransport.decodeVarint(input) catch return error.Malformed;
    var pos: usize = t.len;
    const l = webtransport.decodeVarint(input[pos..]) catch return error.Malformed;
    pos += l.len;
    const length = std.math.cast(usize, l.value) orelse return error.Malformed;
    if (length > input.len - pos) return error.Malformed;
    const payload = input[pos .. pos + length];
    return .{ .frame = .{ .frame_type = t.value, .payload = payload }, .consumed = pos + length };
}

/// Append an HTTP/3 frame (type varint + length varint + payload) to `out`.
pub fn encodeFrame(allocator: Allocator, out: *std.ArrayList(u8), frame_type: u64, payload: []const u8) Error!void {
    var buf: [8]u8 = undefined;
    try out.appendSlice(allocator, try webtransport.encodeVarint(frame_type, &buf));
    const len_u64 = std.math.cast(u64, payload.len) orelse return error.Malformed;
    try out.appendSlice(allocator, try webtransport.encodeVarint(len_u64, &buf));
    try out.appendSlice(allocator, payload);
}

/// Append only an HTTP/3 frame *header* (type varint + length varint) for a
/// frame whose `payload_len`-byte payload will be streamed separately. Used by
/// the large-response path so a multi-hundred-KiB DATA frame never has to be
/// buffered in one allocation: the frame header declares the length, then the
/// body bytes follow on the same stream.
pub fn appendFrameHeader(allocator: Allocator, out: *std.ArrayList(u8), frame_type: u64, payload_len: usize) Error!void {
    var buf: [8]u8 = undefined;
    try out.appendSlice(allocator, try webtransport.encodeVarint(frame_type, &buf));
    const len_u64 = std.math.cast(u64, payload_len) orelse return error.Malformed;
    try out.appendSlice(allocator, try webtransport.encodeVarint(len_u64, &buf));
}

/// Iterate frames in a buffer, skipping unknown/GREASE frame types. Returns the
/// first frame whose type matches `want`, or null if the buffer is exhausted.
/// `start` is advanced past every frame inspected so the caller can resume.
pub fn findFrame(input: []const u8, start: *usize, want: u64) Error!?H3Frame {
    var pos = start.*;
    while (pos < input.len) {
        const d = try decodeFrame(input[pos..]);
        pos += d.consumed;
        if (d.frame.frame_type == want) {
            start.* = pos;
            return d.frame;
        }
        // Unknown / GREASE / other known-but-uninteresting frames are skipped
        // (RFC 9114 §9 — reserved frame types of the form 0x1f*N+0x21 and any
        // unrecognised type MUST be ignored).
    }
    start.* = pos;
    return null;
}

// ===========================================================================
// SETTINGS codec (RFC 9114 §7.2.4) — sequence of (identifier, value) varints
// ===========================================================================

/// The SETTINGS values we care about, decoded from a peer SETTINGS frame body
/// or used to build our own. Absent settings keep their default (0 / false).
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    max_field_section_size: u64 = 0,
    enable_webtransport: bool = false,
    h3_datagram: bool = false,
    enable_connect_protocol: bool = false,

    /// The server SETTINGS this layer advertises: WebTransport + H3 Datagrams +
    /// Extended CONNECT enabled, and a zero-capacity QPACK dynamic table.
    pub fn serverDefault() Settings {
        return .{
            .qpack_max_table_capacity = 0,
            .qpack_blocked_streams = 0,
            .enable_webtransport = true,
            .h3_datagram = true,
            .enable_connect_protocol = true,
        };
    }

    /// True if the peer advertised what WebTransport-over-HTTP/3 requires:
    /// `SETTINGS_ENABLE_WEBTRANSPORT` and `SETTINGS_H3_DATAGRAM` (RFC 9220 §3.1,
    /// RFC 9297). `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08, RFC 8441) is an
    /// HTTP/2 setting and is NOT used in HTTP/3 — Extended CONNECT is enabled in
    /// H3 by the presence of `SETTINGS_ENABLE_WEBTRANSPORT` itself. Real browsers
    /// (Chrome) therefore omit 0x08 from their H3 SETTINGS, so it MUST NOT be
    /// required here; requiring it rejects every browser WebTransport CONNECT.
    pub fn supportsWebTransport(self: Settings) bool {
        return self.enable_webtransport and self.h3_datagram;
    }
};

/// Encode a SETTINGS frame *body* (the (id,value) pairs only, no frame header).
pub fn encodeSettingsBody(allocator: Allocator, s: Settings) Error![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var buf: [8]u8 = undefined;

    const Pair = struct { id: u64, value: u64 };
    var pairs: [6]Pair = undefined;
    var n: usize = 0;
    // Always advertise the QPACK zero-capacity settings explicitly so the peer
    // knows the dynamic table is unused.
    pairs[n] = .{ .id = Setting.qpack_max_table_capacity, .value = s.qpack_max_table_capacity };
    n += 1;
    pairs[n] = .{ .id = Setting.qpack_blocked_streams, .value = s.qpack_blocked_streams };
    n += 1;
    if (s.max_field_section_size != 0) {
        pairs[n] = .{ .id = Setting.max_field_section_size, .value = s.max_field_section_size };
        n += 1;
    }
    if (s.enable_connect_protocol) {
        pairs[n] = .{ .id = Setting.enable_connect_protocol, .value = 1 };
        n += 1;
    }
    if (s.h3_datagram) {
        pairs[n] = .{ .id = Setting.h3_datagram, .value = 1 };
        n += 1;
    }
    if (s.enable_webtransport) {
        pairs[n] = .{ .id = Setting.enable_webtransport, .value = 1 };
        n += 1;
    }

    for (pairs[0..n]) |p| {
        try body.appendSlice(allocator, try webtransport.encodeVarint(p.id, &buf));
        try body.appendSlice(allocator, try webtransport.encodeVarint(p.value, &buf));
    }
    return body.toOwnedSlice(allocator);
}

/// Decode a SETTINGS frame body into a `Settings`. Unknown setting identifiers
/// are skipped (RFC 9114 §7.2.4 — an endpoint MUST ignore unknown settings).
/// Bounds-checked: a value varint running past the body is `error.Malformed`.
pub fn decodeSettingsBody(body: []const u8) Error!Settings {
    var s = Settings{};
    var pos: usize = 0;
    while (pos < body.len) {
        const id = webtransport.decodeVarint(body[pos..]) catch return error.Malformed;
        pos += id.len;
        if (pos >= body.len) return error.Malformed; // value missing
        const val = webtransport.decodeVarint(body[pos..]) catch return error.Malformed;
        pos += val.len;
        switch (id.value) {
            Setting.qpack_max_table_capacity => s.qpack_max_table_capacity = val.value,
            Setting.qpack_blocked_streams => s.qpack_blocked_streams = val.value,
            Setting.max_field_section_size => s.max_field_section_size = val.value,
            Setting.enable_connect_protocol => s.enable_connect_protocol = val.value != 0,
            Setting.h3_datagram => s.h3_datagram = val.value != 0,
            Setting.enable_webtransport => s.enable_webtransport = val.value != 0,
            else => {}, // ignore unknown / GREASE settings
        }
    }
    return s;
}

// ===========================================================================
// Extended CONNECT request / response (RFC 9220 §3, RFC 8441)
// ===========================================================================

/// The pseudo-headers of an Extended CONNECT request, borrowing the decoded
/// QPACK strings. A valid WebTransport CONNECT has method=CONNECT,
/// protocol=webtransport, scheme=https, and an :authority + :path.
pub const ConnectRequest = struct {
    method: []const u8 = "",
    protocol: []const u8 = "",
    scheme: []const u8 = "",
    authority: []const u8 = "",
    path: []const u8 = "",

    pub fn isWebTransport(self: ConnectRequest) bool {
        return std.mem.eql(u8, self.method, "CONNECT") and
            std.mem.eql(u8, self.protocol, "webtransport");
    }
};

/// Decode a QPACK header block (the HEADERS frame payload) into a
/// `ConnectRequest`. The returned strings borrow `section` (owned by caller);
/// free it with `section.deinit(allocator)`. The `FieldSection` owns any
/// Huffman-decoded string bytes the request pseudo-headers point into.
pub fn decodeConnectHeaders(allocator: Allocator, header_block: []const u8) Error!struct {
    request: ConnectRequest,
    section: qpack.FieldSection,
} {
    var section = try qpack.decodeFieldSectionAlloc(allocator, header_block);
    errdefer section.deinit(allocator);
    var req = ConnectRequest{};
    for (section.headers) |h| {
        if (std.mem.eql(u8, h.name, ":method")) {
            req.method = h.value;
        } else if (std.mem.eql(u8, h.name, ":protocol")) {
            req.protocol = h.value;
        } else if (std.mem.eql(u8, h.name, ":scheme")) {
            req.scheme = h.value;
        } else if (std.mem.eql(u8, h.name, ":authority")) {
            req.authority = h.value;
        } else if (std.mem.eql(u8, h.name, ":path")) {
            req.path = h.value;
        }
    }
    return .{ .request = req, .section = section };
}

/// Encode the QPACK header block for an Extended CONNECT request (client side,
/// used by the test helper and by any client embedding). Caller owns the slice.
pub fn encodeConnectHeaders(
    allocator: Allocator,
    authority: []const u8,
    path: []const u8,
) Error![]u8 {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = path },
    };
    return qpack.encodeFieldSection(allocator, &hdrs);
}

/// Encode the QPACK header block for the `:status` response. `ok` selects 200
/// (CONNECT accepted) vs a 4xx rejection. Caller owns the slice.
pub fn encodeStatusHeaders(allocator: Allocator, status: []const u8) Error![]u8 {
    const hdrs = [_]qpack.Header{
        .{ .name = ":status", .value = status },
    };
    return qpack.encodeFieldSection(allocator, &hdrs);
}

// ===========================================================================
// WebTransport session model
// ===========================================================================

pub const SessionId = webtransport.SessionId;

/// A WebTransport stream opened/accepted within a session. `stream_id` is the
/// underlying QUIC stream id; `is_bidirectional` distinguishes WT bidi vs uni.
pub const WtStream = struct {
    stream_id: u64,
    is_bidirectional: bool,
};

/// An established WebTransport session, keyed by the CONNECT (bidi) stream id.
/// Owns copies of the authority/path so they survive past the decoded HEADERS.
pub const Session = struct {
    allocator: Allocator,
    /// The CONNECT stream id == the WebTransport session id (RFC 9220 §4.2).
    session_id: SessionId,
    authority: []u8, // owned
    path: []u8, // owned
    /// WT streams known to this session (opened locally or accepted from peer).
    streams: std.ArrayList(WtStream),
    closed: bool = false,

    fn init(allocator: Allocator, connect_stream_id: u64, authority: []const u8, path: []const u8) Error!Session {
        const sid = SessionId.initClientBidirectional(connect_stream_id) catch return error.Malformed;
        const auth_copy = try allocator.dupe(u8, authority);
        errdefer allocator.free(auth_copy);
        const path_copy = try allocator.dupe(u8, path);
        errdefer allocator.free(path_copy);
        return .{
            .allocator = allocator,
            .session_id = sid,
            .authority = auth_copy,
            .path = path_copy,
            .streams = .empty,
        };
    }

    fn deinit(self: *Session) void {
        self.allocator.free(self.authority);
        self.allocator.free(self.path);
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }

    /// The quarter-stream-id used to prefix this session's datagrams (RFC 9297).
    pub fn quarterStreamId(self: *const Session) u64 {
        return self.session_id.quarterStreamId();
    }
};

// ===========================================================================
// Http3Conn — the server-side driver over a `*quic_conn.Conn`
// ===========================================================================

/// Events surfaced to the caller (the IRC bridge / listener layer).
pub const Event = union(enum) {
    /// A WebTransport session was established. The `Session` is owned by the
    /// `Http3Conn`; the slices borrow it and are valid until the session closes.
    session_established: struct {
        session_id: u64,
        authority: []const u8,
        path: []const u8,
    },
    /// The (single) WebTransport session closed.
    session_closed: struct { session_id: u64 },
    /// A CONNECT request was rejected (e.g. not WebTransport). The stream was
    /// answered with `status` and finished.
    connect_rejected: struct { stream_id: u64, status: []const u8 },
    /// A plain (non-WebTransport) HTTP/3 request was answered with a complete
    /// response (HEADERS + optional DATA + fin). `status` is the `:status` we
    /// sent; `path` borrows storage owned by this Http3Conn until deinit. Used
    /// by curl/browser GETs that probe the endpoint; the bridge ignores it.
    http_responded: struct { stream_id: u64, status: []const u8, path: []const u8 },
};

pub const SnapshotError = error{ InvalidSnapshot, SnapshotTooLarge, ConfigMismatch } || Allocator.Error;
pub const snapshot_max_streams: usize = 64;
pub const snapshot_max_wt_streams: usize = 256;
pub const snapshot_max_events: usize = 256;
pub const snapshot_max_owned_bytes: usize = 64 * 1024 * 1024;
const snapshot_max_buffer: usize = 4 * 1024 * 1024;
const snapshot_max_text: usize = 8 * 1024;
const snapshot_max_varint: u64 = (1 << 62) - 1;

const SessionSnapshot = struct {
    session_id: u64,
    authority: []u8,
    path: []u8,
    streams: []WtStream,
    closed: bool,

    fn deinit(self: *SessionSnapshot, allocator: Allocator) void {
        allocator.free(self.authority);
        allocator.free(self.path);
        allocator.free(self.streams);
        self.* = undefined;
    }
};

const UniSnapshot = struct {
    id: u64,
    stream_type: ?u64,
    wt_session_id: ?u64,
    prefix: []u8,
    body: []u8,
    settings_done: bool,

    fn deinit(self: *UniSnapshot, allocator: Allocator) void {
        allocator.free(self.prefix);
        allocator.free(self.body);
        self.* = undefined;
    }
};

const BidiSnapshot = struct {
    id: u64,
    bytes: []u8,

    fn deinit(self: *BidiSnapshot, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

const EventStatus = enum { ok_200, not_found_404, method_405, conflict_409, unsupported_501 };
const EventSnapshot = union(enum) {
    session_established: u64,
    session_closed: u64,
    connect_rejected: struct { stream_id: u64, status: EventStatus },
    http_responded: struct { stream_id: u64, status: EventStatus, path: []u8 },

    fn deinit(self: *EventSnapshot, allocator: Allocator) void {
        switch (self.*) {
            .http_responded => |event| allocator.free(event.path),
            else => {},
        }
        self.* = undefined;
    }
};

/// Owned logical H3/WT state. The QUIC Conn is deliberately external: restore
/// must receive the fully restored, stable candidate Conn pointer first.
pub const Http3Snapshot = struct {
    local_settings: Settings,
    control_stream_id: ?u64,
    settings_sent: bool,
    peer_control_stream_id: ?u64,
    peer_settings: ?Settings,
    qpack_encoder_stream_id: ?u64,
    session: ?SessionSnapshot,
    uni: []UniSnapshot,
    bidi: []BidiSnapshot,
    bidi_handled: []u64,
    events: []EventSnapshot,

    pub fn deinit(self: *Http3Snapshot, allocator: Allocator) void {
        if (self.session) |*session| session.deinit(allocator);
        for (self.uni) |*entry| entry.deinit(allocator);
        allocator.free(self.uni);
        for (self.bidi) |*entry| entry.deinit(allocator);
        allocator.free(self.bidi);
        allocator.free(self.bidi_handled);
        for (self.events) |*event| event.deinit(allocator);
        allocator.free(self.events);
        self.* = undefined;
    }

    pub fn validate(self: *const Http3Snapshot) SnapshotError!void {
        try validateSnapshotSettings(self.local_settings);
        if (self.peer_settings) |settings| try validateSnapshotSettings(settings);
        if (self.local_settings.qpack_max_table_capacity != 0 or self.local_settings.qpack_blocked_streams != 0 or
            self.uni.len > snapshot_max_streams or self.bidi.len > snapshot_max_streams or
            self.bidi_handled.len > snapshot_max_streams or self.events.len > snapshot_max_events)
            return error.SnapshotTooLarge;
        if (self.settings_sent and (self.control_stream_id == null or self.qpack_encoder_stream_id == null))
            return error.InvalidSnapshot;
        if (self.control_stream_id) |id| try validateSnapshotStreamId(id, 3);
        if (self.qpack_encoder_stream_id) |id| try validateSnapshotStreamId(id, 3);
        if (self.control_stream_id != null and self.qpack_encoder_stream_id != null and
            self.control_stream_id.? == self.qpack_encoder_stream_id.?) return error.InvalidSnapshot;
        if (self.peer_control_stream_id) |id| try validateSnapshotStreamId(id, 2);
        var total: usize = 0;
        if (self.session) |session| {
            if (session.session_id > snapshot_max_varint or session.session_id % 4 != 0 or
                session.authority.len > snapshot_max_text or session.path.len > snapshot_max_text or
                session.streams.len > snapshot_max_wt_streams) return error.InvalidSnapshot;
            if (!self.settings_sent or self.peer_settings == null or
                !self.peer_settings.?.supportsWebTransport()) return error.InvalidSnapshot;
            try snapshotAddBytes(&total, session.authority.len);
            try snapshotAddBytes(&total, session.path.len);
            for (session.streams) |stream| {
                if (stream.stream_id > snapshot_max_varint or
                    (stream.is_bidirectional and stream.stream_id & 2 != 0) or
                    (!stream.is_bidirectional and stream.stream_id & 2 == 0)) return error.InvalidSnapshot;
            }
        }
        for (self.uni, 0..) |entry, i| {
            try validateSnapshotStreamId(entry.id, 2);
            if (i > 0 and self.uni[i - 1].id >= entry.id) return error.InvalidSnapshot;
            if (entry.stream_type) |value| if (value > snapshot_max_varint) return error.InvalidSnapshot;
            if (entry.wt_session_id) |value| if (value > snapshot_max_varint) return error.InvalidSnapshot;
            if (entry.prefix.len > snapshot_max_buffer or entry.body.len > snapshot_max_buffer or
                (entry.stream_type == null and (entry.settings_done or entry.wt_session_id != null)) or
                (entry.stream_type == null and entry.body.len != 0) or
                (entry.stream_type != null and entry.prefix.len != 0) or
                (entry.settings_done and (entry.stream_type == null or entry.stream_type.? != UniStreamType.control)) or
                (entry.wt_session_id != null and (entry.stream_type == null or entry.stream_type.? != UniStreamType.webtransport)))
                return error.InvalidSnapshot;
            try snapshotAddBytes(&total, entry.prefix.len);
            try snapshotAddBytes(&total, entry.body.len);
        }
        for (self.bidi, 0..) |entry, i| {
            try validateSnapshotStreamId(entry.id, 0);
            if (i > 0 and self.bidi[i - 1].id >= entry.id or entry.bytes.len > snapshot_max_buffer)
                return error.InvalidSnapshot;
            try snapshotAddBytes(&total, entry.bytes.len);
        }
        for (self.bidi_handled, 0..) |id, i| {
            try validateSnapshotStreamId(id, 0);
            if (i > 0 and self.bidi_handled[i - 1] >= id) return error.InvalidSnapshot;
        }
        if (self.peer_control_stream_id) |id| {
            const entry = findUniSnapshot(self.uni, id) orelse return error.InvalidSnapshot;
            if (entry.stream_type == null or entry.stream_type.? != UniStreamType.control) return error.InvalidSnapshot;
            if ((self.peer_settings != null) != entry.settings_done) return error.InvalidSnapshot;
        } else if (self.peer_settings != null) return error.InvalidSnapshot;
        for (self.events) |event| {
            switch (event) {
                .session_established => |id| {
                    if (self.session == null or self.session.?.session_id != id) return error.InvalidSnapshot;
                },
                .session_closed => |id| {
                    if (self.session == null or self.session.?.session_id != id or !self.session.?.closed)
                        return error.InvalidSnapshot;
                },
                .connect_rejected => |item| {
                    try validateSnapshotStreamId(item.stream_id, 0);
                    if (item.status != .method_405 and item.status != .conflict_409 and item.status != .unsupported_501)
                        return error.InvalidSnapshot;
                },
                .http_responded => |item| {
                    try validateSnapshotStreamId(item.stream_id, 0);
                    if (item.status != .ok_200 and item.status != .not_found_404 or item.path.len > snapshot_max_text)
                        return error.InvalidSnapshot;
                    try snapshotAddBytes(&total, item.path.len);
                },
            }
        }
    }
};

fn validateSnapshotSettings(settings: Settings) SnapshotError!void {
    if (settings.qpack_max_table_capacity > snapshot_max_varint or settings.qpack_blocked_streams > snapshot_max_varint or
        settings.max_field_section_size > snapshot_max_varint) return error.InvalidSnapshot;
}

fn validateSnapshotStreamId(id: u64, residue: u64) SnapshotError!void {
    if (id > snapshot_max_varint or id % 4 != residue) return error.InvalidSnapshot;
}

fn snapshotAddBytes(total: *usize, n: usize) SnapshotError!void {
    total.* = std.math.add(usize, total.*, n) catch return error.SnapshotTooLarge;
    if (total.* > snapshot_max_owned_bytes) return error.SnapshotTooLarge;
}

fn findUniSnapshot(entries: []const UniSnapshot, id: u64) ?UniSnapshot {
    for (entries) |entry| if (entry.id == id) return entry;
    return null;
}

/// H3 keeps only references to streams whose bytes and send cursors live in
/// the separately restored QUIC connection. Reject a mismatched connection
/// before publishing the detached H3 driver.
fn snapshotConnJoin(conn: *quic_conn.Conn, snapshot: *const Http3Snapshot) bool {
    if (snapshot.settings_sent and
        (!conn.stream_senders.contains(snapshot.control_stream_id.?) or
            !conn.stream_senders.contains(snapshot.qpack_encoder_stream_id.?))) return false;
    if (snapshot.peer_control_stream_id) |id| {
        if (conn.engine.getStream(id) == null) return false;
    }
    if (snapshot.session) |session| {
        if (conn.engine.getStream(session.session_id) == null or
            !conn.stream_senders.contains(session.session_id)) return false;
        for (session.streams) |stream| {
            if (stream.stream_id & 1 == 0) {
                if (conn.engine.getStream(stream.stream_id) == null) return false;
            } else if (!conn.stream_senders.contains(stream.stream_id)) return false;
        }
    }
    for (snapshot.uni) |entry| {
        if (conn.engine.getStream(entry.id) == null) return false;
    }
    for (snapshot.bidi) |entry| {
        if (conn.engine.getStream(entry.id) == null) return false;
    }
    for (snapshot.bidi_handled) |id| {
        if (conn.engine.getStream(id) == null) return false;
    }
    return true;
}

fn snapshotEventStatus(status: []const u8) SnapshotError!EventStatus {
    if (std.mem.eql(u8, status, "200")) return .ok_200;
    if (std.mem.eql(u8, status, "404")) return .not_found_404;
    if (std.mem.eql(u8, status, "405")) return .method_405;
    if (std.mem.eql(u8, status, "409")) return .conflict_409;
    if (std.mem.eql(u8, status, "501")) return .unsupported_501;
    return error.InvalidSnapshot;
}

fn snapshotStatusText(status: EventStatus) []const u8 {
    return switch (status) {
        .ok_200 => "200",
        .not_found_404 => "404",
        .method_405 => "405",
        .conflict_409 => "409",
        .unsupported_501 => "501",
    };
}

/// The server-side HTTP/3 + WebTransport driver. Wraps a `*quic_conn.Conn`
/// (which it does NOT own — the listener owns the QUIC connection). Drives the
/// control stream + SETTINGS, accepts the Extended CONNECT, and models the WT
/// session. Call `service` after feeding the QUIC conn its datagrams.
pub const Http3Conn = struct {
    allocator: Allocator,
    conn: *quic_conn.Conn,
    role: quic_conn.Role,

    /// Local SETTINGS we advertise (server defaults).
    local_settings: Settings,
    /// The control uni-stream id we opened, once opened.
    control_stream_id: ?u64 = null,
    /// True once we have written our SETTINGS frame on the control stream.
    settings_sent: bool = false,
    /// The peer's control stream id, once detected (first uni stream whose type
    /// prefix is 0x00). On the server this is the client's control stream.
    peer_control_stream_id: ?u64 = null,
    /// Peer SETTINGS, once its control stream delivered a SETTINGS frame.
    peer_settings: ?Settings = null,
    /// QPACK encoder uni-stream id (opened empty, zero dynamic table).
    qpack_encoder_stream_id: ?u64 = null,

    /// The established WebTransport session (one per connection), if any.
    session: ?Session = null,

    /// Per-incoming-uni-stream read state: tracks the parsed type prefix so we
    /// can demux control vs qpack vs WT uni streams across multiple reads.
    uni_state: std.AutoHashMapUnmanaged(u64, UniStreamState) = .empty,
    /// Per-incoming-bidi-stream buffered bytes (for assembling the CONNECT
    /// HEADERS frame which may span multiple STREAM frames).
    bidi_buf: std.AutoHashMapUnmanaged(u64, std.ArrayListUnmanaged(u8)) = .empty,
    /// Bidi streams already handled (CONNECT accepted or rejected) so we do not
    /// re-process them.
    bidi_handled: std.AutoHashMapUnmanaged(u64, void) = .empty,

    /// Pending events for the caller to drain via `nextEvent`.
    events: std.ArrayList(Event),
    /// Plain HTTP response paths need storage beyond the QPACK field section
    /// whose slices produced them. At most one response is handled per scanned
    /// peer bidi stream, so this remains bounded for the connection lifetime.
    event_paths: std.ArrayList([]u8) = .empty,

    /// Scratch read buffer for stream reads.
    read_scratch: [4096]u8 = undefined,

    const UniStreamState = struct {
        /// The varint stream-type prefix, once fully read. null until decoded.
        stream_type: ?u64 = null,
        /// For a WT uni stream: the session id that follows the type prefix.
        wt_session_id: ?u64 = null,
        /// Bytes buffered while we accumulate the (possibly fragmented) prefix.
        prefix_buf: std.ArrayListUnmanaged(u8) = .empty,
        /// For the control stream: bytes buffered to assemble the SETTINGS frame.
        body_buf: std.ArrayListUnmanaged(u8) = .empty,
        /// True once we have processed SETTINGS on a control stream.
        settings_done: bool = false,
    };

    pub fn init(allocator: Allocator, conn: *quic_conn.Conn) Http3Conn {
        return .{
            .allocator = allocator,
            .conn = conn,
            .role = conn.role,
            .local_settings = Settings.serverDefault(),
            .events = .empty,
        };
    }

    pub fn deinit(self: *Http3Conn) void {
        if (self.session) |*s| s.deinit();
        {
            var it = self.uni_state.iterator();
            while (it.next()) |e| {
                e.value_ptr.prefix_buf.deinit(self.allocator);
                e.value_ptr.body_buf.deinit(self.allocator);
            }
            self.uni_state.deinit(self.allocator);
        }
        {
            var it = self.bidi_buf.iterator();
            while (it.next()) |e| e.value_ptr.deinit(self.allocator);
            self.bidi_buf.deinit(self.allocator);
        }
        self.bidi_handled.deinit(self.allocator);
        self.events.deinit(self.allocator);
        for (self.event_paths.items) |path| self.allocator.free(path);
        self.event_paths.deinit(self.allocator);
        self.* = undefined;
    }

    /// Capture logical HTTP/3 and WebTransport state at a quiescent service
    /// boundary. The QUIC Conn and any event value already handed to a caller
    /// remain external; the caller must not retain borrowed event slices across
    /// the source/candidate ownership switch.
    pub fn captureServerSnapshot(self: *const Http3Conn, allocator: Allocator) SnapshotError!Http3Snapshot {
        if (self.role != .server or self.conn.role != .server or !self.conn.isEstablished())
            return error.InvalidSnapshot;
        const alpn = self.conn.selectedAlpn() orelse return error.InvalidSnapshot;
        if (!std.mem.eql(u8, alpn, "h3")) return error.InvalidSnapshot;
        var session: ?SessionSnapshot = null;
        errdefer if (session) |*item| item.deinit(allocator);
        if (self.session) |source| {
            const authority = try allocator.dupe(u8, source.authority);
            errdefer allocator.free(authority);
            const path = try allocator.dupe(u8, source.path);
            errdefer allocator.free(path);
            const streams = try allocator.dupe(WtStream, source.streams.items);
            session = .{
                .session_id = source.session_id.stream_id,
                .authority = authority,
                .path = path,
                .streams = streams,
                .closed = source.closed,
            };
        }

        if (self.uni_state.count() > snapshot_max_streams or self.bidi_buf.count() > snapshot_max_streams or
            self.bidi_handled.count() > snapshot_max_streams or self.events.items.len > snapshot_max_events)
            return error.SnapshotTooLarge;
        const uni = try allocator.alloc(UniSnapshot, self.uni_state.count());
        var uni_count: usize = 0;
        errdefer {
            for (uni[0..uni_count]) |*item| item.deinit(allocator);
            allocator.free(uni);
        }
        var uni_it = self.uni_state.iterator();
        while (uni_it.next()) |entry| {
            const state = entry.value_ptr.*;
            const prefix = try allocator.dupe(u8, state.prefix_buf.items);
            errdefer allocator.free(prefix);
            const body = try allocator.dupe(u8, state.body_buf.items);
            uni[uni_count] = .{
                .id = entry.key_ptr.*,
                .stream_type = state.stream_type,
                .wt_session_id = state.wt_session_id,
                .prefix = prefix,
                .body = body,
                .settings_done = state.settings_done,
            };
            uni_count += 1;
        }
        std.mem.sort(UniSnapshot, uni, {}, struct {
            fn less(_: void, a: UniSnapshot, b: UniSnapshot) bool {
                return a.id < b.id;
            }
        }.less);

        const bidi = try allocator.alloc(BidiSnapshot, self.bidi_buf.count());
        var bidi_count: usize = 0;
        errdefer {
            for (bidi[0..bidi_count]) |*item| item.deinit(allocator);
            allocator.free(bidi);
        }
        var bidi_it = self.bidi_buf.iterator();
        while (bidi_it.next()) |entry| {
            bidi[bidi_count] = .{ .id = entry.key_ptr.*, .bytes = try allocator.dupe(u8, entry.value_ptr.items) };
            bidi_count += 1;
        }
        std.mem.sort(BidiSnapshot, bidi, {}, struct {
            fn less(_: void, a: BidiSnapshot, b: BidiSnapshot) bool {
                return a.id < b.id;
            }
        }.less);

        const bidi_handled = try allocator.alloc(u64, self.bidi_handled.count());
        errdefer allocator.free(bidi_handled);
        var handled_it = self.bidi_handled.keyIterator();
        var handled_count: usize = 0;
        while (handled_it.next()) |id| {
            bidi_handled[handled_count] = id.*;
            handled_count += 1;
        }
        std.mem.sort(u64, bidi_handled, {}, std.sort.asc(u64));

        const events = try allocator.alloc(EventSnapshot, self.events.items.len);
        var event_count: usize = 0;
        errdefer {
            for (events[0..event_count]) |*event| event.deinit(allocator);
            allocator.free(events);
        }
        for (self.events.items, 0..) |event, i| {
            events[i] = switch (event) {
                .session_established => |item| .{ .session_established = item.session_id },
                .session_closed => |item| .{ .session_closed = item.session_id },
                .connect_rejected => |item| .{ .connect_rejected = .{
                    .stream_id = item.stream_id,
                    .status = try snapshotEventStatus(item.status),
                } },
                .http_responded => |item| .{ .http_responded = .{
                    .stream_id = item.stream_id,
                    .status = try snapshotEventStatus(item.status),
                    .path = try allocator.dupe(u8, item.path),
                } },
            };
            event_count += 1;
        }
        const snapshot: Http3Snapshot = .{
            .local_settings = self.local_settings,
            .control_stream_id = self.control_stream_id,
            .settings_sent = self.settings_sent,
            .peer_control_stream_id = self.peer_control_stream_id,
            .peer_settings = self.peer_settings,
            .qpack_encoder_stream_id = self.qpack_encoder_stream_id,
            .session = session,
            .uni = uni,
            .bidi = bidi,
            .bidi_handled = bidi_handled,
            .events = events,
        };
        try snapshot.validate();
        if (!snapshotConnJoin(self.conn, &snapshot)) return error.InvalidSnapshot;
        return snapshot;
    }

    /// Build a detached H3/WT driver around an already restored candidate Conn.
    /// The caller must keep `conn` at the same address through H3 deinit; no
    /// source pointer is retained. All allocations complete before publication.
    pub fn restoreServerSnapshot(allocator: Allocator, conn: *quic_conn.Conn, snapshot: *const Http3Snapshot) SnapshotError!Http3Conn {
        try snapshot.validate();
        if (conn.role != .server or !conn.isEstablished()) return error.ConfigMismatch;
        const alpn = conn.selectedAlpn() orelse return error.ConfigMismatch;
        if (!std.mem.eql(u8, alpn, "h3")) return error.ConfigMismatch;
        if (!snapshotConnJoin(conn, snapshot)) return error.ConfigMismatch;
        var result = Http3Conn.init(allocator, conn);
        errdefer result.deinit();
        result.local_settings = snapshot.local_settings;
        result.control_stream_id = snapshot.control_stream_id;
        result.settings_sent = snapshot.settings_sent;
        result.peer_control_stream_id = snapshot.peer_control_stream_id;
        result.peer_settings = snapshot.peer_settings;
        result.qpack_encoder_stream_id = snapshot.qpack_encoder_stream_id;
        if (snapshot.session) |part| {
            result.session = Session.init(allocator, part.session_id, part.authority, part.path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidSnapshot,
            };
            result.session.?.closed = part.closed;
            try result.session.?.streams.appendSlice(allocator, part.streams);
        }
        for (snapshot.uni) |part| {
            const gop = try result.uni_state.getOrPut(allocator, part.id);
            gop.value_ptr.* = .{
                .stream_type = part.stream_type,
                .wt_session_id = part.wt_session_id,
                .settings_done = part.settings_done,
            };
            try gop.value_ptr.prefix_buf.appendSlice(allocator, part.prefix);
            try gop.value_ptr.body_buf.appendSlice(allocator, part.body);
        }
        for (snapshot.bidi) |part| {
            const gop = try result.bidi_buf.getOrPut(allocator, part.id);
            gop.value_ptr.* = .empty;
            try gop.value_ptr.appendSlice(allocator, part.bytes);
        }
        for (snapshot.bidi_handled) |id| try result.bidi_handled.put(allocator, id, {});
        for (snapshot.events) |event| {
            const restored: Event = switch (event) {
                .session_established => |id| .{ .session_established = .{
                    .session_id = id,
                    .authority = result.session.?.authority,
                    .path = result.session.?.path,
                } },
                .session_closed => |id| .{ .session_closed = .{ .session_id = id } },
                .connect_rejected => |item| .{ .connect_rejected = .{
                    .stream_id = item.stream_id,
                    .status = snapshotStatusText(item.status),
                } },
                .http_responded => |item| blk: {
                    const path = try allocator.dupe(u8, item.path);
                    errdefer allocator.free(path);
                    try result.event_paths.append(allocator, path);
                    break :blk .{ .http_responded = .{
                        .stream_id = item.stream_id,
                        .status = snapshotStatusText(item.status),
                        .path = path,
                    } };
                },
            };
            try result.events.append(allocator, restored);
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // Public surface
    // -----------------------------------------------------------------------

    pub fn sessionEstablished(self: *const Http3Conn) bool {
        return self.session != null and !self.session.?.closed;
    }

    /// Whether the peer advertised the settings WebTransport-over-HTTP/3 requires
    /// (RFC 9220 §3.1). A plain HTTP/3 client omits them; this gates only the
    /// Extended CONNECT path, never ordinary requests.
    pub fn peerSupportsWebTransport(self: *const Http3Conn) bool {
        const s = self.peer_settings orelse return false;
        return s.supportsWebTransport();
    }

    /// Drain the next pending event, or null. Events borrow this struct's owned
    /// data; consume them before the next `service` call that may close them.
    pub fn nextEvent(self: *Http3Conn) ?Event {
        if (self.events.items.len == 0) return null;
        return self.events.orderedRemove(0);
    }

    /// Drive one service step: once the QUIC connection is established, open the
    /// control stream + QPACK encoder stream and send SETTINGS; then process any
    /// newly-readable peer control / bidi / WT streams and queued WT datagrams.
    ///
    /// The caller invokes this after every `conn.recvDatagram(...)` and before
    /// `conn.sendDatagrams(...)`.
    pub fn service(self: *Http3Conn) Error!void {
        if (!self.conn.isEstablished()) return;

        try self.ensureControlStream();
        try self.serviceUniStreams();
        try self.serviceBidiStreams();
    }

    /// Open the server control + QPACK encoder uni-streams and send our SETTINGS
    /// once the connection is established. Idempotent.
    fn ensureControlStream(self: *Http3Conn) Error!void {
        if (self.settings_sent) return;

        if (self.control_stream_id == null) {
            self.control_stream_id = self.conn.openUniStream() catch return error.NotReady;
        }
        if (self.qpack_encoder_stream_id == null) {
            self.qpack_encoder_stream_id = self.conn.openUniStream() catch return error.NotReady;
        }

        const ctl = self.control_stream_id.?;
        // Control stream type prefix (0x00) followed by a SETTINGS frame.
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(self.allocator, try webtransport.encodeVarint(UniStreamType.control, &vbuf));

        const settings_body = try encodeSettingsBody(self.allocator, self.local_settings);
        defer self.allocator.free(settings_body);
        try encodeFrame(self.allocator, &out, FrameType.settings, settings_body);
        self.conn.sendStream(ctl, out.items, false) catch return error.NotReady;

        // QPACK encoder stream: just the type prefix (0x02). With a zero-capacity
        // dynamic table it carries no instructions, but RFC 9204 §4.2 expects the
        // stream to exist.
        const enc = self.qpack_encoder_stream_id.?;
        var enc_prefix: [8]u8 = undefined;
        const enc_bytes = try webtransport.encodeVarint(UniStreamType.qpack_encoder, &enc_prefix);
        self.conn.sendStream(enc, enc_bytes, false) catch return error.NotReady;

        self.settings_sent = true;
    }

    // -----------------------------------------------------------------------
    // Incoming unidirectional streams: control / qpack / WebTransport-uni
    // -----------------------------------------------------------------------

    /// Probe the QUIC engine for received unidirectional streams the peer
    /// opened (client uni = 2,6,10,…) and process newly-readable bytes.
    fn serviceUniStreams(self: *Http3Conn) Error!void {
        // The peer (client) opens uni streams at ids 2,6,10,…  We scan a bounded
        // window of candidate ids; a stream only "exists" once the engine has
        // received a STREAM frame for it (getStream != null surfaced via a
        // non-zero read or a recorded final size).
        var ord: u64 = 0;
        const peer_uni_base: u64 = if (self.role == .server) 2 else 3;
        while (ord < max_scanned_streams) : (ord += 1) {
            const sid = peer_uni_base + ord * 4;
            if (!self.streamExists(sid)) continue;
            try self.serviceOneUniStream(sid);
        }
    }

    fn serviceOneUniStream(self: *Http3Conn, sid: u64) Error!void {
        const gop = try self.uni_state.getOrPut(self.allocator, sid);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const st = gop.value_ptr;

        // Drain all currently-readable bytes into the per-stream prefix/body.
        try self.drainStream(sid, st);

        // Decode the stream-type prefix once enough bytes are present.
        if (st.stream_type == null) {
            const dec = webtransport.decodeVarint(st.prefix_buf.items) catch return; // need more
            st.stream_type = dec.value;
            // Move the post-prefix bytes into body_buf.
            const rest = st.prefix_buf.items[dec.len..];
            try st.body_buf.appendSlice(self.allocator, rest);
            st.prefix_buf.clearRetainingCapacity();
        }

        const stype = st.stream_type orelse return;
        switch (stype) {
            UniStreamType.control => {
                if (self.peer_control_stream_id == null) self.peer_control_stream_id = sid;
                try self.processPeerControl(st);
            },
            UniStreamType.qpack_encoder, UniStreamType.qpack_decoder => {
                // Zero-capacity dynamic table: nothing to process. Drain & drop.
                st.body_buf.clearRetainingCapacity();
            },
            UniStreamType.webtransport => {
                try self.processWtUniStream(sid, st);
            },
            else => {
                // Unknown uni stream type: ignore its bytes (RFC 9114 §6.2 —
                // reserved/unknown stream types are abandoned).
                st.body_buf.clearRetainingCapacity();
            },
        }
    }

    /// Process the peer control stream: decode its SETTINGS frame (the first
    /// frame on the control stream per RFC 9114 §6.2.1) and record it. We do NOT
    /// reject a peer that lacks the WebTransport settings here: a plain HTTP/3
    /// client (curl, a browser doing a normal `fetch`/navigation) legitimately
    /// omits them and must still be served ordinary requests. The WebTransport
    /// requirement is enforced only when a client actually attempts the Extended
    /// CONNECT handshake (`handleConnect` → `isWebTransport`), where a missing
    /// capability is the relevant failure. See `peerSupportsWebTransport`.
    fn processPeerControl(self: *Http3Conn, st: *UniStreamState) Error!void {
        if (st.settings_done) {
            st.body_buf.clearRetainingCapacity();
            return;
        }
        var pos: usize = 0;
        const frame = (try findFrame(st.body_buf.items, &pos, FrameType.settings)) orelse return;
        const settings = try decodeSettingsBody(frame.payload);
        self.peer_settings = settings;
        h3Dbg("peer SETTINGS: enable_webtransport={} h3_datagram={} supportsWT={}", .{
            settings.enable_webtransport, settings.h3_datagram, settings.supportsWebTransport(),
        });
        st.settings_done = true;
        // Keep any trailing bytes after the SETTINGS frame for completeness.
        const remaining = st.body_buf.items[pos..];
        const kept = try self.allocator.dupe(u8, remaining);
        defer self.allocator.free(kept);
        st.body_buf.clearRetainingCapacity();
        try st.body_buf.appendSlice(self.allocator, kept);
    }

    /// Process a WebTransport unidirectional stream: read the session id varint
    /// that follows the 0x54 type prefix, register the WT stream on the session.
    fn processWtUniStream(self: *Http3Conn, sid: u64, st: *UniStreamState) Error!void {
        if (st.wt_session_id == null) {
            const dec = webtransport.decodeVarint(st.body_buf.items) catch return; // need more
            st.wt_session_id = dec.value;
            const rest = st.body_buf.items[dec.len..];
            const kept = try self.allocator.dupe(u8, rest);
            defer self.allocator.free(kept);
            st.body_buf.clearRetainingCapacity();
            try st.body_buf.appendSlice(self.allocator, kept);
            // Register the stream on the matching session.
            if (self.session) |*s| {
                if (s.session_id.stream_id == st.wt_session_id.?) {
                    try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = false });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Incoming bidirectional streams: the Extended CONNECT + WT bidi streams
    // -----------------------------------------------------------------------

    fn serviceBidiStreams(self: *Http3Conn) Error!void {
        // Peer (client) bidi streams are 0,4,8,…
        var ord: u64 = 0;
        const peer_bidi_base: u64 = if (self.role == .server) 0 else 1;
        while (ord < max_scanned_streams) : (ord += 1) {
            const sid = peer_bidi_base + ord * 4;
            if (self.bidi_handled.contains(sid)) continue;
            if (!self.streamExists(sid)) continue;
            try self.serviceOneBidiStream(sid);
        }
    }

    fn serviceOneBidiStream(self: *Http3Conn, sid: u64) Error!void {
        // Once a session exists, a new client bidi stream MAY be a WT bidi stream
        // (it begins with the 0x41 signal + session id). Detect that first.
        if (self.session != null) {
            if (try self.maybeWtBidiStream(sid)) return;
        }

        // Otherwise this is (expected to be) the Extended CONNECT request stream.
        const gop = try self.bidi_buf.getOrPut(self.allocator, sid);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const buf = gop.value_ptr;

        // Accumulate readable bytes.
        try self.drainStreamInto(sid, buf);

        // Try to decode a HEADERS frame.
        var pos: usize = 0;
        const headers_frame = (try findFrame(buf.items, &pos, FrameType.headers)) orelse return;
        h3Dbg("request on bidi stream {d}: HEADERS frame ({d} bytes)", .{ sid, headers_frame.payload.len });
        try self.handleConnect(sid, headers_frame.payload);

        // Done with this stream's request buffer.
        _ = self.bidi_handled.put(self.allocator, sid, {}) catch {};
        buf.deinit(self.allocator);
        _ = self.bidi_buf.remove(sid);
    }

    /// If `sid` begins with a WebTransport bidi stream signal (0x41 + session
    /// id), register it on the session and return true. Returns false (and leaves
    /// the stream untouched) if it does not look like a WT bidi stream yet.
    fn maybeWtBidiStream(self: *Http3Conn, sid: u64) Error!bool {
        // Peek a small prefix without consuming, by reading into scratch. The
        // engine's readStream consumes, so we buffer into bidi_buf and re-parse.
        const gop = try self.bidi_buf.getOrPut(self.allocator, sid);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const buf = gop.value_ptr;
        try self.drainStreamInto(sid, buf);
        if (buf.items.len == 0) return false;

        // The first byte 0x40 0x41 (two-byte varint for 0x41) signals WT bidi.
        const sig = webtransport.decodeVarint(buf.items) catch return false;
        if (sig.value != webtransport.StreamType.webtransport_bidirectional) return false;
        const after_sig = buf.items[sig.len..];
        const sess = webtransport.decodeVarint(after_sig) catch return false;
        // Register the WT bidi stream on the session.
        if (self.session) |*s| {
            if (s.session_id.stream_id == sess.value) {
                try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = true });
            }
        }
        // The remaining bytes (after signal+session id) are the WT payload; the
        // caller reads them via readWtStream, which strips the prefix. Mark the
        // stream handled here so we do not re-CONNECT it, but keep the buffer so
        // readWtStream can return the payload.
        _ = self.bidi_handled.put(self.allocator, sid, {}) catch {};
        // Store the payload offset by trimming the consumed prefix from the buf.
        const payload_off = sig.len + sess.len;
        const payload = buf.items[payload_off..];
        const kept = try self.allocator.dupe(u8, payload);
        defer self.allocator.free(kept);
        buf.clearRetainingCapacity();
        try buf.appendSlice(self.allocator, kept);
        return true;
    }

    /// Validate and answer a request on a client bidi stream. A WebTransport
    /// Extended CONNECT establishes the WT session and answers `:status=200`
    /// (stream stays open). Any other request (a plain `GET`/`POST`/… from
    /// curl/a browser, or a non-WT CONNECT) is answered as an ordinary HTTP/3
    /// response and the stream is finished — see `respondHttpRequest`.
    fn handleConnect(self: *Http3Conn, sid: u64, header_block: []const u8) Error!void {
        var decoded = try decodeConnectHeaders(self.allocator, header_block);
        defer decoded.section.deinit(self.allocator);
        const req = decoded.request;

        h3Dbg("CONNECT sid={d} method='{s}' protocol='{s}' scheme='{s}' path='{s}' isWT={} peerWT={}", .{
            sid,
            req.method,
            req.protocol,
            req.scheme,
            req.path,
            req.isWebTransport(),
            self.peerSupportsWebTransport(),
        });

        if (!req.isWebTransport()) {
            // Not a WebTransport CONNECT: serve it as a normal HTTP/3 request
            // (curl/browser GET probing the endpoint). This keeps the server
            // answerable by an independent HTTP/3 client without touching the
            // WebTransport path.
            try self.respondHttpRequest(sid, req);
            return;
        }
        // A WebTransport CONNECT requires the peer to have advertised the
        // WebTransport-over-HTTP/3 settings (RFC 9220 §3.1: Extended CONNECT +
        // H3 Datagrams + WebTransport). If it did not, reject this CONNECT (501
        // Not Implemented for the requested protocol) rather than failing the
        // whole connection — a plain client never reaches this branch.
        if (!self.peerSupportsWebTransport()) {
            try self.answerStatus(sid, "501");
            try self.events.append(self.allocator, .{ .connect_rejected = .{
                .stream_id = sid,
                .status = "501",
            } });
            return;
        }
        if (self.session != null) {
            try self.answerStatus(sid, "409");
            try self.events.append(self.allocator, .{ .connect_rejected = .{
                .stream_id = sid,
                .status = "409",
            } });
            return;
        }

        // Establish the session keyed by the CONNECT stream id.
        self.session = try Session.init(self.allocator, sid, req.authority, req.path);
        errdefer {
            if (self.session) |*s| s.deinit();
            self.session = null;
        }

        // Answer :status=200 (do NOT fin — the CONNECT stream stays open as the
        // session's control channel, RFC 9220 §4.2).
        try self.answerStatus(sid, "200");

        const s = &self.session.?;
        try self.events.append(self.allocator, .{ .session_established = .{
            .session_id = s.session_id.stream_id,
            .authority = s.authority,
            .path = s.path,
        } });
    }

    /// Write a `:status` HEADERS frame on the CONNECT/request stream. `fin` is
    /// false for a 200 (the stream stays open) and true for a rejection.
    fn answerStatus(self: *Http3Conn, sid: u64, status: []const u8) Error!void {
        const block = try encodeStatusHeaders(self.allocator, status);
        defer self.allocator.free(block);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        try encodeFrame(self.allocator, &out, FrameType.headers, block);
        const is_reject = !std.mem.eql(u8, status, "200");
        self.conn.sendStream(sid, out.items, is_reject) catch return error.NotReady;
    }

    /// Answer a plain (non-WebTransport) HTTP/3 request on bidi stream `sid` with
    /// a complete, real HTTP/3 response: a QPACK-encoded HEADERS frame
    /// (`:status`, `content-type: text/plain`, `content-length`) followed by a
    /// DATA frame carrying a short body, finishing the stream. `GET /` → 200 with
    /// a small body; any other path → 404 (still a valid, finished response). The
    /// stream is marked handled so we never re-CONNECT it, and an
    /// `http_responded` event is queued for the caller. No WebTransport state is
    /// touched.
    fn respondHttpRequest(self: *Http3Conn, sid: u64, req: ConnectRequest) Error!void {
        // A non-WebTransport CONNECT (i.e. CONNECT without :protocol=webtransport)
        // is not a method this endpoint serves as a content request: answer 405
        // Method Not Allowed, preserving the "rejected" semantics for the
        // WebTransport handshake path.
        if (std.mem.eql(u8, req.method, "CONNECT")) {
            try self.writeHttpResponse(sid, "405", http_method_not_allowed_body);
            try self.events.append(self.allocator, .{ .connect_rejected = .{
                .stream_id = sid,
                .status = "405",
            } });
            return;
        }

        // Split the request-target into its path and (optional) query string.
        // `:path` is e.g. "/big?n=262144"; routing keys off the path component
        // while the query carries the size parameter.
        const target = splitTarget(req.path);

        // Route `/big`: a large, deterministic, verifiable response body streamed
        // as one H3 DATA frame across MANY QUIC packets. This is the path that
        // exercises the real flow-control + congestion-window + ACK machinery;
        // see `writeLargeResponse`. The size comes from `?n=<bytes>` (clamped to
        // a sane maximum so a client cannot ask us to produce unbounded output).
        if (std.mem.eql(u8, target.path, "/big")) {
            const n = parseSizeQuery(target.query);
            h3Dbg("HTTP/3 {s} {s} on stream {d} → 200 (big, {d} bytes)", .{ req.method, req.path, sid, n });
            try self.writeLargeResponse(sid, n);
            try self.appendHttpResponded(sid, "200", req.path);
            return;
        }

        // Route: only the root path gets the 200 body; everything else is a
        // clean 404. We respond to any request method (GET/HEAD/POST/…) — curl's
        // probe uses GET; a body on a non-GET is harmless for this minimal
        // responder.
        const is_root = std.mem.eql(u8, target.path, "/") or target.path.len == 0;
        const status: []const u8 = if (is_root) "200" else "404";
        const body: []const u8 = if (is_root) http_ok_body else http_not_found_body;

        h3Dbg("HTTP/3 {s} {s} on stream {d} → {s}", .{ req.method, req.path, sid, status });
        try self.writeHttpResponse(sid, status, body);
        try self.appendHttpResponded(sid, status, req.path);
    }

    fn appendHttpResponded(self: *Http3Conn, sid: u64, status: []const u8, path: []const u8) Error!void {
        if (self.event_paths.items.len >= max_scanned_streams) return error.Malformed;
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.event_paths.append(self.allocator, owned);
        errdefer _ = self.event_paths.pop();
        try self.events.append(self.allocator, .{ .http_responded = .{
            .stream_id = sid,
            .status = status,
            .path = owned,
        } });
    }

    /// Encode + send a full HTTP/3 response (HEADERS + DATA + fin) on `sid`. The
    /// HEADERS field section is QPACK-encoded with the static table + literals
    /// (no dynamic table), matching the zero-capacity QPACK settings we
    /// advertise, so any conformant HTTP/3 client (curl/ngtcp2, browsers) decodes
    /// it. `content-length` is set from the body so the client knows the message
    /// is complete even before the FIN.
    fn writeHttpResponse(self: *Http3Conn, sid: u64, status: []const u8, body: []const u8) Error!void {
        // content-length as decimal text.
        var len_buf: [20]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch return error.Malformed;

        const hdrs = [_]qpack.Header{
            .{ .name = ":status", .value = status },
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "content-length", .value = len_str },
        };
        const block = try qpack.encodeFieldSection(self.allocator, &hdrs);
        defer self.allocator.free(block);

        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.allocator);
        try encodeFrame(self.allocator, &out, FrameType.headers, block);
        if (body.len > 0) try encodeFrame(self.allocator, &out, FrameType.data, body);

        // Finish the stream: a plain HTTP/3 response is a complete message.
        self.conn.sendStream(sid, out.items, true) catch return error.NotReady;
    }

    /// Answer `GET /big` with a large, deterministic body (`total` bytes) as a
    /// single HTTP/3 DATA frame, streamed to the QUIC layer in bounded chunks so
    /// we never materialise the whole body at once. The QUIC engine then carries
    /// it across many packets, paced by curl's MAX_DATA/MAX_STREAM_DATA credit
    /// and our own congestion window (RFC 9002) — exactly the machinery a tiny
    /// GET never touched.
    ///
    /// The body is a repeated, line-oriented pattern (`bigBodyByteAt`) that the
    /// client can verify byte-exactly: the byte at absolute offset `i` is fully
    /// determined by `i`, so a checksum/length assertion catches any reordering,
    /// duplication, or truncation in the flow-control/loss-recovery path.
    fn writeLargeResponse(self: *Http3Conn, sid: u64, total: usize) Error!void {
        // 1) HEADERS frame: 200 with the exact content-length so the client knows
        //    the full size up front (and flags truncation as a hard error).
        var len_buf: [20]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{total}) catch return error.Malformed;
        const hdrs = [_]qpack.Header{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "content-length", .value = len_str },
        };
        const block = try qpack.encodeFieldSection(self.allocator, &hdrs);
        defer self.allocator.free(block);

        var head: std.ArrayList(u8) = .empty;
        defer head.deinit(self.allocator);
        try encodeFrame(self.allocator, &head, FrameType.headers, block);
        // The DATA frame *header* (type + length varint); its payload (the body)
        // is streamed separately below so we never buffer `total` bytes here.
        try appendFrameHeader(self.allocator, &head, FrameType.data, total);
        // The HEADERS + DATA-frame-header go out first, NOT finishing the stream.
        self.conn.sendStream(sid, head.items, false) catch return error.NotReady;

        if (total == 0) {
            self.conn.sendStream(sid, &.{}, true) catch return error.NotReady;
            return;
        }

        // 2) Stream the deterministic body in bounded chunks. Each chunk is copied
        //    into the QUIC send queue (which dups it), so a fixed scratch buffer
        //    suffices — peak extra memory is one chunk, not the whole body. The
        //    QUIC layer segments these queued bytes into <= max_datagram packets
        //    and only puts a congestion-window's worth on the wire per flush,
        //    re-draining as ACKs free the window. Offsets are tracked by
        //    `sendStream`, so successive chunks append seamlessly.
        var sent: usize = 0;
        var chunk: [big_chunk_len]u8 = undefined;
        while (sent < total) {
            const n = @min(big_chunk_len, total - sent);
            fillBigBody(chunk[0..n], sent);
            const is_last = (sent + n == total);
            self.conn.sendStream(sid, chunk[0..n], is_last) catch return error.NotReady;
            sent += n;
        }
    }

    // -----------------------------------------------------------------------
    // WebTransport stream + datagram I/O (RFC 9220 §4, RFC 9297)
    // -----------------------------------------------------------------------

    /// Open a new WebTransport unidirectional stream for the session. Returns the
    /// underlying QUIC stream id. Writes the 0x54 signal + session id prefix.
    pub fn openWtUniStream(self: *Http3Conn) Error!u64 {
        const s = if (self.session) |*ss| ss else return error.NotReady;
        const sid = self.conn.openUniStream() catch return error.NotReady;
        const prefix = try webtransport.encodeStreamSignal(
            self.allocator,
            webtransport.StreamType.webtransport_unidirectional,
            s.session_id,
        );
        defer self.allocator.free(prefix);
        self.conn.sendStream(sid, prefix, false) catch return error.NotReady;
        try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = false });
        return sid;
    }

    /// Open a new WebTransport bidirectional stream for the session. Returns the
    /// underlying QUIC stream id. Writes the 0x41 signal + session id prefix.
    pub fn openWtBidiStream(self: *Http3Conn) Error!u64 {
        const s = if (self.session) |*ss| ss else return error.NotReady;
        const sid = self.conn.openStream() catch return error.NotReady;
        const prefix = try webtransport.encodeStreamSignal(
            self.allocator,
            webtransport.StreamType.webtransport_bidirectional,
            s.session_id,
        );
        defer self.allocator.free(prefix);
        self.conn.sendStream(sid, prefix, false) catch return error.NotReady;
        try s.streams.append(self.allocator, .{ .stream_id = sid, .is_bidirectional = true });
        return sid;
    }

    /// Write application bytes on an already-opened WT stream `sid` (the signal
    /// prefix has already been sent by `openWtUniStream`/`openWtBidiStream`).
    pub fn writeWtStream(self: *Http3Conn, sid: u64, bytes: []const u8, fin: bool) Error!void {
        self.conn.sendStream(sid, bytes, fin) catch return error.NotReady;
    }

    /// Read application bytes from a WT stream `sid` into `dst`. For a WT bidi
    /// stream that arrived from the peer, the leading signal+session prefix was
    /// already stripped into `bidi_buf`; return those buffered bytes first, then
    /// any freshly-readable QUIC bytes. Returns the number of bytes written.
    pub fn readWtStream(self: *Http3Conn, sid: u64, dst: []u8) usize {
        var written: usize = 0;
        // Drain any buffered (already-stripped) prefix payload from a peer WT
        // bidi stream first.
        if (self.bidi_buf.getPtr(sid)) |buf| {
            const n = @min(dst.len, buf.items.len);
            if (n > 0) {
                @memcpy(dst[0..n], buf.items[0..n]);
                // Compact.
                std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - n], buf.items[n..]);
                buf.shrinkRetainingCapacity(buf.items.len - n);
                written += n;
            }
        }
        // For a peer WT uni stream, the body_buf holds post-prefix bytes.
        if (self.uni_state.getPtr(sid)) |st| {
            if (written < dst.len and st.body_buf.items.len > 0) {
                const n = @min(dst.len - written, st.body_buf.items.len);
                @memcpy(dst[written .. written + n], st.body_buf.items[0..n]);
                std.mem.copyForwards(u8, st.body_buf.items[0 .. st.body_buf.items.len - n], st.body_buf.items[n..]);
                st.body_buf.shrinkRetainingCapacity(st.body_buf.items.len - n);
                written += n;
            }
        }
        if (written < dst.len) {
            written += self.conn.readStream(sid, dst[written..]);
        }
        return written;
    }

    /// Send a WebTransport datagram on the session: prefix the payload with the
    /// session's quarter-stream-id and hand it to the QUIC DATAGRAM path.
    pub fn sendWtDatagram(self: *Http3Conn, payload: []const u8) Error!void {
        const s = if (self.session) |*ss| ss else return error.NotReady;
        const framed = try webtransport.encodeSessionDatagram(self.allocator, s.session_id, payload);
        defer self.allocator.free(framed);
        self.conn.sendDatagram(framed) catch return error.NotReady;
    }

    /// Receive the next WebTransport datagram for the session, or null if none.
    /// The returned payload is an owned copy (free via the allocator). Datagrams
    /// whose quarter-stream-id does not match the session are dropped.
    pub fn recvWtDatagram(self: *Http3Conn) Error!?[]u8 {
        const s = if (self.session) |*ss| ss else return null;
        while (self.conn.recvDatagramPayload()) |raw| {
            defer self.allocator.free(raw);
            const decoded = webtransport.decodeSessionDatagram(raw) catch continue;
            if (decoded.session_id.stream_id != s.session_id.stream_id) continue;
            return try self.allocator.dupe(u8, decoded.payload);
        }
        return null;
    }

    /// Close the WebTransport session: emit a session_closed event and mark it.
    pub fn closeSession(self: *Http3Conn) Error!void {
        if (self.session) |*s| {
            if (!s.closed) {
                s.closed = true;
                try self.events.append(self.allocator, .{ .session_closed = .{
                    .session_id = s.session_id.stream_id,
                } });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Whether the QUIC engine has any received state for `sid` (a STREAM frame
    /// arrived). Used to decide which candidate stream ids to service.
    fn streamExists(self: *Http3Conn, sid: u64) bool {
        return self.conn.engine.getStream(sid) != null;
    }

    /// Drain all currently-readable bytes from QUIC stream `sid` into the
    /// per-uni-stream prefix/body buffers (prefix while the type is unknown,
    /// body afterwards).
    fn drainStream(self: *Http3Conn, sid: u64, st: *UniStreamState) Error!void {
        while (true) {
            const n = self.conn.readStream(sid, &self.read_scratch);
            if (n == 0) break;
            if (st.stream_type == null) {
                try st.prefix_buf.appendSlice(self.allocator, self.read_scratch[0..n]);
            } else {
                try st.body_buf.appendSlice(self.allocator, self.read_scratch[0..n]);
            }
        }
    }

    /// Drain all currently-readable bytes from QUIC stream `sid` into `buf`.
    fn drainStreamInto(self: *Http3Conn, sid: u64, buf: *std.ArrayListUnmanaged(u8)) Error!void {
        while (true) {
            const n = self.conn.readStream(sid, &self.read_scratch);
            if (n == 0) break;
            try buf.appendSlice(self.allocator, self.read_scratch[0..n]);
        }
    }
};

/// How many candidate stream ids per (initiator, directionality) class to scan
/// when probing the QUIC engine for newly-received streams. Bounded so a peer
/// cannot make us scan unboundedly; the control + qpack + a handful of WT
/// streams fit comfortably.
const max_scanned_streams: u64 = 64;

/// Body returned for `GET /` — a short, fixed text/plain payload proving the
/// QUIC + TLS-1.3-over-QUIC + HTTP/3 stack answered an independent client.
const http_ok_body: []const u8 = "onyx quic ok\n";
/// Body returned for any other path (a clean 404; still a valid response).
const http_not_found_body: []const u8 = "not found\n";
/// Body returned for a non-WebTransport CONNECT (405 Method Not Allowed).
const http_method_not_allowed_body: []const u8 = "method not allowed\n";

// --- large-response (`/big`) parameters ------------------------------------

/// How many body bytes each `sendStream` chunk carries while streaming a `/big`
/// response. Bounds the H3 layer's peak scratch to one chunk regardless of the
/// total size; the QUIC layer re-segments these into <= max_datagram packets.
const big_chunk_len: usize = 16 * 1024;
/// Default `/big` body size when `?n=` is absent (256 KiB — large enough to span
/// hundreds of packets and many congestion-window rounds).
const big_default_bytes: usize = 256 * 1024;
/// Hard ceiling on a `/big` body so a client cannot request unbounded output
/// (1 MiB). Bytes are generated on the fly, so this caps work, not memory.
const big_max_bytes: usize = 1024 * 1024;

/// The deterministic body byte at absolute offset `i`. The body is a stream of
/// fixed-width lines `"<offset-of-line-start padded>: onyx big body line\n"`
/// — but we don't need the textual form to verify it; what matters is that the
/// byte at offset `i` is a pure function of `i`, so the client can recompute the
/// full expected body (or its checksum/length) and catch any reordering,
/// duplication, or truncation introduced by the flow-control / loss-recovery
/// path. We use a cheap, well-mixed function of `i` that still yields printable
/// bytes (so a `curl ... | xxd` is human-readable during triage).
inline fn bigBodyByteAt(i: usize) u8 {
    // A 64-byte repeating window of printable ASCII; position within the window
    // is `i % 64`, the window's "phase" rotates every 64 bytes. This makes every
    // 64-byte aligned block distinct from its neighbours, so a dropped or
    // duplicated block is detectable, while keeping generation O(1) per byte.
    const col: u8 = @intCast(i % 64);
    const row: u8 = @intCast((i / 64) % 26);
    if (col == 63) return '\n';
    return 0x21 + ((col + row) % 0x5e); // printable range 0x21..0x7e
}

/// Fill `dst` with the deterministic body starting at absolute offset `start`.
fn fillBigBody(dst: []u8, start: usize) void {
    for (dst, 0..) |*b, k| b.* = bigBodyByteAt(start + k);
}

/// The path and (optional) query parts of an HTTP request-target. `query` is the
/// text after the first '?', or empty when there is none.
const RequestTarget = struct { path: []const u8, query: []const u8 };

/// Split an HTTP `:path` value into its path and query components on the first
/// '?'. Borrows `target`.
fn splitTarget(target: []const u8) RequestTarget {
    if (std.mem.indexOfScalar(u8, target, '?')) |q| {
        return .{ .path = target[0..q], .query = target[q + 1 ..] };
    }
    return .{ .path = target, .query = "" };
}

/// Parse the `n=<bytes>` parameter from a query string into a clamped body size.
/// Missing/invalid → the default; values above the ceiling are clamped down so a
/// client can never request unbounded output.
fn parseSizeQuery(query: []const u8) usize {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (std.mem.startsWith(u8, pair, "n=")) {
            const v = std.fmt.parseInt(usize, pair[2..], 10) catch return big_default_bytes;
            return @min(v, big_max_bytes);
        }
    }
    return big_default_bytes;
}

/// HTTP/3 interop tracing, gated on `ONYX_QUIC_DEBUG` (any non-empty value).
/// Off by default; only read by interop triage. Linux reads
/// /proc/self/environ; Windows reads the native process environment.
// 0 = unread, 1 = disabled, 2 = enabled; multiple reactor shards may log.
var h3_dbg_enabled: std.atomic.Value(u8) = .init(0);
fn h3Dbg(comptime fmt: []const u8, args: anytype) void {
    const cached = h3_dbg_enabled.load(.monotonic);
    const on = if (cached == 0) blk: {
        const e = h3EnvFlagSet("ONYX_QUIC_DEBUG");
        h3_dbg_enabled.store(if (e) 2 else 1, .monotonic);
        break :blk e;
    } else cached == 2;
    if (!on) return;
    std.debug.print("[h3] " ++ fmt ++ "\n", args);
}
fn h3EnvFlagSet(comptime name: []const u8) bool {
    if (comptime @import("builtin").os.tag == .windows) return @import("../substrate/platform.zig").windowsEnvFlagSet(name);
    if (@import("builtin").os.tag != .linux) return false;
    const linux = std.os.linux;
    const rc = linux.open("/proc/self/environ", .{ .ACCMODE = .RDONLY }, 0);
    const sfd: isize = @bitCast(rc);
    if (sfd < 0) return false;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var b: [16384]u8 = undefined;
    var total: usize = 0;
    while (total < b.len) {
        const n = linux.read(fd, b[total..].ptr, b.len - total);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        total += n;
    }
    var it = std.mem.splitScalar(u8, b[0..total], 0);
    while (it.next()) |record| {
        const eq = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (std.mem.eql(u8, record[0..eq], name)) return record.len > eq + 1;
    }
    return false;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;
const Ed25519 = std.crypto.sign.Ed25519;
const x509_selfsign = @import("x509_selfsign.zig");
const quic_transport_params = @import("quic_transport_params.zig");

// ---- pure codec tests (no QUIC) -------------------------------------------

test "h3 frame codec round-trips DATA/HEADERS/SETTINGS" {
    const alloc = testing.allocator;
    inline for (.{ FrameType.data, FrameType.headers, FrameType.settings }) |ft| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(alloc);
        const payload = "hello frame payload";
        try encodeFrame(alloc, &out, ft, payload);
        const d = try decodeFrame(out.items);
        try testing.expectEqual(@as(u64, ft), d.frame.frame_type);
        try testing.expectEqualStrings(payload, d.frame.payload);
        try testing.expectEqual(out.items.len, d.consumed);
    }
}

test "h3 frame codec skips unknown / GREASE frame types" {
    const alloc = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    // An unknown (GREASE) frame type 0x21, then a SETTINGS frame.
    try encodeFrame(alloc, &out, 0x21, "greasy");
    try encodeFrame(alloc, &out, 0x1f * 7 + 0x21, "more grease");
    try encodeFrame(alloc, &out, FrameType.settings, "SETTINGS-BODY");

    var pos: usize = 0;
    const found = (try findFrame(out.items, &pos, FrameType.settings)).?;
    try testing.expectEqual(@as(u64, FrameType.settings), found.frame_type);
    try testing.expectEqualStrings("SETTINGS-BODY", found.payload);
}

test "h3 frame codec rejects a length running past the buffer" {
    // type=0x04 (settings), length=0x10 (16) but only 2 payload bytes present.
    const bad = [_]u8{ 0x04, 0x10, 0xaa, 0xbb };
    try testing.expectError(error.Malformed, decodeFrame(&bad));
}

test "settings round-trip includes WT / datagram / connect-protocol settings" {
    const alloc = testing.allocator;
    const s = Settings.serverDefault();
    const body = try encodeSettingsBody(alloc, s);
    defer alloc.free(body);

    const decoded = try decodeSettingsBody(body);
    try testing.expect(decoded.enable_webtransport);
    try testing.expect(decoded.h3_datagram);
    try testing.expect(decoded.enable_connect_protocol);
    try testing.expectEqual(@as(u64, 0), decoded.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), decoded.qpack_blocked_streams);
    try testing.expect(decoded.supportsWebTransport());
}

test "settings decode ignores unknown settings and reports missing WT support" {
    const alloc = testing.allocator;
    // Only QPACK settings — no WebTransport / datagram / connect-protocol.
    const s = Settings{};
    const body = try encodeSettingsBody(alloc, s);
    defer alloc.free(body);
    const decoded = try decodeSettingsBody(body);
    try testing.expect(!decoded.supportsWebTransport());

    // A SETTINGS body with an unknown identifier is tolerated.
    var custom: std.ArrayList(u8) = .empty;
    defer custom.deinit(alloc);
    var vbuf: [8]u8 = undefined;
    try custom.appendSlice(alloc, try webtransport.encodeVarint(0xdead, &vbuf)); // unknown id
    try custom.appendSlice(alloc, try webtransport.encodeVarint(0x1234, &vbuf)); // value
    try custom.appendSlice(alloc, try webtransport.encodeVarint(Setting.enable_webtransport, &vbuf));
    try custom.appendSlice(alloc, try webtransport.encodeVarint(1, &vbuf));
    const d2 = try decodeSettingsBody(custom.items);
    try testing.expect(d2.enable_webtransport);
}

test "supportsWebTransport accepts an HTTP/3 peer that omits ENABLE_CONNECT_PROTOCOL" {
    // RFC 9220 §3.1: in HTTP/3, WebTransport requires only
    // SETTINGS_ENABLE_WEBTRANSPORT + SETTINGS_H3_DATAGRAM. The HTTP/2-only
    // SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) is NOT sent by H3 peers (Chrome
    // 149 omits it), so its absence MUST NOT reject the session. This mirrors
    // exactly what a real browser's H3 SETTINGS carry.
    const browser_like = Settings{
        .enable_webtransport = true,
        .h3_datagram = true,
        .enable_connect_protocol = false, // browser omits 0x08 in H3
    };
    try testing.expect(browser_like.supportsWebTransport());

    // But datagrams are still mandatory (RFC 9297): drop them and WT is off.
    const no_dgram = Settings{ .enable_webtransport = true, .h3_datagram = false };
    try testing.expect(!no_dgram.supportsWebTransport());

    // As is WebTransport itself.
    const no_wt = Settings{ .enable_webtransport = false, .h3_datagram = true };
    try testing.expect(!no_wt.supportsWebTransport());
}

test "settings decode rejects a truncated value varint" {
    // id present (0x06), but the value varint declares 2 bytes and only 1 is
    // present.
    const bad = [_]u8{ 0x06, 0x40 };
    try testing.expectError(error.Malformed, decodeSettingsBody(&bad));
}

test "qpack: decodes CONNECT pseudo-headers from the static table + literals" {
    const alloc = testing.allocator;
    const block = try encodeConnectHeaders(alloc, "irc.example", "/wt");
    defer alloc.free(block);

    var decoded = try decodeConnectHeaders(alloc, block);
    defer decoded.section.deinit(alloc);
    const req = decoded.request;
    try testing.expectEqualStrings("CONNECT", req.method);
    try testing.expectEqualStrings("webtransport", req.protocol);
    try testing.expectEqualStrings("https", req.scheme);
    try testing.expectEqualStrings("irc.example", req.authority);
    try testing.expectEqualStrings("/wt", req.path);
    try testing.expect(req.isWebTransport());
}

test "qpack: encodes :status=200 decodable with the static table" {
    const alloc = testing.allocator;
    const block = try encodeStatusHeaders(alloc, "200");
    defer alloc.free(block);
    var section = try qpack.decodeFieldSectionAlloc(alloc, block);
    defer section.deinit(alloc);
    try testing.expectEqual(@as(usize, 1), section.headers.len);
    try testing.expectEqualStrings(":status", section.headers[0].name);
    try testing.expectEqualStrings("200", section.headers[0].value);
}

test "connect request without :protocol=webtransport is not WebTransport" {
    const alloc = testing.allocator;
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "irc.example" },
        // no :protocol
    };
    const block = try qpack.encodeFieldSection(alloc, &hdrs);
    defer alloc.free(block);
    var decoded = try decodeConnectHeaders(alloc, block);
    defer decoded.section.deinit(alloc);
    try testing.expect(!decoded.request.isWebTransport());
}

// ---- loopback establish-session + WT datagram/stream tests ----------------

const test_client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
const test_server_cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
const test_initial_dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
const test_alpn = [_][]const u8{"h3"};

fn mintCert(out: *[1024]u8, kp: Ed25519.KeyPair) ![]const u8 {
    return x509_selfsign.buildSelfSigned(out, .{
        .common_name = "wt.test",
        .not_before = 1_704_067_200,
        .not_after = 4_102_444_800,
        .serial = &.{ 0x51, 0x99 },
        .key_pair = kp,
        .dns_names = &.{"wt.test"},
        .is_ca = true,
    });
}

const server_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_server_cid,
    .max_idle_timeout = 30_000,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};
const client_params: quic_transport_params.TransportParameters = .{
    .initial_source_connection_id = &test_client_cid,
    .initial_max_data = 1 << 20,
    .initial_max_stream_data_bidi_local = 256 * 1024,
    .initial_max_stream_data_bidi_remote = 256 * 1024,
    .initial_max_streams_bidi = 100,
};

const WtLoopback = struct {
    kp: Ed25519.KeyPair,
    cert_buf: [1024]u8,
    cert: []const u8,
    cert_chain: [1][]const u8,
    server: quic_conn.Conn,
    client: quic_conn.Conn,

    fn init(alloc: Allocator) !*WtLoopback {
        const lb = try alloc.create(WtLoopback);
        errdefer alloc.destroy(lb);
        lb.kp = try Ed25519.KeyPair.generateDeterministic(@as([Ed25519.KeyPair.seed_length]u8, @splat(0x37)));
        lb.cert = try mintCert(&lb.cert_buf, lb.kp);
        lb.cert_chain = .{lb.cert};

        lb.server = try quic_conn.Conn.initServer(alloc, .{
            .cert_chain = &lb.cert_chain,
            .signing_key = .{ .ed25519 = lb.kp },
            .alpn_protocols = &test_alpn,
            .transport_params = server_params,
            .local_cid = &test_server_cid,
            .x25519_seed = @as([32]u8, @splat(0x21)),
            .server_random = @as([32]u8, @splat(0x55)),
        });
        errdefer lb.server.deinit();
        lb.client = try quic_conn.Conn.initClient(alloc, .{
            .alpn_protocols = &test_alpn,
            .transport_params = client_params,
            .local_cid = &test_client_cid,
            .initial_dcid = &test_initial_dcid,
            .x25519_seed = @as([32]u8, @splat(0x42)),
            .client_random = @as([32]u8, @splat(0x11)),
        });
        return lb;
    }

    fn deinit(self: *WtLoopback, alloc: Allocator) void {
        self.server.deinit();
        self.client.deinit();
        alloc.destroy(self);
    }
};

fn pump(alloc: Allocator, from: *quic_conn.Conn, to: *quic_conn.Conn) !void {
    var out: std.ArrayList(quic_conn.OutDatagram) = .empty;
    defer {
        for (out.items) |d| alloc.free(d.bytes);
        out.deinit(alloc);
    }
    _ = try from.sendDatagrams(&out);
    for (out.items) |d| try to.recvDatagram(d.bytes);
}

fn driveHandshake(alloc: Allocator, lb: *WtLoopback) !void {
    var rounds: usize = 0;
    while (rounds < 12) : (rounds += 1) {
        try pump(alloc, &lb.client, &lb.server);
        try pump(alloc, &lb.server, &lb.client);
        if (lb.client.isEstablished() and lb.server.isEstablished()) return;
    }
    return error.HandshakeDidNotComplete;
}

/// A minimal WebTransport *client* helper for the loopback test: it sends the
/// control stream + SETTINGS and the Extended CONNECT, then exchanges WT
/// streams/datagrams. It reuses the same codecs as the server.
const WtClient = struct {
    alloc: Allocator,
    conn: *quic_conn.Conn,
    control_stream: ?u64 = null,
    connect_stream: ?u64 = null,
    session_id: ?SessionId = null,
    status_ok: bool = false,
    connect_buf: std.ArrayListUnmanaged(u8) = .empty,

    fn deinit(self: *WtClient) void {
        self.connect_buf.deinit(self.alloc);
    }

    fn sendControlAndConnect(self: *WtClient, authority: []const u8, path: []const u8) !void {
        // Control stream + SETTINGS.
        const ctl = try self.conn.openUniStream();
        self.control_stream = ctl;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(self.alloc);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(self.alloc, try webtransport.encodeVarint(UniStreamType.control, &vbuf));
        const body = try encodeSettingsBody(self.alloc, Settings.serverDefault());
        defer self.alloc.free(body);
        try encodeFrame(self.alloc, &out, FrameType.settings, body);
        try self.conn.sendStream(ctl, out.items, false);

        // Extended CONNECT on a fresh bidi stream.
        const cs = try self.conn.openStream();
        self.connect_stream = cs;
        self.session_id = try SessionId.initClientBidirectional(cs);
        const block = try encodeConnectHeaders(self.alloc, authority, path);
        defer self.alloc.free(block);
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(self.alloc);
        try encodeFrame(self.alloc, &req, FrameType.headers, block);
        try self.conn.sendStream(cs, req.items, false);
    }

    /// Read the CONNECT response on the connect stream; set status_ok on 200.
    fn pollConnectResponse(self: *WtClient) !void {
        const cs = self.connect_stream orelse return;
        var scratch: [2048]u8 = undefined;
        while (true) {
            const n = self.conn.readStream(cs, &scratch);
            if (n == 0) break;
            try self.connect_buf.appendSlice(self.alloc, scratch[0..n]);
        }
        var pos: usize = 0;
        const frame = (try findFrame(self.connect_buf.items, &pos, FrameType.headers)) orelse return;
        var section = try qpack.decodeFieldSectionAlloc(self.alloc, frame.payload);
        defer section.deinit(self.alloc);
        for (section.headers) |h| {
            if (std.mem.eql(u8, h.name, ":status") and std.mem.eql(u8, h.value, "200")) {
                self.status_ok = true;
            }
        }
    }

    fn sendWtDatagram(self: *WtClient, payload: []const u8) !void {
        const sid = self.session_id.?;
        const framed = try webtransport.encodeSessionDatagram(self.alloc, sid, payload);
        defer self.alloc.free(framed);
        try self.conn.sendDatagram(framed);
    }

    fn recvWtDatagram(self: *WtClient) !?[]u8 {
        const sid = self.session_id.?;
        while (self.conn.recvDatagramPayload()) |raw| {
            defer self.alloc.free(raw);
            const decoded = webtransport.decodeSessionDatagram(raw) catch continue;
            if (decoded.session_id.stream_id != sid.stream_id) continue;
            return try self.alloc.dupe(u8, decoded.payload);
        }
        return null;
    }

    /// Open a WT uni stream and write `payload` after the signal prefix.
    fn openWtUniAndWrite(self: *WtClient, payload: []const u8) !u64 {
        const sid = try self.conn.openUniStream();
        const prefix = try webtransport.encodeStreamSignal(
            self.alloc,
            webtransport.StreamType.webtransport_unidirectional,
            self.session_id.?,
        );
        defer self.alloc.free(prefix);
        try self.conn.sendStream(sid, prefix, false);
        try self.conn.sendStream(sid, payload, false);
        return sid;
    }
};

fn pumpBoth(alloc: Allocator, lb: *WtLoopback) !void {
    try pump(alloc, &lb.client, &lb.server);
    try pump(alloc, &lb.server, &lb.client);
}

test "http3 snapshot restores active WebTransport session streams settings and pending events" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);
    var source = Http3Conn.init(alloc, &lb.server);
    defer source.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();
    try source.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try source.service();
        try client.pollConnectResponse();
        if (source.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(source.sessionEstablished());
    _ = try client.openWtUniAndWrite("stream-payload");
    try pump(alloc, &lb.client, &lb.server);
    try source.service();
    try testing.expect(source.uni_state.count() > 0);
    try testing.expect(source.session.?.streams.items.len > 0);

    var snapshot = try source.captureServerSnapshot(alloc);
    defer snapshot.deinit(alloc);
    var restored = try Http3Conn.restoreServerSnapshot(alloc, &lb.server, &snapshot);
    defer restored.deinit();
    var again = try restored.captureServerSnapshot(alloc);
    defer again.deinit(alloc);
    try testing.expectEqualDeep(snapshot, again);
    const control_id = snapshot.control_stream_id;
    snapshot.control_stream_id = 259;
    try snapshot.validate();
    try testing.expectError(error.ConfigMismatch, Http3Conn.restoreServerSnapshot(alloc, &lb.server, &snapshot));
    snapshot.control_stream_id = control_id;
    const peer_settings = snapshot.peer_settings;
    snapshot.peer_settings.?.enable_webtransport = false;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.peer_settings = peer_settings;
    try testing.expect(restored.sessionEstablished());
    const ev = restored.nextEvent().?;
    try testing.expectEqual(@as(std.meta.Tag(Event), .session_established), std.meta.activeTag(ev));
    try testing.expectEqualStrings("irc.example", ev.session_established.authority);
    try testing.expectEqualStrings("/wt", ev.session_established.path);
}

test "http3 snapshot owns HTTP response event path and rejects tampering" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);
    var source = Http3Conn.init(alloc, &lb.server);
    defer source.deinit();
    var path = [_]u8{ '/', 'p', 'r', 'o', 'b', 'e' };
    try source.appendHttpResponded(0, "200", &path);
    path[1] = 'X';
    var snapshot = try source.captureServerSnapshot(alloc);
    defer snapshot.deinit(alloc);
    try testing.expectEqualStrings("/probe", snapshot.events[0].http_responded.path);
    snapshot.settings_sent = true;
    try testing.expectError(error.InvalidSnapshot, snapshot.validate());
    snapshot.settings_sent = false;
    var restored = try Http3Conn.restoreServerSnapshot(alloc, &lb.server, &snapshot);
    defer restored.deinit();
    const ev = restored.nextEvent().?;
    try testing.expectEqualStrings("/probe", ev.http_responded.path);
}

test "http3 snapshot capture and restore allocation failures leave source intact" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);
    var source = Http3Conn.init(alloc, &lb.server);
    defer source.deinit();
    try source.service();
    try source.appendHttpResponded(0, "200", "/probe");
    const CaptureSweep = struct {
        fn run(failing: Allocator, h3: *const Http3Conn) !void {
            var snapshot = try h3.captureServerSnapshot(failing);
            defer snapshot.deinit(failing);
            try snapshot.validate();
        }
    };
    try testing.checkAllAllocationFailures(alloc, CaptureSweep.run, .{&source});
    var snapshot = try source.captureServerSnapshot(alloc);
    defer snapshot.deinit(alloc);
    const RestoreSweep = struct {
        fn run(failing: Allocator, conn: *quic_conn.Conn, carry: *const Http3Snapshot) !void {
            var restored = try Http3Conn.restoreServerSnapshot(failing, conn, carry);
            defer restored.deinit();
        }
    };
    try testing.checkAllAllocationFailures(alloc, RestoreSweep.run, .{ &lb.server, &snapshot });
    try testing.expect(source.conn == &lb.server);
    try testing.expectEqualStrings("/probe", source.events.items[0].http_responded.path);
}

test "wt loopback establishes a WebTransport session over Extended CONNECT" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    // Server opens its control stream + SETTINGS.
    try server_h3.service();
    // Client sends control + SETTINGS + Extended CONNECT.
    try client.sendControlAndConnect("irc.example", "/wt");

    // Drive a few round trips: client→server delivers CONNECT, server replies.
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }

    try testing.expect(server_h3.sessionEstablished());
    try testing.expect(client.status_ok);

    // The session surfaces authority/path.
    var saw_event = false;
    while (server_h3.nextEvent()) |ev| {
        switch (ev) {
            .session_established => |se| {
                try testing.expectEqualStrings("irc.example", se.authority);
                try testing.expectEqualStrings("/wt", se.path);
                saw_event = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_event);
    // The session id is the CONNECT stream id (the client's first bidi stream).
    try testing.expectEqual(client.connect_stream.?, server_h3.session.?.session_id.stream_id);
}

test "wt loopback exchanges a datagram byte-exact in both directions" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    try server_h3.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(server_h3.sessionEstablished());
    while (server_h3.nextEvent()) |_| {}

    // client → server datagram.
    try client.sendWtDatagram("voice-frame-c2s");
    try pump(alloc, &lb.client, &lb.server);
    const got_s = (try server_h3.recvWtDatagram()).?;
    defer alloc.free(got_s);
    try testing.expectEqualStrings("voice-frame-c2s", got_s);

    // server → client datagram.
    try server_h3.sendWtDatagram("voice-frame-s2c");
    try pump(alloc, &lb.server, &lb.client);
    const got_c = (try client.recvWtDatagram()).?;
    defer alloc.free(got_c);
    try testing.expectEqualStrings("voice-frame-s2c", got_c);
}

test "wt loopback exchanges a unidirectional stream byte-exact (client → server)" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    try server_h3.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(server_h3.sessionEstablished());
    while (server_h3.nextEvent()) |_| {}

    // Client opens a WT uni stream and writes a payload after the signal prefix.
    const wt_msg = "WEBTRANSPORT-UNI-STREAM-PAYLOAD :: byte exact";
    const wsid = try client.openWtUniAndWrite(wt_msg);
    try pump(alloc, &lb.client, &lb.server);
    try server_h3.service();

    // The server registered the WT uni stream on the session.
    var found = false;
    var stream_id: u64 = 0;
    for (server_h3.session.?.streams.items) |s| {
        if (!s.is_bidirectional and s.stream_id == wsid) {
            found = true;
            stream_id = s.stream_id;
        }
    }
    try testing.expect(found);

    // Read the payload (prefix already stripped by the service step).
    var rbuf: [256]u8 = undefined;
    var total: usize = 0;
    var tries: usize = 0;
    while (tries < 4 and total < wt_msg.len) : (tries += 1) {
        try server_h3.service();
        total += server_h3.readWtStream(stream_id, rbuf[total..]);
    }
    try testing.expectEqualSlices(u8, wt_msg, rbuf[0..total]);
}

test "wt loopback exchanges a bidirectional stream byte-exact (client → server)" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    var client = WtClient{ .alloc = alloc, .conn = &lb.client };
    defer client.deinit();

    try server_h3.service();
    try client.sendControlAndConnect("irc.example", "/wt");
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        try client.pollConnectResponse();
        if (server_h3.sessionEstablished() and client.status_ok) break;
    }
    try testing.expect(server_h3.sessionEstablished());
    while (server_h3.nextEvent()) |_| {}

    // Client opens a WT bidi stream: signal 0x41 + session id, then payload.
    const bsid = try lb.client.openStream();
    const prefix = try webtransport.encodeStreamSignal(
        alloc,
        webtransport.StreamType.webtransport_bidirectional,
        client.session_id.?,
    );
    defer alloc.free(prefix);
    try lb.client.sendStream(bsid, prefix, false);
    const bmsg = "WT-BIDI :: hello over a bidirectional WebTransport stream";
    try lb.client.sendStream(bsid, bmsg, false);

    var rbuf: [256]u8 = undefined;
    var total: usize = 0;
    var tries: usize = 0;
    while (tries < 6 and total < bmsg.len) : (tries += 1) {
        try pump(alloc, &lb.client, &lb.server);
        try server_h3.service();
        total += server_h3.readWtStream(bsid, rbuf[total..]);
    }
    try testing.expectEqualSlices(u8, bmsg, rbuf[0..total]);

    // The WT bidi stream is registered on the session.
    var found = false;
    for (server_h3.session.?.streams.items) |s| {
        if (s.is_bidirectional and s.stream_id == bsid) found = true;
    }
    try testing.expect(found);
}

test "wt loopback rejects a CONNECT without :protocol=webtransport" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();
    try server_h3.service();

    // Client control stream + SETTINGS.
    const ctl = try lb.client.openUniStream();
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(alloc);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(alloc, try webtransport.encodeVarint(UniStreamType.control, &vbuf));
        const body = try encodeSettingsBody(alloc, Settings.serverDefault());
        defer alloc.free(body);
        try encodeFrame(alloc, &out, FrameType.settings, body);
        try lb.client.sendStream(ctl, out.items, false);
    }

    // A plain CONNECT (no :protocol) on a bidi stream.
    const cs = try lb.client.openStream();
    {
        const hdrs = [_]qpack.Header{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "irc.example" },
        };
        const block = try qpack.encodeFieldSection(alloc, &hdrs);
        defer alloc.free(block);
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(alloc);
        try encodeFrame(alloc, &req, FrameType.headers, block);
        try lb.client.sendStream(cs, req.items, false);
    }

    var round: usize = 0;
    var rejected = false;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        while (server_h3.nextEvent()) |ev| {
            switch (ev) {
                .connect_rejected => |cr| {
                    // A non-WebTransport CONNECT is answered 405 (not a content
                    // request); the WT session is still not established.
                    try testing.expectEqualStrings("405", cr.status);
                    rejected = true;
                },
                else => {},
            }
        }
        if (rejected) break;
    }
    try testing.expect(rejected);
    // No session was established.
    try testing.expect(!server_h3.sessionEstablished());
}

test "wt malformed HEADERS block on the CONNECT stream errors without panicking" {
    const alloc = testing.allocator;
    // A HEADERS frame whose QPACK body is a bare dynamic-table reference (0x80),
    // which the static-only decoder rejects. Drive it through decodeConnectHeaders.
    const bad_block = [_]u8{ 0x00, 0x00, 0x80 }; // RIC=0, Base=0, indexed dynamic
    try testing.expectError(error.InvalidRepresentation, decodeConnectHeaders(alloc, &bad_block));
}

// ---- plain HTTP/3 GET responder (curl / browser probe) --------------------

/// Encode a plain HTTP/3 request HEADERS block (no WebTransport :protocol),
/// QPACK static-table + literals — the exact shape an ordinary H3 client emits.
fn encodeGetHeaders(alloc: Allocator, method: []const u8, path: []const u8) ![]u8 {
    const hdrs = [_]qpack.Header{
        .{ .name = ":method", .value = method },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "irc.example" },
        .{ .name = ":path", .value = path },
    };
    return qpack.encodeFieldSection(alloc, &hdrs);
}

/// Drive a handshake + server SETTINGS + client control SETTINGS, then send one
/// plain HTTP/3 request and return the parsed (status, body) the server sent.
/// Asserts the response is a single HEADERS frame followed by a DATA frame and
/// that the stream was finished by the server.
const GetResult = struct { status: [8]u8, status_len: usize, body: std.ArrayListUnmanaged(u8), finished: bool };

fn runPlainRequest(alloc: Allocator, lb: *WtLoopback, server_h3: *Http3Conn, method: []const u8, path: []const u8) !GetResult {
    // Server opens its control stream + SETTINGS.
    try server_h3.service();

    // Client control stream + SETTINGS (an H3 client MUST send these first).
    const ctl = try lb.client.openUniStream();
    {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(alloc);
        var vbuf: [8]u8 = undefined;
        try out.appendSlice(alloc, try webtransport.encodeVarint(UniStreamType.control, &vbuf));
        const body = try encodeSettingsBody(alloc, Settings.serverDefault());
        defer alloc.free(body);
        try encodeFrame(alloc, &out, FrameType.settings, body);
        try lb.client.sendStream(ctl, out.items, false);
    }

    // Plain request HEADERS on a fresh bidi stream, fin (request complete).
    const cs = try lb.client.openStream();
    {
        const block = try encodeGetHeaders(alloc, method, path);
        defer alloc.free(block);
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(alloc);
        try encodeFrame(alloc, &req, FrameType.headers, block);
        try lb.client.sendStream(cs, req.items, true);
    }

    // Drive round trips: deliver the request, let the server answer, collect.
    var resp: std.ArrayListUnmanaged(u8) = .empty;
    errdefer resp.deinit(alloc);
    var got_response = false;
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        try pumpBoth(alloc, lb);
        try server_h3.service();
        var scratch: [2048]u8 = undefined;
        while (true) {
            const n = lb.client.readStream(cs, &scratch);
            if (n == 0) break;
            try resp.appendSlice(alloc, scratch[0..n]);
            got_response = true;
        }
        if (got_response and lb.client.streamFinished(cs)) break;
    }

    // Parse: HEADERS frame (status) then DATA frame (body).
    var result = GetResult{ .status = undefined, .status_len = 0, .body = .empty, .finished = lb.client.streamFinished(cs) };
    errdefer result.body.deinit(alloc);

    var pos: usize = 0;
    const hf = (try findFrame(resp.items, &pos, FrameType.headers)) orelse return error.NoHeaders;
    var section = try qpack.decodeFieldSectionAlloc(alloc, hf.payload);
    defer section.deinit(alloc);
    for (section.headers) |h| {
        if (std.mem.eql(u8, h.name, ":status")) {
            @memcpy(result.status[0..h.value.len], h.value);
            result.status_len = h.value.len;
        }
    }
    // DATA frame (resume scanning after the HEADERS frame).
    if (try findFrame(resp.items, &pos, FrameType.data)) |df| {
        try result.body.appendSlice(alloc, df.payload);
    }
    resp.deinit(alloc);
    return result;
}

test "h3 plain GET / is answered 200 text/plain with a body, stream finished" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();

    var result = try runPlainRequest(alloc, lb, &server_h3, "GET", "/");
    defer result.body.deinit(alloc);

    try testing.expectEqualStrings("200", result.status[0..result.status_len]);
    try testing.expectEqualStrings("onyx quic ok\n", result.body.items);
    try testing.expect(result.finished);

    // An http_responded event was queued (the WT session was NOT established).
    var saw = false;
    while (server_h3.nextEvent()) |ev| switch (ev) {
        .http_responded => |r| {
            try testing.expectEqualStrings("200", r.status);
            try testing.expectEqualStrings("/", r.path);
            saw = true;
        },
        else => {},
    };
    try testing.expect(saw);
    try testing.expect(!server_h3.sessionEstablished());
}

test "h3 plain GET of an unknown path is answered 404" {
    const alloc = testing.allocator;
    const lb = try WtLoopback.init(alloc);
    defer lb.deinit(alloc);
    try driveHandshake(alloc, lb);

    var server_h3 = Http3Conn.init(alloc, &lb.server);
    defer server_h3.deinit();

    var result = try runPlainRequest(alloc, lb, &server_h3, "GET", "/nope");
    defer result.body.deinit(alloc);

    try testing.expectEqualStrings("404", result.status[0..result.status_len]);
    try testing.expectEqualStrings("not found\n", result.body.items);
    try testing.expect(result.finished);
}
