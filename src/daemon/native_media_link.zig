// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native media link — the live-transport glue for the native Undertow SFU leg.
//!
//! `NativeMediaPlane` (substrate) makes the pure forwarding *decision* in terms
//! of `ParticipantId`s; live datagrams instead carry a cadence_frame `stream_id`
//! and arrive from / depart to a `TransportAddress`. This module is the binding
//! between the two: it owns the per-call registry mapping
//!
//!     stream_id  ->  source ParticipantId   (who is publishing this frame)
//!     ParticipantId  ->  TransportAddress    (where to send a recipient's copy)
//!
//! so a raw inbound native datagram can be turned into "forward these exact bytes
//! to this set of addresses". It NEVER touches the payload — the SFU forwards the
//! opaque, already-encoded cadence frame verbatim (no encode/decode/transcode).
//!
//! Layer selection: the container's `band_id` encodes the spatial layer by the
//! convention `band_id = MEDIA_BAND_FLOOR + spatial` (the publisher chooses the
//! band per simulcast layer). Temporal SVC selection over native frames is not
//! yet carried in the container header, so the link forwards on spatial ceiling +
//! keyframe only (temporal 0); finer temporal dropping is deferred to when the
//! container gains a layer-marking byte. Keyframes at/below a receiver's spatial
//! ceiling are always delivered.
//!
//! Transport-neutral: it commits to no socket. The daemon's media pump calls
//! `inbound` and sends the opaque datagram to each returned address.
const std = @import("std");
const native_plane = @import("../substrate/native_media_plane.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const media_transport = @import("../substrate/media_transport.zig");

pub const ParticipantId = native_plane.ParticipantId;
pub const MediaKind = native_plane.MediaKind;
pub const Selection = native_plane.Selection;
pub const TransportAddress = media_transport.TransportAddress;

/// Result of registering: whether this was a fresh slot or an update.
pub const RegisterError = error{ Full, BadId };

/// Which transport produced a tapped packet.
pub const TapTransport = enum { native_cadence, webrtc_rtp };

/// Codec identity reported to a tap. Native cadence codecs come from the
/// frame header; RTP codecs are resolved from the payload type (native and
/// gateway codecs share dynamic PTs, so see the emitting transport's docs).
pub const TapCodec = enum { cadencevox, cadencevis, opus, vp8, raw, unknown };

/// Media kind reported to a tap (mirrors `MediaKind` plus `unknown` for RTP
/// payload types the transport cannot classify).
pub const TapKind = enum { voice, video, screen, unknown };

/// One accepted, actually-forwarded media packet, as seen by a `MediaTap`.
///
/// Every slice is BORROWED: it is valid only for the duration of the tap
/// callback. A tap that needs the data later must copy it during the call.
/// `channel`/`participant` are empty when the emitting transport does not
/// carry that identity at its forward point. `timestamp` is the cadence
/// media-clock timestamp (native) or the 32-bit RTP timestamp zero-extended
/// (WebRTC). `keyframe` is null when the transport cannot derive it without
/// parsing codec payloads (RTP). `payload` is the encoded codec payload
/// only — container/RTP headers are stripped.
pub const TapEvent = struct {
    transport: TapTransport,
    channel: []const u8 = "",
    participant: []const u8 = "",
    /// Cadence `stream_id` (native) or RTP SSRC (WebRTC).
    stream_id: u32 = 0,
    codec: TapCodec = .unknown,
    kind: TapKind = .unknown,
    timestamp: ?u64 = null,
    sequence: ?u32 = null,
    keyframe: ?bool = null,
    payload: []const u8,
};

/// Optional, default-off observation hook for forwarded media packets.
///
/// The callback runs SYNCHRONOUSLY on the media forwarding thread (the
/// native media pump thread for `NativeMediaLink`, the `MediaPlane` pump
/// thread for WebRTC) and therefore must NEVER block: no socket/file I/O,
/// no lock that can be held across I/O, no unbounded allocation, and no
/// re-entering the forwarding object that invoked it. The intended shape is
/// "copy the event into the tap's own bounded queue and return". A slow or
/// blocking callback directly stalls media forwarding for every call on
/// that pump. The callback must not retain any slice from `TapEvent`.
///
/// A tap is process-local authority: it is never serialized into Helix
/// snapshots, and a restored link/plane always starts with a null tap.
pub const MediaTap = struct {
    ctx: *anyopaque,
    on_packet: *const fn (ctx: *anyopaque, event: TapEvent) void,
};

fn tapKindOf(kind: MediaKind) TapKind {
    return switch (kind) {
        .voice => .voice,
        .video => .video,
        .screen => .screen,
    };
}

fn tapCodecOf(codec: cadence_frame.CodecTag) TapCodec {
    return switch (codec) {
        .cadencevox_audio => .cadencevox,
        .cadencevis_video => .cadencevis,
        .raw => .raw,
    };
}

pub fn NativeMediaLink(comptime max_participants: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            id: ParticipantId,
            kind: MediaKind,
            stream_id: u32,
            addr: TransportAddress,
            addr_bound: bool = false,
            live: bool = false,
            /// Media frames/bytes received from this publisher and forwarded.
            rx_packets: u64 = 0,
            rx_bytes: u64 = 0,
        };

        /// Per-participant transport stats snapshot.
        pub const Stat = struct {
            id: ParticipantId,
            stream_id: u32,
            rx_packets: u64,
            rx_bytes: u64,

            pub fn name(self: *const Stat) []const u8 {
                return self.id.slice();
            }
        };

        plane: native_plane.NativeMediaPlane(max_participants),
        entries: [max_participants]Entry = undefined,
        len: usize = 0,
        max_participants_runtime: usize = max_participants,
        /// Optional forwarded-packet tap; null (the default) is byte-identical
        /// to no tap and costs one null check per forwarded frame. Excluded
        /// from snapshots (process-local callback; see `MediaTap`).
        tap: ?MediaTap = null,
        /// Copied channel label reported to the tap; empty until the owner
        /// calls `setTapChannel`. Copied so the label never dangles.
        tap_channel_buf: [128]u8 = @splat(0),
        tap_channel_len: usize = 0,

        pub const SnapshotEntry = struct {
            id: ParticipantId = .{},
            kind: MediaKind = .voice,
            stream_id: u32 = 0,
            addr: TransportAddress = .{},
            addr_bound: bool = false,
            live: bool = false,
            rx_packets: u64 = 0,
            rx_bytes: u64 = 0,
        };
        pub const Snapshot = struct {
            plane: native_plane.NativeMediaPlane(max_participants).Snapshot = .{},
            entries: [max_participants]SnapshotEntry = @splat(.{}),
            len: usize = 0,
            max_participants_runtime: usize = 0,

            pub fn validate(self: *const Snapshot, expected_capacity: usize) error{InvalidSnapshot}!void {
                if (self.max_participants_runtime != @min(expected_capacity, max_participants) or self.len > self.max_participants_runtime or self.len > max_participants) return error.InvalidSnapshot;
                try self.plane.validate();
                if (self.plane.session.len != self.len) return error.InvalidSnapshot;
                for (self.entries[0..self.len], 0..) |entry, i| {
                    try @import("../substrate/undertow/media.zig").validateParticipantId(entry.id);
                    if (!entry.live or (entry.addr.ip_len != 0 and entry.addr.ip_len != 4 and entry.addr.ip_len != 16)) return error.InvalidSnapshot;
                    for (entry.addr.ip[entry.addr.ip_len..]) |byte| if (byte != 0) return error.InvalidSnapshot;
                    for (self.entries[0..i]) |prior| if (prior.id.eql(&entry.id)) return error.InvalidSnapshot;
                    var found = false;
                    for (self.plane.session.participants[0..self.plane.session.len]) |row| {
                        if (row.id.eql(&entry.id)) {
                            if (row.joined.bits != @as(u8, 1) << @intCast(@backingInt(entry.kind))) return error.InvalidSnapshot;
                            found = true;
                            break;
                        }
                    }
                    if (!found) return error.InvalidSnapshot;
                    // Duplicate stream IDs retain source order/first-match
                    // behavior. updateAddress may preserve a bound empty addr.
                }
                for (self.entries[self.len..]) |entry| if (!std.meta.eql(entry, SnapshotEntry{})) return error.InvalidSnapshot;
            }
        };

        pub fn capture(self: *const Self) error{InvalidSnapshot}!Snapshot {
            if (self.len > max_participants) return error.InvalidSnapshot;
            var snapshot: Snapshot = .{ .plane = try self.plane.capture(), .len = self.len, .max_participants_runtime = self.max_participants_runtime };
            for (self.entries[0..self.len], snapshot.entries[0..self.len]) |entry, *out| out.* = .{ .id = entry.id, .kind = entry.kind, .stream_id = entry.stream_id, .addr = entry.addr, .addr_bound = entry.addr_bound, .live = entry.live, .rx_packets = entry.rx_packets, .rx_bytes = entry.rx_bytes };
            try snapshot.validate(self.max_participants_runtime);
            return snapshot;
        }

        pub fn prepareRestore(snapshot: *const Snapshot, expected_capacity: usize) error{InvalidSnapshot}!Self {
            try snapshot.validate(expected_capacity);
            var candidate: Self = .{ .plane = try native_plane.NativeMediaPlane(max_participants).prepareRestore(&snapshot.plane), .len = snapshot.len, .max_participants_runtime = snapshot.max_participants_runtime };
            for (snapshot.entries[0..snapshot.len], candidate.entries[0..snapshot.len]) |entry, *out| out.* = .{ .id = entry.id, .kind = entry.kind, .stream_id = entry.stream_id, .addr = entry.addr, .addr_bound = entry.addr_bound, .live = entry.live, .rx_packets = entry.rx_packets, .rx_bytes = entry.rx_bytes };
            return candidate;
        }

        pub fn init() Self {
            return initConfig(max_participants);
        }

        pub fn initConfig(max_participants_runtime: usize) Self {
            return .{
                .plane = native_plane.NativeMediaPlane(max_participants).init(),
                .max_participants_runtime = @min(max_participants_runtime, max_participants),
            };
        }

        fn findById(self: *Self, id: ParticipantId) ?*Entry {
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.id.eql(&id)) return e;
            }
            return null;
        }

        pub fn streamIdFor(self: *Self, id_bytes: []const u8) ?u32 {
            const id = ParticipantId.init(id_bytes) catch return null;
            if (self.findById(id)) |e| return e.stream_id;
            return null;
        }

        pub fn idForStream(self: *Self, stream_id: u32) ?[]const u8 {
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.stream_id == stream_id) return e.id.slice();
            }
            return null;
        }

        /// Bind or verify the transport address for `stream_id`. Used by native
        /// control feedback, which does not carry a cadence frame but still needs
        /// the same anti-spoofing address ownership as media datagrams.
        pub fn bindAddressForStream(self: *Self, stream_id: u32, from: TransportAddress) bool {
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.stream_id == stream_id) {
                    if (e.addr_bound and !e.addr.eql(from)) return false;
                    e.addr = from;
                    e.addr_bound = true;
                    return true;
                }
            }
            return false;
        }

        /// Register (or update) a participant: join the forwarding session and
        /// record its publishing `stream_id` and current `TransportAddress`.
        /// Re-registering the same id updates its address/stream/kind in place.
        pub fn register(
            self: *Self,
            id_bytes: []const u8,
            kind: MediaKind,
            stream_id: u32,
            addr: TransportAddress,
        ) RegisterError!void {
            const id = ParticipantId.init(id_bytes) catch return error.BadId;

            if (self.findById(id)) |e| {
                if (e.kind != kind) {
                    self.plane.leave(id, e.kind) catch {};
                    self.plane.join(id, kind) catch return error.Full;
                }
                e.kind = kind;
                e.stream_id = stream_id;
                e.addr = addr;
                e.addr_bound = addr.ip_len != 0 and addr.port != 0;
                return;
            }

            if (self.len >= @min(self.max_participants_runtime, max_participants)) return error.Full;
            self.plane.join(id, kind) catch return error.Full;
            self.entries[self.len] = .{
                .id = id,
                .kind = kind,
                .stream_id = stream_id,
                .addr = addr,
                .addr_bound = addr.ip_len != 0 and addr.port != 0,
                .live = true,
            };
            self.len += 1;
        }

        /// Update a registered participant's address (e.g. ICE re-binding to a new
        /// remote). No-op if unknown.
        pub fn updateAddress(self: *Self, id_bytes: []const u8, addr: TransportAddress) void {
            const id = ParticipantId.init(id_bytes) catch return;
            if (self.findById(id)) |e| e.addr = addr;
        }

        /// Set a receiver's simulcast spatial/temporal ceiling.
        pub fn setSelection(self: *Self, id_bytes: []const u8, sel: Selection) void {
            const id = ParticipantId.init(id_bytes) catch return;
            self.plane.setSelection(id, sel);
        }

        pub fn selectionOf(self: *const Self, id_bytes: []const u8) Selection {
            const id = ParticipantId.init(id_bytes) catch return .{};
            return self.plane.selectionOf(id);
        }

        /// Remove a participant (MEDIA LEAVE / disconnect).
        pub fn unregister(self: *Self, id_bytes: []const u8) void {
            const id = ParticipantId.init(id_bytes) catch return;
            for (self.entries[0..self.len], 0..) |*e, i| {
                if (e.live and e.id.eql(&id)) {
                    self.plane.leave(e.id, e.kind) catch {};
                    self.entries[i] = self.entries[self.len - 1];
                    self.len -= 1;
                    return;
                }
            }
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// Install (or clear, with null) the forwarded-packet tap. Not
        /// internally synchronized: call it from the same thread that drives
        /// `inbound`/`inboundFrom`, or before that pump starts. See
        /// `MediaTap` for the non-blocking callback contract.
        pub fn setTap(self: *Self, tap: ?MediaTap) void {
            self.tap = tap;
        }

        /// Set the channel label reported in tap events (copied; a label
        /// longer than the buffer is truncated). The link is per-call, so
        /// the owning transport supplies the name once at setup.
        pub fn setTapChannel(self: *Self, channel: []const u8) void {
            const n = @min(channel.len, self.tap_channel_buf.len);
            @memcpy(self.tap_channel_buf[0..n], channel[0..n]);
            self.tap_channel_len = n;
        }

        /// Fire the tap once for a frame that `forwardView` actually
        /// forwarded (non-empty recipient set). One null check when no tap
        /// is installed.
        inline fn emitTap(self: *Self, view: cadence_frame.FrameView, source: ParticipantId, kind: MediaKind) void {
            const tap = self.tap orelse return;
            tap.on_packet(tap.ctx, .{
                .transport = .native_cadence,
                .channel = self.tap_channel_buf[0..self.tap_channel_len],
                .participant = source.slice(),
                .stream_id = view.stream_id,
                .codec = tapCodecOf(view.codec),
                .kind = tapKindOf(kind),
                .timestamp = view.timestamp,
                .sequence = view.sequence,
                .keyframe = view.keyframe,
                .payload = view.payload,
            });
        }

        fn addrForId(self: *Self, id: ParticipantId) ?TransportAddress {
            if (self.findById(id)) |e| return e.addr;
            return null;
        }

        /// The learned transport address of a participant by string id, or null
        /// if unknown / not yet learned. Used to deliver cross-leg (WebRTC→native)
        /// frames to a native peer.
        pub fn addrFor(self: *Self, id_bytes: []const u8) ?TransportAddress {
            const id = ParticipantId.init(id_bytes) catch return null;
            return self.addrForId(id);
        }

        /// Snapshot per-participant stats into `out`; returns the count.
        pub fn stats(self: *Self, out: []Stat) usize {
            var n: usize = 0;
            for (self.entries[0..self.len]) |e| {
                if (!e.live or n >= out.len) continue;
                out[n] = .{ .id = e.id, .stream_id = e.stream_id, .rx_packets = e.rx_packets, .rx_bytes = e.rx_bytes };
                n += 1;
            }
            return n;
        }

        /// Decode one inbound native datagram and compute the forward set as
        /// transport addresses. The SAME `datagram` bytes are then sent verbatim
        /// to each address in `out[0..n]`. Returns 0 (and forwards nothing) when
        /// the datagram is not a decodable media frame or its source is unknown.
        pub fn inbound(
            self: *Self,
            datagram: []const u8,
            out: []TransportAddress,
        ) usize {
            const view = cadence_frame.decode(datagram) catch return 0;
            return self.forwardView(view, datagram.len, out);
        }

        /// Like `inbound`, but first learns the source participant's transport
        /// address from `from` (the datagram's origin) — how the live SFU
        /// discovers each publisher's return path on a connectionless socket.
        pub fn inboundFrom(
            self: *Self,
            datagram: []const u8,
            from: TransportAddress,
            out: []TransportAddress,
        ) usize {
            const view = cadence_frame.decode(datagram) catch return 0;
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.stream_id == view.stream_id) {
                    if (e.addr_bound and !e.addr.eql(from)) return 0;
                    e.addr = from;
                    e.addr_bound = true;
                    break;
                }
            }
            return self.forwardView(view, datagram.len, out);
        }

        fn forwardView(self: *Self, view: cadence_frame.FrameView, datagram_len: usize, out: []TransportAddress) usize {
            // Identify the publishing participant by the frame's stream_id, and
            // meter the frame against that publisher.
            var src_id: ?ParticipantId = null;
            var src_kind: MediaKind = .voice;
            for (self.entries[0..self.len]) |*e| {
                if (e.live and e.stream_id == view.stream_id) {
                    src_id = e.id;
                    src_kind = e.kind;
                    e.rx_packets += 1;
                    e.rx_bytes += datagram_len;
                    break;
                }
            }
            const source = src_id orelse return 0;

            // band_id = MEDIA_BAND_FLOOR + spatial (publisher convention).
            const spatial: u8 = @intCast(view.band_id - cadence_frame.MEDIA_BAND_FLOOR);

            var ids: [max_participants]ParticipantId = undefined;
            const m = self.plane.forward(source, src_kind, spatial, 0, view.keyframe, &ids);

            var n: usize = 0;
            for (ids[0..m]) |rid| {
                if (n >= out.len) break;
                if (self.addrForId(rid)) |a| {
                    out[n] = a;
                    n += 1;
                }
            }
            // Single post-acceptance tap point for the native leg: by here
            // the frame decoded, its publisher is a registered participant
            // (callers authenticate datagrams — MAC / address ownership —
            // before `inboundFrom`), and the layer-selection decision kept
            // at least one recipient. Unknown streams, spoofed sources and
            // fully layer-dropped frames never reach this call.
            if (n != 0) self.emitTap(view, source, src_kind);
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests (run under the unified build; transitively imports cadence via the
// native plane, so not standalone `zig test`-able — expected).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mkAddr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

fn frame(stream_id: u32, band: u8, seq: u32, keyframe: bool, buf: []u8) []const u8 {
    const n = cadence_frame.encode(.{
        .band_id = band,
        .stream_id = stream_id,
        .sequence = seq,
        .timestamp = 0,
        .keyframe = keyframe,
        .codec = .cadencevox_audio,
        .payload = &[_]u8{ 0xAA, 0xBB, 0xCC },
    }, buf) catch unreachable;
    return buf[0..n];
}

test "inbound forwards a base-layer frame to the other registered addresses" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("alice", .voice, 100, mkAddr(1, 5000));
    try link.register("bob", .voice, 200, mkAddr(2, 5000));
    try link.register("carol", .voice, 300, mkAddr(3, 5000));

    var fbuf: [64]u8 = undefined;
    const dgram = frame(100, floor, 1, false, &fbuf);

    var out: [8]TransportAddress = undefined;
    const n = link.inbound(dgram, &out);
    try testing.expectEqual(@as(usize, 2), n); // bob + carol, not the source alice
    // and never alice's own address
    for (out[0..n]) |a| try testing.expect(!a.eql(mkAddr(1, 5000)));
}

test "inbound drops an unknown stream_id" {
    var link = NativeMediaLink(8).init();
    try link.register("alice", .voice, 100, mkAddr(1, 5000));
    try link.register("bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [64]u8 = undefined;
    const dgram = frame(999, cadence_frame.MEDIA_BAND_FLOOR, 1, false, &fbuf);
    var out: [8]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 0), link.inbound(dgram, &out));
}

test "spatial ceiling drops higher band but keyframes always pass" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("src", .video, 10, mkAddr(1, 6000));
    try link.register("lowbw", .video, 11, mkAddr(2, 6000));
    link.setSelection("lowbw", .{ .max_spatial = 0, .max_temporal = 0 });

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;

    // spatial layer 1 (band floor+1), non-keyframe -> dropped for lowbw
    try testing.expectEqual(@as(usize, 0), link.inbound(frame(10, floor + 1, 1, false, &fbuf), &out));
    // spatial layer 0 -> delivered
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(10, floor, 2, false, &fbuf), &out));
    // keyframe at base layer -> delivered
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(10, floor, 3, true, &fbuf), &out));
}

test "GAP-V3 native receivers keep different spatial ceilings" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("src", .video, 10, mkAddr(1, 6100));
    try link.register("low", .video, 11, mkAddr(2, 6100));
    try link.register("high", .video, 12, mkAddr(3, 6100));
    link.setSelection("low", .{ .max_spatial = 0, .max_temporal = 0 });
    link.setSelection("high", .{ .max_spatial = 2, .max_temporal = 0 });

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const high_n = link.inbound(frame(10, floor + 2, 1, false, &fbuf), &out);
    try testing.expectEqual(@as(usize, 1), high_n);
    try testing.expect(out[0].eql(mkAddr(3, 6100)));

    const base_n = link.inbound(frame(10, floor, 2, false, &fbuf), &out);
    try testing.expectEqual(@as(usize, 2), base_n);

    link.setSelection("low", .{ .max_spatial = 1, .max_temporal = 0 });
    try testing.expectEqual(@as(u8, 2), link.selectionOf("high").max_spatial);
    const mid_n = link.inbound(frame(10, floor + 1, 3, false, &fbuf), &out);
    try testing.expectEqual(@as(usize, 2), mid_n);
    try testing.expectEqual(@as(u8, 1), link.selectionOf("low").max_spatial);
}

test "unregister removes a participant from the forward set" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("a", .voice, 1, mkAddr(1, 7000));
    try link.register("b", .voice, 2, mkAddr(2, 7000));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(1, floor, 1, false, &fbuf), &out));
    link.unregister("b");
    try testing.expectEqual(@as(usize, 0), link.inbound(frame(1, floor, 2, false, &fbuf), &out));
    try testing.expectEqual(@as(usize, 1), link.count());
}

test "register refuses new native participants at runtime cap" {
    var link = NativeMediaLink(8).initConfig(2);
    try link.register("a", .voice, 1, mkAddr(1, 7000));
    try link.register("b", .voice, 2, mkAddr(2, 7000));
    try testing.expectError(error.Full, link.register("c", .voice, 3, mkAddr(3, 7000)));
    try link.register("a", .video, 4, mkAddr(4, 7000));
    try testing.expectEqual(@as(usize, 2), link.count());
    try testing.expectEqual(@as(?u32, 4), link.streamIdFor("a"));
}

test "inboundFrom learns the publisher's address and still forwards to others" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    // alice registered with a placeholder address (unknown until she sends).
    try link.register("alice", .voice, 100, mkAddr(0, 0));
    try link.register("bob", .voice, 200, mkAddr(2, 9000));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const learned = mkAddr(7, 1234);
    const n = link.inboundFrom(frame(100, floor, 1, false, &fbuf), learned, &out);

    // forwarded to bob only (source excluded)
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(2, 9000)));

    // alice's address was learned from the datagram origin: a frame from bob
    // now forwards back to alice's learned address.
    const n2 = link.inboundFrom(frame(200, floor, 1, false, &fbuf), mkAddr(2, 9000), &out);
    try testing.expectEqual(@as(usize, 1), n2);
    try testing.expect(out[0].eql(learned));
}

test "inboundFrom rejects a bound stream_id from a different source address" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("alice", .voice, 100, mkAddr(0, 0));
    try link.register("bob", .voice, 200, mkAddr(2, 9000));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const learned = mkAddr(7, 1234);
    try testing.expectEqual(@as(usize, 1), link.inboundFrom(frame(100, floor, 1, false, &fbuf), learned, &out));
    try testing.expectEqual(@as(usize, 0), link.inboundFrom(frame(100, floor, 2, false, &fbuf), mkAddr(8, 1234), &out));
}

test "stats meter received frames against the publisher" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("alice", .voice, 100, mkAddr(1, 5000));
    try link.register("bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const d1 = frame(100, floor, 1, false, &fbuf);
    const dlen = d1.len;
    _ = link.inbound(d1, &out);
    _ = link.inbound(frame(100, floor, 2, false, &fbuf), &out);

    var stats: [8]NativeMediaLink(8).Stat = undefined;
    const n = link.stats(&stats);
    try testing.expectEqual(@as(usize, 2), n);
    for (stats[0..n]) |s| {
        if (std.mem.eql(u8, s.name(), "alice")) {
            try testing.expectEqual(@as(u64, 2), s.rx_packets);
            try testing.expectEqual(@as(u64, 2 * dlen), s.rx_bytes);
        } else {
            try testing.expectEqual(@as(u64, 0), s.rx_packets); // bob published nothing
        }
    }
}

test "updateAddress redirects a receiver's copies" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("a", .voice, 1, mkAddr(1, 8000));
    try link.register("b", .voice, 2, mkAddr(2, 8000));
    link.updateAddress("b", mkAddr(9, 8001));

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    const n = link.inbound(frame(1, floor, 1, false, &fbuf), &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(9, 8001)));
}

test "active media DTO native link preserves ordered aliases counters and address binding" {
    const L = NativeMediaLink(4);
    var old = L.initConfig(3);
    const addr = TransportAddress.fromBytes(&.{ 127, 0, 0, 1 }, 9080) catch unreachable;
    try old.register("A", .voice, 7, addr);
    try old.register("B", .video, 7, addr); // supported ordered stream alias
    old.setSelection("orphan", .{ .max_spatial = 2, .max_temporal = 1 });
    var encoded: [64]u8 = undefined;
    var recipients: [4]TransportAddress = undefined;
    _ = old.inboundFrom(frame(7, cadence_frame.MEDIA_BAND_FLOOR, 1, false, &encoded), addr, &recipients);
    _ = old.inboundFrom(frame(7, cadence_frame.MEDIA_BAND_FLOOR, 2, false, &encoded), addr, &recipients);
    old.updateAddress("A", .{}); // source keeps addr_bound, exact negative fact
    const carry = try old.capture();
    var candidate = try L.prepareRestore(&carry, 3);
    try testing.expectEqualDeep(carry, try candidate.capture());
    try testing.expectEqualStrings("A", candidate.idForStream(7).?);
    try testing.expect(candidate.entries[0].addr_bound);
    try testing.expectEqual(@as(u8, 0), candidate.addrFor("A").?.ip_len);
    try testing.expectEqual(@as(u64, 2), candidate.entries[0].rx_packets);
    try testing.expectError(error.InvalidSnapshot, L.prepareRestore(&carry, 2));
    var bad = carry;
    bad.len = 5;
    try testing.expectError(error.InvalidSnapshot, L.prepareRestore(&bad, 3));
    bad = carry;
    bad.entries[1].id = bad.entries[0].id;
    try testing.expectError(error.InvalidSnapshot, L.prepareRestore(&bad, 3));
    bad = carry;
    bad.entries[0].addr.ip_len = 5;
    try testing.expectError(error.InvalidSnapshot, L.prepareRestore(&bad, 3));
    bad = carry;
    bad.plane.session.participants[0].joined.bits = 4;
    try testing.expectError(error.InvalidSnapshot, L.prepareRestore(&bad, 3));
    candidate.unregister("A");
    try testing.expectEqualStrings("B", candidate.idForStream(7).?);
    try testing.expectEqualDeep(carry, try old.capture());
}

test "active media DTO native link next genuine cadence datagram preserves forwarding and spoof refusal" {
    const L = NativeMediaLink(4);
    var old = L.init();
    const source = mkAddr(1, 9300);
    const receiver = mkAddr(2, 9301);
    try old.register("A", .voice, 100, source);
    try old.register("B", .voice, 101, receiver);
    const carry = try old.capture();
    var candidate = try L.prepareRestore(&carry, 4);
    var encoded: [64]u8 = undefined;
    const packet = frame(100, cadence_frame.MEDIA_BAND_FLOOR, 5, false, &encoded);
    var a: [4]TransportAddress = undefined;
    var b: [4]TransportAddress = undefined;
    try testing.expectEqual(@as(usize, 0), candidate.inboundFrom(packet, mkAddr(3, 9302), &b));
    try testing.expectEqual(@as(usize, 1), old.inboundFrom(packet, source, &a));
    try testing.expectEqual(@as(usize, 1), candidate.inboundFrom(packet, source, &b));
    try testing.expect(a[0].eql(receiver) and b[0].eql(receiver));
    try testing.expectEqualDeep(try old.capture(), try candidate.capture());
}

const TapProbe = struct {
    calls: usize = 0,
    transport: TapTransport = .webrtc_rtp,
    channel_buf: [32]u8 = undefined,
    channel_len: usize = 0,
    participant_buf: [32]u8 = undefined,
    participant_len: usize = 0,
    stream_id: u32 = 0,
    codec: TapCodec = .unknown,
    kind: TapKind = .unknown,
    timestamp: ?u64 = null,
    sequence: ?u32 = null,
    keyframe: ?bool = null,
    payload_buf: [16]u8 = undefined,
    payload_len: usize = 0,

    fn onPacket(ctx: *anyopaque, event: TapEvent) void {
        const self: *TapProbe = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.transport = event.transport;
        self.channel_len = @min(event.channel.len, self.channel_buf.len);
        @memcpy(self.channel_buf[0..self.channel_len], event.channel[0..self.channel_len]);
        self.participant_len = @min(event.participant.len, self.participant_buf.len);
        @memcpy(self.participant_buf[0..self.participant_len], event.participant[0..self.participant_len]);
        self.stream_id = event.stream_id;
        self.codec = event.codec;
        self.kind = event.kind;
        self.timestamp = event.timestamp;
        self.sequence = event.sequence;
        self.keyframe = event.keyframe;
        self.payload_len = @min(event.payload.len, self.payload_buf.len);
        @memcpy(self.payload_buf[0..self.payload_len], event.payload[0..self.payload_len]);
    }

    fn tap(self: *TapProbe) MediaTap {
        return .{ .ctx = self, .on_packet = onPacket };
    }
};

test "media tap fires exactly once per forwarded native frame with borrowed payload" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("alice", .voice, 100, mkAddr(1, 5000));
    try link.register("bob", .voice, 200, mkAddr(2, 5000));
    try link.register("carol", .voice, 300, mkAddr(3, 5000));
    var probe: TapProbe = .{};
    link.setTap(probe.tap());
    link.setTapChannel("#tapchan");

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    // Forwarded to TWO recipients, but the tap is per-packet: exactly once.
    try testing.expectEqual(@as(usize, 2), link.inbound(frame(100, floor, 7, true, &fbuf), &out));
    try testing.expectEqual(@as(usize, 1), probe.calls);
    try testing.expectEqual(TapTransport.native_cadence, probe.transport);
    try testing.expectEqualStrings("#tapchan", probe.channel_buf[0..probe.channel_len]);
    try testing.expectEqualStrings("alice", probe.participant_buf[0..probe.participant_len]);
    try testing.expectEqual(@as(u32, 100), probe.stream_id);
    try testing.expectEqual(TapCodec.cadencevox, probe.codec);
    try testing.expectEqual(TapKind.voice, probe.kind);
    try testing.expectEqual(@as(?u32, 7), probe.sequence);
    try testing.expectEqual(@as(?bool, true), probe.keyframe);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, probe.payload_buf[0..probe.payload_len]);
}

test "media tap does not fire for rejected or dropped native frames" {
    var link = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    try link.register("src", .video, 10, mkAddr(1, 6000));
    try link.register("lowbw", .video, 11, mkAddr(2, 6000));
    link.setSelection("lowbw", .{ .max_spatial = 0, .max_temporal = 0 });
    var probe: TapProbe = .{};
    link.setTap(probe.tap());

    var fbuf: [64]u8 = undefined;
    var out: [8]TransportAddress = undefined;
    // Unknown stream_id: rejected before the forward decision.
    try testing.expectEqual(@as(usize, 0), link.inbound(frame(999, floor, 1, false, &fbuf), &out));
    // Malformed datagram: rejected at decode.
    try testing.expectEqual(@as(usize, 0), link.inbound("not a frame", &out));
    // Known publisher but layer-dropped for every recipient.
    try testing.expectEqual(@as(usize, 0), link.inbound(frame(10, floor + 1, 2, false, &fbuf), &out));
    try testing.expectEqual(@as(usize, 0), probe.calls);
    // Same publisher at the base layer forwards, and only then taps.
    try testing.expectEqual(@as(usize, 1), link.inbound(frame(10, floor, 3, false, &fbuf), &out));
    try testing.expectEqual(@as(usize, 1), probe.calls);
    // Spoofed source address after binding: refused, no tap.
    try testing.expectEqual(@as(usize, 0), link.inboundFrom(frame(10, floor, 4, false, &fbuf), mkAddr(9, 6000), &out));
    try testing.expectEqual(@as(usize, 1), probe.calls);
}

test "null media tap (default and after clearing) changes no forwarding behavior" {
    var plain = NativeMediaLink(8).init();
    var cleared = NativeMediaLink(8).init();
    const floor = cadence_frame.MEDIA_BAND_FLOOR;
    for ([_]*NativeMediaLink(8){ &plain, &cleared }) |link| {
        try link.register("alice", .voice, 100, mkAddr(1, 5000));
        try link.register("bob", .voice, 200, mkAddr(2, 5000));
    }
    var probe: TapProbe = .{};
    cleared.setTap(probe.tap());
    cleared.setTap(null);

    var fbuf: [64]u8 = undefined;
    const dgram = frame(100, floor, 1, false, &fbuf);
    var out_a: [8]TransportAddress = undefined;
    var out_b: [8]TransportAddress = undefined;
    const na = plain.inbound(dgram, &out_a);
    const nb = cleared.inbound(dgram, &out_b);
    try testing.expectEqual(na, nb);
    for (out_a[0..na], out_b[0..nb]) |a, b| try testing.expect(a.eql(b));
    try testing.expectEqual(@as(usize, 0), probe.calls);
    try testing.expectEqualDeep(try plain.capture(), try cleared.capture());
}
