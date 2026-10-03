// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-owned native media transport: the live UDP leg for Onyx Server's own
//! codec (CadenceVox/CadenceVis). Mirrors `media_plane.MediaPlane` (the WebRTC/UDP leg) but
//! carries `cadence_frame` datagrams instead of RTP, and forwards them through a
//! per-channel `NativeMediaLink` (stream_id → publisher → recipients).
//!
//! Per-channel isolation: each media call (channel) has its own `NativeMediaLink`
//! so media never crosses between channels. A global `stream_id → channel` index
//! lets the pump route an inbound datagram (which carries only a stream_id) to
//! the right channel's link.
//!
//! The pump thread blocks on the socket (short recv timeout to observe the stop
//! flag), and for each datagram that parses as an cadence frame: routes by
//! stream_id to the owning channel, learns the publisher's return address from
//! the datagram origin, computes the SFU forward set, and resends the SAME opaque
//! bytes to each recipient. The server NEVER encodes/decodes/transcodes — frames
//! are forwarded verbatim.
const std = @import("std");
const native_media_link = @import("native_media_link.zig");
const media_bridge = @import("media_bridge.zig");
const media_socket = @import("../substrate/media_socket.zig");
const cadence_frame = @import("../substrate/cadence_frame.zig");
const native_feedback = @import("../substrate/native_feedback.zig");

pub const MediaSocket = media_socket.MediaSocket;
pub const TransportAddress = native_media_link.TransportAddress;
pub const MediaKind = native_media_link.MediaKind;
pub const Selection = native_media_link.Selection;
pub const loopback_be = media_socket.loopback_be;
pub const any_be = media_socket.any_be;
pub const max_datagram = media_socket.max_datagram;

/// Max participants per native call (inline forward fan-out bound).
///
/// The native (CadenceVox/CadenceVis) leg is for point-to-point / small calls; group
/// sessions go through the SFU `Room` (ceiling 256, pointer-indirected per room).
/// This `Link` is stored BY VALUE in a rehashing map, so its inline ceiling stays
/// at 64 to keep the per-entry size (and rehash memcpy cost) bounded; the
/// `[media].max_participants` runtime cap still applies (clamped to this ceiling).
pub const default_max_call_participants = 64;
pub const max_call_participants = 64;

pub const Link = native_media_link.NativeMediaLink(max_call_participants);

/// Blocking acquire on the tryLock-only `std.atomic.Mutex`. Contention is
/// near-zero (rare register/remove vs. the single pump thread), so yielding.
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

pub const NativeMediaTransport = struct {
    allocator: std.mem.Allocator,
    /// channel name (owned key) -> that call's forward link.
    channels: std.StringHashMapUnmanaged(Link) = .empty,
    /// stream_id -> the channel key that owns the publisher (borrows a key from
    /// `channels`, so it is only valid while that channel entry exists).
    stream_index: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    socket: ?MediaSocket = null,
    mutex: std.atomic.Mutex = .unlocked,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Bound local UDP port (0 until started); advertised to native clients.
    port: u16 = 0,
    /// Runtime cap for accepted cadence datagrams.
    max_frame_bytes: usize = media_socket.max_datagram,
    /// Runtime cap reserved for upload-bearing media operations.
    max_upload_bytes: u64 = 16 * 1024 * 1024,
    /// Runtime cap for per-channel native participants below the inline ceiling.
    max_participants: usize = default_max_call_participants,
    /// Require authenticated native-media datagrams. Defaults false so legacy
    /// clients that do not append the MAC tag are still accepted.
    require_mac: bool = false,
    /// Existing stream-id PRF root, copied from LinuxServer.native_stream_key.
    mac_stream_key: [16]u8 = @splat(0),
    mac_key_configured: bool = false,
    /// Optional cross-leg sink: after forwarding a native frame to native peers,
    /// the pump hands it here to also reach the channel's WebRTC members
    /// (rewrapped to RTP). Null = native-only call (no bridging).
    cross: ?media_bridge.CrossLegSink = null,

    pub fn init(allocator: std.mem.Allocator) NativeMediaTransport {
        return initConfig(allocator, default_max_call_participants);
    }

    pub fn initConfig(allocator: std.mem.Allocator, max_participants: usize) NativeMediaTransport {
        return .{
            .allocator = allocator,
            .max_participants = @min(max_participants, max_call_participants),
        };
    }

    /// Install the cross-leg sink (call before `start`, or while stopped).
    pub fn setCrossLegSink(self: *NativeMediaTransport, sink: media_bridge.CrossLegSink) void {
        self.cross = sink;
    }

    pub fn configureMac(self: *NativeMediaTransport, stream_key: *const [16]u8, require_mac: bool) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        self.mac_stream_key = stream_key.*;
        self.require_mac = require_mac;
        self.mac_key_configured = true;
    }

    pub fn deinit(self: *NativeMediaTransport) void {
        self.shutdown();
        std.crypto.secureZero(u8, self.mac_stream_key[0..]);
        var it = self.channels.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.channels.deinit(self.allocator);
        self.stream_index.deinit(self.allocator);
        self.* = undefined;
    }

    /// Whether this native transport has no registered call state that would be
    /// lost by an in-place exec. A bound/idle UDP socket and configured MAC or
    /// cross-leg policy are process configuration, not an active media session.
    /// Both registries are checked under their native mutex so an unregister or
    /// pump address learn cannot race the fail-closed decision.
    pub fn upgradeContinuityReady(self: *NativeMediaTransport) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.channels.count() == 0 and self.stream_index.count() == 0;
    }

    /// Bind on `bind_be`:`port` (port 0 = ephemeral) and spawn the pump thread.
    /// No-op if already started.
    pub fn start(self: *NativeMediaTransport, bind_be: u32, port: u16) !void {
        if (self.socket != null) return;
        var sock = try MediaSocket.bind(bind_be, port);
        errdefer sock.deinit();
        self.port = try sock.localPort();
        sock.setRecvTimeoutMs(250); // wake to observe the stop flag
        self.socket = sock;

        self.stop_flag.store(false, .release);
        self.thread = std.Thread.spawn(.{}, pumpLoop, .{self}) catch |e| {
            self.socket.?.deinit();
            self.socket = null;
            return e;
        };
    }

    /// Signal the pump to stop, join it, and close the socket.
    pub fn shutdown(self: *NativeMediaTransport) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        if (self.socket) |*s| {
            s.deinit();
            self.socket = null;
        }
    }

    fn pumpLoop(self: *NativeMediaTransport) void {
        var buf: [media_socket.max_datagram]u8 = undefined;
        var targets: [max_call_participants]TransportAddress = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const sock = &(self.socket orelse return);
            const got = sock.recvFrom(&buf) orelse continue; // timeout/idle
            // Require cadence framing so the port is not an open UDP reflector.
            if (got.data.len > self.max_frame_bytes) continue;
            if (native_feedback.isEnvelope(got.data)) {
                self.handleFeedback(got.from, got.data);
                continue;
            }
            if (got.data.len < cadence_frame.MIN_FRAME_WIRE_BYTES) continue;
            const frame_bytes = cadence_frame.authenticatedFrameBytes(got.data) catch continue;
            const view = cadence_frame.decode(frame_bytes) catch continue;

            lockSpin(&self.mutex);
            var n: usize = 0;
            var chanbuf: [256]u8 = undefined;
            var chanlen: usize = 0;
            var forward_datagram: []const u8 = &.{};
            var bridge_datagram: []const u8 = &.{};
            if (self.stream_index.get(view.stream_id)) |chan| {
                if (self.channels.getPtr(chan)) |link| {
                    if (link.idForStream(view.stream_id)) |participant| {
                        const auth_frame = self.authenticateDatagram(chan, participant, got.data) catch null;
                        if (auth_frame) |exact_frame| {
                            n = link.inboundFrom(exact_frame, got.from, &targets);
                            forward_datagram = if (got.data.len == exact_frame.len + cadence_frame.MAC_TAG_BYTES) got.data else exact_frame;
                            bridge_datagram = exact_frame;
                            // Copy the channel name out under the lock so the cross-leg
                            // sink can use it after we unlock (the key may be freed if the
                            // channel is torn down concurrently).
                            if (chan.len <= chanbuf.len) {
                                @memcpy(chanbuf[0..chan.len], chan);
                                chanlen = chan.len;
                            }
                        }
                    }
                }
            }
            self.mutex.unlock();

            for (targets[0..n]) |dst| sock.sendTo(dst, forward_datagram);

            // Bridge the same frame to any WebRTC members of this channel.
            if (chanlen != 0) {
                if (self.cross) |sink| sink.onNativeFrame(chanbuf[0..chanlen], bridge_datagram);
            }
        }
    }

    fn handleFeedback(self: *NativeMediaTransport, from: TransportAddress, datagram: []const u8) void {
        if (!self.mac_key_configured) return;
        const peek = native_feedback.peekEnvelope(datagram) catch return;

        // Pass 1 (AUTH prerequisites): resolve the channel/participant that owns
        // this stream_id and copy them out under the lock, WITHOUT mutating any
        // address-ownership trust state. The envelope is still unauthenticated, so
        // we must not bind (or otherwise trust) the source address yet.
        var channel_buf: [256]u8 = undefined;
        var channel_len: usize = 0;
        var participant_buf: [64]u8 = undefined;
        var participant_len: usize = 0;
        lockSpin(&self.mutex);
        if (self.stream_index.get(peek.sender_stream_id)) |channel| {
            if (channel.len <= channel_buf.len) {
                if (self.channels.getPtr(channel)) |link| {
                    if (link.idForStream(peek.sender_stream_id)) |participant| {
                        if (participant.len <= participant_buf.len) {
                            @memcpy(channel_buf[0..channel.len], channel);
                            channel_len = channel.len;
                            @memcpy(participant_buf[0..participant.len], participant);
                            participant_len = participant.len;
                        }
                    }
                }
            }
        }
        self.mutex.unlock();
        if (channel_len == 0 or participant_len == 0) return;

        // AUTH: verify the envelope MAC before touching any trust state. A forged
        // or short tag is dropped here, so it can never rebind the victim's
        // inbound-media return path. The lock is NOT held across openEnvelope.
        var key: [native_feedback.envelope_key_len]u8 = undefined;
        cadence_frame.deriveNativeMediaMacKey(
            &self.mac_stream_key,
            channel_buf[0..channel_len],
            participant_buf[0..participant_len],
            &key,
        );
        defer std.crypto.secureZero(u8, key[0..]);
        const opened = native_feedback.openEnvelope(datagram, &key) catch return;
        if (opened.sender_stream_id != peek.sender_stream_id) return;

        // Pass 2 (BIND): only now, on an authenticated envelope, take the lock
        // again and bind the sender's address (anti-spoofing address ownership).
        // The channel may have been torn down between passes, so re-resolve.
        lockSpin(&self.mutex);
        const bound = if (self.channels.getPtr(channel_buf[0..channel_len])) |link|
            link.bindAddressForStream(opened.sender_stream_id, from)
        else
            false;
        self.mutex.unlock();
        if (!bound) return;

        if (self.cross) |sink| _ = sink.onNativeFeedback(channel_buf[0..channel_len], opened.sender_stream_id, opened.payload);
    }

    fn authenticateDatagram(
        self: *const NativeMediaTransport,
        channel: []const u8,
        participant: []const u8,
        datagram: []const u8,
    ) cadence_frame.MacError![]const u8 {
        if (!self.mac_key_configured) {
            const exact_frame = try cadence_frame.authenticatedFrameBytes(datagram);
            if (try cadence_frame.hasAuthenticationTag(datagram)) return error.BadTag;
            if (self.require_mac) return error.MissingTag;
            return exact_frame;
        }
        return cadence_frame.acceptNativeMediaMac(&self.mac_stream_key, channel, participant, datagram, self.require_mac);
    }

    fn tagOutbound(
        self: *NativeMediaTransport,
        channel: []const u8,
        bytes: []const u8,
        out: []u8,
    ) cadence_frame.MacError![]const u8 {
        if (!self.require_mac) return bytes;
        if (!self.mac_key_configured) return error.MissingTag;

        const view = try cadence_frame.decode(bytes);
        var participant_buf: [64]u8 = undefined;
        var participant_len: usize = 0;
        lockSpin(&self.mutex);
        if (self.stream_index.get(view.stream_id)) |owner| {
            if (std.mem.eql(u8, owner, channel)) {
                if (self.channels.getPtr(channel)) |link| {
                    if (link.idForStream(view.stream_id)) |participant| {
                        if (participant.len <= participant_buf.len) {
                            @memcpy(participant_buf[0..participant.len], participant);
                            participant_len = participant.len;
                        }
                    }
                }
            }
        }
        self.mutex.unlock();
        if (participant_len == 0) return error.MissingTag;

        return cadence_frame.appendNativeMediaMac(
            &self.mac_stream_key,
            channel,
            participant_buf[0..participant_len],
            bytes,
            out,
        );
    }

    // -- Main-thread registry operations (all under the mutex) --------------

    fn linkForChannel(self: *NativeMediaTransport, channel: []const u8) !*Link {
        const gop = try self.channels.getOrPut(self.allocator, channel);
        if (!gop.found_existing) {
            const key = self.allocator.dupe(u8, channel) catch |e| {
                _ = self.channels.remove(channel);
                return e;
            };
            gop.key_ptr.* = key;
            gop.value_ptr.* = Link.initConfig(self.max_participants);
        }
        return gop.value_ptr;
    }

    fn removeStreamEntriesForChannel(self: *NativeMediaTransport, channel_key: []const u8) void {
        while (true) {
            var doomed: ?u32 = null;
            var it = self.stream_index.iterator();
            while (it.next()) |e| {
                if (std.mem.eql(u8, e.value_ptr.*, channel_key)) {
                    doomed = e.key_ptr.*;
                    break;
                }
            }
            if (doomed) |sid| {
                _ = self.stream_index.remove(sid);
            } else {
                break;
            }
        }
    }

    /// Register/update a native participant in `channel` (MEDIA OFFER). `addr`
    /// may be a placeholder; the pump learns the real return path from the
    /// participant's first datagram. `stream_id` is what the publisher stamps
    /// into its cadence frames (advertised back to the client).
    pub fn register(
        self: *NativeMediaTransport,
        channel: []const u8,
        id: []const u8,
        kind: MediaKind,
        stream_id: u32,
        addr: TransportAddress,
    ) !void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (self.stream_index.get(stream_id)) |owner| {
            if (!std.mem.eql(u8, owner, channel)) return error.StreamInUse;
        }
        const link = try self.linkForChannel(channel);
        const old_stream_id = link.streamIdFor(id);
        try link.register(id, kind, stream_id, addr);
        if (old_stream_id) |old| {
            if (old != stream_id) _ = self.stream_index.remove(old);
        }
        // Index stream_id -> channel key (borrow the map's stable key pointer).
        const key = self.channels.getKey(channel).?;
        try self.stream_index.put(self.allocator, stream_id, key);
    }

    /// Remove a participant from `channel` (MEDIA LEAVE / disconnect). Drops the
    /// channel (and its stream-index entries) once the last participant leaves.
    pub fn unregister(self: *NativeMediaTransport, channel: []const u8, id: []const u8) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return;
        if (link.streamIdFor(id)) |sid| _ = self.stream_index.remove(sid);
        link.unregister(id);
        if (link.count() != 0) return;

        // Last participant gone: tear the channel down. Clear stream-index
        // entries that borrow this channel's key BEFORE freeing the key.
        const key = self.channels.getKey(channel).?;
        self.removeStreamEntriesForChannel(key);
        _ = self.channels.remove(channel);
        self.allocator.free(key);
    }

    /// Set a receiver's simulcast spatial/temporal ceiling within `channel`.
    pub fn setSelection(self: *NativeMediaTransport, channel: []const u8, id: []const u8, sel: Selection) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return;
        link.setSelection(id, sel);
    }

    /// The receiver's stored ceiling, or the default (every layer) when the
    /// channel or participant has no row yet.
    pub fn selectionOf(self: *NativeMediaTransport, channel: []const u8, id: []const u8) Selection {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return .{};
        return link.selectionOf(id);
    }

    /// Send `bytes` to `dest` on the native socket. Used by the WebRTC relay's
    /// cross-leg sink to deliver cadence-rewrapped frames to native peers.
    pub fn sendTo(self: *NativeMediaTransport, channel: []const u8, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| {
            var tagged_buf: [media_socket.max_datagram]u8 = undefined;
            const out = self.tagOutbound(channel, bytes, &tagged_buf) catch return;
            s.sendTo(dest, out);
        }
    }

    /// Send a native control-plane feedback message to `dest`. This is not a
    /// cadence media frame and must not pass through media-frame MAC tagging.
    pub fn sendFeedbackTo(self: *NativeMediaTransport, dest: TransportAddress, bytes: []const u8) void {
        if (self.socket) |*s| s.sendTo(dest, bytes);
    }

    /// The learned transport address of a native participant in `channel`, or
    /// null if unknown / not yet learned (the peer hasn't published a datagram).
    pub fn remoteFor(self: *NativeMediaTransport, channel: []const u8, id: []const u8) ?TransportAddress {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return null;
        return link.addrFor(id);
    }

    pub const Stat = Link.Stat;

    /// Snapshot per-participant native transport stats for `channel` into `out`.
    pub fn statsForChannel(self: *NativeMediaTransport, channel: []const u8, out: []Stat) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return 0;
        return link.stats(out);
    }

    /// Participant count in `channel` (0 if the channel has no native call).
    pub fn countChannel(self: *NativeMediaTransport, channel: []const u8) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const link = self.channels.getPtr(channel) orelse return 0;
        return link.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn opframe(stream_id: u32, buf: []u8) []const u8 {
    const n = cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR,
        .stream_id = stream_id,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = true,
        .codec = .cadencevox_audio,
        .payload = &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
    }, buf) catch unreachable;
    return buf[0..n];
}

fn taggedOpframe(stream_id: u32, key: *const [16]u8, channel: []const u8, participant: []const u8, buf: []u8) []const u8 {
    var frame_buf: [64]u8 = undefined;
    const frame = opframe(stream_id, &frame_buf);
    return cadence_frame.appendNativeMediaMac(key, channel, participant, frame, buf) catch unreachable;
}

fn mkAddr(last: u8, port: u16) TransportAddress {
    return TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, last }, port) catch unreachable;
}

test "NativeMediaTransport: pump learns sender + forwards an cadence frame to the receiver" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    var bob = try MediaSocket.bind(loopback_be, 0);
    defer bob.deinit();
    bob.setRecvTimeoutMs(2000);
    const bob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try bob.localPort());

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, bob_addr);

    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = bob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, frame, got.data);
}

test "upgrade continuity: NativeMediaTransport ignores idle socket and gates registrations" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    try testing.expect(nmt.upgradeContinuityReady());
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.upgradeContinuityReady());

    try nmt.register("#c", "alice", .voice, 0xA11CE, .{});
    try testing.expect(!nmt.upgradeContinuityReady());
    nmt.unregister("#c", "alice");
    try testing.expect(nmt.upgradeContinuityReady());
}

test "NativeMediaTransport: required MAC drops untagged and accepts valid tagged datagrams" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const mac_key = @as([16]u8, @splat(0x5A));
    nmt.configureMac(&mac_key, true);

    try nmt.register("#secure", "alice", .voice, 100, .{});
    try nmt.register("#secure", "bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [128]u8 = undefined;
    const untagged = opframe(100, &fbuf);
    try testing.expectError(error.MissingTag, nmt.authenticateDatagram("#secure", "alice", untagged));

    const tagged = taggedOpframe(100, &mac_key, "#secure", "alice", &fbuf);
    const exact_frame = try nmt.authenticateDatagram("#secure", "alice", tagged);
    try testing.expectEqual(tagged.len - cadence_frame.MAC_TAG_BYTES, exact_frame.len);

    const link = nmt.channels.getPtr("#secure").?;
    var out: [max_call_participants]TransportAddress = undefined;
    const n = link.inboundFrom(exact_frame, mkAddr(1, 5000), &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(2, 5000)));
}

test "NativeMediaTransport: MAC flag off preserves untagged datagram behavior" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const mac_key = @as([16]u8, @splat(0x33));
    nmt.configureMac(&mac_key, false);

    try nmt.register("#compat", "alice", .voice, 100, .{});
    try nmt.register("#compat", "bob", .voice, 200, mkAddr(2, 5000));

    var fbuf: [128]u8 = undefined;
    const untagged = opframe(100, &fbuf);
    const exact_frame = try nmt.authenticateDatagram("#compat", "alice", untagged);
    try testing.expectEqualSlices(u8, untagged, exact_frame);

    const link = nmt.channels.getPtr("#compat").?;
    var out: [max_call_participants]TransportAddress = undefined;
    const n = link.inboundFrom(exact_frame, mkAddr(1, 5000), &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expect(out[0].eql(mkAddr(2, 5000)));
}

test "NativeMediaTransport: media never crosses channels" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    // A listener registered in a DIFFERENT channel must never receive the frame.
    var other = try MediaSocket.bind(loopback_be, 0);
    defer other.deinit();
    other.setRecvTimeoutMs(400);
    const other_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try other.localPort());

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();

    try nmt.register("#a", "alice", .voice, 100, .{});
    try nmt.register("#b", "eve", .voice, 999, other_addr); // different channel

    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    try testing.expect(other.recvFrom(&rbuf) == null); // eve hears nothing
}

test "NativeMediaTransport: setSelection drops higher layers over the wire" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);

    var lowbw = try MediaSocket.bind(loopback_be, 0);
    defer lowbw.deinit();
    lowbw.setRecvTimeoutMs(400);
    const lowbw_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try lowbw.localPort());

    var src = try MediaSocket.bind(loopback_be, 0);
    defer src.deinit();

    try nmt.register("#v", "src", .video, 10, .{});
    try nmt.register("#v", "lowbw", .video, 11, lowbw_addr);
    nmt.setSelection("#v", "lowbw", .{ .max_spatial = 0, .max_temporal = 0 });

    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    var fbuf: [64]u8 = undefined;
    var rbuf: [media_socket.max_datagram]u8 = undefined;

    // A spatial layer-1 (band floor+1) non-keyframe must be dropped for lowbw.
    const hi = cadence_frame.encode(.{
        .band_id = cadence_frame.MEDIA_BAND_FLOOR + 1,
        .stream_id = 10,
        .sequence = 1,
        .timestamp = 0,
        .keyframe = false,
        .codec = .cadencevis_video,
        .payload = &[_]u8{ 1, 2, 3 },
    }, &fbuf) catch unreachable;
    src.sendTo(server_addr, fbuf[0..hi]);
    try testing.expect(lowbw.recvFrom(&rbuf) == null);

    // The base layer (band floor) is delivered.
    const base = opframe(10, &fbuf);
    src.sendTo(server_addr, base);
    const got = lowbw.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, base, got.data);
}

test "NativeMediaTransport: unregister drops the channel and frees its index" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, .{});
    try testing.expectEqual(@as(usize, 2), nmt.countChannel("#call"));

    nmt.unregister("#call", "alice");
    try testing.expectEqual(@as(usize, 1), nmt.countChannel("#call"));
    nmt.unregister("#call", "bob");
    try testing.expectEqual(@as(usize, 0), nmt.countChannel("#call"));
    // channel torn down; re-registering works cleanly (no stale key/index)
    try nmt.register("#call", "carol", .voice, 300, .{});
    try testing.expectEqual(@as(usize, 1), nmt.countChannel("#call"));
}

test "NativeMediaTransport: register enforces runtime participant cap" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.initConfig(testing.allocator, 2);
    defer nmt.deinit();

    try nmt.register("#call", "alice", .voice, 100, .{});
    try nmt.register("#call", "bob", .voice, 200, .{});
    try testing.expectError(error.Full, nmt.register("#call", "carol", .voice, 300, .{}));
    try nmt.register("#call", "alice", .video, 400, .{});
    try testing.expectEqual(@as(usize, 2), nmt.countChannel("#call"));
}

const rtp_profile = @import("../proto/rtp_profile.zig");
const TestBridge = media_bridge.ChannelBridge(8);

const TestXCtx = struct {
    bridge: *TestBridge,
    sock: *MediaSocket, // stands in for the media_plane (WebRTC) socket

    fn onNative(ctx: *anyopaque, channel: []const u8, datagram: []const u8) void {
        _ = channel;
        const self: *TestXCtx = @ptrCast(@alignCast(ctx));
        self.bridge.fanoutNativeToWebrtc(datagram, ctx, sendVia);
    }
    fn sendVia(ctx: *anyopaque, target: *const media_bridge.Member, bytes: []const u8) void {
        const self: *TestXCtx = @ptrCast(@alignCast(ctx));
        self.sock.sendTo(target.addr, bytes);
    }
};

const TestFeedbackCtx = struct {
    sock: *MediaSocket,
    dest: TransportAddress,

    fn onNativeFrame(_: *anyopaque, _: []const u8, _: []const u8) void {}

    fn onNativeFeedback(ctx: *anyopaque, channel: []const u8, sender_stream_id: u32, feedback: []const u8) bool {
        _ = sender_stream_id;
        if (!std.mem.eql(u8, channel, "#call")) return false;
        const self: *TestFeedbackCtx = @ptrCast(@alignCast(ctx));
        self.sock.sendTo(self.dest, feedback);
        return true;
    }
};

test "NativeMediaTransport: pump bridges a native frame to a WebRTC member as RTP" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();

    // WebRTC receiver (mob) + the socket the sink sends RTP from (WebRTC plane).
    var mob = try MediaSocket.bind(loopback_be, 0);
    defer mob.deinit();
    mob.setRecvTimeoutMs(2000);
    const mob_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try mob.localPort());
    var wsock = try MediaSocket.bind(loopback_be, 0);
    defer wsock.deinit();

    var bridge = TestBridge.init();
    try bridge.register("mob", .{ .leg = .webrtc, .addr = mob_addr, .ssrc = 0x1234 });

    var xctx = TestXCtx{ .bridge = &bridge, .sock = &wsock };
    nmt.setCrossLegSink(.{ .ctx = &xctx, .on_native_frame = TestXCtx.onNative });
    try nmt.start(loopback_be, 0);

    try nmt.register("#call", "alice", .voice, 100, .{}); // native publisher

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    var fbuf: [64]u8 = undefined;
    const frame = opframe(100, &fbuf);
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, frame);

    // mob receives the same opaque payload, now wrapped as RTP for its ssrc.
    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = mob.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, rtp_profile.header_len + 4), got.data.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, got.data[rtp_profile.header_len..]);
}

test "NativeMediaTransport: pump accepts authenticated native feedback envelope" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x4B));
    nmt.configureMac(&root, false);

    var capture = try MediaSocket.bind(loopback_be, 0);
    defer capture.deinit();
    capture.setRecvTimeoutMs(2000);
    const capture_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try capture.localPort());

    var feedback_ctx = TestFeedbackCtx{ .sock = &capture, .dest = capture_addr };
    nmt.setCrossLegSink(.{
        .ctx = &feedback_ctx,
        .on_native_frame = TestFeedbackCtx.onNativeFrame,
        .on_native_feedback = TestFeedbackCtx.onNativeFeedback,
    });
    try nmt.start(loopback_be, 0);

    try nmt.register("#call", "alice", .voice, 100, .{});

    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);

    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, envelope);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    const got = capture.recvFrom(&rbuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, payload, got.data);
}

test "NativeMediaTransport: pump rejects native feedback with a bad tag" {
    // Loopback UDP via posix poll/sendto has no Winsock mapping yet.
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x4B));
    nmt.configureMac(&root, false);

    var capture = try MediaSocket.bind(loopback_be, 0);
    defer capture.deinit();
    capture.setRecvTimeoutMs(400);
    const capture_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, try capture.localPort());

    var feedback_ctx = TestFeedbackCtx{ .sock = &capture, .dest = capture_addr };
    nmt.setCrossLegSink(.{
        .ctx = &feedback_ctx,
        .on_native_frame = TestFeedbackCtx.onNativeFrame,
        .on_native_feedback = TestFeedbackCtx.onNativeFeedback,
    });
    try nmt.start(loopback_be, 0);
    try nmt.register("#call", "alice", .voice, 100, .{});

    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);

    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);
    env_buf[envelope.len - 1] ^= 0x80;

    var alice = try MediaSocket.bind(loopback_be, 0);
    defer alice.deinit();
    const server_addr = try TransportAddress.fromBytes(&[_]u8{ 127, 0, 0, 1 }, nmt.port);
    alice.sendTo(server_addr, envelope);

    var rbuf: [media_socket.max_datagram]u8 = undefined;
    try testing.expect(capture.recvFrom(&rbuf) == null);
}

const FeedbackFlagCtx = struct {
    hits: usize = 0,
    last_stream: u32 = 0,

    fn onFrame(_: *anyopaque, _: []const u8, _: []const u8) void {}

    fn onFeedback(ctx: *anyopaque, channel: []const u8, sender_stream_id: u32, feedback: []const u8) bool {
        _ = feedback;
        if (!std.mem.eql(u8, channel, "#call")) return false;
        const self: *FeedbackFlagCtx = @ptrCast(@alignCast(ctx));
        self.hits += 1;
        self.last_stream = sender_stream_id;
        return true;
    }
};

// Regression: the native feedback path must be AUTH-THEN-BIND. A structurally
// valid envelope with a BAD tag, arriving from a WRONG source address under
// require_mac, must NOT rebind the victim's inbound-media return path. Before
// the fix `handleFeedback` bound the address (mutating trust state) off an
// unauthenticated peekEnvelope, so a forged flood right after the victim
// re-OFFERed (addr_bound reset to false) would hijack the return path.
test "NativeMediaTransport: forged feedback with a bad tag does not rebind the victim address" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x77));
    nmt.configureMac(&root, true); // hardened require_mac deployment

    // Victim registered with a placeholder address (addr_bound reset), stream 100.
    try nmt.register("#call", "alice", .voice, 100, .{});

    // Correct per-{channel,participant} key + a valid envelope, then corrupt the tag.
    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);
    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);
    env_buf[envelope.len - 1] ^= 0x80; // forge the tag

    // Attacker source address, distinct from the victim's (still-unbound) addr.
    const attacker = mkAddr(9, 9999);
    nmt.handleFeedback(attacker, envelope);

    // The victim's return path must NOT have moved to the attacker; it is still
    // the unbound placeholder.
    const bound = nmt.remoteFor("#call", "alice").?;
    try testing.expect(!bound.eql(attacker));
    try testing.expect(bound.eql(TransportAddress{}));
}

// The authenticated case is unchanged: a valid feedback envelope from the
// correct source still binds the sender's address and reaches the sink.
test "NativeMediaTransport: valid feedback from the correct source still binds and is processed" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    const root = @as([16]u8, @splat(0x77));
    nmt.configureMac(&root, true);

    var ctx = FeedbackFlagCtx{};
    nmt.setCrossLegSink(.{
        .ctx = &ctx,
        .on_native_frame = FeedbackFlagCtx.onFrame,
        .on_native_feedback = FeedbackFlagCtx.onFeedback,
    });

    try nmt.register("#call", "alice", .voice, 100, .{});

    var key: [native_feedback.envelope_key_len]u8 = undefined;
    cadence_frame.deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, key[0..]);
    var payload_buf: [32]u8 = undefined;
    const payload = try native_feedback.encodeKeyframeRequest(200, &payload_buf);
    var env_buf: [96]u8 = undefined;
    const envelope = try native_feedback.encodeEnvelope(100, payload, &key, &env_buf);

    const sender = mkAddr(3, 4000);
    nmt.handleFeedback(sender, envelope);

    const bound = nmt.remoteFor("#call", "alice").?;
    try testing.expect(bound.eql(sender));
    try testing.expectEqual(@as(usize, 1), ctx.hits);
    try testing.expectEqual(@as(u32, 100), ctx.last_stream);
}

test "NativeMediaTransport: start/shutdown is clean and re-startable" {
    var nmt = NativeMediaTransport.init(testing.allocator);
    defer nmt.deinit();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
    nmt.shutdown();
    try nmt.start(loopback_be, 0);
    try testing.expect(nmt.port != 0);
}
