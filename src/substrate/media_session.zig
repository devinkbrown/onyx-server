// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Media session: composes the shipped media primitives into a send/receive
//! pipeline over the mesh's media bands (>=64).
//!
//!   negotiate()            -> agree codecs/FEC/direction via sdp offer/answer
//!   Packetizer.packetize() -> cadence MediaFrame (seq/ts) -> wire bytes
//!   Receiver.ingest()      -> decode -> reassembly reorder buffer
//!   protectGeneration()    -> red_fec (ULPFEC) parity over a generation of frames
//!   recoverFrame()         -> rebuild a single dropped frame from the FEC packet
//!
//! This is the media analog of `transport_stack.zig`: a thin coordinator wiring
//! independently-tested modules (sdp, cadence_frame, red_fec) so a stream of
//! media frames survives reordering and single-packet loss end to end.
const std = @import("std");

const cadence = @import("cadence_frame.zig");
const red_fec = @import("red_fec.zig");
const sdp = @import("../proto/sdp.zig");
const toml = @import("../proto/toml.zig");

pub const MediaFrame = cadence.MediaFrame;
pub const CodecTag = cadence.CodecTag;
pub const PushResult = cadence.PushResult;
pub const MediaDescription = sdp.MediaDescription;

/// Canonical Receiver wiring defaults.
///
/// `Receiver(max_payload, window)` is a COMPTIME-parameterized type — the inline
/// `[window]Slot(max_payload)` ring cannot be made runtime without reworking the
/// substrate buffer onto the heap, so the *type parameters* are DEFERRED. This
/// Config carries the documented runtime defaults so a caller can build the
/// `ReassemblyConfig` window from `[media]` and pick comptime bounds that cover
/// it. Defaults equal the historical wiring (`Receiver(256, 64)` with a runtime
/// `.window = 16`).
pub const default_max_payload_bytes: usize = 256;
pub const default_reorder_window_frames: u32 = 16;

pub const Config = struct {
    max_payload_bytes: usize = default_max_payload_bytes,
    reorder_window_frames: u32 = default_reorder_window_frames,
};

/// Overlay `[media]` keys from a parsed TOML document onto `cfg`.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.max_payload_bytes")) |v| cfg.max_payload_bytes = @intCast(v);
    if (doc.getUint("media.reorder_window_frames")) |v| cfg.reorder_window_frames = @intCast(v);
}

/// Build the runtime `ReassemblyConfig` (reorder window) for a Receiver from
/// `cfg`. The window must be <= the comptime `window` bound of the Receiver type.
pub fn reassemblyConfig(cfg: Config) cadence.ReassemblyConfig {
    return .{ .window = cfg.reorder_window_frames };
}

/// Run the sdp offer/answer to produce the negotiated media description.
/// Caller owns the returned description (call `deinit`).
pub fn negotiate(
    allocator: std.mem.Allocator,
    local_offer: MediaDescription,
    remote_offer: MediaDescription,
) !MediaDescription {
    return sdp.offerAnswer(allocator, local_offer, remote_offer);
}

/// Sender-side framing: assigns monotonic sequence numbers and encodes frames.
pub const Packetizer = struct {
    band_id: u8,
    stream_id: u32,
    codec: CodecTag,
    next_seq: u32 = 0,

    pub fn init(band_id: u8, stream_id: u32, codec: CodecTag) Packetizer {
        std.debug.assert(cadence.isMediaBand(band_id));
        return .{ .band_id = band_id, .stream_id = stream_id, .codec = codec };
    }

    pub fn frameFor(self: *Packetizer, payload: []const u8, keyframe: bool, timestamp: u64) MediaFrame {
        const f = MediaFrame{
            .band_id = self.band_id,
            .stream_id = self.stream_id,
            .sequence = self.next_seq,
            .timestamp = timestamp,
            .keyframe = keyframe,
            .codec = self.codec,
            .payload = payload,
        };
        self.next_seq +%= 1;
        return f;
    }

    /// Encode the next frame's wire bytes into `out`; returns the byte length.
    pub fn packetize(self: *Packetizer, payload: []const u8, keyframe: bool, timestamp: u64, out: []u8) cadence.EncodeError!usize {
        return cadence.encode(self.frameFor(payload, keyframe, timestamp), out);
    }
};

/// Receiver-side reorder + in-order delivery over an cadence reassembly buffer.
pub fn Receiver(comptime max_payload: usize, comptime window: u32) type {
    return struct {
        const Self = @This();
        reasm: cadence.ReassemblyBuffer(max_payload, window),

        pub fn init(cfg: cadence.ReassemblyConfig) Self {
            return .{ .reasm = cadence.ReassemblyBuffer(max_payload, window).init(cfg) };
        }

        /// Decode wire bytes and admit the frame to the reorder buffer.
        pub fn ingest(self: *Self, frame_bytes: []const u8) cadence.DecodeError!PushResult {
            const f = try cadence.decode(frame_bytes);
            return self.reasm.push(f);
        }

        /// Admit an already-decoded frame (e.g. one recovered via FEC).
        pub fn admit(self: *Self, frame: MediaFrame) PushResult {
            return self.reasm.push(frame);
        }

        /// Pull in-order frames into `out`; returns how many were written.
        pub fn drain(self: *Self, out: []MediaFrame) usize {
            return self.reasm.drain(out);
        }
    };
}

/// Map a media frame to the red_fec RTP-shaped packet model (the FEC layer keys
/// by 16-bit sequence; a generation stays within one 16-bit window).
fn toFecPacket(f: MediaFrame) red_fec.MediaPacket {
    return .{
        .seq = @truncate(f.sequence),
        .pt = @intCast(@backingInt(f.codec) & 0x7f),
        .marker = f.keyframe,
        .timestamp = @truncate(f.timestamp),
        .payload = f.payload,
    };
}

/// Build a single ULPFEC parity packet protecting `frames` (one generation,
/// <= 16 frames). Returns the FEC bytes written into `out`.
pub fn protectGeneration(frames: []const MediaFrame, out: []u8) !usize {
    var pkts: [16]red_fec.MediaPacket = undefined;
    std.debug.assert(frames.len <= pkts.len);
    for (frames, 0..) |f, i| pkts[i] = toFecPacket(f);
    return red_fec.buildFecPacket(pkts[0..frames.len], out);
}

pub fn fecSizeFor(frames: []const MediaFrame) usize {
    var pkts: [16]red_fec.MediaPacket = undefined;
    for (frames, 0..) |f, i| pkts[i] = toFecPacket(f);
    return red_fec.fecPacketSize(pkts[0..frames.len]);
}

/// Recover a single dropped frame in a generation from the FEC packet plus the
/// surviving frames. `template` supplies band/stream/codec for reconstruction.
/// The returned frame's `payload` is allocator-owned; free it when done.
pub fn recoverFrame(
    allocator: std.mem.Allocator,
    fec_bytes: []const u8,
    received: []const MediaFrame,
    missing_sequence: u32,
    template: MediaFrame,
) !?MediaFrame {
    var pkts: [16]red_fec.MediaPacket = undefined;
    std.debug.assert(received.len <= pkts.len);
    for (received, 0..) |f, i| pkts[i] = toFecPacket(f);
    const recovered = try red_fec.recoverPacket(fec_bytes, pkts[0..received.len], @truncate(missing_sequence), allocator) orelse return null;
    return MediaFrame{
        .band_id = template.band_id,
        .stream_id = template.stream_id,
        .sequence = missing_sequence,
        .timestamp = recovered.timestamp,
        .keyframe = recovered.marker,
        .codec = template.codec,
        .payload = recovered.payload, // allocator-owned
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const MEDIA_BAND: u8 = 64;

test "negotiate intersects codecs and FEC via sdp" {
    const allocator = testing.allocator;
    const local_codecs = [_]sdp.Codec{
        .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 },
        .{ .tag = .raw, .clock_rate = 8000, .params = 0 },
    };
    const remote_codecs = [_]sdp.Codec{
        .{ .tag = .raw, .clock_rate = 8000, .params = 0 },
        .{ .tag = .cadencevox, .clock_rate = 48000, .params = 0 },
    };
    const local = MediaDescription{ .band_id = MEDIA_BAND, .kind = .audio, .codecs = &local_codecs, .fec = .{ .scheme = .rs_block, .redundancy = 1 }, .direction = .sendrecv };
    const remote = MediaDescription{ .band_id = MEDIA_BAND, .kind = .audio, .codecs = &remote_codecs, .fec = .{ .scheme = .rs_block, .redundancy = 1 }, .direction = .sendrecv };
    var neg = try negotiate(allocator, local, remote);
    defer neg.deinit(allocator);
    try testing.expect(neg.codecs.len >= 1);
    try testing.expectEqual(MEDIA_BAND, neg.band_id);
}

test "packetize -> reorder -> in-order delivery" {
    var pk = Packetizer.init(MEDIA_BAND, 7, .cadencevox_audio);
    var rx = Receiver(256, 64).init(.{ .window = 16 });

    // Produce 4 frames, deliver them out of order (2,0,3,1).
    var wire: [4][128]u8 = undefined;
    var lens: [4]usize = undefined;
    const payloads: [4][]const u8 = .{ "frame-zero", "frame-one!", "frame-two!", "frame-three" };
    for (0..4) |i| lens[i] = try pk.packetize(payloads[i], i == 0, @intCast(i * 960), &wire[i]);

    // Anchor on the lowest seq, then deliver the rest out of order within the
    // forward reorder window.
    for ([_]usize{ 0, 3, 1, 2 }) |i| {
        _ = try rx.ingest(wire[i][0..lens[i]]);
    }
    var out: [8]MediaFrame = undefined;
    const n = rx.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    for (0..4) |i| try testing.expectEqual(@as(u32, @intCast(i)), out[i].sequence);
    try testing.expectEqualStrings("frame-zero", out[0].payload);
}

test "FEC recovers a single dropped frame and delivery completes in order" {
    const allocator = testing.allocator;
    var pk = Packetizer.init(MEDIA_BAND, 9, .cadencevox_audio);
    var rx = Receiver(256, 64).init(.{ .window = 16 });

    // Build a generation of 4 frames (kept for FEC), encode each to the wire.
    var frames: [4]MediaFrame = undefined;
    var wire: [4][128]u8 = undefined;
    var lens: [4]usize = undefined;
    const payloads = [_][]const u8{ "gen-aaaa", "gen-bbbb", "gen-cccc", "gen-dddd" };
    for (0..4) |i| {
        frames[i] = pk.frameFor(payloads[i], false, @intCast(i * 960));
        lens[i] = try cadence.encode(frames[i], &wire[i]);
    }

    var fec_buf: [256]u8 = undefined;
    const fec_len = try protectGeneration(&frames, &fec_buf);

    // Drop frame index 1; ingest the other three.
    var survivors: [3]MediaFrame = undefined;
    var s: usize = 0;
    for (0..4) |i| {
        if (i == 1) continue;
        _ = try rx.ingest(wire[i][0..lens[i]]);
        survivors[s] = frames[i];
        s += 1;
    }

    // Recover the dropped frame from the FEC packet + survivors.
    const recovered = (try recoverFrame(allocator, fec_buf[0..fec_len], &survivors, frames[1].sequence, frames[0])).?;
    defer allocator.free(recovered.payload);
    try testing.expectEqualStrings("gen-bbbb", recovered.payload);
    _ = rx.admit(recovered);

    var out: [8]MediaFrame = undefined;
    const n = rx.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    for (0..4) |i| try testing.expectEqual(@as(u32, @intCast(i)), out[i].sequence);
}

test "applyToml defaults match the canonical Receiver wiring" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(default_max_payload_bytes, cfg.max_payload_bytes);
    try testing.expectEqual(default_reorder_window_frames, cfg.reorder_window_frames);
    try testing.expectEqual(default_reorder_window_frames, reassemblyConfig(cfg).window);
}

test "applyToml overlays media keys and drives a Receiver window" {
    const src =
        \\[media]
        \\max_payload_bytes = 512
        \\reorder_window_frames = 8
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(usize, 512), cfg.max_payload_bytes);
    try testing.expectEqual(@as(u32, 8), cfg.reorder_window_frames);

    // Comptime bounds must cover the configured runtime window; the runtime
    // window is taken from config.
    var rx = Receiver(256, 64).init(reassemblyConfig(cfg));
    var pk = Packetizer.init(MEDIA_BAND, 1, .cadencevox_audio);
    var wire: [64]u8 = undefined;
    const len = try pk.packetize("hi", true, 0, &wire);
    try testing.expectEqual(PushResult.buffered, try rx.ingest(wire[0..len]));
}
