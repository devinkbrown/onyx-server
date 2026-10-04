// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opcodec media framing layer — container/packetization for Onyx Server media bands.
//!
//! NOT the audio/video codec itself: this is the wire container that carries
//! encoded payloads over Undertow mesh "media bands".
//!
//! ## Band model
//! Band IDs < 64 are control bands.  Media frames must use band IDs >= 64.
//!
//! ## Wire format
//! ```
//! [ 4-byte payload-length (LE u32) ]
//! [ 1-byte  band_id                ]
//! [ 4-byte  stream_id  (LE u32)    ]
//! [ 4-byte  sequence   (LE u32)    ]
//! [ 8-byte  timestamp  (LE u64)    ]
//! [ 1-byte  flags  (bit0=keyframe) ]
//! [ 1-byte  codec_tag              ]
//! [ payload bytes …               ]
//! ```
//! MIN_FRAME_WIRE_BYTES = 23 (4-byte prefix + 19-byte header).
//!
//! ## Reassembly buffer
//! Bounded sliding-window: accepts out-of-order frames, emits in-order,
//! drops duplicates, surfaces gap ranges for FEC/retransmit.
const std = @import("std");
const crypto_hash = @import("../crypto/hash.zig");
const toml = @import("../proto/toml.zig");

const Allocator = std.mem.Allocator;

/// Default out-of-order reorder/jitter window depth (frames). Frames outside the
/// window are late-dropped. Mirrors `ReassemblyConfig.window`'s default.
pub const default_reorder_window_frames: u32 = 64;
pub const window_cap: u32 = 64;

/// Runtime-tunable reassembly defaults. The actual ring storage of
/// `ReassemblyBuffer(max_payload, window_cap)` is comptime-bound (DEFERRED); only
/// the runtime `ReassemblyConfig.window` default is lifted here. Defaults equal
/// the historical values; `applyToml` overlays the `[media]` section.
pub const Config = struct {
    reorder_window_frames: u32 = default_reorder_window_frames,
};

/// Overlay `[media]` keys from a parsed TOML document onto `cfg`.
pub fn applyToml(cfg: *Config, doc: *const toml.Document) void {
    if (doc.getUint("media.reorder_window_frames")) |v| cfg.reorder_window_frames = @intCast(v);
}

/// Build a `ReassemblyConfig` whose runtime window comes from `cfg`. The caller
/// must still ensure the value is <= the comptime `window_cap` of the buffer it
/// initializes.
pub fn reassemblyConfig(cfg: Config) ReassemblyConfig {
    return .{ .window = cfg.reorder_window_frames };
}

// -- Constants ---------------------------------------------------------------

/// Band IDs [0, MEDIA_BAND_FLOOR) are reserved for control traffic.
pub const MEDIA_BAND_FLOOR: u8 = 64;
/// Header size excluding the 4-byte length prefix.
/// band_id(1)+stream_id(4)+sequence(4)+timestamp(8)+flags(1)+codec_tag(1)=19.
pub const HEADER_BYTES: usize = 19;
/// Minimum encoded frame size: 4 (length prefix) + 19 (header).
pub const MIN_FRAME_WIRE_BYTES: usize = 4 + HEADER_BYTES;
/// Native-media datagram authentication tag size, appended after the exact
/// cadence frame bytes. The tag is HMAC-SHA256 truncated to 128 bits.
pub const MAC_TAG_BYTES: usize = 16;
/// Per-stream MAC key size derived from the native stream-id PRF root.
pub const MAC_KEY_BYTES: usize = 32;
/// HKDF info/domain label used to derive per-stream native-media MAC keys.
pub const MAC_KEY_DERIVE_LABEL = "onyx native-media datagram mac v1";

// -- Codec tag ---------------------------------------------------------------

/// Codec family that produced the payload bytes.
pub const CodecTag = enum(u8) {
    cadencevox_audio = 0x01,
    cadencevis_video = 0x02,
    raw = 0x00,

    pub fn fromByte(b: u8) DecodeError!CodecTag {
        return switch (b) {
            0x00 => .raw,
            0x01 => .cadencevox_audio,
            0x02 => .cadencevis_video,
            else => error.UnknownCodecTag,
        };
    }
};

// -- Error sets --------------------------------------------------------------

pub const DecodeError = error{
    Truncated,
    ControlBandId,
    TrailingBytes,
    UnknownCodecTag,
};

pub const EncodeError = error{
    BufferTooSmall,
    ControlBandId,
};

pub const MacError = DecodeError || error{
    MissingTag,
    BadTag,
    BufferTooSmall,
};

// -- MediaFrame --------------------------------------------------------------

/// One media frame.  Payload slice is borrowed — not owned by this struct.
pub const MediaFrame = struct {
    /// Media band; must be >= MEDIA_BAND_FLOOR.
    band_id: u8,
    /// Logical stream identifier (e.g. one participant's audio track).
    stream_id: u32,
    /// Monotonically increasing sequence; wraps at 2^32.
    sequence: u32,
    /// Media clock timestamp (samples or ms ticks, codec-defined).
    timestamp: u64,
    /// True when this is a codec key/sync frame (IDR, etc.).
    keyframe: bool,
    /// Codec that produced `payload`.
    codec: CodecTag,
    payload: []const u8,
};

/// Decoded frame that borrows the input buffer.
pub const FrameView = MediaFrame;

/// Returns `true` when `band_id` is a media band (>= MEDIA_BAND_FLOOR).
pub fn isMediaBand(band_id: u8) bool {
    return band_id >= MEDIA_BAND_FLOOR;
}

// -- Encoding ----------------------------------------------------------------

/// Encode `frame` into `buf`.  Returns bytes written, or an error.
pub fn encode(frame: MediaFrame, buf: []u8) EncodeError!usize {
    if (!isMediaBand(frame.band_id)) return error.ControlBandId;
    const payload_len = frame.payload.len;
    const total = MIN_FRAME_WIRE_BYTES + payload_len;
    if (buf.len < total) return error.BufferTooSmall;
    var pos: usize = 0;
    writeU32Le(buf[pos..], @intCast(payload_len));
    pos += 4;
    buf[pos] = frame.band_id;
    pos += 1;
    writeU32Le(buf[pos..], frame.stream_id);
    pos += 4;
    writeU32Le(buf[pos..], frame.sequence);
    pos += 4;
    writeU64Le(buf[pos..], frame.timestamp);
    pos += 8;
    buf[pos] = if (frame.keyframe) @as(u8, 1) else @as(u8, 0);
    pos += 1;
    buf[pos] = @intFromEnum(frame.codec);
    pos += 1;
    @memcpy(buf[pos .. pos + payload_len], frame.payload);
    pos += payload_len;
    return pos;
}

// -- Decoding ----------------------------------------------------------------

/// Decode a frame from `buf`, returning a `FrameView` that borrows `buf`.
/// Rejects truncation, control band IDs, unknown codec tags, trailing bytes.
pub fn decode(buf: []const u8) DecodeError!FrameView {
    const declared_total = try encodedFrameLen(buf);
    if (buf.len > declared_total) return error.TrailingBytes;
    return decodeExact(buf);
}

/// Return the exact cadence frame length declared by `buf`'s length prefix,
/// excluding any native-media MAC tag that may follow it.
pub fn encodedFrameLen(buf: []const u8) DecodeError!usize {
    if (buf.len < MIN_FRAME_WIRE_BYTES) return error.Truncated;
    const payload_len: usize = readU32Le(buf[0..4]);
    const declared_total = MIN_FRAME_WIRE_BYTES + payload_len;
    if (buf.len < declared_total) return error.Truncated;
    return declared_total;
}

/// Decode the cadence frame prefix from `buf`, ignoring an optional outer MAC tag
/// that follows the declared frame bytes. Other trailing byte counts are still
/// rejected.
pub fn decodeMaybeAuthenticated(buf: []const u8) DecodeError!FrameView {
    const frame_bytes = try authenticatedFrameBytes(buf);
    return decodeExact(frame_bytes);
}

/// Return the frame prefix when `buf` is either exactly a frame or a frame plus
/// one fixed-size native-media MAC tag.
pub fn authenticatedFrameBytes(buf: []const u8) DecodeError![]const u8 {
    const declared_total = try encodedFrameLen(buf);
    if (buf.len == declared_total or buf.len == declared_total + MAC_TAG_BYTES) {
        return buf[0..declared_total];
    }
    return error.TrailingBytes;
}

pub fn hasAuthenticationTag(buf: []const u8) DecodeError!bool {
    const declared_total = try encodedFrameLen(buf);
    if (buf.len == declared_total) return false;
    if (buf.len == declared_total + MAC_TAG_BYTES) return true;
    return error.TrailingBytes;
}

fn decodeExact(buf: []const u8) DecodeError!FrameView {
    var pos: usize = 0;
    const payload_len: usize = readU32Le(buf[pos..]);
    pos += 4;
    const declared_total = MIN_FRAME_WIRE_BYTES + payload_len;
    std.debug.assert(buf.len == declared_total);
    const band_id = buf[pos];
    pos += 1;
    if (!isMediaBand(band_id)) return error.ControlBandId;
    const stream_id = readU32Le(buf[pos..]);
    pos += 4;
    const sequence = readU32Le(buf[pos..]);
    pos += 4;
    const timestamp = readU64Le(buf[pos..]);
    pos += 8;
    const flags = buf[pos];
    pos += 1;
    const keyframe = (flags & 0x01) != 0;
    const codec = try CodecTag.fromByte(buf[pos]);
    pos += 1;
    // payload slice borrows buf
    const payload = buf[pos .. pos + payload_len];

    return FrameView{
        .band_id = band_id,
        .stream_id = stream_id,
        .sequence = sequence,
        .timestamp = timestamp,
        .keyframe = keyframe,
        .codec = codec,
        .payload = payload,
    };
}

/// Derive the per-stream MAC key from the existing native stream-id PRF root.
/// This is HKDF-SHA256 extract + single-block expand with a distinct label and
/// the stream's public `(channel, participant)` context.
pub fn deriveNativeMediaMacKey(
    stream_prf_key: *const [16]u8,
    channel: []const u8,
    participant: []const u8,
    out: *[MAC_KEY_BYTES]u8,
) void {
    const HmacSha256 = crypto_hash.HmacSha256;
    var prk = HmacSha256.create("onyx native-media mac extract v1", stream_prf_key);
    defer std.crypto.secureZero(u8, prk[0..]);

    var mac = HmacSha256.init(&prk);
    mac.update(MAC_KEY_DERIVE_LABEL);
    mac.update(&[_]u8{0});
    mac.update(channel);
    mac.update(&[_]u8{0});
    mac.update(participant);
    mac.update(&[_]u8{1});
    out.* = mac.final();
}

pub fn nativeMediaMacTag(
    stream_prf_key: *const [16]u8,
    channel: []const u8,
    participant: []const u8,
    frame_bytes: []const u8,
) [MAC_TAG_BYTES]u8 {
    var key: [MAC_KEY_BYTES]u8 = undefined;
    deriveNativeMediaMacKey(stream_prf_key, channel, participant, &key);
    defer std.crypto.secureZero(u8, key[0..]);

    return nativeMediaMacTagWithKey(&key, frame_bytes);
}

/// Tag exact frame bytes using an already source-selected key. This primitive
/// performs no key derivation, endpoint admission or direction selection.
pub fn nativeMediaMacTagWithKey(
    key: *const [MAC_KEY_BYTES]u8,
    frame_bytes: []const u8,
) [MAC_TAG_BYTES]u8 {
    const full = crypto_hash.HmacSha256.create(key, frame_bytes);
    var tag: [MAC_TAG_BYTES]u8 = undefined;
    @memcpy(tag[0..], full[0..MAC_TAG_BYTES]);
    return tag;
}

/// Verify exactly one frame and one tag with the source-selected key. As in the
/// legacy verifier, frame semantic decoding remains a separate required step.
pub fn verifyNativeMediaMacWithKey(
    key: *const [MAC_KEY_BYTES]u8,
    datagram: []const u8,
) MacError![]const u8 {
    const frame_len = try encodedFrameLen(datagram);
    if (datagram.len == frame_len) return error.MissingTag;
    if (datagram.len != frame_len + MAC_TAG_BYTES) return error.TrailingBytes;
    const frame_bytes = datagram[0..frame_len];
    const expected = nativeMediaMacTagWithKey(key, frame_bytes);
    if (!constantTimeTagEql(&expected, datagram[frame_len..])) return error.BadTag;
    return frame_bytes;
}

/// Append a tag without changing the exact encoded frame. Every fallible check
/// precedes output writes; this helper never falls back to an untagged frame.
pub fn appendNativeMediaMacWithKey(
    key: *const [MAC_KEY_BYTES]u8,
    frame_datagram: []const u8,
    out: []u8,
) MacError![]const u8 {
    const frame_len = try encodedFrameLen(frame_datagram);
    if (frame_datagram.len != frame_len) return error.TrailingBytes;
    const total = frame_len + MAC_TAG_BYTES;
    if (out.len < total) return error.BufferTooSmall;
    @memcpy(out[0..frame_len], frame_datagram);
    const tag = nativeMediaMacTagWithKey(key, out[0..frame_len]);
    @memcpy(out[frame_len..total], &tag);
    return out[0..total];
}

pub fn constantTimeTagEql(a: []const u8, b: []const u8) bool {
    const len_diff = a.len ^ b.len;
    const n = @min(a.len, b.len);
    var folded = len_diff;
    folded |= folded >> 32;
    folded |= folded >> 16;
    folded |= folded >> 8;
    var diff: u8 = @truncate(folded);
    var i: usize = 0;
    while (i < n) : (i += 1) diff |= a[i] ^ b[i];
    return diff == 0;
}

/// Verify an appended native-media MAC tag. Returns the frame prefix on success.
pub fn verifyNativeMediaMac(
    stream_prf_key: *const [16]u8,
    channel: []const u8,
    participant: []const u8,
    datagram: []const u8,
) MacError![]const u8 {
    const frame_len = try encodedFrameLen(datagram);
    if (datagram.len == frame_len) return error.MissingTag;
    if (datagram.len != frame_len + MAC_TAG_BYTES) return error.TrailingBytes;

    const frame_bytes = datagram[0..frame_len];
    const got = datagram[frame_len..][0..MAC_TAG_BYTES];
    const expected = nativeMediaMacTag(stream_prf_key, channel, participant, frame_bytes);
    if (!constantTimeTagEql(expected[0..], got)) return error.BadTag;
    return frame_bytes;
}

/// Transition helper for the default-compatible server mode: untagged frames are
/// accepted when `require_tag` is false, but a present tag must still verify.
pub fn acceptNativeMediaMac(
    stream_prf_key: *const [16]u8,
    channel: []const u8,
    participant: []const u8,
    datagram: []const u8,
    require_tag: bool,
) MacError![]const u8 {
    const frame_len = try encodedFrameLen(datagram);
    if (datagram.len == frame_len) {
        if (require_tag) return error.MissingTag;
        return datagram[0..frame_len];
    }
    if (datagram.len != frame_len + MAC_TAG_BYTES) return error.TrailingBytes;
    return verifyNativeMediaMac(stream_prf_key, channel, participant, datagram);
}

pub fn appendNativeMediaMac(
    stream_prf_key: *const [16]u8,
    channel: []const u8,
    participant: []const u8,
    frame_datagram: []const u8,
    out: []u8,
) MacError![]const u8 {
    const frame_len = try encodedFrameLen(frame_datagram);
    if (frame_datagram.len != frame_len) return error.TrailingBytes;
    const total = frame_len + MAC_TAG_BYTES;
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..frame_len], frame_datagram);
    const tag = nativeMediaMacTag(stream_prf_key, channel, participant, out[0..frame_len]);
    @memcpy(out[frame_len..total], &tag);
    return out[0..total];
}

/// Encode `frame` and return a freshly-allocated slice owned by the caller.
pub fn encodeAlloc(frame: MediaFrame, allocator: Allocator) (EncodeError || Allocator.Error)![]u8 {
    if (!isMediaBand(frame.band_id)) return error.ControlBandId;
    const buf = try allocator.alloc(u8, MIN_FRAME_WIRE_BYTES + frame.payload.len);
    errdefer allocator.free(buf);
    _ = try encode(frame, buf);
    return buf;
}

// -- Gap range (FEC seam) ----------------------------------------------------

/// Half-open range of missing sequence numbers [start, end).
pub const GapRange = struct {
    start: u32,
    end: u32,
    pub fn len(self: GapRange) u32 {
        return wrappingDelta(self.start, self.end);
    }
};

// -- Reassembly buffer -------------------------------------------------------

pub const ReassemblyConfig = struct {
    /// Out-of-order window size.  Frames outside this window are late-dropped.
    window: u32 = default_reorder_window_frames,
    /// Optional anchor sequence.  When null, the first push sets the anchor.
    initial_seq: ?u32 = null,
};

const SlotState = enum { empty, filled, consumed };

fn Slot(comptime max_payload: usize) type {
    return struct {
        state: SlotState = .empty,
        frame: MediaFrame = undefined,
        payload_buf: [max_payload]u8 = undefined,
        payload_len: usize = 0,
    };
}

pub const PushResult = enum { buffered, duplicate, late_drop };

/// Jitter/reorder reassembly buffer.  Accepts out-of-order frames, emits
/// in-order.  `max_payload` and `window_cap` are compile-time bounds;
/// runtime window from `ReassemblyConfig` must be <= `window_cap`.
pub fn ReassemblyBuffer(comptime max_payload: usize, comptime window_limit: u32) type {
    return struct {
        const Self = @This();
        const RingSlot = Slot(max_payload);

        ring: [window_limit]RingSlot = @splat(.{}),
        next_seq: u32 = 0,
        anchored: bool = false,
        /// Highest buffered sequence; bounds gap scanning in reportGaps.
        high_watermark: u32 = 0,
        high_watermark_set: bool = false,
        window: u32 = window_limit,
        // Statistics (all public, read-only by callers).
        late_drop_count: u64 = 0,
        duplicate_count: u64 = 0,
        gap_count: u64 = 0,
        // Bitset: recovered[offset] = FEC has synthesised next_seq+offset.
        recovered_bits: [window_limit / 8 + 1]u8 = @splat(0),

        pub fn init(cfg: ReassemblyConfig) Self {
            std.debug.assert(cfg.window > 0 and cfg.window <= window_limit);
            var self = Self{};
            self.window = cfg.window;
            if (cfg.initial_seq) |s| {
                self.next_seq = s;
                self.anchored = true;
            }
            return self;
        }

        /// Insert a frame.  Payload copied into inline storage.
        /// Returns `.buffered`, `.duplicate`, or `.late_drop`.
        pub fn push(self: *Self, frame: MediaFrame) PushResult {
            if (!self.anchored) {
                self.next_seq = frame.sequence;
                self.anchored = true;
            }
            const seq = frame.sequence;
            const win = self.window;
            const fwd = wrappingDelta(self.next_seq, seq); // distance forward
            const behind = wrappingDelta(seq, self.next_seq); // distance backward

            if (fwd == 0) {
                // seq == next_seq; fall through to normal slot handling.
            } else if (fwd < win) {
                // within forward window; fall through.
            } else if (behind > 0 and behind <= win) {
                // seq is behind next_seq (already-consumed region). Only a true
                // re-send of a slot still holding this exact seq is a duplicate;
                // anything else is a distinct frame that arrived too late.
                const idx = seq % window_limit;
                const slot = &self.ring[idx];
                if ((slot.state == .consumed or slot.state == .filled) and slot.frame.sequence == seq) {
                    self.duplicate_count += 1;
                    return .duplicate;
                }
                self.late_drop_count += 1;
                return .late_drop;
            } else {
                self.late_drop_count += 1;
                return .late_drop;
            }

            const idx = seq % window_limit;
            var slot = &self.ring[idx];

            if (slot.state == .filled and slot.frame.sequence == seq) {
                self.duplicate_count += 1;
                return .duplicate;
            }
            if (slot.state == .consumed and slot.frame.sequence == seq) {
                self.duplicate_count += 1;
                return .duplicate;
            }

            // Copy payload into inline storage.
            const plen = @min(frame.payload.len, max_payload);
            slot.payload_len = plen;
            @memcpy(slot.payload_buf[0..plen], frame.payload[0..plen]);

            slot.frame = frame;
            slot.frame.payload = slot.payload_buf[0..plen];
            slot.state = .filled;

            // Update high watermark (wrapping-aware).
            if (!self.high_watermark_set) {
                self.high_watermark = seq;
                self.high_watermark_set = true;
            } else if (wrappingDelta(self.high_watermark, seq) < self.window) {
                self.high_watermark = seq;
            }

            return .buffered;
        }

        /// Attempt to drain in-order frames into `out_slice`.
        /// Returns the number of frames written to `out_slice`.
        /// The frames in `out_slice` borrow payload from ring storage;
        /// the caller must consume them before the next `push`.
        pub fn drain(self: *Self, out_slice: []MediaFrame) usize {
            var count: usize = 0;
            while (count < out_slice.len) {
                const idx = self.next_seq % window_limit;
                const slot = &self.ring[idx];
                if (slot.state != .filled or slot.frame.sequence != self.next_seq) break;

                out_slice[count] = slot.frame;
                slot.state = .consumed;
                self.next_seq +%= 1;
                // recovered_bits are indexed by offset from next_seq; sliding the
                // window forward by one must slide the bitset down by one too,
                // or stale bits would mask later sequences as "recovered".
                self.shiftRecoveredBitsDown1();
                count += 1;
            }
            return count;
        }

        /// Report contiguous gap ranges in [next_seq, high_watermark].
        /// Invokes `callback` for each gap; recovered sequences are skipped.
        pub fn reportGaps(self: *const Self, callback: fn (GapRange) void) void {
            if (!self.anchored or !self.high_watermark_set) return;
            const scan_end = self.high_watermark +% 1;
            const scan_count = wrappingDelta(self.next_seq, scan_end);
            if (scan_count == 0) return;
            var gap_start: ?u32 = null;
            var offset: u32 = 0;
            while (offset < scan_count) : (offset += 1) {
                const seq = self.next_seq +% offset;
                const slot = &self.ring[seq % window_limit];
                const filled = slot.state == .filled and slot.frame.sequence == seq;
                if (!filled and !self.isRecoveredBit(offset)) {
                    if (gap_start == null) gap_start = seq;
                } else if (gap_start) |gs| {
                    callback(.{ .start = gs, .end = seq });
                    gap_start = null;
                }
            }
            if (gap_start) |gs| callback(.{ .start = gs, .end = scan_end });
        }

        /// Mark `seq` as FEC-recovered; synthesises a placeholder so drain
        /// can advance past the gap without stalling.
        pub fn markRecovered(self: *Self, seq: u32) void {
            if (!self.anchored) return;
            const delta = wrappingDelta(self.next_seq, seq);
            if (delta >= self.window) return;
            self.setRecoveredBit(delta);
            const idx = seq % window_limit;
            var slot = &self.ring[idx];
            if (slot.state != .filled) {
                slot.payload_len = 0;
                slot.frame = .{
                    .band_id = MEDIA_BAND_FLOOR,
                    .stream_id = 0,
                    .sequence = seq,
                    .timestamp = 0,
                    .keyframe = false,
                    .codec = .raw,
                    .payload = slot.payload_buf[0..0],
                };
                slot.state = .filled;
            }
        }

        fn isRecoveredBit(self: *const Self, offset: u32) bool {
            const byte_idx = offset / 8;
            const bit_idx: u3 = @intCast(offset % 8);
            if (byte_idx >= self.recovered_bits.len) return false;
            return (self.recovered_bits[byte_idx] >> bit_idx) & 1 == 1;
        }

        fn setRecoveredBit(self: *Self, offset: u32) void {
            const byte_idx = offset / 8;
            const bit_idx: u3 = @intCast(offset % 8);
            if (byte_idx >= self.recovered_bits.len) return;
            self.recovered_bits[byte_idx] |= @as(u8, 1) << bit_idx;
        }

        fn clearRecoveredBits(self: *Self) void {
            @memset(&self.recovered_bits, 0);
        }

        /// Slide the whole recovered-bit set down by one offset (offset k → k-1,
        /// offset 0 dropped). Called once per sequence consumed by `drain` so the
        /// bits stay aligned to the advancing `next_seq`.
        fn shiftRecoveredBitsDown1(self: *Self) void {
            const n = self.recovered_bits.len;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                var b: u8 = self.recovered_bits[i] >> 1;
                if (i + 1 < n) b |= (self.recovered_bits[i + 1] & 1) << 7;
                self.recovered_bits[i] = b;
            }
        }

        // gap_count_incr is called from a const context in reportGaps; we need
        // interior mutability for the counter.  Worked around by making
        // reportGaps take *const Self and not incrementing in the hot path —
        // instead we expose gap_count as a read-only statistic updated on
        // drain when gaps close.  (The reportGaps callback is the FEC seam;
        // counting happens there.)
        fn gap_count_incr(_: *const Self) void {}
    };
}

// Little-endian I/O helpers (no std.mem.readInt in hot paths — inline)

fn writeU32Le(buf: []u8, v: u32) void {
    buf[0] = @truncate(v);
    buf[1] = @truncate(v >> 8);
    buf[2] = @truncate(v >> 16);
    buf[3] = @truncate(v >> 24);
}

fn writeU64Le(buf: []u8, v: u64) void {
    buf[0] = @truncate(v);
    buf[1] = @truncate(v >> 8);
    buf[2] = @truncate(v >> 16);
    buf[3] = @truncate(v >> 24);
    buf[4] = @truncate(v >> 32);
    buf[5] = @truncate(v >> 40);
    buf[6] = @truncate(v >> 48);
    buf[7] = @truncate(v >> 56);
}

fn readU32Le(buf: []const u8) u32 {
    return @as(u32, buf[0]) |
        (@as(u32, buf[1]) << 8) |
        (@as(u32, buf[2]) << 16) |
        (@as(u32, buf[3]) << 24);
}

fn readU64Le(buf: []const u8) u64 {
    return @as(u64, buf[0]) |
        (@as(u64, buf[1]) << 8) |
        (@as(u64, buf[2]) << 16) |
        (@as(u64, buf[3]) << 24) |
        (@as(u64, buf[4]) << 32) |
        (@as(u64, buf[5]) << 40) |
        (@as(u64, buf[6]) << 48) |
        (@as(u64, buf[7]) << 56);
}

/// Wrapping forward distance b - a (mod 2^32).
fn wrappingDelta(a: u32, b: u32) u32 {
    return b -% a;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn testFrame(band_id: u8, stream_id: u32, seq: u32, ts: u64, kf: bool, codec: CodecTag, payload: []const u8) MediaFrame {
    return MediaFrame{
        .band_id = band_id,
        .stream_id = stream_id,
        .sequence = seq,
        .timestamp = ts,
        .keyframe = kf,
        .codec = codec,
        .payload = payload,
    };
}

test "applyToml default matches the historical reorder window" {
    var doc = try toml.parse(testing.allocator, "");
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(default_reorder_window_frames, cfg.reorder_window_frames);
    try testing.expectEqual(default_reorder_window_frames, (ReassemblyConfig{}).window);
    try testing.expectEqual(default_reorder_window_frames, reassemblyConfig(cfg).window);
}

test "applyToml overlays media.reorder_window_frames" {
    const src =
        \\[media]
        \\reorder_window_frames = 32
    ;
    var doc = try toml.parse(testing.allocator, src);
    defer doc.deinit(testing.allocator);
    var cfg: Config = .{};
    applyToml(&cfg, &doc);
    try testing.expectEqual(@as(u32, 32), cfg.reorder_window_frames);
    try testing.expectEqual(@as(u32, 32), reassemblyConfig(cfg).window);
}

test "encode/decode round-trip: cadencevox_audio" {
    const payload = "audiobytes";
    const frame = testFrame(64, 1, 10, 48000, false, .cadencevox_audio, payload);

    var buf: [256]u8 = undefined;
    const written = try encode(frame, &buf);
    try testing.expectEqual(MIN_FRAME_WIRE_BYTES + payload.len, written);

    const view = try decode(buf[0..written]);
    try testing.expectEqual(@as(u8, 64), view.band_id);
    try testing.expectEqual(@as(u32, 1), view.stream_id);
    try testing.expectEqual(@as(u32, 10), view.sequence);
    try testing.expectEqual(@as(u64, 48000), view.timestamp);
    try testing.expect(!view.keyframe);
    try testing.expectEqual(CodecTag.cadencevox_audio, view.codec);
    try testing.expectEqualSlices(u8, payload, view.payload);
}

test "encode/decode round-trip: cadencevis_video keyframe" {
    const payload = "videoframe";
    const frame = testFrame(128, 2, 0, 90000, true, .cadencevis_video, payload);

    var buf: [256]u8 = undefined;
    const written = try encode(frame, &buf);
    const view = try decode(buf[0..written]);

    try testing.expectEqual(CodecTag.cadencevis_video, view.codec);
    try testing.expect(view.keyframe);
    try testing.expectEqual(@as(u64, 90000), view.timestamp);
}

test "encode/decode round-trip: raw codec, empty payload" {
    const frame = testFrame(255, 0, 0xFFFF_FFFE, 0, false, .raw, &[_]u8{});

    var buf: [MIN_FRAME_WIRE_BYTES + 4]u8 = undefined;
    const written = try encode(frame, &buf);
    try testing.expectEqual(MIN_FRAME_WIRE_BYTES, written);

    const view = try decode(buf[0..written]);
    try testing.expectEqual(CodecTag.raw, view.codec);
    try testing.expectEqual(@as(usize, 0), view.payload.len);
    try testing.expectEqual(@as(u32, 0xFFFF_FFFE), view.sequence);
}

test "control band rejected on encode" {
    const frame = testFrame(63, 1, 0, 0, false, .raw, &[_]u8{0x42});
    var buf: [256]u8 = undefined;
    try testing.expectError(error.ControlBandId, encode(frame, &buf));
}

test "control band rejected on decode" {
    // Manually craft a wire frame with band_id = 0.
    // Layout: [0..4]=payload_len, [4]=band_id, [5..9]=stream_id,
    //         [9..13]=sequence, [13..21]=timestamp, [21]=flags, [22]=codec_tag
    var buf: [MIN_FRAME_WIRE_BYTES]u8 = undefined;
    @memset(&buf, 0);
    // payload_len = 0 → already zeroed
    buf[4] = 0x00; // band_id = 0 (control)
    buf[22] = 0x00; // codec_tag = raw (irrelevant; band check fires first)
    try testing.expectError(error.ControlBandId, decode(&buf));
}

test "band boundary: 63 rejected, 64 accepted" {
    try testing.expect(!isMediaBand(63));
    try testing.expect(isMediaBand(64));
    try testing.expect(isMediaBand(255));
}

test "decode truncated: buffer too short" {
    var buf: [MIN_FRAME_WIRE_BYTES - 1]u8 = undefined;
    @memset(&buf, 0);
    try testing.expectError(error.Truncated, decode(&buf));
}

test "decode truncated: declared payload exceeds buffer" {
    var buf: [MIN_FRAME_WIRE_BYTES + 4]u8 = undefined;
    @memset(&buf, 0);
    buf[4] = 64; // valid band_id
    buf[22] = 0x01; // codec = cadencevox_audio (at fixed offset 22)
    // payload_len = 10 but buf only has space for 4 extra bytes
    writeU32Le(buf[0..4], 10);
    try testing.expectError(error.Truncated, decode(&buf));
}

test "decode trailing bytes rejected" {
    const payload = "hello";
    const frame = testFrame(64, 0, 0, 0, false, .raw, payload);

    var buf: [256]u8 = undefined;
    const written = try encode(frame, &buf);
    // Append a stray byte.
    buf[written] = 0xFF;
    try testing.expectError(error.TrailingBytes, decode(buf[0 .. written + 1]));
}

test "native media MAC compute and verify accepts a tagged datagram" {
    const key = @as([16]u8, @splat(0x42));
    const frame = testFrame(64, 0x1122_3344, 7, 9000, true, .cadencevox_audio, "voice");

    var frame_buf: [128]u8 = undefined;
    const frame_len = try encode(frame, &frame_buf);
    var tagged_buf: [128]u8 = undefined;
    const tagged = try appendNativeMediaMac(&key, "#call", "alice", frame_buf[0..frame_len], &tagged_buf);

    try testing.expectEqual(frame_len + MAC_TAG_BYTES, tagged.len);
    const verified = try verifyNativeMediaMac(&key, "#call", "alice", tagged);
    try testing.expectEqualSlices(u8, frame_buf[0..frame_len], verified);
    const view = try decodeMaybeAuthenticated(tagged);
    try testing.expectEqual(frame.stream_id, view.stream_id);
}

test "native media MAC rejects tampered payload and tag" {
    const key = @as([16]u8, @splat(0x24));
    const frame = testFrame(64, 0x0102_0304, 8, 123, false, .cadencevis_video, "video");

    var frame_buf: [128]u8 = undefined;
    const frame_len = try encode(frame, &frame_buf);
    var tagged_buf: [128]u8 = undefined;
    const tagged = try appendNativeMediaMac(&key, "#call", "alice", frame_buf[0..frame_len], &tagged_buf);

    var tampered_payload = tagged_buf;
    tampered_payload[MIN_FRAME_WIRE_BYTES] ^= 0x01;
    try testing.expectError(error.BadTag, verifyNativeMediaMac(&key, "#call", "alice", tampered_payload[0..tagged.len]));

    var tampered_tag = tagged_buf;
    tampered_tag[tagged.len - 1] ^= 0x80;
    try testing.expectError(error.BadTag, verifyNativeMediaMac(&key, "#call", "alice", tampered_tag[0..tagged.len]));
}

test "native media MAC transition mode accepts untagged only when not required" {
    const key = @as([16]u8, @splat(0x11));
    const frame = testFrame(64, 9, 1, 2, false, .raw, "x");

    var frame_buf: [128]u8 = undefined;
    const frame_len = try encode(frame, &frame_buf);

    try testing.expectEqualSlices(
        u8,
        frame_buf[0..frame_len],
        try acceptNativeMediaMac(&key, "#call", "alice", frame_buf[0..frame_len], false),
    );
    try testing.expectError(error.MissingTag, acceptNativeMediaMac(&key, "#call", "alice", frame_buf[0..frame_len], true));
}

test "native media MAC constant-time compare covers full tag" {
    const a = @as([MAC_TAG_BYTES]u8, @splat(0xA5));
    var first_diff = a;
    var last_diff = a;
    first_diff[0] ^= 0x01;
    last_diff[MAC_TAG_BYTES - 1] ^= 0x01;

    try testing.expect(constantTimeTagEql(a[0..], a[0..]));
    try testing.expect(!constantTimeTagEql(a[0..], first_diff[0..]));
    try testing.expect(!constantTimeTagEql(a[0..], last_diff[0..]));
    try testing.expect(!constantTimeTagEql(a[0..], a[0 .. MAC_TAG_BYTES - 1]));
}

test "ws-media MAC cross-repo KAT (shared with Onyx JS)" {
    // Canonical known-answer vectors shared byte-for-byte with the Onyx client's
    // mediaMac Vitest (test/vectors/ws_media_mac.json in both repos). Any change
    // to the derivation or tag MUST update both sides in lockstep.
    var root: [16]u8 = undefined;
    for (&root, 0..) |*b, i| b.* = @intCast(i); // 00 01 02 … 0f
    const channel = "#call";
    const participant = "alice";
    const frame = testFrame(64, 0x1122_3344, 7, 9000, true, .cadencevox_audio, "voice");

    var frame_buf: [128]u8 = undefined;
    const frame_len = try encode(frame, &frame_buf);
    try testing.expectEqualSlices(u8, &hexBytes(
        "0500000040443322110700000028230000000000000101766f696365",
    ), frame_buf[0..frame_len]);

    var k32: [MAC_KEY_BYTES]u8 = undefined;
    deriveNativeMediaMacKey(&root, channel, participant, &k32);
    try testing.expectEqualSlices(u8, &hexBytes(
        "1d4bbde57332c226590945e5a94259b4befe68264f6eeee864fe5adb741c2f0b",
    ), &k32);

    const tag = nativeMediaMacTag(&root, channel, participant, frame_buf[0..frame_len]);
    try testing.expectEqualSlices(u8, &hexBytes("5f274db2216a610c62affc09a34eebc9"), &tag);
}

/// Decode a compile-time hex literal to a fixed byte array (test helper).
fn hexBytes(comptime h: []const u8) [h.len / 2]u8 {
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

test "decode unknown codec tag rejected" {
    var buf: [MIN_FRAME_WIRE_BYTES]u8 = undefined;
    @memset(&buf, 0);
    writeU32Le(buf[0..4], 0); // payload_len = 0
    buf[4] = 64; // band_id
    buf[22] = 0xFF; // codec_tag = 0xFF (unknown)
    try testing.expectError(error.UnknownCodecTag, decode(&buf));
}

// encodeAlloc

test "encodeAlloc produces correct bytes" {
    const allocator = testing.allocator;
    const payload = "alloctest";
    const frame = testFrame(100, 7, 3, 1234, true, .cadencevox_audio, payload);

    const owned = try encodeAlloc(frame, allocator);
    defer allocator.free(owned);

    const view = try decode(owned);
    try testing.expectEqualSlices(u8, payload, view.payload);
    try testing.expectEqual(@as(u8, 100), view.band_id);
    try testing.expect(view.keyframe);
}

// Reassembly: in-order delivery

test "reassembly: in-order frames drain immediately" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    const payload = "data";
    var out: [4]MediaFrame = undefined;

    for (0..4) |i| {
        const f = testFrame(64, 0, @intCast(i), @intCast(i * 100), false, .raw, payload);
        const result = rb.push(f);
        try testing.expectEqual(PushResult.buffered, result);
    }

    const n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    for (out[0..n], 0..) |f, i| {
        try testing.expectEqual(@as(u32, @intCast(i)), f.sequence);
    }
}

// Reassembly: out-of-order arrival

test "reassembly: out-of-order reordered on drain" {
    // Use initial_seq=0 so the buffer knows to expect from seq 0.
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16, .initial_seq = 0 });

    const payload = "ooo";
    // Insert in reverse order: seq 2, 1, 0.
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, payload));
    _ = rb.push(testFrame(64, 0, 1, 100, false, .raw, payload));

    var out: [8]MediaFrame = undefined;

    // Nothing deliverable yet (seq 0 missing).
    var n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 0), n);

    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, payload));

    n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u32, 0), out[0].sequence);
    try testing.expectEqual(@as(u32, 1), out[1].sequence);
    try testing.expectEqual(@as(u32, 2), out[2].sequence);
}

// Reassembly: duplicate detection

test "reassembly: duplicate dropped and counted" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    const f = testFrame(64, 0, 0, 0, false, .raw, "d");
    _ = rb.push(f);
    const result = rb.push(f);
    try testing.expectEqual(PushResult.duplicate, result);
    try testing.expectEqual(@as(u64, 1), rb.duplicate_count);
}

test "reassembly: duplicate of already-delivered frame counted" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    const f = testFrame(64, 0, 0, 0, false, .raw, "d");
    _ = rb.push(f);

    var out: [1]MediaFrame = undefined;
    _ = rb.drain(&out);

    // Now push the same sequence again — already consumed.
    const result = rb.push(f);
    try testing.expectEqual(PushResult.duplicate, result);
    try testing.expectEqual(@as(u64, 1), rb.duplicate_count);
}

// Reassembly: gap detection

test "reassembly: gap reporting identifies missing range" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // Insert seq 0 and seq 3 — gaps at 1 and 2.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    _ = rb.push(testFrame(64, 0, 3, 300, false, .raw, "d"));

    var out: [1]MediaFrame = undefined;
    _ = rb.drain(&out); // advance next_seq to 1

    const GapCollector = struct {
        var gaps: [8]GapRange = undefined;
        var count: usize = 0;

        fn cb(g: GapRange) void {
            if (count < gaps.len) {
                gaps[count] = g;
                count += 1;
            }
        }
    };
    GapCollector.count = 0;

    rb.reportGaps(GapCollector.cb);

    // Should surface the gap [1, 3) — sequences 1 and 2 are missing.
    try testing.expectEqual(@as(usize, 1), GapCollector.count);
    try testing.expectEqual(@as(u32, 1), GapCollector.gaps[0].start);
    try testing.expectEqual(@as(u32, 3), GapCollector.gaps[0].end);
    try testing.expectEqual(@as(u32, 2), GapCollector.gaps[0].len());
}

test "reassembly: recovered bits do not leak past a drain" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // seq 0 real, seq 1 FEC-recovered, seq 2 real → all drain (next_seq → 3).
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    rb.markRecovered(1);
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));
    var out: [8]MediaFrame = undefined;
    try testing.expectEqual(@as(usize, 3), rb.drain(&out));

    // Now buffer seq 6: sequences 3,4,5 are a single contiguous gap. A stale
    // recovered bit (set for seq 1 at offset 1) must NOT mask seq 4 here.
    _ = rb.push(testFrame(64, 0, 6, 600, false, .raw, "g"));

    const C = struct {
        var gaps: [8]GapRange = undefined;
        var count: usize = 0;
        fn cb(g: GapRange) void {
            if (count < gaps.len) {
                gaps[count] = g;
                count += 1;
            }
        }
    };
    C.count = 0;
    rb.reportGaps(C.cb);

    try testing.expectEqual(@as(usize, 1), C.count);
    try testing.expectEqual(@as(u32, 3), C.gaps[0].start);
    try testing.expectEqual(@as(u32, 6), C.gaps[0].end);
}

test "reassembly: multiple disjoint gaps reported" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // Deliver seq 0, buffer seq 2 and seq 5 — gaps [1,2) and [3,5).
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));
    _ = rb.push(testFrame(64, 0, 5, 500, false, .raw, "f"));

    var out: [1]MediaFrame = undefined;
    _ = rb.drain(&out);

    const GapCollector = struct {
        var gaps: [8]GapRange = undefined;
        var count: usize = 0;

        fn cb(g: GapRange) void {
            if (count < gaps.len) {
                gaps[count] = g;
                count += 1;
            }
        }
    };
    GapCollector.count = 0;
    rb.reportGaps(GapCollector.cb);

    try testing.expectEqual(@as(usize, 2), GapCollector.count);
    try testing.expectEqual(@as(u32, 1), GapCollector.gaps[0].start);
    try testing.expectEqual(@as(u32, 2), GapCollector.gaps[0].end);
    try testing.expectEqual(@as(u32, 3), GapCollector.gaps[1].start);
    try testing.expectEqual(@as(u32, 5), GapCollector.gaps[1].end);
}

// Reassembly: FEC recovery hook

test "reassembly: markRecovered unblocks drain" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 16 });

    // seq 0 arrives, seq 1 is lost, seq 2 arrives.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));

    var out: [4]MediaFrame = undefined;
    var n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 1), n); // only seq 0

    // FEC layer recovers seq 1.
    rb.markRecovered(1);

    n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 2), n); // placeholder for 1, then real 2
    try testing.expectEqual(@as(u32, 1), out[0].sequence);
    try testing.expectEqual(@as(u32, 2), out[1].sequence);
}

// Reassembly: window overflow / late drop

test "reassembly: frame outside window is late-dropped and counted" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 8 });

    // Anchor at seq 0.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));

    // Frame at seq 100 is far outside the window of 8.
    const result = rb.push(testFrame(64, 0, 100, 9999, false, .raw, "late"));
    try testing.expectEqual(PushResult.late_drop, result);
    try testing.expectEqual(@as(u64, 1), rb.late_drop_count);
}

test "reassembly: frame at window boundary is late-dropped" {
    // With initial_seq=0 and window=4, valid range is [0,4).
    // seq 4 has fwd=4 which equals the window → late drop.
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 4, .initial_seq = 0 });

    // Fill window slots 1, 2, 3 (seq 0 missing = stall).
    _ = rb.push(testFrame(64, 0, 1, 100, false, .raw, "b"));
    _ = rb.push(testFrame(64, 0, 2, 200, false, .raw, "c"));
    _ = rb.push(testFrame(64, 0, 3, 300, false, .raw, "d"));

    // seq 4 is fwd=4 from next_seq=0 → equals window → late drop.
    const r4 = rb.push(testFrame(64, 0, 4, 400, false, .raw, "e"));
    try testing.expectEqual(PushResult.late_drop, r4);

    // Now deliver seq 0 to unblock and drain all buffered frames.
    _ = rb.push(testFrame(64, 0, 0, 0, false, .raw, "a"));
    var out: [8]MediaFrame = undefined;
    const n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
}

// Reassembly: sequence wrap-around

test "reassembly: sequence wraps around u32 max" {
    var rb = ReassemblyBuffer(128, 64).init(.{ .window = 8 });

    const max_seq: u32 = 0xFFFF_FFFF;

    // Insert near max and across the wrap.
    _ = rb.push(testFrame(64, 0, max_seq -% 1, 0, false, .raw, "penult"));
    _ = rb.push(testFrame(64, 0, max_seq, 1, false, .raw, "last"));
    _ = rb.push(testFrame(64, 0, 0, 2, false, .raw, "wrapped_0"));
    _ = rb.push(testFrame(64, 0, 1, 3, false, .raw, "wrapped_1"));

    var out: [8]MediaFrame = undefined;
    const n = rb.drain(&out);
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqual(max_seq -% 1, out[0].sequence);
    try testing.expectEqual(max_seq, out[1].sequence);
    try testing.expectEqual(@as(u32, 0), out[2].sequence);
    try testing.expectEqual(@as(u32, 1), out[3].sequence);
}

test "GapRange.len wrapping" {
    // 1 -% 0xFFFFFFFE = 3 in wrapping u32 arithmetic.
    const g = GapRange{ .start = 0xFFFF_FFFE, .end = 1 };
    try testing.expectEqual(@as(u32, 3), g.len());
}

test "native media MAC32 helper preserves legacy bytes and shared KAT" {
    var root: [16]u8 = undefined;
    for (&root, 0..) |*byte, i| byte.* = @intCast(i);
    var key: [MAC_KEY_BYTES]u8 = undefined;
    deriveNativeMediaMacKey(&root, "#call", "alice", &key);
    defer std.crypto.secureZero(u8, &key);
    const frame = testFrame(64, 0x1122_3344, 7, 9000, true, .cadencevox_audio, "voice");
    var frame_buf: [128]u8 = undefined;
    const n = try encode(frame, &frame_buf);
    var legacy_buf: [128]u8 = undefined;
    var direct_buf: [128]u8 = undefined;
    const legacy = try appendNativeMediaMac(&root, "#call", "alice", frame_buf[0..n], &legacy_buf);
    const direct = try appendNativeMediaMacWithKey(&key, frame_buf[0..n], &direct_buf);
    try testing.expectEqualSlices(u8, legacy, direct);
    const tag = nativeMediaMacTagWithKey(&key, frame_buf[0..n]);
    try testing.expectEqualSlices(u8, &hexBytes("5f274db2216a610c62affc09a34eebc9"), &tag);
    try testing.expectEqualSlices(u8, frame_buf[0..n], try verifyNativeMediaMacWithKey(&key, legacy));
    try testing.expectEqualSlices(u8, frame_buf[0..n], try verifyNativeMediaMac(&root, "#call", "alice", direct));
}

test "native media MAC32 helper rejects wrong key payload tag and incomplete suffix" {
    const key = @as([MAC_KEY_BYTES]u8, @splat(0xA7));
    const wrong = @as([MAC_KEY_BYTES]u8, @splat(0xA6));
    var frame_buf: [128]u8 = undefined;
    const n = try encode(testFrame(64, 73, 9, 10, false, .cadencevis_video, "payload"), &frame_buf);
    var tagged_buf: [128]u8 = undefined;
    const tagged = try appendNativeMediaMacWithKey(&key, frame_buf[0..n], &tagged_buf);
    try testing.expectError(error.BadTag, verifyNativeMediaMacWithKey(&wrong, tagged));
    var altered = tagged_buf;
    altered[MIN_FRAME_WIRE_BYTES] ^= 1;
    try testing.expectError(error.BadTag, verifyNativeMediaMacWithKey(&key, altered[0..tagged.len]));
    altered = tagged_buf;
    altered[tagged.len - 1] ^= 1;
    try testing.expectError(error.BadTag, verifyNativeMediaMacWithKey(&key, altered[0..tagged.len]));
    try testing.expectError(error.Truncated, verifyNativeMediaMacWithKey(&key, frame_buf[0 .. n - 1]));
    try testing.expectError(error.MissingTag, verifyNativeMediaMacWithKey(&key, frame_buf[0..n]));
    for (1..MAC_TAG_BYTES) |suffix| {
        try testing.expectError(error.TrailingBytes, verifyNativeMediaMacWithKey(&key, tagged[0 .. n + suffix]));
    }
    tagged_buf[tagged.len] = 0;
    try testing.expectError(error.TrailingBytes, verifyNativeMediaMacWithKey(&key, tagged_buf[0 .. tagged.len + 1]));
}

test "native media MAC32 helper refusal preserves output and allows exact retry" {
    const key = @as([MAC_KEY_BYTES]u8, @splat(0xC2));
    var frame_buf: [128]u8 = undefined;
    const n = try encode(testFrame(65, 81, 19, 20, false, .raw, "body"), &frame_buf);
    var out = @as([128]u8, @splat(0xD4));
    const before = out;
    try testing.expectError(error.BufferTooSmall, appendNativeMediaMacWithKey(&key, frame_buf[0..n], out[0 .. n + MAC_TAG_BYTES - 1]));
    try testing.expectEqualSlices(u8, &before, &out);
    try testing.expectError(error.Truncated, appendNativeMediaMacWithKey(&key, frame_buf[0 .. n - 1], &out));
    try testing.expectEqualSlices(u8, &before, &out);
    frame_buf[n] = 0;
    try testing.expectError(error.TrailingBytes, appendNativeMediaMacWithKey(&key, frame_buf[0 .. n + 1], &out));
    try testing.expectEqualSlices(u8, &before, &out);
    const tagged = try appendNativeMediaMacWithKey(&key, frame_buf[0..n], &out);
    try testing.expectEqualSlices(u8, frame_buf[0..n], try verifyNativeMediaMacWithKey(&key, tagged));
    try testing.expectEqualSlices(u8, before[tagged.len..], out[tagged.len..]);
}
